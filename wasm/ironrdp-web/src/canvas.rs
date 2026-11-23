use core::cell::RefCell;
use core::num::NonZeroU32;
use std::rc::Rc;

#[cfg(target_arch = "wasm32")]
use anyhow::anyhow;
use ironrdp::pdu::geometry::InclusiveRectangle;
#[cfg(target_arch = "wasm32")]
use ironrdp::pdu::geometry::Rectangle as _;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::closure::Closure;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{Clamped, JsCast as _};
#[cfg(target_arch = "wasm32")]
use web_sys::ImageData;
use web_sys::{CanvasRenderingContext2d, HtmlCanvasElement};

/// 待合成的一帧：脏区并集与调度状态。
///
/// 脏区合并到一次 `drawImage` 而不是每个矩形提交一次，理由见 `Canvas::draw`。
struct Present {
    /// (left, top, width, height)，已裁剪到画布范围内。
    dirty: Option<(u32, u32, u32, u32)>,
    /// 已经排过一次 `requestAnimationFrame`，避免同一帧重复排队。
    scheduled: bool,
    width: u32,
    height: u32,
}

impl Present {
    fn mark(&mut self, region: InclusiveRectangle) {
        let x = u32::from(region.left);
        let y = u32::from(region.top);
        let w = u32::from(region.width());
        let h = u32::from(region.height());
        if w == 0 || h == 0 || self.width == 0 || self.height == 0 {
            return;
        }
        let right = (x + w).min(self.width);
        let bottom = (y + h).min(self.height);
        if x >= right || y >= bottom {
            return;
        }

        self.dirty = Some(match self.dirty {
            None => (x, y, right - x, bottom - y),
            Some((dx, dy, dw, dh)) => {
                let nx = dx.min(x);
                let ny = dy.min(y);
                let nr = (dx + dw).max(right);
                let nb = (dy + dh).max(bottom);
                (nx, ny, nr - nx, nb - ny)
            }
        });
    }

    fn take(&mut self) -> Option<(u32, u32, u32, u32)> {
        let dirty = self.dirty.take();
        self.scheduled = false;
        dirty
    }
}

/// 渲染表面：像素先进离屏后备画布，再由 `requestAnimationFrame` 合成到显示画布。
///
/// 直接把 `putImageData` 打到显示画布上会让它退出 GPU 合成路径：之后每次把
/// 1920×1080 的位图缩放到 CSS 尺寸都要在 CPU 上重采样整屏，这是画面卡顿的主要来源。
/// 改成「离屏承接像素、显示画布只做 `drawImage`」后，显示画布始终由 GPU 合成，
/// 并且一帧内的多个脏区会合并成一次提交。
pub(crate) struct Canvas {
    canvas: HtmlCanvasElement,
    backing: HtmlCanvasElement,
    backing_ctx: CanvasRenderingContext2d,
    state: Rc<RefCell<Present>>,
    /// 常驻闭包，反复交给 `requestAnimationFrame` 使用；丢弃会导致回调失效。
    #[cfg(target_arch = "wasm32")]
    raf: Closure<dyn FnMut()>,
}

impl Canvas {
    pub(crate) fn new(render_canvas: HtmlCanvasElement, width: NonZeroU32, height: NonZeroU32) -> anyhow::Result<Self> {
        render_canvas.set_width(width.get());
        render_canvas.set_height(height.get());
        let ctx = context_2d(&render_canvas)?;

        let backing = create_backing_canvas(&render_canvas)?;
        backing.set_width(width.get());
        backing.set_height(height.get());
        let backing_ctx = context_2d(&backing)?;

        let state = Rc::new(RefCell::new(Present {
            dirty: None,
            scheduled: false,
            width: width.get(),
            height: height.get(),
        }));

        #[cfg(target_arch = "wasm32")]
        let raf = present_closure(ctx, backing.clone(), Rc::clone(&state));
        #[cfg(not(target_arch = "wasm32"))]
        let _ = &ctx;

        Ok(Self {
            canvas: render_canvas,
            backing,
            backing_ctx,
            state,
            #[cfg(target_arch = "wasm32")]
            raf,
        })
    }

    /// Resizes the backing store. Note: this also clears the canvas and resets 2D context state;
    /// the cached `ctx` stays valid.
    pub(crate) fn resize(&mut self, width: NonZeroU32, height: NonZeroU32) {
        self.canvas.set_width(width.get());
        self.canvas.set_height(height.get());
        self.backing.set_width(width.get());
        self.backing.set_height(height.get());

        let mut state = self.state.borrow_mut();
        state.width = width.get();
        state.height = height.get();
        // 尺寸变化会清空两张画布，旧的脏区已经没有意义；
        // 但保留 scheduled，让已排队的那一帧自己消费掉，避免多排一次空回调。
        state.dirty = None;
    }

    /// Blits a dirty region into the offscreen backing store and schedules one composite.
    ///
    /// `alpha: false` on both contexts means the framebuffer's alpha channel is ignored.
    pub(crate) fn draw(&self, buffer: &mut [u8], region: InclusiveRectangle) -> anyhow::Result<()> {
        #[cfg(target_arch = "wasm32")]
        {
            let image = ImageData::new_with_u8_clamped_array_and_sh(
                Clamped(&*buffer),
                u32::from(region.width()),
                u32::from(region.height()),
            )
            .map_err(|err| anyhow!("ImageData::new failed: {err:?}"))?;
            self.backing_ctx
                .put_image_data(&image, f64::from(region.left), f64::from(region.top))
                .map_err(|err| anyhow!("put_image_data failed: {err:?}"))?;

            let mut state = self.state.borrow_mut();
            state.mark(region);
            if !state.scheduled {
                state.scheduled = true;
                drop(state);
                self.schedule_present();
            }
            Ok(())
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&self.backing_ctx, buffer, region);
            unimplemented!("web canvas is only available on wasm32")
        }
    }

    /// Schedules one composite. Nothing happens when the tab is in the background: the next
    /// `requestAnimationFrame` after it becomes visible picks up the accumulated dirty area.
    #[cfg(target_arch = "wasm32")]
    fn schedule_present(&self) {
        let scheduled = web_sys::window()
            .map(|window| window.request_animation_frame(self.raf.as_ref().unchecked_ref()).is_ok())
            .unwrap_or(false);
        if !scheduled {
            // 没有窗口（或调用失败）时不能留下 scheduled 标记，否则下一次更新再也不会上屏。
            self.state.borrow_mut().scheduled = false;
        }
    }
}

/// 构造合成回调：取走脏区并集，从离屏画布拷到显示画布的同位置。
#[cfg(target_arch = "wasm32")]
fn present_closure(
    ctx: CanvasRenderingContext2d,
    backing: HtmlCanvasElement,
    state: Rc<RefCell<Present>>,
) -> Closure<dyn FnMut()> {
    Closure::wrap(Box::new(move || {
        let Some((x, y, width, height)) = state.borrow_mut().take() else {
            return;
        };
        let (x, y) = (f64::from(x), f64::from(y));
        let (width, height) = (f64::from(width), f64::from(height));
        let _ = ctx.draw_image_with_html_canvas_element_and_sw_and_sh_and_dx_and_dy_and_dw_and_dh(
            &backing, x, y, width, height, x, y, width, height,
        );
    }) as Box<dyn FnMut()>)
}

#[cfg(target_arch = "wasm32")]
fn create_backing_canvas(source: &HtmlCanvasElement) -> anyhow::Result<HtmlCanvasElement> {
    let document = source
        .owner_document()
        .ok_or_else(|| anyhow!("canvas has no owner document"))?;
    document
        .create_element("canvas")
        .map_err(|err| anyhow!("create_element(\"canvas\") failed: {err:?}"))?
        .dyn_into::<HtmlCanvasElement>()
        .map_err(|_| anyhow!("created element is not an HTMLCanvasElement"))
}

#[cfg(not(target_arch = "wasm32"))]
fn create_backing_canvas(source: &HtmlCanvasElement) -> anyhow::Result<HtmlCanvasElement> {
    let _ = source;
    unimplemented!("web canvas is only available on wasm32")
}

/// Acquires the canvas 2D context (wasm only; panics on other targets).
fn context_2d(canvas: &HtmlCanvasElement) -> anyhow::Result<CanvasRenderingContext2d> {
    #[cfg(target_arch = "wasm32")]
    {
        // alpha:false —— 桌面画面本身不透明，关掉 alpha 让浏览器省掉逐像素混合，
        // 也让 draw() 不必再补 alpha 通道。desynchronized —— 降低合成延迟。
        let options = js_sys::Object::new();
        let _ = js_sys::Reflect::set(
            &options,
            &wasm_bindgen::JsValue::from_str("alpha"),
            &wasm_bindgen::JsValue::FALSE,
        );
        let _ = js_sys::Reflect::set(
            &options,
            &wasm_bindgen::JsValue::from_str("desynchronized"),
            &wasm_bindgen::JsValue::TRUE,
        );
        canvas
            .get_context_with_context_options("2d", &options)
            .map_err(|err| anyhow!("get_context(\"2d\") failed: {err:?}"))?
            .ok_or_else(|| anyhow!("canvas has no 2d context"))?
            .dyn_into::<CanvasRenderingContext2d>()
            .map_err(|_| anyhow!("2d context is not a CanvasRenderingContext2d"))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = canvas;
        unimplemented!("web canvas is only available on wasm32")
    }
}
