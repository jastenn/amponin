window.addEventListener("DOMContentLoaded", () => {
	const menus = document.querySelectorAll("[data-js-menu]")

	for (let menu of menus) {
		const targetActiveClass = menu.getAttribute("data-js-target-active-class")
		const targetSelector = menu.getAttribute("data-js-target")
		if (!targetSelector) {
			console.error("data-js-menu-target attribute is required", { element: menu })
		}

		const target = document.querySelector(targetSelector)
		if (!target) {
			console.error("target element not found", { menuElement: menu })
		}

		menu.addEventListener("click", () => {
			target.classList.toggle(targetActiveClass)
			
			//TODO: control aria attributes
		})
	}
})
