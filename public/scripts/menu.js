window.addEventListener("DOMContentLoaded", () => {
	const menus = document.querySelectorAll("[data-js-menu]")

	for (let menu of menus) {
		const targetActiveClass = menu.getAttribute("data-js-active-class")
		const control = menu.querySelector("[data-js-control]")
		if (!control) {
			console.warn("menu control not found.")
			return
		}

		control.addEventListener("click", () => {
			menu.classList.toggle(targetActiveClass)
			
			//TODO: control aria attributes
		})
	}
})
