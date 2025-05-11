document.addEventListener("DOMContentLoaded", () => {
	const userMenu = document.getElementById("user-menu")
	const button = document.getElementById("user-menu-button")
	const items = document.getElementById("user-menu-items")
	const activeClass = userMenu.getAttribute("data-js-active-class") || "active"

	button.addEventListener("click", () => {
		userMenu.classList.toggle(activeClass)
	})
})
