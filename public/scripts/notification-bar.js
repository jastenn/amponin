document.addEventListener("DOMContentLoaded", () => {
	const $notificationBars = document.querySelectorAll("[data-js-notification-bar]")

	for (const $notificationBar of $notificationBars) {
		const $control = $notificationBar.querySelector("[data-js-notification-bar-control]")
		if (!$control) {
			return
		}

		$control.addEventListener("click", () => {
			$notificationBar.remove()
		})
	}
})
