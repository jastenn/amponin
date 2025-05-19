document.addEventListener("DOMContentLoaded", () => {
	const imagesInput = document.querySelector("[data-js-images-input]")
	const control = imagesInput.querySelector("[data-js-images-input-control]")
	const previewContainer = imagesInput.querySelector("[data-js-images-input-preview-container]")
	const previewTemplate = imagesInput.querySelector("#images-input-preview-item-template")
	if (!control) {
		console.error("input control is required children of images input")
	}
	control.addEventListener("change", (e) => {
		previewContainer.innerHTML = ``
		for (const file of e.target.files) {
			const previewItem = previewTemplate.content.cloneNode(true)
			const removeControl = previewItem.querySelector("[data-js-images-input-preview-remove-control]")
			const image = previewItem.querySelector("[data-js-images-input-preview-image]")
			image.src = URL.createObjectURL(file)
			previewContainer.appendChild(previewItem)

			removeControl.onclick = function () {
				const dt = new DataTransfer()
				for (const f of e.target.files) {
					if (file === f) {
						continue
					}
					dt.items.add(f)
				}
				e.target.files = dt.files
				control.dispatchEvent(new Event("change"))
			}
		}
	})
})
