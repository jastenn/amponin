document.addEventListener("DOMContentLoaded", () => {
	const fileInputs = document.querySelectorAll("input[type=file][data-js-file-preview]")
	for (fileInput of fileInputs) {
		const previewElement = document.getElementById(fileInput.getAttribute("data-js-file-preview"))
		if (previewElement == null) {
			console.error("preview element not found", { file_input: fileInput })
			return
		}

		if (previewElement.nodeName != "IMG") { 
			console.error(
				"preview element is not an image",
				{ file_input: fileInput, preview_element: previewElement},
			)
			return
		}

		fileInput.addEventListener("change", (e) => {
			const url = URL.createObjectURL(e.target.files[0])
			previewElement.src = url
		})
	}
})
