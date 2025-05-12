class CoordinatesInput extends HTMLElement {
	static formAssociated = true
	static observedAttributes = ["value"]

	constructor() {
		super()
		this.internals = this.attachInternals();

		this.innerHTML = `
			<div data-js-map style="min-height: 10rem; height: auto;"></div>
		`

		const el = this.querySelector("[data-js-map]")
		this.map = L.map(el).setView({ lat: 14.82349398411418, lng: 120.95374484326904 }, 13)

		L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
		    maxZoom: 19,
		    attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a>'
		}).addTo(this.map);

		this.map.addEventListener("click", (e) => {
			this.setValue(e.latlng)
		})
	}

	attributeChangedCallback(name, oldValue, newValue) {
		if (name == "value") {
			const latlng = this.decodeLatLng(newValue)
			if (!oldValue) {
				this.map.setView(latlng)
			}
			this.setValue(latlng)
		}
	}

	setValue(newValue) {
		if (!this.marker) {
			this.marker = L.marker(newValue).addTo(this.map);
		} else {
			this.marker.setLatLng(newValue)
		}
		this.internals.setFormValue(this.encodeLatLng(newValue))
	}

	encodeLatLng(latlng) {
		return `${latlng.lat} ${latlng.lng}`
	}

	decodeLatLng(s) {
		const latlng = s.split(" ")
		return L.latLng(latlng)
	}
}

customElements.define("coordinates-input", CoordinatesInput)
