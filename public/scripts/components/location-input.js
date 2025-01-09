customElements.define("location-input", class extends HTMLElement {
	static formAssociated = true
	static observedAttributes = ["value"]

	constructor() {
		super()

		this._internals = this.attachInternals()

		this.style.minHeight = "10rem"
		this.style.display = "block"

		if (L == null) {
			throw new Error("L is undefined: Please include Leaflet CDN")
		}
		this.map = L.map(this).setView([14.48369, 120.89878], 13);
		L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
			maxZoom: 19,
			attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a>'
		}).addTo(this.map);


		this.map.on("click", (e) => {
			this.value = `${e.latlng.lat},${e.latlng.lng}`
		})
	}

	attributeChangedCallback(name, _, newValue) {
		if (name == "value") {
			if (newValue == "") {
				return
			}
			this.value = newValue
		}
	}

	set value(s) {
		let latLng = s.split(",");
		if (latLng.length != 2) {
			console.error("unable to set value: invalid latlng string")
			return
		}

		latLng[0] = parseFloat(latLng[0]);
		latLng[1] = parseFloat(latLng[1]);
		if (isNaN(latLng[0]) || isNaN(latLng[1])) {
			throw new Error("unable to set value: must be a pair or floats")
		}

		if (this.marker == null) {
			this.marker = L.marker(latLng)
			this.marker.addTo(this.map)
		} else {
			this.marker.setLatLng(latLng)
		}
		this.map.setView(latLng)
		this._internals.setFormValue(s)
	}
})

