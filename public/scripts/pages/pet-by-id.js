document.addEventListener("DOMContentLoaded", () => {
	const petImagesCarouselThumbs = new Swiper("#pet-images-carousel-thumbs", {
		slidesPerView: 4,
		spaceBetween: 10,
	});

	new Swiper("#pet-images-carousel", {
		speed: 400,
		thumbs: {
			slideThumbActiveClass: "pet-images__thumbs-item--active",
			swiper: petImagesCarouselThumbs,
		},
	});
})
