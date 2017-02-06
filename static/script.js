'use strict';

let links = document.querySelectorAll(".links a");
links.forEach(function(link){
  link.addEventListener('click', function() {
    if (!this.classList.contains("checked")) {
      for (var i = 0; i < links.length; i++) {
        links[i].classList.remove("checked")
      }
      this.classList.add("checked");
    }
  });
});
