// Search Live Filtering (for store.html)
document.addEventListener("DOMContentLoaded", function(){
    const searchInput = document.getElementById("search");
    if(searchInput){
        searchInput.addEventListener("input", function(){
            const query = this.value.toLowerCase();
            const products = document.querySelectorAll(".product-card");
            products.forEach(p=>{
                const name = p.querySelector("h3").textContent.toLowerCase();
                if(name.includes(query)){
                    p.style.display = "block";
                } else {
                    p.style.display = "none";
                }
            });
        });
    }
});