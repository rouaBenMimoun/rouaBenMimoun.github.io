import VanillaRouter from "./router.js";
import { checkSession } from "./iam.js";

const presenters = new Map(); // To store presenters and avoid re-instantiating them

const router = new VanillaRouter({
    type: "history",
    routes: {
        "/": "app",
    }
}).listen().on("route", async e => {
    if (checkSession()) {
        console.log(e.detail.route, e.detail.url);
        // Fetch the HTML content for the route
        const mainElem = document.getElementById("mainElem");
        mainElem.innerHTML = await fetch("pages/"+e.detail.route + ".html").then(x => x.text());
        console.log(mainElem.innerHTML);
        loadAndExecuteScripts(mainElem.innerHTML);


    } else {

    }
});

const loadAndExecuteScripts = (htmlText) => {
    const tempDiv = document.createElement("div");
    tempDiv.innerHTML = htmlText;
    const scripts = tempDiv.querySelectorAll("script");

    scripts.forEach(script => {
        const newScript = document.createElement("script");
        if (script.src) {
            newScript.src = script.src;
            newScript.defer = script.defer;
            newScript.type = script.type || "text/javascript";
        } else {
            newScript.textContent = script.textContent;
        }
        console.log(newScript);
        document.body.appendChild(newScript);
    });
};