/* Menu visual: não altera sessões, dados ou chamadas da API. */
(()=>{'use strict';
const sidebar=document.querySelector('.sidebar');if(!sidebar)return;
const button=sidebar.querySelector('.sidebar-toggle');
const key='ct_sidebar_expanded';
const mobile=()=>window.matchMedia('(max-width:720px)').matches;
function apply(expanded){sidebar.classList.toggle('is-expanded',expanded&&!mobile());if(button){button.setAttribute('aria-expanded',String(expanded&&!mobile()));button.setAttribute('aria-label',expanded?'Recolher menu':'Expandir menu');button.title=expanded?'Recolher menu':'Expandir menu';}}
let expanded=true;try{const saved=localStorage.getItem(key);expanded=saved===null?true:saved==='true';}catch(e){}
apply(expanded);
button?.addEventListener('click',()=>{expanded=!expanded;apply(expanded);try{localStorage.setItem(key,String(expanded));}catch(e){}});
window.addEventListener('resize',()=>apply(expanded));
sidebar.querySelectorAll('.sidebar-link').forEach(link=>{if(link.classList.contains('active'))link.setAttribute('aria-current','page');});
})();
