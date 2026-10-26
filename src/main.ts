import "./style.css";
import { mount } from "./ui/app";

const root = document.querySelector<HTMLElement>("#main");
if (!root) throw new Error("missing #main");
mount(root);
