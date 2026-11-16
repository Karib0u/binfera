import { useMedia } from "./panels";

/** Phones and portrait tablets get the app-style layout: below this the side panels leave no room for code. */
export const useMobile = () => useMedia("(max-width: 900px)");
