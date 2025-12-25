import { PORT, app } from "./app"

const startServer = () => {
    try {
        app.listen(PORT, () => {
            console.log(`Server started on PORT: ${PORT}`);
        })
    } catch (error) {   
        console.log("Error while starting server: ", error);
    }
};

startServer();