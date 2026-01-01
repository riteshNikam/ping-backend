import nodemailer from "nodemailer";
import { SMPT_HOST, SMPT_PORT, SMPT_USER, SMPT_PASS } from "../env";

interface EmailOptions {
    email: string;
    subject: string;
    message: string;
}

const sendEmail = async (options: EmailOptions): Promise<void> => {
    // Create a transporter using SMTP (can be configured as per email service) 

    // Looking to send emails in production? Check out our Email API/SMTP product!
    const transporter = nodemailer.createTransport({
        host: SMPT_HOST,
        port: SMPT_PORT,
        auth: {
            user: SMPT_USER,
            pass: SMPT_PASS
        }
    });

    // Define the email details
    const mailOptions = {
        from: '"Ping App" <noreply@ping.com>', // sender address
        to: options.email, // receiver address
        subject: options.subject, // Subject line
        html: options.message, // plain text body
    };

    await transporter.sendMail(mailOptions);

}

export default sendEmail;