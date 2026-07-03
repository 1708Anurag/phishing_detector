"""
Small labeled sample dataset (email text -> 1 phishing / 0 legitimate).

NOTE FOR THE TEAM: this in-repo dataset exists so the project runs out of
the box without downloading anything. For the final submission you should
replace/extend this with a larger public dataset (e.g. the Nazario phishing
corpus or a Kaggle phishing-email dataset) and retrain via
`detection/train_model.py`.
"""

SAMPLES = [
    # --- Phishing examples (label 1) ---
    ("Dear Customer, your account has been suspended due to unusual activity. "
     "Click here immediately to verify your identity: http://192.168.44.12/verify", 1),
    ("URGENT: Your PayPal account will be limited. Confirm your identity now at "
     "http://paypal-secure-login.xyz/confirm or lose access permanently.", 1),
    ("Congratulations! You have won a $1000 gift card. Claim your reward now by "
     "entering your bank account and PIN number at http://freegiftcard.top/claim", 1),
    ("Dear user, we detected unauthorized login to your Apple ID. Verify your "
     "password immediately: http://apple-id-support.tk/reset", 1),
    ("Your invoice attached is overdue. Open invoice.zip immediately and enter your "
     "credit card number to avoid a late fee.", 1),
    ("Security Alert: unusual sign-in activity detected on your Microsoft account. "
     "Act now and confirm your identity at http://micros0ft-verify.click", 1),
    ("Final notice: your tax refund of $845 is pending. Submit your social security "
     "number and bank account to receive payment within 24 hours.", 1),
    ("Dear valued customer, your Netflix payment failed. Update your billing details "
     "immediately at http://netflix-billing-update.work/login", 1),
    ("Your mailbox is almost full. Click here to verify your account and increase "
     "storage: http://mail-storage-verify.gq/login", 1),
    ("We noticed unusual activity on your bank account. For your safety we have "
     "restricted access. Verify now: http://secure-bank-alert.cf/verify", 1),
    ("You have received an important document from your HR department. Enter your "
     "company login and password to view it: http://hr-portal-login.zip/doc", 1),
    ("Your package could not be delivered. Pay a small customs fee using your credit "
     "card number here: http://delivery-fee-payment.xyz", 1),
    ("Dear customer, your one time password (OTP) request failed. Re-enter your OTP "
     "and CVV at http://otp-verify-secure.top to complete verification.", 1),
    ("ATTENTION: Your email password will expire today. Click here to keep the same "
     "password: http://webmail-password-expire.click/renew", 1),
    ("Wire transfer required urgently for the pending invoice. Please send bitcoin "
     "to the address below before end of day.", 1),
    ("Dear user, your account shows unauthorized login from a new device. Confirm "
     "your identity immediately or your account will be closed within 24 hours: "
     "http://accounts-verify-support.zip", 1),
    ("You've been selected for a exclusive prize draw! Claim your reward now, act "
     "now before this limited time offer expires: http://prize-draw-claim.gq", 1),
    ("IMPORTANT: Your outlook mailbox storage exceeded quota. Verify your account "
     "now at http://outlook-quota-verify.tk/login or lose all your emails.", 1),
    ("Dear customer, we could not process your recent card payment. Update your "
     "credit card number and CVV immediately to avoid account suspension.", 1),
    ("Security alert: Someone tried to sign in to your Google account. If this "
     "wasn't you, verify your password now: http://google-account-secure.xyz", 1),

    # --- Legitimate examples (label 0) ---
    ("Hi team, just a reminder that our sprint planning meeting is scheduled for "
     "10am tomorrow in the main conference room. See you there.", 0),
    ("Hello, thank you for your order #48213. Your package has shipped and should "
     "arrive within 3-5 business days. Track it on our official website.", 0),
    ("Hey, can you send me the quarterly report when you get a chance? No rush, "
     "just need it before Friday's review.", 0),
    ("Hi Sarah, attaching the meeting notes from today's call. Let me know if I "
     "missed anything important.", 0),
    ("Your monthly statement is now available in your online banking portal. Log "
     "in through the app as usual to view the details.", 0),
    ("Reminder: your dentist appointment is confirmed for Thursday at 2:30pm. "
     "Reply to this email if you need to reschedule.", 0),
    ("Hi, thanks for signing up for our newsletter! Here are this month's top "
     "articles on web development and design.", 0),
    ("Good morning, the office will be closed on Monday for the public holiday. "
     "Regular hours resume Tuesday.", 0),
    ("Hi John, attached is the invoice for last month's consulting work. Payment "
     "is due within 30 days as per our agreement.", 0),
    ("Your flight booking is confirmed. Flight AB123 departs at 6:45am on "
     "Saturday. Check-in opens 24 hours before departure.", 0),
    ("Hello, just following up on our conversation from last week. Do you have "
     "time for a quick call this Thursday afternoon?", 0),
    ("Hi team, the new project repository has been created on GitHub. Please "
     "clone it and set up your local environment before Monday's standup.", 0),
    ("Thank you for your purchase! Your receipt is attached. If you have any "
     "questions about your order, contact our support team.", 0),
    ("Hi, I've reviewed the document you shared and left a few comments. Overall "
     "it looks great, just a couple of minor edits needed.", 0),
    ("Reminder: your library books are due back in 3 days. You can renew them "
     "online through the library website if needed.", 0),
    ("Hi everyone, please find attached the agenda for tomorrow's town hall "
     "meeting. Looking forward to seeing you all there.", 0),
    ("Your subscription renewal was successful. You will be charged $9.99 next "
     "month as usual. Thanks for being a subscriber.", 0),
    ("Hi, congratulations on completing the course! Your certificate is attached "
     "as a PDF for your records.", 0),
    ("Hey, are we still on for lunch tomorrow at noon? Let me know if the time "
     "still works for you.", 0),
    ("Hi team, the server maintenance window is scheduled for Sunday night from "
     "1am to 3am. Expect brief downtime during this period.", 0),
]
