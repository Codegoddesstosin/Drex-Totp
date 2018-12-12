function generateCode() {
    /**Replace this function block with logic for retrieving the generated code from the server */
    let generateCode = document.querySelector('.generated-code');
    $.ajax({
        type: "GET",
        url: "api/otp/generateotp",
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        data: {},
        success: function (res) {
            if (res !== "") {
                generateCode.innerHTML = res;
            } else {
                alert("System is currently unable to generate otp please try again.")
            }
        },
        error: function () {
            alert("System is currently unable to generate otp please try again.")
        }
    });
}

function validateCode() {
    /**Replace this function block with logic for validating the token. You should replace the "validated-code-status" with the result of your validation */
    let otpCode = $(".token-input").val();
    let validatedCodeStatus = document.querySelector(".validated-code-status");
    let status = ["The code you supplied is true", "The code you supplied is not correct"];
    $.ajax({
        type: "POST",
        url: "api/otp/verifyotp",
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        data: JSON.stringify({ OtpCode: otpCode }),
        success: function (res) {
            validatedCodeStatus.innerHTML = res;
        },
        error: function () {
            alert("System is currently unable to verify otp please try again.")
        }
    });
}