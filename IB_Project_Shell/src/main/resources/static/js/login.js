// API url
var URL = "http://localhost:8080";

var signInButton;
var email;
var password;

$(document).ready(function() {
	
	signInButton = $("#log");
	email = $("#email");
	password = $("#password");
	
	login();
	})
	

function login(){
	
	signInButton.click(function(){
		
		var data = {
				"username" : email.val(),
				"password" : password.val()
		}
		
		$.ajax({
			url: URL + "/authenticate",
			type : "POST",
			contentType: "application/json",
			data: JSON.stringify(data),
			success: function(token){
				localStorage.setItem("MvsToken", token.token);
				
				location.assign("chooseAccount.html")
			}
		})
	});
}