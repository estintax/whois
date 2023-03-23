/*
    Copyright (c) 2023 Maksim Pinigin
*/

const queryDomain = () => {
    const val = $("#query").val();
    if(val === "") {
        $("#result").html("Please, enter valid domain name");
        return;
    }

    $("#result").html("Please wait...");
    $.ajax({
        method: "POST",
        url: "./api/whoisQuery.php",
        data: {
            domain: val
        },
        success: (data) => {
            switch(data) {
                case "badargs", "bad_domain":
                    $("#result").html("Please, enter a valid domain name");
                    break;
                case "root_connection_error":
                    $("#result").html("Error connecting to IANA whois server");
                    break;
                case "bad_tld":
                    $("#result").html("This TLD doesn't exists!");
                    break;
                case "tld_connection_error":
                    $("#result").html("Error connecting to TLD whois server");
                    break;
                default:
                    $("#result").html(data.replaceAll("\n", "<br>").replaceAll("@", "(аt)"));
                    $("#query").val("");
            }
        }
    });
};

$("#search-btn").click(queryDomain);
$("#query").keypress((event) => {
    if(event.key === "Enter") {
        event.preventDefault();
        queryDomain();
    }
});
