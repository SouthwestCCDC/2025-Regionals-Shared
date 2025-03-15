# Based on https://github.com/carlospolop/PEASS-ng/blob/master/parsers/json2html.py
# TODO: create the script
function parse_dict {
    param (
        [System.Object] $json_dict
    )

    # Parse the given dict from the given json adding it to the HTML file
    $dict_text = ""
    foreach($obj in $json_dict.psobject.properties){
        $key = $obj.Name
        $value = $obj.Value
        $n = Get-Random -Minimum 1 -Maximum 999999
        $infos = [System.Collections.ArrayList]@()

        foreach($info in $value."infos"){
            if(([string]$info).StartsWith('http')){
                $infos.Add("<a href=$info>$info</a><br>`n")
            }
            else{
                $infos.Add([string]$info + "<br>`n")
            }
        }

        $dict_text += "`t`t<button type=""button"" class=""btn1"" data-toggle=""collapse"" data-target=""#lines$n"">$key</button><br>`n"
        $dict_text += "<i>" + ($infos -join "") + "</i>"
        $dict_text += "<div id=""lines$n"" class=""collapse1 collapse in"">`n"

        if($value."lines"){
            $dict_text += $("`n" + (parse_list $value."lines") + "`n")
        }

        if($value."sections"){
            $dict_text += (parse_dict $value."sections")
        }
    }

    return $dict_text
    
}

function parse_list {
    param (
        [System.Object] $json_list
    )
    # Parse the given list from the given json adding it to the HTML file

    $color_text=""
    $color_class=""

    $special_char = [String][char]0x2550
    $special_char_2 = [String][char]0x2563

    foreach($i in $json_list){
        if(-not $i."clean_text".Contains($special_char*3)){
            if($i."clean_text"){
                $color_text += "<div class = `""
                $text = [string]$i."clean_text"
                foreach($color_obj in $i."colors".psobject.properties){
                    $color_words = $color_obj.Value
                    $color = $color_obj.name
                    if($color -eq "BLUE"){
                        $style = "#0000FF"
                        $color_class = "blue"
                    }
                    if($color -eq "LIGHT_GREY"){
                        $style = "#adadad"
                        $color_class = "light_grey"
                    }
                    if($color -eq "REDYELLOW"){
                        $style = "#FF0000; background-color: #FFFF00"
                        $color_class = "redyellow"
                    }
                    if($color -eq "RED"){
                        $style = "#FF0000"
                        $color_class = "red"
                    }
                    if($color -eq "GREEN"){
                        $style = "#008000"
                        $color_class = "green"
                    }
                    if($color -eq "MAGENTA"){
                        $style = "#FF00FF"
                        $color_class = "magenta"
                    }
                    if($color -eq "YELLOW"){
                        $style = "#FFFF00"
                        $color_class = "yellow"
                    }
                    if($color -eq "DARKGREY"){
                        $style = "#A9A9A9"
                        $color_class = "darkgrey"
                    }
                    if($color -eq "CYAN"){
                        $style = "#00FFFF"
                        $color_class = "cyan"
                    }
                    foreach($replacement in $color_words){
                        $text=$text.Replace($replacement, " <b style=`"color:" + $style + "`">" + $replacement + "</b>")
                        if($text.Contains($special_char_2)){
                            $text = $text.Replace($special_char_2, "<li>")
                            $text += "</li>"
                        }
                    }
                    $color_text += "" + $color_class + " "
                }
                $color_text += "no_color`" >" + $text + "<br></div>`n"
            }

        }
    }
    return $color_text + "`t`t`t</div>`n"
}

function parse_json {
    param (
        $json_data
    )

    $body = ""
    $i = 1

    foreach($obj in $json_data.psobject.properties){
        $key = $obj.Name
        $value = $obj.Value
        $body += " `t`t<button type=""button"" class=""btn"" data-toggle=""collapse"" data-target=""#demo"" " + [string]$i + "`"><b>" + $key + " </button></b><br>`n <div id=""demo"" " + [string]$i + "`" class=""collapse"">`n"
        $i += 1
        foreach($obj_2 in $value.psobject.properties) {
            $key1 = $obj_2.Name
            $value1 = $obj_2.Value
            if($value1.GetType().BaseType -eq [System.Object]){
                $body += parse_dict $value1
            }

        }

        $body += "`t`t`t</div>`n"
    }

    return $body 
}

$HTML_HEADER = @"
<html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" charset="UTF-8">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
        <style>
            .btn {
            border-radius: 2px;
            border: 2px solid #000000;
            background-color: #33adff;
            color: white;
            padding: 8px 16px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 8px 40%;
            transition-duration: 0.4s;
            cursor: pointer;
            border-radius: 8px;
            
            }

            .btn1 {
            border-radius: 2px;
            border: 2px solid #000000;
            background-color: #33adff;
            color: white;
            padding: 4px 8px;
            text-align: center;
            text-decoration: none;
            display: inline-block;
            font-size: 16px;
            margin: 8px 4px;
            transition-duration: 0.4s;
            cursor: pointer;
            border-radius: 8px;
            
            }

            .btn:hover {
                box-shadow: 0 12px 16px 0 rgba(0,0,0,0.24), 0 17px 50px 0 rgba(0,0,0,0.19);
                background-color: #6fd1ff;
                color: white;
            }

            .btn1:hover {
                box-shadow: 0 12px 16px 0 rgba(0,0,0,0.24), 0 17px 50px 0 rgba(0,0,0,0.19);
                background-color: #6fd1ff;
                color: white;
            }

            .collapse {
                margin: 15px 8%;
                padding: 8px 8px;
                border: 1px solid #000000;
                width: 80%;
                background-color: #adebad;
            }
            
            .collapse1 {
                margin: 15px 8%;
                padding: 8px 8px;
                border: 2px solid #000000;
                width: 80%;
                background-color: #91ff96;
            }

            .peass_image{
                display: block;
				margin-left:30%;
                margin-right:30%;
				width: 30%;
            }
            
            .div_redyellow{
                
                margin-left:35%;
                margin-right:35%; 
            }

            .btn_redyellow{
                background-color: #FFFF00;
                padding: 4px 8px;
                border-radius: 8px;
                color:#FF0000;
                border:2px solid #FF0000;
            }

            .btn_redyellow:hover {
                box-shadow: 0 12px 16px 0 rgba(0,0,0,0.24), 0 17px 50px 0 rgba(0,0,0,0.19);
                background-color: #FF0000;
                border: 2px solid #FF0000;
                color: #FFFF00;
                transition-duration: 0.4s;
            }
            
            .btn_red_redyellow{
                background: #FFFF00;
                padding: 4px 8px;
                border-radius: 8px;
                color:#FF0000;
                border:2px solid #FF0000;
            }

            .btn_red_redyellow:hover {
                box-shadow: 0 12px 16px 0 rgba(0,0,0,0.24), 0 17px 50px 0 rgba(0,0,0,0.19);
                background: #FF0000;
                border: 2px solid #FF0000;
                color: #FFFF00;
                transition-duration: 0.4s;
            }
            
            .btn_restore, .btn_show_all, .btn_hide_all{
                margin-top: 3px;
                border-radius: 2px;
                padding: 4px 8px;
                background-color: #00ff15;
                border: 2px solid #06660e;
                border-radius: 8px;
            }

            .btn_restore:hover, .btn_show_all:hover, .btn_hide_all:hover{
                box-shadow: 0 12px 16px 0 rgba(0,0,0,0.24), 0 17px 50px 0 rgba(0,0,0,0.19);
                border: 2px solid #00ff15;
                color: #00ff15;
                transition-duration: 0.4s;
                background: rgb(300, 300, 300);
            }

            body{
                background-color: #91ff96
            }

        </style>
    </head>

"@

$HTML_END = @"
<script>

            `$(document).ready(() => {
                `$('.btn_show_all').click(function() {
                    show_all();
                });
                `$('.btn_hide_all').click(function() {
                    hide_all();
                });
                `$('.btn_redyellow').click(function() {
                    only_redyellow();
                });
                `$('.btn_red_redyellow').click(function() {
                    only_red_redyellow();
                });
                `$('.btn_restore').click(function() {
                    restore();
                });
            });
            function show_all(){
                `$('.collapse').show();
            }
            function hide_all(){
                `$('.collapse').hide();
            }
            function only_redyellow(){
                `$('.red').hide();
                `$('.light_grey').hide();
                `$('.blue').hide();
                `$('.green').hide();
                `$('.magenta').hide();
                `$('.yellow').hide();
                `$('.darkgrey').hide();
                `$('.cyan').hide();
                `$('.no_color').hide();
                `$('.redyellow').show();
            }

            function only_red_redyellow(){

                `$('.light_grey').hide();
                `$('.blue').hide();
                `$('.green').hide();
                `$('.magenta').hide();
                `$('.yellow').hide();
                `$('.darkgrey').hide();
                `$('.cyan').hide();
                `$('.no_color').hide();
                `$('.red').show();
                `$('.redyellow').show();
            }

            function restore(){

                `$('.light_grey').show();
                `$('.blue').show();
                `$('.green').show();
                `$('.magenta').show();
                `$('.yellow').show();
                `$('.darkgrey').show();
                `$('.cyan').show();
                `$('.no_color').show();
                `$('.red').show();
                `$('.redyellow').show();
            }
        </script>
    </body>
</html>
"@

$HTML_INIT_BODY = @"
<body>
        <div class = "div_redyellow">
            <button type="button" class="btn_redyellow"> Only RedYellow </button>
            <button type="button" class="btn_red_redyellow"> Only Red + RedYellow </button><br>
            <button type="button" class="btn_restore"> All Colors </button>
            <button type="button" class="btn_show_all"> Show All </button>
            <button type="button" class="btn_hide_all"> Hide All </button>
        </div>
"@

$body = @"
<body>
	<div class = "div_redyellow">
            <button type="button" class="btn_redyellow"> Only RedYellow </button>
            <button type="button" class="btn_red_redyellow"> Only Red + RedYellow </button><br>
            <button type="button" class="btn_restore"> All Colors </button>
            <button type="button" class="btn_show_all"> Show All </button>
            <button type="button" class="btn_hide_all"> Hide All </button>
        </div>
"@

function json2html {
    $json_data = Get-Content $JSON_PATH -Raw | ConvertFrom-Json
    $html = $HTML_HEADER
    $html += $HTML_INIT_BODY
    $html += parse_json $json_data
    $html += $HTML_END

    $html | Out-File $HTML_PATH
}
