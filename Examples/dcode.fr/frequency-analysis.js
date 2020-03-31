if (top != self) top.location = self.location;
window.google_analytics_uacct = "UA-647045-2";
window.last_query_start = Date.now();
window.last_query_end = Date.now();
$(function () { // jQuery
    window.h1_results_offset = parseInt($("h1").offset().top);
    deactivate_forms();
    add_jquery_functions();
    activate_float_left();
    activate_share();
    activate_gprd();
    activate_tool_search();
    activate_contact();
    activate_support();
    activate_up_button();
    activate_keywords();
    activate_form_math();
    activate_form_joker();
    activate_form_textarea_icons();
    activate_form_radioinput();
    activate_right_part_hide();
    activate_edit_qa();
    activate_form_buttons();
    load_form_previous_input();
    $('.pointer').each(function () {
        $(this).css('cursor', 'pointer');
    });
    // MOBILE APP
    $('#mobile_app').click(function () {
        $('#mobile_app_dialog').load('/include/static/mobile_app.' + window.dCode.lang + '.html', function () {
            $('#mobile_app_dialog').dialog({
                autoOpen: false,
                modal: true,
                title: $('#mobile_app').text()
            }).dialog('open');
        });
    });
    // All content buttons
    $('#center form[id] button').click(function () {
        var delay = (Date.now() - window.last_query_start < 1000 || Date.now() - window.last_query_end < 1000);
        window.last_query_start = Date.now();
        $('html, body').animate({
            scrollTop: window.h1_results_offset
        }, 750);
        $('#title_left').hide();
        $('#overview').hide();
        $('#search_results').empty();
        $('#results').html($('<img>', {
            'src': '/images/loading.gif'
        }));
        if (delay) {
            var thatbutton = $(this);
            if (window.floodTimeout !== undefined) clearTimeout(window.floodTimeout);
            window.floodTimeout = setTimeout(function () {
                thatbutton.click();
            }, 3000);
            return;
        }
        var form_id = $(this).closest('form').attr('id');
        var parameters = $(this).attr('post').split(',');
        var post = generate_post_data(form_id, parameters);
        save_in_local_storage(form_id, post);
        try {
            $.ajax({
                type: "POST",
                url: 'api/',
                data: post,
                retryLimit: 1,
                dataType: 'json',
                success: function (data) {
                    $('#results').empty().hide();
                    if (data.fatalerror) {
                        send_message('FatalError', print_r(post), true);
                    }
                    if (data.caption) {
                        $('#results').append($('<div>').addClass('caption').html(data.caption));
                    }
                    if (data.note) {
                        $('#results').append($('<div class="notice">').html(data.note));
                    }
                    if (data.error) {
                        var label = '';
                        if (data.error.parameter) {
                            var form_item = $('#' + form_id + ' [name=' + data.error.parameter + ']');
                            form_item.addClass('error');
                            label = $('#' + form_id + ' [for=' + form_item.attr('id') + ']').html();
                            if (label === undefined) label = $('#' + form_item.attr('aria-labelledby')).text();
                            if (label === undefined) label = data.error.parameter;
                        }
                        $('#results').append($('<p class="error">').html(label + '<br>' + data.error.message));
                    }
                    var div = $('<div>');
                    if (data.results && typeof data.results !== "string" && typeof data.results !== "number") {
                        var table = '';
                        if (data.multirows) table = tablen_html(data.results, false, data.total);
                        else table = table_html(data.results, false, data.total);
                        div.html(table);
                    } else {
                        div.addClass('result').html(data.results);
                    }
                    $('#results').append(div);
                    if (data.time) {
                        $('#results_title').attr('title', data.time);
                        if (parseInt(data.time) > 30) {
                            send_message('Error Timeout', print_r(post) + '<br>' + data.time, true);
                        }
                    }
                    if (data.html) {
                        $('#results').append($('<div>').html(data.html));
                    }
                    $('#results').slideDown();
                    var print_logo = $('#logo').prop('outerHTML');
                    var print_title = $('#title').prop('outerHTML');
                    var print_url = $('#source').prop('outerHTML');
                    var print_res = $('#results').html();
                    var print = print_logo + print_title + print_url + print_res;
                    var b64print = window.btoa(unescape(encodeURIComponent(print)));
                    var b64json = window.btoa(unescape(encodeURIComponent(JSON.stringify(data.results))));
                    $('#results_icons').html('<form action="/api/export/" method="post" target="_blank"><button class="button" type="button" title="copy" name="copy"><span class="ui-icon ui-icon-copy"></span></button><button class="button" type="button" title="auto-format" name="formatter"><span class="ui-icon ui-icon-script"></span></button><button class="button" type="submit" title="print" name="print" value="' + b64print + '"><span class="ui-icon ui-icon-print"></span></button><button class="button" type="submit" title="download" name="download" value="' + b64json + '"><span class="ui-icon ui-icon-arrowthickstop-1-s"></span></button><button class="button" type="button" title="close" name="close"><span class="ui-icon ui-icon-close"></span></button></form>');
                    $('button[name=copy]').click(function () {
                        var aux = document.createElement("div");
                        var res_div = document.getElementById('results');
                        aux.setAttribute("contentEditable", true);
                        aux.innerHTML = res_div.innerHTML;
                        aux.setAttribute("onfocus", "document.execCommand('selectAll',false,null)");
                        res_div.insertBefore(aux, res_div.firstChild);
                        aux.focus();
                        document.execCommand("copy");
                        res_div.removeChild(aux);
                    });
                    $('button[name=close]').click(function () {
                        $('#results').slideToggle();
                    });
                    $('button[name=formatter]').click(function () {
                        if ($('#results span.formatted_number').length) {
                            $('#results span.formatted_number').each(function () {
                                formatted_number = $(this).text().replace(/ /g, '');
                                $(this).html(formatted_number);
                                $(this).contents().unwrap(".formatted_number");
                            });
                            return;
                        }
                        var numbers_nodes = $('#results *').contents().filter(function () {
                            return (this.nodeType == 3) && this.nodeValue.match(/^\-?[0-9]+\.?[0-9]*$/);
                        });
                        $(numbers_nodes).each(function () {
                            $(this).wrap('<span class="formatted_number"></span>');
                        });
                        $('#results span.formatted_number').each(function () {
                            var formatted_number = $(this).text().replace(/^(\-?[0-9]+)(\.?)([0-9]*)$/g, function (fullMatch, $1, $2, $3) {
                                var integer_part = $1.replace(/\B(?=(\d{3})+(?!\d))/g, " ");
                                if ($3 === '') return integer_part;
                                var decimal_part = $3.match(/\d{1,3}/g).join(' ');
                                return integer_part + '.' + decimal_part;
                            });
                            $(this).html(formatted_number);
                        });
                    });
                    if (data.display) {
                        $('#results .result').click(function () {
                            var result_text = joli($(this).html());
                            if (result_text.replace(/[^a-z]/gi, '').length < 2) return;
                            $(this).qtip({
                                content: {
                                    text: qtip_text(result_text, data.display)
                                },
                                position: {
                                    my: 'left top',
                                    at: 'right middle'
                                },
                                hide: {
                                    fixed: true,
                                    delay: 1000
                                },
                                style: {
                                    tip: {
                                        corner: 'left top'
                                    }
                                }
                            });
                            $(this).qtip("show");
                            return;
                        });
                    } // !display
                    if (data.math && MathJax !== undefined) {
                        MathJax.Hub.Queue(['Typeset', MathJax.Hub, 'results']);
                    }
                    // wordwrap
                    var table_size = parseInt($('#results table').first().css('width'));
                    var nb_columns = $('#results table').find("tr:first td").length;
                    var nb_rows = $('#results table').find("tr").length;
                    if (table_size < 280 && nb_rows <= 50) {
                        $('#results table tbody').css('font-size', '1.2em');
                    }
                    if (table_size < 180) {
                        $('#results table').css('min-width', Math.round(table_size * 1.5) + 'px');
                    }
                    if (table_size >= 320) {
                        $('#results table tr:first th').each(function (index, value) {
                            var col_size = parseInt($(this).css('width'), 10);
                            if (col_size / table_size < 0.1) $(this).css('width', '10%');
                            else if (col_size / table_size < 0.25) $(this).css('width', '25%');
                        });
                        $('#results table').first().css('width', '320px');
                        $('#results table').css('table-layout', 'fixed');
                    }
                    window.last_query_end = Date.now();
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    var error_number = jqXHR.status;
                    $('#results').html('ERROR ' + error_number);
                    if (error_number == 429) return;
                    if (error_number == 500 || error_number == 200) this.retryLimit = 0;
                    if (this.retryLimit-- > 0) {
                        $('#results').html($('<img>', {
                            'src': '/images/loading.gif'
                        }));
                        that = this;
                        if (window.floodTimeout !== undefined) clearTimeout(window.floodTimeout);
                        window.floodTimeout = setTimeout(function () {
                            $.ajax(that);
                        }, 1000);
                        return;
                    }
                    if ((error_number == 503 || error_number == 504) && Math.round(Math.random())) return;
                    $('#results').append(jqXHR.responseText);
                    var bug = {};
                    bug['DATE'] = new Date().toJSON();
                    bug['PAGE'] = window.location.href;
                    bug['POST'] = post;
                    bug['TIME'] = (Date.now() - window.last_query_start) / 1000;
                    bug['ERROR'] = errorThrown;
                    bug['TEXTSTATUS'] = textStatus;
                    bug['XHR'] = jqXHR;
                    send_message(textStatus + ' ' + error_number, print_r(bug), true);
                }
            });
        } catch (e) {
            send_message(window.dCode.tool.title, "ERROR:" + e.message, true);
        }
        $('#results_title').effect("pulsate", {
            'times': 4
        }, 3000);
        window.last_query_end = Date.now();
        return false;
    });
});

function generate_post_data(form_id, parameters) {
    var post = {
        'tool': window.dCode.tool.address
    };
    for (var i in parameters) {
        var p = parameters[i];
        var value = undefined;
        if (p == 'autorefresh') {
            value = (new Date()).getTime();
            post[p] = value;
            continue;
        }
        if (p.indexOf('=') != -1) {
            value = p.substring(p.indexOf('=') + 1);
            p = p.substring(0, p.indexOf('='));
            post[p] = value;
            continue;
        }
        var input_array = $('#' + form_id + ' [name^="' + p + '[]"]');
        if (input_array.length) {
            value = [];
            input_array.each(function () {
                value.push($(this).val());
            });
            post[p] = value;
            continue;
        }
        var input = $('#' + form_id + ' [name="' + p + '"]');
        input.removeClass('error');
        if (input.is(':checkbox')) value = $('#' + form_id + ' [name="' + p + '"]').is(':checked');
        else if (input.is(':radio')) value = $('#' + form_id + ' [name="' + p + '"]:checked').val();
        else if (input.is(':file')) value = $('#' + form_id + '_' + p + '_file').val();
        if (value === undefined) value = input.val();
        if (value === undefined) value = true;
        post[p] = value;
    }
    return post;
}

function deactivate_forms() {
    $('form').each(function () {
        if ($(this).attr('encoding') != 'multipart/form-data') {
            $(this).submit(function () {
                return false;
            });
        }
    });
}

function add_jquery_functions() {
    jQuery.fn.getCursorStart = function () {
        var input = this.get(0);
        if (!input) return;
        if ('selectionStart' in input) {
            return input.selectionStart;
        } else if (document.selection) {
            input.focus();
            var sel = document.selection.createRange();
            var selLen = document.selection.createRange().text.length;
            sel.moveStart('character', -input.value.length);
            return sel.text.length - selLen;
        }
    };
    jQuery.fn.getCursorEnd = function () {
        var input = this.get(0);
        if (!input) return;
        if ('selectionEnd' in input) {
            return input.selectionEnd;
        } else if (document.selection) {
            input.focus();
            var sel = document.selection.createRange();
            var selLen = document.selection.createRange().text.length;
            sel.moveStart('character', -input.value.length);
            return sel.text.length;
        }
    };
    jQuery.event.special.click = {
        setup: function () {
            $(this).css('cursor', 'pointer');
            return false;
        }
    };
}

function activate_float_left() {
    $('#left').ready(function () {
        var width = $('#left').width();
        var float_div = $('#float_left');
        $(window).scroll(function () {
            var results_height = $('#results').outerHeight();
            var results_offset = $('#results').offset().top;
            if ($(window).scrollTop() >= (results_height + results_offset)) {
                float_div.css({
                    'position': 'fixed',
                    'top': '10px',
                    'width': width
                });
            } else {
                float_div.css({
                    'position': 'static',
                    'top': 'auto',
                    'width': 'inherit'
                });
            }
        });
    });
}

function activate_share() {
    $('#share').click(function () {
        if (navigator.share) {
            navigator.share({
                title: window.dCode.tool.title,
                text: ':)',
                url: window.dCode.tool.url
            });
        }
        if ($('#share_buttons').length) return;
        var row = function (name, content) {
            return "<div>" + name + ":<br/>" + content + "</div>";
        }
        var facebook_link = function (url) {
            return "<div id='fb-root'></div><div class='fb-like' data-href='" + url + "' data-width='' data-layout='button_count' data-action='like' data-show-faces='false' data-share='true'></div>";
        };
        var twitter_link = function (url) {
            return "<a href='https://twitter.com/share' class='twitter-share-button' data-url='" + url + "' data-via='dCode_fr' data-lang='" + window.dCode.lang + "' data-size='large' data-hashtags='dcode'>Tweet</a>";
        }
        var linkedin_link = function (url) {
            return "<script src='//platform.linkedin.com/in.js'>lang: " + window.dCode.lang + "</script><script type='IN/Share' data-url='" + url + "' data-counter='right'></script>";
        }
        var reddit_link = function (url) {
            return "<a href='//www.reddit.com/submit?url=" + encodeURI(url) + "' target='_blank'><img src='https://upload.wikimedia.org/wikipedia/sco/thumb/8/82/Reddit_logo_and_wordmark.svg/80px-Reddit_logo_and_wordmark.svg.png' alt='Reddit'></a>";
        }
        var email_link = function (url) {
            return "<a href='mailto:?subject=" + encodeURI(url) + "&amp;body=" + encodeURI(url) + "' target='_blank'><span class='ui-icon ui-icon-mail-closed'></span> e-Mail</a>";
        }
        var html = "<div><strong>" + $("#share").prev().text() + " " + window.dCode.tool.title + "</strong><br/><em>" + window.dCode.tool.url + "</em></div>";
        html += row('Facebook', facebook_link(window.dCode.tool.url));
        html += row('Twitter', twitter_link(window.dCode.tool.url));
        html += row('LinkedIn', linkedin_link(window.dCode.tool.url));
        html += row('Reddit', reddit_link(window.dCode.tool.url));
        html += row('e-Mail', email_link(window.dCode.tool.url));
        html += "<script>(function(d, s, id) { var js, fjs = d.getElementsByTagName(s)[0]; if (d.getElementById(id)) return; js = d.createElement(s); js.id = id; js.src = '//connect.facebook.net/fr_FR/sdk.js#xfbml=1&version=v2.0'; fjs.parentNode.insertBefore(js, fjs); }(document, 'script', 'facebook-jssdk'));</script>"; // facebook
        html += "<script>!function(d,s,id){var js,fjs=d.getElementsByTagName(s)[0],p=/^http:/.test(d.location)?'http':'https';if(!d.getElementById(id)){js=d.createElement(s);js.id=id;js.src=p+'://platform.twitter.com/widgets.js';fjs.parentNode.insertBefore(js,fjs);}}(document, 'script', 'twitter-wjs');</script>"; // Twitter
        try {
            FB.XFBML.parse();
        } catch (ex) {}
        var div = $('<div>').attr('id', 'share_buttons').html(html);
        $(this).after(div);
    });
}

function activate_gprd() {
    var cookie_value = '',
        my_cookie, my_cookies = document.cookie.split('; ');
    for (var i = 0; i < my_cookies.length; i++) {
        my_cookie = my_cookies[i].split('=');
        if (my_cookie[0] == 'cookies_ok') {
            cookies_ok();
        }
    }
}

function cookies_ok() {
    $('#cookie-bar').fadeOut();
    var expireDate = new Date();
    expireDate.setTime(expireDate.getTime() + (13 * 30 * 86400 * 1000));
    var cookieEntry = 'cookies_ok=1; expires=' + expireDate.toGMTString() + '; path=/';
    document.cookie = cookieEntry;
}

function activate_tool_search() {
    $('#search input').keyup(function () {
        if (window.search_timeout !== undefined) clearTimeout(window.search_timeout);
        window.search_timeout = setTimeout(function () {
            var search_query = $('#search input').val();
            var query_keywords = search_query.replace(/[^a-z0-9]/gi, ' ').trim().split(' ');
            if (query_keywords.length) {
                $.post('search.php', {
                    'q': search_query
                }, function (data) {
                    $('#search_results').empty();
                    if (data.caption) {
                        $('#search_results').append($('<div>').addClass('caption').html(data.caption));
                    }
                    var ul = $('<ul>');
                    $.each(data.results, function (address, result) {
                        var li = $('<li>');
                        var a = $('<a>', {
                            'href': address,
                            'title': result.overview
                        }).html(result.title);
                        var span = $('<span>');
                        var matches = [];
                        $.each(result.matches, function (i, m) {
                            var regexp = new RegExp('(' + query_keywords.join('|') + ')', 'gi');
                            matches.push(m.toString().replace(regexp, '<u>$1</u>'));
                        });
                        span.html(' (' + matches.join(', ') + ')');
                        li.append(a);
                        li.append(span);
                        li.appendTo(ul);
                    });
                    $('#search_results').append(ul);
                    $('#search_results').append($('<div>').addClass('note').append(data.note));
                }, 'json');
            }
        }, 500);
    });
    $('#search button').click(function () {
        $('#search input').keyup();
    });
    if ('URLSearchParams' in window) {
        var urlParams = new URLSearchParams(window.location.search);
        if (urlParams.get('query')) {
            $('#search input').val(urlParams.get('query'));
            $('#search input').keyup();
        }
    }
}

function activate_contact() {
    $('.contact').click(function () {
        $('#contact').dialog({
            width: "auto",
            create: function (event, ui) {
                $(this).css("maxWidth", "600px");
            }
        });
    });
    $('#contact_form button').click(function () {
        var thank_you = $('<div>').html('<span class="ui-icon ui-icon-check"></span> Thank You !');
        var message = $('#contact_message').val();
        if (message.length > 5) send_message(window.dCode.tool.title, message);
        $('#contact').dialog("close");
        thank_you.dialog({
            open: function (event, ui) {
                setTimeout(function () {
                    thank_you.dialog('close');
                }, 2000);
            }
        });
    });
}

function activate_support() {
    $('#support').click(function () {
        $('#support_dialog').load('/include/static/support.' + window.dCode.lang + '.html', function () {
            $('#support_dialog').dialog({
                autoOpen: false,
                modal: true,
                width: 'auto'
            }).dialog('open');
        });
    });
}

function activate_up_button() {
    $('#up-button').on('click', function (e) {
        e.preventDefault();
        $('html, body').animate({
            scrollTop: 0
        }, '300');
    });
    $(window).scroll(function () {
        if ($(window).scrollTop() > 300) {
            $('#up-button').show();
        } else {
            $('#up-button').hide();
        }
    });
}

function activate_keywords() {
    $('#keywords').ready(function () {
        var keywords = $('#keywords').html().split(',');
        $('#keywords').empty();
        $.each(keywords, function (index, value) {
            var a = $('<a>', {
                'href': '#search'
            }).html(value).click(function () {
                $('#search input').val(value);
                $('#search input').keyup();
            });
            $('#keywords').append(a);
            if (index + 1 != keywords.length) $('#keywords').append(', ');
        });
    });
}

function activate_form_math() {
    $('#center .math').each(function () {
        var input = $(this);
        input.on('change keyup paste', function () {
            $(this).val($(this).val().toLowerCase());
        });
        if ($(this).parents().find('.matrix').length) return;
        var classes = input.attr('class').split(' ').join('.');
        $(this).qtip({
            content: {
                text: function (event, api) {
                    $.ajax({
                            url: '/include/static/' + classes + '.' + window.dCode.lang + '.html'
                        })
                        .then(function (content) {
                            api.set('content.text', content);
                        }, function (xhr, status, error) {
                            api.set('content.text', status + ': ' + error);
                        });
                    return '...';
                }
            },
            position: {
                my: 'top left',
                at: 'top right'
            }
        });
    });
}

function activate_form_joker() {
    $('input.joker').keyup(function () {
        var old_val = $(this).val();
        var new_val = old_val.replace(/ /g, '-');
        if (old_val != new_val) {
            $(this).val(new_val);
        }
    });
}

function activate_form_textarea_icons() {
    $('#center textarea').each(function () {
        var textarea = $(this);
        var bydefault = textarea.text();
        var delete_button = $('<button title="delete"><span class="ui-icon ui-icon-trash"></span></button>').click(function () {
            textarea.val('');
            textarea.focus();
        });
        var example_button = $('<button title="default example"><span class="ui-icon ui-icon-refresh"></span></button>').click(function () {
            textarea.val(bydefault);
        });
        textarea.qtip({
            overwrite: false,
            content: $('<span>').append(delete_button).append('<br>').append(example_button),
            position: {
                my: 'top left',
                at: 'top right'
            },
            hide: {
                fixed: true
            },
            style: {
                tip: false
            }
        });
    });
}

function activate_form_radioinput() {
    $('input[data-radio_id]').keydown(function () {
        var radio_id = $(this).data('radio_id');
        $('#' + radio_id).prop('checked', 'checked');
    });
    $('label.radioinput').click(function () {
        $(this).next('input:text').focus();
    });
}

function activate_right_part_hide() {
    var right_part_hide_button = $('<button class="button" type="button" title="hide_right_part" name="hide_right_part"><span class="ui-icon ui-icon-circlesmall-minus"></span></button>').css('float', 'right');
    $("#right .heading_bar").first().prepend(right_part_hide_button);
    $(right_part_hide_button).click(function () {
        $('#right_part_to_hide').slideToggle(1000);
    });
}

function activate_edit_qa() {
    $('div.qa').each(function () {
        var qa = this;
        var old_text = $(qa).text();
        var old_html = $(qa).html();
        var p = $('<p>').addClass('warn').append($(qa).data('edit')).insertBefore($(qa)).hide();
        var button_edit = $('<button><span class="ui-icon ui-icon-pencil"></span></button>');
        var button_ok = $('<button><span class="ui-icon ui-icon-check"></span></button>').hide();
        var button_ko = $('<button><span class="ui-icon ui-icon-close"></span></button>').hide();
        $(qa).qtip({
            content: {
                text: $('<div>').append(button_edit).append(button_ok).append('<br>').append(button_ko)
            },
            position: {
                my: 'right top',
                at: 'left top'
            },
            hide: {
                fixed: true,
                delay: 2000
            },
            style: {
                tip: {
                    corner: 'right center'
                }
            }
        });
        button_edit.click(function () {
            $(qa).attr('contenteditable', 'true');
            $(qa).focus();
            old_text = $(qa).text();
            $([button_edit, button_ok, button_ko, p]).each(function () {
                this.toggle();
            });
        });
        button_ok.click(function () {
            $(qa).attr('contenteditable', 'false');
            $('.contact').click();
            var new_text = $(qa).text();
            if (new_text != old_text) {
                var diff1 = $(new_text.split(/\s+/)).not(old_text.split(/\s+/)).get();
                var diff2 = $(old_text.split(/\s+/)).not(new_text.split(/\s+/)).get();
                $('#contact_message').val('NEW:' + new_text + "\n\nDIFF+:" + diff1 + "\n\nDIFF-:" + diff2 + "\n\nOLD:" + old_text);
            }
            $('#contact_form button').click();
            $('#contact_message').val('');
            $([button_edit, button_ok, button_ko, p]).each(function () {
                this.toggle();
            });
        });
        button_ko.click(function () {
            $(qa).attr('contenteditable', 'false');
            $(qa).html(old_html);
            $([button_edit, button_ok, button_ko, p]).each(function () {
                this.toggle();
            });
        });
    });
}

function activate_form_buttons() {
    $('#center button').each(function () {
        var margin = ($(this).parent().width() - $(this).outerWidth(true)) / 2 - 1;
        $(this).css('margin', '0.2em ' + margin + 'px');
    });
}

function load_form_previous_input() {
    if (!is_local_storage_available()) return;
    $('#center form').each(function (form_nb, form) {
        var form_id = $(form).attr('id');
        if (form_id === undefined) return;
        if (localStorage.getItem(form_id) === null) return;
        var form_data = JSON.parse(localStorage.getItem(form_id));
        $.each(form_data, function (input_name, input_value) {
            var input = $('#' + form_id + ' [name="' + input_name + '"]');
            if (input.attr('data-reload')) input.trigger('reload', input_value);
            else if (input.attr('autocomplete')) return;
            else if (input.is(':checkbox')) input.prop('checked', input_value);
            else if (input.is(':file')) return;
            else if (input.is('select')) $(input).find('option[value="' + input_value + '"]').prop('selected', true);
            else if (input.is(':radio')) $('#' + form_id + ' [name="' + input_name + '"][value="' + input_value + '"]').prop('checked', true);
            else if (input.hasClass('cryptoarea')) input.next('.crypto-wysiwyg-editor').empty();
            else input.val(input_value);
        });
    });
}
// Results
function table_html(data, nosort, total) {
    var table = $('<table>');
    var table_header = $('<thead>');
    var table_footer = $('<tfoot>');
    var table_body = $('<tbody>');
    var is_associative_array = is_associative(data);
    var datasort1 = 'int';
    var datasort2 = 'int';
    var sum = 0;
    var nb_rows = Object.keys(data).length;
    $.each(data, function (key, result) {
        if (result === null) {
            result = '';
        }
        if (!$.isNumeric(key) && !$.isNumeric(joli(key))) datasort1 = 'string';
        if (!$.isNumeric(result) && !$.isNumeric(joli(result))) datasort2 = 'string';
        else sum += parseFloat(result);
        var addclass = true;
        if (typeof result !== 'string' && typeof result !== 'number') {
            result = table_html(result, true, total);
            addclass = false;
        }
        var tr = $('<tr>');
        var td = $('<td>');
        if (is_associative_array) {
            tr.append($('<td>').html(key).addClass('result'));
            td.html(result);
            if (addclass) td.addClass('result');
            if (datasort2 == 'int') td.addClass('number');
        } else {
            td.addClass('result').html(result);
            if (!$.isNumeric(result) && !$.isNumeric(joli(result))) datasort1 = 'string'; /////////////////
            else td.addClass('number');
        }
        tr.append(td);
        tr.appendTo(table_body);
    });
    if (is_associative_array) {
        if (nb_rows > 2) table_header.append($('<tr>').append($('<th>', {
            'data-sort': datasort1
        }).html('<span class="arrow">â†‘â†“</span>')).append($('<th>', {
            'data-sort': datasort2
        }).html('<span class="arrow">â†‘â†“</span>')));
        if (nb_rows > 5) table_footer.append($('<tr>').append($('<th>', {
            'colspan': 2
        }).html('#' + nb_rows)));
        if (total && datasort2 == 'int' && nb_rows > 1) table_footer.append($('<tr>').append($('<th>').html('Total (Î£)')).append($('<th>').html(sum)));
    } else {
        if (nb_rows > 2) table_header.append($('<tr>').append($('<th>', {
            'data-sort': datasort1
        }).html('<span class="arrow">â†‘â†“</span>')));
        if (nb_rows > 5) table_footer.append($('<tr>').append($('<th>').html('#N : ' + nb_rows)));
        if (total && nb_rows > 1) table_footer.append($('<tr>').append($('<th>').html('Î£ = ' + sum)));
    }
    if (!nosort) table.append(table_header);
    table.append(table_body);
    if (!nosort) table.append(table_footer);
    table.stupidtable();
    table.bind('aftertablesort', function (event, data) {
        var th = $(this).find("th");
        th.find(".arrow").remove();
        var arrow = data.direction === "asc" ? "â†“" : "â†‘";
        th.eq(data.column).append('<span class="arrow">' + arrow + '</span>');
    });
    return table;
}

function tablen_html(data, nosort, total) {
    var table = $('<table>');
    var table_header = $('<thead>');
    var table_footer = $('<tfoot>');
    var table_body = $('<tbody>');
    var datasort = [];
    var sum = [];
    var nb_rows = Object.keys(data).length;
    for (var n = 0; n < nb_rows; n++) {
        if (n == 0) {
            var nb_columns = Object.keys(data[n]).length;
            $.each(data[n], function (i, row) {
                datasort[i] = 'int';
                sum[i] = 0;
            });
        }
        $.each(data[n], function (i, row) {
            if (row === null) row = '';
            if (!$.isNumeric(row) && !$.isNumeric(joli(row))) datasort[i] = 'string';
            else sum[i] += parseFloat(row);
        });
        tr = $('<tr>');
        $.each(data[n], function (i, row) {
            if (typeof row !== 'string' && typeof row !== 'number') {
                row = table_html(row, true, total);
            }
            var td = $('<td>').addClass('result').html(row);
            if (row == '|') td.attr('title', 'Stop');
            if (datasort[i] == 'int') td.addClass('number');
            td.appendTo(tr);
        });
        tr.appendTo(table_body);
    }
    if (nb_rows > 2) {
        tr = $('<tr>');
        for (var n = 0; n < nb_columns; n++) {
            tr.append($('<th>', {
                'data-sort': datasort[n]
            }).html('<span class="arrow">â†‘â†“</span>'));
        }
        table_header.append(tr);
    }
    if (nb_rows > 5) {
        tr = $('<tr>');
        for (var n = 0; n < nb_columns; n++) {
            if (total) {
                if (datasort[n] == 'int') tr.append($('<th>').html('Î£ = ' + sum[n].toPrecision(5)));
                else tr.append($('<th>').html('#N : ' + nb_rows));
            }
        }
        if (!total) {
            tr.append($('<th>', {
                'colspan': nb_columns
            }).html('#N : ' + nb_rows));
        }
        table_footer.append(tr);
    }
    if (!nosort) table.append(table_header);
    table.append(table_body);
    if (!nosort) table.append(table_footer);
    table.stupidtable();
    table.bind('aftertablesort', function (event, data) {
        var th = $(this).find("th");
        th.find(".arrow").remove();
        var arrow = data.direction === "asc" ? "â†“" : "â†‘";
        th.eq(data.column).append('<span class="arrow">' + arrow + '</span>');
    });
    return table;
}

function qtip_text(txt, mode) {
    var qtip = $('<dl>');
    var source = $('<details>');
    if (mode == 'fr' || mode == 'en') {
        $.ajax({
            type: "POST",
            async: false,
            url: 'api/',
            data: {
                'tool': 'def',
                'w': txt,
                'lang': mode
            },
            dataType: 'json',
            success: function (data) {
                $.each(data, function (key, result) {
                    qtip.append($('<dt>').text(key));
                    var results = result.split("\n");
                    $.each(results, function (key, def) {
                        qtip.append($('<dd>').text('â€¢ ' + def));
                    });
                    source.append($('<div>').append($('<a>').attr('href', 'https://' + mode + '.wiktionary.org/wiki/' + key).attr('target', '_blank').text('https://' + mode + '.wiktionary.org/wiki/' + key)));
                });
                if (source.is(':empty')) {
                    source.append($('<span>').text(txt + ' ???'));
                } else {
                    source.prepend($('<summary>').text('Source'));
                }
                qtip.append(source);
            }
        });
    }
    if (mode == 'crypto') {
        var txt = result.text();
        if (txt.length < 15) return;
        var txt2 = txt.toUpperCase().replace(/[^A-Z0-9]/g, '');
        var txt3 = txt.toLowerCase().replace(/[^a-z0-9]/g, '');
        var txt4 = [],
            pos = 0,
            len = txt2.length;
        while (pos < len) {
            txt4.push(txt2.slice(pos, pos += 5));
        }
        txt4 = txt4.join(' ');
        qtip = $('<ul>')
            .append($('<li>').text(txt2.substring(0, 17)).click(function () {
                result.html(txt2)
            }))
            .append($('<li>').text(txt3.substring(0, 17)).click(function () {
                result.html(txt3)
            }))
            .append($('<li>').text(txt4.substring(0, 17)).click(function () {
                result.html(txt4)
            }))
            .append($('<li>').text(txt.replace(/\r\n/g, '').substring(0, 17)).click(function () {
                result.html(txt)
            }));
    }
    return qtip;
}

function send_message(subject, message, is_error) {
    var user = {};
    if (navigator.userAgent) user['USERAGENT'] = navigator.userAgent;
    if (navigator.platform) user['OS'] = navigator.platform;
    if (navigator.language) user['LANGUAGE'] = navigator.language;
    if (screen.width && screen.height) user['SCREEN'] = screen.width + 'x' + screen.height;
    if (is_local_storage_available()) user['LOCALSTORAGE'] = localStorage;
    $.post('/api/contact/', {
        'subject': subject,
        'message': message,
        'error': is_error,
        'page': window.location.href,
        'user': JSON.stringify(user)
    });
}

function SetCookie(name, value, expires, path, domain, secure) {
    var temp = name + "=" + escape(value);
    if (expires) temp += "; expires=" + expires.toGMTString();
    if (path) temp += "; path=" + path;
    if (domain) temp += "; domain=" + domain;
    if (secure) temp += "; secure";
    document.cookie = temp;
}

function GetCookie(name) {
    var arg = name + "=";
    var alen = arg.length;
    var clen = document.cookie.length;
    var i = 0;
    while (i < clen) {
        var j = i + alen;
        if (document.cookie.substring(i, j) == arg) {
            return getCookieVal(j);
        }
        i = document.cookie.indexOf(" ", i) + 1;
        if (i == 0) {
            break;
        }
    }
    return null;
}

function getCookieVal(offset) {
    var endstr = document.cookie.indexOf(";", offset);
    if (endstr == -1) {
        endstr = document.cookie.length;
    }
    return unescape(document.cookie.substring(offset, endstr));
}

function DeleteCookie(name, path, domain) {
    if (GetCookie(name)) {
        var temp = name + "=";
        temp += ((path) ? "; path=" + path : "");
        temp += ((domain) ? "; domain=" + domain : "");
        temp += "; expires=Thu, 01-Jan-70 00:00:01 GMT";
        document.cookie = temp;
    }
}

function is_local_storage_available() {
    try {
        localStorage.setItem('test', 'test');
        localStorage.removeItem('test');
        return true;
    } catch (e) {
        return false;
    }
}

function save_in_local_storage(form_id, post) {
    if (!is_local_storage_available()) return;
    var local = {};
    $.each(post, function (index, value) {
        if (index == 'tool') return;
        if (value === null) return;
        if (value.length > 1000) return;
        local[index] = value;
    });
    localStorage.setItem(form_id, JSON.stringify(local));
}

function is_associative(array) {
    var i = 0;
    $.each(array, function (key, value) {
        if (key != i) return;
        i++;
    });
    return (i != array.length);
}

function is_char_key(e) {
    return (!e.ctrlKey && !e.altKey && !e.metaKey && ((e.keyCode >= 48 && e.keyCode <= 57) ||
        (e.keyCode >= 65 && e.keyCode <= 90) ||
        (e.keyCode >= 97 && e.keyCode <= 122) ||
        e.keyCode == 39 || e.keyCode == 32));
}

function print_r(o, html) {
    if (html !== undefined) return $('<div>').text(o).html();
    return JSON.stringify(o, null, 4);
}

function joli(res) {
    if (typeof res == "object") return res;
    if (!res) return res;
    return res.replace(/ *<c>[\s\S]*?<\/c>/g, '').replace(/<.>([\s\S]*?)<\/.>/g, '$1').trim();
}
(function (d) {
    d.fn.stupidtable = function (b) {
        return this.each(function () {
            var a = d(this);
            b = b || {};
            b = d.extend({}, d.fn.stupidtable.default_sort_fns, b);
            a.on("click.stupidtable", "thead th", function () {
                var c = d(this),
                    f = 0,
                    g = d.fn.stupidtable.dir;
                c.parents("tr").find("th").slice(0, c.index()).each(function () {
                    var a = d(this).attr("colspan") || 1;
                    f += parseInt(a, 10)
                });
                var e = c.data("sort-default") || g.ASC;
                c.data("sort-dir") && (e = c.data("sort-dir") === g.ASC ? g.DESC : g.ASC);
                var l = c.data("sort") || null;
                null !== l && (a.trigger("beforetablesort", {
                    column: f,
                    direction: e
                }), a.css("display"), setTimeout(function () {
                    var h = [],
                        m = b[l],
                        k = a.children("tbody").children("tr");
                    k.each(function (a, b) {
                        var c = d(b).children().eq(f),
                            e = c.data("sort-value"),
                            c = "undefined" !== typeof e ? e : c.text();
                        h.push([c, b])
                    });
                    h.sort(function (a, b) {
                        return m(a[0], b[0])
                    });
                    e != g.ASC && h.reverse();
                    k = d.map(h, function (a) {
                        return a[1]
                    });
                    a.children("tbody").append(k);
                    a.find("th").data("sort-dir", null).removeClass("sorting-desc sorting-asc");
                    c.data("sort-dir", e).addClass("sorting-" + e);
                    a.trigger("aftertablesort", {
                        column: f,
                        direction: e
                    });
                    a.css("display")
                }, 10))
            })
        })
    };
    d.fn.stupidtable.dir = {
        ASC: "asc",
        DESC: "desc"
    };
    d.fn.stupidtable.default_sort_fns = {
        "int": function (b, a) {
            return parseInt(b, 10) - parseInt(a, 10)
        },
        "float": function (b, a) {
            return parseFloat(b) - parseFloat(a)
        },
        string: function (b, a) {
            a = joli(a);
            b = joli(b);
            return b < a ? -1 : b > a ? 1 : 0
        },
        "string-ins": function (b, a) {
            b = b.toLowerCase();
            a = a.toLowerCase();
            return b < a ? -1 : b > a ? 1 : 0
        }
    }
})(jQuery);