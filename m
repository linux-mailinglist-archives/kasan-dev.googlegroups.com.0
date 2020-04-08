Return-Path: <kasan-dev+bncBD7OB4EO4UNRBNXLW32AKGQE56AZYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AE791A1FD6
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Apr 2020 13:30:00 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id k18sf5176050otr.3
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Apr 2020 04:30:00 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H/vu4nSWt18VWWs2o9JUDxvYD0HC2oDAgaxLWhpPfLQ=;
        b=Yg+B75nFPYcksZT7Fw28anYRSflZRJe8no32KC7iIROFK/m74kgKMvpAX9FnZUjz5n
         rSX5gS50ylWprmzuLboqv7CoUH0TDN4RZa2Ul1LFt6DY1qyhecrMIVNkuy44LBXjsPK0
         o2z/qOoY4CUzZGdi1/6J4HrKJtVJJzNkxhS5VUr2UZ/zECeiRpnZeqg1/Ff6JYGGb4PJ
         /BYiC1Lw95fWSBLYx3pQUGAMQMHCHZk1RpGZ3rB+7yYKvNHDo7FvYdRzVjD6vOKW3lBX
         nKqZQTpDAGgajqsQzDfktoQ7LVZsQitDLLWEXgRtbVOQvM/V5eOGv2LYwmeJK9WvXMqG
         NLQA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H/vu4nSWt18VWWs2o9JUDxvYD0HC2oDAgaxLWhpPfLQ=;
        b=BdQYcZ+OD6+tMx65HO7MxCIzNiJgPKl+AT8PGtsXXkE8+SgmzdZQgtsW+YMuivKtra
         yCjt/0DkHbE6MbWtMOqe3zvClOgPcTyOVxiYlY1E5QjMVi0f8TvJFaHL7ZQjdSfSAY6g
         s6Xkt/SFDzxnaCN0+ocPOgWXqMPh4FItMzPu2Oeu155wMiK9UXFa/jzTf0XVzgqSZCnX
         WD4ZgvnE0VbIkDS5DrrJiu2K0TOKFtM+z641c4nznj3slL/sH66YMZ5GRlDajG7Rpr3k
         Z/Uqsr00r1irvbYbrjdPyeVf9q9pgU/9SGlwsBaFRZtnxK3BcOD0SkfsaJ9hMwia6A2j
         Zvjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H/vu4nSWt18VWWs2o9JUDxvYD0HC2oDAgaxLWhpPfLQ=;
        b=dCYHFpAgyE7FYzDm01i0oNLt3GGdwTx+djMiFDHGiK6BNoyJHORIpjh+ieT2E4eykG
         7thzjD3d5weP50+UDHdj6WvDuEO28djHzmqfzGuXaTJKvt5T4hBdJP+Yga7l1+p53NUL
         xV9Db0Gx84EDpu0O+gjVz5F72HnXtbchzpmKGeisy53YAaJ20bD6B6mj2U/zQFNFFVP9
         JGUg7Eu3DAbfjJajvK8MKnU/1LwGoeaXR5pZA2ZtZ4thHmbVV1Sb/Y+X8o38DvvgRCnL
         Kz21vmZIyy9XAdnOr+/v+151meOe2KwJzxN5sb/afc9gIw+8jk6F3E/VpNmqc6a+KvE9
         jHyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Puav8Jv5G8WC/roFrcILJbhh2oB+DQTHkoRcRbNn+7B37URfSgQe
	pm7jy+hO/VH6HdDe01y9XME=
X-Google-Smtp-Source: APiQypKZoRaZUoAyxzCcBCvBF69cHJ+U+kJRqR8TpawjOcbPXHSuV4xcpS6jzhSb+AJ8zoVL34eAUg==
X-Received: by 2002:a05:6830:8d:: with SMTP id a13mr5287102oto.321.1586345399028;
        Wed, 08 Apr 2020 04:29:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6006:: with SMTP id h6ls866792otj.3.gmail; Wed, 08 Apr
 2020 04:29:58 -0700 (PDT)
X-Received: by 2002:a9d:7409:: with SMTP id n9mr4949733otk.173.1586345397306;
        Wed, 08 Apr 2020 04:29:57 -0700 (PDT)
Date: Wed, 8 Apr 2020 04:29:56 -0700 (PDT)
From: Johannes Wagner <ickyphuz@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <fe8bfc10-2d1c-4f47-9f11-df4d3c77a7d7@googlegroups.com>
In-Reply-To: <CACT4Y+aqy0MgJntoKPcjoxnyH3w4n0UW5yxFJX-prm-Zgqn+0g@mail.gmail.com>
References: <78d7f888-7960-433f-9807-d703e57002bf@googlegroups.com>
 <CACT4Y+ZvX1Cs1SJppVfLXyV9F4hra=JdBaQCqBTeFX3++f48kQ@mail.gmail.com>
 <CACT4Y+abK5o34h_rks7HMivmVigTG3CM9X93MOt9d7B6dxY_9w@mail.gmail.com> <CABDgRhumwQxxpQDmGq6=zf9Xi4DY4tM=_kOdbf=SFvfPYMNYrQ@mail.gmail.com>
 <CACT4Y+aqy0MgJntoKPcjoxnyH3w4n0UW5yxFJX-prm-Zgqn+0g@mail.gmail.com>
Subject: Re: [libfuzzer] Linker fails on finding Symbols on (Samsung)
 Android Kernel Build
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_2955_1914295789.1586345396639"
X-Original-Sender: ickyphuz@gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

------=_Part_2955_1914295789.1586345396639
Content-Type: multipart/alternative; 
	boundary="----=_Part_2956_30623569.1586345396639"

------=_Part_2956_30623569.1586345396639
Content-Type: text/plain; charset="UTF-8"



> >> It looks like you have an old kernel and a new compiler. 
> >> You either need to backport KASAN patches for stack support, or take 
> >> an older compiler maybe, or maybe disabling KASAN stack 
> >> instrumentation will help. 
>

Thanks for the Pointers Dmitry,

i backported the commits from your suggestion in another thread [1] <[1] 
https://groups.google.com/d/msg/kasan-dev/xXmG0cnIkaI/LQ9o0BmjAgAJ>, and it 
resolved a lot of issues except for the symbol 
'__asan_set_shadow_00'

which is like the others defined in the mm/kasan/kasan.c and exportet in 
mm/kasan/kasan.h file. 
i tought maybe the macro fails because of the 00 so i also tried expanding 
this macro myself. but did also not work.
may it be a missing/missplaced import? 
CONFIG_KASAN_STACK=0
did not lead to a successful build as well as using older compiler 
toolchains.

[1] https://groups.google.com/d/msg/kasan-dev/xXmG0cnIkaI/LQ9o0BmjAgAJ

attached the whole remaining error:
  MODPOST vmlinux.o
WARNING: modpost: Found 2 section mismatch(es).
To see full details build your kernel with:
'make CONFIG_DEBUG_SECTION_MISMATCH=y'
drivers/misc/modem_v1/modem_main.o: In function `modem_probe':
/home/kerneldev/kernel/drivers/misc/modem_v1/modem_main.c:1103: undefined 
reference to `__asan_set_shadow_00'
drivers/net/wireless/broadcom/bcmdhd_100_15/wl_cfgvendor.o: In function 
`wl_cfgvendor_send_nan_event':
/home/kerneldev/kernel/drivers/net/wireless/broadcom/bcmdhd_100_15/
wl_cfgvendor.c:5475: undefined reference to `__asan_set_shadow_00'
drivers/net/usb/r8152.o: In function `rtl8152_up':
/home/kerneldev/kernel/drivers/net/usb/r8152.c:5466: undefined reference to 
`__asan_set_shadow_00'
drivers/net/usb/r8152.o: In function `r8153_init':
/home/kerneldev/kernel/drivers/net/usb/r8152.c:5953: undefined reference to 
`__asan_set_shadow_00'
drivers/net/usb/r8152.o: In function `rtl8153_up':
/home/kerneldev/kernel/drivers/net/usb/r8152.c:5495: undefined reference to 
`__asan_set_shadow_00'
drivers/net/usb/r8152.o:/home/kerneldev/kernel/drivers/net/usb/r8152.c:5093: 
more undefined references to `__asan_set_shadow_00' follow
Makefile:1142: recipe for target 'vmlinux' failed
make: *** [vmlinux] Error 1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe8bfc10-2d1c-4f47-9f11-df4d3c77a7d7%40googlegroups.com.

------=_Part_2956_30623569.1586345396639
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br><blockquote class=3D"gmail_quote" style=3D"margin: 0;m=
argin-left: 0.8ex;border-left: 1px #ccc solid;padding-left: 1ex;">&gt;&gt; =
It looks like you have an old kernel and a new compiler.
<br>&gt;&gt; You either need to backport KASAN patches for stack support, o=
r take
<br>&gt;&gt; an older compiler maybe, or maybe disabling KASAN stack
<br>&gt;&gt; instrumentation will help.
<br></blockquote><div><br></div><div>Thanks for the Pointers Dmitry,</div><=
div><br></div><div>i backported the commits from your suggestion in another=
 <a href=3D"[1] https://groups.google.com/d/msg/kasan-dev/xXmG0cnIkaI/LQ9o0=
BmjAgAJ">thread [1]</a>, and it resolved a lot of issues except for the sym=
bol <div style=3D"background-color: rgb(250, 250, 250); border-color: rgb(1=
87, 187, 187); border-style: solid; border-width: 1px; overflow-wrap: break=
-word;" class=3D"prettyprint"><code class=3D"prettyprint"><div class=3D"sub=
prettyprint"><span style=3D"color: #080;" class=3D"styled-by-prettify">&#39=
;__asan_set_shadow_00&#39;</span></div></code></div><br>which is like the o=
thers defined in the mm/kasan/kasan.c and exportet in mm/kasan/kasan.h file=
. <br></div><div>i tought maybe the macro fails because of the 00 so i also=
 tried expanding this macro myself. but did also not work.<br></div><div>ma=
y it be a missing/missplaced import? <br><div style=3D"background-color: rg=
b(250, 250, 250); border-color: rgb(187, 187, 187); border-style: solid; bo=
rder-width: 1px; overflow-wrap: break-word;" class=3D"prettyprint"><code cl=
ass=3D"prettyprint"><div class=3D"subprettyprint"><span style=3D"color: #00=
0;" class=3D"styled-by-prettify">CONFIG_KASAN_STACK</span><span style=3D"co=
lor: #660;" class=3D"styled-by-prettify">=3D</span><span style=3D"color: #0=
66;" class=3D"styled-by-prettify">0</span></div></code></div>did not lead t=
o a successful build as well as using older compiler toolchains.</div><div>=
<br></div><div>[1] https://groups.google.com/d/msg/kasan-dev/xXmG0cnIkaI/LQ=
9o0BmjAgAJ</div><div><br></div><div>attached the whole remaining error:<br>=
</div><div><div style=3D"background-color: rgb(250, 250, 250); border-color=
: rgb(187, 187, 187); border-style: solid; border-width: 1px; overflow-wrap=
: break-word;" class=3D"prettyprint"><code class=3D"prettyprint"><div class=
=3D"subprettyprint"><span style=3D"color: #000;" class=3D"styled-by-prettif=
y">=C2=A0 MODPOST vmlinux</span><span style=3D"color: #660;" class=3D"style=
d-by-prettify">.</span><span style=3D"color: #000;" class=3D"styled-by-pret=
tify">o<br>WARNING</span><span style=3D"color: #660;" class=3D"styled-by-pr=
ettify">:</span><span style=3D"color: #000;" class=3D"styled-by-prettify"> =
modpost</span><span style=3D"color: #660;" class=3D"styled-by-prettify">:</=
span><span style=3D"color: #000;" class=3D"styled-by-prettify"> </span><spa=
n style=3D"color: #606;" class=3D"styled-by-prettify">Found</span><span sty=
le=3D"color: #000;" class=3D"styled-by-prettify"> </span><span style=3D"col=
or: #066;" class=3D"styled-by-prettify">2</span><span style=3D"color: #000;=
" class=3D"styled-by-prettify"> section mismatch</span><span style=3D"color=
: #660;" class=3D"styled-by-prettify">(</span><span style=3D"color: #000;" =
class=3D"styled-by-prettify">es</span><span style=3D"color: #660;" class=3D=
"styled-by-prettify">).</span><span style=3D"color: #000;" class=3D"styled-=
by-prettify"><br></span><span style=3D"color: #606;" class=3D"styled-by-pre=
ttify">To</span><span style=3D"color: #000;" class=3D"styled-by-prettify"> =
see full details build your kernel </span><span style=3D"color: #008;" clas=
s=3D"styled-by-prettify">with</span><span style=3D"color: #660;" class=3D"s=
tyled-by-prettify">:</span><span style=3D"color: #000;" class=3D"styled-by-=
prettify"><br></span><span style=3D"color: #080;" class=3D"styled-by-pretti=
fy">&#39;make CONFIG_DEBUG_SECTION_MISMATCH=3Dy&#39;</span><span style=3D"c=
olor: #000;" class=3D"styled-by-prettify"><br>drivers</span><span style=3D"=
color: #660;" class=3D"styled-by-prettify">/</span><span style=3D"color: #0=
00;" class=3D"styled-by-prettify">misc</span><span style=3D"color: #660;" c=
lass=3D"styled-by-prettify">/</span><span style=3D"color: #000;" class=3D"s=
tyled-by-prettify">modem_v1</span><span style=3D"color: #660;" class=3D"sty=
led-by-prettify">/</span><span style=3D"color: #000;" class=3D"styled-by-pr=
ettify">modem_main</span><span style=3D"color: #660;" class=3D"styled-by-pr=
ettify">.</span><span style=3D"color: #000;" class=3D"styled-by-prettify">o=
</span><span style=3D"color: #660;" class=3D"styled-by-prettify">:</span><s=
pan style=3D"color: #000;" class=3D"styled-by-prettify"> </span><span style=
=3D"color: #606;" class=3D"styled-by-prettify">In</span><span style=3D"colo=
r: #000;" class=3D"styled-by-prettify"> </span><span style=3D"color: #008;"=
 class=3D"styled-by-prettify">function</span><span style=3D"color: #000;" c=
lass=3D"styled-by-prettify"> </span><span style=3D"color: #080;" class=3D"s=
tyled-by-prettify">`modem_probe&#39;:<br>/home/kerneldev/kernel/drivers/mis=
c/modem_v1/modem_main.c:1103: undefined reference to `</span><span style=3D=
"color: #000;" class=3D"styled-by-prettify">__asan_set_shadow_00</span><spa=
n style=3D"color: #080;" class=3D"styled-by-prettify">&#39;<br>drivers/net/=
wireless/broadcom/bcmdhd_100_15/wl_cfgvendor.o: In function `wl_cfgvendor_s=
end_nan_event&#39;</span><span style=3D"color: #660;" class=3D"styled-by-pr=
ettify">:</span><span style=3D"color: #000;" class=3D"styled-by-prettify"><=
br></span><span style=3D"color: #080;" class=3D"styled-by-prettify">/home/<=
/span><span style=3D"color: #000;" class=3D"styled-by-prettify">kerneldev</=
span><span style=3D"color: #660;" class=3D"styled-by-prettify">/</span><spa=
n style=3D"color: #000;" class=3D"styled-by-prettify">kernel</span><span st=
yle=3D"color: #660;" class=3D"styled-by-prettify">/</span><span style=3D"co=
lor: #000;" class=3D"styled-by-prettify">drivers</span><span style=3D"color=
: #660;" class=3D"styled-by-prettify">/</span><span style=3D"color: #000;" =
class=3D"styled-by-prettify">net</span><span style=3D"color: #660;" class=
=3D"styled-by-prettify">/</span><span style=3D"color: #000;" class=3D"style=
d-by-prettify">wireless</span><span style=3D"color: #660;" class=3D"styled-=
by-prettify">/</span><span style=3D"color: #000;" class=3D"styled-by-pretti=
fy">broadcom</span><span style=3D"color: #660;" class=3D"styled-by-prettify=
">/</span><span style=3D"color: #000;" class=3D"styled-by-prettify">bcmdhd_=
100_15</span><span style=3D"color: #660;" class=3D"styled-by-prettify">/</s=
pan><span style=3D"color: #000;" class=3D"styled-by-prettify">wl_cfgvendor<=
/span><span style=3D"color: #660;" class=3D"styled-by-prettify">.</span><sp=
an style=3D"color: #000;" class=3D"styled-by-prettify">c</span><span style=
=3D"color: #660;" class=3D"styled-by-prettify">:</span><span style=3D"color=
: #066;" class=3D"styled-by-prettify">5475</span><span style=3D"color: #660=
;" class=3D"styled-by-prettify">:</span><span style=3D"color: #000;" class=
=3D"styled-by-prettify"> </span><span style=3D"color: #008;" class=3D"style=
d-by-prettify">undefined</span><span style=3D"color: #000;" class=3D"styled=
-by-prettify"> reference to </span><span style=3D"color: #080;" class=3D"st=
yled-by-prettify">`__asan_set_shadow_00&#39;<br>drivers/net/usb/r8152.o: In=
 function `</span><span style=3D"color: #000;" class=3D"styled-by-prettify"=
>rtl8152_up</span><span style=3D"color: #080;" class=3D"styled-by-prettify"=
>&#39;:<br>/home/kerneldev/kernel/drivers/net/usb/r8152.c:5466: undefined r=
eference to `__asan_set_shadow_00&#39;</span><span style=3D"color: #000;" c=
lass=3D"styled-by-prettify"><br>drivers</span><span style=3D"color: #660;" =
class=3D"styled-by-prettify">/</span><span style=3D"color: #000;" class=3D"=
styled-by-prettify">net</span><span style=3D"color: #660;" class=3D"styled-=
by-prettify">/</span><span style=3D"color: #000;" class=3D"styled-by-pretti=
fy">usb</span><span style=3D"color: #660;" class=3D"styled-by-prettify">/</=
span><span style=3D"color: #000;" class=3D"styled-by-prettify">r8152</span>=
<span style=3D"color: #660;" class=3D"styled-by-prettify">.</span><span sty=
le=3D"color: #000;" class=3D"styled-by-prettify">o</span><span style=3D"col=
or: #660;" class=3D"styled-by-prettify">:</span><span style=3D"color: #000;=
" class=3D"styled-by-prettify"> </span><span style=3D"color: #606;" class=
=3D"styled-by-prettify">In</span><span style=3D"color: #000;" class=3D"styl=
ed-by-prettify"> </span><span style=3D"color: #008;" class=3D"styled-by-pre=
ttify">function</span><span style=3D"color: #000;" class=3D"styled-by-prett=
ify"> </span><span style=3D"color: #080;" class=3D"styled-by-prettify">`r81=
53_init&#39;:<br>/home/kerneldev/kernel/drivers/net/usb/r8152.c:5953: undef=
ined reference to `</span><span style=3D"color: #000;" class=3D"styled-by-p=
rettify">__asan_set_shadow_00</span><span style=3D"color: #080;" class=3D"s=
tyled-by-prettify">&#39;<br>drivers/net/usb/r8152.o: In function `rtl8153_u=
p&#39;</span><span style=3D"color: #660;" class=3D"styled-by-prettify">:</s=
pan><span style=3D"color: #000;" class=3D"styled-by-prettify"><br></span><s=
pan style=3D"color: #080;" class=3D"styled-by-prettify">/home/</span><span =
style=3D"color: #000;" class=3D"styled-by-prettify">kerneldev</span><span s=
tyle=3D"color: #660;" class=3D"styled-by-prettify">/</span><span style=3D"c=
olor: #000;" class=3D"styled-by-prettify">kernel</span><span style=3D"color=
: #660;" class=3D"styled-by-prettify">/</span><span style=3D"color: #000;" =
class=3D"styled-by-prettify">drivers</span><span style=3D"color: #660;" cla=
ss=3D"styled-by-prettify">/</span><span style=3D"color: #000;" class=3D"sty=
led-by-prettify">net</span><span style=3D"color: #660;" class=3D"styled-by-=
prettify">/</span><span style=3D"color: #000;" class=3D"styled-by-prettify"=
>usb</span><span style=3D"color: #660;" class=3D"styled-by-prettify">/</spa=
n><span style=3D"color: #000;" class=3D"styled-by-prettify">r8152</span><sp=
an style=3D"color: #660;" class=3D"styled-by-prettify">.</span><span style=
=3D"color: #000;" class=3D"styled-by-prettify">c</span><span style=3D"color=
: #660;" class=3D"styled-by-prettify">:</span><span style=3D"color: #066;" =
class=3D"styled-by-prettify">5495</span><span style=3D"color: #660;" class=
=3D"styled-by-prettify">:</span><span style=3D"color: #000;" class=3D"style=
d-by-prettify"> </span><span style=3D"color: #008;" class=3D"styled-by-pret=
tify">undefined</span><span style=3D"color: #000;" class=3D"styled-by-prett=
ify"> reference to </span><span style=3D"color: #080;" class=3D"styled-by-p=
rettify">`__asan_set_shadow_00&#39;<br>drivers/net/usb/r8152.o:/home/kernel=
dev/kernel/drivers/net/usb/r8152.c:5093: more undefined references to `</sp=
an><span style=3D"color: #000;" class=3D"styled-by-prettify">__asan_set_sha=
dow_00</span><span style=3D"color: #080;" class=3D"styled-by-prettify">&#39=
; follow<br>Makefile:1142: recipe for target &#39;</span><span style=3D"col=
or: #000;" class=3D"styled-by-prettify">vmlinux</span><span style=3D"color:=
 #080;" class=3D"styled-by-prettify">&#39; failed<br>make: *** [vmlinux] Er=
ror 1<br></span></div></code></div><br></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/fe8bfc10-2d1c-4f47-9f11-df4d3c77a7d7%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/fe8bfc10-2d1c-4f47-9f11-df4d3c77a7d7%40googlegroups.com</a>.<br =
/>

------=_Part_2956_30623569.1586345396639--

------=_Part_2955_1914295789.1586345396639--
