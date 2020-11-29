Return-Path: <kasan-dev+bncBDC7ZQ52YQBBBYHER77AKGQEDNEZ6VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id E7C132C7ADA
	for <lists+kasan-dev@lfdr.de>; Sun, 29 Nov 2020 20:11:29 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id b4sf3206599vkg.10
        for <lists+kasan-dev@lfdr.de>; Sun, 29 Nov 2020 11:11:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606677088; cv=pass;
        d=google.com; s=arc-20160816;
        b=gPFva4JUjgvLZ/fyE0TpaKXFmdGTm+/S/7IPPl1PgQ235Ry+c5T1eUikh69UJ48e4L
         JSBjjrawrAvvoMuzZ4tfFd29IqVkzqs5QRKxRyBrAZ5sWkwKpS4B2l13dg0rWm6krM4l
         HugjPpoKB3v4EiekdrXUsuMyPUZpj5bJ8CJlyjjU7hhxGFbeNmeXQiZs3DIF3VFPPv6w
         ZzoSAVBIflEnHUcdGmUVamCCBltbh2ub17wUGUzvzN1zh9o8DSaGqbyTF6k29LhrLUdS
         BVZbKz/HwlwQdCU7ZFdLJoDPBxmyJYhT7OH0gsDLAMvE01d7oFuZKjW7KwLhTTiybZvB
         b52A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:date:message-id
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=QJ7DhNglzBawMSrTNCeOqh2S0QkH2wi/AGkjxI5dKV0=;
        b=uDBPJcd3iHoWFUeSGm5sxYr31WeLfh0tNmvzCVnM67lPhfSuZip+mBCis3i7pEop/v
         emXNJmmHLdrAKw4PMXbPR89b8VhCpQDbmn0k/V0HmXfM/49S0ItwIC5hT0olavdJlQHh
         3+2bu6BM13dM5QtHjd/7SmQrHoorqMsLyeC44mhYe3aLS9swnPaYo4YfjK3lz2c2KTg+
         0/JXrhbC+G70ABDfxEKCI6w67h7B3faNcNj1hKDE190k9KP5bfdfA5wUXmEzd1sRnKgI
         HeSN0gIDvR0Rav1akoLEvQrUPLxs8OcK7MjCT8dsz1Z25ZjWSdr58MR2s5EXm2K2lHB0
         HC9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ZkjQzjeY;
       spf=pass (google.com: domain of 3ypldxw4jcvk29c1cdfii9jtus7d19c.3fdb1j1e-45m7ff7c57iflgj.3fd@trix.bounces.google.com designates 2607:f8b0:4864:20::b48 as permitted sender) smtp.mailfrom=3YPLDXw4JCVk29C1CDFII9JTUS7D19C.3FDB1J1E-45M7FF7C57IFLGJ.3FD@trix.bounces.google.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:message-id:date:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QJ7DhNglzBawMSrTNCeOqh2S0QkH2wi/AGkjxI5dKV0=;
        b=q/tPRi4bkfma5tfoGfnfVU1ziq3BpDvI2TFYvrj6TaZTIHN2OVm7vsRYG4LGTj7hPf
         77vi5sz7xCCNrn5uSW6ZgJswkvcGJZ9pFqjzx7hAK8Y4pv+fVdad9goXTAd1nS3XGcE9
         IgF6KZcK7iOvVuuZJJnkqJIL0y7DPSzSFlyAHHNdBEtEweEuyNH2X6+I2lKZNl5zg0Ln
         1oBOaL4qOxfLYMPnmVZxDuqH3v4VgnDqNAPJ8dQUyYgRj4PMbahs0fGy6Q/cr0itBzwF
         zR8g4/fFB1dz39X+HDADvAPw7maGUur/oeb84yvLRwYYW/tmU9FQErhNN4uFsyZu9xV3
         7bsQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:message-id:date:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QJ7DhNglzBawMSrTNCeOqh2S0QkH2wi/AGkjxI5dKV0=;
        b=m6zHiWHuIkOqld2jynZBroGulh478RFqGaNL/QwigM4lR2bil+qUwWiEVKowWodzdK
         grxKVH99dNe/sxeBZIbVVlHzEyBUmgm2tQnQCJxYsiAmjBjl4WIP+ZSocxHZgq0QFdQ/
         4UI5x92NSNn60As+G4zoUMYamQmAje1b3bKGy661O1SGqZeuTaiU1UHMSNzU0DdCyljz
         DJULaLNz7zbvswZP1/qwt9uFFH1gStR1EBny9zV4P+QdrDP6A14utRDdmyxcvisjhhOF
         Rjyz/i3x1/rLrCWn/RlPD7Z+NTvuoDnFZ85WKvae+PWaaDTSShep4EJkd3BWMeA7dK8X
         J0Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:message-id:date
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QJ7DhNglzBawMSrTNCeOqh2S0QkH2wi/AGkjxI5dKV0=;
        b=MqJkAnr0xcZQ3Yvs5KTW/TPaa8ncc62ANeIpZ9gH31LWpu/bvLFleJbfkzqDeMXKr4
         BC/BdqshGFiHfKt2ywGlTqVrulC7GDAxajoYzvdkve8nJMZ8Gi9bTsg+qSMgQpoCI+Zj
         IQ4mgmPK8/tBqZxGskDwTyUZSTlcwQtR523gGwxd+MnOfXrZRanbqd2tcoBeJoEfl9wb
         ySaANKNuhdJVsXT+PTHGMZbEouo1NtAVAHMuhhCzPvetU7/bYFdojVvHH3qMjkg7Mv8R
         N9Pgkd3e8Njeqi53D3BGd9CRZ5qNvRwjr7kwkwxhbPZKDK0a119o9rjGi8BuklbkJ+Iy
         tZEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530lucO+cxW6ryzypP0eVL8UyK+m9wgDBwASM+kL7G38oOymJBzl
	Qs/WAoG7DZfGib1FHmlq50s=
X-Google-Smtp-Source: ABdhPJwRTbK4u37oodePYbpNQN+TnHKdpdJ7PMM+iU3eKCTSFFZIUtvfQa6wG/epz33sGMuEF753DA==
X-Received: by 2002:a67:ff01:: with SMTP id v1mr13405618vsp.16.1606677088639;
        Sun, 29 Nov 2020 11:11:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls979342vsm.3.gmail; Sun, 29 Nov
 2020 11:11:28 -0800 (PST)
X-Received: by 2002:a67:d097:: with SMTP id s23mr12096126vsi.24.1606677088197;
        Sun, 29 Nov 2020 11:11:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606677088; cv=none;
        d=google.com; s=arc-20160816;
        b=pnXp8Rg4R43SjBmDH+RaHq0TuVE5N7DQoYKSzSyu5E8AX48DNelcOwHSAzNM8r11KT
         1oCAWvINXNiPszdd98X9pzDLZSXq0qGtjzc+2L6Hoo+Fi1ryRj5FQ3RVJbwp6tTKKM+8
         +FNDtniykPtriW3ayCde/yvDw8nQbdkEf5cegNelEegtCh6j7smJtO/C7+5XFw5WTS4e
         ocajWlHfTmOQZVt94QqAuyTfRLjUY21a/IqzdZKrVfRh/nkhCcfOpNaDyy1Mxe57lWNo
         8MQgYwOiWdizcGHsbenooFn0i69hBYGmKSckAbIyxuU27j82pnTRtmDgVdIWL0yKK+Az
         nEGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:date:message-id:reply-to:mime-version
         :dkim-signature;
        bh=MtsHJUwR7yeIxWVzyGyzOIo4tKwJRTAFQm3adsqIG20=;
        b=xGt8QRrwv4F6BGlSRHYXNhK01bmuxuJeBRt91ygG3Fk+xGRGjKU0YsNh8YDMgVuZfB
         5Sg7wuizD609we36F8WgxXl+/TviXJqLKJgW2uBTNaQQDIeWKsJEn6Zs3hF4D4N3bVln
         SIFpO0NCZppcGGC4zb7iSkSwjmqQ8UGvsCJUi2Rk2SaTsnFo+m0AK0G29v1cmbNVfoWD
         6s3pTsgSkjXomaz+Fi/vAXrfYDphPdQkGV1t+8EwJ7DHWko50dQmJaHprXUieO7Suf11
         wWUgKq1J3EvkGoI+qM5ZDejiYz7kW5VmE/gB7D2tGvh/teUrpsWsFXMaxoNP6KkosWuP
         XwRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ZkjQzjeY;
       spf=pass (google.com: domain of 3ypldxw4jcvk29c1cdfii9jtus7d19c.3fdb1j1e-45m7ff7c57iflgj.3fd@trix.bounces.google.com designates 2607:f8b0:4864:20::b48 as permitted sender) smtp.mailfrom=3YPLDXw4JCVk29C1CDFII9JTUS7D19C.3FDB1J1E-45M7FF7C57IFLGJ.3FD@trix.bounces.google.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yb1-xb48.google.com (mail-yb1-xb48.google.com. [2607:f8b0:4864:20::b48])
        by gmr-mx.google.com with ESMTPS id a16si865363uas.1.2020.11.29.11.11.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 29 Nov 2020 11:11:28 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ypldxw4jcvk29c1cdfii9jtus7d19c.3fdb1j1e-45m7ff7c57iflgj.3fd@trix.bounces.google.com designates 2607:f8b0:4864:20::b48 as permitted sender) client-ip=2607:f8b0:4864:20::b48;
Received: by mail-yb1-xb48.google.com with SMTP id a13so13158674ybj.3
        for <kasan-dev@googlegroups.com>; Sun, 29 Nov 2020 11:11:28 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a25:4c89:: with SMTP id z131mt18213783yba.339.1606677088006;
 Sun, 29 Nov 2020 11:11:28 -0800 (PST)
Reply-To: bilalmorris231@gmail.com
X-No-Auto-Attachment: 1
Message-ID: <00000000000019778b05b543a944@google.com>
Date: Sun, 29 Nov 2020 19:11:28 +0000
Subject: Congratulation! (Mega Millions Lottery)
From: bilalmorris231@gmail.com
To: kasan-dev@googlegroups.com
Content-Type: multipart/alternative; boundary="0000000000001af96f05b543a985"
X-Original-Sender: bilalmorris231@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ZkjQzjeY;       spf=pass
 (google.com: domain of 3ypldxw4jcvk29c1cdfii9jtus7d19c.3fdb1j1e-45m7ff7c57iflgj.3fd@trix.bounces.google.com
 designates 2607:f8b0:4864:20::b48 as permitted sender) smtp.mailfrom=3YPLDXw4JCVk29C1CDFII9JTUS7D19C.3FDB1J1E-45M7FF7C57IFLGJ.3FD@trix.bounces.google.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--0000000000001af96f05b543a985
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes

I've invited you to fill out the following form:
Untitled form

To fill it out, visit:
https://docs.google.com/forms/d/e/1FAIpQLSejitRsY0yrE6F4TILKy0bfmau43DYeveiXnH_uGVxYOKKetw/viewform?vc=0&amp;c=0&amp;w=1&amp;flr=0&amp;usp=mail_form_link

Congratulations You have won $ 850,000.00USD Your E-Mail Name Is Among
the Lucky Winners at Mega Millions Lottery Online promo, Ticket Number
(88910), For more information contact us Via Tel: +44} 7045746552. or
reply to this email: peterjeng042@gmail.com

Your winning reference numbers are PMG / EBD / 850AF and will Instruct you
on claim arrangements for your winning prize.

Please note this, You are only required to forward your Name and your  
Address.

Your Full Name.
Your Age.
Your Country / Home Address.
Your Telephone Number.
Your Occupation.

Thank you and once More Congratulations.

Yours faithfully,
Agent Morris Bilal.
Claims / verification Agent,

Google Forms: Create and analyze surveys.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00000000000019778b05b543a944%40google.com.

--0000000000001af96f05b543a985
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<html><body style=3D"font-family: Roboto,Helvetica,Arial,sans-serif; margin=
: 0; padding: 0; height: 100%; width: 100%;"><table border=3D"0" cellpaddin=
g=3D"0" cellspacing=3D"0" style=3D"background-color:rgb(103,58,183);" width=
=3D"100%" role=3D"presentation"><tbody><tr height=3D"64px"><td style=3D"pad=
ding: 0 24px;"><img alt=3D"Google Forms" height=3D"26px" style=3D"display: =
inline-block; margin: 0; vertical-align: middle;" width=3D"143px" src=3D"ht=
tps://www.gstatic.com/docs/forms/google_forms_logo_lockup_white_2x.png"></t=
d></tr></tbody></table><div style=3D"padding: 24px; background-color:rgb(23=
7,231,246)"><div align=3D"center" style=3D"background-color: #fff; border-b=
ottom: 1px solid #e0e0e0;margin: 0 auto; max-width: 624px; min-width: 154px=
;padding: 0 24px;"><table align=3D"center" cellpadding=3D"0" cellspacing=3D=
"0" style=3D"background-color: #fff;" width=3D"100%" role=3D"presentation">=
<tbody><tr height=3D"24px"><td></td></tr><tr><td><span style=3D"display: ta=
ble-cell; vertical-align: top; font-size: 13px; line-height: 18px; color: #=
424242;" dir=3D"auto">Congratulations You have won $ 850,000.00USD Your E-M=
ail Name Is Among<br>the Lucky Winners at Mega Millions Lottery Online prom=
o, Ticket Number<br>(88910), For more information contact us Via Tel: +44} =
7045746552. or<br>reply to this email: peterjeng042@gmail.com<br><br>Your w=
inning reference numbers are PMG / EBD / 850AF and will Instruct you<br>on =
claim arrangements for your winning prize.<br><br>Please note this, You are=
 only required to forward your Name and your Address.<br><br>Your Full Name=
.<br>Your Age.<br>Your Country / Home Address.<br>Your Telephone Number.<br=
>Your Occupation.<br><br>Thank you and once More Congratulations.<br><br>Yo=
urs faithfully,<br>Agent Morris Bilal.<br>Claims / verification Agent,</spa=
n></td></tr><tr height=3D"20px"><td></tr><tr style=3D"font-size: 20px; line=
-height: 24px;"><td dir=3D"auto"><a href=3D"https://docs.google.com/forms/d=
/e/1FAIpQLSejitRsY0yrE6F4TILKy0bfmau43DYeveiXnH_uGVxYOKKetw/viewform?vc=3D0=
&amp;c=3D0&amp;w=3D1&amp;flr=3D0&amp;usp=3Dmail_form_link" style=3D"color: =
rgb(103,58,183); text-decoration: none; vertical-align: middle; font-weight=
: 500">Untitled form</a><div itemprop=3D"action" itemscope itemtype=3D"http=
://schema.org/ViewAction"><meta itemprop=3D"url" content=3D"https://docs.go=
ogle.com/forms/d/e/1FAIpQLSejitRsY0yrE6F4TILKy0bfmau43DYeveiXnH_uGVxYOKKetw=
/viewform?vc=3D0&amp;c=3D0&amp;w=3D1&amp;flr=3D0&amp;usp=3Dmail_goto_form">=
<meta itemprop=3D"name" content=3D"Fill out form"></div></td></tr><tr heigh=
t=3D"24px"></tr><tr><td><table border=3D"0" cellpadding=3D"0" cellspacing=
=3D"0" width=3D"100%"><tbody><tr><td><a href=3D"https://docs.google.com/for=
ms/d/e/1FAIpQLSejitRsY0yrE6F4TILKy0bfmau43DYeveiXnH_uGVxYOKKetw/viewform?vc=
=3D0&amp;c=3D0&amp;w=3D1&amp;flr=3D0&amp;usp=3Dmail_form_link" style=3D"bor=
der-radius: 3px; box-sizing: border-box; display: inline-block; font-size: =
13px; font-weight: 700; height: 40px; line-height: 40px; padding: 0 24px; t=
ext-align: center; text-decoration: none; text-transform: uppercase; vertic=
al-align: middle; color: #fff; background-color: rgb(103,58,183);" target=
=3D"_blank" rel=3D"noopener">Fill out form</a></td></tr></tbody></table></t=
d></tr><tr height=3D"24px"></tr></tbody></table></div><table align=3D"cente=
r" cellpadding=3D"0" cellspacing=3D"0" style=3D"max-width: 672px; min-width=
: 154px;" width=3D"100%" role=3D"presentation"><tbody><tr height=3D"24px"><=
td></td></tr><tr><td><a href=3D"https://docs.google.com/forms?usp=3Dmail_fo=
rm_link" style=3D"color: #424242; font-size: 13px;">Create your own Google =
Form</a></td></tr></tbody></table></div></body></html>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/00000000000019778b05b543a944%40google.com?utm_medium=
=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/0=
0000000000019778b05b543a944%40google.com</a>.<br />

--0000000000001af96f05b543a985--
