Return-Path: <kasan-dev+bncBCWM5NUYSUDRBO75T7XQKGQERYBSLZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2F1DE113523
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 19:45:17 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id 60sf375678otd.19
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 10:45:17 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YB4wH/pNDNAtbMu514gttgjLc21/I9fpifSVku4po9o=;
        b=e8Ypfs2K5NFATNSyeX6RpAwHma57xU0kyvjPZx1JZlmaWAC1rCuesObjp2pdj5VQrC
         6Qo8mJwjQkRlvClsqaP8ffbgZeNjoUBuh0XAQ+GmvfWpn3qSo93CfC3MoX0RTtkw7b4G
         oH+M20HlfTAbl/Z/KgwdMbrHkLoHkxhJy0hQ50AXs8RjNUXZexn9rz/sWKKjD5wyYBZw
         XLoeyQOtuSEL4qrOl4pLvmk1p4mQiAnsSmdgRFNbjwq6RH8bs3wLNxZC9GBoZTrRu6NJ
         VegZtYPeGoAIr4eAn31ALtkHcq0IbwiW+5qrIXNLnWJhv51+B6tni6ZzUY+AHO6+RuZD
         4dyA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YB4wH/pNDNAtbMu514gttgjLc21/I9fpifSVku4po9o=;
        b=nQpZcQF3Zl9mWYRIQc2PeItL2OQnapWwk4dTYNqAm8u4qtr7KBJhH7cOby6DUaIyKR
         liL5MeshMcoCNe1KlfkqAD1PzFoasNuw8rYPmkOBL79hWzZK8iupblDAVq4H1JNm6d/P
         hD4Zwr2xeBUs6xl5DaST0Yw+tVwSPpf/MbY7h70QflGz/PBwMxwpkySb/7+sunSnjghl
         mHyo+YKVjcoCfYapCwbsRG0aG4F4M5jsEjkuz2PAJpz9gd+cHYxJmGGfSYYwZM9qQH3Y
         hmv49P/4LgdaBwuIfvqZ7g+wQUwIZ7IXIZYNLaJkdJADnc9MAfTqL8R4d0vjWSb0qv9o
         Z0Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YB4wH/pNDNAtbMu514gttgjLc21/I9fpifSVku4po9o=;
        b=VKoVag0r+gP5ruNhUswvkcRaE6w62AZPrRzJi6nWyhq957l3FGm5lwM2dgFn88p7j5
         U7thkOiig7TqwTfy2SijwB4oY/GNrarzISTVnh2u6iDtvQIVJxCQohQOjhjrUSMneX90
         BWae3KIMwPmEj5i6COmwSuwa69wreu9O3FdD8ibyA2sQsFp7EUBqq+TZ/sKbTB66tkvp
         nqKg/y1+woRnBVw8jkexvLU5/FmPcqrEDnjtmQiR2cMlB2vih6nMlq0BSveZIBoyxO7z
         Zk9OgaFJXfkz3g0ro4oCpugiYkfrIKZrFTLvvwjjX4Out3pwpwvo2bYFoJXojSj7o4nz
         Fkbw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUsINhm6CJ96UieN/+E2ymXhC6kjFOPiIkYFqbEHan2pjJs2WaV
	dGGg6N8QR63iogUgUYNvobU=
X-Google-Smtp-Source: APXvYqxGHjjP2LEOMXcV/fEBUqsxzMrHFBhDnjf/yXaIMHWRNRY47BeSU6UYpukeSmQppsFntrgnJg==
X-Received: by 2002:a05:6830:120c:: with SMTP id r12mr3761711otp.327.1575485115728;
        Wed, 04 Dec 2019 10:45:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:60de:: with SMTP id b30ls126098otk.0.gmail; Wed, 04 Dec
 2019 10:45:15 -0800 (PST)
X-Received: by 2002:a9d:6419:: with SMTP id h25mr3672673otl.267.1575485115292;
        Wed, 04 Dec 2019 10:45:15 -0800 (PST)
Date: Wed, 4 Dec 2019 10:45:14 -0800 (PST)
From: deepthi.sales15@gmail.com
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <d44487db-c375-40f5-a6aa-cd45aa0e5c2e@googlegroups.com>
Subject: Direct client requirement Salesforce Lightning Developer
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_1530_345342590.1575485114654"
X-Original-Sender: deepthi.sales15@gmail.com
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

------=_Part_1530_345342590.1575485114654
Content-Type: multipart/alternative; 
	boundary="----=_Part_1531_2102355106.1575485114654"

------=_Part_1531_2102355106.1575485114654
Content-Type: text/plain; charset="UTF-8"

Hi,

Please find the below requirement. If you are comfortable with the 
requirement send me your updated profile.

Job Title: Salesforce Lightning Developer  
Location: Springfield MA 
Duration: Long Term
Visa: H1B/GC EAD/GC/USC

- Strong Salesforce experience (and certifications)
- Lightning administration and development experience
- Experience integrating Salesforce with external systems and data sources
- Sales Cloud, Service Cloud & Knowledge experience
- Experience with Agile/Scrum software development, DevOps and the 
financial services industry

Please send profiles to deepthi@webilent.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d44487db-c375-40f5-a6aa-cd45aa0e5c2e%40googlegroups.com.

------=_Part_1531_2102355106.1575485114654
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div><font face=3D"Times New Roman, serif"><span style=3D"=
font-size: 16px;">Hi,</span></font></div><div><font face=3D"Times New Roman=
, serif"><span style=3D"font-size: 16px;"><br></span></font></div><div><fon=
t face=3D"Times New Roman, serif"><span style=3D"font-size: 16px;">Please f=
ind the below requirement. If you are comfortable with the requirement send=
 me your updated profile.</span></font></div><div><font face=3D"Times New R=
oman, serif"><span style=3D"font-size: 16px;"><br></span></font></div><div>=
<font face=3D"Times New Roman, serif"><span style=3D"font-size: 16px;">Job =
Title: Salesforce Lightning Developer=C2=A0=C2=A0</span></font></div><div><=
font face=3D"Times New Roman, serif"><span style=3D"font-size: 16px;">Locat=
ion: Springfield MA=C2=A0</span></font></div><div><font face=3D"Times New R=
oman, serif"><span style=3D"font-size: 16px;">Duration: Long Term</span></f=
ont></div><div><font face=3D"Times New Roman, serif"><span style=3D"font-si=
ze: 16px;">Visa: H1B/GC EAD/GC/USC</span></font></div><div><font face=3D"Ti=
mes New Roman, serif"><span style=3D"font-size: 16px;"><br></span></font></=
div><div><font face=3D"Times New Roman, serif"><span style=3D"font-size: 16=
px;">- Strong Salesforce experience (and certifications)</span></font></div=
><div><font face=3D"Times New Roman, serif"><span style=3D"font-size: 16px;=
">- Lightning administration and development experience</span></font></div>=
<div><font face=3D"Times New Roman, serif"><span style=3D"font-size: 16px;"=
>- Experience integrating Salesforce with external systems and data sources=
</span></font></div><div><font face=3D"Times New Roman, serif"><span style=
=3D"font-size: 16px;">- Sales Cloud, Service Cloud &amp; Knowledge experien=
ce</span></font></div><div><font face=3D"Times New Roman, serif"><span styl=
e=3D"font-size: 16px;">- Experience with Agile/Scrum software development, =
DevOps and the financial services industry</span></font></div><div><font fa=
ce=3D"Times New Roman, serif"><span style=3D"font-size: 16px;"><br></span><=
/font></div><div><font face=3D"Times New Roman, serif"><span style=3D"font-=
size: 16px;">Please send profiles to deepthi@webilent.com</span></font></di=
v></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/d44487db-c375-40f5-a6aa-cd45aa0e5c2e%40googlegroups.co=
m?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid=
/kasan-dev/d44487db-c375-40f5-a6aa-cd45aa0e5c2e%40googlegroups.com</a>.<br =
/>

------=_Part_1531_2102355106.1575485114654--

------=_Part_1530_345342590.1575485114654--
