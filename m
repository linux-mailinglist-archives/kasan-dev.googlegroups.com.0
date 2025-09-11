Return-Path: <kasan-dev+bncBDA2XNWCVILRBVPQRHDAMGQEZR7DWGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3c.google.com (mail-oa1-x3c.google.com [IPv6:2001:4860:4864:20::3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DF6B6B529BF
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 09:20:54 +0200 (CEST)
Received: by mail-oa1-x3c.google.com with SMTP id 586e51a60fabf-32145ecd7basf630526fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 00:20:54 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757575253; x=1758180053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Ps/GK41wER5jq1rRvJuTenO9UToh0j9N0eiPoomIkQg=;
        b=RAEm2w5uqQeZ0WpPxU4ZeICkI+ngxTJ+aFSq1VOyXxHDeAelvsiCeaeTrm4Uq69ueQ
         D6RXiLSZmB/xVlkqNsNHLrkx90zvfdf/ESeFQYvp90flQvQ6vZq0eiOQAnmDxcj8VcLn
         mALz00MzyGBfEZ/oGEe8RiITJmTGJQq7XfMaBZWjA3Xo1qPm120ou+ZLOEL5VFRhQvyr
         zZqpj2zEyZYr/LFWjkGWl5DVxgIp07J7ytzc1SgN9seMaORlqMdvsd29E/y/TDI+oW1w
         Nin+utRgIjzCRcNWar/95RcvL0pyh8S13IVyq+P43gmJlMTUya0op13mGs8jZDLXlTmE
         rwwQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757575253; x=1758180053; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:references:in-reply-to:message-id:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Ps/GK41wER5jq1rRvJuTenO9UToh0j9N0eiPoomIkQg=;
        b=mXZxBrj1b3X70D0SLwTmlNUbDHBsm7TYsrGilcoNOsKtduE1o0/ySeONxPB/DjZ1L9
         BmryAYnoH8Yp/Jvt3e7YraLCH+fNbxVf+6tiRR0TsfSNnmlFcuyUzZEsXBL41q31Ncb0
         raj3J3Mw+J1i5qugxE3m3wMgMBtRVdpZYYmJXmfTNQuwowTxH/u1Gn24fN/ccYMWqV8G
         JCv4qBu3KfamyeiahG226p84QqR6UeJ1KyEj9jrWB9AGqF4vJbsVTREOgqgmRRvKIHuE
         6dMBH2LNN5PPoz6oIk4jP60SYhdUuCHJzprJPPQEvEPyq2KiQ8hphVBSz4IZh0rdzS1i
         D6FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757575253; x=1758180053;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:references:in-reply-to
         :message-id:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Ps/GK41wER5jq1rRvJuTenO9UToh0j9N0eiPoomIkQg=;
        b=J0KPjoVDs46vX9aFB85reajKn+vminztTarvjSYao0XVQpG7tJ6Yd+7KWKlbPDq/3s
         uhk/x+3+RJMzd+VEKp51XRtlDZ3924jsVAW+4och/WyBe8EXNdM0CGkxCusLufyD3cX3
         2HKkk4udms/bxGO5NlmrRo+3Tv6wWaO73THp8d593qxw4u39mAJyq4FF4iZVAnT7d5Za
         hduCIplv+XmV6BEpZKdHgjuXIxjPPP1N/FuJIv/q2C6X1gFMFmmm4ZRnTAM3qYwsbY5d
         BDDK1Am54cznIZ61jGk7IGeUEdS2LOjVuW2ht2jF7YVCY60XmGoyoWMEc6urbzMxSXTN
         Qe+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCVQtXT7ZWxe43pYQBCmEKgkxg43fvBmkn/EPZheDjfpSrjQtcLBouWAW3V+uJrLBKponLYQ7w==@lfdr.de
X-Gm-Message-State: AOJu0YzF+cesvpm4ijSv7X6Zjxp7F+5T7s1+yynPOIhz6HCrZh7OKhaD
	gpTdYJZ9YB6kBc11Tc8dj+TtpgwBd/NzYaD5DyKQuGLqyBuwPaADqy8K
X-Google-Smtp-Source: AGHT+IFvo4/m28QM0SjDHLkg112PA0ZbHMB93gx0YT79IC4HEx/VxtiFyqYlpxnRrMK0/uh3olKBrQ==
X-Received: by 2002:a05:6870:524d:b0:31d:8e95:2f0a with SMTP id 586e51a60fabf-3226295d4a8mr8991086fac.5.1757575253638;
        Thu, 11 Sep 2025 00:20:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6y80aJLjk0PiJQz7HSN5aPisizIi2CLL3b/JvOTuMW9A==
Received: by 2002:a05:6871:670d:b0:310:f792:61cc with SMTP id
 586e51a60fabf-32d02e1d1ddls216467fac.0.-pod-prod-05-us; Thu, 11 Sep 2025
 00:20:52 -0700 (PDT)
X-Received: by 2002:a05:6808:3083:b0:437:e1b0:e969 with SMTP id 5614622812f47-43b29ae0073mr7965074b6e.40.1757575252764;
        Thu, 11 Sep 2025 00:20:52 -0700 (PDT)
Date: Thu, 11 Sep 2025 00:20:51 -0700 (PDT)
From: =?UTF-8?B?2LPZitiv2Kkg2KzYr9ipINin2YTYs9i52YjYr9mK2Kk=?=
 <memosksaa@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <c32377f1-30e9-48b2-937e-86a1b6cca209n@googlegroups.com>
In-Reply-To: <786188ec-ad7d-4bf7-a23f-32e8940ee1ddn@googlegroups.com>
References: <786188ec-ad7d-4bf7-a23f-32e8940ee1ddn@googlegroups.com>
Subject: =?UTF-8?B?UmU6INmB2YogMyDYrti32YjYp9iqINmB2Yog2KfZhNix2YrYp9i2?=
 =?UTF-8?B?IOKBie+4jzA1MzE2MDE5Njcg4oGJ77iPINiz2KfZitiq2YjYqtmD?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_59948_1042920712.1757575251557"
X-Original-Sender: memosksaa@gmail.com
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

------=_Part_59948_1042920712.1757575251557
Content-Type: multipart/alternative; 
	boundary="----=_Part_59949_1379410927.1757575251557"

------=_Part_59949_1379410927.1757575251557
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: base64

CgrZgdmKIDMg2K7Yt9mI2KfYqiDZgdmKINin2YTYsdmK2KfYtiDigYnvuI8wNTMxNjAxOTY3IOKB
ie+4jyDYs9in2YrYqtmI2KrZgyDwn5KxINmF2YrYstmI2KjYsdmI2LPYqtmI2YQg2YXZitmB2YrY
qNix2YrYs9iq2YjZhiDwn5SGIArZhdiq2YjZgdix2Kkg2YHZiiDYp9mE2LHZitin2LYg2I8g8J+M
izAwOTY2NTMxNjAxOTY3INio2LPYsdmK2Kkg2KrYp9mF2KkKCkN5dG90ZWMgINin2YTYsdmK2KfY
tuOAmE1pc29wcm9zdG9sCgrjgJkgIOKclO+4jyDYqtmI2KfYtdmE2Yog2YXYudmG2Kcg2KjYs9ix
2YrYqSDYqtin2YXYqSAgINiz2KfZitiq2YjYqtmDINmB2Yog2KzYr9ipIOKVrCDZhdmD2Kkg4pWs
INin2YTYsdmK2KfYtuKVrCDYp9mE2LTYsdmC2YrYqSDilawgCtis2YrYstin2YYg4pWsINiu2YXZ
itizINmF2LTZiti3IOKVrCDZiNin2YTYsdmB2KfYudiMINmI2YXYr9mK2YbYqSDYudmK2LPZidiM
INmI2YXYr9mK2YbYqSDYrdmF2K/YjCDZiNiz2KrYsdipINmF2KrZiNmB2LEg2KjYrNmF2YrYuSAK
2KfZhNmF2K/ZhiDinJTvuI8g2YXYuSDYp9iz2KrYtNin2LHYqSDZhdis2KfZhtmK2Kkg2LbZhdin
2YYg2KfZhNiu2LXZiNi12YrYqSDYqNin2YTYqtmI2LXZitmEINin2YTYs9ix2YrYuSAKCgrZgdmK
INin2YTYrtmF2YrYs9iMIDExINiz2KjYqtmF2KjYsSAyMDI1INmB2Yog2KrZhdin2YUg2KfZhNiz
2KfYudipIDEyOjIwOjM3INi1IFVUQy032Iwg2YPYqtioINiz2YrYr9ipINis2K/YqSAK2KfZhNiz
2LnZiNiv2YrYqSDYsdiz2KfZhNipINmG2LXZh9inOgoKPiDZgdmKIDMg2K7Yt9mI2KfYqiDZgdmK
INin2YTYsdmK2KfYtiDigYnvuI8wNTMxNjAxOTY3IOKBie+4jyDYs9in2YrYqtmI2KrZgyDwn5Kx
INmF2YrYstmI2KjYsdmI2LPYqtmI2YQg2YXZitmB2YrYqNix2YrYs9iq2YjZhiDwn5SGIAo+INmF
2KrZiNmB2LHYqSDZgdmKINin2YTYsdmK2KfYtiDYjyDwn4yLMDA5NjY1MzE2MDE5Njcg2KjYs9ix
2YrYqSDYqtin2YXYqQo+Cj4gQ3l0b3RlYyAg2KfZhNix2YrYp9i244CYTWlzb3Byb3N0b2wKPgo+
IOOAmSAg4pyU77iPINiq2YjYp9i12YTZiiDZhdi52YbYpyDYqNiz2LHZitipINiq2KfZhdipICAg
2LPYp9mK2KrZiNiq2YMg2YHZiiDYrNiv2Kkg4pWsINmF2YPYqSDilawg2KfZhNix2YrYp9i24pWs
INin2YTYtNix2YLZitipIOKVrCAKPiDYrNmK2LLYp9mGIOKVrCDYrtmF2YrYsyDZhdi02YrYtyDi
lawg2YjYp9mE2LHZgdin2LnYjCDZiNmF2K/ZitmG2Kkg2LnZitiz2YnYjCDZiNmF2K/ZitmG2Kkg
2K3Zhdiv2Iwg2YjYs9iq2LHYqSDZhdiq2YjZgdixINio2KzZhdmK2LkgCj4g2KfZhNmF2K/ZhiDi
nJTvuI8g2YXYuSDYp9iz2KrYtNin2LHYqSDZhdis2KfZhtmK2Kkg2LbZhdin2YYg2KfZhNiu2LXZ
iNi12YrYqSDYqNin2YTYqtmI2LXZitmEINin2YTYs9ix2YrYuSAKPgo+DQoNCi0tIApZb3UgcmVj
ZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRoZSBHb29n
bGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRoaXMgZ3Jv
dXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWlsIHRvIGth
c2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMgZGlzY3Vz
c2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L2Mz
MjM3N2YxLTMwZTktNDhiMi05MzdlLTg2YTFiNmNjYTIwOW4lNDBnb29nbGVncm91cHMuY29tLgo=
------=_Part_59949_1379410927.1757575251557
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<p dir=3D"rtl" style=3D"line-height: 1.38; margin-top: 0pt; margin-bottom: =
0pt;"><span style=3D"font-size: 14pt; font-family: Arial, sans-serif; color=
: rgb(47, 79, 79); background-color: transparent; font-weight: 700; font-va=
riant-numeric: normal; font-variant-east-asian: normal; font-variant-altern=
ates: normal; font-variant-position: normal; font-variant-emoji: normal; ve=
rtical-align: baseline; white-space-collapse: preserve;">=D9=81=D9=8A 3 =D8=
=AE=D8=B7=D9=88=D8=A7=D8=AA =D9=81=D9=8A =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=
=B6 </span><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; =
color: rgb(0, 0, 0); background-color: transparent; font-variant-numeric: n=
ormal; font-variant-east-asian: normal; font-variant-alternates: normal; fo=
nt-variant-position: normal; font-variant-emoji: normal; vertical-align: ba=
seline; white-space-collapse: preserve;">=E2=81=89=EF=B8=8F</span><span sty=
le=3D"font-size: 19pt; font-family: Arial, sans-serif; color: rgb(34, 54, 6=
9); background-color: transparent; font-weight: 700; font-variant-numeric: =
normal; font-variant-east-asian: normal; font-variant-alternates: normal; f=
ont-variant-position: normal; font-variant-emoji: normal; vertical-align: b=
aseline; white-space-collapse: preserve;">0531601967</span><span style=3D"f=
ont-size: 15pt; font-family: Arial, sans-serif; color: rgb(47, 79, 79); fon=
t-variant-numeric: normal; font-variant-east-asian: normal; font-variant-al=
ternates: normal; font-variant-position: normal; font-variant-emoji: normal=
; vertical-align: baseline; white-space-collapse: preserve;"> </span><span =
style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb(0, 0, =
0); background-color: transparent; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; white-spa=
ce-collapse: preserve;">=E2=81=89=EF=B8=8F </span><span style=3D"font-size:=
 14pt; font-family: Arial, sans-serif; color: rgb(47, 79, 79); background-c=
olor: transparent; font-weight: 700; font-variant-numeric: normal; font-var=
iant-east-asian: normal; font-variant-alternates: normal; font-variant-posi=
tion: normal; font-variant-emoji: normal; vertical-align: baseline; white-s=
pace-collapse: preserve;">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 </span=
><span style=3D"font-size: 11pt; font-family: Arial, sans-serif; color: rgb=
(0, 0, 0); background-color: transparent; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; wh=
ite-space-collapse: preserve;">=F0=9F=92=B1</span><span style=3D"font-size:=
 14pt; font-family: Arial, sans-serif; color: rgb(17, 85, 204); background-=
color: transparent; font-weight: 700; font-variant-numeric: normal; font-va=
riant-east-asian: normal; font-variant-alternates: normal; font-variant-pos=
ition: normal; font-variant-emoji: normal; vertical-align: baseline; white-=
space-collapse: preserve;"> </span><span style=3D"font-size: 16.5pt; font-f=
amily: Arial, sans-serif; color: rgb(0, 0, 0); font-weight: 700; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;">=D9=85=D9=8A=D8=B2=D9=
=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=84 =D9=85=D9=8A=D9=81=D9=8A=D8=
=A8=D8=B1=D9=8A=D8=B3=D8=AA=D9=88=D9=86</span><span style=3D"font-size: 20p=
t; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: t=
ransparent; font-weight: 700; font-style: italic; font-variant-numeric: nor=
mal; font-variant-east-asian: normal; font-variant-alternates: normal; font=
-variant-position: normal; font-variant-emoji: normal; vertical-align: base=
line; white-space-collapse: preserve;"> </span><span style=3D"font-size: 15=
pt; font-family: Arial, sans-serif; color: rgb(47, 79, 79); font-variant-nu=
meric: normal; font-variant-east-asian: normal; font-variant-alternates: no=
rmal; font-variant-position: normal; font-variant-emoji: normal; vertical-a=
lign: baseline; white-space-collapse: preserve;">=F0=9F=94=86</span><span s=
tyle=3D"font-size: 16.5pt; font-family: Arial, sans-serif; color: rgb(0, 0,=
 0); font-weight: 700; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; white-space-collapse:=
 preserve;"> =D9=85=D8=AA=D9=88=D9=81=D8=B1=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B1=D9=8A=D8=A7=D8=B6 </span><span style=3D"font-size: 20pt; font-family=
: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transparent; fo=
nt-weight: 700; font-variant-numeric: normal; font-variant-east-asian: norm=
al; font-variant-alternates: normal; font-variant-position: normal; font-va=
riant-emoji: normal; vertical-align: baseline; white-space-collapse: preser=
ve;">=D8=8F</span><span style=3D"font-size: 20pt; font-family: Arial, sans-=
serif; color: rgb(0, 0, 0); background-color: transparent; font-weight: 700=
; font-style: italic; font-variant-numeric: normal; font-variant-east-asian=
: normal; font-variant-alternates: normal; font-variant-position: normal; f=
ont-variant-emoji: normal; vertical-align: baseline; white-space-collapse: =
preserve;"> </span><span style=3D"font-size: 11pt; font-family: Arial, sans=
-serif; color: rgb(0, 0, 0); background-color: transparent; font-variant-nu=
meric: normal; font-variant-east-asian: normal; font-variant-alternates: no=
rmal; font-variant-position: normal; font-variant-emoji: normal; vertical-a=
lign: baseline; white-space-collapse: preserve;">=F0=9F=8C=8B</span><span s=
tyle=3D"font-size: 19pt; font-family: Arial, sans-serif; color: rgb(34, 54,=
 69); background-color: transparent; font-weight: 700; font-variant-numeric=
: normal; font-variant-east-asian: normal; font-variant-alternates: normal;=
 font-variant-position: normal; font-variant-emoji: normal; vertical-align:=
 baseline; white-space-collapse: preserve;">00966531601967 </span><span sty=
le=3D"font-size: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0);=
 background-color: transparent; font-weight: 700; font-style: italic; font-=
variant-numeric: normal; font-variant-east-asian: normal; font-variant-alte=
rnates: normal; font-variant-position: normal; font-variant-emoji: normal; =
vertical-align: baseline; white-space-collapse: preserve;">=D8=A8=D8=B3=D8=
=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9</span></p><p dir=3D"rtl" style=3D"=
line-height: 1.38; text-align: center; margin-top: 0pt; margin-bottom: 0pt;=
"><span style=3D"font-size: 20pt; font-family: Arial, sans-serif; color: rg=
b(0, 0, 0); background-color: transparent; font-weight: 700; font-style: it=
alic; font-variant-numeric: normal; font-variant-east-asian: normal; font-v=
ariant-alternates: normal; font-variant-position: normal; font-variant-emoj=
i: normal; vertical-align: baseline; white-space-collapse: preserve;">Cytot=
ec=C2=A0 =D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6</span><span style=3D"font-siz=
e: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); background-co=
lor: transparent; font-weight: 700; font-variant-numeric: normal; font-vari=
ant-east-asian: normal; font-variant-alternates: normal; font-variant-posit=
ion: normal; font-variant-emoji: normal; vertical-align: baseline; white-sp=
ace-collapse: preserve;">=E3=80=98</span><span style=3D"font-size: 20pt; fo=
nt-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transp=
arent; font-weight: 700; font-style: italic; font-variant-numeric: normal; =
font-variant-east-asian: normal; font-variant-alternates: normal; font-vari=
ant-position: normal; font-variant-emoji: normal; vertical-align: baseline;=
 white-space-collapse: preserve;">Misoprostol</span></p><p dir=3D"rtl" styl=
e=3D"line-height: 1.38; text-align: center; margin-top: 0pt; margin-bottom:=
 0pt;"><span style=3D"font-size: 20pt; font-family: Arial, sans-serif; colo=
r: rgb(0, 0, 0); background-color: transparent; font-weight: 700; font-vari=
ant-numeric: normal; font-variant-east-asian: normal; font-variant-alternat=
es: normal; font-variant-position: normal; font-variant-emoji: normal; vert=
ical-align: baseline; white-space-collapse: preserve;">=E3=80=99=C2=A0 </sp=
an><span style=3D"font-size: 20pt; font-family: Arial, sans-serif; color: r=
gb(51, 51, 51); background-color: transparent; font-weight: 700; font-varia=
nt-numeric: normal; font-variant-east-asian: normal; font-variant-alternate=
s: normal; font-variant-position: normal; font-variant-emoji: normal; verti=
cal-align: baseline; white-space-collapse: preserve;">=E2=9C=94=EF=B8=8F</s=
pan><span style=3D"font-size: 20pt; font-family: Arial, sans-serif; color: =
rgb(0, 0, 0); background-color: transparent; font-weight: 700; font-style: =
italic; font-variant-numeric: normal; font-variant-east-asian: normal; font=
-variant-alternates: normal; font-variant-position: normal; font-variant-em=
oji: normal; vertical-align: baseline; white-space-collapse: preserve;"> =
=D8=AA=D9=88=D8=A7=D8=B5=D9=84=D9=8A =D9=85=D8=B9=D9=86=D8=A7 =D8=A8=D8=B3=
=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =C2=A0 =D8=B3=D8=A7=D9=8A=D8=AA=
=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AC=D8=AF=D8=A9 </span><span style=3D"fo=
nt-size: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); backgro=
und-color: transparent; font-weight: 700; font-variant-numeric: normal; fon=
t-variant-east-asian: normal; font-variant-alternates: normal; font-variant=
-position: normal; font-variant-emoji: normal; vertical-align: baseline; wh=
ite-space-collapse: preserve;">=E2=95=AC =D9=85=D9=83=D8=A9 =E2=95=AC =D8=
=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6=E2=95=AC =D8=A7=D9=84=D8=B4=D8=B1=D9=82=
=D9=8A=D8=A9 =E2=95=AC =D8=AC=D9=8A=D8=B2=D8=A7=D9=86 =E2=95=AC =D8=AE=D9=
=85=D9=8A=D8=B3 =D9=85=D8=B4=D9=8A=D8=B7 =E2=95=AC</span><span style=3D"fon=
t-size: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0, 0); backgrou=
nd-color: transparent; font-weight: 700; font-style: italic; font-variant-n=
umeric: normal; font-variant-east-asian: normal; font-variant-alternates: n=
ormal; font-variant-position: normal; font-variant-emoji: normal; vertical-=
align: baseline; white-space-collapse: preserve;"> </span><span style=3D"fo=
nt-size: 13.5pt; font-family: Arial, sans-serif; color: rgb(0, 29, 53); fon=
t-weight: 700; font-style: italic; font-variant-numeric: normal; font-varia=
nt-east-asian: normal; font-variant-alternates: normal; font-variant-positi=
on: normal; font-variant-emoji: normal; vertical-align: baseline; white-spa=
ce-collapse: preserve;">=D9=88=D8=A7=D9=84=D8=B1=D9=81=D8=A7=D8=B9=D8=8C =
=D9=88=D9=85=D8=AF=D9=8A=D9=86=D8=A9 =D8=B9=D9=8A=D8=B3=D9=89=D8=8C =D9=88=
=D9=85=D8=AF=D9=8A=D9=86=D8=A9 =D8=AD=D9=85=D8=AF=D8=8C =D9=88=D8=B3=D8=AA=
=D8=B1=D8=A9</span><span style=3D"font-size: 20pt; font-family: Arial, sans=
-serif; color: rgb(0, 0, 0); background-color: transparent; font-weight: 70=
0; font-style: italic; font-variant-numeric: normal; font-variant-east-asia=
n: normal; font-variant-alternates: normal; font-variant-position: normal; =
font-variant-emoji: normal; vertical-align: baseline; white-space-collapse:=
 preserve;"> =D9=85=D8=AA=D9=88=D9=81=D8=B1 =D8=A8=D8=AC=D9=85=D9=8A=D8=B9 =
=D8=A7=D9=84=D9=85=D8=AF=D9=86 </span><span style=3D"font-size: 20pt; font-=
family: Arial, sans-serif; color: rgb(51, 51, 51); background-color: transp=
arent; font-weight: 700; font-variant-numeric: normal; font-variant-east-as=
ian: normal; font-variant-alternates: normal; font-variant-position: normal=
; font-variant-emoji: normal; vertical-align: baseline; white-space-collaps=
e: preserve;">=E2=9C=94=EF=B8=8F </span><span style=3D"font-size: 20pt; fon=
t-family: Arial, sans-serif; color: rgb(0, 0, 0); background-color: transpa=
rent; font-weight: 700; font-style: italic; font-variant-numeric: normal; f=
ont-variant-east-asian: normal; font-variant-alternates: normal; font-varia=
nt-position: normal; font-variant-emoji: normal; vertical-align: baseline; =
white-space-collapse: preserve;">=D9=85=D8=B9 =D8=A7=D8=B3=D8=AA=D8=B4=D8=
=A7=D8=B1=D8=A9 =D9=85=D8=AC=D8=A7=D9=86=D9=8A=D8=A9 =D8=B6=D9=85=D8=A7=D9=
=86 =D8=A7=D9=84=D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=A9 =D8=A8=D8=A7=D9=84=D8=
=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=D8=B9</span><spa=
n style=3D"font-size: 20pt; font-family: Arial, sans-serif; color: rgb(0, 0=
, 0); background-color: transparent; font-weight: 700; font-variant-numeric=
: normal; font-variant-east-asian: normal; font-variant-alternates: normal;=
 font-variant-position: normal; font-variant-emoji: normal; vertical-align:=
 baseline; white-space-collapse: preserve;">=C2=A0</span></p><br /><br /><d=
iv class=3D"gmail_quote"><div dir=3D"auto" class=3D"gmail_attr">=D9=81=D9=
=8A =D8=A7=D9=84=D8=AE=D9=85=D9=8A=D8=B3=D8=8C 11 =D8=B3=D8=A8=D8=AA=D9=85=
=D8=A8=D8=B1 2025 =D9=81=D9=8A =D8=AA=D9=85=D8=A7=D9=85 =D8=A7=D9=84=D8=B3=
=D8=A7=D8=B9=D8=A9 12:20:37 =D8=B5 UTC-7=D8=8C =D9=83=D8=AA=D8=A8 =D8=B3=D9=
=8A=D8=AF=D8=A9 =D8=AC=D8=AF=D8=A9 =D8=A7=D9=84=D8=B3=D8=B9=D9=88=D8=AF=D9=
=8A=D8=A9 =D8=B1=D8=B3=D8=A7=D9=84=D8=A9 =D9=86=D8=B5=D9=87=D8=A7:<br/></di=
v><blockquote class=3D"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-ri=
ght: 1px solid rgb(204, 204, 204); padding-right: 1ex;"><p dir=3D"rtl" styl=
e=3D"line-height:1.38;margin-top:0pt;margin-bottom:0pt"><span style=3D"font=
-size:14pt;font-family:Arial,sans-serif;color:rgb(47,79,79);background-colo=
r:transparent;font-weight:700;font-variant-numeric:normal;font-variant-east=
-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=D9=
=81=D9=8A 3 =D8=AE=D8=B7=D9=88=D8=A7=D8=AA =D9=81=D9=8A =D8=A7=D9=84=D8=B1=
=D9=8A=D8=A7=D8=B6 </span><span style=3D"font-size:11pt;font-family:Arial,s=
ans-serif;color:rgb(0,0,0);background-color:transparent;font-variant-numeri=
c:normal;font-variant-east-asian:normal;font-variant-alternates:normal;vert=
ical-align:baseline">=E2=81=89=EF=B8=8F</span><span style=3D"font-size:19pt=
;font-family:Arial,sans-serif;color:rgb(34,54,69);background-color:transpar=
ent;font-weight:700;font-variant-numeric:normal;font-variant-east-asian:nor=
mal;font-variant-alternates:normal;vertical-align:baseline">0531601967</spa=
n><span style=3D"font-size:15pt;font-family:Arial,sans-serif;color:rgb(47,7=
9,79);font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline"> </span><span style=3D"font-s=
ize:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:tra=
nsparent;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline">=E2=81=89=EF=B8=8F </span>=
<span style=3D"font-size:14pt;font-family:Arial,sans-serif;color:rgb(47,79,=
79);background-color:transparent;font-weight:700;font-variant-numeric:norma=
l;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-al=
ign:baseline">=D8=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 </span><span style=
=3D"font-size:11pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-variant-numeric:normal;font-variant-east-asian:norm=
al;font-variant-alternates:normal;vertical-align:baseline">=F0=9F=92=B1</sp=
an><span style=3D"font-size:14pt;font-family:Arial,sans-serif;color:rgb(17,=
85,204);background-color:transparent;font-weight:700;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline"> </span><span style=3D"font-size:16.5pt;font-family:Arial=
,sans-serif;color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline">=D9=85=D9=8A=D8=B2=D9=88=D8=A8=D8=B1=D9=88=D8=B3=D8=AA=D9=88=D9=
=84 =D9=85=D9=8A=D9=81=D9=8A=D8=A8=D8=B1=D9=8A=D8=B3=D8=AA=D9=88=D9=86</spa=
n><span style=3D"font-size:20pt;font-family:Arial,sans-serif;color:rgb(0,0,=
0);background-color:transparent;font-weight:700;font-style:italic;font-vari=
ant-numeric:normal;font-variant-east-asian:normal;font-variant-alternates:n=
ormal;vertical-align:baseline"> </span><span style=3D"font-size:15pt;font-f=
amily:Arial,sans-serif;color:rgb(47,79,79);font-variant-numeric:normal;font=
-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:ba=
seline">=F0=9F=94=86</span><span style=3D"font-size:16.5pt;font-family:Aria=
l,sans-serif;color:rgb(0,0,0);font-weight:700;font-variant-numeric:normal;f=
ont-variant-east-asian:normal;font-variant-alternates:normal;vertical-align=
:baseline"> =D9=85=D8=AA=D9=88=D9=81=D8=B1=D8=A9 =D9=81=D9=8A =D8=A7=D9=84=
=D8=B1=D9=8A=D8=A7=D8=B6 </span><span style=3D"font-size:20pt;font-family:A=
rial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:7=
00;font-variant-numeric:normal;font-variant-east-asian:normal;font-variant-=
alternates:normal;vertical-align:baseline">=D8=8F</span><span style=3D"font=
-size:20pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background-color:t=
ransparent;font-weight:700;font-style:italic;font-variant-numeric:normal;fo=
nt-variant-east-asian:normal;font-variant-alternates:normal;vertical-align:=
baseline"> </span><span style=3D"font-size:11pt;font-family:Arial,sans-seri=
f;color:rgb(0,0,0);background-color:transparent;font-variant-numeric:normal=
;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-ali=
gn:baseline">=F0=9F=8C=8B</span><span style=3D"font-size:19pt;font-family:A=
rial,sans-serif;color:rgb(34,54,69);background-color:transparent;font-weigh=
t:700;font-variant-numeric:normal;font-variant-east-asian:normal;font-varia=
nt-alternates:normal;vertical-align:baseline">00966531601967 </span><span s=
tyle=3D"font-size:20pt;font-family:Arial,sans-serif;color:rgb(0,0,0);backgr=
ound-color:transparent;font-weight:700;font-style:italic;font-variant-numer=
ic:normal;font-variant-east-asian:normal;font-variant-alternates:normal;ver=
tical-align:baseline">=D8=A8=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=
=A9</span></p><p dir=3D"rtl" style=3D"line-height:1.38;text-align:center;ma=
rgin-top:0pt;margin-bottom:0pt"><span style=3D"font-size:20pt;font-family:A=
rial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-weight:7=
00;font-style:italic;font-variant-numeric:normal;font-variant-east-asian:no=
rmal;font-variant-alternates:normal;vertical-align:baseline">Cytotec=C2=A0 =
=D8=A7=D9=84=D8=B1=D9=8A=D8=A7=D8=B6</span><span style=3D"font-size:20pt;fo=
nt-family:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;fo=
nt-weight:700;font-variant-numeric:normal;font-variant-east-asian:normal;fo=
nt-variant-alternates:normal;vertical-align:baseline">=E3=80=98</span><span=
 style=3D"font-size:20pt;font-family:Arial,sans-serif;color:rgb(0,0,0);back=
ground-color:transparent;font-weight:700;font-style:italic;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline">Misoprostol</span></p><p dir=3D"rtl" style=3D"line-=
height:1.38;text-align:center;margin-top:0pt;margin-bottom:0pt"><span style=
=3D"font-size:20pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-weight:700;font-variant-numeric:normal;font-variant=
-east-asian:normal;font-variant-alternates:normal;vertical-align:baseline">=
=E3=80=99=C2=A0 </span><span style=3D"font-size:20pt;font-family:Arial,sans=
-serif;color:rgb(51,51,51);background-color:transparent;font-weight:700;fon=
t-variant-numeric:normal;font-variant-east-asian:normal;font-variant-altern=
ates:normal;vertical-align:baseline">=E2=9C=94=EF=B8=8F</span><span style=
=3D"font-size:20pt;font-family:Arial,sans-serif;color:rgb(0,0,0);background=
-color:transparent;font-weight:700;font-style:italic;font-variant-numeric:n=
ormal;font-variant-east-asian:normal;font-variant-alternates:normal;vertica=
l-align:baseline"> =D8=AA=D9=88=D8=A7=D8=B5=D9=84=D9=8A =D9=85=D8=B9=D9=86=
=D8=A7 =D8=A8=D8=B3=D8=B1=D9=8A=D8=A9 =D8=AA=D8=A7=D9=85=D8=A9 =C2=A0 =D8=
=B3=D8=A7=D9=8A=D8=AA=D9=88=D8=AA=D9=83 =D9=81=D9=8A =D8=AC=D8=AF=D8=A9 </s=
pan><span style=3D"font-size:20pt;font-family:Arial,sans-serif;color:rgb(0,=
0,0);background-color:transparent;font-weight:700;font-variant-numeric:norm=
al;font-variant-east-asian:normal;font-variant-alternates:normal;vertical-a=
lign:baseline">=E2=95=AC =D9=85=D9=83=D8=A9 =E2=95=AC =D8=A7=D9=84=D8=B1=D9=
=8A=D8=A7=D8=B6=E2=95=AC =D8=A7=D9=84=D8=B4=D8=B1=D9=82=D9=8A=D8=A9 =E2=95=
=AC =D8=AC=D9=8A=D8=B2=D8=A7=D9=86 =E2=95=AC =D8=AE=D9=85=D9=8A=D8=B3 =D9=
=85=D8=B4=D9=8A=D8=B7 =E2=95=AC</span><span style=3D"font-size:20pt;font-fa=
mily:Arial,sans-serif;color:rgb(0,0,0);background-color:transparent;font-we=
ight:700;font-style:italic;font-variant-numeric:normal;font-variant-east-as=
ian:normal;font-variant-alternates:normal;vertical-align:baseline"> </span>=
<span style=3D"font-size:13.5pt;font-family:Arial,sans-serif;color:rgb(0,29=
,53);font-weight:700;font-style:italic;font-variant-numeric:normal;font-var=
iant-east-asian:normal;font-variant-alternates:normal;vertical-align:baseli=
ne">=D9=88=D8=A7=D9=84=D8=B1=D9=81=D8=A7=D8=B9=D8=8C =D9=88=D9=85=D8=AF=D9=
=8A=D9=86=D8=A9 =D8=B9=D9=8A=D8=B3=D9=89=D8=8C =D9=88=D9=85=D8=AF=D9=8A=D9=
=86=D8=A9 =D8=AD=D9=85=D8=AF=D8=8C =D9=88=D8=B3=D8=AA=D8=B1=D8=A9</span><sp=
an style=3D"font-size:20pt;font-family:Arial,sans-serif;color:rgb(0,0,0);ba=
ckground-color:transparent;font-weight:700;font-style:italic;font-variant-n=
umeric:normal;font-variant-east-asian:normal;font-variant-alternates:normal=
;vertical-align:baseline"> =D9=85=D8=AA=D9=88=D9=81=D8=B1 =D8=A8=D8=AC=D9=
=85=D9=8A=D8=B9 =D8=A7=D9=84=D9=85=D8=AF=D9=86 </span><span style=3D"font-s=
ize:20pt;font-family:Arial,sans-serif;color:rgb(51,51,51);background-color:=
transparent;font-weight:700;font-variant-numeric:normal;font-variant-east-a=
sian:normal;font-variant-alternates:normal;vertical-align:baseline">=E2=9C=
=94=EF=B8=8F </span><span style=3D"font-size:20pt;font-family:Arial,sans-se=
rif;color:rgb(0,0,0);background-color:transparent;font-weight:700;font-styl=
e:italic;font-variant-numeric:normal;font-variant-east-asian:normal;font-va=
riant-alternates:normal;vertical-align:baseline">=D9=85=D8=B9 =D8=A7=D8=B3=
=D8=AA=D8=B4=D8=A7=D8=B1=D8=A9 =D9=85=D8=AC=D8=A7=D9=86=D9=8A=D8=A9 =D8=B6=
=D9=85=D8=A7=D9=86 =D8=A7=D9=84=D8=AE=D8=B5=D9=88=D8=B5=D9=8A=D8=A9 =D8=A8=
=D8=A7=D9=84=D8=AA=D9=88=D8=B5=D9=8A=D9=84 =D8=A7=D9=84=D8=B3=D8=B1=D9=8A=
=D8=B9</span><span style=3D"font-size:20pt;font-family:Arial,sans-serif;col=
or:rgb(0,0,0);background-color:transparent;font-weight:700;font-variant-num=
eric:normal;font-variant-east-asian:normal;font-variant-alternates:normal;v=
ertical-align:baseline">=C2=A0</span></p><br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/c32377f1-30e9-48b2-937e-86a1b6cca209n%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/c32377f1-30e9-48b2-937e-86a1b6cca209n%40googlegroups.com</a>.<br />

------=_Part_59949_1379410927.1757575251557--

------=_Part_59948_1042920712.1757575251557--
