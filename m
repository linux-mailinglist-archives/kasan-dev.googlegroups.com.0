Return-Path: <kasan-dev+bncBDA2XNWCVILRBR7QRHDAMGQEPDI6UTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x39.google.com (mail-oa1-x39.google.com [IPv6:2001:4860:4864:20::39])
	by mail.lfdr.de (Postfix) with ESMTPS id 09DF8B529BE
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 09:20:41 +0200 (CEST)
Received: by mail-oa1-x39.google.com with SMTP id 586e51a60fabf-3282ac80fe7sf617146fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Sep 2025 00:20:40 -0700 (PDT)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757575239; x=1758180039; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lzldI8RYgUfs+7w7kmY8VzbgdgA3BOnhrVPW7NkoXIg=;
        b=iVjB1UrK372rydhg0s2FURC3CP3M7qy4SvxktPxWrQz0iS6CeJWmm2nCUcBerrXn7e
         VlqLBTZ8tarwDPtseJvIsNf48uiMbybRfD2O8huPPN/yjrVm1I4nElEQ4IgIhWtW1CY8
         akh9u7JxJQWjqPo0W6rxN02kUj6LKjeA2iRKmqA7JJN3RSy0Da3rqYeMyPV0TB9qcGGY
         q2FqRGaeVWh1MbKKqv30sWidXNxxPpFkheHccFMgoKIcRn0mqgLFClAn+x3s+00BkxvU
         pDhoPv3dnfLuxfvscb0RBh+TZSG3o+di4wCw0VfQq33kOsHzp4xtBmreQmqcgr1iFtp3
         dzEg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757575240; x=1758180040; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-sender:mime-version
         :subject:message-id:to:from:date:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lzldI8RYgUfs+7w7kmY8VzbgdgA3BOnhrVPW7NkoXIg=;
        b=ULTi+bphY6M0n/oA1j8sca8GZ34Mgxr/JVVE+NRnb7gV2s2n5gTrIEp3nnHvF479Hb
         3d+eZK7zEAnllfrDelLnDL1TyLFO4XVx40N8ZsXkmiJtJSyqUDPqxcn3LYqnT9d23RXr
         +wK3Ov2MFFe152dgNRES/NNxzB+sBrgTqAIxniTs5RfrnSFCqMi9XebgFOnGDJI9q6o0
         rnrflCvnnnYXQbvVYF/n7LVkzNamhal98W59U01oOvZlNlwyo2SjIgZlUdvSJ9zXd90a
         gigP90xJA5v/uCTv19BHfEAy+aJCTZI0IYT3GVd2xwWN9xgvYV80gtpH6Tt6/7zX1AYr
         3noA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757575240; x=1758180040;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-sender:mime-version:subject:message-id:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lzldI8RYgUfs+7w7kmY8VzbgdgA3BOnhrVPW7NkoXIg=;
        b=iRIIlBOKCaRcDJsczNL8vjH5Al50hxqsuaK4gzJi5JxR9ul3kMiluaQ4sUI6cNgq8R
         7niLFZZHu8uVWqF4YkgmpvaeVeiDlGxFvY3MoaWgIA5HeUVrSszbgfD9mB4NUMsbaTHt
         NR+quxX41+AOFA0ajqfCnaDPZp0qBx3hU++7/EUpwqqfr8VhUBWMJZo7g/lS+y3itFw1
         05WMn3ZVrUlpAOJGpUHNc/KjVGieU6Sdyvsbh71DHmGx43BkxysXyGcOxlRQOalB7ioC
         PEbz9fb061xuR9dAY0tRmUDZ2OthjWuF0mcC1KXXAiG29FS3SoFUjLykwd8FgNeSpW52
         BWJA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=1; AJvYcCXmz/fHYUDhbGtGw2oAz5h1F6CxQA4ihtGIOvGG2aM0r8R2zDEU3oihwtT5vhM6+mX5WSDGWQ==@lfdr.de
X-Gm-Message-State: AOJu0YywEkrPdoMi0wYN64fJEIlMcKnhMN79Xke9GtKr+12G0VTTgP5D
	0mt8RzyW+jtL5rQeFSR1KzRpTTYhb7v8ug/4TkTRmkBG1G5c2bQDb9qp
X-Google-Smtp-Source: AGHT+IH/ho15xe4nV2/oVklG7lB6fM7KX+apFi40u4Ek3DBL1T9/K1X4+UKfDdLxGkTBh/MpED6NuA==
X-Received: by 2002:a05:6870:d294:b0:314:9684:fe12 with SMTP id 586e51a60fabf-32265a1da28mr9794127fac.45.1757575239655;
        Thu, 11 Sep 2025 00:20:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5n4f0ctbUEKUfjP8QGhDZVEE8Is92bXQS/WmbF5GdMPQ==
Received: by 2002:a05:6871:330f:b0:31e:1dff:4875 with SMTP id
 586e51a60fabf-32d055d8097ls244578fac.2.-pod-prod-09-us; Thu, 11 Sep 2025
 00:20:38 -0700 (PDT)
X-Received: by 2002:a05:6808:4482:b0:438:3621:1bc5 with SMTP id 5614622812f47-43b299fe4c9mr7529553b6e.4.1757575238692;
        Thu, 11 Sep 2025 00:20:38 -0700 (PDT)
Date: Thu, 11 Sep 2025 00:20:37 -0700 (PDT)
From: =?UTF-8?B?2LPZitiv2Kkg2KzYr9ipINin2YTYs9i52YjYr9mK2Kk=?=
 <memosksaa@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <786188ec-ad7d-4bf7-a23f-32e8940ee1ddn@googlegroups.com>
Subject: =?UTF-8?B?2YHZiiAzINiu2LfZiNin2Kog2YHZiiDYp9mE2LHZitin2LYg4oGJ?=
 =?UTF-8?B?77iPMDUzMTYwMTk2NyDigYnvuI8g2LPYp9mK2KrZiNiq2YMg?=
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_135132_758248594.1757575237427"
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

------=_Part_135132_758248594.1757575237427
Content-Type: multipart/alternative; 
	boundary="----=_Part_135133_1617308019.1757575237427"

------=_Part_135133_1617308019.1757575237427
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
2YYg2KfZhNiu2LXZiNi12YrYqSDYqNin2YTYqtmI2LXZitmEINin2YTYs9ix2YrYuSAKCi0tIApZ
b3UgcmVjZWl2ZWQgdGhpcyBtZXNzYWdlIGJlY2F1c2UgeW91IGFyZSBzdWJzY3JpYmVkIHRvIHRo
ZSBHb29nbGUgR3JvdXBzICJrYXNhbi1kZXYiIGdyb3VwLgpUbyB1bnN1YnNjcmliZSBmcm9tIHRo
aXMgZ3JvdXAgYW5kIHN0b3AgcmVjZWl2aW5nIGVtYWlscyBmcm9tIGl0LCBzZW5kIGFuIGVtYWls
IHRvIGthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tLgpUbyB2aWV3IHRoaXMg
ZGlzY3Vzc2lvbiB2aXNpdCBodHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4t
ZGV2Lzc4NjE4OGVjLWFkN2QtNGJmNy1hMjNmLTMyZTg5NDBlZTFkZG4lNDBnb29nbGVncm91cHMu
Y29tLgo=
------=_Part_135133_1617308019.1757575237427
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
 baseline; white-space-collapse: preserve;">=C2=A0</span></p><br />

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/786188ec-ad7d-4bf7-a23f-32e8940ee1ddn%40googlegroups.com?utm_medi=
um=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev=
/786188ec-ad7d-4bf7-a23f-32e8940ee1ddn%40googlegroups.com</a>.<br />

------=_Part_135133_1617308019.1757575237427--

------=_Part_135132_758248594.1757575237427--
