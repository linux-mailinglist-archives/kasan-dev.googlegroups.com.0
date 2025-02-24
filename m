Return-Path: <kasan-dev+bncBDC7NWVR6EDRBIH46G6QMGQEJGP34CI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id EB605A42287
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2025 15:11:46 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-3093984061esf25024571fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Feb 2025 06:11:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740406306; cv=pass;
        d=google.com; s=arc-20240605;
        b=hMm9BLtCmyejOSIUkOPvjLVnqTjGzNGcK+KijnHbUSAHTVyOo3Q+rDNQkQoJPZkGhw
         LC8VNLWzUxpfqxuN6a2RGfCRsNuFI/roOU2Vk9N6XU2U0tTAeLnRQ1CYUtjs2c9Psq5Q
         KlVs9bqKDdfxf3ld08xIFielKyOjBuWs6hUNZwmkaLIbx56/UMYYMWG3Zxyveemi2NK3
         nZbH2Wo46hjeKd1OfV+XO+9V5g2tLEyDK5KXGHAFpj2qkyvZg+oCmlvQfrCM+6aDOxfK
         A66PHXcukIoUWiIuiefM3pcG7wHBwy5X7sUkIGjJIE7X/IGfvbwOMrKdY7lDuNhrsMcg
         tArQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:mime-version:feedback-id
         :list-unsubscribe-post:list-unsubscribe:message-id:subject:reply-to
         :from:to:date:sender:dkim-signature;
        bh=NF6rrDZPhWQ0v4+iRPnzkBYg33Qdl9rYLR72CshDQ5M=;
        fh=DjUU70Pv0X4TrN5px9M0wT9q/qWav86k505y5nLZkZM=;
        b=WpGRGzRl4cEIr8ybe5bnUqGGCtr/5M9Q4rOmLgDIw4634PEv/+CQROsEb+bKXcxmg0
         xdLwcb1cO3Aht+Nl7Qxyf3hzthBXhgl5U3VNryOzhy3YOwOeZ0yJ4CfmdssEyy/kE40N
         ljnRWbPV7CnKfRbS9OZNR/9wiurjSvO7inShySwgmS6Ajv2tZzcUgsllL3p2dve97sVW
         uO97/LH83tgt3Y2AreTbDFSM7WAQfXBDLsfdRgEnvVL9E+J+OLd1ZjXNqOQeJW2QD1pM
         VPXLmJyrui/Db6FfDBFyUWxii2JDkCNEIZAIx1n2MIz40vQ8+N4OeqxhiNh1Z+dloyH4
         MRoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mailchef.4dem.it header.s=mailchef header.b=oBddkIGX;
       dkim=pass header.i=@fiscozen.it header.s=nwslauth header.b=Mk2cVOA0;
       spf=pass (google.com: domain of bounce-95815784-7662692-22280720-4982744@mailchef.4dem.it designates 176.221.48.107 as permitted sender) smtp.mailfrom=bounce-95815784-7662692-22280720-4982744@mailchef.4dem.it;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fiscozen.it
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740406306; x=1741011106; darn=lfdr.de;
        h=list-subscribe:list-archive:list-help:list-post:list-id
         :mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:feedback-id:list-unsubscribe-post
         :list-unsubscribe:message-id:subject:reply-to:from:to:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NF6rrDZPhWQ0v4+iRPnzkBYg33Qdl9rYLR72CshDQ5M=;
        b=tPrm0WR8lTGynkRR7odMXomJ3NdR+lrGO1qD9RPBqSno1AgQ/4xmwmZcCXxm46DNe8
         q9FMQa+b3LpZ81bdJzIhADSeBqhr3Pm0F00n+hVcbk8fny3MEB2Onl/hzaeRyPCUxlwT
         5VVRYs7YgJHSzY2Knrb7+HnIKaTRJRctuUJ2q6G9DwHB9DwQsz0xzCssm27+A4eAW+Nb
         tsWHS18dGisF2g3IdKz9lUhTUltwy/zzLqkfpaj+Zl2oPpw59n5ecRamPEsbexLfxU5g
         8szqZnBH0zG3vpS7eTgb84CKBmitwtLrq4TbfX5uRHtnHWJnuTebgkZoaHdAeAsBcMfJ
         jtJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740406306; x=1741011106;
        h=list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:list-unsubscribe-post:list-unsubscribe:message-id
         :subject:reply-to:from:to:date:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=NF6rrDZPhWQ0v4+iRPnzkBYg33Qdl9rYLR72CshDQ5M=;
        b=O8OzIrMKd9FzSWOL/1T4s/Euy69RVCUkt+lTMc+1keZBhx1oxGRZ38srMmif5j25A1
         cK0KsrCAY2igHgiZqVsyLDGdeUpZVxInLRjJ/Rn06zOG37d5XeFyOiMt0X1XBqUK2Y8t
         N4RrtBmP1rpJoIGVqIjbKX3+lCgU6M0w9X59mI07HUIxGvmDDUiuJrrQWuhRVI7fKPwK
         owPjrqiXjnaLXg1TJaDQnVXDqoxuCYd/WYyCoit42gLLxDbq/nO8uyyBikY0szA2B0cG
         YvUusqaOn7jHzQcG3VmpOJkjyqguJ/U2CvbOWqYePiTFLdoUr2wGEWylqqnvlXzvL8rv
         6Pug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWa5RUdIBTmzJslSwZGfSsfO0yRgAO3VQjQOQiVlZR8ze8Q4aBbK3EQYlU4UEiObs37AyOjmQ==@lfdr.de
X-Gm-Message-State: AOJu0YznC7vMxPDvlF9dpITruFhxUUwiotQscwrVQIaSYzHkMMvGJE2v
	xXumfgc9fGiA1mZcaEL06UQt7NbAzPFCNhN/8bVgIBfpHkQK42cG
X-Google-Smtp-Source: AGHT+IHJAWmaSAj/E6859STgA/j94vUqPufp6tRb+rqF6ePeqpGc390lE9HEO+UNanlaQ5yR+hxKiw==
X-Received: by 2002:a2e:920a:0:b0:309:2746:f74 with SMTP id 38308e7fff4ca-30a59858ddemr36927121fa.7.1740406305295;
        Mon, 24 Feb 2025 06:11:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHrJEQmc+nJYQTFUqiXN3/4UaTvWtRKq/POtIVt824s6g==
Received: by 2002:a05:651c:b12:b0:309:1c03:d2d7 with SMTP id
 38308e7fff4ca-30a5001468fls1093071fa.2.-pod-prod-08-eu; Mon, 24 Feb 2025
 06:11:42 -0800 (PST)
X-Received: by 2002:a05:6512:110d:b0:53e:383a:639a with SMTP id 2adb3069b0e04-54838f4e402mr5859505e87.37.1740406302463;
        Mon, 24 Feb 2025 06:11:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740406302; cv=none;
        d=google.com; s=arc-20240605;
        b=MO+6SG2d2bH+GMXH9bVgpLX6E0sldrt1YKmlepAdsvOoOErqBZwGYEq9NGPM+I1lAj
         OS7uB/9RZXAY9JYYVyWBzEIBmiaeP+N5GsFU7bb00n/b0sUpzmcg9cWPMF1lMmY1uLP7
         HwWBofyLmJ/LYRfsUo9lR0jqjWJiMc/nBxLQFcYmygtzOa3oRMLxRrfs2VOAwcAJOgSN
         M650UrerBAUr/zbn84hdhmcIiE05In3wPvZb18n5w0R1bU0dh8P+Id1YZ4IRRFldPVNF
         TMhTHBi3fFjxzjv6wJtGmoMk6Sasc0htd2lA4parzeqJDpwBmJT0z1hulGAg/uYCVUF+
         G+5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:feedback-id:list-unsubscribe-post:list-unsubscribe
         :message-id:subject:reply-to:from:to:date:dkim-signature
         :dkim-signature;
        bh=pvDUSHQJaopRYJR49yAYcSg0NIfWdG+RDS5MBjdQz6U=;
        fh=RYEHzHU/HAyeZBCO4E+IbnoHdOzcm1YWiVKtSJ7fCDU=;
        b=JNhXZFPsvXBTJtA6SafsiVffmQ/Igjgd/0mX961BpTcnOPjq9HmPVANMs7u1dCLhpn
         8fVrLJj0TiMoAZwItHCvgO6So2uB2y1IpLMRkzeD8RMuHvl8I+nRTV9mYj5TEde08rDn
         OMiPCMKfUkU/vWfLdVHj4avFYCF2MJ3Cn2po43G5EMlzXU5XPyu1jpCivwbGNqLvG+b8
         ILu39Ufq8tqC3Og3k9FWtux03Eo7+jxwVdZVir4fCoZ0TWkpg9VzTOFz0ln2J/xxcquq
         7ne9nuUxVx8NreqU6Cwdz0l2N3QtEufWI0n9ouELeHi1nEJnQmjvVZhGzrKBXWBnokKD
         1ecg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mailchef.4dem.it header.s=mailchef header.b=oBddkIGX;
       dkim=pass header.i=@fiscozen.it header.s=nwslauth header.b=Mk2cVOA0;
       spf=pass (google.com: domain of bounce-95815784-7662692-22280720-4982744@mailchef.4dem.it designates 176.221.48.107 as permitted sender) smtp.mailfrom=bounce-95815784-7662692-22280720-4982744@mailchef.4dem.it;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fiscozen.it
Received: from mx10.h.4dem.it (mx10.h.4dem.it. [176.221.48.107])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5461bb2a2bfsi225929e87.3.2025.02.24.06.11.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 24 Feb 2025 06:11:42 -0800 (PST)
Received-SPF: pass (google.com: domain of bounce-95815784-7662692-22280720-4982744@mailchef.4dem.it designates 176.221.48.107 as permitted sender) client-ip=176.221.48.107;
Received: from mailrelayer.production.4dem.it (unknown [10.44.15.44])
	(Authenticated sender: mxsender)
	by mx10.h.4dem.it (Postfix) with ESMTPA id B785327B7D
	for <kasan-dev@googlegroups.com>; Mon, 24 Feb 2025 14:11:41 +0000 (UTC)
Received: from mailchef.4dem.it (unknown [10.44.32.48])
	by mailrelayer.production.4dem.it (Postfix) with ESMTP id 87DD2A0008
	for <kasan-dev@googlegroups.com>; Mon, 24 Feb 2025 14:11:41 +0000 (UTC)
Date: Mon, 24 Feb 2025 15:10:44 +0100
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
From: Francesca Ciani <francesca.ciani@fiscozen.it>
Reply-To: Francesca Ciani <francesca.ciani@fiscozen.it>
Subject: Possiamo pubblicare un guest post sul vostro sito?
Message-ID: <37fa97697f5127cc8d81defa296fad34@mailchef.4dem.it>
X-Mailer: postfix
X-Complaints-To: abuse@mailchef.4dem.it
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>
List-Unsubscribe-Post: List-Unsubscribe=One-Click
X-MessageID: a36l-tr6-a2FzYW4tZGV2QGdvb2dsZWdyb3Vwcy5jb20%3D-2d1n-jm9-rs-rs-RpsXFDFvAu
X-Report-Abuse: <https://mailchef.4dem.it/report_abuse.php?mid=a36l-tr6-a2FzYW4tZGV2QGdvb2dsZWdyb3Vwcy5jb20%3D-2d1n-jm9-rs-rs-RpsXFDFvAu>
Feedback-ID: 24425:469685:109219:RpsXFDFvAu
X-CmpID: 469685
X-UiD: %User:UserID%
X-Sender-Filter: 24425-francesca.ciani@fiscozen.it
X-SMTPAPI: {"unique_args":{"abuse-id":"a36l-tr6-a2FzYW4tZGV2QGdvb2dsZWdyb3Vwcy5jb20%3D-2d1n-jm9-rs-rs-RpsXFDFvAu"}, "category":"campaign"}
MIME-Version: 1.0
Content-Type: multipart/alternative;
	boundary="b1_37fa97697f5127cc8d81defa296fad34"
X-Original-Sender: francesca.ciani@fiscozen.it
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mailchef.4dem.it header.s=mailchef header.b=oBddkIGX;
       dkim=pass header.i=@fiscozen.it header.s=nwslauth header.b=Mk2cVOA0;
       spf=pass (google.com: domain of bounce-95815784-7662692-22280720-4982744@mailchef.4dem.it
 designates 176.221.48.107 as permitted sender) smtp.mailfrom=bounce-95815784-7662692-22280720-4982744@mailchef.4dem.it;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=fiscozen.it
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>

This is a multi-part message in MIME format.

--b1_37fa97697f5127cc8d81defa296fad34
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

=20

[Fiscozen]=20

=C2=A0
Ciao,
=C2=A0
Sono Francesca, digital marketing specialist in Fiscozen.
=C2=A0
Vi contatto per sapere se siete disponibili a pubblicare un guest post
su=C2=A0googleprojectzero.blogspot.com
=C2=A0
Se siete interessati, vi chiedo di rispondere ad un paio di domande
presenti al link qui sotto. Ci servono per capire se effettivamente
possiamo collaborare.

=C2=A0

Link da compilare:=C2=A0Inizia cliccando qui [1]

=C2=A0

Grazie in anticipo,

=C2=A0

 		[Francesca C.]

FRANCESCA C.=20
Digital marketing specialist

=20

Links:
------
[1] https://survey.typeform.com/to/cLq2dtHy?utm_source=3Dbrevo&amp;utm_camp=
aign=3Dguestpost_qualification&amp;utm_medium=3Demail#site=3Dgoogleprojectz=
ero.blogspot.com
 		=C2=A0

_Questa email =C3=A8 stata inviata a kasan-dev@googlegroups.com_

=C2=A0

_Fiscozen s.p.a. - 10062090963_

_Via XX Settembre 27, Milano, 20123, Milano, Italia_

_francesca.ciani@fiscozen.it - +393230748523_

Non vuoi pi=C3=B9 ricevere queste email? Clicca qui [/https://675846e82c2ba=
b00139b6289.trk.mailchef.4dem.it/app/public/unsubscribe/jm9/a36l/tr6/2d1n/9=
egs/rs/rt/c]
per disiscriverti

Area abuse [/https://675846e82c2bab00139b6289.trk.mailchef.4dem.it/report_a=
buse.php?mid=3Da36l-tr6-a2FzYW4tZGV2QGdvb2dsZWdyb3Vwcy5jb20%3D-2d1n-jm9-rs]


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
7fa97697f5127cc8d81defa296fad34%40mailchef.4dem.it.

--b1_37fa97697f5127cc8d81defa296fad34
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<!DOCTYPE html>
<html>
<head>
	<title>2025-02-24_lista2_richiesta contatti guest post</title>
</head>
<body aria-disabled=3D"false" style=3D"cursor: auto;">
<table fr-original-style=3D"width:640px;max-width:100%;text-align:left; fon=
t-family: 'Work Sans', sans-serif;" style=3D"width: 640px; max-width: 100%;=
 font-family: &quot;Work Sans&quot;, sans-serif; border-width: 0px; border-=
style: none; border-color: currentcolor; border-collapse: collapse; empty-c=
ells: show;">
	<thead>
		<tr>
			<th colspan=3D"2" fr-original-style=3D"" style=3D"background: unset; bor=
der-style: solid; border-color: transparent; -webkit-user-select: text;">
			<div style=3D"background-image:url(https://www.fiscozen.it/site/uploads/=
2022/04/bkg-nero-fiscozen.png);background-position:center center;background=
-size:cover;background-repeat:repeat;padding: 8px 32px;border-radius:2px;">=
<img alt=3D"Fiscozen" fr-original-class=3D"logo fr-draggable" fr-original-s=
tyle=3D"" height=3D"10" src=3D"https://www.fiscozen.it/site/uploads/2022/04=
/logo-email-dem-light.png" style=3D"cursor: pointer; padding: 0px 1px; posi=
tion: relative; max-width: 100%;" width=3D"70" /></div>
			</th>
		</tr>
	</thead>
	<tbody>
		<tr>
			<td colspan=3D"2" fr-original-style=3D"padding:19px 32px;" style=3D"padd=
ing: 19px 32px; min-width: 5px; border-style: solid; border-color: transpar=
ent; -webkit-user-select: text; background: unset;">
			<div>&nbsp;</div>

			<p dir=3D"ltr" id=3D"isPasted" style=3D"line-height:1.2;margin-top:0pt;m=
argin-bottom:0pt;"><span style=3D"font-size: 11pt; font-family: Arial, Helv=
etica, sans-serif; background-color: rgb(255, 255, 255); font-variant-ligat=
ures: normal; font-variant-alternates: normal; font-variant-numeric: normal=
; font-variant-east-asian: normal; font-variant-position: normal; vertical-=
align: baseline; white-space: pre-wrap;">Ciao,</span></p>
			&nbsp;

			<p dir=3D"ltr" style=3D"line-height:1.2;margin-top:0pt;margin-bottom:0pt=
;"><span style=3D"font-size: 11pt; font-family: Arial, Helvetica, sans-seri=
f; background-color: rgb(255, 255, 255); font-variant-ligatures: normal; fo=
nt-variant-alternates: normal; font-variant-numeric: normal; font-variant-e=
ast-asian: normal; font-variant-position: normal; vertical-align: baseline;=
 white-space: pre-wrap;">Sono Francesca, digital marketing specialist in Fi=
scozen.</span></p>
			&nbsp;

			<p dir=3D"ltr" style=3D"line-height:1.2;margin-top:0pt;margin-bottom:0pt=
;"><span style=3D"font-size: 11pt; font-family: Arial, Helvetica, sans-seri=
f; background-color: rgb(255, 255, 255); font-variant-ligatures: normal; fo=
nt-variant-alternates: normal; font-variant-numeric: normal; font-variant-e=
ast-asian: normal; font-variant-position: normal; vertical-align: baseline;=
 white-space: pre-wrap;">Vi contatto per sapere se siete disponibili a pubb=
licare un guest post su&nbsp;googleprojectzero.blogspot.com</span></p>
			&nbsp;

			<p dir=3D"ltr" style=3D"line-height:1.2;margin-top:0pt;margin-bottom:0pt=
;"><span style=3D"font-size: 11pt; font-family: Arial, Helvetica, sans-seri=
f; background-color: rgb(255, 255, 255); font-variant-ligatures: normal; fo=
nt-variant-alternates: normal; font-variant-numeric: normal; font-variant-e=
ast-asian: normal; font-variant-position: normal; vertical-align: baseline;=
 white-space: pre-wrap;">Se siete interessati, vi chiedo di rispondere ad u=
n paio di domande presenti al link qui sotto. Ci servono per capire se effe=
ttivamente possiamo collaborare.</span></p>

			<p dir=3D"ltr" style=3D"line-height:1.2;margin-top:0pt;margin-bottom:0pt=
;">&nbsp;</p>

			<p dir=3D"ltr" style=3D"line-height:1.2;margin-top:0pt;margin-bottom:0pt=
;"><span id=3D"isPasted" style=3D"font-size: 11pt; font-family: Arial, Helv=
etica, sans-serif; background-color: rgb(255, 255, 255); font-variant-ligat=
ures: normal; font-variant-alternates: normal; font-variant-numeric: normal=
; font-variant-east-asian: normal; font-variant-position: normal; vertical-=
align: baseline; white-space: pre-wrap;">Link da compilare:&nbsp;</span><sp=
an style=3D"color: rgb(39, 27, 220);"><a fr-original-style=3D"text-decorati=
on:none;" href=3D"https://675846e82c2bab00139b6289.trk.mailchef.4dem.it/tra=
ck/click?q=3DeyJkYXRhIjoiMlJ6YVpqN3ZJZ29EbHJ4T3pSaStOOUVuNExZbWxoS0UyU1Q2ZU=
tXZGlVNldyUUg5b0x2UVwvOHBlV2JidG1hdkxCTE0rVGloS09FUmZWZ1RaRHNYbHRha0VzRURJd=
lJaalFPdVFxRVwvWXZtQjdwMmlTcEh3T2NMQzBvUFprMStzaWJsbjFXa1wvbFpzRW52MzN4UGZv=
XC9yQlhxeXM3ZUJ1ejFITStMeEJLRGo0a1NtNUpvQUt6bGRVaEdlUTBsOVlObCtcL2RsejRYZ1c=
xd1ozUU9GU3I5dmYrbkxFcFRJWlVzXC9PVnN5REw0MXljNCs2UTVqd25nZWthWFZDaEI2dlZtSi=
tFb1J2M3JuRjRXXC94SkxFTmtWNEpcLzVCdytXY1RYRVh5QlwvSG92eWhPRGZGaG5mN2c2Yjk3W=
EZhZ2RDSWl1R1d2ZTV5U3FRWTBtQzhNcTZvWVNORENqclBKZ2FrY1hpZ3BBVUs5dzJcL0pqb092=
WXRVMkxnUUlDOXNtd0xLZlhQV1JPQlwvXC9sTlFhVGtjY2drbys3VFE0Q280SGhcL1JnK0FWVUd=
5bHBSY1AxbDJ0cWs0eUhHVnFLdEVCbjdxZSt0a21kV1NwV3Fxbm15N1ZNanp4bWJBaW9mSElLdF=
FabTVtZ2N3eVB0TmlDelZpZlZlbFwvcTloeEhidVVqbmJoVW5MSXYzMGxLMjFmbGFmN05EZDcyR=
nFTeXlPOExSekZTREFIT0R2WjNhY3Y2UkJjakhUQ2VuTm9uVWJ5ZzRLTTJFZkpxb3QwMDhXelwv=
b1luMDJWbGw4NlhJZz09IiwiaXYiOiJ1TDJvb3ZLQlA4cTI3VmxFYktjMUZRPT0ifQ=3D=3D" s=
tyle=3D"text-decoration: none; -webkit-user-select: auto;"><span style=3D"b=
ackground-color: rgb(255, 255, 255); font-size: 11pt; font-family: Arial, H=
elvetica, sans-serif; font-variant-ligatures: normal; font-variant-alternat=
es: normal; font-variant-numeric: normal; font-variant-east-asian: normal; =
font-variant-position: normal; vertical-align: baseline; white-space: pre-w=
rap; text-decoration-skip-ink: none;"><u>Inizia cliccando qui</u></span></a=
></span></p>

			<p dir=3D"ltr" style=3D"line-height:1.2;margin-top:0pt;margin-bottom:0pt=
;">&nbsp;</p>

			<p dir=3D"ltr" style=3D"line-height:1.2;margin-top:0pt;margin-bottom:0pt=
;"><span style=3D"background-color: rgb(255, 255, 255); font-size: 11pt; fo=
nt-family: Arial, Helvetica, sans-serif; font-variant-ligatures: normal; fo=
nt-variant-alternates: normal; font-variant-numeric: normal; font-variant-e=
ast-asian: normal; font-variant-position: normal; vertical-align: baseline;=
 white-space: pre-wrap; text-decoration-skip-ink: none;">Grazie in anticipo=
,</span></p>

			<p dir=3D"ltr" style=3D"line-height:1.2;margin-top:0pt;margin-bottom:0pt=
;">&nbsp;</p>
			</td>
		</tr>
		<tr>
			<td fr-original-style=3D"padding: 0 32px 32px 32px;" style=3D"padding: 0=
px 32px 32px; min-width: 5px; border-style: solid; border-color: transparen=
t; -webkit-user-select: text; background: unset;" width=3D"70px"><span styl=
e=3D"font-size: 14px;"><img alt=3D"Francesca C." fr-original-class=3D"fr-dr=
aggable" fr-original-style=3D"width: 70px; height: 70px;" src=3D"https://ww=
w.fiscozen.it/site/uploads/2023/09/francesca.png" style=3D"width: 70px; hei=
ght: 70px; cursor: pointer; padding: 0px 1px; position: relative; max-width=
: 100%;" /></span></td>
			<td fr-original-style=3D"padding: 0 32px 32px 0;" style=3D"padding: 0px =
32px 32px 0px; min-width: 5px; border-style: solid; border-color: transpare=
nt; -webkit-user-select: text; background: unset;">
			<p style=3D"margin:0;"><span style=3D"font-size: 14px;"><strong fr-origi=
nal-style=3D"">Francesca C.</strong> </span><br />
			<span style=3D"opacity: 0.6; font-size: 14px;">Digital marketing special=
ist</span></p>
			</td>
		</tr>
	</tbody>
</table>

<p><br />
<style type=3D"text/css">@import url('https://fonts.googleapis.com/css2?fam=
ily=3DWork+Sans:ital,wght@0,400;0,600;1,400;1,600&display=3Dswap'); table,
			th,
			td {
				border: 0;
			}
</style>
</p>
<div style=3D"font-size:14px;"><table align=3D"center" border=3D"0" cellpad=
ding=3D"0" cellspacing=3D"0" height=3D"100%" style=3D"margin:0; padding:0; =
width:100% !important;" width=3D"100%">
	<tbody>
		<tr>
			<td align=3D"center" class=3D"wrap" valign=3D"top" width=3D"100%">
			<center><!-- content -->
			<div style=3D"padding:0px">
			<table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"100%">
				<tbody>
					<tr>
						<td style=3D"padding:0px" valign=3D"top">
						<table align=3D"center" cellpadding=3D"0" cellspacing=3D"0" class=3D"=
email-root-wrapper" style=3D"max-width:600px;min-width:240px;margin:0 auto"=
 width=3D"600">
							<tbody>
								<tr>
									<td style=3D"padding:0px" valign=3D"top">
									<table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" width=3D"1=
00%">
										<tbody>
											<tr>
												<td style=3D"padding:5px" valign=3D"top">
												<table cellpadding=3D"0" cellspacing=3D"0" width=3D"100%">
													<tbody>
														<tr>
															<td style=3D"padding:0px">
															<table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" widt=
h=3D"100%">
																<tbody>
																	<tr>
																		<td style=3D"padding-top:10px;padding-right:10px;padding-=
bottom:5px;padding-left:10px" valign=3D"top">
																		<table cellpadding=3D"0" cellspacing=3D"0" width=3D"100%"=
>
																			<tbody>
																				<tr>
																					<td style=3D"padding:0px">
																					<table border=3D"0" cellpadding=3D"0" cellspacing=3D"0=
" style=3D"border-top:1px solid #808080" width=3D"100%">
																						<tbody>
																							<tr>
																								<td valign=3D"top">
																								<table cellpadding=3D"0" cellspacing=3D"0" width=3D=
"100%">
																									<tbody>
																										<tr>
																											<td style=3D"padding:0px">&nbsp;</td>
																										</tr>
																									</tbody>
																								</table>
																								</td>
																							</tr>
																						</tbody>
																					</table>
																					</td>
																				</tr>
																			</tbody>
																		</table>
																		</td>
																	</tr>
																</tbody>
															</table>

															<table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" widt=
h=3D"100%">
																<tbody>
																	<tr>
																		<td style=3D"padding:5px" valign=3D"top">
																		<div style=3D"text-align:left;font-family:arial;font-size=
:12px;color:#808080;line-height:18px;mso-line-height:exactly;mso-text-raise=
:3px">
																		<p style=3D"padding: 0; margin: 0;text-align: center;"><e=
m>Questa email &egrave; stata inviata a kasan-dev@googlegroups.com</em></p>

																		<p style=3D"padding: 0; margin: 0;text-align: center;">&n=
bsp;</p>

																		<p style=3D"padding: 0; margin: 0;text-align: center;"><e=
m>Fiscozen s.p.a. - 10062090963</em></p>

																		<p style=3D"padding: 0; margin: 0;text-align: center;"><e=
m>Via XX Settembre 27, Milano, 20123, Milano, Italia</em></p>

																		<p style=3D"padding: 0; margin: 0;text-align: center;"><e=
m>francesca.ciani@fiscozen.it - +393230748523</em></p>
																		</div>
																		</td>
																	</tr>
																</tbody>
															</table>

															<table border=3D"0" cellpadding=3D"0" cellspacing=3D"0" widt=
h=3D"100%">
																<tbody>
																	<tr>
																		<td style=3D"padding-top:5px;padding-right:5px;padding-le=
ft:5px" valign=3D"top">
																		<div style=3D"text-align:left;font-family:arial;font-size=
:12px;color:#808080;line-height:18px;mso-line-height:exactly;mso-text-raise=
:3px">
																		<p style=3D"padding: 0; margin: 0;text-align: center;">No=
n vuoi pi&ugrave; ricevere queste email? <a href=3D"https://675846e82c2bab0=
0139b6289.trk.mailchef.4dem.it/app/public/unsubscribe/jm9/a36l/tr6/2d1n/9eg=
s/rs/rt/c" style=3D"color: #404040 !important; text-decoration: underline !=
important;" target=3D"_blank"><font style=3D" color:#404040;">Clicca qui</f=
ont></a> per disiscriverti</p>

																		<p style=3D"padding: 0; margin: 0;text-align: center;"><s=
pan style=3D"font-size:10px;"><a href=3D"https://675846e82c2bab00139b6289.t=
rk.mailchef.4dem.it/report_abuse.php?mid=3Da36l-tr6-a2FzYW4tZGV2QGdvb2dsZWd=
yb3Vwcy5jb20%3D-2d1n-jm9-rs" style=3D"color: #404040 !important; text-decor=
ation: underline !important;" target=3D"_blank"><font style=3D" color:#4040=
40;">Area abuse</font></a></span></p>
																		</div>
																		</td>
																	</tr>
																</tbody>
															</table>
															</td>
														</tr>
													</tbody>
												</table>
												</td>
											</tr>
										</tbody>
									</table>
									</td>
								</tr>
							</tbody>
						</table>
						</td>
					</tr>
				</tbody>
			</table>
			</div>
			<!-- content end --></center>
			</td>
		</tr>
	</tbody>
</table>
</div>


<img src=3D"https://675846e82c2bab00139b6289.trk.mailchef.4dem.it/track/ope=
n?q=3DeyJkYXRhIjoibzFjbWF1SFpxa2QxdmhZTTlSNExDN1ZLOVE2UWdTeWZ3Wk8rN04zY0lmQ=
WpSM0ZzbjBRSGpRdUJHaUpNZ2V3TGd2TnRKamFaQnV4Ym1IR3BrRzgyUFRGWWEzUVRQRkQwdjg1=
QmJWSWREbDd1T3dTcUQ0dGVJb0t5N3hxMlwvOUpvT3R3MHNwaTZkVjR1dTRoa0FvTER0OXpYTDJ=
ycjlZUmlPdXBLeU83eTE0TXVaTWNSMkJJSnBLeVBsRFd6Vk1SNkVIKzdCenVDcXlFTVFqV2xJYX=
hIamp2S3J1dVdveUtmK3JvWjdyRHBuc1hcL1lOVjVGM0hKeE9hVzhsK1RaVFJtS0trYXlTY0pvW=
nJyTXV1RFdwSFJaQ2VjSitCYXNvc0RJdHJsMDhVYWNHbUlHRmRsWm1pZHVLVjduWnYzTTdTejcw=
end0VVJwN25rVFdhbWdMeWhsOHIxNE8wQ1RlZVZvbTlNVHBNTmJFWEhCd1M2R1pucEVOM1VJd0M=
3OFBFOFAiLCJpdiI6IndqZGtNMEF2ZllJTHdUcnZBMkFUdWc9PSJ9" width=3D"5" height=
=3D"2" alt=3D"." style=3D"width:5px !important; height:2px !important;">

</body>
</html>


<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/37fa97697f5127cc8d81defa296fad34%40mailchef.4dem.it?utm_medium=3D=
email&utm_source=3Dfooter">https://groups.google.com/d/msgid/kasan-dev/37fa=
97697f5127cc8d81defa296fad34%40mailchef.4dem.it</a>.<br />

--b1_37fa97697f5127cc8d81defa296fad34--

