Return-Path: <kasan-dev+bncBDF2DM773IIBBKV25SOQMGQE4DAL7PQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 94DEE6618CD
	for <lists+kasan-dev@lfdr.de>; Sun,  8 Jan 2023 20:44:44 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id t13-20020a9d748d000000b00682cd587d0csf3336037otk.7
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Jan 2023 11:44:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673207083; cv=pass;
        d=google.com; s=arc-20160816;
        b=uklajk4dWdskOswqzsZ1Had8Z0xdwuW1dfVwupqMkbLmbMWsQ5NahvfShlpoME9k3i
         xGrFrghQ3YU4GXRgdDdrFy5aC/gRoLKYSvVtkr/76pT302ap80aNtBuDZ3JW+wy0Tbjk
         10Ifp/J0ke72ARAYMuggfUmkUJkNIZMG00WVnyiGSHH6IbBqSrS1d6Q5HsCf5wiBYqnM
         fxL2ZlJlLPys0Nt9BxeRHGWE1KKN8I57iDyvW4LvM8wy4QLBTMzu7ewVOYnN/N4wqqf3
         mXRra6UujcWaJnQLdQEGizQMLQy5A0yHSS3G6bMwTcvcUZrZGcqvGtnn9v7NEAm8jUYl
         8iqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=SQUu7j//+53Bau6wWWzWXQGza20ePJTREQWPT+WP4HI=;
        b=Famn3HDv3TiohNKE+Bbguf44XWALADKZr7a0/U8UCWnIw3sZ6xMJ2Y0ipmVLajE1fO
         D+Q9YZTbXKh1U6+MSG4aLDX9LcpC7SUQrHSPDrvF8M5ciT1ewyvCBruwJScWL1raf6j8
         PseP/TwEFQfZVEJuxdjtKk5BKomZLbyN3TJX/AwYb87OjoeKtCX8g1aAACNoFUiuHm0B
         d1HFwZNAAIuawBRQqJLytoI8++P6z1+hP+t3aOUPFJYY3X7UQxRhbnUbBaNr3AnRcicp
         zElY8eiXMgNLN9XIcWub/3+eeoNjNkMWkH89tGUxDBwnN3h7S3EaN5zqP3NnS6zVq5i3
         t8qg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UUzWe4hG;
       spf=pass (google.com: domain of tcharahien552@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=tcharahien552@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SQUu7j//+53Bau6wWWzWXQGza20ePJTREQWPT+WP4HI=;
        b=GLPXVcPREk7QPTPRWEvR8FKfA+kqpMNlglfLEt40EEKNKW/ibXaAglovsXeE/RGX+T
         Gi0B1AwFJRJw5iXX+I3Xyn93J/JnPqp2o8cg+b9sZPDXz/070USm2FEG/f+CeOmE7rSC
         /pn5Awne0Qg+x8X+Mh2pFzIaA1yo8gJ7BGgjJ4BhWS/Lu9a1XrkD4XMT5SZfG0OsSLSd
         3Hm39I/iUNOVsn33NWY0vVaiCEnk6cXu+ByXma/V1lbJYj783JRg6NJS3VLRFCdWrknV
         96cRA1HzEOA63TFibaOEZwqHycpE7QpBCrOOcrbZugx/6R91CcqRx/4U4fEs4jy2VfaG
         wMaA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=SQUu7j//+53Bau6wWWzWXQGza20ePJTREQWPT+WP4HI=;
        b=LQ9uaAEXJo5/nKWdQKuhXto9JMrtY+TH6hG8Yo3bi1HuhawbwcB6ugVeu6scH51m2e
         v0f7hYIEIml6jRiOzItbXKJ/jzAPXiBmkYeJeyGAJbzi5vKNfRSXwa+ZxJy3FZ7ZmZzY
         ie6+lWRzniUDaX1Yve6jRHofIi3/eGUDYZqzN350p6Bx5lbCS4TmfTM1TQkj1sa/qrUm
         sdetrIZh1KqoAICyKuZ7czq3hafWVvPFLPqdZnmttZmyXtb45hkF7mbrdqR+TVXrdW50
         xRjqckfakLjqIzEiH2TGUU5cro+GattcZuhHHHLuy/Kh6UoP1M2vSEfQL7/Z6vdzrK97
         KtAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=SQUu7j//+53Bau6wWWzWXQGza20ePJTREQWPT+WP4HI=;
        b=b46FldTT8Ph3vinHm5ZF6PiCRv30nch/DaKIs6RJPQ6nZYq+Ks6gme4WnpFzsNj9dV
         6XJ+yqCU20gFFNQ0zposz6RXijJpvt7oeZYeolrAKuPVMINEFD+fUtaBjeUINLb2JrWw
         yWcvW9gQbIAV6p4oODB6fuKBWiSTmbeZO5v8AtTZD1Buczcau6LivrBEzpPe/nWfezNF
         dGluyW2LHwdA1a3SEgkROzbjpl28GaAckx4WMRk0yxUk5faoUaL4o/U5lKV2w/TfrLQM
         MPgx/ecKDMdxfHVR6fNWq5jZen/K7kcgz+AhZGA3gTRk443kTH9w/DPWe7xlh3MfnOG4
         sVnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krGSYbBvfHK1X0CY0eAleHq7I5iuzfHj07JYiC+bTX6P+O2tYf6
	ambDjMamH8/eFa4edQmVVRE=
X-Google-Smtp-Source: AMrXdXun6twzj32NpclBMUeufcM+EfaQu52M36f0Jki7pCOSgP7VgNlBuKp7XwOPgOfYr4K5raC9lw==
X-Received: by 2002:a4a:950a:0:b0:4e7:10fa:80e0 with SMTP id m10-20020a4a950a000000b004e710fa80e0mr1525927ooi.55.1673207083013;
        Sun, 08 Jan 2023 11:44:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4e08:0:b0:35b:2747:ee0f with SMTP id a8-20020a544e08000000b0035b2747ee0fls1594824oiy.3.-pod-prod-gmail;
 Sun, 08 Jan 2023 11:44:42 -0800 (PST)
X-Received: by 2002:aca:1b0c:0:b0:364:3085:a6f2 with SMTP id b12-20020aca1b0c000000b003643085a6f2mr3210943oib.55.1673207082609;
        Sun, 08 Jan 2023 11:44:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673207082; cv=none;
        d=google.com; s=arc-20160816;
        b=ifFeO4Tlv7E/PaZNzcozaJn2uiYPqV618gqw+zBDWTfXDi1OGNTElBvD8V+I/lam6n
         i0H9dBNGYWrlAKw1dvRIa1M4hBDbAKRvsdzvtS/7Lx8Om3gdVPbQVW5KdaAu0X5FUm0j
         zIXkIM1ZnzqkUzpoxWcly8G5IhxNHIm+Z8IQsADbFI5IVYkEv9mQqAPYIxSGPyLiS80N
         slgYalJK+NNqoqauVTMrQvNPUxLoVHzyRwEyD41sx+UM2inHRMKllQbUbstlM4cnbhlf
         BK2y0ENqI/0vocF3Uiv70nhNoGL9UFA7X+W5gmVJsS2g7nH+2H/Biz49BnpnaN+G0o9U
         VhxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=vAt27wy77sKb9qg/HTbnPWodzxZjL8WEADB1TGecVzY=;
        b=v2eBFCIEoz0m9R4c7MED7g/SpNy8BPJ19QD/Ft/k+EA1sXTQj0uEzUV53m13MTfu1z
         Pov3sOyddMFznPWEO7DauBbBx9mp9fiq2dA7AoEpHCEtlrNT9o3iTa8BQwkevN8tbM+h
         eR2Hznuyc08da64q22vl1HAs/wEfZv6Nsysgpq+WPn9luhxIw3mYCu1ENu5x7Auntmkq
         aB7xCcmBjbAlG9a6AaewnaUwoFc1tnjKCr3Y/4i9dcpsX+wn1mNG5q+K8jheKkKBDblF
         4boQxIRpB/LrFn1sjaFyLPSegM2ZQmsfyb4LOLd/81xcdPv2gBJs8xFr0FG7LhsZRh2V
         rwgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=UUzWe4hG;
       spf=pass (google.com: domain of tcharahien552@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=tcharahien552@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id g84-20020acab657000000b00353e4e7f335si804135oif.4.2023.01.08.11.44.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 Jan 2023 11:44:42 -0800 (PST)
Received-SPF: pass (google.com: domain of tcharahien552@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id p9so3526506iod.13
        for <kasan-dev@googlegroups.com>; Sun, 08 Jan 2023 11:44:42 -0800 (PST)
X-Received: by 2002:a05:6e02:f0f:b0:30c:2c6f:5aa0 with SMTP id
 x15-20020a056e020f0f00b0030c2c6f5aa0mr3772288ilj.188.1673206698588; Sun, 08
 Jan 2023 11:38:18 -0800 (PST)
MIME-Version: 1.0
From: AGENCE IMMO <immobilierintern@gmail.com>
Date: Sun, 8 Jan 2023 19:38:07 +0000
Message-ID: <CAPrpWc4g71OCWirGR4zzk-aFz44T9i_64DnG+VaHfOKcrhzsGQ@mail.gmail.com>
Subject: =?UTF-8?Q?R=C3=A8glement=2DLoyer?=
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000e7c37605f1c5cae9"
X-Original-Sender: immobilierintern@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=UUzWe4hG;       spf=pass
 (google.com: domain of tcharahien552@gmail.com designates 2607:f8b0:4864:20::d33
 as permitted sender) smtp.mailfrom=tcharahien552@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000e7c37605f1c5cae9
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

A votre aimable attention,



Nous vous informons qu'une mise =C3=A0 jour a =C3=A9t=C3=A9 effectu=C3=A9e =
au sein de notre
=C3=A9tablissement. De ce fait, nous avons apport=C3=A9 quelques changement=
s au
niveau compta,




Veuillez confirmer la r=C3=A9ception de notre diffusion, afin de vous envoy=
er
les nouvelles coordonn=C3=A9es bancaires pour le versement mensuel.



Vous souhaitant une tr=C3=A8s bonne et heureuse ann=C3=A9e 2023, ainsi qu'u=
ne bonne
r=C3=A9ception de la pr=C3=A9sente.



Bien cordialement,



*Le S.ervice G.estion L.ocative.*

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAPrpWc4g71OCWirGR4zzk-aFz44T9i_64DnG%2BVaHfOKcrhzsGQ%40mail.gmai=
l.com.

--000000000000e7c37605f1c5cae9
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div id=3D"gmail-:33c" class=3D"gmail-Ar gmail-Au" style=
=3D"display:block"><div id=3D"gmail-:338" class=3D"gmail-Am gmail-Al editab=
le gmail-LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Corps du message" ro=
le=3D"textbox" aria-multiline=3D"true" style=3D"direction:ltr;min-height:33=
1px" tabindex=3D"1" aria-controls=3D":364"><div id=3D"gmail-:1u2" class=3D"=
gmail-Ar gmail-Au" style=3D"display:block"><div id=3D"gmail-:1ty" class=3D"=
gmail-Am gmail-Al editable gmail-LW-avf gmail-tS-tW gmail-tS-tY" aria-label=
=3D"Corps du message" role=3D"textbox" aria-multiline=3D"true" style=3D"dir=
ection:ltr;min-height:331px" tabindex=3D"1" aria-controls=3D":1wu"><div id=
=3D"gmail-:ad" class=3D"gmail-Ar gmail-Au gmail-Ao" style=3D"display:block"=
><div id=3D"gmail-:f1" class=3D"gmail-Am gmail-Al editable gmail-LW-avf gma=
il-tS-tW gmail-tS-tY" aria-label=3D"Corps du message" role=3D"textbox" aria=
-multiline=3D"true" style=3D"direction:ltr;min-height:331px" tabindex=3D"1"=
 aria-controls=3D":12l"><div id=3D"gmail-:p0" class=3D"gmail-Ar gmail-Au" s=
tyle=3D"display:block"><div id=3D"gmail-:ow" class=3D"gmail-Am gmail-Al edi=
table gmail-LW-avf gmail-tS-tW gmail-tS-tY" aria-label=3D"Corps du message"=
 role=3D"textbox" aria-multiline=3D"true" style=3D"direction:ltr;min-height=
:331px" tabindex=3D"1" aria-controls=3D":rs"><div id=3D"gmail-:et" class=3D=
"gmail-Ar gmail-Au gmail-Ao" style=3D"display:block"><div id=3D"gmail-:ep" =
class=3D"gmail-Am gmail-Al editable gmail-LW-avf gmail-tS-tW gmail-tS-tY" a=
ria-label=3D"Corps du message" role=3D"textbox" aria-multiline=3D"true" sty=
le=3D"direction:ltr;min-height:331px" tabindex=3D"1" aria-controls=3D":hl">=
<p style=3D"font-style:normal;font-variant-caps:normal;font-weight:400;lett=
er-spacing:normal;text-align:start;text-indent:0px;text-transform:none;whit=
e-space:normal;word-spacing:0px;text-decoration:none;box-sizing:content-box=
;margin:0cm 0cm 0.0001pt;line-height:1.4em;font-family:Calibri,sans-serif;c=
olor:rgb(68,68,68);font-size:11pt"><span style=3D"box-sizing:content-box;li=
ne-height:1.4em;font-size:13.5pt;font-family:&quot;Times New Roman&quot;,se=
rif;color:rgb(20,20,20)">A votre aimable attention,</span></p><p style=3D"f=
ont-style:normal;font-variant-caps:normal;font-weight:400;letter-spacing:no=
rmal;text-align:start;text-indent:0px;text-transform:none;white-space:norma=
l;word-spacing:0px;text-decoration:none;box-sizing:content-box;margin:0cm 0=
cm 0.0001pt;line-height:1.4em;font-family:Calibri,sans-serif;color:rgb(68,6=
8,68);font-size:11pt">=C2=A0</p><p style=3D"font-style:normal;font-variant-=
caps:normal;font-weight:400;letter-spacing:normal;text-align:start;text-ind=
ent:0px;text-transform:none;white-space:normal;word-spacing:0px;text-decora=
tion:none;box-sizing:content-box;margin:0cm 0cm 0.0001pt;line-height:1.4em;=
font-family:Calibri,sans-serif;color:rgb(68,68,68);font-size:11pt"><span st=
yle=3D"box-sizing:content-box;line-height:1.4em;font-size:13.5pt;font-famil=
y:&quot;Times New Roman&quot;,serif;color:rgb(20,20,20)">Nous vous informon=
s qu&#39;une mise =C3=A0 jour a =C3=A9t=C3=A9 effectu=C3=A9e au sein de not=
re =C3=A9tablissement. De ce fait, nous avons apport=C3=A9 quelques changem=
ents au niveau compta,<span class=3D"gmail-Apple-converted-space">=C2=A0</s=
pan><br></span></p><p style=3D"font-style:normal;font-variant-caps:normal;f=
ont-weight:400;letter-spacing:normal;text-align:start;text-indent:0px;text-=
transform:none;white-space:normal;word-spacing:0px;text-decoration:none;box=
-sizing:content-box;margin:0cm 0cm 0.0001pt;line-height:1.4em;font-family:C=
alibri,sans-serif;color:rgb(68,68,68);font-size:11pt"><span style=3D"box-si=
zing:content-box;line-height:1.4em;font-size:13.5pt;font-family:&quot;Times=
 New Roman&quot;,serif;color:rgb(20,20,20)"><br></span></p><p style=3D"font=
-style:normal;font-variant-caps:normal;font-weight:400;letter-spacing:norma=
l;text-align:start;text-indent:0px;text-transform:none;white-space:normal;w=
ord-spacing:0px;text-decoration:none;box-sizing:content-box;margin:0cm 0cm =
0.0001pt;line-height:1.4em;font-family:Calibri,sans-serif;color:rgb(68,68,6=
8);font-size:11pt">=C2=A0</p><p style=3D"font-style:normal;font-variant-cap=
s:normal;font-weight:400;letter-spacing:normal;text-align:start;text-indent=
:0px;text-transform:none;white-space:normal;word-spacing:0px;text-decoratio=
n:none;box-sizing:content-box;margin:0cm 0cm 0.0001pt;line-height:1.4em;fon=
t-family:Calibri,sans-serif;color:rgb(68,68,68);font-size:11pt"><span style=
=3D"box-sizing:content-box;line-height:1.4em;font-size:13.5pt;font-family:&=
quot;Times New Roman&quot;,serif;color:rgb(20,20,20)">Veuillez confirmer la=
 r=C3=A9ception de notre diffusion, afin de vous envoyer les nouvelles coor=
donn=C3=A9es bancaires pour le versement mensuel.</span></p><p style=3D"fon=
t-style:normal;font-variant-caps:normal;font-weight:400;letter-spacing:norm=
al;text-align:start;text-indent:0px;text-transform:none;white-space:normal;=
word-spacing:0px;text-decoration:none;box-sizing:content-box;margin:0cm 0cm=
 0.0001pt;line-height:1.4em;font-family:Calibri,sans-serif;color:rgb(68,68,=
68);font-size:11pt">=C2=A0</p><p style=3D"font-style:normal;font-variant-ca=
ps:normal;font-weight:400;letter-spacing:normal;text-align:start;text-inden=
t:0px;text-transform:none;white-space:normal;word-spacing:0px;text-decorati=
on:none;box-sizing:content-box;margin:0cm 0cm 0.0001pt;line-height:1.4em;fo=
nt-family:Calibri,sans-serif;color:rgb(68,68,68);font-size:11pt"><span styl=
e=3D"box-sizing:content-box;line-height:1.4em;font-size:13.5pt;font-family:=
Times,serif;color:rgb(12,12,12)">Vous souhaitant une tr=C3=A8s bonne et heu=
reuse ann=C3=A9e 2023, ainsi qu&#39;une bonne r=C3=A9ception de la pr=C3=A9=
sente.</span></p><p style=3D"font-style:normal;font-variant-caps:normal;fon=
t-weight:400;letter-spacing:normal;text-align:start;text-indent:0px;text-tr=
ansform:none;white-space:normal;word-spacing:0px;text-decoration:none;box-s=
izing:content-box;margin:0cm 0cm 0.0001pt;line-height:1.4em;font-family:Cal=
ibri,sans-serif;color:rgb(68,68,68);font-size:11pt">=C2=A0</p><p style=3D"f=
ont-style:normal;font-variant-caps:normal;font-weight:400;letter-spacing:no=
rmal;text-align:start;text-indent:0px;text-transform:none;white-space:norma=
l;word-spacing:0px;text-decoration:none;box-sizing:content-box;margin:0cm 0=
cm 0.0001pt;line-height:1.4em;font-family:Calibri,sans-serif;color:rgb(68,6=
8,68);font-size:11pt"><span style=3D"box-sizing:content-box;line-height:1.4=
em;font-size:13.5pt;font-family:Times,serif;color:rgb(14,14,14)">Bien cordi=
alement,</span></p><p style=3D"font-style:normal;font-variant-caps:normal;f=
ont-weight:400;letter-spacing:normal;text-align:start;text-indent:0px;text-=
transform:none;white-space:normal;word-spacing:0px;text-decoration:none;box=
-sizing:content-box;margin:0cm 0cm 0.0001pt;line-height:1.4em;font-family:C=
alibri,sans-serif;color:rgb(68,68,68);font-size:11pt">=C2=A0</p><p style=3D=
"font-style:normal;font-variant-caps:normal;font-weight:400;letter-spacing:=
normal;text-align:start;text-indent:0px;text-transform:none;white-space:nor=
mal;word-spacing:0px;text-decoration:none;box-sizing:content-box;margin:0cm=
 0cm 0.0001pt;line-height:1.4em;font-family:Calibri,sans-serif;color:rgb(68=
,68,68);font-size:11pt"><i style=3D"box-sizing:content-box;line-height:1.4e=
m"><span style=3D"box-sizing:content-box;line-height:1.4em;font-size:13.5pt=
;font-family:Times,serif;color:rgb(60,115,191)">Le S.ervice G.estion L.ocat=
ive.</span></i></p></div></div></div></div></div></div></div></div></div></=
div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAPrpWc4g71OCWirGR4zzk-aFz44T9i_64DnG%2BVaHfOKcrhzsGQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAPrpWc4g71OCWirGR4zzk-aFz44T9i_64DnG%2BVaHfOKcrh=
zsGQ%40mail.gmail.com</a>.<br />

--000000000000e7c37605f1c5cae9--
