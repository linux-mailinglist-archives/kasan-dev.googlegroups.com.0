Return-Path: <kasan-dev+bncBDU3FVHVUUNRBIUIZOXAMGQEV4YNDKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D7AA859AE0
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Feb 2024 03:59:47 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-36525729ea3sf8885875ab.2
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Feb 2024 18:59:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708311586; cv=pass;
        d=google.com; s=arc-20160816;
        b=B+1V5kayLlLimnAcNNGuOqaITsFbMDT4+qS/nIIpDdihsBFYkc7J8xpguvA8wzsudr
         91cO9ma+8STI1oIUIs/9PNdAes7aDgb60bjt/aXIWbN7sRtjcC2VvEECe+MYuZCfugOZ
         P1yxvOBmrzBN6/3uT5ZbeZ98RLHKRt8BlPkWMXLDSeozDq9vwLOJN0VEWM62upHcS/7E
         vMUU1NExN14mBwa10QQzK759qy4G8yYA/xeRa+X7K9nahwfejP0Pvkh+FzVGh0iO1/fC
         8RyLo6OJvxXkeAS6ov/Un5HiuIhrVAsCWJvinw3vKH1NQPsU1AvptAs4DLsmCcidrQlj
         LKEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=DCkmZrpO+WoaBhGWWcXUUkGbaK/OOObKzYETSU+/G8s=;
        fh=85/ytlEulQzXgNDCJsDUhgU5fT8sXHdqyYQu4GeQ4pE=;
        b=h08h1qIt8SM7x8dy17NpwW4cw806qmnV2bmc6O00JHSJkdSH+XkSzFWWeoUz39EEnu
         C5OHM200Wjq2cw8W4tjxnn8U1HsMykltuXezKlAh3YEoF5UigJ0zRA9yd5UyLYc9EV2A
         0DVe6R0XOGRs0NwUlQb9a0KUsdDPrU80ZZavtn6a73ubkZjK2igQ0t3+w85knIHw9QTj
         AIqCstyiLog3JdIoGZqO0gIicxlsdS2GT2XYn9aXIuveyzX1Ybs0TxPuodes18EtSjAM
         Ej5NbrFX2tS/QyW7pm/nspvoc6vR7RLpDieQ9LmXqcxFOquPyfWFk3n1Uyvn0fTxGizF
         AQJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZuVryVfW;
       spf=pass (google.com: domain of infobanqueatlantique001@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=infobanqueatlantique001@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708311586; x=1708916386; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DCkmZrpO+WoaBhGWWcXUUkGbaK/OOObKzYETSU+/G8s=;
        b=sPuBFP4AFnjVXAfynNeUnD6RGZksUBspGCd6rEzWBT8tTOBlOCceJ6TivNdquT1tjR
         Aokq45si1sHotyJ70tW3jsXRBzzuPYkcf2WLbhIy4p3zj7l/phnKLi1SXSQP52LFwlSM
         BorB9NYnNrw0ybgf0TSmQBe/VhiYG0xa47ZuSc0/dzPysrMGtjMEf56aQMoqFh4I/hEI
         LSTR5upIbaNIoAP4AGVS4eFOVE5E/q46br/AwImV0Zi2vUg5QBJrzF9Gg3uW5SSiQXbX
         npWU14QRqbzlBLQYJOlYX1D8+nTDdh0RMygNktaHXBMgXRbNMXcOSADOlKCRzp+r3JGg
         XNmA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1708311586; x=1708916386; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=DCkmZrpO+WoaBhGWWcXUUkGbaK/OOObKzYETSU+/G8s=;
        b=UnDpDdyLV/eqLeTxaABs3PX/Yb/lhdfwCslr8V8CeSQhNbnnuDW+z9km43+PdksxYC
         oyG5uOBddwfGX2c2zAfzqw8NusfNJ/Bvao93CE9jRJXnM61pIMH8avzUgFJVT2rpHBR7
         n2DUdXgeRpXYmF9TNaFmxny3H412KKvNjhV+wdz5DDm6pWuBTPoBPirnbrc5vct5lL2U
         1zIliV9puzoZqHbYSwdHVMXkCsziYtRQLq4X7sS2nDF1TZocs3sQOfItyBeBfqaFdsKM
         roBq+WWAGuqMXblhMF/9sCrVbCcIQ+01+mgJck1qvBeF78xXRx/wCYwU64M7jYft6wFS
         6pkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708311586; x=1708916386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DCkmZrpO+WoaBhGWWcXUUkGbaK/OOObKzYETSU+/G8s=;
        b=I+nuSGKe563x0MwFG0YnQ9Zk9gTlxF5Am9dkjAzNdaCxNhtWMJ0sRgHEE+43YvjgK0
         ynnbXxPOqHJ6QC7dcH0ifDXlhYku+rEVGcsmJPPQhzrmu79ZTLS1AhvYH0LtCzERWuTi
         +sb6gP5RtneEUobhaRkFWCT6x6XzSP70XhvHmEIslkV3g3KOg/8+ySkBa7o3NDonG/SI
         2u858u7JOIAMPfvZRfd89GELc48dloBP6mNFkyzQl+4W6CJ4Q3SjE/nsabIDUDJCzip9
         Z2vg6U1TEoE4eae2opmlYGzW3rritoi6l7ZTi43HZ44UeCmIc2XK2cbLooY96NVJHvhH
         BLpA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW66ji3Y5xaqUprGo4EF5329RdO3BZuL+mQxcH0A9wb0WN5JJt3yCQxEXGU6ueWh4HMS5bgWtDYdgvqFl5XU44VBh0hkn83Ew==
X-Gm-Message-State: AOJu0Yw7shsMG9nIiK4VPHjx6aD9dnVCxMgJF0bwRP/K4wpuJgBtmQww
	r0XrKef6Wf/k7dnljglu/UpfRgw7aSatOT92pRCivJpNTi9pJLrK
X-Google-Smtp-Source: AGHT+IEWzVYboSi0500PuxFao7eccUXzzf/Q0YYbXnDj9nZmPVRjCtyEUogEq2Mr9TlP2vPRiA3Q5Q==
X-Received: by 2002:a05:6e02:12c5:b0:365:2f0:267 with SMTP id i5-20020a056e0212c500b0036502f00267mr12505141ilm.14.1708311586155;
        Sun, 18 Feb 2024 18:59:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c14b:0:b0:364:f794:ec1e with SMTP id b11-20020a92c14b000000b00364f794ec1els693767ilh.1.-pod-prod-08-us;
 Sun, 18 Feb 2024 18:59:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWmzU1/GoexKmEbf4HKuCb+syg2ELYiy59cBUmI0uWXwP+GxXIlQ+0KyXbwkGa61W9KdaGddXb9TTnR3BbcTRAHCC99+8wzkGmSBA==
X-Received: by 2002:a5d:8958:0:b0:7c4:1df1:14d7 with SMTP id b24-20020a5d8958000000b007c41df114d7mr12634484iot.6.1708311585315;
        Sun, 18 Feb 2024 18:59:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708311585; cv=none;
        d=google.com; s=arc-20160816;
        b=sOtdJDyeh6xFcI5TpIaxn7yZfqmZstCbnd+R2f04bt5CByQ27EMXUcX1BNLYxmWDYc
         pcHL3bwD2w7354AY4eqoO62xJpsIivvfP69pVWo0grffomxHIo+k19galaIyRiHIcVFy
         5ho0vrWHFJ6lWAHrfwiZzC6pIrsLO1/KFdVZTTVfLw3OC1rEe2xbFvT+8fYdDMXYd0ML
         +R03oz8QaF+8p3QvGaWwW0Gx7SqvA52lCtnhd2cHoJg/ocEUyVxPkHsYqN/8baJ4cZUL
         4Z3lwD4s6hL+1+/2gz/l55Xd5cwvqBCWckKF4RpHnb/xdrYjYrIlPxTUNsHyDdY+J09S
         SRVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=oLdm8h8QSGbAQx38fdnqCF6ugKh1DTiKNt8rj8x52oc=;
        fh=yzZNqt8UI9zQbX6SDSxZ33uaTGtLR2JTmNky+hkP7as=;
        b=gxRfCaahnnKZN3x2FX0JQj79CxuJ6W72FA/1B8QhUiCk1GlmBoJYYIjLBOmHCZrVw6
         Jh64kDP5eduv59ml8VA7cZDttOSRwxZm20JnIdtAo5jJDWYOt/TyxnrbI8uAJNWZGn1v
         P4BJqmpnuiI+gB2roJDhCzTcJsKCtKbPoW+otLNRGdns/e5LpRK1xjOAmOs8zmT94EJJ
         W6GQk+N+hZynji0dD63OGsFsdCMeSRoX+il0C82JpGyIVFe8yS+CYCFjWnpei4ML+2Bx
         FlJWJuvZ0F9vCAFot8NSenabegqKWW4qa4uZ1m1mpKw6HUoKJBCjIvWH2Bqu4bJvAUbS
         /N9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZuVryVfW;
       spf=pass (google.com: domain of infobanqueatlantique001@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=infobanqueatlantique001@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12f.google.com (mail-il1-x12f.google.com. [2607:f8b0:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id z2-20020a056638240200b004732e25d67csi245119jat.4.2024.02.18.18.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 18 Feb 2024 18:59:45 -0800 (PST)
Received-SPF: pass (google.com: domain of infobanqueatlantique001@gmail.com designates 2607:f8b0:4864:20::12f as permitted sender) client-ip=2607:f8b0:4864:20::12f;
Received: by mail-il1-x12f.google.com with SMTP id e9e14a558f8ab-3650df44657so5858395ab.0
        for <kasan-dev@googlegroups.com>; Sun, 18 Feb 2024 18:59:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX4+087lrO4yUALnOL2iyBwD6/cUUDPOVo3GERFmqzp4obbE6256SKBOJgSd5mhvTIzXsoGzxvHvt5FwoHqpo4HERIV4kIgau6SsA==
X-Received: by 2002:a05:6e02:1147:b0:365:2b8d:e26a with SMTP id
 o7-20020a056e02114700b003652b8de26amr2255001ill.1.1708311584924; Sun, 18 Feb
 2024 18:59:44 -0800 (PST)
MIME-Version: 1.0
From: ROSE RICHARD <r2000016@gmail.com>
Date: Mon, 19 Feb 2024 03:59:32 +0100
Message-ID: <CANNWOeL47QN14QG8gzusr=fLG67n8NgWZEcjXqpJ+MugdCp+2Q@mail.gmail.com>
Subject: Hallo Schatz
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000002f718f0611b34945"
X-Original-Sender: r2000016@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZuVryVfW;       spf=pass
 (google.com: domain of infobanqueatlantique001@gmail.com designates
 2607:f8b0:4864:20::12f as permitted sender) smtp.mailfrom=infobanqueatlantique001@gmail.com;
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

--0000000000002f718f0611b34945
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hallo Schatz
Ich bin Miss.Rose Richard aus Abidjan, Elfenbeink=C3=BCste (C=C3=B4te d'Ivo=
ire). Ich
bin ein 17-j=C3=A4hriges M=C3=A4dchen, eine Waise. Da ich keine Eltern habe=
, drohen
meine Onkel, mich wegen des Erbes, das mein Vater mir hinterlassen hat,
umzubringen.
Bitte, ich brauche Ihre aufrichtige Hilfe. Ich habe (3.500.000,00 $
(US-Dollar) Drei Millionen f=C3=BCnfhunderttausend US-Dollar, die ich von m=
einem
verstorbenen Vater geerbt habe, aber er hat das Geld auf ein Fest-/Suspense
Konto bei einer der besten Banken hier in Abidjan eingezahlt, in Absprache
mit der Bank, an die das Geld =C3=BCberwiesen werden soll ein ausl=C3=A4ndi=
sches
Bankkonto f=C3=BCr Investitionen im Ausland, er verstarb jedoch, ohne das G=
eld
zu =C3=BCberweisen.
Mein Vater hat meinen Namen als seine einzige Tochter f=C3=BCr die n=C3=A4c=
hsten
Angeh=C3=B6rigen verwendet, als er das Geld eingezahlt hat, und das Geld ka=
nn
nur auf ein ausl=C3=A4ndisches Bankkonto =C3=BCberwiesen werden.
Alles, was ich brauche, ist Ihre Ehrlichkeit als mein ausl=C3=A4ndischer
Berater, Ihre Hilfe bei der Anlage des Fonds und Ihre Hilfe bei der
Fortf=C3=BChrung meiner Ausbildung in Ihrem Land.
Bitte bekunden Sie Ihr Interesse, indem Sie mir zur=C3=BCckschreiben, wenn =
Sie
bereit sind, mir bei diesem Zweck zu helfen. Anschlie=C3=9Fend werde ich Ih=
nen
die erforderlichen Informationen zum weiteren Vorgehen zukommen lassen und
Ihnen anschlie=C3=9Fend 20 % des Gesamtbetrags f=C3=BCr Ihre Hilfe auszahle=
n . Danke
f=C3=BCr deine Besorgnis.
Dein,
Miss.Rose Richard

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANNWOeL47QN14QG8gzusr%3DfLG67n8NgWZEcjXqpJ%2BMugdCp%2B2Q%40mail.=
gmail.com.

--0000000000002f718f0611b34945
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hallo Schatz<br>Ich bin Miss.Rose Richard aus Abidjan, Elf=
enbeink=C3=BCste (C=C3=B4te d&#39;Ivoire). Ich bin ein 17-j=C3=A4hriges M=
=C3=A4dchen, eine Waise. Da ich keine Eltern habe, drohen meine Onkel, mich=
 wegen des Erbes, das mein Vater mir hinterlassen hat, umzubringen.<br>Bitt=
e, ich brauche Ihre aufrichtige Hilfe. Ich habe (3.500.000,00 $<br>(US-Doll=
ar) Drei Millionen f=C3=BCnfhunderttausend US-Dollar, die ich von meinem ve=
rstorbenen Vater geerbt habe, aber er hat das Geld auf ein Fest-/Suspense K=
onto bei einer der besten Banken hier in Abidjan eingezahlt, in Absprache m=
it der Bank, an die das Geld =C3=BCberwiesen werden soll ein ausl=C3=A4ndis=
ches Bankkonto f=C3=BCr Investitionen im Ausland, er verstarb jedoch, ohne =
das Geld zu =C3=BCberweisen.<br>Mein Vater hat meinen Namen als seine einzi=
ge Tochter f=C3=BCr die n=C3=A4chsten Angeh=C3=B6rigen verwendet, als er da=
s Geld eingezahlt hat, und das Geld kann nur auf ein ausl=C3=A4ndisches Ban=
kkonto =C3=BCberwiesen werden.<br>Alles, was ich brauche, ist Ihre Ehrlichk=
eit als mein ausl=C3=A4ndischer Berater, Ihre Hilfe bei der Anlage des Fond=
s und Ihre Hilfe bei der Fortf=C3=BChrung meiner Ausbildung in Ihrem Land.<=
br>Bitte bekunden Sie Ihr Interesse, indem Sie mir zur=C3=BCckschreiben, we=
nn Sie bereit sind, mir bei diesem Zweck zu helfen. Anschlie=C3=9Fend werde=
 ich Ihnen die erforderlichen Informationen zum weiteren Vorgehen zukommen =
lassen und Ihnen anschlie=C3=9Fend 20 % des Gesamtbetrags f=C3=BCr Ihre Hil=
fe auszahlen . Danke f=C3=BCr deine Besorgnis.<br>Dein,<br>Miss.Rose Richar=
d<br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CANNWOeL47QN14QG8gzusr%3DfLG67n8NgWZEcjXqpJ%2BMugdCp%2=
B2Q%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CANNWOeL47QN14QG8gzusr%3DfLG67n8NgWZEcjXqpJ%2=
BMugdCp%2B2Q%40mail.gmail.com</a>.<br />

--0000000000002f718f0611b34945--
