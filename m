Return-Path: <kasan-dev+bncBCA6R5545EJBBTFO4ODQMGQEHDQWQCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id ACA5B3D1BC1
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jul 2021 04:26:21 +0200 (CEST)
Received: by mail-io1-xd38.google.com with SMTP id b136-20020a6bb28e0000b0290520c8d13420sf2934076iof.19
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 19:26:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626920780; cv=pass;
        d=google.com; s=arc-20160816;
        b=LyAxIp5B/vr8s8UBhKNwwjVjqZOeW4N2p3aYYSn6PqiD1fnMU2uMXyK+/4YL6IbTvs
         Gmu/pzGrph9jIugzVtyHcVKw5Gbxihn7wM2FQu/W9wu+TJUrHoGcUL01/JBwa4Ia+LhK
         YpedIkKZ2kprpxSJAqWmy0Zd+lFIbJHilVz5MNZVEbGecHftV/0zCh+k+ccr0EjOfAcv
         y1lcynWRDrtGQPe+b6b/pKgyVxUOS5CExRZuZkxkirkTf5V5KZ+1Oq8r0Lf03EB8fiC7
         6KrzIJyncJgpuKL2OfBAEGQnWDY+9qIF0OrMHGv0rMjn302QYrNHbOwD49yrhHe9tgYB
         T+Og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=tlRzCPqNV1B1XWdUkCA9894waHv9mCIMu9EgIwDGhKY=;
        b=WhMddzfYAkifpiSvTDJxppOvQmIlCU11ZSphs54XecIO+PHGKDlxUPXJpsn+YOClcY
         cGNWQIrqIMZ2unGu99V8lPn9LpOnnCNPO2DlYyFJ11Iohq5k+6isB30p6VKZmENibbBH
         zJ/9woKLHIWgyR4kI2F586qmlWWapofMgkJCi2HIsL+qm5Kjr23lhY+Qtk+uUJhJ2Lqr
         /sUCWsNyfx6neKXQ9hCHyJ5eYudEWM9bsSgOZL/7ZwxOCFTtjzcAyZd34WH1JeCc5UTw
         1HFLPxC0QZK7ISPNxt2m/MQpOFdb0REJBX/VnsIDSuogHujAKpyaUWSCtS8cgZVcgwSm
         1dcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=OIYVNWor;
       spf=pass (google.com: domain of fshconsultantsgh@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=fshconsultantsgh@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tlRzCPqNV1B1XWdUkCA9894waHv9mCIMu9EgIwDGhKY=;
        b=FbCuzqjZS9PwFvvPuA5hWt1lS9E910JPTqUhu5dAH8aiwhGZWD4nWW/lLAWeB00zcx
         T3hVY71xh6GIW7Av4MWIf6Wbcr4/uXXtMzyhqL+u0K8swmHRqLzYdl1GGDsY6a8rkown
         VoHG8huuT4/0a9S0/VJtPEOeqvQbwn9aJQ9N1E/zotCbWEYplQmK9oLayxNGzDiyPmO0
         GtnYrJK3U9SWUnckxFLbjhben4bch7o3bsw+wwd4cU+OgW8BSJDebNPfQd4tNks1CG4+
         1as6vAxBD8WL/XM3L4lPnczULeNweQPNwuHxCeV7mjn33t3fxdnjMRXUVM+NDA1a2Yay
         np/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tlRzCPqNV1B1XWdUkCA9894waHv9mCIMu9EgIwDGhKY=;
        b=m90Tzi3Cry4MFjZ3rTm3uyLko5H5ArLz5AjZihcUn9CXPoAZbzKwG6hRJL/d/Z+C1c
         HIKnIII7IKpDQC8hjRSaPezZ8XeN+mrUG9DLu8v7miFQzsDyZh55JKwatN9kIPO20ieo
         SwlsjWGXkwQW/dJ39KbptxMkghefkBhHYeVIQDt9pj208110H9j0ZTLIoZBqMpwT7Lp3
         Q3erdkCBy8QSmxZqaXGu4x6hw+AhUrHQr6fiU1POwUDjU2ZmOyyELNDP3765vBbsRJgo
         fQAbVpjfi6F16iNigP93rmID3ogclbApqSQ6GjHZwO7DVfto9ZnDHtX6z51Vu1JylJvA
         9Hvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tlRzCPqNV1B1XWdUkCA9894waHv9mCIMu9EgIwDGhKY=;
        b=LDUZpDDW3qiDhaJGJMKEyWAMJy/i5hhetU+PpUITY5WGHT0QbsWyWLZuZzbm0OMdEO
         r30K2/5DpY2NO1tDWs0NE9QUbqIIUAvfibnEsTFTlKy4vldFL+nN/8e7pSrhPaNA1yW7
         rROMCXHKDJwqIlWLYpKWo8rmkTZBTF0r1/+ICOxBUn3BLpVlgCifW4XX6y71UEvf2+va
         T19qougpbcqhWOw6MjI5oGJgdoPYgP/xfpkmXhISX4n5FbHma/0USwj9yZTyWP5hmykp
         J6Kel2cijaeBWA5Kcl0yB9mqA5v/UUdQPgfZsnZPczcN8whetuCxvdwGVV1UyJfD9Ccv
         gSZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZP+nE1w0na22hhduLUwXgLy2YhYHJZR3wXabqPTFtb12upd47
	5ZRtxSnPCUV+nCLhv2IoAQw=
X-Google-Smtp-Source: ABdhPJy+7vJXZW4RU4vs1sCU+iNJXb5tL5jUuQKaLW6YUSrIfudbwa39IC9x8GTvpdVMkg/ESfH+1Q==
X-Received: by 2002:a05:6602:2057:: with SMTP id z23mr14358995iod.29.1626920780582;
        Wed, 21 Jul 2021 19:26:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:4bc5:: with SMTP id q188ls776490jaa.9.gmail; Wed, 21 Jul
 2021 19:26:20 -0700 (PDT)
X-Received: by 2002:a02:942e:: with SMTP id a43mr34110239jai.74.1626920780199;
        Wed, 21 Jul 2021 19:26:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626920780; cv=none;
        d=google.com; s=arc-20160816;
        b=NE1iw4H59iwz32dB1NXqKrsVD8CHjryV8UkKWHlHf0BS2gqEdHVELSHAmbSC0RbYW+
         2mkWTrV+LBJUvZn+VtL2EzhpEpOJyK2s10Wu1ZKgqd2vd6ruQPGzGJCnOhQZCpdgQLPc
         iq5Zr2l4mPOxjKrXo67gD9IiaJ+AgOTuJRchH3IXfShczY+k0WjtKT5VsvzBuR0b5VlX
         P/9R4xNy3qiBi6DTycBMjCzQdJsP96Vo0v5pX4DMLJ4DChysHGwDaEpCr4XPOJhTBneV
         eZ+UZVRiYcJd0Q1DNK77cG9wpLwb8FfO/mslGgHHiFN5oaD4xet7MtRw0fXgsfIT6LgF
         S1tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=yO8r+FaKYp3ZV4LnMz7AOPSZyr0u6fQYe8Uu3YlXSb8=;
        b=jptZFb8Me3TgHb/DP8df30GW1iQiCIRIfp5MIlRwv7feu9OBt6hmeseYJGR0H4acEn
         Km3p87t5mcbVCr/wCsUQZ5/f33E4jk/BnNaD3iz9hCZ2KIESxjIndaTn+ujoaratIpCi
         NiyQoOeJV16/eNhTObKcl4cFk02BAwua1GacuK6YNJ8wGjt6pSrsx+PYXifrphq915uJ
         5ytXMoT3c6ckhpZGsFLNaoIyZcxOeCI5sVGJ5j7lZzK1bi5Xk7MpXoM+kRKy6I1MX3h4
         BF0s6cl+Cf5J0fi+Plw2j2201kMNUDFmHhW57BWkKO2Px0CBVUkVGr5FJpI44KPRiC4M
         RGdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=OIYVNWor;
       spf=pass (google.com: domain of fshconsultantsgh@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=fshconsultantsgh@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id q14si329689ior.1.2021.07.21.19.26.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jul 2021 19:26:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of fshconsultantsgh@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id l5so4642681iok.7
        for <kasan-dev@googlegroups.com>; Wed, 21 Jul 2021 19:26:20 -0700 (PDT)
X-Received: by 2002:a6b:b883:: with SMTP id i125mr29474369iof.104.1626920779974;
 Wed, 21 Jul 2021 19:26:19 -0700 (PDT)
MIME-Version: 1.0
From: FSH CONSULTING GH <fshconsultantsgh@gmail.com>
Date: Wed, 21 Jul 2021 14:26:03 -1200
Message-ID: <CAC8T_6m4=EaDAJrx=nc-RRsfF+rx0619HM=yoxg5WfvyiYF6pg@mail.gmail.com>
Subject: Hello
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000002b0dd605c7ad03fb"
X-Original-Sender: fshconsultantsgh@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=OIYVNWor;       spf=pass
 (google.com: domain of fshconsultantsgh@gmail.com designates
 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=fshconsultantsgh@gmail.com;
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

--0000000000002b0dd605c7ad03fb
Content-Type: text/plain; charset="UTF-8"

Hello.

How are you doing today? It's my pleasure to introduce myself to you.

I am Mr Nana Kwame a financial consultant whose firm is here in Accra
 Ghana West Africa.whom also have branches in the United Kingdom and United
States of America .


It will interest you to note that one of my financial services includes
procurement of financial investors to clients who seek for financial
partnership.

However our services cover mostly businesses such as gold, diamond and oil
business.

I can assure you that should you be interested in our services, you will
not be spending a dime of your money till the business is  concluded.

All I will be needing from you is our maximum cooperation. As the investors
will shoulder the financial expenses, and only take back their money and
additional 30% from the profit proceeds of the business after successful
execution.

Kindly contact me if you require my assistance as I will gladly work with
you.

Hoping to hear from you, till then remain good and God blessed.


CEO: Mr. Nana Kwame Addo,
FSH CONSULTING GH
P.O. Box 1452 CT; Achimota, Accra Ghana
Email: fshconsultantsgh@gmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAC8T_6m4%3DEaDAJrx%3Dnc-RRsfF%2Brx0619HM%3Dyoxg5WfvyiYF6pg%40mail.gmail.com.

--0000000000002b0dd605c7ad03fb
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hello.<br><br>How are you doing today? It&#39;s my pleasur=
e to introduce myself to you.<br><br>I am Mr Nana Kwame a financial consult=
ant whose firm is here in Accra =C2=A0Ghana West Africa.whom also have bran=
ches in the United Kingdom and United States of America .<br><br><br>It wil=
l interest you to note that one of my financial services includes procureme=
nt of financial investors to clients who seek for financial partnership.<br=
><br>However our services cover mostly businesses such as gold, diamond and=
 oil business.<br><br>I can assure you that should you be interested in our=
 services, you will not be spending a dime of your money till the business =
is =C2=A0concluded.<br><br>All I will be needing from you is our maximum co=
operation. As the investors will shoulder the financial expenses, and only =
take back their money and additional 30% from the profit proceeds of the bu=
siness after successful execution.<br><br>Kindly contact me if you require =
my assistance as I will gladly work with you.<br><br>Hoping to hear from yo=
u, till then remain good and God blessed.<br><br><br>CEO: Mr. Nana Kwame Ad=
do,<br>FSH CONSULTING GH<br>P.O. Box 1452 CT; Achimota, Accra Ghana<br>Emai=
l: <a href=3D"mailto:fshconsultantsgh@gmail.com">fshconsultantsgh@gmail.com=
</a><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAC8T_6m4%3DEaDAJrx%3Dnc-RRsfF%2Brx0619HM%3Dyoxg5Wfvyi=
YF6pg%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://grou=
ps.google.com/d/msgid/kasan-dev/CAC8T_6m4%3DEaDAJrx%3Dnc-RRsfF%2Brx0619HM%3=
Dyoxg5WfvyiYF6pg%40mail.gmail.com</a>.<br />

--0000000000002b0dd605c7ad03fb--
