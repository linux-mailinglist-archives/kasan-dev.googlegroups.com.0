Return-Path: <kasan-dev+bncBDRZDJEH2UHBBQ5K2W3QMGQELPWH5RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 998479873AE
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 14:36:24 +0200 (CEST)
Received: by mail-ot1-x338.google.com with SMTP id 46e09a7af769-70941d49c08sf468875a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 05:36:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727354181; cv=pass;
        d=google.com; s=arc-20240605;
        b=CeXFK0MEeiuvBrqjLSaiGIGwtjGZ0rq8zZWCd886wzMsFA/mExmG+iz2piset+GDhJ
         yI+1t4POfjN5K/NPE2tAv/MHceRZMHtT1Zq+NsgD4dJM86weSHP7mp0Pb8Zn4jV0gRox
         6FadtLN8nckXV9c56Kje1021uuolSpLFAtADaEPIPLf1XWmvWGNwPDQi3Flwb9tOmfo7
         VZfdTmFIE0ar+q6ySD70TgSm2xRHDzfwZJEMQIOBLTK0mo5u1r03Fp1YJEt8EiluncNt
         IRmvwFuCzAto0xv/eInfwgZDmNTwzfK/JWM8snuol09Gfz5dSg+Tn/cbZ7UHHw+Cy4oP
         72mQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=fNp64M3yc+7E0bIgOoYsuWU3JWcRROGwmNjQhX72fpo=;
        fh=fLBn0Wa0Dnj9dxG0hxLzXZoWiEUTKSk1LZEwHMgjyvI=;
        b=NfmqoSpuA9871/k51g6soaODCBjXY7FYTcSYQLqMdPHxWZ3LWKcMQB2HpyJlicWxa7
         nDiFOrwDR0G82WEslZ/74hkvvUer1A+HsO29pWV2GAgeTt3JRwrZ8KCdO6YxHM3tgZoy
         ogVlt28lfzC5dotCWV0M/enIOelAnF1gPmMHHiyIpQOaSQ9XXlgm9dquZykoHNwGBGkE
         1MrQX+yW4FtAT+lPnG+IJlKBPr3odRzLEB3304VBOX3E31orcnyfUFBXrJrTDYI9hxi8
         U6L/wDr+NUdDkGLHbB1lvil1LTlsmNupUVikKanN1nRSFFxb/gNn4W+1EyzHbiz4n8hr
         wFJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jxHQS7hG;
       spf=pass (google.com: domain of bahajoy63@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=bahajoy63@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727354181; x=1727958981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fNp64M3yc+7E0bIgOoYsuWU3JWcRROGwmNjQhX72fpo=;
        b=KoJxu2J4FQ9AaZwnFpbXyrHzKWEXk8IpeF3pQ14jsmuVX2KTP+Di5KYOhcupJFrWpy
         lhl9QhA763X90XGqhYBLChbZT+ObHZv3rAiSB0mZl8fKBlHKdAoCG18Ed4lpmaBJaSDN
         6WlJxFpTcdEfdHKNbTGVdiQiHKKLhiO1V9IwxoGMjRPuR16C2Tz19Z86v8NrjlF2DTdw
         XAhZ3STmiHW7PPGB3zLQcmFgm6XjVj+VokqawIjH4bA3MfOEtqWszE0/qVdYJIqpp23L
         yxZ0KftyuxwrPkRWRTWBuUo3HPDv9U3aI2CG/s34ppyneQfnURycXZOVut0d5GrptrQ8
         e7/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727354181; x=1727958981; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=fNp64M3yc+7E0bIgOoYsuWU3JWcRROGwmNjQhX72fpo=;
        b=m91foH10aNljJNoHhz/1I8DvibbZXwF7NnlzJ3s8GSjIe0oOdcUbzl73SEgWsJZHrq
         kW87ZcAtB1oANeZiwve6Y92P9t88jXrlb6k4Vjz0dQzDdFrMxc4hdyP5xCaTuCmsOj8L
         2jXmMYZTDFoStCYJA5I1c1F+Yw4aFfgIOOnL+m6KGrkAZmipBUVLs7VSQu9c8EkzkbuV
         phgELKVw6/7MRfvX0wqiZjyBBi06JN36zbqITeANV5wPowAWYT1jk5Zp/ehQOlhVYKMd
         UJmLEUtYJuYpl7BuFGoJgkdU6fwORQ8FSj30t1QUUhT12Tw/gAmDWJGsQ+4KT/SvCF5u
         NFkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727354181; x=1727958981;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fNp64M3yc+7E0bIgOoYsuWU3JWcRROGwmNjQhX72fpo=;
        b=UONaHoKVBpS/8l6q+P3PKfXb7qM4KA/kS2B65Xn3HbthAcXhp61KS7Liw1xcicrP/k
         HszdE0Qk6DkOexX79UIXJSD7J9bbBZ1OMGM18EbBseHA05ekZVEoJ15yCrAp8iFCcXet
         i5fvFaSRkc0oCXy7uHXPSlmhEJh8lfnnVclgKmoxuoRs4VMmZ1+ZSFbN9RrFlmm/3rLG
         dBFuQAo0FbBKKBpWEEk8qJvupIm1VYTFvUPzcfy7hQx/pGM5uosYgdaloxeOnE0xz0L3
         z7e4MPHQEP0pQ08m3tbsfnOpxCVUPTVJH7T/DF0JYCLzCRDBL1cjf+ZSrZAPFrUDnXnm
         3Avw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWyR5e6WwUekApm5H8yfY7jhQ9YC0kqVnFKt+8USUvErid/t+7MT4wHdRDM4dI3KD1urwQh6g==@lfdr.de
X-Gm-Message-State: AOJu0Yz8prbAOSDlVTikJ1dH7La0ORGn6uOFSzTSDiCR2Rid6xTczbyB
	NkMSYyC08xLb4vaPfsZ9hygP7tg7SYVBrNUCsk+9yqXGyUal9aCJ
X-Google-Smtp-Source: AGHT+IEO3TqJqU/wA1zDXzL3Ph0qmGqZ8zad12pkV5byC0hpfV8ecjoXfT/rkSbdy5/cZ8v0o69cCQ==
X-Received: by 2002:a05:6830:4181:b0:710:f34b:b486 with SMTP id 46e09a7af769-713c7e1df44mr5078007a34.20.1727354179644;
        Thu, 26 Sep 2024 05:36:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e79a:0:b0:5e1:eb5b:d265 with SMTP id 006d021491bc7-5e5d451be40ls415299eaf.1.-pod-prod-08-us;
 Thu, 26 Sep 2024 05:36:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV5y3NFl2wn4L1P3y4VlnOFPYykH9eGop0gMLusJynO0umT7op93FuBdeZmvdlMS9iSy3imjaDHcIA=@googlegroups.com
X-Received: by 2002:a05:6830:310b:b0:709:30eb:dfcb with SMTP id 46e09a7af769-713c7dc0610mr3745598a34.18.1727354178711;
        Thu, 26 Sep 2024 05:36:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727354178; cv=none;
        d=google.com; s=arc-20240605;
        b=Oj/L1TnSsZ/HYtMsopDvhqVBgeCDLrEP2RMTbnKKgMf3IWGeCxFZgSQEUnSfXMuFU7
         hJCcAkBGC01756x7A7Wa82Mjkv0T17oezz6b8lII5hwT9AtLweN1veKtokWj2BkVyVHO
         eKV9JASOvItUEZ6ad4Mfn7LIVxOC2nH64Ya3TG8JO2dqJIRHZlTlGsykLBRloprmMt3I
         9CPVjeY6O6/gNW8xRcQw7ozmGOjbuBxnBhskgmm74Ek6GEa3BB3RYylTthuZUkNRHCO6
         89891fWZpz4cjeDWtlh/FDJl4+rJvZawXa8cIf0yj92VtdV7biiKedVe57X+gzMUiGuc
         NdFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=6F423oy/JLkYI4CLH3J/seCMLOnSiPro3rifwg7CYzA=;
        fh=4mHCevXS/5BH3g1erpSXBtMRaHel5jFcnmNCVPDHluo=;
        b=ki7EuvfDJoWJwN6SWdo17v0nF3gP96apZhzCiZ64zcNs7UU0aaVnoDIRsIChk9f2yV
         5C5P7ILNG7rjOL3W1lIeHW5vTHuHuuR+0mmjt1u52/WbnGVX40BSCPBOdkWZaDl/IIeS
         ZRZof/Qjp9Z/wZiIowrBRdKxlmwqN2uFIbgXIr3UAuhmjV7oUtjOtc6sQdAev5U5pnM5
         7lkCqq0rMPx6tqUYd+2JBvakITE2f5IK4Q7AMf4hqVLCdToOVA6YH41j/yUuFXbSvyFq
         GDSiIoDhjKxpOEF4rBIncf0zIPOVZercC7dSbkyahBQxV+F2BGRfpQl2Y/+Zl/fSQQsv
         yTMw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jxHQS7hG;
       spf=pass (google.com: domain of bahajoy63@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=bahajoy63@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-713beaa1723si227932a34.1.2024.09.26.05.36.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Sep 2024 05:36:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of bahajoy63@gmail.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 3f1490d57ef6-e24a2bc0827so913319276.2
        for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2024 05:36:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWA5txpYdrWWJS87M5+1KJXXodKNzIl+qaghCosdAfuhvNSlSIbsVOe1GlQKyg+2VkMIrrAPoIrEqg=@googlegroups.com
X-Received: by 2002:a05:6902:1613:b0:e21:3cce:3a99 with SMTP id
 3f1490d57ef6-e24d9ec0aa8mr5672091276.47.1727354177437; Thu, 26 Sep 2024
 05:36:17 -0700 (PDT)
MIME-Version: 1.0
From: "Mr. John Robinson" <jhrobinson1956@gmail.com>
Date: Thu, 26 Sep 2024 07:36:05 -0500
Message-ID: <CABbyfzDGzk8-vRbcBBCRLD7aQNK5wdhA=nUpQkwYiT5Ahy7r1A@mail.gmail.com>
Subject: Donatie in geld!
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="00000000000025c88f062304fc44"
X-Original-Sender: jhrobinson1956@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jxHQS7hG;       spf=pass
 (google.com: domain of bahajoy63@gmail.com designates 2607:f8b0:4864:20::b36
 as permitted sender) smtp.mailfrom=bahajoy63@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--00000000000025c88f062304fc44
Content-Type: text/plain; charset="UTF-8"

U bent de gelukkige winnaar. De som van (EUR 1.500.000) is aan u gedoneerd
door de heer John Robinson. Reageer op de e-mail voor meer informatie

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABbyfzDGzk8-vRbcBBCRLD7aQNK5wdhA%3DnUpQkwYiT5Ahy7r1A%40mail.gmail.com.

--00000000000025c88f062304fc44
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div><div dir=3D"ltr" class=3D"gmail_signature" data-smart=
mail=3D"gmail_signature"><div dir=3D"ltr">U bent de gelukkige winnaar. De s=
om van (EUR 1.500.000) is aan u gedoneerd door de heer John Robinson. Reage=
er op de e-mail voor meer informatie<br></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CABbyfzDGzk8-vRbcBBCRLD7aQNK5wdhA%3DnUpQkwYiT5Ahy7r1A%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CABbyfzDGzk8-vRbcBBCRLD7aQNK5wdhA%3DnUpQkwYiT5Ahy=
7r1A%40mail.gmail.com</a>.<br />

--00000000000025c88f062304fc44--
