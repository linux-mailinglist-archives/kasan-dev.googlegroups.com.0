Return-Path: <kasan-dev+bncBD4YRJMIRILRB5VD2K3QMGQEPECBQHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CAE9986946
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2024 00:43:03 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-458278ff48fsf4584311cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 15:43:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727304182; cv=pass;
        d=google.com; s=arc-20240605;
        b=ku/BGYIIOnQ3WB4YaWPGFBEO4n0wB2Ue1TnenZ2t6jzU7HEgX3s95/pQMU9qabvEKG
         BdRGo9oJnluGb6ToUkDDhw7dcyvhe5ptlRS5fZe75m1fdYuT5XW6oUrh3EJfpMHJ5/vQ
         eytn+hS8podR95AKeGG9Sj/R0SRawD2nUk5c8Rhq+v37bBypKQHHhgb7VsYo7FNHwkS1
         DqhTahINfns0g78gEsOm5fvH7uCcvBmtW/GkaSpK3EFZlMv92TOQij1QyIVahYKIxlR8
         IhyasOux/UhvieESZJ2PeQ4Ebw0/dUouqMAu3GQo2faF9Cmp4Se/9WjPPt/eSNAuRSVF
         hzBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=kiU272Tk7M7Xt7RpsZ9eWOf5aWBTtTx+Zf/3bNcqPec=;
        fh=BiPneaRTNxZsVRvWoS2NBjDgIb0C5RGcTo+IsQRM3X8=;
        b=cUTsxXI8KUMr7CL2LecUhuMvewIcdSqiwwfvIKTTxcws3mmIujOUi7hFPX/xI8P0yA
         s3DsBKCzppQU5L2CVGmavtqu6Jy/vMZNXc1Rpi+UhDZOiM0SGXUYY6sDV7PnEIeaVnnv
         8j6eAXqaKcNZay8YIXG/+LtOXsM3PCrTTDa9eEQ5QRI78bmOARFelWNq+8RG+MisRJu7
         bQOd6PJM5Ae26y99bETAF8bYeDu8oVjuDQRYBy83ymroDzf3cYW47wewYbyaIj2dIpFe
         yhR6d3AXM/7AJp+OnWWlufJxWonKgXc9mkdICI6AoHNVQcHsVXBJj6JnIpCGXcSfVuA9
         Cj3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GIgnxgUS;
       spf=pass (google.com: domain of izuchukwuajima@gmail.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=izuchukwuajima@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727304182; x=1727908982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kiU272Tk7M7Xt7RpsZ9eWOf5aWBTtTx+Zf/3bNcqPec=;
        b=V0tTBPkcG3QXHkirfy5PJwZCN2ogvGtF9b48lhnj6sQgGH6VRaLzh/9glF51NbVeFN
         tiMWvZh92VpqjpWb2tPw6fOvBmRDy33Hkh6g7D789M5C8cVD0xSzb6QI4ROvxYfgLCaG
         GBbDDCXqFeEjrtCVQtNmTrQvsQHcFom7if7nhxwaPEgEKYDJspefyGwsaBerQ2L8CWBC
         iQFz4/J1HTQGiulRGczk2gKStYNt3LySJAZa4HRI5G70NiU9QDqUA9hABZUnEaINFhhN
         0b98yUa+V/lTt3ne6AFS4staNwKd0Ypdi8cX9NPrRn6I2wBlp293ZrYEZmLVxGp7M6E/
         eGZA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727304182; x=1727908982; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=kiU272Tk7M7Xt7RpsZ9eWOf5aWBTtTx+Zf/3bNcqPec=;
        b=GFuyM3jaegBkVKH5HnpY7sTgojMLCt8rSNdF5GdMqpIvDIwwmlNmy4NCq9IOIXJImm
         nB6+elQCfjqJaGxOYLp/iMJzEoqBlpHUqt/2xj/QWc6isA6Y/aBgj5T+sV0SUZBIVIFC
         tqBRi8V+2tlEEXsmIgO9hndwf6/BU0yLkc6eSroUzBlfjwxLjWfW5ZmhmE62XGMBejbt
         7TGZOe+I0W73wk/A+udSIoNWWNOgka8n5+CjNnyNSzXfn/dGTqxzW67zkuFrtYqyCnjz
         zEaEZQeBWqB2rNxT/5Q5sym37T4fpOXPDisIqsplOOpVTk2A3hrtQoGTrXI9pme519hH
         JgMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727304182; x=1727908982;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:reply-to:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kiU272Tk7M7Xt7RpsZ9eWOf5aWBTtTx+Zf/3bNcqPec=;
        b=ZbXuXhAnYTnp7qLyfNBTX5toruDBkoUZrzFL+qhSNNijBzWSAPikTYURdB4AEGEDxl
         NOIVMM4i7FLpuG5800kdidQ6+hDetjCgEgZKUFsWp8GLHW6HizlFplK6UMzsfNQS3Jly
         BgLRZNZ9X3qUQqXi3Lro9zQT+Nc1XFZ/mQMoc/d4ZHzcK518C9MaOJ/jd7/6xqvWwj2l
         J+X+Cc8yvs2LwcnItKAxD0q6V0HloVd0BYuI+uWH7pFbkH4kS+hC4GDvJ0+NCIxRku2w
         ju3+HzuDVxpiMMwMykVnifigfk0N+PW8ckXLDqW3wSsmJ9CCR2/QmlXaaVRuhM5WWLPh
         InYg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXDSlT36RRPioWB0wbHJBCUk5EPlEXBJj92hWwD0nNO4B3XfoEicDRnvbom3w08T8NyyqYJjg==@lfdr.de
X-Gm-Message-State: AOJu0Yz0BDljqdXofTfLbEsB7YZhg1sw8JKg12PDqC5JsQTLXrhpHsIu
	NOf9TD+oS/O0KEgqNm//HwvGiO38ztniTL6zfoYVo7WcFN4soJ1G
X-Google-Smtp-Source: AGHT+IEfxNzh70vgeEAdBrAmMnZJtqFOpkwRBaqEc+C9lLP2FVkcvHbI+emzFTZ3MD4OokyuL1l6lA==
X-Received: by 2002:a05:622a:1189:b0:458:5bec:41b7 with SMTP id d75a77b69052e-45b5def1a67mr72516811cf.26.1727304182120;
        Wed, 25 Sep 2024 15:43:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1a19:b0:447:ed03:aa4b with SMTP id
 d75a77b69052e-45c94ae1737ls5835581cf.2.-pod-prod-09-us; Wed, 25 Sep 2024
 15:43:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV69P5ZcmD90VuoSPIaOPvMAAzIzaYZCJklmghYPEgKerlLUW82UBh+rZMmqVSQm0q3af2t9whShPM=@googlegroups.com
X-Received: by 2002:ac8:7c47:0:b0:458:294c:39e7 with SMTP id d75a77b69052e-45b5e02c757mr57664041cf.38.1727304181413;
        Wed, 25 Sep 2024 15:43:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727304181; cv=none;
        d=google.com; s=arc-20240605;
        b=FU7bif8AIsnpZUaPMEbAB3Zx1JQezfFAdomd9W1kz+X+vWwiA4L3ww6hx+O2qAMG0h
         55DI9TauidCuUZT5nA4MNzYbaUFU3yX+BtnGUv1EQdlMT7bfnHlrA/m31jWhWAUh8P2L
         PqZl0ayTpPJnikx8b7JfM5u4ItPjd752S33Mf+ISLbotjQOmPTbPMGVvg1ZHI63jzhT7
         LeMVWaGRHQyZli/uXnX+f16B+p6KEq4b+RZfM12D3vL6hEqaBm54iNL+9JP/XYFP9rjq
         RjlM9jOsH53bWbtsCsdd+iZtUUaA93jhfhKLhjfZMPM4otWoW2EvATw/ITTvqlbnpiCO
         2tag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=xIKx4DAZfAQcloYeydUG/pS60Uby9ZxqYqME4LDmlAM=;
        fh=r9QKVjVdSrLIAIoxs5gpyjbFkDnjeTtS0ElHIxJlbQc=;
        b=PAIrBS8kcxT+qms47i2bkP1PF3JTJE45tYL5R3pemMQQsO3mDRQBc4D3kP9SW1nvU6
         W5fIJhxw74oHsyhvEoYxgNKcWNI+P7QkPx7xHyQK94WxfuH6w20XjwxWJK2HocLSDYFD
         jZy/EtFEP70cZAlZ8nqcvPgCc0DA8kOuW9KM5mIW/3NtBzGw/Ed04LH2VacYPEPS9nY3
         Uhw51ND6Ko9Bcv5hmRz5DaQAWbyAZMFMYv9Xx/YYrezhRnbLO2ZV3zio8UryhQApA/nb
         SU/OfyztIVP2GHziBFClnCSyDWZBH+vy/lNs02ZREx14cPCxBdtY0wuOYA1GJhl2JMrE
         9K6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GIgnxgUS;
       spf=pass (google.com: domain of izuchukwuajima@gmail.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=izuchukwuajima@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-45b525bb1c5si2163361cf.1.2024.09.25.15.43.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2024 15:43:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of izuchukwuajima@gmail.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id 46e09a7af769-710e910dd7dso206773a34.2
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2024 15:43:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVwbY1UVJXQj0KxHz2JO6pr73KRMz4NH0mu6Cn64IgFQgxuRl9ShJcJhmiZkoTYv55rXK3unoIOwJE=@googlegroups.com
X-Received: by 2002:a05:6a00:3cd1:b0:70d:1b48:e362 with SMTP id
 d2e1a72fcca58-71b0ac7f76bmr5579545b3a.26.1727297874783; Wed, 25 Sep 2024
 13:57:54 -0700 (PDT)
MIME-Version: 1.0
Reply-To: mariaelizabethschaeffler44@gmail.com
From: maria elizabeth schaeffle <izuchukwuajima@gmail.com>
Date: Wed, 25 Sep 2024 13:57:41 -0700
Message-ID: <CACddU0ATG3gYHRdtOJKJuop4gNEJ4N-+dk5ZFwXGssCBciGeSQ@mail.gmail.com>
Subject: donate 1,500,000.00 euros for you
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="0000000000003f7ae30622f7e008"
X-Original-Sender: izuchukwuajima@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GIgnxgUS;       spf=pass
 (google.com: domain of izuchukwuajima@gmail.com designates
 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=izuchukwuajima@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

--0000000000003f7ae30622f7e008
Content-Type: text/plain; charset="UTF-8"

-- 
Hello

I am Ms. Maria Elisabeth Schaeffler, a German entrepreneur and investor
and philanthropist. I am the Chairman of Wipro Limited. 25 percent of it
My personal fortune is spent on charity. And I also promised to give
The remaining 25% will go to private individuals in 2024. I have decided to
do this
donate 1,500,000.00 euros for you. If you are interested in mine
Donation, contact me for more information.

You can also read more about me using the link below

https://en.wikipedia.org/wiki/Maria-Elisabeth_Schaeffler

Greetings

Managing Director Wipro Limited
Maria Elizabeth Schaeffler.
Email: mariaelizabethschaeffler44@gmail.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACddU0ATG3gYHRdtOJKJuop4gNEJ4N-%2Bdk5ZFwXGssCBciGeSQ%40mail.gmail.com.

--0000000000003f7ae30622f7e008
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><br></div><span class=3D"gmail_sign=
ature_prefix">-- </span><br><div dir=3D"ltr" class=3D"gmail_signature" data=
-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div>Hello</div><div><br></=
div><div>I am Ms. Maria Elisabeth Schaeffler, a German entrepreneur and inv=
estor</div><div>and philanthropist. I am the Chairman of Wipro Limited. 25 =
percent of it</div><div>My personal fortune is spent on charity. And I also=
 promised to give</div><div>The remaining 25% will go to private individual=
s in 2024. I have decided to do this</div><div>donate 1,500,000.00 euros fo=
r you. If you are interested in mine</div><div>Donation, contact me for mor=
e information.</div><div><br></div><div>You can also read more about me usi=
ng the link below</div><div><br></div><div><a href=3D"https://en.wikipedia.=
org/wiki/Maria-Elisabeth_Schaeffler" target=3D"_blank">https://en.wikipedia=
.org/wiki/Maria-Elisabeth_Schaeffler</a></div><div><br></div><div>Greetings=
</div><div><br></div><div>Managing Director Wipro Limited</div><div>Maria E=
lizabeth Schaeffler.</div><div>Email: <a href=3D"mailto:mariaelizabethschae=
ffler44@gmail.com" target=3D"_blank">mariaelizabethschaeffler44@gmail.com</=
a></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CACddU0ATG3gYHRdtOJKJuop4gNEJ4N-%2Bdk5ZFwXGssCBciGeSQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CACddU0ATG3gYHRdtOJKJuop4gNEJ4N-%2Bdk5ZFwXGssCBci=
GeSQ%40mail.gmail.com</a>.<br />

--0000000000003f7ae30622f7e008--
