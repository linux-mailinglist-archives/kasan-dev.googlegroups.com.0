Return-Path: <kasan-dev+bncBC4PX4ET44HBBKOKSOXAMGQEZJOEQYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id C795884E325
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Feb 2024 15:28:58 +0100 (CET)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-604a1a44b56sf16513357b3.2
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Feb 2024 06:28:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707402537; cv=pass;
        d=google.com; s=arc-20160816;
        b=mYqBfKoAMmiAexfo9NeV0CHBGBG7OO/glWu+gQZWeeuwVL6QocxON2Tsc0hllUKoKv
         uiEOpyKNcKUEYIi7iDFWAVwmMCb4MY0lWdx1Cl/kHWCn8kTAtlbecvDniKiQmSGQ8u8c
         RUm9Ze4kJIE4zPwc+8SsRLvS3h+DoE7GTrJR7oaju4gSf7y7WaDyynW0kpVBbcGr6kWR
         IGZqqH6dT17KAoJn3SgSL6hbwL2TzrVOGxZtFJxaU5x9EZt5XDuuAeD84rGinM+6Jinp
         uq+D3CCpTBSQVply5vmlVFUOFcnc/1QlMOPYxE7HVHjv5fFIBUsA4UyTiANngO3NFEmI
         ce3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=UZ7OIG7Jn1NUBj5Ayv2UKilHMrrttJfIjJ5q9dqjjL8=;
        fh=0+qOi/UH4sz30XQuYJ126XXshqyW78ZYN1QJZigA9Gc=;
        b=HCSD9ncCPlYxJizbk5n7uzYbG9vFm6xcQ38VhXEVqBEH3HwhS0tQ6EnNlth75rrJpI
         JNyP/kgw0TC09C7L0pnbJcX0+FfkWhyMDC0sWuHqTgbHvFD97C47rBgYw0WhMhQrvO0c
         vbEJfzw6NSCAKFOBtbxo5Cw5cDlc+94brkBcjowo7y5Y6X95abXYUS09yShVWO2SZIJI
         IZo623IPP6zQrKvHQZySSnhB+6ZNIWTrxYh57B37LpNZp7LX5j/RbunqPPN3wcgF5HBg
         j34RSAfpPyjBpksIt/uNItSn/438dxnmQEOGHTSUgmHxN976rIeZuCQtMLA4zo5ZtlBf
         BWWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dcL7v7ub;
       spf=pass (google.com: domain of wesomonu@gmail.com designates 2001:4860:4864:20::34 as permitted sender) smtp.mailfrom=wesomonu@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707402537; x=1708007337; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UZ7OIG7Jn1NUBj5Ayv2UKilHMrrttJfIjJ5q9dqjjL8=;
        b=S3b9iqaPaU2FTcq01kxb4sGhXX8KyeD4PiF5F/3XYtLP7jo98IzpGOvmJD2zd3T6KY
         opzSiAAigJ6kQkoIYfjKm3ew75SIW/EvBI83B2H5/i5Z+m5+Zq7eHBCIuy4AomUzD443
         xbLbefDHfbNR1FjTeAnogRX2K+uUjrvDaJd4ePyBaoS/PAsPTzN6ksSyylNnGQFkM2dt
         FB1sSk8DG854fHuajO96hXCujAmk+5/iouYwzb7syPNt8+tNZpd1Rw9AlhfxxJa/2EDN
         KrpBZOa2v8rfTL3b4V9EdPQFdqtI1X14k2NWVw0manHhoI4QBrYfOOtYcPwgoWK77dWm
         QHuA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707402537; x=1708007337; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=UZ7OIG7Jn1NUBj5Ayv2UKilHMrrttJfIjJ5q9dqjjL8=;
        b=bjZkLz/f0w87bLi0nGhTugFmEuvZ+7oTROGBxz2q+hThHLYeCdCvu96EdeG90SEEK3
         Ug13OhZllelvgxI965yOr8KLmf9Nb+TezSqc3wlH4ZvFFj8rQ+6uq6VLRf6/pZc5VTYZ
         H+vT1W3X/HldzggJjguzQti/wdpT5MS7gYHdx1LBYpgM6YmQUbNL5KP7x4U+GXsfyjb+
         x0lKOOTDXwEZ2Fy0YPlfnzAlWTh4FEIPePcuMjI1H5GpvVppUtnXJadOjmx/aQOtnsm/
         NxPUdtkef+CH3OX/j2AKYbJDEpV3Qzo+dLS4sUghc3RXkDHPW0hx439hIuIrC+Ecpp1y
         Hccw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707402537; x=1708007337;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:reply-to:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UZ7OIG7Jn1NUBj5Ayv2UKilHMrrttJfIjJ5q9dqjjL8=;
        b=PaCb7J7ykHjZEq/PLlvv3g6BX0Z274N1tRtWtVIu2cTU+EtFHFWzJO/EL/ghN+dXmm
         jheIU2zyo+C7STsiGcYFh2RuOcK9hNhXCDo5mRqgnkiCfzHj8RxwGSSoqHqDufkrFJ7h
         ZAwvTayKXiz4Mpk5EPUvXJDH7J7MT5fGKW5celtpil4Jo/ox6Xety7BmzmTqP/S0qUJh
         eJjgNmCQy9QVenTKFfxPmZP1Jcux/blojOdxQYaex0f68NuPI8/M79EDZLhZH13DlWWI
         hyRMQpt/6jyK8A88UrxCEGT42TssGg7TRm8NCFw4+9FoHHGKC6ytgPr7UkIlxgo61XfV
         qfKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw6k+X9pwj3GxK9x4st01PEIBXP9ush2xAqmaXcyxTApVvspHtG
	hd23qg7PueNiWDzqz9SwiiNIxxARN6wkzYQiDtWOHp3cdIvDSf+h
X-Google-Smtp-Source: AGHT+IGDYGO1nQCLHK2yE4L6mJyRDmXSPGedJB95Li9f5Lrz+GvMrGlPibj1/Wty+/QdxZpgtr+5rg==
X-Received: by 2002:a81:8841:0:b0:604:9c80:687a with SMTP id y62-20020a818841000000b006049c80687amr4234049ywf.6.1707402537617;
        Thu, 08 Feb 2024 06:28:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d55:0:b0:42b:f2bd:53f9 with SMTP id g21-20020ac85d55000000b0042bf2bd53f9ls2654736qtx.0.-pod-prod-01-us;
 Thu, 08 Feb 2024 06:28:57 -0800 (PST)
X-Received: by 2002:ac8:65d0:0:b0:42a:6133:d192 with SMTP id t16-20020ac865d0000000b0042a6133d192mr8182828qto.21.1707402536864;
        Thu, 08 Feb 2024 06:28:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707402536; cv=none;
        d=google.com; s=arc-20160816;
        b=1JA1SgP1il/gIVnR7EIJQoLgjzvV7EuBH915FYz0cq+edpC16ZFxCpo1w1jiRVRmSu
         BXEPS8KwzIQGrRga98RqAmDp6p9msvWdwrXChACz8ol4ERZMBxWVYnPAYRwpkEa0Ynom
         xd09r5guzZx9xfPlXzJLTqT0YlV1fR3bq6uIrZTbuHITy2yb0LrKxJ7ade+70E6JX1Ug
         VC93Mou6bDJAst04JDwGGdFsz+7+FNMHs94ukluSefhMmiMBbX7AXcBCa9FEPG/zUnXh
         h/HE0yE1lXKm0oXkmV3UmV9DGoancZ8gVLNGtyw/BSWuKEcFZsX02iLJvnoESneGSVTC
         HL3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=QySMIi+Qi44osZSA/YObU85JEg7SNifbyHclfRuR9Vo=;
        fh=0+qOi/UH4sz30XQuYJ126XXshqyW78ZYN1QJZigA9Gc=;
        b=TN0w9mHrF/z4o3YwVgiOIFG7+tjx7/74q34X/xfj+wi+gYUDTsCxD1jROmPEgghttv
         Ljjy4bjW+vmpsi+DHZ8I1qPcGk2DVnipcGkpQ5FbGjQYbSTMStdm6fU+7rczoyiOoWxz
         cgft81CBFJx5hVh5Eh5zsaNGfrCPUtPBevu6X/SctD6YOPNhlqDPKoAH88/BoERqjvj6
         84vmuWlDoJ0tpqNyyua8A+51Gc5L+UO713n/O5p1J898pqY2TmrQCgtPa05kw/PLlVJr
         tB0NufxprkS4PK2nsnuaaeCzeXD2Lm4zsuAtnFAaFGdJZM8LZB8myYtj5iYrvj8+s6to
         BKIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dcL7v7ub;
       spf=pass (google.com: domain of wesomonu@gmail.com designates 2001:4860:4864:20::34 as permitted sender) smtp.mailfrom=wesomonu@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=1; AJvYcCUP38pNH5ixVVb1qpf2u+Fl9VCXqGfV9W+xe1jT7mL6fplTN5MNwNHYS0xZzN/UIoSFScYdpqTJUb/5EOfR/pug8T0oxCxQhqKMWA==
Received: from mail-oa1-x34.google.com (mail-oa1-x34.google.com. [2001:4860:4864:20::34])
        by gmr-mx.google.com with ESMTPS id bb25-20020a05622a1b1900b0042c4e0d5cfdsi14049qtb.0.2024.02.08.06.28.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 08 Feb 2024 06:28:56 -0800 (PST)
Received-SPF: pass (google.com: domain of wesomonu@gmail.com designates 2001:4860:4864:20::34 as permitted sender) client-ip=2001:4860:4864:20::34;
Received: by mail-oa1-x34.google.com with SMTP id 586e51a60fabf-2193ccbb885so843628fac.2
        for <kasan-dev@googlegroups.com>; Thu, 08 Feb 2024 06:28:56 -0800 (PST)
X-Received: by 2002:a05:6870:6114:b0:219:7880:f859 with SMTP id
 s20-20020a056870611400b002197880f859mr10614584oae.29.1707402536303; Thu, 08
 Feb 2024 06:28:56 -0800 (PST)
MIME-Version: 1.0
Reply-To: mrsmeijerink@gmail.com
From: Sara Meijerink <wesomonu@gmail.com>
Date: Thu, 8 Feb 2024 06:28:45 -0800
Message-ID: <CAJjqWDkzkMN7Hwgh-NeewWhjvCJ3MbfeY5ni=9D8c9gxxw7+5A@mail.gmail.com>
Subject: Hello From Mrs. Meijerink
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000aa42060610dfa1a1"
X-Original-Sender: wesomonu@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dcL7v7ub;       spf=pass
 (google.com: domain of wesomonu@gmail.com designates 2001:4860:4864:20::34 as
 permitted sender) smtp.mailfrom=wesomonu@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

--000000000000aa42060610dfa1a1
Content-Type: text/plain; charset="UTF-8"

Hello From Mrs. Meijerink

My name is Mrs. Sara Meijerink. I am married to Mr. Jan Hendrik Meijerink,
a Dutchman who lived in England before his death.

My husband recently died of heart disease and I am suffering from cancer.
Due to my poor health, my doctor told me that I might not live longer than
2 months. Before my husband died, he has a deposit of 5.000,000.00 EURO
[Five Million Euros] in a bank. He told me to use the funds to establish an
Animal Care Foundation to support animal welfare. We love animals so much.

Due to my poor health, I cannot handle this project. That's why I contacted
you. I want to donate the 5.000,000.00 EURO to you so that you can
establish an Animal Care Foundation to support endangered animals, homeless
animals and abandoned animals. I always saw on TV that people donate money
to orphanages, but don't care about animals. Many animals are at risk and
face many challenges such as: hunger, lack of medical care, homelessness
and abandonment on the streets. We want people to understand that animals
need special care, support and protection. Together we can help animals.

Please let me know your interest in implementing this animal care project
in your country so that I can provide you with all the necessary
information to transfer the 5.000,000.00 EURO to your account.

I'm waiting for your quick reply

Thank you,
From Mrs. Meijerink

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAJjqWDkzkMN7Hwgh-NeewWhjvCJ3MbfeY5ni%3D9D8c9gxxw7%2B5A%40mail.gmail.com.

--000000000000aa42060610dfa1a1
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><br clear=3D"all"><div><div dir=3D"ltr" class=3D"gmail_sig=
nature" data-smartmail=3D"gmail_signature"><div dir=3D"ltr"><div>Hello From=
 Mrs. Meijerink<br><br>My name is Mrs. Sara Meijerink. I am married to Mr. =
Jan Hendrik Meijerink, a Dutchman who lived in England before his death.<br=
><br>My husband recently died of heart disease and I am suffering from canc=
er. Due to my poor health, my doctor told me that I might not live longer t=
han 2 months. Before my husband died, he has a deposit=C2=A0of 5.000,000.00=
 EURO [Five Million Euros] in a bank. He told me to use the funds to establ=
ish an Animal Care Foundation to support animal welfare. We love animals so=
 much.<br><br>Due to my poor health, I cannot handle this project. That&#39=
;s why I contacted you. I want to donate the 5.000,000.00 EURO to you so th=
at you can establish an Animal Care Foundation to support endangered animal=
s, homeless animals and abandoned animals. I always saw on TV that people d=
onate money to orphanages, but don&#39;t care about animals. Many animals a=
re at risk and face many challenges such as: hunger, lack of medical care, =
homelessness and abandonment on the streets. We want people to understand t=
hat animals need special care, support and protection. Together we can help=
 animals.<br><br>Please let me know your interest in implementing this anim=
al care project in your country so that I can provide you with all the nece=
ssary information to transfer the 5.000,000.00 EURO to your account.<br><br=
>I&#39;m waiting for your quick reply<br><br>Thank you,<br>From Mrs. Meijer=
ink<br></div></div></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAJjqWDkzkMN7Hwgh-NeewWhjvCJ3MbfeY5ni%3D9D8c9gxxw7%2B5=
A%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.g=
oogle.com/d/msgid/kasan-dev/CAJjqWDkzkMN7Hwgh-NeewWhjvCJ3MbfeY5ni%3D9D8c9gx=
xw7%2B5A%40mail.gmail.com</a>.<br />

--000000000000aa42060610dfa1a1--
