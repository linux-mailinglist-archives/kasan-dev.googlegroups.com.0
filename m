Return-Path: <kasan-dev+bncBCP4VPPT6YMRBI5OR2XAMGQEPXN2C3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 962D384CD15
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Feb 2024 15:43:48 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5601d32ac1csf13589a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Feb 2024 06:43:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707317028; cv=pass;
        d=google.com; s=arc-20160816;
        b=wyaQr1o2pbtBEvmETeBFjCz+IqdfZjugiiutZNfavhuT9VY4ivjMRNbt5FuiFiyP/k
         atHjOlPhuRNO9pQ/bGxfGfeHDrXqkHhRpwcZiG/VHt2uvgyy3EJkQ8cveBpy2Yn430Su
         FvzhnhvlhEl6c3XqpWOFfMbyFlZTdnAZqm6oKa2EvttOF/Yo2lp2oBYVfE0tX9vJqmkY
         vh6DAJSsXS6dB39YUAXySNPHw3wcWNDM/bfF8aSPFuqeKOp+CtxnN4k4bIh6IB2rPaHw
         t8SEVXEQeHv3beX6y4BD48hbkg3UTOHUI0ecTJXdr2FIHiW93gHhHtxvdeH5oEKWLdZE
         uErQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=c/q0BsfaUj1iqR73isjvTCc4ejtysAQ+43Bqe3phLSg=;
        fh=VLIkuPGcO/VfHoKmOisARoRpMjkrfZ7aXMpKGSPANVY=;
        b=icnBz89tk60YXflmCQghkDAW4qlEPF1d3jtWjWJ0lDxGSnl9BRSyz+1PtrgiEDV0Mo
         M7xt4P7+UhWLOCK/xq8QAsWwYDN5tr4tvcfrAWc/DkiWnwJMzvcqp0NO76cmsAhIfxmF
         w6WiOaFh3t5sEx5rEmAlLBrKPOt8hJCCk8Ao9a4k16Lg87JTviSCt8qd5IsHKNrHTv19
         uZz09Nr2Qohlh2HGbdqqakte3OXp9uUJZ9FL0R7HtqWNtnRkv7cb8OZSUzswbFWQhW8I
         n2FUhveYrY1zKRSYpqH3QvgseCrdh3nwGOKrW7Fx23VNxheeZ4hzM3ymzqMwtrBixhMr
         dp6Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dY/Kf4Bp";
       spf=pass (google.com: domain of astt77538@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=astt77538@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707317028; x=1707921828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c/q0BsfaUj1iqR73isjvTCc4ejtysAQ+43Bqe3phLSg=;
        b=nY+A9KQqnxr8nLGNHwdGbGXuH5XdedWahD6CZV5OdNk/DDbIPi37GbDS3MJcILNavp
         IBuUEDwwjylxhZPdrLDp1o25wRDVCksKQ9l5UtLZdu7vvDqEmtwb1Pdv37OfDGRQnI+W
         ZVm710PwDmzswsek3G2XFoBuupw1FU8NQIeQHRtJzml7HsyCcojLf98C9PTp5LOF8rPd
         OLUyrNhxPDiyJMzhNrLLzw7r42yICMht4KniiiEAc9PXErXvu2BKI4XXXNZUDwyTnqlm
         VgFH9sSHX8+lOCUBpSLCg6sNYoCZghM+IN13BYrLurTT9a2sWg4iNG55G44FuiBq+EQ2
         8EIg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707317028; x=1707921828; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:mime-version:from
         :to:cc:subject:date:message-id:reply-to;
        bh=c/q0BsfaUj1iqR73isjvTCc4ejtysAQ+43Bqe3phLSg=;
        b=fXt05hi6CPJm52h8eY4vDpluFsnx8ab12w+4Y7wf+jxrmIQeEdU7uk0twfXqjpLT+M
         H2xtcygeZvDyIQWKbhtalOC7MBt3/91H4nwKrUXR2xWGlyCfrwTBg+P2L0urK/p7Lkds
         1Ya57Tr5beevuzinS7RkKakfvCAnZ7xeFY7NBqH1k/F+rg1f5lV/eBuF4beCjO+tx4wI
         u5gjHcmjiYGqG8754oYlNGu+sVSDTF+picEm0PwKqVXomgbvqRkGdMbFXxyFPL/Ja0lK
         x8SiO2gQWoM0h1lAidfmY9J4SP8urIHDBaFchtUl7Ch+Yowq3o+t6anlJhQ9xVFcnyao
         l1DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707317028; x=1707921828;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c/q0BsfaUj1iqR73isjvTCc4ejtysAQ+43Bqe3phLSg=;
        b=Qr9ER6VmFx70QIMpdwrv6BVQ/tKKTZ0xg0BqRcd6m+I1Na9sJUO3xTD2u0TBa6bWKC
         oRGquDQadI940a7aOmbG9SWOTQC3LHtlCu3sdYjxOf4EIIyQGQ1bK0BayFjQ9Nt+jk9g
         GMA8m1KBh63oJBo2vVU/QJXko3kZF5AqKdTOSU52oKZjZlediF6/3AgwTT4TZ9ECnzYE
         HeMqzbC2eADnTOfD6lhhZUOv97QPRLVBAWXnHUoLAreXt65zYYxG4IEZ0R8ZMtRSJ8JD
         ihBc7GLiH3wwfGBvmWGyt6vO6SCKS7hAWBxMvK4b59/79+ACn2tTZKFIQp9utc3jKRa8
         J6Vw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWuu01W3zjA+WHWKN4rnRRE8rmecv+LOgsZoQssVDM7u73X6iNaw/Fu/I8XUmDXRFHG0o10ZTsKqFO4FIlCYqI+F3v7KGbr1A==
X-Gm-Message-State: AOJu0YxeTgcvVGmz2NkJYaJUFgquU16viDqG0GIVuhTLipGUgeb3aLA3
	l3NVqsYYbjYdQlljgIKQt18vDy6S8PBShHKgjCjDBKynEQNSuJ8K
X-Google-Smtp-Source: AGHT+IH6xxR8w10qjATGPR/VVVeKv0vBIoglBelD/5tT61+2iRzuIAGisljZONaoiekXsQP8YmNWag==
X-Received: by 2002:a50:c05a:0:b0:55f:daaa:1698 with SMTP id u26-20020a50c05a000000b0055fdaaa1698mr129461edd.6.1707317027344;
        Wed, 07 Feb 2024 06:43:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9881:0:b0:2d0:9106:7f3b with SMTP id b1-20020a2e9881000000b002d091067f3bls206374ljj.1.-pod-prod-06-eu;
 Wed, 07 Feb 2024 06:43:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWnVWzWIi5M/YpRq46Eet4d86baGaZYf+riiMsZw8t8pXG6il4gwvmQQP5VTr2WeNgslZpepIMvyEK0lYOBRSmBisDVFMaAghP4xg==
X-Received: by 2002:a05:651c:1a0e:b0:2d0:c2b4:5914 with SMTP id by14-20020a05651c1a0e00b002d0c2b45914mr3176730ljb.51.1707317025066;
        Wed, 07 Feb 2024 06:43:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707317025; cv=none;
        d=google.com; s=arc-20160816;
        b=nM+V3uOENQOmIX9z42jEo6GxcqXpUQJIG88JERuududXuwIXUnL7vSaYEiORhHj+6E
         f4owPbua8/yZl0cihAbfLcAnaiF5k2c/wAlO/o/QeHgMD1PeF58zoCFVIJM/Vnhva6BT
         cuPp1Ccz6T+62APwcnWCoZFd7Q34fXfGq7Y/T1cw7acECBgcBZt01k2HA6/FL4+IxYMK
         GtZ4SrvdDyFatO/wJh74L4JiruDrDUFNFqZSmVYZF1eD9VfCwoJec3z7fOJ6dO/z5pUa
         jeX6qRhZRunrR1ZBoGjEGkltbxdIiKYG9RBi4Cp0ImYx2r1u8ytdDnrto8PkLFuB0XQN
         Pldw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=lBr7ASk9f8+6IE7wMmlBKWxAs1GrMx3AzvZPeWUFOmM=;
        fh=cEZ94HzqNL62aFxCR88Qpx0ONfUgPm9KG0YEMbEimuM=;
        b=egOb9pHIxb/L1nNAstqQQ7diSBOHYJwVs088uWa314ZzL2cW8q1aNoQKcf2V63sYKX
         QdXHpHdG5Rq9b5jiZbpPYJfHLRIeyJsYl/GUoNT1ObhGy1kyKOdlMyS+0KmuoE4aMBOa
         paDwtxlwZKIS/f+AzyvCSXNonvfXpLh745FIotaPVAafiBilLw51p2gcxXCBK3VDgMvU
         MAHaABcUEjmdgAkgtBd5sXN3RYsXZ7gedOsDZZU/hn/CCd2PoIY5W7Q2wOwqtZLAYNSS
         ePDFfWz/ZapljjBEUW3lwlxZiwkNIW9+r+TzCdhZRooO3r580KrKV9OBbDOd4Vw99s1A
         IyFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="dY/Kf4Bp";
       spf=pass (google.com: domain of astt77538@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) smtp.mailfrom=astt77538@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=1; AJvYcCX0gpJuGa2eD1lsTH7ivsSEcWOf3vhfjiFCATIlMuXIR5RPrqgcIt1UBb3/buXeUHcqB8fs0zkazWDvN+z+ytDf9iSvCmnSFAmj6Q==
Received: from mail-ej1-x629.google.com (mail-ej1-x629.google.com. [2a00:1450:4864:20::629])
        by gmr-mx.google.com with ESMTPS id s9-20020a2e81c9000000b002d0a7814671si99714ljg.7.2024.02.07.06.43.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 Feb 2024 06:43:45 -0800 (PST)
Received-SPF: pass (google.com: domain of astt77538@gmail.com designates 2a00:1450:4864:20::629 as permitted sender) client-ip=2a00:1450:4864:20::629;
Received: by mail-ej1-x629.google.com with SMTP id a640c23a62f3a-a370328e8b8so88767066b.3
        for <kasan-dev@googlegroups.com>; Wed, 07 Feb 2024 06:43:45 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXG1YbDn31l4hcplL/r6bg3fPBsv9psr0r+M1O2XHUMag3y4MtisT58zoLxylGOzX3XrdoRWbjguSEpTYB0+OsEftu2hU6+h4uw/g==
X-Received: by 2002:a17:907:7803:b0:a37:501c:9eab with SMTP id
 la3-20020a170907780300b00a37501c9eabmr4124230ejc.43.1707317024320; Wed, 07
 Feb 2024 06:43:44 -0800 (PST)
MIME-Version: 1.0
From: Phai Hang <astt77538@gmail.com>
Date: Wed, 7 Feb 2024 14:41:11 +0100
Message-ID: <CAK5DR48_qbpQn_YtdC6p5vBo4yoOHm9ZOwd8W+k7FCAHZR-bhg@mail.gmail.com>
Subject: From Mrs.Phai
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000c0f2700610cbb8d3"
X-Original-Sender: astt77538@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="dY/Kf4Bp";       spf=pass
 (google.com: domain of astt77538@gmail.com designates 2a00:1450:4864:20::629
 as permitted sender) smtp.mailfrom=astt77538@gmail.com;       dmarc=pass
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

--000000000000c0f2700610cbb8d3
Content-Type: text/plain; charset="UTF-8"

Hello Beloved,

My name is Mrs Phai Hang. Not to take much of your time. I come to you with
an opportunity that can be beneficial for us both.

I have a profitable business which I would like to discuss with you. If you
will be interested, reply back to enable me to give you further details.

Regards,

Mrs Phai Hang.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK5DR48_qbpQn_YtdC6p5vBo4yoOHm9ZOwd8W%2Bk7FCAHZR-bhg%40mail.gmail.com.

--000000000000c0f2700610cbb8d3
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr">Hello Beloved,<br><br>My name is Mrs Phai Hang. Not to tak=
e much of your time. I come to you with an opportunity that can be benefici=
al for us both.<br><br>I have a profitable business which I would like to d=
iscuss with you. If you will be interested, reply back to enable me to give=
 you further details.<br><br>Regards,<br><br>Mrs Phai Hang.<br></div><img w=
idth=3D"0" height=3D"0" alt=3D"" style=3D"display:flex" src=3D"https://api.=
getemail.io/extension/track-mail/60wvbwwp4i5lo17ismbp8by9fz6yzfuo">

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAK5DR48_qbpQn_YtdC6p5vBo4yoOHm9ZOwd8W%2Bk7FCAHZR-bhg%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAK5DR48_qbpQn_YtdC6p5vBo4yoOHm9ZOwd8W%2Bk7FCAHZR=
-bhg%40mail.gmail.com</a>.<br />

--000000000000c0f2700610cbb8d3--
