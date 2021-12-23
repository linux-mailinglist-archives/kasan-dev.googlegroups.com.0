Return-Path: <kasan-dev+bncBCFI3XXFQYIBBQ6ESGHAMGQEAVUDMZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 943FD47E294
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 12:49:24 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id e7-20020a05651c090700b0022d70efe931sf1341656ljq.10
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Dec 2021 03:49:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640260164; cv=pass;
        d=google.com; s=arc-20160816;
        b=lVPTl1VfSOnII1v1YpU0EwNYXH/l2P3s8JFSKqcjYuh4wOc/xfkK009RfSgC7ql5xK
         N73tPade2w8MgjsAjK3Z6GkEjV6e8M0wAL5FNcIDxLNOAGfxmTC8Uj7+nMYJ//lfAWMG
         E/yMsH9EZ1e6TBlrb8KEpL4E8WzNVb5O1dx4UUME+SuIjKO10NZJ/+42fMVWqVPpERT6
         pSzdLRcosK87mb9kD6ZTsaa7Nktc3fcgHGkxO5/iw4d06vqwPlT+S62SdS9/RDVWkeHp
         V89OVvfxTcaWAiWCPbYFk7bZDS8rJBaUms9Nw03o9Zw3kLpPAm1D/fxq8PTpU0f722xB
         IP2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=ZNAYbQ+kKMxO65tIEkE9/7gK8DuNuJt7Zsk+EyVT/0U=;
        b=yAug5VOBuygtIydsgmRluKrKT3CL1nqv3F7QE+dC3i/00hPMVEONsnrYWcbtQOmWfL
         fWjOvZwK8rfCMzLglCakwAa/Ne403FwolFM7V7QjYU2uVbsuxHK2rw6Z7W2Gg25xZXsL
         v1nQbSzY3uFZS1AwkWS7SaKr1mLP2TjXuR4I+fJ7kABjgjPKL+CMPg8tSs/wRl8Bqj7F
         M+jtwdQsCGv5F8FaOTmAS+/I9qNBtjCuP5kBGSkvebj5i65DZ+YFm6vp3Z5j29PncnT6
         A6EoTPNtUs+Ex0HWqutcDx+L45W905otl1yvQ8Oe+J0uTkVknNpO8KLmSzamsA/RX/Qs
         QKOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=KBwuW6iI;
       spf=pass (google.com: domain of kossitiglo@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=kossitiglo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZNAYbQ+kKMxO65tIEkE9/7gK8DuNuJt7Zsk+EyVT/0U=;
        b=UxxtRBqPR/84jBYMAo1jMqG/c5teLYT885JH/AjYKw3mWiJcQtyzXXBJQQZy257sbt
         +/on5a4i9A8MmD00bOLa18fjplDnKnotZCf2zngHZe+YP8CFE6HKQfabI83y4dDX19x9
         eLT8TWaFl3UWh9/kxC8khxzEgRpkCqCwoJkZ8b8J/HYK/ulZ2sM0dUW+KlVxg+i40lCz
         hjtknOU8976lgK2jhIOjQgNCkOL9sJdZUDKq2QefygV3lZJtJjuQROHuPTM5+UJutoKa
         UHZ1t1lng2mlGaL66IE815pj2bu9V3vLEtn9bE8OwWx3EXxwpXJO8ZNYBKSoR1PsR/Vj
         4yxg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZNAYbQ+kKMxO65tIEkE9/7gK8DuNuJt7Zsk+EyVT/0U=;
        b=Ql+oEWL81PCL9A9Ytuq1i5oVwltSpvPts+rcpLMLahSWuMSHfpkkBtfMBrpDMBqL9u
         D7pYYegWEua9vMWrhVu7zisNxLHTP/AOzY70xT7uW/fNbfP4kRdLHmSPwi62q4ZeUaZ/
         74LzAUXxFPdvSoUhZ9Cxq0YcRXvo7muhsp10HpdZF64kb6C/DUoxeDnwkZe93vwSH2iQ
         vf1yuyiaXuC0E/6tBg20EQuve9BCxumtjyUlXKrR0gzrVqqQ0b7n/utv5GOsvGsTdcqM
         H/MoJmE/DLna+L9LYH0lxNFi9DQujews9keune6qtVdiOXBzd9RfhRfOGHWJ+fj9UZ7J
         8d/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZNAYbQ+kKMxO65tIEkE9/7gK8DuNuJt7Zsk+EyVT/0U=;
        b=GGHTTNn8eLCeVjscwDJWIYp984nQTZ97CiXdKwQbgF+Y8yQFB5usyz4CPIetnKSgd+
         c35rZgQwnJ/B2j61UOKJIbkc3zEk5PuF760Mbv3MXv/PJAlIk/tTCDF4Fjr7kDs0VPga
         V63u8Sc8fHIigTLwZX039ifvioM0O0AwJxHgYOdBokLhysexvomwZzgOBG5in1T/A1rT
         LvkTTfcGTDysPCP/8MRDjEm7Lxw1xMvTKTjee50i8vT6bBxQiX4DtHC6WEe4JilAPjjB
         cTATh9nSZhIh/IzzsYsXyfLO6kU27wC1b+UBkCcfAbJ2VaRDPGTZlk4VAnOHuZlP+e0B
         6Dpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WEUpu6Ptau+I7yIqkg+/QEqHemEA+F9l9hpIMOoK3b3rDJdUR
	3cVGEBx+6627frjpLTO8QPU=
X-Google-Smtp-Source: ABdhPJw8NBtjMJLuS1t1btlkQwHmLLoBy+kOK19d6VX0lIN79lIm73VMSywqTQGoONVf7rCkskNNUg==
X-Received: by 2002:a05:6512:368a:: with SMTP id d10mr1519443lfs.476.1640260163871;
        Thu, 23 Dec 2021 03:49:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5304:: with SMTP id c4ls3269235lfh.3.gmail; Thu, 23 Dec
 2021 03:49:22 -0800 (PST)
X-Received: by 2002:a05:6512:3b13:: with SMTP id f19mr1594191lfv.305.1640260162658;
        Thu, 23 Dec 2021 03:49:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640260162; cv=none;
        d=google.com; s=arc-20160816;
        b=iGzzyvihTogmBp/aBg7gDnXVxm37R4mAksPb4W8gYh7L0Rdjia7pYr0/kbU5/eSUph
         MuU5w9X0Cw9BFaXH0DRL+EPGJHCXbQw18+Cua5Jw3jVt+OmBbv3y6mtCIv/wbltCpTYS
         dSpCV+XKSiElhd7mRn7ZLn4JbjDlDU7StfGQ5gS798OiDQg/8K+i/uBGkSGI0PheRjoh
         UEkciLMDmx6/MuHXzumxndn2gkNiBdez/6cNwubphYbHL5doHmXFNipxFEQEEZOkuSb2
         oOdyup4f2t8cVZMnRgdz4+cKpM3/y7SBzdyxdb9Lo2yLi73ELanwqB/4WpOewV08Gz76
         uxXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=dR73GMHh28yiRtrqX3oOUKfh9Dfy3TV1yYRSNvY/+4U=;
        b=chzI+auZYDWZuj/+Wi8dW532HjMq8MqlM+NiuS1vUTVnHQxJ08T92QBO/gsCs3eb95
         /mxFOvqU4sQ6DLczdcuJPdLGUOiOQSKQxPqpBaCO1jFf4M/JLqI+OTSaaWA1ElK5EKVc
         dXC+EZI4uS/HvRrcrZPppvKgjdkMvi7TiikbAqktzm+r5YeN2/6OrNRnV1N13DYyF2sg
         wlQ4LnU1ojLh1uf8ZG2s9UlQbfi7Kd7vY4L5Tt7LU1Q7wtzyXPme++sMcElkgFn4t1De
         /O6ag4vppyHi07a0P/We4Dnlxw1lvVrBreLaAdoeA5xMkusoTncd+U7eubxBJthWO4RU
         02oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=KBwuW6iI;
       spf=pass (google.com: domain of kossitiglo@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) smtp.mailfrom=kossitiglo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x22a.google.com (mail-lj1-x22a.google.com. [2a00:1450:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id u7si158853lfs.7.2021.12.23.03.49.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Dec 2021 03:49:22 -0800 (PST)
Received-SPF: pass (google.com: domain of kossitiglo@gmail.com designates 2a00:1450:4864:20::22a as permitted sender) client-ip=2a00:1450:4864:20::22a;
Received: by mail-lj1-x22a.google.com with SMTP id bn20so8633124ljb.8
        for <kasan-dev@googlegroups.com>; Thu, 23 Dec 2021 03:49:22 -0800 (PST)
X-Received: by 2002:a2e:870b:: with SMTP id m11mr1406877lji.20.1640260162444;
 Thu, 23 Dec 2021 03:49:22 -0800 (PST)
MIME-Version: 1.0
From: "constance.bedard" <constance.bedard66@gmail.com>
Date: Thu, 23 Dec 2021 11:49:10 +0000
Message-ID: <CANbW91g+crm9jWZt6zw6M=LUxDjmVhwLP+TMO=5GHo9secF1kw@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: multipart/related; boundary="00000000000052a5ba05d3ced49b"
X-Original-Sender: constance.bedard66@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=KBwuW6iI;       spf=pass
 (google.com: domain of kossitiglo@gmail.com designates 2a00:1450:4864:20::22a
 as permitted sender) smtp.mailfrom=kossitiglo@gmail.com;       dmarc=pass
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

--00000000000052a5ba05d3ced49b
Content-Type: multipart/alternative; boundary="00000000000052a5b905d3ced49a"

--00000000000052a5b905d3ced49a
Content-Type: text/plain; charset="UTF-8"

[image: image.png]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANbW91g%2Bcrm9jWZt6zw6M%3DLUxDjmVhwLP%2BTMO%3D5GHo9secF1kw%40mail.gmail.com.

--00000000000052a5b905d3ced49a
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><img src=3D"cid:ii_kxiwj2kg0" alt=3D"image.png" width=3D"4=
16" height=3D"302"><br><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CANbW91g%2Bcrm9jWZt6zw6M%3DLUxDjmVhwLP%2BTMO%3D5GHo9se=
cF1kw%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://grou=
ps.google.com/d/msgid/kasan-dev/CANbW91g%2Bcrm9jWZt6zw6M%3DLUxDjmVhwLP%2BTM=
O%3D5GHo9secF1kw%40mail.gmail.com</a>.<br />

--00000000000052a5b905d3ced49a--
--00000000000052a5ba05d3ced49b
Content-Type: image/png; name="image.png"
Content-Disposition: inline; filename="image.png"
Content-Transfer-Encoding: base64
Content-ID: <ii_kxiwj2kg0>
X-Attachment-Id: ii_kxiwj2kg0

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
Q/APiYihjAtDLJkAAAAASUVORK5CYII=
--00000000000052a5ba05d3ced49b--
