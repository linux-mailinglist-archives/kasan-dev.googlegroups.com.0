Return-Path: <kasan-dev+bncBCSL3FUC5IEBBTM4522QMGQEXQBSBNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id A9952950ABB
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 18:48:14 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-367990b4beesf2872420f8f.2
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2024 09:48:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723567694; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+SXmXtc0qM+R3oIxjq0u67d/DQBN2QIoGau30rOCfM2yucCedFcEzPNiUtkzPS3dl
         U0fLvnA1lKPZ/SvevzY67YJjuhHd7LYyDmfxD1UtF8DJJMao1nnFk/lhxnWRfMkg8Cbv
         x7eU8JqzOtboaBn+al8So7+JXCTtncF4d186NB0BZ3NflNqIkfeBmtfVCGJ5uciyeOIz
         Fca7F+njxhy6Rx9b12kWpurJyiCBBfUaqcm1ugLeawDOxL6PNti/liX3qvwhMVPnHqH5
         CIaik1o/WCMrKFXh3f8iGP9Jrz4HXdYyCTo6uj/H7TddEJME0E/Dboi8cMiSuKC7lCbJ
         DM9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=O+YXCN//Gkp17oGpfm8lstYxJWzRUyAsFJVTMJINmEk=;
        fh=Wg3R+9aqqn6hHyymvzT8Uxwzw+7aDHO1FD4qFrUeG2o=;
        b=bA+NBmFoU1qs6oJuxuqzBV/+B5lP+YaBS23i5IrVGF1oS+wv3bX+mtHkKmJPJ6azQR
         jLry0PVopYm/sOoFOhbVXyqZfvzNYRPKxnKM/CT1Np4qZOdGT2ko+9ijq9FGwmawLfQR
         RhVOQIDaWs6IYEBJ7U3OnB98cbhlCnbye0dATwO6Ekg3b9vOqiY9EPwY1y1cGyIlygXE
         VEQIMyoJBbUCswlrPS/cuEeQexihhdRGFdyczkSrGL0YgK+98esdN56KH0P29SsfXotT
         2VWqd17ArqZquoRIsvZDtTa9K6vUi+LHw/uplPi21liWowmAWy3keuDlRmxKX08JDXPQ
         bsaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JA3woURi;
       spf=pass (google.com: domain of contactdreik@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=contactdreik@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723567694; x=1724172494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=O+YXCN//Gkp17oGpfm8lstYxJWzRUyAsFJVTMJINmEk=;
        b=v4wlvnkJKy2hV75NIV4NTg4gN2YVvypMoO0biYwNdKZzUrRRzhgOG8+hf8tqTNdWHW
         XWAhhgYtXawUdjENttNwISFga3UqpDcTbQ86i1/+dU6OgaLkrkoeeM9eJT5LG0oX1FCa
         jNkzw/aVkiMO4q57D2DOV05Tap2KXHXAHjhSRfjvql2RBk++H5uc9k/M7Cf1rjjqBEyG
         ZfiXHf6ImkCIXRrd6i/Iht8gULbP1eHaD9Z/xpVSaWNLoqMVzUTa5HBzBEK8XyOgfLAm
         qcFpxLRoRWqjuchNDsQD29BViczmf5FMVCoIwioXAx3v052cpBhfyPq0TR67CuxxWCxW
         Qg5A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723567694; x=1724172494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:subject:message-id:date:from:reply-to
         :mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=O+YXCN//Gkp17oGpfm8lstYxJWzRUyAsFJVTMJINmEk=;
        b=SgPDtoKHD8e2u0sfJMr9s1SKMfcyvJZH4uRsdI/vDT71yqYGEOQwLhW0r7DhiObuFT
         w0BJIamncVBiP6y9/JYk3as4PCY+9FCHACcDve0117iwv8t1e0dGMPb4AnE8i6ZrI3eF
         ruVWWtwsq+I/6VqnPI06Cb1Y5YnyqQLpGf2jLcw25kQkaRFVhQGV9oxfJ0IEnN18DCcD
         IcqlIyQLn2+kQyYts/ap8RPfgZIlywkMZg0kkX9GpY5IyMAeX5Z/n4qicYgPhyHX/F1A
         UBSKHZbymTh7lNEpo8zNd9FK7J7OLTkKBuCLVXxvj+TuVBpkAY/RGV7jkE6qPLwPTmm6
         lzSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723567694; x=1724172494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:reply-to:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O+YXCN//Gkp17oGpfm8lstYxJWzRUyAsFJVTMJINmEk=;
        b=F3rBPyDeU/ykiwX/gFG8i1uO4Uup+7ZiHBig7VlA6SoS6EpYlim2L/tFkGJ4N24mTV
         AXwgw3BUNYpu9pKpCKqVir3WGFxr/Tu/LJ9ZZsorvml9uosiiTCzPTc6NpIA7CLg/ijU
         oIqASn/4f48z6UyUpqEeHHKm7bBWFc3uBJa5iTdKLi2+llfP1MV6xzRo/E60a1B3L46h
         FUk8MKIseWwXPW2xbXL/wAsKf1Be/7qIATa2wB9NKumUUQsxU1s3WR+CFJYh/CarMD1s
         1peV3wZJMC2c6ZUXC9Ok+pOasMJwXr74pgWHtCW39czmYJYShBDfInVu9Wo8f0D0hiGG
         G3vg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXk16DPjYogiew7IwFYyD6hyJHhC8RuagS/hTB/UcbZnJfSR1118mj4AKQL6Jo1RbnovWsvAIaU3wFG1OKaZ3L79LoKLBty1g==
X-Gm-Message-State: AOJu0Yz2NCZ5gxre9W4krWFymsqJuSdisdVs8t4CatFaWlz6uD0css6C
	2EI8pFMxT9/SgZLHTZusKT16qia9j1rwQYMaNwvmLbWFauRksFdx
X-Google-Smtp-Source: AGHT+IHTDODJ7MVzK9WY5gncxIWlBkuMi75wNqQL0C5z7Ty988JptCycOfIW7wlH8QDkxH4PNHehAQ==
X-Received: by 2002:adf:e304:0:b0:367:9575:2820 with SMTP id ffacd0b85a97d-37177810485mr133828f8f.45.1723567693414;
        Tue, 13 Aug 2024 09:48:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c98:b0:426:68ce:c965 with SMTP id
 5b1f17b1804b1-42909184ff9ls22681825e9.1.-pod-prod-01-eu; Tue, 13 Aug 2024
 09:48:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLlTHTJD6XlSyaLx4Q1rkdMkA2NdRkPDK54iNC3Sy9HupUuaNsfD5BudnQfB52wy3F1t0eVnF+4knQEh0yYyuZoPYEveADv+Scaw==
X-Received: by 2002:a05:600c:4688:b0:426:59fe:ac2d with SMTP id 5b1f17b1804b1-429dd2666edmr843675e9.32.1723567691319;
        Tue, 13 Aug 2024 09:48:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723567691; cv=none;
        d=google.com; s=arc-20160816;
        b=txsEzta1e0MYA51IDDc7V8LP43FjOLB1pJ3DkR6HZwMcuDocOswMjRyWYdQck9ptwd
         JswK5y5TEEjdH7flUekhBQWXKnVgdHPjwsSM5By/HrABMnonBqo/ltd4a7Oa1HWgcMAo
         qv94h9hXUOaJaRTBgyBK0VOhZazQ62QCx9Gb0kv1Yc4lu7adIyUJ12e/p7BLylPUYf/M
         o/UOdz5AhxHCHnHYMqQnzaiq15qjkQ/DV6gszYHhPEzXy+aj7WRtlP32Jyi48yUihSyJ
         xHRBeYToRYq1Lps1e6DVpEDlhhYau3hkFKsYEeqDq5sIeC5zBu4pHKMuiknocaejZTTI
         /Jtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=UBiF3s7tivGVH9zXZFN5nVcbPIOe6WweJvBaNMDONJo=;
        fh=tVNUs+ebxMrpUrLoegrFA9FVjb4apPhMEZ7DKz+LDN4=;
        b=zsvfPdZy2r/gutsifxQhzrBkYjcKiM14r7Xq7GwHhjst0gvGj7G5I8INDAsrFK4pok
         fbZ5limyDW6Prhe+dIpPFyKC5aMfzk1jsjSFNzBmVd09SKrE3Py43Tw/A9V/yjCre+77
         gxisDCbD0XPRnz57qflWCmbta3gKcyClbs4E/TbA47yyaqmIHk35p/+ATntS2d2JKuGG
         GSQgsK702yE3dOXWmQDzLJToNpyiKADVHP88mdkur5CRRUnrI5jG0hw827hTmnZ6+t/C
         zbgYYG3rs8fpOTXfYT9w4uiqslglEiAn1g10dnc7RYZrCjJTS+D2GJR+/YUBJNOlBjJF
         J2ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JA3woURi;
       spf=pass (google.com: domain of contactdreik@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) smtp.mailfrom=contactdreik@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52f.google.com (mail-ed1-x52f.google.com. [2a00:1450:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36e4bbb15dbsi144845f8f.1.2024.08.13.09.48.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Aug 2024 09:48:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of contactdreik@gmail.com designates 2a00:1450:4864:20::52f as permitted sender) client-ip=2a00:1450:4864:20::52f;
Received: by mail-ed1-x52f.google.com with SMTP id 4fb4d7f45d1cf-5b8c2a61386so6529057a12.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2024 09:48:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX7QNVhNroR8r4fy37fcVIfEV9rosoavW1EQH7m+/Eptu0W2uX9i19a5zR/SKYb8ImTAKQ3Gzbs3Zp4mKo8NUU8wKfa2M4PuywsGQ==
X-Received: by 2002:a17:907:3f19:b0:a72:8d40:52b8 with SMTP id
 a640c23a62f3a-a80ed1b5915mr302850066b.3.1723567690239; Tue, 13 Aug 2024
 09:48:10 -0700 (PDT)
MIME-Version: 1.0
Reply-To: yahmed9936@gmail.com
From: Yousef Ahmed <contactdreik@gmail.com>
Date: Tue, 13 Aug 2024 19:47:12 +0300
Message-ID: <CAFAYhz63+0eC9tRnTGErddNCQiRStxYpO3KwA9wbpK2YM9CjHQ@mail.gmail.com>
Subject: service provider.
To: undisclosed-recipients:;
Content-Type: multipart/alternative; boundary="000000000000ec5788061f935fff"
X-Original-Sender: contactdreik@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JA3woURi;       spf=pass
 (google.com: domain of contactdreik@gmail.com designates 2a00:1450:4864:20::52f
 as permitted sender) smtp.mailfrom=contactdreik@gmail.com;       dmarc=pass
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

--000000000000ec5788061f935fff
Content-Type: text/plain; charset="UTF-8"

Hello Dear,

We are looking for project owners, who require loans for their projects. We
have finance available for your projects with over 2 trillion private and
corporate investment portfolios. We are looking for entrepreneurs / project
owners who will pay up to 3% interest annually and we also give a 1.5%
commission to brokers, who bring project owners for finance or other
opportunities.

We are also sourcing for a foreign direct investment partner in any of the
sectors stated below.

Energy and Power Sectors, Oil & Gas, Agriculture, Acquisition, Health, Real
Estate, IT, Technology, Transportation, Mining, Maritime and Manufacturing,
hotels etc. We are willing to fund your projects.

I wait for your response, for further details.

Regards,
Yousef

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFAYhz63%2B0eC9tRnTGErddNCQiRStxYpO3KwA9wbpK2YM9CjHQ%40mail.gmail.com.

--000000000000ec5788061f935fff
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"ltr"><div class=3D"gmail_signature"><span style=3D"font-size:13=
px;color:rgb(29,34,40);font-family:Helvetica,Arial,sans-serif;outline:none"=
>Hello Dear,</span></div><div style=3D"font-size:13px;color:rgb(29,34,40);f=
ont-family:Helvetica,Arial,sans-serif;outline:none"><br style=3D"outline:no=
ne"><span style=3D"outline:none">We are looking for project owners, who req=
uire loans for their projects. We have finance available for your projects =
with over 2 trillion private and corporate investment portfolios. We are lo=
oking for entrepreneurs / project owners who will pay up to 3% interest ann=
ually and we also give a 1.5% commission to brokers, who bring project owne=
rs for finance or other opportunities.</span><br style=3D"outline:none"><br=
 style=3D"outline:none"><span style=3D"outline:none">We are also sourcing f=
or a foreign direct investment partner in any of the sectors stated below.<=
/span><br style=3D"outline:none"><br style=3D"outline:none"><span style=3D"=
outline:none">Energy and Power Sectors, Oil &amp; Gas, Agriculture, Acquisi=
tion, Health, Real Estate, IT, Technology, Transportation, Mining, Maritime=
 and Manufacturing, hotels etc. We are willing to fund your projects.</span=
><br style=3D"outline:none"><br style=3D"outline:none"><span style=3D"outli=
ne:none">I wait for your response, for further details.</span></div><div st=
yle=3D"font-size:13px;color:rgb(29,34,40);font-family:Helvetica,Arial,sans-=
serif;outline:none"><span style=3D"outline:none"><br></span></div><div styl=
e=3D"font-size:13px;color:rgb(29,34,40);font-family:Helvetica,Arial,sans-se=
rif;outline:none"><span style=3D"outline:none">Regards,</span></div><div st=
yle=3D"font-size:13px;color:rgb(29,34,40);font-family:Helvetica,Arial,sans-=
serif;outline:none">Yousef</div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAFAYhz63%2B0eC9tRnTGErddNCQiRStxYpO3KwA9wbpK2YM9CjHQ%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAFAYhz63%2B0eC9tRnTGErddNCQiRStxYpO3KwA9wbpK2YM9=
CjHQ%40mail.gmail.com</a>.<br />

--000000000000ec5788061f935fff--
