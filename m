Return-Path: <kasan-dev+bncBCV7JPVCWIDRBB6JRK6QMGQEXTXAG6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FFEEA27FAF
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2025 00:36:41 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-307359756d0sf23494501fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 15:36:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738712200; cv=pass;
        d=google.com; s=arc-20240605;
        b=j5YUli//8O8FsmrTn5qnZSk6KvXXVQrA8NAjZbwaOv4nfSy5O0sO2IEbGgH2w1TICe
         VW75h0ekJbniI+PFYHGKopEMfTPtQrVgCRv2RPz/DCJfZYhG+Eo7yJGP4iQaguJivxZd
         bAq4iE8WRK6w/zAAjqfB3vykb9OoaymoBwh1hS1xdEodB/p72Nay3eylrM5KIKtm9+Fp
         oGP07nYZqzyUhzr3BJDLs3lQo2KfiFe4jUM4igIv++iI8QU7NZ9iCEQJ/nEAwED5sie4
         fK1CVtTEddvdgnk+YheSYkvPUhV2NubeprKzluE9gxIlg2I3ybCPFwb3me01ibFYrD1h
         VHIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=5+0BKFj5Nb11ygqHFm2qV3WmjAHBnZNiWZaYPjqmYpo=;
        fh=L3ABnvb10y6fGej52NYU6hHWogBinJ+TuYc37LRRvc8=;
        b=MJuiGaD45IlNokNhED+uZLqhmqjF9NCcLcWQEBTtLXv6nfZm4Ftns1B6XyF3FqoOR3
         APCvTtIFP8RrCzIkJy8t6O3ZtKKwlXAutrqUIEyCmCPEA/pL0WedCy9AI39xcclxOWjB
         1oy7EWxlpOYiyY+RFCX7l+UXgsxUaNvCwXqitYxgBB99D5bM8Z/dI4FxGnUxcjMnLtqG
         x6iTRDHU/fkfFbiWauYRZl+SxdB847O0qPjsQbcgKwx3NZMdODQPRCK2ALdohj+4Cr6i
         cn1ePIed2J9woFnnVRasqfHh7MDgfHZlyh6tMc54gLKDuIh46EwHHqpiun+iltUR+b8A
         JKtw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=F9JeH5Oe;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738712200; x=1739317000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5+0BKFj5Nb11ygqHFm2qV3WmjAHBnZNiWZaYPjqmYpo=;
        b=w0jHUmiWp2/BpefZF6UQMZHh4Gu9HkOXzfx/pFUxaefAAC+l2gHWIZC8B6uG1lT/Tx
         /B1R9lV/ryJBg+E/7Tm9wR8Sv29aGU2Ix1amUWP3NLkUUktmkeTSdh5mPirxd5Gbu65y
         GlKPZULHJrxltFsp3nuWClO6nhJwJ/+Pnd/3AKx6VQR9xORAmp02h0PKnwzOUHHyIw8w
         1F5th3/3mp1blmq4Kak5HrIGFFu3S++ucx6wVTC78ohgZNB0hE8AiZkkbjwE5md4RQFO
         el4WD/+rY3TKxTw5H8iEtIj8Ofycqz3mJ+NoI+0Als/bG+OpYUdQbOYvvuoZB67HvP3Q
         HS6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738712200; x=1739317000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:content-transfer-encoding:cc:date:in-reply-to:from
         :subject:mime-version:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=5+0BKFj5Nb11ygqHFm2qV3WmjAHBnZNiWZaYPjqmYpo=;
        b=qFzXDuv88VOEUR8j8G+uBUl7ihpgFfo4KyuUw38cRYChic27QQl8iLPIIc+dvFUqdl
         BeUruVAebHA4JhodQnJABgYqa3GMkGVW1StxijwD1wHAuXsD2j4hMH8bK0erl2DJDqjl
         4sGkTEw3qXt8ILTKCIJWIdpzaYvBs+ZUuEIWLzB/IIUqrPe6VBm27PdWN89bSArfp/JI
         SBn+dziLlKRr1Urw4JkZ2KJg9G4EjLBtKsQ94hTDTvIQA2QaiTljN5qJXlkAF7VkdYsk
         CePfIOfLMx++RfJBDNvWxRP5RVx2GEc6TRwYWnuT+4UfQUNgUmXtDuN1GqbZUXbJ9g/v
         Z1lw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWlDd289u0yDkbWBD/R/8wcYv2Q7WOwRjIXYhOp1AtgujppLeX2hQt9gNdNxkeiO/1+NtnPQw==@lfdr.de
X-Gm-Message-State: AOJu0Yxr6xOMKg8UFjlXsA9vnkTpshbFib0xogf4hPWU1somtpxIPBbh
	QEqflK3R0LuSIblnm4lM+Vuz4giPBoJJBXQ3o/qnEHDyN/XwS5zH
X-Google-Smtp-Source: AGHT+IGgRkikiFwoLXic+F2JCOVcvEGo6oMdQjmF0xhuMJE4/KcYpz02fOVnWDZnw3qcKjGL3CplHg==
X-Received: by 2002:a05:6512:401a:b0:542:28b7:2701 with SMTP id 2adb3069b0e04-54405a1074amr160286e87.18.1738712199565;
        Tue, 04 Feb 2025 15:36:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ee01:0:b0:53d:e8e5:35c6 with SMTP id 2adb3069b0e04-543ea3d354dls116478e87.2.-pod-prod-06-eu;
 Tue, 04 Feb 2025 15:36:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWgHCN9U1ESagV7n1R9DRcE4HSXIJR7eBM6o8wRW4/VO1SlPR4tCn6hRxAYUt/DL+RQ5r3FkLHcAoE=@googlegroups.com
X-Received: by 2002:a05:6512:2006:b0:543:e4ac:1df5 with SMTP id 2adb3069b0e04-544059fcdc7mr122116e87.9.1738712197107;
        Tue, 04 Feb 2025 15:36:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738712197; cv=none;
        d=google.com; s=arc-20240605;
        b=dvYUZjYLbUzGpDUxDto+DjQea9weCDCY/gpBErXJml3WDWJXoH3Syxvd4//C78BU4X
         2IMMLnhwWv6qnvNLFrjhXO1W1lxQE5tZTKDaXDgDYoB/kZHPqMC90vx+6DgD3NkafY4A
         kXhJsFz3t+hb6CF9zcDo6vQ+pBE5GxlinQgKVF40jhjeONoLS2RbyBwrO4bvX5b/Kf8e
         ow0baAYRxrpqT84jhu+K/X1XkDQVGpNJV85l4g3QIObPrVUYCPORFouavJ94QSNPO/lF
         IHMHy4VUVD+yw3AnVSJw9PScgbD/oZcMaIfAEj8TW1gydBNYxogWHAMDohw57GXBvMvz
         v3sQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=QjEre/G3BLqcrCF5wreFajQVoRGv9unmtvDg4S23UQU=;
        fh=xHECUlZ0FU4BHAuCQ//lOLtP6AOYOJJyeKEBpKPZqW8=;
        b=jPNTOEDw3ULmNFgauYRsNlUDgGBZ2pWt4z95l2uXbNRHRWOZ74YR159ByXfNDjM58N
         JZ1Dr5BC3NymcGeqiYqZfG/wtleCtDUZu+hurg7ZuFlWR4eLtTB0S0uElsEM+L8QFLnP
         uiqMDr/DIDlqoueGQPMHBN742Gh6N30BAVLwE/AScVDbfVfBmAXwX6U4bY04T4skYoSq
         NOnl4Oa/vkKMpxnD+UqbcO4e2PmGKtda2vkyuhUj3Gpnc5p/F5cN2RdjFV7Wry2aGKf5
         6VBa97mBBDM9n5HShaS9lAnt4LkMuGUYLFJAT3be7EITVAzy3aUtume33IwfsrcCtr6q
         Cl4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=F9JeH5Oe;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-543ebcb8446si132972e87.0.2025.02.04.15.36.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2025 15:36:37 -0800 (PST)
Received-SPF: pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-38daa53a296so594432f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2025 15:36:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWoBZeF9H5N0SaGNFNYEvGiCn87A+xgvKT+jL3kSl6J8lv1hCftPjgLUq2Vef1E9v+QJnngo35+SrE=@googlegroups.com
X-Gm-Gg: ASbGncvvGuONTA67PCCVJVTq4OtG3893G3KnYBxIv+NQWNRJeoJ7d5BWhIq4ATjNVu8
	AM+1tPQgeSXRAlFotFlQ2VQ5Lc3+Tpr9Zziqi+XxkJ4zjcirQ3GzndcGrhG30z+tNuMk4y/lY+n
	4RtdLT77PekjkT5UhIUFT3Eq+LN/Rj9CghLjnxm20IJ/1BfieGsIB63IK3UY5Vr77G4iGQgPMvf
	IX67x0hYfjOuJGDI6jvj+1Sh8g8/mj8WFhZJjWRsxw14VP45eA7cz+iHkJyYBA5vF5UEGQ4n0uE
	XWgHu+37HCC4lCk5uLa6oN1j54D2
X-Received: by 2002:a5d:4c47:0:b0:38b:dc3d:e4be with SMTP id ffacd0b85a97d-38db49214e3mr355994f8f.51.1738712196024;
        Tue, 04 Feb 2025 15:36:36 -0800 (PST)
Received: from smtpclient.apple ([131.111.5.201])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-38c5c0ec369sm16900115f8f.8.2025.02.04.15.36.34
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Feb 2025 15:36:35 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3826.300.87.4.3\))
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for
 x86
From: Jessica Clarke <jrtc27@jrtc27.com>
In-Reply-To: <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
Date: Tue, 4 Feb 2025 23:36:23 +0000
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 luto@kernel.org,
 xin@zytor.com,
 kirill.shutemov@linux.intel.com,
 palmer@dabbelt.com,
 tj@kernel.org,
 andreyknvl@gmail.com,
 brgerst@gmail.com,
 ardb@kernel.org,
 dave.hansen@linux.intel.com,
 jgross@suse.com,
 will@kernel.org,
 akpm@linux-foundation.org,
 arnd@arndb.de,
 corbet@lwn.net,
 dvyukov@google.com,
 richard.weiyang@gmail.com,
 ytcoode@gmail.com,
 tglx@linutronix.de,
 hpa@zytor.com,
 seanjc@google.com,
 paul.walmsley@sifive.com,
 aou@eecs.berkeley.edu,
 justinstitt@google.com,
 jason.andryuk@amd.com,
 glider@google.com,
 ubizjak@gmail.com,
 jannh@google.com,
 bhe@redhat.com,
 vincenzo.frascino@arm.com,
 rafael.j.wysocki@intel.com,
 ndesaulniers@google.com,
 mingo@redhat.com,
 catalin.marinas@arm.com,
 junichi.nomura@nec.com,
 nathan@kernel.org,
 ryabinin.a.a@gmail.com,
 dennis@kernel.org,
 bp@alien8.de,
 kevinloughlin@google.com,
 morbo@google.com,
 dan.j.williams@intel.com,
 julian.stecklina@cyberus-technology.de,
 peterz@infradead.org,
 kees@kernel.org,
 kasan-dev@googlegroups.com,
 x86@kernel.org,
 linux-arm-kernel@lists.infradead.org,
 linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org,
 linux-mm@kvack.org,
 llvm@lists.linux.dev,
 linux-doc@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <0BDD645A-3BBE-4A85-9098-257B281A3BA0@jrtc27.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
X-Mailer: Apple Mail (2.3826.300.87.4.3)
X-Original-Sender: jrtc27@jrtc27.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=F9JeH5Oe;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates
 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
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

On 4 Feb 2025, at 18:58, Christoph Lameter (Ampere) <cl@gentwo.org> wrote:
> ARM64 supports MTE which is hardware support for tagging 16 byte granules
> and verification of tags in pointers all in hardware and on some platform=
s
> with *no* performance penalty since the tag is stored in the ECC areas of
> DRAM and verified at the same time as the ECC.
>=20
> Could we get support for that? This would allow us to enable tag checking
> in production systems without performance penalty and no memory overhead.

It=E2=80=99s not =E2=80=9Cno performance penalty=E2=80=9D, there is a cost =
to tracking the MTE
tags for checking. In asynchronous (or asymmetric) mode that=E2=80=99s not =
too
bad, but in synchronous mode there is a significant overhead even with
ECC. Normally on a store, once you=E2=80=99ve translated it and have the da=
ta,
you can buffer it up and defer the actual write until some time later.
If you hit in the L1 cache then that will probably be quite soon, but
if you miss then you have to wait for the data to come back from lower
levels of the hierarchy, potentially all the way out to DRAM. Or if you
have a write-around cache then you just send it out to the next level
when it=E2=80=99s ready. But now, if you have synchronous MTE, you cannot
retire your store instruction until you know what the tag for the
location you=E2=80=99re storing to is; effectively you have to wait until y=
ou
can do the full cache lookup, and potentially miss, until it can
retire. This puts pressure on the various microarchitectural structures
that track instructions as they get executed, as instructions are now
in flight for longer. Yes, it may well be that it is quicker for the
memory controller to get the tags from ECC bits than via some other
means, but you=E2=80=99re already paying many many cycles at that point, wi=
th
the relevant store being stuck unable to retire (and thus every
instruction after it in the instruction stream) that whole time, and no
write allocate or write around schemes can help you, because you
fundamentally have to wait for the tags to be read before you know if
the instruction is going to trap.

Now, you can choose to not use synchronous mode due to that overhead,
but that=E2=80=99s nuance that isn=E2=80=99t considered by your reply here =
and has some
consequences.

Jess

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
BDD645A-3BBE-4A85-9098-257B281A3BA0%40jrtc27.com.
