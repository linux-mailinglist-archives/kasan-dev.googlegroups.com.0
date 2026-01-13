Return-Path: <kasan-dev+bncBDW2JDUY5AORBEWHS3FQMGQEII6ZBEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id DD8EDD16313
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 02:44:51 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-38303040a01sf31413151fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 17:44:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768268691; cv=pass;
        d=google.com; s=arc-20240605;
        b=g5OZ7w1DAfoFRgFi9iR6GQh9n1PBE3BCpwzhFADH2EB9lceIZFskBXjwweHirbnuXA
         j1KZFof8JQv4oFrtzzi6wBBxoHqfJHiNRjTY2b+ktUmDqySprDCNCb1tu2T2SE+rbx+v
         zuiazZdr0VkOcYVKygmuiJV74+vFVmvn0o5niNwGvLJ6T9pQZidZxLXWARcA/VNpfIFo
         wrv7NEPH3dXEM0e/uSPCpNINyTUDIDj6ZPia9Z1WQXMk179m+Cf8O2scA7qg6tmKwKBc
         buUXdyLjZMP3VShnOuqB8eN6VNf/y12spppOOrgOzkBtLrVO9JXzLBqfMIJrUVCRorjk
         JE/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=MOPC9OP5XENenzpPfEq//URg9D1A7zTf8/iyVEaVsWY=;
        fh=1CbsHlhdc1d9ti+PgbsM3Z6CXVppwTeF4imuSRE8jE4=;
        b=jWgFOajakaOuuumYTSJKdmfXPMXhd9Or0afQ4U7h9xDOEiDwNPdNDTAidZ5KCclZDL
         VQxuygwhsJCOJIVWcsYn8SkWLhyLTXkxz/JXvo5SpadoShQ/9eVcc5Xe4ezmIFD0u/uL
         W0HSIfRvuZiztisHokSsM2uTJMi/3Nkxlw5dA8z4jYX4uUKn6tLSetxI1R/pplnuOoWY
         xTTdrRkpAzvlqY9r9fUv6f/y8bocCfE8aw43gTU7eSV+xqJJEn2WQjqzPAUM2EC/zRB5
         LN7ACPxdHHtrr2mvLIiufzG0QQdI7NHKXChY/RQWnHFYR5K8LIUkU/89yTPZEzj30t1y
         xo/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RGDK53dn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768268691; x=1768873491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MOPC9OP5XENenzpPfEq//URg9D1A7zTf8/iyVEaVsWY=;
        b=CARlMSZie/Xzd4hubCN3lMSpbQwJnbNKnvmIE8oNVbDVS6BdMSP/cd6nY0DxnmSZUx
         qkVLAbRHnPa5Ze1J4OqDvtmZ8yYrFzUpRaW0JZRQ4MyAKz/WQIXMRoZmj2Ytf60RWINe
         aNYeLp+LzBYE07mvjaCZnOvb4DmrL0EUMZk+sJX9wpYjhdVTyosQoi+kzXBaBZnoNeTP
         litRvsC2Kq/GmZo4alN21PT/C3jUVTQDPOXngi5qBfw/v2GGitndtKyNeDCC0/DKk/ta
         HhvQ7OHeIO2sNejroCUFH6vm0thRmikqYn9o7/ZkQ2lgwZfce5U1s3P5CjPd8IOmUVIE
         WcWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768268691; x=1768873491; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MOPC9OP5XENenzpPfEq//URg9D1A7zTf8/iyVEaVsWY=;
        b=MTwP0Gk9qbHDzX3iqruDJjqrlwgnLNuTuRqMIaZR/ktKWg8hEkQz1nQt2TU8WHDObT
         LTRFw0HkVanXOdyrUcfVc7vymcDWMLjSZWkXefvVyCFnB4Tgtw0ZRSQflUjO69+2AeXT
         SFOzuYBW2W3ONrzxDnwSUJBDIwCAgcpCsSHGQ32s1/8czDD19HpLqFX5516VoeOS6V5Z
         tqLBTFzSKkQ+ImGrcRzVWaW9IXx7Gu3YtP0W5lm7dp1z6QJbZZ/T38w4f+8wUMfeK2cl
         G9xA/9bbfjdeeWiLQ0cZSWz2Po/+RrYipyDykEz91xIjdARr4u8H4uAqArgG4h0tPtZI
         f9fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768268691; x=1768873491;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MOPC9OP5XENenzpPfEq//URg9D1A7zTf8/iyVEaVsWY=;
        b=JM63t6VrP4TlRfFDqRk5nKG09Jyb2sPY4XLJxndv60/xzvpLedHkJKai3SW0N4MgfM
         CaK8Kz5flgusI9V5RKB9XIe5UrNk09hJT02W5VdiivAn0g/UGgXg/8at1/P4QEBvI2vj
         a0zCbDgWkbhdajaKnc4CUSAQqXBEchVEcVRzJcmZh8DIFJ5RXoOCYWbNymZRSu6x4Oya
         BZUqHzrTjo15dSccKL6maZQBjA+kYqwyLZSnHc4EgQ9e9tTZ4etIxYUgvo8x7PWfvDQa
         PuT5iKexLsNR0QrisbN/y9/aCS6jiI5A1P2fZmMl9sAQq+c18e33y2KXlkQhfga77AJI
         6mpg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUNMT8x441cOX9ItHgnGBbFitBs20iahPi2N9UHyJscbsH+3QiBgBpb0GnKr2HPRoSbN+NKFQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxzg/OXOnVnP4WFX9dsk1b36kzU8OASJ7GjfzcfoomseNu7ApzX
	dynnicjeSLIa4IUzM/dZaRmUByrgJvOExMzBKRxdBIz61/es/IPCQwpt
X-Google-Smtp-Source: AGHT+IGklHCI2sUbAAmWMBVgNYXtSfepfWpdlL+5tgSE8IDHW9w8/xVOntQ7ycHy+2Mfz3xAXUxLvw==
X-Received: by 2002:a05:6512:2248:b0:59b:8259:5fb8 with SMTP id 2adb3069b0e04-59b825960d0mr3938812e87.7.1768268690654;
        Mon, 12 Jan 2026 17:44:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HW5MR9OC/FYK+hkG/IKeq/rld8wk1b4fU9lQmM5Pe3bw=="
Received: by 2002:a05:6512:2254:b0:59b:6ead:861e with SMTP id
 2adb3069b0e04-59b6ead876dls376822e87.1.-pod-prod-05-eu; Mon, 12 Jan 2026
 17:44:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUtqISAgGyUg5OKAsCqZEpO3rePy4qem/Hkh1OMUnVRw57VqawAEymlJIStBeJ3CzaJuQXnaK2A7c8=@googlegroups.com
X-Received: by 2002:a05:651c:a07:b0:37f:cb34:211b with SMTP id 38308e7fff4ca-382ff68c23emr61346111fa.18.1768268687940;
        Mon, 12 Jan 2026 17:44:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768268687; cv=none;
        d=google.com; s=arc-20240605;
        b=QHHsxpPS4g2Gz3/+dgN0W1Adwob6WhqQ1OS9irzoLPgO+INM8/JYXfga4N8PGMpuP1
         IctUly89sjnVAIRtxMiFwBPS/L+c2N5/qQLpKhqJDiBMAy6RtgkIxoiFT4fjc/Bt0FhC
         wBNycq93n0tn7JcG/QC/9g8v492ksGWehQJ7b0/NLnCBpSFIE6+Rtwb4rvHPUC8E2t8v
         m0VWKZ6DGeoyB397Ul+zc2NLbEavAc1j/1w08vIOX9SowDnLf578ls1bbXEx7Dl67hFb
         jkDRIQ2rIybsTrtC0on97N8C0jWyyjUBmEH2mt+rW0gvv/TvfNgMBg3Uvw8F1Loaxx68
         su4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=8QXuf4cwRpBOzqTZvP4qMKCqVPPc0MElEg+LdlADa3c=;
        fh=4TEFNJ5oXfSNfac3eNP6PKPwgL4aSw/IDbBPkKPwipA=;
        b=k+lgDbkd1Su9R7YSCU0jEvZVk7ZCERoA1DhF9QJbFD8BNnPx3j8An5tb+7qvldwAj9
         ujasVbReD+0UWGFBGD17rs4i8N2xljll9oUqFT5XFmLRT3PlH5VLQFEmQ6dFX7mwqt9i
         oarGImiNA4x0ryjliHOBemXg3gusDoL+wM9TJ1N8kRg1/R+w90GiAMqR5cZ5ev9Rhzi2
         mT+wKI4UZoqOGdC5PlG6qGgZhcUFoQNqrdYHrstG1UEPFx+34SmqFxoE2ybTNzjGbf2H
         KAgBI7TXXJ2v1+glccNQpQlPy+PHaOIhDAdKfuqKLSsnrT1bSnE3Kobh5KcXcasS3PlB
         koUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=RGDK53dn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-382fc3b94f2si3000251fa.7.2026.01.12.17.44.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 17:44:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-42fb0fc5aa4so5219536f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 17:44:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX2c69nwzuNNfZJWVyhhsqmm+kuWz2BDamfm1a7aStza/1pH5W18kowjZ78SRRif0wN+cCSjTCdfEI=@googlegroups.com
X-Gm-Gg: AY/fxX6y6KeYQ5z+qifNmkQ3tkJmX8EBfVAn4ZUOFGdTPrVaEoNkvYd5TEKvBWqNSlD
	LkwFieELEL87xbeCEMWqLQPbiNbQ/NzFlXulIckSgz5OdAWEcdLthk8EYbYC/rSP9WQf4r1GWvG
	W6yUZ0e6LjEWbotZT+k+6+XBMcZkExzh8SlAULNKoz1Pc10X+Moz8nu6tfgeXM3h0pcpHbkRV7p
	cJXZ5p913gHMpXkDno73wq5j68NB87Z9VQDsrr85WQ64YWx/ediCkTcyEcGnzTJ71/A8faek8Se
	cm5108oyZKGeAVEHHZwU9Gg2QA3s6Q==
X-Received: by 2002:a05:6000:25c6:b0:42b:4267:83e3 with SMTP id
 ffacd0b85a97d-432c374f5femr24312893f8f.5.1768268687045; Mon, 12 Jan 2026
 17:44:47 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 13 Jan 2026 02:44:35 +0100
X-Gm-Features: AZwV_Qg49kJdgHS5b0feyJ3FQ4qpkZSxgMzwvg9-kXkrvqB0Op5YiaAIZPipNv4
Message-ID: <CA+fCnZf5NMa=_Aic_gVQ05rvAvYx0xUpbZ=hOg2=7A9=ZbPdFw@mail.gmail.com>
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: corbet@lwn.net, morbo@google.com, rppt@kernel.org, 
	lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com, 
	vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org, 
	catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org, 
	jackmanb@google.com, samuel.holland@sifive.com, glider@google.com, 
	osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org, 
	akpm@linux-foundation.org, Liam.Howlett@oracle.com, kees@kernel.org, 
	jan.kiszka@siemens.com, thomas.lendacky@amd.com, jeremy.linton@arm.com, 
	dvyukov@google.com, axelrasmussen@google.com, leitao@debian.org, 
	ryabinin.a.a@gmail.com, bigeasy@linutronix.de, peterz@infradead.org, 
	mark.rutland@arm.com, urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, 
	mhocko@suse.com, weixugc@google.com, kbingham@kernel.org, vbabka@suse.cz, 
	nathan@kernel.org, trintaeoitogc@gmail.com, samitolvanen@google.com, 
	tglx@kernel.org, thuth@redhat.com, surenb@google.com, 
	anshuman.khandual@arm.com, smostafa@google.com, yuanchu@google.com, 
	ada.coupriediaz@arm.com, dave.hansen@linux.intel.com, kas@kernel.org, 
	nick.desaulniers+lkml@gmail.com, david@kernel.org, bp@alien8.de, 
	ardb@kernel.org, justinstitt@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=RGDK53dn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Mon, Jan 12, 2026 at 6:26=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> =3D=3D=3D=3D=3D=3D=3D Introduction
> The patchset aims to add a KASAN tag-based mode for the x86 architecture
> with the help of the new CPU feature called Linear Address Masking
> (LAM). Main improvement introduced by the series is 2x lower memory
> usage compared to KASAN's generic mode, the only currently available
> mode on x86. The tag based mode may also find errors that the generic
> mode couldn't because of differences in how these modes operate.
>
> =3D=3D=3D=3D=3D=3D=3D How does KASAN' tag-based mode work?
> When enabled, memory accesses and allocations are augmented by the
> compiler during kernel compilation. Instrumentation functions are added
> to each memory allocation and each pointer dereference.
>
> The allocation related functions generate a random tag and save it in
> two places: in shadow memory that maps to the allocated memory, and in
> the top bits of the pointer that points to the allocated memory. Storing
> the tag in the top of the pointer is possible because of Top-Byte Ignore
> (TBI) on arm64 architecture and LAM on x86.
>
> The access related functions are performing a comparison between the tag
> stored in the pointer and the one stored in shadow memory. If the tags
> don't match an out of bounds error must have occurred and so an error
> report is generated.
>
> The general idea for the tag-based mode is very well explained in the
> series with the original implementation [1].
>
> [1] https://lore.kernel.org/all/cover.1544099024.git.andreyknvl@google.co=
m/
>
> =3D=3D=3D=3D=3D=3D=3D Differences summary compared to the arm64 tag-based=
 mode
> - Tag width:
>         - Tag width influences the chance of a tag mismatch due to two
>           tags from different allocations having the same value. The
>           bigger the possible range of tag values the lower the chance
>           of that happening.
>         - Shortening the tag width from 8 bits to 4, while it can help
>           with memory usage, it also increases the chance of not
>           reporting an error. 4 bit tags have a ~7% chance of a tag
>           mismatch.
>
> - Address masking mechanism
>         - TBI in arm64 allows for storing metadata in the top 8 bits of
>           the virtual address.
>         - LAM in x86 allows storing tags in bits [62:57] of the pointer.
>           To maximize memory savings the tag width is reduced to bits
>           [60:57].
>
> - Inline mode mismatch reporting
>         - Arm64 inserts a BRK instruction to pass metadata about a tag
>           mismatch to the KASAN report.
>         - Right now on x86 the INT3 instruction is used for the same
>           purpose. The attempt to move it over to use UD1 is already
>           implemented and tested but relies on another series that needs
>           merging first. Therefore this patch will be posted separately
>           once the dependency is satisfied by being merged upstream.
>

Please also update the Software Tag-Based KASAN section in
Documentation/dev-tools/kasan.rst accordingly.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf5NMa%3D_Aic_gVQ05rvAvYx0xUpbZ%3DhOg2%3D7A9%3DZbPdFw%40mail.gmail.c=
om.
