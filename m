Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBHV74PCQMGQEHVPSBLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D554B42E4F
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 02:38:57 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-329d88c126csf346751a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 17:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756946335; cv=pass;
        d=google.com; s=arc-20240605;
        b=LyYsyIT861tHVi1K2DqTMiLHRVnBg7wihA3m15DWwM5KF6E6aVo+nJ9iKKreLJn2a0
         xaQ7CnbTxAtBRTunRXIompr06d2RHv5vYS4Fph3kfgqxqJPTqJ4qQ6XFrMEDyzZn2iae
         3UO2I49VX/MWgAICiaPZN3yYPF+8+6tlasv5sFBCiX97faoDH+wl0vNBMLVNG2gIr8y2
         McPHmTaUGx3CaJmd0toxvbhWu3aVIeQr4v39HZqq89l+dHa8TOTLZ8yeMHPTLpzYXcwJ
         ZiKO1PyATixZYYtLk1g0zFsJyLQuP3dFskoszx2vWaVVMjU5tXnqI/MSmt2rH3POePqv
         Sf6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:message-id:date
         :in-reply-to:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=ziGRsyYOAU7tnHCTNHqh1Eya24Wt0SHJl176ZSakaFI=;
        fh=V2vWJDOKSzlpPRT4LZCTXcr9CSo4j5g6Q+uG2hNs4g4=;
        b=k76i4wEnGRNdVZ3RIdPLs57aXEMHrLsUro8jT5gKT/lEevCd6c8ulXhWAnHseAS4/q
         ur/cXpnNtdNjw4s71cIEb3rDbGVf7e4tNe04djasTq8Z1uQzq4raCjMEZap7Za8h+aaS
         kTzi8cryZjRuo6msTbBAs/2WFeOBTgbll34Db3+IYfeb4bX45iwxWMv3u8pOYCcImi3S
         8+obmN53APtf+/OmLFq8Vxb8eASGD/5APt37nw5hW7cZSqKU6km8pHZSrc/q31p/U1ko
         YlVC6YyEn/8gineY0Dj1SbCDjOcBDpgi53hfA6HMi3nij7SWxhKdhKXPt/rl9PAHLT+Q
         0l4w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZjqfyKkK;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756946335; x=1757551135; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:message-id:date:in-reply-to:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ziGRsyYOAU7tnHCTNHqh1Eya24Wt0SHJl176ZSakaFI=;
        b=ddgss/AOZL5GjUXhKndTagWVUpo3UsDRYMUYiPclPEc6nAXnEUz5ExBJL5Ypf3+TQU
         g+l6AOizBlRQ7ndN/BPfeGe6MQ4I9VwTxE5F97phxHga8iRPAridHlq11HyBLtOJih/f
         2SDbXu5mz5WLdRVSDRNpRvn+o/CumbuRyTIJ9emdwuuhyTF7OBxj4IMLhKSy93xGi5J/
         WMlVaLQHldBea6wvj4qDX/oIdUiEvNuLcwYK38Wgc7EJKOtvsojkEsmKducu4vyYc40z
         e4rqJdjomp5MiZp1e7WOM4R6xsYL0m+1nkv9ldwsLrPNI1Cts9PJAQwUCSKd7JC58FQZ
         piJw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756946335; x=1757551135; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:message-id:date:in-reply-to:subject:cc
         :to:from:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=ziGRsyYOAU7tnHCTNHqh1Eya24Wt0SHJl176ZSakaFI=;
        b=OQmcHC2F6qnarOQVz0zhHiyfigm29u9OSBlCJcyfQwRTtfuFExUg+8gO23LEH3TvtN
         CP97U0aKw0Xw+QZsbDCP2HORVtKPchVp+j/y/oFJmLYNM4RQ9S0xnnmZO05WB93niNqB
         hj3IpCnerNRZ/srY48uTCh861b7Wp3J6vgTu9jE+wvx/WeqF0AX9rs1ppWV1218A53ss
         GCEPKA1xvITremZCnKf2aGwDlA7izCeJpF52RqiQZhQmkVXXHJ8JPGBoUjyRdnlpj7iZ
         bgO87anCK25dLc2faazOowodn2CCqtfChBIon1+tc2h0n1+R4fjjJoH1Fpe4f77cRvMv
         1VZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756946335; x=1757551135;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :message-id:date:in-reply-to:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ziGRsyYOAU7tnHCTNHqh1Eya24Wt0SHJl176ZSakaFI=;
        b=hDJRgCKcMIypqq8xe/wjSTbrqnf1/kGBrNMBmZCCrKI/DqopFp79YBnfRygiEGj6ME
         0KWK1vttwzbY5wkMyrDF6dqiHHNoTvIuphGYyFbhW1p93Erx3m1p/3aUiEdoppV89+Ok
         HJYv4eqUyzWz9+ao8PkJjnaUfdrq1XzrO0E9FJUyZQCqJQfwmQenvKd9/dhDMjcx1wMZ
         HTzm5ggg85kZ7dngWkMYPqijwAjQh4emUvxLN3gjWvKmEkiJuCWayYIsmhTDHlKppBqv
         ke56SMIGv1yy1wMDEfmaxU3MnN4rZaLJTtkBgoFxmMi45mycQlDdLITm2nd2dxsNrF34
         12tw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkb0BjZ9bdLLbBUvsoBJu9aJMpWkOtnnsxprYu+p4q3a7OX36PTfMbytGcNuZv2JDXtrB6Sg==@lfdr.de
X-Gm-Message-State: AOJu0YzmvwP+8WR1gunNCrLTrRyH4R0Ov0INjZR0HLPaUm1iqkddbxSC
	I9dAyH5LPqr9xihe0RgV5tkpGH4TaPzJTRsczbM6ecpYFUuBdrwB0XGn
X-Google-Smtp-Source: AGHT+IFT7vqh5PsFG0jj/rW8OJMsCZaWVCbftLvKEgLM3UISju+gr1DvBvgP+bSfPc/pnbiRz+BFwA==
X-Received: by 2002:a17:90b:1848:b0:327:6de3:24b6 with SMTP id 98e67ed59e1d1-3281541223dmr21467076a91.8.1756946335225;
        Wed, 03 Sep 2025 17:38:55 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeiNCpp3/94f/vhGmzVt09Q2p9Df0HY0vZn3du17p1R2A==
Received: by 2002:a17:90b:3754:b0:31c:c0bd:10f8 with SMTP id
 98e67ed59e1d1-32b5ed78079ls1355354a91.0.-pod-prod-09-us; Wed, 03 Sep 2025
 17:38:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlvoFkNVsHBVFDOVExKG93fMm+n69qC/UZqPC/hDbXHWwDvo81fFhW+iSSYwDVLYOB+qOhjGBhNp0=@googlegroups.com
X-Received: by 2002:a05:6a21:9989:b0:243:78a:8280 with SMTP id adf61e73a8af0-243d6f8e6e2mr24301384637.56.1756946333673;
        Wed, 03 Sep 2025 17:38:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756946333; cv=none;
        d=google.com; s=arc-20240605;
        b=UoeJI8FIgBG+Qe48fn+M+Z1HLMjegPjWDcecfzYPGhpYOnosODgcUJQW/MKLTgPpSi
         nw1/GMeG8MWIebQ8p5egWhqWG4x96S3SFYjXiTfrfLDdxPWbj14vSXSRnDJGBAEFpa94
         jviTbiLRdpm/9MPpisWSPMXGv54iaHQg3bp3FDzZ0LQaSzdW74WJ2bZlBnYRGEf151Zq
         XnepT+wn05dguDq4ZiSvjADdSPfGfCelhlKs37YI/TfBanoli29Mw7Lb41thY+kJG9vs
         8lAr0yofQv74BYKTF7mL2bv94+d65CDCkAEbS/44iL0qInBzcq37P42PRL5cCp/MW54O
         UOSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:message-id:date:in-reply-to:subject:cc:to:from
         :dkim-signature;
        bh=M9wjahpjajRVdLTvLPg2jmwGdR+YAWepelf042yY0AY=;
        fh=2KIh0XGGpFdFGWhQ7JQwy5uIIYri8yDuZtFJigSbfsw=;
        b=RBnXo7GeBP0vG6diaGEQzQ8B+zB02PeGSYKMqLkoDNem//xQPAqyPgoV5Rt1pRH5vb
         fowXUoupulD5euF7WLF8Kqxgb6WEU0OVJO2E30LtthnnltwY2yb5s4dZmClhYozJDNkC
         Gb/eL2qLSEYeeNkhyz5srHjSgiDASbaZHqaKZO5TXKiY4VTA/zkD0i6G3jV7WwimJb5/
         5Xiu5A9OWngv50f/AgVdsduHYmHHwoZ3PJNm/X84czC7VHf9MuoHM2Htxp+xzZJkYY3U
         0i00x1xoOoyhckTiRtQDXAVpCBEQKU+vmpKw7CnaPXatnfUvgzpWBtrMrYYvHkrRG9ej
         UjIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZjqfyKkK;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4fabd11096si94625a12.5.2025.09.03.17.38.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 17:38:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-327771edfbbso385042a91.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 17:38:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXJLaBQV052esUZnpOcYq8fZ9eIWU2sbRMkOEZBYvkq+Degkh7ow+0wgxsEZ5QmO1zWIzV2YiBCNM=@googlegroups.com
X-Gm-Gg: ASbGncvP8mNgs20f3glSs9OXCi8oXaDcLKygxlfE8uXZpHiR6Xc0dm2qJQh4odKBto4
	em7cKWm3fJNBMVoTdR7nin8WETWCgM++yibnikvPhdEjwUCiUrdjUyQ9JH5GzXSJMu+ntkBGQAB
	jKm4FEI2fvtmeVmlZ62pIkc0kOSJZhc9mHs7Asjog1lJUOwYxMqgjPos8sBMPNGbNoX0BMsu653
	HHMJEh3crmQNdowVJhyt1jT1Lgy+n6viV2VfQ/DY2Lh3WQsseSMqLIqd7eHbUIzJiKq2vT/nCNw
	oMkCh560VyAXiRTr1TQfjQVgM9hKsn2VDjQ4ykpjc4TOXUeNSvURJvT/nTyguK3m9so9jQla26i
	S/3yxRnPTVmx2phExTuDobJ8=
X-Received: by 2002:a17:90b:3811:b0:32b:6145:fa63 with SMTP id 98e67ed59e1d1-32b614601acmr4849866a91.4.1756946333006;
        Wed, 03 Sep 2025 17:38:53 -0700 (PDT)
Received: from dw-tp ([171.76.85.3])
        by smtp.gmail.com with ESMTPSA id 41be03b00d2f7-b4fb98f9f6asm1185841a12.8.2025.09.03.17.38.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Sep 2025 17:38:52 -0700 (PDT)
From: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com, christophe.leroy@csgroup.eu, bhe@redhat.com, hca@linux.ibm.com, andreyknvl@gmail.com, akpm@linux-foundation.org, zhangqing@loongson.cn, chenhuacai@loongson.cn, davidgow@google.com, glider@google.com, dvyukov@google.com, alexghiti@rivosinc.com
Cc: alex@ghiti.fr, agordeev@linux.ibm.com, vincenzo.frascino@arm.com, elver@google.com, kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org, snovitoll@gmail.com
Subject: Re: [PATCH v6 1/2] kasan: introduce ARCH_DEFER_KASAN and unify static key across modes
In-Reply-To: <20250810125746.1105476-2-snovitoll@gmail.com>
Date: Thu, 04 Sep 2025 05:54:04 +0530
Message-ID: <87ldmv6p5n.ritesh.list@gmail.com>
References: <20250810125746.1105476-1-snovitoll@gmail.com> <20250810125746.1105476-2-snovitoll@gmail.com>
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZjqfyKkK;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::1030
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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

Sabyrzhan Tasbolatov <snovitoll@gmail.com> writes:

> Introduce CONFIG_ARCH_DEFER_KASAN to identify architectures [1] that need
> to defer KASAN initialization until shadow memory is properly set up,
> and unify the static key infrastructure across all KASAN modes.
>
> [1] PowerPC, UML, LoongArch selects ARCH_DEFER_KASAN.
>
> The core issue is that different architectures haveinconsistent approaches
> to KASAN readiness tracking:
> - PowerPC, LoongArch, and UML arch, each implement own
>   kasan_arch_is_ready()
> - Only HW_TAGS mode had a unified static key (kasan_flag_enabled)
> - Generic and SW_TAGS modes relied on arch-specific solutions or always-on
>     behavior
>
> This patch addresses the fragmentation in KASAN initialization
> across architectures by introducing a unified approach that eliminates
> duplicate static keys and arch-specific kasan_arch_is_ready()
> implementations.
>
> Let's replace kasan_arch_is_ready() with existing kasan_enabled() check,
> which examines the static key being enabled if arch selects
> ARCH_DEFER_KASAN or has HW_TAGS mode support.
> For other arch, kasan_enabled() checks the enablement during compile time.
>
> Now KASAN users can use a single kasan_enabled() check everywhere.
>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> Changes in v6:
> - Added more details in git commit message
> - Fixed commenting format per coding style in UML (Christophe Leroy)
> - Changed exporting to GPL for kasan_flag_enabled (Christophe Leroy)
> - Converted ARCH_DEFER_KASAN to def_bool depending on KASAN to avoid
>         arch users to have `if KASAN` condition (Christophe Leroy)
> - Forgot to add __init for kasan_init in UML
>
> Changes in v5:
> - Unified patches where arch (powerpc, UML, loongarch) selects
>     ARCH_DEFER_KASAN in the first patch not to break
>     bisectability
> - Removed kasan_arch_is_ready completely as there is no user
> - Removed __wrappers in v4, left only those where it's necessary
>     due to different implementations
>
> Changes in v4:
> - Fixed HW_TAGS static key functionality (was broken in v3)
> - Merged configuration and implementation for atomicity
> ---
>  arch/loongarch/Kconfig                 |  1 +
>  arch/loongarch/include/asm/kasan.h     |  7 ------
>  arch/loongarch/mm/kasan_init.c         |  8 +++----
>  arch/powerpc/Kconfig                   |  1 +
>  arch/powerpc/include/asm/kasan.h       | 12 ----------
>  arch/powerpc/mm/kasan/init_32.c        |  2 +-
>  arch/powerpc/mm/kasan/init_book3e_64.c |  2 +-
>  arch/powerpc/mm/kasan/init_book3s_64.c |  6 +----
>  arch/um/Kconfig                        |  1 +
>  arch/um/include/asm/kasan.h            |  5 ++--
>  arch/um/kernel/mem.c                   | 13 ++++++++---
>  include/linux/kasan-enabled.h          | 32 ++++++++++++++++++--------
>  include/linux/kasan.h                  |  6 +++++
>  lib/Kconfig.kasan                      | 12 ++++++++++
>  mm/kasan/common.c                      | 17 ++++++++++----
>  mm/kasan/generic.c                     | 19 +++++++++++----
>  mm/kasan/hw_tags.c                     |  9 +-------
>  mm/kasan/kasan.h                       |  8 ++++++-
>  mm/kasan/shadow.c                      | 12 +++++-----
>  mm/kasan/sw_tags.c                     |  1 +
>  mm/kasan/tags.c                        |  2 +-
>  21 files changed, 106 insertions(+), 70 deletions(-)
>
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index 93402a1d9c9f..4730c676b6bf 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -122,6 +122,7 @@ config PPC
>  	# Please keep this list sorted alphabetically.
>  	#
>  	select ARCH_32BIT_OFF_T if PPC32
> +	select ARCH_NEEDS_DEFER_KASAN		if PPC_RADIX_MMU
>  	select ARCH_DISABLE_KASAN_INLINE	if PPC_RADIX_MMU
>  	select ARCH_DMA_DEFAULT_COHERENT	if !NOT_COHERENT_CACHE
>  	select ARCH_ENABLE_MEMORY_HOTPLUG
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
> index b5bbb94c51f6..957a57c1db58 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -53,18 +53,6 @@
>  #endif
>  
>  #ifdef CONFIG_KASAN
> -#ifdef CONFIG_PPC_BOOK3S_64
> -DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> -
> -static __always_inline bool kasan_arch_is_ready(void)
> -{
> -	if (static_branch_likely(&powerpc_kasan_enabled_key))
> -		return true;
> -	return false;
> -}
> -
> -#define kasan_arch_is_ready kasan_arch_is_ready
> -#endif
>  
>  void kasan_early_init(void);
>  void kasan_mmu_init(void);
> diff --git a/arch/powerpc/mm/kasan/init_32.c b/arch/powerpc/mm/kasan/init_32.c
> index 03666d790a53..1d083597464f 100644
> --- a/arch/powerpc/mm/kasan/init_32.c
> +++ b/arch/powerpc/mm/kasan/init_32.c
> @@ -165,7 +165,7 @@ void __init kasan_init(void)
>  
>  	/* At this point kasan is fully initialized. Enable error messages */
>  	init_task.kasan_depth = 0;
> -	pr_info("KASAN init done\n");
> +	kasan_init_generic();
>  }
>  
>  void __init kasan_late_init(void)
> diff --git a/arch/powerpc/mm/kasan/init_book3e_64.c b/arch/powerpc/mm/kasan/init_book3e_64.c
> index 60c78aac0f63..0d3a73d6d4b0 100644
> --- a/arch/powerpc/mm/kasan/init_book3e_64.c
> +++ b/arch/powerpc/mm/kasan/init_book3e_64.c
> @@ -127,7 +127,7 @@ void __init kasan_init(void)
>  
>  	/* Enable error messages */
>  	init_task.kasan_depth = 0;
> -	pr_info("KASAN init done\n");
> +	kasan_init_generic();
>  }
>  
>  void __init kasan_late_init(void) { }
> diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kasan/init_book3s_64.c
> index 7d959544c077..dcafa641804c 100644
> --- a/arch/powerpc/mm/kasan/init_book3s_64.c
> +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> @@ -19,8 +19,6 @@
>  #include <linux/memblock.h>
>  #include <asm/pgalloc.h>
>  
> -DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> -
>  static void __init kasan_init_phys_region(void *start, void *end)
>  {
>  	unsigned long k_start, k_end, k_cur;
> @@ -92,11 +90,9 @@ void __init kasan_init(void)
>  	 */
>  	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>  
> -	static_branch_inc(&powerpc_kasan_enabled_key);
> -
>  	/* Enable error messages */
>  	init_task.kasan_depth = 0;
> -	pr_info("KASAN init done\n");
> +	kasan_init_generic();
>  }
>  

Only book3s64 needs static keys here because of radix v/s hash mode
selection during runtime. The changes in above for powerpc looks good to
me. It's a nice cleanup too.

So feel free to take:
Reviewed-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com> #powerpc

However I have few comments below...

...
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 9142964ab9c9..e3765931a31f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -32,6 +32,15 @@
>  #include "kasan.h"
>  #include "../slab.h"
>  
> +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
> +/*
> + * Definition of the unified static key declared in kasan-enabled.h.
> + * This provides consistent runtime enable/disable across KASAN modes.
> + */
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +EXPORT_SYMBOL_GPL(kasan_flag_enabled);
> +#endif
> +
>  struct slab *kasan_addr_to_slab(const void *addr)
>  {
>  	if (virt_addr_valid(addr))
> @@ -246,7 +255,7 @@ static inline void poison_slab_object(struct kmem_cache *cache, void *object,
>  bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>  				unsigned long ip)
>  {
> -	if (!kasan_arch_is_ready() || is_kfence_address(object))
> +	if (is_kfence_address(object))

For changes in mm/kasan/common.c.. you have removed !kasan_enabled()
check at few places. This seems to be partial revert of commit [1]:
  
  b3c34245756ada "kasan: catch invalid free before SLUB reinitializes the object" 

Can you please explain why this needs to be removed? 
Also the explaination of the same should be added in the commit msg too.

[1]: https://lore.kernel.org/all/20240809-kasan-tsbrcu-v8-1-aef4593f9532@google.com/

>  		return false;
>  	return check_slab_allocation(cache, object, ip);
>  }
> @@ -254,7 +263,7 @@ bool __kasan_slab_pre_free(struct kmem_cache *cache, void *object,
>  bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
>  		       bool still_accessible)
>  {
> -	if (!kasan_arch_is_ready() || is_kfence_address(object))
> +	if (is_kfence_address(object))
>  		return false;
>  
>  	/*
> @@ -293,7 +302,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, bool init,
>  
>  static inline bool check_page_allocation(void *ptr, unsigned long ip)
>  {
> -	if (!kasan_arch_is_ready())
> +	if (!kasan_enabled())
>  		return false;
>  
>  	if (ptr != page_address(virt_to_head_page(ptr))) {
> @@ -522,7 +531,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
>  		return true;
>  	}
>  
> -	if (is_kfence_address(ptr) || !kasan_arch_is_ready())
> +	if (is_kfence_address(ptr))
>  		return true;
>  
>  	slab = folio_slab(folio);

-ritesh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87ldmv6p5n.ritesh.list%40gmail.com.
