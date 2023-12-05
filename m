Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBJGDXOVQMGQE6MT4IQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id 9645F804CAF
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Dec 2023 09:39:02 +0100 (CET)
Received: by mail-oo1-xc40.google.com with SMTP id 006d021491bc7-58a5860c88fsf7212182eaf.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Dec 2023 00:39:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701765541; cv=pass;
        d=google.com; s=arc-20160816;
        b=X1AxOnpe36VnkjOPY1cPeYgARd2rmf7Y06cISbzbyQf3y6f8mC8kgfZxbA4gLCp1XC
         FKNP9+1ylfZ+nOPJSsiOvEUaRq4ueXdMJrGnAXJ+vFk623BZhtXabK4Ao8/xjESm3MxJ
         2gxUlSPENJhTxzcNSqnLCRn+3RFwMTmri49Zpui1gSKXZaTH6X1YWPIxkMbDTmQit2ME
         NkgwXNoDcnJCoe6qKpRBXE3o8elDBj0drS0GGXoYwWYI/I0MwAbEFGGNRg/sLWP0P4bG
         imrjMPtwVh8JgLdLS9hZNV2xr63qDAjjqzk8IkmmtDmlIhI9hXhJV8YxadeOmkrqX80f
         hLsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=5jtYKOHkuKDsvS4+dg3zHrl7R7ONdKSEA+ndZTNzs1g=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=ZVLaXnQfl9QA4zueUw6ElXMjfGDabOwgLlDp5PTJYndDpT/MyW5RZgeEiBCgCtnuY7
         yd4x+1I+Oa3krrT1uYlI9/lNF39h3wdIi0hFUtUojM0KHkg7oImqyeCSM3zhuomglYzw
         FXwQ0iEdzN1Z0Tun/mdVFkFvDH096tjzT+rfd17Ovtix1DYbmVzGLCAR9LyzISURmWdS
         82fLoUEKkBqJFdyPDjYONo4TcIFFxSo+FRanLCtC8HRLE9MwTz8cvYWR1c0PTwuOZAf9
         r8Md//w5flxUGMrMl0DZo7/xtqDUsARiUwxwVgSNW7Nc6Fa9Elhtcy7MnJj/d06lgesO
         5+/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HeLHxVsP;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701765541; x=1702370341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=5jtYKOHkuKDsvS4+dg3zHrl7R7ONdKSEA+ndZTNzs1g=;
        b=Z8xeHfbdjcRX1CgNb3I61na5PAnggpBue0RVsFO7j8akFa/8rM8z99rEPQan3iy9Rq
         NTZWHOf0G10hvIxqucGZbTd0ArOkGyvkAmsVWHV1RAWBA42qzXpdk6sigSyleGPjttN8
         RXgJyxgbyrjCi99GXNfjRo0nB3EthD/YdzGUNZhbjZq5ogGB3iVhaiHeuALShfHcce23
         JaQIrruzzwpwRLQI7ESJ+J5DK6UIO3XYKViF2Jk0LzDYRCKnfArGaQZiAylte1ZrHcia
         ACd2+XhTBRvBVF2HHl4Z8um3E88LWCFEPhH9G/7tB9niwP8+K0JmnizvXyzgxTiVY0n/
         VkZA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701765541; x=1702370341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=5jtYKOHkuKDsvS4+dg3zHrl7R7ONdKSEA+ndZTNzs1g=;
        b=Cfj74IMEQPbr+GRW4jLGpI7W1ORSf6zV1deRHUgZh8rlYx/49fUSB68+8XNf/tiWvH
         /5kul6FUud0H3jkwraaf6BMlYVWrXq2Tg2Sc5IjqIKMa+vUw55WiPIw+0dIqb1ZIKhMW
         S2UVXlKT9tUMWQdok9wnLcTDODpRxjlxInDWnKLYo1XKAMTOswq/G0QsQEmKzGB4CD9S
         wIE307yOlMOuX8jufk/bTBLOkoWKIS7LR86Hk/2odaVG9rHrCpIDyIzH5h61XSifqS+Y
         Tjtr3FbORNhp+XMAVmYzCspNzAChnCPOhWnr6a2ofzU/2XjTIa25+KWzBQL3mX0PL8/z
         vNIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701765541; x=1702370341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=5jtYKOHkuKDsvS4+dg3zHrl7R7ONdKSEA+ndZTNzs1g=;
        b=EQOngx3BJkepC+PE9aVUctc1pzdKZ9XfPz9VJWHFBmlquv5HnwqevMu6AbyC/oGWjy
         VYgn7nMFCDKsmzuHhdhpWw7T55wzrmvVuZau2LWdyhQkPUTlqsSynmZvU35S3mf/Vcyw
         1hbLbhcq8CldeKehch9tXL4S01Mo2kml474HvbE067rFDW73MTqUG7GyuRDYmv6qCRFy
         6p4kHvfwQ7BHoGDwI2QL8FnslrDSn5tltiUBXMhAEqJA7ytgTIyVzKcyK38hFUWjB+p8
         SOTWDRHsjsfZJJIxnSLhfzUhR7JfVkABUcka3kCGy3fNVoa9P2Bo+pPUmV90nOf24HWt
         dLcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yx4H4zkvw2JVtpUeVPIna2MUfS4//E7z4wa0zfQbgzkWseBzmeL
	3t/ThpFl94QUGtO/Ouhg9mc=
X-Google-Smtp-Source: AGHT+IEEidWECcwwODKpraqVCejj1+EwAxjBj8EXcAVtt1VSzsIzrYzuiVR+lFqu5Zvyz9sYC3UfLw==
X-Received: by 2002:a05:6820:2282:b0:58d:9b89:a844 with SMTP id ck2-20020a056820228200b0058d9b89a844mr4873020oob.7.1701765541017;
        Tue, 05 Dec 2023 00:39:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:2219:b0:587:9477:19 with SMTP id
 cj25-20020a056820221900b0058794770019ls220548oob.2.-pod-prod-07-us; Tue, 05
 Dec 2023 00:39:00 -0800 (PST)
X-Received: by 2002:a05:6808:f0e:b0:3b8:9cc8:86d4 with SMTP id m14-20020a0568080f0e00b003b89cc886d4mr3294376oiw.11.1701765540646;
        Tue, 05 Dec 2023 00:39:00 -0800 (PST)
Received: by 2002:a05:6808:1a0d:b0:3b3:ed04:dbd0 with SMTP id 5614622812f47-3b8a856eed1msb6e;
        Mon, 4 Dec 2023 20:15:54 -0800 (PST)
X-Received: by 2002:a05:6808:1707:b0:3b8:b063:666e with SMTP id bc7-20020a056808170700b003b8b063666emr5648062oib.101.1701749753587;
        Mon, 04 Dec 2023 20:15:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701749753; cv=none;
        d=google.com; s=arc-20160816;
        b=pKyUtRzQRzraSbUv1qCsr46CSItPt8nPNL6cjo1SnaSplzQMaPl+oqYxpAaVGNwDvb
         DsVVMl7rHcGJA+ZZbxTg2soS3vs8bWF+OslAqD3G+z+gI2SirAhsIIFR8DTxfk1lNLK0
         u8X0c+nSlUyCZqezA5yV05lq93WRGxYghfxT+dlPtoUMDCVjvdb1dsDWpniXC2kbrZ3b
         B0+CX9KEux4oY4/2glAwKNJ9Z/xLgweV9+weWBRvPPsTw6KmKgOzTae7oZ3GNVlnc5Zx
         YX+2/TJzk6H07ZvyN1Th53JhPr+pYbAoXmiCXG6kAozvJaa7ZMn0dney9EyRt79V0hvV
         WadQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=nezVQBT1yQ9zvp+x3Q4cJHMG0UzgLInrLLV8pipEpYA=;
        fh=ezGgTJoHdqijbJ6IWHiSjHZUYI0p+VPBCX/sPRmQd+E=;
        b=J5xVorPTFXVPguMUhOjuKRciX0m5Ln1jCFlehiiWd01F6IE8yU52uOCKbWzFKrjHNl
         77WA6JJWkYD0xhePcBceIFI+dKrrsj7/5Ml1jwWy3EY2HKQ8e6Pc+f4rF5rGOHqUA+pi
         gcOIMjw5djMxvZR2nJSZVoOeYoWIesjnnLwiEi+ZXU6MTvd+YFIN9Q5QKUswhFD4Jy7M
         QHG2ISjU9RBBqOpVhkT/D5jKQGs0Avmb0ZiWkZDipweUepXSICyYJePj7aTDFQqJLU2g
         GR45Y04RHQIi0rsAVwAPtEfdkpYdFqfo0Wh54dI4mIUNonNuhId8dhQHb4PWD4Rw89wd
         VMog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=HeLHxVsP;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id e21-20020a0561020f9500b004649987350fsi653720vsv.0.2023.12.04.20.15.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Dec 2023 20:15:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id 41be03b00d2f7-5c66e7eafabso1942465a12.0
        for <kasan-dev@googlegroups.com>; Mon, 04 Dec 2023 20:15:53 -0800 (PST)
X-Received: by 2002:a17:90a:e654:b0:285:b78a:dbce with SMTP id ep20-20020a17090ae65400b00285b78adbcemr616157pjb.37.1701749752278;
        Mon, 04 Dec 2023 20:15:52 -0800 (PST)
Received: from localhost.localdomain ([1.245.180.67])
        by smtp.gmail.com with ESMTPSA id i4-20020a17090332c400b001d071d58e85sm5371227plr.98.2023.12.04.20.15.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 04 Dec 2023 20:15:51 -0800 (PST)
Date: Tue, 5 Dec 2023 13:15:37 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH v2 02/21] mm/slab: remove CONFIG_SLAB from all Kconfig
 and Makefile
Message-ID: <ZW6j6aTpuJF0keS7@localhost.localdomain>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
 <20231120-slab-remove-slab-v2-2-9c9c70177183@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20231120-slab-remove-slab-v2-2-9c9c70177183@suse.cz>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=HeLHxVsP;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52d
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Mon, Nov 20, 2023 at 07:34:13PM +0100, Vlastimil Babka wrote:
> Remove CONFIG_SLAB, CONFIG_DEBUG_SLAB, CONFIG_SLAB_DEPRECATED and
> everything in Kconfig files and mm/Makefile that depends on those. Since
> SLUB is the only remaining allocator, remove the allocator choice, make
> CONFIG_SLUB a "def_bool y" for now and remove all explicit dependencies
> on SLUB or SLAB as it's now always enabled. Make every option's verbose
> name and description refer to "the slab allocator" without refering to
> the specific implementation. Do not rename the CONFIG_ option names yet.
>=20
> Everything under #ifdef CONFIG_SLAB, and mm/slab.c is now dead code, all
> code under #ifdef CONFIG_SLUB is now always compiled.
>=20
> Reviewed-by: Kees Cook <keescook@chromium.org>
> Reviewed-by: Christoph Lameter <cl@linux.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  arch/arm64/Kconfig |  2 +-
>  arch/s390/Kconfig  |  2 +-
>  arch/x86/Kconfig   |  2 +-
>  lib/Kconfig.debug  |  1 -
>  lib/Kconfig.kasan  | 11 +++------
>  lib/Kconfig.kfence |  2 +-
>  lib/Kconfig.kmsan  |  2 +-
>  mm/Kconfig         | 68 ++++++++++++------------------------------------=
------
>  mm/Kconfig.debug   | 16 ++++---------
>  mm/Makefile        |  6 +----
>  10 files changed, 28 insertions(+), 84 deletions(-)
>=20
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 7b071a00425d..325b7140b576 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -154,7 +154,7 @@ config ARM64
>  	select HAVE_MOVE_PUD
>  	select HAVE_PCI
>  	select HAVE_ACPI_APEI if (ACPI && EFI)
> -	select HAVE_ALIGNED_STRUCT_PAGE if SLUB
> +	select HAVE_ALIGNED_STRUCT_PAGE
>  	select HAVE_ARCH_AUDITSYSCALL
>  	select HAVE_ARCH_BITREVERSE
>  	select HAVE_ARCH_COMPILER_H
> diff --git a/arch/s390/Kconfig b/arch/s390/Kconfig
> index 3bec98d20283..afa42a6f2e09 100644
> --- a/arch/s390/Kconfig
> +++ b/arch/s390/Kconfig
> @@ -146,7 +146,7 @@ config S390
>  	select GENERIC_TIME_VSYSCALL
>  	select GENERIC_VDSO_TIME_NS
>  	select GENERIC_IOREMAP if PCI
> -	select HAVE_ALIGNED_STRUCT_PAGE if SLUB
> +	select HAVE_ALIGNED_STRUCT_PAGE
>  	select HAVE_ARCH_AUDITSYSCALL
>  	select HAVE_ARCH_JUMP_LABEL
>  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 3762f41bb092..3f460f334d4e 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -169,7 +169,7 @@ config X86
>  	select HAS_IOPORT
>  	select HAVE_ACPI_APEI			if ACPI
>  	select HAVE_ACPI_APEI_NMI		if ACPI
> -	select HAVE_ALIGNED_STRUCT_PAGE		if SLUB
> +	select HAVE_ALIGNED_STRUCT_PAGE
>  	select HAVE_ARCH_AUDITSYSCALL
>  	select HAVE_ARCH_HUGE_VMAP		if X86_64 || X86_PAE
>  	select HAVE_ARCH_HUGE_VMALLOC		if X86_64
> diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> index cc7d53d9dc01..e1765face106 100644
> --- a/lib/Kconfig.debug
> +++ b/lib/Kconfig.debug
> @@ -1985,7 +1985,6 @@ config FAULT_INJECTION
>  config FAILSLAB
>  	bool "Fault-injection capability for kmalloc"
>  	depends on FAULT_INJECTION
> -	depends on SLAB || SLUB
>  	help
>  	  Provide fault-injection capability for kmalloc.
> =20
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index fdca89c05745..97e1fdbb5910 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -37,7 +37,7 @@ menuconfig KASAN
>  		     (HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS)) && \
>  		    CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
>  		   HAVE_ARCH_KASAN_HW_TAGS
> -	depends on (SLUB && SYSFS && !SLUB_TINY) || (SLAB && !DEBUG_SLAB)
> +	depends on SYSFS && !SLUB_TINY
>  	select STACKDEPOT_ALWAYS_INIT
>  	help
>  	  Enables KASAN (Kernel Address Sanitizer) - a dynamic memory safety
> @@ -78,7 +78,7 @@ config KASAN_GENERIC
>  	bool "Generic KASAN"
>  	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
>  	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
> -	select SLUB_DEBUG if SLUB
> +	select SLUB_DEBUG
>  	select CONSTRUCTORS
>  	help
>  	  Enables Generic KASAN.
> @@ -89,13 +89,11 @@ config KASAN_GENERIC
>  	  overhead of ~50% for dynamic allocations.
>  	  The performance slowdown is ~x3.
> =20
> -	  (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)
> -
>  config KASAN_SW_TAGS
>  	bool "Software Tag-Based KASAN"
>  	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
>  	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
> -	select SLUB_DEBUG if SLUB
> +	select SLUB_DEBUG
>  	select CONSTRUCTORS
>  	help
>  	  Enables Software Tag-Based KASAN.
> @@ -110,12 +108,9 @@ config KASAN_SW_TAGS
>  	  May potentially introduce problems related to pointer casting and
>  	  comparison, as it embeds a tag into the top byte of each pointer.
> =20
> -	  (Incompatible with CONFIG_DEBUG_SLAB: the kernel does not boot.)
> -
>  config KASAN_HW_TAGS
>  	bool "Hardware Tag-Based KASAN"
>  	depends on HAVE_ARCH_KASAN_HW_TAGS
> -	depends on SLUB
>  	help
>  	  Enables Hardware Tag-Based KASAN.
> =20
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 459dda9ef619..6fbbebec683a 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -5,7 +5,7 @@ config HAVE_ARCH_KFENCE
> =20
>  menuconfig KFENCE
>  	bool "KFENCE: low-overhead sampling-based memory safety error detector"
> -	depends on HAVE_ARCH_KFENCE && (SLAB || SLUB)
> +	depends on HAVE_ARCH_KFENCE
>  	select STACKTRACE
>  	select IRQ_WORK
>  	help
> diff --git a/lib/Kconfig.kmsan b/lib/Kconfig.kmsan
> index ef2c8f256c57..0541d7b079cc 100644
> --- a/lib/Kconfig.kmsan
> +++ b/lib/Kconfig.kmsan
> @@ -11,7 +11,7 @@ config HAVE_KMSAN_COMPILER
>  config KMSAN
>  	bool "KMSAN: detector of uninitialized values use"
>  	depends on HAVE_ARCH_KMSAN && HAVE_KMSAN_COMPILER
> -	depends on SLUB && DEBUG_KERNEL && !KASAN && !KCSAN
> +	depends on DEBUG_KERNEL && !KASAN && !KCSAN
>  	depends on !PREEMPT_RT
>  	select STACKDEPOT
>  	select STACKDEPOT_ALWAYS_INIT
> diff --git a/mm/Kconfig b/mm/Kconfig
> index 89971a894b60..4636870499bb 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -226,52 +226,17 @@ config ZSMALLOC_CHAIN_SIZE
> =20
>  	  For more information, see zsmalloc documentation.
> =20
> -menu "SLAB allocator options"
> -
> -choice
> -	prompt "Choose SLAB allocator"
> -	default SLUB
> -	help
> -	   This option allows to select a slab allocator.
> -
> -config SLAB_DEPRECATED
> -	bool "SLAB (DEPRECATED)"
> -	depends on !PREEMPT_RT
> -	help
> -	  Deprecated and scheduled for removal in a few cycles. Replaced by
> -	  SLUB.
> -
> -	  If you cannot migrate to SLUB, please contact linux-mm@kvack.org
> -	  and the people listed in the SLAB ALLOCATOR section of MAINTAINERS
> -	  file, explaining why.
> -
> -	  The regular slab allocator that is established and known to work
> -	  well in all environments. It organizes cache hot objects in
> -	  per cpu and per node queues.
> +menu "Slab allocator options"
> =20
>  config SLUB
> -	bool "SLUB (Unqueued Allocator)"
> -	help
> -	   SLUB is a slab allocator that minimizes cache line usage
> -	   instead of managing queues of cached objects (SLAB approach).
> -	   Per cpu caching is realized using slabs of objects instead
> -	   of queues of objects. SLUB can use memory efficiently
> -	   and has enhanced diagnostics. SLUB is the default choice for
> -	   a slab allocator.
> -
> -endchoice
> -
> -config SLAB
> -	bool
> -	default y
> -	depends on SLAB_DEPRECATED
> +	def_bool y
> =20
>  config SLUB_TINY
> -	bool "Configure SLUB for minimal memory footprint"
> -	depends on SLUB && EXPERT
> +	bool "Configure for minimal memory footprint"
> +	depends on EXPERT
>  	select SLAB_MERGE_DEFAULT
>  	help
> -	   Configures the SLUB allocator in a way to achieve minimal memory
> +	   Configures the slab allocator in a way to achieve minimal memory
>  	   footprint, sacrificing scalability, debugging and other features.
>  	   This is intended only for the smallest system that had used the
>  	   SLOB allocator and is not recommended for systems with more than
> @@ -282,7 +247,6 @@ config SLUB_TINY
>  config SLAB_MERGE_DEFAULT
>  	bool "Allow slab caches to be merged"
>  	default y
> -	depends on SLAB || SLUB
>  	help
>  	  For reduced kernel memory fragmentation, slab caches can be
>  	  merged when they share the same size and other characteristics.
> @@ -296,7 +260,7 @@ config SLAB_MERGE_DEFAULT
> =20
>  config SLAB_FREELIST_RANDOM
>  	bool "Randomize slab freelist"
> -	depends on SLAB || (SLUB && !SLUB_TINY)
> +	depends on !SLUB_TINY
>  	help
>  	  Randomizes the freelist order used on creating new pages. This
>  	  security feature reduces the predictability of the kernel slab
> @@ -304,21 +268,19 @@ config SLAB_FREELIST_RANDOM
> =20
>  config SLAB_FREELIST_HARDENED
>  	bool "Harden slab freelist metadata"
> -	depends on SLAB || (SLUB && !SLUB_TINY)
> +	depends on !SLUB_TINY
>  	help
>  	  Many kernel heap attacks try to target slab cache metadata and
>  	  other infrastructure. This options makes minor performance
>  	  sacrifices to harden the kernel slab allocator against common
> -	  freelist exploit methods. Some slab implementations have more
> -	  sanity-checking than others. This option is most effective with
> -	  CONFIG_SLUB.
> +	  freelist exploit methods.
> =20
>  config SLUB_STATS
>  	default n
> -	bool "Enable SLUB performance statistics"
> -	depends on SLUB && SYSFS && !SLUB_TINY
> +	bool "Enable performance statistics"
> +	depends on SYSFS && !SLUB_TINY
>  	help
> -	  SLUB statistics are useful to debug SLUBs allocation behavior in
> +	  The statistics are useful to debug slab allocation behavior in
>  	  order find ways to optimize the allocator. This should never be
>  	  enabled for production use since keeping statistics slows down
>  	  the allocator by a few percentage points. The slabinfo command
> @@ -328,8 +290,8 @@ config SLUB_STATS
> =20
>  config SLUB_CPU_PARTIAL
>  	default y
> -	depends on SLUB && SMP && !SLUB_TINY
> -	bool "SLUB per cpu partial cache"
> +	depends on SMP && !SLUB_TINY
> +	bool "Enable per cpu partial caches"
>  	help
>  	  Per cpu partial caches accelerate objects allocation and freeing
>  	  that is local to a processor at the price of more indeterminism
> @@ -339,7 +301,7 @@ config SLUB_CPU_PARTIAL
> =20
>  config RANDOM_KMALLOC_CACHES
>  	default n
> -	depends on SLUB && !SLUB_TINY
> +	depends on !SLUB_TINY
>  	bool "Randomize slab caches for normal kmalloc"
>  	help
>  	  A hardening feature that creates multiple copies of slab caches for
> @@ -354,7 +316,7 @@ config RANDOM_KMALLOC_CACHES
>  	  limited degree of memory and CPU overhead that relates to hardware an=
d
>  	  system workload.
> =20
> -endmenu # SLAB allocator options
> +endmenu # Slab allocator options
> =20
>  config SHUFFLE_PAGE_ALLOCATOR
>  	bool "Page allocator randomization"
> diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
> index 018a5bd2f576..321ab379994f 100644
> --- a/mm/Kconfig.debug
> +++ b/mm/Kconfig.debug
> @@ -45,18 +45,10 @@ config DEBUG_PAGEALLOC_ENABLE_DEFAULT
>  	  Enable debug page memory allocations by default? This value
>  	  can be overridden by debug_pagealloc=3Doff|on.
> =20
> -config DEBUG_SLAB
> -	bool "Debug slab memory allocations"
> -	depends on DEBUG_KERNEL && SLAB
> -	help
> -	  Say Y here to have the kernel do limited verification on memory
> -	  allocation as well as poisoning memory on free to catch use of freed
> -	  memory. This can make kmalloc/kfree-intensive workloads much slower.
> -
>  config SLUB_DEBUG
>  	default y
>  	bool "Enable SLUB debugging support" if EXPERT
> -	depends on SLUB && SYSFS && !SLUB_TINY
> +	depends on SYSFS && !SLUB_TINY
>  	select STACKDEPOT if STACKTRACE_SUPPORT
>  	help
>  	  SLUB has extensive debug support features. Disabling these can
> @@ -66,7 +58,7 @@ config SLUB_DEBUG
> =20
>  config SLUB_DEBUG_ON
>  	bool "SLUB debugging on by default"
> -	depends on SLUB && SLUB_DEBUG
> +	depends on SLUB_DEBUG
>  	select STACKDEPOT_ALWAYS_INIT if STACKTRACE_SUPPORT
>  	default n
>  	help
> @@ -231,8 +223,8 @@ config DEBUG_KMEMLEAK
>  	  allocations. See Documentation/dev-tools/kmemleak.rst for more
>  	  details.
> =20
> -	  Enabling DEBUG_SLAB or SLUB_DEBUG may increase the chances
> -	  of finding leaks due to the slab objects poisoning.
> +	  Enabling SLUB_DEBUG may increase the chances of finding leaks
> +	  due to the slab objects poisoning.
> =20
>  	  In order to access the kmemleak file, debugfs needs to be
>  	  mounted (usually at /sys/kernel/debug).
> diff --git a/mm/Makefile b/mm/Makefile
> index 33873c8aedb3..e4b5b75aaec9 100644
> --- a/mm/Makefile
> +++ b/mm/Makefile
> @@ -4,7 +4,6 @@
>  #
> =20
>  KASAN_SANITIZE_slab_common.o :=3D n
> -KASAN_SANITIZE_slab.o :=3D n
>  KASAN_SANITIZE_slub.o :=3D n
>  KCSAN_SANITIZE_kmemleak.o :=3D n
> =20
> @@ -12,7 +11,6 @@ KCSAN_SANITIZE_kmemleak.o :=3D n
>  # the same word but accesses to different bits of that word. Re-enable K=
CSAN
>  # for these when we have more consensus on what to do about them.
>  KCSAN_SANITIZE_slab_common.o :=3D n
> -KCSAN_SANITIZE_slab.o :=3D n
>  KCSAN_SANITIZE_slub.o :=3D n
>  KCSAN_SANITIZE_page_alloc.o :=3D n
>  # But enable explicit instrumentation for memory barriers.
> @@ -22,7 +20,6 @@ KCSAN_INSTRUMENT_BARRIERS :=3D y
>  # flaky coverage that is not a function of syscall inputs. E.g. slab is =
out of
>  # free pages, or a task is migrated between nodes.
>  KCOV_INSTRUMENT_slab_common.o :=3D n
> -KCOV_INSTRUMENT_slab.o :=3D n
>  KCOV_INSTRUMENT_slub.o :=3D n
>  KCOV_INSTRUMENT_page_alloc.o :=3D n
>  KCOV_INSTRUMENT_debug-pagealloc.o :=3D n
> @@ -66,6 +63,7 @@ obj-y +=3D page-alloc.o
>  obj-y +=3D init-mm.o
>  obj-y +=3D memblock.o
>  obj-y +=3D $(memory-hotplug-y)
> +obj-y +=3D slub.o
> =20
>  ifdef CONFIG_MMU
>  	obj-$(CONFIG_ADVISE_SYSCALLS)	+=3D madvise.o
> @@ -82,8 +80,6 @@ obj-$(CONFIG_SPARSEMEM_VMEMMAP) +=3D sparse-vmemmap.o
>  obj-$(CONFIG_MMU_NOTIFIER) +=3D mmu_notifier.o
>  obj-$(CONFIG_KSM) +=3D ksm.o
>  obj-$(CONFIG_PAGE_POISONING) +=3D page_poison.o
> -obj-$(CONFIG_SLAB) +=3D slab.o
> -obj-$(CONFIG_SLUB) +=3D slub.o
>  obj-$(CONFIG_KASAN)	+=3D kasan/
>  obj-$(CONFIG_KFENCE) +=3D kfence/
>  obj-$(CONFIG_KMSAN)	+=3D kmsan/

Looks good to me,
Reviewed-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>

Nit:

- Some arch configs enables DEBUG_SLAB
- Some documentations refers to {DEBUG_,}SLAB config (i.e. "enable
DEBUG_SLAB for debugging", or "use SLUB instead of SLAB for reducing OS
jitter", ... etc)
- fs/orangefs/orangefs-kernel.h uses #if (defined CONFIG_DEBUG_SLAB)

$ git grep DEBUG_SLAB arch/
arch/arm/configs/ep93xx_defconfig:CONFIG_DEBUG_SLAB=3Dy
arch/arm/configs/tegra_defconfig:CONFIG_DEBUG_SLAB=3Dy
arch/microblaze/configs/mmu_defconfig:CONFIG_DEBUG_SLAB=3Dy

$ git grep SLAB Documentation/

[... some unrelated lines removed ...]

Documentation/admin-guide/cgroup-v1/cpusets.rst:PFA_SPREAD_SLAB, and approp=
riately marked slab caches will allocate
Documentation/admin-guide/cgroup-v1/memory.rst:  pages allocated by the SLA=
B or SLUB allocator are tracked. A copy
Documentation/admin-guide/kernel-per-CPU-kthreads.rst:          CONFIG_SLAB=
=3Dy, thus avoiding the slab allocator's periodic
Documentation/admin-guide/mm/pagemap.rst:   The page is managed by the SLAB=
/SLUB kernel memory allocator.
Documentation/dev-tools/kasan.rst:For slab, both software KASAN modes suppo=
rt SLUB and SLAB allocators, while
Documentation/dev-tools/kfence.rst:of the sample interval, the next allocat=
ion through the main allocator (SLAB or
Documentation/mm/slub.rst:The basic philosophy of SLUB is very different fr=
om SLAB. SLAB
Documentation/mm/slub.rst:                      Sorry SLAB legacy issues)
Documentation/process/4.Coding.rst: - DEBUG_SLAB can find a variety of memo=
ry allocation and use errors; it
Documentation/process/submit-checklist.rst:    ``CONFIG_DEBUG_SLAB``, ``CON=
FIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
Documentation/scsi/ChangeLog.lpfc:        CONFIG_DEBUG_SLAB set).
Documentation/translations/it_IT/process/4.Coding.rst: - DEBUG_SLAB pu=C3=
=B2 trovare svariati errori di uso e di allocazione di memoria;
Documentation/translations/it_IT/process/submit-checklist.rst:    ``CONFIG_=
DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
Documentation/translations/ja_JP/SubmitChecklist:12: CONFIG_PREEMPT, CONFIG=
_DEBUG_PREEMPT, CONFIG_DEBUG_SLAB,
Documentation/translations/zh_CN/dev-tools/kasan.rst:=E5=AF=B9=E4=BA=8Eslab=
=EF=BC=8C=E4=B8=A4=E7=A7=8D=E8=BD=AF=E4=BB=B6KASAN=E6=A8=A1=E5=BC=8F=E9=83=
=BD=E6=94=AF=E6=8C=81SLUB=E5=92=8CSLAB=E5=88=86=E9=85=8D=E5=99=A8=EF=BC=8C=
=E8=80=8C=E5=9F=BA=E4=BA=8E=E7=A1=AC=E4=BB=B6=E6=A0=87=E7=AD=BE=E7=9A=84
Documentation/translations/zh_CN/process/4.Coding.rst: - DEBUG_SLAB =E5=8F=
=AF=E4=BB=A5=E5=8F=91=E7=8E=B0=E5=90=84=E7=A7=8D=E5=86=85=E5=AD=98=E5=88=86=
=E9=85=8D=E5=92=8C=E4=BD=BF=E7=94=A8=E9=94=99=E8=AF=AF=EF=BC=9B=E5=AE=83=E5=
=BA=94=E8=AF=A5=E7=94=A8=E4=BA=8E=E5=A4=A7=E5=A4=9A=E6=95=B0=E5=BC=80=E5=8F=
=91=E5=86=85=E6=A0=B8=E3=80=82
Documentation/translations/zh_CN/process/submit-checklist.rst:    ``CONFIG_=
DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,
Documentation/translations/zh_TW/dev-tools/kasan.rst:=E5=B0=8D=E6=96=BCslab=
=EF=BC=8C=E5=85=A9=E7=A8=AE=E8=BB=9F=E4=BB=B6KASAN=E6=A8=A1=E5=BC=8F=E9=83=
=BD=E6=94=AF=E6=8C=81SLUB=E5=92=8CSLAB=E5=88=86=E9=85=8D=E5=99=A8=EF=BC=8C=
=E8=80=8C=E5=9F=BA=E6=96=BC=E7=A1=AC=E4=BB=B6=E6=A8=99=E7=B1=A4=E7=9A=84
Documentation/translations/zh_TW/process/4.Coding.rst: - DEBUG_SLAB =E5=8F=
=AF=E4=BB=A5=E7=99=BC=E7=8F=BE=E5=90=84=E7=A8=AE=E5=85=A7=E5=AD=98=E5=88=86=
=E9=85=8D=E5=92=8C=E4=BD=BF=E7=94=A8=E9=8C=AF=E8=AA=A4=EF=BC=9B=E5=AE=83=E6=
=87=89=E8=A9=B2=E7=94=A8=E6=96=BC=E5=A4=A7=E5=A4=9A=E6=95=B8=E9=96=8B=E7=99=
=BC=E5=85=A7=E6=A0=B8=E3=80=82
Documentation/translations/zh_TW/process/submit-checklist.rst:    ``CONFIG_=
DEBUG_SLAB``, ``CONFIG_DEBUG_PAGEALLOC``, ``CONFIG_DEBUG_MUTEXES``,

--
Hyeonggon

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZW6j6aTpuJF0keS7%40localhost.localdomain.
