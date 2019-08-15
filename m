Return-Path: <kasan-dev+bncBDAZZCVNSYPBB24W2XVAKGQEXXS72MY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B89808EB20
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 14:09:16 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id b23sf483319vsl.20
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 05:09:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565870955; cv=pass;
        d=google.com; s=arc-20160816;
        b=nRNLexV5p1RxaL1MPLzwqRIpge/8Rz5FewwbaonU33fA3Bx0p8i8gl3oIeHVNS27z1
         41tIFY1IxeH9YoBsAfhn2wSm5y9qTO1WcJtno32RDBsa4l4bZBDvoK8JkIW+hG772IDQ
         q0w9IS6Cj/T3Z10IOrkh+Mw34dNgHkgY1xaeNEBlL8F55/+ZFe3dLMPEoGIp9VBQEcU6
         aTtVhiOg6c8ZeQkwj2SvBgz8PQDL+vRbU02XqcINwVD4go8qksiAl7NSy/pFsWcGrqV4
         b8cEb5sKvrpv/CPn22xUncHxT4DkvHkoXQTCE8HS1kEAY2ad066rPtIz4mu+inVkCtCM
         gjlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=LiY5F7MPPbgN3PNlPcH/dlRhyOPWVPyt3upM+z2m7u4=;
        b=0svoQG4hafm2uUHyDIzamBMtjt1x5tqAQ0yXRMRLuI9SZ+QM9qoezqcu1XO5HGFMPT
         seJMiIfZ75SR8bRIgMn96grrTz1ZcJflVLHQkIfWfPWf28dIS3iK7995yPyjD1FKJfm9
         XELmaP+UCY7EhLWm4Oa6kkkXZQnkT0mHwiOia+/dFZwR8rgbYVHmpg2/xMLvecjtdZr8
         lczb02oOTfJ/wQqbkN+gua1DgAQ6GYIxxI36yVCPYdovCek/Vz76JR/2h1B1E/okBpgH
         BG76SJ4Mo2erPFEJDVE/l/xJ1Qkow2cF7PCSNEumLBf649RK8EF7ONg0PNE8A5PXAfU1
         8EJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=qGn+tEkE;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LiY5F7MPPbgN3PNlPcH/dlRhyOPWVPyt3upM+z2m7u4=;
        b=g6l3UA6PupS7NzI/K6Frgymf+mj4VGNmK51d2XHNhD1oRQJ6ekrgO4ySMJLzmmcJqK
         3F2+n2su6eeHr4SviYMQZx9Tl77k3DFa74z9hS8J6WiLUTQUfEyMDgYIkPKu8wdc4p8/
         T/HoA3c5f+Z4nn7ibf1gOj7BAR27GDxB0IV98ouqW+MTbmfe5dAf0LzYjSficcFWruNg
         uIHb1bRiJMEdkclXkxoU0FxckvZFNm+8nj9Bc8el1AH15SGxKsQORc/xzrSdbkKE3UeM
         Q1Il6O2ToLfII6YBbhVTmrospfphQluJ3Pwpn1ajQKFmc7KAHYcvWjGKCkwO8Jb7W6r4
         OTNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LiY5F7MPPbgN3PNlPcH/dlRhyOPWVPyt3upM+z2m7u4=;
        b=oe69Yfq7MXEy3+07TDMjJrfRW4fV4t9MSVejQpLsJbpdi+tLwJOPweGC9CHcoy6MY8
         3uYYG9EZGbzhIb5jZu+jxo3kEBtOeDYM0dKRI9BgR8pFmj8qgdQLhkxNOYX2zPToE2q0
         5ePnwilLx1zhfTdbo2sxieNJELUqVzcx8FmVU7jP5DL12BPOeJtZ81j74HYBI8w0k1Y/
         iMc++xvHB9v40WZRxO9+s8YMRSbcYRC/VK/LjgCJQlZhRx6m0xtoRtr9DmxahkI8yhwI
         x0nhTIAG3tJl97BI5QFiVgRTdR/AEzQ1868QV1CX24nLjTEBIWrnE3ALjXi+4+j7ea9n
         UPgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV1sZfzcUEyYoI1s3Ex4APABm0eDe4LlH3EdjJfb+sRvzLR7JrO
	tLxTeQynEtEIRBKMMKQwqjc=
X-Google-Smtp-Source: APXvYqz/EY+ZcW+wt9zP+JBZBS7og2BfWW5/QejbPMi/kG6of3qzbUV4vmI6zn5i9Zna4oZG+Hyl3w==
X-Received: by 2002:a67:ea44:: with SMTP id r4mr2882680vso.86.1565870955769;
        Thu, 15 Aug 2019 05:09:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2a09:: with SMTP id o9ls336567uar.11.gmail; Thu, 15 Aug
 2019 05:09:15 -0700 (PDT)
X-Received: by 2002:ab0:59cb:: with SMTP id k11mr2764676uad.36.1565870955408;
        Thu, 15 Aug 2019 05:09:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565870955; cv=none;
        d=google.com; s=arc-20160816;
        b=0HpNXAWad1IvCaWBx0UTYeKfa0s0x28vZIT587uuBoyb1N2LxLdz0oiGeZrSZ40lvH
         XRMbvpJSDX9aK8nyjFXW06a2mu3hAM5D/gFe9T2Ey+OrbNsAtruYeqqBxTeS7F3O67cg
         Vw7N/TA5iSMoOndBsQKAKuC9thlR42drARiLApqdE6sx4CIuAJS0uDOfixczhl72C2kn
         A7nobSf8lscKzPbTCBCJYFHEJCDMdNgLimI2es92VXqM96CtF1HACx7g+GgalR7Bq9YM
         l9lA23Uodd6dKTe3YxB2lq10UGiOOO+lG+5X+C7FcD5HzOl9DEOtULXb0rSbiYkJxGMY
         hhRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=E2RMYVgZhmMjuTbupygWcFQTGOI4EqfWkOyhppYaEpo=;
        b=lPM1MoPopr4b2IDCvjqU16smyp3C4UHMLjcuaMnKtP20tlGyE8rZt/c1EWl1RheyVJ
         JydQgGorsCZ1s2FZaiEN9yddHUfrOOVbxQsSzx9cRk6VEBqVjbZ+UHY0z//Phdh9+sDp
         MCyJT82sUyLlvbNtSbVth20CgI5v9abh7oHF2yL4t2MB0dcivU8ETy+inoYx44tcrwWX
         c2Uvy/8gNFc0Ip/PKa3GVPaSGtx1hEPpuDvTSXN6gNIieDfN6Au6XxS3vqUnEAHe4lTz
         hpBDNPJUxKUnKe4VF5YD1irJ+/FCn8InU0dLG/JH+TqpdL+W7q1uk1IqMjTpnO4eaU/j
         xgQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=qGn+tEkE;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a128si135526vkh.1.2019.08.15.05.09.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 15 Aug 2019 05:09:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from willie-the-truck (236.31.169.217.in-addr.arpa [217.169.31.236])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 44B9120665;
	Thu, 15 Aug 2019 12:09:12 +0000 (UTC)
Date: Thu, 15 Aug 2019 13:09:09 +0100
From: Will Deacon <will@kernel.org>
To: Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Steve Capper <steve.capper@arm.com>,
	linux-arm-kernel@lists.infradead.org, crecklin@redhat.com,
	ard.biesheuvel@linaro.org, catalin.marinas@arm.com,
	bhsharma@redhat.com, maz@kernel.org, glider@google.com,
	dvyukov@google.com, kasan-dev@googlegroups.com
Subject: Re: [PATCH] arm64: fix CONFIG_KASAN_SW_TAGS && CONFIG_KASAN_INLINE
 (was: Re: [PATCH V5 03/12] arm64: kasan: Switch to using)
 KASAN_SHADOW_OFFSET
Message-ID: <20190815120908.kboyqfnr2fivuva4@willie-the-truck>
References: <20190807155524.5112-1-steve.capper@arm.com>
 <20190807155524.5112-4-steve.capper@arm.com>
 <20190814152017.GD51963@lakrids.cambridge.arm.com>
 <20190814155711.ldwot7ezrrqjlswc@willie-the-truck>
 <20190814160324.GE51963@lakrids.cambridge.arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190814160324.GE51963@lakrids.cambridge.arm.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=qGn+tEkE;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

[+more kasan people and the kasan-dev list]

On Wed, Aug 14, 2019 at 05:03:24PM +0100, Mark Rutland wrote:
> On Wed, Aug 14, 2019 at 04:57:11PM +0100, Will Deacon wrote:
> > On Wed, Aug 14, 2019 at 04:20:18PM +0100, Mark Rutland wrote:
> > > On Wed, Aug 07, 2019 at 04:55:15PM +0100, Steve Capper wrote:
> > > > diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
> > > > index b2400f9c1213..2b7db0d41498 100644
> > > > --- a/arch/arm64/Makefile
> > > > +++ b/arch/arm64/Makefile
> > > > @@ -126,14 +126,6 @@ KBUILD_CFLAGS += -DKASAN_SHADOW_SCALE_SHIFT=$(KASAN_SHADOW_SCALE_SHIFT)
> > > >  KBUILD_CPPFLAGS += -DKASAN_SHADOW_SCALE_SHIFT=$(KASAN_SHADOW_SCALE_SHIFT)
> > > >  KBUILD_AFLAGS += -DKASAN_SHADOW_SCALE_SHIFT=$(KASAN_SHADOW_SCALE_SHIFT)
> > > >  
> > > > -# KASAN_SHADOW_OFFSET = VA_START + (1 << (VA_BITS - KASAN_SHADOW_SCALE_SHIFT))
> > > > -#				 - (1 << (64 - KASAN_SHADOW_SCALE_SHIFT))
> > > > -# in 32-bit arithmetic
> > > > -KASAN_SHADOW_OFFSET := $(shell printf "0x%08x00000000\n" $$(( \
> > > > -	(0xffffffff & (-1 << ($(CONFIG_ARM64_VA_BITS) - 1 - 32))) \
> > > > -	+ (1 << ($(CONFIG_ARM64_VA_BITS) - 32 - $(KASAN_SHADOW_SCALE_SHIFT))) \
> > > > -	- (1 << (64 - 32 - $(KASAN_SHADOW_SCALE_SHIFT))) )) )
> > > > -
> > > >  export	TEXT_OFFSET GZFLAGS
> > > >  
> > > >  core-y		+= arch/arm64/kernel/ arch/arm64/mm/
> > > 
> > > I've just spotted this breaks build using CONFIG_KASAN_SW_TAGS &&
> > > CONFIG_KASAN_INLINE, as scripts/Makefile.kasan only propagates
> > > CONFIG_KASAN_SHADOW_OFFSET into KASAN_SHADOW_OFFSET when
> > > CONFIG_KASAN_GENERIC is selected, but consumes KASAN_SHADOW_OFFSET
> > > regardless.
> > > 
> > > I think that's by accident rather than by design, but to
> > > minimize/localize the fixup, how about the below? I can send a cleanup
> > > patch for scripts/Makefile.kasan later.
> > 
> > How much work is that? I've dropped this stuff from -next for now, so we
> > have time to fix it properly as long as it's not going to take weeks.
> 
> I wrote it first, so no effort; patch below.

The patch looks fine to me, but I'd like an Ack from one of the KASAN
folks before I queue this via the arm64 tree (where support for 52-bit
virtual addressing in the kernel [1] depends on this being fixed).

Patch is quoted below. Please can somebody take a look?

Thanks,

Will

[1] https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/log/?h=for-next/52-bit-kva

> From ecdf60051a850f817d98f84ae9011afa2311b8f1 Mon Sep 17 00:00:00 2001
> From: Mark Rutland <mark.rutland@arm.com>
> Date: Wed, 14 Aug 2019 15:31:57 +0100
> Subject: [PATCH] kasan/arm64: fix CONFIG_KASAN_SW_TAGS && KASAN_INLINE
> 
> The generic Makefile.kasan propagates CONFIG_KASAN_SHADOW_OFFSET into
> KASAN_SHADOW_OFFSET, but only does so for CONFIG_KASAN_GENERIC.
> 
> Since commit:
> 
>   6bd1d0be0e97936d ("arm64: kasan: Switch to using KASAN_SHADOW_OFFSET")
> 
> ... arm64 defines CONFIG_KASAN_SHADOW_OFFSET in Kconfig rather than
> defining KASAN_SHADOW_OFFSET in a Makefile. Thus, if
> CONFIG_KASAN_SW_TAGS && KASAN_INLINE are selected, we get build time
> splats due to KASAN_SHADOW_OFFSET not being set:
> 
> | [mark@lakrids:~/src/linux]% usellvm 8.0.1 usekorg 8.1.0  make ARCH=arm64 CROSS_COMPILE=aarch64-linux- CC=clang
> | scripts/kconfig/conf  --syncconfig Kconfig
> |   CC      scripts/mod/empty.o
> | clang (LLVM option parsing): for the -hwasan-mapping-offset option: '' value invalid for uint argument!
> | scripts/Makefile.build:273: recipe for target 'scripts/mod/empty.o' failed
> | make[1]: *** [scripts/mod/empty.o] Error 1
> | Makefile:1123: recipe for target 'prepare0' failed
> | make: *** [prepare0] Error 2
> 
> Let's fix this by always propagating CONFIG_KASAN_SHADOW_OFFSET into
> KASAN_SHADOW_OFFSET if CONFIG_KASAN is selected, moving the existing
> common definition of +CFLAGS_KASAN_NOSANITIZE to the top of
> Makefile.kasan.
> 
> Signed-off-by: Mark Rutland <mark.rutland@arm.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Steve Capper <steve.capper@arm.com>
> Cc: Will Deacon <will@kernel.org>
> ---
>  scripts/Makefile.kasan | 11 +++++------
>  1 file changed, 5 insertions(+), 6 deletions(-)
> 
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 6410bd22fe38..03757cc60e06 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -1,4 +1,9 @@
>  # SPDX-License-Identifier: GPL-2.0
> +ifdef CONFIG_KASAN
> +CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> +KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
> +endif
> +
>  ifdef CONFIG_KASAN_GENERIC
>  
>  ifdef CONFIG_KASAN_INLINE
> @@ -7,8 +12,6 @@ else
>  	call_threshold := 0
>  endif
>  
> -KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
> -
>  CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
>  
>  cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
> @@ -45,7 +48,3 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
>  		$(instrumentation_flags)
>  
>  endif # CONFIG_KASAN_SW_TAGS
> -
> -ifdef CONFIG_KASAN
> -CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> -endif
> -- 
> 2.11.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190815120908.kboyqfnr2fivuva4%40willie-the-truck.
