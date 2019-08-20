Return-Path: <kasan-dev+bncBCK3VI7AWMIBB6UZ53VAKGQEHGJR4MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E0CC89570C
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Aug 2019 08:02:35 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id 67sf6681083iob.15
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 23:02:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566280954; cv=pass;
        d=google.com; s=arc-20160816;
        b=h0wtwjYfIOem4RpNiI028lBR9z4GEfE7x9AU+lRxK8+2R9p0p+2L5Ynhq4MUObrKcC
         Itw4Z/0k8vmcBAbE7H7c8u0wHSQeXaHpbei+8PsUbcgz3gFgSnYjlYNcESOv2P76sgml
         mdbPVuvBbgBciSXJ9EA+6UBrOAwuJHaKicBNOk1OkqKlSvj1zf2pToEVVROsz/7QhyuE
         pkH9ueR6IE4k2gAx0T8nPp21/VYLmnDT8ZaNK/d3iwwEGtuNfhC93Ijt0yESZhdN75AS
         URwbuLM1Nf4GNYbR5eGQNuCUQo2jCXJrzkI0BBjoSx5ZrrEkOYX5Pn/mcKlX+auGb3wA
         Z9ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=lhaFSdOvm1mmi+hq+WZVJBC03auGS36/zrddL3rPqcA=;
        b=ErlNlKnGByDMQE41vYE1ZdblmoTNyC1N8ReN0BnFe+hR0WTWoytZoeKIyHWQQ1Aew3
         4Oafh4DgWCZVAjCWG2dBHqXEIvI9tOwz4nsP3tV+YKnaQU5UlHarF8SZ4+HmXviUZZ9M
         QoVvNJSp13zRwvCKQXIHoQ/q/D9cdno45Q94B1q/VMlMGBCMPPWuKMWc11xGoRZXCihH
         4R5g/X5OtfVS/o5N/RP0vHwgdw9AFruOdCYVrUbtgsvGxM/rAJLIFUfqTh5x7aTnkEeT
         29UVtcb64LvHBnyEnZzYYUMTWCpSZlOvdZpEVEz0tAYL3LNjbrVRvHvL+OtSIq5g/3uO
         DhuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bhsharma@redhat.com designates 209.132.183.28 as permitted sender) smtp.mailfrom=bhsharma@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lhaFSdOvm1mmi+hq+WZVJBC03auGS36/zrddL3rPqcA=;
        b=ZJJciPxiMup5ESaJjsuBbQd4Eg3mVXivsH/vu74AjWjxxHIpem3R20DkLgPxb7eKJc
         pQZpyyxb4QQqG3OEKvjKwY2hkrsYI70Ta1FgJoxJzefJLETUDBEXkMfP7kvPfMk9qJ8o
         MyBJMphgRPUcQuUh02rC2x5o0vRDHNH2cK7StzOEp9QmEiDYLmg3p1SO4TFII/m2WWYR
         T9WPQ3jqAyuuakoiZY5+pTwB6wFbbSTTVmWKPbe+axgE1Q32sHkCS9z2EH1FTOeVvA6Y
         qgUSQbwSvptwsbdAyAzGZWN1rCMYe7AhM2frlcsQnMl8RE4v0wPPvu3Cc7fpQuHAyWQ5
         QjWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lhaFSdOvm1mmi+hq+WZVJBC03auGS36/zrddL3rPqcA=;
        b=O2zJh3FHgmHkOMPcRT4WJUt8piPPvHJQQPXGj5dKFEw5uMvyoiGnLEBODxhwTL7yCv
         KDQ+nimRLkKk5O3TCJAg3MNHvsQexgZwWLC24Y/gOIHLgzriekfLi+jNokjUntMNevqd
         fZ7L9bVorIvjW0w3X1jJpxJ9aSdhP/3rv1sIGojxVumb35dEbVR/Li0Mp6UNkGYKwt35
         8k2MlTE/wnSxYoSYcJs9OYpKYT3q3GKABvI+/kDyAeic04YfVMVQaXy5gwsHDGOPl4Cn
         ydR7GXwY3R0t3JlkR02yVEBRiYCbFcHe+MsR4GUgb7+JxaAdqlzrLULzx7pVPVU5Kqv+
         nmeA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXG1HT3SoS7KLXpSoXBmVl49emNfQQZupgc2QH55bOJAjMJaa0N
	kSo5luFSvUoULaWTeQM6GTU=
X-Google-Smtp-Source: APXvYqwhT+jZ37tqL4w0ad7fDrNiOQjFRAAYZtGvb9VLcAe8TdTNhG76STERAZYgGNPhvvzjHu8s0Q==
X-Received: by 2002:a02:bb8c:: with SMTP id g12mr1933425jan.116.1566280954237;
        Mon, 19 Aug 2019 23:02:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:9852:: with SMTP id p18ls4568350ios.9.gmail; Mon, 19 Aug
 2019 23:02:33 -0700 (PDT)
X-Received: by 2002:a5e:9818:: with SMTP id s24mr29170914ioj.0.1566280953929;
        Mon, 19 Aug 2019 23:02:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566280953; cv=none;
        d=google.com; s=arc-20160816;
        b=0BpQ49r293Wb9j40Bf0DcptoKGfIygoBeBek6fPXxealc5HOu0PBXK3AjaGyVxJiAn
         BntElP1rbmf4xAl/PLwX/hE0Yu9UfxN8/6zjfbLVasvNw8VYCCM7C1pNfATqSIQmRXQP
         mK3rbsm7v3l3jjDlsklT/MkSw9uHm0QWGyxptumye4gHZgJ8vKih+21kuOlXN3O8Eng2
         AXI68vozvJHcM8fZB5h/yWA8x3skwXdec8drcWpOniAKv6dskH++cVRzxO5kyatxBzWH
         TLhlfuUtNqIVx6Bp/xhuzieRY4yJFG+vzODQ1+0BQ/Vb5Pq4aF3mawGLGiqu9D5U2PAx
         cywQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=H1XYrAigqvbUZcJ7lyXFTe/3R+TlefZrR2FBfbX9mlI=;
        b=z2JzccYCHpO8T2rB54bzVE8eZ3iK7fYylo1duZZa4UbcKEEjFfkejgXZrlO1xSPjUR
         c/Bg7xmguAZXS1XAwiN4i5M39D3WyUfkWy+tEzrJzRyRbS4a8CrDXQSDH2mP/NQ8iQn8
         5qtYHug/AaIVBna24+E5WbEMbOcv8aqhSVxmfxNGDLp4Mlfim4xl8IdBLYWFhtqgFJUv
         9uDu1OW5jYE6C8U/deBM2EXf+yIwJhLb4JOoPjVNKYHL6/gTz/Xllxpiwv1g7A0VyVPL
         /hoxsJIxxknXgDhkJWR6Mh8tmI0g434ei7alZlFITjQRH/ykyTsPnCwZzC/MZQhGEftJ
         9Y8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bhsharma@redhat.com designates 209.132.183.28 as permitted sender) smtp.mailfrom=bhsharma@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from mx1.redhat.com (mx1.redhat.com. [209.132.183.28])
        by gmr-mx.google.com with ESMTPS id p25si343261ios.1.2019.08.19.23.02.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 19 Aug 2019 23:02:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhsharma@redhat.com designates 209.132.183.28 as permitted sender) client-ip=209.132.183.28;
Received: from mail-lf1-f72.google.com (mail-lf1-f72.google.com [209.85.167.72])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mx1.redhat.com (Postfix) with ESMTPS id 79D8FCAA7F
	for <kasan-dev@googlegroups.com>; Tue, 20 Aug 2019 06:02:32 +0000 (UTC)
Received: by mail-lf1-f72.google.com with SMTP id e21so1026103lfn.13
        for <kasan-dev@googlegroups.com>; Mon, 19 Aug 2019 23:02:32 -0700 (PDT)
X-Received: by 2002:ac2:545b:: with SMTP id d27mr14550844lfn.36.1566280950567;
        Mon, 19 Aug 2019 23:02:30 -0700 (PDT)
X-Received: by 2002:ac2:545b:: with SMTP id d27mr14550826lfn.36.1566280950341;
 Mon, 19 Aug 2019 23:02:30 -0700 (PDT)
MIME-Version: 1.0
References: <20190807155524.5112-1-steve.capper@arm.com> <20190807155524.5112-4-steve.capper@arm.com>
 <20190814152017.GD51963@lakrids.cambridge.arm.com> <20190814155711.ldwot7ezrrqjlswc@willie-the-truck>
 <20190814160324.GE51963@lakrids.cambridge.arm.com> <20190815120908.kboyqfnr2fivuva4@willie-the-truck>
In-Reply-To: <20190815120908.kboyqfnr2fivuva4@willie-the-truck>
From: Bhupesh Sharma <bhsharma@redhat.com>
Date: Tue, 20 Aug 2019 11:32:18 +0530
Message-ID: <CACi5LpMGcp2LLJAVeQU0Erj+EsqQnPkjzbga3MDxJ_+d0B-Ydg@mail.gmail.com>
Subject: Re: [PATCH] arm64: fix CONFIG_KASAN_SW_TAGS && CONFIG_KASAN_INLINE
 (was: Re: [PATCH V5 03/12] arm64: kasan: Switch to using) KASAN_SHADOW_OFFSET
To: Will Deacon <will@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Steve Capper <steve.capper@arm.com>, 
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>, 
	Christoph von Recklinghausen <crecklin@redhat.com>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, maz@kernel.org, glider@google.com, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: bhsharma@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bhsharma@redhat.com designates 209.132.183.28 as
 permitted sender) smtp.mailfrom=bhsharma@redhat.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=redhat.com
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

On Thu, Aug 15, 2019 at 5:39 PM Will Deacon <will@kernel.org> wrote:
>
> [+more kasan people and the kasan-dev list]
>
> On Wed, Aug 14, 2019 at 05:03:24PM +0100, Mark Rutland wrote:
> > On Wed, Aug 14, 2019 at 04:57:11PM +0100, Will Deacon wrote:
> > > On Wed, Aug 14, 2019 at 04:20:18PM +0100, Mark Rutland wrote:
> > > > On Wed, Aug 07, 2019 at 04:55:15PM +0100, Steve Capper wrote:
> > > > > diff --git a/arch/arm64/Makefile b/arch/arm64/Makefile
> > > > > index b2400f9c1213..2b7db0d41498 100644
> > > > > --- a/arch/arm64/Makefile
> > > > > +++ b/arch/arm64/Makefile
> > > > > @@ -126,14 +126,6 @@ KBUILD_CFLAGS += -DKASAN_SHADOW_SCALE_SHIFT=$(KASAN_SHADOW_SCALE_SHIFT)
> > > > >  KBUILD_CPPFLAGS += -DKASAN_SHADOW_SCALE_SHIFT=$(KASAN_SHADOW_SCALE_SHIFT)
> > > > >  KBUILD_AFLAGS += -DKASAN_SHADOW_SCALE_SHIFT=$(KASAN_SHADOW_SCALE_SHIFT)
> > > > >
> > > > > -# KASAN_SHADOW_OFFSET = VA_START + (1 << (VA_BITS - KASAN_SHADOW_SCALE_SHIFT))
> > > > > -#                               - (1 << (64 - KASAN_SHADOW_SCALE_SHIFT))
> > > > > -# in 32-bit arithmetic
> > > > > -KASAN_SHADOW_OFFSET := $(shell printf "0x%08x00000000\n" $$(( \
> > > > > -       (0xffffffff & (-1 << ($(CONFIG_ARM64_VA_BITS) - 1 - 32))) \
> > > > > -       + (1 << ($(CONFIG_ARM64_VA_BITS) - 32 - $(KASAN_SHADOW_SCALE_SHIFT))) \
> > > > > -       - (1 << (64 - 32 - $(KASAN_SHADOW_SCALE_SHIFT))) )) )
> > > > > -
> > > > >  export TEXT_OFFSET GZFLAGS
> > > > >
> > > > >  core-y         += arch/arm64/kernel/ arch/arm64/mm/
> > > >
> > > > I've just spotted this breaks build using CONFIG_KASAN_SW_TAGS &&
> > > > CONFIG_KASAN_INLINE, as scripts/Makefile.kasan only propagates
> > > > CONFIG_KASAN_SHADOW_OFFSET into KASAN_SHADOW_OFFSET when
> > > > CONFIG_KASAN_GENERIC is selected, but consumes KASAN_SHADOW_OFFSET
> > > > regardless.
> > > >
> > > > I think that's by accident rather than by design, but to
> > > > minimize/localize the fixup, how about the below? I can send a cleanup
> > > > patch for scripts/Makefile.kasan later.
> > >
> > > How much work is that? I've dropped this stuff from -next for now, so we
> > > have time to fix it properly as long as it's not going to take weeks.
> >
> > I wrote it first, so no effort; patch below.
>
> The patch looks fine to me, but I'd like an Ack from one of the KASAN
> folks before I queue this via the arm64 tree (where support for 52-bit
> virtual addressing in the kernel [1] depends on this being fixed).
>
> Patch is quoted below. Please can somebody take a look?

I tested this on my hpe and apm arm64 hardware boxes and the issue I
reported via <http://lists.infradead.org/pipermail/linux-arm-kernel/2019-August/673424.html>
seem fixed, so:

Tested-by: Bhupesh Sharma <bhsharma@redhat.com>

Thanks,
Bhupesh

> [1] https://git.kernel.org/pub/scm/linux/kernel/git/arm64/linux.git/log/?h=for-next/52-bit-kva
>
> > From ecdf60051a850f817d98f84ae9011afa2311b8f1 Mon Sep 17 00:00:00 2001
> > From: Mark Rutland <mark.rutland@arm.com>
> > Date: Wed, 14 Aug 2019 15:31:57 +0100
> > Subject: [PATCH] kasan/arm64: fix CONFIG_KASAN_SW_TAGS && KASAN_INLINE
> >
> > The generic Makefile.kasan propagates CONFIG_KASAN_SHADOW_OFFSET into
> > KASAN_SHADOW_OFFSET, but only does so for CONFIG_KASAN_GENERIC.
> >
> > Since commit:
> >
> >   6bd1d0be0e97936d ("arm64: kasan: Switch to using KASAN_SHADOW_OFFSET")
> >
> > ... arm64 defines CONFIG_KASAN_SHADOW_OFFSET in Kconfig rather than
> > defining KASAN_SHADOW_OFFSET in a Makefile. Thus, if
> > CONFIG_KASAN_SW_TAGS && KASAN_INLINE are selected, we get build time
> > splats due to KASAN_SHADOW_OFFSET not being set:
> >
> > | [mark@lakrids:~/src/linux]% usellvm 8.0.1 usekorg 8.1.0  make ARCH=arm64 CROSS_COMPILE=aarch64-linux- CC=clang
> > | scripts/kconfig/conf  --syncconfig Kconfig
> > |   CC      scripts/mod/empty.o
> > | clang (LLVM option parsing): for the -hwasan-mapping-offset option: '' value invalid for uint argument!
> > | scripts/Makefile.build:273: recipe for target 'scripts/mod/empty.o' failed
> > | make[1]: *** [scripts/mod/empty.o] Error 1
> > | Makefile:1123: recipe for target 'prepare0' failed
> > | make: *** [prepare0] Error 2
> >
> > Let's fix this by always propagating CONFIG_KASAN_SHADOW_OFFSET into
> > KASAN_SHADOW_OFFSET if CONFIG_KASAN is selected, moving the existing
> > common definition of +CFLAGS_KASAN_NOSANITIZE to the top of
> > Makefile.kasan.
> >
> > Signed-off-by: Mark Rutland <mark.rutland@arm.com>
> > Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> > Cc: Catalin Marinas <catalin.marinas@arm.com>
> > Cc: Steve Capper <steve.capper@arm.com>
> > Cc: Will Deacon <will@kernel.org>
> > ---
> >  scripts/Makefile.kasan | 11 +++++------
> >  1 file changed, 5 insertions(+), 6 deletions(-)
> >
> > diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> > index 6410bd22fe38..03757cc60e06 100644
> > --- a/scripts/Makefile.kasan
> > +++ b/scripts/Makefile.kasan
> > @@ -1,4 +1,9 @@
> >  # SPDX-License-Identifier: GPL-2.0
> > +ifdef CONFIG_KASAN
> > +CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> > +KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
> > +endif
> > +
> >  ifdef CONFIG_KASAN_GENERIC
> >
> >  ifdef CONFIG_KASAN_INLINE
> > @@ -7,8 +12,6 @@ else
> >       call_threshold := 0
> >  endif
> >
> > -KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
> > -
> >  CFLAGS_KASAN_MINIMAL := -fsanitize=kernel-address
> >
> >  cc-param = $(call cc-option, -mllvm -$(1), $(call cc-option, --param $(1)))
> > @@ -45,7 +48,3 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
> >               $(instrumentation_flags)
> >
> >  endif # CONFIG_KASAN_SW_TAGS
> > -
> > -ifdef CONFIG_KASAN
> > -CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> > -endif
> > --
> > 2.11.0
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACi5LpMGcp2LLJAVeQU0Erj%2BEsqQnPkjzbga3MDxJ_%2Bd0B-Ydg%40mail.gmail.com.
