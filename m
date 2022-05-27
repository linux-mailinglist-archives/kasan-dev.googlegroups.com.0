Return-Path: <kasan-dev+bncBCMIZB7QWENRBKGEYGKAMGQESVZZWRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 886DD5358C3
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 07:31:22 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id b2-20020a0565120b8200b00477a4532448sf1486947lfv.22
        for <lists+kasan-dev@lfdr.de>; Thu, 26 May 2022 22:31:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653629482; cv=pass;
        d=google.com; s=arc-20160816;
        b=O7YwAu3s7mGfpa/l3+ylLNYmq4SK5hNHgN6XJmQGZHb+XtHE3oIMxifQYpwRRz/pcP
         0QUQDV27m3/UG71URktmYZqX6MMxfIltp3Aviozckf29SSTZHUgm1/3C2EiV43SEJh57
         CeIDYcl33i6hpWspK6BcIFy3CCtv+xMoPApqJ/1MJgN2xabraFh7vVRkqk0GrmtJFqpi
         5uvVIUCnez9XqH90InJZLEi29mBdVPlG6aHj5OY4RMUHdMYwRsF8Dlys+raRqmhF3Wf0
         iynUs77q7cwxo/2x+7j07mYQX/frvDTvKhLUcErstzKSuFCSHMotu9pZzP+OLbg7ZJHC
         y7wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VuCMc2JO01cAjY2EIlCoN8TReUfKM8g3NZLgLj3vdaw=;
        b=LFciBPalzzRg50rx0cxoYsfrfXLGTAG+v4yj5mMxhZXQMD5JkcjM/n7ibA+yg7DVd0
         SDvDxdhHc3U6iaPpBj3ab2NuYY1BMIXd7m7oZvNngL66b0XWRZ34OMB/Cfeu/8/DWnC/
         NcvpwPEqOI5wgREezThVDJMZSEzaBsAeuSGNkuTlWd+zcvnYTti5yiq7SIMMuRBcRfpv
         Hze6hXThtiyXMmuZH/ZwQ9j3ERmjvk/Y2fRDM4kIxahn3/2q63KHeA2t1hgQVlMrFov5
         3kYTSVjzyp9MMJFLYWAHlXtAqlaH5Axi5vKNMriz2fcixwwO0kacsanmUkP7IenXnC4L
         tYww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TvxRlvu5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VuCMc2JO01cAjY2EIlCoN8TReUfKM8g3NZLgLj3vdaw=;
        b=ZLZZ2tZV1cdfQpQDnHfz/HWawfi62ebm3oA206Z64vWWkWJ3LjiC09QIlqOK6qRXdG
         5ChTUNl2kwYVztLfBi7HoAWbbgPZ/5RurrqB6IyhNRrdnY292ZB9Oun/8Z/qJPaMKJN7
         aL8c5mjWmjZEqlg5c7zVjFj1NHHmHIZj0W8LduCrL82y5W4EBs2t/4ecoVFwDpZnHaQk
         UdBzmsGl6kkdeBVgsk3PF4TLx3VOIpxHfOctO0qrJ/pJ1OGtGOsndXUseTgj1izkt4OQ
         qraujThMqWBgYgprSjhCzRQegIc8dakykUw6cKfZjeQfXwRR0G5y7DAlY5qdYkyfJTEz
         TaIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VuCMc2JO01cAjY2EIlCoN8TReUfKM8g3NZLgLj3vdaw=;
        b=eRLuD8WcbNLzWLi/zIafB2fJKugD+8ZRa2niiZYPDZzEY36JQJAIlXyXsufPO3bhXO
         u8pqCHNoLQyTxgX5FU9G9izCw4BRCeA6G/OsRLo6MQTpc0sRgfMgv6pZ6d3/TBx0pJet
         AVJD9tAi7rJAbbPO/25i3RRGAVVGKTbzzHfPCc9T3iEcsCMH0WRL7mp7OKZSOTemx7VH
         b8GAziDW+7mJTmpUbZ9MEDqOJ8NU4BMYx2Z8XZuwwJIWP+KHrc/LikzHqTwMnlT1G3Qe
         xHRZkb77liRSjCu+N2svbpcJ1l1x/T3dIPAbpX8906uCFk2M+q6iBVw0a/9RaIzayC4F
         CzEg==
X-Gm-Message-State: AOAM532O8hzZm4DnByxrU0CjXlKyDiAtnCCgLipwZIgPncyEwzhlk3ze
	XdM7W3pNbaxDnjY4jBxy9xA=
X-Google-Smtp-Source: ABdhPJzXHEKqBnuD7uS62HzIJEuCEXTZAadmKHXtxo6EDEeOg36+pNJXsTMxvMuJTxQKyNmhs/rdCA==
X-Received: by 2002:a2e:b0c1:0:b0:254:1fc5:3122 with SMTP id g1-20020a2eb0c1000000b002541fc53122mr3731762ljl.114.1653629481407;
        Thu, 26 May 2022 22:31:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls338380lfu.0.gmail; Thu, 26 May 2022
 22:31:20 -0700 (PDT)
X-Received: by 2002:a05:6512:3502:b0:474:21a5:8d41 with SMTP id h2-20020a056512350200b0047421a58d41mr29255129lfs.570.1653629479947;
        Thu, 26 May 2022 22:31:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653629479; cv=none;
        d=google.com; s=arc-20160816;
        b=swW7njPw83Ouo8lNmF0V0/G5r29oE+JSi3prlCmHxxis97F8hXbONY7Ip/5KTL/jL5
         cq7jDAMmzqqJDXl0zalMZbMKk/IZr3wWlo7suQz9BnUHh0NkeZK8tN2YPWvQjFfCuhhx
         nZC8cInlIal0rZGC6nxCqotBzGpLFEr3GQAqJcqPQZki1og/Kudv6hrVbqVUkEkSgJUT
         TsbE4amrJ3gr0JrifpN9KNXuNyGlXtcmsp1oywQnYQeSr/zkp3ZdDh7RxRlQEocDxV+J
         yCcvvJGZZUmX9s2iCuaIrYpCPCDwuNxCOjUTUKg31G8DSPhxOXoaYr8kwESsjCcU/NM8
         j7CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FXpXFDqSJSH7QNVAUYO8Ygf0XCIT9cNVqP2wBQ1nUX4=;
        b=j10gPgdcPN0fZpBwXhibfmiJz+QEArVZqYqoEr6nluNVgujbbTX82EGAVXtLlqxZwS
         UzLOG0Ae3+GPihXVF3w6+Y6oyPGUwxez/7bSNN7Bx6QpK208KWP/PYqxHeHcRVMod51K
         GKlZ9hq2E842ffnL20C2gF1saUsYWBugNdS6NnbQ48055H1vEpzcJwOHpngHOrdmUMkt
         FCJEI3Vj2QTtb7anJavJxW4I4SJUqbBN/bVJUgCFewittBbi7bPBlujw19MdO+bSj98i
         Lphu7ooE0hCdyuzRQMLWAGMgDtj93LMqHdToDBl6KIZOTdCxfdFDTy7BU++f3Q7KbA/B
         RTow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TvxRlvu5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x130.google.com (mail-lf1-x130.google.com. [2a00:1450:4864:20::130])
        by gmr-mx.google.com with ESMTPS id a6-20020ac25e66000000b00472523f3a8esi152202lfr.6.2022.05.26.22.31.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 May 2022 22:31:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130 as permitted sender) client-ip=2a00:1450:4864:20::130;
Received: by mail-lf1-x130.google.com with SMTP id br17so5312988lfb.2
        for <kasan-dev@googlegroups.com>; Thu, 26 May 2022 22:31:19 -0700 (PDT)
X-Received: by 2002:a05:6512:3d0:b0:478:9aca:4a06 with SMTP id
 w16-20020a05651203d000b004789aca4a06mr9088099lfp.410.1653629479269; Thu, 26
 May 2022 22:31:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220525111756.GA15955@axis.com> <20220526010111.755166-1-davidgow@google.com>
In-Reply-To: <20220526010111.755166-1-davidgow@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 07:31:00 +0200
Message-ID: <CACT4Y+a191xbPi_0w6imTAYHDeAoudrxbWiuERBOk41e5q_K_Q@mail.gmail.com>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
To: David Gow <davidgow@google.com>
Cc: Vincent Whitchurch <vincent.whitchurch@axis.com>, Johannes Berg <johannes@sipsolutions.net>, 
	Patricia Alfonso <trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, 
	Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, LKML <linux-kernel@vger.kernel.org>, 
	Daniel Latypov <dlatypov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=TvxRlvu5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::130
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 26 May 2022 at 03:02, David Gow <davidgow@google.com> wrote:
>
> From: Patricia Alfonso <trishalfonso@google.com>
>
> Make KASAN run on User Mode Linux on x86_64.
>
> The UML-specific KASAN initializer uses mmap to map the roughly 2.25TB
> of shadow memory to the location defined by KASAN_SHADOW_OFFSET.
> kasan_init() utilizes constructors to initialize KASAN before main().
>
> The location of the KASAN shadow memory, starting at
> KASAN_SHADOW_OFFSET, can be configured using the KASAN_SHADOW_OFFSET
> option. UML uses roughly 18TB of address space, and KASAN requires 1/8th
> of this. The default location of this offset is 0x100000000000, which
> keeps it out-of-the-way even on UML setups with more "physical" memory.
>
> For low-memory setups, 0x7fff8000 can be used instead, which fits in an
> immediate and is therefore faster, as suggested by Dmitry Vyukov. There
> is usually enough free space at this location; however, it is a config
> option so that it can be easily changed if needed.
>
> Note that, unlike KASAN on other architectures, vmalloc allocations
> still use the shadow memory allocated upfront, rather than allocating
> and free-ing it per-vmalloc allocation.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
> Co-developed-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: Vincent Whitchurch <vincent.whitchurch@axis.com>
> Signed-off-by: David Gow <davidgow@google.com>
> ---
>
> This is a new RFC for the KASAN/UML port, based on the patch v1:
> https://lore.kernel.org/all/20200226004608.8128-1-trishalfonso@google.com/
>
> With several fixes by Vincent Whitchurch:
> https://lore.kernel.org/all/20220525111756.GA15955@axis.com/
>
> That thread describes the differences from the v1 (and hence the
> previous RFCs better than I can here), but the gist of it is:
> - Support for KASAN_VMALLOC, by changing the way
>   kasan_{populate,release}_vmalloc work to update existing shadow
>   memory, rather than allocating anything new.
> - A similar fix for modules' shadow memory.
> - Support for KASAN_STACK
>   - This requires the bugfix here:
> https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
>   - Plus a couple of files excluded from KASAN.
> - Revert the default shadow offset to 0x100000000000
>   - This was breaking when mem=1G for me, at least.
> - A few minor fixes to linker sections and scripts.
>   - I've added one to dyn.lds.S on top of the ones Vincent added.

Excited to see this revived!

> There are still a few things to be sorted out before this is ready to go
> upstream, in particular:
> - We've got a bunch of checks for CONFIG_UML, where a more specific
>   config option might be better. For example: CONFIG_KASAN_NO_SHADOW_ALLOC.

Probably. But with 1 arch setting it, I am fine either way.

> - Alternatively, the vmalloc (and module) shadow memory allocators could
>   support per-architecture replacements.

Humm... again hard to say while we have only 1 arch doing this.
Another option: leave a comment on the first CONFIG_UML check listing
these alternatives. When another arch needs something similar, then we
can switch to one of these options.

> - Do we want to the alignment before or after the __memset() in
>   kasan_populate_vmalloc()?

I think you did it correctly (alignment after).
8 normal pages map to 1 shadow page. For the purposes of mapping pages
lazily on other arches, we want to over-map. But for the memset, we
want to clear only the shadow that relates to the current region.


> - This doesn't seem to work when CONFIG_STATIC_LINK is enabled (because
>   libc crt0 code calls memory functions, which expect the shadow memory
>   to already exist, due to multiple symbols being resolved.
>   - I think we should just make this depend on dynamic UML.
>   - For that matter, I think static UML is actually broken at the
>     moment. I'll send a patch out tomorrow.

I don't know how important the static build is for UML.
Generally I prefer to build things statically b/c e.g. if a testing
system builds on one machine but runs tests on another, dynamic link
may be a problem. Or, say, if a testing system provides binary
artifacts, and then nobody can run it locally.

One potential way to fix it is to require outline KASAN
instrumentation for static build and then make kasan_arch_is_ready()
return false until the shadow is mapped. I see kasan_arch_is_ready()
is checked at the beginning of all KASAN runtime entry points.
But it would be nice if the dynamic build also supports inline and
does not add kasan_arch_is_ready() check overhead.

> - And there's a checkpatch complaint about a long __memset() line.
>
> Thanks again to everyone who's contributed and looked at these patches!
> Note that I removed the Reviewed-by tags, as I think this version has
> enough changes to warrant a re-review.
>
> -- David
>
> ---
>  arch/um/Kconfig                  | 15 +++++++++++++++
>  arch/um/Makefile                 |  6 ++++++
>  arch/um/include/asm/common.lds.S |  2 ++
>  arch/um/kernel/Makefile          |  3 +++
>  arch/um/kernel/dyn.lds.S         |  6 +++++-
>  arch/um/kernel/mem.c             | 18 ++++++++++++++++++
>  arch/um/os-Linux/mem.c           | 22 ++++++++++++++++++++++
>  arch/um/os-Linux/user_syms.c     |  4 ++--
>  arch/x86/um/Makefile             |  3 ++-
>  arch/x86/um/vdso/Makefile        |  3 +++
>  mm/kasan/shadow.c                | 20 +++++++++++++++++++-
>  11 files changed, 97 insertions(+), 5 deletions(-)
>
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index 4d398b80aea8..c28ea5c89381 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -11,6 +11,8 @@ config UML
>         select ARCH_HAS_STRNLEN_USER
>         select ARCH_NO_PREEMPT
>         select HAVE_ARCH_AUDITSYSCALL
> +       select HAVE_ARCH_KASAN if X86_64
> +       select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ASM_MODVERSIONS
>         select HAVE_UID16
> @@ -219,6 +221,19 @@ config UML_TIME_TRAVEL_SUPPORT
>
>           It is safe to say Y, but you probably don't need this.
>
> +config KASAN_SHADOW_OFFSET
> +       hex
> +       depends on KASAN
> +       default 0x100000000000
> +       help
> +         This is the offset at which the ~2.25TB of shadow memory is
> +         mapped and used by KASAN for memory debugging. This can be any
> +         address that has at least KASAN_SHADOW_SIZE(total address space divided
> +         by 8) amount of space so that the KASAN shadow memory does not conflict
> +         with anything. The default is 0x100000000000, which works even if mem is
> +         set to a large value. On low-memory systems, try 0x7fff8000, as it fits
> +         into the immediate of most instructions, improving performance.
> +
>  endmenu
>
>  source "arch/um/drivers/Kconfig"
> diff --git a/arch/um/Makefile b/arch/um/Makefile
> index f2fe63bfd819..a98405f4ecb8 100644
> --- a/arch/um/Makefile
> +++ b/arch/um/Makefile
> @@ -75,6 +75,12 @@ USER_CFLAGS = $(patsubst $(KERNEL_DEFINES),,$(patsubst -I%,,$(KBUILD_CFLAGS))) \
>                 -D_FILE_OFFSET_BITS=64 -idirafter $(srctree)/include \
>                 -idirafter $(objtree)/include -D__KERNEL__ -D__UM_HOST__
>
> +# Kernel config options are not included in USER_CFLAGS, but the option for KASAN
> +# should be included if the KASAN config option was set.
> +ifdef CONFIG_KASAN
> +       USER_CFLAGS+=-DCONFIG_KASAN=y
> +endif
> +
>  #This will adjust *FLAGS accordingly to the platform.
>  include $(srctree)/$(ARCH_DIR)/Makefile-os-$(OS)
>
> diff --git a/arch/um/include/asm/common.lds.S b/arch/um/include/asm/common.lds.S
> index eca6c452a41b..fd481ac371de 100644
> --- a/arch/um/include/asm/common.lds.S
> +++ b/arch/um/include/asm/common.lds.S
> @@ -83,6 +83,8 @@
>    }
>    .init_array : {
>         __init_array_start = .;
> +       *(.kasan_init)
> +       *(.init_array.*)
>         *(.init_array)
>         __init_array_end = .;
>    }
> diff --git a/arch/um/kernel/Makefile b/arch/um/kernel/Makefile
> index 1c2d4b29a3d4..a089217e2f0e 100644
> --- a/arch/um/kernel/Makefile
> +++ b/arch/um/kernel/Makefile
> @@ -27,6 +27,9 @@ obj-$(CONFIG_EARLY_PRINTK) += early_printk.o
>  obj-$(CONFIG_STACKTRACE) += stacktrace.o
>  obj-$(CONFIG_GENERIC_PCI_IOMAP) += ioport.o
>
> +KASAN_SANITIZE_stacktrace.o := n
> +KASAN_SANITIZE_sysrq.o := n
> +
>  USER_OBJS := config.o
>
>  include arch/um/scripts/Makefile.rules
> diff --git a/arch/um/kernel/dyn.lds.S b/arch/um/kernel/dyn.lds.S
> index 2f2a8ce92f1e..2b7fc5b54164 100644
> --- a/arch/um/kernel/dyn.lds.S
> +++ b/arch/um/kernel/dyn.lds.S
> @@ -109,7 +109,11 @@ SECTIONS
>       be empty, which isn't pretty.  */
>    . = ALIGN(32 / 8);
>    .preinit_array     : { *(.preinit_array) }
> -  .init_array     : { *(.init_array) }
> +  .init_array     : {
> +    *(.kasan_init)
> +    *(.init_array.*)
> +    *(.init_array)
> +  }
>    .fini_array     : { *(.fini_array) }
>    .data           : {
>      INIT_TASK_DATA(KERNEL_STACK_SIZE)
> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> index 15295c3237a0..a32cfce53efb 100644
> --- a/arch/um/kernel/mem.c
> +++ b/arch/um/kernel/mem.c
> @@ -18,6 +18,24 @@
>  #include <kern_util.h>
>  #include <mem_user.h>
>  #include <os.h>
> +#include <linux/sched/task.h>
> +
> +#ifdef CONFIG_KASAN
> +void kasan_init(void)
> +{
> +       /*
> +        * kasan_map_memory will map all of the required address space and
> +        * the host machine will allocate physical memory as necessary.
> +        */
> +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> +       init_task.kasan_depth = 0;
> +       os_info("KernelAddressSanitizer initialized\n");
> +}
> +
> +static void (*kasan_init_ptr)(void)
> +__section(".kasan_init") __used
> += kasan_init;
> +#endif
>
>  /* allocated in paging_init, zeroed in mem_init, and unchanged thereafter */
>  unsigned long *empty_zero_page = NULL;
> diff --git a/arch/um/os-Linux/mem.c b/arch/um/os-Linux/mem.c
> index 3c1b77474d2d..8530b2e08604 100644
> --- a/arch/um/os-Linux/mem.c
> +++ b/arch/um/os-Linux/mem.c
> @@ -17,6 +17,28 @@
>  #include <init.h>
>  #include <os.h>
>
> +/*
> + * kasan_map_memory - maps memory from @start with a size of @len.
> + * The allocated memory is filled with zeroes upon success.
> + * @start: the start address of the memory to be mapped
> + * @len: the length of the memory to be mapped
> + *
> + * This function is used to map shadow memory for KASAN in uml
> + */
> +void kasan_map_memory(void *start, size_t len)
> +{
> +       if (mmap(start,
> +                len,
> +                PROT_READ|PROT_WRITE,
> +                MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_NORESERVE,
> +                -1,
> +                0) == MAP_FAILED) {
> +               os_info("Couldn't allocate shadow memory: %s\n.",
> +                       strerror(errno));
> +               exit(1);
> +       }
> +}
> +
>  /* Set by make_tempfile() during early boot. */
>  static char *tempdir = NULL;
>
> diff --git a/arch/um/os-Linux/user_syms.c b/arch/um/os-Linux/user_syms.c
> index 715594fe5719..cb667c9225ab 100644
> --- a/arch/um/os-Linux/user_syms.c
> +++ b/arch/um/os-Linux/user_syms.c
> @@ -27,10 +27,10 @@ EXPORT_SYMBOL(strstr);
>  #ifndef __x86_64__
>  extern void *memcpy(void *, const void *, size_t);
>  EXPORT_SYMBOL(memcpy);
> -#endif
> -
>  EXPORT_SYMBOL(memmove);
>  EXPORT_SYMBOL(memset);
> +#endif
> +
>  EXPORT_SYMBOL(printf);
>
>  /* Here, instead, I can provide a fake prototype. Yes, someone cares: genksyms.
> diff --git a/arch/x86/um/Makefile b/arch/x86/um/Makefile
> index ba5789c35809..f778e37494ba 100644
> --- a/arch/x86/um/Makefile
> +++ b/arch/x86/um/Makefile
> @@ -28,7 +28,8 @@ else
>
>  obj-y += syscalls_64.o vdso/
>
> -subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o
> +subarch-y = ../lib/csum-partial_64.o ../lib/memcpy_64.o ../entry/thunk_64.o \
> +       ../lib/memmove_64.o ../lib/memset_64.o
>
>  endif
>
> diff --git a/arch/x86/um/vdso/Makefile b/arch/x86/um/vdso/Makefile
> index 5943387e3f35..8c0396fd0e6f 100644
> --- a/arch/x86/um/vdso/Makefile
> +++ b/arch/x86/um/vdso/Makefile
> @@ -3,6 +3,9 @@
>  # Building vDSO images for x86.
>  #
>
> +# do not instrument on vdso because KASAN is not compatible with user mode
> +KASAN_SANITIZE                 := n
> +
>  # Prevents link failures: __sanitizer_cov_trace_pc() is not linked in.
>  KCOV_INSTRUMENT                := n
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index a4f07de21771..d8c518bd0e7d 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -295,8 +295,14 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
>                 return 0;
>
>         shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> -       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>         shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> +
> +       if (IS_ENABLED(CONFIG_UML)) {
> +               __memset(kasan_mem_to_shadow((void *)addr), KASAN_VMALLOC_INVALID, shadow_end - shadow_start);

"kasan_mem_to_shadow((void *)addr)" can be replaced with shadow_start.


> +               return 0;
> +       }
> +
> +       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>         shadow_end = ALIGN(shadow_end, PAGE_SIZE);

There is no new fancy PAGE_ALIGN macro for this. And I've seen people
sending clean up patches with replacements.
But unfortunately no PAGE_ALIGN_DOWN :(



>
>         ret = apply_to_page_range(&init_mm, shadow_start,
> @@ -466,6 +472,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>
>         if (shadow_end > shadow_start) {
>                 size = shadow_end - shadow_start;
> +               if (IS_ENABLED(CONFIG_UML)) {
> +                       __memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
> +                       return;
> +               }
>                 apply_to_existing_page_range(&init_mm,
>                                              (unsigned long)shadow_start,
>                                              size, kasan_depopulate_vmalloc_pte,
> @@ -531,6 +541,11 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>         if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
>                 return -EINVAL;
>
> +       if (IS_ENABLED(CONFIG_UML)) {
> +               __memset((void *)shadow_start, KASAN_SHADOW_INIT, shadow_size);
> +               return 0;
> +       }
> +
>         ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
>                         shadow_start + shadow_size,
>                         GFP_KERNEL,
> @@ -554,6 +569,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
>
>  void kasan_free_module_shadow(const struct vm_struct *vm)
>  {
> +       if (IS_ENABLED(CONFIG_UML))
> +               return;
> +
>         if (vm->flags & VM_KASAN)
>                 vfree(kasan_mem_to_shadow(vm->addr));
>  }
> --
> 2.36.1.124.g0e6072fb45-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba191xbPi_0w6imTAYHDeAoudrxbWiuERBOk41e5q_K_Q%40mail.gmail.com.
