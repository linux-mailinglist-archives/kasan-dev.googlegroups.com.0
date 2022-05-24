Return-Path: <kasan-dev+bncBC6OLHHDVUOBBEXHWSKAMGQEILLG7HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id E324C5331CB
	for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 21:35:46 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id i8-20020a50fd08000000b0042baef934f5sf744334eds.16
        for <lists+kasan-dev@lfdr.de>; Tue, 24 May 2022 12:35:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653420946; cv=pass;
        d=google.com; s=arc-20160816;
        b=hHQXlvMOW0qRFSEXu1UKxezuoMqttaQ4zJEmSflsPtG383oWPsTh0nRUep68UcwN08
         jGHSE1vqetPmPB7APHqbTDJPjlM0w0kebBodP/AQAmB+vV2pyc7gDv7f2IVtFmzwL6At
         Qj/jH0FIuor53T9V/vY7pYIWVNHZYFjM87XWg2rTFkWt9u5G5hvTOn7fh8MnQ2TfD9iZ
         M6zlh1xfCizu69Qjr4+LgNje2fWV3J8u61lNTQ4Pu4azbUXS9Xyg9dnNWUWiDKeGA9Ap
         KTNsoR9rgLi08emhQmMp0SftGNXdlYKNClFn4oz+7GS3H2rSqqU8Hl8NtGkVYPrW+Khk
         7HaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=14W+djSqO65qb2yocjNhULHQsGvtouE0aLUsedYOqh0=;
        b=Ly5ye7TV8m1ub/kOmTDgNr6RScSfBzSpVcwCuRFsGVxFHCd8M/P/eaL5kAITsWy7Kq
         u5mFEZ2nmSaVSV53u5bY+Y+nhyOqPDNWi/k1M37DnJi+1WJ/NPy0mpG+j1fbWh10dmNP
         Bjr25yQm1sef4xuMKZCXtjv9aLyo39nNHhW6rL+unewOqnGPxufO/N45+RT6LRyQb26r
         Is1xmjB7sv7FupoxvWTW0UqzCeJNZDAb0hXuzI7z1RosJArdednCNUJapjU9KxEIRURi
         U9DBmK1gN+BrEh87f6vKCDkijOrtUp/+VsGHtNRjom3QnsVuyMVi/n4+kRnHLaHb1V8X
         a5SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cqHVg8BL;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=14W+djSqO65qb2yocjNhULHQsGvtouE0aLUsedYOqh0=;
        b=P5AzVg6AIdzsb3F21fpBItkj5InapCQb8++GcZT1aUyMRy7Uw7Nh+scdKzPrpwdcL6
         wiv1CkmUq2AUaUk+sOpLQgPqh6Uk55OmUs7RL2lG2iht/e7IWIT/IBXkcw2BkxapBN0x
         Pv7m3EljO8sc1mxHtSht+XEhuRqXwqAQpNORyBgTVR3EZCMtz7rZICAAjEPAu3gfkWc6
         wTN56VLscuv1NlyTucFvlHPw9KpsaNziNvxrzk8wISCPqFxv4LjHLEmOhdjPrw2Pghbf
         PzpI3NuSmj5xQM+znh/OZTjeBnJ7tgE3e2h/vdbSNMAh7K3YDS6ozllOU+TOE3T//IjC
         kZPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=14W+djSqO65qb2yocjNhULHQsGvtouE0aLUsedYOqh0=;
        b=Pu/BImsUctFCdr8Vav4dgRTQegMmlMO0A7sTW/TbTwlEtEJPIV0vmy7nKKAMaYKCvw
         sWkfTwNV8Yw/HWI5/oWe+yUSHWMhMyGahVvpuqkm8fR62NdtEoGNcWrg25M1bNOjKMuN
         645rPjcKj+HZO6Q/mbtEF2xrKKpxwO8ML2HaBdOLjoILc80B50NYY9vxboHdCp9OYcUm
         vMxrHNoqcZC/2cCQWVkdZCTINhA3KzE0/OfGjL5QEhdE6fbMBZ4qJgxUhxvBttqliHpp
         vkyPGH/pn7m3JE0ykHejqFzQcO4su+qT/p9X+zujn/S0+rgxsZiWalhoE6fvSwicM+/8
         TT5A==
X-Gm-Message-State: AOAM531XSv0yxQWx8/teD5iqPIBY87acaV3mcXD+ojqjCsQ5f6xc8yJU
	muQh++hG4503MDqg1WpGxPg=
X-Google-Smtp-Source: ABdhPJy+s5bCZd8RDQDi4NGFWxP9z0FQDYzviM09NIGtssAErppOM0xBsouXSmDuwAcJsHyahw2VJw==
X-Received: by 2002:a17:906:87cd:b0:6ff:6a:f38 with SMTP id zb13-20020a17090687cd00b006ff006a0f38mr5320342ejb.511.1653420946410;
        Tue, 24 May 2022 12:35:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:4d8:b0:6fe:cede:95d7 with SMTP id
 vz24-20020a17090704d800b006fecede95d7ls4458324ejb.4.gmail; Tue, 24 May 2022
 12:35:45 -0700 (PDT)
X-Received: by 2002:a17:907:3e9d:b0:6fe:e980:d3de with SMTP id hs29-20020a1709073e9d00b006fee980d3demr10139488ejc.586.1653420945114;
        Tue, 24 May 2022 12:35:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653420945; cv=none;
        d=google.com; s=arc-20160816;
        b=JOiTdnHrPI6sJ2W/JWQJvLmctXQnyryce3OBmpczCMfQ53STmoFFa54IYq8M5jxmo7
         TTs/gnYfAe9ZCJMD9dMD+/zI+OElvYPXZY6BzOdGZ/VDDNnioNNUY0wVC05X3PKs7/VL
         50VfZYX8Qriekf0X5yyB6Vms0VwMWyWysw4Y00BqODd5dfXlwiISHTuCTg4eWZKQwPxs
         K51Lboe0rLxh+D0o+GxVwhPcaB7gEJKH5KkjUumqPQ2mQjma7KiywTPQQQgl72EesBW3
         45yFRijv4ZiFWp+DAcxGc6pBpPppYivQEh6wKKOuV+HiI3uixqRxiQqY0UxDJ/Ggqkpv
         fjbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DKr04/qhAYfOWpJdZJZ4WTvOPBDiDY9sF4C4nLhfMw4=;
        b=lrX3gGgoJQmFb+ONqDKlyl5pyDf2fr6B49mWgokRmz3bop4VMBQdeR9e5Tln28JCYL
         akEyMFSFZWUyG547eCpzqaYOcvNwN6Ax2YvEEzrT/cUdcsC0Ep141TTyw+SKFtlm4QHt
         hLGtKr7AlNe3IaudzR04fnhUaT4Ty/IKrVTXb2fUSEEtN0n2QyMw7b8w2lQvbhtW9hfK
         LNc8IOmZQ2WTd4D2Rzm6e99G1ZiE2tke6pX2ncuM2JdE0FPmJhj7tKRELKrVH8eD8jFK
         7oNbo7UnEd/bbsrkZJrzU/5Vjvw3BIZITjL/TQyDrX3yiLl//ABWmfqsLGbzdXetU6nl
         HE0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=cqHVg8BL;
       spf=pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id z6-20020a509e06000000b00425adbac75dsi698993ede.2.2022.05.24.12.35.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 May 2022 12:35:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id m32-20020a05600c3b2000b0039756bb41f2so2017532wms.3
        for <kasan-dev@googlegroups.com>; Tue, 24 May 2022 12:35:45 -0700 (PDT)
X-Received: by 2002:a05:600c:48aa:b0:397:55ba:adb3 with SMTP id
 j42-20020a05600c48aa00b0039755baadb3mr5023648wmp.73.1653420944632; Tue, 24
 May 2022 12:35:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
 <CAKFsvULGSQRx3hL8HgbYbEt_8GOorZj96CoMVhx6sw=xWEwSwA@mail.gmail.com>
 <1fb57ec2a830deba664379f3e0f480e08e6dec2f.camel@sipsolutions.net> <20220524103423.GA13239@axis.com>
In-Reply-To: <20220524103423.GA13239@axis.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 May 2022 12:35:33 -0700
Message-ID: <CABVgOSnTX_e+tzR6c3KnGhDidVtEoUdtt_CJ62g2+MQDMp657g@mail.gmail.com>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
To: Vincent Whitchurch <vincent.whitchurch@axis.com>
Cc: Johannes Berg <johannes@sipsolutions.net>, Patricia Alfonso <trishalfonso@google.com>, 
	Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, 
	Anton Ivanov <anton.ivanov@cambridgegreys.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	linux-um <linux-um@lists.infradead.org>, Daniel Axtens <dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=cqHVg8BL;       spf=pass
 (google.com: domain of davidgow@google.com designates 2a00:1450:4864:20::330
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

+dja in case he has any KASAN_VMALLOC thoughts.

On Tue, May 24, 2022 at 3:34 AM Vincent Whitchurch
<vincent.whitchurch@axis.com> wrote:
>
> On Wed, Mar 11, 2020 at 11:44:37PM +0100, Johannes Berg wrote:
> > On Wed, 2020-03-11 at 15:32 -0700, Patricia Alfonso wrote:
> > > I'll need some time to investigate these all myself. Having just
> > > gotten my first module to run about an hour ago, any more information
> > > about how you got these errors would be helpful so I can try to
> > > reproduce them on my own.
> >
> > See the other emails, I was basically just loading random modules. In my
> > case cfg80211, mac80211, mac80211-hwsim - those are definitely available
> > without any (virtio) hardware requirements, so you could use them.
> >
> > Note that doing a bunch of vmalloc would likely result in similar
> > issues, since the module and vmalloc space is the same on UML.
>
> Old thread, but I had a look at this the other day and I think I got it
> working.  Since the entire shadow area is mapped at init, we don't need
> to do any mappings later.

Wow -- thanks for looking at this again. It's been on my to-do list
for quite a while, too. I'd somewhat resigned myself to having to
re-implement the shadow memory stuff on top of page allocation
functions, so I'm particularly thrilled to see this working without
needing to do that.

>
> It works both with and without KASAN_VMALLOC.  KASAN_STACK works too
> after I disabled sanitization of the stacktrace code.  All kasan kunit
> tests pass and the test_kasan.ko module works too.

I've got this running myself, and can confirm the kasan tests work
under kunit_tool in most cases, though there are a couple of failures
when built with clang/llvm:
[11:56:30] # kasan_global_oob_right: EXPECTATION FAILED at lib/test_kasan.c:732
[11:56:30] KASAN failure expected in "*(volatile char *)p", but none occurred
[11:56:30] not ok 32 - kasan_global_oob_right
[11:56:30] [FAILED] kasan_global_oob_right
[11:56:30] # kasan_global_oob_left: EXPECTATION FAILED at lib/test_kasan.c:746
[11:56:30] KASAN failure expected in "*(volatile char *)p", but none occurred
[11:56:30] not ok 33 - kasan_global_oob_left
[11:56:30] [FAILED] kasan_global_oob_left

The global_oob_left test doesn't work on gcc either (but fails on all
architectures, so is disabled), but kasan_global_oob_right should work
in theory.

>
> Delta patch against Patricia's is below.  The CONFIG_UML checks need to
> be replaced with something more appropriate (new config? __weak
> functions?) and the free functions should probably be hooked up to
> madvise(MADV_DONTNEED) so we discard unused pages in the shadow mapping.

I'd probably go with a new config here, rather than using __weak
functions. Either have a "shadow already allocated" config like the
CONFIG_KASAN_NO_SHADOW_ALLOC Johannes suggests, or something like
CONFIG_KASAN_HAS_ARCH_SHADOW_ALLOC, and call into an
architecture-specific "shadow allocator", which would just do the
__memset(). The latter would make adding the madvise(MADV_DONTNEED)
easier, I think, though it's more work in general. Ultimately a
question for the KASAN folks, though.

> Note that there's a KASAN stack-out-of-bounds splat on startup when just
> booting UML.  That looks like a real (17-year-old) bug, I've posted a
> fix for that:
>
>  https://lore.kernel.org/lkml/20220523140403.2361040-1-vincent.whitchurch@axis.com/
>

Wow, that's a good catch. And also explains a bit why I was so
confused trying to understand that code when we were originally
looking at this.

> 8<-----------
> diff --git a/arch/um/Kconfig b/arch/um/Kconfig
> index a1bd8c07ce14..5f3a4d25d57e 100644
> --- a/arch/um/Kconfig
> +++ b/arch/um/Kconfig
> @@ -12,6 +12,7 @@ config UML
>         select ARCH_NO_PREEMPT
>         select HAVE_ARCH_AUDITSYSCALL
>         select HAVE_ARCH_KASAN if X86_64
> +       select HAVE_ARCH_KASAN_VMALLOC if HAVE_ARCH_KASAN
>         select HAVE_ARCH_SECCOMP_FILTER
>         select HAVE_ASM_MODVERSIONS
>         select HAVE_UID16
> @@ -223,7 +224,7 @@ config UML_TIME_TRAVEL_SUPPORT
>  config KASAN_SHADOW_OFFSET
>         hex
>         depends on KASAN
> -       default 0x7fff8000
> +       default 0x100000000000
>         help
>           This is the offset at which the ~2.25TB of shadow memory is
>           mapped and used by KASAN for memory debugging. This can be any
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
> diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
> index 7c3196c297f7..a32cfce53efb 100644
> --- a/arch/um/kernel/mem.c
> +++ b/arch/um/kernel/mem.c
> @@ -33,7 +33,7 @@ void kasan_init(void)
>  }
>
>  static void (*kasan_init_ptr)(void)
> -__section(.kasan_init) __used
> +__section(".kasan_init") __used
>  = kasan_init;
>  #endif
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 1113cf5fea25..1f3e620188a2 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -152,7 +152,7 @@ config KASAN_STACK
>         bool "Enable stack instrumentation (unsafe)" if CC_IS_CLANG && !COMPILE_TEST
>         depends on KASAN_GENERIC || KASAN_SW_TAGS
>         depends on !ARCH_DISABLE_KASAN_INLINE
> -       default y if CC_IS_GCC && !UML
> +       default y if CC_IS_GCC
>         help
>           The LLVM stack address sanitizer has a know problem that
>           causes excessive stack usage in a lot of functions, see
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
> +               return 0;
> +       }
> +
> +       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>         shadow_end = ALIGN(shadow_end, PAGE_SIZE);

Is there a particular reason we're not doing the rounding under UML,
particularly since I think it's happening anyway in
kasan_release_vmalloc() below. (I get that it's not really necessary,
but is there an actual bug you've noticed with it?)

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

In any case, this looks pretty great to me. I still definitely want to
play with it a bit more, particularly with various module loads -- and
it'd be great to track down why those global_oob tests are failing --
but I'm definitely hopeful that we can finish this off and get it
upstream.

It's probably worth sending a new rebased/combined patch out which has
your fixes and applies more cleanly on recent kernels. (I've got a
working tree here, so I can do that if you'd prefer.)

Cheers,
-- David

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSnTX_e%2BtzR6c3KnGhDidVtEoUdtt_CJ62g2%2BMQDMp657g%40mail.gmail.com.
