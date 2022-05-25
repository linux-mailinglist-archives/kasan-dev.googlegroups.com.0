Return-Path: <kasan-dev+bncBD653A6W2MGBBZNAXCKAMGQEUARN5VI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id ED4C2533B96
	for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 13:17:58 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id m11-20020a2ea88b000000b0024db6246908sf4407023ljq.22
        for <lists+kasan-dev@lfdr.de>; Wed, 25 May 2022 04:17:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653477478; cv=pass;
        d=google.com; s=arc-20160816;
        b=SbPKfIC/MgdWtkzz4OlyQbg4pYKgD875/3WmtXDwYoCUDmsr+6jzJ4FOeMDMBumdDv
         b1hI+tZkPQe/hbVdIIVxf2R+b4LWfqgAxUKX9mgdLow6RXPfWThMPskth+YkTt4yDHd/
         raxc/FbuEmGcpAbB9PRJ5PTp0LU/QOgrOew5/m+myyr0CKzqFgkJmV3fT5B+k0XvtdBE
         u61Q//5DP6klKJ3BvdOYYsYd6ZWCDRMkfXV81HbcPBghwYKYLyf3Vtw+q7X8eSSmQgIi
         XxxZPghFNhcPTq1NyYML52k5YmHlrrdxlyM6H2Czfhf7oe4BoftUmGqGohRaiLCa9JBx
         jJNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=DbwApAF5F5Cby6RTI8AY5WIWqJjj+fe85m0bsMOu64A=;
        b=UMz1uWZWVLhxCJ4DKmp56hOUz+mZrg6fdc6UipB2041h/EvJzDnVT/ZyIQ34QGH2MH
         YSjuIwX8D2R5hHNNY2/dc9LK0FfXenkJhDLYPZdjdwngBWYHCSKV+xgMgQRJutYstfTW
         a927JPGrk1gbjVLPLKEWJ6DPcD3aiS1xUj04eabjCtm38EMbL22RyvCa/dKIGfTdjUmD
         Y3EzdgpgYOuc05fYfNTRwwmIw0g9Y1Enlm+40JMw0l4e4kWBvc2SlC7kXzAx4PmJs07i
         R12ig5SrfDhhwShlx5al96ReJWUtK2kWzbM7xUauSGwn8OXnzJZOOPNfkWYUa6GMKsQI
         2kYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=euQg8vly;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DbwApAF5F5Cby6RTI8AY5WIWqJjj+fe85m0bsMOu64A=;
        b=HLErRLuerchpxKtLPFw2frVrf436cWW+ERvjB5HMYHh+9OC2GSbvXDyPjd2MnnrBbx
         rKe3PKqrfzAvsMYpKVVyFZzbrZnFChA0jnZOOPHun+SBCDXpioapCblu/gV4pCGKMFjq
         ye57w7++WyyU6fwS84woujONywP5e9q8QpoH04zMDQYUrNmA6kTifgg345G9zL5aOfmc
         3fTSqtRymnNpEktLwemFwCREYSmE2vT5t/5XI7In3RRJGDYSM9Vx/LKNb2eXvwhJOMaE
         Xqg6tYhC4QicK7ExUiDa0RmJ8JkeicMvxFIvv/osPb1d4OS7cad85y+wbvYYAtTxOf6D
         sDDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DbwApAF5F5Cby6RTI8AY5WIWqJjj+fe85m0bsMOu64A=;
        b=8MUYTcUafYuInjF8621mdsVBihcTCJO5Q3HIW2IjkqLQkXONQ+tIU/EJMXW6l8MAG8
         PNzOqMNe3+ZdSt1g2En2Og8+YihnB3PR0wtmRwIAURAVo7ok+GyRCVohpPK5bE4JWlas
         MkqLA2tRDl8Iilq5pL3r/RXSGDDFolMlqNmZatet55DUmiaHQBH43a4sjwq/J8bwmOjh
         UAs5n2K0GgoxU8m2TwBj1Zgc9Cf3KxToycnIYlJ1LFnoGjhuEzeeF4YmRsPEB6KjvQKF
         /pIHTHcCQRVQno4bEL26plF/pifMBHLYcg1KNascszF47NINYZGuwkEM137BuwTlf26g
         ElcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532eclS2BsdkSFc8Kv/irccigFtXbggWq7Kt7+lJdWzndsEqPSed
	AP7Mg/yApBoQYCyCOHQZChk=
X-Google-Smtp-Source: ABdhPJwFoglVj6HH1DgJ+bZUgQlHpg9QkyBckaxIEytG6bHnDGOQY/nhS15fJCyrzLbha1sT923Qjw==
X-Received: by 2002:ac2:5509:0:b0:477:b18a:b5b5 with SMTP id j9-20020ac25509000000b00477b18ab5b5mr22191215lfk.297.1653477478054;
        Wed, 25 May 2022 04:17:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bf11:0:b0:24a:fdc1:7af4 with SMTP id c17-20020a2ebf11000000b0024afdc17af4ls3569421ljr.1.gmail;
 Wed, 25 May 2022 04:17:56 -0700 (PDT)
X-Received: by 2002:a05:651c:a10:b0:253:f3e1:a847 with SMTP id k16-20020a05651c0a1000b00253f3e1a847mr5476883ljq.392.1653477476869;
        Wed, 25 May 2022 04:17:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653477476; cv=none;
        d=google.com; s=arc-20160816;
        b=gYfjEwR9VJZ8bk8cm19mW16Qvdr6rxfh4sxfI1yQ7nHMF/Fa3ONPprWw7H0lVqG/SJ
         r5iqdId51BeqH8rqslwBFgoZygnNqvY4UjhiSHpLNL2RMU/Cb2oAUMBPmWuNiTQII+Lq
         744XmZp2bYuPRqWJ/aF4qM321wOmC6m1tgyUnzc+bgxpQMDLgj838Y0i09f/2pZjRnuZ
         O5UY4a2W41ZMglg9ZIaNRrddGJodW+3nP/0otFGjOJrAi+U6ZLYTef5HUXLM4RBJbM5/
         8wa6fYWX+8AiB9rD7ZqQcITgn87h8nZWsnBRprxMp8Qyi+iekkAKasNhyTjeHpePs3FT
         TDdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/o4LP8ko0WJUyW9IItPnIXW6I9eQMh03kw30Jeb8Yro=;
        b=DDRDWKrs4p6uBuBE9JcbvNkyThli/fDN2MVVdf0u35ioJLfDMxo5TVCGS8+leP2ShV
         ti36q7LHoX2R4wukZtmSq/+gs4TVNlZKH4/WVIOOhPYeHPJNZJZ8OeQchjG3SwKUDPau
         mWNJPALJps51+I7qh+JqkTtA9QZT4eo8fNeK6y97tA8osanhNLpHgIz5fd4jStXrxyWD
         GCaYB4oYeyFAqQyqMDSAKMl+SWZs/vBUvreW777Aum7PnZ/uaAarIF8PCQTgEFaHFbiC
         65TUVhnRzE6hVXjAooSsUN+lHct7PcnIVL4oUOaHv1o6svVfk/ladQgyzcFfuwebQcs7
         zCMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@axis.com header.s=axis-central1 header.b=euQg8vly;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
Received: from smtp2.axis.com (smtp2.axis.com. [195.60.68.18])
        by gmr-mx.google.com with ESMTPS id cf28-20020a056512281c00b00478805f57b5si318350lfb.11.2022.05.25.04.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 25 May 2022 04:17:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincent.whitchurch@axis.com designates 195.60.68.18 as permitted sender) client-ip=195.60.68.18;
Date: Wed, 25 May 2022 13:17:56 +0200
From: Vincent Whitchurch <vincent.whitchurch@axis.com>
To: David Gow <davidgow@google.com>
CC: Johannes Berg <johannes@sipsolutions.net>, Patricia Alfonso
	<trishalfonso@google.com>, Jeff Dike <jdike@addtoit.com>, Richard Weinberger
	<richard@nod.at>, Anton Ivanov <anton.ivanov@cambridgegreys.com>, Andrey
 Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>,
	Brendan Higgins <brendanhiggins@google.com>, kasan-dev
	<kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, linux-um
	<linux-um@lists.infradead.org>, Daniel Axtens <dja@axtens.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
Message-ID: <20220525111756.GA15955@axis.com>
References: <20200226004608.8128-1-trishalfonso@google.com>
 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
 <CAKFsvULGSQRx3hL8HgbYbEt_8GOorZj96CoMVhx6sw=xWEwSwA@mail.gmail.com>
 <1fb57ec2a830deba664379f3e0f480e08e6dec2f.camel@sipsolutions.net>
 <20220524103423.GA13239@axis.com>
 <CABVgOSnTX_e+tzR6c3KnGhDidVtEoUdtt_CJ62g2+MQDMp657g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CABVgOSnTX_e+tzR6c3KnGhDidVtEoUdtt_CJ62g2+MQDMp657g@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: vincent.whitchurch@axis.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@axis.com header.s=axis-central1 header.b=euQg8vly;
       spf=pass (google.com: domain of vincent.whitchurch@axis.com designates
 195.60.68.18 as permitted sender) smtp.mailfrom=Vincent.Whitchurch@axis.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=axis.com
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

On Tue, May 24, 2022 at 09:35:33PM +0200, David Gow wrote:
> On Tue, May 24, 2022 at 3:34 AM Vincent Whitchurch
> <vincent.whitchurch@axis.com> wrote:
> > It works both with and without KASAN_VMALLOC.  KASAN_STACK works too
> > after I disabled sanitization of the stacktrace code.  All kasan kunit
> > tests pass and the test_kasan.ko module works too.
> 
> I've got this running myself, and can confirm the kasan tests work
> under kunit_tool in most cases, though there are a couple of failures
> when built with clang/llvm:
> [11:56:30] # kasan_global_oob_right: EXPECTATION FAILED at lib/test_kasan.c:732
> [11:56:30] KASAN failure expected in "*(volatile char *)p", but none occurred
> [11:56:30] not ok 32 - kasan_global_oob_right
> [11:56:30] [FAILED] kasan_global_oob_right
> [11:56:30] # kasan_global_oob_left: EXPECTATION FAILED at lib/test_kasan.c:746
> [11:56:30] KASAN failure expected in "*(volatile char *)p", but none occurred
> [11:56:30] not ok 33 - kasan_global_oob_left
> [11:56:30] [FAILED] kasan_global_oob_left
> 
> The global_oob_left test doesn't work on gcc either (but fails on all
> architectures, so is disabled), but kasan_global_oob_right should work
> in theory.

kasan_global_oob_right works for me with GCC, but it looks like
__asan_register_globals() never gets called when built with clang.  This
fixes it:

diff --git a/arch/um/include/asm/common.lds.S b/arch/um/include/asm/common.lds.S
index 731f8c8422a2..fd481ac371de 100644
--- a/arch/um/include/asm/common.lds.S
+++ b/arch/um/include/asm/common.lds.S
@@ -84,6 +84,7 @@
   .init_array : {
 	__init_array_start = .;
 	*(.kasan_init)
+	*(.init_array.*)
 	*(.init_array)
 	__init_array_end = .;
   }

With that:

[13:12:15] =================== kasan (55 subtests) ====================
[13:12:15] [PASSED] kmalloc_oob_right
[13:12:15] [PASSED] kmalloc_oob_left
[13:12:15] [PASSED] kmalloc_node_oob_right
[13:12:15] [PASSED] kmalloc_pagealloc_oob_right
[13:12:15] [PASSED] kmalloc_pagealloc_uaf
[13:12:15] [PASSED] kmalloc_pagealloc_invalid_free
[13:12:15] [SKIPPED] pagealloc_oob_right
[13:12:15] [PASSED] pagealloc_uaf
[13:12:15] [PASSED] kmalloc_large_oob_right
[13:12:15] [PASSED] krealloc_more_oob
[13:12:15] [PASSED] krealloc_less_oob
[13:12:15] [PASSED] krealloc_pagealloc_more_oob
[13:12:15] [PASSED] krealloc_pagealloc_less_oob
[13:12:15] [PASSED] krealloc_uaf
[13:12:15] [PASSED] kmalloc_oob_16
[13:12:15] [PASSED] kmalloc_uaf_16
[13:12:15] [PASSED] kmalloc_oob_in_memset
[13:12:15] [PASSED] kmalloc_oob_memset_2
[13:12:15] [PASSED] kmalloc_oob_memset_4
[13:12:15] [PASSED] kmalloc_oob_memset_8
[13:12:15] [PASSED] kmalloc_oob_memset_16
[13:12:15] [PASSED] kmalloc_memmove_negative_size
[13:12:15] [PASSED] kmalloc_memmove_invalid_size
[13:12:15] [PASSED] kmalloc_uaf
[13:12:15] [PASSED] kmalloc_uaf_memset
[13:12:15] [PASSED] kmalloc_uaf2
[13:12:15] [PASSED] kfree_via_page
[13:12:15] [PASSED] kfree_via_phys
[13:12:15] [PASSED] kmem_cache_oob
[13:12:15] [PASSED] kmem_cache_accounted
[13:12:15] [PASSED] kmem_cache_bulk
[13:12:15] [PASSED] kasan_global_oob_right
[13:12:15] [PASSED] kasan_global_oob_left
[13:12:15] [PASSED] kasan_stack_oob
[13:12:15] [PASSED] kasan_alloca_oob_left
[13:12:15] [PASSED] kasan_alloca_oob_right
[13:12:15] [PASSED] ksize_unpoisons_memory
[13:12:15] [PASSED] ksize_uaf
[13:12:15] [PASSED] kmem_cache_double_free
[13:12:15] [PASSED] kmem_cache_invalid_free
[13:12:15] [PASSED] kmem_cache_double_destroy
[13:12:15] [PASSED] kasan_memchr
[13:12:15] [PASSED] kasan_memcmp
[13:12:15] [PASSED] kasan_strings
[13:12:15] [PASSED] kasan_bitops_generic
[13:12:15] [SKIPPED] kasan_bitops_tags
[13:12:15] [PASSED] kmalloc_double_kzfree
[13:12:15] [SKIPPED] vmalloc_helpers_tags
[13:12:15] [PASSED] vmalloc_oob
[13:12:15] [SKIPPED] vmap_tags
[13:12:15] [SKIPPED] vm_map_ram_tags
[13:12:15] [SKIPPED] vmalloc_percpu
[13:12:15] [SKIPPED] match_all_not_assigned
[13:12:15] [SKIPPED] match_all_ptr_tag
[13:12:15] [SKIPPED] match_all_mem_tag
[13:12:15] ====================== [PASSED] kasan ======================
[13:12:15] ============================================================
[13:12:15] Testing complete. Passed: 46, Failed: 0, Crashed: 0, Skipped: 9, Errors: 0

> > diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> > index a4f07de21771..d8c518bd0e7d 100644
> > --- a/mm/kasan/shadow.c
> > +++ b/mm/kasan/shadow.c
> > @@ -295,8 +295,14 @@ int kasan_populate_vmalloc(unsigned long addr, unsigned long size)
> >                 return 0;
> >
> >         shadow_start = (unsigned long)kasan_mem_to_shadow((void *)addr);
> > -       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> >         shadow_end = (unsigned long)kasan_mem_to_shadow((void *)addr + size);
> > +
> > +       if (IS_ENABLED(CONFIG_UML)) {
> > +               __memset(kasan_mem_to_shadow((void *)addr), KASAN_VMALLOC_INVALID, shadow_end - shadow_start);
> > +               return 0;
> > +       }
> > +
> > +       shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
> >         shadow_end = ALIGN(shadow_end, PAGE_SIZE);
> 
> Is there a particular reason we're not doing the rounding under UML,
> particularly since I think it's happening anyway in
> kasan_release_vmalloc() below. (I get that it's not really necessary,
> but is there an actual bug you've noticed with it?)

No, I didn't notice any bug.

> >         ret = apply_to_page_range(&init_mm, shadow_start,
> > @@ -466,6 +472,10 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
> >
> >         if (shadow_end > shadow_start) {
> >                 size = shadow_end - shadow_start;
> > +               if (IS_ENABLED(CONFIG_UML)) {
> > +                       __memset(shadow_start, KASAN_SHADOW_INIT, shadow_end - shadow_start);
> > +                       return;
> > +               }
> >                 apply_to_existing_page_range(&init_mm,
> >                                              (unsigned long)shadow_start,
> >                                              size, kasan_depopulate_vmalloc_pte,
> > @@ -531,6 +541,11 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
> >         if (WARN_ON(!PAGE_ALIGNED(shadow_start)))
> >                 return -EINVAL;
> >
> > +       if (IS_ENABLED(CONFIG_UML)) {
> > +               __memset((void *)shadow_start, KASAN_SHADOW_INIT, shadow_size);
> > +               return 0;
> > +       }
> > +
> >         ret = __vmalloc_node_range(shadow_size, 1, shadow_start,
> >                         shadow_start + shadow_size,
> >                         GFP_KERNEL,
> > @@ -554,6 +569,9 @@ int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
> >
> >  void kasan_free_module_shadow(const struct vm_struct *vm)
> >  {
> > +       if (IS_ENABLED(CONFIG_UML))
> > +               return;
> > +
> >         if (vm->flags & VM_KASAN)
> >                 vfree(kasan_mem_to_shadow(vm->addr));
> >  }
> 
> In any case, this looks pretty great to me. I still definitely want to
> play with it a bit more, particularly with various module loads -- and
> it'd be great to track down why those global_oob tests are failing --
> but I'm definitely hopeful that we can finish this off and get it
> upstream.
> 
> It's probably worth sending a new rebased/combined patch out which has
> your fixes and applies more cleanly on recent kernels. (I've got a
> working tree here, so I can do that if you'd prefer.)

Please feel free to do so.  Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220525111756.GA15955%40axis.com.
