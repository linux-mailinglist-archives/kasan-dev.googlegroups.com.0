Return-Path: <kasan-dev+bncBDQ27FVWWUFRBCEEXLVQKGQECKUMPJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 139EDA6C6C
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2019 17:08:58 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id h11sf505261vsj.15
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 08:08:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567523337; cv=pass;
        d=google.com; s=arc-20160816;
        b=hQ5hnEkPsekNL+1QmrvuEUd9LZDh8lwWzuD3+bf1OF2HIb2DmvxX0NrhrTWHZ0Dzqe
         xTu3NTGwAzGPHyW+Kf85U6EJJo+QxxxjrkjIqDtftvbnLMUVXAjtEp3/AUGqTHcZUJxB
         tH/7k5+SbdW6vbVGKNHzxh1FT8KmA2PBMXVkCL7Gd7CF0KwljH7F7xRnULpgbyZDFyL7
         slPgpOZak0zQrlAMEvJ1Fb+tCPgt2RNVB8rBSQWPD7Xjqf1zSdFh/Pi3NlneiiGItN7y
         yZv791olurGqnLBbKbuzPihbk5HMxQ2DyOpvbGGpRXUJv/3TrzYVzRG9N9Dt/8S3e5ft
         eimQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=agZY7BIujXFpkzQP7lTA8vF/7RzujqZiJUJxg7uX12Y=;
        b=xBafEiAIAi8VDT4krMo7rDkbpqKfpjvI4RfwywZ5YLxcQsNc8O7kzKQJPafvosiaz7
         EWkxPOihN6P8yE0oTq1KRCJH2XnVWKz3bqPOrGzhS43j0ZVuCsYhvJcP5wXHnuxjncrX
         xAzkZl4BtEnYFwdKuc0VnklJpzaMxDvhtVmD07gfW9RnqFxjHhcn/jgXiu/RcNVnLius
         X8Y+LC2TRxBc4zS54zWgNa74z+2WmnVpQQmOyRyi7PvdsBiMA83HwcOt134n37o1F6yO
         ZMQNq/BOgAvtQ1uvJBbM+M1YWGJ1XQx4ZjrtNeGhvw4qfBLmbJS8wOT+gRBYqjAJzx5a
         tFeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=aWiI9WRg;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=agZY7BIujXFpkzQP7lTA8vF/7RzujqZiJUJxg7uX12Y=;
        b=IwZxY5cluJxr60GCeXuRUwo1LsM8jGbaVH+cBAgh1zqRauy3c6gj6uGp1Bo7nY0nJS
         HObTBoVggzUafqC6pDCIs77olFimt3lQ25FF0DRBUWrDMg72ymZrVxDprD1Tjik4ghH/
         1eLKyZCKsSwPkSoMmwuR4fMP1WnlewI1d/z2n20Vge6WUhO57jAb/J1l/vHAT0v6LV6l
         2KLNhxdcKYVGjaSFqaaJYFHiDrV4c+N+c0bv419e9nwYU3vK7/GyzyK6NHg2PUZMVE9z
         kF0PWn53nXOKfihKoUkn+mHarpEJEhpbtb85YG9ucSzXWZfLtEFhByQtQqjwv+o9G++t
         GgLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=agZY7BIujXFpkzQP7lTA8vF/7RzujqZiJUJxg7uX12Y=;
        b=bO/LZFX52RgAwYFPgDC9yoDEFawVA5DOVx3Q6W4dBhlKFUjr729QDcG4vwHSbeg5gT
         jpli+4N7ao631hz9DrxovBSXIw7T2vd2vIn3InXNdNSU9Iflt0p0fjiCzKw9Vf2UXw6H
         SX5559ET9cv4Bux18/8oXhjxSEsFo1VTpOtbUlD+PaKHVaQDyGL21gqss1FUD/WPDBya
         B4RmmvWY6lTyZs5g5PrQRiRX17eNIniFLw2OVhJHBpuAuP50WRsq75rHDBerYn4Vkj1I
         gxl1X6/lJwkd+d4btAQ2oQfqlpvm7d4vPLnDHqWIc/oK1KpURtcJe7Sweg2gktVGrNLC
         v8zw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXAT02nBVz0tOersTTJDetFFOkU4G/qjMTzPaYIdE4rgYdHjSzM
	Re6yFNPTOJ6J1XE2Mb8iNjI=
X-Google-Smtp-Source: APXvYqwfgelBP8psdhkx0I0Q2eJeBYui48KiJZFT0Tbo3oAgBj5/1++xBVmuarZgngOudN2W0tIK2Q==
X-Received: by 2002:ab0:620a:: with SMTP id m10mr139539uao.128.1567523337005;
        Tue, 03 Sep 2019 08:08:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:380b:: with SMTP id p11ls870954uad.0.gmail; Tue, 03 Sep
 2019 08:08:56 -0700 (PDT)
X-Received: by 2002:ab0:2ea8:: with SMTP id y8mr6353079uay.74.1567523336648;
        Tue, 03 Sep 2019 08:08:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567523336; cv=none;
        d=google.com; s=arc-20160816;
        b=n54scRppt+JfSL5C7J9smhKeq5B9u8I5TlYCYbLlyXNIkz+Tf99p3rDP40nqcuOv3N
         wROdkINuYc2TnqYiIq4QhsR1yFB4L1bF1gPIFmSm957qRds3tLKJJRDJdLgYXCxs05Qa
         kOf5MnOY+f2hCCQNhtNYxMWNfEKkK7j96UF+sJL8YTA4PRx0F9A0wAhdYINmgnygHt+c
         kakd04SMFu/xgIUdPnG69cEdsXdLom1iNBM5fXjHMxgsqXZ7z/k2RWbICsv+rL/yry6J
         v0RlmELlc0i9mVr2eKllu5xZ6s2/MMWG+gJBrJZZkNfnT8FdlKJ7P2cc1GfOJq88+BvF
         +zBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=iV/j2+7ceSELqxPlCshRDxNfNslsjKkYw2OY9C0rDVo=;
        b=g/vS6NUTy+IY94jx+JGe0IqyOt1F/bsEGfWr0Nfgw0cSLsxJfy5NV1y3QPiFy/GrNn
         smKazEIgBc6RF8r393jGd3+hd/jPSX2OzCh1+QwXBZwLuXr7YE1vB8qQV89RqFDuZt70
         u5OYxK4COupx5A6R+x1M9jUOQJm7aMuEk3pbvYtSecv/iK/nJotjLVfp//hOIRnLCeNa
         NpKUSvv6Ah1xeBNgEZWR3PmKckqO7sMK6R/7KpWGq4ARFwAhZpo9ZUDHlYv2iLHslG/K
         2DUOnJQ49GoOyXCFsEY7+UpNrVtDIZ9JAoLJzQHjsIQijlGs2DeqcKSJO5KfKjWQeVGF
         7WEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=aWiI9WRg;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id y12si575526vke.5.2019.09.03.08.08.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2019 08:08:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id b13so4328444pfo.8
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2019 08:08:56 -0700 (PDT)
X-Received: by 2002:a17:90a:9486:: with SMTP id s6mr585156pjo.0.1567523335724;
        Tue, 03 Sep 2019 08:08:55 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id m9sm26858738pgr.24.2019.09.03.08.08.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 03 Sep 2019 08:08:54 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Nick Hu <nickhu@andestech.com>, Christoph Hellwig <hch@infradead.org>
Cc: =?utf-8?Q?Alan_Quey-Liang_Kao=28=E9=AB=98=E9=AD=81=E8=89=AF=29?=
 <alankao@andestech.com>, "paul.walmsley\@sifive.com"
 <paul.walmsley@sifive.com>, "palmer\@sifive.com" <palmer@sifive.com>,
 "aou\@eecs.berkeley.edu" <aou@eecs.berkeley.edu>, "green.hu\@gmail.com"
 <green.hu@gmail.com>, "deanbo422\@gmail.com" <deanbo422@gmail.com>,
 "tglx\@linutronix.de" <tglx@linutronix.de>,
 "linux-riscv\@lists.infradead.org" <linux-riscv@lists.infradead.org>,
 "linux-kernel\@vger.kernel.org" <linux-kernel@vger.kernel.org>,
 "aryabinin\@virtuozzo.com" <aryabinin@virtuozzo.com>, "glider\@google.com"
 <glider@google.com>, "dvyukov\@google.com" <dvyukov@google.com>,
 "Anup.Patel\@wdc.com" <Anup.Patel@wdc.com>, "gregkh\@linuxfoundation.org"
 <gregkh@linuxfoundation.org>, "alexios.zavras\@intel.com"
 <alexios.zavras@intel.com>, "atish.patra\@wdc.com" <atish.patra@wdc.com>,
 =?utf-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
 <zong@andestech.com>, "kasan-dev\@googlegroups.com"
 <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 2/2] riscv: Add KASAN support
In-Reply-To: <20190814074417.GA21929@andestech.com>
References: <cover.1565161957.git.nickhu@andestech.com> <88358ef8f7cfcb7fd01b6b989eccaddbe00a1e57.1565161957.git.nickhu@andestech.com> <20190812151050.GJ26897@infradead.org> <20190814074417.GA21929@andestech.com>
Date: Wed, 04 Sep 2019 01:08:51 +1000
Message-ID: <87k1apto1o.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=aWiI9WRg;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Nick Hu <nickhu@andestech.com> writes:

> Hi Christoph,
>
> Thanks for your reply. I will answer one by one.
>
> Hi Alexander,
>
> Would you help me for the question about SOFTIRQENTRY_TEXT?
>
> On Mon, Aug 12, 2019 at 11:10:50PM +0800, Christoph Hellwig wrote:
>> > 2. KASAN can't debug the modules since the modules are allocated in VMALLOC
>> > area. We mapped the shadow memory, which corresponding to VMALLOC area,
>> > to the kasan_early_shadow_page because we don't have enough physical space
>> > for all the shadow memory corresponding to VMALLOC area.
>> 
>> How do other architectures solve this problem?
>> 
> Other archs like arm64 and x86 allocate modules in their module region.

I've run in to a similar difficulty in ppc64. My approach has been to
add a generic feature to allow kasan to handle vmalloc areas:

https://lore.kernel.org/linux-mm/20190903145536.3390-1-dja@axtens.net/

I link this with ppc64 in this series:

https://lore.kernel.org/linuxppc-dev/20190806233827.16454-1-dja@axtens.net/

However, see Christophe Leroy's comments: he thinks I should take a
different approach in a number of places, including just adding a
separate module area. I haven't had time to think through all of his
proposals yet; in particular I'd want to think through what the
implication of a separate module area is for KASLR.

Regards,
Daniel

>
>> > @@ -54,6 +54,8 @@ config RISCV
>> >  	select EDAC_SUPPORT
>> >  	select ARCH_HAS_GIGANTIC_PAGE
>> >  	select ARCH_WANT_HUGE_PMD_SHARE if 64BIT
>> > +	select GENERIC_STRNCPY_FROM_USER if KASAN
>> 
>> Is there any reason why we can't always enabled this?  Also just
>> enabling the generic efficient strncpy_from_user should probably be
>> a separate patch.
>> 
> You're right, always enable it would be better.
>
>> > +	select HAVE_ARCH_KASAN if MMU
>> 
>> Based on your cover letter this should be if MMU && 64BIT
>> 
>> >  #define __HAVE_ARCH_MEMCPY
>> >  extern asmlinkage void *memcpy(void *, const void *, size_t);
>> > +extern asmlinkage void *__memcpy(void *, const void *, size_t);
>> >  
>> >  #define __HAVE_ARCH_MEMMOVE
>> >  extern asmlinkage void *memmove(void *, const void *, size_t);
>> > +extern asmlinkage void *__memmove(void *, const void *, size_t);
>> > +
>> > +#define memcpy(dst, src, len) __memcpy(dst, src, len)
>> > +#define memmove(dst, src, len) __memmove(dst, src, len)
>> > +#define memset(s, c, n) __memset(s, c, n)
>> 
>> This looks weird and at least needs a very good comment.  Also
>> with this we effectively don't need the non-prefixed prototypes
>> anymore.  Also you probably want to split the renaming of the mem*
>> routines into a separate patch with a proper changelog.
>> 
> I made some mistakes on this porting, this would be better:
>
> #define __HAVE_ARCH_MEMSET
> extern asmlinkage void *memset(void *, int, size_t);
> extern asmlinkage void *__memset(void *, int, size_t);
>
> #define __HAVE_ARCH_MEMCPY
> extern asmlinkage void *memcpy(void *, const void *, size_t);
> extern asmlinkage void *__memcpy(void *, const void *, size_t);
>
> #define __HAVE_ARCH_MEMMOVE
> extern asmlinkage void *memmove(void *, const void *, size_t);
> extern asmlinkage void *__memmove(void *, const void *, size_t);
>
> #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
>
> #define memcpy(dst, src, len) __memcpy(dst, src, len)
> #define memmove(dst, src, len) __memmove(dst, src, len)
> #define memset(s, c, n) __memset(s, c, n)
>
> #endif
>
>> >  #include <asm/tlbflush.h>
>> >  #include <asm/thread_info.h>
>> >  
>> > +#ifdef CONFIG_KASAN
>> > +#include <asm/kasan.h>
>> > +#endif
>> 
>> Any good reason to not just always include the header?
>>
> Nope, I would remove the '#ifdef CONFIG_KASAN', and do the logic in the header
> instead.
>
>> > +
>> >  #ifdef CONFIG_DUMMY_CONSOLE
>> >  struct screen_info screen_info = {
>> >  	.orig_video_lines	= 30,
>> > @@ -64,12 +68,17 @@ void __init setup_arch(char **cmdline_p)
>> >  
>> >  	setup_bootmem();
>> >  	paging_init();
>> > +
>> >  	unflatten_device_tree();
>> 
>> spurious whitespace change.
>> 
>> > diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.lds.S
>> > index 23cd1a9..9700980 100644
>> > --- a/arch/riscv/kernel/vmlinux.lds.S
>> > +++ b/arch/riscv/kernel/vmlinux.lds.S
>> > @@ -46,6 +46,7 @@ SECTIONS
>> >  		KPROBES_TEXT
>> >  		ENTRY_TEXT
>> >  		IRQENTRY_TEXT
>> > +		SOFTIRQENTRY_TEXT
>> 
>> Hmm.  What is the relation to kasan here?  Maybe we should add this
>> separately with a good changelog?
>> 
> There is a commit for it:
>
> Author: Alexander Potapenko <glider@google.com>
> Date:   Fri Mar 25 14:22:05 2016 -0700
>
>     arch, ftrace: for KASAN put hard/soft IRQ entries into separate sections
>
>     KASAN needs to know whether the allocation happens in an IRQ handler.
>     This lets us strip everything below the IRQ entry point to reduce the
>     number of unique stack traces needed to be stored.
>
>     Move the definition of __irq_entry to <linux/interrupt.h> so that the
>     users don't need to pull in <linux/ftrace.h>.  Also introduce the
>     __softirq_entry macro which is similar to __irq_entry, but puts the
>     corresponding functions to the .softirqentry.text section.
>
> After reading the patch I understand that soft/hard IRQ entries should be
> separated for KASAN to work, but why?
>
> Alexender, do you have any comments on this?
>
>> > +++ b/arch/riscv/mm/kasan_init.c
>> > @@ -0,0 +1,102 @@
>> > +// SPDX-License-Identifier: GPL-2.0
>> 
>> This probably also wants a copyright statement.
>> 
>> > +	// init for swapper_pg_dir
>> 
>> Please use /* */ style comments.
>
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190814074417.GA21929%40andestech.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87k1apto1o.fsf%40dja-thinkpad.axtens.net.
