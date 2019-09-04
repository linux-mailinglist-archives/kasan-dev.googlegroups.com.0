Return-Path: <kasan-dev+bncBAABBXOAXTVQKGQEKTC2OLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 532C0A78B8
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Sep 2019 04:24:31 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id h5sf12195631pgq.23
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2019 19:24:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567563870; cv=pass;
        d=google.com; s=arc-20160816;
        b=wk3xzDWTKL83Lq4gt1EL1MewOk1TYWXAuTbU3V3rx8CGvcqRuEZJJ1PphWNT8ZfbdH
         KfyedRb31fHnxAXnerinXkwpviN0ZGdnnc384BAjQhT7SoSWbBLIr3eHT6JZl32YoGbt
         KDKZOMcAVCHudhsM/rAVrMN4IUoD6LjNDu9oCFD+01LF4AucJEK+S2iTiYmZJnJoVpZp
         kpdUCTrjnN/G2V8RNxZ+VK9tWBCP+CMFHtBp1Vvu8MUZspp5iIVxCtpm3T+84tew2uIN
         0cE7iHyU+9Dv3cR80UADksCop6xnKSJi1Ak7pCsZemhJOOdXCb2y4+Y3erNFcEjXand0
         loyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=oMoIoFsPbwv9Rd0fjD0/3TRaSSp7gxmFiiOZVvqPCO4=;
        b=cUuYibeq6ZWXt/XNQLnduaBs1GOqUTiI1bgT35pA/PlFi0iQ/S+C7e/uEf9e5kBG2h
         lmaykGAxOr2BaW/jRTOnd0iQwzEo/VmxdUx7qdqUzgCF05cM2nh7X8yE6Xo160/eNVGG
         kh0eyfrCHH3D9PJ6DSxEQ30m1Bt9IsDEiW2wbA7Os/U8o1I9k8q85+fVZs/xGMlZ6wcj
         otn1vObPYAzdGZ3he0b+1ug4B8VeGgK7MuZef7TANQFDZZQHTYvip0WeDxWJSRH2xH8H
         SIoNQniCz+Bobqj0tgFattNRacJopT5BzxeW4RiZTZpgDGoiOUebERcdsA2H3s3ThFhb
         +cvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oMoIoFsPbwv9Rd0fjD0/3TRaSSp7gxmFiiOZVvqPCO4=;
        b=UfWplBBYyloxgKaudl28iyg5XYesck+vctIFL2PFwt1wK7vaGJ0c665Ftt7AVWE86S
         mwmNjB9yjyeX9rQG+zoaF6U95kvQPWu2BqfxRb1jWZID7ez1ih86FztwaiJnuNsHPfY2
         Y27DqFlwAbpsGJIBdWguqhkPZ5J1xdLSrhF/HTdnhkgXnu/Am4Ke275YWb690KgDZW6y
         gcES7Hik60tHNhjc+xiCNdHdnnAUZitotdMAwYRxpHdJuqWx7TED45zqO9FtITshgzkf
         ztgusXleTlrLiiMPMaMGvwW2VxlSOr3vj5wZkuDAK9rJ7hSTCT2T1t8gw4vh5WZX52Wr
         pQWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oMoIoFsPbwv9Rd0fjD0/3TRaSSp7gxmFiiOZVvqPCO4=;
        b=Z4HtO/1PrnxCNBJvxJDRgdG9b+BWxoQtVMEFJbx6ODe2xRZzBP30KOuBfoPPwaEGeu
         7xIj/h2CVR+kdMlyi8NY3+nMYhCYPwxIs56/y8fO4yTQxpMi91+jlR+Oeyn7cmfAzs47
         GhHPk4fVCm3SqNWr4LIIWljQFY+501zqqaRGg7ZNmCo1HyIUZ9TIhKLyTdaDIu2spdjE
         kQr3BW5ZMhHu9WxZbYNy/7O7ZOes8gC/0W1S4+edhMhio1N7OcjIm7k6kdbZTxY+JgNG
         606Qc+afKhYMwMKbbPAugXOLydkaPu7zGkpAMCLK8+WWtzc60vjTWbqIMwZ8XGvMJP7M
         bCPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX0sjX8hanevYPKLX/rNrbKTHaIFm9+NS26hHdTWx2TJ7HJfGMB
	iJioT7N/R8ceZZ7vGqkpvNE=
X-Google-Smtp-Source: APXvYqxdr9s1FvqkKImhcZukIKfTxljXofvNdO4iiPfv5WE/+ulLapDJ+K0hHswz5+IOJS9DWz7LEg==
X-Received: by 2002:a65:690e:: with SMTP id s14mr33562942pgq.47.1567563869852;
        Tue, 03 Sep 2019 19:24:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac01:: with SMTP id o1ls210282pjq.5.gmail; Tue, 03
 Sep 2019 19:24:29 -0700 (PDT)
X-Received: by 2002:a17:902:fe0f:: with SMTP id g15mr15782844plj.2.1567563869496;
        Tue, 03 Sep 2019 19:24:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567563869; cv=none;
        d=google.com; s=arc-20160816;
        b=T8TEiHTPcKqrcTrQp4qm7yVvBi2y6F+vMqJ3SwJNKKXMCzEotCh9wGA2+nMy2gucZy
         lOBtC5FsWzDWD/a8I3PL8sKMFQzGMKEU88xpK9ywj/TDajki0QTZm7OZRZlfVXmnkMQ+
         wq62nduADVhZCRkWtbeF2EJOoiKsiYhMZzEI49w3kES0Itt+fVkjbylBdvOkYqIAeIU+
         sQbDwuhH3mfK5+3hHILAN7b5eN063gDJ64YWSuIOiHdpUDoHAsWf1WCiFZrbS7xAUv0e
         DjmVfLaa3w+oaqvN9Hs50Cfn+KVACVKGqFY0ENRB7PhGQNlTXI5WJ2sX8aSJZCM2xjLD
         dU4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=J6OW4u1AsiW5XdP1iqIuhiMI+v6LrvvBXrAQZUqj/0s=;
        b=vvJQgGAjST3IG/U2/6arQHnluBu0oD0qV9lmhcp7JR6qwgRV+vnAe/FCRv7sP45BA2
         lfxi+2bQOcDG74rwWeGD0XZhPSq/e71dramjmJLPANEmDzOU+JibNEOJdLpBVz9qtUi4
         lzE46FXGH45jEM7upaNW/TJaXctrEwuB2Vin/0E5kCHTiVhwEPC3qkU6p1DKXq37daYB
         1+XX89xD+kW2HdWbmXbYsALzd/9xYb+yIIBhFooU2bnN232EITZVw124xLH4BTfepLkm
         b/BWR404CqkPnxm9QrT+654Lany/p45oVMfnoB8abvh0ghlvHeye8GObcwyey5BKt6x3
         gCVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id q2si980720pgq.3.2019.09.03.19.24.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 03 Sep 2019 19:24:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x842ArUi069839;
	Wed, 4 Sep 2019 10:10:53 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 4 Sep 2019
 10:24:06 +0800
Date: Wed, 4 Sep 2019 10:24:07 +0800
From: Nick Hu <nickhu@andestech.com>
To: Daniel Axtens <dja@axtens.net>
CC: Christoph Hellwig <hch@infradead.org>,
        Alan Quey-Liang
 =?utf-8?B?S2FvKOmrmOmtgeiJryk=?= <alankao@andestech.com>,
        "paul.walmsley@sifive.com" <paul.walmsley@sifive.com>,
        "palmer@sifive.com"
	<palmer@sifive.com>,
        "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "green.hu@gmail.com" <green.hu@gmail.com>,
        "deanbo422@gmail.com"
	<deanbo422@gmail.com>,
        "tglx@linutronix.de" <tglx@linutronix.de>,
        "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
        "aryabinin@virtuozzo.com" <aryabinin@virtuozzo.com>,
        "glider@google.com"
	<glider@google.com>,
        "dvyukov@google.com" <dvyukov@google.com>,
        "Anup.Patel@wdc.com" <Anup.Patel@wdc.com>,
        "gregkh@linuxfoundation.org"
	<gregkh@linuxfoundation.org>,
        "alexios.zavras@intel.com"
	<alexios.zavras@intel.com>,
        "atish.patra@wdc.com" <atish.patra@wdc.com>,
        =?utf-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
	<zong@andestech.com>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH 2/2] riscv: Add KASAN support
Message-ID: <20190904022407.GA14994@andestech.com>
References: <cover.1565161957.git.nickhu@andestech.com>
 <88358ef8f7cfcb7fd01b6b989eccaddbe00a1e57.1565161957.git.nickhu@andestech.com>
 <20190812151050.GJ26897@infradead.org>
 <20190814074417.GA21929@andestech.com>
 <87k1apto1o.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87k1apto1o.fsf@dja-thinkpad.axtens.net>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x842ArUi069839
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Hi Daniel,

On Wed, Sep 04, 2019 at 01:08:51AM +1000, Daniel Axtens wrote:
> Nick Hu <nickhu@andestech.com> writes:
> 
> > Hi Christoph,
> >
> > Thanks for your reply. I will answer one by one.
> >
> > Hi Alexander,
> >
> > Would you help me for the question about SOFTIRQENTRY_TEXT?
> >
> > On Mon, Aug 12, 2019 at 11:10:50PM +0800, Christoph Hellwig wrote:
> >> > 2. KASAN can't debug the modules since the modules are allocated in VMALLOC
> >> > area. We mapped the shadow memory, which corresponding to VMALLOC area,
> >> > to the kasan_early_shadow_page because we don't have enough physical space
> >> > for all the shadow memory corresponding to VMALLOC area.
> >> 
> >> How do other architectures solve this problem?
> >> 
> > Other archs like arm64 and x86 allocate modules in their module region.
> 
> I've run in to a similar difficulty in ppc64. My approach has been to
> add a generic feature to allow kasan to handle vmalloc areas:
> 
> https://lore.kernel.org/linux-mm/20190903145536.3390-1-dja@axtens.net/
> 
> I link this with ppc64 in this series:
> 
> https://lore.kernel.org/linuxppc-dev/20190806233827.16454-1-dja@axtens.net/
> 
> However, see Christophe Leroy's comments: he thinks I should take a
> different approach in a number of places, including just adding a
> separate module area. I haven't had time to think through all of his
> proposals yet; in particular I'd want to think through what the
> implication of a separate module area is for KASLR.
> 
> Regards,
> Daniel
>
 
Thanks for the advice! I would study on it.

Regards,
Nick

> >
> >> > @@ -54,6 +54,8 @@ config RISCV
> >> >  	select EDAC_SUPPORT
> >> >  	select ARCH_HAS_GIGANTIC_PAGE
> >> >  	select ARCH_WANT_HUGE_PMD_SHARE if 64BIT
> >> > +	select GENERIC_STRNCPY_FROM_USER if KASAN
> >> 
> >> Is there any reason why we can't always enabled this?  Also just
> >> enabling the generic efficient strncpy_from_user should probably be
> >> a separate patch.
> >> 
> > You're right, always enable it would be better.
> >
> >> > +	select HAVE_ARCH_KASAN if MMU
> >> 
> >> Based on your cover letter this should be if MMU && 64BIT
> >> 
> >> >  #define __HAVE_ARCH_MEMCPY
> >> >  extern asmlinkage void *memcpy(void *, const void *, size_t);
> >> > +extern asmlinkage void *__memcpy(void *, const void *, size_t);
> >> >  
> >> >  #define __HAVE_ARCH_MEMMOVE
> >> >  extern asmlinkage void *memmove(void *, const void *, size_t);
> >> > +extern asmlinkage void *__memmove(void *, const void *, size_t);
> >> > +
> >> > +#define memcpy(dst, src, len) __memcpy(dst, src, len)
> >> > +#define memmove(dst, src, len) __memmove(dst, src, len)
> >> > +#define memset(s, c, n) __memset(s, c, n)
> >> 
> >> This looks weird and at least needs a very good comment.  Also
> >> with this we effectively don't need the non-prefixed prototypes
> >> anymore.  Also you probably want to split the renaming of the mem*
> >> routines into a separate patch with a proper changelog.
> >> 
> > I made some mistakes on this porting, this would be better:
> >
> > #define __HAVE_ARCH_MEMSET
> > extern asmlinkage void *memset(void *, int, size_t);
> > extern asmlinkage void *__memset(void *, int, size_t);
> >
> > #define __HAVE_ARCH_MEMCPY
> > extern asmlinkage void *memcpy(void *, const void *, size_t);
> > extern asmlinkage void *__memcpy(void *, const void *, size_t);
> >
> > #define __HAVE_ARCH_MEMMOVE
> > extern asmlinkage void *memmove(void *, const void *, size_t);
> > extern asmlinkage void *__memmove(void *, const void *, size_t);
> >
> > #if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)
> >
> > #define memcpy(dst, src, len) __memcpy(dst, src, len)
> > #define memmove(dst, src, len) __memmove(dst, src, len)
> > #define memset(s, c, n) __memset(s, c, n)
> >
> > #endif
> >
> >> >  #include <asm/tlbflush.h>
> >> >  #include <asm/thread_info.h>
> >> >  
> >> > +#ifdef CONFIG_KASAN
> >> > +#include <asm/kasan.h>
> >> > +#endif
> >> 
> >> Any good reason to not just always include the header?
> >>
> > Nope, I would remove the '#ifdef CONFIG_KASAN', and do the logic in the header
> > instead.
> >
> >> > +
> >> >  #ifdef CONFIG_DUMMY_CONSOLE
> >> >  struct screen_info screen_info = {
> >> >  	.orig_video_lines	= 30,
> >> > @@ -64,12 +68,17 @@ void __init setup_arch(char **cmdline_p)
> >> >  
> >> >  	setup_bootmem();
> >> >  	paging_init();
> >> > +
> >> >  	unflatten_device_tree();
> >> 
> >> spurious whitespace change.
> >> 
> >> > diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.lds.S
> >> > index 23cd1a9..9700980 100644
> >> > --- a/arch/riscv/kernel/vmlinux.lds.S
> >> > +++ b/arch/riscv/kernel/vmlinux.lds.S
> >> > @@ -46,6 +46,7 @@ SECTIONS
> >> >  		KPROBES_TEXT
> >> >  		ENTRY_TEXT
> >> >  		IRQENTRY_TEXT
> >> > +		SOFTIRQENTRY_TEXT
> >> 
> >> Hmm.  What is the relation to kasan here?  Maybe we should add this
> >> separately with a good changelog?
> >> 
> > There is a commit for it:
> >
> > Author: Alexander Potapenko <glider@google.com>
> > Date:   Fri Mar 25 14:22:05 2016 -0700
> >
> >     arch, ftrace: for KASAN put hard/soft IRQ entries into separate sections
> >
> >     KASAN needs to know whether the allocation happens in an IRQ handler.
> >     This lets us strip everything below the IRQ entry point to reduce the
> >     number of unique stack traces needed to be stored.
> >
> >     Move the definition of __irq_entry to <linux/interrupt.h> so that the
> >     users don't need to pull in <linux/ftrace.h>.  Also introduce the
> >     __softirq_entry macro which is similar to __irq_entry, but puts the
> >     corresponding functions to the .softirqentry.text section.
> >
> > After reading the patch I understand that soft/hard IRQ entries should be
> > separated for KASAN to work, but why?
> >
> > Alexender, do you have any comments on this?
> >
> >> > +++ b/arch/riscv/mm/kasan_init.c
> >> > @@ -0,0 +1,102 @@
> >> > +// SPDX-License-Identifier: GPL-2.0
> >> 
> >> This probably also wants a copyright statement.
> >> 
> >> > +	// init for swapper_pg_dir
> >> 
> >> Please use /* */ style comments.
> >
> > -- 
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190814074417.GA21929%40andestech.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190904022407.GA14994%40andestech.com.
