Return-Path: <kasan-dev+bncBAABB2PXZ3VAKGQEVL2LNMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 63BDB8CD1F
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 09:44:43 +0200 (CEST)
Received: by mail-vs1-xe3f.google.com with SMTP id k1sf29694973vsq.8
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 00:44:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565768682; cv=pass;
        d=google.com; s=arc-20160816;
        b=dY926DaJTe6i15c/iRU+8bEkTSZ9TYzuPKJqklFrsIZZCQOzh7CELe8AO5XWlGOhiv
         V7ojy/XWA2P/mR5CzaMFAn9VxXvEkvrJnQlfnDd8LISJBeC0bmNLwZo9c1nioOjTLQ45
         4Hf2pJfYfhhrJnHiJxlefv6vzD9stWOpYD8XFuaRdTylOlKFrM2WAGSRDMbzI0njN3Eu
         zLOC+osIsRGMBsG2ATwcuHsheTw9r7eJvYNgyD5UXHUyTtIZTXkuLA7i5dPjePKtgVpG
         tEfie5Lxgg+uvrOTODn8cyow9wgcAZatFPIPT7uYguB7MF3rR4kNFxmKiLM42xZqP6LO
         jOhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=otfPw6f5tS1DVfDEAKKCF8uJiG+JPi3Q9yyTPr0zpWk=;
        b=qtw3YzI8Pt6jRk6wauTJAfijJ5CATee5yzzXedRFbVAWnzEVAm59zNZvntOCZ6pNzG
         HdKov2wUEHbhM+HiU2HuYWzzM+Ef24J57OVBY6fQk9iWyCzPCtLZBN4C8SCbANUHfflA
         Utwc/elKeq0UthPQ5RGjNcTrpWPQ0xrMc4xqOcX7HEZWbQ8FR4iMd4+a65/da3PJMw4g
         8aJSprt3caQwkiXWq9iIOpHldIAKnhYV7CRHT+L0T1v69btBY3D5qrLPyARR8epXJSuJ
         glUj5ky8UlkweIYwfkeH6W6Y/aJjxzMhvqTmVWksVzo2UrPgpadULzo21S0dx00PxftV
         jSqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=otfPw6f5tS1DVfDEAKKCF8uJiG+JPi3Q9yyTPr0zpWk=;
        b=j7FcmLnK/vjG8xEviQ7015F662rMr/Dki6fTmjd27PAVAshhkWrYICpu6XezDLHC6C
         I9QtYa6i4UtBnLiYtRPajCu9dnjApO46WoV5bS2y4lLWPWegKLC+7XZXZFpmFI+xezKV
         bJkjT/jPUQ+dgEY3SrM8y/EaYWP+MSZJwaqAnN5QfXdg/le7CKXh5pwJWLv+I2AOzE8j
         pLdWQoxlf45VSAn27Y/anZ5zV/Yxx+ocmU06LBHeLukuL4sKc9/0h90XEGPm9rQw86Nj
         trkkqzmfOPRNTcglb5lK9/aaVB8C8LKq8Yto/bqbp/hhW3eEJESFoMtE4TOsuOiKo6+E
         W2gg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=otfPw6f5tS1DVfDEAKKCF8uJiG+JPi3Q9yyTPr0zpWk=;
        b=cKPpolcp9O7mYkix7KJEnl4p84jrEXtVPAjtsGD+jCznRSPRB2pi5zTbfVBug7zuv6
         6Z/hKttAvi/bFUWnpDDXTgbsQZO6ZlEyzHj2drOTgfsq/MWNgYeXqInDB+9wnZogEreS
         tUR4lzB7ovdy2I41VLElf5Mcf6NEOFIZPKnLLW+RfemPSsLZk9toaI+NY3v6hIw0r0oP
         q5gESmukQvpxKXYnLjx8F+JJimnaO3gXy7DqyC615sNd3DruM83JMY99Ztut+D4449dr
         FISU+cd7zftXDVUWINI9OqCDpMdGNNhYfr7PomZLODvFziCUHOplSl/o5aqJTbpqUsqo
         /kLg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUfbPMiXGPFp6L4lSJsc48GTdxEAMIRyompUBmEL/xDRSN2C9gz
	AOAy5XHfkOG21ZlzoTxfhpk=
X-Google-Smtp-Source: APXvYqygeUPC6j0rpfmVPcibu/A35spAFCFQ+4vz/bWFv0tROaS8fzwxh53Bs2dm/22jekRN/5U1fQ==
X-Received: by 2002:ac5:c935:: with SMTP id u21mr7651638vkl.81.1565768682171;
        Wed, 14 Aug 2019 00:44:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8e47:: with SMTP id q68ls183949vsd.10.gmail; Wed, 14 Aug
 2019 00:44:41 -0700 (PDT)
X-Received: by 2002:a67:d496:: with SMTP id g22mr18429191vsj.168.1565768681765;
        Wed, 14 Aug 2019 00:44:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565768681; cv=none;
        d=google.com; s=arc-20160816;
        b=BFL0ZUQ2guXw6RRGcTd9QZOHVebaz0XV4aH3XIIcZnbeE3nOzny01t87K1ntSoFCB8
         VbmreHGY18pvn8VrQV78IebbL4Eluz19eQy/EBsN0kSv0WNkK4nX3rQTMpvxepCiquKB
         IzZ/nVji0Rw1Xqeh7cABdw5s9OiQQMi+lVem+bjXayQM3GaZCxP30sUPQDMfrB3KBcaU
         Bb8xDixtdgoU91epMug/NEC5+7AGCkazD8THMhY4/0pdwe/PyfBZIBf3jobFoutuXrhi
         9QerTF+sKZ9xma9xPBFaCpWL0UPb6phcCPKpBhzPOtNryLS+0NuKzNL56wQb4mzoHwsY
         SNBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=D2decu3goWlUwZL60Uu5VhqNA6IzXQyAEvXbUcSVZqE=;
        b=gXmRFj7WsifqtBCRHUx7I8kxDQ7Msty8nra8+A5lbc+k7CjICm+Yr5g2Ew5CAHUpre
         r/ZNts3AFQvI9lBLUBqBm9At4ENAZ6X9IZUMzRwHE97L4xYACBjyR1jsmnu/AaYVQ7ot
         /q5knj21G9AyLWRpBDoKfb4q4zrMZYeFN+0N0Jg1iFlhVTQWTYDHuO+elPtk+fyaf1ej
         8inEM3+2lO/eCvZweL7OuZNFWO+qc79J063JKJbC3OOY7biiVEgpVNfL3kZQdq4/Qbza
         fmOYWAnMPZj0+AKRNcHX9Aftk/w+jGudzDBAZVj6wjXFmwGhYCwXueTyJkXrHu+pDMt7
         SHzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id k125si5806056vkh.4.2019.08.14.00.44.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Aug 2019 00:44:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x7E7WkLS078787;
	Wed, 14 Aug 2019 15:32:46 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Wed, 14 Aug 2019
 15:44:17 +0800
Date: Wed, 14 Aug 2019 15:44:18 +0800
From: Nick Hu <nickhu@andestech.com>
To: Christoph Hellwig <hch@infradead.org>
CC: Alan Quey-Liang =?utf-8?B?S2FvKOmrmOmtgeiJryk=?= <alankao@andestech.com>,
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
Message-ID: <20190814074417.GA21929@andestech.com>
References: <cover.1565161957.git.nickhu@andestech.com>
 <88358ef8f7cfcb7fd01b6b989eccaddbe00a1e57.1565161957.git.nickhu@andestech.com>
 <20190812151050.GJ26897@infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190812151050.GJ26897@infradead.org>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x7E7WkLS078787
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

Hi Christoph,

Thanks for your reply. I will answer one by one.

Hi Alexander,

Would you help me for the question about SOFTIRQENTRY_TEXT?

On Mon, Aug 12, 2019 at 11:10:50PM +0800, Christoph Hellwig wrote:
> > 2. KASAN can't debug the modules since the modules are allocated in VMALLOC
> > area. We mapped the shadow memory, which corresponding to VMALLOC area,
> > to the kasan_early_shadow_page because we don't have enough physical space
> > for all the shadow memory corresponding to VMALLOC area.
> 
> How do other architectures solve this problem?
> 
Other archs like arm64 and x86 allocate modules in their module region.

> > @@ -54,6 +54,8 @@ config RISCV
> >  	select EDAC_SUPPORT
> >  	select ARCH_HAS_GIGANTIC_PAGE
> >  	select ARCH_WANT_HUGE_PMD_SHARE if 64BIT
> > +	select GENERIC_STRNCPY_FROM_USER if KASAN
> 
> Is there any reason why we can't always enabled this?  Also just
> enabling the generic efficient strncpy_from_user should probably be
> a separate patch.
> 
You're right, always enable it would be better.

> > +	select HAVE_ARCH_KASAN if MMU
> 
> Based on your cover letter this should be if MMU && 64BIT
> 
> >  #define __HAVE_ARCH_MEMCPY
> >  extern asmlinkage void *memcpy(void *, const void *, size_t);
> > +extern asmlinkage void *__memcpy(void *, const void *, size_t);
> >  
> >  #define __HAVE_ARCH_MEMMOVE
> >  extern asmlinkage void *memmove(void *, const void *, size_t);
> > +extern asmlinkage void *__memmove(void *, const void *, size_t);
> > +
> > +#define memcpy(dst, src, len) __memcpy(dst, src, len)
> > +#define memmove(dst, src, len) __memmove(dst, src, len)
> > +#define memset(s, c, n) __memset(s, c, n)
> 
> This looks weird and at least needs a very good comment.  Also
> with this we effectively don't need the non-prefixed prototypes
> anymore.  Also you probably want to split the renaming of the mem*
> routines into a separate patch with a proper changelog.
> 
I made some mistakes on this porting, this would be better:

#define __HAVE_ARCH_MEMSET
extern asmlinkage void *memset(void *, int, size_t);
extern asmlinkage void *__memset(void *, int, size_t);

#define __HAVE_ARCH_MEMCPY
extern asmlinkage void *memcpy(void *, const void *, size_t);
extern asmlinkage void *__memcpy(void *, const void *, size_t);

#define __HAVE_ARCH_MEMMOVE
extern asmlinkage void *memmove(void *, const void *, size_t);
extern asmlinkage void *__memmove(void *, const void *, size_t);

#if defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__)

#define memcpy(dst, src, len) __memcpy(dst, src, len)
#define memmove(dst, src, len) __memmove(dst, src, len)
#define memset(s, c, n) __memset(s, c, n)

#endif

> >  #include <asm/tlbflush.h>
> >  #include <asm/thread_info.h>
> >  
> > +#ifdef CONFIG_KASAN
> > +#include <asm/kasan.h>
> > +#endif
> 
> Any good reason to not just always include the header?
>
Nope, I would remove the '#ifdef CONFIG_KASAN', and do the logic in the header
instead.

> > +
> >  #ifdef CONFIG_DUMMY_CONSOLE
> >  struct screen_info screen_info = {
> >  	.orig_video_lines	= 30,
> > @@ -64,12 +68,17 @@ void __init setup_arch(char **cmdline_p)
> >  
> >  	setup_bootmem();
> >  	paging_init();
> > +
> >  	unflatten_device_tree();
> 
> spurious whitespace change.
> 
> > diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.lds.S
> > index 23cd1a9..9700980 100644
> > --- a/arch/riscv/kernel/vmlinux.lds.S
> > +++ b/arch/riscv/kernel/vmlinux.lds.S
> > @@ -46,6 +46,7 @@ SECTIONS
> >  		KPROBES_TEXT
> >  		ENTRY_TEXT
> >  		IRQENTRY_TEXT
> > +		SOFTIRQENTRY_TEXT
> 
> Hmm.  What is the relation to kasan here?  Maybe we should add this
> separately with a good changelog?
> 
There is a commit for it:

Author: Alexander Potapenko <glider@google.com>
Date:   Fri Mar 25 14:22:05 2016 -0700

    arch, ftrace: for KASAN put hard/soft IRQ entries into separate sections

    KASAN needs to know whether the allocation happens in an IRQ handler.
    This lets us strip everything below the IRQ entry point to reduce the
    number of unique stack traces needed to be stored.

    Move the definition of __irq_entry to <linux/interrupt.h> so that the
    users don't need to pull in <linux/ftrace.h>.  Also introduce the
    __softirq_entry macro which is similar to __irq_entry, but puts the
    corresponding functions to the .softirqentry.text section.

After reading the patch I understand that soft/hard IRQ entries should be
separated for KASAN to work, but why?

Alexender, do you have any comments on this?

> > +++ b/arch/riscv/mm/kasan_init.c
> > @@ -0,0 +1,102 @@
> > +// SPDX-License-Identifier: GPL-2.0
> 
> This probably also wants a copyright statement.
> 
> > +	// init for swapper_pg_dir
> 
> Please use /* */ style comments.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190814074417.GA21929%40andestech.com.
