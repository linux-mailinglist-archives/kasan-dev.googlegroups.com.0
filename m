Return-Path: <kasan-dev+bncBCMIZB7QWENRBSWQQDYQKGQEI32ORSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A1A813D66C
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 10:09:31 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id f193sf7392930ybb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 01:09:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579165770; cv=pass;
        d=google.com; s=arc-20160816;
        b=xf1sBLHp3IkxmPwYq00ThuZRs7ES8tqWAXYZZKFdmaRu0vwfzXzOBuDH9kReiyS3o8
         09AvogI4xTrAZgvlnIs7URt28Y9+A3hky7KikXP9yKh2OE6DM7rVxhpizcdhSpz1m+wx
         tDJbgEL+iMo+40UTlY+cxU1n8Gz0UUmUvi7vV6gkmCp7MPQf3XVRsqh1Di081AujP500
         CeDPgMSg9fs7FP8OXLJ48lwDAotDkBvWr3erKLTPfoOj+XCuycqMGiqbH82a6/brV1Zm
         oKshuFJ4XDruIxxnWzkyEEDkzSy1/gNTTzPR8OtO1LJAeVTaWm0Up1cg+4YjvQBp95Zq
         wqYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2W68QtlNQVO8yg4sYWfgqExv9TMtGQCFgZEq0VfsDWo=;
        b=FpSgxHSzMTbIBxArwjN+4OqDZ1eowyUCmy7MwqwfSXG6BjwxvQE4Z+uRWdtgoq4ksy
         UO/QzyXh6QD3F/v+pTAZY+arlhDlnKLQsixmbdTmcIG8OX1q5DW7jv2mHHz42D8f0gzV
         ZJBaEIO+ASJ3BGZK06bScMGlgFvA5sYbu2Iq82sMLrtXJuTglq6Aalul9RmOR54Is62C
         jRaj6XlQhTroIJXkTW0FqfD3pP+tyxVskFWsxo2GxWbL92Hl+gzNXQS+TUjkvoMmbci8
         AoLWeboE8k/xlHedy95DtDIx15p+mxN5qdgC7rSXLRxIpZGJHHXjV2t5r+9awhZZdSiv
         z9OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GTR/LPR5";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2W68QtlNQVO8yg4sYWfgqExv9TMtGQCFgZEq0VfsDWo=;
        b=GgmOYzQzRGJ7URCiaFSdD2SE7kLQn1vXVD7R+fXdV3FrIDJJYugELgknYWg/qVZI0w
         zNM7GLUTjTzCNBb7Il7Sy8ey4bYncU3NgGAIuWoMy5Va/2NUNXGa8vnHBEr/XY1UoHSk
         xzeihqFu8XZAjAR84cO1nH1XOmP1bXnLp8KLTkoEJigS0Op51zKluhSVG+WKarwf5nyl
         JsPQ5Fvi4DlBBT+4rQrdYvLjuO2LD82YA+aefSzptHVFlBjHqTEHdMnXeGutDSchI1w/
         yPxKQwRP4a+sLWgSfaKAzk9+7snzkU37UvqBJ24lA0hsJE58p9LS5AVGgIA+7NVioA8x
         l4XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2W68QtlNQVO8yg4sYWfgqExv9TMtGQCFgZEq0VfsDWo=;
        b=KGIeGSzM4h9rbwY8b5PXNb1CIu4nwYr/ZoIc6vFFvLfwKlbUB0LUZBtjl5K5941gzo
         78Mka3/+h1wF8pS6C21BZIg5fbz9eAUiH4AEU7XIPRHwrsVu3jg3bFslPGQzTSNLSbbK
         TJBR9wdN+Q5mHzY7ii32o6/l+owfi8otsVF84WYdnUek2dYhl/9Ua3HqSa24xQX5nNGq
         C1eCx1eOfekTk+JivjVgyZXhohgzIc30DHQlObqL4vFUigMnOpLZgIgDssQ/S8G4W/HM
         lgm5pT4s9aUp+pqTm+UcHcjko02nLF97xg+uVxpZ1N4s4yUDBX3HZNmwmLhOB0Mu0I4B
         g+jA==
X-Gm-Message-State: APjAAAV5WomPKKXIOPHrRzHwu8gL+eaANxrGs+iRrY6F7ec6Rg1zZjxH
	cEjJkPKiAaDiXI3CCNhtbb4=
X-Google-Smtp-Source: APXvYqyO7KL7q+SSg7Tu5v6TzbNf/lmAt68tWd6V7XqzYmXTU0WGRQUGEM7idNUzfQZiB93uLe4Rwg==
X-Received: by 2002:a5b:ec2:: with SMTP id a2mr20635099ybs.459.1579165770190;
        Thu, 16 Jan 2020 01:09:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:66c6:: with SMTP id a189ls3468530ywc.8.gmail; Thu, 16
 Jan 2020 01:09:29 -0800 (PST)
X-Received: by 2002:a0d:db47:: with SMTP id d68mr26778850ywe.152.1579165769839;
        Thu, 16 Jan 2020 01:09:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579165769; cv=none;
        d=google.com; s=arc-20160816;
        b=d8cHd/ChKDMNXtulWhI462oiawmFMJo03n435IqJDv83nMJIJD9vmzXUkq4Ei3zHVQ
         xvWPhm7wSXyzwxAOh8/Df/RalTOWSkXFwWPfvlCsJtLDGrvE+XHzP/A8Lehc0GU7cDO/
         O6Hw7ck6gZ/xkt6UtocZC1O60j1gcR/O7nfNQebdIxM1icGuF8ieGxsXYiJ5CJqNkv7A
         07mmYV+D4u3qdOqHBZMXUQxdYTC6pVvm6PktQG86zazJj2PILEKLO6PcTLfXhcUrXJz2
         bkyJZodZBp+WJMQDnXDFtW1MCqZzYJMM/f9WUK/mh4iv7DI+C50nYzlPhzocPuqYebVI
         Vpyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tonFvUx7UkLvzdq6Qt10/rB0wyKCjPpdmSM6EzK1Zgc=;
        b=MYfm4WfQEMdBSVRnh78ivpLMtDXtUmyNbflDcGcpNTvQUZok2vrsiWa+6YVn99NXdf
         kaHCG1TFPoxZN76ZwznVdWaR1dr8vNYet0d2Y8b7G0kiVVX2QcWTy4nCveHVnOo4fpOt
         ZbjGN2zNOpxpk0LISRN7B5N9FmD/j+7ctPRmatoVF5GTaMpeUIJ9WyphZVgUnNOylzkZ
         oYj4swGeLZ2qcmpztsnbkGMvabyjyRkl4S8surGu1kETyZuZD7sMsARxlztSng+opihl
         D8GQrLnGKbCVXW8Vr6lEX+8Po/QeAbjXe5gMKAW/zdp3ai5KZ7YZquDGVpEdiL1cJ+lK
         XXmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="GTR/LPR5";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id y3si1018002ybg.3.2020.01.16.01.09.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 01:09:29 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id x1so18400670qkl.12
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 01:09:29 -0800 (PST)
X-Received: by 2002:a05:620a:1136:: with SMTP id p22mr32318196qkk.8.1579165769218;
 Thu, 16 Jan 2020 01:09:29 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
In-Reply-To: <20200115182816.33892-1-trishalfonso@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 10:09:17 +0100
Message-ID: <CACT4Y+ahnhTXQPfxcJPEFOA1saAr4xOGY583am8buW7kMJiq8w@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Patricia Alfonso <trishalfonso@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="GTR/LPR5";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Wed, Jan 15, 2020 at 7:28 PM Patricia Alfonso
<trishalfonso@google.com> wrote:
> diff --git a/arch/um/include/asm/kasan.h b/arch/um/include/asm/kasan.h
> new file mode 100644
> index 000000000000..ca4c43a35d41
> --- /dev/null
> +++ b/arch/um/include/asm/kasan.h
> @@ -0,0 +1,32 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_UM_KASAN_H
> +#define __ASM_UM_KASAN_H
> +
> +#include <linux/init.h>
> +#include <linux/const.h>
> +
> +#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
> +#ifdef CONFIG_X86_64
> +#define KASAN_SHADOW_SIZE 0x100000000000UL

How was this number computed? Can we replace this with some formula?
I suspect this may be an order of magnitude off. Isn't 0x10000000000 enough?

> +#else
> +#error "KASAN_SHADOW_SIZE is not defined in this sub-architecture"
> +#endif
> +
> +// used in kasan_mem_to_shadow to divide by 8
> +#define KASAN_SHADOW_SCALE_SHIFT 3
> +
> +#define KASAN_SHADOW_START (KASAN_SHADOW_OFFSET)
> +#define KASAN_SHADOW_END (KASAN_SHADOW_START + KASAN_SHADOW_SIZE)
> +
> +#ifdef CONFIG_KASAN
> +void kasan_init(void);
> +void kasan_map_shadow(void);
> +#else
> +static inline void kasan_early_init(void) { }
> +static inline void kasan_init(void) { }
> +#endif /* CONFIG_KASAN */
> +
> +void kasan_map_memory(void *start, unsigned long len);

This better be moved under #ifdef CONFIG_KASAN, it's not defined
otherwise, right?

> +void kasan_unpoison_shadow(const void *address, size_t size);

This is defined by <linux/kasan.h>. It's better to include that file
where you need this function. Or there are some issues with that?

> +
> +#endif /* __ASM_UM_KASAN_H */



> diff --git a/arch/um/kernel/kasan_init_um.c b/arch/um/kernel/kasan_init_um.c
> new file mode 100644
> index 000000000000..2e9a85216fb5
> --- /dev/null
> +++ b/arch/um/kernel/kasan_init_um.c
> @@ -0,0 +1,20 @@
> +// SPDX-License-Identifier: GPL-2.0
> +#include <asm/kasan.h>
> +#include <linux/sched.h>
> +#include <linux/sched/task.h>
> +#include <asm/dma.h>
> +#include <as-layout.h>
> +
> +void kasan_init(void)
> +{
> +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> +
> +       // unpoison the kernel text which is form uml_physmem -> uml_reserved

Why do we need to unpoison _text_? Who is accessing shadow for it? Do
you mean data/bss?
But on a more general point, we just allocated it with mmap, mmap
always gives zeroed memory and asan shadow is specifically arranged so
that 0's mean "good". So I don't think we need to unpoison anything
separately.

What may be more useful is to poison (or better mprotect, unmap, not
mmap) regions that kernel is not supposed to ever touch. One such
region is shadow self-mapping (shadow for shadow), in user-space we
mprotect that region. For KASAN we don't map shadow for user-space
part of VM, but I don't know if UML has such separation. We could also
protect other UML-specific regions if there are any, e.g does anybody
read/write text?


> +       kasan_unpoison_shadow((void *)uml_physmem, physmem_size);
> +
> +       // unpoison the vmalloc region, which is start_vm -> end_vm
> +       kasan_unpoison_shadow((void *)start_vm, (end_vm - start_vm + 1));
> +
> +       init_task.kasan_depth = 0;
> +       pr_info("KernelAddressSanitizer initialized\n");
> +}

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BahnhTXQPfxcJPEFOA1saAr4xOGY583am8buW7kMJiq8w%40mail.gmail.com.
