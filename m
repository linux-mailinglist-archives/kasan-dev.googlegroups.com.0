Return-Path: <kasan-dev+bncBCK2XL5R4APRBBUDY3VAKGQE2D4CPYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 32E728A1FE
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 17:11:03 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id p80sf4067623ybc.17
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 08:11:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565622662; cv=pass;
        d=google.com; s=arc-20160816;
        b=P5jIAVlEjjlLFfLORYoiyOZ8NMIkwTDVY5ur3OpyXYiRLTAeCxYrgHL+1hJCNn8/1/
         ZHNoK/tHhvm0JNt3/ehrrUuqdRfW4oYf8SKSXGfKmjQG/4b2OBxkKkmHoEWl3F2SqjSO
         Ji4b76ONArsLCE4Oz4nhwgNyC/b/eFlch2QUzgZAy7rU6X0/FBlf937I54QjOtnBHg2x
         ozYn4JkbIUETHiMZ7hFASxyEhXRV61XokprQguviqwH9ermgud+q+PK/ghqowCsalHbD
         hfE2BpUg29TC3aZE+T94CKLn+pTusYpCHvVbxwRu63SRR/7SFMuvTJ7V9gQBhlH1GaO+
         zS5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=u3s7LgdXHSSiBcM4+syoO3rMm8lP7XiTRFvL2z6jxlU=;
        b=ZK2HyGKQ2nI00csb1OLZlG7FA2gaJ3gHxDZ0lSO1Vb/cu1s54+W/qSTov5FX5OvDXg
         YwL9d/LBdiskSZu61+FgYUYLRio4XnLW38f/eI5d14ASF0yxcqoWzzuEm4jEsHNrn3Cm
         07TYyw/7AJuuky3cZphkUxdN5o/W3o2MmBZroC52gnebcVTChs+iQw8sXbttcr93YQXo
         Hh0azigirKjMosofLAp3hoTmvyFMcyVjg2jvtCcTLVbg5KK68wJWdBBuv+6maoknedws
         P8Gao0juebCZMKSNSZvjuoW5uJHhxoK//nJfks6vnrLhXQ18wItu8boZ00PSsayek8Hn
         NrjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=jYgWhBde;
       spf=pass (google.com: best guess record for domain of batv+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=u3s7LgdXHSSiBcM4+syoO3rMm8lP7XiTRFvL2z6jxlU=;
        b=QCw6LkITVW4xwDllvDQmEq6w6Wo2LRBeVjfQ5kiiYAAz/W+Iyzr2WtvnCJ4rNyW5s1
         bs5/B6i/VjCi7VoZxcqKQyaecRzJ7YcmsCTnzSPp8zmZP5TzFv7kd83ab2fr/QwADF5C
         8ZkxFktg5tkTRPyH1aT4XiM2GevAmSwVkno3aOpW1/zC5Skbw5CRA8EIbjlsi+XCj+lx
         bituUZ9FtgpKfAWesZUK3cG6k331wG2NO3351KqpWY9at0kacT2KJAMXDbbRI4drn2pi
         6qKG7bP6X12ojlj9ZfzN/73uy1UDHpla4BuWBICpMLS1mb7HZz7s0wRkgnyw6ON/Tf5K
         kGIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=u3s7LgdXHSSiBcM4+syoO3rMm8lP7XiTRFvL2z6jxlU=;
        b=UfHRB0G/07lTCn+d9tmteJzHc3lla5t7U0wpqz1J69fjTqRdXMPcdlDjurPfVLjng5
         STaFLv5Xu6bTnpfyxXVsc8mzDmLR5Eeit3qn8pR5pDlQxj4uQaGKnOQBDrlSZ5bq9juh
         RxgdtrGd1WVnA4jah6uWb0db5g6h/15ptEQvI+ow7X7a8PZPEI6MdSHuXIXfQVRqm78R
         zpKv6xg8kdOK+F/I9E1lCppLPx70lFTYl943BixdQs0rwsmXRxcmfkFXhxdiah4JKnv4
         9aNkLj7qoVT+sRME7pXNgzuoqlXiV2FcFOgN7llIRiYjZ7R9quxP+38zaPkYpCPeQkZk
         u+Eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUea/9gYGX+wHJ4sVk8e1bsJqBd+NCVdyfrf6yQfGy9MucyoW+O
	ecn9duLGlCzvAUBoxGYgGiA=
X-Google-Smtp-Source: APXvYqxzXwC0kTe00AdDgh1e/GVKvANi0H2z9B6KYKaubLqHRAndZFC0aIBtCkBVTEmf6f/dQuSsbw==
X-Received: by 2002:a81:37c7:: with SMTP id e190mr23025462ywa.144.1565622662195;
        Mon, 12 Aug 2019 08:11:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:550b:: with SMTP id j11ls1249363ywb.15.gmail; Mon, 12
 Aug 2019 08:11:01 -0700 (PDT)
X-Received: by 2002:a81:25c6:: with SMTP id l189mr24143140ywl.202.1565622661917;
        Mon, 12 Aug 2019 08:11:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565622661; cv=none;
        d=google.com; s=arc-20160816;
        b=d1vw+VwHdCFowJ2bakyohxCQOy4DDzuvOW0r/lrgqJ+xNpEU+ZAbClTslPO7zt6/SU
         42sMhRGanpNQWI/Ovq3PRFbXPsTh3SNwjk9Hd2+IZCmrW0SGKfjdocUlWFs514Dt+tvg
         B7d6BKCdTZLgvrZz5WWqwR5l/s/TSt0UQq0eAB/AT6a7VNT5rdZH5tvQg4dnHlqzcTp0
         LNEg6sXZUel8r62PxdKl9j6q+d4AOLEaxfuFxxAtPXgG2foHjSGfjqZVbzOl+Acn1ZKc
         opxEwbSaVhq9493mVrMs5qsMWMlt2DrYVLZ/7+V9W1oTEpVzj2Ppf5cqZ8fRjjoY+bGy
         7OUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=c3bQwvEBKBc0pEEHbp7FCzV/9a7dwVZ1tfrux53aQUk=;
        b=JG30VfrqOqt6z4qeSQQz5UIcbqW11XLFbhwRBXBvcaLWVlH1KUQMmBthDZbdxH4XE6
         pPaeOH8etgGPn6U0lzVtaYsAoB7ctEPv5vY+AYhXyNNm3s8MgQs9P4K4sRRB6yfew76B
         i/PM9K6IKR0fi07oNQKnjxkKDc4MLyDFU4P/pADiikQUrXwswpCtpnjeSKaSf4VtfVe2
         09EtK4/7GN/azKoJ5/2AYWHTlGLHbtMXksJmWtrxOZMTA8pvHkZouA/sLRcrHc7AjjTO
         cSv5Swlj6dIOkWZVBCMycCA5+yqwo3ITOwyXu5ZdsFHlDK+E9j06LUhVJXXlQAM4/EQA
         H6Gg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=jYgWhBde;
       spf=pass (google.com: best guess record for domain of batv+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id f131si4571920ybf.5.2019.08.12.08.11.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 12 Aug 2019 08:11:01 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of batv+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from hch by bombadil.infradead.org with local (Exim 4.92 #3 (Red Hat Linux))
	id 1hxByE-0001gG-Rz; Mon, 12 Aug 2019 15:10:50 +0000
Date: Mon, 12 Aug 2019 08:10:50 -0700
From: Christoph Hellwig <hch@infradead.org>
To: Nick Hu <nickhu@andestech.com>
Cc: alankao@andestech.com, paul.walmsley@sifive.com, palmer@sifive.com,
	aou@eecs.berkeley.edu, green.hu@gmail.com, deanbo422@gmail.com,
	tglx@linutronix.de, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, aryabinin@virtuozzo.com,
	glider@google.com, dvyukov@google.com, Anup.Patel@wdc.com,
	gregkh@linuxfoundation.org, alexios.zavras@intel.com,
	atish.patra@wdc.com, zong@andestech.com, kasan-dev@googlegroups.com
Subject: Re: [PATCH 2/2] riscv: Add KASAN support
Message-ID: <20190812151050.GJ26897@infradead.org>
References: <cover.1565161957.git.nickhu@andestech.com>
 <88358ef8f7cfcb7fd01b6b989eccaddbe00a1e57.1565161957.git.nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <88358ef8f7cfcb7fd01b6b989eccaddbe00a1e57.1565161957.git.nickhu@andestech.com>
User-Agent: Mutt/1.11.4 (2019-03-13)
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=jYgWhBde;
       spf=pass (google.com: best guess record for domain of
 batv+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org
 designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org
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

> 2. KASAN can't debug the modules since the modules are allocated in VMALLOC
> area. We mapped the shadow memory, which corresponding to VMALLOC area,
> to the kasan_early_shadow_page because we don't have enough physical space
> for all the shadow memory corresponding to VMALLOC area.

How do other architectures solve this problem?

> @@ -54,6 +54,8 @@ config RISCV
>  	select EDAC_SUPPORT
>  	select ARCH_HAS_GIGANTIC_PAGE
>  	select ARCH_WANT_HUGE_PMD_SHARE if 64BIT
> +	select GENERIC_STRNCPY_FROM_USER if KASAN

Is there any reason why we can't always enabled this?  Also just
enabling the generic efficient strncpy_from_user should probably be
a separate patch.

> +	select HAVE_ARCH_KASAN if MMU

Based on your cover letter this should be if MMU && 64BIT

>  #define __HAVE_ARCH_MEMCPY
>  extern asmlinkage void *memcpy(void *, const void *, size_t);
> +extern asmlinkage void *__memcpy(void *, const void *, size_t);
>  
>  #define __HAVE_ARCH_MEMMOVE
>  extern asmlinkage void *memmove(void *, const void *, size_t);
> +extern asmlinkage void *__memmove(void *, const void *, size_t);
> +
> +#define memcpy(dst, src, len) __memcpy(dst, src, len)
> +#define memmove(dst, src, len) __memmove(dst, src, len)
> +#define memset(s, c, n) __memset(s, c, n)

This looks weird and at least needs a very good comment.  Also
with this we effectively don't need the non-prefixed prototypes
anymore.  Also you probably want to split the renaming of the mem*
routines into a separate patch with a proper changelog.

>  #include <asm/tlbflush.h>
>  #include <asm/thread_info.h>
>  
> +#ifdef CONFIG_KASAN
> +#include <asm/kasan.h>
> +#endif

Any good reason to not just always include the header?

> +
>  #ifdef CONFIG_DUMMY_CONSOLE
>  struct screen_info screen_info = {
>  	.orig_video_lines	= 30,
> @@ -64,12 +68,17 @@ void __init setup_arch(char **cmdline_p)
>  
>  	setup_bootmem();
>  	paging_init();
> +
>  	unflatten_device_tree();

spurious whitespace change.

> diff --git a/arch/riscv/kernel/vmlinux.lds.S b/arch/riscv/kernel/vmlinux.lds.S
> index 23cd1a9..9700980 100644
> --- a/arch/riscv/kernel/vmlinux.lds.S
> +++ b/arch/riscv/kernel/vmlinux.lds.S
> @@ -46,6 +46,7 @@ SECTIONS
>  		KPROBES_TEXT
>  		ENTRY_TEXT
>  		IRQENTRY_TEXT
> +		SOFTIRQENTRY_TEXT

Hmm.  What is the relation to kasan here?  Maybe we should add this
separately with a good changelog?

> +++ b/arch/riscv/mm/kasan_init.c
> @@ -0,0 +1,102 @@
> +// SPDX-License-Identifier: GPL-2.0

This probably also wants a copyright statement.

> +	// init for swapper_pg_dir

Please use /* */ style comments.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190812151050.GJ26897%40infradead.org.
