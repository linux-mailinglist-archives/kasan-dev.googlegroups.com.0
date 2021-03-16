Return-Path: <kasan-dev+bncBDDL3KWR4EBRBP7NYOBAMGQEQR7JLOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id F186133DC71
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 19:19:44 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id u8sf25919566qvm.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 11:19:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615918784; cv=pass;
        d=google.com; s=arc-20160816;
        b=kJVNzNgyiouHzIyfa2o1mkihe5tZgOnWGP7emnf9R94ebSM/qjUmZqBqJgC0IJEN3Z
         HQAmsI1K9qSzg6Rp4oNEy8+eIjGTYtqfg6Ymfer28caklUuuFNRsLMaIMY6do6eDetwG
         56pyQPlpBf91lMiC+r0Jz55Y792sNMM5OYdjvxoWnSNCclSbOiywziqNLVVq5kUFYbtZ
         Tk2hJhWoJJxHEJM6UfvLMdE7iU7kmId0Z7oJaZ97qaIKVM46OT/FqoRsvaLZYwiJqCGw
         TaPgIRxwurZMvtj+qnuTbrTmXe7mM+Z7BKbYvVuNO235+xoifX+r9PjH0kQc6wwH42FC
         YTlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=gsE6T9qvLbdh1vlK3aOzi+MAdNv8XMJTR9XGrFL/BjE=;
        b=eL1XnmWSJaoIY9aFQ/bpLpYkn9UeM756XyFIF8HCAKTr/B2CoqySLkkdVH9i27fm4W
         BWRJTaUbgGUza5vmoj00vHr8tT0srlDdbdYPsiIZ8AIG/I2G0iXShY8VaK/pNik6OxV0
         yVAFNoPHLemj3J3zPRfJVCqc4mTwygyBrt0iETYoX21UXYDHH1b0TDaJGuwa6GTUlfLo
         o4TjUvz6JXRFR22dkpXuPI3i5fjKii7z0E12y4CBFTtxSookGwu27xcy443nSQ1boE5n
         e2Kx/Sq/zXI0QNL+nyRzbEjPneXINwE61JUNVHqp4aQO8RBRepG16HhG3JSCRp28bsXb
         2esQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=gsE6T9qvLbdh1vlK3aOzi+MAdNv8XMJTR9XGrFL/BjE=;
        b=A10UUna3fLYa0N5YmaAatsr1B+JZbEhBRSKeRz2NKUhf+O56SnebIAAu/DokIBgwf5
         65KchpVVxiFxptxKp4aIq6vxVI2AAwQjWW1dMJQpEGWdfe93+4MOdxUs2x80ZrLnqaGi
         xTH9Rm+4h1t69fcsuB+mzfqnLMb3KGi7j8UhhrGdiXwR4oVovL28i0WivL6V/iz0KrWE
         p2wt6+tsYi9Q+W4pVUL88WkSiYF1b13lLIBz1TIw4PGjSlTHhthxGT4PrKf2gCE+/B4+
         aF3pkPDj1zhLzybNWP55IG4BTBYmcBubOS3i9ZUiIu4ydxhtSVN6c/f2ralGzbHHid3L
         StYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gsE6T9qvLbdh1vlK3aOzi+MAdNv8XMJTR9XGrFL/BjE=;
        b=bjbnQfpS5NmkIPQRxZ7080gy6o7zf+ib+vKUACG1SEJTTovch87NGeJ0Ji4CRDOuP2
         HlV6tk2lg/6Ksm/gWKDd2KOcDGzzTzdagJAIs1sutDU15r0fk1glVtUWKaRPDu+/t8g2
         dnK8RF99+NKt5CEWcTZZKvBkB74ZqZo21xiIoXdphJY4CbFjzXqRi1gO0KrOtv9k3vwM
         a+T6FpKErLRWvaaGSmeKODcMhlnwWMNMBXzDxnbseakgoRjx8GaQgZk9HqUqc9uq4HPo
         cqAl+osnqJIP1XIVNrwOsIwoqTi+8KweQNte1Mbk8iSUOFCv46KEFQWQadlJocDZUNQm
         5M4Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531wi+uAl8Y6ygLV0P3qfezXXPrrvOBqkhoUtzfpCuP+fi8eH8Ru
	PlXAKxvijKEfhe2MpqMHmi8=
X-Google-Smtp-Source: ABdhPJyR0WCp1dnmULFku1ksy3rOLwyvs7BbbTBhQykv6x9x8+Z24ByM3FHmy2I4C84Xrt4zhU2M9Q==
X-Received: by 2002:a05:620a:14f:: with SMTP id e15mr313783qkn.315.1615918784059;
        Tue, 16 Mar 2021 11:19:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:df0a:: with SMTP id g10ls3210103qvl.0.gmail; Tue, 16 Mar
 2021 11:19:43 -0700 (PDT)
X-Received: by 2002:a05:6214:b04:: with SMTP id u4mr764152qvj.0.1615918783613;
        Tue, 16 Mar 2021 11:19:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615918783; cv=none;
        d=google.com; s=arc-20160816;
        b=Bhfha6PmidHJTqCHFplBuOKVBSEhmzdnJcoGSe5QTQGghwNN3TN0MDJID8EsIt5QEr
         LEtgVYBSiITPrmnzg8X+JAJEW2nznjiH1IOUUrd604pkujx/fWo86SchxbcuIuRsobOc
         YKnmHhOJjZOK4BqjrWNw4iz2jPP7n4i/GNPGLmlYnTD3kDNr1Bb7YYaqjIS3BPjqKCT2
         sSgZNjDVfiVoiN7kqfGV7BStzsEiWgABhoOWaWuAC4M5wan+fZc9g9AAdm4nI6IuNFf0
         sxttTzmUbyjzVyG7KIzQwmTlYnIfOxr0fc3ZtPb4xtEJGyZxmiGOW7qAQ8pOrReebDhH
         h/Pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=36fxbzPMyXQRevZ78mkLaAbwL23cAdf1nDlC9TpFyn0=;
        b=DSauadkzxav3M6VUT3so9jaEWfCax/uZ7PrzbwQF0rvcJh6a/Pc1HCTQ/kPAqLE4nv
         8cqSmFMTPKgnKnzBY38bKWDKoiW7kCYCg3WCx0kEje0rH5mCh0v2n9e43h05YuUrSixv
         WgkgsJZmkIycaYyRPfhr/aKNwijCcVYum5+qZ3t1/lLEEQettJIVjZa1nXfkHZltbup4
         R+bSluF8Mm7KJoDRPwlgZ9Iqh4HWF5iS55Jr3izGqMEIxWCUprNiA2nczxcKvBuXMxOa
         ABL9AzM73D916TqJbhGsvRRUpO1IO8GU58I0uLRO1DXoiDTbfOpVMuiLGftKoAMahm8T
         0aug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id g4si731252qtg.3.2021.03.16.11.19.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Mar 2021 11:19:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id F09A165116;
	Tue, 16 Mar 2021 18:19:40 +0000 (UTC)
Date: Tue, 16 Mar 2021 18:19:38 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: Luis Henriques <lhenriques@suse.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: Issue with kfence and kmemleak
Message-ID: <20210316181938.GA28565@arm.com>
References: <YFDf6iKH1p/jGnM0@suse.de>
 <YFDrGL45JxFHyajD@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YFDrGL45JxFHyajD@elver.google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Mar 16, 2021 at 06:30:00PM +0100, Marco Elver wrote:
> On Tue, Mar 16, 2021 at 04:42PM +0000, Luis Henriques wrote:
> > This is probably a known issue, but just in case: looks like it's not
> > possible to use kmemleak when kfence is enabled:
> > 
> > [    0.272136] kmemleak: Cannot insert 0xffff888236e02f00 into the object search tree (overlaps existing)
> > [    0.272136] CPU: 0 PID: 8 Comm: kthreadd Not tainted 5.12.0-rc3+ #92
> > [    0.272136] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a-rebuilt.opensuse.org 04/01/2014
> > [    0.272136] Call Trace:
> > [    0.272136]  dump_stack+0x6d/0x89
> > [    0.272136]  create_object.isra.0.cold+0x40/0x62
> > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > [    0.272136]  kmem_cache_alloc_trace+0x110/0x2f0
> > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > [    0.272136]  kthread+0x3f/0x150
> > [    0.272136]  ? lockdep_hardirqs_on_prepare+0xd4/0x170
> > [    0.272136]  ? __kthread_bind_mask+0x60/0x60
> > [    0.272136]  ret_from_fork+0x22/0x30
> > [    0.272136] kmemleak: Kernel memory leak detector disabled
> > [    0.272136] kmemleak: Object 0xffff888236e00000 (size 2097152):
> > [    0.272136] kmemleak:   comm "swapper", pid 0, jiffies 4294892296
> > [    0.272136] kmemleak:   min_count = 0
> > [    0.272136] kmemleak:   count = 0
> > [    0.272136] kmemleak:   flags = 0x1
> > [    0.272136] kmemleak:   checksum = 0
> > [    0.272136] kmemleak:   backtrace:
> > [    0.272136]      memblock_alloc_internal+0x6d/0xb0
> > [    0.272136]      memblock_alloc_try_nid+0x6c/0x8a
> > [    0.272136]      kfence_alloc_pool+0x26/0x3f
> > [    0.272136]      start_kernel+0x242/0x548
> > [    0.272136]      secondary_startup_64_no_verify+0xb0/0xbb
> > 
> > I've tried the hack below but it didn't really helped.  Obviously I don't
> > really understand what's going on ;-)  But I think the reason for this
> > patch not working as (I) expected is because kfence is initialised
> > *before* kmemleak.
> > 
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 3b8ec938470a..b4ffd7695268 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -631,6 +631,9 @@ void __init kfence_alloc_pool(void)
> >  
> >  	if (!__kfence_pool)
> >  		pr_err("failed to allocate pool\n");
> > +	kmemleak_no_scan(__kfence_pool);
> >  }
> 
> Can you try the below patch?
> 
> Thanks,
> -- Marco
> 
> ------ >8 ------
> 
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index f7106f28443d..5891019721f6 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -12,6 +12,7 @@
>  #include <linux/debugfs.h>
>  #include <linux/kcsan-checks.h>
>  #include <linux/kfence.h>
> +#include <linux/kmemleak.h>
>  #include <linux/list.h>
>  #include <linux/lockdep.h>
>  #include <linux/memblock.h>
> @@ -481,6 +482,13 @@ static bool __init kfence_init_pool(void)
>  		addr += 2 * PAGE_SIZE;
>  	}
>  
> +	/*
> +	 * The pool is live and will never be deallocated from this point on;
> +	 * tell kmemleak this is now free memory, so that later allocations can
> +	 * correctly be tracked.
> +	 */
> +	kmemleak_free_part_phys(__pa(__kfence_pool), KFENCE_POOL_SIZE);

I presume this pool does not refer any objects that are only tracked
through pool pointers.

kmemleak_free() (or *_free_part) should work, no need for the _phys
variant (which converts it back with __va).

Since we normally use kmemleak_ignore() (or no_scan) for objects we
don't care about, I'd expand the comment that this object needs to be
removed from the kmemleak object tree as it will overlap with subsequent
allocations handled by kfence which return pointers within this range.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210316181938.GA28565%40arm.com.
