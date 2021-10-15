Return-Path: <kasan-dev+bncBDOY5FWKT4KRBLEEUWFQMGQEUYLRVIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 783DD42ECE6
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 10:56:17 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id k3-20020a4a3103000000b002b733cd21e6sf3207495ooa.19
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Oct 2021 01:56:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634288173; cv=pass;
        d=google.com; s=arc-20160816;
        b=hVOTPfKW8QmRV40Xmi56uoomT0m3XLZ8zueuTKDm3/wh3PohCXML7LXI2J8GIWFRKx
         eFUGsgj0WjaDJxtWYsWjqwNBAyP3PjbLIBnggfoDXF7cbnQx4z5OH0VSCk5zNognXdGQ
         sZ51+6JEVf/8Qe14mZUMpieDH/SQAdwoxu80W6S1pJqMbENpVhu+K1unda2zgTVS3Ll9
         F6HvnJvWGn3FQDU4K8FlitpQ3QkIs16Ehm9ai/PdKECggQizRoF0Xk5NDmWW+Raealwa
         445G5U/67SPYly4IHxPQlS9dNf43+5fZ/tFAEmxwzQ4xeT8UzBxLPQPSGRVK9DueGqCc
         Et4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=wUksYGlPZ1okYcJUd418z/1QxnMYDFg2ly7Z1qmQJ6k=;
        b=AyHIm/b5Xgc1We7AIgk+C5RaJmbwjtWn3Jt4HF0rYtNk+/8VBIUBMYTB6OCRes9LNd
         3oSzOG3DDRNjGUr6ZbE3x6wfGDk3R61quWjlfNHFvPMnkgYcTdRuFHreTqgIucauCA8h
         MxWjv5JlQVs4LxmNgYFKx/n5pETSHazzUJMumPcc5FfcNfp0ccsNIccY5BmN6+Vln37V
         RwyfHNGw0sR/OtxEeZZIXQrEkWA/HcxbmPF5WRAJyMnGa2tvgZU9qNPwWWh4D721ATkJ
         t6FK3JOI2yQDmvd1pWbxn9q/igbqlMFYnAu3z/UtpIpC1TPTqzAmz5BkL/P33Jmr4vxJ
         jjSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uHWFxjgN;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wUksYGlPZ1okYcJUd418z/1QxnMYDFg2ly7Z1qmQJ6k=;
        b=Qcz1rXHJLqLN1aVQdWTTF70nDQ/AK11gOz+E3II+2kxRlu7pfJHV3CuQKXRqPQeV4R
         CpLbB46PhTTxQEX5dzv15bEXdIJglNIVFU5+f/5DsMU042WJymdVpq5hUZ8AjJn0dUqP
         rtFW+xSb6nNNLYGjPr++8FHWzV9EeRlY5jEutI0Av2Ca1jWLfjg+Dan2xJ8vzMkZXxsf
         0ElTxaO/pCccXqUQpoIqW+hmEDntODfZ0nqc1sN+W2wX8JC8i0izucDWDUsPoa8k6Kvz
         vdBMe2MGe98CvpMsPj18hZKOcQgwUtvVTT16pVU8gArGVgWf2LzmYbqnQ7zGqLZM/aAp
         jN5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wUksYGlPZ1okYcJUd418z/1QxnMYDFg2ly7Z1qmQJ6k=;
        b=AygrMFyxAmakhWa95SxwBcXH189BES6i0fX7jjncVYSJUr0sC01liemXvf91u1GVUj
         70t59JjQ86lrgCtpEzvgcHZka6UOQ7cLAsiXb2hluVJMcp7OpzI5i/urKXr+EWB/tcIV
         N7skGbAs/R1UAX89diY3xXVliFmGsStbnNYpML3s0rdRZJJ9WPza2cAV0KJwZdbykFCH
         BcxX9ouqh0ZkSLyfW882NswNzAbFfxIwRnk3czW7N/VZtAuoCBPQeINtrrYzakBoB5j3
         F4DmVlnLUw/4P313fy0B9SwZ4Gjah1gHbJ/pZyVodaF64zWNezH35xcvR3qHxZl7TuUq
         TJjw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/7P8EN2njeOEyQeYEajo7w/MV4iomJoRNbJ1a1lUYaD1pxzUH
	P0Vnldx7urNRnYqgjfWCL8E=
X-Google-Smtp-Source: ABdhPJxfK6SEJESvwpv/BUUrHHdfewjaEYW+18lgnTAvch/2xxiKhtXhsdtdkDUI9QOyQxEPsB3Yog==
X-Received: by 2002:a05:6830:43aa:: with SMTP id s42mr7088052otv.136.1634288172084;
        Fri, 15 Oct 2021 01:56:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:460d:: with SMTP id y13ls2597924ote.11.gmail; Fri, 15
 Oct 2021 01:56:11 -0700 (PDT)
X-Received: by 2002:a9d:4c8:: with SMTP id 66mr7111623otm.113.1634288171680;
        Fri, 15 Oct 2021 01:56:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634288171; cv=none;
        d=google.com; s=arc-20160816;
        b=NKC9mOXMAGaGK5OUsFBSOK+Y6F8NakOk6vVZues2hj4s3V5z0JT+rdLAb7NbS/RpfL
         r9Om7U7o2TqWuOodY2WFcARC27Qb0cA+zskl5UYYGcYYf79NTxN+Bs8nHuo3IU0TV+Tt
         93r8runUu84ftjO4qkxsP/Y2dwHBBFWZ800xCP1+fXq7UaZd44LAgDZZATujmA4eOUIz
         pr2BqHvGZvxUyP90gV8FMvX0NHAnM+BCsCaUS+LqZ8pZmTbLNghLBA4eAFLIEDwIxbfm
         WMNXJufcyeZaE0tjrSbbmbZWomTdZG4Z/qYUta1kW6Hfp7MnBA03JdzebU+IK84L5MoL
         7XBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=/ttHx/rEjYBoqUkZIaGtEXyDLWjP5Qm04VJxdL79k80=;
        b=HwVXvf40TyOJnwpfylWoS1izO0IdVev2kMZN70LD1JQRuGi9VIyhrs93shJ5pheqsv
         B+/RnKuW+jETHEgduxxC1nIUg1GOAR+qp5Ys03z5aW3TbwNnpoxok+hcVW6+Iz6a1y1z
         ejjYqoESmeJEjzv7eqqlwjAaL3X5gNYRCTcBo0evstydej22FQQDyG+Zxx6Y/Y1rDSae
         XrZjZsP3R10CMTAXC0gWWPZ5cnxj8Yrv1OJp8idBmVnzpkSYuHtREWQEMjjSGwKWA8od
         RLmzfHfWsQDEaE45+Q2pUd/0+hlIlbW8jalHd8eg1Kv2L1ic7yBq0b59/5OsbQarYPAH
         mPNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=uHWFxjgN;
       spf=pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id v21si415684oto.0.2021.10.15.01.56.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Oct 2021 01:56:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id BAD2E61053;
	Fri, 15 Oct 2021 08:56:03 +0000 (UTC)
Date: Fri, 15 Oct 2021 11:55:58 +0300
From: Mike Rapoport <rppt@kernel.org>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <oliver.sang@intel.com>, 0day robot <lkp@intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	Vijayanand Jitta <vjitta@codeaurora.org>,
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>,
	Maxime Ripard <mripard@kernel.org>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Oliver Glitta <glittao@gmail.com>,
	Imran Khan <imran.f.khan@oracle.com>,
	LKML <linux-kernel@vger.kernel.org>, lkp@lists.01.org,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
	kasan-dev@googlegroups.com
Subject: Re: [lib/stackdepot] 1cd8ce52c5:
 BUG:unable_to_handle_page_fault_for_address
Message-ID: <YWlCHtDOLAzDTU67@kernel.org>
References: <20211014085450.GC18719@xsang-OptiPlex-9020>
 <4d99add1-5cf7-c608-a131-18959b85e5dc@suse.cz>
 <YWgDkjqtJO4e3DM6@kernel.org>
 <137e4211-266f-bdb3-6830-e101c27c3be4@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <137e4211-266f-bdb3-6830-e101c27c3be4@suse.cz>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=uHWFxjgN;       spf=pass
 (google.com: domain of rppt@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Oct 15, 2021 at 10:27:17AM +0200, Vlastimil Babka wrote:
> On 10/14/21 12:16, Mike Rapoport wrote:
> > On Thu, Oct 14, 2021 at 11:33:03AM +0200, Vlastimil Babka wrote:
> >> On 10/14/21 10:54, kernel test robot wrote:
> >> 
> >> In my local testing of the patch, when stackdepot was initialized through
> >> page owner init, it was using kvmalloc() so slab_is_available() was true.
> >> Looks like the exact order of slab vs page_owner alloc is non-deterministic,
> >> could be arch-dependent or just random ordering of init calls. A wrong order
> >> will exploit the apparent fact that slab_is_available() is not a good
> >> indicator of using memblock vs page allocator, and we would need a better one.
> >> Thoughts?
> > 
> > The order of slab vs page_owner is deterministic, but it is different for
> > FLATMEM and SPARSEMEM. And page_ext_init_flatmem_late() that initializes
> > page_ext for FLATMEM is called exactly between buddy and slab setup:
> 
> Oh, so it was due to FLATMEM, thanks for figuring that out!
> 
> > static void __init mm_init(void)
> > {
> > 	...
> > 
> > 	mem_init();
> > 	mem_init_print_info();
> > 	/* page_owner must be initialized after buddy is ready */
> > 	page_ext_init_flatmem_late();
> > 	kmem_cache_init();
> > 
> > 	...
> > }
> > 
> > I've stared for a while at page_ext init and it seems that the
> > page_ext_init_flatmem_late() can be simply dropped because there is anyway
> > a call to invoke_init_callbacks() in page_ext_init() that is called much
> > later in the boot process.
> 
> Yeah, but page_ext_init() only does something for SPARSEMEM, and is empty on
> FLATMEM. Otherwise it would be duplicating all the work. So I'll just move
> page_ext_init_flatmem_late() below kmem_cache_init() in mm_init().

I hope at some point we'll have cleaner mm_init(), but for now simply
moving page_ext_init_flatmem_late() should work.

> Thanks again!

Welcome :)
 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWlCHtDOLAzDTU67%40kernel.org.
