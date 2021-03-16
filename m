Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMH2YOBAMGQECBYHY3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 24D9133DCCE
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 19:47:13 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id 3sf13939785ljf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 11:47:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615920432; cv=pass;
        d=google.com; s=arc-20160816;
        b=GMdN6Y4uNbZBndbesYDgDlo5+WA8OOvy7XjRza/wTMBmv6MT5jmR8WhzIkNPFozdu0
         uOqWVtLTgLgmkaGHClauBGMhIbeumvzpPodxkagH2pLNcsVzB8Ia7QZGUPvCErABXMc2
         J3GLj6k0FURInWwyn5l18c51sFxC0qZsaSk9n+TD3YaVp/IDMdPxCqMdSkj5ZOdg0+XV
         XOvQ82BvVtSj41NN3E24A1JYLq597CaI+ElndB9rk2NMTOVY9Pu3n+ymqj9k6yfx09eI
         JJ8J3CCEKtCYg17yFLJv1spM/PwZIvkVx+7n8UynB3Xz/ZHI0KJJvbZm8WbJapas28xY
         7ZOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=y7mv5QmiJ+gjVM4N86WKWLB1Ye5gD4KKt6TEl2b8nI4=;
        b=fIckVWBDue8swhV7MIhvp5q8EABzkT1XJdqeaktZiYZKd3ifgoNvUg16c+g14zUKto
         5rOQlpq5xXKhF7l9uPMYylw60jojo8mxbiQc2rBKNdpn7o1qtS0DbkoFAPHT/5khKO9J
         Wud/jnTLC01e/CxBAnLWw5P0ZmdJyR7Nv//50dMzavq45C0W/OohYxFq39NcIjV2cqnf
         tMb9bPO4MTgCZiUW8rRBTVbqzoX9ALmvMwojWF0YoVklCSVyLNUdx5bovmsV2Y/Z35DT
         I8w9ILP0Cn7uVo9fGTW9R7CJ1Bz23wHHBdQ06Eu8cW63DA2GuOCiuOWZZzmHtI+3sFH+
         U97Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rM3fdiR9;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=y7mv5QmiJ+gjVM4N86WKWLB1Ye5gD4KKt6TEl2b8nI4=;
        b=AGmAwO+ux/9V8Ln0yrxFHvDBrr3QIBN7ifZBggSuHKq2rYXPc11qiKXrSIt3gA6KiX
         Nqy2sgU9+DMqWNhinDfrEmOeVfcViq/aYG7yNOJCTj3o7JPerw+24DKniK6hoJZw8YnA
         Tqpusnt0KWI6o6dzI5S0BjT/aRC1H6YdEw36qgxKtMH1GplSrjJNMf7hLq+F6cuBz9ig
         X2vbIyQVV9DsJoYtiEgorJE+1zIoMt3+7JzW2K6lpXjsO5Vm7vABUNc3u+jjQc8s8I5C
         Yn+OQ4R/9Ncmm0uXM6etF7R9fsVKzU7sRDisN1jcBPY/3S9DGYqCv+a/LzAoD4UeFm5v
         N8eA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y7mv5QmiJ+gjVM4N86WKWLB1Ye5gD4KKt6TEl2b8nI4=;
        b=Rv/xCcLRvjsYqI73tyK7B+6f/HaUTRCsESMOF0yluvx09GnfaLQ+uOTkzrDbqWLX/G
         Ws4dpdEJ19i9c2ZpEFuHiu36LhJfvxafEOZ8Q3oFgpc5yFRMu+ZMxXuObM4TT7wp1LtK
         n5VpR/r918ThTir2Di3Jj367e5BBErYxknYkkIwZTWPziSueQcDFOnYiZIpitz4G9TDD
         jYH9HT02bN7zUxiGuHBy5M0hSASGcZ1WIZkkC/RhTIGHJ1SzL7CI2QP6uWib9lD+5etB
         RUe3BADynmOxra6Tdh9kET+PJmDRqT2ybYgYI5JfYCF9Ec5YI+MvnP9uK8MQcKQlaCLx
         03/A==
X-Gm-Message-State: AOAM530/PjWOM4XhaQDQOG2I8ZAIwl9Qr8BytShfQZYvCu+VGWDLc1f2
	x1RP32O6HG7NtUd5sg9GXPA=
X-Google-Smtp-Source: ABdhPJxRdgScJ6GhcRHoki5NMRrjyfpruj8+Wq+tyqaUYjV8jkVljSOQf9kSAGn5y0Ze+9Lqormh6g==
X-Received: by 2002:a19:7ed6:: with SMTP id z205mr117272lfc.12.1615920432730;
        Tue, 16 Mar 2021 11:47:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b603:: with SMTP id r3ls4396834ljn.5.gmail; Tue, 16 Mar
 2021 11:47:11 -0700 (PDT)
X-Received: by 2002:a2e:9857:: with SMTP id e23mr71036ljj.78.1615920431577;
        Tue, 16 Mar 2021 11:47:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615920431; cv=none;
        d=google.com; s=arc-20160816;
        b=S6jEncmyXkdQ8B5c8SZcZyg3kwFiy4AuK9+MFF10zXUWo+j4aAK0DZpsA/CLIXM+VQ
         0d4v9E4HCT83G1nZAirZw9Uh73KyUvikBFoKqtGEVumJjn23yxce7rj2clGpMV6q0n6W
         xqtXXl+W5JhQGGVnsty3DceHax0kFTtZRii/MkgIWFPRSFoHIO5mwqk5KtIvVg5Wo9jC
         bRDT+GnwRDIT17EY3LsAQYU2f70HzwjdD50/DdrmCnG7bY4qFVN8bpyc90ciGU3DVrVj
         kmhyTbnP7QVAVpB0WJEltxWsaOBrO/uFjigtBixkNwqOaiflXCNySPSHV2TvMmPrjnGo
         xKbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/z2fIfiSMbNLDzKmZ65SrMYqzt+vbhT5AuPhg7JmU1A=;
        b=QmAJYMRnzsngHbohjXzr6vE8BxY5OHjOjEMMW4t+9i8yVVvoR9xrktdC7aTZmG/LXK
         iJC3+YE6YOXBWGyt1+0dZIRNJf3npQQIOYxxnURU1IA1W/zXKa2D22qIkBPYT7SCN+cr
         RhnmpkfOmFjCaw5j5hyAo03IAVK5bVgGJX5vrkD320HEHcebUslNyg4PY6+VPR3i3KDT
         I89PWORwaL70Nlzx8QMEoFQIRCOocDHlX6cep0qBcsArZm5zzqGP1hiAYR7I9bm16PHA
         lcFna+dBcU1kJyhVNwdWTncVGgJvS73Wej2eiZ/nAGBbq4ThM8rBAPiYHwIA1kofHH0/
         1bWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rM3fdiR9;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id x41si504804lfu.10.2021.03.16.11.47.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Mar 2021 11:47:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id o14so7223544wrm.11
        for <kasan-dev@googlegroups.com>; Tue, 16 Mar 2021 11:47:11 -0700 (PDT)
X-Received: by 2002:adf:83c2:: with SMTP id 60mr438331wre.386.1615920430858;
        Tue, 16 Mar 2021 11:47:10 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:1d09:9676:5eaa:550])
        by smtp.gmail.com with ESMTPSA id 12sm191075wmw.43.2021.03.16.11.47.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Mar 2021 11:47:10 -0700 (PDT)
Date: Tue, 16 Mar 2021 19:47:00 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Luis Henriques <lhenriques@suse.de>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: Issue with kfence and kmemleak
Message-ID: <YFD9JEdQNI1TqSuL@elver.google.com>
References: <YFDf6iKH1p/jGnM0@suse.de>
 <YFDrGL45JxFHyajD@elver.google.com>
 <20210316181938.GA28565@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210316181938.GA28565@arm.com>
User-Agent: Mutt/2.0.5 (2021-01-21)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rM3fdiR9;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, Mar 16, 2021 at 06:19PM +0000, Catalin Marinas wrote:
> On Tue, Mar 16, 2021 at 06:30:00PM +0100, Marco Elver wrote:
> > On Tue, Mar 16, 2021 at 04:42PM +0000, Luis Henriques wrote:
> > > This is probably a known issue, but just in case: looks like it's not
> > > possible to use kmemleak when kfence is enabled:
> > > 
> > > [    0.272136] kmemleak: Cannot insert 0xffff888236e02f00 into the object search tree (overlaps existing)
> > > [    0.272136] CPU: 0 PID: 8 Comm: kthreadd Not tainted 5.12.0-rc3+ #92
> > > [    0.272136] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a-rebuilt.opensuse.org 04/01/2014
> > > [    0.272136] Call Trace:
> > > [    0.272136]  dump_stack+0x6d/0x89
> > > [    0.272136]  create_object.isra.0.cold+0x40/0x62
> > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > [    0.272136]  kmem_cache_alloc_trace+0x110/0x2f0
> > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > [    0.272136]  kthread+0x3f/0x150
> > > [    0.272136]  ? lockdep_hardirqs_on_prepare+0xd4/0x170
> > > [    0.272136]  ? __kthread_bind_mask+0x60/0x60
> > > [    0.272136]  ret_from_fork+0x22/0x30
> > > [    0.272136] kmemleak: Kernel memory leak detector disabled
> > > [    0.272136] kmemleak: Object 0xffff888236e00000 (size 2097152):
> > > [    0.272136] kmemleak:   comm "swapper", pid 0, jiffies 4294892296
> > > [    0.272136] kmemleak:   min_count = 0
> > > [    0.272136] kmemleak:   count = 0
> > > [    0.272136] kmemleak:   flags = 0x1
> > > [    0.272136] kmemleak:   checksum = 0
> > > [    0.272136] kmemleak:   backtrace:
> > > [    0.272136]      memblock_alloc_internal+0x6d/0xb0
> > > [    0.272136]      memblock_alloc_try_nid+0x6c/0x8a
> > > [    0.272136]      kfence_alloc_pool+0x26/0x3f
> > > [    0.272136]      start_kernel+0x242/0x548
> > > [    0.272136]      secondary_startup_64_no_verify+0xb0/0xbb
> > > 
> > > I've tried the hack below but it didn't really helped.  Obviously I don't
> > > really understand what's going on ;-)  But I think the reason for this
> > > patch not working as (I) expected is because kfence is initialised
> > > *before* kmemleak.
> > > 
> > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > index 3b8ec938470a..b4ffd7695268 100644
> > > --- a/mm/kfence/core.c
> > > +++ b/mm/kfence/core.c
> > > @@ -631,6 +631,9 @@ void __init kfence_alloc_pool(void)
> > >  
> > >  	if (!__kfence_pool)
> > >  		pr_err("failed to allocate pool\n");
> > > +	kmemleak_no_scan(__kfence_pool);
> > >  }
> > 
> > Can you try the below patch?
> > 
> > Thanks,
> > -- Marco
> > 
> > ------ >8 ------
> > 
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index f7106f28443d..5891019721f6 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -12,6 +12,7 @@
> >  #include <linux/debugfs.h>
> >  #include <linux/kcsan-checks.h>
> >  #include <linux/kfence.h>
> > +#include <linux/kmemleak.h>
> >  #include <linux/list.h>
> >  #include <linux/lockdep.h>
> >  #include <linux/memblock.h>
> > @@ -481,6 +482,13 @@ static bool __init kfence_init_pool(void)
> >  		addr += 2 * PAGE_SIZE;
> >  	}
> >  
> > +	/*
> > +	 * The pool is live and will never be deallocated from this point on;
> > +	 * tell kmemleak this is now free memory, so that later allocations can
> > +	 * correctly be tracked.
> > +	 */
> > +	kmemleak_free_part_phys(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> 
> I presume this pool does not refer any objects that are only tracked
> through pool pointers.

No, at this point this memory should not have been touched by anything.

> kmemleak_free() (or *_free_part) should work, no need for the _phys
> variant (which converts it back with __va).

Will fix.

> Since we normally use kmemleak_ignore() (or no_scan) for objects we
> don't care about, I'd expand the comment that this object needs to be
> removed from the kmemleak object tree as it will overlap with subsequent
> allocations handled by kfence which return pointers within this range.

One thing I've just run into: "BUG: KFENCE: out-of-bounds read in
scan_block+0x6b/0x170 mm/kmemleak.c:1244"

Probably because kmemleak is passed the rounded size for the size-class,
and not the real allocation size. Can this be fixed with
kmemleak_ignore() only called on the KFENCE guard pages?

I'd like kmemleak to scan the valid portion of an object allocated
through KFENCE, but no further than that.

Or do we need to fix the size if it's a kfence object:

diff --git a/mm/kmemleak.c b/mm/kmemleak.c
index c0014d3b91c1..fe6e3ae8e8c6 100644
--- a/mm/kmemleak.c
+++ b/mm/kmemleak.c
@@ -97,6 +97,7 @@
 #include <linux/atomic.h>
 
 #include <linux/kasan.h>
+#include <linux/kfence.h>
 #include <linux/kmemleak.h>
 #include <linux/memory_hotplug.h>
 
@@ -589,7 +590,7 @@ static struct kmemleak_object *create_object(unsigned long ptr, size_t size,
 	atomic_set(&object->use_count, 1);
 	object->flags = OBJECT_ALLOCATED;
 	object->pointer = ptr;
-	object->size = size;
+	object->size = kfence_ksize((void *)ptr) ?: size;
 	object->excess_ref = 0;
 	object->min_count = min_count;
 	object->count = 0;			/* white color initially */


The alternative is to call kfence_ksize() in slab_post_alloc_hook() when
calling kmemleak_alloc.

Do you have a preference?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YFD9JEdQNI1TqSuL%40elver.google.com.
