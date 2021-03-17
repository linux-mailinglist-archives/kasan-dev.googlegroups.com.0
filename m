Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZMEY6BAMGQECCSN5RY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 05A9C33EBD2
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 09:48:39 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id j7sf21642937pfa.14
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 01:48:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615970917; cv=pass;
        d=google.com; s=arc-20160816;
        b=emT+FM2OXdHkEBgW+w+Zs4k2RJ5ilqo0Xd0PvVoQ96neSgmXD2C/iQy14t2WM5nF3x
         KBWcoKBCUZiuS53a+LHjQHaMWv/GOzhYg235HaMut5axLjzvrxSV0aCxT0EwQq7MRSFA
         MDCyO5lDFynt7D4wokItf3uzbWdstsu1CVK8/Dx4V+X8Wz5+J1NB96n7Ia9ZlNZl7qzJ
         S80rI5Gax/Yy4yQQU1f1BK2XrGTHtRo2UZmZeFC6IFZgXFkRiy+80bIk5RF4hBimFoeZ
         QbKyw8AyZ9x0GAe7Yh3nW5YQdTb586iZmx/hdw+WABNeXvNm32QKUVt6g5XWHOoCmTqq
         g8vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xTtx68ryY5mo6d3rcaWEPDARiJk++I3nRR/d5dh8jXk=;
        b=GFDNUDQour146vOOltAzDlkQhDoastwV5Kvjvn/xOIjxWZAvhPIQuaMKnvFTO0oNlh
         TM1lGBycNETKb+oxFjZHccXufy6WRXh6xv/rZFX5ZR3PNTw1ebLRZjm6hlKunlUUDLMo
         9HkgBlLpT2LbgTwFFFM3JgEEefWRVwHKLaFkWJ7CTMdOi3+/+PLZrCOd/63pHntQuvX0
         QEfmG9FCChA85Q4DZvD6w8aZOgG2EQwhL0TeQMcjSQWSs7/a2L9mQoAoB4zX8O9O/QBk
         sBNq30bx8AHjHO4PGyl0X9ruRgVQ58RyLfv/tmJ9+Fjc9YhMg4O768EehXii0jxg9GU7
         lOWg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UpCpQm6q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xTtx68ryY5mo6d3rcaWEPDARiJk++I3nRR/d5dh8jXk=;
        b=XV4G860xhcntyGSlZ3+KBJZGrMiFGgkTbq+2Eq2hLdoi+U7CEVKDgk9CQ/sguxgmI9
         4Ll5S6v12rZV3Zefg8mvBqj7bTwTgIpSxm0NNAMu10f1Xu0RfeDu3LfZopvKIpyq6CyW
         1SFczVcenfuDA8YLtoWaU6skf/Ev96W92z4e/Fr0Pi6usr/cRFJMihLh5pQx9pM2NPAp
         JNlHQLFbuIQrexjkLaAWn0U2kuqSqJDGNDXH/rVftdLO8rf9B1NX1nreYrDAwd4f8HXs
         EmedsBPzf+h0pLy9DT8TRLBVltF2e/2Tn6/o88cQKFFtqBHxjsMz1paibiNaqlQsmcQN
         wA4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xTtx68ryY5mo6d3rcaWEPDARiJk++I3nRR/d5dh8jXk=;
        b=ID2qmKA81n0riezKZctALF4R78BAHAw2Qh+/p5tD16ox/axNbKyHH46mk83bNQPEj2
         DuIbh9RePp4uRLWIf4UzfKixSrN9Lv+XoYJsJVV9b7ydhR1xsP9e0ONLG82z8Qn+HElo
         hQSPOgrLJ5YWdIy+cPHzu3E0QhNIpcmhxYpyC4x2fX26yTpIYKHaGlXUAFD/VNdUZ89H
         q/BJvNtEDAbi2oqDny26/aOJwBepfrxPxnio7jXLx+oDOU8ma/GnOsDKlGfDZfSLGDnY
         BHZE+SzjkJ2p3Wnx3W7GipsJV/wyiJ3jeycCZsgFNWMC7lUyrDSj7QTmE99UjgLiq4Wl
         7/1A==
X-Gm-Message-State: AOAM532MBx6/dmk4XV9RuTqbUGkm55Je/4JyeLJneAz7TdZF1CFKwlyw
	rkF65Acssnb5L75xYZBObIo=
X-Google-Smtp-Source: ABdhPJwxJwA2ZLWnNJs+2UOUwdzKoXq1u33Y7NnYuN8VML2NncV5ff6CsocCLSxZwt7dvHglhM1J0w==
X-Received: by 2002:a17:902:9894:b029:e5:ce48:5808 with SMTP id s20-20020a1709029894b02900e5ce485808mr3385554plp.31.1615970917531;
        Wed, 17 Mar 2021 01:48:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:9106:: with SMTP id k6ls1359754pjo.0.canary-gmail;
 Wed, 17 Mar 2021 01:48:37 -0700 (PDT)
X-Received: by 2002:a17:90b:e0d:: with SMTP id ge13mr3614081pjb.1.1615970916938;
        Wed, 17 Mar 2021 01:48:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615970916; cv=none;
        d=google.com; s=arc-20160816;
        b=xNU1GxzHHKqfCLUPYvlHiaY8pXN57GICGQfmzHHlz/wmRNmOOynWNwlJCtWAZJk0QE
         0O2BNvFMtMZX3NvZlXXAO7koz6+c4vFPQ+3ilypWgnIez+qsotXo9J+lUw8d8kt/DY7W
         LlnCcK5++1dshRaFAuale0rR2TLMA1YWJ9SsYzxL07GvB2YJ+DqNgLIML8+e6kdCScj7
         T9VKWJUXehkphMYlTh6kYGAT4HevLgxTp+U6/ftVLlqpcTEn4Q0xfcCRctJbog79e4EB
         bbKV4NR5PqITkPzDQ8HEiDU1VROkuiJGXILF1mUr/mMeLODbpxzFTnbm32wL/TwM9qo5
         KofA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I2lDZOKUu2tocdd1TqzDB8RH8osZOQXjtwD5b7bHNt4=;
        b=KSSK7w7C9bUXjjIAznDCJUeWNGBqOJGBtXjMXYSLna6v4qJakzA6MLIRSb8g4OUvis
         ug7duMFs12fQmo47JL6OJCZP3DJI4Qp3YIQsobzKH5jbxGLAZS/NYDqUU+2GUpmNWcgw
         FCjOgnc23NKwUUdLsVCWOmf4nPyLENPQgxUOsFmx4Noj2z7/vbmO/FUxVbZR61R+7Qrd
         jOd4gFe8r40x/zel35iY9Xb5EqTpui/+9DUUsqQpkZia+7tT0/rBE1d/KlmKVLuNXqD4
         0XAvIVj3u9gwSPCeTZYcRLBHGUkUutv0HkGz2yC+5TbzocLUIGBFSWR9ICOL6elxPiS9
         Si9Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UpCpQm6q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x229.google.com (mail-oi1-x229.google.com. [2607:f8b0:4864:20::229])
        by gmr-mx.google.com with ESMTPS id y17si631414plr.4.2021.03.17.01.48.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Mar 2021 01:48:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as permitted sender) client-ip=2607:f8b0:4864:20::229;
Received: by mail-oi1-x229.google.com with SMTP id t83so31033383oih.12
        for <kasan-dev@googlegroups.com>; Wed, 17 Mar 2021 01:48:36 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr1990854oif.121.1615970916125;
 Wed, 17 Mar 2021 01:48:36 -0700 (PDT)
MIME-Version: 1.0
References: <YFDf6iKH1p/jGnM0@suse.de> <YFDrGL45JxFHyajD@elver.google.com>
 <20210316181938.GA28565@arm.com> <YFD9JEdQNI1TqSuL@elver.google.com> <YFHApOWeDRWncdrQ@suse.de>
In-Reply-To: <YFHApOWeDRWncdrQ@suse.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 17 Mar 2021 09:48:24 +0100
Message-ID: <CANpmjNMxg-unHe2C5BaW1yaSpLOvms6rn2beFz04EwB_UepDfg@mail.gmail.com>
Subject: Re: Issue with kfence and kmemleak
To: Luis Henriques <lhenriques@suse.de>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UpCpQm6q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::229 as
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

On Wed, 17 Mar 2021 at 09:39, Luis Henriques <lhenriques@suse.de> wrote:
> On Tue, Mar 16, 2021 at 07:47:00PM +0100, Marco Elver wrote:
> > On Tue, Mar 16, 2021 at 06:19PM +0000, Catalin Marinas wrote:
> > > On Tue, Mar 16, 2021 at 06:30:00PM +0100, Marco Elver wrote:
> > > > On Tue, Mar 16, 2021 at 04:42PM +0000, Luis Henriques wrote:
> > > > > This is probably a known issue, but just in case: looks like it's not
> > > > > possible to use kmemleak when kfence is enabled:
> > > > >
> > > > > [    0.272136] kmemleak: Cannot insert 0xffff888236e02f00 into the object search tree (overlaps existing)
> > > > > [    0.272136] CPU: 0 PID: 8 Comm: kthreadd Not tainted 5.12.0-rc3+ #92
> > > > > [    0.272136] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.14.0-0-g155821a-rebuilt.opensuse.org 04/01/2014
> > > > > [    0.272136] Call Trace:
> > > > > [    0.272136]  dump_stack+0x6d/0x89
> > > > > [    0.272136]  create_object.isra.0.cold+0x40/0x62
> > > > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > > > [    0.272136]  kmem_cache_alloc_trace+0x110/0x2f0
> > > > > [    0.272136]  ? process_one_work+0x5a0/0x5a0
> > > > > [    0.272136]  kthread+0x3f/0x150
> > > > > [    0.272136]  ? lockdep_hardirqs_on_prepare+0xd4/0x170
> > > > > [    0.272136]  ? __kthread_bind_mask+0x60/0x60
> > > > > [    0.272136]  ret_from_fork+0x22/0x30
> > > > > [    0.272136] kmemleak: Kernel memory leak detector disabled
> > > > > [    0.272136] kmemleak: Object 0xffff888236e00000 (size 2097152):
> > > > > [    0.272136] kmemleak:   comm "swapper", pid 0, jiffies 4294892296
> > > > > [    0.272136] kmemleak:   min_count = 0
> > > > > [    0.272136] kmemleak:   count = 0
> > > > > [    0.272136] kmemleak:   flags = 0x1
> > > > > [    0.272136] kmemleak:   checksum = 0
> > > > > [    0.272136] kmemleak:   backtrace:
> > > > > [    0.272136]      memblock_alloc_internal+0x6d/0xb0
> > > > > [    0.272136]      memblock_alloc_try_nid+0x6c/0x8a
> > > > > [    0.272136]      kfence_alloc_pool+0x26/0x3f
> > > > > [    0.272136]      start_kernel+0x242/0x548
> > > > > [    0.272136]      secondary_startup_64_no_verify+0xb0/0xbb
> > > > >
> > > > > I've tried the hack below but it didn't really helped.  Obviously I don't
> > > > > really understand what's going on ;-)  But I think the reason for this
> > > > > patch not working as (I) expected is because kfence is initialised
> > > > > *before* kmemleak.
> > > > >
> > > > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > > > index 3b8ec938470a..b4ffd7695268 100644
> > > > > --- a/mm/kfence/core.c
> > > > > +++ b/mm/kfence/core.c
> > > > > @@ -631,6 +631,9 @@ void __init kfence_alloc_pool(void)
> > > > >
> > > > >         if (!__kfence_pool)
> > > > >                 pr_err("failed to allocate pool\n");
> > > > > +       kmemleak_no_scan(__kfence_pool);
> > > > >  }
> > > >
> > > > Can you try the below patch?
> > > >
> > > > Thanks,
> > > > -- Marco
> > > >
> > > > ------ >8 ------
> > > >
> > > > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > > > index f7106f28443d..5891019721f6 100644
> > > > --- a/mm/kfence/core.c
> > > > +++ b/mm/kfence/core.c
> > > > @@ -12,6 +12,7 @@
> > > >  #include <linux/debugfs.h>
> > > >  #include <linux/kcsan-checks.h>
> > > >  #include <linux/kfence.h>
> > > > +#include <linux/kmemleak.h>
> > > >  #include <linux/list.h>
> > > >  #include <linux/lockdep.h>
> > > >  #include <linux/memblock.h>
> > > > @@ -481,6 +482,13 @@ static bool __init kfence_init_pool(void)
> > > >           addr += 2 * PAGE_SIZE;
> > > >   }
> > > >
> > > > + /*
> > > > +  * The pool is live and will never be deallocated from this point on;
> > > > +  * tell kmemleak this is now free memory, so that later allocations can
> > > > +  * correctly be tracked.
> > > > +  */
> > > > + kmemleak_free_part_phys(__pa(__kfence_pool), KFENCE_POOL_SIZE);
> > >
> > > I presume this pool does not refer any objects that are only tracked
> > > through pool pointers.
> >
> > No, at this point this memory should not have been touched by anything.
> >
> > > kmemleak_free() (or *_free_part) should work, no need for the _phys
> > > variant (which converts it back with __va).
> >
> > Will fix.
> >
> > > Since we normally use kmemleak_ignore() (or no_scan) for objects we
> > > don't care about, I'd expand the comment that this object needs to be
> > > removed from the kmemleak object tree as it will overlap with subsequent
> > > allocations handled by kfence which return pointers within this range.
> >
> > One thing I've just run into: "BUG: KFENCE: out-of-bounds read in
> > scan_block+0x6b/0x170 mm/kmemleak.c:1244"
>
> FWIW, I just saw this as well.  It doesn't happen every time, but yeah I
> missed it in my initial testing.

I've just sent the patch, please re-test if you can:
https://lkml.kernel.org/r/20210317084740.3099921-1-elver@google.com

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMxg-unHe2C5BaW1yaSpLOvms6rn2beFz04EwB_UepDfg%40mail.gmail.com.
