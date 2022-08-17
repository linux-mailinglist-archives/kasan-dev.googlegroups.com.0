Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBTOI6SLQMGQEFVZYNGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id ADECE5974FF
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 19:24:31 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id s22-20020a056a00195600b0052ece6c829fsf5236238pfk.6
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 10:24:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660757070; cv=pass;
        d=google.com; s=arc-20160816;
        b=NYFEKLryriFw8DhuZzcnyI2yn+JT5bwODtQpF2iSOe8wfMIXu/pVqihVI67EV66c8u
         8uokO+omeXBafmaXdDANKhvVEfQXnjjpg9+LPXNNBz67sGKVPjukr0A4mxVZqLkuPRJm
         q3sWenBgIWfmLWhplOniRR9fVNtCBrUZpA2+kDTm0/J9ORMO9q6LDyZA0jGNUlS7Itaw
         Kaz2PaXD4xAjxAT8zhT/Puo1wgrbKWuuItqkXkEFMIBWtgAIyWSccYW1vqZGeLYOq0of
         3s73EFpratP/151UYVgUr+OmsmrMUtqGncLsr4WhbkqK7R7tRZN78Hbh95rzySJuuQkK
         rvHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HABE8b4OfaBRAV4SonBh4SQXMPeF5uorY0t71zXChUY=;
        b=Knu+QSQmOZXW5QxNw2JwqDokAqiABBXJqqILSFd8eJvDrrWnxDllp01+t9HS3z1+Nl
         g6oqxQuVMFuzLD7S9TR475ZhZtcsn2MC/Py8+s9qSZc7tEPBTaV9/nYvhzN8jVqocNo0
         MW1YAKCUve0WALAnabG9ucPpJ4pYFxdAbzHrauCtKrDDahSokEHapcgFTYCjNxv9qM6R
         VI4ImgLj3WBh4BuqL1V2EuzjIgxB2iCWddNlYrd1nyvfsGOAFOnket5wwf1V5aj8mX9o
         ppx1ZGxPzvtzrXsITMHC0Kdmfv/rGYbtcFd7BGUZXC6CmxITzB0BdbhEoxgaA/86cRhq
         Mizg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=Uk33DHdV;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=HABE8b4OfaBRAV4SonBh4SQXMPeF5uorY0t71zXChUY=;
        b=Bkq/P3dwc0NN49EOTn+RWC5WJx+7iQJqw1DRy75UuoK2DAOOv3LgoHUAWG5Z3cwG9+
         qW7tuCi+aoEpZ0TbHnOzrLHwunbPcAmQ9YAs22vM2JF5RjWy/EG1ePSvz9qbJLeErDXG
         qQXHXDMYuwL74DALjFRQOLNTANPdu4xXhcx5cy+ReU1E55VI3NAYWd7KQF7FC8YjdJ7L
         bu7BtqZAP9rmIXwO3bwY6s3KOe4r9hIjX+E50dUeo0/JaQLgGY5w1cBx3TmBhayUhvUd
         clLp90HwbBjBVqqqGxG0Mmgo14TCNdC6ETQ8Gmlob2adYlo4jm95bFsr+WS5A5A4k+Ph
         iT7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=HABE8b4OfaBRAV4SonBh4SQXMPeF5uorY0t71zXChUY=;
        b=1IuTyuYecvwREwVg/V1aTMDPq73mYh+Dh7wFULk61DauiknKn/98G7UZzEpb+iqJP4
         SjGuGrOUhjg6kBsBcWVVKQQJYEBfSOcWoZcVioB71Dib2riuv7ovbwxAGYwuItj6jK5I
         DJrgACYZBp6k5TLMFCmCUGIB1LC50hxzG9sJH41IA6guGwW5MqpMyLXp8ad3MuA6MEhe
         Raoy50FET9T7nW9lgWTPuXcoygwShHQbM3hLoiCeZJktLFMapazu5uFQovFziEydo/xV
         HqBpmRgc3ABycOinXejYxyi8Gmqnc9X/Zvv5cHO81GC9OfKgfVAUQGqTRQtNB2GeOZxa
         kPvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0dOQs0FUqnZfBJwO+v6pYwahow9gLD5FIpqyxT2eNl0lJawT4o
	qXlih6sRLK8AQNYmKY7Pl5E=
X-Google-Smtp-Source: AA6agR7P3ufMbSiEQH6XZAGAjNGenkTIXVToJqiQDhiwnmMjZ9Z3x0OZ1GQN735dikIvcFVTiE6nLA==
X-Received: by 2002:a17:902:e8d8:b0:172:7e6b:c8ec with SMTP id v24-20020a170902e8d800b001727e6bc8ecmr7978718plg.171.1660757069960;
        Wed, 17 Aug 2022 10:24:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e78a:b0:16d:82eb:cc57 with SMTP id
 cp10-20020a170902e78a00b0016d82ebcc57ls10560897plb.11.-pod-prod-gmail; Wed,
 17 Aug 2022 10:24:29 -0700 (PDT)
X-Received: by 2002:a17:902:8f87:b0:172:83b5:d771 with SMTP id z7-20020a1709028f8700b0017283b5d771mr7712402plo.159.1660757069163;
        Wed, 17 Aug 2022 10:24:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660757069; cv=none;
        d=google.com; s=arc-20160816;
        b=zSw2ZVrv77mTdlkDdismS5bTjZIsgvCQC0TuJdj5t0RAXFIudndkkShXGPIEQHTeZM
         nuJITDfx7deCvimGb/KzAw8ubYuRG1LHurGR+jAAK66tvNJbN9dUhx+9eudgX7WNuSAm
         a4efqNHBuG3Em9PfvAf95DmwoNUD5XS6d69ls41UlB8gCealykwetYQWMivMOFN8HtVa
         GCT3YfAcr4lvXzDjbIxW1UJIjn73blPcdmp8LMR+gbP4AaQ74wWiHlPfC8F7D50h6/w1
         m4GGXgvDNt1Schud30hqIXl2HRpvsro+L3uwgqylhhei/4WB+hkez7NoDfpHrW9kj4BM
         O/KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vLaPO5doVC7HHM7jnBeiSMKGX2zBCQhfl8h75emFA4o=;
        b=FEO3O7ivY0KIjcBiweYV1+fdvjuc43a46CF/shYQAXEAU7uJfleBEC1sYUu93VgEwD
         P8XrZi8BxTy1Y1xR1WiKIgM1vPh3iwt9AR7dAtwYl6ajjiXKu1juktKlmdXAvv9+4TjS
         dHspaMkPGrG00DvpkGhKxOOMKCv6o+4l/8muhnKUV24Nuj6+MwvfqX+Vy4eYK3HHgZvd
         yKAKCJWKteA/Tt+5aCFIB89rpW3fP4++yVshdpZtIUlNnUnWZrkazIe5/lkt3wm+ZP0k
         oGijF4+T6rEOvYLN8DajECQ5LMWNXuGmO11jHLHFdF2fHwbYrzIrs4iIXQIZ5b7X5Y6n
         aZoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=Uk33DHdV;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id e18-20020a17090301d200b0016d3382bc9asi26193plh.0.2022.08.17.10.24.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 10:24:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 27358CE1E23;
	Wed, 17 Aug 2022 17:24:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id ED61DC433C1;
	Wed, 17 Aug 2022 17:24:24 +0000 (UTC)
Date: Wed, 17 Aug 2022 19:24:23 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Marco Elver <elver@google.com>
Cc: stable@vger.kernel.org, Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Will Deacon <will@kernel.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Yee Lee <yee.lee@mediatek.com>, Max Schulze <max.schulze@online.de>
Subject: Re: [PATCH 5.19.y] Revert "mm: kfence: apply kmemleak_ignore_phys on
 early allocated pool"
Message-ID: <Yv0kRz2AmDX8jmBW@kroah.com>
References: <20220816163641.2359996-1-elver@google.com>
 <CANpmjNP0TMenugBVCqCYLT4AGCTH80RafcmgQRN7X8SzGjoQ6g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP0TMenugBVCqCYLT4AGCTH80RafcmgQRN7X8SzGjoQ6g@mail.gmail.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=Uk33DHdV;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Tue, Aug 16, 2022 at 06:42:46PM +0200, Marco Elver wrote:
> On Tue, 16 Aug 2022 at 18:37, Marco Elver <elver@google.com> wrote:
> >
> > This reverts commit 07313a2b29ed1079eaa7722624544b97b3ead84b.
> >
> > Commit 0c24e061196c21d5 ("mm: kmemleak: add rbtree and store physical
> > address for objects allocated with PA") is not yet in 5.19 (but appears
> > in 6.0). Without 0c24e061196c21d5, kmemleak still stores phys objects
> > and non-phys objects in the same tree, and ignoring (instead of freeing)
> > will cause insertions into the kmemleak object tree by the slab
> > post-alloc hook to conflict with the pool object (see comment).
> >
> > Reports such as the following would appear on boot, and effectively
> > disable kmemleak:
> >
> >  | kmemleak: Cannot insert 0xffffff806e24f000 into the object search tree (overlaps existing)
> >  | CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.19.0-v8-0815+ #5
> >  | Hardware name: Raspberry Pi Compute Module 4 Rev 1.0 (DT)
> >  | Call trace:
> >  |  dump_backtrace.part.0+0x1dc/0x1ec
> >  |  show_stack+0x24/0x80
> >  |  dump_stack_lvl+0x8c/0xb8
> >  |  dump_stack+0x1c/0x38
> >  |  create_object.isra.0+0x490/0x4b0
> >  |  kmemleak_alloc+0x3c/0x50
> >  |  kmem_cache_alloc+0x2f8/0x450
> >  |  __proc_create+0x18c/0x400
> >  |  proc_create_reg+0x54/0xd0
> >  |  proc_create_seq_private+0x94/0x120
> >  |  init_mm_internals+0x1d8/0x248
> >  |  kernel_init_freeable+0x188/0x388
> >  |  kernel_init+0x30/0x150
> >  |  ret_from_fork+0x10/0x20
> >  | kmemleak: Kernel memory leak detector disabled
> >  | kmemleak: Object 0xffffff806e24d000 (size 2097152):
> >  | kmemleak:   comm "swapper", pid 0, jiffies 4294892296
> >  | kmemleak:   min_count = -1
> >  | kmemleak:   count = 0
> >  | kmemleak:   flags = 0x5
> >  | kmemleak:   checksum = 0
> >  | kmemleak:   backtrace:
> >  |      kmemleak_alloc_phys+0x94/0xb0
> >  |      memblock_alloc_range_nid+0x1c0/0x20c
> >  |      memblock_alloc_internal+0x88/0x100
> >  |      memblock_alloc_try_nid+0x148/0x1ac
> >  |      kfence_alloc_pool+0x44/0x6c
> >  |      mm_init+0x28/0x98
> >  |      start_kernel+0x178/0x3e8
> >  |      __primary_switched+0xc4/0xcc
> >
> > Reported-by: Max Schulze <max.schulze@online.de>
> > Signed-off-by: Marco Elver <elver@google.com>
> 
> The discussion is:
> 
> Link: https://lore.kernel.org/all/b33b33bc-2d06-1bcd-2df7-43678962b728@online.de/
> 
> > ---
> >  mm/kfence/core.c | 18 +++++++++---------
> >  1 file changed, 9 insertions(+), 9 deletions(-)
> >
> > diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> > index 6aff49f6b79e..4b5e5a3d3a63 100644
> > --- a/mm/kfence/core.c
> > +++ b/mm/kfence/core.c
> > @@ -603,6 +603,14 @@ static unsigned long kfence_init_pool(void)
> >                 addr += 2 * PAGE_SIZE;
> >         }
> >
> > +       /*
> > +        * The pool is live and will never be deallocated from this point on.
> > +        * Remove the pool object from the kmemleak object tree, as it would
> > +        * otherwise overlap with allocations returned by kfence_alloc(), which
> > +        * are registered with kmemleak through the slab post-alloc hook.
> > +        */
> > +       kmemleak_free(__kfence_pool);
> > +
> >         return 0;
> >  }
> >
> > @@ -615,16 +623,8 @@ static bool __init kfence_init_pool_early(void)
> >
> >         addr = kfence_init_pool();
> >
> > -       if (!addr) {
> > -               /*
> > -                * The pool is live and will never be deallocated from this point on.
> > -                * Ignore the pool object from the kmemleak phys object tree, as it would
> > -                * otherwise overlap with allocations returned by kfence_alloc(), which
> > -                * are registered with kmemleak through the slab post-alloc hook.
> > -                */
> > -               kmemleak_ignore_phys(__pa(__kfence_pool));
> > +       if (!addr)
> >                 return true;
> > -       }
> >
> >         /*
> >          * Only release unprotected pages, and do not try to go back and change
> > --
> > 2.37.1.595.g718a3a8f04-goog
> >

Now queued up, thanks.

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yv0kRz2AmDX8jmBW%40kroah.com.
