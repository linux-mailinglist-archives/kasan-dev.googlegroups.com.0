Return-Path: <kasan-dev+bncBD7JD3WYY4BBBV4P2SCQMGQEWYKSRKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6653739647C
	for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 17:59:20 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id p6-20020a92d6860000b02901bb4be9e3c1sf8298834iln.11
        for <lists+kasan-dev@lfdr.de>; Mon, 31 May 2021 08:59:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622476759; cv=pass;
        d=google.com; s=arc-20160816;
        b=h59gzz7f4Wi+PUQvNN9lvgdWeo/N5ObvE2BXdlMI3xG8HhocXsf21Vf6imFD6vopha
         JDHlTzxOW3ucDUzoQqqqkoizuveFPIIMRzwJcN8FMpuqimO1sw58zlDKv+TootjvtEPd
         NZkVLA+OHKhmFZ/qy0xo5neLQdtruA36Czh9GY8r+Wdmwvdi7X6AFJJ/Gc8uiumC058Q
         KVfbCjvhaoJpqiWIU5y7HcQUAdPGrB2/v/AcOYRRKlDwvxUzLVDb6NoZz4pOKDB/FyQ2
         ZG488rzSG8WOrCI0XM9ZqHJ4DtlvgvzfnAcLAwMlb/JgBcKz4F/37x7C7Fp/7l1I99fb
         NG9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=itLx36PQSBVPRI53TCnkEcuRrKWcpP/WXHKcaqkJNEk=;
        b=ELxKH5ZUDutF2wvVvAUyQH3U2sut+m8CxrVZs0Te9cvvuCKTocn/y3yhgWrpb8iq5V
         QQgK8WAtT35plTxVdapmFAsHXPnpwTuNSRRunrx3UtAvcWE5dV/tOa14DNShunka6TCG
         C0bC22arKk0dzscFEF3QJb0pWtueRVp5E2RNtWjnar8o+nYgudpWKhzr9DTvKZO8WGR8
         GU6XMffEtMbgC+uVYaN+n9XMARZb2E5gwyD0ck+IWLoWYIudbfOVsF2hWPHSP+Zte+CV
         Gq2qwQ702NMXzx+LjMSOU0KQNZsJxXSZul7rbAd23pGZ9mUizE652VjTxxb8D+B+zpMR
         J6Ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vFmuMxLR;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=itLx36PQSBVPRI53TCnkEcuRrKWcpP/WXHKcaqkJNEk=;
        b=hj2FojqTMkAr2CaGZPQSI9ZX80ndRtqdACjecNornO4a5tckaU/8WB24ymtznZ7qXN
         kZzVkTUGqGRqk6AdJQiD7KhjyqCkmy99UTFgHJm5ATp+Jo5zJuazO3ZRK2VaiDSXtrn5
         ih7sZfLdH/jxHOETdE3dKbhp3BGXC0KICp71WPur2sK6l1XTfmA0gJ6u/U30zYAAoO8c
         jWXBH/JnCbZQjKs/7pP/0OM4vwLHf3L7wzwWUyCNIYSev2ooP73Srb14VPOoeoUjNJaK
         XYUt9DmkkolDBrhVZCgYTdLp010KkbOUj/ZMwCv3JMl8ZIohM18F98fHLdVnkN0/4lHg
         dMtw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=itLx36PQSBVPRI53TCnkEcuRrKWcpP/WXHKcaqkJNEk=;
        b=kOXmNmucrJQymSGmLXpvsZQs/1lR9UBHNP+ywLJ+mfyqlazlVnfTzASLWpf4/iWjOe
         yCAJzWmHYBcPhS9BvIo7BQvnrVBVBYCt4bRki4AlYGRGPxhm5lRy2UmkPnVAHiOnehbP
         nBL8LS/mK494LSFssbqnIrP3BYH5WTydPL9RfeYBqa0avhtkLdzDnl8R5XZU3Nct5Rk8
         K+Us8g4ZN925r4Bi1FNpQ+cXKvg82fcdNGOLKwIzYOab3Yv8fKj2+AA1p0RK1ICE/Ss6
         SDz5i2U5azlO+boHNHlnGkGyknvoa6r9Vq0fYpKG60jHPujVD/vrePTCJdzWpoZukNgc
         +qxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=itLx36PQSBVPRI53TCnkEcuRrKWcpP/WXHKcaqkJNEk=;
        b=bp0BdpvNR+NlcN6JMzQjRduq1H8lHWxryZSl5YwZUB812odh+8etEV35UUh3IdkewG
         yLOr1rmS0ZBH6G2XREtI9JSwwBSKRSv7cg7Z8XDx2E0cMG/roAOElM+7hhrCr7jd+dWH
         iVIWQ/hAi3m/ZDBhmGstpnRftK1QXQSCMamzOmyI0kSkDe2huVET5ZIu3ABA4vqsI5Ux
         vn8Uppd8NMazf2yRkZW9xpMAVRAP9+QNH39AX1eVL0xFkyvia81VycwAbvZoKsnM4tno
         bSxBIRCUEU2kXLmYZEAXfwSshFZWrTSRUZFEOAFhqp+J+/d+CDGXHaXbARCwvVObDS2+
         JC/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531X+d5FnytUxykl6fCPy+tNpIY+qI1LWH8GqZdeFqTkjEWyh6Pq
	nvIOECbKd7jhsEomzXUWmJE=
X-Google-Smtp-Source: ABdhPJy4WMovaSvE2ac3b0Jl0SmAxB0ld6QGdbh7vaL2JgNVWWndAmPWjX7MNojHvVchJnG/PPRN2Q==
X-Received: by 2002:a5d:88c2:: with SMTP id i2mr17180404iol.18.1622476759184;
        Mon, 31 May 2021 08:59:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d212:: with SMTP id y18ls1073666ily.5.gmail; Mon, 31 May
 2021 08:59:18 -0700 (PDT)
X-Received: by 2002:a92:d1c3:: with SMTP id u3mr2678879ilg.190.1622476758751;
        Mon, 31 May 2021 08:59:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622476758; cv=none;
        d=google.com; s=arc-20160816;
        b=kzmKowAkzK4foUduEdN/fEMzAVBjWBU24Cm7Mj5RMvARQXEP65WFQFBQGysoCq5QwS
         3HR0WKh1LAOuO9yWgRX8PfhMJc5kZ9pZYPQGiy2MObUmtHCJWUIXmc0Xlzb7HCkmk0/K
         7pz3O3uqabENYfdkVyYzNJPgeFvm5uNbpe2zBMMoTqUiI/UHE+6evQmETZcpORHM3ceT
         3jAREGePcQshd38aWeGkCfHhGIXZ+5AoJyTTu7kY1Sm2f4qgTdz6qOsbof8Q0BW8UTvz
         mahI7jrsw0IRXcAsLOo734xiM9r9UtIG1r7dCunBFB8pgUyed5KOBu7IkC1SQ6QSOteR
         vIwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=by1GcBcH0zFhFff68TJvck6DvOHLGQmEOlvl4E3sn6M=;
        b=H6fRUmoBNObmGGj/CWZPfm7uk6bPJvfs6LbI8m7dGhHKuHiugV7bgzE/EjYeUXlt4P
         /0a5FrNB7zWPzFDXQhoQm9lOvi6c8Ef+L8K8+xIvUZi1ahmkStOmMgHjOeeXsfBAvEWX
         fLjaQ3Oad2vTfxVh9yjOBlL57RuF+lJHFB0Lsy6YZHKad5Pb7XtYaikWsfMBBRyXLqlz
         NuqrfuEud/XJGUP+Z1fPF19GQrrlDKB1WzTTz02rC5l1ThePUwbzO5Fxc6Y8g0LQY0k4
         /buU60+latWwMkYY52T75gSHKROkllTYctDUbQKiZ3DpWinZpsyTnZLgWCksOxgVZILb
         SAqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vFmuMxLR;
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id h15si1152842ili.5.2021.05.31.08.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 May 2021 08:59:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id g6-20020a17090adac6b029015d1a9a6f1aso144179pjx.1
        for <kasan-dev@googlegroups.com>; Mon, 31 May 2021 08:59:18 -0700 (PDT)
X-Received: by 2002:a17:90a:668d:: with SMTP id m13mr15376267pjj.144.1622476758139;
        Mon, 31 May 2021 08:59:18 -0700 (PDT)
Received: from DESKTOP-PJLD54P.localdomain (122-116-74-98.HINET-IP.hinet.net. [122.116.74.98])
        by smtp.gmail.com with ESMTPSA id t12sm11259049pjw.57.2021.05.31.08.59.15
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 31 May 2021 08:59:17 -0700 (PDT)
Date: Mon, 31 May 2021 23:59:12 +0800
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, Walter Wu <walter-zh.wu@mediatek.com>
Subject: Re: [PATCH 1/1] kasan: add memory corruption identification for
 hardware tag-based mode
Message-ID: <20210531155912.GC622@DESKTOP-PJLD54P.localdomain>
References: <20210530044708.7155-1-kylee0686026@gmail.com>
 <20210530044708.7155-2-kylee0686026@gmail.com>
 <YLSjUOVo5c+gTbzA@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <YLSjUOVo5c+gTbzA@elver.google.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=vFmuMxLR;       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, May 31, 2021 at 10:50:24AM +0200, Marco Elver wrote:
> On Sun, May 30, 2021 at 12:47PM +0800, Kuan-Ying Lee wrote:
> > Add memory corruption identification at bug report for hardware tag-based
> > mode. The report shows whether it is "use-after-free" or "out-of-bound"
> > error instead of "invalid-access" error. This will make it easier for
> > programmers to see the memory corruption problem.
> > 
> > We extend the slab to store five old free pointer tag and free backtrace,
> > we can check if the tagged address is in the slab record and make a good
> > guess if the object is more like "use-after-free" or "out-of-bound".
> > therefore every slab memory corruption can be identified whether it's
> > "use-after-free" or "out-of-bound".
> > 
> > Signed-off-by: Kuan-Ying Lee <kylee0686026@gmail.com>
> 

> On a whole this makes sense because SW_TAGS mode supports this, too.
> 
> My main complaints are the copy-paste of the SW_TAGS code.
> 
> Does it make sense to refactor per my suggestions below?

Thanks for your suggestions.
I will refactor them in v2.
> 
> This is also a question to KASAN maintainers (Andrey, any preference?).
> 
> > ---
> >  lib/Kconfig.kasan         |  8 ++++++++
> >  mm/kasan/hw_tags.c        | 25 ++++++++++++++++++++++---
> >  mm/kasan/kasan.h          |  4 ++--
> >  mm/kasan/report_hw_tags.c | 28 ++++++++++++++++++++++++++++
> >  4 files changed, 60 insertions(+), 5 deletions(-)
> > 
> > diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> > index cffc2ebbf185..f7e666b23058 100644
> > --- a/lib/Kconfig.kasan
> > +++ b/lib/Kconfig.kasan
> > @@ -163,6 +163,14 @@ config KASAN_SW_TAGS_IDENTIFY
> >  	  (use-after-free or out-of-bounds) at the cost of increased
> >  	  memory consumption.
> >  
> > +config KASAN_HW_TAGS_IDENTIFY
> > +	bool "Enable memory corruption identification"
> > +	depends on KASAN_HW_TAGS
> > +	help
> > +	  This option enables best-effort identification of bug type
> > +	  (use-after-free or out-of-bounds) at the cost of increased
> > +	  memory consumption.
> 
> Can we rename KASAN_SW_TAGS_IDENTIFY -> KASAN_TAGS_IDENTIFY in a
> separate patch and then use that?
> 
> Or do we have a problem renaming this options if there are existing
> users of it?

I tend to keep KASAN_SW_TAGS_IDENTIFY and KASAN_HW_TAGS_IDENTIFY
separately.

We need these two configs to decide how many stacks we will store.

If we store as many stacks as SW tag-based kasan does(5 stacks), we might
mistake out-of-bound issues for use-after-free sometime. Becuase HW
tag-based kasan only has 16 kinds of tags. When Out-of-bound issues happened, it might
find the same tag in the stack we just stored and mistake happened.
There is high probability that this mistake will happen.
> 
> >  config KASAN_VMALLOC
> >  	bool "Back mappings in vmalloc space with real shadow memory"
> >  	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index 4004388b4e4b..b1c6bb116600 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -220,22 +220,41 @@ void kasan_set_free_info(struct kmem_cache *cache,
> >  				void *object, u8 tag)
> >  {
> >  	struct kasan_alloc_meta *alloc_meta;
> > +	u8 idx = 0;
> >  
> >  	alloc_meta = kasan_get_alloc_meta(cache, object);
> > -	if (alloc_meta)
> > -		kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
> > +	if (!alloc_meta)
> > +		return;
> > +
> > +#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
> > +	idx = alloc_meta->free_track_idx;
> > +	alloc_meta->free_pointer_tag[idx] = tag;
> > +	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
> > +#endif
> > +
> > +	kasan_set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
> >  }
> >  
> >  struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
> >  				void *object, u8 tag)
> >  {
> >  	struct kasan_alloc_meta *alloc_meta;
> > +	int i = 0;
> >  
> >  	alloc_meta = kasan_get_alloc_meta(cache, object);
> >  	if (!alloc_meta)
> >  		return NULL;
> >  
> > -	return &alloc_meta->free_track[0];
> > +#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
> > +	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > +		if (alloc_meta->free_pointer_tag[i] == tag)
> > +			break;
> > +	}
> > +	if (i == KASAN_NR_FREE_STACKS)
> > +		i = alloc_meta->free_track_idx;
> > +#endif
> > +
> > +	return &alloc_meta->free_track[i];
> >  }
> 
> Again, we now have code duplication. These functions are now identical
> to the sw_tags.c ones?
> 
> Does it make sense to also move them in a preparatory patch to a new
> 'tags.c'?
> 
Yes, moving them into tags.c will be better.
I will refactor in v2.
> >  #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 8f450bc28045..41b47f456130 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -153,7 +153,7 @@ struct kasan_track {
> >  	depot_stack_handle_t stack;
> >  };
> >  

I think my v1 patch sets KASAN_NR_FREE_STACKS to 5 is not suitable.
The same reason as above.

I am thinking to store 2 or 1 stacks is acceptable in HW tag-based kasan mode.
Does it make sense?
Any suggetions are appreciated.

> > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > +#if defined(CONFIG_KASAN_SW_TAGS_IDENTIFY) || defined(CONFIG_KASAN_HW_TAGS_IDENTIFY)
> >  #define KASAN_NR_FREE_STACKS 5
> >  #else
> >  #define KASAN_NR_FREE_STACKS 1
> > @@ -170,7 +170,7 @@ struct kasan_alloc_meta {
> >  #else
> >  	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
> >  #endif
> > -#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
> > +#if defined(CONFIG_KASAN_SW_TAGS_IDENTIFY) || defined(CONFIG_KASAN_HW_TAGS_IDENTIFY)
> >  	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
> >  	u8 free_track_idx;
> >  #endif
> > diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> > index 42b2168755d6..d77109b85a09 100644
> > --- a/mm/kasan/report_hw_tags.c
> > +++ b/mm/kasan/report_hw_tags.c
> > @@ -14,9 +14,37 @@
> >  #include <linux/types.h>
> >  
> >  #include "kasan.h"
> > +#include "../slab.h"
> >  
> >  const char *kasan_get_bug_type(struct kasan_access_info *info)
> >  {
> > +#ifdef CONFIG_KASAN_HW_TAGS_IDENTIFY
> > +	struct kasan_alloc_meta *alloc_meta;
> > +	struct kmem_cache *cache;
> > +	struct page *page;
> > +	const void *addr;
> > +	void *object;
> > +	u8 tag;
> > +	int i;
> > +
> > +	tag = get_tag(info->access_addr);
> > +	addr = kasan_reset_tag(info->access_addr);
> > +	page = kasan_addr_to_page(addr);
> > +	if (page && PageSlab(page)) {
> > +		cache = page->slab_cache;
> > +		object = nearest_obj(cache, page, (void *)addr);
> > +		alloc_meta = kasan_get_alloc_meta(cache, object);
> > +
> > +		if (alloc_meta) {
> > +			for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
> > +				if (alloc_meta->free_pointer_tag[i] == tag)
> > +					return "use-after-free";
> > +			}
> > +		}
> > +		return "out-of-bounds";
> > +	}
> > +
> > +#endif
> >  	return "invalid-access";
> >  }
> 
> This function is an almost copy-paste of what we have in
> report_sw_tags.c. Does it make sense to try and share this code or would
> it complicate things?
> 

I got your point.
I will refactor them in v2.

Thanks,
Kuan-Ying Lee

> I imagine we could have a header report_tags.h, which defines a static
> const char *kasan_try_get_bug_type(..), and simply returns NULL if it
> couldn't identify it:
> 
> 	#if defined(CONFIG_KASAN_SW_TAGS_IDENTIFY) || defined(CONFIG_KASAN_HW_TAGS_IDENTIFY)
> 	static const char *kasan_try_get_bug_type(struct kasan_access_info *info)
> 	{
> 		... the code above ...
> 
> 		return NULL;
> 	}
> 	#else
> 	static const char *kasan_try_get_bug_type(struct kasan_access_info *info) { return NULL; }
> 	#endif
> 
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210531155912.GC622%40DESKTOP-PJLD54P.localdomain.
