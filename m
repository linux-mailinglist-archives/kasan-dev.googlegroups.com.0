Return-Path: <kasan-dev+bncBDZMFEH3WYFBBHEHVPDAMGQEYBVFT6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 722AFB7FE46
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 16:20:17 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-78ea15d3548sf8827006d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 07:20:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758118813; cv=pass;
        d=google.com; s=arc-20240605;
        b=OhN5yXiMFWe1wuhhVuJ6lDANar3lBKTgolTQkKHeAKAK9Gmhoz7bElX3VTCs9OVkSe
         dzgvWGzOQZ2uEFzTCsDYH4lZj1aYp2wvJ5FDB/kWpMsdbD/U6RlTkngBcs5x1aEYx1DQ
         hBEqetGb2HXUwB8hOxAqvjGvSZhfClNIX1Tg3eZmthzkojmMkBEcxn08+0yNmyCARiQJ
         99Ub2ldLmUTRtl6ra2dMB8lyBLoJx+4E61Yyom8DkM9UQfoPce5V2NfyitWC8fuW8QP7
         TwdtJ4f/FAj6pC0j11a+PVTM3L0S6DaUlBaGc9E/GF/T02+imJXkUKvgnwLzTsqI9FvK
         oAlA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=nRq7+0Gk6QOO06fFbDDn6ZDxgnKMlXl326FtI6ciihQ=;
        fh=T4KRbyV2vmTIr4L85I/81TtP9Vugpd+L5oUtpyitmIQ=;
        b=GXhhwJB/KjkbEZQfoMm78Q6rqSgdfwihPabiyy833wQNCzmUMyPXxJtKHw5H5i8mo6
         Ds1+6ZKVWBUoEf9z9Zod44rBL8xF0p546W9oelq5SeyWgSruqyDx4Xi3SKllKRfYmBNI
         HKHsfWdRUsipTlv70RK8tSs31Zb1zIaHUKM5rosV2OQxZVLl4mvhd52ev4llLSdp9EOH
         bl5dO+6eRqQWqirH38VRjERkOJIwpJX4gGnl+VB7YvLTmCkEWLwNBWwQZOcFCGnD8OT7
         7QKVoI9wNb7oVgUrSsX1HzXeFGWod7S2SCFLwPaYim8WVkU2IgHYGIXF8oWZzNFAQpKh
         wCjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ju8TW1WS;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758118813; x=1758723613; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=nRq7+0Gk6QOO06fFbDDn6ZDxgnKMlXl326FtI6ciihQ=;
        b=Sazrb0H2RtO9xr16lgt910EeNdjARqeVTcOLPv25HYQYPQQlQ/zCNxRA6FUTbkei9S
         reNI3PMJwXa+Vp1AIcBQClp1kYKsDsMfUmRH/1pHzTrNaSTjcoU1WfeOyNhGahQWE+DW
         QYYl6f+YtIYGKG0SixiGwyWELQiEv3o/aekfTrrDQstfnboAK4en8eVs//DlxFdZQlgp
         H3VijgzqNeoa8KCO8RVpPhYHvZZDUhVkc5vzIVx7/s6k1kgeFPwXTKeffP8BC5kScYC4
         3ZrDwjKXNZkqyNQCF0ulxcSjBPt6U8W0Fcxw9ErCNEkixx2V/yLiFfd/Lf2CsvSK2XnH
         LUVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758118813; x=1758723613;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nRq7+0Gk6QOO06fFbDDn6ZDxgnKMlXl326FtI6ciihQ=;
        b=qToSPaUsQtUa22YR/sBK4H1Em4mr+K6ahZ2vUVFc34KC14GR565pe9H5Ym9Mh/Ynfs
         eaLgFr4Pg0EzXGvhsKx6kOcpJNyJEONL1dAfiL+dCaiU3p40F1sX9ppUMtLglDVVuwV5
         bXq77JnAVYaETvbdzmJcjB4RkfzzOY+0RHQxxNHbmezUINGE2s75viDoxoY31oCWWuYq
         Ko/VR6ADfAR+jy3cTuke0wtFfBzEenQ5z/OlXduATr99jRI8OAN+92wz9UreCvuSV+Rc
         FtGo/qNjT46yJfF+OjYklGUX+L4akHIdyH0R0OYsfWoyn0fxUvyCFv1Mdjs6mpWIwkM0
         qohg==
X-Forwarded-Encrypted: i=2; AJvYcCXjOXyhgJej20gx1+Q8c/MG2KRshpM7yfqqIe0SYjZJd09UD2NCd8t4+o7F6lw58h/JM8GMjg==@lfdr.de
X-Gm-Message-State: AOJu0Yx2u72MWt2xfzP0wPgHuYDQHmaTNn15kPJtUCzpHt0widlT8hi9
	v50orrOOdzMYD+tKcjjlMYbtOJ7DsBwSws1PrBOz4ZRgavWVgdb66Qn5
X-Google-Smtp-Source: AGHT+IF2P3THtb8chlXOyMe7ikK98PEPMTbjn1tabuGX039If31/gzUgegiVBgi2ZB3wutS+aPi/Rg==
X-Received: by 2002:a05:6214:3482:b0:78f:5313:1417 with SMTP id 6a1803df08f44-78f531316a6mr10710206d6.32.1758118812731;
        Wed, 17 Sep 2025 07:20:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4eqm86lnjjRRvW+I1JaAPlrq49LY7uK2tGeYrxk0m8/g==
Received: by 2002:a05:6214:5991:b0:783:6e2:3e57 with SMTP id
 6a1803df08f44-78306e24a40ls42382156d6.0.-pod-prod-08-us; Wed, 17 Sep 2025
 07:20:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+D8I3CN9N6X0xTwZc6h0xGJ/zEkcLeWpIowUuJMxBjbNW1cYW7as7vW7G8cP5gpbKK03Q1nzLKH8=@googlegroups.com
X-Received: by 2002:a05:6122:829c:b0:539:3bb5:e4c8 with SMTP id 71dfb90a1353d-54a60a7a014mr728485e0c.12.1758118811311;
        Wed, 17 Sep 2025 07:20:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758118811; cv=none;
        d=google.com; s=arc-20240605;
        b=NkE2yQeqyEBj6wbZcVl3n0ewMwMiCXqjIrfnWtd82djDfAPSL3gQTksevCKYN+pU3C
         4WwJU5Azc28+uLXtK5oKYlz1zHL379fiL7h4IpD+NK+7oFKtwhEcUum0N4kmY5VjUnRC
         42IUspNyjl3Hu8kiNSS3mlnfrlQv5EQqo/Mq211u86Aoq4d9gG+UAGBf8tDdKNgEO9+m
         4OSAYyu63ezI/zyehBb0rlx82mHjgQpDuafJ+F2KlyInPHkJo1+7+DCJP/s0H2IyR4Fn
         kNti5CoH04ZSi1EcxfQA58MwWKJB5s7aBA2nA8Qza+Mu83t1q5s7hgmKHCInbbHFOdmg
         kX7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=drLEf2q8/O80+2XBQUBylxJhwjKLYp3hBHu2eslb7MQ=;
        fh=RVjfqWzGQeu5i5loCiSENJ2garnvcOzlGFsODAp8UHs=;
        b=flu6EaFFGI2Ba/BX3iqmfZk2cbf1rizGO5M08HactRKgz+op1GwA/CNp/hhXz44zq/
         Wj0pqhKV+glT4J5x9oFrdjk7I+rWi7T/+vLGSeyA9cDx9EAlTAKnTjwxoF92IoX+e7EC
         hFW2hvR5XEvWJorDFeJJwHpPY1T8vMiqDTyWJQPYryDBGS2ApqmbiYpwSQOJCx1W2SfR
         oe3VgZKEnWWF5QkaOeKfWjf7QlnDU4RFVmtV8W6igYF4i7F1vPEQhNw6oLLRRzyjWwZT
         puCwlvB5vJODRDGCG4YWrLkY7gNXtbjaUtkh1lkj4tlgKl0sID7wtP6Qm5OGHxXrj0Iv
         i6gw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ju8TW1WS;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-54a1716bc45si658111e0c.3.2025.09.17.07.20.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 07:20:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 9986B60233;
	Wed, 17 Sep 2025 14:20:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2755DC4CEE7;
	Wed, 17 Sep 2025 14:20:06 +0000 (UTC)
Date: Wed, 17 Sep 2025 17:20:03 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: David Hildenbrand <david@redhat.com>
Cc: Alexander Potapenko <glider@google.com>, akpm@linux-foundation.org,
	vbabka@suse.cz, linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	elver@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	Aleksandr Nogikh <nogikh@google.com>
Subject: Re: [PATCH v1] mm/memblock: Correct totalram_pages accounting with
 KMSAN
Message-ID: <aMrDk9ypD20H6zpx@kernel.org>
References: <20250917123250.3597556-1-glider@google.com>
 <aba22290-3577-44fa-97b3-71abd3429de7@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aba22290-3577-44fa-97b3-71abd3429de7@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ju8TW1WS;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Wed, Sep 17, 2025 at 03:29:51PM +0200, David Hildenbrand wrote:
> On 17.09.25 14:32, Alexander Potapenko wrote:
> > When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
> > for metadata instead of returning them to the early allocator. The callers,
> > however, would unconditionally increment `totalram_pages`, assuming the
> > pages were always freed. This resulted in an incorrect calculation of the
> > total available RAM, causing the kernel to believe it had more memory than
> > it actually did.
> > 
> > This patch refactors `memblock_free_pages()` to return the number of pages
> > it successfully frees. If KMSAN stashes the pages, the function now
> > returns 0; otherwise, it returns the number of pages in the block.
> > 
> > The callers in `memblock.c` have been updated to use this return value,
> > ensuring that `totalram_pages` is incremented only by the number of pages
> > actually returned to the allocator. This corrects the total RAM accounting
> > when KMSAN is active.
> > 
> > Cc: Aleksandr Nogikh <nogikh@google.com>
> > Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > ---
> >   mm/internal.h |  4 ++--
> >   mm/memblock.c | 18 +++++++++---------
> >   mm/mm_init.c  |  9 +++++----
> >   3 files changed, 16 insertions(+), 15 deletions(-)
> > 
> > diff --git a/mm/internal.h b/mm/internal.h
> > index 45b725c3dc030..ae1ee6e02eff9 100644
> > --- a/mm/internal.h
> > +++ b/mm/internal.h
> > @@ -742,8 +742,8 @@ static inline void clear_zone_contiguous(struct zone *zone)
> >   extern int __isolate_free_page(struct page *page, unsigned int order);
> >   extern void __putback_isolated_page(struct page *page, unsigned int order,
> >   				    int mt);
> > -extern void memblock_free_pages(struct page *page, unsigned long pfn,
> > -					unsigned int order);
> > +extern unsigned long memblock_free_pages(struct page *page, unsigned long pfn,
> > +					 unsigned int order);
> >   extern void __free_pages_core(struct page *page, unsigned int order,
> >   		enum meminit_context context);
> > diff --git a/mm/memblock.c b/mm/memblock.c
> > index 117d963e677c9..de7ff644d8f4f 100644
> > --- a/mm/memblock.c
> > +++ b/mm/memblock.c
> > @@ -1834,10 +1834,9 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
> >   	cursor = PFN_UP(base);
> >   	end = PFN_DOWN(base + size);
> > -	for (; cursor < end; cursor++) {
> > -		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
> > -		totalram_pages_inc();
> > -	}
> > +	for (; cursor < end; cursor++)
> > +		totalram_pages_add(
> > +			memblock_free_pages(pfn_to_page(cursor), cursor, 0));
> >   }
> 
> That part is clear. But for readability we should probably just do
> 
> if (memblock_free_pages(pfn_to_page(cursor), cursor, 0))
> 	totalram_pages_inc();
> 
> Or use a temp variable as an alternative.

I prefer this one and totalram_pages_add() after the loop 
 
> LGTM
> 
> Reviewed-by: David Hildenbrand <david@redhat.com>
> 
> -- 
> Cheers
> 
> David / dhildenb
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aMrDk9ypD20H6zpx%40kernel.org.
