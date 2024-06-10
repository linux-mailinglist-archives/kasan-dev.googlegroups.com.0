Return-Path: <kasan-dev+bncBCO3JTUR7UBRBZX7TGZQMGQEAVSIPLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id CF54F9019B7
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Jun 2024 06:24:09 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-52c8a6142bbsf290898e87.0
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Jun 2024 21:24:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717993449; cv=pass;
        d=google.com; s=arc-20160816;
        b=PEdn+0RY04F8u5lxAaEnFMOmHl7ukcXP3EBr+b0BI6KC/Inaecb2wkSYDRHju9kg8D
         eB+7OTiWhbKggWCaRAiJFqzciygKTWrGJaZaI8YNSKKRo2CvPLbCuXeZ+evVR7tWFHhE
         0TwSeXuS2jREjHOa32b3Kdl9yTWjjnu4vP8r5cIRpbgQ8StxnJ1HO4EPGSsnjbIurf+a
         JGgyi8QSdZ4/s0Kc4xo64FuKo+PCd283ZNgXw4wDO0oVyAcM2FwWB5AcEgTMmwej9apr
         ZESgrjEp3YmqkEBy6KbdpXhWlOQIo8KgcXrgxwSwLBwR1ms5LZfvJrVf/qH2k9zVeRny
         ATOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zDmS1zTESYHQXcUJmtiiE/jRqJNnMUum+dE5XNkPH8E=;
        fh=R6E6ZoXAiptFRVVVKU2eBYfKLmez8eFDTGqaGIn8rkA=;
        b=m0qlX3PiY8mOGsrcNydEmnU2ZV7XSuzKm/YggoDpubcy+WccqURyBGqjleuhZ/uYa8
         /RTNFxcAQbvZ5JtLNTORfo9tyl4s1deqcx/K6fpOKcKdxD1pm7LxC5yrMan34WWQZUc+
         lTc1N2oZ+etbLULWIldh5cqgWeiAiInExPe7+jUiZBv09i819RYb6ryiMTWJ/zzPXqFI
         W67htUVqo5ha1QJqtijFOMtYe7xuE/cDwekV4DFcDa5Z+tZqD3149mXf0XV34A4gYnJB
         hPzjiAzQLiREo8DDdTcvwqORwR89VEVWG3FJt/q0RDskhHUc9IBRzens0KA4hjlhzlbi
         jwaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=o8tqZ6pt;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=o8tqZ6pt;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717993449; x=1718598249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zDmS1zTESYHQXcUJmtiiE/jRqJNnMUum+dE5XNkPH8E=;
        b=ZI4Rds+B9SL5jpZE3XMSG4JI/A5zCDZd3v0cljnUCHzODj7Pxztod4SCIuCK7L8drp
         qNVHPVUpJYILKbP+l/9e0kc3xxy8kUsqhBgGMKzh5Qp8JXFhrr3v/7KAWz8swlqKOvkS
         1j+mVYRGYwNnRc4auhKEkR9BPXIARai1OQJigt7IkwogPYu9PlnE/Jqj4YXjhzw1uhFF
         7WvXAEWckDQ28CEqgeV2FzqtqTHf1Tu4lgv8aVS1ksAh/1CMDQw6GqbIMRvKojiiqIb8
         +rnZhkmaYjDCdXiXL5g69VIVsmKBZtq4c5Z6oMCu1d05XeKqqbXO9VRT1zxv7OYrgoKH
         Q0aQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717993449; x=1718598249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zDmS1zTESYHQXcUJmtiiE/jRqJNnMUum+dE5XNkPH8E=;
        b=eQc29xrf5faR9YeF0tgLfYRSrV+kcKJUxu+llBZcODggfg9s/NlfwhdaRpyR8Wbv3y
         jDGuFyUKI0Fc96VYC2cIuPOzhgWyaA6u2lyD46PvdvTG+tDHoLfeOTeA0xQDmGpGTEum
         KfLQ9lGythywZjqY9JiMcW3xwm+pWt3qy0kUtVOHjs6AhR5PT8dfAh4WX0BEOu6PThT4
         bHBLFHMFtwCZavhNbgO9guyISKMPX9NoJWYLW5QU4xZaeKj6dn7ed84schJ4VfzkB9ng
         yGHdH99xtxQREsn9CGOIMGXGC8PVoChDSOHvjTYOrP0xK/gZfRL2SmX3R/+jBAYl9U/i
         QOpw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVfdT4z7DTYGLDCVqIIF0YPlTr7fEX8fsqFiqQkhWf/vbVNe42bc1fq7L36aE2Ws51+hkqvAz88AdJ6Iy1uYlN0MvtaoL/MYw==
X-Gm-Message-State: AOJu0YwmmDOhnP902JT31mSj+Qyx8gZOkmZ/zZg97HbGJ9LY0qHd36CC
	QtIYPWZiTfm9n0cZWseAZMGZS0D/O8L1baWjRctN8Cf4456Qb3CM
X-Google-Smtp-Source: AGHT+IF5vVXzzpxC4j9aAL9ty28saXmXupQrKiO4tTzd2FTVQF33PSfHqRymHhx8R4h9+EQneLbHug==
X-Received: by 2002:a05:6512:70a:b0:52c:2b7b:2c24 with SMTP id 2adb3069b0e04-52c2b7b2db5mr2892010e87.50.1717993447665;
        Sun, 09 Jun 2024 21:24:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d02:b0:52c:8476:eaf with SMTP id
 2adb3069b0e04-52c84761063ls640701e87.2.-pod-prod-03-eu; Sun, 09 Jun 2024
 21:24:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXH/A+jqL7Z8DdaiVA1Ku6H3DORYmsAU3KPRgxUopbJwhV8Q0e4ivGx6a6nSGDEwOMEHF6/aOsLPWr9w8f0RVmIqrQKcXo45jgErw==
X-Received: by 2002:a05:6512:3ca1:b0:52c:859f:9f77 with SMTP id 2adb3069b0e04-52c859fa036mr1885417e87.19.1717993445043;
        Sun, 09 Jun 2024 21:24:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717993445; cv=none;
        d=google.com; s=arc-20160816;
        b=zj0admaMGbjKZcoXszjTrGmtRnqQ4mwOcKY37ODy23UjiRW9tmKAqh9pewD/SIkvCl
         lLihsHFwaCqadOVP1in9fP95YZPULwn/QwhM+ZhtR/ztd4qMRK+yPN5vZV79UxyCz/uh
         u26mhXH2osiN61vg/cviF5QRt9rgJmkQ+7zKT88LTd4FWw33Gu0rY9QJJT5gm0QMQZ8y
         cxg6Pu3PrnnZ0XqjktwRL3j5apepTXBkEsdFC4/ZxABoHWLxCPvH7hZiNXZ1z8pbl7nX
         sQvWwVWUSca1VqYcufs2PPfWpVloPJhVAOmXLmjyQSd0+NinFIE+QFb/FSQuX2ehsd/b
         uTQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=STes9dvsOiZHvfV9vRJe27/8pEpJsEu/gt/yrG0Qqek=;
        fh=opXV1WEp03kbeubOZloyb10FoNtntQdRllRWblbVMRI=;
        b=BnfkgEf29KQoRZooK8pDBDNfJrWWBi7n1cx8aDVq2PQ1/w6yQHza+hKk0c3K/hyOHF
         b60jMLj0YbaWrGEPqan0J0yXHClvP7rZxcpWC82Ft0/SGolaFJxfBGeCalUrdlufgxOq
         l4mleIFJbgSdR0xVs/vDbUBfMjxHjESGOwJw8TTMSxPrq7Ho4Ijb0CtFoTBO1iPVLMf0
         y2wL2UlSxBB7VxPkEGj875v/pCpYnWl6tufCDEiHu9wC5pKrMjpcfhEmF7MKgvH29D/r
         iysC7Dp2QIXQsZPHP6DzhQ496W4Cqqun5zaLVLNPFLJhaS/C3BROtg4eghZXYSL8Ceey
         5gmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=o8tqZ6pt;
       dkim=neutral (no key) header.i=@suse.de;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=o8tqZ6pt;
       dkim=neutral (no key) header.i=@suse.de;
       spf=pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4217a4f531asi2379635e9.0.2024.06.09.21.24.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 09 Jun 2024 21:24:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of osalvador@suse.de designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 88FA1219DC;
	Mon, 10 Jun 2024 04:24:04 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 5D2BD13A7F;
	Mon, 10 Jun 2024 04:24:03 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id jBLQE+N/ZmYYFwAAD6G6ig
	(envelope-from <osalvador@suse.de>); Mon, 10 Jun 2024 04:24:03 +0000
Date: Mon, 10 Jun 2024 06:23:57 +0200
From: Oscar Salvador <osalvador@suse.de>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-hyperv@vger.kernel.org, virtualization@lists.linux.dev,
	xen-devel@lists.xenproject.org, kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Mike Rapoport <rppt@kernel.org>,
	"K. Y. Srinivasan" <kys@microsoft.com>,
	Haiyang Zhang <haiyangz@microsoft.com>,
	Wei Liu <wei.liu@kernel.org>, Dexuan Cui <decui@microsoft.com>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Juergen Gross <jgross@suse.com>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Oleksandr Tyshchenko <oleksandr_tyshchenko@epam.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Subject: Re: [PATCH v1 2/3] mm/memory_hotplug: initialize memmap of
 !ZONE_DEVICE with PageOffline() instead of PageReserved()
Message-ID: <ZmZ_3Xc7fdrL1R15@localhost.localdomain>
References: <20240607090939.89524-1-david@redhat.com>
 <20240607090939.89524-3-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240607090939.89524-3-david@redhat.com>
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	DKIM_SIGNED(0.00)[suse.de:s=susede2_rsa,suse.de:s=susede2_ed25519];
	SUBJECT_HAS_EXCLAIM(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	RCPT_COUNT_TWELVE(0.00)[23];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	MISSING_XM_UA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo]
X-Spam-Score: -4.30
X-Spam-Flag: NO
X-Original-Sender: osalvador@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=o8tqZ6pt;       dkim=neutral
 (no key) header.i=@suse.de;       dkim=pass header.i=@suse.de
 header.s=susede2_rsa header.b=o8tqZ6pt;       dkim=neutral (no key)
 header.i=@suse.de;       spf=pass (google.com: domain of osalvador@suse.de
 designates 195.135.223.130 as permitted sender) smtp.mailfrom=osalvador@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
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

On Fri, Jun 07, 2024 at 11:09:37AM +0200, David Hildenbrand wrote:
> We currently initialize the memmap such that PG_reserved is set and the
> refcount of the page is 1. In virtio-mem code, we have to manually clear
> that PG_reserved flag to make memory offlining with partially hotplugged
> memory blocks possible: has_unmovable_pages() would otherwise bail out on
> such pages.
> 
> We want to avoid PG_reserved where possible and move to typed pages
> instead. Further, we want to further enlighten memory offlining code about
> PG_offline: offline pages in an online memory section. One example is
> handling managed page count adjustments in a cleaner way during memory
> offlining.
> 
> So let's initialize the pages with PG_offline instead of PG_reserved.
> generic_online_page()->__free_pages_core() will now clear that flag before
> handing that memory to the buddy.
> 
> Note that the page refcount is still 1 and would forbid offlining of such
> memory except when special care is take during GOING_OFFLINE as
> currently only implemented by virtio-mem.
> 
> With this change, we can now get non-PageReserved() pages in the XEN
> balloon list. From what I can tell, that can already happen via
> decrease_reservation(), so that should be fine.
> 
> HV-balloon should not really observe a change: partial online memory
> blocks still cannot get surprise-offlined, because the refcount of these
> PageOffline() pages is 1.
> 
> Update virtio-mem, HV-balloon and XEN-balloon code to be aware that
> hotplugged pages are now PageOffline() instead of PageReserved() before
> they are handed over to the buddy.
> 
> We'll leave the ZONE_DEVICE case alone for now.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>

> diff --git a/mm/memory_hotplug.c b/mm/memory_hotplug.c
> index 27e3be75edcf7..0254059efcbe1 100644
> --- a/mm/memory_hotplug.c
> +++ b/mm/memory_hotplug.c
> @@ -734,7 +734,7 @@ static inline void section_taint_zone_device(unsigned long pfn)
>  /*
>   * Associate the pfn range with the given zone, initializing the memmaps
>   * and resizing the pgdat/zone data to span the added pages. After this
> - * call, all affected pages are PG_reserved.
> + * call, all affected pages are PageOffline().
>   *
>   * All aligned pageblocks are initialized to the specified migratetype
>   * (usually MIGRATE_MOVABLE). Besides setting the migratetype, no related
> @@ -1100,8 +1100,12 @@ int mhp_init_memmap_on_memory(unsigned long pfn, unsigned long nr_pages,
>  
>  	move_pfn_range_to_zone(zone, pfn, nr_pages, NULL, MIGRATE_UNMOVABLE);
>  
> -	for (i = 0; i < nr_pages; i++)
> -		SetPageVmemmapSelfHosted(pfn_to_page(pfn + i));
> +	for (i = 0; i < nr_pages; i++) {
> +		struct page *page = pfn_to_page(pfn + i);
> +
> +		__ClearPageOffline(page);
> +		SetPageVmemmapSelfHosted(page);

So, refresh my memory here please.
AFAIR, those VmemmapSelfHosted pages were marked Reserved before, but now,
memmap_init_range() will not mark them reserved anymore.
I do not think that is ok? I am worried about walkers getting this wrong.

We usually skip PageReserved pages in walkers because are pages we cannot deal
with for those purposes, but with this change, we will leak
PageVmemmapSelfHosted, and I am not sure whether are ready for that.

Moreover, boot memmap pages are marked as PageReserved, which would be
now inconsistent with those added during hotplug operations.

All in all, I feel uneasy about this change.

-- 
Oscar Salvador
SUSE Labs

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZmZ_3Xc7fdrL1R15%40localhost.localdomain.
