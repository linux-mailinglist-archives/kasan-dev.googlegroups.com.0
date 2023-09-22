Return-Path: <kasan-dev+bncBD2ZJZWL7ICRBW73WSUAMGQEFLVXFPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 4752B7AA9C1
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 09:10:21 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-32001e60fb3sf1432747f8f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Sep 2023 00:10:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1695366621; cv=pass;
        d=google.com; s=arc-20160816;
        b=g2hcS+XH692+LgaUa1LSXLpnwoZaNKDH2JHOlq/91D8+uZyZVy65xNIUwCCfhk1yqL
         szcLgoKn87OvtuRhzpvk9yBMgwOFx0wdnxGyEwuwjQq6LAsZT6PvEVGxkge13HBOgRRR
         V4eSaGs+TCwXGBYK6xnz3/rKbubehTQTgp2T6js5J9wuIGDkPoyIYVHESjqiB3T1a9GF
         YzI+vfrumdwBAmsCDhnua8zRPeHLhOUvWI+6m55jUWvZxt1EO73t6FqgcZ45hDLgfIKz
         LpS9bCc8UDsDWaMBqpFqdByB+SlWICZsAQBA62CnMsGpehLqmiDyoZ3EL+8w4xYmxoAf
         vfMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hp2gAmNUzwErXmtfxpcUQfwHvm5H61X/57Uyersdabk=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=YaVxNSNKCq9aQQ7QcSSy9fJbOCKwUd/KLFUvSVelUOPSfrKKygVKf+RgB+yr/zeZ9f
         VQzoZRnKgln/f2wIRsbH3EakUcu6kcKNt9Yvyc+G9yXvZmzWBHmniV+RWCBC8Rr14NHa
         s7QUJy/YXseIoZy8F49w6ty3/mbULyWYOIC6X4xtiqJ3ptHnNthHWI4xd4cmRYLDiL+2
         oYXjPK47I5TbH/T2T/PpLDSeolptsWaWM4ncLT6ilA+WgtKg1Md8arEj48nTCahP3/hj
         oNjElE7HCOlVSa7NBaD2L/6I0e/1kjx9yUi3oo8/BpFnQK8aKIdMLVckeuMmXWsZ7vER
         WZnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AFYpk1uq;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e0 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1695366621; x=1695971421; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hp2gAmNUzwErXmtfxpcUQfwHvm5H61X/57Uyersdabk=;
        b=UOtuJkszKC2kWgvr8QxgesA9pN/GYJ+7GqqgabziFIEvtwOtE2R68cpUrnVtWN96Qq
         UmKDihk5IEYWBwJGGkSWq+7kmwOL/6nN8vDl0LwPTTKWGYJdFUAQyrbfGOANKtYuK9HB
         5YCNiGJleIAJ+oa3DB0Wiqmq5zWaVUDSZg7/mYWXs9ASOT0tYgv+rjxyGxwdUhHeHJDW
         6sp6noGZ2/DIR5oji0WnL2LUv7TQqpcNjBtc8tuDz1qJEP4PwjuEs6eWigViPMjKNePe
         MYNwDRNPlwUyXMQKbM5Ct1JGFd1FVN1j6nyKQX4ZAe2XyWPgBjgEQeosl+mprx4rSER9
         IbCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1695366621; x=1695971421;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hp2gAmNUzwErXmtfxpcUQfwHvm5H61X/57Uyersdabk=;
        b=oAOwB0i9LV+8+fPwzF1hbvb+FPaOVTzw0BEF2rkJsYD6lahGBhJRGzbBJXpvbEtaxM
         PNQV5EYIGta7UjOYaVMOxhOZmlVhRIGFyhxsjY7eebYXhnsmrt3eNwQ7b+vrdCZ84QWj
         DkJUvZpZdHbtE/LqNt2JvkYbJyfcQp66SQauV6lnRTv2mGEymXjy7vaGk9x7bPZ9TySD
         fwHTSqMUhI7E8pPp228nEPMdWjApzk5VJJMk7gERkOVlkolo6gXR+qdIMWZ4tIRCWaiC
         tfIvTSDaeSzQm0bhhmhl9SO5q2/GGdbLQeS1ryOe/nkSy4pGsTWPEpoPrVy0RR8IrTps
         KnnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzUHyTco157NcloOqKta7DBMDIJ/0IN9qtaqw+7HQBe1qat2BbF
	wWD45Jmhktl5pDrB0vEwZiE=
X-Google-Smtp-Source: AGHT+IHWVoHjPRJnfC4k5haP4W94A0CxzBPoMpoV0jZm6AfNlgHCxexOT7tGaYVdZsfIcQ2tEmt7Xg==
X-Received: by 2002:adf:dcc7:0:b0:31f:c89b:91fc with SMTP id x7-20020adfdcc7000000b0031fc89b91fcmr1240175wrm.7.1695366619867;
        Fri, 22 Sep 2023 00:10:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:601b:b0:404:74f4:1b5f with SMTP id
 az27-20020a05600c601b00b0040474f41b5fls652650wmb.0.-pod-prod-00-eu; Fri, 22
 Sep 2023 00:10:18 -0700 (PDT)
X-Received: by 2002:a7b:c8cb:0:b0:405:251f:8455 with SMTP id f11-20020a7bc8cb000000b00405251f8455mr1260846wml.7.1695366618194;
        Fri, 22 Sep 2023 00:10:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1695366618; cv=none;
        d=google.com; s=arc-20160816;
        b=i4UZqyMExmKmDnnezkjYgT1lvS8CySSldKcG0LTaDQM2I71eBTqvxA1AoZf3/wTJVR
         uv8WDHNYWZweVtno3whKpkEgWAUlVlgKVWWLnGGLIlTFcnJS3+DVdTU0Y8K2ZgJ7tNAS
         k2WC55AtQqVLdrMlUmENkC1M1OQu4teKstH/2mlG1fv7g8o1JKcXNCQQ5yIfpJJX9XqV
         VIwyJJXIZLmZCobqKoGoPm/wTlRoqM01DunueWjRv0Fq89x575NhnC+LSzUV/e1oeEHd
         gCEvP5ZRoa+ukG9FlPLxCD8St99gyEYu4mT2tLc+qRfR6GqRUSyRqQXgmuJRx/DYoXWw
         1h4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=YklfUpteE5FTVxoZIVXyNtzYnXnzzLxI2l0gg0fMR4U=;
        fh=KSy1dDf6lUvgdoPctzpy47/Mjv6bi14N3nvpkZLQDdc=;
        b=msfR4pFvpjV5UKrAz7QE/JTT8QNOnbiz/M6PF3pJLupVXuAb3RmjnE5IFrzdSrDt61
         K6g+IIOIUJB3dN/TBxmNqJwHvMIcNxuFLl4Exsclq/QFNxwTVmsdCsMUXaP8EALmp7bc
         UDHjXNhRRo3XocmysdFn9ApAPND3IEQNedgptNKqGMUtzOD5eNWCfGZOKKoVLsDtY/Oo
         byb/G0e7dlqKiPWdaBTMCtmiRWu+NNzOZKl51ioUI508lsfbj+9embydSi9jMJy7Sx25
         LwcZp9fFp2Vmc6A3pPTNhcZgpMLA70tTsmCply/1hTqYKcW8PUl+/z3E7L77TUxm/lm6
         DUsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AFYpk1uq;
       spf=pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e0 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-224.mta0.migadu.com (out-224.mta0.migadu.com. [2001:41d0:1004:224b::e0])
        by gmr-mx.google.com with ESMTPS id d14-20020a05600c3ace00b00404ca34ab7csi493861wms.1.2023.09.22.00.10.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Sep 2023 00:10:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e0 as permitted sender) client-ip=2001:41d0:1004:224b::e0;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Yajun Deng <yajun.deng@linux.dev>
To: akpm@linux-foundation.org,
	mike.kravetz@oracle.com,
	muchun.song@linux.dev,
	glider@google.com,
	elver@google.com,
	dvyukov@google.com,
	rppt@kernel.org,
	david@redhat.com,
	osalvador@suse.de
Cc: linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Yajun Deng <yajun.deng@linux.dev>
Subject: [PATCH 3/4] mm: Set page count and mark page reserved in reserve_bootmem_region
Date: Fri, 22 Sep 2023 15:09:22 +0800
Message-Id: <20230922070923.355656-4-yajun.deng@linux.dev>
In-Reply-To: <20230922070923.355656-1-yajun.deng@linux.dev>
References: <20230922070923.355656-1-yajun.deng@linux.dev>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: yajun.deng@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AFYpk1uq;       spf=pass
 (google.com: domain of yajun.deng@linux.dev designates 2001:41d0:1004:224b::e0
 as permitted sender) smtp.mailfrom=yajun.deng@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

memmap_init_range() would set page count of all pages, but the free
pages count would be reset in __free_pages_core(). These two are
opposite operations. It's unnecessary and time-consuming when it's
in MEMINIT_EARLY context.

Set page count and mark page reserved in reserve_bootmem_region when
in MEMINIT_EARLY context, and change the context from MEMINIT_LATE
to MEMINIT_EARLY in __free_pages_memory.

At the same time, the init list head in reserve_bootmem_region isn't
need. As it already done in __init_single_page.

The following data was tested on an x86 machine with 190GB of RAM.

before:
free_low_memory_core_early()	342ms

after:
free_low_memory_core_early()	286ms

Signed-off-by: Yajun Deng <yajun.deng@linux.dev>
---
 mm/memblock.c   |  2 +-
 mm/mm_init.c    | 20 ++++++++++++++------
 mm/page_alloc.c |  8 +++++---
 3 files changed, 20 insertions(+), 10 deletions(-)

diff --git a/mm/memblock.c b/mm/memblock.c
index a32364366bb2..9276f1819982 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -2089,7 +2089,7 @@ static void __init __free_pages_memory(unsigned long start, unsigned long end)
 		while (start + (1UL << order) > end)
 			order--;
 
-		memblock_free_pages(start, order, MEMINIT_LATE);
+		memblock_free_pages(start, order, MEMINIT_EARLY);
 
 		start += (1UL << order);
 	}
diff --git a/mm/mm_init.c b/mm/mm_init.c
index 0a4437aae30d..1cc310f706a9 100644
--- a/mm/mm_init.c
+++ b/mm/mm_init.c
@@ -718,7 +718,7 @@ static void __meminit init_reserved_page(unsigned long pfn, int nid)
 		if (zone_spans_pfn(zone, pfn))
 			break;
 	}
-	__init_single_page(pfn_to_page(pfn), pfn, zid, nid, true, false);
+	__init_single_page(pfn_to_page(pfn), pfn, zid, nid, false, false);
 }
 #else
 static inline void pgdat_set_deferred_range(pg_data_t *pgdat) {}
@@ -756,8 +756,8 @@ void __meminit reserve_bootmem_region(phys_addr_t start,
 
 			init_reserved_page(start_pfn, nid);
 
-			/* Avoid false-positive PageTail() */
-			INIT_LIST_HEAD(&page->lru);
+			/* Set page count for the reserve region */
+			init_page_count(page);
 
 			/*
 			 * no need for atomic set_bit because the struct
@@ -888,9 +888,17 @@ void __meminit memmap_init_range(unsigned long size, int nid, unsigned long zone
 		}
 
 		page = pfn_to_page(pfn);
-		__init_single_page(page, pfn, zone, nid, true, false);
-		if (context == MEMINIT_HOTPLUG)
-			__SetPageReserved(page);
+
+		/* If the context is MEMINIT_EARLY, we will set page count and
+		 * mark page reserved in reserve_bootmem_region, the free region
+		 * wouldn't have page count and reserved flag and we don't
+		 * need to reset pages count and clear reserved flag in
+		 * __free_pages_core.
+		 */
+		if (context == MEMINIT_EARLY)
+			__init_single_page(page, pfn, zone, nid, false, false);
+		else
+			__init_single_page(page, pfn, zone, nid, true, true);
 
 		/*
 		 * Usually, we want to mark the pageblock MIGRATE_MOVABLE,
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index 6c4f4531bee0..6ac58c5f3b00 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -1285,9 +1285,11 @@ void __free_pages_core(struct page *page, unsigned int order, enum meminit_conte
 	unsigned int loop;
 
 	/*
-	 * When initializing the memmap, __init_single_page() sets the refcount
-	 * of all pages to 1 ("allocated"/"not free"). We have to set the
-	 * refcount of all involved pages to 0.
+	 * When initializing the memmap, memmap_init_range sets the refcount
+	 * of all pages to 1 ("allocated"/"not free") in hotplug context. We
+	 * have to set the refcount of all involved pages to 0. Otherwise,
+	 * we don't do it, as reserve_bootmem_region only set the refcount on
+	 * reserve region ("allocated") in early context.
 	 */
 	if (context != MEMINIT_EARLY) {
 		prefetchw(p);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230922070923.355656-4-yajun.deng%40linux.dev.
