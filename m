Return-Path: <kasan-dev+bncBC32535MUICBBRMDX3CQMGQER5L633A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 246CEB38CA4
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:08:07 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id af79cd13be357-7f7ff7acb97sf72185385a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:08:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332486; cv=pass;
        d=google.com; s=arc-20240605;
        b=BOON7ny6iGA6Jr6pfpbM142GA0/hlDmPQvfURV1xSKlqmUu+nqfxKUtflqVuuV0f0w
         M+N6fukx1y90Ex3PKATfhvMr5elfF5Z7OjeI3C3z6BXd+tFZvyKEp1rBVGgDWtA87rjI
         Y8Ao/kXfhaedkJdC/qqKkujbMMwiVzDBefgCReyredJLsDwl6IsvB/mVDWVVzVAwc+y0
         fnYfSivo04YhG4YVfyiC3VzLslsA5Npa+xO8I1MC/MHDM4tIkwr6uhmDtCBaX6zG8880
         nNg0CXJckaUgBJZI7bfd/ZypwL/MF6WfMM36p7FC5gpydC3Rfyf/wh89CUlIBQlSRbHx
         phXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=Cz/hgDePj04FhgGqeGSsW4RtHXqNYpuyn7L7Xk3SgME=;
        fh=/xUquZWlo93Z7ih5MaVPwMD5X4WMHhQ9NAehz9YuZgQ=;
        b=OSqJjCQgEKp4/rGHPkpyucR4VkZN1Qv7U+zSW3FCPR5G65L2XShEgnQSEin/WOzfrI
         j3ZZEv4gPQ9KAhTamCrtwD1FQxa548zZE70pTVNEVtMDG4pwtemQCDGnbD/C5TuVvk9e
         P7CZpN4+gaGOEk6TPWyu2glDh6JyKSPqxIM/VWJlDdU6DKD09LDzj+Y+NBvWy0T3mMvM
         PjnjZSEupaumQkUtF5iLkTX217KACSrFqNNu6ThdWtCzDymXiQuzeLmIid6kTfMOKu7J
         ZSTLEUiNDmL5Aar2BMKTPYMezjMVdhTKJtE5VHIp1yqPTBvvzT+4PAJ+c5h81TilEd3V
         4ryg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bWxUf5wO;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332486; x=1756937286; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Cz/hgDePj04FhgGqeGSsW4RtHXqNYpuyn7L7Xk3SgME=;
        b=IkI4jABWO5QEuvDB92SYttkhkUTm69bQxoBB7pxT2/fyRlhz3cbVGMZ+PuglK/+VCp
         FRtMGKBhtWZwQxU1nbSXM+vlDaGWA4zbICly8CxpAnNi+m/MAWHtzcqYtGeeImFCXok+
         XUiTDjE9v3/FJzSpZW8qTsBPRwE24kPa6wtLSiI3VVlxWPqlTKDT73EwLS/yfTPSAzk0
         2z3QYNJmWN3S+Ha3pqxwF10AdLwRM7PQq4YJuaYWeTI5I1aDLXHzQ7YCD9Fc6AWlLg7o
         uMI8IMXpPWOVnlcX9Ro/n521ICxR/fVAdey7E6kocHOEofSR+MY2kL2UI/gPV+/QBBwt
         Jdig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332486; x=1756937286;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Cz/hgDePj04FhgGqeGSsW4RtHXqNYpuyn7L7Xk3SgME=;
        b=e+kYeNzVIAQRFuDFiKkBJCbSHvDEgYbPrQq+1oLE9vKTF9z81oHKOYw2rQk8EcFUod
         wQbXaydmhg1iGGvfBFL6LNXgO5UjIp0FKf9Ebrz3S3NN7jTW9DsH0LBq/u8hDfjZrNVQ
         xiKnonhHBMEEs0TYUiUHxYpbVjZGtuD3A9Rs2nuWkJVpqYYbnU2Vgx8ZaWLmmX0M6Lda
         xh8BHGwzUKESyvibWg22+rVAs9jB/MVVRQT8NpEJrAkV9OMNPdopeYtV7FvWdWWzJulZ
         W7FYuXHYYlfGK9iwLG9VWhjOZDChJ+0hdlMcLJ7O/2ohp2RYozblkQ9QD95GiWSNm74Y
         gXUA==
X-Forwarded-Encrypted: i=2; AJvYcCW15fiudC5qUal4nrU4wfCo8qVIQpnQ321XhqRfHLJSFJo1BevLOdPDb+CtZYvyMxYRz/yrQg==@lfdr.de
X-Gm-Message-State: AOJu0YxMxHXgnSSxBC7YVTLsIS03M/LCV6/Y9BdAB6ucFJ+NvIOB92do
	KepNQoyTX2x6W2d/1M8wk8K1L1cDr3MKeJh09GnLjklYIH50X/TZdNH2
X-Google-Smtp-Source: AGHT+IEjIz0Y8zvhoHFjxxOtYwHg5ak0NkatJWMCzn2o4u3as7JSgy6VWFJ295m3xk5sr0OYBp7bkA==
X-Received: by 2002:a05:620a:a49b:b0:7e9:f81f:cebc with SMTP id af79cd13be357-7ea11091a20mr1947165485a.86.1756332485677;
        Wed, 27 Aug 2025 15:08:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdsj2Y5/AqLi6OfhUqNW9/ahsbFX71+QO/tsAodgQhV7Q==
Received: by 2002:ad4:5743:0:b0:70b:acc1:ba4f with SMTP id 6a1803df08f44-70df04c37b8ls2220286d6.1.-pod-prod-08-us;
 Wed, 27 Aug 2025 15:08:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVosNfLMfcqhpHMyjI/HZhtTBs1soLdJ9kqKiEz0tB2hE58ZHhiYrAgvXjlRyUgBmnptNHMZpPfbjQ=@googlegroups.com
X-Received: by 2002:ad4:5aa3:0:b0:70d:a985:79d7 with SMTP id 6a1803df08f44-70da9857f0amr179043536d6.47.1756332484880;
        Wed, 27 Aug 2025 15:08:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332484; cv=none;
        d=google.com; s=arc-20240605;
        b=CQb7oc1wAVwV1kK3rn5+DRERGM1SWKRDX71RQAPDfYpkCnShJJbxITREY+NKvxR+Qw
         l/TwxIqxzqSWa675PxQatnbG6OyIHjOAf8HA2SnN2AGIafYaNUKdthK30rPgy0Uy5Gi/
         wkpgBe96ivjtJ7CL0B+TmzEtbDNHo34DljFTjC71ZIfIn3tmNbyrj37crO2QVtJvdE5+
         BCfKAYnAAoqYUPFREUlTbK/kc559XFyTx/ilXx0p3Im7OSZzzBwZVO9V8crPj1cqoY1b
         KsLwB9ATNClLrLsRXPykUqM+uKqVXpSNiVUmdDZoB0PdfYMyrBJ5FnE12qmGETwRfE+X
         96FQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=3ZA4z8X3DBAGYUxj/2WGnSPhW3B2O9Q5Mn2y+SAGx1Y=;
        fh=/8v1ZO0Hg4/rJJNe0KyNXHtJUZOvRN9woepc/1DMyJY=;
        b=CEPsiX4Fru8+cE2gqwM5KIHAOYcIKNyKPwf4rM6AZzYO3gjs3TvJL9hM8WUPtBY9/M
         RS3irPALVhwoybzk3iSDmTRFQ2Cyw78TuaRrmsbFSTQmMKgVuA1nsQnQItG6Q7K1EoYt
         mUDx0cP4Xa81pJH6EZ5bljD0CZKi8XaanzEdxIMGcLj3CZjWtVT1H1zqOQH2JoeXqODg
         tNf5J20AR/c9qvBxKWmoYtEuTGLZ0aimWKBsQVA4mM5+GBA3i6PPjrHuo8I5Ltq/LjC3
         M7KtASB0Ow9h3HtkkpsB8PdyGVniKsbLIXPeJt8WgCZA1vFDL5NRc+4ziti3XoEuY7IS
         TbQw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bWxUf5wO;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70da723854csi5115956d6.6.2025.08.27.15.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:08:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-35-9CODWK8aMK6h5vL0lOzKFQ-1; Wed,
 27 Aug 2025 18:07:57 -0400
X-MC-Unique: 9CODWK8aMK6h5vL0lOzKFQ-1
X-Mimecast-MFC-AGG-ID: 9CODWK8aMK6h5vL0lOzKFQ_1756332470
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id AD5F5195608A;
	Wed, 27 Aug 2025 22:07:50 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 7867C30001A1;
	Wed, 27 Aug 2025 22:07:34 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Thomas Bogendoerfer <tsbogend@alpha.franken.de>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>,
	Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev,
	io-uring@vger.kernel.org,
	Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com,
	kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org,
	linux-mm@kvack.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>,
	Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>,
	Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev,
	Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com,
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v1 20/36] mips: mm: convert __flush_dcache_pages() to __flush_dcache_folio_pages()
Date: Thu, 28 Aug 2025 00:01:24 +0200
Message-ID: <20250827220141.262669-21-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bWxUf5wO;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

Let's make it clearer that we are operating within a single folio by
providing both the folio and the page.

This implies that for flush_dcache_folio() we'll now avoid one more
page->folio lookup, and that we can safely drop the "nth_page" usage.

Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 arch/mips/include/asm/cacheflush.h | 11 +++++++----
 arch/mips/mm/cache.c               |  8 ++++----
 2 files changed, 11 insertions(+), 8 deletions(-)

diff --git a/arch/mips/include/asm/cacheflush.h b/arch/mips/include/asm/cacheflush.h
index 5d283ef89d90d..8d79bfc687d21 100644
--- a/arch/mips/include/asm/cacheflush.h
+++ b/arch/mips/include/asm/cacheflush.h
@@ -50,13 +50,14 @@ extern void (*flush_cache_mm)(struct mm_struct *mm);
 extern void (*flush_cache_range)(struct vm_area_struct *vma,
 	unsigned long start, unsigned long end);
 extern void (*flush_cache_page)(struct vm_area_struct *vma, unsigned long page, unsigned long pfn);
-extern void __flush_dcache_pages(struct page *page, unsigned int nr);
+extern void __flush_dcache_folio_pages(struct folio *folio, struct page *page, unsigned int nr);
 
 #define ARCH_IMPLEMENTS_FLUSH_DCACHE_PAGE 1
 static inline void flush_dcache_folio(struct folio *folio)
 {
 	if (cpu_has_dc_aliases)
-		__flush_dcache_pages(&folio->page, folio_nr_pages(folio));
+		__flush_dcache_folio_pages(folio, folio_page(folio, 0),
+					   folio_nr_pages(folio));
 	else if (!cpu_has_ic_fills_f_dc)
 		folio_set_dcache_dirty(folio);
 }
@@ -64,10 +65,12 @@ static inline void flush_dcache_folio(struct folio *folio)
 
 static inline void flush_dcache_page(struct page *page)
 {
+	struct folio *folio = page_folio(page);
+
 	if (cpu_has_dc_aliases)
-		__flush_dcache_pages(page, 1);
+		__flush_dcache_folio_pages(folio, page, folio_nr_pages(folio));
 	else if (!cpu_has_ic_fills_f_dc)
-		folio_set_dcache_dirty(page_folio(page));
+		folio_set_dcache_dirty(folio);
 }
 
 #define flush_dcache_mmap_lock(mapping)		do { } while (0)
diff --git a/arch/mips/mm/cache.c b/arch/mips/mm/cache.c
index bf9a37c60e9f0..e3b4224c9a406 100644
--- a/arch/mips/mm/cache.c
+++ b/arch/mips/mm/cache.c
@@ -99,9 +99,9 @@ SYSCALL_DEFINE3(cacheflush, unsigned long, addr, unsigned long, bytes,
 	return 0;
 }
 
-void __flush_dcache_pages(struct page *page, unsigned int nr)
+void __flush_dcache_folio_pages(struct folio *folio, struct page *page,
+		unsigned int nr)
 {
-	struct folio *folio = page_folio(page);
 	struct address_space *mapping = folio_flush_mapping(folio);
 	unsigned long addr;
 	unsigned int i;
@@ -117,12 +117,12 @@ void __flush_dcache_pages(struct page *page, unsigned int nr)
 	 * get faulted into the tlb (and thus flushed) anyways.
 	 */
 	for (i = 0; i < nr; i++) {
-		addr = (unsigned long)kmap_local_page(nth_page(page, i));
+		addr = (unsigned long)kmap_local_page(page + i);
 		flush_data_cache_page(addr);
 		kunmap_local((void *)addr);
 	}
 }
-EXPORT_SYMBOL(__flush_dcache_pages);
+EXPORT_SYMBOL(__flush_dcache_folio_pages);
 
 void __flush_anon_page(struct page *page, unsigned long vmaddr)
 {
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-21-david%40redhat.com.
