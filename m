Return-Path: <kasan-dev+bncBC32535MUICBBUHO23CQMGQEZSIHIMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113e.google.com (mail-yw1-x113e.google.com [IPv6:2607:f8b0:4864:20::113e])
	by mail.lfdr.de (Postfix) with ESMTPS id A8981B3E8B4
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:10:09 +0200 (CEST)
Received: by mail-yw1-x113e.google.com with SMTP id 00721157ae682-71d603c7e05sf62011687b3.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:10:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739408; cv=pass;
        d=google.com; s=arc-20240605;
        b=BXPgI+VK4McVDy+xI1f57BaOxFhp0Ia6xonRzNPLMT638bj7uZyxc42Cn5fq8pLIqT
         0g/trXlp8aJUQJw+B6/iCdxY67xM1WjRLE3QIYgsA68deeClAPkCZCL9pCP4SDewYYIh
         KEqTSiZlG012LUAjN1dYjBZm7VHaF629ZiiJ97kA/sEqNR6PWN+IPG1GP+5IyLdwF4qh
         4/hY1ha/Ds+IgFiyEKa/HknoyCBvfBRfODw7U0sqy4VkGrboZtukSoJ0BUI3tHo0gCWE
         e/A7dvov/ZG0eBDhqEW2NJEyzNdFWhJVZ3YbhhrHrio8XZpD/BFCdEQLWmMCDFSpSr4G
         /1gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=TctDf+Zq/Yxt8anjBb8IsUdZDghvlRFpBl2r8oO2lJ8=;
        fh=FDoy6ATsorNe78tnW2hOlgyRQCOeYVbR5priCtEHCWE=;
        b=Rc5XbTUDNOowOl2gx9meqy6OWvLJsMmuYZoRuCD1j+Z9w1eGsy9pspwKy+Lp/kQXYc
         MCCSUucivZ2NzrF0T/gY9s/0kPpLk9whvMS0/7rO8DZnHaNTwZUMjsBfQophGaFRyJ7s
         rU0gbbGrPs/ttOsv0YWzrTlls90pAdUEMkgpXq6y/spkB/5IDWu5zhSztEB5hD3IOacY
         MQbrfszCh3gYNME3sb0s1/scnhbjZNAXwypCC2yDwOY9PFYHNQCmiGut4pZ1xRIad6P/
         ABR+BG9X2XW0rg+HhL7zCnSrX4C5bRRmlvlgN5bIPosFnEZ00uq3aNG82P/RIn9K3fgX
         1v3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="abk12R/m";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739408; x=1757344208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=TctDf+Zq/Yxt8anjBb8IsUdZDghvlRFpBl2r8oO2lJ8=;
        b=kR7msE3wS9m1TU6l6HIu9cC/4sKxw5+gcLRRaYcggVKKQ1VzovSiruzGBiFHHh62Qn
         +E6g1dl7/dienIpWzjiFdyaW+JCyilttO/bbRXj5PxrEevfezs3iiKhVRS8bPv06gCXv
         7P5h24cisSMRGvaDSJ7n7eKChP1FrCGukOx1SMpXwAO+N0wEjdMuKAWD0Wpa+I98XDRP
         yqwhJjuyq6J5XeP09DELwtnMAdUQO2MiH/YzXu0h+vRspzyZbnTgOse5WB6rpnj8BPW8
         jkbBV1s5v4wLhZV8n4xVq2GTBahXe5hCbp5NpjKy4x/ErJ0dOJ8f8vCwW50H4ofpLQ1k
         qvnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739408; x=1757344208;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TctDf+Zq/Yxt8anjBb8IsUdZDghvlRFpBl2r8oO2lJ8=;
        b=hGxh10UxybSXZ1VZPvKy00YxTjRxNdGwM0vXBWyLNk+8EC6RTwnch90wgqU8L3HfCM
         D61enMwV1QEhbPzwfrALarbgg/NrLwhtH+pdvZprcbfiQKmTRr9IJgQLGiHOWnILDJkD
         Fo+SJUE+289OzcmbWr2WA/Y48F/fJTQ/Y21L8cKb+EavRPcVHVL5xm5CTrQN+wSJhWrv
         4c5EsPa01xt70F0QLe0fBZ7w7VLK56cO77J6jG85Ywe3nJzQAgo0mhLirF64Vik9zMmN
         bP8EUDgKsVze8p2LgGVuKZcpOft4R4ghrjGPHAxJifJ7HhQn81AqSAnVFmKS2xrBvYWp
         ImxA==
X-Forwarded-Encrypted: i=2; AJvYcCVqWxVBg81aSc6vmxCnsxUEMQtoR3DliM+7XShyYML3fUPZKw8WStLwgzDhaDjSlqf4jHSLFQ==@lfdr.de
X-Gm-Message-State: AOJu0YyLJ9wHXgHl6JaePnkM5UY4t1nwl89zDveA9BwIqTko2ak1gOUy
	2MF9b75VIRF+r/Z+QnbJRC834FTDJNYnAvUt0Sy8nxwbue4MGkgW9PbR
X-Google-Smtp-Source: AGHT+IFMLl6ogOOiyzz9LgLVYIfo0Gqqs3xCSBJXD5TRvB4TH7PerWdbY/vzjDfBCiFiO31H3W6paQ==
X-Received: by 2002:a05:6902:2192:b0:e97:4bd:6e4a with SMTP id 3f1490d57ef6-e98a585bd81mr7626363276.45.1756739408256;
        Mon, 01 Sep 2025 08:10:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcAbO7NNss8qSjLVU2ARfZT3tDwvAe0XnCL2/AGWn9P4g==
Received: by 2002:a25:7a86:0:b0:e96:ea4f:634e with SMTP id 3f1490d57ef6-e989fe3a53cls2188221276.1.-pod-prod-04-us;
 Mon, 01 Sep 2025 08:10:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWU8g/ozgCCu7MgZ92OSU1Db/0Z6cGgpu00N0xN3CXx+ljTyFaKNBh+gH19R0JcDAFVAzMKMZRc+84=@googlegroups.com
X-Received: by 2002:a05:690c:930a:b0:722:8cbe:b6fa with SMTP id 00721157ae682-7228cbebf4dmr50177667b3.20.1756739407245;
        Mon, 01 Sep 2025 08:10:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739407; cv=none;
        d=google.com; s=arc-20240605;
        b=Y7bp0U9Qf6UDA5MLpIpyT4lXnepWGPliX93RiW4scGw8p2ChFa8XX2HiQSDDv1EPHg
         QuHY2ebW4LXczz09n/QtIw/EDph/cpMkYcBUgOv+uoqYYd+10Ncp7vyZNeUhxAWiy6nF
         zKig29JafBNhv2X6Rmwpyuad3yKa4+pf0chgLjJUrKCI7xzd8KJETvhZCE2aSJW7J502
         5lCHBz8+PLoioiT5XzVK8wZC3Rsv1Hiv9aenmnVDsfKCoinwiThTQKyUstKJ0kJ+eIhF
         uQyyi+FaY8gRjnicU6OFJrvVlBykgUVU+SOL9BX2iDKiuiQpFeXcete8C9jF6FRIj4EJ
         N4yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uU2NKjv7pCAnTWqWuT9I20VPbssYf2aSlCzQiIN12S0=;
        fh=/8v1ZO0Hg4/rJJNe0KyNXHtJUZOvRN9woepc/1DMyJY=;
        b=PurViDrMRu4w1D3tlEf7++WheMhrPTxycasW8oPn+YYcyQruRTtBwn4QxGPe3zNzxW
         mj/uducn1OW0vCgBbyhEd51gYvrN4eXkFt3yZ5jjSKiYb/FtNoR5zT5/N7A6NDFWSAf2
         Qn5Z5PSM+X8mh3IIHeLge+PhgE3Cs0j1JHsqmL5GtRBNKYJSUe74b0ePg3P1zRa+Zhr7
         vBej0u9ELZFNj+1AB+FZZn1abBOhNq+CQRY/73cPx7dXPw/KRW0owN72Zs+GgqTX6h8/
         B0/A0Xs8YQQ5ibfxlEXKMJeQMOuaxMkr368q4QszZiZzPKSQxm2pi5dMVappRbE48yUu
         i9MQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="abk12R/m";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7227d8cbd71si2219177b3.3.2025.09.01.08.10.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:10:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-292-1HVSq5buOB-VfBHfHyNaeA-1; Mon,
 01 Sep 2025 11:10:03 -0400
X-MC-Unique: 1HVSq5buOB-VfBHfHyNaeA-1
X-Mimecast-MFC-AGG-ID: 1HVSq5buOB-VfBHfHyNaeA_1756739398
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 7363A180034F;
	Mon,  1 Sep 2025 15:09:58 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id B1B6A180029B;
	Mon,  1 Sep 2025 15:09:43 +0000 (UTC)
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
Subject: [PATCH v2 21/37] mips: mm: convert __flush_dcache_pages() to __flush_dcache_folio_pages()
Date: Mon,  1 Sep 2025 17:03:42 +0200
Message-ID: <20250901150359.867252-22-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="abk12R/m";
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
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

While at it, drop the "extern" from the function declaration.

Cc: Thomas Bogendoerfer <tsbogend@alpha.franken.de>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 arch/mips/include/asm/cacheflush.h | 11 +++++++----
 arch/mips/mm/cache.c               |  8 ++++----
 2 files changed, 11 insertions(+), 8 deletions(-)

diff --git a/arch/mips/include/asm/cacheflush.h b/arch/mips/include/asm/cacheflush.h
index 5d283ef89d90d..5099c1b65a584 100644
--- a/arch/mips/include/asm/cacheflush.h
+++ b/arch/mips/include/asm/cacheflush.h
@@ -50,13 +50,14 @@ extern void (*flush_cache_mm)(struct mm_struct *mm);
 extern void (*flush_cache_range)(struct vm_area_struct *vma,
 	unsigned long start, unsigned long end);
 extern void (*flush_cache_page)(struct vm_area_struct *vma, unsigned long page, unsigned long pfn);
-extern void __flush_dcache_pages(struct page *page, unsigned int nr);
+void __flush_dcache_folio_pages(struct folio *folio, struct page *page, unsigned int nr);
 
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
+		__flush_dcache_folio_pages(folio, page, 1);
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-22-david%40redhat.com.
