Return-Path: <kasan-dev+bncBC32535MUICBBPXZTXCQMGQEDLKRNUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EE82B303BB
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:32 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-74381e06d51sf2718765a34.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806911; cv=pass;
        d=google.com; s=arc-20240605;
        b=hr4NTwYI7hLqJzmCsbdIsmYhb00PQNV0NiRNf/SH1Yw7wJtyzt79il9ysSn96AfW1c
         GY+NAFUkeM4mT/qHAslyQe+rgUvECn0Ur19jDbqDCge9yLrfGecZ/WblCiVBpghvrEAq
         g1/voxMEkrR6b39nqvtzAeGH05opudp7oATKHJRwTf6YDyqgrsMQdP5WlYaX4xv6khmm
         5bTU23287KiCfA+DyQKcxDYJ3uhAQAucEAqz+SiLmYCLO5rdJIXAlHttE/Tqsfu3juXO
         jhpKH2eafrQ/mDjxMfAVvb36WWh7aKNquWTLvv2/BtszvGrdZ1lW8nqL3BL1+/Sdz+Lk
         2BbQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qkiqfYLP9kwVYnlPr+gusgB3Ovek/73CP5v8OWI+8Ig=;
        fh=3enp07H4S6r0l+6pFPFrfi4On93Tnn+zVOyE9ufwgtw=;
        b=RLAJQi2ha7OXkpNpbNCyJPvXt43JeE7QBMPfUaIARzbg2tYm4TShFVYrBHTnSp8gsk
         Mirzq7osBwPDQZfnk6aAx0RfAcKtEiZ9FljsTVPFEgiyki9VhD8Anfam3rZaKNqmAUNe
         X/jiDSN0vSf2hoLPWgDXUXecMR2JSlEt7A3aXA/XKx9Cex7XUKVmmXIZf16L5+F/OAQX
         j0Ih1JiLVjFMtamfPhzYBGQBNSH0Mz1G/3NlZbjV2MhzM2rKK9f6Mu+nc7fjO8zRju0Y
         nDnzcusgX30wLvRAy5EAjy7IdakSR6KZRdnqZTR5kR1LJVq+eGVf6Ew1hw8ZEzZ1cSlT
         vtOA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Gwa3d17M;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806911; x=1756411711; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qkiqfYLP9kwVYnlPr+gusgB3Ovek/73CP5v8OWI+8Ig=;
        b=ukztKc9HG9qfgl9eAYRpGb9CRW9pElQfiCKOC6vz+tjpwqZpD50ZjeKxBPHNMTaCrw
         CwBUPM15EQ+XEHh5P78Wj3C9YqyuyhmZaIFBjlpiUVg5r696OpyYG4Uv3M382A7E7iUM
         28mLU3K9iRjmXm8ad+TUtiqc7rc/11poMDVLGn/g/ZNi5LnhzknRs/dculGKUXMrFGNr
         InzVY47DfVsVxjxT0osleVQOQg9GMhOYTLBQR/Waa8IujrgJngjnwrJzEggU1Tf4KD6m
         7VCWsQjR+a2VRSqgETCYHSq0vSnnDdJkvIO8vBKZKT0VaBKZwGPITNEw/Ip6hrSvBZe5
         GGDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806911; x=1756411711;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qkiqfYLP9kwVYnlPr+gusgB3Ovek/73CP5v8OWI+8Ig=;
        b=IJocfWsw7J3RAbFu/3gCZWh9huEGZ/o5/jAWTiP2uc/XruTmEbehupTCdAxGivgiNa
         R57PCxoshff+fcODZ+124xllAgCHRSaUfolk6oKY74zH69zb2pTs6kpWHwEoP3y8/sBh
         NUlZ5WHwcPwnJwAHWTogDNca3Ic/YaE8IOowvCkncunonhhNyv4MZpuVcvPddtlvsbGW
         nVYrOoctR/gXJRe572F+7XxZh2qoPAEmxnD4mZHuqmGMGBzs04ZsmlqHCOn5Uwv/4QL4
         dvmgZfgkXVuF5oGfxAJpkz0XsrIVpDGfnZvvZxsiDuUBtA1Rh/TiAF51HDTlOljp9gIv
         YALA==
X-Forwarded-Encrypted: i=2; AJvYcCUZkRMxQdFNXXO3iSmlhzhUAhWMSsNsn5f/khQtJf9vW+33+4674yt4sBqi92XV6f+QHWkc+g==@lfdr.de
X-Gm-Message-State: AOJu0YxWFgTVIzWSFenBrkiVV21AmmzB5qy9sKfToy291UNA2ZcuE3A6
	mw9/6qnZhS0iZAo2kFlNOObuD3gYW9vyxMWjbJqYEdNJ0e7hpwqltX19
X-Google-Smtp-Source: AGHT+IHvsHPM5un3+0p9bytTTSfk6JL1LsXFjeLj60PQFzZeNlTRUioChCSHVjrPAlZrWD+mOKDheg==
X-Received: by 2002:a05:6830:6086:b0:741:b8fb:539e with SMTP id 46e09a7af769-745004d3c0fmr514939a34.0.1755806911010;
        Thu, 21 Aug 2025 13:08:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeXrf+mT9OjJPQ8mULATIdwfyU4GdRF1MIV23ldgX7H4Q==
Received: by 2002:a05:6820:4006:b0:61b:a7e2:c7a6 with SMTP id
 006d021491bc7-61da8c8502cls662422eaf.2.-pod-prod-01-us; Thu, 21 Aug 2025
 13:08:30 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPumbJCuXrPQXKlyt+QGsEBa6hpB4f7iptwHAjAEfAJk832+L5HUffrJ3GxjENgV6PhlWEVKNQy2Y=@googlegroups.com
X-Received: by 2002:a05:6830:2805:b0:73e:aade:aa28 with SMTP id 46e09a7af769-7450094630emr440745a34.10.1755806910189;
        Thu, 21 Aug 2025 13:08:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806910; cv=none;
        d=google.com; s=arc-20240605;
        b=MdeWmSWPXuPvdzCM0AWOwoFthRHM6xaemWkRhumECJfxjLTYFuFzWBlHhLNt+xkUnn
         OgGotIqHkLETaIsTo62IkE7ulA5aW91h4p8gC74w0z97lzaBWr6HNF27rKrmdj9HQdHo
         FFqMEzAOBrmf/MBBV59tYuORustVvrRIKYgNh2nvzf1N5KZx0R671Mltco5+hcdpBfyS
         NPBQV4Msz0oxT3C56+6gylSSUyu72VnhUu5lS4TXpJ+hJD66DP4SzYkyDS3VxBKzRv9e
         Q0sc1YIZIS+wvl3fWhpbC+aysX2a11GSr3mRznhnvvaHndmEW5/yVoPEsIL+Y74nXXGl
         J4VA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jaRFM4K4Pg6WYlxhcM2k1BGbQ/DW6XfjnDsCttbmjXY=;
        fh=Kn/mGLlzXk+9GkV3uqJg73Fc0ywyK7B/mzpR5tflr3I=;
        b=URCRiSzKzxl9tbZUW941DOiecGHk1rBLaHumAE4vWJz+NkFK1hwfBp4vizPKZOjwM/
         xH42qCkVXsjWriBrFk8oWOCVkQL1r79fWXayGuuwnkeJ1MMMfurFWvl4uSeUyFHO4woO
         ZsWRWbGX+HalEqw/Y76i8JOCsw63JVAGLiuqHy8Cwq0cn+GEdMxa3jvBzAN0wICoA+/h
         B2rpLHxkYXK2sAc7ic6U7BYOxOxdzi2NSw4w96YvXVUoXxFQs1xxuhxJajBzjtFBu4HD
         eMBU5zpOwOwseXvSMCc8Wx4csuGi9xd3cLnWM0dkj4wr4qRfwfyFK6VtOd+rEOTDiaKt
         Ljng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Gwa3d17M;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74392039539si233250a34.4.2025.08.21.13.08.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-428-PPIaUwjgPlCMqHdrAfCMRA-1; Thu, 21 Aug 2025 16:08:06 -0400
X-MC-Unique: PPIaUwjgPlCMqHdrAfCMRA-1
X-Mimecast-MFC-AGG-ID: PPIaUwjgPlCMqHdrAfCMRA_1755806883
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b0cc989so8653065e9.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:08:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU1XkoHCZKuiwwvQ9Uv0nYB+rQgHNcxgi9QY/DNwYNQNPYstgNYPh+C8mWB06oSIBQl3FVi5LujAq4=@googlegroups.com
X-Gm-Gg: ASbGncsYLBYN8MIG7PhFNST6n77r0ORfxugL/Q+Gx58RRikf53Y9tqGk7H/IkXu4YzQ
	5mukZK2y4llLDkjyxK1Cuzu1VLIsxVTUQTEsvNLxb7cv05R14iV/TUyGFBLCWNO8u/ovqOxUQ57
	uBCcJEUgUacRTVrLxOwg6wAzDRrYnuLHfC2i2aKRirXtFOA1inTvi7nl4w50fwK2XgzQiwRYuHo
	QBCuhlgiNzSFyAYCA+GlQDoBe5DL/WNp5Yk+zE+5dV2ll1r4yGeYmeDL4GmY3SQJPMVj5qdRDpY
	iuab1CK9G2wNwCECETZ/yeSj/QGAXU+BF6xWDQAw5Le7NZbt7KvKX/D0V8NIu+xb7yu3KJsNxqG
	hjd1uRK5qNTeot3DhBc23xg==
X-Received: by 2002:a05:6000:2012:b0:3b7:dd87:d741 with SMTP id ffacd0b85a97d-3c5dcc095c3mr196216f8f.42.1755806882820;
        Thu, 21 Aug 2025 13:08:02 -0700 (PDT)
X-Received: by 2002:a05:6000:2012:b0:3b7:dd87:d741 with SMTP id ffacd0b85a97d-3c5dcc095c3mr196155f8f.42.1755806882316;
        Thu, 21 Aug 2025 13:08:02 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b50e0b299sm8957945e9.22.2025.08.21.13.08.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:08:01 -0700 (PDT)
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
Subject: [PATCH RFC 20/35] mips: mm: convert __flush_dcache_pages() to __flush_dcache_folio_pages()
Date: Thu, 21 Aug 2025 22:06:46 +0200
Message-ID: <20250821200701.1329277-21-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: njvltaSmnbSzRssBfwmmi93uj1Jx2Wypk0hCk0CyaM4_1755806883
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Gwa3d17M;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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
index 1f14132b3fc98..8a2de28936e07 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-21-david%40redhat.com.
