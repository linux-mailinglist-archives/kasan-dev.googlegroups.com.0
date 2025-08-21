Return-Path: <kasan-dev+bncBC32535MUICBBFHZTXCQMGQE2746YMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 2597BB30388
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:09 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b4761f281a8sf1074075a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806869; cv=pass;
        d=google.com; s=arc-20240605;
        b=DZydP8aIvAXJpSlISmvTjLslSOwCNb0g2tfo5Tl56MbYVTv69zSQm4qslCM93hXidk
         Q4SftTTmiyTIcByJoKk9yKo/6JGhgoeZUrT2ZGRGJ4wfyxQE/J0YSrR9/zDWSccEpbGb
         h9DTcyR3+V7vxOrXqbihnLsi8h7WEjHvZsTLsoMqT9/FSc0DHHduXucTqbUT2E7VlWjE
         Iz0V6yUOkqWq8PRJAVQFyHYlw0RASVyw3GH/aFBkjwoZx0Vhw4OyJwqbEo1k0mIpHWub
         06csSSbN3XmFRSggTeksHRjycZH2qw9Vu+x5n/UT3UDrLwVtWjOJ9MlRJY2FzfSzmkF5
         wHqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=0GrOo/rAqVoTPl4v/2me471WH8J8B8WzqYbtKPPUDyc=;
        fh=hRVuKH6i3fUYGWcwGoTodvrL+jYxFXjEhYeTbdnDDRU=;
        b=gIt76MBhbGAX2OYVTuPQDIeQL1OIlja28dxkniSmtzz4raxP5pZx0+q2lygyf7Nvhd
         tY6Rn0PGLKns+EjnvjPNR4rgX4coIyIXt++r6CWGKmRDOKsg05Rq5zICmiwFOCP5rjZP
         d9RK8MnlLnvI45VLFME+Tsa/wIWliR/6ndTfcAI01fu1WSHt7t8IMAIRskySvhg3ywGd
         3SEIn/iv7coj2/no+FSwxrXkzPam0Z8EZyKI3GfZ1kw8mL1ShLvHoKqA/litWvagFGOj
         z63zDVbkQMbffJjmLALNAQDgn1UIgqHlRfElmxzWio9xWIBQSxWfT6Lnp/POBmdk4lTo
         uz/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SyYTfZbu;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806869; x=1756411669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=0GrOo/rAqVoTPl4v/2me471WH8J8B8WzqYbtKPPUDyc=;
        b=WUCvxoppbBy2XRZaai+GMw9BMmuef1anyO5qDDjBPsldDthLx5D37ikmOIkIGyUisa
         hfcifSL5Tq7tHxNG9hX0cZn03kG53Jd1N4ocJGgM8tb2qnu2InTr1Dv5kKxNc4vhFybT
         L6Zw+Of2vFwC1OwKSB9TkyL5zLLnYQ04m8J2XI027vw4rcFmtGzuYFBWGoSrTfUlYo/N
         6fHPAQhEWEryPvzkIQcqIzSJy6eWQoTYgA2VbaPFLjA7u9IlAcWuKJRRBR3JKvmN3wY7
         r49sNLhk7AzDAtt+bUIzIEf+PFmBIk/O9KPLxkQAXWgXLd97mVPTbHjTWOhAbMnWnPJu
         uePA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806869; x=1756411669;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=0GrOo/rAqVoTPl4v/2me471WH8J8B8WzqYbtKPPUDyc=;
        b=sjtKAHWaPjrZZRlyaxjd0On0xqDcQCltHvHbpOH7xRywHNd+rDXr8l3NGNWF3GhWs+
         45xgIOkpqLwHv3Tq5cwF3n5hhSq5AJrDIrYXvYes9w7XW1PQoSfmoBWQZR4c0gTk91el
         VCJQ9i3GD9zWkI3HCyC0LVbKKTFcIgJFSUORKqG8xH8uPPHp5QzYatENZVMmpnWPMPLU
         POIFnS2wfdIdk10nKbL8k+p4Xg70D0Xv8efUN0d8PWFQstJFZQ1QJ9d6Depj1foA5Kd2
         q8dU8F8o51z2keh4Tx01hgcKDUWEjBP6NGT1r46k5+Wm1GexHNN1weT5l4jhZxb/IGdy
         eSiw==
X-Forwarded-Encrypted: i=2; AJvYcCVYwQowUIrarJ8eUvG7Z7uoKqp/4rpCUjDVYZtzzLMcOtXFXG7k2U4epbsCBvG/9h1+V5OaeQ==@lfdr.de
X-Gm-Message-State: AOJu0YzVWLEKVoG22QsJxoMj4uGkOu8sPaPidf8VUwYhZLT5PDVZRcey
	u/ZzP6pUovPK97Uz825r/ZGa2zEuds84zP8yY+U9M7bdm4nPfJjTAiHO
X-Google-Smtp-Source: AGHT+IH/T+KYkdopDEd6S5sergShZx3l+GgU18VFHYeQe4xQCdXIsR5BC1qccHGEjicohOs/6EHFXA==
X-Received: by 2002:a17:90b:5585:b0:324:e714:2abc with SMTP id 98e67ed59e1d1-32515ee1501mr1001545a91.15.1755806869266;
        Thu, 21 Aug 2025 13:07:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcb9VAiA73bDO3XftoQ8e1flabjysSSG0XrYdLdtKiXtQ==
Received: by 2002:a17:90b:3144:b0:325:2132:a299 with SMTP id
 98e67ed59e1d1-3252132a488ls27750a91.0.-pod-prod-04-us; Thu, 21 Aug 2025
 13:07:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlaLHdai3KrdJsItil+1gZGceuwyUhOLzdVqzSjWmQlur8UFX0mrhL1rGsaRSAX+4fS+HnQ4bjw9I=@googlegroups.com
X-Received: by 2002:a17:90b:3b42:b0:325:dc7:7d35 with SMTP id 98e67ed59e1d1-32515ec320bmr814954a91.8.1755806866989;
        Thu, 21 Aug 2025 13:07:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806866; cv=none;
        d=google.com; s=arc-20240605;
        b=TtSK50GiMCG1TycjgyHq+tUyq97u7ccNrA70uafEG2C4K6VQK7bUzZ/WfmxF3PyAr7
         ruBvMbGQRSF5u3j8OXT9ycVlrFwNOio2d4QPLNxfbm9CAXUPmNQRlgyJSJzhu6FlyTQF
         hVEXILbfOCOqIiyJV2kWl3/ITIBCxHcNKrwoHXuRU7Zoh1PZnxykS0p6yLzY0CVzp2W6
         VnDvuqXzKT4WPE6x/yOlyHwraJycFQXAA2ypEw3KH3Rgdi+FRZ+Ebq+f7O6TF3/tMpi7
         VoF8nXzOvbsBkFNxtNccJReF6xBpWonZXU0Hk43JD+eQuR+fwDd80XWSpANf2SW1+0oB
         xqCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PkrXh5PHMEq3NY5i+0892fbAshOERsmwyMLhbVIa0Cc=;
        fh=kt+765PMUR+fZowp83MlQf1li5reE6I6RJUaJwoMXBo=;
        b=S4h2dZzQUh1KXj+OHHiElfvHRKmwLq1RHUPq/vxvQicyJa8mEpDdq8t0FODsSQSqv7
         53EhnhQcBo6330sH9WNX0KNcUWWKHl6R+kyTTVhnSTTOA4eMnOakBRZKUI9SBV7xdoMd
         x2HEdvkXxTex1mm/HXAPioReFL91tmGoHx7Bcy3FqASdDslL/YQVEBMKLGvwTL1u2yMK
         14p6+9G1JW5bLz2zhPHSIeAm9Yk/umBvCmg7TNgvZPrzjzDXGQ9GNK6MC7V7eqWJ375y
         DJOqsVmQoZFRK5UMomV6+yKZy8tw+LfCmFcOryc97QmMz1pHiFCmmrz2JZXBkctewTMx
         SvQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=SyYTfZbu;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-324f3840f6bsi112786a91.0.2025.08.21.13.07.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-541-GyWLjwwqM9CeI4tgN975dg-1; Thu, 21 Aug 2025 16:07:44 -0400
X-MC-Unique: GyWLjwwqM9CeI4tgN975dg-1
X-Mimecast-MFC-AGG-ID: GyWLjwwqM9CeI4tgN975dg_1755806864
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3b9e4f039ecso759277f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXdBC7lMiNpjMt1QfvgDuMdq7mYKtH0ERQKrzNMwEydfE7/8N3yefZYzItwwSZEX7zVWmby/wAGGo=@googlegroups.com
X-Gm-Gg: ASbGncutNxDirWpxPE0I96D0o6a4M8sQpxUgh/IrHdos9NWi5WNU7tJaBndgcEwso2y
	aNasL+DRi+LGHzLYdDqRdVw3neUbyUGmvAfQk4THzEkKFVLCOwG7ajpZ969j6LkMYtUU0TrICcl
	cS7C32K9J97NS7guPjBKEZQjb6CJtWJtmZUjM7cx8Z/cc5rXdxM9cZ8GRoJbPRVFRrFxa4UG0PV
	UcMR6SWQiz+JqI5Gtkb8KRmnIOGbSOx0bnvdjj1my/lRvebez7UDeLR6SedNa2A7YGJrEPHrjzU
	BVjpECDw39CEisQ70vpn0zjhK/W1fgkSo0F+XHgwpbz3RDEuAAU02Ff5NZuivSxaqYLNaW8Od2X
	AjlTtx2UNReLiJaGuQ4loGA==
X-Received: by 2002:a5d:5d0a:0:b0:3b9:14f2:7eea with SMTP id ffacd0b85a97d-3c5daefc2a3mr192555f8f.18.1755806863491;
        Thu, 21 Aug 2025 13:07:43 -0700 (PDT)
X-Received: by 2002:a5d:5d0a:0:b0:3b9:14f2:7eea with SMTP id ffacd0b85a97d-3c5daefc2a3mr192518f8f.18.1755806862961;
        Thu, 21 Aug 2025 13:07:42 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id 5b1f17b1804b1-45b51b61256sm1742995e9.3.2025.08.21.13.07.40
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:42 -0700 (PDT)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
Subject: [PATCH RFC 13/35] mm: simplify folio_page() and folio_page_idx()
Date: Thu, 21 Aug 2025 22:06:39 +0200
Message-ID: <20250821200701.1329277-14-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: z1_P41TaJ2bK3mEgFhNC-ooAolrIYuhXMz2upZeAh0E_1755806864
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=SyYTfZbu;
       spf=pass (google.com: domain of dhildenb@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
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

Now that a single folio/compound page can no longer span memory sections
in problematic kernel configurations, we can stop using nth_page().

While at it, turn both macros into static inline functions and add
kernel doc for folio_page_idx().

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h         | 16 ++++++++++++++--
 include/linux/page-flags.h |  5 ++++-
 2 files changed, 18 insertions(+), 3 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 48a985e17ef4e..ef360b72cb05c 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -210,10 +210,8 @@ extern unsigned long sysctl_admin_reserve_kbytes;
 
 #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
 #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
-#define folio_page_idx(folio, p)	(page_to_pfn(p) - folio_pfn(folio))
 #else
 #define nth_page(page,n) ((page) + (n))
-#define folio_page_idx(folio, p)	((p) - &(folio)->page)
 #endif
 
 /* to align the pointer to the (next) page boundary */
@@ -225,6 +223,20 @@ extern unsigned long sysctl_admin_reserve_kbytes;
 /* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
 #define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
 
+/**
+ * folio_page_idx - Return the number of a page in a folio.
+ * @folio: The folio.
+ * @page: The folio page.
+ *
+ * This function expects that the page is actually part of the folio.
+ * The returned number is relative to the start of the folio.
+ */
+static inline unsigned long folio_page_idx(const struct folio *folio,
+		const struct page *page)
+{
+	return page - &folio->page;
+}
+
 static inline struct folio *lru_to_folio(struct list_head *head)
 {
 	return list_entry((head)->prev, struct folio, lru);
diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
index d53a86e68c89b..080ad10c0defc 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -316,7 +316,10 @@ static __always_inline unsigned long _compound_head(const struct page *page)
  * check that the page number lies within @folio; the caller is presumed
  * to have a reference to the page.
  */
-#define folio_page(folio, n)	nth_page(&(folio)->page, n)
+static inline struct page *folio_page(struct folio *folio, unsigned long nr)
+{
+	return &folio->page + nr;
+}
 
 static __always_inline int PageTail(const struct page *page)
 {
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-14-david%40redhat.com.
