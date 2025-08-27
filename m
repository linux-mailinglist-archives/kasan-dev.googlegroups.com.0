Return-Path: <kasan-dev+bncBC32535MUICBBQUCX3CQMGQEB4NUXIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 22BF7B38C5D
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:05:58 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-244581ce13asf4531335ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:05:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332355; cv=pass;
        d=google.com; s=arc-20240605;
        b=MY9MU0/6YkbuCjt9uW2+BW4DaOXfMH99+DAlzQwaikzei87S3z/u0dDvFx8uPGThVy
         vW47cjWa3Sapr5bcSH6NKUrPpJm9GXlfauqEzwpOUuo25T9xYdKsKgMw5Oq3Bh+D0A+r
         RTi2sjbjR1dVFsmI1g6Q/YBgNj/jPnBHmU+0daBW8+U5vdgw6tg0fFNK17ZkkaFPj3Z1
         JaNyPhq3sH/ZoFrGq1TdIlx+RkWq+hnTwDQoX5wF9zuo/gi0dE9VEcw3D5V8lEd5OrHk
         m4XJjTrUe8XMDIijye3oZea3e9QJKKkOFjFv2QhjPhigVUF1/D3d0EI61SKTMg7z8P4U
         hzeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=UF9OEOQuaAlh2eJ8DfUPeJ6V8JP7Em6el04FlMzQY2w=;
        fh=Ny7nKNQs6hZNSR9v1qTkAq5MJ1adKhQpnpjUNLNljaI=;
        b=gEYKuZwIBi/8MFDFcI1i4+JE5uNv+Q6S06p40jmclDfcyIz4at9y9gov1S+SnwxWhv
         jQ0uuqmN6WqjJnFQYiQldT4jzaECNgmJ0YXPtZBmlp/O8TCY3XPPUsNUtm5L+E5CL1oo
         uoyA9acfhtFViH2m+It91o1m94cvd68gT626UffIk9i/bBOAchH5kXaMK1Nl0t6qX0JE
         Tnr8pBQkQpbM9j/NFWdhmbpU7dgoAL+NGbdIengLMES9Rxleqd/sENRsd6AUwc1gE3xf
         NTTSD+L3Jwj1HV1BkQmZDlR61t26KppQrsP7R9TbExZlMjFRQpe39vWSoezYA2c1Z84q
         bWwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="NN/a0zeo";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332355; x=1756937155; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=UF9OEOQuaAlh2eJ8DfUPeJ6V8JP7Em6el04FlMzQY2w=;
        b=tNnrMI6KXKeUno8E6cmMMaDoGYsowsT848L/BQ5dgCsLnNxwYEmedUZ15MbfojF2OW
         ER9o80LJTKkiHYZSIjpiQJm4CxttsBvhvDC8sMDtqGdpBBbCdCTheedeE64bCOjjMS3g
         5CWeuWPUeu7EgNudVu3RX1Rhzao7FkkWBIJ3Xp6ANOLaFg6Vu2LrakjMFgoVfcWYxMaT
         U6NfZW/qe6Tj8+IdvcLWtU15rZqHWFwehfbL5hmYrKTClKPQ/bEKG0YDQENin4Ptl7vG
         Rjm4Tqss+YjhqB+xsnui4t95Xau7GFz7igVzCmfLOlXKv+4q6zQ1/AnhEw2OPC2h1Q3X
         i/EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332355; x=1756937155;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=UF9OEOQuaAlh2eJ8DfUPeJ6V8JP7Em6el04FlMzQY2w=;
        b=MUO0+Vo497/VOUeQIjS1ls/U2Kn2skYS5jzKS1RizO/pr0fI/g6NMhKoI2cWOdG67y
         hk0uMQ4gVRLYHU5WJPMH9HXcerg0qF5vshFh7JH0+6rNUXu8ffKTij8YsyxSSriuTKru
         0VK+BeDWwPDX2HV5TLJaCWkYwYJ5ZT2F2E3cifjcVsMFqaRv+5LfuP7Q6nKbMONcQbr3
         G5eeNgGgtWAKSuBR0wp2AS0afZfcAAEAXQJfvUHbQ1DqAK15PXrQYDzznYD2Q0FLzZgG
         mwY6uEnxGIz0N7Hu7QG6y5kOHTTngaRTTKkXeEPLAT6JxxntUsXIZcrKSVQxZyKBoWww
         rymg==
X-Forwarded-Encrypted: i=2; AJvYcCXxG+aZK6DFlXSt+li3nHrJBPC8OTueibgclBJIH1fvyDH9RFWnPbEGm/+ejlFuL3jBrQ2+Ew==@lfdr.de
X-Gm-Message-State: AOJu0YzK/PMOFMsh7/fDuJ30+eBdQxiHP7Q6AcjuKEh44vmKvELG0bnV
	wM0E2+0PrfmkOWXpgOgPRbluc8k+N/V4T0W45k0M6zVqVuxqVCLpY1wN
X-Google-Smtp-Source: AGHT+IGcw7QZ2BHo6+zglDvYTJHS8qlA1xLBj3fQ2wJAhPwrHjfVzt79CsK5IAvQATLhGp3N+eNDrA==
X-Received: by 2002:a17:903:2347:b0:246:d743:b0fc with SMTP id d9443c01a7336-246d743bde9mr157147335ad.44.1756332355006;
        Wed, 27 Aug 2025 15:05:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdUG/gNVaht33cClbVwIvxWJKolL3YPuOWOeOijT15n6A==
Received: by 2002:a17:902:fc85:b0:248:8490:feaa with SMTP id
 d9443c01a7336-248d4de702cls1284695ad.1.-pod-prod-03-us; Wed, 27 Aug 2025
 15:05:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWE7icQdkEVd5WH9JQi3RdQP/3UIx9HZSKNxE2oHk20/I/5ZtjmbPw/3yFH8oANLNrFpRYErYtevek=@googlegroups.com
X-Received: by 2002:a17:903:38cd:b0:246:644f:5b81 with SMTP id d9443c01a7336-246644f5e62mr235082765ad.32.1756332353707;
        Wed, 27 Aug 2025 15:05:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332353; cv=none;
        d=google.com; s=arc-20240605;
        b=NRW9VTe2hzrKkB1BG3w+oeZbnrwR7a60NxYJ7SsB6Mv4oALjzdq/g7EXykx1Caxhfm
         j/uR+x3SNXlLmmYRy94W53olGE5A0t4iBkrqDoQzZCkPaxbBxrOUnphjlsIyj1ybsKjQ
         HDsGfv4v3A4BoVVkST3mCoyUl/vTYPwhA0yFSyPJxe64rXnvdj8ZvI9nlowFb8U7smSD
         SyVRKR8tn4SeQ3Ttow3VAU+AiMYKS2/js+O5y1u4tV7VR/ILnNu5HyzpesyrkV9HgaMC
         j+DCuD7eujltlhAiV9bMjstzByko/JDO25L7j6fouSoB8oNCPoDFvj/slz4RMsI81a+S
         u7ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tOg+y93CWdttiSRHo5MMFmvDG+rRd/OMag8GX96YAWo=;
        fh=BCe2j8uw4cDMMzBBisW+kIEepM9ekfrlw/UgVNc9CbM=;
        b=TI1G0Zs+naueJcsH8F5TF8UvXNjyyo4A8Vls3kkAe5IzcqTNO63J1ykes9Bt5+nIa6
         M0QkGXIlMXzsN8mjtDbURxJfOUtAXwi0BBbJs3/dSWGi7qqruotFyBSiwZODP+4Vll1u
         tYsYM1QdlipzMJy/LchVTtMgAw/0U51G7hRfrAhByXbwCeYQbmfr9+vuXaPPaNFfxUug
         yq30/eJPS78L2dSxtEJOmwsAfBc8dPU5KkNRoBqVVFgZIs64tTmSWsZcL5HhSxOMIhUm
         d8f5+iXRl8d2FrGKKVc4WJQoN1JXXA19sgSr46+lTFoSDH8MKLHTvfmdH4Z6y4XukRtT
         RH0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="NN/a0zeo";
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2466879c3f0si6247125ad.1.2025.08.27.15.05.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:05:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-468-z4mlROjvMIiLD1GebYFmSQ-1; Wed,
 27 Aug 2025 18:05:47 -0400
X-MC-Unique: z4mlROjvMIiLD1GebYFmSQ-1
X-Mimecast-MFC-AGG-ID: z4mlROjvMIiLD1GebYFmSQ_1756332341
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id BEADE195419A;
	Wed, 27 Aug 2025 22:05:41 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id DDB1430001A5;
	Wed, 27 Aug 2025 22:05:26 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
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
	x86@kernel.org
Subject: [PATCH v1 12/36] mm: simplify folio_page() and folio_page_idx()
Date: Thu, 28 Aug 2025 00:01:16 +0200
Message-ID: <20250827220141.262669-13-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="NN/a0zeo";
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

Now that a single folio/compound page can no longer span memory sections
in problematic kernel configurations, we can stop using nth_page().

While at it, turn both macros into static inline functions and add
kernel doc for folio_page_idx().

Reviewed-by: Zi Yan <ziy@nvidia.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h         | 16 ++++++++++++++--
 include/linux/page-flags.h |  5 ++++-
 2 files changed, 18 insertions(+), 3 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 2dee79fa2efcf..f6880e3225c5c 100644
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
index 5ee6ffbdbf831..faf17ca211b4f 100644
--- a/include/linux/page-flags.h
+++ b/include/linux/page-flags.h
@@ -316,7 +316,10 @@ static __always_inline unsigned long _compound_head(const struct page *page)
  * check that the page number lies within @folio; the caller is presumed
  * to have a reference to the page.
  */
-#define folio_page(folio, n)	nth_page(&(folio)->page, n)
+static inline struct page *folio_page(struct folio *folio, unsigned long n)
+{
+	return &folio->page + n;
+}
 
 static __always_inline int PageTail(const struct page *page)
 {
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-13-david%40redhat.com.
