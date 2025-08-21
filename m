Return-Path: <kasan-dev+bncBC32535MUICBBDPZTXCQMGQEH7R2LJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 330B2B3037D
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:43 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-76e2eac5c63sf1298403b3a.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806861; cv=pass;
        d=google.com; s=arc-20240605;
        b=QrEBlOkBRK/sJohal/k9/mclpjpE0D88UAMZ/U/X9qw0aFGnVWh0sH74Kj7aqw7e5h
         Puw7Yp4BQJNspIV7cq22Tzcp3FqVp08UxStuTIdmPQZIn63MU6RuimZouUKbTKd8txJt
         aEfFhpbaAmzv687L/BDd5332jkyAVuHBLST8WylQlehDes8yRIh+TY9oOuTfgsxrIUfL
         /lLyKYAjjtIHMrjMXgpC+QqWmBCzqD25dG42fVAEL3KE1pVegUPXQmthvhfkH1DzDxxu
         ovxP/QOk+f+UqVFmrM019pUN4yoEmKRusc2KqBj61za1kq79gIJn3zvu+SCzSe6wt6Wq
         +qcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qRcq+dK5S0ULsIY58Ws7NiK/VlcZ0OxzjwJ5djo9kis=;
        fh=DjQ6NHAyMT79eZCM2FTTZDrv7SWhV5KLvcEE2TydQd8=;
        b=J9oXJ1gdP7Djq0v2GZxCSe4b5Hy86dNyADH9vU8llRs/1/ONAw4R/1YgsibwcLxLan
         pOeD34ugNLPgA4gdqAwR9Xq4lT2JXtHTBy63GgkmSZzf5SGSRMwyAxoVlI+kjIqM5kWO
         E8y5thEP9N8LLWaI71584ZDnbR2JcA70b0E2BlsdW4L6hDU+51zAmo3pS9+YWeQG8QwZ
         zx/8jxAnC3ekHIJAHB23OkePFq60B7xug/qO7y2wAfOXTQzz24YQIlsEOJ3bbi5M5zYu
         QE7jEu9SDTY11Daon+c4zR+/fggEMuLHMx/aEaoiZfYVUv4w+6E6oqm+XLlMIsUl1K6Q
         8qTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EJZSkesp;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806861; x=1756411661; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qRcq+dK5S0ULsIY58Ws7NiK/VlcZ0OxzjwJ5djo9kis=;
        b=u7sWSpt9NZkTkOM/2B4v/Mfw/wp5zpXIJ+zYMxOAUKITJS1x9S6VsswizDNAwJGYt4
         IdEPcZKOST2IoYULVBe7S2BmhZWXWOjwnn1bLpGpqCqEkjuFG3L9W0VUtINRRglBunL6
         lXrV6vEdmrnR4jt28IR+Dotb2j8P1nG8XpHNvAruwAqm0xA75vQpNb+uJxbBAyt8I0Ow
         EOAll9X6VZNsX4PXIDTfg4l6BBLPAlkMyKHoHCjS1NNKHoGe1tZ1tjv9XSm0RyjqhQzY
         MuKnVkx1r5Lao4cM+inGPaut1ufD+C/NQIiOb0wlYe2pnoqQyAwvdU9LxG2MRkyjT/ya
         gP8w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806861; x=1756411661;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qRcq+dK5S0ULsIY58Ws7NiK/VlcZ0OxzjwJ5djo9kis=;
        b=chpo0R741yq8bkUbyqrUkvcwxZW2UWW5DiEXWAg3UNoAKTN1dvjpjdPvdLoedkz9m0
         zBOw4eN9E1w22QTkh4RQFr9UAXsZDlvMfuHHmXZ/wNxlA9CuFEAkeZu5uID87Vsp/d5r
         zL6NLYCk9wfpM3wGCDW2a6mQFwy1nBZ4VZJ5k5ViFxw37V+RC5rC+08DCj8RO280a+c1
         jyvW5MmQJ0BWw+amGJYKui31nmRlJYDnMoz86xy6GIeh9dbtMJpTTvXIbtqvPDlFWM02
         oH3TpQqfGaJhuS7a36LMCfsb6UuVawzUvr1VbhOgIJ7EbnWPGiOvKHSUhHmE6qPwUV6p
         kPNg==
X-Forwarded-Encrypted: i=2; AJvYcCV/2hZwIM6rQ+dOWi5UMW+WdXtxgDw8sgg3dYt0u8l1aQly+Z24Xa8wyA683y+qPkIbHEetRA==@lfdr.de
X-Gm-Message-State: AOJu0Yz44I9vqJrdVqixIMSXfWnasxFqNX4RZWnDKDHwG9CXuOBURJN4
	JMQJxSCFF2TZyN0RcjHaoOSPXaWtqtwKXVFxkbSX8t2zMBO88w33FstZ
X-Google-Smtp-Source: AGHT+IHbB/XbMjigfQA4vnzpYTwsC2xd1WDrAC1yUSSyqI0mRZLhiqpmfTbxjZ9OL75WdFO9Lhbarw==
X-Received: by 2002:a05:6a20:244f:b0:230:3710:9aa9 with SMTP id adf61e73a8af0-24340bce30emr544649637.4.1755806861524;
        Thu, 21 Aug 2025 13:07:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwMDon/NlKbMsTDcLdX/dn8VmAXPOdZ9YtqrhyRvlIZQ==
Received: by 2002:a05:6a00:301c:b0:742:c6df:df1d with SMTP id
 d2e1a72fcca58-76ea02a0804ls1306725b3a.2.-pod-prod-05-us; Thu, 21 Aug 2025
 13:07:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIsNXVB72mGcbcU2yO64GCOzNkH1gYLsMLuVVYC/Y4VnusmMXJ7IZshPvDq/wQsIavRfdsNfcfc6c=@googlegroups.com
X-Received: by 2002:a05:6a00:bd90:b0:76e:885a:c339 with SMTP id d2e1a72fcca58-7702fc292a6mr779338b3a.31.1755806859972;
        Thu, 21 Aug 2025 13:07:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806859; cv=none;
        d=google.com; s=arc-20240605;
        b=efUHNIysneqDcbR9OPLnyAQweyp2f5SzT+zAmyAKoXWDXBQOB0rBxIY6LZ2O05UVJK
         9n+X742QCO0FN3IOyMuhPbUdZsJSjd0vY22x0b9eMgxe5h7uJ95GUYboWu9kqBj9TYcr
         4PVMchU3bese2CsRE5juFxCFXx3YXd9l26jvA15TXGZMK4dCiCCYL5f1I7QFcucJI+F4
         GrS0SFHQFoTv91kjJ6MeY3LXONlsgoARcEYnvufLhAoFL7TgQtdU+a3/OowVIXI69Ml9
         fxyBNo8sWfqlywTHNs5J5RFw/uoE4j2jB2buzK0JlOHN0M61bNqxa64JCUwYDvH0iqLe
         nxuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fXj+9vT03G0X8fnCGUCy6hSTWwnZnWm2sdD6cJzGZDI=;
        fh=1turZchpS4R7R2BfGmk723QisuyUFiK7CIM00edyd0c=;
        b=QpMH6xLAKk7P9iHjdj1qJRlZDeXhwyG9dXp9bCVSCh1tiqU6Ttp2wJ581fFyZ5jrG/
         Tx2Q32vjxXfcWKjMre32nngcqjKh4VxIPSr2ARcsckhDneGhwfjf7xjuzpjgF+7Wyexn
         /Y7kzQUqf2s7ZlWxBKxoNq9cqjb9ZRNlqKx6NO09i1H1BbjzfAXGU7lgkyf9oPF0+A0L
         db2b/iZocSUD6xmJyKYo/f9Aga47cZp4C+1UhowwSEfQRxD1nx921p8ogJYA/fFBvSQ8
         m88DZvgo2wmUb5dDnBHQQlQbg0pTKPEMxKbabey8yvRPA8+W/UVZFZgdU5gGS/FTV33Z
         n2FA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EJZSkesp;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e7cce9ba0si159635b3a.0.2025.08.21.13.07.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mail-wr1-f69.google.com (mail-wr1-f69.google.com
 [209.85.221.69]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-367-ibJ0c9yHPaeQNKi0RL7oUw-1; Thu, 21 Aug 2025 16:07:36 -0400
X-MC-Unique: ibJ0c9yHPaeQNKi0RL7oUw-1
X-Mimecast-MFC-AGG-ID: ibJ0c9yHPaeQNKi0RL7oUw_1755806855
Received: by mail-wr1-f69.google.com with SMTP id ffacd0b85a97d-3b9dc5c2c7dso513038f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUxfqyuqh0Cy07pvkgKhwRvnk4/rFHty2uatVggCFUSXIisTmErnG80cZvsTFLtCAOjicTfl/esPJI=@googlegroups.com
X-Gm-Gg: ASbGncv1h/qV/P+8tWxASHfPGTEV+idY8EmFVp20kIAkSeiO5/UcJrRhIntOgI7I34L
	V6zCAtIClCr8VkZk7uMdEnw4sY9kRXvn+QE6hINHER3oasG2rEayMhsLXFn/p/67tceevdO+tb7
	JdHgJb2DTo/nrA6GWmR79tQuQJ2JFBazBw8FHWi5kN8Y1Out6Gi46M80hj6GvtDy731fynSLlw+
	JHpb/e8vxDFKxJ+XwLrtHE6t+bx7dlcbQB/LxG2/Be33WrdNOX3Gp5ghM9Ds85H/8u+EjYVBKT7
	LnTRjYprTHZkMr/hl/PPC+m1P6KH5QqV91Pim34nWCFYrbQbTGZlhhIwgR58LONhXKoIktGZmaQ
	3nnlheL9EwqBO6mhLUsyMsA==
X-Received: by 2002:a05:6000:2303:b0:3b8:d893:5230 with SMTP id ffacd0b85a97d-3c5ddd7f36emr169057f8f.47.1755806855253;
        Thu, 21 Aug 2025 13:07:35 -0700 (PDT)
X-Received: by 2002:a05:6000:2303:b0:3b8:d893:5230 with SMTP id ffacd0b85a97d-3c5ddd7f36emr169035f8f.47.1755806854709;
        Thu, 21 Aug 2025 13:07:34 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c077788b39sm12802789f8f.47.2025.08.21.13.07.32
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:34 -0700 (PDT)
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
Subject: [PATCH RFC 10/35] mm/hugetlb: cleanup hugetlb_folio_init_tail_vmemmap()
Date: Thu, 21 Aug 2025 22:06:36 +0200
Message-ID: <20250821200701.1329277-11-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: iNfUp1JTWjSXwg_RYru1FsshzBvHxwL1naycbc3FgoA_1755806855
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=EJZSkesp;
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

All pages were already initialized and set to PageReserved() with a
refcount of 1 by MM init code.

In fact, by using __init_single_page(), we will be setting the refcount to
1 just to freeze it again immediately afterwards.

So drop the __init_single_page() and use __ClearPageReserved() instead.
Adjust the comments to highlight that we are dealing with an open-coded
prep_compound_page() variant.

Further, as we can now safely iterate over all pages in a folio, let's
avoid the page-pfn dance and just iterate the pages directly.

Note that the current code was likely problematic, but we never ran into
it: prep_compound_tail() would have been called with an offset that might
exceed a memory section, and prep_compound_tail() would have simply
added that offset to the page pointer -- which would not have done the
right thing on sparsemem without vmemmap.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 mm/hugetlb.c | 21 ++++++++++-----------
 1 file changed, 10 insertions(+), 11 deletions(-)

diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index d12a9d5146af4..ae82a845b14ad 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -3235,17 +3235,14 @@ static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
 					unsigned long start_page_number,
 					unsigned long end_page_number)
 {
-	enum zone_type zone = zone_idx(folio_zone(folio));
-	int nid = folio_nid(folio);
-	unsigned long head_pfn = folio_pfn(folio);
-	unsigned long pfn, end_pfn = head_pfn + end_page_number;
+	struct page *head_page = folio_page(folio, 0);
+	struct page *page = folio_page(folio, start_page_number);
+	unsigned long i;
 	int ret;
 
-	for (pfn = head_pfn + start_page_number; pfn < end_pfn; pfn++) {
-		struct page *page = pfn_to_page(pfn);
-
-		__init_single_page(page, pfn, zone, nid);
-		prep_compound_tail((struct page *)folio, pfn - head_pfn);
+	for (i = start_page_number; i < end_page_number; i++, page++) {
+		__ClearPageReserved(page);
+		prep_compound_tail(head_page, i);
 		ret = page_ref_freeze(page, 1);
 		VM_BUG_ON(!ret);
 	}
@@ -3257,12 +3254,14 @@ static void __init hugetlb_folio_init_vmemmap(struct folio *folio,
 {
 	int ret;
 
-	/* Prepare folio head */
+	/*
+	 * This is an open-coded prep_compound_page() whereby we avoid
+	 * walking pages twice by preparing+freezing them in the same go.
+	 */
 	__folio_clear_reserved(folio);
 	__folio_set_head(folio);
 	ret = folio_ref_freeze(folio, 1);
 	VM_BUG_ON(!ret);
-	/* Initialize the necessary tail struct pages */
 	hugetlb_folio_init_tail_vmemmap(folio, 1, nr_pages);
 	prep_compound_head((struct page *)folio, huge_page_order(h));
 }
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-11-david%40redhat.com.
