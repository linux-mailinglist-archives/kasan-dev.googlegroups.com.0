Return-Path: <kasan-dev+bncBC32535MUICBBTPN23CQMGQEH4MOSGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id E68CFB3E87B
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:07:58 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-b47630f9aa7sf3795960a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:07:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739277; cv=pass;
        d=google.com; s=arc-20240605;
        b=dsTwVxa/kOlBvBLGujxHsdKad244nrfyVu7zR3DyKlHJ19g2Tm0DanXazx6w4on1kw
         VVi6rA7PYDKHciybSo7MwkIhzYIrE3DFrIehzJ0xuXlHShKuW2xXyvR6QDtSLORxnJUC
         DkwZ0Jrz1b14Wt3U9ikmzE5s5rHV+HzCiNPllM+4OD2ck678IVTv9D2qWVPcbaQdMiLv
         p00xwTidIP/Vt0Il+3FWOYNsYu6mC3G2phsujFzNadubc5txbu9lJSJlO89TK0ctZAIO
         N9mng2AY5x+gNV1skfxXvMjS0DIU006gw8DVr9oCEmE/sKQYcCX+ljF1d+G9WilADxRO
         A7jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=PpoNfgTVGN12dsr/g+kajH1rDj6IrR39SsVaIvQQGwA=;
        fh=sLUTpFiDb5hxorNft+UJkqiWVGwnCrCXzACWyqQeK6Q=;
        b=PY0z+EnQBVZYNWIKUZreqHHGstZ3Utp8XrzCQpLwObVsnxIFYsg+J7qjABoByKOPOa
         OwTEtn38DMm5MINrNwPEqndXSDIhKIgYBSd3IXNwV9pcqtmudpOFou/nt/jtSfq8Tfns
         eATL10QERjKUXNULibj3K4XJFIQD7Gft4EjT254LP4VrJJcZ8Nk+01Rm2dhNFM73TtKU
         KY9H2YmoPWvMO3YyCE1OMPLn4OO8IMDIba7qT8/p3LFkfjSPyEiz3McDzY4yMuPtFZpb
         THSLpPM0phtXUC34li1C0Xp3ybyEG2DJhT4OWK5aZRyhT57PrGffoQIr6skRmhXvaBEy
         wUGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cBvLhJre;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739277; x=1757344077; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PpoNfgTVGN12dsr/g+kajH1rDj6IrR39SsVaIvQQGwA=;
        b=FpPqUvxsq30mXz6pE7Qw2f1/dsSv+WXBGrDopOVByZYGH4BJzBg1e2c3WmeclOI+Ey
         8DkEQJPXE03MLVOjPhdVowsDieFewIlvJOh4i3Sd25EhpjDWjc22XQsk0QhPFSEktnjZ
         iMUoGtTVO/xVLASwQp2Ro3hga6em0zvxP/6iqshZ8OpZ68DN6mJJvhmwHoRZ92HQMouC
         eE/XxQsgoZjZEGZnJa5/c9C7RcsntoOGTgMIiftKccQAPSP7Pz371PhS9iVDD/raItE2
         MnMcY3LiAuUYG5bbzhpKkBSnYlcA1/5Be3Ornk9T4SVT5JSsljI+ekm24jyL6wsnMs2m
         kW/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739277; x=1757344077;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=PpoNfgTVGN12dsr/g+kajH1rDj6IrR39SsVaIvQQGwA=;
        b=eMVF3YF1elVIeqpyUh7IUYDlmyyEoTNnyhiu6+xBnWgkAELWhGjwNXWzUI8ZU3QO86
         sOadO3XFBA6ztTcoc7l8h01AIvw1acS7AaMGgg1yXN6egrMKQzV4IGWuUQPgYu1D6vC1
         I4uJZqgZ9fVG2Oe+YUd4dX5siuXnkU7Q9e5qrdP9WKslDa6qADjFglMpFvYoAbM36D/e
         O+F3+k6fPeF6Pqhl4+XeKCi+ssAxlzA9jpnMWjvbFeOND5ut9tyVpekgmWDwdvgYiAX6
         7ptHxzJjUjjwE3MEkUDvOcb0XXaIe2JWZ7mllOy+MiJwx/sRt4kB87q1/3qEBeplrt1s
         yt5A==
X-Forwarded-Encrypted: i=2; AJvYcCUDjQedd9l0cIOZRufrJwfShqVqX91XN2KOAteHJbeW3j5frfOPGF+QHTHTvhp64Bx6NvAt/Q==@lfdr.de
X-Gm-Message-State: AOJu0YxGcoLTtESfTjEm+Opap86OY82u5eGXJH5RWFMwkXG4LFN4ujxL
	MWeGPMQg9yfVqF/I8UgYbk0M2O6jv/m86g8WT7ATrO/DHSsXj7P/ff6x
X-Google-Smtp-Source: AGHT+IEUsvsXaISIr4Vl8nt9dK2m11nP5jx15Be0SawzLfwHIJZqPWNLi8r6zNH6CrNQS4KvE5qeag==
X-Received: by 2002:a05:6a20:7b06:b0:243:fe1e:2f97 with SMTP id adf61e73a8af0-243fe1e3014mr338894637.19.1756739277319;
        Mon, 01 Sep 2025 08:07:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcMj9Cq9v5Tm/kitB6N2X/tUAaFrDnvgPZaZNM0nAdu7g==
Received: by 2002:a05:6a00:800b:b0:772:6b0d:37ce with SMTP id
 d2e1a72fcca58-7726b0d3d77ls207271b3a.1.-pod-prod-02-us; Mon, 01 Sep 2025
 08:07:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU2Fx59Si67HCfMy0gQ2kvLvaixy0CsxHgiMg8FSGpki1DdOlYepPugBv+O6fZUxbkHFkdy4DIRnCM=@googlegroups.com
X-Received: by 2002:a05:6a20:4321:b0:243:b8c8:a247 with SMTP id adf61e73a8af0-243d6dd8d9dmr11893307637.2.1756739275758;
        Mon, 01 Sep 2025 08:07:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739275; cv=none;
        d=google.com; s=arc-20240605;
        b=Bo5Vsmj9mQ/qSUiAQbyrbEDOAige1YiaWLhUSLxGp4VbmBiqp81RxR3cO01ZzACPlP
         M7NtvcrCezxqvQJtQCfXNnMmUFKY4ep2jRzxLb039TuzT1Yk85xK25IYjMTHTi3pUqgd
         jro6Ki8DVwW4C38PNrkFhmGgj3iAYkWe/iTtJItecLRXFrxKZMh4lq93krTlZBHl7ybo
         pk6gTj5P/pnCkYc/6+kUauBQSvVQzTkDfdjGxwcwmVaAoPztkYqKUXxsxBvc1hz+GY8l
         nZN4vYiP/QMOmiB9BvANcKpQro5lgdv+jUyZgn6R0XABNQg5e6x/r+cSb660q4Vcqi1I
         fbSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1NuKSd2ef5HwYax7pwu6yf7kwVuEbI8vaAEgix6O8kQ=;
        fh=C29x4Vv0csHPF9cut5UHVlExc2+JnwAY8sXblkE4YL4=;
        b=Jl9YDuBPE8yuBI//wjbQxox+JhAWBLRkOFF7Kuq4Xw7lC4O1nm40UFcDnzy0WZxwZj
         SHw8IIht3XQeE3SCY0FMjEf08abi+8A5ZgjBIfNyFIlQqQhTeqeoMdnlkof8T4j7RQRI
         Crl4rHxiHNu8G4ufp/U7SWxhwlxbXFdLLg3b1MUhK0veeitKyphFy+/LlR070qTbm/Tz
         BihijKzIz7ymXz3fvs70UsCRurc+9hr/Anqol4hB1WetfSkpvn2O+qdZYtll2uweBmfL
         iA6bgqMSC2bnHv3vUcVVm8IVXEzHSmf5G7C6cxj4kbwUzNrQ8eotGZr1AjTIKZR2ZY07
         jZ+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cBvLhJre;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-328027692f6si266988a91.1.2025.09.01.08.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:07:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-319-WXE1NSHDPjahq0Msave6uA-1; Mon,
 01 Sep 2025 11:07:49 -0400
X-MC-Unique: WXE1NSHDPjahq0Msave6uA-1
X-Mimecast-MFC-AGG-ID: WXE1NSHDPjahq0Msave6uA_1756739264
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 34D8B195609E;
	Mon,  1 Sep 2025 15:07:44 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id D513D18003FC;
	Mon,  1 Sep 2025 15:07:29 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
	Zi Yan <ziy@nvidia.com>,
	Wei Yang <richard.weiyang@gmail.com>,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
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
Subject: [PATCH v2 12/37] mm: simplify folio_page() and folio_page_idx()
Date: Mon,  1 Sep 2025 17:03:33 +0200
Message-ID: <20250901150359.867252-13-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=cBvLhJre;
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

Now that a single folio/compound page can no longer span memory sections
in problematic kernel configurations, we can stop using nth_page() in
folio_page() and folio_page_idx().

While at it, turn both macros into static inline functions and add
kernel doc for folio_page_idx().

Reviewed-by: Zi Yan <ziy@nvidia.com>
Reviewed-by: Wei Yang <richard.weiyang@gmail.com>
Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-13-david%40redhat.com.
