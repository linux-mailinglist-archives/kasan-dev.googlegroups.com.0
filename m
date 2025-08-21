Return-Path: <kasan-dev+bncBC32535MUICBBAPZTXCQMGQEP3RJPVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id B8D98B3036F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:07:31 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-76e8ae86ab3sf1565753b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:07:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806850; cv=pass;
        d=google.com; s=arc-20240605;
        b=NweSYTh8PPCxlFg2meeGVdHwGo1+sBKRRDWBwbISv04rKN9PRNHrFhq0PszS/dmQLw
         EE0Q2Wat3nBHRnblWjUF6rkU2vkCYWxUSFYQ1MQQCuAf0zFZ7WfEIoH1CWefSTqZsBHv
         truEucUOs51tREkj+mRIZi3Aw3XaMmEXRwfiZpSmxKtmUkvd/m2oVHXUOd57PMmt29Gl
         /TWggNHHZvhUxSNia5MNhcfRTG2jMf5MnFoN8evMtYjDYlwT9Qxuc+BVY5/bpn+iuGQd
         2jrvDifJJphGuswQZ13vrViIUjmzD1wZhhfQ3DXlGvyNeMMvbIXzgFNqngA3l9Oxiu0b
         /uTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=kOEW6Nx8/rN1Lm1LcFTpa1Lwm6rNXepFPnGQWbpS4JQ=;
        fh=tcsYDdrLUvKQHNuktx6q8Z7m0+5BllVNSnaBmC8lqNA=;
        b=aCbkedLEud7qgRNsX0kxS33jV8nQYOFKQJ8kLkDC7U9i9ufLNSwLEDFfk3B7is/bmU
         3d+YfdyBJ2QJkO5FRjbb45dCekUTMX4Vqh47bfKAe5GBdbsnfidL5SETAC1ttqDq6SsR
         l2NEe3THmR0pT1FI8fid1JNqRTR3jb6iyBE7CEppF/5Oy+BRlJAkfBjafMwvMZjhmOyg
         w1oChn2LGa1s08+vvKpdqRPW+voaHK0/ErRH4l0fJi/Y99Ukj35YpByhrBQ7O1DcfPpW
         lcca66UF5OiqXemn5aSwDpxtmJEl5Gp+woEtV+0keIjDdeBRM5PmI0V/vBEPwZJ7bH5n
         wjJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dBdGbLGc;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806850; x=1756411650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=kOEW6Nx8/rN1Lm1LcFTpa1Lwm6rNXepFPnGQWbpS4JQ=;
        b=TPmFzDpBKo529umB4uUad5pgiBkrGFvzm3+MZUBw5XnXWCge4T+XtDlMBEzZKJzXmx
         wpOVssjU9DInm6W9a1uWV5D1RXmbRwh4RygMjQRH1UwYAmpZb2MZmrLNuS6nE92ufLMP
         zU8gbfvQLfqzWGmcHOd6ldfbdfEnvGWaqpCR1cNcslrI+dVSzEs2RlM4Iq34EMRRokjQ
         OIHsIsZ65XW+Bo91rRTikx4UN9spi/FsZBq4GBD4qLLGD1oYSOWt7evoZzb5SlYJKGh2
         4kWrzKP7FNkx94BiO0s7hkT0VEotWo1jwk1PEd9JR3JlZfTCGXXaNXF1FA1M4+DL+PlR
         c9Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806850; x=1756411650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kOEW6Nx8/rN1Lm1LcFTpa1Lwm6rNXepFPnGQWbpS4JQ=;
        b=vTBFppdh5OCZ+eYdobZschVL07nHaDKuCwU0jx9E9oiig01PhvR6wd2Rq5pk05FwFC
         yx7N5uh6u1QJHDWCirc7Ml2sStk95Hlgd+A8LXhLGKp+5YH9HsKw2RxgkvwHYriafc0T
         hUjGtL7eeKxTPNu5e4rOouun3ts3EyZ3IXCJgZSp5GDUR567DO3QTX76XL4Rpu5WIuYM
         olBh8xhUZ/NWXJY9R2wOQKAJ06o5Tksm8esGxSAfXb/4A/cBH3a7keXSymeDVJWxSbGv
         ySTuDvvxgwgyL362aUCS0LJKnpiNVnI1tKOMrZd7wyZV2jG5CvLk9M13xYNuGgLWP1QO
         LMqQ==
X-Forwarded-Encrypted: i=2; AJvYcCWyYjzXgxvdwGSDj1tpfF71XS+NXvI9k8FFugBdYnoEy/T5vXEEHoyYo2/DT+c9g/S8MeLIMA==@lfdr.de
X-Gm-Message-State: AOJu0YzmPjm/yIhAdQwigu5LGcRajUMxRIEh+UFGX4n/bDQw2sJ2DV14
	UIJVPQd+B/Z+qrp8mzBaKZgnXT8xpd+VYS+TX+mJpwrBAUBUe+zeizSZ
X-Google-Smtp-Source: AGHT+IEVW1Ip3saZdwl5aFAmHuzH+87EFLoG1L1JZmOzesOCTuR3uceN5UZ2MxgW9GtfJWgIuIxdLw==
X-Received: by 2002:a05:6a00:6e9d:b0:740:9d7c:aeb9 with SMTP id d2e1a72fcca58-7702faac219mr646637b3a.21.1755806849748;
        Thu, 21 Aug 2025 13:07:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcLCxm3+rY9lJNL9QI9U9eynDjZw8FG7borO4SUPO6Qtg==
Received: by 2002:a05:6a00:1d9c:b0:736:a84e:944a with SMTP id
 d2e1a72fcca58-76ea02646bdls992280b3a.0.-pod-prod-02-us; Thu, 21 Aug 2025
 13:07:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVz84jir7CDfixi+46fdb7TRG6w6XjkO+tChzR3Ay7l8ANQiWY2SRJaB8a8FRCcHYyzBRzYJPr88TQ=@googlegroups.com
X-Received: by 2002:a05:6a00:3cd3:b0:74d:3a57:81d9 with SMTP id d2e1a72fcca58-7702fa03ca2mr847309b3a.8.1755806848126;
        Thu, 21 Aug 2025 13:07:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806848; cv=none;
        d=google.com; s=arc-20240605;
        b=GXGSr/FqHLWz9rn7ZW9cs4nFFY6woUZwMD4tmib9K9TUpDoog0A9ursEWFQ5bTzi7S
         qVJFkflJ3IT+DDa3HpDV3VB4nLla9ov7eIGnzxJ8ajx0Sa0OtZKj70+IikAdIT7c5IHx
         15/iuXXKXFscISKCIan5TC/XQWDbgOaob1lgwXbmJI+goLhsX5gZFEGoA89kwMhM0S77
         pYaFJMN8GXyoh3hNy1IKKFOHSWSZlea45FqyEY3UVeSzIgtjaEZRUrgBoqB0gLqemidU
         3RMke7MavJmvbh1vfiNeSH9UY/oD9ew2u6kRJzLjcfvwn/+XDas5d4fxDpkdhjMQqHz9
         ydrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=saIpwl0G6zoDDZA6kqzaAKGDHCkLp/ivw/dNNi90asQ=;
        fh=2OMyPUzHgJO9fL3OsyTrbjtEIshvKI5kbHqlaNss9sU=;
        b=hDjOivgE7U/OIHRSWWGsbne7efOEquJa4zmXDx62WXSecCdHwa1RbhN4oChqRxbdzG
         NABhttq7LKP2/m7U+byq57XRPCXsXFtUjZCiBfsFEOQjXdBm16YEiwvqxM1e1UbhuNLZ
         7l4b42F6sUFiJreWlO4WtSFyP8sFxjw6EVAovfqpy1OQ0pGfAhRApnf+AwijHRlb6BTD
         lcmFpgjxb45/2a9UNrlErty8K5fJiW8CQxbkvcdcUH2OKFGOGVEEofltoLHB/UjoD8lM
         4rMDTWGSGBSfb0W1NrVB7SbiWBL6U9+R7DFP106NIUBoVel9Bhlknp1/TMOrt2T6ZUKu
         YXCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dBdGbLGc;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76e7cce9ba0si159614b3a.0.2025.08.21.13.07.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:07:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f72.google.com (mail-wm1-f72.google.com
 [209.85.128.72]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-498-CuPolG76N6WN55FxgYAd8g-1; Thu, 21 Aug 2025 16:07:25 -0400
X-MC-Unique: CuPolG76N6WN55FxgYAd8g-1
X-Mimecast-MFC-AGG-ID: CuPolG76N6WN55FxgYAd8g_1755806845
Received: by mail-wm1-f72.google.com with SMTP id 5b1f17b1804b1-45a1b0ccb6cso6971375e9.3
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVQmvVk/VMuRtnZyIWZ6RAge55FjqfDyNj5lXniqGo9z4wLsY8N2+6Vqqg/uWouUmU+BOBK59l1s88=@googlegroups.com
X-Gm-Gg: ASbGnctpeX6vi4W/AROUea5JZSXTpRmlswejJDFRWL5LtVmzYAjIWAQfQ2dRguzPUn0
	lZqxH3ZECowA01BYJF6xa+jrDLP4rZVgCuYWh1IeTzc9RrkhphuCShxMYbxE4L2lJTPnM97Dipm
	4h7HjYIU0fqjhFonX94IFtT7qlZHfwqoLpA3IThd333Wf7tvivX0hYgMTQAL6IVxX9ieSzv6oRr
	k/ZZt7uZbnfxH16u8MepqlJvyaphiM75iBsQzHsV596Q1waP6pVlV/KXnShMY5F57MSkfZ2ly+j
	PsgN5n/a/uFDqjxSargzXAhrIQc8s/XKkuoEgicZGTamEBPyTCBIFQ1Skh3pDDDDvENtsrJNtLP
	QH7xpONx4JtHpNCS4mPwD+w==
X-Received: by 2002:a05:600c:35c3:b0:456:285b:db3c with SMTP id 5b1f17b1804b1-45b5178e768mr3050045e9.3.1755806844539;
        Thu, 21 Aug 2025 13:07:24 -0700 (PDT)
X-Received: by 2002:a05:600c:35c3:b0:456:285b:db3c with SMTP id 5b1f17b1804b1-45b5178e768mr3049835e9.3.1755806844048;
        Thu, 21 Aug 2025 13:07:24 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c074e38d65sm12980909f8f.27.2025.08.21.13.07.22
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:23 -0700 (PDT)
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
Subject: [PATCH RFC 06/35] mm/page_alloc: reject unreasonable folio/compound page sizes in alloc_contig_range_noprof()
Date: Thu, 21 Aug 2025 22:06:32 +0200
Message-ID: <20250821200701.1329277-7-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: OZ_IYl_qfqg0-fpJjCCHidJYp4a5gRm3wtc0VlGLj-A_1755806845
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dBdGbLGc;
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

Let's reject them early, which in turn makes folio_alloc_gigantic() reject
them properly.

To avoid converting from order to nr_pages, let's just add MAX_FOLIO_ORDER
and calculate MAX_FOLIO_NR_PAGES based on that.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h | 6 ++++--
 mm/page_alloc.c    | 5 ++++-
 2 files changed, 8 insertions(+), 3 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 00c8a54127d37..77737cbf2216a 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -2055,11 +2055,13 @@ static inline long folio_nr_pages(const struct folio *folio)
 
 /* Only hugetlbfs can allocate folios larger than MAX_ORDER */
 #ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
-#define MAX_FOLIO_NR_PAGES	(1UL << PUD_ORDER)
+#define MAX_FOLIO_ORDER		PUD_ORDER
 #else
-#define MAX_FOLIO_NR_PAGES	MAX_ORDER_NR_PAGES
+#define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
 #endif
 
+#define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
+
 /*
  * compound_nr() returns the number of pages in this potentially compound
  * page.  compound_nr() can be called on a tail page, and is defined to
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index ca9e6b9633f79..1e6ae4c395b30 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -6833,6 +6833,7 @@ static int __alloc_contig_verify_gfp_mask(gfp_t gfp_mask, gfp_t *gfp_cc_mask)
 int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 			      acr_flags_t alloc_flags, gfp_t gfp_mask)
 {
+	const unsigned int order = ilog2(end - start);
 	unsigned long outer_start, outer_end;
 	int ret = 0;
 
@@ -6850,6 +6851,9 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 					    PB_ISOLATE_MODE_CMA_ALLOC :
 					    PB_ISOLATE_MODE_OTHER;
 
+	if (WARN_ON_ONCE((gfp_mask & __GFP_COMP) && order > MAX_FOLIO_ORDER))
+		return -EINVAL;
+
 	gfp_mask = current_gfp_context(gfp_mask);
 	if (__alloc_contig_verify_gfp_mask(gfp_mask, (gfp_t *)&cc.gfp_mask))
 		return -EINVAL;
@@ -6947,7 +6951,6 @@ int alloc_contig_range_noprof(unsigned long start, unsigned long end,
 			free_contig_range(end, outer_end - end);
 	} else if (start == outer_start && end == outer_end && is_power_of_2(end - start)) {
 		struct page *head = pfn_to_page(start);
-		int order = ilog2(end - start);
 
 		check_new_pages(head, order);
 		prep_new_page(head, order, gfp_mask, 0);
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-7-david%40redhat.com.
