Return-Path: <kasan-dev+bncBC32535MUICBBK7ZTXCQMGQE4UJWXVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 69DF8B303A1
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 22:08:13 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-70a928dc378sf30813856d6.2
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Aug 2025 13:08:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755806892; cv=pass;
        d=google.com; s=arc-20240605;
        b=lmXNQpt27mgw6I2sSdJAYw1NQYiDZC5bh1xN9Sb+ur/pRxRp6cCROOezHkY6IenSCo
         /ib+QUhJs68rr9lShxapKs/LYdBTG9pvnvoRXfmkFuOwj8zDzmRAsMBfwt87TqlQW/J4
         B3QZn5gpRiFA0GFkwxeNgnT5fdFRvXZS902NVH59AYWNlh1XsGnhv9McnJB4yj1qdCzQ
         GD6XIOHV+I8G6Bu1o7peP9VRnlpvLndxX2pSPSF9Ah6eMjjvXAbVsrFW1s6y/G78Kcsf
         iuhTSAQ4w6coPLsl2hK1y8v4BGmHBNON6nHnEPYqKUX/5aVskl0OmJWxGFt4xueyv4kM
         V7iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=LTO0k3xBUeeal5NSIqqtSrjo5Z4hn32584/aJsZjmq8=;
        fh=YDwJYt/JVXHhlaJ0RI2pRqbuk6WdV+/YsYpIn0xj4XM=;
        b=c+MgjMiG4d/EH+SY1RKiLoqgGspPOWUkraQxQzBRjnraRk17suUpQ7//0viWS2Y+Ag
         Hb5PKl5FnK/c7ZYapgCbNDKbJabw3t/+LqDCpUKvZhJxlVpjbFlynamAbsFA7DsRput9
         ngy6aOLZn9/uOBsFJI6lrNBveGj2DZzrv2aMtgNPFo1v/EJCCkSOV3kouEbpGOW9dI6E
         H5sIMm5rBTepMUC125ixgzHw+V8Ky/jvK068mT2Qi/S7owTtV3zUJ6Cjt3Qj9WQN8zF+
         B+0GQxSI15EMWdDOSWJCQZoM/Stiug9j/7aT+WxhBlkLxwW1u3d65AQAdAQeqSLXpffO
         oVHQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Wd+3b7VW;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755806892; x=1756411692; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LTO0k3xBUeeal5NSIqqtSrjo5Z4hn32584/aJsZjmq8=;
        b=sfJyRkWW0t3g4FZl+8L4wpL+kyZnAxaXn8hmiroV1fqofZLEyJpjAnAmZjzfzisi2R
         +QD8WytDQIsi7xndcSKKKBvILAXEcIZTiMl61eG6R1KrZ7xWP4+UbInhA1/wfrBFwicp
         5TvyILAGNOyFA5ERKI7EK02+w66Zaz6NawiLoUJX7Yt5mpKw880QOiKoxGHuxvkaF1tU
         QRiSk6eSOkUoEBGTuXQXtMz7vA0AFzwLVk3HibgUK8KLJgqYgQtxUGcvmMlgo6f4QYCD
         h+cIWd7MmMiRN8DQeernFd5QoSU+NMe78Cihuaap5AE/++gUuRTBkZhzXTZGsK/CIOi/
         v+mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755806892; x=1756411692;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LTO0k3xBUeeal5NSIqqtSrjo5Z4hn32584/aJsZjmq8=;
        b=DolLTnXoopeuJ322hzO/9/ajv8gBmDNiIb6vT6nEksl3ggQP7vW/LYCDe1SXlXUKs8
         sSqvt8kAjte8mFKRMtUs7+RdAOaxPvgK1+h0heOu6lqpC5dFti4oxZBpDwpysGiBbbsK
         1nlvKHU6vS4RmnF/btEcRiBRLhjCOqSKy5JsjP2a5wBFXtbOgkIxRUywi7s6tKZCKRaC
         jeDB+JKCG188/DeKtuKcpuklm3KRXel1bgtp3nQzSzclc8a0CSFQB10vhnVWkvwRKdJc
         B3P3yVLHCQyso5Yyot5Tq5JjUnrlLUnNOLnDN1HCcqmiQt9eTraaYiOaoNumLYofM3E4
         FZkg==
X-Forwarded-Encrypted: i=2; AJvYcCU5ZT9/SWrcyvccVO0VeqSNos+ZMnKHsCEhMyyMgRifTbgM9HlwXQy8Tm5LEOPrKJrDf4hfxg==@lfdr.de
X-Gm-Message-State: AOJu0Yy9UxjIUihNRAQKUabz+A/aVTnXoimUWJMVmzZaGNua1QCy0EwE
	IzKE6h9GYH26KEMObsx2yvqROGqYVkMvuL+PYM0t9Xr/9VT6kyc/LtDw
X-Google-Smtp-Source: AGHT+IGzps5TzPVaziRFZEIh5ZVCdEJyuMIbHv2c+l8WlKvQKTabVLHOOpwLnxGIl78YDDR/Zdb/nA==
X-Received: by 2002:ad4:5766:0:b0:70d:6de2:50bd with SMTP id 6a1803df08f44-70d9734dc69mr10087416d6.58.1755806891868;
        Thu, 21 Aug 2025 13:08:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfvYDWzH2IxbQHQpJGvVJBSdyBbKAVOh8Lo8+MuCW2pMw==
Received: by 2002:a05:6214:1247:b0:70b:acc1:ba52 with SMTP id
 6a1803df08f44-70d85d0cedals21912726d6.2.-pod-prod-02-us; Thu, 21 Aug 2025
 13:08:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXgfYCLFNhpaVS9P8vTgBJ4tzHGjriHpra51OkqS8GLmSJzT0lWdcyaJhUZlv66fewwIJiInvTq2a0=@googlegroups.com
X-Received: by 2002:a05:6214:e65:b0:707:92b:477b with SMTP id 6a1803df08f44-70d972f8f39mr8616066d6.44.1755806890986;
        Thu, 21 Aug 2025 13:08:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755806890; cv=none;
        d=google.com; s=arc-20240605;
        b=M5hwWMZms+ETYJ8Cd//KyLHMfdyumwco6R/Pvlai+BETMUu2JAOjJO8lqmo7gRlpMi
         /52pAMJTQ1X6VEfXNp+AvZFvnAPiiSgbsP2VAt7co4nvednup6Ykl0z60hSt6ZV8ggC+
         P7tXFkHnLlOLJy5EnIOyiygiUCTSt3ap0k9Q1oB7/xji/ze5Mu9mLuqfO5CrY8oM0doy
         NFDec/X6yGthDccCC/3YVfcT5nuQXcqwBXY4nGxgAWo2Ac+HZEDMtDfMZp1mJ8G+mPQK
         aMyBIK0qLOA6rf8zCsQs3WkooY6p1DAO18rmyKPra0y/70Tn4AQuA9XP8QT8/O8UOM31
         D9bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MzMWVCGQW0mP4+/ULAfe7CdOmgWkAKLnoxAB4Fy092E=;
        fh=OPD2eI/4C9AKwgSCkOWyQFixGXdG+uiiN37k+9WJKNk=;
        b=gMZ5ah+4jEu6KjqXAf614DvRd5fSmxRYMfr56T2z+FARO1s+9T1ol+HaaPdAS3lC53
         jKVsSVhDkXTVhCKOiNqK7IKoYLFlukCgmIqNvlcU6iBoUd5Pj7xoLWF8m8hL1S8z/Ill
         KstQRGPCwToOol95VzhnawrnhEU3kZF5CWpZW0p9loQ0jpbPb8rqNFQTbTnT0KrsRK3m
         PTm3vyGAlowrUNBQ7istwYqZD2Ahn9JBG+jVH9+PhVCoLW5TL9TgWECHHgRNgCn4OBXy
         qBOQgyP/k0FxnMqT/ZCpj5fg0d3X0jy/Kb5pEfSo1+8Oc9O7KVDb8k/f0Xh5KG0tOqnw
         uE4A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Wd+3b7VW;
       spf=pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=dhildenb@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba9220586si6179416d6.7.2025.08.21.13.08.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 21 Aug 2025 13:08:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dhildenb@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wr1-f71.google.com (mail-wr1-f71.google.com
 [209.85.221.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-612-sM4FLPCrPf2z5AH0NdNVyA-1; Thu, 21 Aug 2025 16:07:50 -0400
X-MC-Unique: sM4FLPCrPf2z5AH0NdNVyA-1
X-Mimecast-MFC-AGG-ID: sM4FLPCrPf2z5AH0NdNVyA_1755806869
Received: by mail-wr1-f71.google.com with SMTP id ffacd0b85a97d-3b9dc56225aso832661f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 21 Aug 2025 13:07:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVD+U8uM7dPJW3uunFRnIzcRAq3GbY7ebnVLJoW5ZnZ4TxHVIu0w4R08XnG3SWcp0M5TiTSQ4R/qz8=@googlegroups.com
X-Gm-Gg: ASbGncvsVaA5/m6uI1d7I9iTkNRktOg0Wnz4d1MeVF3GK4D4qwKLhhof1F74CtCvNcy
	4QJdImYns9PJdtrYTI8M3QmI9UpoUOM8wrJYoSXk4Hm3wcSoYI5QZcxU+GVAzk7RdnDLhB943qM
	7qToz/zi7SGu0au033jB7zTSKTSWa+bilAlr+YUEqfYMC+hDOrI4TFY2tqLBhf1Dtm0MztvKOAL
	bougV2m8l5HFlM9rRDg1/57RT2JUWzcsu9rWLBSOdfeDkSGkJUFV4zXKvHh+QjZDW7O67sl/6TT
	XVQ249zWkSWhn4wsTdXgZaeKvh/s6Gzn2z3AROLxcHSq7E2NOQWAj9Zb2s4cOf4+yMu5GdnMzf4
	u2WiU3mq7wEBUvpDpfARGbg==
X-Received: by 2002:a05:6000:2901:b0:3b7:c703:ce4 with SMTP id ffacd0b85a97d-3c5dcff5f3amr167793f8f.59.1755806868889;
        Thu, 21 Aug 2025 13:07:48 -0700 (PDT)
X-Received: by 2002:a05:6000:2901:b0:3b7:c703:ce4 with SMTP id ffacd0b85a97d-3c5dcff5f3amr167760f8f.59.1755806868453;
        Thu, 21 Aug 2025 13:07:48 -0700 (PDT)
Received: from localhost (p200300d82f26ba0008036ec5991806fd.dip0.t-ipconnect.de. [2003:d8:2f26:ba00:803:6ec5:9918:6fd])
        by smtp.gmail.com with UTF8SMTPSA id ffacd0b85a97d-3c5826751d5sm1323274f8f.14.2025.08.21.13.07.46
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Aug 2025 13:07:47 -0700 (PDT)
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
Subject: [PATCH RFC 15/35] fs: hugetlbfs: remove nth_page() usage within folio in adjust_range_hwpoison()
Date: Thu, 21 Aug 2025 22:06:41 +0200
Message-ID: <20250821200701.1329277-16-david@redhat.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <20250821200701.1329277-1-david@redhat.com>
References: <20250821200701.1329277-1-david@redhat.com>
MIME-Version: 1.0
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: JLF5HsVo9rCB0zuEn_ZgPDomTFJ9huq7siJbujn0yf8_1755806869
X-Mimecast-Originator: redhat.com
content-type: text/plain; charset="UTF-8"; x-default=true
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Wd+3b7VW;
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

The nth_page() is not really required anymore, so let's remove it.
While at it, cleanup and simplify the code a bit.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 fs/hugetlbfs/inode.c | 25 ++++++++-----------------
 1 file changed, 8 insertions(+), 17 deletions(-)

diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
index 34d496a2b7de6..dc981509a7717 100644
--- a/fs/hugetlbfs/inode.c
+++ b/fs/hugetlbfs/inode.c
@@ -198,31 +198,22 @@ hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
 static size_t adjust_range_hwpoison(struct folio *folio, size_t offset,
 		size_t bytes)
 {
-	struct page *page;
-	size_t n = 0;
-	size_t res = 0;
+	struct page *page = folio_page(folio, offset / PAGE_SIZE);
+	size_t n, safe_bytes;
 
-	/* First page to start the loop. */
-	page = folio_page(folio, offset / PAGE_SIZE);
 	offset %= PAGE_SIZE;
-	while (1) {
+	for (safe_bytes = 0; safe_bytes < bytes; safe_bytes += n) {
+
 		if (is_raw_hwpoison_page_in_hugepage(page))
 			break;
 
 		/* Safe to read n bytes without touching HWPOISON subpage. */
-		n = min(bytes, (size_t)PAGE_SIZE - offset);
-		res += n;
-		bytes -= n;
-		if (!bytes || !n)
-			break;
-		offset += n;
-		if (offset == PAGE_SIZE) {
-			page = nth_page(page, 1);
-			offset = 0;
-		}
+		n = min(bytes - safe_bytes, (size_t)PAGE_SIZE - offset);
+		offset = 0;
+		page++;
 	}
 
-	return res;
+	return safe_bytes;
 }
 
 /*
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250821200701.1329277-16-david%40redhat.com.
