Return-Path: <kasan-dev+bncBC32535MUICBB7UCX3CQMGQE7L5EK5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DBB8B38C7E
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:06:56 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4b109bd3fa0sf4773351cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:06:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332415; cv=pass;
        d=google.com; s=arc-20240605;
        b=hTh4G8AXosTXFB/vz6mzonDZ/AGoy8Nrqf4rrYiEerEIWjolKuWZeABN5UeRMRq4mi
         ZT3TvEUkMs/RH4+vgzZyiW4XY9K0Bm3Myo2+N63CHatsZQntUpWpKR/NFuXZ1Ed454Cy
         o1Cv8+cJpRjfYOK89eAmjZ232Xc4ghetyN07ERaH19QZqK06OI60f3ag5FKqpxjEihGT
         1mFNF4rZD4b1msuIyYVroaFjikzi5xm0RHmAVGmytnxC57hGPfjRu7SRfuSpTtH94QlP
         pTMWJV1PJ/mYqm9P9vXMXSVh518d6YvsMJRMjLOQWXfJYTQQbj2Ga4Hll05Z8kUB4IM1
         ceYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=tW7jWzq+7tP6ZsHb75uM3pfz3BriV9fa8UZIGaQp7fI=;
        fh=eLt1gyFDhmrafwymSw033N0TqoWxPjXLdMN6OrLpD1A=;
        b=OTHkt/bY0OxDLs/r92y2VR81TJiFOsU3pEQyM58PvMjL71lX6o35xiedFARwn36546
         RDRyJUDd5EDP8rfFcYnUWh5BOFsAAPjuzWd7y8vrpSHNHDlbehCv1ufCbIxlBA7anFwp
         lfvyVFqXP3F6VD3Gfmc9oiPYwnVhwB3za0X/ysuyxRyU8UCUTbaIDiUoymQa4DnBmk2Q
         F4sTewOmpCTfCE9zbPVuYAHOd2TeuGsU3OFyZmrpJiRecAPAZa17lR+AM3udcsl6NLxa
         VRIjIv3bM1vM72DYKgebU5Qyi/zfW4NzZB3TVnQ4hyXeGGWdHCLMs3wt55cRe7OYAGM6
         lJVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=H6ikshVo;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332415; x=1756937215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tW7jWzq+7tP6ZsHb75uM3pfz3BriV9fa8UZIGaQp7fI=;
        b=Gfb/OUNxdcvVl0epuIl7t9eTCXWTFM9e7IH6a673862pqDtxMhtj2jM+1gHxzhLWdx
         D1IuQVfTT5bkYGIIluJa9j29i8GFlkwMRLr6xXK7rZwhKTZv3XFL/lrI+dXqsDiVrphj
         MVccZorJleGuq/x3Yfu7vz8LqUZbFV1GVlPWxIq3k/Nu7J9DyQJyFrSuxepEJ5+4Qhk5
         ChHwxCHpx94oZpqO/h9tXKFdlvv2omP4aMMrkJLKb21UeFbo9gfcVfVSrjBBX6I4x+I+
         SzSHP20AEJrOsUhbDt42utkMaKidUnGM/t8uF5J2EgGaT9/Xysa2Mo5usQpSX4uJ7OII
         e20Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332415; x=1756937215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tW7jWzq+7tP6ZsHb75uM3pfz3BriV9fa8UZIGaQp7fI=;
        b=EgiVfcAArh3AB35lnkHciyZbi+bQXWcTCet5u1bqM/ailf/G3KgSI9AngMsw+4KTig
         lvcVmZX3W2JK37Z4lhVH6eEDenCGN/uiq+g8ZIz2tFELwLXDxn2IFxqvJu3KVTUWBo/2
         LSe7mzsmvyoNga6XeKl1MgWwnSiKUyt3vgfI1o9C6e/LEW7WlMRUoud+IZxQ7qa8AxpM
         cbbR+q0rm6KMoiEMvsU1C1PRRDr6eMftHhxlRjh7hUW920+01khg851zy0msatJPCTzG
         l2ZYO8XWY42pAe0nitY7djFLogPtRqDvU/J4J76jPphkYv0Ign8DcEpHBmeCGAX49LdR
         jgPw==
X-Forwarded-Encrypted: i=2; AJvYcCWp8TStrjbyXso1sRRWDnQmxxWp3ERH3Xhi5dR7Nt+Z8qvXBP/FNzjJUPc9NWVN+NnT7SLlcA==@lfdr.de
X-Gm-Message-State: AOJu0YwhtQ4gSo4cCSt/dGVIOFoX4axwAqmynlzdrKC+ZDwMZCsjX1bY
	PvdhQGWhTOZ/8Qy/HlS2HYQf9TL8IDqVZ69BfR3lJp4Yci3sW6u5A84+
X-Google-Smtp-Source: AGHT+IFXPsusdGsjHaRGCloycE2TlEACAwwFSrQFW7in7lmhyThGSpK2Hy3S1tU+L1Ap3xVZdxzjBg==
X-Received: by 2002:a05:622a:241:b0:4ae:cc75:46e7 with SMTP id d75a77b69052e-4b2aab44eb1mr234799531cf.57.1756332414714;
        Wed, 27 Aug 2025 15:06:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf8bmlBqAa5nwIbT5vpdzfifWmRnCt6YJldiOGLhKdoXg==
Received: by 2002:a05:622a:1190:b0:4a8:17dc:d1ee with SMTP id
 d75a77b69052e-4b2fe6343dels1986651cf.0.-pod-prod-08-us; Wed, 27 Aug 2025
 15:06:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVBAqAZL5ImjITtcsNdEdqKuG/ES5E4S+AJkS2EzScGzlqvvZLyOk6keqao2DVgxjhbY4+s1FHmPVU=@googlegroups.com
X-Received: by 2002:a05:620a:450f:b0:7e6:6028:6180 with SMTP id af79cd13be357-7ea10faa10dmr2176156685a.30.1756332413826;
        Wed, 27 Aug 2025 15:06:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332413; cv=none;
        d=google.com; s=arc-20240605;
        b=dAUvsxTIdCUkWGtnDRbmxqhKRKHYvA3tvEHqFh25zzdCbE/GUuk99+iVB1BOg5Vr5u
         lXP9Wwm7WaXynjlgMmulzYhWUMAdsNshbR0DddXAViErz4jEUpThahRVcXsf61ZpTfMP
         zB8R0vAY38LE4cTXoOipfll42199iyab1qNci5fchY2EbBQql5mTN+G82beL+Jm+E9TD
         9GJeHJDamvX5/8qdu9HkSM+7H9gRdRS1chsTkt4cygCpXm5AELfptDeWSr/eLP62qsMX
         5xPKFoHKRi+zwHAzHLRSscZV55PgPMURi5KdjwJr6HhmF8A7+N9amXPozatkhp1gaeNm
         ZWSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6MroGOug632a51ffxPVHU3ATCsOwaa4b3tJ1MTGryys=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=KxXZQx8FoDICCm3ATSkiiMcF8MKGloIbB9yfyErCHPJ390loCYMuVeAEtd8i4XN8lb
         wj5okgYhO/10MiKWMjiJMv7yX6hb9DGLxMjINYpR91xCfOVgKiKLDanoRCPTic3EL5DK
         952WgJ59m7wJH3uCMcTwR1ILf3+6nU68nAEQaH21youtgBt1f728Hg4R8DKU4CiDFhnO
         vUwCvo8WQPaEYN5gOrRqRA8wffFpuIBK9SIfN7lotbAZXgVgHmrhzcAXsFt3DtY3ziU3
         +ouLibT4qnXkpAr/dItoOil7G4SJuhFEi0eO16QAhxGyZ9vzscUPIGQ2BMRSPF4Z1H85
         u9Jw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=H6ikshVo;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ebf103de0fsi53471985a.6.2025.08.27.15.06.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:06:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-556-a2F6JvbVP--8yuHhX8WRDg-1; Wed,
 27 Aug 2025 18:06:50 -0400
X-MC-Unique: a2F6JvbVP--8yuHhX8WRDg-1
X-Mimecast-MFC-AGG-ID: a2F6JvbVP--8yuHhX8WRDg_1756332405
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 2834019541AC;
	Wed, 27 Aug 2025 22:06:45 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8C0E530001A1;
	Wed, 27 Aug 2025 22:06:29 +0000 (UTC)
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
Subject: [PATCH v1 16/36] fs: hugetlbfs: cleanup folio in adjust_range_hwpoison()
Date: Thu, 28 Aug 2025 00:01:20 +0200
Message-ID: <20250827220141.262669-17-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=H6ikshVo;
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

Let's cleanup and simplify the function a bit.

Signed-off-by: David Hildenbrand <david@redhat.com>
---
 fs/hugetlbfs/inode.c | 33 +++++++++++----------------------
 1 file changed, 11 insertions(+), 22 deletions(-)

diff --git a/fs/hugetlbfs/inode.c b/fs/hugetlbfs/inode.c
index c5a46d10afaa0..6ca1f6b45c1e5 100644
--- a/fs/hugetlbfs/inode.c
+++ b/fs/hugetlbfs/inode.c
@@ -198,31 +198,20 @@ hugetlb_get_unmapped_area(struct file *file, unsigned long addr,
 static size_t adjust_range_hwpoison(struct folio *folio, size_t offset,
 		size_t bytes)
 {
-	struct page *page;
-	size_t n = 0;
-	size_t res = 0;
-
-	/* First page to start the loop. */
-	page = folio_page(folio, offset / PAGE_SIZE);
-	offset %= PAGE_SIZE;
-	while (1) {
-		if (is_raw_hwpoison_page_in_hugepage(page))
-			break;
+	struct page *page = folio_page(folio, offset / PAGE_SIZE);
+	size_t safe_bytes;
+
+	if (is_raw_hwpoison_page_in_hugepage(page))
+		return 0;
+	/* Safe to read the remaining bytes in this page. */
+	safe_bytes = PAGE_SIZE - (offset % PAGE_SIZE);
+	page++;
 
-		/* Safe to read n bytes without touching HWPOISON subpage. */
-		n = min(bytes, (size_t)PAGE_SIZE - offset);
-		res += n;
-		bytes -= n;
-		if (!bytes || !n)
+	for (; safe_bytes < bytes; safe_bytes += PAGE_SIZE, page++)
+		if (is_raw_hwpoison_page_in_hugepage(page))
 			break;
-		offset += n;
-		if (offset == PAGE_SIZE) {
-			page++;
-			offset = 0;
-		}
-	}
 
-	return res;
+	return min(safe_bytes, bytes);
 }
 
 /*
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-17-david%40redhat.com.
