Return-Path: <kasan-dev+bncBC32535MUICBBUXQ23CQMGQER5MTDQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 70605B3E921
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Sep 2025 17:14:28 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-7f73ccde87dsf694060885a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Sep 2025 08:14:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756739667; cv=pass;
        d=google.com; s=arc-20240605;
        b=cSVp9kE/ViwPoe0+3kqy9QPT926ferJ9nwQVc5qpyksUEDAqSHKl+TJOQ3L8yk8euy
         KC35Fp4Q8IBerKKLoPTWOtV91RRxJDgs/zBCeMpyjlVkrhUtlqZZDIdb/uSjTzb+mhEd
         2q9sUf4EfDV/WAhEIPzbco8U+7gAqCbGS/boK77+DoW1+XvbJg/leSIZg0buf0EV1re7
         hyB72/ffX8QdKSVziddkxhCfdkGOJi52+Jqbzefw4k2qkdaaSeSfsi4D7BSbIN3qGx+d
         a3ElUL7yaFw+IVle1Qo6DhkxBqiKNm5L86Efv7snqsbOOemHYIJ1Lmu275Y9EPS4BxH0
         Il1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=/ZGRGvTJJlQm/l7y48HKwFSv/lOHcAgXAoQCc2HxWM4=;
        fh=KPR6NxYNfMScYVCI7gTcozmZdMwFMYqJG0yOrHg5YRM=;
        b=lQHVbcjsVpQwgaywIaU6+fDDb7ryXM8U+H7VB2ZUzoaz/3dC9fXqzEoGR6o+I13gxW
         KO6UsSjdbBo9b3dDu6ir8f1hVZuYiNAYTMBLsoBdA2Y4jf5/215DJIReoRVKNwRVTmlq
         VvDRK+xc9Jn4H/xB6ZESl+t6AsyyDozpMxppvRGSBkN/fWH1RZXnTHSx7ArfGICrH2Dy
         X6gq2RA/8YYPPKrNvx31q9sMcQfzfVw6YVipMDmiN0QSyQ5y6VbaTRi9Qplu0hP9FFnx
         IcfN5YN2e2CF1SqVBCCvIbUmainCKdxrVlGBlzhJUHrr4dQ5B6unvQt0FR3+Ys3oAvGy
         YNlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=R6QIe2kh;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756739667; x=1757344467; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=/ZGRGvTJJlQm/l7y48HKwFSv/lOHcAgXAoQCc2HxWM4=;
        b=SMjlXP/j/KHtxBZo7783eqLxU1KSaqUQm2A1Ni/o1tDjjs2X9XDMuPUbi2DP2prGPe
         A/7Jnped3WBGkEupLhaQmI/ghWBtZZEK2JzWNs0YD7LmanWe8PgTki5IJzQ2XmmlvDlQ
         2LliLYzYvkJXVVyS+z1Br+Lq6DzE8D+7CQhh4tBpyKeH/Ae0zbbhrCwCvqjDktmnfd2y
         R4yrXiGaZHYyT+aYQY4V3N26RAaWV7rCYDPUGhvrNVlZ75/pWI7NeiLbe3pyA1clAyCh
         tmZBNnMG/QxEm9j/CxL2dybU+AC3u8495OIwDkFFztCA9UOmub9HsKHwhqWGNuair9Fr
         pCgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756739667; x=1757344467;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=/ZGRGvTJJlQm/l7y48HKwFSv/lOHcAgXAoQCc2HxWM4=;
        b=ipwEZIaAkbN5oNq3iiiudlztDtcmgJo2Xa+KOOYoT6fdrC8xc/V1PKRSWAHnQWpjxK
         92QWQBj7B8fVhcTehkFEo6X2bq/hK8e49g8M9aMRsTvVJs1orjzZXFdVPapu6dXIg0TM
         prwOO9WueppwX5GH2vifl5zL2ASye4Px2ZOt6lmxuG8qFrIYCI1SA2uoITMnXXGW304Z
         bWOj3etVk1BXVvoMTgKjQ3Jz6LV4b+McqQ7CoaqgeMbkvz+4xehywAQJVb5lnHY7VV8r
         krslZHJWielUw2IPZ0g0c+vKLcI3WNJ8WBh1QrSFgYt3wNrvPiw9iYOCGG0SdtoPyzpn
         ZuQw==
X-Forwarded-Encrypted: i=2; AJvYcCXRY9rXg8blvxJVnHHvxvMxFKSkJyD/YEbgryCgkLag5FaX8yFrvvtra5q6mRUmjJiHG18rnw==@lfdr.de
X-Gm-Message-State: AOJu0Yy9jOHDDw7R27bdLDjYT7krHFEVi2B4VnYit6uwM3fnMK27b+HI
	ci/XuzWLiGbJjcl2f4uVR4XitYIheKudW2u5jHQ3ZUbWydrL61MM5NTU
X-Google-Smtp-Source: AGHT+IHG7YprYp9Zfq9M3ebN0uLgN7/R1OLjZt3dZeHns3/2bfyeArapaWAsjlfyZvzPh+1bYR5y4w==
X-Received: by 2002:a05:620a:2549:b0:7e9:f81f:ce70 with SMTP id af79cd13be357-7ff2ccd073emr804057585a.70.1756739666882;
        Mon, 01 Sep 2025 08:14:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf/j68n0HZUShRf65i5Z6RKPqSg+aWkqVDPqrPAJF9aBw==
Received: by 2002:ac8:5895:0:b0:4ab:825d:60e7 with SMTP id d75a77b69052e-4b2fe86dc86ls72949831cf.2.-pod-prod-01-us;
 Mon, 01 Sep 2025 08:14:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUUljBjZOyvzhVhnnxq0ASoz8+OvMHh02FDEWcoemCkR6B8cH/ndgUpg/yKpLKsEgPbccKxJkM9zC8=@googlegroups.com
X-Received: by 2002:a05:620a:2a01:b0:802:2b8a:3c22 with SMTP id af79cd13be357-8022b8a406bmr476241185a.32.1756739665240;
        Mon, 01 Sep 2025 08:14:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756739665; cv=none;
        d=google.com; s=arc-20240605;
        b=MvzwgSp5Q4Nmohn/71aJFOu2hi3Ffcqd1DqkJJf304zCrxS9bHbCfROs7Ak5qeIZBH
         Etx9e/gY4+G9DUllUAxwCXudwoLgiyiGv7EMwnBDHYZTGDe5iOjKsWvADpcZxufdDG9X
         VTuw0M5uHsZbFS+UMNvf7/sDJDHKWQcGV5aZAAb3OYHjtNUBXtoWHqqMg0b3E3RsQ940
         HrLSz9hKe15yWLL/usIMclHf8Yhlsyt4PX4dvdhqgqOwDrYCRyph+7odv22Gpva/ODFR
         XuiqOYpZbU81mBEQvE2pX3+pG5kd+eA9ikHFI1bEejcAVTRydL5L4kZO0tMGkvyhAJeb
         xXjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wgq8t08BL7RNfQ5mX4qRFuahvfg5EKXwRMG9Zf68USY=;
        fh=a+0inipWR+gxi2bF8fgHCUkmRRcEkdXajxBfbsdM2UE=;
        b=P1pyZlQIvV5Ly0rvZ5B1aRe8SvfPBo2gt0cFuDF0TiXiMg8vfJ6OI/ucD2sdSKSZXE
         K2Wnm23nDhcDUUPbY50AJ1jZMnsx74HDTvYXkj/dd0OGFJBiWHwXsa/QPCN35VmnMV2v
         HcJLcFbjdLBxDdj1zuIM23RZIbXZwD/mQ0KQJoGDf+ev25gmZ0aE29fnpNbeLHk3xzaH
         hwpixs8S3AUCBa+cT42tIcW9YUG0NrwNJjcf00zs4+BbK9ARQlxes38u2NKeRweYpkaQ
         fc2FtONCcszGmSLsXDjSuUrrREBk96hslxB1MiXoWsSQ23o/3a9W2WIxhW5hAU38fses
         HT9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=R6QIe2kh;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7fc11905071si36424385a.7.2025.09.01.08.14.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 01 Sep 2025 08:14:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-618-GxSXaOqMOKWCp_wVKjXAog-1; Mon,
 01 Sep 2025 11:14:20 -0400
X-MC-Unique: GxSXaOqMOKWCp_wVKjXAog-1
X-Mimecast-MFC-AGG-ID: GxSXaOqMOKWCp_wVKjXAog_1756739656
Received: from mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.93])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id C598B1800366;
	Mon,  1 Sep 2025 15:14:15 +0000 (UTC)
Received: from t14s.fritz.box (unknown [10.22.88.45])
	by mx-prod-int-06.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 0A0B1180044F;
	Mon,  1 Sep 2025 15:14:00 +0000 (UTC)
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-kernel@vger.kernel.org
Cc: David Hildenbrand <david@redhat.com>,
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
	x86@kernel.org,
	Zi Yan <ziy@nvidia.com>
Subject: [PATCH v2 37/37] mm: remove nth_page()
Date: Mon,  1 Sep 2025 17:03:58 +0200
Message-ID: <20250901150359.867252-38-david@redhat.com>
In-Reply-To: <20250901150359.867252-1-david@redhat.com>
References: <20250901150359.867252-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.93
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=R6QIe2kh;
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

Now that all users are gone, let's remove it.

Reviewed-by: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Signed-off-by: David Hildenbrand <david@redhat.com>
---
 include/linux/mm.h                   | 2 --
 tools/testing/scatterlist/linux/mm.h | 1 -
 2 files changed, 3 deletions(-)

diff --git a/include/linux/mm.h b/include/linux/mm.h
index 2ca1eb2db63ec..b26ca8b2162d9 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -210,9 +210,7 @@ extern unsigned long sysctl_admin_reserve_kbytes;
 
 #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
 bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
-#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
 #else
-#define nth_page(page,n) ((page) + (n))
 static inline bool page_range_contiguous(const struct page *page,
 		unsigned long nr_pages)
 {
diff --git a/tools/testing/scatterlist/linux/mm.h b/tools/testing/scatterlist/linux/mm.h
index 5bd9e6e806254..121ae78d6e885 100644
--- a/tools/testing/scatterlist/linux/mm.h
+++ b/tools/testing/scatterlist/linux/mm.h
@@ -51,7 +51,6 @@ static inline unsigned long page_to_phys(struct page *page)
 
 #define page_to_pfn(page) ((unsigned long)(page) / PAGE_SIZE)
 #define pfn_to_page(pfn) (void *)((pfn) * PAGE_SIZE)
-#define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
 
 #define __min(t1, t2, min1, min2, x, y) ({              \
 	t1 min1 = (x);                                  \
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250901150359.867252-38-david%40redhat.com.
