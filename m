Return-Path: <kasan-dev+bncBC32535MUICBBTMFX3CQMGQEA2XP5BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 84C86B38D35
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:12:37 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-72112230256sf2076137b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Aug 2025 15:12:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756332749; cv=pass;
        d=google.com; s=arc-20240605;
        b=Gmcq2lsmp6kRv1dG1uxw/59sDgUJCHHPwh+xWJ/srunPSLN10DOAXOZ6kE5Dt2744J
         ND4wA8+Eqq3Pk9dffkMWomFLQKY6GJafVS5AmJJTfby/pqckFyyN6wZMUbJiluagLYZO
         VvrVoU8GhvVJJDH1/1poNXTFLty8yc67gQJZDsTwqC+WBqOfb9hhiwUSmgDhJO55oCpn
         nMzjGRI0+UUgt/ZTfK1rjmtslYS7SaC2inNAWmbRwYFXuJvCPMGTdeW+C8Kxyjqee8xL
         WhgcCSVgoRXgORV8H/4n4nBkL28GHaPfZ9W/9eOLFak3X4TYgdeYT2ptnAs5DBA4p0cm
         IlPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=eem/mrTo8+VY7x8D8gomCF3+sVaqftl8bIxVkh42/l8=;
        fh=ceOzYb9i+8BMnBnEDTp/oxV93klLhAKbg3pBoDL0BuI=;
        b=bBBNZMtAfDr4wwTD3hZ+oY/Tj85iMoTPtfDs1RKgbu2QKHU1I/dVeCAajkjhS7XNw5
         IZEuhUrZJrTCIxAX1BKZ5cIXxgymY7As/CZguPyl0dKpKFd+j+M5t4UluUWeT/qWLLOI
         ZX6798/ZsZdw8+glRwAIhDd/RNShFlgm5oN+JJ08RGMc9G0Xjs9s1j8tlk17Cq/fZfGa
         3ig4aWNgGEm9E/Ifjntjrs9XXsvLIqZPX6jqLJA0LfQ++p0FmX3RI6RCzGrgaXvvJKyV
         B96VLBAhMUqh/bWPF0ELN1895+ZhNzaCck9290IyLffDiwOpJD6V8t+li9YsQcG9xbMs
         LHjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RGhE5J1r;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756332749; x=1756937549; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=eem/mrTo8+VY7x8D8gomCF3+sVaqftl8bIxVkh42/l8=;
        b=NW9evtVTbKDLh+e5j9KJx8uAcB/rJy84g0uEte3SDo5jDfhhC88eDPIIlIFkXoj6+D
         oaVcDTCMMNcEZLZuG6TjxqkQnXhT1WoilRwKpWPCX3OckUSxYycfgrBm/ogia+mqpOq/
         Ut8ea6lOJ5TdUlOJ0TTOthJ/NXXBWHrZ4xi8rvPbaUk03wj/gd39DjsRg4h1Ro/iVuj5
         0fqkWfD9nT5v+u+WZJJ9tjiRl3NsMS9ZDnA4iBdctMOppzgH9dvCELQ6q3I8ZsgJxoPa
         Tebv172EBA0kuEtQeVJJxrJ7/5tzUaxSh3bOoIhHTHtDFq7L2anukZ9k1jkSAjkW2+gn
         OnJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756332749; x=1756937549;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eem/mrTo8+VY7x8D8gomCF3+sVaqftl8bIxVkh42/l8=;
        b=i54+Wu+IGWKBDf2iSz6Xw7/zttEbXgNZA2+M0OLEnqAdbkYJyNuX2FSpH+QfRNH1g7
         h9pDFR0fGQnBWIZYk37sTJZH8XbsKPosil1xwOK8yYCnB2NDcsTdU/1HPWKQP1f3f7gB
         yyrp3YWlIEPlCApr/dJhvJrkodjWESxtbtqOujibNpSerJfS1zEPOPacyCuM5NRBcsXy
         6ewtx3wiPziNdu+fxMPkOEpt6FkDWYLY6atQeSoz2/KIKJ90umdTF+MpESU9BeTCNO+u
         zK4MzeHmLzq7fgG3QQw/FN0937ACGoXolpsCAdZvGN5BTNoZmNS0aRPiMpgsiFihm36F
         6QuQ==
X-Forwarded-Encrypted: i=2; AJvYcCWo2qBV17/ScjVS7lRuvjCfegX+RkrviIqPYMVosBzRsMxkPFkI4x9HCcvf00A4FKwlXztcbA==@lfdr.de
X-Gm-Message-State: AOJu0YzFD8yWUyiJemlH7dqrua7WkEmjJMCmAVK6MRf3uJPNN67quMw0
	Sr/EaIt3NQP+X+zPUX+EJ1cTicjcbsuL+Nxg5GQpUXWfFBGWjtrLXn7g
X-Google-Smtp-Source: AGHT+IF4LY0p3eaHasB+F3Q2dL3qvodRw5CE/x47mSgjKLPIr9Mc3vnq/sIg3M/AXLu6LJOzmEjcCg==
X-Received: by 2002:a05:6902:600b:b0:e93:38c1:1fa0 with SMTP id 3f1490d57ef6-e951c2f2fbbmr22349932276.22.1756332749361;
        Wed, 27 Aug 2025 15:12:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeEExEIEXgGrwLiXsjiZUlAOT27YLrgDXyJVuz5d0C7tQ==
Received: by 2002:a25:6a05:0:b0:e93:349e:511f with SMTP id 3f1490d57ef6-e9700ebc802ls165656276.1.-pod-prod-05-us;
 Wed, 27 Aug 2025 15:12:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWQaZ5E2sub9yHmYf1+66FUPfZplw4LJhkpoFU1kmG1r9JRsppzaUtGTuHs0RT5K2CscVJd3EWTaN4=@googlegroups.com
X-Received: by 2002:a05:6902:10c2:b0:e97:398:42c with SMTP id 3f1490d57ef6-e9703980727mr59398276.33.1756332748538;
        Wed, 27 Aug 2025 15:12:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756332748; cv=none;
        d=google.com; s=arc-20240605;
        b=Ugttb/OsiX0Lqc8DENdo0GucC5wT+X+W+z66IsMuZG8/6VQ3yQ50ifZQs75rz5qtwU
         7V2CD0RvrxiwnoTvGt4SFoc41O5IGFk1+p+IN7OsGSjOT8h1lNzH4sy67dqgTl9a/Kte
         sSo7CsaK/ENZllZPTeNTyxYm5d/u0YRMpyWAGiAa7wJNFQ1siVJykWK495aydYYJgSZn
         hQ4QV+0+KzGxYcMAeiMYjI//c1sAf1oJcBih5xMCfIIeXOlatdS4gnyA5NEsiw4Qie8v
         GMYZ5SwpDWejFxDgX9mpDW9Mqik+lIuIDVobWh1vTkDrYh4EcDaTCtLQorDDcSJ3k0Lq
         6C3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=xokvzkSIEpQffuWgfIG7Waj6e5Wn3/nTay4YDrY+vKU=;
        fh=b8pL5mxsrifaEynZEGzAqvQF5L+S8U+H1jEuAVk/IKA=;
        b=dCLQ2Wf5DW3YO2a1Q7E0fNVwE6BHVdMEavfQN5rKcTk6/1A88UtwpLxOdLQCMYCWc3
         Ne7VNADOVKmRUjtipQMKOsX7ucXFKEa7OdhegaMMpKl2ln96nNKWSKe6Dv+k5kvejKW6
         0MefnL4hVIMcFyyiT5lQDNiBeZqknM5++P+owXhsqvopwy/fXYtIg0UuX3fY8vdFnK1I
         I/MYJR4ubPPLnLFEbMG8TSOXY5qf0WUwZVwT7vjdFqIxXCsafWjFNDbI288waFyW5jkn
         fqXvz6HYJ7M7FIhUynRedQ6Qz5VS5KiPnJmrGYSt8qnosm/j4w6mnvA7Z1TRwsEUBa2q
         V5Hg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=RGhE5J1r;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e96d869d159si276863276.3.2025.08.27.15.12.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Aug 2025 15:12:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-488-RQvXUovaMI65FI3R-Bh1mA-1; Wed,
 27 Aug 2025 18:12:26 -0400
X-MC-Unique: RQvXUovaMI65FI3R-Bh1mA-1
X-Mimecast-MFC-AGG-ID: RQvXUovaMI65FI3R-Bh1mA_1756332741
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A0A3C19560AA;
	Wed, 27 Aug 2025 22:12:21 +0000 (UTC)
Received: from t14s.redhat.com (unknown [10.22.80.195])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 2874830001A5;
	Wed, 27 Aug 2025 22:12:05 +0000 (UTC)
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
Subject: [PATCH v1 36/36] mm: remove nth_page()
Date: Thu, 28 Aug 2025 00:01:40 +0200
Message-ID: <20250827220141.262669-37-david@redhat.com>
In-Reply-To: <20250827220141.262669-1-david@redhat.com>
References: <20250827220141.262669-1-david@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=RGhE5J1r;
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-37-david%40redhat.com.
