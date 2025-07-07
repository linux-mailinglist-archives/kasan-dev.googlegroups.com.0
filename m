Return-Path: <kasan-dev+bncBAABBT5LVXBQMGQEYB3G6GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DBDBAFAABA
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jul 2025 07:06:25 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-4a44c8e11efsf94011351cf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Jul 2025 22:06:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751864784; cv=pass;
        d=google.com; s=arc-20240605;
        b=U6GNmNi0k5V16CSqTabpIRyrN10urc3Azfww9BXjDEpGjE4G+P8yO1TeByRFPL4nyY
         YFI1+xLNdajhY34/HkDEz1AzE/cvP524n+yAQ3kiQMvIlxe0Vcx5pASA3gdPThoCKPkF
         NpkXv65gQwOZ1Rg98NpjF8CHW+FoMoUxxQKgP54FhpTb/041Vjm9r/aJjhJWaWLaxGt3
         +aRP8I2muCZj0OsP7fjoPtJNgdscQCWbDjPjXcPXROPA6/rYUNs6p6k/mzL/lAk8vEUA
         tG0nLHgfCojYGvY3hAGWnWV8rejBFL5YL5lw7Ebug0r2T8RSwRF7/PpP5c50IRvFZ1lx
         yCDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=rxvxZ3A38RFVW1yFePt3QvC9tPk3hPb2btTJX6xQ7qE=;
        fh=amGNynIjRxoyrvJ6nrHIGD9ed0I+BzQgClngxkwywWI=;
        b=FbBiEGYOAuwNyUcoFkZFSQgoMOOzLqIMV59p4BlbDdINCDX3GXb+65zZtzPVYwTBNe
         ppSO/eUaAFIhqyu6AExhhO7Q2B35zAUCJz1LSlPkGB3Is0uwSLPVyh8b3AvtiUna2Ljv
         A0B2wzkvJ2W/WdGYJXOLdQk4PmYwP7nwp+zEVrbiGSub1IVykhwab3+ukPcYxa20T8Fp
         VpE6F5HnqYi48pq7iMaZa+i6QioiZmSuUhG0RY7aeUGhre3yilUMP9ks/eMNJnJqew9h
         sCkSZUZd8Td9p0qB0Uy5bnW9W9hAY4QxZf3M2bI/SOPN5laUxOFZ3GFCexT6zg5IdVVo
         xSfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SSvChMM4;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751864784; x=1752469584; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=rxvxZ3A38RFVW1yFePt3QvC9tPk3hPb2btTJX6xQ7qE=;
        b=v3Z3emta/u1PQLaKx9HpqR/NYKUIcjPaJn/TF0RFSRqKmjqtdTG3bc3XRAIuZ588GW
         MJaiOMUpDWxG3Rttd80/1wgy9YGu5F84dgJT+nGL86np2ctQVp1rXOD/Jri5AkoFn7Js
         on3jGbKRtrtl01XBj8uSr6mvsGIS885esRduIa8SXL/KkLdvRIvklqqVeHiRsXceFtfS
         zDDBHBRwFXxN6CuANAGUzmXkVKbUshkRbJEnU5lJb+hPCEY6xjRFMC6tUfTtet7wKrYL
         BXLXNvf6c+Zqnp3QV4gV7CnRx9GVvIEWyA3Ku+m7VfwMQvRSS3nGxqjfKfXzmBA+rrK9
         XTww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751864784; x=1752469584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rxvxZ3A38RFVW1yFePt3QvC9tPk3hPb2btTJX6xQ7qE=;
        b=FSrzxLgUrn3DzJBah5les8ChJG0K+1vjSs065e/xB4AH+KISSL60O40Nw6mnXhdJam
         ruaBwiIGsq1Ew79KX77MvtXHM5w+4gnR6NR2fbS5LDrTHO2oCfVXXBGDOGWhYOfOans5
         YLRaPwuHwcSUWqbxMbULHeV3SrxQJgPAaNbrFME5xyBCDB8GYvNq9Fq49zmGjojz7tQl
         l+eeVa2OH1biXnk5VlzcDvnyoQslkjjfH8v83DUwkmjkzddoMh94WqDVjPf/AsSmeofQ
         UURzuki2dPnngNXYV/ByU5xNf4xr06YVHE1+DMKZ7zux671/XMuPPXmnksgtLdgvSVUK
         4m3w==
X-Forwarded-Encrypted: i=2; AJvYcCUtkY54WKFrQeTv6JxeatiCEYMivxcztUEJTX+DLSACvEt0KNWWZHydXFd8v4Ajstq/0WqjJQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxdw84WCotY7SNZorjof0oiyOB2DotPvVBFflNTkIPhN7BE+YMX
	Dnl2Ut8hBhvwaJfwHAMwv9gqPvGtvqitjQQCIsgSnS4XHh/b9j8+7+K5
X-Google-Smtp-Source: AGHT+IEksEdDL9TKAgfEC15x8p5y5r2BPvSCK4je1OTo2E1rknUanBb0UjmEctk6k7GzwbMeHhRDXg==
X-Received: by 2002:a05:622a:142:b0:47a:e1b1:c6c9 with SMTP id d75a77b69052e-4a99689f4f1mr172839591cf.42.1751864784029;
        Sun, 06 Jul 2025 22:06:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcljKhyNytABV91JdXnKtri36vXQYfmeLbnAWgIplPA+g==
Received: by 2002:a05:622a:2b48:b0:4a9:95a3:9e9a with SMTP id
 d75a77b69052e-4a99be588ccls41064121cf.2.-pod-prod-06-us; Sun, 06 Jul 2025
 22:06:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWOh+p99HgMS8aW5cMDr1TU/iEhDXlhnZ6sv6XubkUm+Yab9rQ/nqkrjt7wBt0KEil2cXP2nVZJV38=@googlegroups.com
X-Received: by 2002:a05:620a:28c2:b0:7d0:a0f2:e6b1 with SMTP id af79cd13be357-7d5dccf4a18mr1930566585a.32.1751864783357;
        Sun, 06 Jul 2025 22:06:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751864783; cv=none;
        d=google.com; s=arc-20240605;
        b=b1Xo/90KlDq0/9YR2vpI9FXLIqw+UkrzcoXPvip0wLSGWJYDG8wnn4K8yS0oA9BPBb
         vLTIvLy2tBLJzaH7bPS2zwa4msBsyX9rrmQqYGT3WEE4pouui7IwDJQMpngHFKO1keNc
         vETw8OdNiXeHGi4GHWUEiTR1t23DvF+xfSjI/RMTkxZdPAJuM2nQXe91WguNovLgOk9h
         y9ljsDeikB79CGF2y1BGpjy5F522OwF4EWSR6gowvDT4TeSiahk5NhYf/w4tZcUL/aZJ
         O3cB8G6knGyXRUA8LgxMqEetMLhJAYltabbmk8MMKg0MuFJVknFvCaTKdlrIwZrtaEeQ
         e/tA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=q2yGqvVq6LEpD0b3a5OqKRptUUKyXtz9GTGn6fNo7es=;
        fh=bGOSWPRaEaNPf+ttcItAvdRcTCsALM11wypoPWX8Mxk=;
        b=Ofgca3W9QfcJ5fBbUSJMRr1Apgrla8XbczomnAbJdAKoiwDUd6aGVR+A1yJt4cifdG
         pxGZZMK2xsf05/o6hPF+E1LZiqzruxNEGWNXXIyE7hjgfvs0fRhBq/ZHcaAaexmcmTv1
         F7okAC2h5YsMzS7ZTC6fbC2tuT8IO6Duc5HWfjKEYRnPSV7Ae15VeV9KFQuoEhWYsKyl
         xJjytZFQBMsgw3R+hjHoZBDbhXGnHiAhN2l741qJm/eaVAGKj5kTOaa3qsrYCp5FbzEd
         h+IlTOE2CAFJF1Uecx+GY86jCYPslUa0aL9erNfg9e/2yhgAT7Ka0u4FpT0LZezAsdg7
         BgiA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SSvChMM4;
       spf=pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-702c4d1a451si3448396d6.6.2025.07.06.22.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Jul 2025 22:06:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C92F35C5789;
	Mon,  7 Jul 2025 05:06:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 29016C4CEE3;
	Mon,  7 Jul 2025 05:06:21 +0000 (UTC)
Date: Mon, 7 Jul 2025 07:06:20 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>
Subject: [RFC v3 7/7] mm: Use [V]STPRINTF() to avoid specifying the array size
Message-ID: <d0e95db3c80a7356e33587065d258838651b48c0.1751862634.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751862634.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1751862634.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SSvChMM4;       spf=pass
 (google.com: domain of alx@kernel.org designates 139.178.84.217 as permitted
 sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Alejandro Colomar <alx@kernel.org>
Reply-To: Alejandro Colomar <alx@kernel.org>
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

Signed-off-by: Alejandro Colomar <alx@kernel.org>
---
 mm/backing-dev.c    | 2 +-
 mm/cma.c            | 4 ++--
 mm/cma_debug.c      | 2 +-
 mm/hugetlb.c        | 3 +--
 mm/hugetlb_cgroup.c | 2 +-
 mm/hugetlb_cma.c    | 2 +-
 mm/kasan/report.c   | 3 +--
 mm/memblock.c       | 4 ++--
 mm/percpu.c         | 2 +-
 mm/shrinker_debug.c | 2 +-
 mm/zswap.c          | 2 +-
 11 files changed, 13 insertions(+), 15 deletions(-)

diff --git a/mm/backing-dev.c b/mm/backing-dev.c
index 783904d8c5ef..408fdf52ee5d 100644
--- a/mm/backing-dev.c
+++ b/mm/backing-dev.c
@@ -1090,7 +1090,7 @@ int bdi_register_va(struct backing_dev_info *bdi, const char *fmt, va_list args)
 	if (bdi->dev)	/* The driver needs to use separate queues per device */
 		return 0;
 
-	vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
+	VSTPRINTF(bdi->dev_name, fmt, args);
 	dev = device_create(&bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
 	if (IS_ERR(dev))
 		return PTR_ERR(dev);
diff --git a/mm/cma.c b/mm/cma.c
index c04be488b099..49c54a74d6ce 100644
--- a/mm/cma.c
+++ b/mm/cma.c
@@ -237,9 +237,9 @@ static int __init cma_new_area(const char *name, phys_addr_t size,
 	cma_area_count++;
 
 	if (name)
-		snprintf(cma->name, CMA_MAX_NAME, "%s", name);
+		STPRINTF(cma->name, "%s", name);
 	else
-		snprintf(cma->name, CMA_MAX_NAME,  "cma%d\n", cma_area_count);
+		STPRINTF(cma->name, "cma%d\n", cma_area_count);
 
 	cma->available_count = cma->count = size >> PAGE_SHIFT;
 	cma->order_per_bit = order_per_bit;
diff --git a/mm/cma_debug.c b/mm/cma_debug.c
index fdf899532ca0..ae94b7ae6710 100644
--- a/mm/cma_debug.c
+++ b/mm/cma_debug.c
@@ -186,7 +186,7 @@ static void cma_debugfs_add_one(struct cma *cma, struct dentry *root_dentry)
 	rangedir = debugfs_create_dir("ranges", tmp);
 	for (r = 0; r < cma->nranges; r++) {
 		cmr = &cma->ranges[r];
-		snprintf(rdirname, sizeof(rdirname), "%d", r);
+		STPRINTF(rdirname, "%d", r);
 		dir = debugfs_create_dir(rdirname, rangedir);
 		debugfs_create_file("base_pfn", 0444, dir,
 			    &cmr->base_pfn, &cma_debugfs_fops);
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 6a3cf7935c14..6d0bd88eeba9 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -4780,8 +4780,7 @@ void __init hugetlb_add_hstate(unsigned int order)
 	for (i = 0; i < MAX_NUMNODES; ++i)
 		INIT_LIST_HEAD(&h->hugepage_freelists[i]);
 	INIT_LIST_HEAD(&h->hugepage_activelist);
-	snprintf(h->name, HSTATE_NAME_LEN, "hugepages-%lukB",
-					huge_page_size(h)/SZ_1K);
+	STPRINTF(h->name, "hugepages-%lukB", huge_page_size(h)/SZ_1K);
 
 	parsed_hstate = h;
 }
diff --git a/mm/hugetlb_cgroup.c b/mm/hugetlb_cgroup.c
index 58e895f3899a..8f5ffe35d16d 100644
--- a/mm/hugetlb_cgroup.c
+++ b/mm/hugetlb_cgroup.c
@@ -822,7 +822,7 @@ hugetlb_cgroup_cfttypes_init(struct hstate *h, struct cftype *cft,
 	for (i = 0; i < tmpl_size; cft++, tmpl++, i++) {
 		*cft = *tmpl;
 		/* rebuild the name */
-		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.%s", buf, tmpl->name);
+		STPRINTF(cft->name, "%s.%s", buf, tmpl->name);
 		/* rebuild the private */
 		cft->private = MEMFILE_PRIVATE(idx, tmpl->private);
 		/* rebuild the file_offset */
diff --git a/mm/hugetlb_cma.c b/mm/hugetlb_cma.c
index e0f2d5c3a84c..c28d09e0ce68 100644
--- a/mm/hugetlb_cma.c
+++ b/mm/hugetlb_cma.c
@@ -211,7 +211,7 @@ void __init hugetlb_cma_reserve(int order)
 
 		size = round_up(size, PAGE_SIZE << order);
 
-		snprintf(name, sizeof(name), "hugetlb%d", nid);
+		STPRINTF(name, "hugetlb%d", nid);
 		/*
 		 * Note that 'order per bit' is based on smallest size that
 		 * may be returned to CMA allocator in the case of
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8357e1a33699..62a9bcff236a 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -486,8 +486,7 @@ static void print_memory_metadata(const void *addr)
 		char buffer[4 + (BITS_PER_LONG / 8) * 2];
 		char metadata[META_BYTES_PER_ROW];
 
-		snprintf(buffer, sizeof(buffer),
-				(i == 0) ? ">%px: " : " %px: ", row);
+		STPRINTF(buffer, (i == 0) ? ">%px: " : " %px: ", row);
 
 		/*
 		 * We should not pass a shadow pointer to generic
diff --git a/mm/memblock.c b/mm/memblock.c
index 0e9ebb8aa7fe..20d3928a6b13 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -2021,7 +2021,7 @@ static void __init_memblock memblock_dump(struct memblock_type *type)
 		flags = rgn->flags;
 #ifdef CONFIG_NUMA
 		if (numa_valid_node(memblock_get_region_node(rgn)))
-			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
+			STPRINTF(nid_buf, " on node %d",
 				 memblock_get_region_node(rgn));
 #endif
 		pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n",
@@ -2379,7 +2379,7 @@ int reserve_mem_release_by_name(const char *name)
 
 	start = phys_to_virt(map->start);
 	end = start + map->size - 1;
-	snprintf(buf, sizeof(buf), "reserve_mem:%s", name);
+	STPRINTF(buf, "reserve_mem:%s", name);
 	free_reserved_area(start, end, 0, buf);
 	map->size = 0;
 
diff --git a/mm/percpu.c b/mm/percpu.c
index b35494c8ede2..8d5b5ac7dbef 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3186,7 +3186,7 @@ int __init pcpu_page_first_chunk(size_t reserved_size, pcpu_fc_cpu_to_node_fn_t
 	int upa;
 	int nr_g0_units;
 
-	snprintf(psize_str, sizeof(psize_str), "%luK", PAGE_SIZE >> 10);
+	STPRINTF(psize_str, "%luK", PAGE_SIZE >> 10);
 
 	ai = pcpu_build_alloc_info(reserved_size, 0, PAGE_SIZE, NULL);
 	if (IS_ERR(ai))
diff --git a/mm/shrinker_debug.c b/mm/shrinker_debug.c
index 20eaee3e97f7..7194f2de8594 100644
--- a/mm/shrinker_debug.c
+++ b/mm/shrinker_debug.c
@@ -176,7 +176,7 @@ int shrinker_debugfs_add(struct shrinker *shrinker)
 		return id;
 	shrinker->debugfs_id = id;
 
-	snprintf(buf, sizeof(buf), "%s-%d", shrinker->name, id);
+	STPRINTF(buf, "%s-%d", shrinker->name, id);
 
 	/* create debugfs entry */
 	entry = debugfs_create_dir(buf, shrinker_debugfs_root);
diff --git a/mm/zswap.c b/mm/zswap.c
index 204fb59da33c..01c96cb5e84f 100644
--- a/mm/zswap.c
+++ b/mm/zswap.c
@@ -271,7 +271,7 @@ static struct zswap_pool *zswap_pool_create(char *type, char *compressor)
 		return NULL;
 
 	/* unique name for each pool specifically required by zsmalloc */
-	snprintf(name, 38, "zswap%x", atomic_inc_return(&zswap_pools_count));
+	STPRINTF(name, "zswap%x", atomic_inc_return(&zswap_pools_count));
 	pool->zpool = zpool_create_pool(type, name, gfp);
 	if (!pool->zpool) {
 		pr_err("%s zpool not available\n", type);
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d0e95db3c80a7356e33587065d258838651b48c0.1751862634.git.alx%40kernel.org.
