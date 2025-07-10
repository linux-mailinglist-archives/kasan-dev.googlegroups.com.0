Return-Path: <kasan-dev+bncBAABBNHCYDBQMGQEZOJQKRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 30491B00DDC
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:31:34 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 41be03b00d2f7-b31bc3128fcsf1987508a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 14:31:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752183092; cv=pass;
        d=google.com; s=arc-20240605;
        b=JQ1wcneWkjHuuxQy4lVL/UHT+XnpLUEZhQ0mhv5PEZxh4Z5zQ1FJae4mbTA1YmdAvf
         +F97oklW6MfegqNdTieRJtmC4zWxPWdu5Pbnk3JWmPKDVULL34v5u6IYe2dpeePVpT4J
         qz4apPRx+bChVhLkuX12GLwdyl4ZVJQbk6OriTV+qAPH9peSXvJ1Vts+VaUmJhXoK685
         pOW8+rPdaGbN5Nc+2pn3eSj/t107uYlx95STxVxUjXgNF5NYJAfD2il5usFtCxnsWhC7
         VVp3yYPP5Qx+XClGGVUpDHJPMNBc6OXu/WxLdsHeoDBYfQMGLVpryw9iOaTU4BUfCJHf
         yLmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=AcowfZKNijDS135fTzToPAhEC/MlEA8ctbhHxsliX2c=;
        fh=+16IKc/oI8njc6/P1XEno9eXhQqPOogeTh87R3XJsTc=;
        b=eXRDYDDHTOPyN5G7oyeQGsSMl7o85gckS+ntSbeqTJCtVTyJfMhFSyawqNKhXsQzlM
         7b8pAAVU3lo9YE+2fpMa9XtN1a5VCpquuw9Vb5KN/V/Wi5nSbESWgZhYVzvQSXlKHGdo
         /k6NwkdlQ/OB7c1JLR49WJ0bFXTy57GIn8OxkVV9p27gV4xmtVaE3N8TpSwLqlgrRD6B
         yzwPrIYmO2ZlB4Vtrv7pChS5Ud3UYc9wSLUyez/J+7oN2RgkZdUu9Z1L0aQY0Q04aFn9
         w7DH3au+tLfe8NZISjHnClKladqmfJeespVecgOXiyO3EHyA6G3B/1ITY97igIwSjVGj
         grMw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CeSK1sDO;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752183092; x=1752787892; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=AcowfZKNijDS135fTzToPAhEC/MlEA8ctbhHxsliX2c=;
        b=dKNwPzgjTnEL2Hmkm7Xd7nRxFn4S1TDX4ogtgGqYsTJO+VAfnfXaECTARRwpF7cHvz
         IeEX+ZhZ3Cjti8OUrzhPRDh17Zwqmt3vzg9OOeIZs43Nnfu7ROMn8rncvW8yVEE+sBIW
         0gNl64nDHiwcs/FRCkqFpF5xsFLUtIX451GM/ay9ekuqGd3y4mTKk+qGjrjcHrcvGF+O
         8/+YNGsf91Yr0LM6o7bn17fDBXVUcY2TpT4ZsMogR5u6e+J/Bbv1pw08oqvGNchn4Thx
         fTgx39OYAUZdvd9FIBWeW3NQR3dTBEl+BLYgEOx/52TYD6SveU3GxTWPBBrjONi0XLPM
         QfNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752183092; x=1752787892;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AcowfZKNijDS135fTzToPAhEC/MlEA8ctbhHxsliX2c=;
        b=Q7JeN6lJOQE7yTPZIxmDfh/b3kLjfrYI4cUI9aoAK/aPln4/HovmrdDEy+oVtvNHjD
         mTLstSkMRxY8HURcdHJOGwFREfUVDQDR+MPlW+oliHNfB9bjn99gfvMaZMWSLBXrqweV
         qsMQcPfPnQxpfpPRYt83TB2Y3B/Om9HaYSzoIKLqZUPaOzWYSrLJIxP44DbCCYYRBvo9
         QoJrMVCrPd3SQcUWyvp716j5hHqJ8wcbIczrWOuD7N1c46dd7LaQrC1XkNEYTlmnrp32
         tpOtbIuU6BHCVuCrFTOTM5E/d5Hh/9M3tklh6MUtL4B5JyxZkAWKOtqKsdm8OR4qdXkI
         Bcpg==
X-Forwarded-Encrypted: i=2; AJvYcCWQMvIdeGJV0laWUlQVgLCBK95K93PQ8meCY2D6LRJh7z0BpJRog+DZRHdRqWhYkgn6borgag==@lfdr.de
X-Gm-Message-State: AOJu0YzYKwOhhg9VQqE7ahsKsatC4cysa73bjvdpk/ZUR3KFbceGY5fR
	5dGk0Nfr8Kez5ZmagukNhkPFB6VenwUcpZSCnTem1G4Ssd8ndAlq1b0o
X-Google-Smtp-Source: AGHT+IH4E6CeEPVc4OubeTQrCPWWO/WQdJUGg0ylnwec10k3Ip44xUR5grIO1TDw+f7mfyasP97pIg==
X-Received: by 2002:a05:6a21:496:b0:220:8b27:1b4e with SMTP id adf61e73a8af0-2311ee4b14amr1210740637.26.1752183092487;
        Thu, 10 Jul 2025 14:31:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfvy0kkdyMhhyqh3zwVMMV+4VT7aQ6BZAiTL1ucKwqqtw==
Received: by 2002:a05:6a00:3e15:b0:730:7e1b:db16 with SMTP id
 d2e1a72fcca58-74eb493c8e2ls1442251b3a.1.-pod-prod-06-us; Thu, 10 Jul 2025
 14:31:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU5YwlwlmaK0NQ4lYkeM9MlMo5IJbguBlrubgGN5wmlxnFvUZLEUWOC9kMzV/oziRbguZfhrRPxFrs=@googlegroups.com
X-Received: by 2002:a05:6a00:391e:b0:748:311a:8aef with SMTP id d2e1a72fcca58-74ee284c6f9mr681198b3a.12.1752183091364;
        Thu, 10 Jul 2025 14:31:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752183091; cv=none;
        d=google.com; s=arc-20240605;
        b=N7wKAeu9HOie1988c/nHkqdkV11FmhrJwjEc0Ap7KgPJ1ZgbLy6aUR41ccBkcLb5Dp
         /RZ9gg4A/OIr/9vFU1y9k+2+fFUtsekdHErqZDLQOL5ov81JR2Xf2FPzPC4xE7/h2pMt
         TTvqsg/Pp4BZKHnLsjEawXmZOsVwS/6H0B3uFkL9kj01o97pLPGuBYTyPEw+c/K2CulT
         gAI+2lXRWvSUgPvn30wQl6yZGHslRpZoYZqSbwyJsoJCcDsh2CFJY2tZVT9uXPpi1s9O
         Hnx0ZU77Wl5jZZ85I1usW2okv5Ps1jwYCXQ9nnDnT6Jla/1gReH/96tinTpKvwBVmgYO
         DFlw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f7V0UXpqm2+kx37h0QSk+F+9RqgBVa4RJTJIm9NL4M8=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=iO1rl8p9q9g4z8kKreUEUrBB3E4I9NzaR95BBFES+yUfa5xqx7ytEx0aTqE5AM0wmP
         lQdzvYwrBPcdZwoeGa93zGBVpCwWiJkbR125QliLxCsReLeR+8MESfQbk0d2klc6ShMe
         kSkgWxfSOO+sOGCfzOYCcCn7bTJ4zv+wrxp5dv2yktrAMUnoReoQXro6Y4CuLHHsoifO
         yQnh1LWM/OIYWdU+9lnyPFmk3Kzfa6TE/XyDf9RgTsL0Mmvrxt2w/Y2hvnMe311GXuFJ
         KBDmqMqMbHtGtPTrOI3iuxOqE9Swvc+HbXB3mZ6K9MWwJNrTznmfhG8nQPXUgA0291Zn
         7Whg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CeSK1sDO;
       spf=pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-74eb9e220e7si94994b3a.1.2025.07.10.14.31.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 14:31:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 2AD28459BE;
	Thu, 10 Jul 2025 21:31:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7DFACC4CEF4;
	Thu, 10 Jul 2025 21:31:26 +0000 (UTC)
Date: Thu, 10 Jul 2025 23:31:24 +0200
From: "'Alejandro Colomar' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org, linux-hardening@vger.kernel.org
Cc: Alejandro Colomar <alx@kernel.org>, Kees Cook <kees@kernel.org>, 
	Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow <~hallyn/shadow@lists.sr.ht>, 
	linux-kernel@vger.kernel.org, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Andrew Clayton <andrew@digital-domain.net>, Rasmus Villemoes <linux@rasmusvillemoes.dk>, 
	Michal Hocko <mhocko@suse.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	Al Viro <viro@zeniv.linux.org.uk>, Martin Uecker <uecker@tugraz.at>, Sam James <sam@gentoo.org>, 
	Andrew Pinski <pinskia@gmail.com>
Subject: [RFC v5 7/7] mm: Use [v]sprintf_array() to avoid specifying the
 array size
Message-ID: <e53d87e684ef4aa940e71e679b6e75fd7cedac36.1752182685.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752182685.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752182685.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CeSK1sDO;       spf=pass
 (google.com: domain of alx@kernel.org designates 172.234.252.31 as permitted
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

Cc: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Marco Elver <elver@google.com>
Cc: Michal Hocko <mhocko@suse.com>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Al Viro <viro@zeniv.linux.org.uk>
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
index 783904d8c5ef..c4e588135aea 100644
--- a/mm/backing-dev.c
+++ b/mm/backing-dev.c
@@ -1090,7 +1090,7 @@ int bdi_register_va(struct backing_dev_info *bdi, const char *fmt, va_list args)
 	if (bdi->dev)	/* The driver needs to use separate queues per device */
 		return 0;
 
-	vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
+	vsprintf_array(bdi->dev_name, fmt, args);
 	dev = device_create(&bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
 	if (IS_ERR(dev))
 		return PTR_ERR(dev);
diff --git a/mm/cma.c b/mm/cma.c
index c04be488b099..61d97a387670 100644
--- a/mm/cma.c
+++ b/mm/cma.c
@@ -237,9 +237,9 @@ static int __init cma_new_area(const char *name, phys_addr_t size,
 	cma_area_count++;
 
 	if (name)
-		snprintf(cma->name, CMA_MAX_NAME, "%s", name);
+		sprintf_array(cma->name, "%s", name);
 	else
-		snprintf(cma->name, CMA_MAX_NAME,  "cma%d\n", cma_area_count);
+		sprintf_array(cma->name, "cma%d\n", cma_area_count);
 
 	cma->available_count = cma->count = size >> PAGE_SHIFT;
 	cma->order_per_bit = order_per_bit;
diff --git a/mm/cma_debug.c b/mm/cma_debug.c
index fdf899532ca0..751eae9f6364 100644
--- a/mm/cma_debug.c
+++ b/mm/cma_debug.c
@@ -186,7 +186,7 @@ static void cma_debugfs_add_one(struct cma *cma, struct dentry *root_dentry)
 	rangedir = debugfs_create_dir("ranges", tmp);
 	for (r = 0; r < cma->nranges; r++) {
 		cmr = &cma->ranges[r];
-		snprintf(rdirname, sizeof(rdirname), "%d", r);
+		sprintf_array(rdirname, "%d", r);
 		dir = debugfs_create_dir(rdirname, rangedir);
 		debugfs_create_file("base_pfn", 0444, dir,
 			    &cmr->base_pfn, &cma_debugfs_fops);
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 6a3cf7935c14..70acc8b3cbb8 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -4780,8 +4780,7 @@ void __init hugetlb_add_hstate(unsigned int order)
 	for (i = 0; i < MAX_NUMNODES; ++i)
 		INIT_LIST_HEAD(&h->hugepage_freelists[i]);
 	INIT_LIST_HEAD(&h->hugepage_activelist);
-	snprintf(h->name, HSTATE_NAME_LEN, "hugepages-%lukB",
-					huge_page_size(h)/SZ_1K);
+	sprintf_array(h->name, "hugepages-%lukB", huge_page_size(h)/SZ_1K);
 
 	parsed_hstate = h;
 }
diff --git a/mm/hugetlb_cgroup.c b/mm/hugetlb_cgroup.c
index 58e895f3899a..0953cea93759 100644
--- a/mm/hugetlb_cgroup.c
+++ b/mm/hugetlb_cgroup.c
@@ -822,7 +822,7 @@ hugetlb_cgroup_cfttypes_init(struct hstate *h, struct cftype *cft,
 	for (i = 0; i < tmpl_size; cft++, tmpl++, i++) {
 		*cft = *tmpl;
 		/* rebuild the name */
-		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.%s", buf, tmpl->name);
+		sprintf_array(cft->name, "%s.%s", buf, tmpl->name);
 		/* rebuild the private */
 		cft->private = MEMFILE_PRIVATE(idx, tmpl->private);
 		/* rebuild the file_offset */
diff --git a/mm/hugetlb_cma.c b/mm/hugetlb_cma.c
index e0f2d5c3a84c..bae82a97a43c 100644
--- a/mm/hugetlb_cma.c
+++ b/mm/hugetlb_cma.c
@@ -211,7 +211,7 @@ void __init hugetlb_cma_reserve(int order)
 
 		size = round_up(size, PAGE_SIZE << order);
 
-		snprintf(name, sizeof(name), "hugetlb%d", nid);
+		sprintf_array(name, "hugetlb%d", nid);
 		/*
 		 * Note that 'order per bit' is based on smallest size that
 		 * may be returned to CMA allocator in the case of
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8357e1a33699..3b40225e7873 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -486,8 +486,7 @@ static void print_memory_metadata(const void *addr)
 		char buffer[4 + (BITS_PER_LONG / 8) * 2];
 		char metadata[META_BYTES_PER_ROW];
 
-		snprintf(buffer, sizeof(buffer),
-				(i == 0) ? ">%px: " : " %px: ", row);
+		sprintf_array(buffer, (i == 0) ? ">%px: " : " %px: ", row);
 
 		/*
 		 * We should not pass a shadow pointer to generic
diff --git a/mm/memblock.c b/mm/memblock.c
index 0e9ebb8aa7fe..3eea7a177330 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -2021,7 +2021,7 @@ static void __init_memblock memblock_dump(struct memblock_type *type)
 		flags = rgn->flags;
 #ifdef CONFIG_NUMA
 		if (numa_valid_node(memblock_get_region_node(rgn)))
-			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
+			sprintf_array(nid_buf, " on node %d",
 				 memblock_get_region_node(rgn));
 #endif
 		pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n",
@@ -2379,7 +2379,7 @@ int reserve_mem_release_by_name(const char *name)
 
 	start = phys_to_virt(map->start);
 	end = start + map->size - 1;
-	snprintf(buf, sizeof(buf), "reserve_mem:%s", name);
+	sprintf_array(buf, "reserve_mem:%s", name);
 	free_reserved_area(start, end, 0, buf);
 	map->size = 0;
 
diff --git a/mm/percpu.c b/mm/percpu.c
index b35494c8ede2..a467102c2405 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3186,7 +3186,7 @@ int __init pcpu_page_first_chunk(size_t reserved_size, pcpu_fc_cpu_to_node_fn_t
 	int upa;
 	int nr_g0_units;
 
-	snprintf(psize_str, sizeof(psize_str), "%luK", PAGE_SIZE >> 10);
+	sprintf_array(psize_str, "%luK", PAGE_SIZE >> 10);
 
 	ai = pcpu_build_alloc_info(reserved_size, 0, PAGE_SIZE, NULL);
 	if (IS_ERR(ai))
diff --git a/mm/shrinker_debug.c b/mm/shrinker_debug.c
index 20eaee3e97f7..f529ac29557c 100644
--- a/mm/shrinker_debug.c
+++ b/mm/shrinker_debug.c
@@ -176,7 +176,7 @@ int shrinker_debugfs_add(struct shrinker *shrinker)
 		return id;
 	shrinker->debugfs_id = id;
 
-	snprintf(buf, sizeof(buf), "%s-%d", shrinker->name, id);
+	sprintf_array(buf, "%s-%d", shrinker->name, id);
 
 	/* create debugfs entry */
 	entry = debugfs_create_dir(buf, shrinker_debugfs_root);
diff --git a/mm/zswap.c b/mm/zswap.c
index 204fb59da33c..e66b5c5b1ecf 100644
--- a/mm/zswap.c
+++ b/mm/zswap.c
@@ -271,7 +271,7 @@ static struct zswap_pool *zswap_pool_create(char *type, char *compressor)
 		return NULL;
 
 	/* unique name for each pool specifically required by zsmalloc */
-	snprintf(name, 38, "zswap%x", atomic_inc_return(&zswap_pools_count));
+	sprintf_array(name, "zswap%x", atomic_inc_return(&zswap_pools_count));
 	pool->zpool = zpool_create_pool(type, name, gfp);
 	if (!pool->zpool) {
 		pr_err("%s zpool not available\n", type);
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e53d87e684ef4aa940e71e679b6e75fd7cedac36.1752182685.git.alx%40kernel.org.
