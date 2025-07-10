Return-Path: <kasan-dev+bncBAABBKOUXTBQMGQEW3UNALQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EFE0AFF70F
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 04:49:15 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id ca18e2360f4ac-86f4f032308sf108910339f.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jul 2025 19:49:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752115753; cv=pass;
        d=google.com; s=arc-20240605;
        b=lAC/Vbx11iDFiRLRkYTT9H6PaO5Bj5gI3ekm4Sq/34aimtwRNOdwWtDLRSxtRWMr6X
         EWcLDvXUIHqsIwwUu3GY/bFf3cPPJlmyKgocs0SuC75PeyXxqxNu7i53cZijGjDH7oZB
         f6JP6ycMtm76OxrJwgGpzrWVCPzoaWJgHsC6Dodjc7o4veCrMNVL03xyrT1xWzjd5Neg
         xIeRKjcVh6LaZfH1WHMZirWWA7VzFtLBhAfeXvtdAejYi2XaVoPsS2TMYDrmQ9IPNEAn
         r84RCeA8WoS145MOK7K52YgM3pMnrqO+l2mkiORcRj+iQcuawrmXc4VQ1psK6ZavP6/p
         YfBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=7WpCVF+Tm1M7xh1AfB7McgjGXaD2JYauq1c+FBBZ0xQ=;
        fh=T/p5riNGAV8ZMGYJBtevfAUPLIjGErt5pEYU0RXy7U4=;
        b=YZTD/U4HJEos2SoEZ53r4RQHO86HNZBFOhsujc7lClDpeZpsTKz8QBDqsDnSaYQuh9
         qoL6tKGFIsObc7iB8kGYJj7EehG4ghtWYlfr0gcR3mWNQMiovJKO5SYxJ68sJ3BxbKJA
         J6RhLEsEcIPRQxvoo7l1b47iC4lpF+cmBMEtw6PMK20149OMo+4q6kqtIIOMCm9rntOz
         Vizb1Gu/qQZ4BV7y4T6fg3/UWADEWVBhglBRmx3Vc0jHoSbMXxXAG+9YGVs2hNZrhMWK
         KC27AMSa8zEm9F52jn0P7Ct2a0UTMz5w045aChCOYz2H//1ahD+OgIAlmXca7kJ2jR2y
         DNmg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Rtj1GYIu;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752115753; x=1752720553; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=7WpCVF+Tm1M7xh1AfB7McgjGXaD2JYauq1c+FBBZ0xQ=;
        b=fDJ46F7IQBexayLtr8yCskv/s3J+emmieAnTr91/mnjS3kanE4pcn6rj666tAS2hna
         Squ/2Tg8V5kiKaUGWDqR53qtjwwptuXg8XF0vdJfF1uXbg6Xt/BVhu4xHLdjxT4SyWgj
         LccaCOmJdN9TOajb4NzKwVxyPMrS6TnTNuFaVK5ZRcFuNHKMQTG6XJXsUdim0pkn9phB
         9NOqCTRpYPmnzcysukxNomVkQhWdAKeDRYStt61CdSeprcDI/opZyJTvcxUkktw9RuvV
         8laWrNGQOZwNjuQ6rxY/HQ8rI/tfOf6OJ0/TRPA9jvLvuWLtraOvk7P2w6DxIX636xAC
         wVxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752115753; x=1752720553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7WpCVF+Tm1M7xh1AfB7McgjGXaD2JYauq1c+FBBZ0xQ=;
        b=le3MGnTch04IW7dG8B/HSsjLgkn8/qKphB3ul35NHKTviUDm8sGXLeybhGC2nxMG/9
         QjWkbepoqxzQ+6gJ3v978Gzcs4exffsYBEVUyXpMJXVJzLB7ib/7Nd6H9csfdFkS2tXq
         WnOL0ESKYJ5XhQsdgEmJuHXzjBr/0fdqEIkOl6PdoFwo8LA38iHu4DMfFEWdIxGiBBIZ
         cBnOiyxdVYoBgD/alTboW/hEX14W7rH23dTJDczF0Rc5T4m4UMCYwDUA/c/7rjuAaoZU
         IMbW5lF4xg5IZ3+PbjdpBi+mua2Tlfj4gylEikSI72xvOvXUQ1M2Tk5+VSsn4FnITP19
         jdjQ==
X-Forwarded-Encrypted: i=2; AJvYcCVUrhRAthyjmWzCAdPIVPttSgD2SGt0zc3wlt14LtYbK9PDddJSt8NkM/B6Eb0j2OKUkpvxGg==@lfdr.de
X-Gm-Message-State: AOJu0Yx6VGHPWCJenWMdmHjW2/zsEBxrC7BsUGvT58oEvCuoCxNt06d0
	BF4VFt8N6ELl/JZ9GTq+RlarJ01VmA09vuFMJSgCfxugoAQygJFCgMe9
X-Google-Smtp-Source: AGHT+IEXv4mkOJvIhR5IULCft5PlmkWkpJF0tqfNtbtVYxcVxYNFfbFumdyVSZz2/47I+WJH5hZrTw==
X-Received: by 2002:a05:6e02:258e:b0:3df:2f9e:3db4 with SMTP id e9e14a558f8ab-3e1670ac614mr47762795ab.13.1752115753421;
        Wed, 09 Jul 2025 19:49:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcYwd2NLe2H7VMmdPZKw5lkhMXgxeC0GBR0/A6s1f2jrQ==
Received: by 2002:a05:6e02:4602:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e2440f6fbels4664825ab.2.-pod-prod-02-us; Wed, 09 Jul 2025
 19:49:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWv3ktvYkoNJ0+sBCLgGkshk72Wpr24AnK6rYGgwCgc4jEHc2I0W4HLHyYfQDN3P/zZJxAUDwgFg8I=@googlegroups.com
X-Received: by 2002:a05:6602:29a9:b0:86d:f35:a100 with SMTP id ca18e2360f4ac-8795b0b2b4emr638923339f.5.1752115752493;
        Wed, 09 Jul 2025 19:49:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752115752; cv=none;
        d=google.com; s=arc-20240605;
        b=Mjo6eej7+LqaE7GZ/j7tovqf1IbqNgzSazio0p8LSeBit1ykYejLuRDH+vPxuV503J
         8GnSf9oV9iQ8f5X/UXIb9q/c1JLH0R1ec9T7R94wX+IMn7kvkBIcuQSXJwt5qjBmuSgP
         r53hZkWeyE8uUTxnXuN7aD1gxJvoAwUWnxioSNcmd8BkMS5RbY05J/a9oEaaMCiK9RJR
         TNnzE3JzosoPJj9Xv/DqpQdig4igVUSAqHtbSXAZzRmwI4BnDaaLlNpc1h3ggiDOoXKK
         BnFXXuDEzBrDswemooXbY6OBU6aodjVsb2Vrx9LtN5iYXu5kGBy/TB++o5AnbwTGhWty
         lKRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=rGub8rjx+mnwzeSATZsYngbxCItCiY7i6tQqrFSacj0=;
        fh=n7kMCQJrry/6/0/v2g7rS6NiIhn1Yg+3PC4f8tlptsI=;
        b=C/CPRh35tgJMvLwXkyE/o6tnNKX7gS0pitKpwyJf39PMwkobTW6ZMvBYo4gZTHQDEu
         J/nvo2aKGboHmGG8TJAqHGo7JrGJMgXUBPGLhfa85cEF9Pmz3ebsyC20HqTjqJFqVp+U
         2/bqKHhSL5pigU9Rla6IXA9Wu3GihE2IpnqgPCoR1aWNrRvosUfk0IKtMFH8520+bLXX
         9q6B4S/cAEzRJGZLk3rzCaQapAFBz646X1iFX6sPT+mFs2lY+n1U4Cr0z3IVIHh7XEXl
         Whqi4wPehorjQZzRKsGSvmE/Xo00RxY5wZUxeuY3bsqKl/bnFbGjcsvocKJNngXiXhon
         dejw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Rtj1GYIu;
       spf=pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8796ba9c146si1837339f.2.2025.07.09.19.49.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Jul 2025 19:49:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E145D61139;
	Thu, 10 Jul 2025 02:49:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C1F95C4AF09;
	Thu, 10 Jul 2025 02:49:05 +0000 (UTC)
Date: Thu, 10 Jul 2025 04:49:03 +0200
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
	Al Viro <viro@zeniv.linux.org.uk>
Subject: [RFC v4 7/7] mm: Use [V]SPRINTF_END() to avoid specifying the array
 size
Message-ID: <f99632f42eee7203424488b42e0eff2bd25b0ea0.1752113247.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752113247.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752113247.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Rtj1GYIu;       spf=pass
 (google.com: domain of alx@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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
index 783904d8c5ef..20a75fd9f205 100644
--- a/mm/backing-dev.c
+++ b/mm/backing-dev.c
@@ -1090,7 +1090,7 @@ int bdi_register_va(struct backing_dev_info *bdi, const char *fmt, va_list args)
 	if (bdi->dev)	/* The driver needs to use separate queues per device */
 		return 0;
 
-	vsnprintf(bdi->dev_name, sizeof(bdi->dev_name), fmt, args);
+	VSPRINTF_END(bdi->dev_name, fmt, args);
 	dev = device_create(&bdi_class, NULL, MKDEV(0, 0), bdi, bdi->dev_name);
 	if (IS_ERR(dev))
 		return PTR_ERR(dev);
diff --git a/mm/cma.c b/mm/cma.c
index c04be488b099..05f8f036b811 100644
--- a/mm/cma.c
+++ b/mm/cma.c
@@ -237,9 +237,9 @@ static int __init cma_new_area(const char *name, phys_addr_t size,
 	cma_area_count++;
 
 	if (name)
-		snprintf(cma->name, CMA_MAX_NAME, "%s", name);
+		SPRINTF_END(cma->name, "%s", name);
 	else
-		snprintf(cma->name, CMA_MAX_NAME,  "cma%d\n", cma_area_count);
+		SPRINTF_END(cma->name, "cma%d\n", cma_area_count);
 
 	cma->available_count = cma->count = size >> PAGE_SHIFT;
 	cma->order_per_bit = order_per_bit;
diff --git a/mm/cma_debug.c b/mm/cma_debug.c
index fdf899532ca0..6df439b400c1 100644
--- a/mm/cma_debug.c
+++ b/mm/cma_debug.c
@@ -186,7 +186,7 @@ static void cma_debugfs_add_one(struct cma *cma, struct dentry *root_dentry)
 	rangedir = debugfs_create_dir("ranges", tmp);
 	for (r = 0; r < cma->nranges; r++) {
 		cmr = &cma->ranges[r];
-		snprintf(rdirname, sizeof(rdirname), "%d", r);
+		SPRINTF_END(rdirname, "%d", r);
 		dir = debugfs_create_dir(rdirname, rangedir);
 		debugfs_create_file("base_pfn", 0444, dir,
 			    &cmr->base_pfn, &cma_debugfs_fops);
diff --git a/mm/hugetlb.c b/mm/hugetlb.c
index 6a3cf7935c14..2e6aa3efafb2 100644
--- a/mm/hugetlb.c
+++ b/mm/hugetlb.c
@@ -4780,8 +4780,7 @@ void __init hugetlb_add_hstate(unsigned int order)
 	for (i = 0; i < MAX_NUMNODES; ++i)
 		INIT_LIST_HEAD(&h->hugepage_freelists[i]);
 	INIT_LIST_HEAD(&h->hugepage_activelist);
-	snprintf(h->name, HSTATE_NAME_LEN, "hugepages-%lukB",
-					huge_page_size(h)/SZ_1K);
+	SPRINTF_END(h->name, "hugepages-%lukB", huge_page_size(h)/SZ_1K);
 
 	parsed_hstate = h;
 }
diff --git a/mm/hugetlb_cgroup.c b/mm/hugetlb_cgroup.c
index 58e895f3899a..4b5330ff9cef 100644
--- a/mm/hugetlb_cgroup.c
+++ b/mm/hugetlb_cgroup.c
@@ -822,7 +822,7 @@ hugetlb_cgroup_cfttypes_init(struct hstate *h, struct cftype *cft,
 	for (i = 0; i < tmpl_size; cft++, tmpl++, i++) {
 		*cft = *tmpl;
 		/* rebuild the name */
-		snprintf(cft->name, MAX_CFTYPE_NAME, "%s.%s", buf, tmpl->name);
+		SPRINTF_END(cft->name, "%s.%s", buf, tmpl->name);
 		/* rebuild the private */
 		cft->private = MEMFILE_PRIVATE(idx, tmpl->private);
 		/* rebuild the file_offset */
diff --git a/mm/hugetlb_cma.c b/mm/hugetlb_cma.c
index e0f2d5c3a84c..6bccad5b4216 100644
--- a/mm/hugetlb_cma.c
+++ b/mm/hugetlb_cma.c
@@ -211,7 +211,7 @@ void __init hugetlb_cma_reserve(int order)
 
 		size = round_up(size, PAGE_SIZE << order);
 
-		snprintf(name, sizeof(name), "hugetlb%d", nid);
+		SPRINTF_END(name, "hugetlb%d", nid);
 		/*
 		 * Note that 'order per bit' is based on smallest size that
 		 * may be returned to CMA allocator in the case of
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 8357e1a33699..c2c9bef78edf 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -486,8 +486,7 @@ static void print_memory_metadata(const void *addr)
 		char buffer[4 + (BITS_PER_LONG / 8) * 2];
 		char metadata[META_BYTES_PER_ROW];
 
-		snprintf(buffer, sizeof(buffer),
-				(i == 0) ? ">%px: " : " %px: ", row);
+		SPRINTF_END(buffer, (i == 0) ? ">%px: " : " %px: ", row);
 
 		/*
 		 * We should not pass a shadow pointer to generic
diff --git a/mm/memblock.c b/mm/memblock.c
index 0e9ebb8aa7fe..6bb21aacb15d 100644
--- a/mm/memblock.c
+++ b/mm/memblock.c
@@ -2021,7 +2021,7 @@ static void __init_memblock memblock_dump(struct memblock_type *type)
 		flags = rgn->flags;
 #ifdef CONFIG_NUMA
 		if (numa_valid_node(memblock_get_region_node(rgn)))
-			snprintf(nid_buf, sizeof(nid_buf), " on node %d",
+			SPRINTF_END(nid_buf, " on node %d",
 				 memblock_get_region_node(rgn));
 #endif
 		pr_info(" %s[%#x]\t[%pa-%pa], %pa bytes%s flags: %#x\n",
@@ -2379,7 +2379,7 @@ int reserve_mem_release_by_name(const char *name)
 
 	start = phys_to_virt(map->start);
 	end = start + map->size - 1;
-	snprintf(buf, sizeof(buf), "reserve_mem:%s", name);
+	SPRINTF_END(buf, "reserve_mem:%s", name);
 	free_reserved_area(start, end, 0, buf);
 	map->size = 0;
 
diff --git a/mm/percpu.c b/mm/percpu.c
index b35494c8ede2..efe5d1517a96 100644
--- a/mm/percpu.c
+++ b/mm/percpu.c
@@ -3186,7 +3186,7 @@ int __init pcpu_page_first_chunk(size_t reserved_size, pcpu_fc_cpu_to_node_fn_t
 	int upa;
 	int nr_g0_units;
 
-	snprintf(psize_str, sizeof(psize_str), "%luK", PAGE_SIZE >> 10);
+	SPRINTF_END(psize_str, "%luK", PAGE_SIZE >> 10);
 
 	ai = pcpu_build_alloc_info(reserved_size, 0, PAGE_SIZE, NULL);
 	if (IS_ERR(ai))
diff --git a/mm/shrinker_debug.c b/mm/shrinker_debug.c
index 20eaee3e97f7..9a6e959882c6 100644
--- a/mm/shrinker_debug.c
+++ b/mm/shrinker_debug.c
@@ -176,7 +176,7 @@ int shrinker_debugfs_add(struct shrinker *shrinker)
 		return id;
 	shrinker->debugfs_id = id;
 
-	snprintf(buf, sizeof(buf), "%s-%d", shrinker->name, id);
+	SPRINTF_END(buf, "%s-%d", shrinker->name, id);
 
 	/* create debugfs entry */
 	entry = debugfs_create_dir(buf, shrinker_debugfs_root);
diff --git a/mm/zswap.c b/mm/zswap.c
index 204fb59da33c..7a8041f84e18 100644
--- a/mm/zswap.c
+++ b/mm/zswap.c
@@ -271,7 +271,7 @@ static struct zswap_pool *zswap_pool_create(char *type, char *compressor)
 		return NULL;
 
 	/* unique name for each pool specifically required by zsmalloc */
-	snprintf(name, 38, "zswap%x", atomic_inc_return(&zswap_pools_count));
+	SPRINTF_END(name, "zswap%x", atomic_inc_return(&zswap_pools_count));
 	pool->zpool = zpool_create_pool(type, name, gfp);
 	if (!pool->zpool) {
 		pr_err("%s zpool not available\n", type);
-- 
2.50.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f99632f42eee7203424488b42e0eff2bd25b0ea0.1752113247.git.alx%40kernel.org.
