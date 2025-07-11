Return-Path: <kasan-dev+bncBAABBDO7YHBQMGQETD3VXAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 877E1B0110B
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 03:57:34 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6ff810877aasf36768966d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 18:57:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752199053; cv=pass;
        d=google.com; s=arc-20240605;
        b=Ng74OUwhMGtikhG4HK9qAihuqEVRl/BrwTC3SUF1kLqxAcIY2tZYUXtF/Dw0YeQ4E2
         5gubLaT8T/pb5pWWA2bIQrIQk+D0mYahvAPC1ZYpT1nFLY9xZ74nd1KgVmF+rgakCTAt
         FLK68YfF1OJtMFA+7tfqXygTyLDaultjE7D5q/7QV/QGBEMz9stxa9qbOUX1dsjwsmoM
         MxV7rVHYplYNMxWFSvzGmrSNN/tm5EzIkHnSDK+Wm9Liy3mIVGoB0GAS/I9BKMOljSTI
         nWoJtU26O45bvD2Vm80ePf3zhpRW8z3VqRI/0J6oq/mIkSI8Kw/QFJ/ijgYZn4Bc+7OJ
         X6KA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=C328h1iE+J7LK7tXC/dyynAK9u3ZQLOS7NJfr1Wne2I=;
        fh=MWQg/JoaHQsEuLJKW8r1Xgn+M29IR+Rd0YzLH1IpkDo=;
        b=h2EInHoTvRwL6mYkll7tLEBQH1YPdSxwV3udzvEMKiVZKmVKqhcMDQB2V10aT4alB8
         qHBt0FTdO3jWRoiMJpdziV/qTVzm1p2Up4mkxy4TWEgXaWlX7bRy+lvmODE+FvAGNVCL
         tO0GmRlDNllZ6jvTg6mGy318PLtfmhYE0znPYBb0kSq5IulReoZhkF6bXvpmXoc0cB5Z
         FjqKAgNcehT95+nWs8eDAUMRrKMVFF374THVB7IgC1DaFGGeYJSIyPDmXBIAHmTwKzJ8
         aHYT6HcoXc0T+WLzRYs0NnQrYF9GoA4KfhR5ldbJJ0pJqMP4kNNZTHRwQrAXE9gP1dHP
         2irA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AmQHu3Fm;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752199053; x=1752803853; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=C328h1iE+J7LK7tXC/dyynAK9u3ZQLOS7NJfr1Wne2I=;
        b=bg2+HZgCNtDTQUG0pcUMvF2J0GCRc2A/fBvAVTYQPmtvK+fbs295Ylem9OapmUjKaB
         7J0oH4zbFUVANQoBzq8uvac0osUEC8haeW4ZhVM1XUj0eouZy+oG4jgwBDK+XeA0ly/E
         EYMM5PPdtEQuGbcL/sawP3YPfaN5HebFXZma6IrI/5cDc3rbrBuR58zR8PXkPFkxKqGl
         SoFaqj1mhOA23AvBvIxqQjUpmZWTe9f56qZ0BKAqXfe22naw5/5pFybwJDZw0Ht1atMO
         yX5qoUYQgrliEvbjWNfYsQv1bdvD1FGP6QAVR25FO313bV2tZH9fREca0m5VxGNoTvJF
         8xYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752199053; x=1752803853;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=C328h1iE+J7LK7tXC/dyynAK9u3ZQLOS7NJfr1Wne2I=;
        b=WShVSRie5bcwHUNXkdS7lnLf5HIIr+fl48MiPtnkys/Laq3KqtODzwY7FRBHk+Fm0O
         8OLBDji8ab2oQzQ+fyWlZ8/8OgPotKyYAPHWbZUS4hzjYqJtIZ/hWE9XUK27UrDAECYy
         whhum/Ums8FXKOo4LWoCCzvjvGTa1cAPycTIHs2CTmA9MgyvzK66tlW8fKTvgwQ6d5u/
         9WI/EYdKo1W9UVa1T57uHqoq8p8TTP7e3dk1NJU19ZGiTFkMxfb42A0yi7DukdJetBNI
         hgru8Lb7Yx9cMif7uLVLN8H/oMXPwqy5eZ83wiwiqU0YsjkYfwmuKbL7RntDFUHAtpfZ
         NC5A==
X-Forwarded-Encrypted: i=2; AJvYcCVtF1fozBjMXkyTDnopTKfYMrhW8o/mkKIQdHZWlBGWoHV8oagHdi7J5mBzef+CoqJikaAQow==@lfdr.de
X-Gm-Message-State: AOJu0Yx8Pc1thdTTd3ROKfta8N4ApWxiB3NxNOiK0XOp3D6QW+C4m4EH
	yDIxmYT0y3xIXktSV0YX4NKIlf+9W+tJRHG3x6I7i34xe84hWvdveaWH
X-Google-Smtp-Source: AGHT+IHIX8vpZxJYUsdIzKQO5d9iY1mrEmyok4g+FMRSo+UQoZHY90ftsRenQ63uzA4YigjbMRjC7Q==
X-Received: by 2002:a05:6214:b62:b0:704:8920:d5c0 with SMTP id 6a1803df08f44-704a35f56edmr26269756d6.12.1752199053303;
        Thu, 10 Jul 2025 18:57:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeT7idGJRfcbp+3l64eax1R51jCmCNc5uLJoYA+loSpBg==
Received: by 2002:a05:6214:c4f:b0:6fb:4bc7:dc0d with SMTP id
 6a1803df08f44-704956ba0c3ls24753976d6.1.-pod-prod-06-us; Thu, 10 Jul 2025
 18:57:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnQpRaZzC0UTy76mAIZaMKfLfWTNVPzQVpBzpj8mN9Ajg72b39RkWd34GekJOjGd2l5zupXRvxj7Y=@googlegroups.com
X-Received: by 2002:a05:6214:f22:b0:704:7750:e2f1 with SMTP id 6a1803df08f44-704a353bdb7mr27046336d6.6.1752199052604;
        Thu, 10 Jul 2025 18:57:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752199052; cv=none;
        d=google.com; s=arc-20240605;
        b=hgnLCqeOjcDRLaq1BlSJbeqZJ1njIKY9IkniU4rY3v6AB2F5h08ImJg8vSZxG8y5IS
         L98rEz2L3LnB2uQd7oKpB80wiKb/HXhxWxZPZ+yKQSkeqYcGJMDTN0abKfSMwugOMA81
         aRoni+LCZtKzTOiNV7ejq01eoiqMdS92Rc838+0iYYnt8B2NlzyN2RZ4hNQ398BjEe7C
         bXFu2vekvbJ2rAygMMryLXZPtiRDKVq8SDCBN7EG5RaGdLqj1AeHS3mf9Rw8f1fqeAci
         7YGph+IUTV2iRFOK69Q7LO3kLlQIPNIGsdy9/zLsxcFXz1Y1oUq7VGTkjruw7JOGjhHy
         gviw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=f7V0UXpqm2+kx37h0QSk+F+9RqgBVa4RJTJIm9NL4M8=;
        fh=QOnzKEUq9WcvM0XNCrg2hWMbQW8+1K0P/8Aq77keZA4=;
        b=dUHJt8aAoN2KWl+F/AOEhmlS/YAXSlkvamknFdYgQWTzbMJo//qjF0KPLy7ohTqxmq
         g8e9THAL/+FT0SVZGyc0R/4EPSMxpIIYOJgYo0ZYTnZbitRhsUhEgSIm3SXrSe17CTES
         WQxUBBISRtxmncPVrsWSZOAL1Vqgg3u3/IzBKTzRCZ/fssUsVZE++Zj3qCoriUv0NbH9
         SlZnUlWVFmCX/G/LK0L5aL+F+zU+7LgDlhr0+98MSZQWNMjuQdUhLWnhyxcRaNRgvm/b
         NDWIYUJzpPYv0wFVAXFK1MjqdrnD11w9oI3v+wk61v9dvzdS4Wp3XoabrnJMmd6rdozp
         or2w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=AmQHu3Fm;
       spf=pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=alx@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70497d7fa21si1329946d6.6.2025.07.10.18.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 18:57:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 133855C6F23;
	Fri, 11 Jul 2025 01:57:32 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3A25DC4CEE3;
	Fri, 11 Jul 2025 01:57:27 +0000 (UTC)
Date: Fri, 11 Jul 2025 03:57:25 +0200
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
Subject: [RFC v6 8/8] mm: Use [v]sprintf_array() to avoid specifying the
 array size
Message-ID: <aa6323cbea649950487ea4c0518a4b8d2e0aa68f.1752193588.git.alx@kernel.org>
X-Mailer: git-send-email 2.50.0
References: <cover.1751823326.git.alx@kernel.org>
 <cover.1752193588.git.alx@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <cover.1752193588.git.alx@kernel.org>
X-Original-Sender: alx@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=AmQHu3Fm;       spf=pass
 (google.com: domain of alx@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=alx@kernel.org;       dmarc=pass
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aa6323cbea649950487ea4c0518a4b8d2e0aa68f.1752193588.git.alx%40kernel.org.
