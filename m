Return-Path: <kasan-dev+bncBAABBX6UXOHQMGQEPF5GASY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C9084987B6
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:05:20 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id l18-20020a1709063d3200b006a93f7d4941sf2425829ejf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:05:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047520; cv=pass;
        d=google.com; s=arc-20160816;
        b=BWwFfmerqeTVBJ/wI1cy5iFSMXT+ElWOxNOmxks5PqZ/YrKYfvr3GyENz3xDPL+y4m
         kNdR60eYF2IuvUhF95SjQ2E6oqNyoQmQ8GqjBTuManMq+FttzKl46GH31HehGqbeT2nb
         g7O9+6TsVs98v6ZlPcNGVwf7La3z9xvYh4Dwu8leg/dC2UjiQqKFch5i3EXa52nYMUFf
         mpRZFq6UMkKZdla2zAT4TIJrCe4ueIn2QD4CaYnFBl75mGuonMGjqgST5E8ykzV00w52
         YZjACMFAx2/rX5IFXTPBFH9oi5nek+97XfJ+RhtguBBDJOiZQE5pzGxXxXqfnwS8rFY8
         p7cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=kzi/m4XvM3hk/keY8jF9Iqu+1LenQGf61qMGwF0tc3E=;
        b=HN2eD4jzbsm1HJf5St/ezQbbrMp/asRqZLJ5TJR01Be+aUvZOAfnSNoDqf6fQ2QFxQ
         jXTURtKOzSsTWzIgA+1gPswuHG7uiOfpuarSolq5aecQSOS5ia+Iy6XAXSlyTJpWcjDY
         wXljojI9uzC3ffgCpkEXESz4YmDCcsJxTnVxSOu9aUVNQeH8qo3hN/sUI11pM1qzYXjM
         du9UWMAGWk+YYK4VMWni+ubfuezjP59oyyyTN23esUrInI/+1vhV0mRC4akAdWJZwIql
         uquJSg7clqb+AbHGdOAtV9yNfHmv18Pj48BDDK9YWIu4eXDizHEvLJa4B8ynoivbsv9s
         +1Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=X22x6Nk7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kzi/m4XvM3hk/keY8jF9Iqu+1LenQGf61qMGwF0tc3E=;
        b=sTSeVxGe/qyzHZ+Ykk3vlyBnf36qfXIi9kJfT9ejc5o2zk7BIL1Mkd4a6R/khdso1/
         f2AC02j9c3rxQX8tJ7EiPETd7FzLE96ryKC/8w8abs+aZsBgRszfjuNfexD94zBKf0/L
         FiK3aWFUU0ILjxVFFFRtwHq08/OVok+JntnksPOQhmGVkE9V2r9Nbn3DgQb0/R1EmkX8
         /TAnVpUWYPJZJPZXT0OvekiiCQuqy9GvvmxA7BioIcyl3g3Tb1/JD2wuEfkoqdJGymZ/
         wp4eEhJPHPiFQAtROwc/Yokc4tKBtVSlO/4rAbE6aaV3Fr2MFG2qOwSRS+zK2brm+GKd
         c6Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kzi/m4XvM3hk/keY8jF9Iqu+1LenQGf61qMGwF0tc3E=;
        b=6QmdPkf/ytVIYcByC3ztfMDOFgowskXHvRJVoNkYl7Ncd5VZfi9SBUpUmApfpC2Sc7
         Zc0e5HsnwBEmC6vPHtUB+eLzrj+QMj0ZJSP6fL4Rqv8OOWkQI543UJD8qaujNtIuRVmK
         XBE1a6LnMlSmB/z9WMSlSwQcs6R80XMGo1chXI7pygcNFQtQILk2iGgbzP67ifDkLgAb
         2+MPS85d4FSPT/YtZQJAfym+nn9stPQehKS52b4/r5QKlNMQs4Sr3U86ccokJUrhByaa
         Lh25g0FhY3EYQkjWjrgKt2FF+GBxjjC8FNXIq0FZjEtFlJfHdtgclafI8oY3zzTCvYsi
         yn3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5309KamfBq9kAyEqBJvE0z3XdkuWsFhUr4XFk7pcw55yK2q8DR0/
	SIf9gW5mV0+TFqbG2SuaLdY=
X-Google-Smtp-Source: ABdhPJzaayFz5nizpMNNqZw3YSAeJdA+uL0IizFltgV7Hh/RnN9k/sPgbHTpLdqlF3cAEF5hdlxFfA==
X-Received: by 2002:a05:6402:27ce:: with SMTP id c14mr16940830ede.246.1643047520210;
        Mon, 24 Jan 2022 10:05:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1b15:: with SMTP id mp21ls6542414ejc.11.gmail; Mon,
 24 Jan 2022 10:05:19 -0800 (PST)
X-Received: by 2002:a17:906:af8b:: with SMTP id mj11mr13681740ejb.66.1643047519430;
        Mon, 24 Jan 2022 10:05:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047519; cv=none;
        d=google.com; s=arc-20160816;
        b=0of+nR4U2pvkInNysOP0C45DJqbozY12JzKRmOTwmCDkn2thDEizd+5FlrtlnCIAHK
         FVfE3oUyfyKJx7/1US2Vjqj+kPU30k7xctrrm2qSkiXv0mc6BK+qemgx+jwrYjtJPSo4
         0bRSXKUPDFTZBThspj60ckiKbRbyGKtw3N8oxO74CEmdS3J68pZcyUmB7To3mWTN2J+9
         HtiXyvp4puq2zyWtWGw63uXi/m+0yZ9ZBuf+IQ8gac7IJY0Q82rry+tcdVD7zlfL1MmV
         p1F0YTesPeoC29dj9dl5PpamlQZ/2qkfl8tcif7t4cWcFoyA939OszIz6Sh2QMCy4S+O
         P02g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/N3qdDIkK02IcRD/4YwZog5TYpzf/9zqE2SCjAPJ/fo=;
        b=BIWRvhXCqtOjvY5C6msazkLC1uONfb/GRLtQDtXxE98/31v2VJ0ndj6C9b5N3K57zG
         GOPPRGEUG+R8jvLN8pupKfxod55o5+G7SUUJz6ymmhc5h2IIzxHhWxS65NEH6lhJ1UNq
         oKJCsi74E9bAlq0OWVlqc1WAExNK3iy6wVRz17y2K/K3cuuRWT9TeCQ0j/p+bAtT6FQP
         MVAehkZmABaB8bCGqNChzGcUrZfr8yUMr6qcvQYsaM9t0yhY1GA5cKobj5NTzvtdqDcg
         +v6e80fUAnaYI1g0qiRwJMmSi5cD9US5lQ/j4pB3vddVJEmux7/u4MuTCTWWgtej+bNd
         35AQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=X22x6Nk7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id s15si707665eji.1.2022.01.24.10.05.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:05:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 21/39] kasan, vmalloc: reset tags in vmalloc functions
Date: Mon, 24 Jan 2022 19:04:55 +0100
Message-Id: <046003c5f683cacb0ba18e1079e9688bb3dca943.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=X22x6Nk7;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

In preparation for adding vmalloc support to SW/HW_TAGS KASAN,
reset pointer tags in functions that use pointer values in
range checks.

vread() is a special case here. Despite the untagging of the addr
pointer in its prologue, the accesses performed by vread() are checked.

Instead of accessing the virtual mappings though addr directly, vread()
recovers the physical address via page_address(vmalloc_to_page()) and
acceses that. And as page_address() recovers the pointer tag, the
accesses get checked.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Clarified the description of untagging in vread().
---
 mm/vmalloc.c | 12 +++++++++---
 1 file changed, 9 insertions(+), 3 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index b6712a25c996..38bf3b418b81 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -74,7 +74,7 @@ static const bool vmap_allow_huge = false;
 
 bool is_vmalloc_addr(const void *x)
 {
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 
 	return addr >= VMALLOC_START && addr < VMALLOC_END;
 }
@@ -632,7 +632,7 @@ int is_vmalloc_or_module_addr(const void *x)
 	 * just put it in the vmalloc space.
 	 */
 #if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 	if (addr >= MODULES_VADDR && addr < MODULES_END)
 		return 1;
 #endif
@@ -806,6 +806,8 @@ static struct vmap_area *find_vmap_area_exceed_addr(unsigned long addr)
 	struct vmap_area *va = NULL;
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *tmp;
 
@@ -827,6 +829,8 @@ static struct vmap_area *__find_vmap_area(unsigned long addr)
 {
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *va;
 
@@ -2145,7 +2149,7 @@ EXPORT_SYMBOL_GPL(vm_unmap_aliases);
 void vm_unmap_ram(const void *mem, unsigned int count)
 {
 	unsigned long size = (unsigned long)count << PAGE_SHIFT;
-	unsigned long addr = (unsigned long)mem;
+	unsigned long addr = (unsigned long)kasan_reset_tag(mem);
 	struct vmap_area *va;
 
 	might_sleep();
@@ -3404,6 +3408,8 @@ long vread(char *buf, char *addr, unsigned long count)
 	unsigned long buflen = count;
 	unsigned long n;
 
+	addr = kasan_reset_tag(addr);
+
 	/* Don't allow overflow */
 	if ((unsigned long) addr + count < count)
 		count = -(unsigned long) addr;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/046003c5f683cacb0ba18e1079e9688bb3dca943.1643047180.git.andreyknvl%40google.com.
