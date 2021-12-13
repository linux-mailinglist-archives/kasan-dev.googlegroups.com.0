Return-Path: <kasan-dev+bncBAABB7EB36GQMGQEQQTM2CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BCA84736E4
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:04 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id j193-20020a1c23ca000000b003306ae8bfb7sf10282703wmj.7
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432444; cv=pass;
        d=google.com; s=arc-20160816;
        b=jmL1o6ZwZ6p4OSm8qwYEJ/wlST5N24Fzzwv1KSSydWT23x+nD/otaa7QsnOn3i57Tn
         yJyoHXu8NmonWpIOJkra/o8M5+JwmaV+O61ujjLAn460EabMxVK2hWG80erK46pM1cEC
         oqbrowkW9oe2ACPf+vMXFuVlfoZ9nCmiThjSxwgf9CgdEH9NP+wjRy5PkfIQpU6FCA+S
         6vEOzFWZwEQhj1qPD/1frLj9A6z1zaJGJsv8aANYgbnWxooRct/VH9A4oPsdQa60ky3/
         oNSWTi3fHKBLICgxuyjE9V21g12EyjNqDrOeQHisKR7HMRHcwr5DAPjtijoygEqABRAZ
         nB7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rvylFKhqUhn0GzNJHcnWyv9TCDMXePmz3t3PvWIZX0I=;
        b=T5/VOnCACelZPYjdBe3bjyyUZa5xC4Hzmem66Jv+1K+ROLd6senCWEVFML69M7kjMn
         SYRtxI9vq2BF1QMyh6E9syKQB3+CwWiYeeZPoV3qzw9Hr3x4Xo72bJ+EiyDrPfIH6WdA
         hxuA4YaZbHgM/yKK56zcDh5RoA5uFEAElkZTsZRyTlhyFwGcpETtCY8PFofFmNRjPowv
         45rEUH163iO0V3Q4WNydLS3RDThMiEPSUAyF3S7kt3bYfBYLvoUMQZDgq+3faon3mac6
         DcEXJd3c/oPTXzrKvsuUkyQwbFAIVtSmJdaxQChhxdSsNN0GQB4gcUh2W8NWhprLuQNd
         TCrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qtKtE2km;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rvylFKhqUhn0GzNJHcnWyv9TCDMXePmz3t3PvWIZX0I=;
        b=rcyhySwbBlSokHJ0+8Nauiv9eQI+4w+LfSsYuAxQe2Gv3/3t06tnEdeGKqG+sYDP+I
         5wGjLomIcO2iK2IOcZm4yHfJFKuilcSTg3lsn7cYeCV1w4HNnjQClMXWCrc1kxk51LY3
         iSJBl2/OFw2iksLMukMGtiR9+7wF0IKwn8HgaISiEp8EgAhI7NNBfGs7H3W4Cg7tGIy0
         /KNwgEUlTFPstMnHJmQq/3R/2B+TaykszAqAxUs7/+r95oWxVYrbA83sT0+jXlAUg1w2
         6L8UgsVzmpj9f5U6lZLHlmVNFAg8O+MpqQGJHblATv+99RW0cg0iFzHafXBjl+BHGxLT
         GMlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rvylFKhqUhn0GzNJHcnWyv9TCDMXePmz3t3PvWIZX0I=;
        b=DPUDVEXFsrMmczEFHZtGy/1p4Pz41Z/JckrOQFWtAMd1fTRxweQDIcS/Sp3wXmRdp+
         LEVW5bbmbpCOjnvbDjYJJD9A4SM2Py49yy9noRppuQCM6VhycNlV4gkHEHuzCp79u5sG
         Ydq5v3LjngtHbj5Vw3KuR5fz2/kReLoHG+anx0/DkrEdF3eOQnZD9JOLKV6jUb1vFSYq
         mbJ4mln/9J5ty3dZMjhTXWh6dO0XxSvbt641gL3u8T4mDs9CfxYuguw1Hzuhjzkdkj/E
         yDe0LovIAV9QI2udeC8nro1MzcL21Ie6l7+lZ5fs5R6LnzRq0p4UJG6NqEX0mRoLHY4H
         uQUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532JHgUfS3yYLsROJdHFBJFCYM3S837C5xEIXRXIZOLvghvN+LtJ
	/JWaibzL7+GEFtf/Ob3EDYU=
X-Google-Smtp-Source: ABdhPJxTzYztz8JVWadyoRQhN/IYhniRGdJSlJbExyV7StpqDxfeGfaSouTiRWqBrnzigDKnOMdi3Q==
X-Received: by 2002:a7b:cf10:: with SMTP id l16mr41306993wmg.17.1639432444201;
        Mon, 13 Dec 2021 13:54:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls500045wrp.1.gmail; Mon, 13 Dec
 2021 13:54:03 -0800 (PST)
X-Received: by 2002:adf:ce03:: with SMTP id p3mr1258608wrn.145.1639432443543;
        Mon, 13 Dec 2021 13:54:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432443; cv=none;
        d=google.com; s=arc-20160816;
        b=HGFjxQK7w0d/ex8+cXll/pYwGwhJYu0T7jos1F/v3MCy64cJbbaH0E26c2yqEwM8Qc
         7IwUhEZaWnvbZAMu9n9R+/an3yX60ZbqXIIvnpXEzbg4zcAleQeJio+CBy4nLeh3QpJ5
         fOVLFjHhfPHr2P39hlejioFnhMIeGkfJYLsUFZ/9IryRVSo/+K4LESpytRs6z4EfkmCU
         FHoapQSfUrIVHVpkQ198BBe9sqgyPvsirmz8g0oj5KHUo8hZIelrMdrT2BLvPMUXFL58
         5aiv0nauptUE0rvleCxO0vcdVLLDbnEozv2ZRcnpoxSqU/oI+TmgzbUZvvvKTWQ/stda
         YTfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=td/TtoF7cXxMeVx908agEEKdFK6FpXlk5RKSWg4HTMg=;
        b=lKfFtAtfQWKUOAlz00b1/RlINBumWRJ+diydzIlbGhUyqVToYrqOQ6PrkTMAweL03+
         XvqEbRjb1dKn5a/zTpsCYsYw0YBXRogLkXphmKUPpTSj1uGUUMYMWqcpby5mS2Fg9EwZ
         zKsU6GpkDMp0gfKt+2cWigkPHlZJetcR6RaVX13n6+rYGnBxbb0SmX0TXISyTDf3/Amh
         XBgAWmsinJg6aaPIgFp8g//TkMhTN4j6dMbfPInxdGCE5tqRpnM/LLUwR2chKxZRWn7X
         2r38KStPkS/TNVCs77AEv8gZZQyhrgnLeox+XmkWfNw+g8kxxkM8JxGfJnPBBZiWfwHv
         h79w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=qtKtE2km;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id r6si662667wrj.2.2021.12.13.13.54.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v3 21/38] kasan, vmalloc: reset tags in vmalloc functions
Date: Mon, 13 Dec 2021 22:53:11 +0100
Message-Id: <e908da1b8224665f987347b58cf3c8bf1d73d0db.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=qtKtE2km;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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
index a6b61e24a703..42406c53e2a5 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -72,7 +72,7 @@ static const bool vmap_allow_huge = false;
 
 bool is_vmalloc_addr(const void *x)
 {
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 
 	return addr >= VMALLOC_START && addr < VMALLOC_END;
 }
@@ -630,7 +630,7 @@ int is_vmalloc_or_module_addr(const void *x)
 	 * just put it in the vmalloc space.
 	 */
 #if defined(CONFIG_MODULES) && defined(MODULES_VADDR)
-	unsigned long addr = (unsigned long)x;
+	unsigned long addr = (unsigned long)kasan_reset_tag(x);
 	if (addr >= MODULES_VADDR && addr < MODULES_END)
 		return 1;
 #endif
@@ -804,6 +804,8 @@ static struct vmap_area *find_vmap_area_exceed_addr(unsigned long addr)
 	struct vmap_area *va = NULL;
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *tmp;
 
@@ -825,6 +827,8 @@ static struct vmap_area *__find_vmap_area(unsigned long addr)
 {
 	struct rb_node *n = vmap_area_root.rb_node;
 
+	addr = (unsigned long)kasan_reset_tag((void *)addr);
+
 	while (n) {
 		struct vmap_area *va;
 
@@ -2143,7 +2147,7 @@ EXPORT_SYMBOL_GPL(vm_unmap_aliases);
 void vm_unmap_ram(const void *mem, unsigned int count)
 {
 	unsigned long size = (unsigned long)count << PAGE_SHIFT;
-	unsigned long addr = (unsigned long)mem;
+	unsigned long addr = (unsigned long)kasan_reset_tag(mem);
 	struct vmap_area *va;
 
 	might_sleep();
@@ -3394,6 +3398,8 @@ long vread(char *buf, char *addr, unsigned long count)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e908da1b8224665f987347b58cf3c8bf1d73d0db.1639432170.git.andreyknvl%40google.com.
