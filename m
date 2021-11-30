Return-Path: <kasan-dev+bncBAABBRGBTKGQMGQECR64L4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id A334B464103
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:08:04 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id m18-20020a05600c3b1200b0033283ea5facsf6596667wms.1
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:08:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310084; cv=pass;
        d=google.com; s=arc-20160816;
        b=iZMfL0b5LAEt0atka4s0GZer8/EYguAzaUa22XhhUsc79vwswxjk2GOM+8v04oQQa9
         c6kesCk93VahYDaKbVigVPUc1c01ZVoEIpAhBSYeRxGBd3EH+475cg3LJuohTJ6M1IeO
         pnFqK5GJ5jn+3AUPI/ifN7UI02CXm1isEV5axRy0BpG2GgBkOnlsua0bqz22WRTmgI5J
         gZC8Ix0WpqIp/0d4zGOg3k2+Xexh4Tp4JhriR4IlHmFdOTN+2K2gKC3x4dVwIbrs3emE
         RvkyjI8UhVP95N2WqVnA859bSQOya0ibgzOYBtRkk1OrJtfR8zCkDkx6dBjlop8jz3/X
         R7Yg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=zA1p3zZyMEdj8oW47xn1qql8sQllcs5/WAcqwBG2kp0=;
        b=SQA0YC9K3h8aSwlSL3sTN4FF3DAUc8cDHCuSBA/cwDckjPrncWZT+UkXf2F3gaKfzD
         PkMeVx/I6paHEKiwYvNYzLtkKLOUW70VzRpd+5lLVzffhXFR10CfBBDaisH5mFWkZeYa
         CWVOWE3+cehyr5n00XgMmDST5jBrbYWKXjoR/E8d5/XQgbgMklUHrQ8YitOmB35vCqF1
         rw+ohvD6nNDMcfyQLL3CoXktyvhYiAyJbQfahBw5enKHS3C9y8ULahZyM4C9qHRs5S2G
         6ge4Kt86Kuc1UfVmdc8BLBMy/AnlzoL1BQcOhZ0YCYjaM3ZvJPkFVZQ3QH8QCfwicEYS
         fCIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xp8MsUnB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zA1p3zZyMEdj8oW47xn1qql8sQllcs5/WAcqwBG2kp0=;
        b=i+kO5iDSnLDXCFZMGNQb82DbmpOyBN+bjLEpO/2p591UUiWskUFgC0/X0gkGcbLI8p
         KgSfzLtMomKtj4usrVNkKboyTefm3iVb7zUTS5Z0m+S+S+b0TxX4vtjU/DSMSVSS5dye
         LjKlM+2kVRZtFM7wDnYsfugDcFL5rrb9B7d7U9g8G+6INti7lYDKlv+pPQPHqgR7oAAE
         Gx9TMbMcdqzXtz9p9Ie1+rO1VgusIWGNO8+1OHNEjWpEIu0YfKG1Bs86E5B7jhwHN4Cz
         VClVdf/QkroX0RP+Tj+dCRfyN/QZQCIlvHjLXgZ3uARV/vZ6c2wdZNP7z8g67mjYEPtx
         p4fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zA1p3zZyMEdj8oW47xn1qql8sQllcs5/WAcqwBG2kp0=;
        b=SbEHwE8u9sbvRJTa8PPRrIKaBsQ3tQZgqsYu62pUrWsbe16ItXqKIHkeKWs95vH+Xi
         aPVqtgYaX1Iw2xmQsJYa4IrvNTR40Ru3piNA+CUfLLye98YI5EVGx9+04ahRbCKUxLwH
         YcqNTkgif3IWF5cKZgShC+eiKvj9EcodtncDM8y/yn8D8m6jlZ8C8zI94KJNfzXM+oDP
         tEOM/wIwD/osL1w8pmSY2vuB5jDQG/ZfJFeXhvCqbk0ALkBRW2JfhVn8lRU0OAYkarTX
         cwv4iRJ3AFOzSiUTbL4bYkPHMao1nrQrd5psuCNHBLjClCmT1zfZrEI8MOiusH+Lu0mi
         o7JA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QO6bLt7Jr04o7xubHOMd2flNZ+apgsSW81bSp2Uu9rk3pXtn5
	yuIqa666uxrrhgu+4f0M0xc=
X-Google-Smtp-Source: ABdhPJyGhxvPLM+6yaCzpUMoaadnbyCy8siNDRi3kKJmmQt+eHW0T2COnQ6lyROoTd7Br6COJSzkVQ==
X-Received: by 2002:a5d:59a2:: with SMTP id p2mr1924651wrr.252.1638310084419;
        Tue, 30 Nov 2021 14:08:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:416:: with SMTP id 22ls2138968wme.0.canary-gmail; Tue,
 30 Nov 2021 14:08:03 -0800 (PST)
X-Received: by 2002:a1c:3b04:: with SMTP id i4mr1808712wma.126.1638310083738;
        Tue, 30 Nov 2021 14:08:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310083; cv=none;
        d=google.com; s=arc-20160816;
        b=j2wCjmexFnFhUslm56NRzpUk70uIxEryzb05zCTV9UgpBDr9kbReeUAZJH/6arwKkq
         VGzx4pzEvhizvPtQwc1X0OEfCgvPx/UzT2ssAbqPDclX/0k/m2CIuG88mJAujdU8v+vp
         5Q4iaz8qR0fU+Eu+0Ymv2k6o2ohRZFGZdCaXH7ogwL6zGtpWng9qyGpKAj9DYHiwI/DO
         5mkVpGso8wEu3XLXlzKdRTaMNtxcBjz+wEn5N4grJHm/VpuUvu62ujG/g8FPpx0ct7gc
         rpfhgaXxbbjzuIM+AfqXNRRpjmd2xp4LPD2Y9SChOsVcNXWbr3BQmLEFiM1LEQMh3wK6
         X8CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CceoAuXc8ztt6c/41GK5sR1YQRKzgrFVIEpBFl753js=;
        b=zh3siNnxL0XO8TvtKb/zb7a3G9296yFwg4+iXQ8Bo56gusZUnbI87vmpeO7a3CJ+n8
         CCsicVGpoKRO6lAIoPv74tt2gk9SoFAzSfBwH3UkZzY1xhxKyvb/YJ3nIv18ip1MIrnJ
         6kk/7p8lSuucljHlhFG9hgw1eg76e4TN9OSmuHk5+Y/r4z/hA9jGYVkUDzXcWV/9FYhV
         vUBN47UjCoz17tSy/wgZ1YNIDDbQGJxKK2wLILAib2SmgOKomNPKvpGEFw3JKLRHxuey
         wf/UDeFnxOjrx22KkRinA8gOG3XDNRbasAR9U2e1nt8ZYyAczs0Nzz1Wwt2YeQTj7W4m
         43xQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xp8MsUnB;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id c2si689112wmq.2.2021.11.30.14.08.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:08:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 25/31] kasan, vmalloc: don't unpoison VM_ALLOC pages before mapping
Date: Tue, 30 Nov 2021 23:08:01 +0100
Message-Id: <0b79da9e534bfa35d11154b940095df23ee68a16.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xp8MsUnB;       spf=pass
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

This patch makes KASAN unpoison vmalloc mappings after that have been
mapped in when it's possible: for vmalloc() (indentified via VM_ALLOC)
and vm_map_ram().

The reasons for this are:

- For vmalloc() and vm_map_ram(): pages don't get unpoisoned in case
  mapping them fails.
- For vmalloc(): HW_TAGS KASAN needs pages to be mapped to set tags via
  kasan_unpoison_vmalloc().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/vmalloc.c | 26 ++++++++++++++++++++++----
 1 file changed, 22 insertions(+), 4 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index f37d0ed99bf9..82ef1e27e2e4 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2208,14 +2208,15 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	mem = kasan_unpoison_vmalloc(mem, size);
-
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
 		vm_unmap_ram(mem, count);
 		return NULL;
 	}
 
+	/* Mark the pages as accessible after they were mapped in. */
+	mem = kasan_unpoison_vmalloc(mem, size);
+
 	return mem;
 }
 EXPORT_SYMBOL(vm_map_ram);
@@ -2443,7 +2444,14 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 
 	setup_vmalloc_vm(area, va, flags, caller);
 
-	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+	/*
+	 * For VM_ALLOC mappings, __vmalloc_node_range() mark the pages as
+	 * accessible after they are mapped in.
+	 * Otherwise, as the pages can be mapped outside of vmalloc code,
+	 * mark them now as a best-effort approach.
+	 */
+	if (!(flags & VM_ALLOC))
+		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
 
 	return area;
 }
@@ -3072,6 +3080,12 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!addr)
 		goto fail;
 
+	/*
+	 * Mark the pages for VM_ALLOC mappings as accessible after they were
+	 * mapped in.
+	 */
+	addr = kasan_unpoison_vmalloc(addr, real_size);
+
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
 	 * flag. It means that vm_struct is not fully initialized.
@@ -3766,7 +3780,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
-	/* mark allocated areas as accessible */
+	/*
+	 * Mark allocated areas as accessible.
+	 * As the pages are mapped outside of vmalloc code,
+	 * mark them now as a best-effort approach.
+	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
 							 vms[area]->size);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0b79da9e534bfa35d11154b940095df23ee68a16.1638308023.git.andreyknvl%40google.com.
