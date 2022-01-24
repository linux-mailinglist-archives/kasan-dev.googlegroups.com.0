Return-Path: <kasan-dev+bncBAABBIGVXOHQMGQEU3WIQ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 2AC9F4987C2
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:06:25 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id w42-20020a0565120b2a00b00432f6a227e0sf9368338lfu.3
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:06:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047584; cv=pass;
        d=google.com; s=arc-20160816;
        b=blbVAvgM91x39FgIC8PdKoPYugS/AAMg0F7YUURRxy8lqDiDTNUg/v7gxAFVbhbdpt
         KBPxiCrSRRHgno53TzQSod79A+Mjxa1XaFk7tgvNA5ZqC750YjKZQQsE2/rtbmezS46u
         qOKYu05HPKoHbR+YVve2LoWvepmuUkh05AXktjhVYO4BS6mXcOni8H5PyfryfObzQa8k
         6VzGbXRkl06NiC9akUWm1v7xPEoqD7IpvDhdp1ejAk8um/lg+sVQM0uOgoXnl874dUZ3
         SrXfMUaau1e6FrVy9disiMUABiZCgZnQ+lzbBLd01W/OZn816EVCnUXWJK7fGEj7TU6a
         pgOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MXLTCYNG40rX2bW98Od5oQLajA85qefrSvEBwUKFkzU=;
        b=cy8MXHhQRvb7wuCkW6+SFDxfrtlxyVXmcLs9i3WRsqHcHHUyi/IDwQmRddaG8sWK+T
         XhA02Gq5s82qfW+BIyHz+6BTneiMMIIQJCDNJp+dqUMVT2qQTWQ7PItF2RPzFmWT+Jdm
         u0PUa3zrYKS9/t/z51/D6qnqlY/Al/15FemHVNbc8AkK6A0e01EMh7c6YXlZfybvLa5n
         3R3Z93g0bV/eGi/G1/TJ8JcjFn5pXlL9SDe6Z55sc0/qWdiu7+keiF0WyZqiV/ZDYFF0
         95pkbianH72B6DNF9txzJq6gpnj0/eQeuUcdiMol6HreBNNpbTsh8ezviFk2FLGpgp63
         c4nQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cEt2JHsQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MXLTCYNG40rX2bW98Od5oQLajA85qefrSvEBwUKFkzU=;
        b=O6lvRUc0fbpId08HrfC8P0WTjBzA6g9iO9JHE49nSp6yImAmFievELLbQQXmked9Kt
         c12j4cgHhh7wGAt5DWPyhnK9c5312ZipjzBA44hM0/6lvNrQ2cvF8MUxrlD3WSCas6lR
         0t04L0kkj/ORr6KPly/+h8BI24uaxCEyQPTD9Snu1BwIFVIr8+J1d4glB0374FwErwlh
         Xbvd+3pbkWCYlQDu5ppysrl6NhOBT06gqNeZR9ATXU5h+EWUfYwtf7OYlNnk2pS1Zomz
         qOeLYliK/QH9Zv5xfuCQR6RJ25S7PNJS/mH9WJLhw9Xb75YfEHSyEQKPKlxXeS7OXkwb
         KkEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MXLTCYNG40rX2bW98Od5oQLajA85qefrSvEBwUKFkzU=;
        b=fMxhyxCiTdoegGPx2SFDjhHR8xiiM8bWhRNKCKJXlnBGWsa/lf7TTyAKU5zCVZgsY7
         NcPnk4zwE7mgjeS7QogjmdJpXY452tpxvV3Qq12bfJbZtVwWKj0KwYVvxGAX1TRxQYQO
         S77lnxx8txWzBnKi/1GDItAIcmJ4CvrMJ0iHZ3Rnp6TmTTh9DSGvF3ihO8ePNJV+YxOE
         id2T4XxCxBzKcbdpV2g0201b1wQCAqKVi83ltQB2rpjXn4DXcjrPQ1uwLH75TVfFGdgX
         CLBGMCCLtpgazs1iZGc88KLurH4Z1rMk0jTpPxH6W8ZahKD4aOOFio5PC7rbbOMNVbXz
         BXPg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532k6ceY6u/RkdNA3RidHsK7Yg3JcnD7YWspONyB8mY8Vyx/1n3/
	wr7XlOlKk3+CKitmU3tcj6k=
X-Google-Smtp-Source: ABdhPJz9GaItmL6QaWMXqUaOOydCs6wX31r4AOwroSFGAgp2ARmBW67yjGRewd1dWLO1F84SkluBoA==
X-Received: by 2002:a2e:9ec7:: with SMTP id h7mr12020580ljk.394.1643047584734;
        Mon, 24 Jan 2022 10:06:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ac9:: with SMTP id n9ls572572lfu.1.gmail; Mon, 24
 Jan 2022 10:06:24 -0800 (PST)
X-Received: by 2002:a19:5047:: with SMTP id z7mr767744lfj.666.1643047583981;
        Mon, 24 Jan 2022 10:06:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047583; cv=none;
        d=google.com; s=arc-20160816;
        b=DBPz/37jLObOQEpPRxjBla4J/dhz+yH3NhXEYnlwVzYnPvuZQNOV7rTr4T6uFZJrm3
         vA2ga9/YmVDeCitMMaNvyhHJuFohRIEUC11sH2qrjf/EbpurJ+Tli1S2k3ta1rjd+DRt
         QPc4U5zchL8Ej4VO+NW/tuZJxa0BaZmvp5osa7f2IrD0sCPQf5o//D8PyCRYdex+pSq8
         mDReX7dJMEFWAhPPmXw1isx5OfUln5V0Ud8pNKVjGvHBVSFwwwzA0nAVeIsM166W9LmO
         LS/jaJW6+yvnn8FOA+JCE6DiGgtaMqPI5QFwnB/jC65X9uSwMItpYSzK3/qZoqm20u2E
         lxbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4/y0HjGmlj8gRZl7sKKC15OiIQ+URUy4QXcXfGAQLsE=;
        b=GfvleTD70GcnY2OnFZIVyjVNvvxMdPF3PRCjjVmZU6pO67YERAakVC3nQ3KfOxg6qr
         uambOt1+msRfbus2exw9q5ujmZB8lG5vtoUMsrfAdlB14qg9y/bnVS969V2AA0KbZRuh
         hhPI5Xqwv+MEgZAPN5Rs+xoqWhWyijX0T5hAINzkDg02e4dx0b0ImZByZ+zoW2dpSWsv
         RNzdlldWUG+QEhOozw4HQQRcf8+JZGFWCpX+wCNHJ2bgj2D1o2TiuGExttv7zqH89b0c
         LlGj47K/r38IrWNVzlQ/c2RrjWMRCq7SHX8vjT6jjOVF7s2AE4yWVMe/zD4RQvWzCc8S
         u20Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=cEt2JHsQ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id n22si93707lji.7.2022.01.24.10.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:06:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH v6 26/39] kasan, vmalloc: unpoison VM_ALLOC pages after mapping
Date: Mon, 24 Jan 2022 19:05:00 +0100
Message-Id: <fcb98980e6fcd3c4be6acdcb5d6110898ef28548.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=cEt2JHsQ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Make KASAN unpoison vmalloc mappings after they have been mapped in
when it's possible: for vmalloc() (indentified via VM_ALLOC) and
vm_map_ram().

The reasons for this are:

- For vmalloc() and vm_map_ram(): pages don't get unpoisoned in case
  mapping them fails.
- For vmalloc(): HW_TAGS KASAN needs pages to be mapped to set tags via
  kasan_unpoison_vmalloc().

As a part of these changes, the return value of __vmalloc_node_range()
is changed to area->addr. This is a non-functional change, as
__vmalloc_area_node() returns area->addr anyway.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

---

Changes v3->v4:
- Don't forget to save tagged addr to vm_struct->addr for VM_ALLOC
  so that find_vm_area(addr)->addr == addr for vmalloc().
- Reword comments.
- Update patch description.

Changes v2->v3:
- Update patch description.
---
 mm/vmalloc.c | 30 ++++++++++++++++++++++--------
 1 file changed, 22 insertions(+), 8 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 92e635b7490c..b65adac1cd80 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2210,14 +2210,15 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	mem = kasan_unpoison_vmalloc(mem, size);
-
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
 		vm_unmap_ram(mem, count);
 		return NULL;
 	}
 
+	/* Mark the pages as accessible, now that they are mapped. */
+	mem = kasan_unpoison_vmalloc(mem, size);
+
 	return mem;
 }
 EXPORT_SYMBOL(vm_map_ram);
@@ -2445,7 +2446,14 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 
 	setup_vmalloc_vm(area, va, flags, caller);
 
-	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+	/*
+	 * Mark pages for non-VM_ALLOC mappings as accessible. Do it now as a
+	 * best-effort approach, as they can be mapped outside of vmalloc code.
+	 * For VM_ALLOC mappings, the pages are marked as accessible after
+	 * getting mapped in __vmalloc_node_range().
+	 */
+	if (!(flags & VM_ALLOC))
+		area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
 
 	return area;
 }
@@ -3055,7 +3063,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 			const void *caller)
 {
 	struct vm_struct *area;
-	void *addr;
+	void *ret;
 	unsigned long real_size = size;
 	unsigned long real_align = align;
 	unsigned int shift = PAGE_SHIFT;
@@ -3117,10 +3125,13 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 		prot = arch_vmap_pgprot_tagged(prot);
 
 	/* Allocate physical pages and map them into vmalloc space. */
-	addr = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
-	if (!addr)
+	ret = __vmalloc_area_node(area, gfp_mask, prot, shift, node);
+	if (!ret)
 		goto fail;
 
+	/* Mark the pages as accessible, now that they are mapped. */
+	area->addr = kasan_unpoison_vmalloc(area->addr, real_size);
+
 	/*
 	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
 	 * flag. It means that vm_struct is not fully initialized.
@@ -3132,7 +3143,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	if (!(vm_flags & VM_DEFER_KMEMLEAK))
 		kmemleak_vmalloc(area, size, gfp_mask);
 
-	return addr;
+	return area->addr;
 
 fail:
 	if (shift > PAGE_SHIFT) {
@@ -3816,7 +3827,10 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
-	/* mark allocated areas as accessible */
+	/*
+	 * Mark allocated areas as accessible. Do it now as a best-effort
+	 * approach, as they can be mapped outside of vmalloc code.
+	 */
 	for (area = 0; area < nr_vms; area++)
 		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
 							 vms[area]->size);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fcb98980e6fcd3c4be6acdcb5d6110898ef28548.1643047180.git.andreyknvl%40google.com.
