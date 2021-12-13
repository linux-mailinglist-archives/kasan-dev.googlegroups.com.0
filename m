Return-Path: <kasan-dev+bncBAABBKEC36GQMGQEBQDBV3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id D9BF14736F0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:48 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id ay17-20020a05600c1e1100b0033f27b76819sf10284658wmb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432488; cv=pass;
        d=google.com; s=arc-20160816;
        b=sn4cll6+5jjt1tV520F27cNdGuNRu0REejUoVE44Tj+YnR5K86h6+OVd9elOY2WZnd
         CqT6qUBKn0zhufD7I0/TM8z+Xy1x+bcE4GpvoQFOpE/WdnEUPXz4o5RK0A9jpC05S95N
         SM/WD7m05xTjW/EZHmIBLXZbAdTCALlLaLfKKoTlLStgNaQjl1miLMThm6MAUlcBsIvb
         NlHEEHpHMLOOGFyf0KcA6jgteNaO5KBc9/YHAxrTb1BMrxBKeUAsWs7hbHDpMclbecnY
         yKYx3DzxX23lm9s5HlpbHH+9apr2jjy5d+75iMzr2QY+SZ3WO67vRH4g2KT+aCs0C1el
         WnQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=EC0gQAhuq5BtqPTMCHbeC4ELDvA4kUgyILXAA8GzKMk=;
        b=wDWnV/F/Q47rC9PJZcygXFyphwHi7VCJw4/qpjOqryLKRe2cmrnzBLZJi3OeGu5PNn
         uQCuUXrv8lMOaD/+V8BPPPouYSp+QqQStZaZX5mpJ+VR44DVm4M2N7Mx9YWV1BvDh/S8
         jY/XyWp2lRAeUcXky3WW3FNkpAecHWxKspQ0sxoQOaXn2g+xnp4ZLHdkNLxWJZH+UNjn
         wXkkR8CYjiJYqAPZUhXA5/FIE9cB8hOrBbC0XaRiMRTjRm0t35dn+s+bRr7YjP/LA1sS
         li63rD+LDQnWphkzHva9/HV9UXaAY7LjXlBx1QCmeD3PZRamD6zdvj3fiXKznnl61Hyz
         ysyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xYHLkvnv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EC0gQAhuq5BtqPTMCHbeC4ELDvA4kUgyILXAA8GzKMk=;
        b=W2Hhi+Yl3te9CIbaYykapuIMUZJoMSSd17OVB6NU0elxynYy4kSTNdFDL47v6DQKJT
         9U1d+zUGV080dTReJ9oqjARTfcnbQJRcSjn1Iuyoc52h4n+x4u7eHHuXgbhGF53UsdRj
         ldLc9I3PoWhfpr+lVZoTVVAzQYMKpa8UvD37qJMe5NPa2kfeMcHfSzA/Zf5nu4Ac74ZK
         XK/HAXKI9QHrAjbqkx74hyyP+bh3lRl///H6hnmWw3zUH84pHPUoKgrzuX/Q+xjRTm68
         nzcxd/g97UF82ep5aA/Mwup/vS3UA1v72oXynbjoWWkCq/ZYI4LcJvgnZCIhu59W9rx9
         /3Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EC0gQAhuq5BtqPTMCHbeC4ELDvA4kUgyILXAA8GzKMk=;
        b=RjP3GC3fpcWPVhSjQHU6IgRRMQYzucsbQde3eFc4uky0xOaV0+s/35qGErEcZ3L+Os
         IngZGvfJ1d8u5fbKsX5+p9Wl8Aq9YGvuqti5z1+EOOKzDZqBqf+WMaD6fYkX5D3Ct+a6
         iPooxrjIH88E28XU0XOkTVuCmJw1TQGGbgLk3QBFgzk9cuvTtRAwKJyOj3s7dCy5X5WP
         K7GOKKrgxWluy6QfoVv0YfAeRIhsZXbC0GZPFnhpgZNJ9gUamJn9k6eqD5LJTJNm/3fd
         gjTV0UAOqnzj9VKQBCv3nGQMYn1sdN2TwwSXlZ2pPLELj+XIvBsUAkHIlxunUpZbtu1P
         9HOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53352qfLPM5a5kxu3oXQuaXdL4r8zHSbs7viw/zF3QNKKzQgVmB+
	8Wj0ulx5PcG2WCPZlosgG7M=
X-Google-Smtp-Source: ABdhPJxgJseb6fmPNVpmPOgM9IZmzLvdBeQJisyTTt03fWoiiAjnI+labeR1gq/YnPD2iA7UpUGCvQ==
X-Received: by 2002:adf:a512:: with SMTP id i18mr35839wrb.287.1639432488605;
        Mon, 13 Dec 2021 13:54:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls502129wrp.3.gmail; Mon, 13 Dec
 2021 13:54:47 -0800 (PST)
X-Received: by 2002:a05:6000:1a45:: with SMTP id t5mr1245382wry.306.1639432487875;
        Mon, 13 Dec 2021 13:54:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432487; cv=none;
        d=google.com; s=arc-20160816;
        b=Za2knDi8UREgpP84gSVvtQRQvc/whfPpakUpb1ZjQ9vVJcobC2iwJgn3YUxj6UcieU
         FLrPAvJKrwOgyWIVXV2Qp6lWOLOsjLVuTY9wxn03zOXlc3iClE5V8EuOuIYY2eL8sD7F
         ntimqZfXjQyMqOm+c0oAVe3ViDGXyshQTe+/pQSff3SB5H7U6ELAGrY7cPw8xReFbTrZ
         WgiKouwysGvEWsw6zFc56YWIt/Yenb02bJIIZmTc5GQxEemON4hJgbkqpj8OLeVumZUh
         ly3+lRdkls9yO2kj+zURMQQ7HU2vR4qm6N77NInn4Yk1qPK+stTbiUgBNYzyIPo8rgc2
         F54g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6sq+eBKmPs7noJHajriN1+v4kOdtPX3nQQgZ/NueHSg=;
        b=UHMiLx4LuL8yE2OW30oQVUVTeoUA8z3aNSErXaHADXrcLWDtpjN+WVlfIQnrrCnM/l
         6/uQOn1qagNPG8upcyAFPaft8lWkTFwNDO/NoLQ6CWpgA7XCFTXnK8uR8/NXDM3kg4dX
         ipyjtUzq5Yw+tcDsIYVJUvBxCHGuq1d0/gnhtwxz6RjVCwjucNMCvIIDjGTMsf6c+nZv
         bzo+yMyd8mfP6nOfQDjahvKryFIT02+buP1c9QHvC8x9pO5bpbpy0GibbiSpSHDOJygu
         BH2bocYt0+O/h9S7tJ9xNSxV8gBh4m8jYYnUDdICsoo9KbqshF4o3IEcict8udeuCs1c
         talA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=xYHLkvnv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id f10si17597wrf.5.2021.12.13.13.54.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:47 -0800 (PST)
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
Subject: [PATCH mm v3 26/38] kasan, vmalloc: don't unpoison VM_ALLOC pages before mapping
Date: Mon, 13 Dec 2021 22:54:22 +0100
Message-Id: <1a2b5e3047faf05e5c11a9080c3f97a9b9b4c383.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=xYHLkvnv;       spf=pass
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

Make KASAN unpoison vmalloc mappings after that have been mapped in
when it's possible: for vmalloc() (indentified via VM_ALLOC) and
vm_map_ram().

The reasons for this are:

- For vmalloc() and vm_map_ram(): pages don't get unpoisoned in case
  mapping them fails.
- For vmalloc(): HW_TAGS KASAN needs pages to be mapped to set tags via
  kasan_unpoison_vmalloc().

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Update patch description.
---
 mm/vmalloc.c | 26 ++++++++++++++++++++++----
 1 file changed, 22 insertions(+), 4 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 58bd2f7f86d7..9a6862e274df 100644
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
@@ -3104,6 +3112,12 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
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
@@ -3799,7 +3813,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1a2b5e3047faf05e5c11a9080c3f97a9b9b4c383.1639432170.git.andreyknvl%40google.com.
