Return-Path: <kasan-dev+bncBDQ27FVWWUFRBL4IVSDAMGQEJ4JUHRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id CCD113AAE86
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 10:13:36 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id s14-20020a5eaa0e0000b02904abce57cb24sf1295047ioe.21
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 01:13:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623917616; cv=pass;
        d=google.com; s=arc-20160816;
        b=HU+q9SYXZ1eVAtH2IhHH0trXlyTJk5LcG1RVQlf33qd5RUmcoForyxXbtxtnnAV+q4
         apnx4JOp9QCeQiEJNNYJ0MysWsirZ85v4wbfu9IQJzlh11Ht72zsJF7HmQ4cgi3S9P3t
         yN1mmUzNVbyiCegAayS6CdPct9RkBZtOQX2o11DhoAj2MMdC4culn3bHazsSmsN4OiiY
         3bCGeBYHzkj1/Cb+PEQjn0o7uHVc1/NLfW5X15fLETTf9RPwUymC+d/fHCpakLxhG1fg
         0fMB6vsAFoc49wH39iHsUdNVh45h+ILp+L9M3NKi6Po7NPBLZMr0ZFTqA+cD4afOL8Qq
         RVJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=4wMuQ08fA+n0andF3k8AkuhuW1SA5ZecvDhDgyE8t90=;
        b=I8igQmYmFvcVoE+MpLYmd+qgE4dwS6fpRXKlUp3aBPz3pCxOxQGChNSA3C7KjI4wAF
         Y5i+sdCpiDwUJXiyfqMQRev5Py0cwh/DTqfTXO1X/7+ScgyUes361FiMdMcNZ5icMl4w
         yp5JE+s4pt4Jm3APstWesyOSo8rV5REObXnSKEjJDejWAIDCKKDb0TDaEqcHu0Uv4cAw
         48QEcb/0j5k12ag9lASVL1qEl0e3uDy872EGqSAOhMbTb2A6Iru3u6/hX4Aq23QMqJ2z
         mgbb8PH5KPMBDATf+sGpH0BW5ZNAjHGQ/bkWZ2eNmZPebkhTTk2/O4ml5bMWQmSMRZRR
         9hVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="N15/0qJH";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4wMuQ08fA+n0andF3k8AkuhuW1SA5ZecvDhDgyE8t90=;
        b=ov7g3lOY47GrO2uinvb7/yMQKcSrp/Eyc5eX08gY0W6NkhwydftGJcP8sUcUYpy5pg
         PoOYKatsBLgHfVaheB+k9FXuc9PiHaR1tmACNb+oot+WigdAbuHQJD3/awRgGJEnrBNr
         trdM85MXAsXMe3v6TO01lKUIyasEKs0olmjPj1cJtIZNt4tQyvpJmGZtav00XRypuQQp
         4vLz4LXJ2DeHUwb0PhaxL5CZ72qgnbv/JLOzKMse3X+EH2mlsktNSbx4F+qQICazJBGP
         M6O6UkdnUXQwTXLLVB+JofLT6CZws4bOtPIdte4hsCuBTk5a7yAd0kpcHB/KQGa7XW4/
         YmaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4wMuQ08fA+n0andF3k8AkuhuW1SA5ZecvDhDgyE8t90=;
        b=jIWhLNMQUBs7kNPGRUEpJvEIIJJf/RAEB0gZ5xsBPMO9p9+eapTU0yypl4EUDBBpwE
         NDDr+QkCKslDLDruhCa3+yS5+Z6KhC1S4JBfYcl6i0wQ9TsgS6FY+NO2dLY6n7LgrmOW
         cdkjHKTUidUDd1DgYcHmapsyInmME0hi/OBmIhGUR/puoBOAwWzURSDNRUEArXx656Kn
         ww2tRt6B/5b69f4dGPidK8CWWz5aOlqiIaM/2OEc45NSC0mu8/s+EbYV+Z2MG0219zFp
         LQMIF2xE/XEKgQLBkpPaoFA/gqmEvNQLt9cuTbZ16bG7Otb1pqcACmZk8PTQUAt+XyL4
         +V0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JX7vjMQemFHex0yBcQPDd3w1vdGDV2WvN7U+DQ9d93LAWeaPm
	pFrfnUqkrp9igNLtVgvvAfU=
X-Google-Smtp-Source: ABdhPJysyDQDqr7rxGsaDllE/cVz/mnr7Wr1YqJ2cAT0nuC9kGuD5xUS2fpxNS0gk5DBH/H54Kn4OA==
X-Received: by 2002:a05:6602:2049:: with SMTP id z9mr940505iod.72.1623917615901;
        Thu, 17 Jun 2021 01:13:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:1302:: with SMTP id 2ls1115593ilt.8.gmail; Thu, 17 Jun
 2021 01:13:35 -0700 (PDT)
X-Received: by 2002:a92:bd06:: with SMTP id c6mr2627489ile.110.1623917615490;
        Thu, 17 Jun 2021 01:13:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623917615; cv=none;
        d=google.com; s=arc-20160816;
        b=XSAPGzUbaAAdvjqauGQKBOfpb5GBxJyOE6EpkKIG4cIg4lcmEd0N/0Xw9dfi4Cbjaa
         wiQIEY2gS+AjAPPBmIeA3wztGolmHkCw7HOa0Akkq4yVq3rZpZsU904BPdYxsc4EcxW/
         98rueOYEery+x0IoXj7zPFLVUEDOiCcRp/wd/N76IQkbszSMlSaggZn1z03RjBszoUIJ
         m1haYdUzc1yhuc4kvO9cfxwazTybEfKZ5sryeWgQwzWYZnmDsToctehuuNx2z1qc9PXT
         GwF3oULVEJRB06GuarnP/pqaZfNaGu7IPC5TsIe+L0ilgafvi3+7XX7F2UapKSX1Z8aO
         WHXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OTHwuB2mCohnRjYeuyJYonCC4hSvfxMb+kfGOcySdeA=;
        b=DQTIBbO6qnwrXsbIbiwgpFv5if5bS/KW5VKNZgZKYbisUryUZ0CTHW8R26vBu3YEvu
         PXAVvV6c1C6l0eX/6U+zymwe9DhGITYnr9qXhohsNs6xzvqAI/wQsfMz87ItF3Nf9wXc
         +0wJFRaal+sTWFoNjuQebOooBEkKOi6HZ9kuhbpHvCIlA8lgoMO1zUGfo783jWQGcKme
         CHSmYDzk59komnWliF8tErMnfpMzY4Agrf/nx8cbBwkXMgJeIDQeYeTOIxY4NY5bH7ih
         8qOFV8ti+SHlHrhFj6lNn1KSYzZ82+z73Rf7/Ft2OmuxcQEPhXK/I0ROaY0SCqwn6W+v
         oy3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="N15/0qJH";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::635 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x635.google.com (mail-pl1-x635.google.com. [2607:f8b0:4864:20::635])
        by gmr-mx.google.com with ESMTPS id a2si395225ili.4.2021.06.17.01.13.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 01:13:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::635 as permitted sender) client-ip=2607:f8b0:4864:20::635;
Received: by mail-pl1-x635.google.com with SMTP id c15so2432896pls.13
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 01:13:35 -0700 (PDT)
X-Received: by 2002:a17:902:748c:b029:103:267f:a2b3 with SMTP id h12-20020a170902748cb0290103267fa2b3mr3483380pll.23.1623917615084;
        Thu, 17 Jun 2021 01:13:35 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id z6sm4623868pgs.24.2021.06.17.01.13.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 01:13:34 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	akpm@linux-foundation.org
Cc: Daniel Axtens <dja@axtens.net>,
	Nicholas Piggin <npiggin@gmail.com>,
	David Gow <davidgow@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Uladzislau Rezki <urezki@gmail.com>
Subject: [PATCH] mm/vmalloc: unbreak kasan vmalloc support
Date: Thu, 17 Jun 2021 18:13:30 +1000
Message-Id: <20210617081330.98629-1-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="N15/0qJH";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::635 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

In commit 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings"),
__vmalloc_node_range was changed such that __get_vm_area_node was no
longer called with the requested/real size of the vmalloc allocation, but
rather with a rounded-up size.

This means that __get_vm_area_node called kasan_unpoision_vmalloc() with
a rounded up size rather than the real size. This led to it allowing
access to too much memory and so missing vmalloc OOBs and failing the
kasan kunit tests.

Pass the real size and the desired shift into __get_vm_area_node. This
allows it to round up the size for the underlying allocators while
still unpoisioning the correct quantity of shadow memory.

Adjust the other call-sites to pass in PAGE_SHIFT for the shift value.

Cc: Nicholas Piggin <npiggin@gmail.com>
Cc: David Gow <davidgow@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Uladzislau Rezki (Sony) <urezki@gmail.com>
Link: https://bugzilla.kernel.org/show_bug.cgi?id=213335
Fixes: 121e6f3258fe ("mm/vmalloc: hugepage vmalloc mappings")
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 mm/vmalloc.c | 24 ++++++++++++++----------
 1 file changed, 14 insertions(+), 10 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index aaad569e8963..3471cbeb083c 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2362,15 +2362,16 @@ static void clear_vm_uninitialized_flag(struct vm_struct *vm)
 }
 
 static struct vm_struct *__get_vm_area_node(unsigned long size,
-		unsigned long align, unsigned long flags, unsigned long start,
-		unsigned long end, int node, gfp_t gfp_mask, const void *caller)
+		unsigned long align, unsigned long shift, unsigned long flags,
+		unsigned long start, unsigned long end, int node,
+		gfp_t gfp_mask, const void *caller)
 {
 	struct vmap_area *va;
 	struct vm_struct *area;
 	unsigned long requested_size = size;
 
 	BUG_ON(in_interrupt());
-	size = PAGE_ALIGN(size);
+	size = ALIGN(size, 1ul << shift);
 	if (unlikely(!size))
 		return NULL;
 
@@ -2402,8 +2403,8 @@ struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
 				       unsigned long start, unsigned long end,
 				       const void *caller)
 {
-	return __get_vm_area_node(size, 1, flags, start, end, NUMA_NO_NODE,
-				  GFP_KERNEL, caller);
+	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags, start, end,
+				  NUMA_NO_NODE, GFP_KERNEL, caller);
 }
 
 /**
@@ -2419,7 +2420,8 @@ struct vm_struct *__get_vm_area_caller(unsigned long size, unsigned long flags,
  */
 struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
 {
-	return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
+	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
+				  VMALLOC_START, VMALLOC_END,
 				  NUMA_NO_NODE, GFP_KERNEL,
 				  __builtin_return_address(0));
 }
@@ -2427,7 +2429,8 @@ struct vm_struct *get_vm_area(unsigned long size, unsigned long flags)
 struct vm_struct *get_vm_area_caller(unsigned long size, unsigned long flags,
 				const void *caller)
 {
-	return __get_vm_area_node(size, 1, flags, VMALLOC_START, VMALLOC_END,
+	return __get_vm_area_node(size, 1, PAGE_SHIFT, flags,
+				  VMALLOC_START, VMALLOC_END,
 				  NUMA_NO_NODE, GFP_KERNEL, caller);
 }
 
@@ -2949,9 +2952,9 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	}
 
 again:
-	size = PAGE_ALIGN(size);
-	area = __get_vm_area_node(size, align, VM_ALLOC | VM_UNINITIALIZED |
-				vm_flags, start, end, node, gfp_mask, caller);
+	area = __get_vm_area_node(real_size, align, shift, VM_ALLOC |
+				  VM_UNINITIALIZED | vm_flags, start, end, node,
+				  gfp_mask, caller);
 	if (!area) {
 		warn_alloc(gfp_mask, NULL,
 			"vmalloc error: size %lu, vm_struct allocation failed",
@@ -2970,6 +2973,7 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	 */
 	clear_vm_uninitialized_flag(area);
 
+	size = PAGE_ALIGN(size);
 	kmemleak_vmalloc(area, size, gfp_mask);
 
 	return addr;
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617081330.98629-1-dja%40axtens.net.
