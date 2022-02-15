Return-Path: <kasan-dev+bncBAABB3XGV6IAMGQEOEFKOTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 12E514B746C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 19:39:43 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id t25-20020a056512209900b004419802fb8asf6460843lfr.19
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Feb 2022 10:39:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644950382; cv=pass;
        d=google.com; s=arc-20160816;
        b=px6tNnG3FBjPTAsyuhm/nlvFlTPMArhYcq7mcFShmxtUbHxKqlxEaY+4uK5vI0nGmJ
         sMPruxMf0cFupUJR4e92H1xeXCW/C/XfFHQYq3c2Inag5uZHClWPIetOvKdDDv/L5AgT
         MhbTt9M/1u6iyGBpMf9/Zrdexzbi9ddCVfbGW7q2zdgTh3ATumFqpnc+zmoLaFHuA7nD
         vmRNsbJzbBDvCOs3jDIbhHHicYM81uJ15Ahq58X8BwlHZxOjYgpbkX+HE6sqQ+vXTRlB
         eqOOcNiCnACe1kYRgtoSFvYhFYJnHJRuoqbbHa2x7xtIFSXxa8wjA0dvmfKXqiZGNZoA
         4SBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xtmGkAR/FgkROJ26anTBmqFxeY7lIbbyVTPEba13zhQ=;
        b=MieX19GSIfsyn7tJaszLXnx6DiUdxFcRzHLe0iLm1CWcfvb3mwPblXNuIxjVjr3DZ4
         Wb16sMRahZmniDI5cuPVBBvh04NRRrG5Lbstm9zo72+bYnYdrbaQp8krwB/tcoaKxmtu
         p1FdFDsBIHT4UQjP1nY+ByczWqW11UFklAe07nfVHcamwwEwO0YJMCKyuLTk5AWg/Cd8
         Eo1ttcOa/sA5Bu5cvNf8aPB/zJSh3UOEwseFSKj9AHrk1MCUjMXj3+ruH5RYIx2RYDDA
         bHwe6fhS6izr7sQtL927oY9+lgfC+BtRMyP5ZeJoMfyb+5wYzpB+MWjr83CRNVFu+tTj
         4vYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tWXktW8o;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xtmGkAR/FgkROJ26anTBmqFxeY7lIbbyVTPEba13zhQ=;
        b=j19WciPJk6T4uUKrWtzugvT+Iz+8/L2rbmFpq2apV5NjX9AXqQAUb8YX30av1ebUVH
         NMiauq2LofR0o6sLejvHrWdWRcQwM5fa5MopLBVRSg/gsHqNa48f1A7UWqgK5Xgxb0/l
         dMBLZVPo179xVIswNfqGKZZOMiy3sj6j1FnvOycq9ihMR1I3NMLsr+pmhSz/qixww7yg
         KI6AA9FOFtBx2xyATmFwx9y3C4mW7lJGek7k064v6N6WSFOsZ8E+CB3MEelZizB/e5CH
         IGXfLb7eVswyLgZ53zSmiJtS29FoDUIVEDUBSGhSxABhyLxf1fdLRmKiGdR5gxUmy1a8
         ufbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xtmGkAR/FgkROJ26anTBmqFxeY7lIbbyVTPEba13zhQ=;
        b=I9Lh/oyK2qMPo/Nt2LOMx5E6cD+oxRWXCfZXQXOrtcC38E9dVb1BGThDRVWfv1v8IK
         9X2/ISN1Vg4+OQPBXhyANIbci9MYxpJjd3VpskXW5Tl5t6IrcCog73FP9kQtMcGh3Lgx
         edc0q5H/HMJcJ+Qqawo10JuGzDvV1a8hoxxxY2Xo1RJ7Y6HHMhwh4m+d/IlZyJi7/INr
         L8apbdGnt13mCOtzn2uqxypgV8tBndMnravK2I6HcrVM+XAKqyQ3HMK6ZXNKxVL6o/zD
         TXrb6stHbEnmhAyzDpkLm0IJSl2hNqAw/iM3Yev6pItj7Ef4dNsfuJZ8JNhCLZBo+xrU
         nvvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jjWcru+muuWYRvSh1AvO/xFZ+fTUPg4pCmLoT8ezTEGh+qh76
	2rfhyxF/3lXsHdpOrm1d0Z8=
X-Google-Smtp-Source: ABdhPJwtK0rnsHRQ188v8/n0cF+v63MGqgYHfYbMXdKS/fBxguRSf3Pd38+r0YhSaQYmx3AmT/Tdnw==
X-Received: by 2002:a2e:9c52:: with SMTP id t18mr241152ljj.415.1644950382517;
        Tue, 15 Feb 2022 10:39:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e11:: with SMTP id e17ls3219708lfr.1.gmail; Tue, 15 Feb
 2022 10:39:41 -0800 (PST)
X-Received: by 2002:a05:6512:1315:: with SMTP id x21mr316915lfu.454.1644950381615;
        Tue, 15 Feb 2022 10:39:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644950381; cv=none;
        d=google.com; s=arc-20160816;
        b=Wc8G2Rry97TMsF6/ewooeCcI9MgHIN6QL0ChUA34QfrVYgAXq40ZbHiy76Dm2iEiUn
         t9aks40Q+QSPCTQVVMDVpPU2IvC2x6hxve7oz1NaG/mn541VZeEthNwcyywhRaF0Rc+c
         KOHGsa7Mp0gzVHW6hZJHTbFOTZffiRGGNYEbZAPDDHXrD63+pfGJLvln1SJ7pDasy3B9
         tFNgWCbulu4SLuxmtlXLl+wHUW/7Gp71jpTFqaDw0RIQXmBSSFA3kk+KMi3fbIElIHAk
         UZ6dikTnTAByT14i6TbvXef4qNb+Uvr1IpAPT9yTKAQrLIIpFy2iQCW81ftnJ9xXzSjK
         TIFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=pwV+5NwZYvQrQ1JgfEXwuJfZqiKqAoxKp8Wr6tUObj4=;
        b=VccaKaP6fHlGom1m/YyVUOXbKfw+mx+zTYK6J+F84tr9slmiDDO0K0FyN0UyrQHqKE
         5DKYFfiKhSe3KHF9yK1c/vb5ttFhfqZr5ZZ4jmlhGMe2qE2bow1gbC94xocS/Xr32Asz
         OViNBfJuY+rbZ4ZlLL/25zrKxQsWWs4VrS5EO3+R+62PFvnlZoDvfP+FIYmbSY/0gFYS
         smRNs3+wykzAESMBuYUJiIk32dHoXY/2PMjidy8IWleF7d3zDfwW9L8K2EVetY+f+3Pv
         6/vICZvhuYIBCzX6A3lBTdJ68VA0PR7xhBUzk0lO3lTGStwa8WigDVR5eSzX3tSrDUcR
         6TLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tWXktW8o;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id x16si936639ljp.6.2022.02.15.10.39.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 15 Feb 2022 10:39:41 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm] fix for "kasan: improve vmalloc tests"
Date: Tue, 15 Feb 2022 19:39:38 +0100
Message-Id: <865c91ba49b90623ab50c7526b79ccb955f544f0.1644950160.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tWXktW8o;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

vmap_tags() and vm_map_ram_tags() pass invalid page array size to
vm_map_ram() and vm_unmap_ram(). It's supposed to be 1, but it's
1 << order == 2 currently.

Remove order variable (it can only be 0 with the current code)
and hardcode the number of pages in these tests.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 16 +++++++---------
 1 file changed, 7 insertions(+), 9 deletions(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 491a82006f06..8416161d5177 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -1149,7 +1149,6 @@ static void vmap_tags(struct kunit *test)
 {
 	char *p_ptr, *v_ptr;
 	struct page *p_page, *v_page;
-	size_t order = 1;
 
 	/*
 	 * This test is specifically crafted for the software tag-based mode,
@@ -1159,12 +1158,12 @@ static void vmap_tags(struct kunit *test)
 
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_VMALLOC);
 
-	p_page = alloc_pages(GFP_KERNEL, order);
+	p_page = alloc_pages(GFP_KERNEL, 1);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_page);
 	p_ptr = page_address(p_page);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_ptr);
 
-	v_ptr = vmap(&p_page, 1 << order, VM_MAP, PAGE_KERNEL);
+	v_ptr = vmap(&p_page, 1, VM_MAP, PAGE_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
 
 	/*
@@ -1186,14 +1185,13 @@ static void vmap_tags(struct kunit *test)
 	KUNIT_EXPECT_PTR_EQ(test, p_page, v_page);
 
 	vunmap(v_ptr);
-	free_pages((unsigned long)p_ptr, order);
+	free_pages((unsigned long)p_ptr, 1);
 }
 
 static void vm_map_ram_tags(struct kunit *test)
 {
 	char *p_ptr, *v_ptr;
 	struct page *page;
-	size_t order = 1;
 
 	/*
 	 * This test is specifically crafted for the software tag-based mode,
@@ -1201,12 +1199,12 @@ static void vm_map_ram_tags(struct kunit *test)
 	 */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_SW_TAGS);
 
-	page = alloc_pages(GFP_KERNEL, order);
+	page = alloc_pages(GFP_KERNEL, 1);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, page);
 	p_ptr = page_address(page);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, p_ptr);
 
-	v_ptr = vm_map_ram(&page, 1 << order, -1);
+	v_ptr = vm_map_ram(&page, 1, -1);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, v_ptr);
 
 	KUNIT_EXPECT_GE(test, (u8)get_tag(v_ptr), (u8)KASAN_TAG_MIN);
@@ -1216,8 +1214,8 @@ static void vm_map_ram_tags(struct kunit *test)
 	*p_ptr = 0;
 	*v_ptr = 0;
 
-	vm_unmap_ram(v_ptr, 1 << order);
-	free_pages((unsigned long)p_ptr, order);
+	vm_unmap_ram(v_ptr, 1);
+	free_pages((unsigned long)p_ptr, 1);
 }
 
 static void vmalloc_percpu(struct kunit *test)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/865c91ba49b90623ab50c7526b79ccb955f544f0.1644950160.git.andreyknvl%40google.com.
