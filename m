Return-Path: <kasan-dev+bncBDDL3KWR4EBRBEGDRWKQMGQEZXF4RYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63b.google.com (mail-ej1-x63b.google.com [IPv6:2a00:1450:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id DF5F1546952
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 17:21:53 +0200 (CEST)
Received: by mail-ej1-x63b.google.com with SMTP id t15-20020a1709066bcf00b0070dedeacb2csf9746784ejs.9
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jun 2022 08:21:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654874513; cv=pass;
        d=google.com; s=arc-20160816;
        b=WKYkQRD20mLw00zmzT3Nbm6Y0nLT66x2hjU3jfMwvdOzZ0A9DPxIDYj0Q5rr3PhYjA
         9IC6AVGkjObuD4d7EvMqWxyKoDSdU0Bs23vLgpevFwH8dtamr+0zyatRxb+99QwnA1Xy
         KW5xkA+RNY+4Acu3fG2uY6f84ux3vGerBz7abbzeF1KCFi6b0jV8JyPhhVI0tvG+cGyF
         UbLV6ykD8QYukhXsQkScZq30izlYsBPD/HM9hcpZhflQU/hfzICtmk0h+KPVeDiQYWc7
         5SYLpkGSYYQakPgp3pGQo+uYBOLxBoTlHJG3YQTkvO0e4ieRPVw9Y/ohfji6za/cYswa
         PDzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JiMpkNfilSkTPsOIdP4vwGYaEM8K6hCCAuNkXxNdiL8=;
        b=B8ibYTUBD8yCGzpnmjn8K2n3/XpBYAYsXiAnddSHg4XBk2TX1YV58C63mV+nN9B430
         zb3fm/sy8lavx/isGMqO7pjmQfc6q9UFP6hX7Lldaq6EAHtzTLKjTjeCV9I4GjVffsDd
         Z1AEHqMkXgcCJ9we6JYD4Udvv+ZaDlLu+khjx4oDV/ao1ztt/Luzn5gxSoAsCZc9Rfi2
         u6zbmm7kjlZ0QMO7fwctpEgllfBR1npDVHMHWFXWDVFA9ixks2hqOxGuBHqZ1/A674af
         K/1fW3d1BaXy0fxc3WDKdiLW923BYLABlKb98skTK+u4suYN58F2BzU23RRjA5K9e6Yx
         oiiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JiMpkNfilSkTPsOIdP4vwGYaEM8K6hCCAuNkXxNdiL8=;
        b=SdPlw/4xgJIhMQaHNSNLthdkzxB+epsUyd1AAo8wAS9Z2GP/t6U1uPjzHRxO7Uk0sC
         vI93DcVQnqIF4q2wht5SzeuUUTCPF8bzXe++N/7dsIvXH+tYO5K8FViTQ96py/mrBQLk
         LCPMNfJYq62tzAQpo71gQYnsNv3aPBP29kXtekIIUZihtqIFS2byrMz5+Km7UAlnO6B6
         erMPLRp0dFbm3rC8G7wAYFZUJfiSiolkMs6P3ogXUVLevfHTc1kFWXUNAOjoebVJ7/8a
         H0exBOqM8q+wNf12dJTk4hA0RcAQr+5Ar17TZJqXedBa3f4csdEmPNr+KyGFeQBJrlnC
         iEow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JiMpkNfilSkTPsOIdP4vwGYaEM8K6hCCAuNkXxNdiL8=;
        b=2yrm0EMrp/UctrRey914QriQsKr+MoZ8cl1yjOqo9Fkwpfgk+StHCNK377qbqJl8g0
         5qxhaAx+QHMEmALjZRcAL8zvmehGLcxUHKmfRfxxKqXEu9NxXU/Mh9O0rT6T32yU2Tws
         8YQhHOYlNxX8+VTdMEE9laCF9ndyBrjaCeSgXWBK4zLzpU30DWpNJWzbX10Y/ZOgBgCt
         Y8zlUx4vTYgEWyFV1fmHoCuCVMy+ryi/I+AhRI/b3bFscUlqpXx3+UJmleNN0Tbfi4rZ
         sr4OahHtvEsw1JRfK1VDSmOEl6YlKIyFR9eCst1xCXhKKvqsY6NCY8IGVze+TG15ta2J
         jXhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NSRXhWcgPgabl1qkF42r0IWAJxUJFcTt/VlK9fwmKo77l/Lrt
	bkbKrlAGtF3iDzexp/Hj/d8=
X-Google-Smtp-Source: ABdhPJzdolj6T0pCT71yhI4uy5EtUimfTeW1dPj9MoVQJsjeYjkyCzDwf7bfrJxW8rovjxgBJXrfFQ==
X-Received: by 2002:a17:907:3e0d:b0:711:dbff:b830 with SMTP id hp13-20020a1709073e0d00b00711dbffb830mr20233951ejc.601.1654874513181;
        Fri, 10 Jun 2022 08:21:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d1c:b0:70e:611f:3585 with SMTP id
 gn28-20020a1709070d1c00b0070e611f3585ls1460705ejc.8.gmail; Fri, 10 Jun 2022
 08:21:51 -0700 (PDT)
X-Received: by 2002:a17:907:6e01:b0:704:8c0e:872f with SMTP id sd1-20020a1709076e0100b007048c0e872fmr41485754ejc.387.1654874511912;
        Fri, 10 Jun 2022 08:21:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654874511; cv=none;
        d=google.com; s=arc-20160816;
        b=gh1m5mBJfjYVo27FOMnNuXyCKlfE/2JDlppkyTxFt85tgPizbVPBiWuTaKCx5p8mxB
         bwcyqXekGlfsuSKI5PwmmhZ5ZZr1XDsR7kkqfX5YXLVSUlKit2GpmPNSgNk4Bc6FKrxK
         vp6onPIToAOaWoea5+wgr6I3jqlhsXP+R9EO25dubnkwfbT8mJ9U36gUOk03o6QbhuY4
         RTEL6/NQKVk4KYnDjlbZXnyEVBPejpPnTO/64f69M7/E6Y1gQjIcSunSQLQFV7M7MrB0
         7sircfh451vP2Uqchu2wx4rv0CM5in5tVa3ZbFrbNwaQVEQUQ53HZWaUa/Vk2Tcljn1i
         uUSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=n7YwtxZb19sKhudiuHN2wnLVKARhT8a2ZJAm9A3/cEo=;
        b=tbTFb91oKrlxWFGVjQf2Vg0bqd0S1gxJpILqGEuBruUqA46Nm2C6saVN0aheMLgVqY
         9UdM9DTWcP/wOQUgp1FvQjgSMIQPm+UWHH0LH2bdMpqViEKeeWZRld2O7FzHMvojz/9l
         0MV5N4O9l/GGCsYvf50UBZHDB1iJbtpGxTC4R9rWdXC27vh0dbjNpjgncLnd4KotSd/G
         OEjvykUW+kbIH5Jp1zFfyVXuANd8NCDrZ8WqORs+3veoBMeD+J8uW1h+olH1keA17Ra0
         nR8Zo66UbELndq2/yFoQDEEzhupYsD3mmpCK9UtPqb3bBOrNP4sMYIpAG3R9SKx/PBMT
         vwpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id a26-20020a170906245a00b007104df95c8bsi937961ejb.2.2022.06.10.08.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 10 Jun 2022 08:21:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 9DDB1B8329C;
	Fri, 10 Jun 2022 15:21:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 88590C3411D;
	Fri, 10 Jun 2022 15:21:48 +0000 (UTC)
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v2 2/4] mm: kasan: Skip unpoisoning of user pages
Date: Fri, 10 Jun 2022 16:21:39 +0100
Message-Id: <20220610152141.2148929-3-catalin.marinas@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20220610152141.2148929-1-catalin.marinas@arm.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
MIME-Version: 1.0
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Commit c275c5c6d50a ("kasan: disable freed user page poisoning with HW
tags") added __GFP_SKIP_KASAN_POISON to GFP_HIGHUSER_MOVABLE. A similar
argument can be made about unpoisoning, so also add
__GFP_SKIP_KASAN_UNPOISON to user pages. To ensure the user page is
still accessible via page_address() without a kasan fault, reset the
page->flags tag.

With the above changes, there is no need for the arm64
tag_clear_highpage() to reset the page->flags tag.

Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/mm/fault.c | 1 -
 include/linux/gfp.h   | 2 +-
 mm/page_alloc.c       | 7 +++++--
 3 files changed, 6 insertions(+), 4 deletions(-)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index c5e11768e5c1..cdf3ffa0c223 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -927,6 +927,5 @@ struct page *alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
 void tag_clear_highpage(struct page *page)
 {
 	mte_zero_clear_page_tags(page_address(page));
-	page_kasan_tag_reset(page);
 	set_bit(PG_mte_tagged, &page->flags);
 }
diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 2d2ccae933c2..0ace7759acd2 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -348,7 +348,7 @@ struct vm_area_struct;
 #define GFP_DMA32	__GFP_DMA32
 #define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
 #define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE | \
-			 __GFP_SKIP_KASAN_POISON)
+			 __GFP_SKIP_KASAN_POISON | __GFP_SKIP_KASAN_UNPOISON)
 #define GFP_TRANSHUGE_LIGHT	((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
 			 __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
 #define GFP_TRANSHUGE	(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
diff --git a/mm/page_alloc.c b/mm/page_alloc.c
index e008a3df0485..f6ed240870bc 100644
--- a/mm/page_alloc.c
+++ b/mm/page_alloc.c
@@ -2397,6 +2397,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
 			!should_skip_init(gfp_flags);
 	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
+	int i;
 
 	set_page_private(page, 0);
 	set_page_refcounted(page);
@@ -2422,8 +2423,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 	 * should be initialized as well).
 	 */
 	if (init_tags) {
-		int i;
-
 		/* Initialize both memory and tags. */
 		for (i = 0; i != 1 << order; ++i)
 			tag_clear_highpage(page + i);
@@ -2438,6 +2437,10 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
 		/* Note that memory is already initialized by KASAN. */
 		if (kasan_has_integrated_init())
 			init = false;
+	} else {
+		/* Ensure page_address() dereferencing does not fault. */
+		for (i = 0; i != 1 << order; ++i)
+			page_kasan_tag_reset(page + i);
 	}
 	/* If memory is still not initialized, do it now. */
 	if (init)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220610152141.2148929-3-catalin.marinas%40arm.com.
