Return-Path: <kasan-dev+bncBC5JXFXXVEGRBMUGS2NAMGQEJRLHR7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 021C05FB53C
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 16:52:35 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id f18-20020a056402355200b0045c13ee57d9sf4690939edd.20
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 07:52:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665499954; cv=pass;
        d=google.com; s=arc-20160816;
        b=cOMUh/HQOp7u+ScCvGpHIzlmxXEoMzmWzuqF2xT7p4Dy/4Z0431192fKosHCo3k5Lo
         /qDAIAyzd2WUOBHxXdU4wE07Nq9+v1FHICTrGRDfgcVJLp5467nSg8ZsFNlbng80c1jg
         MOxyTEf4jMWPpcxkVj+AQutuTFxf/FSegJobCGRqGxDrlpqfzEXYyVI4+XZu677EgQ94
         VqDZzCOKbKD9X9jYU6I/3zrCtiILMzU97n0jV415J3Cyi3ipjopeuv31+x83+BLimDVu
         4r7DYaTwO2AIde9aZMMX9Fp/Mb42vhDL660+eZ1fM0Frq+5u4GB208oRDxgHPWTrOX3p
         d9rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=agRoGns+BF3eQLxYQS6/Uq0wD1Fh7LDx3nUoupSVxPE=;
        b=TFBjbvisZwTaP04tP1i4VI7cYcv4gzKCOX60RmxJCF3lFcbQY+/I/1jASjWjs0fgId
         2dVoD5L4xqlg6FY5KntL5AWGLtnvsUMKwuXDW51hBESIZOMZ4XRodzJnzuJAe7Oz8KT2
         YAZnlB3HXYq94SZQlelbPwtjgCzgYXsRb+bDiTODESxw0KSrj+mj9HvHR1vHmm0w9Hw3
         Rsx36IkfwjTfaRboy2wAMjV0TY9iDjXHLDsNrZ7b9QyxtvD+E90eGt9m464GJ2bnC4YM
         HRii3QPIiWls8KGWEbbHijjspsKNGrHE8eKwW3dL40X1AYme2gMhPTAfYyzf3Z++8V3w
         u39Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QcMlDUGy;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=agRoGns+BF3eQLxYQS6/Uq0wD1Fh7LDx3nUoupSVxPE=;
        b=FdF4nS9m3vGKmOpwxDq6FGH5gcwA1ziDcelBniMmGXiKBr5LRlUF8XY8jSauDVSGbA
         nWn0YAU4XUvN84cPVCsStxuaj2CLEv3UKhWhR8l+OSkyjcHkUnDDsudHGgAdpXKYHiXT
         Dx3s98mAFM+q1GqPO03Our/p0vqujc0+KkdDKLfndgJxs3gVDjIUu2mDk6Cqrq+dNUW1
         6vdrP10i77/6Z1dZEz4DyZ2Ij1jOjhy7hV1tAnHiNFILam32et9DElsuRfwUf7ZLxze5
         qIomeC3JVRbvp13H/zKH/Vpu6T+Phld8z0lKt1+Zu+59j08tJDWsUrfXmpC4Qa99fkM+
         R4oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=agRoGns+BF3eQLxYQS6/Uq0wD1Fh7LDx3nUoupSVxPE=;
        b=VWi7IarjlvwevcGdPNjtZUnwD1RZ1Tm83uOFnQDy4/cV+sPoEar+++7hCOaMCalThE
         L/dt6/nQI0o8YZrFzcM88iw9AHm8Noi0+Z9sotLu1Kku5UpMKXK75kOFDbRVUWHB+kEY
         Lnhr2Tzp1/5Qz20dM9R1Dj+OtbMnLGMopVv8PNbqQXGtb/MlfxAX5kQYZXXJkjgNappv
         3OfuW0B5ci25ByOxWKRqNwmbYF+t8PgezOkXRUpmQpNvarM/2iW3MyGHBiZaiOhkmq3J
         ZXPQf2Vu3uUs9hVDjodXrw9m+TIjhoKnp8roKHqFiLTzcwit3jdzVj9O4T1VGUM1jUOT
         8P9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1FQsL7O9/CDsvYL7mehQiY2bkhpGVMBJugF0GZ21hOq0JN2Mig
	8Ue3xBiAJI3Lmujd72B5xn8=
X-Google-Smtp-Source: AMsMyM6kVXUK+ZZYGwx7gmKRWUy0htK4Yz5o7VFZLhMzK+Jz8r95Md7C+miFkmwCgwbXHd4jhd1/ew==
X-Received: by 2002:a17:907:2c6a:b0:78d:caaa:27a8 with SMTP id ib10-20020a1709072c6a00b0078dcaaa27a8mr6540591ejc.79.1665499954566;
        Tue, 11 Oct 2022 07:52:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:42c2:b0:448:77f2:6859 with SMTP id
 i2-20020a05640242c200b0044877f26859ls1360867edc.3.-pod-prod-gmail; Tue, 11
 Oct 2022 07:52:33 -0700 (PDT)
X-Received: by 2002:a05:6402:159a:b0:458:d744:8975 with SMTP id c26-20020a056402159a00b00458d7448975mr23369307edv.200.1665499953321;
        Tue, 11 Oct 2022 07:52:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665499953; cv=none;
        d=google.com; s=arc-20160816;
        b=KmeJBmjqDkWN6vhK8sWiZXWImPZktBe0zzAQsrnbwo2RgA0DPSIRWc9r65DvdnA+co
         2tQ4SaoCiEEo2sARvkmW3AG9YKpxUB343vOj2znoKgGWlS3T0TED936BUxjgDhNOYVeB
         tBOQmNw2ZBussrqZeB2iW5YoJpcxX92I9hkRvQfqT6Dxzs3HHPQVM4JvBiA7n1evMXZG
         3kyDigO+s6JMkqKtWEahhH+372+Vuq5QukgmKKsEPN7OC6GL9TELc/iy30Iu2b4uI8wW
         S/CJOo/4oNkPaP+/TxHZuhGENbdfpUbtLT8j2NasFVqGbtQyCI9/Cx0NSjHBxEOERJCe
         1vtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ZYKs19NpNds32LIG5eISO4IzsDRW1ep9Llc5g9G0PkQ=;
        b=MdH2g0fs3ZbHyndYOPRt6sysi3/M8srKBL2ju/RdptRxj8ooaDrQieNtRwbwnfAnKf
         sUzxglcLQrBikIrVbV603CL5OVXtrBerrAuvTi0pOuOpocIiMw6giLMOmF/vxaUWYHUV
         kVH4tFMaRwa60qHDgUa8RIXnKg6mYTxUDZZiUUxbKHaRdoOw+LQbXgho/VVxk4d0+AeJ
         jRWbfb0NissmKABUF+G8f0IoA2mqXRdjS2gMhhHZthKjt3VPtP2MOIMZx+UwxQ+3//3h
         a3Yg/nnIw3qSQocSAUHAXb9K6y0dQETHgUbIzcPX2+65hh8nWydeQoPVxA5nxexdEXWs
         6u/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=QcMlDUGy;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bc4-20020a056402204400b0045a1a4ee8d3si383993edb.0.2022.10.11.07.52.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Oct 2022 07:52:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 0CA2BB81606;
	Tue, 11 Oct 2022 14:52:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B3277C43143;
	Tue, 11 Oct 2022 14:52:30 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Alex Sverdlin <alexander.sverdlin@nokia.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	Russell King <rmk+kernel@armlinux.org.uk>,
	Sasha Levin <sashal@kernel.org>,
	aryabinin@virtuozzo.com,
	linux@armlinux.org.uk,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH AUTOSEL 5.19 39/40] ARM: 9242/1: kasan: Only map modules if CONFIG_KASAN_VMALLOC=n
Date: Tue, 11 Oct 2022 10:51:28 -0400
Message-Id: <20221011145129.1623487-39-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20221011145129.1623487-1-sashal@kernel.org>
References: <20221011145129.1623487-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=QcMlDUGy;       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Alex Sverdlin <alexander.sverdlin@nokia.com>

[ Upstream commit 823f606ab6b4759a1faf0388abcf4fb0776710d2 ]

In case CONFIG_KASAN_VMALLOC=y kasan_populate_vmalloc() allocates the
shadow pages dynamically. But even worse is that kasan_release_vmalloc()
releases them, which is not compatible with create_mapping() of
MODULES_VADDR..MODULES_END range:

BUG: Bad page state in process kworker/9:1  pfn:2068b
page:e5e06160 refcount:0 mapcount:0 mapping:00000000 index:0x0
flags: 0x1000(reserved)
raw: 00001000 e5e06164 e5e06164 00000000 00000000 00000000 ffffffff 00000000
page dumped because: PAGE_FLAGS_CHECK_AT_FREE flag(s) set
bad because of flags: 0x1000(reserved)
Modules linked in: ip_tables
CPU: 9 PID: 154 Comm: kworker/9:1 Not tainted 5.4.188-... #1
Hardware name: LSI Axxia AXM55XX
Workqueue: events do_free_init
unwind_backtrace
show_stack
dump_stack
bad_page
free_pcp_prepare
free_unref_page
kasan_depopulate_vmalloc_pte
__apply_to_page_range
apply_to_existing_page_range
kasan_release_vmalloc
__purge_vmap_area_lazy
_vm_unmap_aliases.part.0
__vunmap
do_free_init
process_one_work
worker_thread
kthread

Reviewed-by: Linus Walleij <linus.walleij@linaro.org>
Signed-off-by: Alexander Sverdlin <alexander.sverdlin@nokia.com>
Signed-off-by: Russell King (Oracle) <rmk+kernel@armlinux.org.uk>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 arch/arm/mm/kasan_init.c | 9 +++++++--
 1 file changed, 7 insertions(+), 2 deletions(-)

diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 5ad0d6c56d56..29d7233e5ad2 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -264,12 +264,17 @@ void __init kasan_init(void)
 
 	/*
 	 * 1. The module global variables are in MODULES_VADDR ~ MODULES_END,
-	 *    so we need to map this area.
+	 *    so we need to map this area if CONFIG_KASAN_VMALLOC=n. With
+	 *    VMALLOC support KASAN will manage this region dynamically,
+	 *    refer to kasan_populate_vmalloc() and ARM's implementation of
+	 *    module_alloc().
 	 * 2. PKMAP_BASE ~ PKMAP_BASE+PMD_SIZE's shadow and MODULES_VADDR
 	 *    ~ MODULES_END's shadow is in the same PMD_SIZE, so we can't
 	 *    use kasan_populate_zero_shadow.
 	 */
-	create_mapping((void *)MODULES_VADDR, (void *)(PKMAP_BASE + PMD_SIZE));
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) && IS_ENABLED(CONFIG_MODULES))
+		create_mapping((void *)MODULES_VADDR, (void *)(MODULES_END));
+	create_mapping((void *)PKMAP_BASE, (void *)(PKMAP_BASE + PMD_SIZE));
 
 	/*
 	 * KAsan may reuse the contents of kasan_early_shadow_pte directly, so
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221011145129.1623487-39-sashal%40kernel.org.
