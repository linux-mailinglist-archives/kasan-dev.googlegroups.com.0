Return-Path: <kasan-dev+bncBAABB3W24CPAMGQECLXBNGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 78E57681BC0
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 21:49:51 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id bi41-20020a0565120ea900b004d584f37a04sf6030117lfb.21
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Jan 2023 12:49:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675111791; cv=pass;
        d=google.com; s=arc-20160816;
        b=DfVkAFFCef8UfsSTLi3KIUGqsSybixsHR9R2Kt8x0byATKcAfbFHw+Zux3Iu8RoSQL
         Ld/8exmFpT59Y925Rp+7tc7lad3T+E1+M5UTDibqkEOhQKoFIlwnU75u1bsdoL/vD5bg
         E4iCExvJWvFD4mw/UBj+IgezSbjpghs0SGcZSVB+tYx65gCRAyoXllzhnzMwlJPzPi3r
         C5JXpFopmNdHv7Re17V+ZQtrGg/yc2cId7GiGdpCdBppDU1BLoM/ATlRCzKD3SYJOlKu
         Ffs4qi3CAWcNtXCFCHZljYr0hNXF/Je69FqUv6E68NPEuDCRZXkLcMcrv4XhIT3iKAJq
         B2cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CYAWKv/YTtD1OXqatJby+hfmtZWYdXvZ7VLCffFJNMw=;
        b=orqcgUn7NxthmbbjfJMCji28tn3RraaUgHVAOa3w6iSeaWqnJ6PbkRzEFIkbGivZzg
         R+TaJiYc2sKTEEBPN5aK4nGHJaU2XwPm8kUDCErgrbxsCu/tj+0eihwVHKYylZqinCMr
         X+F/cu56QttEOi1GbVMaIkJLYuglsUSX7RAY2D14wotYjToGsBfH2civJ/XFmWvxwCvy
         k1kMISgKabGVAWnSezSpWjtZ0XUa/uD0yRRJfffwEE6e/fJuL1/3wU/SBYSr45E3+zGN
         oQz2/NCLabX3vMdrytSGCDK1PywCDscOcVs4G9dK7/c+OQUJy+zgNuMcPGNCX90TiLab
         eH5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iZ2SF3e9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.88 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CYAWKv/YTtD1OXqatJby+hfmtZWYdXvZ7VLCffFJNMw=;
        b=ffu67lyV3K/aUTgmj+g1WK1xGY59alwGaGuvfmrcjm/gYrBWetabcJQQzvOQDIg02M
         KiHR7lxu8Y51VYDVTXtM+hRD/6wtczCd+jzRkR3ca3Svg8RMQ8Bc3LapftbkYwMHtDk8
         fFhKwNIy5ARoVabDbKPWz0UKUHCK1uofECiuPHu13yIxY2MqjzDnCHv4NjjKfev0ZVK9
         mmm+zdOnv2XaCEoAdu+GBuKziiQmn840+PH2hFcX9npwUxGLdNg5A/ywgTQDmwhb0uTT
         9P9aBkmn273HvBycAiX5iaLdmiRHieR7z36uInnJsxPfDSVZPyv2EEoT4ywKc6ZEXCTb
         Ovcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CYAWKv/YTtD1OXqatJby+hfmtZWYdXvZ7VLCffFJNMw=;
        b=YBz4KrnJx49ayywhfw47i3O1kWqnk991cM4kQ2+bgd4HzbCFGDg3KLGuaeJygrp0Dg
         AGOSVpj+Ti0q5qk+xyLfonQbzFRiyqVl9HEvLOWNfWTCLq1DmmhtPKRBUNlWcNsXO9me
         ggaWC+iaS4slDxK0i18hKthO0afCmkGipoUKHOmFeimlAd7eBJ9qwfGz0qUmGVbO0uMT
         oHtEY//D//SlSdaZWNQKNkaURmCAGr1x8Fcrbmk+K4jM6mu756B3jXREe2nJMo5tEzrp
         hc3mlvUvUp2+HdDuNTHlhbR9ya1wSe/V+JaI5bD3Jlr58bm0WasHnn2MQymWy//zOAk+
         BZEQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXcablJ8l0f/r0drA9wFB5nNS3U6smiEPz3FUXG6cfrtngwya/r
	BSToGhlh2LlInYZmOknIHdA=
X-Google-Smtp-Source: AK7set+TLcW5yo6GMaU2NcNwrmrfnEq8Q3utJ8HHgHhZtAPjHC8AMYOX1pXcHIUDY+HNjlEF63RBwA==
X-Received: by 2002:a05:651c:105a:b0:290:57f4:6275 with SMTP id x26-20020a05651c105a00b0029057f46275mr799455ljm.5.1675111790853;
        Mon, 30 Jan 2023 12:49:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2117:b0:290:6f32:2e13 with SMTP id
 a23-20020a05651c211700b002906f322e13ls142448ljq.7.-pod-prod-gmail; Mon, 30
 Jan 2023 12:49:50 -0800 (PST)
X-Received: by 2002:a2e:bc26:0:b0:288:adb2:3f83 with SMTP id b38-20020a2ebc26000000b00288adb23f83mr261578ljf.31.1675111789927;
        Mon, 30 Jan 2023 12:49:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675111789; cv=none;
        d=google.com; s=arc-20160816;
        b=ZU6HqM5tyil1Q/VSLQVXkNU/l3YpQZyMO/Sgw0CUw6HXzvqY6cGT45N2jpnKsK9GWf
         6a+jx6GDiwWRhnxD/xjR3UI+YsZTbg0Av7/mb4i74ue2vMwv6UEHP+zv+WOAzv4ajZ04
         lYcUoffaCgafhNht/TiKRU6Gnvy7AZEXdgtM5pvSc/ZRG45yp9uGHvLQ9U21goTiJ9++
         7LZtpH5RCPKQI4OEMlahPgy+8gy7LOLjMMDLd8QSH355ue48PsjFlO1T75cs1Fq1bfwJ
         czXoQ0ChvEtTzgAyEGfwGRWqiv43Qx52u2P52LtIAm/BH4KerNarzUSnNDfAhkU8bsw5
         /imQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=c95lndz29O0di2fe/164kz+dHAmKL4r6SFIURNRPYhs=;
        b=MBSf3apsabIM2a7ZMiYgZoVUXSkDXnIBscp3jZGwwfE0yu9tlxQw0o1MVMZAw5ykxq
         0GbbHyJa0GJYy9Sil2NlwH5M10GM3Wxa55xIwetY67X7fudSrCUCEhdLkYuzbF/D4Ild
         ywnTXGtbat24DM1CEVwDQySi4wSj8bYrgnJn9F1QT7sbLjlBiK9jpXBCslU2QuLPh0C1
         aQdFye2K1U591CwEnwk5KoPv5v+H6L4z/YXnhj8TsXxXLNRdYVnPNsTC0H7Pjjaj8Ibj
         /Z4wOv9ZEh124SfLB94LH3Wr7q/VK6JQjfjGLeosSADB+suMYU8bJ0FdzuDs/REJ7Ek1
         hZmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=iZ2SF3e9;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.88 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-88.mta1.migadu.com (out-88.mta1.migadu.com. [95.215.58.88])
        by gmr-mx.google.com with ESMTPS id 3-20020a05651c12c300b0028d0067c3d4si264509lje.2.2023.01.30.12.49.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Jan 2023 12:49:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.88 as permitted sender) client-ip=95.215.58.88;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 05/18] lib/stackdepot: rename stack_depot_disable
Date: Mon, 30 Jan 2023 21:49:29 +0100
Message-Id: <293567627b0d59f1ae5a27ac9537c027a5ff729d.1675111415.git.andreyknvl@google.com>
In-Reply-To: <cover.1675111415.git.andreyknvl@google.com>
References: <cover.1675111415.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=iZ2SF3e9;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.88 as
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

Rename stack_depot_disable to stack_depot_disabled to make its name look
similar to the names of other stack depot flags.

Also put stack_depot_disabled's definition together with the other flags.

Also rename is_stack_depot_disabled to disable_stack_depot: this name
looks more conventional for a function that processes a boot parameter.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 20 ++++++++++----------
 1 file changed, 10 insertions(+), 10 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 8743fad1485f..6e8aef12cf89 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -71,6 +71,7 @@ struct stack_record {
 	unsigned long entries[];	/* Variable-sized array of entries. */
 };
 
+static bool stack_depot_disabled;
 static bool __stack_depot_early_init_requested __initdata = IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT);
 static bool __stack_depot_early_init_passed __initdata;
 
@@ -91,21 +92,20 @@ static DEFINE_RAW_SPINLOCK(depot_lock);
 static unsigned int stack_hash_order;
 static unsigned int stack_hash_mask;
 
-static bool stack_depot_disable;
 static struct stack_record **stack_table;
 
-static int __init is_stack_depot_disabled(char *str)
+static int __init disable_stack_depot(char *str)
 {
 	int ret;
 
-	ret = kstrtobool(str, &stack_depot_disable);
-	if (!ret && stack_depot_disable) {
+	ret = kstrtobool(str, &stack_depot_disabled);
+	if (!ret && stack_depot_disabled) {
 		pr_info("disabled\n");
 		stack_table = NULL;
 	}
 	return 0;
 }
-early_param("stack_depot_disable", is_stack_depot_disabled);
+early_param("stack_depot_disable", disable_stack_depot);
 
 void __init stack_depot_request_early_init(void)
 {
@@ -128,7 +128,7 @@ int __init stack_depot_early_init(void)
 	if (kasan_enabled() && !stack_hash_order)
 		stack_hash_order = STACK_HASH_ORDER_MAX;
 
-	if (!__stack_depot_early_init_requested || stack_depot_disable)
+	if (!__stack_depot_early_init_requested || stack_depot_disabled)
 		return 0;
 
 	if (stack_hash_order)
@@ -145,7 +145,7 @@ int __init stack_depot_early_init(void)
 
 	if (!stack_table) {
 		pr_err("hash table allocation failed, disabling\n");
-		stack_depot_disable = true;
+		stack_depot_disabled = true;
 		return -ENOMEM;
 	}
 
@@ -158,7 +158,7 @@ int stack_depot_init(void)
 	int ret = 0;
 
 	mutex_lock(&stack_depot_init_mutex);
-	if (!stack_depot_disable && !stack_table) {
+	if (!stack_depot_disabled && !stack_table) {
 		unsigned long entries;
 		int scale = STACK_HASH_SCALE;
 
@@ -184,7 +184,7 @@ int stack_depot_init(void)
 		stack_table = kvcalloc(entries, sizeof(struct stack_record *), GFP_KERNEL);
 		if (!stack_table) {
 			pr_err("hash table allocation failed, disabling\n");
-			stack_depot_disable = true;
+			stack_depot_disabled = true;
 			ret = -ENOMEM;
 		}
 		stack_hash_mask = entries - 1;
@@ -354,7 +354,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
 	 */
 	nr_entries = filter_irq_stacks(entries, nr_entries);
 
-	if (unlikely(nr_entries == 0) || stack_depot_disable)
+	if (unlikely(nr_entries == 0) || stack_depot_disabled)
 		goto fast_exit;
 
 	hash = hash_stack(entries, nr_entries);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/293567627b0d59f1ae5a27ac9537c027a5ff729d.1675111415.git.andreyknvl%40google.com.
