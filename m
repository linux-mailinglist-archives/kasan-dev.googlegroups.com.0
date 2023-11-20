Return-Path: <kasan-dev+bncBAABBMNX52VAMGQE6VOHPDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A30727F1B55
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:47:30 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-5079630993dsf4282904e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:47:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502450; cv=pass;
        d=google.com; s=arc-20160816;
        b=rucEdxRth5vdpdC9/MSZzTc2SXzpBgoY6NwpGLndiVGfNNOFzkF4+YAb4uOJT8Qo4t
         VDxXy7PZ+jdlkAWL0zSYR1oO9yBrTGPZCTEbpwe0tIq9FfxiICU85wj9yY2PCjKIenwl
         ybjX3g7hAktOEKQLUtRa9P2HIlC3dsSqMBajQ+9IvnjlZeT9HcJfSq6mVcuxdIdgSZdl
         jkxgn4dtv6tyBWQwI5PH/0cdEBbenEOEhAy/9nbLsPh6oTfnOJDQRsGbTfdvB+2Z8GFe
         QAGLkCPYuhmxKZhQLTdxAOkcRwbBZ4VjKobQO0vW7iY/bkfqUwXMWbgigxoQgLNFuoCU
         HgPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=goWVQ720N9VmriCgBUI4RpQ64M6VLpuzM7MxTVwO72U=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=KMOR2BTjsvYFBSU/ne5qTOkpDEF7skka2GyOnHrtUPru/vMUPnEzyjGLinTBu09yPE
         MAXq9xCBom64ERtswJp9kRcJ8v17YDUsiLjsqRq77q/Y165+oW3qircx6zx6ChdxAJRh
         AWSqFXBBZ1R7GOW9cTU3st/TGHFJ8PH6AFoH69iHjph8uJ7abqQRip7GRwEh758LMW4N
         fjSk4A0r8H9NyergWuBQHwMbj9yIZ2eqIJZDFrokXpkG3B8kr7SI68Y9DRvqVFV9V1rb
         589vabEeDeoPUhWH3bnmM/w9RGvDEVU0aFe6KKppAB7RlDxKgZbR1RMS0SH/L5N36JKt
         tThw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="bR/I30d5";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502450; x=1701107250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=goWVQ720N9VmriCgBUI4RpQ64M6VLpuzM7MxTVwO72U=;
        b=B3hoY0y65VqWlLL8KaCHNNlvkAKubMYBgBrr3d/SVixQbi4guqRBqvJSZsjM1zBqgX
         bCOGPXpP1ucBC6hi8TsG5ZPpZRWxlBh29GiBwOpXtAgSOffCPxwcHFCQ1NRHh8jDPEq9
         Gvu+p5uiy7vB4yV4B1wakepKR5z/wofpOd0Z9bu7XJ6JUGujZMQREHoxP2p+RQgWJvgC
         dmv6jwXMLp6OTfmrcp9GsAVvRJygsMoa7IkFdIAR517nvxM9kWPQ9EkfoAPSdRqYWCv9
         xy4K6F8LIDWZtXg2dvghONM9eiWQxjP2hVpesOzXnzTqxueuf17egTrNNdZ1uB9UQ/6P
         89DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502450; x=1701107250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=goWVQ720N9VmriCgBUI4RpQ64M6VLpuzM7MxTVwO72U=;
        b=ghKgLVMhqVznMCLJhyxBYfYKNNSxphmodg7mK6Zx5zZtR0+tnPglpKvksOmbSov6/a
         pBBNjwZI8QS49q4uYjnZe4ZbvLbi6BeVKVJRXk1XTNovwATWI7PfaIDmJyIYRSiHaBux
         VpTJSR/rWUi68jizbeZzTNHIPwD0IO6MtAsg6RPxiqPsUNrw4RJAUUdh/h9jlCFtHCiB
         eCs9wXW/u5VPZdRaYjY/saUxy8K2vQpLRm6l4wZmHpxjJxFdu/6nMvnvH8qTRVZUOMw4
         reiZ74xeAHXleeqUphr8w0NgSB9qtkwzAvNr0ZYfEmSSSkrbZnWJ8v9sTqYvRpMeliy6
         pUyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyLmOaabOBURMhHY7LXY9JDCZ6iQsQdT8Ppm22pGBwXjixmJVT6
	Js3+DhjzktILdoyi3xzCNhk=
X-Google-Smtp-Source: AGHT+IHsUfZ9C34BFBWNrxmjX1j/gjtexBe8w9aMIADrWgNVtvOBIvG9skuM3HdqQPRpPVn/gqMLhQ==
X-Received: by 2002:a19:5f16:0:b0:50a:a331:27d7 with SMTP id t22-20020a195f16000000b0050aa33127d7mr5202259lfb.33.1700502449466;
        Mon, 20 Nov 2023 09:47:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e12:0:b0:507:979a:7f48 with SMTP id e18-20020ac24e12000000b00507979a7f48ls106793lfr.1.-pod-prod-04-eu;
 Mon, 20 Nov 2023 09:47:28 -0800 (PST)
X-Received: by 2002:a2e:5051:0:b0:2c8:736f:2e52 with SMTP id v17-20020a2e5051000000b002c8736f2e52mr6077117ljd.5.1700502447704;
        Mon, 20 Nov 2023 09:47:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502447; cv=none;
        d=google.com; s=arc-20160816;
        b=qak5MXWk/g09h/FvWinKO1ZY2lxjcT+PJCLY/WiJZmqWVFMor0YB5bePikVXsybzOx
         T3Sf9XiHKoigBJGYVuYzf83ij9vnvM2bttvRtsKAhCmocaqd+rmLp0iIISEDGhi672DD
         5xdM/TpvIpAz9AlMsz26rHP4gtg7ViP/StUI964Mej9thHlXjeK3TY2k1Yk3P0NyD32O
         foggD2zLE+mLL1Q5m+8kKrXY9xhQfptX1sH1FZoNBWileCoOde85pTHaY/bew9Y3+SmI
         9sbRcc6DfBTNF3mb/0VVmrQLjc+FGQvfTtsDtIbRhIL3m0lDvk2ZpndQLMiDQ1CCOSd2
         PRSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9mwqfN/pqk9HRQ931HoPPP333OlumxbY++YPCTeY76U=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=HzALgAblI7sLiAFAkN9P5brRciDyPLIZkTqu1l+DTZVHObv9PUwgrCqXgmVDGO809E
         2Eg4XrEtGhyB0rLu1c492luahxMbuoM4I+JcvmxuJIGjHhWyf42PU4pTiW4DzEgPQvtB
         N4urURn4SBOc5vY5ErjhIjP3do2Wk86fzJbDGHsJzDz5PSQuxqdMItRvPygkkpzSYxQX
         Z6C8h7RSQ8JoRcv6n6WaH9PqLRub6AC+DnqyPCySsQPhrGBS/HIKohi8WYCGguLhFMqN
         uGA4V93itPeNbIOHhLRxzDhihvJo5xFm9kl5yKuEgjsaB//xhkJMpwDlGwzdxJmxJyjN
         zkDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="bR/I30d5";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [95.215.58.171])
        by gmr-mx.google.com with ESMTPS id j29-20020a05600c1c1d00b0040a25ec1cfesi535440wms.0.2023.11.20.09.47.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:47:27 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as permitted sender) client-ip=95.215.58.171;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 01/22] lib/stackdepot: print disabled message only if truly disabled
Date: Mon, 20 Nov 2023 18:46:59 +0100
Message-Id: <73a25c5fff29f3357cd7a9330e85e09bc8da2cbe.1700502145.git.andreyknvl@google.com>
In-Reply-To: <cover.1700502145.git.andreyknvl@google.com>
References: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="bR/I30d5";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.171 as
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

Currently, if stack_depot_disable=off is passed to the kernel
command-line after stack_depot_disable=on, stack depot prints a message
that it is disabled, while it is actually enabled.

Fix this by moving printing the disabled message to
stack_depot_early_init. Place it before the
__stack_depot_early_init_requested check, so that the message is printed
even if early stack depot init has not been requested.

Also drop the stack_table = NULL assignment from disable_stack_depot,
as stack_table is NULL by default.

Fixes: e1fdc403349c ("lib: stackdepot: add support to disable stack depot")
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 24 +++++++++++++++---------
 1 file changed, 15 insertions(+), 9 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 2f5aa851834e..0eeaef4f2523 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -101,14 +101,7 @@ static int next_pool_required = 1;
 
 static int __init disable_stack_depot(char *str)
 {
-	int ret;
-
-	ret = kstrtobool(str, &stack_depot_disabled);
-	if (!ret && stack_depot_disabled) {
-		pr_info("disabled\n");
-		stack_table = NULL;
-	}
-	return 0;
+	return kstrtobool(str, &stack_depot_disabled);
 }
 early_param("stack_depot_disable", disable_stack_depot);
 
@@ -130,6 +123,15 @@ int __init stack_depot_early_init(void)
 		return 0;
 	__stack_depot_early_init_passed = true;
 
+	/*
+	 * Print disabled message even if early init has not been requested:
+	 * stack_depot_init() will not print one.
+	 */
+	if (stack_depot_disabled) {
+		pr_info("disabled\n");
+		return 0;
+	}
+
 	/*
 	 * If KASAN is enabled, use the maximum order: KASAN is frequently used
 	 * in fuzzing scenarios, which leads to a large number of different
@@ -138,7 +140,11 @@ int __init stack_depot_early_init(void)
 	if (kasan_enabled() && !stack_bucket_number_order)
 		stack_bucket_number_order = STACK_BUCKET_NUMBER_ORDER_MAX;
 
-	if (!__stack_depot_early_init_requested || stack_depot_disabled)
+	/*
+	 * Check if early init has been requested after setting
+	 * stack_bucket_number_order: stack_depot_init() uses its value.
+	 */
+	if (!__stack_depot_early_init_requested)
 		return 0;
 
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/73a25c5fff29f3357cd7a9330e85e09bc8da2cbe.1700502145.git.andreyknvl%40google.com.
