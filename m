Return-Path: <kasan-dev+bncBAABBHHITKPQMGQEPRFEWIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id A1FE9692902
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 22:16:13 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id k17-20020a05600c1c9100b003dd41ad974bsf3162879wms.3
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 13:16:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676063773; cv=pass;
        d=google.com; s=arc-20160816;
        b=UunKP+3MWRW+x8wN+v2ymxlPAxhiHymLbf8vNUGsITnvhK0zcncYeKvh4gzNJnANlb
         u762arVbuw3iLlzF6uYDCbJ0IiMDOXwpr9JvWScLpZ4BnO8/UJxf8jJ99KVtWo+qd8FR
         PGAFUzREu4d/0xMKMKH75lRzBvmS5APObGjAoRAYRvEnDV78TMEgr4nHP7rYbKexPa3Z
         bn7w28UjqgShSCaak988ai6MxN1LI2ffigysMliFKXi43vkmSzsxhRHBwTfEuSQoXKVp
         WUR7GsmFj/AmT3XwQvfgaX6+Yne3iz74gTBjQIWHc/mr15RPzG0mWT6r6s8xHUbStwDQ
         Kyhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=f6Z2GeKruW2sQAZDswt084RS2DQzcIZwj3dq2c9+Usk=;
        b=DbDLoleqLQgY0kf4g0y+86T6g7nz4reFgrzCTkS7rm0TOXaEFPvPeoETmuafMGerhf
         yqZ440rpiMdk5E4FLy1aVSeC/QsnGT8k+eHaF5Ioi5RGnsiZzwtbq/0SqRBVn0Ff+ecM
         RDTwwUDUJiYS3z88BUdpT5Wa3DQLtDeF2TjF+VNdoPKeSyTjHaDbNREmdWFNarCR/ne2
         /nZnyLRIcx9BhjKzFOdrDBIg8uhWjn0ISoj+kGz84CkBOLx9lkZTNrsI0g9+CZk0fvop
         8xME3m9lQ9lpyAR+AosdcZEmpIQvN0ILBWz38bSFiOi9+bBzKSovNvNqLwSQKcsmkPXe
         qcWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SbrBALja;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.114 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f6Z2GeKruW2sQAZDswt084RS2DQzcIZwj3dq2c9+Usk=;
        b=iyTqxR9rN/DqEDOA9qqrTKemAgGZSZfZ1y++CmL2WUdP77Wrd3Mj+2t6P4VOoa9lDy
         PSys72tzERp3OaSb9WpR1SkvyDIspIf6BRKh5t3/7hz+U788zjRz4LPbYdvC+1nW//s3
         tikldMm28vVS0o9pDYS/ochF+66bwvBd+dNSkX2t6EHqttef2e33Jk4BZ85/jmmiVHjJ
         6GyWFbvuV7J6hPcrFK3X/7yXAl4Jrkk48wwm6sjAjED6jtdMhABwDRdzIFNn/0dd0GEy
         y/NjWFV3MbLpO/lvu7f4uurkObi3DS29f6SHyNaZRkWWFfeb3HTE1Q/e27YlhU6o6MyL
         /oJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=f6Z2GeKruW2sQAZDswt084RS2DQzcIZwj3dq2c9+Usk=;
        b=wWsjJC9e4dbSG5gywujEqK00OAIQZQCAsWjoCDoTMoH2OQ0UmK/y7TC65MM/i7HYou
         MPldo/gsnJyCziwBDJrMNCoNAg0o2+Un4WTIMEEYU5lB5WLcVRyzYQh/1nWmOLe7Ls+Y
         r+sus4AKxEuBVaoVNdkW4fhS9rNvKjmHoWo53VBkl5YO5Yj2e8K2nJ+wJml1FKq5XJJw
         9gOJH2gEiiT2U5ntbDh9FNvja+rq4W5osn77sVXKjmt0W3ZhIFMKQrchtxjw64LT/DlD
         4cHBAjytaFw5sotqRrJipe7ArK5tuAKIKtUe2f4uSzpodhWymI4zp+T54H+H9m+S6dqQ
         8j3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVHWlYF3LPQcfMp1L+cLrDlr/UyAn0WRwbek6qitDfaYv7fvjMZ
	X9PpN1fgxS92qr7cGwZlt0c=
X-Google-Smtp-Source: AK7set8C5N8vW2KymhsWwbM6QCNofHyLuxzLViWLk5a64i4DLR2SVPLcOAngXUgceQbc0MkG5HI4WA==
X-Received: by 2002:a05:600c:45d0:b0:3d3:5315:8de with SMTP id s16-20020a05600c45d000b003d3531508demr1240802wmo.50.1676063773218;
        Fri, 10 Feb 2023 13:16:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:58cd:0:b0:2bf:ccef:53a6 with SMTP id o13-20020a5d58cd000000b002bfccef53a6ls2226199wrf.0.-pod-prod-gmail;
 Fri, 10 Feb 2023 13:16:12 -0800 (PST)
X-Received: by 2002:adf:fcd2:0:b0:2c5:48cd:2f04 with SMTP id f18-20020adffcd2000000b002c548cd2f04mr3081341wrs.6.1676063772132;
        Fri, 10 Feb 2023 13:16:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676063772; cv=none;
        d=google.com; s=arc-20160816;
        b=Vmdx8rWJIzkZM4HziF1kOSFDdRlH2Vi0HqrEtHrtoQDMj2sRe0701MrXZ2g0fHn1BP
         SWVAz4eZn4TamrV9P1aowrsl2flT3quILrNPjCi6jS9dhhjLJMbEv7IeT01qm7k3bJJ5
         akMOGzwtf8p/SCdI1bJ7p4x7xjh0rsBVhgIg/W5w5xBxs22XsbU812dy0xEWwT7rXZRg
         6B+Nc7LUjyE+j9BjKOa0jwe9pxllNqtj5XBHjiy+2MoTaTgvPmW33fMaj7VUqeIi5l13
         8lW7T3WHuXIp0a4kAWy4dL7V2nhAQZUVImRp1ZA8Gn83AbirQFUiKArBF1ppLpccjaAs
         Hn/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1W2C2HZe7YWsaOly5qIInZGLXczRmh4K22qjFQ2kImw=;
        b=q82jwLxzW2pMgFontH5q+t/Wp4eAKTBgmgXjcJls3SW5b/Dq0e+EqK3OJpBKJtCMkq
         yvB0dzjRxibZOEdzZhcqOQV7uHVP/yYpWYa+sm0/37uh1HV4KlXPFdmIyskRwqPDxcqt
         iRaHP/bakTp4BGYF/YWUyHSr7Z3+2AUqKPnOLJNke+R10e/F9zPsq5aXgcvoRmweoEwR
         JL4lzUkzJU2QeCxVW2Xddd8+X6ts902ygZYBL4mdPXpb4fWgKLoDv9wHEq/I9ZSFm6BW
         d+SPWz7Dx3CXyGWbzWzZh+HaYBqyd0z2B1zSXv9iFkvTLyCA1e+ltP07UMJernAgTK+V
         mLrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=SbrBALja;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.114 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-114.mta0.migadu.com (out-114.mta0.migadu.com. [91.218.175.114])
        by gmr-mx.google.com with ESMTPS id b11-20020a05600003cb00b002c547397a4csi169793wrg.1.2023.02.10.13.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Feb 2023 13:16:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.114 as permitted sender) client-ip=91.218.175.114;
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
Subject: [PATCH v2 04/18] lib/stackdepot: rename stack_depot_disable
Date: Fri, 10 Feb 2023 22:15:52 +0100
Message-Id: <d78a07d222e689926e5ead229e4a2e3d87dc9aa7.1676063693.git.andreyknvl@google.com>
In-Reply-To: <cover.1676063693.git.andreyknvl@google.com>
References: <cover.1676063693.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=SbrBALja;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.114
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Rename stack_depot_disable to stack_depot_disabled to make its name look
similar to the names of other stack depot flags.

Also put stack_depot_disabled's definition together with the other flags.

Also rename is_stack_depot_disabled to disable_stack_depot: this name
looks more conventional for a function that processes a boot parameter.

No functional changes.

Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/stackdepot.c | 20 ++++++++++----------
 1 file changed, 10 insertions(+), 10 deletions(-)

diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 136706efe339..202e07c4f02d 100644
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
@@ -353,7 +353,7 @@ depot_stack_handle_t __stack_depot_save(unsigned long *entries,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d78a07d222e689926e5ead229e4a2e3d87dc9aa7.1676063693.git.andreyknvl%40google.com.
