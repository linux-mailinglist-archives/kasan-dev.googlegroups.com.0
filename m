Return-Path: <kasan-dev+bncBAABBYWVXOHQMGQEJGWHKLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x638.google.com (mail-ej1-x638.google.com [IPv6:2a00:1450:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id BD6734987D2
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:07:30 +0100 (CET)
Received: by mail-ej1-x638.google.com with SMTP id 9-20020a170906218900b0065e2a9110b9sf2432066eju.11
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:07:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047650; cv=pass;
        d=google.com; s=arc-20160816;
        b=d4Xl0OVhoAX3Iy3+P8rb+leSC76zvkXjv1/YZ/24xmT0lm6g+ltrfAP8n+hr9aiWoV
         pcfaG8wrKcWCDaEEvkXhNzlUAtzhI5uDQBbJF2ZiC+t3KxHjWB1pQ84UB8g80I+FOC5J
         Z2h7GdaTJM79msxgNvUA5Aop1r+jNxlUVdXis5o3ehIr9YMkDOFEBCO1i8B4pbokel6d
         wzGvQU73HT0Poqw9165nk0XCP0EVEcEj44kMMRk2K12fkajxq2Z2pBrtmuLmL7JYEPSo
         XVXe0zYsDn1p7+O3QXDk0TfMNxDQ90v6wreMi+lmKgH0bkb5+NHVe4N/h8JGuWule95P
         Nv7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=9yn06oaXWYaa2XR7hCX/YRx0vH1zht4b4qGvCugA/Yc=;
        b=YDKZBUXDHuYM/YzD3yaVJF+y8KucsV10nwiPakoqnjylp6KCoqdGVLwb1T+l0fiSfi
         yz332fr9eEjkSeZ+8+TB+OeyRoOK3BeEguyZB4Z4V6xtiJEgEAU93vhKWW6hcv0jXBW7
         xodEO/N33x8uPGRLsU1XnUxORA2i6bVReGcolTHuktvh7Uz8E1avUshsRjUCpeAWHJSx
         V+M3dQ5S2fX60yWbTRhqYm+YO7AqUo1gDO7WDzHqLc7u66FBHoFtUBqg+2RajAtNMO25
         qkkP7BE+ki3UBk7ETZlzRZkmSAfewI94mg4ubMn/W1YXjgMZMBWdlmx5GNk4B7qagKyw
         3IqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h5KNT+HE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9yn06oaXWYaa2XR7hCX/YRx0vH1zht4b4qGvCugA/Yc=;
        b=kSv8QTQFMsxwMvV8SRH/eMDWQh9YleOULiXfJ3ZVqX6qT3pfhiFrHhYxxzwdMCqDWg
         T221clUCN7+ANK1rPfOY39sRCXrtLh5MZdSQ5Up6FM5IsKhMnDXSfHsa3OJw3OweotNG
         pghi1vpz6fwfiTg04YMmSxkSoPKdKR/QaAHLiCa5mTwHiTpMMFN/odi3L9Z27ProqhSP
         YzEFbAm9TVoQlrN4E5d7DAOrb7/WhnoRf6Q8inDHv970VqhbH7URDRZO7wHAndAVRsMB
         pvl8qfPu87HE+G4P9Lzht/nE6khh2UBiTWaype/s3G5Br8djJgowZQD9S/bNHCwwCqRW
         8pdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9yn06oaXWYaa2XR7hCX/YRx0vH1zht4b4qGvCugA/Yc=;
        b=mDY5T7A36ngb64IaCWlDCI5Aejk/A2iaNRv2ZeE3viE33NHK4CnwJprcdWxsaXuAtK
         MB4v/NawFOEjoyRpwS78yo9ejxW3WxKyD9qhkH9iEgrtrGVcAiS0UFOJPU/Zce833g9H
         I5IZ0uqz6rlRlJzz813ADqma2A6jewNeioyFuRfzbgI8wc9YcRbjYNsu958L/suHTPPn
         9SeOy3VPCHkaYLGK0uQFUzxP2GsX9g+4yGH1UzOffDZ10CwGzbR/8zvqco3ywpvP4sxd
         iI3DT3wHpztvpLXTYvND322JqJh9nWxufmeUgQwEK5riCuKGSfsPEWD1lzqi9zy3HN16
         b7tA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OUTz/S9JdvR4pNz8cgyEIv7OaXbb6G+iW4obTqQuoJDPeQyWZ
	J/XLQZpopPfMqKWyiXTC8A0=
X-Google-Smtp-Source: ABdhPJxIPyvKGZpwYFrVZPiIDcYfFxfw9UUHh9+cQZ9QiXSvHz0N1oglXBlavH7VgLCG32OXqGMa0g==
X-Received: by 2002:a17:907:2d2c:: with SMTP id gs44mr3541737ejc.565.1643047650514;
        Mon, 24 Jan 2022 10:07:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1b15:: with SMTP id mp21ls6544755ejc.11.gmail; Mon,
 24 Jan 2022 10:07:29 -0800 (PST)
X-Received: by 2002:a17:907:1c9f:: with SMTP id nb31mr6771390ejc.24.1643047649839;
        Mon, 24 Jan 2022 10:07:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047649; cv=none;
        d=google.com; s=arc-20160816;
        b=bxG3HqCKUHOmr7iH8a+q8DIgSrrtwPOCAvxf4+8p/fKoiA4JUMuTpD690i1p2eO52o
         bjhbbixQL+3LlZ+2UiOlRcXBCpRPkvhlUuIdC8BI7zIBUibqzNRozGKaYTmjtR29mcRR
         tZxUgXic5M3wR6YUlNarUqH/xlSc2Ev3wArxhLnjmWVpCfz/keib1F7uELsPHrMG/XJz
         pLunBXxWjrYeO+pkTxHacGvA+lek46bZFtp8acyvqwdsvOr4oO65mL2KU4fMxIh1upyI
         MRjG+hIfFtFunQaVabAlDaI4WzYs704tWAhahOkH2t7cUe2/1Dvpy4371NkN2ADDb/DC
         hUUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ypDUrRwpvHxVi9/0pzLPCyjGz64l2U6vLcrEu5OiSo8=;
        b=rjbtfPcJTk85Ee/DOtnqZM9JXn6Y8heEn31zmpprVxqZ6vlzCKSsc1VnfjnuDLWJSX
         Z+POaz3oMAMOblAcehb+5jnfBo6BjdkdWs+4I+zIl/ris2Zq5Stpz+W/+VaRD/OgNgeI
         XX0Mx4OgQJnjqNIaYJCqqyCPvd7DFNxaUM/qJ5wZS6xfhczff6qAVcqVAsVgS9pV3HUK
         ccQ5RILs3F6LGnzoafTnyYBo975+1SGypYVzfIiCuuDPshB9eBsHbOhimrYjK9qa26mN
         1E1edSdqNrQftKCTsffrcemBT8DYTLUXP01Lz3lXhFIVyAJWqXJgdoh2R/QNlW0RqQUt
         QMZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=h5KNT+HE;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id f18si551289edf.3.2022.01.24.10.07.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:07:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
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
Subject: [PATCH v6 34/39] kasan: clean up feature flags for HW_TAGS mode
Date: Mon, 24 Jan 2022 19:05:08 +0100
Message-Id: <76ebb340265be57a218564a497e1f52ff36a3879.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=h5KNT+HE;       spf=pass
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

- Untie kasan_init_hw_tags() code from the default values of
  kasan_arg_mode and kasan_arg_stacktrace.

- Move static_branch_enable(&kasan_flag_enabled) to the end of
  kasan_init_hw_tags_cpu().

- Remove excessive comments in kasan_arg_mode switch.

- Add new comments.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v4->v5:
- Add this patch.
---
 mm/kasan/hw_tags.c | 38 +++++++++++++++++++++-----------------
 mm/kasan/kasan.h   |  2 +-
 2 files changed, 22 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 6509809dd5d8..6a3146d1ccc5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -42,16 +42,22 @@ static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
-/* Whether KASAN is enabled at all. */
+/*
+ * Whether KASAN is enabled at all.
+ * The value remains false until KASAN is initialized by kasan_init_hw_tags().
+ */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
 EXPORT_SYMBOL(kasan_flag_enabled);
 
-/* Whether the selected mode is synchronous/asynchronous/asymmetric.*/
+/*
+ * Whether the selected mode is synchronous, asynchronous, or asymmetric.
+ * Defaults to KASAN_MODE_SYNC.
+ */
 enum kasan_mode kasan_mode __ro_after_init;
 EXPORT_SYMBOL_GPL(kasan_mode);
 
 /* Whether to collect alloc/free stack traces. */
-DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
+DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
 /* kasan=off/on */
 static int __init early_kasan_flag(char *arg)
@@ -127,7 +133,11 @@ void kasan_init_hw_tags_cpu(void)
 	 * as this function is only called for MTE-capable hardware.
 	 */
 
-	/* If KASAN is disabled via command line, don't initialize it. */
+	/*
+	 * If KASAN is disabled via command line, don't initialize it.
+	 * When this function is called, kasan_flag_enabled is not yet
+	 * set by kasan_init_hw_tags(). Thus, check kasan_arg instead.
+	 */
 	if (kasan_arg == KASAN_ARG_OFF)
 		return;
 
@@ -154,42 +164,36 @@ void __init kasan_init_hw_tags(void)
 	if (kasan_arg == KASAN_ARG_OFF)
 		return;
 
-	/* Enable KASAN. */
-	static_branch_enable(&kasan_flag_enabled);
-
 	switch (kasan_arg_mode) {
 	case KASAN_ARG_MODE_DEFAULT:
-		/*
-		 * Default to sync mode.
-		 */
-		fallthrough;
+		/* Default is specified by kasan_mode definition. */
+		break;
 	case KASAN_ARG_MODE_SYNC:
-		/* Sync mode enabled. */
 		kasan_mode = KASAN_MODE_SYNC;
 		break;
 	case KASAN_ARG_MODE_ASYNC:
-		/* Async mode enabled. */
 		kasan_mode = KASAN_MODE_ASYNC;
 		break;
 	case KASAN_ARG_MODE_ASYMM:
-		/* Asymm mode enabled. */
 		kasan_mode = KASAN_MODE_ASYMM;
 		break;
 	}
 
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
-		/* Default to enabling stack trace collection. */
-		static_branch_enable(&kasan_flag_stacktrace);
+		/* Default is specified by kasan_flag_stacktrace definition. */
 		break;
 	case KASAN_ARG_STACKTRACE_OFF:
-		/* Do nothing, kasan_flag_stacktrace keeps its default value. */
+		static_branch_disable(&kasan_flag_stacktrace);
 		break;
 	case KASAN_ARG_STACKTRACE_ON:
 		static_branch_enable(&kasan_flag_stacktrace);
 		break;
 	}
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
 		kasan_stack_collection_enabled() ? "on" : "off");
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 020f3e57a03f..efda13a9ce6a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -12,7 +12,7 @@
 #include <linux/static_key.h>
 #include "../slab.h"
 
-DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
+DECLARE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
 enum kasan_mode {
 	KASAN_MODE_SYNC,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/76ebb340265be57a218564a497e1f52ff36a3879.1643047180.git.andreyknvl%40google.com.
