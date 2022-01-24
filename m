Return-Path: <kasan-dev+bncBAABBH6WXOHQMGQEJCKTKKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id B057D4987DE
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:08:31 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id d140-20020a1c1d92000000b0034edefd55casf5055741wmd.4
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:08:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047711; cv=pass;
        d=google.com; s=arc-20160816;
        b=yd7B8fSVh4WfulKkPYL9XNRyoArJwfuQCCqXhyKqCuGOve9eB3rzrlxs4LSI4K/vD0
         kDeb4R87NcMUc/EEMhDpiv7LnEqcbJFMQZkC3MhTBTGdl2zbx3CUklMVciP8zs8aQXe5
         8oVMfvEMNpci/wMbz+bLsKd3j1ZX0TJWgPxnBx7TSOUWNHXLJHyydgxZw370RnfEu4UB
         Y2sDyNKlfj26ExxJUXjEIeRbdZCW171IRPJPT7GPIzpctZPWk7W6EXM9AsvyxM26W/QQ
         wSFrztQ7F15SRdaOKljAxah/CjqWXEPP3RLPPYv7dIYaXfyKezwdow4leyRXrXPaaE2C
         5YlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vjeMUR7ygSlTNk71aauAX8KFNJXTb+leXudv2KI2hSA=;
        b=eqgpeI0uWoXCWZ7NiKeEn25wGAvvroRKii7NEIu/sUKmrp+CUipo7hRKoQh6Hvgojx
         WJP2+sKDoC1M/hIrSTy8hArj7P1kWkLUHkLNGztEve/coCnGh55901al/ExUqmNZTacJ
         2em2vmuoYO2KIaMhuljLcLiOqEK0oX5HCqLSgVnftNnHQ4QiG0nbLKAMmfl1aYJmgiAL
         BLFPgPSZvcV3sKOBCOdoOWYUQ6DALj8hQWPZ93GTrZmwlLAPNEXArNBGcnOJTUbbRbA9
         n08U6RDCofHqnYH24jDkPMnUtl83jPmIuUjQd/FoLknqAfL8WXh32uIJphnyMKeTBmPk
         On+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BUKLmrXv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vjeMUR7ygSlTNk71aauAX8KFNJXTb+leXudv2KI2hSA=;
        b=oReZUMjHRXV6XKvNQDeKDIgaGQ78tUMCE0ns0on20WnmMUod5DF8dMiE5Fk/Hm7QAU
         cK5mNEdkWN2LSx15jXCrkAodcFxU/U/8LBmqepZc8oacwS/ypdCW0EY/JHubJ2lSjaUy
         K3TW16DL8kk5hU2uhGDGC2MLmr/SzBnPhiSZNt6qOS+AD+ENA7PP+1p82asZVX4wY02w
         zVxDC1IE12abkXXR2yWpsLyag6vGUKMcChffanoUKRtaQjc7G3Z0fax4pmrVLXvA4KYn
         7/QR6v7DhQKPvL4IIqHQT5mgvYjSXMzeKquNWd5kvZZTMbb1Z7/Xy+WhsoMzThd/BQcr
         0Kag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vjeMUR7ygSlTNk71aauAX8KFNJXTb+leXudv2KI2hSA=;
        b=t/RxYAXqnSi/JDUW9ygVvr9bPmN1iQJC0ssX5/UaK8obQChcH15NaU3H/KdApAkF6U
         GpMaXQpUJbkpkhgnUjwczFpK5WaX1g09mw+77YDCsckpb7Y/kJzS+5nt7Uky5uniJ4ZK
         7MW/HGUpfUPjmHk3uDBwDYHDje9nkzvoglDDKm6Ru0sMkdqAzofiNxg3UoZV1T0ys/ZM
         YmLLtDX1IKxk+ZxoXnYJ55Ai3Jogu3gmeDWX51NkENi/MToej9IT1pwYl1SbcKiJ4iyj
         2fAFIPuc/jZy85+DuSsy0hE5hgbXza7nGo9QZTUBapPBjwgwPN2hpy+cEnUU4G+TvwlP
         vw4g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530vUIhWgXRwvjxt6wZILh6Y49oE7JSk+gKQ3yjNwjVGtDmnJiXz
	z2p9fqWv8/CXAhBRiCYw/XY=
X-Google-Smtp-Source: ABdhPJyQQpp/Lr9I6Bw8p01qH066oHTGTZLvM2wEaZDrs4a/B/6aKFiT2sVyQtTFlq6al1HrooaY2w==
X-Received: by 2002:a05:6000:18a2:: with SMTP id b2mr5974960wri.282.1643047711511;
        Mon, 24 Jan 2022 10:08:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e390:: with SMTP id e16ls306549wrm.0.gmail; Mon, 24 Jan
 2022 10:08:30 -0800 (PST)
X-Received: by 2002:a5d:61cb:: with SMTP id q11mr11694807wrv.368.1643047710822;
        Mon, 24 Jan 2022 10:08:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047710; cv=none;
        d=google.com; s=arc-20160816;
        b=zdQ8CWNYm3gr0ZnW+bXlFIFEYEq6HbWXTjeU9YRw0mEfmSLg9wW64RvBI2TobSFnlr
         /nrIEQOH7Y/HEUYnT0xblr97O1rsCV+4D7QesRfzgaa3YqOUbfYlzWxUCC5vRSFoRXCo
         he3nv1dbHkPu4rQWwmIB2mvRcNZf+DLPGPqLO9Zl+3mAjvYBVFCJO9hb3LmwNYSpurrp
         Uvh77Wj3Xiug5FlNOplXMbDY3Ga6S46i/0SFs6+VhY3kkhlpDK7oQCKSXKFFX1oW+uTi
         sB74kLHsq2H29iAvbme+stkMw+wXnktw/z5ohfJmO7PVJuVZdjwhD0Rl1mzB2CTUYLwB
         ZTmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5t1XFftR4v8UgokG+BYIbGPBYNE5uJ7BSehShZZUsBk=;
        b=0nNbd2y5a2vitzrwvDH3uALMgAZZnvO8c5YO12pcRvxq12KzbCHyBI+VBB2b4w9W/+
         5omBWSm8a38NJe4ziyV2S4whbDZssnibrVYBY+LSPcNjXpKVod7mBcE8sUTOwj8SrhhY
         pgvUkRzOW9WG5JMIOGtyAzEytL/0YSn8u0joCLtmDK9X+PxaQmRNtjIhpVURYpDCFIzv
         UkQDkAW3BvBR9vYfWanUuduu0DIToL1o1knBd3z1GVPTzBnHIg7j9VmiEbXGeg236vBp
         X7Gl6ZMsPQneIiLn0F7mzaIElevkcpsWbiVQqf7/nVTifWrpn9vbIYorhfuvofRjyaOm
         w8lg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=BUKLmrXv;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id p4si1745wmg.1.2022.01.24.10.08.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:08:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH v6 35/39] kasan: add kasan.vmalloc command line flag
Date: Mon, 24 Jan 2022 19:05:09 +0100
Message-Id: <904f6d4dfa94870cc5fc2660809e093fd0d27c3b.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=BUKLmrXv;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

Allow disabling vmalloc() tagging for HW_TAGS KASAN via a kasan.vmalloc
command line switch.

This is a fail-safe switch intended for production systems that enable
HW_TAGS KASAN. In case vmalloc() tagging ends up having an issue not
detected during testing but that manifests in production, kasan.vmalloc
allows to turn vmalloc() tagging off while leaving page_alloc/slab
tagging on.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v4->v5:
- Use true as kasan_flag_vmalloc static key default.

Changes v1->v2:
- Mark kasan_arg_stacktrace as __initdata instead of __ro_after_init.
- Combine KASAN_ARG_VMALLOC_DEFAULT and KASAN_ARG_VMALLOC_ON switch
  cases.
---
 mm/kasan/hw_tags.c | 45 ++++++++++++++++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h   |  6 ++++++
 2 files changed, 50 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 6a3146d1ccc5..fad1887e54c0 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -32,6 +32,12 @@ enum kasan_arg_mode {
 	KASAN_ARG_MODE_ASYMM,
 };
 
+enum kasan_arg_vmalloc {
+	KASAN_ARG_VMALLOC_DEFAULT,
+	KASAN_ARG_VMALLOC_OFF,
+	KASAN_ARG_VMALLOC_ON,
+};
+
 enum kasan_arg_stacktrace {
 	KASAN_ARG_STACKTRACE_DEFAULT,
 	KASAN_ARG_STACKTRACE_OFF,
@@ -40,6 +46,7 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
+static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
 /*
@@ -56,6 +63,9 @@ EXPORT_SYMBOL(kasan_flag_enabled);
 enum kasan_mode kasan_mode __ro_after_init;
 EXPORT_SYMBOL_GPL(kasan_mode);
 
+/* Whether to enable vmalloc tagging. */
+DEFINE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
@@ -95,6 +105,23 @@ static int __init early_kasan_mode(char *arg)
 }
 early_param("kasan.mode", early_kasan_mode);
 
+/* kasan.vmalloc=off/on */
+static int __init early_kasan_flag_vmalloc(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_vmalloc = KASAN_ARG_VMALLOC_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_vmalloc = KASAN_ARG_VMALLOC_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.vmalloc", early_kasan_flag_vmalloc);
+
 /* kasan.stacktrace=off/on */
 static int __init early_kasan_flag_stacktrace(char *arg)
 {
@@ -179,6 +206,18 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
+	switch (kasan_arg_vmalloc) {
+	case KASAN_ARG_VMALLOC_DEFAULT:
+		/* Default is specified by kasan_flag_vmalloc definition. */
+		break;
+	case KASAN_ARG_VMALLOC_OFF:
+		static_branch_disable(&kasan_flag_vmalloc);
+		break;
+	case KASAN_ARG_VMALLOC_ON:
+		static_branch_enable(&kasan_flag_vmalloc);
+		break;
+	}
+
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
 		/* Default is specified by kasan_flag_stacktrace definition. */
@@ -194,8 +233,9 @@ void __init kasan_init_hw_tags(void)
 	/* KASAN is now initialized, enable it. */
 	static_branch_enable(&kasan_flag_enabled);
 
-	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
+		kasan_vmalloc_enabled() ? "on" : "off",
 		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
@@ -228,6 +268,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	u8 tag;
 	unsigned long redzone_start, redzone_size;
 
+	if (!kasan_vmalloc_enabled())
+		return (void *)start;
+
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index efda13a9ce6a..4d67408e8407 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -12,6 +12,7 @@
 #include <linux/static_key.h>
 #include "../slab.h"
 
+DECLARE_STATIC_KEY_TRUE(kasan_flag_vmalloc);
 DECLARE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
 
 enum kasan_mode {
@@ -22,6 +23,11 @@ enum kasan_mode {
 
 extern enum kasan_mode kasan_mode __ro_after_init;
 
+static inline bool kasan_vmalloc_enabled(void)
+{
+	return static_branch_likely(&kasan_flag_vmalloc);
+}
+
 static inline bool kasan_stack_collection_enabled(void)
 {
 	return static_branch_unlikely(&kasan_flag_stacktrace);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/904f6d4dfa94870cc5fc2660809e093fd0d27c3b.1643047180.git.andreyknvl%40google.com.
