Return-Path: <kasan-dev+bncBAABBWEJXKGQMGQEWZAQJXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C210A46AAE0
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:47:04 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id p12-20020a05600c1d8c00b0033a22e48203sf469813wms.6
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:47:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827224; cv=pass;
        d=google.com; s=arc-20160816;
        b=gbKFM1d9k0pVXLvYrk0SFLI3gydZHQIBUqOJYWtS1IKn/txKzdUzdAGdbQhV1t06He
         M3w9Yl2hneLmmxlI9MVuE7Ila4ZItBiSXwYu3PG7wfr5LjCp1OAICyI9Mgk7pr7Qgj5i
         EOuA5VC1SmT6TRwM4E0kC3RUwnwmoz2xXzo9T0IfMLTutYk57MYTyCCYPUreA+tO6Wi2
         3Wv1Qigm3t2yMLzBZcNyYiDLqqahDdyDupfXa7uq5IpoPt+jlCaMmGeelfdbnV4ng8CN
         VgvoUZ+aAr+c8ziesUjTPZOYcSQwfFsErjd+m9/Pr0xpqI0ezdgQuG8tEQotsp+vW9Fg
         SYGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gfoC6vo7Lxj2YIEzRec36rWf+Rvx50Fs5Qbw9aXe2ec=;
        b=AbIm++jJf5iNDJJw6Ql0u6TsWOddomfWyUUNoW4GPOERQvDcRk0+qP4I83dE+axVap
         DURc+Agp7CpCymVLVurFcEbhzvCGQ0RBnFb7pv0rtH3HFbaQ3YxiKvYt/D4gjF6yOTam
         eECtUfnuH8waFZi+NtB6BrbsiRWAhnRa4i6r3Y3KS43jQYaCs41tcDElDPh9il5cMtL+
         YPNZy4SG1JbWNzEe5bMRsXUcSZeF0mE/B9oJGc1lz14Q7wMbhBzgCOWoExvhAbC2+rOI
         oeO2qsJrhxAf9jZ4B1TeH9nS7U2u4keJsUtVExzopVzfKM8Fjvj50v2S+LFh0GFeGg9T
         ek1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=m1+VKGi0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gfoC6vo7Lxj2YIEzRec36rWf+Rvx50Fs5Qbw9aXe2ec=;
        b=lAazDSgKyjDk2ryomS4Qwa0NGcTiJEoDlAb+mZbQuUNBpHJmqzxnVQvgjPFb/tB4TP
         xUlZL9MuYJiVdl9jiqHmNQcLlJb+X/yLuNWvS2yw9pglY971WAEnE6BBX/r1D4GDOCEe
         e3IPHurpq4V1Hjj5S9jnJYa9LzSfUVNRef4tm2Vh4OXAAuuqkGKYZY8gtHPrKqm9LynI
         RtKZHoCqNlG0y9J1aIbjpPgMyXKHR9siMU0NooBrOUotZejB/A5vhyMtUmJRUfH2T+vI
         brEuSl6Sj3JrA0R0FPGHRIi0W56FXd7bSR1J+mY27J7xHzLH1j/JPW2fqya/oLJTk2Zp
         4VHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gfoC6vo7Lxj2YIEzRec36rWf+Rvx50Fs5Qbw9aXe2ec=;
        b=EstskjaDeMjqzu0ac3MZUoWDrDbPDG8EJ9lJ9PUdVbEcAoxhv1fy6A0JVsn31HhzM3
         4ps7NXRL/XZTRlxHxY9yex9J2GXSLk30aBG5TOIHXxh50ZrFqPIm5iAqH8Ha1es//D9P
         EWyNK7ybyiBpM9OtPFQQkoCf2FwvbP3wl/RkdYlrRRwryaK9eSHYVB5U0PcMUZq6HReU
         svvaVCCXQsxxjDme8KTAi5WtwT9Z13gYP+uqtpxYoBleARXQIb5xQ2wUhmaRb2utQDZB
         cR/8JOYo04Stpx1vnKYyWq6qwNTHnY9J48cGJ2e5yXwAvEbLVCvq0JDXzxMfrVHCsm2J
         IfcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530mfaavUtJLs6Br1+awLNDcZEpXxKIMEvFbBZngeKYhTAo+Tiw0
	jzcWqkC91ybTKFL1r80130w=
X-Google-Smtp-Source: ABdhPJwbb64K0NESy6VtGc7WrJRlropjOM9P/JlZqgoVq7LbXd0eGKNhNHRDcHXZ0L0BRFrs8Y+VRA==
X-Received: by 2002:a5d:628f:: with SMTP id k15mr48442218wru.363.1638827224565;
        Mon, 06 Dec 2021 13:47:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls1152919wrp.3.gmail; Mon, 06 Dec
 2021 13:47:04 -0800 (PST)
X-Received: by 2002:adf:e8c1:: with SMTP id k1mr47422854wrn.257.1638827223950;
        Mon, 06 Dec 2021 13:47:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827223; cv=none;
        d=google.com; s=arc-20160816;
        b=lG/6J0UNMpspGTV/mqzHByd9LLs2A5jnmIDvEdKSMvRjV4rItnHVUqzmR6bd7JMS8L
         rg2SVPohqcRN9Zi51UXEdhkhgZaSpkJHHtwGrinD1BJkXWEtMTg2H5tIrNsV4HWJSQQY
         M6qWkiOkSU6ikIN0Vet3DbvlasFykKbSM/o6FAP+LmAhF5wVmbfopvT4Fldyr6fM8uPI
         A69kvy4gZRbYm30nO+pl2IU9JsN6Mf6GFYa5O0nnlodRvR4xtbcJH+oZW7StBoojlK9V
         WbGKXK3Zm2LbVbBeMZvV8fYE85Sea3W/FkDanuHiqvz2MH0SxB3E/gyW23ovDlt7Gp0i
         hOqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1+9hzOYxgqQnSoACXB+891e/bOFhsq8xWG50JY0SyCM=;
        b=KiEM0Vx7vBAk/U9//K2TQK5y/H4+2cJ//fKzZ6YEq8wFp2y5A7z7txafZePbafzbZ6
         VJuNblZQtseZDPJx6EoH1y0Zew9eGdXyBT4hzJOjsCkvIF1C5hwpJ+xfzLxpqO19IH2u
         dbWc9jPPlLVeJiB6EW7mdlhDtmN3ZX5GRzjxAUnwiQOMkFms4CukQI8+aRwiMcmCBUEo
         IbvE5XTimARbxIaVlAEBqFng4M7K5UsRaS9GhC2Yvu38oBjKw6bkxqK2Z//CP1+yiNqv
         PNx1sDFW/NsHyO/owNtTdqa8phBKPV+dhEpTFiu79SKQGYLmvB6DkG7vcM10PmkD9X01
         SrCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=m1+VKGi0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id 138si71088wme.0.2021.12.06.13.47.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:47:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 31/34] kasan: add kasan.vmalloc command line flag
Date: Mon,  6 Dec 2021 22:44:08 +0100
Message-Id: <eb550a3fb0787729406bf4de05d09607d57d3696.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=m1+VKGi0;       spf=pass
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

Changes v1->v2:
- Mark kasan_arg_stacktrace as __initdata instead of __ro_after_init.
- Combine KASAN_ARG_VMALLOC_DEFAULT and KASAN_ARG_VMALLOC_ON switch
  cases.
---
 mm/kasan/hw_tags.c | 45 ++++++++++++++++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h   |  6 ++++++
 2 files changed, 50 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index e12f2d195cc9..5683eeac7348 100644
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
 
 /* Whether KASAN is enabled at all. */
@@ -50,6 +57,9 @@ EXPORT_SYMBOL(kasan_flag_enabled);
 enum kasan_mode kasan_mode __ro_after_init;
 EXPORT_SYMBOL_GPL(kasan_mode);
 
+/* Whether to enable vmalloc tagging. */
+DEFINE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
+
 /* Whether to collect alloc/free stack traces. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
@@ -89,6 +99,23 @@ static int __init early_kasan_mode(char *arg)
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
@@ -172,6 +199,18 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
+	switch (kasan_arg_vmalloc) {
+	case KASAN_ARG_VMALLOC_DEFAULT:
+		/* Default to enabling vmalloc tagging. */
+		fallthrough;
+	case KASAN_ARG_VMALLOC_ON:
+		static_branch_enable(&kasan_flag_vmalloc);
+		break;
+	case KASAN_ARG_VMALLOC_OFF:
+		/* Do nothing, kasan_flag_vmalloc keeps its default value. */
+		break;
+	}
+
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
 		/* Default to enabling stack trace collection. */
@@ -184,8 +223,9 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
-	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
+		kasan_vmalloc_enabled() ? "on" : "off",
 		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
@@ -218,6 +258,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	u8 tag;
 	unsigned long redzone_start, redzone_size;
 
+	if (!kasan_vmalloc_enabled())
+		return (void *)start;
+
 	if (!is_vmalloc_or_module_addr(start))
 		return (void *)start;
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 0827d74d0d87..b58a4547ec5a 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -12,6 +12,7 @@
 #include <linux/static_key.h>
 #include "../slab.h"
 
+DECLARE_STATIC_KEY_FALSE(kasan_flag_vmalloc);
 DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/eb550a3fb0787729406bf4de05d09607d57d3696.1638825394.git.andreyknvl%40google.com.
