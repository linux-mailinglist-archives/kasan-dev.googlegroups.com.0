Return-Path: <kasan-dev+bncBAABBYMC36GQMGQERG6REAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id DEF56473708
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:55:45 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id l4-20020a05600c1d0400b00332f47a0fa3sf7025661wms.8
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:55:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432545; cv=pass;
        d=google.com; s=arc-20160816;
        b=csKLkvV82yqHUNlr/1eLlH/JR9jZE6VXaUesIebHF8nc/6jpBK1hYUR16L9wY08F8s
         z+EldNIPjnSe0t/W+vYkvua+dRqPicc3kay6dJMoKYNovON3YdKgRcoYgM9VkngryWAX
         Q4tCQ1SDpq0E+9yxQONyaOptBDAJXyyfvScFHuos/OnTxQ6pS1wsWRdf2AVwnic5eN9L
         Jcebzofhl6gh5yY/pUi9b5p7zjB158OF/ig/5OZQsIdMNvO6k39PMUKPb6Zgu1m6g4JV
         rfD+3RNDjxcTZQ1hfy9sAqvxau6VB3EqgkKMvOybmbTvX0VMYiZ54eV7xBLZaOwbJOqk
         gDNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Ofh3w0WsvxAhvqiuC4USqscjcpbrg5cKZeAFZiUkibY=;
        b=kjp/onYI6p4J/3HLbRHLbp7r0X2rnaWJX+gkOFo59KkPLwWy6ypaWhY1+keaSazbdJ
         U3paqxYUhmMAdi5Aocchchj6Cgo2hDWijW8ypxXZEZpQHzbiFPcKUp3JTctTZF18iMln
         U8tOzPOkC1dsPawmA5Bpc77hKizIsgNqzDX4V2fFp/Fhs3HTI239MYLP7WWvg3QsuQZ7
         d/6r3VBPDSk9fYhm/TvSaSueDIEJeqXVoqGg8OcMeW94YDJoP9FpQB4qWtPMEB+fdrDO
         TfhVdQFdh1tFNexTR82W/RozcKeZmCZhSRRjCcH522LgByFcnZQex3GXvPbjS63sEd2j
         gpuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tG0tV54K;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ofh3w0WsvxAhvqiuC4USqscjcpbrg5cKZeAFZiUkibY=;
        b=U7hRT/lMOJ9GwtEPEZt6nDQUZSpIP5UV4LxmcJ2dMpkwOkogkDT4gtAGw/lSYFhfah
         vPXlfxI1mXh5ijyhsBFLv3ImpTCRO6Eg43itWDgpGia23L+8Gnm3KwvShkJh0y2SS4Js
         Hd1O/6P7njsvwBfA0t7M+flCtbv9wV3/PG9zfeOQzN6Uq1kspIDTK/DDkEETnjPD1U6P
         zroBnmGvvB0FzQWSnMZstV95ljcs41JNlvxgm4prrhDRKut2PJ6P7AGYIJTuth3so+ow
         u2Z0aQ7KTrThOWF0tOVkTif5ISzCa/Dm+Luc1Q8bKrLL5p3qk6hSIOp6MrJpjmlh6IVj
         0BNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ofh3w0WsvxAhvqiuC4USqscjcpbrg5cKZeAFZiUkibY=;
        b=Y38ShRmVcGqJp2/oPKNcSME1/iOgZD/d7c7dbJPU3+bXSq4/LjUQx2m79cFYoJD8gb
         c4x4Tmx4cXb8NHeQwVazF+WufirjjJdY+Gm2kxkPcb+ANA4Dt6MbveXJL7gJAK9krWK9
         DI+dFzUrVXN3U54+FJhTbJBI/y4ZsH3JDg9160239SZLK4oTCTssqXRRmQYZumN2MgfT
         pi7GWC+UFXfIpO9JaRx4ehTkZYuAjiYqiOXGkg8RYBHXj+ccGxFGtbxP7Ri44IfW/fSa
         mJ1nLwdd5SeEQS6RglSPECODn+XKoCcW/VjeWOwV8eeDS7IzLT7Rc+EjBWvvs4ct00Mn
         WhLw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rwxl4TQpUWJiUtJppLjJNedziMj0dPxHRsmwRaJ8CR0h2y6hl
	1E/ht3RXQbRFIK+fapseiI8=
X-Google-Smtp-Source: ABdhPJzZFc8FaQopKt/+7v1xqPPp6tBBYD+vf5VV5wbYIaHsROWsDbtZ5qWMJhsIr6XriilEayPv3g==
X-Received: by 2002:a1c:7f43:: with SMTP id a64mr1672473wmd.133.1639432545657;
        Mon, 13 Dec 2021 13:55:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls504353wrp.3.gmail; Mon, 13 Dec
 2021 13:55:45 -0800 (PST)
X-Received: by 2002:a5d:6a4d:: with SMTP id t13mr1346770wrw.36.1639432545056;
        Mon, 13 Dec 2021 13:55:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432545; cv=none;
        d=google.com; s=arc-20160816;
        b=zi+B4ph3l2njO3DFSe5yMt71dh/uTp1x28tLd7QNXjGWf1yhqSv3oRCSZ7ZZKnjWsM
         JrTcI7RXMv0J+EQ+g/tt7FQ4S105rjSF1Emw8+n3FHH5DYngIBuVpB8AzgE/FcswLQLY
         tCpx8B++JrUfNV+fSWN8A/Hv15ozSBeBB/wfKG68CJsV8BxEge75Rcf88wOcqjAeVZWW
         0UjCW/wkGouLeWqb1zzR7itDUk5bav/Uap3/j4GlFqPs8ZTqGwmm1A9fAyQ2g63aivQw
         zPpCSp78iM7hRd05PDG3h7NlbmYirIUKsmuEZ3iplhhnd0/LjpLXVu6YkFJ47fN2OrPh
         oMBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MJ6pLYFtDT6V9GeNlZDhdEu/zisyD2kMmUYDiskQejo=;
        b=fvdjEuFPDMtSLYYH8QfETZFqWruP0tGWSXZBxYddKq3VWv38QXVMvzYLz4oXH8b98g
         JKM8Pb+v+X2giClSfgkb0zzIygwmWLiFUkZlTsjkPjmMp+2Juug3/hgg4nWY4hbA0eg4
         RQWZJjWMpR7N9TRUGgK8Iew1Xx3i4xl5/yvjKRxLaSeo4JDsVPgU6w3tGQlZerY8PCYh
         2QNzCt8zPPgu7eFaoZ73HTYCWk2WBpwi3Avj7v4ShxhCCci5sN/mlyFRjco0CaLunYmW
         bPEjW+Z8bRrxowGvwm5S/m999cr/9botpTCpYbCHFBn2/chCgoE/Yzazs4UB/Vz3YYP+
         CBCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tG0tV54K;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id o17si45594wms.2.2021.12.13.13.55.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:55:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v3 34/38] kasan: add kasan.vmalloc command line flag
Date: Mon, 13 Dec 2021 22:55:36 +0100
Message-Id: <3b5a7874cb4028dbd918b26e41c13e24cb2d55fe.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tG0tV54K;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 6f7ed8e3180c..a595f0d88f41 100644
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
index 020f3e57a03f..49a5d5e2e948 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3b5a7874cb4028dbd918b26e41c13e24cb2d55fe.1639432170.git.andreyknvl%40google.com.
