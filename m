Return-Path: <kasan-dev+bncBAABB772QOHAMGQELAHKPOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 97CFD47B5AA
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:02:39 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id v19-20020a056402349300b003f7eba50675sf8693461edc.12
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:02:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037759; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZTgQXAJxRJCvjfn+4JzLz/aB/WZl/+ioigUaqUTwY90ohGZi2VKYFWx8xkPOvLjko6
         cAkDbbgABJZ0ZZnVo4SknfNAFHRDeGkYaIpNW//eTHO7wL0OqGohmjd0LxYrIDSyorbk
         w0NtB37QjpqAgjFxrK9xJFc59WfNqdSl946oo4qeVk7BIdlOQpUzcmyjzfh8sAcqKgTC
         eYRntJS7zWAj4IbeRf2GUMrCqKx+QfZ6v9LrQmDnQICS6gTtSm3+L5x03RdbqSgMkhVE
         H6w3lOmy7jlpXss/JANbC6tGT7cKvBskiT9l24UgaCFL3+cMjzbJyOB7PT6nMba87zQe
         PlHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Nd5QDYZvBson2ytwf/EPP2k2kCWEv6EBdJY/BYkxzTk=;
        b=pzA32rg9AVObr0JjAKepFKlkWFYGnRHiLrQ0aURHIPRPgv0cGpedDHvrGL4SW9x2g7
         EiL+i9IN30iJOYQsRILWgbDsaOUI4feW8TVVIK86xu7fm4eyCxWQwUlsKz6gFzhFCbAz
         HUu+41TzV+N9JSJ4TkAjIgFoCksayRYPJQrB9ODLou9it3BJFd19CcFXMgU9vKthpbKA
         L+8fcO95OPitaR+CLlwAPmINmfBrn0FHKrJmU5X6fKfWqqjqupMPGkRu3lyFpgrLbYqk
         jCsk3+YFER5DwVwWQ8LrqRDtxZV1XRZXS3F10b7OVCCMo/GsUd5iz4eDiAmZA4dKVy/+
         N5Zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FynG3w6V;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nd5QDYZvBson2ytwf/EPP2k2kCWEv6EBdJY/BYkxzTk=;
        b=EGBQvNyf3pKPVnFFiibhjJgXWoP1FWNHEOpOzlf4XXZTJTvJRd49ywKEALDFDFpMAH
         aSYtOgBAL5pVe/aC/i5I2SmX+0aOGlAXgpO0B1pmg+jEqoSirSAGef4OZsPGj731LvrT
         FrtsiuDCHj9RfLCngXs12urdDe27scjSUk1zhI9uNFAh/Hf5t5aVh7E3ffhOTZRLfDMF
         8cCIZvjOK6wFrbEzvdOkGp2jx8sB6U3yK8nqgIZlOjePpz+Y9MYHuuSGZtdFGf1Gs8Jh
         z/WUgw4FwXV/zBj9jRdRXrU7e6nA3nFlljHDY5z+HZFzmHLsPN+0Lg8pnAhaXQztLUdB
         houA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nd5QDYZvBson2ytwf/EPP2k2kCWEv6EBdJY/BYkxzTk=;
        b=ttW0oxYSEnN3GbUg3082e4D7j+Dpe11C/WS+wAdfitJP1bUnH3jfeEmJKMqypiAd07
         1IIfjgTQwIUvXUtKECzpRtqIQeCPVxhLINmdPwv3XRQbtSkGPF68tigL6XHB3b9ZOW27
         JgRMmCKekHmH4W4hwOsNcmszqdH8U7B+vWl454zrBNfoSzJXHxSdr5i4MCxYpEI4vYDO
         HxZi7IQ6dYCzheafWeyj4TM0LknE8AdLgW4QnsuM8JuxBHdp2K85Lnw4/JXBcqeuUv2J
         KmOCjvmhqfAZnmIauVc+Gvbt/BAUF+lu6qGS0EXRXwDd6uzQYjo4XCbcd9c6sDrS8nAu
         cNlQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323edZ+CYXg752gLescP06AWbiYZJfke7natt2KOlyHMTLzZPmy
	chu/n39joIP+zQ+uWPFZZdg=
X-Google-Smtp-Source: ABdhPJwicAPE5aHrI52jSBS3yZk54rI1OzWQnFTLSIhtkGmKx9FfMuMsJ8TsXbO+ZqDqljGz7rU8lg==
X-Received: by 2002:a17:906:2788:: with SMTP id j8mr145904ejc.203.1640037759405;
        Mon, 20 Dec 2021 14:02:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:8a0c:: with SMTP id sc12ls2176094ejc.2.gmail; Mon,
 20 Dec 2021 14:02:38 -0800 (PST)
X-Received: by 2002:a17:906:1c51:: with SMTP id l17mr155614ejg.610.1640037758648;
        Mon, 20 Dec 2021 14:02:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037758; cv=none;
        d=google.com; s=arc-20160816;
        b=wWOnHJbiJdQnm7f2USBevz9h56QYa2CVCHAZ44jupo7iTBJmNWWYS1b/PA513wI/Rr
         K/55rDmhtkZ2dfYezkE35mkO8FKTEohq9cmL6po2e8kcRP1UcYjXJ8GBqWkVexsCHo4f
         WI5gV+wjMM+m8s+tDCMIlWXjzNfkR/QpBZ389VrYPxuIhQm2GcMuwGurtz/TL3WtW1NN
         Wmn+CzCXY62Sj6Ytf28Lw+fONkoxQIC9uBShu9uU0MetfZKxdBVtDJSD33lIQlpiQ5B7
         ydpShd8BM1z3/S7z09JK85IgtruUacrJ9iX34Y+RUKQxTbZaKbnHxqMCLEDPVO96U5+s
         OtQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HpThRSGWdOarJjOAX9kfY3aMgIuincihYZTBngAmaBg=;
        b=MSmVOpzhfx6eReF6K+TaiFqoIMZAU1r27qK2AU4gka9bRvj3UwvYtRO35zp/B/TSJg
         szvUdxAhlV5NmcFgA8jVYjTyIjNS98nuUP49NDURw+wToPvOBegSv3P1Y/77Se4ih8LU
         /oEMGDEenhZ8kzCp5aPetJvsQv8WZICJA6d2Sv0Dlzh+UYtmj+THPNqLVs7cL9gxDJfi
         OAsmhy6hAs8K0uwDAQwHVEFoZmrj7NkkX2u8XUPvYPZxpb+xvO7fRC9cb8NVichqpbTE
         TkRURcakGbqDjuOM6RuuCYVQY1kUPFxCI6ivbBysPymhM67mkfQmKWvE4LVof7UaQGaW
         MJEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FynG3w6V;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id fl21si1008544ejc.0.2021.12.20.14.02.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:02:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
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
Subject: [PATCH mm v4 35/39] kasan: add kasan.vmalloc command line flag
Date: Mon, 20 Dec 2021 23:02:07 +0100
Message-Id: <f7e26047d2fb7b963aebb894a23989cd830265bd.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FynG3w6V;       spf=pass
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
index 99230e666c1b..657b23cebe28 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f7e26047d2fb7b963aebb894a23989cd830265bd.1640036051.git.andreyknvl%40google.com.
