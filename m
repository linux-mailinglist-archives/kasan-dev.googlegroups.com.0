Return-Path: <kasan-dev+bncBAABBBULXCHAMGQEVIGSTNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 46E0F481FBC
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:16:23 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id v19-20020a2e87d3000000b0022dbe4687f1sf5719205ljj.7
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:16:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891783; cv=pass;
        d=google.com; s=arc-20160816;
        b=k3F07Gj16EmHPlLRosDi+errbuUv4O88fUPj7mY9e+tLroBBTL+v3uWr1Py/W/68Yp
         MzNruXFND5+oBSIXrA5J1SbORKE+aQWTdlk023SLGxjwz49NuzoyBThc36NkspMTaVFY
         zbatLP1I8leOvYL4rrB3naZZPj8k/PlWA/PWTaIYF/OlLFqvHBLLNmDY2KUCcKQ2wljU
         zk5xFOFNtouD5VhvOXm5aUWPv/OT9w1dHAO98ky9P0zLuYe0SZIvZ24imwtgBi+SBCEs
         FX4ZFxI3YFuZSO4X55u+Zv9rW1KWbGUruPA/QtSsN0FzR6OtgJi3Z9lEeCN4ufYuNtrR
         Uq3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SbW++9sQL/tmnLWx73DkQWJYcMj2COERPa64hQUMUSQ=;
        b=dUXSMQefLXrzVhTNLbNTbKaNU+78/FahvE+7tkl+rV+x/8wKWQkEx/gs9lzJ1dYQ3a
         l58e6mtmd0704XgB/GPM1/LvhbRs0fFOe7CZ3m7j66ZaqxOei/aVDQGknJgXvUoRFqwz
         pQvfGawQW4/8/bHxlr3h9nYqaCkCtYNnO1nbYEyYcAWee6w6l/bZ7NIq2e3xWf7Qn0Pu
         hjoe6j5uEAiFFWNGkckLXFf2CJlwh8CP8L1F1NqJwZBmY+Q72ohh3VY+ltZ74p88ENsW
         rDjUqUlsd6exiYAd529e6TkkxlHU9DfijoST0+PqUI29qneOLgp6DaouTzUSpltBfS34
         pZuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kG45zin0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SbW++9sQL/tmnLWx73DkQWJYcMj2COERPa64hQUMUSQ=;
        b=nkSJFP2lTgh9Sef2fQnxXt2QBL0p3HXjqwhTmeOcqqO8OK2Z1JpuvHYzw9QwzZXOHA
         lbG7ekJHOzhfJPaqXBiLgXwvL9SKgdtnNhRzRaZjCviLz9XNPjGJf51eFwTtrtV5dCbI
         njjwqSVmm4TaoNoUfahPFDG2mAAZSsPrRYRDIG1P5okRHgYaapnDjJFjTVrE7j6GvI0W
         +PtORzDRJXHIHDUUwMyz9Vibg5fPjblrbOuuasGk5WXsDrWbYscY6QaUxLCJPU28T7z/
         P3tmzJxNHM3lBAmJgh8oGsuQnCqK6iEnu5W4kjOznV7toZfktv0KQQRB2o5HZne9CUfa
         z5Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SbW++9sQL/tmnLWx73DkQWJYcMj2COERPa64hQUMUSQ=;
        b=xritjwcxkQgs5coqnGoqOOO2TzZlJl3RiyVBuaGV0wcuReJlDzukO7M04fqsoJGF8y
         tOOF/k3AEVvrKqpXN6mx38+4PretexgjmZlrafTvpI4lGFDSk0P2llmgEphbard7+E0o
         CoLO1xCtlxDiaFjsCP3ovnmyt9S/GmbJx26yHs0sP7W4mjq14NkbNPvmbPL92cBbG285
         KOJNJ4HUHVLgMXGsuhlQEhoB0kU2a+TyeX5PGyhnbAKJ/cYp2c3w13NvjQ0QJuVMimFO
         E4kVxuFMCqzHdLuhVqLOWkDbaptM+RsGkcW7G4kEA9m/M6xzIWEVyJNODYRPlILzKd8t
         4stQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530R18xtFyW13nVpIj4OnA1WPxFPvEtURbLRGBjzLIoG0HBgym40
	0AcQnj8k3iLloqTLMwcOSqI=
X-Google-Smtp-Source: ABdhPJzca/YK+DF6Er6uSK8XE49/oS+L1zDLIdhfALEkVHIAtwuUkpKpkUan3JBm7Fq8TXKbdbwsog==
X-Received: by 2002:a2e:b0f8:: with SMTP id h24mr23810040ljl.318.1640891782854;
        Thu, 30 Dec 2021 11:16:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:5c7:: with SMTP id 190ls1650484ljf.5.gmail; Thu, 30 Dec
 2021 11:16:22 -0800 (PST)
X-Received: by 2002:a05:651c:50b:: with SMTP id o11mr15730551ljp.341.1640891782038;
        Thu, 30 Dec 2021 11:16:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891782; cv=none;
        d=google.com; s=arc-20160816;
        b=JrNzl410YjsepqbkfEwzbS8zbzjhFzgELdxou/v5FeCPk4OeyUMR6g8g5CxSP6k2KG
         r1P+Yd5ph7eizHoqWu92abFQWCcbRNXv407xEJGQd94oXkphRH5OtW1cbit5Jo5Py+PY
         Ja5yfy7eUnGHfPQV0tYxpdN/l0hTJQASOC+eO+2EdR3pTmOwRV7GIgXvzpU+OZuE5oMJ
         GDxwC/Qlvu6UqsrHXBn/whP7ampEaaX7/UtfCERVdQxYA2qDqusLmh2jD271CT4rAUya
         EzNhLwOqT7860mx5u1jAWBOXp0SozEQQ+15qCgkcHA6CF8Xpi3usnX3eDf3h2ZdoUaXe
         Hnjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5t1XFftR4v8UgokG+BYIbGPBYNE5uJ7BSehShZZUsBk=;
        b=nyCV/VSqQ8sh+2YHKVjcivuo+CCe8rVq9K2bas0CCKrPSxqYEwiG+9zmyBziIJvP2c
         Lf9W1RO+eAljuhsyzlBbp+JpT9LOa4wxSgrCURAmXnvL4A7Kj4wedufFBgOy7mCC17ph
         Yc+nSRIqokYXxw1EyBHlXjLtWes1WN3OgqhFFnC7AVY8gew4siTXWgAckzdKDF2O57hL
         lEjks14/iMhsaNZkg52+KbFG8WkytehUhBmQjzI5SOPjrhrq3tBRTKGAV9K6qDo0znMv
         ukbWMRUsif1mL+RBYcSXe9b6VbIh0bAc3ZngpVzHlmbSVAaabdApRF2p5YAP5nepEdxU
         5/UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=kG45zin0;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id r5si728640lfp.1.2021.12.30.11.16.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:16:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
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
Subject: [PATCH mm v5 35/39] kasan: add kasan.vmalloc command line flag
Date: Thu, 30 Dec 2021 20:15:00 +0100
Message-Id: <bdfb31e3f87560afb2a3f968efbffa995a28ca12.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=kG45zin0;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bdfb31e3f87560afb2a3f968efbffa995a28ca12.1640891329.git.andreyknvl%40google.com.
