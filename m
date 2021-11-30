Return-Path: <kasan-dev+bncBAABBU6BTKGQMGQENFLUE6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DD9F464107
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:08:19 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id o4-20020adfca04000000b0018f07ad171asf3855223wrh.20
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:08:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310099; cv=pass;
        d=google.com; s=arc-20160816;
        b=NUgj2As0kKC8XbekAR6Vp6L46yVrpBcoeYhPN2kUFxcWUj5uxzGiaAqIJDUGnfohhT
         2VBzX9fiqvhETAFxIxC2HfMzAXUo8i5nOIemkNYPL36Fh+VbxyikkT8Sg8S0Jw/NhJwG
         tC/BIiCBgyUQ8dpXJ9g1HZZmT6Jwr9iG0cRHvVGgIQgDGGg/XhsOIb435MtvjbSqonO7
         PqciFw/KF7/1VRSPy2QiWXEQj30Z5ycaHxSYqYDATqa8B50C8MJM4kzIk03OmACZk3db
         E9DHIlXjvBOfMnteY8qQhjzy1Sk1D1PWxrE0dQpID6+ddlnTNWo2/dsJJVc28hir9v1M
         DJCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=I3yaqJAO0znb/eGEI1HDiRagiUvu19r+cYyDhne4Hbw=;
        b=S2lmEt8LIYlnAlZ5wXlvb/VSa1B0q7EprFIyp0JDaV8Op4e0VPQFVRvimfiOGCism9
         rQDwJF74nsAbs2hyq1g6etyfRpWTYdUKL/q/TSsryqNs37dk3UaqauOW8mx3Bf5aRfZM
         U5+o/XqFg4jiERhGpEJzVXs2i4BdwuY65dbBH45BGo2w3rraxsoRA04jpnldOfjziLx4
         otMr/8pD+l+tMxQF1umo9/iSW3ZIM2Lp0sj8JqvAJrhLZ71/HWU2CPKqq9LeTVuAiZ/2
         Xdm/dlm+2VTtAUdZ8vASvXMQAlyXXSYTT7n5eAl5pVl9S9m8j6etzzTlML0MzhndNgzm
         wYkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HD4yVRk2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3yaqJAO0znb/eGEI1HDiRagiUvu19r+cYyDhne4Hbw=;
        b=tSSLt8ejZQm1a1s70/f9MmR5YeJdtC6LspgEn89I3l0dnis4ha2e5iMu3vdGPiGFYQ
         aMgnwwRuUU7q+uh4/k+/5qV0ctI1AqObVf+W07pQN/k/fA38SRrjFTIDzyL1yhmexUTs
         90BcvQgH2xutpwvU6HgWBQa27d77wKz4nt+2ETxrWXQUf7Uz26Yz2a4T1czHuz8ep2ku
         +/0za51jpy4oSgxJX6Z59g/jvufqU9ZRHhq4vnjca7YnNCBGzdiYrfTyDxMi1P6M2OOo
         Cue9nHxHobK/X6PdsHSd3S/PUBhkRMBQyOAwCPeAswpRGXnMEowtBG8OngcGBHghzHtg
         sMrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3yaqJAO0znb/eGEI1HDiRagiUvu19r+cYyDhne4Hbw=;
        b=HAXiXqUNlVRv0OCN4GbhygNrXvNThZvqTdG/yJSzxwwRnoSUMzqttDZ7dL0F4U71yU
         /6XJ2TuJIUqdgVpaH1to7koGyXKGO/ewRaOwwJx7WNstYJ1sWCmTZJTOIpJxsRTYuUQ9
         H44esucd8MMgz50zbH5hnIa4s10Xz2FW18hfw5PFqOYLeCZYXr/baM7n3h27wqTkvIrn
         whOw5i5+D1bnNLhejY2B/6yvrO5l17469zNLDd8f9T0CqyuE2zmxHW6oL7grGv7plB/D
         tR47j1CUwADt3igTYIMGrkeL0V+S8faJm4xwBXvPS/hYO3auZtwBTaefgDPVhmGqRrU0
         /nlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WYglNxD0V2SQAFBr1JKRn2+0v/FLKJAaLwD9wM//+55IXMyqv
	0a8atK8jOIhyjCQ4Fg1mwhA=
X-Google-Smtp-Source: ABdhPJysUpMVy596Wl1q0hm4OhieV3NH3E68LEG+o5V3iD6KjkOqFfgCbx6E38Vhm12xVWbR0DUlpQ==
X-Received: by 2002:a5d:68cb:: with SMTP id p11mr1947355wrw.262.1638310099331;
        Tue, 30 Nov 2021 14:08:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7e16:: with SMTP id z22ls2135827wmc.2.canary-gmail; Tue,
 30 Nov 2021 14:08:18 -0800 (PST)
X-Received: by 2002:a1c:4303:: with SMTP id q3mr1808079wma.78.1638310098655;
        Tue, 30 Nov 2021 14:08:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310098; cv=none;
        d=google.com; s=arc-20160816;
        b=Wp1rZq5HNE+RFoKCSHoDLs0f2O30q8cWVLM4gYkXxbZjkMsDqa3qSZeSII3YZkwo1z
         b8wK2DgJH8C3DrZbcU1L1J2ywCKmKfWsjTZxwfyYRAiprKpN2dZiKdQ9a60a/pwFzLrK
         YCHTk/YMny4LXlPa4X+hxyskEyQYuUtTYM19u9sXVvvjQAXsIXXXaogNNKB144LD5o0X
         bVrpui9dflsScXe5iWYyK3t6Byg0bHP4F6x0kddRUYuzBoUvJJJ7bVUV2vNvMSCxeb5Z
         lOKTn5fyDAhk1zKm/e3hGgPF6VmqIKqSx4IWua5kFhMPiDnEY8q4S85cOLcws1h5sHI1
         A7mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=I6urKhfqw7JpSyBvAL9pvvA3mZVZS1PNduDQn1CKZuM=;
        b=qHK2QiE43iAigsq1ilkjKe563wySLQjAuTeuGQMlOPa7xXxUZBQcZ0WPTmIYwtggtb
         luj/y1NtLIxe5tenVlSQAusXPoh2xD2NiH1z5rvlDc2VIbtSS7KzvyKto6bGflL8J9sD
         Pv4iOpkQIxcnIUK7vPz6q/B92+wHJ9AN/8FA3Jgox4DFqexHeMIku97sHG5Ql6YG44v6
         fqI71vHDrDtlOG5v19A2DiDpe3EdveGQeeiOVfzFXteGP73CXn2KecgDaLJBSN89laOH
         fCiTW5MunALyAsU657slFlW5foIEWhtizUplC2eBXbX/3TxAvGtXMNxvFnm2vS4tbcLs
         44xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HD4yVRk2;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id c2si689229wmq.2.2021.11.30.14.08.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:08:18 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 28/31] kasan: add kasan.vmalloc command line flag
Date: Tue, 30 Nov 2021 23:08:16 +0100
Message-Id: <b82fe56af4aa45a0895eb31f8e611f24512cf85b.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HD4yVRk2;       spf=pass
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
 mm/kasan/hw_tags.c | 46 +++++++++++++++++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h   |  6 ++++++
 2 files changed, 51 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index fd3a93dfca42..2da9ad051cdd 100644
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
+static enum kasan_arg_vmalloc kasan_arg_vmalloc __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 
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
@@ -174,6 +201,19 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
+	switch (kasan_arg_vmalloc) {
+	case KASAN_ARG_VMALLOC_DEFAULT:
+		/* Default to enabling vmalloc tagging. */
+		static_branch_enable(&kasan_flag_vmalloc);
+		break;
+	case KASAN_ARG_VMALLOC_OFF:
+		/* Do nothing, kasan_flag_vmalloc keeps its default value. */
+		break;
+	case KASAN_ARG_VMALLOC_ON:
+		static_branch_enable(&kasan_flag_vmalloc);
+		break;
+	}
+
 	switch (kasan_arg_stacktrace) {
 	case KASAN_ARG_STACKTRACE_DEFAULT:
 		/* Default to enabling stack trace collection. */
@@ -187,8 +227,9 @@ void __init kasan_init_hw_tags(void)
 		break;
 	}
 
-	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, stacktrace=%s)\n",
+	pr_info("KernelAddressSanitizer initialized (hw-tags, mode=%s, vmalloc=%s, stacktrace=%s)\n",
 		kasan_mode_info(),
+		kasan_vmalloc_enabled() ? "on" : "off",
 		kasan_stack_collection_enabled() ? "on" : "off");
 }
 
@@ -221,6 +262,9 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b82fe56af4aa45a0895eb31f8e611f24512cf85b.1638308023.git.andreyknvl%40google.com.
