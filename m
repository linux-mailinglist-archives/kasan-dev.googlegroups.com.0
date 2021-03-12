Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKHSVWBAMGQEVWSVXMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3a.google.com (mail-vk1-xa3a.google.com [IPv6:2607:f8b0:4864:20::a3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 85F69338FBD
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:22:33 +0100 (CET)
Received: by mail-vk1-xa3a.google.com with SMTP id l2sf7283661vkl.5
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:22:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615558952; cv=pass;
        d=google.com; s=arc-20160816;
        b=djqgZa+vgettYg8lz8X7yQQuxbwqhK0Ap5Pmok1A+q9TRRiomGilfCL7LLQcNjaLOn
         tk0ruIGAEl9C2uKc4EMo2QSYbyz3f7pBI6746dmVBvsc6vDSFs6YGMc7pGsm+KQYja+w
         jpuZAv6WxVfgDn0ykKHq4HuADzk4qqh+P+u0/GRt6XAIeCg4ywUcYeFbkfM8kgonqZC1
         bLLyko2VCSe9+SRCPa48cCGAL6WV0b/8jEU4RGQn/Y6XC3DWGrAMtDtHZdyw5Adn2w0j
         88iOOGtGDnYvD1IanQliTfOzN87nFjammQE3uKLcqC+4OZMImeqZ8CJ46V913OZ8uXkp
         HHwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lp8iqbVk2P/33IhnlXl5NQwGmTPmq2x/isLEpJP5S6A=;
        b=GAyaxvIWZpchUzU3XeaJQG1ZwHPxfCpn1MgkM0z6YX02GCzRyKrOwmotq4UQTXn5w1
         +4CYob1XtZm28z+/Higis1CxDqKv9vdlYpTKivuOVA0zFX7rrj5M9GxhSSVSsTxTLxdr
         qr6WmB2hmrhXL5mHen1K1oyuWfdt00TznBxSMDtpqIvns2ImJPt0Hasr653qadymKZtC
         f10GP/Nr51KIw6ShxCck6njERoXHUsk9G1jp1BkN2imaVzHmRtCIgkirQDdIkTIpu2BH
         uQIFZ8Gv5l4gLCAoCUiXrUdm85MZDw+Ghl+zsP8VsSC6DBAKCDlq/Oufn3kROaNu4L+E
         cwdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lp8iqbVk2P/33IhnlXl5NQwGmTPmq2x/isLEpJP5S6A=;
        b=hbgI7fgx81vobQJ+ZaYmV5YiOuZzUgfcibItule71zuEsAi4HkT5uAZf0SESc4xtYy
         Y2h1z22rpRiHGSeVXGpXrXERzWjJr8z2yZ7rxVBRoLDcL4vdeyF1c37uOV5A/7oGtoMH
         ip0M8nYmx6SlYKlizNZ9/0jClELq6zCDjHNSCQSSCB5c8kvSzombWr6rEctyJNAS+WH+
         0jH9W+J3SmUjiBAZlROr+HFOxmpEHwAdZbVBUtmkOI7pGexxao2VKpxUA4nzAu1vL+2R
         Obhcepla+4+R2jwUyk5tLl4b7CSa+vcbgkcJogLxKt9Tu+QBtlRNOaGpci5pgYs3Pahm
         s6vg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lp8iqbVk2P/33IhnlXl5NQwGmTPmq2x/isLEpJP5S6A=;
        b=hBbdignyvjgNop/gdgdmdPqoCubdeUjY6SIh7yZsa48W2Ppnxoc9R8L0HRi3LEOsVG
         7jwaV2vMQhUuIRHH9MIe/EW+3D465Bm7rzKtQEc+oh5ocYAdqQFjGx/Y5uVZ2zfMQFaK
         JzQCiaBj1dj+qnjtX4rD9+T47DBmgH95qDGVS+Pk0kw1zedJYocoX0SNBz+SdiQitktY
         DrKzBKXn0IXkZgN710bB61VQBe0sBz4u8eKTm/0MQ+EDsIh5sZgCdvN+KpN/ZLd7lhNt
         BqVt8edFy6h2/CwK/MroMkIBvczy+S2M/qIQ6eb/BGY/r+M+5dG68ZF3kj33scmKCT0T
         c/kA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532o4ue8wP0g3Gqrp1N5/zZSDG5MZfzXCr2lksqZDuXCadyUbgHx
	Zq8eouY0gTBf/CvKEx7uYD8=
X-Google-Smtp-Source: ABdhPJx70T6UwZnxKVxIK4bDSgcOGGDOwSCrMZsgnt5QOXIBTtpxGVn45k346AWtINqH2S7ZJEuZAQ==
X-Received: by 2002:a1f:2a03:: with SMTP id q3mr8252505vkq.0.1615558952567;
        Fri, 12 Mar 2021 06:22:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2556:: with SMTP id l22ls717839uan.6.gmail; Fri, 12 Mar
 2021 06:22:32 -0800 (PST)
X-Received: by 2002:a9f:25e6:: with SMTP id 93mr8120499uaf.57.1615558952013;
        Fri, 12 Mar 2021 06:22:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615558952; cv=none;
        d=google.com; s=arc-20160816;
        b=NgGxLSUMFSiwc0Z55rZG/v+Jpr1+xfVOTLOr884tICIs3jLCcCHztr+X8Ue/b+s70w
         pYWWp+gMh0zGv0yJgGEBTVOFzP8ddp5riSvVx3I9HMI+3Km40LOlECk85rYfXnNJntqA
         uqHBtRyxip40lVsacVRWyjJL/TMw4zvu3uXtf9zWouIOkdbgKd80cO5mwq+1L/MX5E22
         vgmibRaLzKCjQXO0O+xrva8c0r54ZiyyqD25Q5Ife5waMif3oqT+DGzaC64M9dlkh3yr
         ZF8EUzU6fuACu65rjKdHa4BQmmjP1gtGrVN5M9bXkLuYOR4aeFMq3pEETTDExXY5VX0l
         KAVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=MmYpqMXe+eRyA1cXnobNHE8eqwDI9XgG2X54ozugZkk=;
        b=PyrtO3PX9zeDF81m4913C6mlwEMDLiGOT/94D4ob6Yrq3PEbijVYpCoUA/2z0Vq/63
         BsvWVnvy2u/jz5WuGTJ4zc4MTsPLmwtDtWoPCv8Gk+29H+WRGIvaCYQ7gL7K9PEvrRDS
         KcyRJHN78QAzOaa/qiq5fJfdVoYdw+go2eoJSDQSh4XRQD9zSn5c/it9wisNbMT+V10r
         9r1lz0ISB3WDETShzD68oXJF9diDngSYTm8xtvAotXvJf/YDpz1mQ+/uxshjkdb672+k
         HnVZ75kvukppHFC6Zkst6H2SaA0ttF7znML8M/eycch75ortpm+ERSyCvtVUGkbWIPHq
         3mqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i8si348549vko.4.2021.03.12.06.22.31
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:22:31 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4FBBA1063;
	Fri, 12 Mar 2021 06:22:31 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 6D9F13F793;
	Fri, 12 Mar 2021 06:22:29 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH v15 4/8] kasan: Add report for async mode
Date: Fri, 12 Mar 2021 14:22:06 +0000
Message-Id: <20210312142210.21326-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210312142210.21326-1-vincenzo.frascino@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

KASAN provides an asynchronous mode of execution.

Add reporting functionality for this mode.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  6 ++++++
 mm/kasan/kasan.h      | 16 ++++++++++++++++
 mm/kasan/report.c     | 17 ++++++++++++++++-
 3 files changed, 38 insertions(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 44c147dae7e3..9f5faefd1744 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -377,6 +377,12 @@ static inline void *kasan_reset_tag(const void *addr)
 
 #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+void kasan_report_async(void);
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #ifdef CONFIG_KASAN_SW_TAGS
 void __init kasan_init_sw_tags(void);
 #else
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 265ad35a04ad..02957cec1a61 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -7,17 +7,33 @@
 #include <linux/stackdepot.h>
 
 #ifdef CONFIG_KASAN_HW_TAGS
+
 #include <linux/static_key.h>
+
 DECLARE_STATIC_KEY_FALSE(kasan_flag_stacktrace);
+extern bool kasan_flag_async __ro_after_init;
+
 static inline bool kasan_stack_collection_enabled(void)
 {
 	return static_branch_unlikely(&kasan_flag_stacktrace);
 }
+
+static inline bool kasan_async_mode_enabled(void)
+{
+	return kasan_flag_async;
+}
 #else
+
 static inline bool kasan_stack_collection_enabled(void)
 {
 	return true;
 }
+
+static inline bool kasan_async_mode_enabled(void)
+{
+	return false;
+}
+
 #endif
 
 extern bool kasan_flag_panic __ro_after_init;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 87b271206163..8b0843a2cdd7 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -87,7 +87,8 @@ static void start_report(unsigned long *flags)
 
 static void end_report(unsigned long *flags, unsigned long addr)
 {
-	trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
+	if (!kasan_async_mode_enabled())
+		trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
@@ -360,6 +361,20 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags, (unsigned long)object);
 }
 
+#ifdef CONFIG_KASAN_HW_TAGS
+void kasan_report_async(void)
+{
+	unsigned long flags;
+
+	start_report(&flags);
+	pr_err("BUG: KASAN: invalid-access\n");
+	pr_err("Asynchronous mode enabled: no access details available\n");
+	pr_err("\n");
+	dump_stack();
+	end_report(&flags, 0);
+}
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210312142210.21326-5-vincenzo.frascino%40arm.com.
