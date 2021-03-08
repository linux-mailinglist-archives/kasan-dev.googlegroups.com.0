Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBCE3TGBAMGQEAHPXOOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 852E333131C
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 17:15:05 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id z21sf7630575pjt.0
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 08:15:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615220104; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dx+3AKmCR/e7XyXuzXhFXUL86KPq2mV7tDi/71b1SuwVMUWEQgMY2/xNckZuZ27BkU
         xA/CBtGOcjw/UxWqDIIPml6iXZ0L2ZCdCLP4LEG3w8eQZ/baaUyZMSBZM5z0zZ8t5344
         XPiazPejFlMAOP6a1DfWFoa5o/t3xuHtRr7BsjZX2GaqHhjJN0bXHTHucbyQpJNuFM0W
         5TWGnw05gtcYqHLbCvn4AVjjSjys0NZzZ+Py4W8USnSJvIUzUk+i510AZfStRR5e8tT+
         SQmquL5XRUs3/l86cc708eRyMdSs4i+Aui/mmTfNzCw6XhEyFaqVr29/IGDiuejjmvPl
         skqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SvOaWWl459aELqXPXeMyob6Mckj+Aw9k1GZRRT9SftE=;
        b=VUsJEUD+5ZK2gnaWw6K4nj8FgLWJOE30MQA/NHt4LorZFDXfyjpZdJRrTmiilhClcp
         f5l2xKbv98KAaYxwEffUKBRgLkUCGLqNo7d7DNaUumLCo3Vdsvn54JQ5JdsD+64cc8iC
         Rs/YwWjWr+wIAf8aKDSPi0aZ8W5xOQmcTJ3NCVGxBTCXcndcz9Azu3j6efQLC3656HQx
         cBx1N8yvtD63fczMKDv8I3W/ZFw8FYkdTfDav+1oWr4/fvhNdeDJnJWaf/xU2eEEn8K3
         t73QWFTQEQxpHR89blkYA3tbZYoVw7UuMrSbiv+uxFiZm1CZFFxcSVekS8LI2gPpCB/q
         0Ubw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SvOaWWl459aELqXPXeMyob6Mckj+Aw9k1GZRRT9SftE=;
        b=bZobB9yuINMLlvinTeRfwhrFB7tRKn6OVf20HbBEvZT1spBetSzCJGUKECHMukDZ34
         hGvGzb990wosXkS4wrOONqOrMbEva0sxC1xZFtT7FdeUFMvBuxklV5JkQJSFGJI6gsYt
         id9Eltmy4Z0s85nI1xPDwcTSr0nHUcSoh2qqHMDuO7gusn1tP9R7z1g4pnVdbknXT7N2
         //djcL7vD9Q9a+1dphwRemKrwniuDqjVtir4tZJJVhJ5C44lKPiraAixhBG8B/+TjKTs
         cw/2Aw9IaSF7yp4FQmUe3uoJUghrUI/3M6CSzJBa6mCE2mlXiOTm0c4E1lpGa0S+5BKd
         fA7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SvOaWWl459aELqXPXeMyob6Mckj+Aw9k1GZRRT9SftE=;
        b=MuqFIVUhEK4JDWQOBayWMQNr2wObVRIPWxXOJHP8PXw9CwVEhyxXEkQntukcXBFt/M
         qlXiMU5QCHnIhwkpeRdpZO4/oJzEVnHYtOgsu9a1k5/Idh9LFZ7GfmDXXsX0wvKsCnGU
         3P2m3FsnOPU/U7ybxmPJYYQxGywFzTAy+Gfn24r1zVk2yMgFNP6nirS8xoNLOMimbwN8
         z77i94FOBSJorc2zws4bNlqrLlqGZRy3tvmh0bErpkpYTpByuHeSdBRoOdyI0ZK/rWd6
         dpy6+fPIVKCdDJROYF6p/9OgnuSMeY7HjCW8Ktnnn+EMr80ss7z7z80acls8hsgeliDO
         44mA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532XhaVfOALrdL6GzwujPgOuEsiyx9E3pmzqkBxLaTIOTxKcvg+B
	UB/9uhJqIZYYk0qjihYjpkg=
X-Google-Smtp-Source: ABdhPJxPR/ilgldtodAat4JxoEIuNT7RLjuDd8Mj7MPD7IjLk5xl0FeNJP5a6mljlJX3HgDs9GkvpQ==
X-Received: by 2002:aa7:90c5:0:b029:1e3:5e84:4a7c with SMTP id k5-20020aa790c50000b02901e35e844a7cmr21342038pfk.71.1615220104290;
        Mon, 08 Mar 2021 08:15:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2286:: with SMTP id b6ls6732437plh.11.gmail; Mon, 08
 Mar 2021 08:15:03 -0800 (PST)
X-Received: by 2002:a17:90a:1f86:: with SMTP id x6mr25011423pja.135.1615220103759;
        Mon, 08 Mar 2021 08:15:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615220103; cv=none;
        d=google.com; s=arc-20160816;
        b=ywJlMYl+d/00My9Q1fcHigcThrhgIm7LSnxGrZd/41znBRCjm7FS2ckhEQou2UCRM0
         CItb30Jmn9MNJdgE/NtIoXcevr4RjO0owFPx4n2qrrZmF51iVRS++4muWCJR9UBpm3vG
         t9RgdlB8eGPUabJwlWIXnfAnMYNc34pWApt7bL+yLmgG4ZqKM0gtFry2DKGnU9b4WZyy
         5eD7maFeL89bP10dtV9x7P0TqRWPK3Z35wJgVvBQWgCQjCCyvI6fYXYmCkZHUu6qrGb9
         70ZTrNtNRb54Vik9wXkNDW3XMRYOEWZ7Sa/rJH3BKD79CsD0yMRx/zI6DAIkCl77J6+d
         M/gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=eug/H07JpWZG7ubk/EDbiumTC689CS4QQkCG31pxd/0=;
        b=zIitDvibGH6Gs+9muYVqq7AUEsJ0vy2Vn7/PeKHoRJbIEVOZznLepiYMU48Msr39XQ
         cwuGbsnPho5QwmWNahT+A8OMfzLQgl0PRG64yonqGoFzqLSgxyTS7a5A4LyTKOi2hbee
         vVwzxaavk+FyMQe2esicVaLQ5L1jbEXthRIsPcEeGOXpfdDOpiAFvssRhrBN9oo6A1Yj
         CyKdygphSmLHRBJIoEWUpqQWW6rd43a+4/DvLGtgfzFoUBBThdQYN0JXhGOK/mSkj2NL
         3dPinv7r/Vsh2STL7+4ULpV0pYoXQJvV6no0dSmmPmikFtfBAiRjn4pxnfmdIsKJhwpf
         Zm1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j6si657398pjg.0.2021.03.08.08.15.03
        for <kasan-dev@googlegroups.com>;
        Mon, 08 Mar 2021 08:15:03 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5B3FDD6E;
	Mon,  8 Mar 2021 08:15:03 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 78A1B3F73C;
	Mon,  8 Mar 2021 08:15:01 -0800 (PST)
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
Subject: [PATCH v14 4/8] kasan: Add report for async mode
Date: Mon,  8 Mar 2021 16:14:30 +0000
Message-Id: <20210308161434.33424-5-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210308161434.33424-1-vincenzo.frascino@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
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
index 14f72ec96492..d53ea3c047bc 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -376,6 +376,12 @@ static inline void *kasan_reset_tag(const void *addr)
 
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
index 2118c2ac9c37..91a3d4ec309d 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210308161434.33424-5-vincenzo.frascino%40arm.com.
