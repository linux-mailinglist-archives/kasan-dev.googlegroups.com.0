Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMVR2GAAMGQE7NKNUSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 86B97308CBD
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:49:23 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id u9sf7843723qkk.5
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:49:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611946162; cv=pass;
        d=google.com; s=arc-20160816;
        b=KglUdXE/GPNJ9DEoJdKpFTQSYoxRwnqlDBlwLq4lcceQnXPY0If8ftaB3y9vRl8JyN
         Hp3SySk5WVNuP0RNddVTrDyqbIudc4ED01m1MW7eiRHIQzcuIgvSq2jmqDFN/oBdWTyM
         OmjOeSmlYXdjL3Ak6eYhuvo7n1SqOx7gJl4/kZFGe1wiIUeD3ONEX2XqehIipASzoE7y
         xK1PPv15CpGiPt0Y85a33J4Fl8NXb9bE3elmcvjlw7w5E3B/w5ONIJb/h+yQW9Fijnly
         SxlpVJFjhlr+bOOGAew54nTe11WojDD8MgEbzPEiI/QaJOFof74rTgE1sM4KlzOrgSJq
         5ltQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=dICaPCOlNPzWtcwp/FgCgvcmsXvf/SbkN2I03/gxW0U=;
        b=EF7WX1BCjHaBXFZFWAIrwRT3RrV8Ge5r2Hj91gOZaUGqXFYEVYMxIlJC/Bj5uGpCiJ
         0+z9Z+Mk7SaDjj1Qj56RBvZlC9RgPFiOwBb4KT7P45pgjSmAG7sv0XkhZ0iMIE4W/ZhB
         t5aaoK3kKtjeiEg2G2O2g66Hm6yDbF7yCfx5qNCVgVcJST0LRPgttzjGdGBlamqaS8F1
         ZpA5qFB6k+/vQpGZ0jeVloCkCBW5uArlgVkmPMyW4RhdpZYMwu1N3sIHxuiGbYZ/H6rC
         lYRG1Yx7B5d1qMlbRY6Fzi02m1pS2DvGmlYglTh701WmSUJl+/IseRTdTnUIYiMq5oCn
         dt+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dICaPCOlNPzWtcwp/FgCgvcmsXvf/SbkN2I03/gxW0U=;
        b=f5N6WWlEsNsLRFJStXSRkBpm0bfmEDbZsUpTtrQ5rTivQ+jpi1Icnk0Nz+IpWlLvZ0
         5hSGm+K+sgwWMNy/rKhUj+SVUPQrYFDsmtN4zY5oqMDEfET6AAxgJd6g2ic996gYkOEa
         JR622jDbRZWBw4+s333g4KK40dVYAjRbL9oEmgky97RaGEAQsA8fCHwOTMon6EGUHpz9
         XhhrKXE+XfK6xmmDtgiUL+rjv0RnASipX6fjsjBog7C0ERg9dmerZwKPw+RwPKmrax1f
         Umygk2tJMjJAQ0aafuH+4t2dWzOKLuwuEw6gSgtNtpVX6rqaGflkkjABOqP8GxXbDSoz
         zY1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dICaPCOlNPzWtcwp/FgCgvcmsXvf/SbkN2I03/gxW0U=;
        b=mTG9gFR9/Cbk3K8WYHSrwSJ8yW+Srmb382p/9k2Mvk8A7jpSYjdovHsoCbNPbjIqlC
         njMy6WOHBTu1j39Dm+R3Ccr9K6GaZ3ulZhfbbYpZpABbY8CgDNLebvTLBh4kgBY2c2fg
         PXSurs/dFbf5uDrNF+QZ4BOFiwcpg8UJNzBdWXMveesvey5PfoV2i39/VRsPlqPo3RPr
         JBaba/NOsVELIWPQVqSP9McinIt1zj9T5H92iZPNLga9rWvTBkx+QhOHQvUr2zAD3nFN
         pGzdolETaCrdhO8e21+am5J4zjDhqMB4toaVZkeF5TGTeuCI7tHlePpS5alC0VhEgQIA
         yvEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ln9GJLLCmPyZs+0V/JYwnZRcMAvq54a9yiHZ/pddDh/6M88Kk
	mAHSwi4YfxNJ63woPcR3Sng=
X-Google-Smtp-Source: ABdhPJzCrBwt8KTqkS3Hewacc8+QiaQW0xuv1cC9uK1BSSKxL65h4YP29l52nHHVw/6j+bKtnY3eXA==
X-Received: by 2002:a0c:c20d:: with SMTP id l13mr5268038qvh.58.1611946162426;
        Fri, 29 Jan 2021 10:49:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:50c3:: with SMTP id e3ls2482568qvq.2.gmail; Fri, 29 Jan
 2021 10:49:22 -0800 (PST)
X-Received: by 2002:a0c:ca8e:: with SMTP id a14mr5473389qvk.58.1611946162033;
        Fri, 29 Jan 2021 10:49:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611946162; cv=none;
        d=google.com; s=arc-20160816;
        b=032OyQodgngyjMmlKKCpzct8ox1X3v14Ox2Rjddd2OuCwHz1dwcTj929+sBRDtmrTG
         LwIN05px8XCsbb9CaydN2NoKV4mbTKcg81mEp1HvYMdTCpj+6ioA9chEjirXC2nIxg4C
         b4cRZh8NqXYIjMAZcfWYsJJ/xHCAD0fug/2azMlsLiKxfGilN6bNbkiRqlWxFkQ5Rqa+
         PDp6HS93mnUEoUe3sLsHzau6UqPe7WnUcMhmc60b3Atx/wl+Bm5pQzfvF+0p4rTRCY4S
         5GIMxpbByBf1SJjs7KYGLeFU1nd9WE1QxKRQ+91GSxrE59wCOBUzOo/tIzhlIs4ZNXxV
         RSdA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=YMYqK1ENWel4G9zza5hpB4nCKUhoQZPnm3ks/tGCA/0=;
        b=mOTlaacfqeJdNCGSO00My2Dte8rDBZ8R+ZRL9ylAaK68NnQJbHm9Oc1NZwfFutwRgm
         iD4QN1QQDcVNDdTFPXbB+PPnHT3s9eC7M9wzZAFuAKR9UvcFx5AIQncDltcOH5aitEWt
         AMAUmYr2gglOLwA70gWdgQ4If0b3oLVr8k2Mg0UGu7hTf12PV1BxnE/6T4d2YH9Vvm2a
         kGWOea3Bdfr704E1gM4H/1KoKghacTWNMHtyd/+ZtlC9pBLx5pXb+7AK/Z4wFFEKevrZ
         hr8rDWot2N6OA1+gHYO50G4MS1nAv4+xK4IpTEz0Gp6o1FIau/MwmUy9FEsWXlobxMC5
         W3lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z14si817528qtv.0.2021.01.29.10.49.21
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 10:49:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 49CC01515;
	Fri, 29 Jan 2021 10:49:21 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 821C73F885;
	Fri, 29 Jan 2021 10:49:19 -0800 (PST)
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
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v10 3/4] kasan: Add report for async mode
Date: Fri, 29 Jan 2021 18:49:04 +0000
Message-Id: <20210129184905.29760-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210129184905.29760-1-vincenzo.frascino@arm.com>
References: <20210129184905.29760-1-vincenzo.frascino@arm.com>
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
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 include/linux/kasan.h |  6 ++++++
 mm/kasan/report.c     | 18 +++++++++++++++++-
 2 files changed, 23 insertions(+), 1 deletion(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1011e4f30284..6d8f3227c264 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -367,6 +367,12 @@ static inline void *kasan_reset_tag(const void *addr)
 
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
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 87b271206163..3a73199c0f5e 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -87,7 +87,9 @@ static void start_report(unsigned long *flags)
 
 static void end_report(unsigned long *flags, unsigned long addr)
 {
-	trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
+	if (addr)
+		trace_error_report_end(ERROR_DETECTOR_KASAN, addr);
+
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
@@ -360,6 +362,20 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210129184905.29760-4-vincenzo.frascino%40arm.com.
