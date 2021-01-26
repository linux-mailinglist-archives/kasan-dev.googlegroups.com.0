Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMF2YCAAMGQE6MTSJNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id C9182303F26
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 14:46:25 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id q13sf2631007pgs.6
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 05:46:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611668784; cv=pass;
        d=google.com; s=arc-20160816;
        b=keHyAYE6z3xw5ywnKZQ9Rx3vtNk9ApNU3qdAPkh27/N26NObdk554ErizB06Dyox1/
         i46yVc7AfIHWLjEwapM5rQ6z/fXh+3YvtdY/i7rqBqpfwuc30sK/RCKy8V4LfOeT/skD
         MazZkbZgAzI2zvsV++5yqF7ya9niPG3wmi3Z2V1XBtDO3FQpG3aVAeHGwH4j87wm0Etj
         uESAQP9JlYFhsJCTSm/ZATTBosu7porKRrIdL8bFwxOGzGCU4rAQaNx55y+Q+Rdpte9B
         koX1DmbocQeO7MXJPiqkIHxnL9h3HALH6qLzdwJCvEd/4bD1JmRL8Vx991NN4nncwFzg
         w0Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xEuCMGp7Ai/32aopU9hFPj95Y7MDQAfY7eYEEeUQpkk=;
        b=H10qLGsn/8q/Oh76kM+WRR48dQUkqUS9ILpL6kQmq3vc6p8qvuXLGt6bXP0kP8VyXd
         OtazrCS7xlyThJo41I2t9NcWsZSRgn/XH3mfjZiw5OSmxJmLvRBEXFRd3pbrh4YnWNAF
         AkkpBiSNWJwhi3vUUaeXy6ohcJY96jvKqdS3lmCbTCbaoZkpabvdcsVtkw8fonXWRt6X
         9fMrXp0YER1BypPly8T6dGCxex+wSwv6DMs0sfAeEmJN2kkenhLYGTYItrqOrTVYGZJn
         04jeaf433PVLq541R3qMMcToRbRvKcuUS7jPfv5ANEbwClWjwb/JRffceGRlqcVFSQZb
         9NWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xEuCMGp7Ai/32aopU9hFPj95Y7MDQAfY7eYEEeUQpkk=;
        b=bH+VjUmQ27pwjof4knVU55KNiNpN7je8bJ8n4dscVEv+8lgdgnpdB3mIq/zUwjMale
         og/Bgq8SvvquDGuDsliyKiFZQaZ/0zt29ehSCUgVzZW/HzUt9au0b3ns4VDugCUR7UpU
         Sr5LTYt3cn8Nepi0GFh8k9ZsKAXb1pqgVGNPX8QO/rfI+Tnh5qagVbiB8actuvrjaROO
         YST7ygy3pKe/JS9g4uDxtQLRYK1r1kqWobCVEQG/at9ZWiCghMqmBGFr7GQJM11x2GwE
         I80IXvNu8bO4kvxB6nHzcv82mJ0C1QRowCsmV649fkPbQbBqxJjAmPwlo2RxGxD/6ZrP
         sP7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xEuCMGp7Ai/32aopU9hFPj95Y7MDQAfY7eYEEeUQpkk=;
        b=CmGw3uf2giixwnaoEDg/QSvgsGoyVjN64eXZODAOUjEOQ67nh3tcxIAyUxPKDSKh+6
         cKbJTNwAyEokAG7z7FppJD7Gka6qohyRyrXbHD3VxCBnb3SXQsNKCzZGUls1dudEPPlK
         SUdUthW4+OYYwq0+0j2p/Deuh/j6iyv5a2oAhxrYEp1YYR1CbLMduDOWNWtN0wHElofY
         QXUlc6AbZ/jzwH3BQ0YSmx2na7+Bji/wLPIJmDwZNE1iB7C2XqR21kHqfrEFo9po2PoU
         LAb4yUuanOC+xnynXl/EYuvlMt0Qge9iX3SUTUWgRiRsFdfWACrgnPfVKEkV9TODCtdV
         CB6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Y8Nb+9iWEhqLdPhCgGHFL7d6TlVDNrGgu+8FNECYsREUiO2hj
	Zt1TEP9gNC7ExXug3iI2oxM=
X-Google-Smtp-Source: ABdhPJxEI1OfQr5lbXcBAgYaMNf0C5HTMGSnTB7kjWqbQKguQaqjFMZlJMBXYVVkEZ/YiTnSi7G7rA==
X-Received: by 2002:a63:f218:: with SMTP id v24mr5730572pgh.244.1611668784216;
        Tue, 26 Jan 2021 05:46:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:778c:: with SMTP id s134ls3013469pgc.0.gmail; Tue, 26
 Jan 2021 05:46:23 -0800 (PST)
X-Received: by 2002:a62:fc84:0:b029:1ba:9b85:2e92 with SMTP id e126-20020a62fc840000b02901ba9b852e92mr5310998pfh.38.1611668783485;
        Tue, 26 Jan 2021 05:46:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611668783; cv=none;
        d=google.com; s=arc-20160816;
        b=WFCGdP4TjigLAOeegiTxIlmVJYYpiSkwWyPebmDZRsK7tdJrj2YO4XO+l8cd41ABQb
         ZNKqULpJb8m1swKetvSKjiZS2BAIbQOPrqUG3PmdhJj9dnY0bFmhX1p0Aj+qVLFlhWTy
         BrpKNObMlgKS4AGdiG42JX5LPjihaecR6o5ALAGsYVZeXIVIQ51b2/CozpyqcWdeSGDj
         /XxjqAaPMjRpr0N/MWE3/ycnuMixDol0v1aWCIsVdhW1C/ggp17mkCq55w7fzRp/Di2j
         VwsF3KYkQu56BP7ly3mlM2I+Bs7nfBRzfspXCXu1gapFzlQaM2w0342WyLpIiZvUZn5S
         Rb8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=9a41Zh1J44i7qGcPqzQ3xrwe9QCgt9EiGPgCYWjTe98=;
        b=Ckp6lUkNJr7x3O7KlhU7xQO4xjOBBMX5UOftSswmsDK7Y8JSzizj0S4QMgdu0DqAVZ
         XW+QURrVJGSCyFgpLW0WPVo7wAyqPfiSyL4MnG3q/+4CnlDqBbEHqGxaKbKa6RWu9rbO
         jL3o31rIjjppgYebWJgk/l2nCTfZgfQXosr6UBOhdTrTDNIjkqXFLe4rBD6Zg/T6Vob3
         DFK4XYQiMPKxTqbz/nJPuiB4qgCUUT9PCQULpiYWc19RCql9hVbeW5+JNlr3tt9KMN7U
         HPBQxrg97Tb4xfMallQqDaj4tF0/tJ5jq4h4sDir1i2CAsq/f2HjQy0DDM+VWE6n/ER9
         8KdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 26si402646pgm.1.2021.01.26.05.46.23
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Jan 2021 05:46:23 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8463511D4;
	Tue, 26 Jan 2021 05:46:22 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id BDCB83F68F;
	Tue, 26 Jan 2021 05:46:20 -0800 (PST)
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
Subject: [PATCH v9 3/4] kasan: Add report for async mode
Date: Tue, 26 Jan 2021 13:46:02 +0000
Message-Id: <20210126134603.49759-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210126134603.49759-1-vincenzo.frascino@arm.com>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
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
---
 include/linux/kasan.h |  6 ++++++
 mm/kasan/report.c     | 13 +++++++++++++
 2 files changed, 19 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bb862d1f0e15..b6c502dad54d 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -360,6 +360,12 @@ static inline void *kasan_reset_tag(const void *addr)
 
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
index 87b271206163..69bad9c01aed 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -360,6 +360,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
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
+	dump_stack();
+	end_report(&flags);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126134603.49759-4-vincenzo.frascino%40arm.com.
