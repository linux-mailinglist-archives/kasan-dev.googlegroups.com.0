Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBHV2VOAAMGQEGKAPFFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E3EC3004F3
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:11:43 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id d6sf3166649plr.17
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:11:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611324702; cv=pass;
        d=google.com; s=arc-20160816;
        b=lGeFB9NrLoW5fabB5iOpgMYnavE6hhCsoms4nnIWOYk+sjpgouLC+0yWYc8rZEVcax
         pk4Xu8/ymb6cLh9X9eCGYozUr2nR8b8gabs3h69LpWkB14MWWUkTtHdQODzkeRsvtyDt
         OvFq3YdViQUb4hzURwJvv1d+XYwDdawB1qGmx9iq8oAXDLLhsujR5mOKWQdLJQnVAK53
         Hd5OkyO2IiSXTTiCQ3qUfhoXBgDWG+thf7iFdFa0lqobnjZh+IXR69lSkbRpFapVvivu
         5KfeaYw+66WKnjZPQcOxXNNQs7UeoMPDm18f1GWNThRhhQwN3f0Oyqh6QAflpHBLVORA
         aDmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=S7hNEjAJCSt2dM7t/fxZwerEcWGcNnF/UGiYkDID8hs=;
        b=A+x70QOGAsoIO+REDF1Q3NUix3JZ4EdD9UQxjcQHomLZh730nQcBqf6xvc1mmEujTC
         cTHITej4ZpCZfvIeZK+ZRlYkRVaekayfRMvOZdHXMKD2jkzBIlITVptTy0zjhZm7bCDb
         l0/9anlgoFktS8KciwqWX3BMIYg8v06Z/UzV0alY596y9xK3GcimrwVVkDe5fwGIYgWj
         xFXEkx9aiXsY+VNnZXcyga73KcKGwza7088UebeyywcYtPW/AKvoTrSDcr/t/udYZHNg
         5WpB2XaZa4/P4ihVY8OqIs53QO6qpCGnIv646w4UiBtTzIwomYG+FS9Lkd2vJqVlAMFv
         YGgA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S7hNEjAJCSt2dM7t/fxZwerEcWGcNnF/UGiYkDID8hs=;
        b=bTF2WdE3X0Qns8DMNcqfKTtK6YrzHvmtVl5/qYoAjGGDmyAnzj44GPJLCxpc+ciZ+N
         MnuCEI3jN6cXUlwS0tYPwzHHpuDBY+SvK/K47W5u+RXQZFUTgJQWCAFYm7uVZT9RFR27
         T7fbFTgN7J1myZQnCmf3HqNWYSItqMiSbF2l93Vfx56lo8m8r6CukPHFr6EeqW3iCu6P
         JNP/0uAaZ11bQY8qojTbw5TmWHQKzeORxM5Xfv0W+4IHdR1lDWKeLGFuqtkc0nWrs9NL
         TBpXjMB0Mi5wwr7TFn3a9i5ebcBTrA9zMcMaDeEB1z5t6YpdqmJWqkK126kI2TYVEHQS
         KfhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S7hNEjAJCSt2dM7t/fxZwerEcWGcNnF/UGiYkDID8hs=;
        b=tokCaY0LrJX+qfL/f+lW6FNPxufr+T9HBXq4H2F8BTWTb3+U8OuY4Nnp742idN9u0R
         RunZn6BE8BPjc4pf7lDPBOQFHGRin6V4xc7ELfODV1nHHLnYKyRrq0G3xfu8D38Igdkf
         T4gT2WD9EDGRSjFcBUCrNfWLsppDc7eqctybC3A/x3dhLauC6a+EJN1fMparWh9Xc739
         Rf8/S59HHDFI3X0ZxJi5anRGEytIGxk/JMYhcJdmse8VfvlRaAMvftSZu6vonpSun68l
         /kR/x0jgTCKREI6eVzjFRyLqYrVe3omCm7k+xoX4E7zjAz1BcGhtShzCKfpGcV6gQh9Q
         FWWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532lk3zO+ZDQPq8IPQSqCUGgIMB3K94dlRhxlq/SE3euMJWak4H3
	h71oJ5e4LeXnpfkIsNbU3cA=
X-Google-Smtp-Source: ABdhPJwHge1A7XVWqYK6SzuNkwBcPaMYYJfxV32uZwQkePzXixgIpx+bnRLdS+KITRFaouyHqYPf6g==
X-Received: by 2002:a17:902:e812:b029:de:57c4:f6f2 with SMTP id u18-20020a170902e812b02900de57c4f6f2mr5132622plg.37.1611324702370;
        Fri, 22 Jan 2021 06:11:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls2179771pga.5.gmail; Fri, 22 Jan
 2021 06:11:41 -0800 (PST)
X-Received: by 2002:a62:97:0:b029:1ab:93bf:43a1 with SMTP id 145-20020a6200970000b02901ab93bf43a1mr5104761pfa.75.1611324701729;
        Fri, 22 Jan 2021 06:11:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611324701; cv=none;
        d=google.com; s=arc-20160816;
        b=ncDC3CdUOjNfozW80hgxSMqwm5hzrq3vJiEjOjPRLyBDE42TBmSs2wpsYK+IP7xAp/
         sN8n2CJnHZGNgT/g0ZdP3B4HKGn5w8TuAwLMljV9oUgnUDVNXVmJeWPpFES2KKpgkCg2
         s+lKaEXVFloiJP1YZIXrH557BYyMUsm5ZwMM1rK75BUQz8szsDIT/kGy/7A5TYaU+Lac
         b4ePKZx/DJl5cw9/7WvSNRYleN2vyeYhIeeyGRq6BviOsMHklIYjb4MXkxxEiXfr4gdV
         oiWr4rfok9NukBV/NXuORBnoIQuHmi6m/3ZUde2XtFy9uEYTB4p04d2nG7918kPi0MyX
         ClMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=tf/KLHfF5TWN573c5lzQlp9JqHAwczCKV0JmGu4pc9U=;
        b=YEYNvJ1bCNdOHzuwI66PHr3ugIlTIvZvbyBXKD1XJcWSsj/90QJ1svgLotkg7ImDAs
         N57/mYMol8Onczpl63kNxlHYjTUOKnlV8Kf3CSIcYc+0Pb3Nntnbeytxtljb7uEsPHLM
         DB3y7esQpqmj/lRf6npSLuHfulb/vr53zwPsIKzlQilk2TA093pMU0T9QYLXYebVnrMv
         YE1Vn65mZWc+yQL5/dt51Xt+cTEObM80yEhtY5H8G65NbaRynFKzTR2UnrX7WOdb9bNX
         nMdb6B84oLYw6VGtbGxp9lxbrpnDdt21BIBv7SMM592/JUnpYkG2Jhzon3Ah2nScevEx
         7eig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t9si1069617pjv.2.2021.01.22.06.11.41
        for <kasan-dev@googlegroups.com>;
        Fri, 22 Jan 2021 06:11:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 33C9F1570;
	Fri, 22 Jan 2021 06:11:41 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 879743F66E;
	Fri, 22 Jan 2021 06:11:39 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v7 3/4] kasan: Add report for async mode
Date: Fri, 22 Jan 2021 14:11:24 +0000
Message-Id: <20210122141125.36166-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210122141125.36166-1-vincenzo.frascino@arm.com>
References: <20210122141125.36166-1-vincenzo.frascino@arm.com>
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
 include/linux/kasan.h |  2 ++
 mm/kasan/report.c     | 13 +++++++++++++
 2 files changed, 15 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bb862d1f0e15..b0a1d9dfa85c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -351,6 +351,8 @@ static inline void *kasan_reset_tag(const void *addr)
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 
+void kasan_report_async(void);
+
 #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
 static inline void *kasan_reset_tag(const void *addr)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 234f35a84f19..1390da06a988 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -358,6 +358,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	end_report(&flags);
 }
 
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
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
+#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
+
 static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 				unsigned long ip)
 {
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210122141125.36166-4-vincenzo.frascino%40arm.com.
