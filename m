Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBE4RYCJAMGQECI2QG7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id E9BB44F927F
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Apr 2022 12:04:03 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id z16-20020a05600c0a1000b0038bebbd8548sf5755877wmp.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Apr 2022 03:04:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649412243; cv=pass;
        d=google.com; s=arc-20160816;
        b=g7HIXR+48vfbb/mRnPvrdzCoz4b00gYfzBsTy6OA6oA/4RAk0VKbNwPatwXTf1Q9Hl
         wWYGukIbPlnDtseJKFdEy51m3uZwgIwJ+zLvj9Jtrpthpwsw4W47s8+qz5D7Us7XM87C
         1XuUZVdXehCHrWZdF3AUnb5U1Iuwz0LcA2sgANPH1kBUJMyf5wOnvnEH06ZEjbbDkm6+
         EgyrrWi3VPSfsF/C86/ZiYo6DGYTU2nPvhD1etwIYgRroQ2reKoUnEdLzHT2auwJB5dN
         lK9mlr0xSzqiwkgZxgzCQ1r4Wy6e3FR/Yatahi5G5Jsg+zgQ4nxgiyAKH7bqI/IVqEyY
         O1cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=bFWnXRZSpBX1ieOOTviVAMp7ocx6d85UPu25Je+QS14=;
        b=pL9BzIQ2RsSPaofjm2g1kxju3OV52KaLGXsa1UuKZS0qwwbLM+QAVb3ozboRRC8PIE
         oc7+XL5VbQUEZk1m/zfT3lhZm2uZ6KFIZ1jEZEV6CyMdHnM1acmvcxGtfZKs5AZt96Ho
         nD9Km1lGPP91wGUrX4tpY7ApnraDbgzfPFAIAt/0oCfZnuPfdIXBs6vyJZlNO9NnTHc4
         iDTycq57JwJVbeMUyPAE9X0UwQPmsSTRoT94SwNwH0Rq8XFDZCb69ndR7tX956C2TSrt
         82lXflH96odA5fgghkGSZARZc+24uT6VNNv9m8pgLtQtdO9+qFO8W25xEaS4rji9fQQj
         kTGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bFWnXRZSpBX1ieOOTviVAMp7ocx6d85UPu25Je+QS14=;
        b=LjFm/3BQ00lZslU3YPQeg+IdHv49FFtiMAM7hXgqr+HLv7vOoFJYTpmuIjhQKRZbfF
         qBkvBnX3ckzA37jcT0X5NL4HGgwIuYvrMLbPJaexN9CS+z1rNj3uogaeRuER/ibrLNzY
         18T4AvlmSnezztj7l5kdR1jr3f00jQNfN++E3jM6pddhziZ6VC1VSYCDNUvxk/0BWIhs
         ht/0/w+Hbz9VEyg6EjQ/g4p7ocsBzGtO8zs3BlIu+GOpDaqIenn8po4nd1/66QVeWFmZ
         qWIV4gjNP3A3kpZkt7QmsbFj2lccdhyQVrUMCD93JTjfUICjbWVlt0Ws/ghbeRH+FXsR
         pPMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=bFWnXRZSpBX1ieOOTviVAMp7ocx6d85UPu25Je+QS14=;
        b=2NQ8GSqMoGfICEh6jAagjiA9JR6nX7niqCA8CizGOCR49nWCl92JhXxsx+G2UaS/zi
         duMjlM+sRjBKy1dmWRvYAp9TGrfA6xUXpne8eowAMKCPT+0Y0s/7CbpQ3zAuI88eN5Lz
         v6gGIp5dQpRzq8wwoLi0fdOMxEwnIluIN2HXWliCDBFbBhxp6AwF8Rm/Yz9Vb6oC+pPX
         0TxvHNIHlmG/pk1tNdCbn3VCFiI7UiL9QFRDIQyHkV7+EIlyEyvmopAsKQ28UrA5lXue
         gwlgW00jDtmZl7EePdMal450Ksmg3k02qmSAQA8So+ZeXWfPBpVaINEK5HZY1PW2BeXH
         p0dQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mXgPC+yXLM0Okf6CYXDht1ajNgvovglkmr7im6NZrijrlXf/w
	vw1lpVPsvrFwFWq0pB3rWhg=
X-Google-Smtp-Source: ABdhPJzpYkMOp6mPXeKgEWf0S9g24D8wME66H5Lcl+K/j4hdXWdF0/LvUh2wxWLFnG+Dy2VvXBUMyA==
X-Received: by 2002:adf:d081:0:b0:1ef:9378:b7cc with SMTP id y1-20020adfd081000000b001ef9378b7ccmr14196430wrh.407.1649412243483;
        Fri, 08 Apr 2022 03:04:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:15ce:b0:1f1:dc97:d9c4 with SMTP id
 y14-20020a05600015ce00b001f1dc97d9c4ls916761wry.3.gmail; Fri, 08 Apr 2022
 03:04:02 -0700 (PDT)
X-Received: by 2002:a05:6000:18a7:b0:204:1bc0:45a with SMTP id b7-20020a05600018a700b002041bc0045amr13788111wri.119.1649412242537;
        Fri, 08 Apr 2022 03:04:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649412242; cv=none;
        d=google.com; s=arc-20160816;
        b=xPXR6oNgpNaR8xuwNtp2iKYW5o8deAavRoPaRdKNtYylH3pRTJeSCA1REtf4sATD+G
         6U4kedMpVJrXX2qeZT0H+fXUseSUeuc8VXKdRbRlRo4RWODtu95BPlqooc1Xd3C4vX7U
         yq6IZDwU5pFOmfpytmWY3qbOa7932CzAMYmENJ5rSUhtZZDy8hRZFk4Q38piT6cpicNB
         rGWJ+kFCRjQVh9gFkWpLrAquSuQmb52rgc1PLJaQuufEpSKn7AuL5kKoFcmt6bVdizVc
         epxqzsIH5axboL6eMsmdwVr2XpdD0cqXO4OHYbaGJNhUleLJRHEPFMpnPbbmd2Kjmnp4
         5UZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=DMcaM0BUS8LeTh2nUi9yDR5zGYAZMrs17IKHZBbwZGs=;
        b=RSoDzDOnQEVp3O1LQM03WzXjwNpYcOqSwWrBJX0YR4yYlG0Vefnk/fvKO6TtMlWr+7
         y3Z4/yWITZ4q/L61ii1kSiPFjrCctsiOELgoK2mMr/ye/N7VPhM3CG4fjwJoZLTmdEvG
         vRgLmpQp/cAftUNGA5j1IZkfLK4uhw9fevpV0Xj1FtWY4IrOeb4ySvgVwW+fAhpjlUd+
         RqMJ2eTJPmaFyFNVoH9My+dEZubbsWrCRRqbCTbh75WEz/p3SlD4P2G/tmghpFJ/xY5s
         tNcybHL/83a+NCf9DIQaM7kt1RP7TRE23PNURvn3vtY8DeEf3SU43kMaVGduFGmk92/e
         FfTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n3-20020a5d4843000000b0020619efb241si39123wrs.4.2022.04.08.03.04.02
        for <kasan-dev@googlegroups.com>;
        Fri, 08 Apr 2022 03:04:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AEA2F139F;
	Fri,  8 Apr 2022 03:04:01 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 4002A3F73B;
	Fri,  8 Apr 2022 03:04:00 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>
Subject: [PATCH] kasan: Fix hw tags enablement when KUNIT tests are disabled
Date: Fri,  8 Apr 2022 11:03:40 +0100
Message-Id: <20220408100340.43620-1-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.35.1
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

Kasan enables hw tags via kasan_enable_tagging() which based on the mode
passed via kernel command line selects the correct hw backend.
kasan_enable_tagging() is meant to be invoked indirectly via the cpu features
framework of the architectures that support these backends.
Currently the invocation of this function is guarded by CONFIG_KASAN_KUNIT_TEST
which allows the enablement of the correct backend only when KUNIT tests are
enabled in the kernel.

This inconsistency was introduced in commit:

  f05842cfb9ae2 ("kasan, arm64: allow using KUnit tests with HW_TAGS mode")

... and prevents to enable MTE on arm64 when KUNIT tests for kasan hw_tags are
disabled.

Fix the issue making sure that the CONFIG_KASAN_KUNIT_TEST guard does not
prevent the correct invocation of kasan_enable_tagging().

Fixes: f05842cfb9ae2 ("kasan, arm64: allow using KUnit tests with HW_TAGS mode")
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/hw_tags.c |  4 ++--
 mm/kasan/kasan.h   | 10 ++++++----
 2 files changed, 8 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 07a76c46daa5..e2677501c36e 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -336,8 +336,6 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 
 #endif
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
-
 void kasan_enable_tagging(void)
 {
 	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
@@ -349,6 +347,8 @@ void kasan_enable_tagging(void)
 }
 EXPORT_SYMBOL_GPL(kasan_enable_tagging);
 
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+
 void kasan_force_async_fault(void)
 {
 	hw_force_async_tag_fault();
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index d79b83d673b1..b01b4bbe0409 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -355,25 +355,27 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define hw_set_mem_tag_range(addr, size, tag, init) \
 			arch_set_mem_tag_range((addr), (size), (tag), (init))
 
+void kasan_enable_tagging(void);
+
 #else /* CONFIG_KASAN_HW_TAGS */
 
 #define hw_enable_tagging_sync()
 #define hw_enable_tagging_async()
 #define hw_enable_tagging_asymm()
 
+static inline void kasan_enable_tagging(void) { }
+
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
-void kasan_enable_tagging(void);
 void kasan_force_async_fault(void);
 
-#else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
+#else /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
 
-static inline void kasan_enable_tagging(void) { }
 static inline void kasan_force_async_fault(void) { }
 
-#endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
+#endif /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
 
 #ifdef CONFIG_KASAN_SW_TAGS
 u8 kasan_random_tag(void);
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220408100340.43620-1-vincenzo.frascino%40arm.com.
