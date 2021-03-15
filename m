Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJF6XWBAMGQE6VKR6PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2371033B3B3
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 14:20:37 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id l10sf9110310otd.16
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 06:20:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615814436; cv=pass;
        d=google.com; s=arc-20160816;
        b=1LRLcKhP/MuqVeoeSf8fLL3h8OG6YNYwdWGIgOlr7bRXtbUm8SDBpEnfzQwdeXQstD
         bTo20dUY9GhPF1TLy5eeXTNCOyFY8TZ3lRAjGQa4LCfx8ywgsjEUqTR8YD/JtL1+QxXd
         Pc5A8gyfxOcL2TvnjUGtmuofp2DJQ6tuS0u2vR0U9oKOo0W8QrM0974Evb/xpJXCOqn1
         wLucPB7bXvmmIzT42VfDW4TpCV61QV7pAwYG0GTIdMLzEVWyUc0wHgl98Azw45AHf3ej
         8vtWPRvzGd5Ek1Bd1u2DN4Uqm+D+UXZgCTOl8pNLvSMSjNwLGeuwsH/bF2zCjxIuZpHp
         yOfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+Z+qF9YUjJuv7WfO5I5lhpXxEOKsm3gsj90srmRWnu8=;
        b=wPSsZy/fLdwtWrIZDoat8or5/rs3ct92AZNnwdEqUprzg0cfmyCOChEKL9aleMguf+
         TZoB+uhMQ+O0mfF8uetAg6DCDvo2qsOuXDPT9ZHBtoWl7bmmb+yEIu1+vjF+T9D9xX9N
         0a/D+nWq0bYv7FYQk0/MwXhR77rf5V6RHT24SVEisJhvdtisG9y5Dw7TIs5ZTqjxnCS9
         9UhlT9trkwuqlGL6Y1MGFxkZSs2CJBtVWl3XQUeGtzmLwNBOo33/IfBt0VmrfC+C3x7P
         XByo8Xc7HPbFfoekmcsvlm3SZqUdJHbZARyoWdmvMDzfx950WyQHLK8gfDQd4d37Zr5t
         myDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Z+qF9YUjJuv7WfO5I5lhpXxEOKsm3gsj90srmRWnu8=;
        b=HEHZPdZfdqg5XvTwr5wBHoq7Eq+YJTnf1zk5dUeRfvcfUtGutjL9n8Ulwlrf3cvzFB
         KKbHRwrzmtqWFNCtwsk37uHVxu5mOJ2ek672+14iZGPnQUQBAvC0uN9GXnv/FW/4rPyf
         z5Wm4ijISSZGgDB35UF0jpTgbuh8FU//kNKmRH6j8EZXd2lQxZ+CUBu6qQxHUa94IZIi
         QGX1r1u+Zaog35bk305ge9pMjrWq+hxmho1hVkM3EPPehYR266InSYn41It2R5T7uCmb
         68RtpATzPaQdOJVkFciysu+WC2ObtKybuNfOJNhe3RSOUffulqUW2wHuRlo7t5hGdCcl
         OXbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+Z+qF9YUjJuv7WfO5I5lhpXxEOKsm3gsj90srmRWnu8=;
        b=jJtCiht0hunCZSGkmODciGVEvaFgoln1MjdFt8h1gpEWOfZeZd+PatIKzI1D5undLi
         FVYaj4haFAwWemnaEfONJMA52pEHqbNGWLfmj16Yz3JN8EuxUIXLpCaodW53tN8HT1h8
         mtCGkqhaBWnBv5Ot7/74hFZJZ6FOC8rWfmWrJGSA8wQJ2de29IdazO4baxa1+Baw+/vC
         SV5vXAYJRUhu8Iw9RhNGOx97aHD931YBLPya6AQR1LYMWU++sPUE7gpPEIUi6g5yEOxg
         NR+QKukeY8TgcRVSwW+qx4LBR0IT4nkr4r9nJRNqVGKOZZpLORMrlBDzwUpLWcN+lzbD
         G3TQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533p3rAO7L+rdydlaV2GYqqYRrEHg18FIQ74+jLCxPHMgNQu7uRE
	1XdyzwJGN8jQX4d7kDCcFB0=
X-Google-Smtp-Source: ABdhPJzJOWHDr+t/jdmrE83ybOpgSZz0r5lirUCyh8NulX3pDCH9GtTkWsGAD4E8+1PzKdN84D8ZGg==
X-Received: by 2002:a9d:62d8:: with SMTP id z24mr9685950otk.258.1615814436137;
        Mon, 15 Mar 2021 06:20:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2256:: with SMTP id z22ls1116784ooe.8.gmail; Mon, 15 Mar
 2021 06:20:35 -0700 (PDT)
X-Received: by 2002:a4a:a223:: with SMTP id m35mr13419290ool.39.1615814435824;
        Mon, 15 Mar 2021 06:20:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615814435; cv=none;
        d=google.com; s=arc-20160816;
        b=m1v5BE6J3ZnHor3ioiO0cXmbeqS95+i9j5kvrStdiTD8y/6/Do3hHEBT5h7i6GZzH0
         yBi84nb3scDa8zzLx2tvOS8gPB8z2P6+gFQw7fVOZlQ5l+n/6ZOUgKe/9eHxtf5Pcy5f
         5Icr4jMy7MnrJy9BdPvIpef0YIUzS6mYwBOZRA1nnnW3IiivNi2m0YEFAEZTW8CuijrC
         kXX2h4cp1lgy3iP/Ygn6dSqI1tsm0btQHQCCx/p3dkGIu+Jbcc27eH9Z8v0d+Fl7mOs2
         lR4Xdly5VWXM202+Jl8LwR+gqTaT/ZBkRxGuqNQ3sl5S1+tI4bqOypFbxPNuz8jcr7eE
         ClqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=f2YJtK4ZkgvGOdH7EJL9jSMYxBFXsJt5Qau6YNKX4so=;
        b=S+UgPqMQOOqy8zZaKDlZUxVgSanhd2EqJ7N+hhq6wQfkOHvK7gqZa54q7qEYS9KG56
         KLQudhXFbFGUO/2uLJxUaLTP2IvvTYl1vJztWhrBlbd3og7z9AW/u4mjnHgw5aNzdbET
         fyBhQBC3TuU/eP8OZXaT6sivdOQIxdI4r+SXBwlT01gTyKXwx8/ksrCwlsn9wycE8uiH
         jUkC76M3ipUaZcU4E+8woHTNWZEXwyn3/4SStlr4XoAeGtp9zY6lidvzjgAiDZXPcZbQ
         sWQ0L9B/m8iIoOfsMs8g9iZ7hCwGjfwBO19K9hOjM2aF/T9t5llVIZVTkmB4tgCwHmzL
         L01Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i14si763337ots.4.2021.03.15.06.20.35
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 06:20:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8D4C011D4;
	Mon, 15 Mar 2021 06:20:35 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AB04B3F792;
	Mon, 15 Mar 2021 06:20:33 -0700 (PDT)
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
Subject: [PATCH v16 3/9] arm64: mte: Drop arch_enable_tagging()
Date: Mon, 15 Mar 2021 13:20:13 +0000
Message-Id: <20210315132019.33202-4-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210315132019.33202-1-vincenzo.frascino@arm.com>
References: <20210315132019.33202-1-vincenzo.frascino@arm.com>
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

arch_enable_tagging() was left in memory.h after the introduction of
async mode to not break the bysectability of the KASAN KUNIT tests.

Remove the function now that KASAN has been fully converted.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Acked-by: Andrey Konovalov <andreyknvl@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 arch/arm64/include/asm/memory.h | 1 -
 1 file changed, 1 deletion(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index f6d1ae69ffb3..a07923eb33c5 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -245,7 +245,6 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 #ifdef CONFIG_KASAN_HW_TAGS
 #define arch_enable_tagging_sync()		mte_enable_kernel_sync()
 #define arch_enable_tagging_async()		mte_enable_kernel_async()
-#define arch_enable_tagging()			arch_enable_tagging_sync()
 #define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210315132019.33202-4-vincenzo.frascino%40arm.com.
