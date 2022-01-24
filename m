Return-Path: <kasan-dev+bncBAABBYOVXOHQMGQE6LW3NNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 67E4E4987D1
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:07:30 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id w5-20020a19c505000000b0043798601906sf2137113lfe.5
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:07:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047650; cv=pass;
        d=google.com; s=arc-20160816;
        b=p13UyskilWBgoB+1u/OmvzySJgDQWu46pRK/xdqLoRjqyKYUfzJ1+2bQLya2Fr6IIZ
         zRnz2kHSDhYNHOJ9CnYKIAtrUlN3ZXfi0j3A5vx4hGq9HlUB4/A05Rs3pONJN5F7Er3a
         YgePTG5NStBndntFFdXf0Xo7ex2ugKgQzehIOEBijgLfs9XqtYfu/N4faCOXyd+wgEuR
         BXkUpAJn2Gm6xZRdsa0a0Z4rdM7MHyMGJJcURojTeXs5BgaH2R9vId4NxX4hOoziyoep
         a27xoeqmn1++E31t/Buw5ncO2GHDLL8GIm5awa/pEjn/UcH5xS8WlXwbQgiSYVUoixXW
         LDvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=weWiPi3iKQiPcSm7lJH7l/SDkLUtbSJmjmspAptnz68=;
        b=GBst3MDgXo5zWyUJAfvGSwoa2XD/e0JtOQmyGQDIt1Opxd/hykWhlw31kzDMwCdTiP
         euHqtYdvpkH1gmioFulg/JiMEYFPCqJ+JeqLDiKUjRlWoIANSNgaTaVOjAN4e2nd/cIX
         br6ZfIHSycuPzdzCsbRjcTmIe/goZo/+/HR40OUGHcBrTWgktSLvDLMaJfmWKZTH/Wxj
         Fvjgpo2v0rTlQnlLA3OZ3s8rbxPm/l8YH0vf7p3Nq+PkiQijvWo3Lc/v1ehhY8Gt0tIW
         fELBTpdI4zWfeEUkNwKkY64/cCScCxWwHPhJf1sKHNzgBdnxhkFhl4P7OXS2AJaFc3cQ
         35GQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LdSOcXw1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=weWiPi3iKQiPcSm7lJH7l/SDkLUtbSJmjmspAptnz68=;
        b=t2vB4mkojBuLLW+N/tIOUGINzG9k0JDVaKHyyRiuT9qa550Zkdno32EN2pi1aiyU9a
         A7GZjU7LNcNiPcbKy+TXUGheZN5hG+Qrh96NvOPyr8lhiiG7g9YKkx40geR+cBrLcRGX
         qlpsYofzMCP3zMq7Y42EPqYae44o+hnv4UMYGh+FcMcOqE825g4zFQOHZu0cR6ONRoxR
         8q2SRSgiclJJdkKWDEg2Es9Xd8XCGrVgm5aHOuJSbcbK42xdQRHOWjRvFFHyYYKcL+48
         CM3s+3mU4ydjil/AMTCYOi54ednN/qY3mdJgXt+G8GGin7lhchfq0qAfkXOLunKTb1ZU
         SkQQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=weWiPi3iKQiPcSm7lJH7l/SDkLUtbSJmjmspAptnz68=;
        b=5TpCy1/BBC4z7qqE/k7aVlPCiQKb+psTuLm9Rwg0aQLeiRrggSrltGtOULD7VGR1Yq
         6y4dyzjGlsKsNuX1b2QjQaE7PFeaTzHUttHaeR3oY0pnjKAIeTw26k7uXjsNUgO8/bqN
         coJkhQtjLJNWKICakcx17+DYC8dDhhOQcZkUDiMA0H/aGdnaPIUHUBROhjmsb75LAi+v
         ZafDFm3BWbBuoisuW9AG+PJaR9f/3vMSmpGOhgq0H3K+yZ2R7mIMOnSB6uaxKqW8iTOL
         8Qe6PsFqkdRhZRrzssJqg5/IGLqofaIvjW9iH1enbXcRik7SdPEU5z/qZifhAvwaVT+6
         pxew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533p15fXzKItoTZJbXh4E5+NzCJpTbYLTCfYcmCzLHvFKwF0Li50
	xAp/5aUSlsx8D+y950k+FOM=
X-Google-Smtp-Source: ABdhPJx+DSa2eHf3j+haelIE5zqxQR4I5alUBRFSvMpJQsW9KBxe2bRyARSa+FB/ClTzKS3cZHY3HQ==
X-Received: by 2002:a05:6512:3f25:: with SMTP id y37mr13866254lfa.675.1643047649999;
        Mon, 24 Jan 2022 10:07:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:39c3:: with SMTP id k3ls574657lfu.0.gmail; Mon, 24
 Jan 2022 10:07:29 -0800 (PST)
X-Received: by 2002:a05:6512:3ba1:: with SMTP id g33mr5191704lfv.419.1643047649368;
        Mon, 24 Jan 2022 10:07:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047649; cv=none;
        d=google.com; s=arc-20160816;
        b=ioz4LQ9jCuMoZ9OIl5NogtY9pJNmrpMtqo18Id9RJKwB6Xn42RobUYYwMo4tbnUvaU
         slppM/oT/0zhn+LMU+e8yvvFUNJsPNUfxMHDTQVzEOrWpWNkseeqWJZ38S6f0d8Ebgf0
         p529HOs0iasxQaRkdPA2N18l3A9iFun9jTNh6mGuM2tWGTrDMFklsc5tctezrdXLrMbE
         ws4ryODw4GctKmuojR/ekRj5rX9SOOR3RKgtkXVycaL3J67DtKuWELmA6oi5y6N+WYbN
         npVvrQd3TWxUCjvQgcFp6RJDMXZn6ijS/d4EbPRjSXmxijeqVqqlJDBjYR1pmFCsfmJF
         w81A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=woHyASpRd1dsSk1k8aXjCDxvW5sGTzgveGosFVStA8I=;
        b=lgqTmKojzh2+R4ivJm0zYMf/X6d43IO1njGHU4+5PdllTuS9mtrzULs2nrpE0z/4O3
         gDNq/EKfFmPmYPqI23O5vu6j+QncLttevvHmLkRzuF+DGTWIcEgSpPtxM3V9wY4rcW+C
         taOlikpLdTrNWKAW+Nx4Jg1qcxG7EL0TIr/YVsq+KpoCQrUm6Xa7s2I9shGHZ4Mckg/Z
         QNBGnj7MEAt+zbDyaGuwFXlMzMwINGODKLwAI5ntAzsU+m04ePK+tH2Y4Bsw5Qkflqkq
         2FFw3Nfb4DXW7RTc7ZEe7aPa91x6krD7jcVtBdPFVGjOQ75KqMw2Z4Qy/0qjAfItS5S8
         RE0Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LdSOcXw1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id e17si328845lfq.9.2022.01.24.10.07.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:07:29 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
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
Subject: [PATCH v6 33/39] kasan: mark kasan_arg_stacktrace as __initdata
Date: Mon, 24 Jan 2022 19:05:07 +0100
Message-Id: <7fa090865614f8e0c6c1265508efb1d429afaa50.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LdSOcXw1;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

As kasan_arg_stacktrace is only used in __init functions, mark it as
__initdata instead of __ro_after_init to allow it be freed after boot.

The other enums for KASAN args are used in kasan_init_hw_tags_cpu(),
which is not marked as __init as a CPU can be hot-plugged after boot.
Clarify this in a comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/kasan/hw_tags.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 2e9378a4f07f..6509809dd5d8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -40,7 +40,7 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
-static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
+static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
 /* Whether KASAN is enabled at all. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
@@ -116,7 +116,10 @@ static inline const char *kasan_mode_info(void)
 		return "sync";
 }
 
-/* kasan_init_hw_tags_cpu() is called for each CPU. */
+/*
+ * kasan_init_hw_tags_cpu() is called for each CPU.
+ * Not marked as __init as a CPU can be hot-plugged after boot.
+ */
 void kasan_init_hw_tags_cpu(void)
 {
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7fa090865614f8e0c6c1265508efb1d429afaa50.1643047180.git.andreyknvl%40google.com.
