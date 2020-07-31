Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO5VSD4QKGQEUY6HDSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A1182346BB
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 15:21:00 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id a3sf13283396otf.8
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:21:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596201659; cv=pass;
        d=google.com; s=arc-20160816;
        b=Df6nRJwgIbCEpL3xoax6eXdhweE+ZmVeyNhx7DwAFPXsoAhg1yEcfrzGtfWwC01iql
         drBXn8pkE2w3wnzyrEolGJIxhR9Ktsdsf1VMtMIwPBBfLCakBTcVSwiYSBGYlrrf40il
         89RKRmghWbHcGUJmBcWae/oxZgRSuUuBrnzJLoRp6ZHgg7LyBdRunkvfM+V4b/4MEfGA
         StXmVUnIgmVdL9GTk7jyAVJtIW8stmnWEslEor0vLO1Z7+UTWvQriQmjzXaFG5y6esW0
         DxP8CObZi/jkd83LprqF7CEUfjGPGvg0RfA2Z88Mgc7BHjpZDgFHA3+Fc66iueIr8uhY
         /Eyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=uY2WMpVSmDv1PDKe6s0u17rlpNjFqkNHyw3beAuQ7RE=;
        b=Gkc9GkMonmxt2LyQFQZKCmxAIiTjRSRpVE4ultpt75AAc1ZsdUE3xZSHu8AykWrhEi
         LUqr77ZBQFflk68RFW5yYIe68+VJG2ZlxWAR96VzCh6FKniUckj/Er9fEwAMLq+HCSw+
         eyLFAekW5XYZzpCM3XkvnRFLnDJFw8xvA/34nDFS68YJxvaVcyh1scw+1pI0BmIuYitr
         pvBtMD2m9B7CgEjU8mI2QkEJ9s49GCsT4/amPJTVUFYptH/D+CxuTnZ3JqldfpUqh7Q8
         fA+WTT+wkWNCT55+1Dkpmic2UbRDoJa9pfqqE2RZds07hfoWEE7sfcWoD59bo4kfS910
         Eizg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IlAhdGFX;
       spf=pass (google.com: domain of 3uhokxwokcx8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3uhokXwoKCX8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uY2WMpVSmDv1PDKe6s0u17rlpNjFqkNHyw3beAuQ7RE=;
        b=jaUG6gtgcZuuXtehohxQjAHMUPqPYSZI9TnVXwqSsgZZFlrXHbxRa6/0cFqggI+73q
         NocpMZxWhsCX4kQ/2bn29XyYT1SZpcGU+mHz/Q861r4umjndOXQuuq+eqsuiusOj6Mlo
         ufmqsb9A3kqKXs8LcO4L7S5nvUwa6AlPPjBdFwuHnghZCg552sbkTBwZXSvhtVtCnnit
         VcUcLsmzA0/JBGjUZyKJHx85So2W4GbpnQduGTI0jWHuY0gqX78tPa97rZujvFoYPjgQ
         RnssUXTl/SeWqbpHaYgWz4std59oPVIWJtzA7rTMdpqiaR5PGxFf4cIku6hbYQeQim9A
         plBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uY2WMpVSmDv1PDKe6s0u17rlpNjFqkNHyw3beAuQ7RE=;
        b=tw2SXKAM0aBbFRyA/XJsOskqsifLHQp35FDS+IjxJGpv/RybWHeI5tBnz9VGKXy89D
         l5Jmaw9iEEUQRCuiJ7cvIubSbkKoMu65aeAyteA4bAPaHg6H1JnfyeWvd54/4tMllZJw
         /orMstaqQHDq/w+uWu8nl19bpExPLUXyGDi0agzWnbkebL7Il/jNa3nhJPGS3oUYXcox
         ebvEQnn3EhrLW+ssEuv9DUKvWijXJFsKOIWE4jPJhYOasy+kfb7bZTBXdyPRGQtVlVhu
         el0WNEGVVPNogQlrUIQWuG7FtoAB7A3k81j+De3I5LUhai5iueSABvGihQFhgcnFJU0w
         jP2A==
X-Gm-Message-State: AOAM531l0cGJUvfaHZxYkkL8zv2T1qOo7QVjtCkLKKVp4vtAllPaKeE5
	JBt4DJX7yZiK+MSWAJXtK/g=
X-Google-Smtp-Source: ABdhPJxX2Gpvq/b0I4/q5FWIpcwDEmGAiCG9K0blB9Z7BpMymqsPCdaAotF7xgpSD70DrjXvM9AtrA==
X-Received: by 2002:a05:6808:b36:: with SMTP id t22mr2879501oij.159.1596201659620;
        Fri, 31 Jul 2020 06:20:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6052:: with SMTP id v18ls1901183otj.6.gmail; Fri, 31 Jul
 2020 06:20:59 -0700 (PDT)
X-Received: by 2002:a9d:7f0a:: with SMTP id j10mr1514291otq.61.1596201659328;
        Fri, 31 Jul 2020 06:20:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596201659; cv=none;
        d=google.com; s=arc-20160816;
        b=WpfbSgS+7UJ/R9JlbKHojx47U7V+0exnNtf11FSxYBeTwuRohqet7aX1zK68VACwjI
         A25L6e9xEKV7aeyYh3842bIdYbzbwTAWpdgGjgdJITMeHowiys4TBrYaVVmZi53MXr5Q
         ev82TTDsV48bj08XufRcokj5Y/sg6OsWPrCjhlBqv4hZuIdg/I5qErRdbmWTR2f9tIdD
         bKNV6yVrosZjMTJnqsmU13pr+2MMRiDYroLoUhaMWROLFG1VKS6KYt8FpDVeDo7U8i+I
         IKU2JYHwBm4JFf9JZsUTHzYp05P6akp9XSoEuQ8o+sNn6OIRTZZPmxIAeyFJUrY+Jzuj
         ljDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=cZVGg5u0amfQd0MGqGsL/eYTxMBPuz1AnwRmMzyUYJ0=;
        b=N+0crOIlE18A4I/ercHUTuqiSw0b0HBQvvd9E+ENUwh8/TmnzMzZV/nah81YyDC4Ex
         o/V3Nz6+jHdCkqJA97E2HNdykoRJC8nMfxZcAc8D2yX9SgUb4JIS7NlRBNDKVRp8vcWc
         y5tRB67sImsr8fzSBTd1Dipmn5nlCx5JgXEtr0QJypKPJgcCtnCqq9ngDEervJBB/+eu
         9458gD8FcQWM+FrSGsydXv2SJMRxQ+ZfvOCBuK9l3rw8PWyTwG0fyLblBrTHVMT/0CM4
         a2GkB/hhnKb+mDDR9OFxn6s5Q/r1LKeaem9bG3dP6Go3lVXVjzXPS/lw4gLQXfsdadbF
         HyfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IlAhdGFX;
       spf=pass (google.com: domain of 3uhokxwokcx8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3uhokXwoKCX8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id c142si499583oig.2.2020.07.31.06.20.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 06:20:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uhokxwokcx8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id m88so20842007qtd.15
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 06:20:59 -0700 (PDT)
X-Received: by 2002:a0c:e8c9:: with SMTP id m9mr4125226qvo.178.1596201658775;
 Fri, 31 Jul 2020 06:20:58 -0700 (PDT)
Date: Fri, 31 Jul 2020 15:20:41 +0200
In-Reply-To: <cover.1596199677.git.andreyknvl@google.com>
Message-Id: <403b259f1de49a7a3694531c851ac28326a586a8.1596199677.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1596199677.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 4/4] kasan: adjust kasan_stack_oob for tag-based mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Walter Wu <walter-zh.wu@mediatek.com>, Elena Petrova <lenaptr@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IlAhdGFX;       spf=pass
 (google.com: domain of 3uhokxwokcx8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3uhokXwoKCX8dqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Use OOB_TAG_OFF as access offset to land the access into the next granule.

Suggested-by: Walter Wu <walter-zh.wu@mediatek.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index f362f2662938..53e953bb1d1d 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -488,7 +488,7 @@ static noinline void __init kasan_global_oob(void)
 static noinline void __init kasan_stack_oob(void)
 {
 	char stack_array[10];
-	volatile int i = 0;
+	volatile int i = OOB_TAG_OFF;
 	char *p = &stack_array[ARRAY_SIZE(stack_array) + i];
 
 	pr_info("out-of-bounds on stack\n");
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/403b259f1de49a7a3694531c851ac28326a586a8.1596199677.git.andreyknvl%40google.com.
