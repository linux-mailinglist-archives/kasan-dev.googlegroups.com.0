Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZFQ6D6QKGQEYF6D4VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id DE7352C1579
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:32 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id a134sf103704wmd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162532; cv=pass;
        d=google.com; s=arc-20160816;
        b=xhmdaAb5WrA+GlTzHDzCOC8tU7xF7xqlcDebG5mxoiC1VSczxjZfUf9mKNYCEP8qxM
         4nUY/0zTKTz3jR+cjoYXXjuwfKH6reHoitFX69l0kHjN4h9Yd8YqMMpT24tdgbX65KHP
         9prehvO1jhv9QT7kXoBEronVBIWg4s7nuTMMWi39sw+SJppuZ59l+f7U8Odk+D2B+Cuw
         b5qM2ov62eKMIH6hnPhR0lggY8MQx+bgYbM/E3e0P6GwKhbmjs6invjGZrdlIsJlyJtq
         P7JqzqMcw5HF2aLARjdmiNMbQt+aRenf+/eKvmbuSoKkNISGzc4f28M0pkyTAb6kIYBX
         78LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pP8byvKf2Y/InyONhwdzRsjhTCGdKlKmYGZwjHd1+UU=;
        b=oI/DuTjbu+RCGAJYZAvZklP30BSkC+X8s0V0Lq0aVMg2aAd5EFWCIvZrwBIcGWYhTb
         nqpbiUo8nx0BNZSLLmSGJD5KJmtqbf0yWfT0eJnZOSSB8taTBPQUClNSnVnqjdGxkL8a
         hRZNN3oqF326OeUHiVOWPZhwgqSwFR4hpAWo9DCZm1E6Nd3ky1i1qMDUgCK2U+5P943Z
         08351wVMaRiPp8Hu6urf2i2/n7X68CZxORWzzD4nz0dhtM/NtXVCFuhtNg2NkCILbqkc
         8y/nBaJsfWgVL9XY3CbOGHY4XuvBP1bcfBiJe6YeALjg37+/mcYe4PhiiLJzqIZMPzlI
         O3Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gPxuvkeW;
       spf=pass (google.com: domain of 3yxi8xwokcygmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Yxi8XwoKCYgmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pP8byvKf2Y/InyONhwdzRsjhTCGdKlKmYGZwjHd1+UU=;
        b=ovpHa2ileMDKeAGRqyirK55c4fVk8Ix2ic729rntlmpZ3h4yVqLL+MsYDZ+VlUtc34
         ONeQjajNt02JzWIc/C3kog92cmkFFdk/vOpUh5fgP9funpxDgjXL05oRJwaljrmGAdLG
         TSvO9KmDp39Ropzc/i0c8L8lsZdcvC9NZE2P93UNfCZmMXJqwr0ZeVqP5ldEz79rENbW
         nyn8PeC1z0bh5ffHqO3StD9n4MzHXMvdv0AD+qhVwxXwJSxA+0xMV28fQqWhAWQ5UnpQ
         ZqCQ9prqI2WP2baJHv7zSirQy41ynknbWrujTC4m6+GKbcqLXsGvL9A/m/0Q/MJ4LobS
         FEpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pP8byvKf2Y/InyONhwdzRsjhTCGdKlKmYGZwjHd1+UU=;
        b=etIVgZIii7RBzGB/9Js6OyWi0KXiGsBT1ejBN7jTFzKXWVmlE6x505WWgzCy8pcYR4
         MuDoTCmBSKQFaoH1t0+odL4X+YdoG3KFLTml0IIgalIUwtmmyAgTnUlGd8t6bCKoMiax
         aMJ3xuvMikL4TGPEaE538cDF4BUX1fG42/rW9cNvmfa2Jk9rybTF+pW13ma6dJHjcl4Z
         yG0y5BGTlGUZh1yGjqmvnpmA30skHjtPWihEzZN1GxLRFDFI0j81hyI4hoZODLWQUEiE
         P9csYmfCnJ8IZGcIGAF8Rfjax0ih4JcbGtHNHYU0mI3tu5JDfCRuMRvUHLyMBxkISk2n
         RR+g==
X-Gm-Message-State: AOAM530+i6ZneI4NwV6bg362duyxmYle5xzC/O114uTnyJtX+OaRbcbb
	vdeD9J81wHa5poTW6Y4SvOA=
X-Google-Smtp-Source: ABdhPJxa1gJ6+7A9fbIWBvFnnoKYN/M8OxdCPk+KylMOAATm/I2Ow2prxvbItrPKqep5pQfCzeJsJQ==
X-Received: by 2002:a5d:44d1:: with SMTP id z17mr1407391wrr.423.1606162532691;
        Mon, 23 Nov 2020 12:15:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a4c2:: with SMTP id n185ls168842wme.2.canary-gmail; Mon,
 23 Nov 2020 12:15:32 -0800 (PST)
X-Received: by 2002:a1c:3c44:: with SMTP id j65mr632708wma.13.1606162531986;
        Mon, 23 Nov 2020 12:15:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162531; cv=none;
        d=google.com; s=arc-20160816;
        b=Au9zC+rwBTaUTqX6CLxJZ3Tle87Pd9K9nuDmaazocgYRjHVOHT9MOle9rjnyfTL/tr
         4AUZ2gShXuvh+JqjnVevM0AmmFBxiPEK/n21JYtVxRKFaBrYlL/UWHY9WAjLd/IkJEFG
         +OCKyqedFPwkEiS8c6J6ZNUd50N8WwxjV5hUogEoSfP1XLcERwOaRq2eW921VQyGiXE7
         a8Ci4Xv1Na2u8LRBdBEHP+haA4J58ppfjeeLtzlPvQ8lOR5814PQgEcO26ZNfzrqD2+9
         fyiyDDhwAti+KjjRVunS1+pa/0t0VDCas+Gfw5H84irw/DuhYFFQXPSDV9blRcx/UeoN
         UzuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=SLF2Qvc7gBcEHnpk1EaOz5XsuYMk/rWEwWdOy/HR3J8=;
        b=bmfYkESv0chU9WSa8rO0ZIxymt1uVX9/8kyht3mZQVKkDxLTf3GoMhr9RFrnvnKUxH
         uC8zBI3zSL6XeNtErEB/3jxfQkDMNcdI5bpD0kq3DNXqY7/KMOAPkxJrmn4AFxVL8XVN
         o2gCD511OxJc0Dcb3+Jrw+DsnGo/xDnjoK+Dufy/U9AmP/CtjL2Z4JjFpD4aXb87wAI2
         hL6wn5ZK36XrpwcBiTOaCOck6+uUjXLGpQ2BWM2QZfnz6SjREgS0LPiTxG1c/4nD6G38
         a2AoVagscqm3UpsrW9DPP5Hv/ZdO/Nh4v7fIlGYjqIWFomfdJ//QKpcDKgnaCZ5tS5oZ
         zNMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gPxuvkeW;
       spf=pass (google.com: domain of 3yxi8xwokcygmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Yxi8XwoKCYgmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id i1si14531wml.2.2020.11.23.12.15.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:31 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yxi8xwokcygmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id d2so151394wmd.8
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:31 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c00b:: with SMTP id
 c11mr587868wmb.175.1606162531510; Mon, 23 Nov 2020 12:15:31 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:46 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <1c8380fe0332a3bcc720fe29f1e0bef2e2974416.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 16/19] kasan: clarify comment in __kasan_kfree_large
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gPxuvkeW;       spf=pass
 (google.com: domain of 3yxi8xwokcygmzp3qawz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3Yxi8XwoKCYgmzp3qAwz7xs00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--andreyknvl.bounces.google.com;
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

Currently it says that the memory gets poisoned by page_alloc code.
Clarify this by mentioning the specific callback that poisons the
memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/I1334dffb69b87d7986fab88a1a039cc3ea764725
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 821678a58ac6..42ba64fce8a3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -453,5 +453,5 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
 		kasan_report_invalid_free(ptr, ip);
-	/* The object will be poisoned by page_alloc. */
+	/* The object will be poisoned by kasan_free_pages(). */
 }
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c8380fe0332a3bcc720fe29f1e0bef2e2974416.1606162397.git.andreyknvl%40google.com.
