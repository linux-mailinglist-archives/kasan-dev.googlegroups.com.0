Return-Path: <kasan-dev+bncBAABBD7R4SJQMGQEOCNZQJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id C42CF52019F
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 17:51:43 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id m186-20020a1c26c3000000b003943e12185dsf4414336wmm.7
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 08:51:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652111503; cv=pass;
        d=google.com; s=arc-20160816;
        b=I0rQNhwPz06z6S0rhg6VJ7ijwtbKkOtNOZGbesWnK4HFXjNVCejorKG0GHbxr8gIa6
         dJE0+0wSNQPBLZJ/7TnS4pB/i91DuERPmD1voES9XZuBPe5x50yIIkGI4QiIQHvtz9BV
         lYk66yeQ39dmmEbEu3bLW5bs1drUaEgB3P6+XXh9+2LcsPt+bLqBYyiGwvB3i0Bo/3O1
         MooOmCoUns6TvMdrE2ImmHxrAa1djVAN9kqDg8fcKj9RAbuMNWrUKE32MTsAu3uMY62E
         a4iVViMQOyzvdLBLVNIFvCk2btQbbaPXdJus8d9x13hlPI1RTkzYD0yi/IplmlVM51eo
         AXxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GwA2jeDpOnUo7oCHG25theG2Nj3kAFLEB6CbtSniTmA=;
        b=tc8B/2izyfcSFXSKWm2I2HCF9vwQS9k7ez6IpN3GHc0+QvS6Gl5Noc4I+phXJaW+Bm
         txrMLfYFHen1T4bOmql0lyVdbjcLS3wjohrE8+sulQA76NTofRk/535gHFflmYtXAKyz
         YcziAoKo1tCKJJYJAPaOgm1yYCiPG5XjQgQyxG9NANqZG/xOs5VlWF7m83c6BRhf7pHm
         Qb1aLWZFCzHBT4emokNV/fD9QdMH8PmoWmeaOBQqLxHj8JumHBVc3YND4Xg+XerDNnUf
         mywYULIVSE505NJwZ77CWudpP8gDeo+bQ9Qzdy/pQfynStvhsqEQD3XYFNw1NpcA9K+F
         hnDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=odwTjasO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GwA2jeDpOnUo7oCHG25theG2Nj3kAFLEB6CbtSniTmA=;
        b=kmJqigV/dgVqDyeMCvyEIfY8Q9kpH8WP4M1bq561Bs7aWOoZMkFXvHVfOjUDmrhJlN
         W3IQsoSzR7ZEgFGCwbefmD3RklVBJ1QMocc+6RfJMKC36DvRGzPrJvBp5GyEz1qlVMDF
         8mwPSOWZE9iHjNvhpDdz42VlEhJt0SggJ0OHvBeW8zwRiljTtfRsMP3Z3YEUSOBPqOTh
         IhNysRt8CofJhJI0LKwF/XiMzT3oSCuwKLSVGmMQlKCHdAwjOaepSGJJv1i4TNEnU6Ct
         Rztmg1KSFl2w78Qs+xhDFpJ+7KRsJB9memHWWM9zx7i4fIbnikj+dWi2pBgfV3hcVhA+
         zKzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GwA2jeDpOnUo7oCHG25theG2Nj3kAFLEB6CbtSniTmA=;
        b=hkt4KuSrkH+SRtFTZGkQ5p8bJ88D0qNIJVdLqW7JGYRIOnsPvCPjWaOtMdZlutVTw1
         0CnDQfHmlLiERr4VOisK2znGWM7jo4oLhL5/oLG7ry0hnB6fdPJSIP1HXa1F4yKVvXRy
         JgajZsCZ8f6tBT0daHF23tgTVtmNWtkAY+1nWOC4CB5hOU/X8ObyfbUOMAr0jSJ6eVew
         jTgQ1gXHIG+zRxAylwhI4coFv62NtguhM7kg21TIGeF1MSXarCdwndJcQTeOYEYM/ksV
         ln8iDDoDWTvxNzrQ6dfRJQAkQVmG5p2NYm2GPcegxg/Q5UNxf1D5MuATjz12K8+Vx/Kt
         +PIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532mzmmubyYMSYOiGPeWsB8N8+/JPDnBWryOQNP5uYbml6WOxu3M
	Qikwot0ui/PybhVjVGyr+FE=
X-Google-Smtp-Source: ABdhPJz57P5pvE3BYIZPKerZExHCLIJdh2ou2XAgAnChekmyIDsEZNsFR2NCKr3bPChJ1c5aSlVsfQ==
X-Received: by 2002:a05:600c:5105:b0:394:7d22:aa93 with SMTP id o5-20020a05600c510500b003947d22aa93mr15314835wms.107.1652111503387;
        Mon, 09 May 2022 08:51:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d96:b0:394:86e0:4174 with SMTP id
 p22-20020a05600c1d9600b0039486e04174ls2479677wms.3.gmail; Mon, 09 May 2022
 08:51:42 -0700 (PDT)
X-Received: by 2002:a05:600c:22d2:b0:393:f4be:ea1f with SMTP id 18-20020a05600c22d200b00393f4beea1fmr16940386wmg.51.1652111502674;
        Mon, 09 May 2022 08:51:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652111502; cv=none;
        d=google.com; s=arc-20160816;
        b=EzLKxLLNmdB2BWDb1PILgBbZwO1nvliotx5V/WAgP0POiNtSOWrfvh4qnSitiAdCi6
         ikXCBxpjDBrClvsTt4H7VAAOSPA2jkh1IhbG47PlchiQJZNLn270V8pmHEIGm786UjRr
         YcQxB5Quw4Gpmk4she6zM+CQs5jha+cBGk69/2Hr1GrEIjDISimmQObua/wNUqYGdqXP
         vMA8g/0v77R9GFKTV6ukwWeBeZBDNN7NK0zDXnDAWbjcw+vwThXIsm79QvfB/Gr2nyyD
         4tbPQJuOV2OH4tdPSD1ELfmIhEzqVu2e91Ykm/qXj51aS8VM8fcheF6YayO3VDkTuqyN
         us2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NF8mg5QhZqll++5M0QCKA3K7h0Z/LuDMIxcghTm14BM=;
        b=PQuDH9EOfUX4LNynW4Jcm6OWN+Ov4Q3LneGCHvafiqa2caGYlFcTs6L7FuAasuT2c2
         WMeIpixWqybzGyC/jh6J0HbP2Q/VjfrYxkpm7OM/5K6XajPKtkHfTu1dXmOgQiTsOvKj
         msSXPdON0gpPKAR5BC+p2EVRLEjsoSVkEALOZBXrCqrCC1ER8wasX8Qq0zD1+QOwKxZy
         SFuMPcWpW1yOUCnuzGNj9bp5rRbripGcnDIsHSMX2DOjulMsECUwNhP1I3omSuM5LvjD
         TicAMQlk0qPiytnUvFZvn6aXXEPgnXZOs+prkieQoIJUcIPM9VA+u0DKsfgf3NjCJf3t
         EJ5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=odwTjasO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id m33-20020a05600c3b2100b0039469a105f3si506364wms.2.2022.05.09.08.51.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 09 May 2022 08:51:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 2/3] kasan: use tabs to align shadow values
Date: Mon,  9 May 2022 17:51:35 +0200
Message-Id: <00e7e66b5fc375d58200dc1489949b3edcd096b7.1652111464.git.andreyknvl@google.com>
In-Reply-To: <a0680ff30035b56cb7bdd5f59fd400e71712ceb5.1652111464.git.andreyknvl@google.com>
References: <a0680ff30035b56cb7bdd5f59fd400e71712ceb5.1652111464.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=odwTjasO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Consistently use tabs instead of spaces to shadow value definitions.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 32 ++++++++++++++++----------------
 1 file changed, 16 insertions(+), 16 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index fed4f7a00d33..a60ed636e899 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -74,29 +74,29 @@ static inline bool kasan_sync_fault_possible(void)
 #define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
 #ifdef CONFIG_KASAN_GENERIC
-#define KASAN_FREE_PAGE         0xFF  /* freed page */
-#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocation */
-#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone for slab object */
-#define KASAN_KMALLOC_FREE      0xFB  /* freed slab object */
-#define KASAN_VMALLOC_INVALID   0xF8  /* inaccessible space in vmap area */
+#define KASAN_FREE_PAGE		0xFF  /* freed page */
+#define KASAN_PAGE_REDZONE	0xFE  /* redzone for kmalloc_large allocation */
+#define KASAN_KMALLOC_REDZONE	0xFC  /* redzone for slab object */
+#define KASAN_KMALLOC_FREE	0xFB  /* freed slab object */
+#define KASAN_VMALLOC_INVALID	0xF8  /* inaccessible space in vmap area */
 #else
-#define KASAN_FREE_PAGE         KASAN_TAG_INVALID
-#define KASAN_PAGE_REDZONE      KASAN_TAG_INVALID
-#define KASAN_KMALLOC_REDZONE   KASAN_TAG_INVALID
-#define KASAN_KMALLOC_FREE      KASAN_TAG_INVALID
-#define KASAN_VMALLOC_INVALID   KASAN_TAG_INVALID /* only used for SW_TAGS */
+#define KASAN_FREE_PAGE		KASAN_TAG_INVALID
+#define KASAN_PAGE_REDZONE	KASAN_TAG_INVALID
+#define KASAN_KMALLOC_REDZONE	KASAN_TAG_INVALID
+#define KASAN_KMALLOC_FREE	KASAN_TAG_INVALID
+#define KASAN_VMALLOC_INVALID	KASAN_TAG_INVALID /* only used for SW_TAGS */
 #endif
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_KMALLOC_FREETRACK 0xFA  /* freed slab object with free track */
-#define KASAN_GLOBAL_REDZONE    0xF9  /* redzone for global variable */
+#define KASAN_KMALLOC_FREETRACK	0xFA  /* freed slab object with free track */
+#define KASAN_GLOBAL_REDZONE	0xF9  /* redzone for global variable */
 
 /* Stack redzone shadow values. Compiler ABI, do not change. */
-#define KASAN_STACK_LEFT        0xF1
-#define KASAN_STACK_MID         0xF2
-#define KASAN_STACK_RIGHT       0xF3
-#define KASAN_STACK_PARTIAL     0xF4
+#define KASAN_STACK_LEFT	0xF1
+#define KASAN_STACK_MID		0xF2
+#define KASAN_STACK_RIGHT	0xF3
+#define KASAN_STACK_PARTIAL	0xF4
 
 /* alloca redzone shadow values. */
 #define KASAN_ALLOCA_LEFT	0xCA
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00e7e66b5fc375d58200dc1489949b3edcd096b7.1652111464.git.andreyknvl%40google.com.
