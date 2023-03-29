Return-Path: <kasan-dev+bncBAABBBMLSKQQMGQEFAIZZ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 774D06CF23A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 20:37:58 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id j27-20020a05600c1c1b00b003edd2023418sf9195725wms.4
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 11:37:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680115078; cv=pass;
        d=google.com; s=arc-20160816;
        b=jjKLOMh8z0zPtrhh79KOUz3THbfpFWDWU/Y+9lZjc38t4DQFjAEL3g9HC13CrBjobJ
         9eiYmeWLwP9JRxXcxBVXw07ybdT1Kw0qyXQqN4sEE+fOnFLAq+qORO8N2N8nOdeBhSwC
         G71nEsDo9qtw2MvcQI9b2vR7MM16aLSu+0OkeZka39aHeeFpXPp3dmpI8e8Ohl0h6UGB
         uaCHUKcWTyDhptbPECXIrNzpbS4WlA9CH1dzywF66oZpEiOioU3tiozpK4C5eCGaIXyW
         /L+1q4fx05ABQfEyYV+fLv9DUGaoMaDMOSSFMuTjJnfZyFkLKALchRv7UEnPkqBQiUXa
         a2Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Q9ls1wND8POu9bYf9HP1tG613btv5a49i0FRKj7cC1w=;
        b=Hs+XDBaWDg36u/cMgtOCS9Ejb9bhJy8xisdBVCd3GrwztGDUMhLsYCV5IN2bGxR83n
         rRyAivabyKz4goi0VYzPUF8PeweiLLB1M5oGmxvsqZ38Qe26nqJeL7fI/BHFvRC45XqY
         WfqIU+Cfo+9fCKgFvyDV5YySn8eXDil1DKxvhqCPvRcRXlnCpwcuqWeUyIWT79kwr2FH
         04QhVYScuqRMxWzHmY1zGU0yWhJDx7msX5egcmFYcCZWUh/zJtkD2fxC9qWd7fVSAQij
         Pl0cz+/M9Ra6WOxlxS+nH5kMFyYsFq81HQWNh1M3guIUiCmc2i5EOLyqM90kGtxvgZul
         3CnA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tIO3PhiO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680115078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Q9ls1wND8POu9bYf9HP1tG613btv5a49i0FRKj7cC1w=;
        b=lgIADUgTPLj0pHMt9I8ChMQSMunk8LUNJJhx0dON1eyq8888A9PZ5Ux00CvQ/EnDpI
         U2KLYTa6vLMIoj/OnTMEgXdC6TFY2rAd1vja24dXfn0MQ/qOPkld98FWncQhI0xQSgIX
         CFewOzCASHrXyUdthwNcHFlPpc/1JREXu5602cZxkbrXtOgpeWI1eDcx6LF4lfI4BCZH
         WmRh604htm8DvuFWJYQrgdXr+J4ZQOeYHOBEJI02ibv6pHVGZqpWRGvl9DrwJm1pbEFT
         JEmwVLEy7lt8bqts/xi61zlKaRrwaG2dxeRy2QPk/atwZYaAxMEfTbkV/yx0XArfaTge
         78PQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680115078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Q9ls1wND8POu9bYf9HP1tG613btv5a49i0FRKj7cC1w=;
        b=xXXVge8mOinHr5Uw949FKsIcUSUl+rL/guJZC8Fz0q2370+5dFU7CQHokAq+RBlqoQ
         3m09zrLD700th5wLxe7V3ERbFQUWiRFQoVgLPKvmCoGasVPoSrnQ+hWGVX9Liq2aUnqv
         KkqzSYDZryHm0Hc4Mh/iwHhRtWgdUi/n5AUspLlDzycGF0H41ilaba6fqu6pSee8zOn/
         5C5K94Zz900iz7LtE8GDRbvFuGJoZRvusoBWyeoKICAx8vUpwdPa7FfcHJN8hrvk2pKw
         nTZzUw/fgEAnbxPFiXjkW1aSK3uQa8d/fPMpRkGJUgv8PFr8LX3g/yx+1sHkx/pPzwGh
         cmtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9cbSIcVJF7gDZGgVhLEcN+cOb8jRXkXwKuDhZyqn2x09uRYH96V
	+svdg5eAmWYOIgSeV5UtnLo=
X-Google-Smtp-Source: AKy350Y8tCYvadAd0/ZokNUNXGHcjEr3nFFhxIpcY7MfqA5f3gb5Fnppd742bPLaQGB6hn0NAFJCXg==
X-Received: by 2002:a5d:680a:0:b0:2d3:a894:a3ba with SMTP id w10-20020a5d680a000000b002d3a894a3bamr4263267wru.10.1680115077811;
        Wed, 29 Mar 2023 11:37:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5e81:0:b0:2cf:ef77:1717 with SMTP id ck1-20020a5d5e81000000b002cfef771717ls25009001wrb.0.-pod-prod-gmail;
 Wed, 29 Mar 2023 11:37:56 -0700 (PDT)
X-Received: by 2002:a5d:66cd:0:b0:2d1:5698:3f70 with SMTP id k13-20020a5d66cd000000b002d156983f70mr2541502wrw.29.1680115076771;
        Wed, 29 Mar 2023 11:37:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680115076; cv=none;
        d=google.com; s=arc-20160816;
        b=jThzBirzKwu2iABOz7fo3hJUJZCQgdnQzPbab6nobWTwNMEpt2DBRFfzkf+ZfQaIds
         Tg8ECk/F2CUvxRxuvb3tWqkEvW89REOTpZ1Xr3yHa83Ad5lZILZ3+pyYeDzOkgmPKmPN
         mdKa2TKMdmeKMGCA3Cn9IDWjrZDYMo69N4fQmrqx2WNvF3Sw1URGr06JsLJO+yDHQRRC
         70zUAyUduvm10tFxP3wn9IW4jW1gdvl8nP00Mx24Qq4PqFtoi9XrjQzkeNUkQl+8JAOu
         Ith8z7P+94UaAOZszNe6lQL6a3aTkuMDE777lbeQOK7gImL6vBS3K9QyBBkTGZZNNk9n
         IYzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=z4DPZvfjlbyZR04Gs5VqWFFoeLvvcar/vhfVx7MEdnM=;
        b=uge3WjbjzOJOlgnFkVfPiY6S9e5nS6XNat3UwGyfCuMw0oqN2iXLU56i1vycQdtYmp
         y8abOdDWq1YjtK8kfmaUg1TxpSFmADSGIOwDJ4RwQyoN3x6WS1uqe2ocU19EceS2ALNX
         /RWsEgXHME41BTMbGTXXh4yHsyLi0oi5h2JYnX+KoAoog61uXb5wuIZEnqrBdd+s7F3c
         N/OjZRNYmco/Ai5nh1IH9eOZaqc4AvS1xniPG43dcxbvmymFBbakpIJMH1/PXusYD0VE
         tgN99XCG9c22RXXIoKvmCHz6DFuo/DmECsCIlE4YbmJYAUE/3f/nZhaf/VqGAnQxSNjR
         RqOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=tIO3PhiO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-9.mta1.migadu.com (out-9.mta1.migadu.com. [2001:41d0:203:375::9])
        by gmr-mx.google.com with ESMTPS id az20-20020adfe194000000b002c59e9a3f66si1632725wrb.2.2023.03.29.11.37.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Mar 2023 11:37:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::9 as permitted sender) client-ip=2001:41d0:203:375::9;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Weizhao Ouyang <ouyangweizhao@zeku.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 1/5] kasan: drop empty tagging-related defines
Date: Wed, 29 Mar 2023 20:37:44 +0200
Message-Id: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=tIO3PhiO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

mm/kasan/kasan.h provides a number of empty defines for a few
arch-specific tagging-related routines, in case the architecture code
didn't define them.

The original idea was to simplify integration in case another architecture
starts supporting memory tagging. However, right now, if any of those
routines are not provided by an architecture, Hardware Tag-Based KASAN
won't work.

Drop the empty defines, as it would be better to get compiler errors
rather than runtime crashes when adding support for a new architecture.

Also drop empty hw_enable_tagging_sync/async/asymm defines for
!CONFIG_KASAN_HW_TAGS case, as those are only used in mm/kasan/hw_tags.c.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 26 --------------------------
 1 file changed, 26 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a61eeee3095a..b1895526d02f 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -395,28 +395,6 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #ifdef CONFIG_KASAN_HW_TAGS
 
-#ifndef arch_enable_tagging_sync
-#define arch_enable_tagging_sync()
-#endif
-#ifndef arch_enable_tagging_async
-#define arch_enable_tagging_async()
-#endif
-#ifndef arch_enable_tagging_asymm
-#define arch_enable_tagging_asymm()
-#endif
-#ifndef arch_force_async_tag_fault
-#define arch_force_async_tag_fault()
-#endif
-#ifndef arch_get_random_tag
-#define arch_get_random_tag()	(0xFF)
-#endif
-#ifndef arch_get_mem_tag
-#define arch_get_mem_tag(addr)	(0xFF)
-#endif
-#ifndef arch_set_mem_tag_range
-#define arch_set_mem_tag_range(addr, size, tag, init) ((void *)(addr))
-#endif
-
 #define hw_enable_tagging_sync()		arch_enable_tagging_sync()
 #define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_enable_tagging_asymm()		arch_enable_tagging_asymm()
@@ -430,10 +408,6 @@ void kasan_enable_tagging(void);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-#define hw_enable_tagging_sync()
-#define hw_enable_tagging_async()
-#define hw_enable_tagging_asymm()
-
 static inline void kasan_enable_tagging(void) { }
 
 #endif /* CONFIG_KASAN_HW_TAGS */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl%40google.com.
