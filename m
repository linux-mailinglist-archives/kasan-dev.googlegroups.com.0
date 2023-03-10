Return-Path: <kasan-dev+bncBAABBKUBV6QAMGQEK3OA36Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 64C276B55DA
	for <lists+kasan-dev@lfdr.de>; Sat, 11 Mar 2023 00:43:39 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id g2-20020a056402320200b004e98d45ee7dsf9771366eda.0
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Mar 2023 15:43:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678491819; cv=pass;
        d=google.com; s=arc-20160816;
        b=CqaNWIlhX4u1UX3o3NZetd7s9BrqE53+zTJFkjoRUC3kN6vZZg9Y4KrOFB8a1D0Crw
         QKiHDAo7zASKoqx1dRaPMTZA71V6GQW88W6zamx4Wsh/6y9Lyb470V2pUgXPMYvqX8qJ
         3/lEPO4vxDNSwIJr+LIB3REV+V49FIIIZ1eYSYo8f9bmq9sViUkeefL0jlmwHAqbtyLP
         zdoQDum5s2Du+4Stqt4+vM0bfi1XWmxnN18cbflN02cmEIrnpv9GtRP204oxfST9QDGi
         k0X0tQC6gVGQy6Ab4MP6AHQe94kPYWkwQfV6/YJsw8Kl5Q8veIQ9IPFOmfZi8EhZkc/V
         YQjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=x0DiItWnfSXolfpcWv3jP34XxlQmhyz4qxdlOvFt18I=;
        b=C7r3bVEMsfZMNC7D9/ZsYP93EIZOlEFbiTsJ+PBquu62B5/5u9FktrdAmZRRxPxvOq
         ArziOMcXF619sQQj9di8YThtTRhuVXhh2JpLorR+KESRc6x60OAlnH4LxaZw0/lfh2qy
         dvasjCH/7iHSn5uyu4CA7+BIC5ztb97sZieSfG6kUnC00fL+U1U6KxEe45Mlc3u0jxcD
         GE889EA1w3OCCOGANbX0lr7Ghl+K0vuZWqpLjt4Ji68eUqJ2Kz8Q059lRBAJ5dqA7Isw
         c5yxpCtEWF+A3hvWm6m7dlVs/uI+nu23+MY4a5lcCs3QSnIpGBmu7WfCjzORsiOpaoLK
         Zdog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=irItE+Jg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.33 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678491819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x0DiItWnfSXolfpcWv3jP34XxlQmhyz4qxdlOvFt18I=;
        b=IRk4bO9VDHQi9EU3nhCdTRf3QTcCN7OXIuukUB6KP5kd6LSvOEPhZR6a/SRK1BRfeN
         UVgCFHswi/JrsTjtOYKuvbtXjkgQVhCrfT5cBzxvHu8zwWak02u20zlhq6IRTwknQN4m
         CpMSQw2wH9U3/GPYXNixuT0SwGVrsjt7kMKr1rMUfd4nHLQSbyWLoShdqTJdsseUmwVv
         844Upq1IULqWWEbu7VUpgviA4xtCj4xoa37fLDVRK6K+ekYdQSpV2tC1FxbV3he6eZxx
         wr03NNHe8aKWICF+sBjfB2iuD/QG20hh/c4mOAZCT4shrRKcXUdi1J2RWjME3PVe1sdc
         Zzbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678491819;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x0DiItWnfSXolfpcWv3jP34XxlQmhyz4qxdlOvFt18I=;
        b=rDXpLL7VR1YvSkzeiavUW57shpqt7gqq44ePd8ch74K8Kc158j6DVG3rbW7SBcp57h
         mycwNRLth0TKFow/w2DdzeKlzpkfaAqEu4/m8ju4bYr6xLNC2s8+hEBse7dTJHO1tJIp
         8cFvfcaNeTy7oAOzzQVKyaOpfQ11GwCOCFjlye3ebziILSRIdkvsmIkXbA1UYqU+5h9I
         NJbstXz/BjaVmQTio0+W6fhUIzMM5LCDFKdEK8CRWVrgm2WOhoYyn3BMegBjfgr6v6IK
         1U8X6QGwVbmmCB4o6uvnmRywFR175/rjxnfYZp7YlW8a/5oa4g3sg0AWzUvpq2i+zMST
         NsrA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXcPunkdrb/8f8rZXjeUvh/ftOUIGN5jKh+ZFg1nfCezF/LtYJd
	IyI6lCqR6KM4WkKadk9q5Po=
X-Google-Smtp-Source: AK7set/2nZEKJLYCS21Pv8zd7t9LleZ5FzFjBR1/33KRqgTRRHmyIiM7JSrnqxJ9FlzdJlY3gSs9HQ==
X-Received: by 2002:a50:f684:0:b0:4fa:3c0b:74b with SMTP id d4-20020a50f684000000b004fa3c0b074bmr393975edn.3.1678491818982;
        Fri, 10 Mar 2023 15:43:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:6cf:b0:8b1:49bd:b751 with SMTP id
 v15-20020a17090606cf00b008b149bdb751ls4591757ejb.11.-pod-prod-gmail; Fri, 10
 Mar 2023 15:43:38 -0800 (PST)
X-Received: by 2002:a17:907:6d18:b0:8f4:3846:31e0 with SMTP id sa24-20020a1709076d1800b008f4384631e0mr34694587ejc.47.1678491817975;
        Fri, 10 Mar 2023 15:43:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678491817; cv=none;
        d=google.com; s=arc-20160816;
        b=Ld1S2100p5gXzqix4u/nhHVu3tsuYd9GOJLuwsKGz1QWvhtqyzSg8GzTa558aceneO
         hU73PT8aatCsDW0lUSHU24y07qIi+othZw1BuOMUuuWNMbEY19QALOWM30gdWr63j/YK
         t3wRBqHr+KuFAlmDMsgy80cbmutNMFQPCpZkWHmGrrCJqmxn1HkPEflUkphv7hSU2cyW
         uEgWwNgKBGwEH+Kz4dMUqp44bzWbIz5bMKnOrXdex57qvSnLOoecCX/TrxErUzgSikZ0
         YqPNS5+EQ0xDqJHRSXxlta0HQxA4a7id8U824Rd4vdcSmJ6K/xtjlMCDBOGU/6s9+eIg
         nvXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FR0GMMMnNdReMCefH2++iHzkAdqxWWuGhtNaRaBked8=;
        b=uaULVTobBu6yRWEBMoBBq2hxG6BwCHXHRhlFV7oMhHhibqLv7EQn62udsqtpGhnG8b
         1nkMBie/MhVhAcUlJWHvp58YCThmgOSZDaLn4lQEsoCNOyULqrBU2PnZpZ6n3xddZ9Uo
         RtIpffdfYsn9Eus9wuA+kaQiWmqcTfL11JI5VNyUok2VHWTMeMsNvqz0GnTbPuKrt32D
         rXrNCl+1qizs43HNhCddlzp3sebD5TAhWWzu4RSBNXVrzx5ZVgpchC5339qWowAvxnFd
         gOvts9Cwo/0up3TR4VvvpHlf3mqRgxR0RzGK97l3d2pHOIO3rphAAg6XjV9e6Ze0j0vB
         oZUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=irItE+Jg;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.33 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-33.mta1.migadu.com (out-33.mta1.migadu.com. [95.215.58.33])
        by gmr-mx.google.com with ESMTPS id y26-20020a1709060a9a00b008b14694acaesi63965ejf.2.2023.03.10.15.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 10 Mar 2023 15:43:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.33 as permitted sender) client-ip=95.215.58.33;
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
Subject: [PATCH 2/5] kasan, arm64: rename tagging-related routines
Date: Sat, 11 Mar 2023 00:43:30 +0100
Message-Id: <069ef5b77715c1ac8d69b186725576c32b149491.1678491668.git.andreyknvl@google.com>
In-Reply-To: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
References: <bc919c144f8684a7fd9ba70c356ac2a75e775e29.1678491668.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=irItE+Jg;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.33 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Rename arch_enable_tagging_sync/async/asymm to
arch_enable_tag_checks_sync/async/asymm, as the new name better reflects
their function.

Also rename kasan_enable_tagging to kasan_enable_hw_tags for the same
reason.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/memory.h |  6 +++---
 mm/kasan/hw_tags.c              | 12 ++++++------
 mm/kasan/kasan.h                | 10 +++++-----
 mm/kasan/kasan_test.c           |  2 +-
 4 files changed, 15 insertions(+), 15 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 78e5163836a0..faf42bff9a60 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -261,9 +261,9 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-#define arch_enable_tagging_sync()		mte_enable_kernel_sync()
-#define arch_enable_tagging_async()		mte_enable_kernel_async()
-#define arch_enable_tagging_asymm()		mte_enable_kernel_asymm()
+#define arch_enable_tag_checks_sync()		mte_enable_kernel_sync()
+#define arch_enable_tag_checks_async()		mte_enable_kernel_async()
+#define arch_enable_tag_checks_asymm()		mte_enable_kernel_asymm()
 #define arch_force_async_tag_fault()		mte_check_tfsr_exit()
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index d1bcb0205327..b092e37b69a7 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -205,7 +205,7 @@ void kasan_init_hw_tags_cpu(void)
 	 * Enable async or asymm modes only when explicitly requested
 	 * through the command line.
 	 */
-	kasan_enable_tagging();
+	kasan_enable_hw_tags();
 }
 
 /* kasan_init_hw_tags() is called once on boot CPU. */
@@ -373,19 +373,19 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 
 #endif
 
-void kasan_enable_tagging(void)
+void kasan_enable_hw_tags(void)
 {
 	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
-		hw_enable_tagging_async();
+		hw_enable_tag_checks_async();
 	else if (kasan_arg_mode == KASAN_ARG_MODE_ASYMM)
-		hw_enable_tagging_asymm();
+		hw_enable_tag_checks_asymm();
 	else
-		hw_enable_tagging_sync();
+		hw_enable_tag_checks_sync();
 }
 
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
-EXPORT_SYMBOL_GPL(kasan_enable_tagging);
+EXPORT_SYMBOL_GPL(kasan_enable_hw_tags);
 
 void kasan_force_async_fault(void)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b1895526d02f..a1613f5d7608 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -395,20 +395,20 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #ifdef CONFIG_KASAN_HW_TAGS
 
-#define hw_enable_tagging_sync()		arch_enable_tagging_sync()
-#define hw_enable_tagging_async()		arch_enable_tagging_async()
-#define hw_enable_tagging_asymm()		arch_enable_tagging_asymm()
+#define hw_enable_tag_checks_sync()		arch_enable_tag_checks_sync()
+#define hw_enable_tag_checks_async()		arch_enable_tag_checks_async()
+#define hw_enable_tag_checks_asymm()		arch_enable_tag_checks_asymm()
 #define hw_force_async_tag_fault()		arch_force_async_tag_fault()
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
 #define hw_set_mem_tag_range(addr, size, tag, init) \
 			arch_set_mem_tag_range((addr), (size), (tag), (init))
 
-void kasan_enable_tagging(void);
+void kasan_enable_hw_tags(void);
 
 #else /* CONFIG_KASAN_HW_TAGS */
 
-static inline void kasan_enable_tagging(void) { }
+static inline void kasan_enable_hw_tags(void) { }
 
 #endif /* CONFIG_KASAN_HW_TAGS */
 
diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 627eaf1ee1db..a375776f9896 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -148,7 +148,7 @@ static void kasan_test_exit(struct kunit *test)
 	    kasan_sync_fault_possible()) {				\
 		if (READ_ONCE(test_status.report_found) &&		\
 		    !READ_ONCE(test_status.async_fault))		\
-			kasan_enable_tagging();				\
+			kasan_enable_hw_tags();				\
 		migrate_enable();					\
 	}								\
 	WRITE_ONCE(test_status.report_found, false);			\
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/069ef5b77715c1ac8d69b186725576c32b149491.1678491668.git.andreyknvl%40google.com.
