Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB5W3YCJAMGQEF5OTQGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 74D174F95FA
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Apr 2022 14:43:35 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id q6-20020a1cf306000000b0038c5726365asf4327567wmq.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Apr 2022 05:43:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649421815; cv=pass;
        d=google.com; s=arc-20160816;
        b=B13LugTOyYs67FQIS6KcBIZo9o+6lPDr3otgG3J4aTxhyMa34fN9bk1Mjtf73AE1Wd
         WnJ2TK3F/rlt6A1oWsB+acgwTxX6PwUGhYRaoL1zWEtBUouqDTWpZPeet8LPkr2nyMdT
         s9QVPUkVLAyKvjlBTr1S75q8dKsnwbr2mfn7s/IduqN/tYOY7348jvqZ0a3btjqF0Ggs
         BmDmFBhBtGuTG7Z25ZA79FQQAafONCBW7A3TzCnkKvZNW5G7rqHevrFoU4JLDYeGBCFs
         u7NoqNSTNcd94oLkeVdYDaoRIckPZXdB1faxjSuSWNoD1Z5H+zcB1lPyOSOKt47OQ6wx
         LxIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=cJEOEdEbZr6rMafh37tqJrQ8IvmNfanWxUntknaUih4=;
        b=06Cs0KkDkboL89Z/oZlj8N5XM4jjnD51PNFW9M04aGFlNLHHuDtPFqYwFkLWB8MJC+
         fnTAp20K8Ux8RwRWQJszlmeK+v4A9cUljVNLyXWtwtBHMAnpxMVVhXMDnQ0gBPXZzLQ4
         RD9tW9rT+7JiLIwoYxjs7gUBSRM0tSoujnYBIt39VSEich4q2ol5JgR9sxcjfYNtgQBa
         tWmjqawaUjzcgeuZ7g0CblKa4z+ZpR1tJCCViPTaY7uvp7Fty0cY1b1IMH8UBLi8KPNm
         pnBfuN0N3KjbxFxRJK5316JKQPOC0Uh7PTsrEpczXE+SElydfz0mG/gmDJiWd9k58WXQ
         R11Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cJEOEdEbZr6rMafh37tqJrQ8IvmNfanWxUntknaUih4=;
        b=eJBE/89z3e2mbebRGwqB89kT1nKU4N7gYsqLtNGWlF6askNbfvr8MV0JhR7TGtMBpl
         rBZwQulyIikmLVaciBmA4DWe6OzqUY2cnkKsSjq6HRh0uxuW1ZM30aI9EaTczed9kyuA
         /ljH91C9TbFBy14mrEalpcHOYBP6OyY0UhemlM+SOaUZnkMZvKJKjwmd62UeSfGQarrc
         sNoS9DBdH0nwrfeURB6cWCCKVHfsvDHHGKvjCfrpa23Q9HkTrwFe+nU1kQ18Uh0dsIle
         LlbQLL8KajrDd8fHtgjuuALcjmFMYBv13qGaVRqFEX1dHTIQKrrWW1JzZOPnrq+f3mc1
         7sQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cJEOEdEbZr6rMafh37tqJrQ8IvmNfanWxUntknaUih4=;
        b=CkG+XCCXz2dC2FemV5A1XmtcgSZzh1x+dVAWZgNBa8SzGEnO8Heta2gvRnewPwacem
         kC+OT1O8QZ2IDurilxV454pRbv1bBfRPVNW95vvQgMQTOQ1eQ72trNwDofSLPPcfxLlP
         6XfdefAAnthVmcLKQDmRGSz+tBoivvBEUL74iAgv+PKOVBUZGn3AAd8SpC704dp0pZ9U
         8SSIV+QWjB/BBZxUR0uy9mNF4SPKkFfZGlclaCt/dVj/KgFndwy1mS2k2gOY3iojG0dF
         llrjFJss4lz+gNyqIHYomoS5Ts4nq9kCejtHYxr8wc0frbrklwp4dZOGNk6MRhp1ezdq
         cmUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530G6yHRMejHy3FyN9MYRA+Pw8KNY3QgcXQYFbUJYqqREAvm2+94
	oOJRxp0zw+jWKuCDIOUAzX4=
X-Google-Smtp-Source: ABdhPJwN4hUiCiEPq5tCaSDR7/3FTGJUg/PUKJv+TmIWmZG38NB9RHvlzCL+Zjz7ZNMOzoOzejVrrA==
X-Received: by 2002:a1c:f616:0:b0:37d:1e1c:f90a with SMTP id w22-20020a1cf616000000b0037d1e1cf90amr17488075wmc.148.1649421815050;
        Fri, 08 Apr 2022 05:43:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f5cf:0:b0:205:e1d9:2a6b with SMTP id k15-20020adff5cf000000b00205e1d92a6bls312405wrp.1.gmail;
 Fri, 08 Apr 2022 05:43:34 -0700 (PDT)
X-Received: by 2002:adf:b605:0:b0:205:ce51:ccc3 with SMTP id f5-20020adfb605000000b00205ce51ccc3mr15105062wre.75.1649421814063;
        Fri, 08 Apr 2022 05:43:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649421814; cv=none;
        d=google.com; s=arc-20160816;
        b=MwOtXxhzSWZmrgC67HNrXAfkyhdvuQA6XphKtzfscnzq6vfb3Bw4E2QMKTUc+xc6R3
         tMhr7rwwbfZYUJHR78I29RwYlENoMySqLqag5wjgN5Wb4t9sTbGxhwgicy9ZhEy0tub1
         +50I1IPH/zQ/drgI3/aKE+XHtOtcAdx6s4B4SC8Q+SeUskKzT6NYx/f+mM0DSBWuAoh7
         9JUXjxesGiIvqq1m9evGMS8U/7OSiYiEpUBgRZ3CF5sNpUeg4lD+4EIUFAGKUgn/TTNQ
         fPpAx9MGbkEnfq7GRfAr70J+4OPj14AgQam+mZ+4rtHgQKm9oYu16VUKuMhDN+88yNpI
         bK3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=+S0fdFHbHrpV0WfWMPU0KwDEp2iLVxk2KWTOjTDn7JI=;
        b=wTaqEWkXIyjouZhMnEY4vtLmPmYqsczZjCly9ewZllbRONgUVFgY/k6RjXeGBlj2sT
         xAk9NgGZCqC9TdIz7xkDTlXvvyxA/0UXsCr2QvVbQ37t4yWQSbKmEcE5UAnJq36uLzmt
         BT1/8X5OW0Hq1S9hIf5NwZdvQbYi+73A973yRTW4XRsX47zVuTRIDu+HmgfOmQoiknuS
         YZJasKks1ZP0Q4tdueVIL/fzA1O+FewIm2S7XBTPswJaNFk7kJDC1SQRfX2nT6ELXVCR
         DQG6uQqQWF8Hr6UDet31pqN9U0HVsufw5RuKrTktCARxibDDC551UmjpZKqitbMq5kdx
         Gv0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 62-20020a1c1941000000b0038e5649eef4si216632wmz.2.2022.04.08.05.43.33
        for <kasan-dev@googlegroups.com>;
        Fri, 08 Apr 2022 05:43:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 117BB113E;
	Fri,  8 Apr 2022 05:43:33 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9C4E73F5A1;
	Fri,  8 Apr 2022 05:43:31 -0700 (PDT)
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
Subject: [PATCH v2] kasan: Fix hw tags enablement when KUNIT tests are disabled
Date: Fri,  8 Apr 2022 13:43:23 +0100
Message-Id: <20220408124323.10028-1-vincenzo.frascino@arm.com>
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

  ed6d74446cbf ("kasan: test: support async (again) and asymm modes for HW_TAGS")

... and prevents to enable MTE on arm64 when KUNIT tests for kasan hw_tags are
disabled.

Fix the issue making sure that the CONFIG_KASAN_KUNIT_TEST guard does not
prevent the correct invocation of kasan_enable_tagging().

Fixes: ed6d74446cbf ("kasan: test: support async (again) and asymm modes for HW_TAGS")
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/hw_tags.c |  5 +++--
 mm/kasan/kasan.h   | 10 ++++++----
 2 files changed, 9 insertions(+), 6 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 07a76c46daa5..9e1b6544bfa8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -336,8 +336,6 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
 
 #endif
 
-#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
-
 void kasan_enable_tagging(void)
 {
 	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
@@ -347,6 +345,9 @@ void kasan_enable_tagging(void)
 	else
 		hw_enable_tagging_sync();
 }
+
+#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
+
 EXPORT_SYMBOL_GPL(kasan_enable_tagging);
 
 void kasan_force_async_fault(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220408124323.10028-1-vincenzo.frascino%40arm.com.
