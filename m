Return-Path: <kasan-dev+bncBAABBBULSKQQMGQE5DCMRSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 91E766CF23B
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 20:37:59 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id l16-20020a05600c4f1000b003ef6ed5f645sf5144790wmq.9
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 11:37:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680115079; cv=pass;
        d=google.com; s=arc-20160816;
        b=wfMBHVQRrMQ1xgHSOTqDKzXg9yOUCtX78Db8ctiUrvj6Q+3xHI3ThG8Ho6c7KINKMJ
         Du1S9v2oYNhHxijrTSkPWsdJSZWBGyOT84FYWmpVOD43eEZwkzBN4CMKjpf/0SbFR1UQ
         3VMLmUH4nBWJf7QZtHeumvqS9Z7kFJiIw2u+EqG96MGvtvIpoxj3xjGYXQqzHijj+mRF
         JSB2/StlVQ++BrDY/Zhdj/N8Aka+H01j5LIXjxtdKe/t1bza/glooumEw3IbE5/NnXb0
         eZP4bHQ4B88NyBpPvMraAHl5Yn6NUjpCsGug+Eo8StDZPk2Av5XpE22ANGywgt/2CgXF
         DRsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=pLjP/AEM58BCGtb3okXKPHEtKQ8VnMvIpfqLfboNvC4=;
        b=aSCzMw+1zuKp7y8VKX27srVYOfNroQyAuQ+Z52t1KczJ8uJB/TjJXRrLCSe3agdFWV
         zlaNMZUKVc3zkD23sxE7TRwcwb1T5bEbhyPCe7WuHJqi/1o1nEXYYIYr3EKj53yNqXVA
         3TCVxJvQ7ZR0kAoau+o2xs4RY/ZTPm3ywpsdlrhthNIWDhKLpGIHbokU+gRkEBI4UgHz
         RGYhZfjYcVw8UoE9q3xvv0XAp5QhKWYHITlKke0jtOXrXFWzrL8jJCJCjqVwVIg6+8hx
         pkyt39PKFATlilJiU2NpOyEuyi4IwoAaU3bg4FE9tkDED9+oZgk6It/eKvx8h7me4bNN
         7z3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DbXVQvkG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.20 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680115079;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pLjP/AEM58BCGtb3okXKPHEtKQ8VnMvIpfqLfboNvC4=;
        b=LpzPoK23z1qmTUjan6tmStQj30/FLGYfxBmtJbTr/8yTScT2G9+DJMEp1mJstrtUd0
         LBimmdbtkU0GOv5eCafcoqjZaZ1bU6VobMBt7dul9nVyzTLbhkukf/jIO8EKg29KUun9
         t1TJd13H6t3tpBQO+OrgAbFCVpvZ5ELiE/Q2LzU1E8bjECNnU1gvznyqcPZc4ES+GiM3
         dMdJxCp3bYoXfTCBZCrCemzXT7SmV2FjrJC5FN9YheqGOtakpZB3sFKWIQB+emhe12rR
         7lFWm+b6KLxPpc01eNm+fwWyU4osp2r9aXSAFZDBOusW0EMYbqhNGRLw5cBiiruwWOqu
         xq5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680115079;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pLjP/AEM58BCGtb3okXKPHEtKQ8VnMvIpfqLfboNvC4=;
        b=ESubuKj0Tiht5vy9935H0+hPLOrSJQCWL9ElvKb5CLraGKhT/fxieIucuE1muwlY+F
         PvHD5sz4+lzRnF2cD60NaBVLmoD+Aa/7oPuLnmfaHSx2eM4gJOkcQDiXUV4Nk43QNebr
         iaKYO30wBz1zSgc5umrZNyXFx5afo9EjGr+usSTfreXQd2KhKhNd4dIJ9ouMLOlQY8aW
         ghpMdpnHWBYKQKHCXmktfVM5LHooTUAW3sV7iH7sMWthGes7s1ZwuXowVlB2w84XEG1i
         cYuG0T5FBatF7ru+qWeAGfCEF45RtpeLi14lXdM0sPcsm/tvX0aWrs5EGjpcf5AF9r+a
         P1GA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9eS7JLBtHzRXnnz+86K20PfQ2uSADh90xjKd+bNxDGGNlpg98Sv
	xBPmYv2DHkSZIr5CSYDq/Dk=
X-Google-Smtp-Source: AKy350ZdkMmHpngxfzKPSYC1I34wzu11iT9TXKHIP9IzxsjKFELjMhjUslUZBrSysaUcRrVgK5pm5A==
X-Received: by 2002:a05:600c:1c23:b0:3ef:6989:19d4 with SMTP id j35-20020a05600c1c2300b003ef698919d4mr1299176wms.0.1680115079044;
        Wed, 29 Mar 2023 11:37:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:993:b0:2c5:557d:88a3 with SMTP id
 by19-20020a056000099300b002c5557d88a3ls24978994wrb.3.-pod-prod-gmail; Wed, 29
 Mar 2023 11:37:58 -0700 (PDT)
X-Received: by 2002:adf:fd47:0:b0:2dc:cad4:87b9 with SMTP id h7-20020adffd47000000b002dccad487b9mr18272844wrs.68.1680115078149;
        Wed, 29 Mar 2023 11:37:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680115078; cv=none;
        d=google.com; s=arc-20160816;
        b=PKpD9PKbRakPW5bGaR8XhNt5OGSAgAIiOKWaaELroRmuJ7vvW6/2ExVL0pBL8rusdc
         +6Kiqo4Abb6haxyQ99jZjeQPfduEHGSQLX1Bpgp9j1TRju92pGUX7sqc8/99lM7/iWH8
         JyEgZDOK1bLhOz/TNAufGu2Th9oRmOs6dfnBV/unu4qc+ZWE2A34LKDHN/p2/0v8rPTe
         SCZU5a2yGowNlOpH2CsK7eUaQL36ZOlNOo7wp1g17v2u4tudCufhWciCfzk/x/eMzLjB
         9RtdfYXObBkP8lBAM+2kimp0HzTw312ZeQir/ZHtGUMApqklsTU87hzXZjW+BpBgrD58
         KO2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FR0GMMMnNdReMCefH2++iHzkAdqxWWuGhtNaRaBked8=;
        b=LbSHJnSzLLulYZbPzzzXR2tnPaxzbB1KbojxciuQqHovH/EHTJz7pfB9M9e9qxtaN5
         08gpYoc/cfOqAOhF+uS418Pn7BAqBxakpBtR3cYFzCUf0PmN28kLNu+wSckKbMGKHtY7
         UV1bJKTIJBg103sCOoZWfdB9rJq8FayQksmftHR5jV41CRPtkGfYsrufYO/cSUCgRjuG
         umA0o1JpuPGHbSqR74CAvWDASFxM7lwPpbMEJDMkgvdZEwjyRRhjrjpVwys/tZIKz/ps
         gaeprJOtSWWUfWON+Q2ZZE1I8CByIAx7R70JYZJBw7YvCVb2K0Re/x7wIXHFrhbkS/ia
         TvvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=DbXVQvkG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.20 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-20.mta1.migadu.com (out-20.mta1.migadu.com. [95.215.58.20])
        by gmr-mx.google.com with ESMTPS id ba20-20020a0560001c1400b002c59bef13d2si1628868wrb.8.2023.03.29.11.37.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Mar 2023 11:37:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.20 as permitted sender) client-ip=95.215.58.20;
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
Subject: [PATCH v2 2/5] kasan, arm64: rename tagging-related routines
Date: Wed, 29 Mar 2023 20:37:45 +0200
Message-Id: <75c4000c862996060a20f1f66d6c9adcf9f23aca.1680114854.git.andreyknvl@google.com>
In-Reply-To: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
References: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=DbXVQvkG;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.20 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/75c4000c862996060a20f1f66d6c9adcf9f23aca.1680114854.git.andreyknvl%40google.com.
