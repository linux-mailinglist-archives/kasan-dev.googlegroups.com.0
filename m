Return-Path: <kasan-dev+bncBCCMH5WKTMGRBO446XBAMGQETMSSOKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 77519AE9F2E
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:42:22 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3a5058f9ef4sf481198f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:42:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750945340; cv=pass;
        d=google.com; s=arc-20240605;
        b=BJEVS+l3XRMUiknjRHdJMgILaGDfT6e6wABqEijbrHEnAeDMQ0jSjewcwpbaA6ntbk
         FF52idQs0gXqnrZy3Z2H17QMzmNC3Zs3vcN6hpczBQZJDQXRHUMlH8Hg1x6joFpBtOmj
         LNCySHgM3DLlCUsWLKzu80WHWK0coWKN5ZBZQhTExau4l1C/gpORbnq4cOiToSTYkCgH
         Z5SwUWsNtLuhUabkCCYxev4IJWjkonOAt9dYxY324AzIKPg3K8OOkiJ648rsZx73osdP
         DiN6EH16fvG8UfcN27F6GC1SNcv3984d7LnWRP0Mf++OaBvRfbarY39+UOxrKdaEALzi
         IlDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=AhXkFrX7JpE4u5zQyMWxodlPeux0zgAW9HVwEYDp17s=;
        fh=twqVslgBQ7788L2kQrCCWfAP7u4o6vYDcJcTq7p258Q=;
        b=d+bIPKkEdPEpW+3XD2SMdSTMcuFu5kEyOtz12704Qkz+5ogLxpvv0TDmvRcSIXD2i2
         KmXs+RHuUrTDcOxOkf83lPdH1OavkFV2G20X9h8sreXMpLvvd55i37Dg7EeEve57wm4J
         U7ti/veoNnpxQ//aBkOz2Ef9CU5cDG4y7W/Q1TmLVqS0/zPzf7Cny9mj9WmtBD4BAbcl
         O61OE2/NEibzLSBhVRfD4J/S0Dk9QuKhEnnqGyey2nXLDd2kFQxC/TxLORS9WBkkR3lS
         frOmQtcX9lUatQj+szsFQijQQBxWh9jO/8VWnbpc5ybG+jkd9M4tLcmweYgZwcMTPMon
         j15w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FZCnW+6+;
       spf=pass (google.com: domain of 3ou5daaykczq49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OU5daAYKCZQ49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750945340; x=1751550140; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=AhXkFrX7JpE4u5zQyMWxodlPeux0zgAW9HVwEYDp17s=;
        b=btiaxCOtMZljhbtT8hx32ka51u1jV0tU9D7ccF/iKlJvEkYdicKa82yAXNPw6/C4Vh
         iDUGMRvSAX/p37YZ8m7wN0jJN4Kttq4YTczPLd860WdyE27rWDh+oTc8/Mie48Rrdp9C
         zSbOZNjyPtn5jvCLldmKOp2U3t+P0aZ3XR8fkOa+R1Vw9WK39Tyoakeivyc9UTrWO/7p
         m+ZJytB5/U0OV9D+CQPP/ghy1gKDfI0juj+DHZZNglA630IA47eAvv6gKnqhP0vG5tWt
         rJrGnESs1Q1Nq1GnjtGVHkhVwuUiFDJCnGfaWDu4joWxfh6SfVSCw7ODWO9RfSfi9pQB
         lSiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750945340; x=1751550140;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AhXkFrX7JpE4u5zQyMWxodlPeux0zgAW9HVwEYDp17s=;
        b=jVMROWyPaajZLJaAJijlgplY0TeJqFJNSAVCwj/cNme/lg633JXgB4HtuVxyHVeaXt
         cSnv844TOAw5l4BqkpkeSLxRATeJ43ruqsFAkn9oyLOzajxOJXh/kcWFvdfipU9hdRJ0
         pj8xDb5UvGYCcV6w6fA6dEerTFN4CDxTyMmJjujZOEi0fjrlBaDQ2NwnXWluzb8VtB9r
         Xiz4fH+SgC+6ofqF1O04i33H2DcKvHKZpbVwQC1vGRNvjwpnh8Pl+SDW8MV16eOpdfqU
         oZ0nfOkjGz4KNbPmvkeaJWFpc770fMPkZlIC9a386ehHV19QF9Ku/rAFdQ1lHkDNjffp
         VseQ==
X-Forwarded-Encrypted: i=2; AJvYcCWiFzcKUtqk6lv/8AxCEtrJ5Uapl6G/0AvltevClOdemdDD2Z22BmQlL7hDaxURtbHJuxzNXQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyg/EEMK3H7KE0KwS0xBNUolt6//ov4xVcPFV4KoD+iGQAfC8qP
	0FgEvtUHB1fWQK6mKXCGZWZb5agjshyj0kKESNoE4xbyTJcLnxpD2mCJ
X-Google-Smtp-Source: AGHT+IFg/ye8+lj0/2hl0diAI2Sz0lpVATI/KotzZ+7dtCM/cwZJAJnLYh6sbe2jTaeBn9Bn6tb1Vg==
X-Received: by 2002:a05:6000:1a8d:b0:3a4:e6bb:2d32 with SMTP id ffacd0b85a97d-3a6f2e8e619mr3295982f8f.22.1750945339859;
        Thu, 26 Jun 2025 06:42:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZduPEgAEI3GFXigMdHUEib3fe+IsCiOTpY3Bi6CuWhC7g==
Received: by 2002:a05:600c:3586:b0:453:87e:c391 with SMTP id
 5b1f17b1804b1-453889d8940ls4773605e9.0.-pod-prod-01-eu; Thu, 26 Jun 2025
 06:42:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU6liNuGHeb/iqYykfQM0aOh8ZRHHPS0zFj7yy01Lleic8cV5i8ph6ISpBtHHLnGXnUsGCUmxolkf4=@googlegroups.com
X-Received: by 2002:a05:600c:3b86:b0:43c:fa24:8721 with SMTP id 5b1f17b1804b1-4538b2e60c9mr25608355e9.17.1750945337486;
        Thu, 26 Jun 2025 06:42:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750945337; cv=none;
        d=google.com; s=arc-20240605;
        b=i3J+WafaBU6lW2Ag01HH6PBh1lOf4t7eXkH+8TmOrcsY8gByq3W9VKpkAUyFk0+IPo
         X7bixUhnSVzsG+fUauCCpHHX+mJixrHxDikX2fngTFtZY+dyvRK9AJJtXRu0gnIWGyss
         IHjxtQvCzm0uhh7rpxYQr9AHv7cpIJUJpm0CatHjQZWapZ/wlj5lvgaq+GRd1ssDjrD0
         MnnNUBqArCoBEEcaPGn931GRmLtCPxQPSwLiHh/zAh+iOIVfUxM5lf96WHoT5Jc0oYS1
         NDWfla2mG/tXQKwbeXuis6mztyIvlv6fn93zQ6rlOkglQR9fU3CFb95u4Wo+vo2Zx+9Y
         F8ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=48paaS1qVo9hnWK9htYJQbyGTvWCJegAFjsjDLyyhLA=;
        fh=eHmQaASoxTiogZokon4FooAq4rLH++w5WkM2YcuFNGQ=;
        b=NgKYh3w2CxppYteHVd7WWg75BZz4RUTmop2MvcD4+RPSTRK4Ob7+bbkaGL7PZIV5hZ
         OnWAmqlBlQ3s/Ra4qo7939PvS5rKWCB+as+FgPQD6Y/Hqa2BlSAPI3ol/PC7h4q0wrxS
         F/y4v+O/mNhheuKWMVp2mZLXvr4gQMVvNlC76zLWh1wiDpP4fKaMFJ6M0iWSs4St/l5E
         uyEc+GvEjBWUIbaBLskprPjtkYTfF4LikK92m6tpxUfkdhL3RD1CTQBm9Eq2ZxsDbnBx
         83eHWMrcjB/6BDB8LBpHhJQMzU1V61An/Oci1dYudsLpbEGhIZLSnrDhvk+NcEMpPZ2b
         BCeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FZCnW+6+;
       spf=pass (google.com: domain of 3ou5daaykczq49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OU5daAYKCZQ49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453814a5390si1054615e9.1.2025.06.26.06.42.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Jun 2025 06:42:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ou5daaykczq49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-450db029f2aso4321425e9.3
        for <kasan-dev@googlegroups.com>; Thu, 26 Jun 2025 06:42:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVRJCjIHEcordldziw8UcbUT0+Pz6hdyasiYM/FmQv7i/rP9LsmUQKjh4zcIPEYj8g7chXILdDtT1c=@googlegroups.com
X-Received: from wmco17.prod.google.com ([2002:a05:600c:a311:b0:43d:5828:13ee])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600d:15a:10b0:43d:b3:fb1
 with SMTP id 5b1f17b1804b1-45382a3dda3mr40122955e9.27.1750945337108; Thu, 26
 Jun 2025 06:42:17 -0700 (PDT)
Date: Thu, 26 Jun 2025 15:41:52 +0200
In-Reply-To: <20250626134158.3385080-1-glider@google.com>
Mime-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com>
X-Mailer: git-send-email 2.50.0.727.gbf7dc18ff4-goog
Message-ID: <20250626134158.3385080-6-glider@google.com>
Subject: [PATCH v2 05/11] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FZCnW+6+;       spf=pass
 (google.com: domain of 3ou5daaykczq49612f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3OU5daAYKCZQ49612F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Calls to __asan_before_dynamic_init() and __asan_after_dynamic_init()
are inserted by Clang when building with coverage guards.
These functions can be used to detect initialization order fiasco bugs
in the userspace, but it is fine for them to be no-ops in the kernel.

Signed-off-by: Alexander Potapenko <glider@google.com>

---
Change-Id: I7f8eb690a3d96f7d122205e8f1cba8039f6a68eb

v2:
 - Address comments by Dmitry Vyukov:
   - rename CONFIG_KCOV_ENABLE_GUARDS to CONFIG_KCOV_UNIQUE
 - Move this patch before the one introducing CONFIG_KCOV_UNIQUE,
   per Marco Elver's request.
---
 mm/kasan/generic.c | 18 ++++++++++++++++++
 mm/kasan/kasan.h   |  2 ++
 2 files changed, 20 insertions(+)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d54e89f8c3e76..b0b7781524348 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -238,6 +238,24 @@ void __asan_unregister_globals(void *ptr, ssize_t size)
 }
 EXPORT_SYMBOL(__asan_unregister_globals);
 
+#if defined(CONFIG_KCOV_UNIQUE)
+/*
+ * __asan_before_dynamic_init() and __asan_after_dynamic_init() are inserted
+ * when the user requests building with coverage guards. In the userspace, these
+ * two functions can be used to detect initialization order fiasco bugs, but in
+ * the kernel they can be no-ops.
+ */
+void __asan_before_dynamic_init(const char *module_name)
+{
+}
+EXPORT_SYMBOL(__asan_before_dynamic_init);
+
+void __asan_after_dynamic_init(void)
+{
+}
+EXPORT_SYMBOL(__asan_after_dynamic_init);
+#endif
+
 #define DEFINE_ASAN_LOAD_STORE(size)					\
 	void __asan_load##size(void *addr)				\
 	{								\
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 129178be5e649..c817c46b4fcd2 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -582,6 +582,8 @@ void kasan_restore_multi_shot(bool enabled);
 
 void __asan_register_globals(void *globals, ssize_t size);
 void __asan_unregister_globals(void *globals, ssize_t size);
+void __asan_before_dynamic_init(const char *module_name);
+void __asan_after_dynamic_init(void);
 void __asan_handle_no_return(void);
 void __asan_alloca_poison(void *, ssize_t size);
 void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom);
-- 
2.50.0.727.gbf7dc18ff4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626134158.3385080-6-glider%40google.com.
