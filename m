Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFF7Z2YQMGQE2LI5B3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id CCB118B9C18
	for <lists+kasan-dev@lfdr.de>; Thu,  2 May 2024 16:13:42 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2ded4efd0a3sf58946131fa.2
        for <lists+kasan-dev@lfdr.de>; Thu, 02 May 2024 07:13:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1714659222; cv=pass;
        d=google.com; s=arc-20160816;
        b=t4h1DDJDhtppkmVzXFH1JaMkri7YoHRuzqKpHF4XY3VMAX9d/YlfIy//3xibY22ZpY
         AwejtEf/ksAtMo7UyJ7oA5ZcupFUT7ciJI7CnTPjULJvJPPILVkFoprtOvt6dbXzPTcC
         HiTWEqMC8P0lQBQCnDUt8r/ASZ+C4yinOoHAS276uxRcTeObDBiKtxgoJrIdkLAmRVWZ
         lW60LV2vek16878G7VHTVx55mzCkX9I8sHMZWt/XHdxmsFGNdmPm8zlF4844y0gUww9T
         dlhFGiy6H1G4A548phHuZ5E1bjdXc5sn4LONqKJ3N8iYqc4+XFewLdKkN+wWdDkiX+8l
         tTKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=CM+wVjb2VO8uv74nW3+AnWQWIpg8Xvf1VLU/ly6B+7A=;
        fh=REMQ9SdFHG/En/m6yHyWwm1+k7Dh2pv9rvXmlzJ9P84=;
        b=sDwibhjX01kCZZFCAadE0lzzw9JWPncXneBNBIgrzyVovUP5BTKnDtm2sR0nbfdkVU
         sqP9KBKIIw8f89MALstZOdZ9+7EhAYXsbiv6d5ow94JsKwSuyKW5LLfkaKI/50wGmZ44
         gD/MXpihve+w/FL9Ftj/1kUpHR66I1HtFQQ4NT/uxCgnQ78AOPG+aQAs0QHQRHydd4MP
         WOWRXQiRSd2WaHKnumV4meOcVU0PRJEBB+ZF332hM8MVsL9df7NXkkgtXkVMkR10MyAB
         pnczaayEN4y1G4CtN8jSEltYcNIfdAQaZiU49K7OsHVu0aR6plOyH6HPMvPVgUTmY9En
         yRLA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T7oK9Ilh;
       spf=pass (google.com: domain of 3kz8zzgukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kZ8zZgUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1714659222; x=1715264022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CM+wVjb2VO8uv74nW3+AnWQWIpg8Xvf1VLU/ly6B+7A=;
        b=FnznA/Y6Odw5qVLdLbZEdddhL9PZJx/4H7mNUU7OPsq7D8ny7ZE7Fd6H+IH7Xn1m99
         oNSxbcxfr1T5dAUNFAxTfn1YjP5911UQz8tLdxIn+psbyHFTLTcWMeyOAfUviosj1ok2
         B1QDJZixpAIG9T8kTep8lLMCws23etjfs7E0gy0eIgSxYKad13nheLr9nKpIp4HK+fcf
         67ispSr4t5G6XSK5ZDbyGcY6BaKkz6W0yqL3ps4go8yN1qIjO0hDy/pwai55X418xSjN
         pH+64hPhYQrX2bsRsVUF3BQQa90wlZ89wL5X0i4bhlRZbbc7XR6N5S5pZyxtjZYcH26S
         imkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1714659222; x=1715264022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CM+wVjb2VO8uv74nW3+AnWQWIpg8Xvf1VLU/ly6B+7A=;
        b=NfJT+miW5cwvHILI2FZQ2fG3lDfXFOKaDRsA3g2i/p110JBEa1h3awjhQoZKrfcExL
         QFvfju7/4aTmq673lt2dBVRChk4wnfBEw6akbAeAnoIOQHkc7imkSn5v1hJkxSu55d9G
         ChBwJz32JGda0xXzN/r2ZoaWFK9yHkr5dhZ7nS/seYOODsK5BSTaYPF0lzbA0mYQBPka
         UYc/yNiEbKAJ5I5vby9FdIUt65pPhgVumpSCMtHbJiD0G7I5NvkBzg6SMn4NdWg+iwYn
         2vHfOPboU54Tud2ltqFeRV/hgZ+rbSwPqswLJb5D0AKcyh2xMRCkecbML/N6eeCnejFp
         +RnA==
X-Forwarded-Encrypted: i=2; AJvYcCXb7WirU8hjLxI3uVvnaj5kxwriJWaTstB2UBtQgAPl9uGjXTlTeJvRuOVg6UjiqUvvFIPgVPGJP+v+bzq3GLOeEBrB0DHWlQ==
X-Gm-Message-State: AOJu0YxywgD7kETXKKxubVSrLZczUkPYBuH1K6Cs02gciPFEkMPYvvu5
	1Shcze/tOw91jzvLlW7KPDJv2HaL02n7nowo6Pdc4v3kEz+pKnZ5
X-Google-Smtp-Source: AGHT+IHkvubihoUMVf3LejAcTRxnUpolLyoGbFxNyLyMsIWjouVoBdK9DeHWW6wK7yXsZpPLlZzvFQ==
X-Received: by 2002:a05:651c:1309:b0:2da:9ed:9b43 with SMTP id u9-20020a05651c130900b002da09ed9b43mr3933357lja.31.1714659220799;
        Thu, 02 May 2024 07:13:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b711:0:b0:2e0:1a91:ca69 with SMTP id 38308e7fff4ca-2e1bbcbc704ls2996221fa.0.-pod-prod-04-eu;
 Thu, 02 May 2024 07:13:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUm4L31FwKigZq6oJr6SZj07NWDYDXGkUlz9sd42tnoZMX2w6jfWXOnK60wwq3jbp4xqtg1XiAilrpudf4RX9WrmPxDh5WcUPIIHg==
X-Received: by 2002:a2e:a685:0:b0:2e0:83a9:e384 with SMTP id q5-20020a2ea685000000b002e083a9e384mr3723895lje.5.1714659218131;
        Thu, 02 May 2024 07:13:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1714659218; cv=none;
        d=google.com; s=arc-20160816;
        b=Y+rizJKS5k3kaElS+WSAR+3lHbc0J0cgE8t92bNgHfMmDSrWEPL4rfe+SiusIZeI9/
         2Mq6eybbFsEHZ4GokPQ4LSCvq4upTkUTt+Pvw74nArfFyVw4j6RfexeQG4FSE2CKpKS0
         DEcARivfaXvwgcybn+3F/RhMHe7Z9m5wAVlxtPQAfBIEGRqkceaEWEq1WA/myLrlPuY0
         cFXMCjYp8v4314fvoSuWqzXO7EFooc7FOGGHP8FtJ3NjaQbCq2fp5zPKxE/ptTsFE816
         vrMcokTBY+DDSvJYyYdtgmPtZgG4UQXRAjIYb+JDCm9SJP5hrg5T++l05Xwkj95u8L/M
         DocQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=HsPj+acZKYK2WoyW/9ElzwwE/qj1TMWpdQ6bEOK7unE=;
        fh=ejl3BtUE8Q10tm3cfGSf0/9Z5FwwY6YhCP+TH3IvdzQ=;
        b=Xy8Ed32xw00Z54z2CJpvYxPrOO3cYP+yXIAA/YcojAeJQ8VuUpqpLFyeHQJ+gYUSS5
         o85b+OQhY+R2qMTZvr6EoJaBtxSymnWraWrkyZmT7lV5tkkJqNFkvHCYVDDET7zQxsi7
         uXEFT79KrWJeKCzV2lCt4fKmGj7X9rCK9dj0Z2kqfeDC6VCUzer+mqLYYiiEYZtJ02Ug
         gpHRjNkqwz6l7kFUsK/nGvvGMz6/bNCArDBRq8Dr+1ONZ4GeNtm+UHhgIlTb4EjZdlsO
         TLPLJHNx93j3dYcm7XWkg9ILNQPdOygfJB1NQVJzS5Vk6KdETdK8Rb9JZZbwK6ayoits
         Y9og==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=T7oK9Ilh;
       spf=pass (google.com: domain of 3kz8zzgukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kZ8zZgUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id ay20-20020a05600c1e1400b00418fd26d618si39568wmb.1.2024.05.02.07.13.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 May 2024 07:13:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kz8zzgukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-a592c35ac06so199464566b.0
        for <kasan-dev@googlegroups.com>; Thu, 02 May 2024 07:13:38 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXU4uarsqFp/9bWajye8EbyFaQ0zYg7mNxGwEoefJtFmNqHkpYvsZaYrBbmudJxURnB9EMXosQib3fYLnaHCMV28/W1zHg+FsQKcg==
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:7572:6c35:c45a:3523])
 (user=elver job=sendgmr) by 2002:a17:907:8691:b0:a58:e8cb:2989 with SMTP id
 qa17-20020a170907869100b00a58e8cb2989mr3504ejc.5.1714659217590; Thu, 02 May
 2024 07:13:37 -0700 (PDT)
Date: Thu,  2 May 2024 16:12:17 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.45.0.rc1.225.g2a3ae87e7f-goog
Message-ID: <20240502141242.2765090-1-elver@google.com>
Subject: [PATCH] kcsan, compiler_types: Introduce __data_racy type qualifier
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>, 
	Linus Torvalds <torvalds@linux-foundation.org>
Cc: Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=T7oK9Ilh;       spf=pass
 (google.com: domain of 3kz8zzgukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kZ8zZgUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Based on the discussion at [1], it would be helpful to mark certain
variables as explicitly "data racy", which would result in KCSAN not
reporting data races involving any accesses on such variables. To do
that, introduce the __data_racy type qualifier:

	struct foo {
		...
		int __data_racy bar;
		...
	};

In KCSAN-kernels, __data_racy turns into volatile, which KCSAN already
treats specially by considering them "marked". In non-KCSAN kernels the
type qualifier turns into no-op.

The generated code between KCSAN-instrumented kernels and non-KCSAN
kernels is already huge (inserted calls into runtime for every memory
access), so the extra generated code (if any) due to volatile for few
such __data_racy variables are unlikely to have measurable impact on
performance.

Link: https://lore.kernel.org/all/CAHk-=wi3iondeh_9V2g3Qz5oHTRjLsOpoy83hb58MVh=nRZe0A@mail.gmail.com/ [1]
Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Marco Elver <elver@google.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
---
 Documentation/dev-tools/kcsan.rst | 10 ++++++++++
 include/linux/compiler_types.h    |  7 +++++++
 kernel/kcsan/kcsan_test.c         | 17 +++++++++++++++++
 3 files changed, 34 insertions(+)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index 94b6802ab0ab..02143f060b22 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -91,6 +91,16 @@ the below options are available:
   behaviour when encountering a data race is deemed safe.  Please see
   `"Marking Shared-Memory Accesses" in the LKMM`_ for more information.
 
+* Similar to ``data_race(...)``, the type qualifier ``__data_racy`` can be used
+  to document that all data races due to accesses to a variable are intended
+  and should be ignored by KCSAN::
+
+    struct foo {
+        ...
+        int __data_racy stats_counter;
+        ...
+    };
+
 * Disabling data race detection for entire functions can be accomplished by
   using the function attribute ``__no_kcsan``::
 
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 2abaa3a825a9..a38162a8590d 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -273,9 +273,16 @@ struct ftrace_likely_data {
  * disable all instrumentation. See Kconfig.kcsan where this is mandatory.
  */
 # define __no_kcsan __no_sanitize_thread __disable_sanitizer_instrumentation
+/*
+ * Type qualifier to mark variables where all data-racy accesses should be
+ * ignored by KCSAN. Note, the implementation simply marks these variables as
+ * volatile, since KCSAN will treat such accesses as "marked".
+ */
+# define __data_racy volatile
 # define __no_sanitize_or_inline __no_kcsan notrace __maybe_unused
 #else
 # define __no_kcsan
+# define __data_racy
 #endif
 
 #ifndef __no_sanitize_or_inline
diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 015586217875..0c17b4c83e1c 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -304,6 +304,7 @@ static long test_array[3 * PAGE_SIZE / sizeof(long)];
 static struct {
 	long val[8];
 } test_struct;
+static long __data_racy test_data_racy;
 static DEFINE_SEQLOCK(test_seqlock);
 static DEFINE_SPINLOCK(test_spinlock);
 static DEFINE_MUTEX(test_mutex);
@@ -358,6 +359,8 @@ static noinline void test_kernel_write_uninstrumented(void) { test_var++; }
 
 static noinline void test_kernel_data_race(void) { data_race(test_var++); }
 
+static noinline void test_kernel_data_racy_qualifier(void) { test_data_racy++; }
+
 static noinline void test_kernel_assert_writer(void)
 {
 	ASSERT_EXCLUSIVE_WRITER(test_var);
@@ -1009,6 +1012,19 @@ static void test_data_race(struct kunit *test)
 	KUNIT_EXPECT_FALSE(test, match_never);
 }
 
+/* Test the __data_racy type qualifier. */
+__no_kcsan
+static void test_data_racy_qualifier(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_data_racy_qualifier, test_kernel_data_racy_qualifier);
+	do {
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
 __no_kcsan
 static void test_assert_exclusive_writer(struct kunit *test)
 {
@@ -1424,6 +1440,7 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_read_plain_atomic_rmw),
 	KCSAN_KUNIT_CASE(test_zero_size_access),
 	KCSAN_KUNIT_CASE(test_data_race),
+	KCSAN_KUNIT_CASE(test_data_racy_qualifier),
 	KCSAN_KUNIT_CASE(test_assert_exclusive_writer),
 	KCSAN_KUNIT_CASE(test_assert_exclusive_access),
 	KCSAN_KUNIT_CASE(test_assert_exclusive_access_writer),
-- 
2.45.0.rc1.225.g2a3ae87e7f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240502141242.2765090-1-elver%40google.com.
