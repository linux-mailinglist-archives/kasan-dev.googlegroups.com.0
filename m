Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7M5TCGQMGQEAYNEEYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id C219D463303
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 12:46:05 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id k15-20020adfe8cf000000b00198d48342f9sf3535426wrn.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 03:46:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638272765; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zi7RpEJvxVeUyv8h99ue3jFD8L47x6c00QScqA+KIKVGNu30Aqatc7vWZt8X+uGyLV
         QgJZNouPv2X4ws7zZqpzHfxM4C1PevEKkT8F1S+RBka/RYDYXHsgyKAqe3lugUiKA/4Y
         yHk7ZMpfjS5KNBaOM+SUJQu3Rge30HM2DLNVPIuVC0rVy8CJe8+3pmDjzfrLyLSLC3x2
         fPCb2bZcWZx/cd89RO1Re0FLq8gY+xqtky0nOiPSnP1gqGiZufFlRe2nxoNk3YA65+w/
         yA4x1snWu7RWrd5WBbiNBBnTa2d1PHIDNViu6MIYPsKxcP6ifwBxYuwsVn0qf+ISNUt4
         p95A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=KnBcuDCLpL9H5eiUU/PsMmzvXS6JVaqTlsS2oOY+OgM=;
        b=MJbipExVaXvKfx2dwvz9J5OAhLIW/V7gea9gVd1K5vAX5UnX+0O0hZmdduKtvIvxCf
         E7gRtFOwmiTbXnUVp2qLtpSl+nxq9CZB0JJvFu5zsoMGjP9y599YJwesfP+5KQ31i6nf
         HMmoaRkGY4g24VB7fea2UKC9Ao4epsQlS8Z8YRl3vKgJ7w/i7b9Q169Jt6NTjGFXtnyw
         CbVrdVHQJDXg1IjbHm/+p51oox93QrK2uBAORBjAbsLnME6h05GXqQiKmDvEXGsF3cSP
         5NYX8pfa22NLyAcWzAO/iSx/EPALFhSoverP8Nc/tdXt+kqOBimkQx5+VIUMGlg5MpTp
         1ndA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qfKYXOVz;
       spf=pass (google.com: domain of 3-w6myqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3-w6mYQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KnBcuDCLpL9H5eiUU/PsMmzvXS6JVaqTlsS2oOY+OgM=;
        b=fUY91uG5LVXC3CB9F4sZNh6Sc1X9PTmNsN2wyMuAfI0fQ+4Vfyz7ymKyEy/Fx43cOJ
         FGC9FQgLdrSkDJoRlgg0knR043QTTX4vZ4vrgqTBoNkQUuFMbv4H2V4wNTHTTGSALnl6
         ccEwnzDgbbmAL+TqFfOkgd/SDfIUvgz62RCuyP8XT5qRPi+l9Pyh6dK4/KkWrWCRPitb
         3U8ACsuGCXHHeT/ieca+TbDQerRiPrZtu/JFxf7DN06RcXFqFeQpmUJfR8mztfFXcglW
         w9Y0POMODvcAYCQ3iKfdeOTM/M7uTFJpJshVjrmU6KoQgRaxco1HJdp9lQ1bQwo+3ED6
         zRuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KnBcuDCLpL9H5eiUU/PsMmzvXS6JVaqTlsS2oOY+OgM=;
        b=vhKzxgred3Ynjh+OSIWAwSFTDdntJd2FsUn5QrKbZxEvYHzgOwEhVORgySKdhx1GKO
         BOwSEt03sVBrMw3UzTDZQNrDwGshZGojtUnJEuS/RH0IT1l1KmCPT4hWQuDoPwgD0Ynz
         Zm8nESKPJutE6vSOY0ZcXyppCp8lFl7muREt1aTyhe0jhVD5AJvkEtSmmzGuYlaGsZPO
         NsIBMtzwjvyjdlpeDb7DbiJ2f5HsMovbLqkzPHJDTjD01F+4IPUevJV9ZBOM6BEbKe/B
         5YRpo5pbfoLXlOugXVm2OhyYt3GXGCyqirP0dGg0UolKMW8LaIJDpHaSKvhzJwCu9Tbu
         VBAg==
X-Gm-Message-State: AOAM532k7LU9vmCI3zs57aXNcGUuqDyFlhmdRQZZrPkosbGEgXhebCj8
	udf8ZsR9hF6INsz2o0VR5sc=
X-Google-Smtp-Source: ABdhPJyUBEjbRmhPxRLJscCM1+evQmnJiqOPc9etzjzppV2nj5FMdSqP/0qJaDbOQHkobOroKNljHw==
X-Received: by 2002:a5d:624f:: with SMTP id m15mr40094734wrv.13.1638272765517;
        Tue, 30 Nov 2021 03:46:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f885:: with SMTP id u5ls13082758wrp.3.gmail; Tue, 30 Nov
 2021 03:46:04 -0800 (PST)
X-Received: by 2002:a5d:604b:: with SMTP id j11mr42049731wrt.22.1638272764725;
        Tue, 30 Nov 2021 03:46:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638272764; cv=none;
        d=google.com; s=arc-20160816;
        b=hNdSTjYUVgZWrDsHjR3yTuA17hOys9zf4pty/qwkkL65y5Qq/Jn6bb9OXHxOz9F3GY
         IXsddM9njO5FDrBZd56kQkImOgBrhoGg8mYEOGFnstvJzHs6GbKXhTKgd16aan9BIHZG
         YXz3EQPZ80ho5z/z4z3YIBbYVgTXj8J/PWJCkFWc54+fC5fxhw2hlBBWnNtdSgOZsvkW
         rz3vVyjrYuIrnXIW4XHgFD4cT7aq/qGuSAG6szD4Ed2xJnhC7uh9SeotqW25pSinudhj
         pdaWYSjigJfBGNvSLpcnJdCvDv/WdR9yLVkxIiH7Ov+hcd5glcWq0v18Bhek0OAd6SYC
         lyRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ykQMG7f7HitTY02bjgroWOqQwac8nTYOVAZLqTXm/og=;
        b=nQvFLmg2LaobTvNC0ubB2T5qNIrNbbsX7j3nY+nKiOqT1dm6kf5KRdwPWQmJjtSKrh
         B9zKXHKYh38OKyQV0g1LPkzoGtbEtvJ+7/XzDAhGmh5LqvMUCiMH8ZvpSUxX0yzLWE3S
         Z674t//w3RlLnGjGkc1PzYyhoaagWfV0tzWe9bKdudDU56BpLGQkakz2VXRjNC0v9mEg
         fiXRyNmeRAGYFcbIMsBq2WKegWT6DzhL3J6moPg7CbalOx5FdDO9PTj3sfIConl9yBRC
         uFtJAGwGZfxiN3QNqGCUbmzMPDoCit/ZmiWlVIOOrDeVUsYCi4gj316ACW2Q/6Q9O5sK
         aJqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qfKYXOVz;
       spf=pass (google.com: domain of 3-w6myqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3-w6mYQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id c2si324543wmq.2.2021.11.30.03.46.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Nov 2021 03:46:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3-w6myqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id bg20-20020a05600c3c9400b0033a9300b44bso12699522wmb.2
        for <kasan-dev@googlegroups.com>; Tue, 30 Nov 2021 03:46:04 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:86b7:11e9:7797:99f0])
 (user=elver job=sendgmr) by 2002:a05:600c:4f0b:: with SMTP id
 l11mr626212wmq.0.1638272763966; Tue, 30 Nov 2021 03:46:03 -0800 (PST)
Date: Tue, 30 Nov 2021 12:44:33 +0100
In-Reply-To: <20211130114433.2580590-1-elver@google.com>
Message-Id: <20211130114433.2580590-26-elver@google.com>
Mime-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v3 25/25] kcsan: Support WEAK_MEMORY with Clang where no
 objtool support exists
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qfKYXOVz;       spf=pass
 (google.com: domain of 3-w6myqukccqov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3-w6mYQUKCcQov5o1qyyqvo.mywuk2kx-no5qyyqvoq1y4z2.myw@flex--elver.bounces.google.com;
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

Clang and GCC behave a little differently when it comes to the
__no_sanitize_thread attribute, which has valid reasons, and depending
on context either one could be right.

Traditionally, user space ThreadSanitizer [1] still expects instrumented
builtin atomics (to avoid false positives) and __tsan_func_{entry,exit}
(to generate meaningful stack traces), even if the function has the
attribute no_sanitize("thread").

[1] https://clang.llvm.org/docs/ThreadSanitizer.html#attribute-no-sanitize-thread

GCC doesn't follow the same policy (for better or worse), and removes
all kinds of instrumentation if no_sanitize is added. Arguably, since
this may be a problem for user space ThreadSanitizer, we expect this may
change in future.

Since KCSAN != ThreadSanitizer, the likelihood of false positives even
without barrier instrumentation everywhere, is much lower by design.

At least for Clang, however, to fully remove all sanitizer
instrumentation, we must add the disable_sanitizer_instrumentation
attribute, which is available since Clang 14.0.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* New patch.
---
 include/linux/compiler_types.h | 13 ++++++++++++-
 lib/Kconfig.kcsan              |  2 +-
 2 files changed, 13 insertions(+), 2 deletions(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 1d32f4c03c9e..3c1795fdb568 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -198,9 +198,20 @@ struct ftrace_likely_data {
 # define __no_kasan_or_inline __always_inline
 #endif
 
-#define __no_kcsan __no_sanitize_thread
 #ifdef __SANITIZE_THREAD__
+/*
+ * Clang still emits instrumentation for __tsan_func_{entry,exit}() and builtin
+ * atomics even with __no_sanitize_thread (to avoid false positives in userspace
+ * ThreadSanitizer). The kernel's requirements are stricter and we really do not
+ * want any instrumentation with __no_kcsan.
+ *
+ * Therefore we add __disable_sanitizer_instrumentation where available to
+ * disable all instrumentation. See Kconfig.kcsan where this is mandatory.
+ */
+# define __no_kcsan __no_sanitize_thread __disable_sanitizer_instrumentation
 # define __no_sanitize_or_inline __no_kcsan notrace __maybe_unused
+#else
+# define __no_kcsan
 #endif
 
 #ifndef __no_sanitize_or_inline
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index e4394ea8068b..63b70b8c5551 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -198,7 +198,7 @@ config KCSAN_WEAK_MEMORY
 	# We can either let objtool nop __tsan_func_{entry,exit}() and builtin
 	# atomics instrumentation in .noinstr.text, or use a compiler that can
 	# implement __no_kcsan to really remove all instrumentation.
-	depends on STACK_VALIDATION || CC_IS_GCC
+	depends on STACK_VALIDATION || CC_IS_GCC || CLANG_VERSION >= 140000
 	help
 	  Enable support for modeling a subset of weak memory, which allows
 	  detecting a subset of data races due to missing memory barriers.
-- 
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211130114433.2580590-26-elver%40google.com.
