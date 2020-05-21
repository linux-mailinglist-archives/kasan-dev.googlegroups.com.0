Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBWDTH3AKGQEFYELJMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A80B1DCBB4
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:09:59 +0200 (CEST)
Received: by mail-oi1-x23a.google.com with SMTP id k23sf3104757oiw.9
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:09:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059398; cv=pass;
        d=google.com; s=arc-20160816;
        b=FV1VDPzF6hOk60cxaKTReC1q9pd9YvkW8LXtRq1CFPD+6HWHFIZKsqOnETRYW+Lxbx
         7+AAW1Ib2NVFKPZOkK6E19V+Q7CTBQoLi03C+uv8i+Ak+caw98tI0PtVELQ+XlXDMHYr
         oHER1jjWerusJfLcmqiE3SGbmuinL8R+s2YfMkdHZLAwHRWmPfIbMrVyEZsXk7BcR3RN
         uiXtbkKVTspFUiri8GgtGUsgDD6NU7Hbv5D61FDr4czZ9rZT/wYXReuCQvcuu2wvFh2B
         84oVYOKde4sVQcU1dKm1P6snWG9d/KxW+R8xm7a8iS0/K+lwjWFQBL0GOFfuSy5lN5Ym
         m9gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=HNILa/fH33gKF5txOBCNEUeGZKGi9jlhQES2JDTf0ds=;
        b=bmPUTJyUyj8ZZIzQPUnrxH/PkY4JjkVpkyKFvlz7lrr5dj0ff0C83OeghUNPdgH6so
         OXdpAQCd1v76P48/im6bV4FZxmA51FjHtwoB+AgK1yL5fkd9WCJd0w7aKW8MhqJ0nBqp
         Al5UDJIDN7AlwyZ/R5Hjad9BVg40sIPd/kgEX6S2DoH2KQzZD9PNAEOEkoa0G7kt6DN6
         SnO1KqoK20dwOe2bDAfbfl8AsK7eMllbERs5X4Pq1rMCi9ylDfjcsQeptUh0cFgWPTvs
         YjGYX7ZD3i1LlyBwLHOV1pZ4cHkgqnk8LO9nWMqtePwHHkeJQWLNJdZyIwVFT0URPzpw
         DDzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="oY/uD0ly";
       spf=pass (google.com: domain of 3hwhgxgukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3hWHGXgUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HNILa/fH33gKF5txOBCNEUeGZKGi9jlhQES2JDTf0ds=;
        b=dhYIx4HqlB1dIiWMeNvxHD3W7hiom/yYKt4BmAI1HQvrIBS/uEetw08P65bqdLi13C
         qpzChypPEq3mBDQ5m2iDnU6hk0b4ebMqolF1D6/DdRkF6Mr6ZWCQsC5gN0X1qpLoS5g2
         hlDt67UpfQFmsOL0zBYzdODLopEU3Krc8fFzu1M7Ig6ByKucqDdb7Cj/bZ3MXryfYibT
         ku/DCpjDxKUuRnhAU8l40teqZ0O7+GENviNjvTllsQt0snZLRGYrtjyWQes/s302GIAJ
         sj8Za5UTkbjcd+P6w4IyBUU75ZI6LtPA1T3jufyI/KOsbpX6F/y9phOEbDF4q4nnczxR
         rovg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HNILa/fH33gKF5txOBCNEUeGZKGi9jlhQES2JDTf0ds=;
        b=KhjYkb6pF6qksgWrl9oBJmTLmxJRh2duLNdqmQaZE2lkEZ5DWTOsr0TLdWw0EYeWxC
         Z6NeeXi9f8yTYkUOYVqFGEjRQ4mbZuRBcgAjg/bmaRhLBPZfiO1I6cMmDdTQogryrXUF
         ClkcYlBzgDpmLyki9qp1CSgDh9Kj+2oBfieP9nUtdo8YWwfN0tqHLkosWCDDjqQpKkCG
         LnjieUVsH4f1R8ottcmIHiuf0YQK0+xEWfjIJfsTMWEoY2T8lNXaHDKgKz7TK46OEevT
         IhQFdXqCBsXJFsGE3eaR1jG3XEN1im72q1qQNHuKFHFY6YJ6pE8xDkWQXP7yGb5ag1xu
         n7fQ==
X-Gm-Message-State: AOAM530m9YHkfKYRfYM+TnvnUt+QI2ackasX+tRtTwX71wqjZrBdAvUT
	HgcZdwERluUGFKw+79jmJWI=
X-Google-Smtp-Source: ABdhPJw0bZBX8uEAF5ygOYpZpUU6wLqSmMZEb2VdK617QZd3Af4mPcTOcMa5UzgTUz5Tz9E6myDc1A==
X-Received: by 2002:aca:6705:: with SMTP id z5mr6058699oix.122.1590059398081;
        Thu, 21 May 2020 04:09:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e907:: with SMTP id z7ls102195ood.8.gmail; Thu, 21 May
 2020 04:09:57 -0700 (PDT)
X-Received: by 2002:a4a:6241:: with SMTP id y1mr4651550oog.14.1590059397736;
        Thu, 21 May 2020 04:09:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059397; cv=none;
        d=google.com; s=arc-20160816;
        b=i2GipKPNgbcEYyFi4dJUu6uLr4k6qThHpCN5zmDGDbQ5z4YElB2HhNufHEVoPf9D8l
         WkcuSOHmqtq2iMlvIFXXfL71kv/XENixTst6rxKOvfpVcR4Y0TGNa3GxnQl/fPEX5Vyc
         HXM7djXner4wPUDbpQNJPIUE+oLgHwGfqH2dJ1HgmOCoblCLE2awJHv57zJpTJGBgS3v
         U3ZNSXfzQVSK8U6nLOypjLlMjG+OxzrmbUh2diMr4+WQ7sIe+4sb8WlRLry4WcFaGU1x
         6VRk7yT8LFfVocSQouv9NS5mdcOz246kgWnr8f1bpb4ux5r8j3gv5g/6vy/ogdjOUCc/
         6N2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=E0UepZUl50HW0uHDfJhRs9oZIgYHrAECVMB9g20DGiQ=;
        b=aDQv99MDMynUGl7EI0KPp12zwN0xG5DljAdOu3HdknS1XA0Wmz3uK6N/DqoS8pDP2F
         5FhS3Jz1hC0OovO/F/98avw+AHfKVvVkgoLMiviEKllEDtwAqyGJmvBUgE6DWfLCzaxA
         p2uoOhd6SB/s2TghDTfQa7dVD+3zAoc+pHVYTXHT3oCd1GR05QfiokAkibhVnIq2Qeus
         zwhRKM7FB0mJHAUXNDcvNiJDDz/tHLrH5itbMIfsPb+wCdvOvAmMfxFvs7PeW0otZQQZ
         7/1tltAUwsZZY0gftWU6Jgh9SBJeMmJEIUYhJrhHW+nW/UwYS7kNVeW+sC8zURotNPQY
         R/Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="oY/uD0ly";
       spf=pass (google.com: domain of 3hwhgxgukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3hWHGXgUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id e20si416409oie.4.2020.05.21.04.09.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:09:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3hwhgxgukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id k15so4933064ybt.4
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:09:57 -0700 (PDT)
X-Received: by 2002:a25:41c3:: with SMTP id o186mr14043993yba.48.1590059397203;
 Thu, 21 May 2020 04:09:57 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:46 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-4-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 03/11] kcsan: Support distinguishing volatile accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com, 
	bp@alien8.de
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="oY/uD0ly";       spf=pass
 (google.com: domain of 3hwhgxgukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3hWHGXgUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

In the kernel, volatile is used in various concurrent context, whether
in low-level synchronization primitives or for legacy reasons. If
supported by the compiler, we will assume that aligned volatile accesses
up to sizeof(long long) (matching compiletime_assert_rwonce_type()) are
atomic.

Recent versions Clang [1] (GCC tentative [2]) can instrument volatile
accesses differently. Add the option (required) to enable the
instrumentation, and provide the necessary runtime functions. None of
the updated compilers are widely available yet (Clang 11 will be the
first release to support the feature).

[1] https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
[2] https://gcc.gnu.org/pipermail/gcc-patches/2020-April/544452.html

This patch allows removing any explicit checks in primitives such as
READ_ONCE() and WRITE_ONCE().

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Reword Makefile comment.
---
 kernel/kcsan/core.c    | 43 ++++++++++++++++++++++++++++++++++++++++++
 scripts/Makefile.kcsan |  5 ++++-
 2 files changed, 47 insertions(+), 1 deletion(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index a73a66cf79df..15f67949d11e 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -789,6 +789,49 @@ void __tsan_write_range(void *ptr, size_t size)
 }
 EXPORT_SYMBOL(__tsan_write_range);
 
+/*
+ * Use of explicit volatile is generally disallowed [1], however, volatile is
+ * still used in various concurrent context, whether in low-level
+ * synchronization primitives or for legacy reasons.
+ * [1] https://lwn.net/Articles/233479/
+ *
+ * We only consider volatile accesses atomic if they are aligned and would pass
+ * the size-check of compiletime_assert_rwonce_type().
+ */
+#define DEFINE_TSAN_VOLATILE_READ_WRITE(size)                                  \
+	void __tsan_volatile_read##size(void *ptr)                             \
+	{                                                                      \
+		const bool is_atomic = size <= sizeof(long long) &&            \
+				       IS_ALIGNED((unsigned long)ptr, size);   \
+		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
+			return;                                                \
+		check_access(ptr, size, is_atomic ? KCSAN_ACCESS_ATOMIC : 0);  \
+	}                                                                      \
+	EXPORT_SYMBOL(__tsan_volatile_read##size);                             \
+	void __tsan_unaligned_volatile_read##size(void *ptr)                   \
+		__alias(__tsan_volatile_read##size);                           \
+	EXPORT_SYMBOL(__tsan_unaligned_volatile_read##size);                   \
+	void __tsan_volatile_write##size(void *ptr)                            \
+	{                                                                      \
+		const bool is_atomic = size <= sizeof(long long) &&            \
+				       IS_ALIGNED((unsigned long)ptr, size);   \
+		if (IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS) && is_atomic)      \
+			return;                                                \
+		check_access(ptr, size,                                        \
+			     KCSAN_ACCESS_WRITE |                              \
+				     (is_atomic ? KCSAN_ACCESS_ATOMIC : 0));   \
+	}                                                                      \
+	EXPORT_SYMBOL(__tsan_volatile_write##size);                            \
+	void __tsan_unaligned_volatile_write##size(void *ptr)                  \
+		__alias(__tsan_volatile_write##size);                          \
+	EXPORT_SYMBOL(__tsan_unaligned_volatile_write##size)
+
+DEFINE_TSAN_VOLATILE_READ_WRITE(1);
+DEFINE_TSAN_VOLATILE_READ_WRITE(2);
+DEFINE_TSAN_VOLATILE_READ_WRITE(4);
+DEFINE_TSAN_VOLATILE_READ_WRITE(8);
+DEFINE_TSAN_VOLATILE_READ_WRITE(16);
+
 /*
  * The below are not required by KCSAN, but can still be emitted by the
  * compiler.
diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
index 20337a7ecf54..75d2942b9437 100644
--- a/scripts/Makefile.kcsan
+++ b/scripts/Makefile.kcsan
@@ -9,7 +9,10 @@ else
 cc-param = --param -$(1)
 endif
 
+# Keep most options here optional, to allow enabling more compilers if absence
+# of some options does not break KCSAN nor causes false positive reports.
 CFLAGS_KCSAN := -fsanitize=thread \
-	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls)
+	$(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
+	$(call cc-param,tsan-distinguish-volatile=1)
 
 endif # CONFIG_KCSAN
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-4-elver%40google.com.
