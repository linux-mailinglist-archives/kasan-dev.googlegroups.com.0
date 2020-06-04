Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAU34L3AKGQENOAGYTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F1F21EDCCB
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 07:58:27 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id h49sf4023607qtk.10
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 22:58:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591250306; cv=pass;
        d=google.com; s=arc-20160816;
        b=VmLO+utEXoJ0sN3IGj0g6lTchMiu2/3CMT48fKg/j4K9oeDKNZ754pateULd5vBY8t
         E7jea7Jfv146nslnNVhfwOB4WRak7UocMX34lUdv8p0T1OACb/9TjzNQKTMJYUUjkIaq
         ZI7sp6J7LAH5v+GQ65C0x9fBS316ZCUlNpFhUbKwTNgFE9bmKhYcnI8k8JjOGtGW552w
         d3PKyv605BRLDnjFDhGGYslJV4MxCN2J5+KfNyB6h5g7KO/9B0Yp9/JqZIHwN3cj52rK
         I8pX/zUDmm4WDG5ksYOBsOzs3nLl6skEg4Nspw2QILxpPghmEr3lUZS+G4Ins/1rebuS
         7Dfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Q2zY7wbbqAoU9hrab7jxFB9Sw2xaaXqp6U+BA5dz1A0=;
        b=qk9StYVRebBKpC/XYZi5jg7KgWUpKX8ehPrNRVgx0urtDBOw1GaJaaHSROwJJvGcEP
         7iLhVa/4L+4nLoQp7nG6U33RPAXS/1tbfGetRcAXLyKFIh3Kcg3ISCCszO/mBs5oHIZ5
         58xdaAvX9P9XyaU8Vcnfn116AfrCou3m28Z8LxTGsgGNraVTfdIg05GmuKLvlF9ziLgr
         JuWDzXNaAQUPjY7IlAa1fflLtd7Lf5nM6wFyR02qDGLiC7yqG9d3riF9X4npSNr2h+3i
         /stF8SNSXvkBKfCMI3WsHJ4yDzStRsOYKs84d2zlWpV9shro4OCMXgYpYwB7t10DdDH9
         Weug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kLpY/vYc";
       spf=pass (google.com: domain of 3gy3yxgukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3gY3YXgUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q2zY7wbbqAoU9hrab7jxFB9Sw2xaaXqp6U+BA5dz1A0=;
        b=Yywk0VwD13uY/y4uDjvKPjCZdif5IXqk7UmLoMSGJ8GLS43XW5PdOBGiACj3eNs2L9
         7u/uFWy5P94NoppcMNnfIpmTfhyl82DKBipjcTXkP3/+L8MTrB1rwpJNTdxzL9ua5dkl
         ycfNn0H0CooKg3jw12oerYAVGA9/1EWDYWTIfhdcWKNX72WMviz532TBbEy4v1ulWBFz
         eXlAyvi6lSQdfk854jANZvN6xXI0CT+WzoG8BhP83tEJLRsusIVgchr5CF78OyqpVQMi
         Gw5e2/mugtZ+2ZttKQPZglsQkO656QKoV7qeP1K7DG0VnbfZ29wgkuqS8RPbgV+ps4RD
         NPuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q2zY7wbbqAoU9hrab7jxFB9Sw2xaaXqp6U+BA5dz1A0=;
        b=Jpfz9CJOnRlN7D7sX0yWU1/st6OkQ9YJRxvTLFRG083GdSV/xzl3tzJOdOZqQXDzAB
         C+FTkQfO1wP0yb9j1SSUi37vYSurKDc/9IF34jSPs85pi7FYHV+BkofrDtFi0AtiuTEq
         k0toZwPSkeGqUiYXHCQazHNre7v0dMUkG2BKnwaFhdmpJ7qAo6u0QAx6u5JNibCR/yzV
         Pcl4Uimxhk/Tc30IGbTQz7f4xdMrDiGuOZDPzwlSG8SXqA4xDMP74vo2cen2HfQfM0K1
         6jWXoLwyzYiukXGcwiI+GwzVKGIIlIYc4gTcvPNnQ1qDPY7MT07Rxmh5qNLHk6JIGjRf
         poeQ==
X-Gm-Message-State: AOAM533pCVYHzmum8LnqSDy9X3CCGWxjsho4EKY0mhyZYk9ijQaPzWv6
	Ib/4oO83bk39LZKyZD8G+ko=
X-Google-Smtp-Source: ABdhPJxCKUG/eFiDgvFveq8B/lZXwppP0u/1CBFGz6uqJngCDpObok/FJbzQ2BssO5PKhgshWpBm0Q==
X-Received: by 2002:a37:9e10:: with SMTP id h16mr3203409qke.381.1591250306422;
        Wed, 03 Jun 2020 22:58:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3384:: with SMTP id v4ls1453563qtd.6.gmail; Wed, 03 Jun
 2020 22:58:26 -0700 (PDT)
X-Received: by 2002:ac8:2fb0:: with SMTP id l45mr2843079qta.260.1591250306076;
        Wed, 03 Jun 2020 22:58:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591250306; cv=none;
        d=google.com; s=arc-20160816;
        b=c/agBKFFjCKliDbQ4L0XiaflC+aKKnXKDeBv7oPL71cvzqWA+WYCHQfZXV1scNygpD
         5vZhWdfzha4rQgmgdWOorXKgeasrHzigO37t36o4oxLKT7ZkoDxwEroG8X5EN+wkkAdP
         JgqvYRrPB5hkcmlxizi7dpQmt/bcryE8bjMSXAU9uFDGOAG95+hNaN6qkWgPtgoQmJl+
         CVyG5rQlHuL/+shVFAEtgvTfIHQw0uycgtpMn+jMoSCZ2I4aLX/Q6tcEVRipsOYnECoZ
         s0di2AqJb0dXK3mbjtz/PRoOIno1WGt+d0Gne8sJf2RIyBcL+11KDRcXkSa0FH/tylyF
         Mr5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=NuYIYrAbbNb8cb+ywlNdLoxBFeloVlNH+GnFfXqWSZA=;
        b=CBnYOpBfQa58ggvaP48JDNLuyzeGwuJk1wnQroPG5kRsEvlFhXr70S5D9f2APggrbn
         iScIPpDgg5Ie1E15LYKM0YlbPl74I2/G15eYIABDhmxWBhahnkk61UVcBFcmg3ZN0mN/
         SZ7MkgiUG+Wuz45F6hbGasNZ6GXS6SKOaf8zugUocu1MzZUElkSnh2ASuzcMWZgTTNkX
         SAbmgjloQLWJg8zahEWSZX4Mtc9DEocnP+xIU+6ckmXWjuuwMAEXx9X5ladPRzG+YGb7
         1ii/p6sPLW9s1z/WeVjQufn20x0hiZp4/9OvDmyou1y0itJzvb68Ym5oXz4UkXpWKWob
         l1xg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="kLpY/vYc";
       spf=pass (google.com: domain of 3gy3yxgukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3gY3YXgUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id x37si337384qtk.5.2020.06.03.22.58.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 22:58:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gy3yxgukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id d6so6834192ybn.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 22:58:26 -0700 (PDT)
X-Received: by 2002:a25:c186:: with SMTP id r128mr5951332ybf.92.1591250305693;
 Wed, 03 Jun 2020 22:58:25 -0700 (PDT)
Date: Thu,  4 Jun 2020 07:58:11 +0200
In-Reply-To: <20200604055811.247298-1-elver@google.com>
Message-Id: <20200604055811.247298-2-elver@google.com>
Mime-Version: 1.0
References: <20200604055811.247298-1-elver@google.com>
X-Mailer: git-send-email 2.27.0.rc2.251.g90737beb825-goog
Subject: [PATCH -tip v2 2/2] compiler_types.h: Add __no_sanitize_{address,undefined}
 to noinstr
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: will@kernel.org, peterz@infradead.org, bp@alien8.de, tglx@linutronix.de, 
	mingo@kernel.org, clang-built-linux@googlegroups.com, paulmck@kernel.org, 
	dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com, 
	Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="kLpY/vYc";       spf=pass
 (google.com: domain of 3gy3yxgukcfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3gY3YXgUKCfognxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com;
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

Adds the portable definitions for __no_sanitize_address, and
__no_sanitize_undefined, and subsequently changes noinstr to use the
attributes to disable instrumentation via KASAN or UBSAN.

Link: https://lore.kernel.org/lkml/000000000000d2474c05a6c938fe@google.com/
Reported-by: syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
Acked-by: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Signed-off-by: Marco Elver <elver@google.com>
---

Note: __no_sanitize_coverage (for KCOV) isn't possible right now,
because neither GCC nor Clang support such an attribute. This means
going and changing the compilers again (for Clang it's fine, for GCC,
it'll take a while).

However, it looks like that KCOV_INSTRUMENT := n is currently in all the
right places. Short-term, this should be reasonable.

v2:
* No change.
---
 include/linux/compiler-clang.h | 8 ++++++++
 include/linux/compiler-gcc.h   | 6 ++++++
 include/linux/compiler_types.h | 3 ++-
 3 files changed, 16 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index 2cb42d8bdedc..c0e4b193b311 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -33,6 +33,14 @@
 #define __no_sanitize_thread
 #endif
 
+#if __has_feature(undefined_behavior_sanitizer)
+/* GCC does not have __SANITIZE_UNDEFINED__ */
+#define __no_sanitize_undefined \
+		__attribute__((no_sanitize("undefined")))
+#else
+#define __no_sanitize_undefined
+#endif
+
 /*
  * Not all versions of clang implement the the type-generic versions
  * of the builtin overflow checkers. Fortunately, clang implements
diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index 7dd4e0349ef3..1c74464c80c6 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -150,6 +150,12 @@
 #define __no_sanitize_thread
 #endif
 
+#if __has_attribute(__no_sanitize_undefined__)
+#define __no_sanitize_undefined __attribute__((no_sanitize_undefined))
+#else
+#define __no_sanitize_undefined
+#endif
+
 #if GCC_VERSION >= 50100
 #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
 #endif
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 02becd21d456..89b8c1ae18a1 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -198,7 +198,8 @@ struct ftrace_likely_data {
 
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
-	noinline notrace __attribute((__section__(".noinstr.text"))) __no_kcsan
+	noinline notrace __attribute((__section__(".noinstr.text")))	\
+	__no_kcsan __no_sanitize_address __no_sanitize_undefined
 
 #endif /* __KERNEL__ */
 
-- 
2.27.0.rc2.251.g90737beb825-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200604055811.247298-2-elver%40google.com.
