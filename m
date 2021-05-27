Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUQX6CQMGQEZGYSPQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B45A3933C0
	for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 18:27:12 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id a1-20020a9d47010000b0290320d09a96aasf339195otf.16
        for <lists+kasan-dev@lfdr.de>; Thu, 27 May 2021 09:27:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622132830; cv=pass;
        d=google.com; s=arc-20160816;
        b=yAK7DbOtMpA8Mw2/9gRn+WpCFjZL2eUalKrcpalycLQUlC5xBkjjfOPZ99QbbxjQ6e
         v2jD7dFJgcUGWPi9xbDaOrqqsk+CYvPvXHABrPrvEVq/m8t+bkvQrcjflh4iGoO5PvlB
         vrhUcfck7+Af83NhIzxBXuees9fe7P2iIW4FH7iFhIrpz+GHIx4Eppz3x9U8pGh5PD/g
         y0epvhQF46Ljeqhz8bn6McFnE7cOZ9IUPuVr8DgjuWVXHE4xYGaadoLJRhmPDODADTwC
         SeI6jgBt7Pei8Cx4Ut1pPhYx06ML8VYwbS6xaslSwmlojM3fQpjnVH0PFwbdQvRTSeqd
         QCiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=fIrrrnig3l2Qn+iNENuu2p+eJGRRNVMZk2pqL/5YaNQ=;
        b=vzAGqTQBbL6W1b02qnxBVhqB4WABf6ZVRNn4zEFhOiwVJqgZBzShlwRzpV1cgphzwG
         rvpTrVJ5BKGygOWR8//Xv7jOjzxmUaEtVexex8tYhM2aGm01x8zhEhVkPEwW0ccMNrjE
         oHAgYauXuvxH60V7StehFwnaFZuvTmsO3SVeWLB9Y7mFzIyGoHAhh5/YZJifqaiav69G
         kHvKxrFpdQKPIiVThRXKj8Mgy4HrUsM/kc49z7oL0b0mYpZmgJc0RoakRKElxcNVGBkf
         9A+iCxwqKLbJCTo4vHr5CJ0+xp5nrca/ij+pkrwWsgqSCZz44i5ZyI0mkEvV9ZD5vjW1
         tY+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f2w+5IQF;
       spf=pass (google.com: domain of 3xcivyaukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XcivYAUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fIrrrnig3l2Qn+iNENuu2p+eJGRRNVMZk2pqL/5YaNQ=;
        b=NCrdFW99gFzWsJ/OreeC7HJVNqjAy3xiuvDh5VpCBu42L6zzK9ZDHJEjwTDZmD6RfS
         VEUvvdgKg0Xxhb12Z8aOTPaLulC+ak+4eCTxoxwNRmSLdpWzQYuaWLv1NahId+bJaNgI
         FllCkBFwlPlWwmBjnU1KTtiMAnpGeSMAYNmREL5zDAvOlHbXU+qS1FBpu6Z6e7E4/pD0
         i0wTyT8IvP+YyRU264aKR4e76DS+XnEYhYDHtiM5BO3cNdFqvPvqH079WIEbBjbMEuaQ
         COh02R3deFrV4FzftORB20vZi51oJFBa2QbMdhRKfNHZjKIKXiKX37s3iwBqEnld0Yi2
         huyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fIrrrnig3l2Qn+iNENuu2p+eJGRRNVMZk2pqL/5YaNQ=;
        b=dB3AXYc5NBWAsSJvz7sHyteN/SP4LIjaqoBLO7e2Z5EJ8Mw7IaufKrHgdPtkwaudos
         JjTqRKR0laCVnZMpcPT2VZyaclaASpqvzJvPWxv8c/vkt5QuE2MeFLnKh9uNi7jWPX1i
         tcRvV8dziwan4DaJpWUzYbB7nMpVfISvyJh90kJB+XsZB3dZ/Ab+l2PON/JFNhj3T6xA
         01VmBccftQS+MIuRirRrZ9RuEjJq8DAhT/O+TUNAB7AVNAQSausSTZlRwImAF0XWH8CU
         q/R5RYJSQ8p9WwDJlgIEpf/C92ycFLoH9ZfD7J/zhS7TagoC4lXKJpK43mjr1I4yeLYB
         mRCQ==
X-Gm-Message-State: AOAM530B6lmtItfy+7yk82pbZ250VzBJInuWk6RHzCnCS/SS3VoX7pZX
	R41JPIV84D1A2R3dMZ6gkVc=
X-Google-Smtp-Source: ABdhPJz48wlWm7I87WDiq07AubsY+UhTv0An/XzxuOQtlnf5iKbDuTcGktAfJE6tVjXwIl6XVSxoZw==
X-Received: by 2002:a4a:d89a:: with SMTP id b26mr3397596oov.11.1622132830638;
        Thu, 27 May 2021 09:27:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5a18:: with SMTP id v24ls1103679oth.1.gmail; Thu, 27 May
 2021 09:27:10 -0700 (PDT)
X-Received: by 2002:a9d:453:: with SMTP id 77mr3568633otc.31.1622132830288;
        Thu, 27 May 2021 09:27:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622132830; cv=none;
        d=google.com; s=arc-20160816;
        b=iaU67g1C3ClYhJU7paKXaTG+lR46fFpXxG1ZaEnev0ksZeYb2GN5Ym9Jn0sz7zTYas
         wbUO9FJiFJwcKciLpEI7KRCJjjzDk8YZ/IWO+eJSq2QTPv14XFrr3aXneGiCl8XxDxKf
         fQhXJhpftv8ghwWc04AkKfp5gi99wp0rqDPzsNv2ZIxkoXvkmyF+xeI4iNjicCKvH6e1
         SYnH1L+08+UH1Bhk5+JefViM4kHz4p4YC5QQBz6PcNXfz5ieHlK6DUTj5eKBctW4OYUH
         tAt9+QzD8Rp1jzuYY2dzdQYQb3AELXzFcEL2Q4iz/AxJTGSF1Ubw+8/GnISx1N2cqlMT
         lRzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=AGqIzmkDxtMVtRwwjXgh0j/7u4mFhsWkmDrrQlHpXTY=;
        b=iJWK9HAe3Mytzr6o4rTEI9RhoeM4GVYVtAS9WT5srcdhgP4c0Rnb0fZBV+O584qj+3
         oqqo/IMJmpPrsbJZmFQXJxVGQ4P9Xk4D41LNSm7kVVp4+fEplgAn0V9d6GG2Ja1h2j6Y
         ZmjC6FtX42j447O4pVeUAHdeGCsOzuJRG/xtQiyiJne3a0KfBUJ1P0bgLn0az3qH+Aqj
         EPBILKPzDGYr1quJxtkqfgofPY8t7xKnzHmjE+g9ZIBDpEK767Y50iFuXH+iBOuilicI
         5/V04XIDerUVRo03Mn2SpKsunseZmb9BflIfLqV+NURVdtHMHcDVTeFJsLUVBXJMKBto
         m1kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=f2w+5IQF;
       spf=pass (google.com: domain of 3xcivyaukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XcivYAUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id c4si464729oto.0.2021.05.27.09.27.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 May 2021 09:27:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xcivyaukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id u13-20020a25f80d0000b029051d7fee31cfso997321ybd.22
        for <kasan-dev@googlegroups.com>; Thu, 27 May 2021 09:27:10 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:d65:1a6a:e560:4abf])
 (user=elver job=sendgmr) by 2002:a25:be41:: with SMTP id d1mr5987917ybm.352.1622132829802;
 Thu, 27 May 2021 09:27:09 -0700 (PDT)
Date: Thu, 27 May 2021 18:26:55 +0200
Message-Id: <20210527162655.3246381-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.1.818.g46aad6cb9e-goog
Subject: [PATCH v2] kcov: add __no_sanitize_coverage to fix noinstr for all architectures
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, nathan@kernel.org, ndesaulniers@google.com, 
	ojeda@kernel.org, peterz@infradead.org, keescook@chromium.org, 
	nivedita@alum.mit.edu, will@kernel.org, luc.vanoostenryck@gmail.com, 
	masahiroy@kernel.org, bp@suse.de, samitolvanen@google.com, arnd@arndb.de, 
	clang-built-linux@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=f2w+5IQF;       spf=pass
 (google.com: domain of 3xcivyaukcbgcjtcpemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3XcivYAUKCbgcjtcpemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--elver.bounces.google.com;
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

Until now no compiler supported an attribute to disable coverage
instrumentation as used by KCOV.

To work around this limitation on x86, noinstr functions have their
coverage instrumentation turned into nops by objtool. However, this
solution doesn't scale automatically to other architectures, such as
arm64, which are migrating to use the generic entry code.

Clang [1] and GCC [2] have added support for the attribute recently.
[1] https://github.com/llvm/llvm-project/commit/280333021e9550d80f5c1152a34e33e81df1e178
[2] https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=cec4d4a6782c9bd8d071839c50a239c49caca689
The changes will appear in Clang 13 and GCC 12.

Add __no_sanitize_coverage for both compilers, and add it to noinstr.

Note: In the Clang case, __has_feature(coverage_sanitizer) is only true
if the feature is enabled, and therefore we do not require an additional
defined(CONFIG_KCOV) (like in the GCC case where __has_attribute(..) is
always true) to avoid adding redundant attributes to functions if KCOV
is off. That being said, compilers that support the attribute will not
generate errors/warnings if the attribute is redundantly used; however,
where possible let's avoid it as it reduces preprocessed code size and
associated compile-time overheads.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
---
v2:
* Implement __has_feature(coverage_sanitizer) in Clang
  (https://reviews.llvm.org/D103159) and use instead of version check.
* Add Peter's Ack.
---
 include/linux/compiler-clang.h | 11 +++++++++++
 include/linux/compiler-gcc.h   |  6 ++++++
 include/linux/compiler_types.h |  2 +-
 3 files changed, 18 insertions(+), 1 deletion(-)

diff --git a/include/linux/compiler-clang.h b/include/linux/compiler-clang.h
index adbe76b203e2..e15eebfa8e5d 100644
--- a/include/linux/compiler-clang.h
+++ b/include/linux/compiler-clang.h
@@ -45,6 +45,17 @@
 #define __no_sanitize_undefined
 #endif
 
+/*
+ * Support for __has_feature(coverage_sanitizer) was added in Clang 13 together
+ * with no_sanitize("coverage"). Prior versions of Clang support coverage
+ * instrumentation, but cannot be queried for support by the preprocessor.
+ */
+#if __has_feature(coverage_sanitizer)
+#define __no_sanitize_coverage __attribute__((no_sanitize("coverage")))
+#else
+#define __no_sanitize_coverage
+#endif
+
 /*
  * Not all versions of clang implement the type-generic versions
  * of the builtin overflow checkers. Fortunately, clang implements
diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index 5d97ef738a57..cb9217fc60af 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -122,6 +122,12 @@
 #define __no_sanitize_undefined
 #endif
 
+#if defined(CONFIG_KCOV) && __has_attribute(__no_sanitize_coverage__)
+#define __no_sanitize_coverage __attribute__((no_sanitize_coverage))
+#else
+#define __no_sanitize_coverage
+#endif
+
 #if GCC_VERSION >= 50100
 #define COMPILER_HAS_GENERIC_BUILTIN_OVERFLOW 1
 #endif
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index d29bda7f6ebd..cc2bee7f0977 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -210,7 +210,7 @@ struct ftrace_likely_data {
 /* Section for code which can't be instrumented at all */
 #define noinstr								\
 	noinline notrace __attribute((__section__(".noinstr.text")))	\
-	__no_kcsan __no_sanitize_address
+	__no_kcsan __no_sanitize_address __no_sanitize_coverage
 
 #endif /* __KERNEL__ */
 
-- 
2.31.1.818.g46aad6cb9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210527162655.3246381-1-elver%40google.com.
