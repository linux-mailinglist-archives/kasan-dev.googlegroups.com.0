Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDGDTH3AKGQEVKP3YIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3d.google.com (mail-oo1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AE6E01DCBBE
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:10:05 +0200 (CEST)
Received: by mail-oo1-xc3d.google.com with SMTP id t24sf3257942oor.0
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:10:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059404; cv=pass;
        d=google.com; s=arc-20160816;
        b=jwJMuGE+5Ac5iEiu3LcrdXHyEf2KUzZ+V6hQQk3pM1n6U7x6FkNGTaqyWmgJCmUUUj
         2t/ELv5Q6mxsGVI8fx4YRNJJ3qtWYcXVUSeO4iDOtqUzFcH88zdNkCv1U3kIz1WLAfpJ
         rhMIfXpN76o1bE/BeKEEiIOY+mPX9zX3X5iQByltM6k7YTV5+AcEoe7sES8IGptN+Uol
         IpfjWWA2yrwi5VbieLXYHXcy7KnvGksygEoJE0+B22CzXx6E/wEelHOJ016gZz4hr3Et
         qPdm7l3nNolfFSd4p3Su8X4NELcE6Baoaj0biVWEIBWG/uUesMyRnhRrW5QKqZCyVwY1
         I5kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=MmMK7QhkWe2j5EkgZYo8lLt0jsp37LXsnAUC9qGTAjI=;
        b=qDPFxx2dZVmlFvj7LAaZlQNVtir/uSSPYIt+Tqcz1VoSJJdp1YhxdPBSkJRj1/mXcP
         qc3scwYh4kkBWB5B16UQ7CYv6Z5b/jFTSh48u2we8IOgVJs5k432tjUMRLBCgtZcg9/W
         UkMEqeaCesYxngM/C+nH1UhNwAH1gHpVxWKJfi1O4iVg2j0HqzOHqeNYT9/vTbz2kyEI
         tkx/DTHPEiqkVVr8ihlf/yjOg5srKMcozyMbcj3nknSQEKWapqnu73UCrMPIa7J8aW2q
         0ddM82ORtdLI53fWKLvrgKgqPY4gpy0ERWkvNyYV86e+X4MdSdpKCWOKCtJx1WYgE/TK
         lwmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gv4cBg7D;
       spf=pass (google.com: domain of 3i2hgxgukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3i2HGXgUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MmMK7QhkWe2j5EkgZYo8lLt0jsp37LXsnAUC9qGTAjI=;
        b=apBp1DrGqFzLgoGVxWdWJlLcbRLQTUvf6tjAlccl0skTyPhxi3e5QLbXh7Jwj5XdEI
         hj8CcKNQef0QTC+WUSOasJNNGra7usMY/NV7VaQvwORVCJZCyD90IeW0o/cnUDymAeTF
         SWOfT6J+TKQOSq9L7rToRdp3pcf9VH/rcge3A7lsAtF3jDuq56eOQlGc0DzlYn7jtsSr
         ZClwvOrzRWKw6MIvdpDI2WvUzOKDSQKPO5sln15ie/u1aV5NtZkX2M2glZ9YHm3/XWDp
         KtsUzuNKLgZEwwKDlC03xqEbhEufwfc3qjiC1eRW96Pa0mDRxla4zHxPJudNcbq+CjO7
         cvdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MmMK7QhkWe2j5EkgZYo8lLt0jsp37LXsnAUC9qGTAjI=;
        b=RVLL7ZkVaxSz3X8eCOC4rv9izDrCIRcL3z+rOXZP6gAbVM7V+mD2qckTj4/4Pg+ZBB
         103g2e+BTASdUJCGtu9Q5VushKo3Vb2gtnjcqj9+c/XxEj615kg8zfu51pRXLhSeqpH4
         zk/Jkx/0uZtzObtG7CZNZLKkOXm0ohHFEY/Uh8rj38hRSbyIl9XSpDNBm8QSSnsCbYbR
         JoMQy4BQ3qsBIUD+aifC0jlt6bipeD4NL9XFLRCr7u7zFer4UQPkpLwUIIv2K1bf/C7K
         mIPSbLNx+tGlYxm+o/54XPdbnTYMyVeE316t9PWmChLoBXatwi3XHGGSRp/n+CmYlCmd
         wLlA==
X-Gm-Message-State: AOAM533kVvzIFcMkd9gU3rEOxMOJX2THr51VXc8YQ3IoaOsSjYWCBcAU
	pyEQWSUwQgA87glz2fzPYuM=
X-Google-Smtp-Source: ABdhPJzVVHexQUTkiMP3YDZqjGjObhZfGcmRlO+DV3xTiEUyLefq8Bnv6Wxrt2EQ+pZIbzC4kGEiXg==
X-Received: by 2002:aca:c046:: with SMTP id q67mr6158595oif.53.1590059404658;
        Thu, 21 May 2020 04:10:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3415:: with SMTP id b21ls100730ooa.5.gmail; Thu, 21 May
 2020 04:10:04 -0700 (PDT)
X-Received: by 2002:a4a:a741:: with SMTP id h1mr7091393oom.0.1590059404319;
        Thu, 21 May 2020 04:10:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059404; cv=none;
        d=google.com; s=arc-20160816;
        b=injjYKHqD4BlTGYAabDPVmjwz52/mawWmCm7m7EjDKleWa3boZVFiAEg7SEVioM8zF
         1uq0EpMEERl+/OzWAWXo19B5RUNPjm7Sl0TqYBwHpH+MWDkyrkKr1ocHb1M7O3mOM5Ad
         AuB6h9/a0GZHOoRD+IW1h5FsF8kkkX8+uRWdVv9n7ycjO/JjtgxQd6h4tkxb217yh1wU
         ScovmeFAF+vVjAv1MMN9aRe6HHrSkrn1KY72eavqRuEGAeKXwe5a8cHwSiMOpreL2ZHV
         0BVeldrHqpsJur1RlGKtUBE9Nvsdzy0SuQTICkmTrS5ZmcFwgzu+TBLcsfYCaQeZ6UEA
         bNMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=H/UmEzoy3I9ShhHc8I+RGwc8p1HVxWjO5wJlJG19fNM=;
        b=JKsbIfLy+qsOvzA/jmoNhGrAyta6VzfVwo7HCHM29SltQ6e9v/CBb3JVwu4iZrNVMQ
         ptXv/mspyMYhyt8LPLnixfY17PYI7z/CDdy1JBTJ5VUKGapFkbFphZWGF2d7JvDNGt3h
         GYR0wFe/5N+FyBIB8xeUm9kkFhUtFhEhI97+8uNP0XkwKuSRCiQ56lnsm6JX1cfu1sEq
         BH06Z3NV9hFp/gvOizXKrCfhOxWbDWAozAjOZBXrCQHWfQEQrNScAzWk4G6TOHTIzFY4
         zvI3lsu5baenDJduX7+kK5kAKMm2iq3fWa8pgsguStxSyQhautqqBmF319BNJSastiF5
         s3UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gv4cBg7D;
       spf=pass (google.com: domain of 3i2hgxgukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3i2HGXgUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id p28si615852ota.3.2020.05.21.04.10.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:10:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3i2hgxgukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id x10so4884064ybx.8
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:10:04 -0700 (PDT)
X-Received: by 2002:a05:6902:6a8:: with SMTP id j8mr13222758ybt.46.1590059403861;
 Thu, 21 May 2020 04:10:03 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:49 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-7-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 06/11] kcsan: Restrict supported compilers
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
 header.i=@google.com header.s=20161025 header.b=Gv4cBg7D;       spf=pass
 (google.com: domain of 3i2hgxgukcwqgnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3i2HGXgUKCWQGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
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

The first version of Clang that supports -tsan-distinguish-volatile will
be able to support KCSAN. The first Clang release to do so, will be
Clang 11. This is due to satisfying all the following requirements:

1. Never emit calls to __tsan_func_{entry,exit}.

2. __no_kcsan functions should not call anything, not even
   kcsan_{enable,disable}_current(), when using __{READ,WRITE}_ONCE => Requires
   leaving them plain!

3. Support atomic_{read,set}*() with KCSAN, which rely on
   arch_atomic_{read,set}*() using __{READ,WRITE}_ONCE() => Because of
   #2, rely on Clang 11's -tsan-distinguish-volatile support. We will
   double-instrument atomic_{read,set}*(), but that's reasonable given
   it's still lower cost than the data_race() variant due to avoiding 2
   extra calls (kcsan_{en,dis}able_current() calls).

4. __always_inline functions inlined into __no_kcsan functions are never
   instrumented.

5. __always_inline functions inlined into instrumented functions are
   instrumented.

6. __no_kcsan_or_inline functions may be inlined into __no_kcsan functions =>
   Implies leaving 'noinline' off of __no_kcsan_or_inline.

7. Because of #6, __no_kcsan and __no_kcsan_or_inline functions should never be
   spuriously inlined into instrumented functions, causing the accesses of the
   __no_kcsan function to be instrumented.

Older versions of Clang do not satisfy #3. The latest GCC currently doesn't
support at least #1, #3, and #7.

Link: https://lkml.kernel.org/r/CANpmjNMTsY_8241bS7=XAfqvZHFLrVEkv_uM4aDUWE_kh3Rvbw@mail.gmail.com
Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kcsan | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index a7276035ca0d..3f3b5bca7a8f 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -3,6 +3,12 @@
 config HAVE_ARCH_KCSAN
 	bool
 
+config HAVE_KCSAN_COMPILER
+	def_bool CC_IS_CLANG && $(cc-option,-fsanitize=thread -mllvm -tsan-distinguish-volatile=1)
+	help
+	  For the list of compilers that support KCSAN, please see
+	  <file:Documentation/dev-tools/kcsan.rst>.
+
 config KCSAN_KCOV_BROKEN
 	def_bool KCOV && CC_HAS_SANCOV_TRACE_PC
 	depends on CC_IS_CLANG
@@ -15,7 +21,8 @@ config KCSAN_KCOV_BROKEN
 
 menuconfig KCSAN
 	bool "KCSAN: dynamic data race detector"
-	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
+	depends on HAVE_ARCH_KCSAN && HAVE_KCSAN_COMPILER
+	depends on DEBUG_KERNEL && !KASAN
 	depends on !KCSAN_KCOV_BROKEN
 	select STACKTRACE
 	help
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-7-elver%40google.com.
