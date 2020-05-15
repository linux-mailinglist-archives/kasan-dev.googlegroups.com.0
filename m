Return-Path: <kasan-dev+bncBC7OBJGL2MHBBY667L2QKGQETSMBR3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id F190E1D52F9
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:04:04 +0200 (CEST)
Received: by mail-vs1-xe38.google.com with SMTP id s25sf267791vsn.11
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:04:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555044; cv=pass;
        d=google.com; s=arc-20160816;
        b=tvV24PcwprEx9dmzOVweRnXkuW+6EyygWke7yJln4AqvoSlk56K14SNZfb3LB3WK+j
         i7d45RsYTqA/509ALac8eE9TDZWDFiABt+w41ZOG1GbxzQHpGy/TYuZMBaEZHlpDWIg8
         FcQST9wKy6Q4LKwR3RqgOr+0UE0GMYHXUA6PrWFxsmHTw6m8BPHX4UoZixfKWW8SPjNs
         +s4+6UUyIcAveODSEv2eACg9DG8ZAZ6C9iRv7IjtRUBSld7qG3WrHt4LiZoGsJQEwkcW
         1OGDOuXuwHSAcU4Zj+Dr+eHQGLGXfkY1UQNKteMZY+V9SmMvOLfu3Ehy4heD5aK4zyFO
         tm3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=76h8/ZrjXWPs3zUrdnW9b4MlR/xLW7ArGs73AeuaiYI=;
        b=1Cmot9u+OIoUW8Q34Ic6jj2Zjg8N4kAEm6Er5AuDF/MfVwB451woqJaw6AjbRrZxtd
         j/8R8OgyOJTfxi3eFKe9Wf1hR7IHEnyiTFGHIWNo4cI4fWngbbE2UzFRuRFy1D5wQyCd
         /6Wzi7WpMqERRJrIduNEKshP/cYY4N/E/7Uu5xLivD78hkCc1W5l3DrIpDeTm3kHFAaV
         xXlRcvVQ+XOYPhQyyH0EQvGueUYsbPFvwjH5oedDNWtrREPVzMDXgRywRCqvLE4k9GN1
         7SNjyvtm+x5cEBerah7kGM9unoPQtha9XXa7ETUFzj9pROUq8esynC2X20Jxi9BTnbB8
         HbzA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z0GnEbiU;
       spf=pass (google.com: domain of 3yk--xgukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3YK--XgUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=76h8/ZrjXWPs3zUrdnW9b4MlR/xLW7ArGs73AeuaiYI=;
        b=Zg+Y2iFx3pDyr6GKq9RxpdBtPwquCOooKVBGSj5cLL4/mhGC1QhC2S+pOanPglzDLc
         A8BMMtf5nluPgoyy+jiHdjgjhbbK1pUwWSkcaHsNKoJGpgxkMIhE/l+1IPXDyc+88Rp7
         f6PRmUASr28HeKvLc1Lxk+wFtn6ammunxSnegaUD75UNWNEfSUlxfa0GUJXYC5COVOdQ
         V5qkw3S5DXl0d1xIAlDn+50TpqMKeW4laOs08tokA+rVrQGYFGh9W+/3sWTqHfX7VAKk
         3SHaClEkzc9fUI7tbFtbWD2NSU0eNSXJTONUl8RGsvtQ/Z48SIhIi/KPvVhcIadY0F/f
         B/tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=76h8/ZrjXWPs3zUrdnW9b4MlR/xLW7ArGs73AeuaiYI=;
        b=iuFXSAtLkBxlv4ZxLXKmUGIv/Re9jNUEK7d7BUBWazV2CAv3UA4BjbRL++THxUh0KD
         ZEcNWr4FJQotYB4RsZMN0iBK0GlI/mpRnS4ePxXjsYO/4RKDbypg/Sbusw54cZDQII+D
         kpNEPFt1KWtk/9zVaBxtWQ4KtMctWkL4vA6NMcSM3ZnjZI57A0kFxCMITvQh4TXx1o8Q
         50rZ0GusCJa+MfdjO/N8P8F4TXdnRrZJ96nA+MB9bWi74d5aR1TmPtRWH7yNmSNIQTxm
         hWulF19nYpF5hnQnm6xOzJJ/cQFrW3+kvHC4bj71JbUeRrAERBQyRlawsVkgvy4na/aF
         Fg1w==
X-Gm-Message-State: AOAM53173rK/sT+y0V1WoauxQxjYcrxvmfE6vW1DRTzMFIUk+E9dC+r3
	kUi1oAsdIO0YJY1S8o+31hE=
X-Google-Smtp-Source: ABdhPJxg02gkORPG0pvk9D9OAWcJMlTOFDszjIJTruPFdaLPl8S85zYWKFwKPEUEjG/gdeRNfx4Brw==
X-Received: by 2002:a1f:3051:: with SMTP id w78mr3051872vkw.65.1589555043845;
        Fri, 15 May 2020 08:04:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:3346:: with SMTP id z67ls338399vsz.6.gmail; Fri, 15 May
 2020 08:04:03 -0700 (PDT)
X-Received: by 2002:a05:6102:7a1:: with SMTP id x1mr3294580vsg.221.1589555040509;
        Fri, 15 May 2020 08:04:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555040; cv=none;
        d=google.com; s=arc-20160816;
        b=00u+ovEuWDGkeIkojyBCBMe2hb0xKJmgoEZdw5PxAynHvJA8gm3kzoI9MnV+4xTUYV
         1ErrNMwnEwspEtXBHOcq3eUxoh6AexG/HHlp3JCGcYyIzip98i4/whdQXbHo2tdI4B69
         CZHWKkEtKQDsRmfwIXc5JRVLQtkOcF1ra56o2QNGnefbIeiHqwERSb2QhTAz+l78XGwj
         qvEI/8Ga+UXW0qh0mh/iZlkfDXQbKPR9yMLgojd0fBSHG5/ZgXmh+k9yZL0UIydTbplD
         mAQqj3KLUgt6aE9K7J/YkeWZ6nbdvtMAZRU2xpzSObuTJNmQ+WnXqaetuOljMij2Xv+v
         rAhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=H/UmEzoy3I9ShhHc8I+RGwc8p1HVxWjO5wJlJG19fNM=;
        b=iidAVT9He+AH38jNLymts7RBDZeagEgaaMjNtoDoNpQw8FqjJwxfNRDAIah2ZWpXOF
         lsF/NL4+RM681oHA9gaDqFBy1KkHLsjoO+TxwTnG6V9bZHO4oQGTK/NIAAC8uoaGhn4d
         y/PTwHCCYCtRtT0sCfxziTtAsRm3ucDbeiq63Bba/4r7t2yEpcKaZlhx/oJyidwWYAfY
         eCYH017J7v1UavjBft0OHrrzNfN/q0343rYTq9t1UVLBxvW1Y10WPI7l46PyMw0MoIZ+
         IHMHfadcNPsVdcOwNpm0ReWwzJ3VLlI6amg6jq7U5NNRBPKcNFIAgqzuV8ET5MMnLUN2
         sulw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Z0GnEbiU;
       spf=pass (google.com: domain of 3yk--xgukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3YK--XgUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id i26si146053vsk.0.2020.05.15.08.04.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:04:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3yk--xgukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 5so2819698ybe.17
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:04:00 -0700 (PDT)
X-Received: by 2002:a25:b10a:: with SMTP id g10mr6214488ybj.220.1589555040007;
 Fri, 15 May 2020 08:04:00 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:34 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-7-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 06/10] kcsan: Restrict supported compilers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Z0GnEbiU;       spf=pass
 (google.com: domain of 3yk--xgukcbuzgqzmbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3YK--XgUKCbUZgqZmbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-7-elver%40google.com.
