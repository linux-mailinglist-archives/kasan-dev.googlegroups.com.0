Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKU5TL3AKGQECKZXN6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B43001DCF80
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:35 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id dm14sf7292581qvb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070954; cv=pass;
        d=google.com; s=arc-20160816;
        b=OEP9cCywhnCYpkGephYfsSa5PJKWBvoN2T/cC2UZpvmkFMhXRC4BfgX+KVkUXL7XuE
         QCwH2JqRiUHPCJSdCL2hOp+rRw8cNR0Oqk6MYpkQQMKu06/EGM93lvBNfbD0gWuPLnu0
         Awf8Sgqj6PVo1Xm9awMQUdlqXmyMl8jifTocOOKefwa6djuWFsZFEuuOI0EWWUiCwHfg
         qnHz7T0umN+ge+mO1q2yM9lPeJzOeyxrRh/JoJ/8LnWS1aqHkvqFDB9FsKPFVt9UWcnW
         k1+1wmNz92YmPgAUesloV3CQMgXdeRYnbTVRGMPMXjfY+Luoj7Vr6pU/8U6GAwwuHIhM
         1mMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5C5fCOA+jExoa5hoyupZFGdQKs6tjZrHFIKmKFLqrPY=;
        b=a4uADV/dUCbUmPBQb+wfjrQyYYDxQx71u0nLcbR4XpN2yIsNcg/MQrot3AknswEkjn
         2KTV6EzeEKTRdA+mPaDA6ye7blUGwqM99+oJ7/aQk+lQkbsZjHgXBvEaqZ5ZwfDu5zWP
         6NdmfrNcz8+j4Fk+/TS47UL3cCfy47yhds5zLpWjOC9j+xPmtXNvnFwVB+Mft64O2nLi
         nj+32cOSIzfaQYy7ntnjnLM07/MS6Z9rHFGmFGQp7fIWUkWtakLBnq1E9Z+6rwcSk16M
         Spxxj1eqNc+2PiNrMWypN4mcGWdKSb6wB/dPd/hg3UzGmh8rWQHWIReB3iVGFsck7hDK
         Lg7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u3EpQ4+D;
       spf=pass (google.com: domain of 3qo7gxgukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3qo7GXgUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5C5fCOA+jExoa5hoyupZFGdQKs6tjZrHFIKmKFLqrPY=;
        b=O16DseGe41muzn/YKJm6JBmvlbBpDQ2C5wMUOKaK9eYyZWG9whPSyzQJE1cY6XAvRl
         zXRvNStXiRaFBtK5Iw3UZlIXWCJ6R8paQ+Q0DykxSyQnO8C0u/VHEvLO99r8rp0bt+yw
         neRhHZHtTk94pfbWHTI6gqu4PJdcaDKKQAz5kySvzNPxeHBIb3f9WIKq09wdR4syyjDh
         6n6gDL5DOtdd1PTnvKCEHrq4XaA7FSuY2J5QNSlHvig7UUE3uHnSSVPVILMPOmuChY0g
         rm4DsBl/RyIYH6gAfhxdn37xu2IqCLv3BxrINaWSpHhNOQn3OQ2+Ftfm4amoo35KC1m2
         hwpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5C5fCOA+jExoa5hoyupZFGdQKs6tjZrHFIKmKFLqrPY=;
        b=eK61KjEx39W8pvhRGNlE6rktcH5hArzhYlyhU6TQvhDCaxW01bXiNlstL6bra/ouSh
         nLvTyb9xOM79pGA6PVFxWYd5/TdqmhUsrb+GEVi530C0ItHem+lJrWB/J3JY2M3555JZ
         A5hmLYzUmC3jZPMKx6D9A4dm11pJMG5oNrTBDnZ4BrrYpqpDQFcqEZcTBRd3MTtq2d5a
         4Q0aq7UDWmBZZ+m//o4FF/7ZgF+/JHVCwft7tAfUD5Q1KigRBEPhlHfF+pTQdHrt4T76
         KdYZwFltbNDN4F7QU7SjyYlZN+dVrAakSAFhfywDzZUEwRjwHKQzlx1NHgSlyxtt0kHs
         E//Q==
X-Gm-Message-State: AOAM531eXex3J5Xs+bd/UYW0F8fXyyz+Bc0dOq46Gl1kqBA94OFaXk0Q
	V0+eh7sns9HxlmdXFRFK7AI=
X-Google-Smtp-Source: ABdhPJzavr9OJtu3ZVoHiWuTaX6FV4ZWva0Dje6O/CBdHy+riYNDYylf5//GLrLP636wUTKsu6sWfw==
X-Received: by 2002:a37:4897:: with SMTP id v145mr10017668qka.26.1590070954821;
        Thu, 21 May 2020 07:22:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:8c81:: with SMTP id p1ls508691qvb.7.gmail; Thu, 21 May
 2020 07:22:34 -0700 (PDT)
X-Received: by 2002:a05:6214:7eb:: with SMTP id bp11mr10516160qvb.8.1590070954511;
        Thu, 21 May 2020 07:22:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070954; cv=none;
        d=google.com; s=arc-20160816;
        b=luEr1fgWBHqKoeZ3wr1TJxPzP4clHkfNsORfZTM45h/I6qBq3U9EDGr26/eF1rmTHE
         cODpV0VVdPynaFFer6dRKIAeRSEBm7Tdoaxq6AJ3AV09JBw2WCPlTrPS6kIf4EuZ3PCz
         wsGHneNTKRyUZV1wKfkaIHON1EzvckhTKnvcuwIW3T/vGars7nihhqGGAB0ytV3nD2Um
         APW8+55eZ15DvQisyNjgupXVLVC/0u+zS2rkWJB7a5qEL+SLs7A/y20gM2Yk+EAumXkp
         f92Is9n2Wvm9jyRKhGclDh+hsF/ExsvQA7CBnV4+aXjOld9bIVlujdKrdqw8sNh2GFgk
         xWhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=rIPGL9CFOAkyWr2JAZKyWj8DzpuO2OFpo2ndoPyjdsU=;
        b=Zo6NdC8IdkiZ2WaMsVwvLrYjgpWYyAhjVACbmO+IO21j/cp7QoGVcUAGLk6Dylyw0M
         GffQxlCYyC98n/Mz0VjBsCDTqR92auRZiAtDMnNG197PSIUlV2YXp0Al1jkPR9KOlQSj
         zj60dKTnhg3c3DM/L2P4W8cIcn0YrbtNk4luvZ0kaGYiF6lZ0E5R49GfoQztAYd3gXpt
         6GZ1I8rsdvq0vC2RoBjNn8EHLlfpTwuSNaawnC66sWRpY9litY7hdWqBHsJCZEMWvZT5
         z8IPUkGY/aVg0GJfE/bM9R8NYMKePZaltyRtAquXL+DiCQhsqKkTDdBwDXMdDex5CSI7
         RPTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=u3EpQ4+D;
       spf=pass (google.com: domain of 3qo7gxgukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3qo7GXgUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id m128si465327qke.3.2020.05.21.07.22.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qo7gxgukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id t57so7858525qte.7
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:34 -0700 (PDT)
X-Received: by 2002:a0c:a184:: with SMTP id e4mr9612716qva.153.1590070954160;
 Thu, 21 May 2020 07:22:34 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:42 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-7-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 06/11] kcsan: Restrict supported compilers
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
 header.i=@google.com header.s=20161025 header.b=u3EpQ4+D;       spf=pass
 (google.com: domain of 3qo7gxgukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3qo7GXgUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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
Acked-by: Will Deacon <will@kernel.org>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-7-elver%40google.com.
