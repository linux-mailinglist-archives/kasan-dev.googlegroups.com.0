Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGGDTH3AKGQEKJ3VTYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id CF3821DCBCA
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:10:17 +0200 (CEST)
Received: by mail-pg1-x53f.google.com with SMTP id 14sf4927877pgm.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:10:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059416; cv=pass;
        d=google.com; s=arc-20160816;
        b=JZjwiyRb/lO8+oM+FXu7bkItylA572bIFaTSw7XYmypNlyFy/9jPjYICr3NnJLyld0
         bO2jFhfcxWD9iT+mtC5cn/pz1K4vTl8Hdfxg1FCe2mW5bPURbyUWwjpeFLFv14XcXmQY
         9SFghmNBrQR/b4GGaPUfxBgNbwDixwcLMDBdbybdfjkJjQp/eN6Vx4fKUgdhGb0969d+
         KXVbBfSLspY4TDTFCGEgGm8gK1dofSZqortDBaD3aLiyM0hOQzdbw8GYZ5lEcyCC3OmG
         18ZAXcMg2aRE0Jas4Y7M1Uxcx7FqFEFinYvvM6on1B5JVjvDJJr0uG9MGk5jeU85ngKD
         gxJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=fiuq2wYKPV8lBWM2bbJGZjBu2e7PuTRJTFYrHbiaWRE=;
        b=mZMbZkf8WO18SDSiAgjLaDU34E9gNdC0XlkcZ8ijN3muWsIHmlWUJJvpz4gYQGw3iE
         z8Uhk+JLMQfnmmZbUn3M2iqbrUx+s9VQtPeXBl2pAzY0v8glUkjdKovsBrLMiB0Hy+qu
         tut5F7HakFlxcfvd3ZGRlVIHDeoG6ZdVtKLB2dUSQ57OxdmSrnTmrLE7BmxvKCPwwPIK
         uNl45AQ25vMEmqHGK+2KhMUhnQ2RYegiPr3eSKVESTYRFtD7KAaIx7MzQ395V5S1YbXl
         /gxMxnMr/lcUWFhwuJNBjLQuUQdLY3sAhFqiBnmoiDzB81VK3ZVf6FUeDm3Hn3ln4dup
         Uvrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qNkmtlLU;
       spf=pass (google.com: domain of 3l2hgxgukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3l2HGXgUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fiuq2wYKPV8lBWM2bbJGZjBu2e7PuTRJTFYrHbiaWRE=;
        b=f+/Gq0GkzkqUYL/Ke25iIcS5PkDuldD3QMZ9vNy88B9NnPalU6mpZ39F67PmAQ177I
         kvBk3Sx0Ce3ZHzCNVN11XhDEgDbrWmJu/zmroTM5824tPZOm1e9UZ5NM0ZkEjBFkSJ/B
         t3brbYANtXu/eHweXztP8tU8VJF+7XN9xkqBK2ZdS8Wjjb2dyINNr4k8aGegJ+3XdQLP
         RUntXZRmB+Gl9SzQX4dC2vPJ8gXpGHG5S62OOtAoz/D8MxJmwE0sQ1JpfpxGdaUSYI1f
         5WIhmLwlwPsYxTz6z6MJstsyDTw/O3VOeWvKE0RG2pEM08w7TqJj6DMr10wxXEGGakW3
         LLjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fiuq2wYKPV8lBWM2bbJGZjBu2e7PuTRJTFYrHbiaWRE=;
        b=jpDEhRZ6cP/UPsda44K95uaoLvdKkgiSYmvcsuBSvyGfMCOz73prfbC8q5PYNlwmyG
         oZdKd5C0+yCuYEY9RcoBpqY6P4C5YPg1LsWSXJySLitp7LT2AuFz7Wxeg8hU7zgSLWoq
         l4bz7PYwaGmylYg4U4iWDyS55ZsFA0wD9QmWu1jEZhe3MQoE5izjtEQhB71pTMT9YVRB
         WaLj24cPOHvXwfsC99OJjxfZj6Ygti0z+aBRdujN4331uu1WtYw5vM9YwnudA5AtPKBC
         lLFjHs1/IHS7uVsLYWXeYUb0/f67SPxcJqEHvYeceoL7JJmAHte37Sq4bKuKiren99G5
         Zf9A==
X-Gm-Message-State: AOAM532WJsIjRo0diUtF5GWHVbSD9K6GgfbU3kedYl9iw4qeJH7MHxnJ
	m2ycaG1WCAA6TupD4/9r+ow=
X-Google-Smtp-Source: ABdhPJzWlStDZ1wKei09Gm+DXmcYSxxUunqeXnrFk12R5UG3+pBEtr9O3cuzj29df445wiLHgfu+6g==
X-Received: by 2002:a17:902:a408:: with SMTP id p8mr9445714plq.36.1590059416579;
        Thu, 21 May 2020 04:10:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c38e:: with SMTP id h14ls1034073pjt.1.canary-gmail;
 Thu, 21 May 2020 04:10:16 -0700 (PDT)
X-Received: by 2002:a17:90a:9606:: with SMTP id v6mr10992416pjo.20.1590059416127;
        Thu, 21 May 2020 04:10:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059416; cv=none;
        d=google.com; s=arc-20160816;
        b=0o5XLTe+rOk/lyUXKvvyMaDD70CXjHBrcygShCfWt4UDjfObtd00sZPX8beGjaKnaZ
         KaSp7dIWWwJcoU0iXlt3gQe+PMtYJ8bXXHAWkdQjN+XbUdj/D+cns5bSx9jrhYFBJHIu
         WsadAET6uJRtm07k3HwqUci+JX5ow/xU7phISLn0yMNIz+gD13dp5XTkTCreKxSFAP54
         SgRTE97/gWiEGNziRpLaeyhGEk/jh99HBc1IroK/Xq4jSr/dEk08W25iOK15Q+iOPzn1
         5cFYf3TiWjruBKNqHx5KL37uLJLuhKS0Q7vW+/dfFofipxsoMT7ryK6JOuNy4wRypxMc
         IwzA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Mg9xxMrsMAxLq6dAWJl0xfMkvPwKVEQaVFcZauCDO10=;
        b=D8B5DLqDZnoIxB1kYGc1Iuwfyo4Z8mj6wmtxLHLvxS7qG3hxXRL9xgWBBiNw1//2d3
         NgUxSXPg9IsUIMk7EWi8qz3cUMshmTs0ImjqPkWzzBG5PvreP6ks6vWzPcT80ZdrTBTt
         uTFWI7Idk/PY7ob8XsOkPPSZHcw8lT7f5TistiZA90BqV48o0pfwOuiM7aEeYWvxIIal
         G9ZJxlIfPFBpH0fdpf67zyNQROAaLk6+DNAN8bH2+FLNAda1nO5TTFtfyHMgb8eXQp5T
         t0W9GuO4p3vQ9JkJTNM9nHKuIAFi+bb0ZR++dAt7qlU3SIkifbwoVEy7QLUenqqUYfcX
         VuUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=qNkmtlLU;
       spf=pass (google.com: domain of 3l2hgxgukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3l2HGXgUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q1si347666pgg.5.2020.05.21.04.10.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:10:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3l2hgxgukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id q16so4883874ybg.18
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:10:16 -0700 (PDT)
X-Received: by 2002:a25:392:: with SMTP id 140mr15229297ybd.507.1590059415347;
 Thu, 21 May 2020 04:10:15 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:54 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-12-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 11/11] compiler_types.h, kasan: Use
 __SANITIZE_ADDRESS__ instead of CONFIG_KASAN to decide inlining
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
 header.i=@google.com header.s=20161025 header.b=qNkmtlLU;       spf=pass
 (google.com: domain of 3l2hgxgukcxaszjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3l2HGXgUKCXASZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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

Like is done for KCSAN, for KASAN we should also use __always_inline in
compilation units that have instrumentation disabled
(KASAN_SANITIZE_foo.o := n). Adds common documentation for KASAN and
KCSAN explaining the attribute.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler_types.h | 13 ++++++++-----
 1 file changed, 8 insertions(+), 5 deletions(-)

diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index b190a12e7089..5faf68eae204 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -167,7 +167,14 @@ struct ftrace_likely_data {
  */
 #define noinline_for_stack noinline
 
-#ifdef CONFIG_KASAN
+/*
+ * Sanitizer helper attributes: Because using __always_inline and
+ * __no_sanitize_* conflict, provide helper attributes that will either expand
+ * to __no_sanitize_* in compilation units where instrumentation is enabled
+ * (__SANITIZE_*__), or __always_inline in compilation units without
+ * instrumentation (__SANITIZE_*__ undefined).
+ */
+#ifdef __SANITIZE_ADDRESS__
 /*
  * We can't declare function 'inline' because __no_sanitize_address conflicts
  * with inlining. Attempt to inline it may cause a build failure.
@@ -182,10 +189,6 @@ struct ftrace_likely_data {
 
 #define __no_kcsan __no_sanitize_thread
 #ifdef __SANITIZE_THREAD__
-/*
- * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
- * compilation units where instrumentation is disabled.
- */
 # define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
 # define __no_sanitize_or_inline __no_kcsan_or_inline
 #else
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-12-elver%40google.com.
