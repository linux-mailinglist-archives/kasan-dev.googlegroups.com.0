Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2W67L2QKGQE6CJ6XZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E6A51D5300
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:04:12 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id f3sf1718462plo.14
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:04:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555051; cv=pass;
        d=google.com; s=arc-20160816;
        b=cTbPgW7Ah9CPRvg9+FPS5B7MULQJ8Kzljczl4/eR7+fwfx467KTneKjyy40Ey/sdES
         fCrA+aworq7L1V+j3N8eDIYVn6h//BsrKsD8ewO38r9FLxbBU9B0lDEYLmwJATU0YAVA
         I0zuZklzUNW3RSprd3WHDPlWm+3iFukXkdTCOPC5/+fOOQaK2b/idZExqHx7l+tJz3Zz
         DEkx31cmL3yVUniqypwrPLhbGJp733JRZgwqxBgCDgEUlwsFK4RJ6BCVNfZwZZb4OvtT
         KVKJlTC0B3tAsjtDfiy2T1CF5bFKbcCGK0FK1JnXN78eZ2te/a8MBvY+o4yS1aUrCpqB
         pO9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=JjR97nSG7zJDDACWwmtw0P+WM+8X0TU22Pir517de98=;
        b=yNxIUVVY7e4DR1UQ3dIS21eCpMxn2w9vftctpPTZZIVj8l4S75MCHnOj3kzSa6qpsx
         0DNIt2tyk39AEJ9gzYztO5lVLwXYuQ0C9/GUCTKviImqmcAu55B2nTyUH5TUL5QlRZR5
         aCh5GeYPQK4F4KuSwwy71mFW0z4XnA4JmD54mPBQWvM0bUItUfasmBoyHqnyiUI9dBCw
         HxypXuyvEUP7HI3eaGoCvA8cL6dJa5LS5pxFm65PXoLTiSB37BIGbCK7aadz8PeoNNmf
         M9CHGuOj04UWumUyN6K+xmtBiXKae9D7pV8Ca+YR7MpCGB2r1pkErrzfSBfRabXPrEAc
         W4Cw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e24SsoWQ;
       spf=pass (google.com: domain of 3aa--xgukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3aa--XgUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JjR97nSG7zJDDACWwmtw0P+WM+8X0TU22Pir517de98=;
        b=rVa7ZUcetmJREhmSeMmN8naFRFZvYCM/sMXomH348MW00+MBO2I4ARdnuDKmbZ7YPT
         Rt45+HSXQBkrxJQbDj2K/bRshgVC9rcNJthNXWXJGLTeD8On8xX1fFSraJYwZZTqaXN8
         TQ91/xJNzHbCJXhDUpLVWAUqyCUKlOqRrY7Y2tSZGQpwlvDRwOofxbsAV4RnidrmOyiu
         imIC8oJiM/1yeKvQBLllqmiQgP4phRSGKz33h1+rg6cROivaILL8G0Q4vgX3PACabapo
         E2kqvlapQBU4z06xQnRDeT5/AE7944X1akelQzj/8tfCcIPBG7d0J2wQ+mHLfFQNyOPI
         1Fzw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JjR97nSG7zJDDACWwmtw0P+WM+8X0TU22Pir517de98=;
        b=l7hMIIQthdvzMnK1wIQXL/B4JSPwLV7/DqMKDOvkGuUCQ1Y7ISvpckBit5nCzJFpvU
         WjY763BGxhZkLMFBbu1Knm20LgOVj1H0h9QBM0bbAXFN4lKXGV5w6QqOyLzfHQdXE14a
         57026arC4sVsFAnB4tqJduoAOymElkl8O8qOGLsiE0uJ8hGV+xjnZsSPEnJib4WbBWjU
         NdE551IRjMb3Ful1tNouh0j5D6V9hEjOdHxMyiaBsLygu8yy2kDOR/K5i/vCezk/F1lF
         1iVaJ6A5ZwnLqlMIJi3o5uvmyaxRj8up2wzA2ypqucsg7DduHsn63tomtiMtwz4e148Q
         HQ9g==
X-Gm-Message-State: AOAM531yo7nVp/OGXSJ7ZpYOT13a+TZWJltqaHJ0h3uTrTl3/cqviePJ
	1Kb0BTWwS2l6b9/G9ufV1a0=
X-Google-Smtp-Source: ABdhPJxAGc4T2Qw+XNGgFvQiz+kg4Qy57pwCcZQ+8pZttMgsOO/qkAcILcQxqX3PzDh7C+TBP0WyJg==
X-Received: by 2002:a63:dd11:: with SMTP id t17mr3648832pgg.348.1589555051039;
        Fri, 15 May 2020 08:04:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:800c:: with SMTP id b12ls1322121pjn.1.gmail; Fri, 15
 May 2020 08:04:10 -0700 (PDT)
X-Received: by 2002:a17:902:8496:: with SMTP id c22mr4087760plo.182.1589555050506;
        Fri, 15 May 2020 08:04:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555050; cv=none;
        d=google.com; s=arc-20160816;
        b=OnkYrOpTGvY8AvztCxLU/rq1+mIpJTozi+2o7vQj9ZP8J/PvXHsv3bNvXQRHWMnouf
         FRe3AmG90kRJvvN/peRRV8xVDaboV/mojVlhh0LFj5/yiqbmot9t1tH7f+lMjf8+aVmr
         /EG5CJ7r9EWAYeSYe6MVgo8gbCpBaDYwz0NCf4vC7LllfGYH/UxrbC9t4VxbXdQ5i0hf
         Sc5G8YoPCTmqebx8/OjAhvRqrflZXWLESseS0PTintlfHfMYeotJWl1f/IjYDLLcrQni
         q71fCmVZzqINyTdS917LyyIfmGekPSO9bBnsEOFmYZ5BqxBJB+PKSHfK5hEBTCk4gNWn
         1ifA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Mg9xxMrsMAxLq6dAWJl0xfMkvPwKVEQaVFcZauCDO10=;
        b=aSq8mf3ezrq4iAFiW4ewW0g2DqrPLE1XUCp/hOo/dPGOfO0zpVtChpfOYGtaWn5IwX
         SS0wGDE/zvSv3g/0ggfvlLhnkxozhLhoe/P6Qi4pxCfvYZtInCiWIgKf5lYHy3BRqRZa
         pzk++i3McK7JAj3CpHgl2h+QE6YERj22bgEypJDRbIg63I1uQXOqCFWZf8EGxr5hpOoK
         msTdxKp9lQGhrpUqcMPDQg/dQytzRNRZQpxCioEF+3FyOiE+trR4UUivpMSTuUPrLMIc
         TGFBmcEzujKQS2DBQ+eHVJWBU7VS/V2AaIjTEZrF95WAjNgyNGWfIs2fuYEOB4AxnL52
         00xA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e24SsoWQ;
       spf=pass (google.com: domain of 3aa--xgukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3aa--XgUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id e6si803150pjp.3.2020.05.15.08.04.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:04:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3aa--xgukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id p126so2498179qke.8
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:04:10 -0700 (PDT)
X-Received: by 2002:a05:6214:8e1:: with SMTP id dr1mr3588892qvb.193.1589555049514;
 Fri, 15 May 2020 08:04:09 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:38 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-11-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 10/10] compiler_types.h, kasan: Use __SANITIZE_ADDRESS__
 instead of CONFIG_KASAN to decide inlining
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=e24SsoWQ;       spf=pass
 (google.com: domain of 3aa--xgukcb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3aa--XgUKCb4ipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-11-elver%40google.com.
