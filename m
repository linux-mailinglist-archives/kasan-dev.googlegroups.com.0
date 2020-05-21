Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKM5TL3AKGQEO5UPJII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 754FE1DCF7F
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:34 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id f15sf5312227pgg.5
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070953; cv=pass;
        d=google.com; s=arc-20160816;
        b=jTRMA3Dkl2y6wKkSJ3NcGiPRkTvG9a6ZDO6PIgvBzzdAqqY1Sf0Vmylb3iGnXvvg+P
         Lp+0hcQMkq8hUzu/g3zh/3oRizO5tTh/u38BEsguvEv4JJHyPwijLkEUDrdzMW7XGG5g
         q0KCnxPUp0wqjsw5TziQMHmpdx8r5cGp8iPTcf05w276stHTAswBCwQnK3A5H/jRQdXh
         m0iQLF0F4FvFlSvKfc6OttS21f6aaYr9JWn9le+s8CfLahqePUY4Cg0Clw3X3NJ33im8
         Q3vbkdd+B9A5oPTlA+iFoB2CoAhK+WzoKXPaLnSqbQ2mGAihbYt08qFtzgw7jQG4VufZ
         k4Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Dr+aVLlpt1xiPxp69IW9AUGpuNa6XodCztijG31oYi4=;
        b=xe2Ns1u5u5+ld+Q/SLekyHlL3EorPPwDGdcLFyX4iG/g12N+4jghcESk7V+FjUjuLg
         bDyCaPvFFhV9SnVm8P++rTPVv+pMRN0VcFNCuoiT6EhwyiXDaaAtMCaasz8zDt8b20DJ
         t+3QL/inkdPEO/rtjCfz2gT9ALlObaDjxeqoRRL22C9N7pCtDEmLZNr5qeZi4qsZLMTX
         i4UsJY7kAMHlvuJNtTNgkXAoLh9FOS/PiS/IMnqPbzDWPxGzR10lyZ8pEn6vecuZSKPI
         F2FygtU7UI+EfINrDoEeuAGIEdSH026pWsnW+QfY1a11K5P9K8EKp7kn8ps/d9PKSVhp
         j8Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="axxi3Qx/";
       spf=pass (google.com: domain of 3p47gxgukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3p47GXgUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dr+aVLlpt1xiPxp69IW9AUGpuNa6XodCztijG31oYi4=;
        b=ZDhT0csrgMf9tTdprkPm2SaH+7k1WkAIsYj9zS1Hkc28hov+De0yNvknCW5IUoU2u0
         /KozzRhbfBIr4q0bFMzuq2cOfzcaNaUuzchAigjwhKlEx5AdYkJE/Xj5WWkjThELZu+L
         X+Ab7ZIly0cTDq3Rv0d4xN7Nn9lpvZqGlB9RRUjtcGnVzvLf/tj0r1YAmC+j3PWkTm7m
         5voSfeN8+beqUgC7BcxqL8UiF6wIPwDnsDYHZHFk5wuuqDihYiHwPPUlQQTt3fHRuOnB
         A3QGckM/RvcSCMXl1oB6ZyBgPG9U0JDAI6Jpt1noBaNuj2Bstv6wtcomm8RF51tQ3Zha
         9nvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Dr+aVLlpt1xiPxp69IW9AUGpuNa6XodCztijG31oYi4=;
        b=tye7GKBqOjDTVnpT+Ad+BrTnyIH4wa+i2Pogrg7GmtC2tnjB5vypjFT0M74qESwUzO
         uYuQdg6YUPTRSO6fHo9s3zgehji+5RkMffUhica7eI8+Uw9PB98Q345mKEZSvhQ4FvL/
         IN8WKYZg3Qqk/olRI5xufY7FGHbxHk60ThNCsEOHER5Yz8J1hTGvm+1SaLtR4XC5efMH
         c7ELF8o2/eG+yDaPh5CEefs5Hoaxk/nkZAOyrNwvpmyt5xnz/vVD3k/ZdWUX7EDRBY6o
         9oa7GS808KgodLCcqijfeYkJ3Owy6RmzfoFnAnekufSnrFXNa/EMvfpNUq4E7lMHSIk+
         KrbA==
X-Gm-Message-State: AOAM533AeIeCRWkR1aV+ZKBIOBiaD0pWxechQUjaBWRMHBWBEnwAIF2l
	n3BgqazybgKBY9z2H0QJj+s=
X-Google-Smtp-Source: ABdhPJxm4eqedjdS+KLrdsIXIknEmvI49SWrMJcnWuV9N1RhZ9JIu4xGs6IuMOp/njL/OUupWqWj6Q==
X-Received: by 2002:a17:90a:9311:: with SMTP id p17mr11744346pjo.145.1590070953127;
        Thu, 21 May 2020 07:22:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7203:: with SMTP id ba3ls881610plb.4.gmail; Thu, 21
 May 2020 07:22:32 -0700 (PDT)
X-Received: by 2002:a17:90a:7f83:: with SMTP id m3mr12141312pjl.147.1590070952621;
        Thu, 21 May 2020 07:22:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070952; cv=none;
        d=google.com; s=arc-20160816;
        b=nCbi6leNc/0NEGyu7kOBtyFW2AohNYXD+DLMh+xZ9CTrV93SNrm4tPK5E/cUo874z2
         pzcLqX9k7IW1+grkQnRVFz1Uz1dZy++dsEdgMqnM40gItvjkg7qZIaQM9o0SKHDYkmoI
         pSaqEPG3Z/f6icknVxfHBCoDfIRljNiSWXlrhVfHzLpcqNMilGchPlc/RIdEeBzEjGca
         ZR/AkLNo3KHkFEYTEgW9ZnOOO5/P0NHAVQA4Wy3tzBW3Cq90EhwGzItLb69DtK+evveF
         CwFhtasM5srFNla0zODxh1xpdLhjfYwiNR9qAP9BImoB/jh1BpM/3sMRNN2YldXuwpVZ
         RUrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=H2uRSUohXbn7nWhU1m6/8O/OIPFFeT1jA5i34XsZ7o0=;
        b=ocnvw1jVxa/ecYXlHF2gOlw+NToAQun+h5QaIYueRzoW/unrkG5jg0iaZOzjJ9Q9tR
         OEh3l9buWBUbvgkXNDQ9zinOMBwJbDyEkHO9PQyVR4X8Z5eQrPrs0fQQ68yVoY1Fm7yB
         AUE4NXos0uIaZI6s4QEErkfZcGRdinLZyjCKde/Le6UZs41lcpTX8oLolVdlDmgWOA3M
         swKw897hLyhp1svyqF3XcgMnObcjI7guMTo/4+5VXCfwLGRshWJzFb6Xxbd65HhSSSho
         qop7r3XVt86k+ckytIeMFY0OeQm0zWMqRtSqj4gKWDqwcEp81o6TLBlHB3a3SsRVzHQm
         XXlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="axxi3Qx/";
       spf=pass (google.com: domain of 3p47gxgukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3p47GXgUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id e6si463015pgr.1.2020.05.21.07.22.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3p47gxgukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id z7so5470265ybn.21
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:32 -0700 (PDT)
X-Received: by 2002:a25:3610:: with SMTP id d16mr15626055yba.222.1590070951790;
 Thu, 21 May 2020 07:22:31 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:41 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-6-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 05/11] kcsan: Remove 'noinline' from __no_kcsan_or_inline
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
 header.i=@google.com header.s=20161025 header.b="axxi3Qx/";       spf=pass
 (google.com: domain of 3p47gxgukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3p47GXgUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

Some compilers incorrectly inline small __no_kcsan functions, which then
results in instrumenting the accesses. For this reason, the 'noinline'
attribute was added to __no_kcsan_or_inline. All known versions of GCC
are affected by this. Supported version of Clang are unaffected, and
never inlines a no_sanitize function.

However, the attribute 'noinline' in __no_kcsan_or_inline causes
unexpected code generation in functions that are __no_kcsan and call a
__no_kcsan_or_inline function.

In certain situations it is expected that the __no_kcsan_or_inline
function is actually inlined by the __no_kcsan function, and *no* calls
are emitted. By removing the 'noinline' attribute we give the compiler
the ability to inline and generate the expected code in __no_kcsan
functions.

Link: https://lkml.kernel.org/r/CANpmjNNOpJk0tprXKB_deiNAv_UmmORf1-2uajLhnLWQQ1hvoA@mail.gmail.com
Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler.h | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index e24cc3a2bc3e..17c98b215572 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -276,11 +276,9 @@ do {									\
 #ifdef __SANITIZE_THREAD__
 /*
  * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
- * compilation units where instrumentation is disabled. The attribute 'noinline'
- * is required for older compilers, where implicit inlining of very small
- * functions renders __no_sanitize_thread ineffective.
+ * compilation units where instrumentation is disabled.
  */
-# define __no_kcsan_or_inline __no_kcsan noinline notrace __maybe_unused
+# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
 # define __no_sanitize_or_inline __no_kcsan_or_inline
 #else
 # define __no_kcsan_or_inline __always_inline
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-6-elver%40google.com.
