Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXW67L2QKGQERZPNZHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B7111D52F6
	for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 17:04:00 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id n5sf1177116uaa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 May 2020 08:03:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589555039; cv=pass;
        d=google.com; s=arc-20160816;
        b=HpYHJtUjzQ6TFqFOTzsqwDxHaQAeHSWJD2CYzRR7bXUaiVc9SkpxH+pu2dAZLm8WBJ
         ax4RDhVcpacSOYARPmjPqW9019Lt2CinjXwx7iH4seqaDdtbApHVBW6MwXK3gGLLlxqQ
         CnhpbsPypXSniUkmHp80pam9uFqiXv+BASL35Ha9+BQZ2HDA5qtYp4grD5Uu3E72eGYt
         Rbziq3JOxWU4yUeKGtdl+1nWj/JnKmi0lNWmfrirOQVnecbULt/8Znxe5Rt12ZCXeugA
         1T8qFP+El5v5YivSo98tIXXhZKOgu0P8BWnrnuc+qYXe3CRhRFuDak5FUprI86pcX7NX
         d3RQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Qo2a2FYCM3B4yvji8ar02m4bkl+7rjFfnn0WxUwqZ7s=;
        b=xmq/M/asndqSoFBEE/8MsHxuHjLEKcRDvmtgrC4zbekMCje1vR/a+LkWctqXDpzxja
         6waru/qJYoflYpVRSiWlI2ksnCmuiXr0crHEI1s2OsnNYWl4cXaoaXaWT6JRSPSogEMv
         Pq898u817Mz96xJ7EY1Wnh8nkrcogIwGUIi8o9hZ6DMw2JWABBpJNyUmZI1GWAqhjlGd
         3kXF97q7tXNciw4wxutLJz7InEcrHOt0nLbLMjNAOOw36uy2D2QvAXFc1dDdgPKSkO/7
         6ELE1qDBfWwEEogakeVNHZxqpp8kH+jNAVy4kdXv7iZekd07yBLRmTy83BrcIg25o2Xk
         HJsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SZSlqP2Z;
       spf=pass (google.com: domain of 3xa--xgukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Xa--XgUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qo2a2FYCM3B4yvji8ar02m4bkl+7rjFfnn0WxUwqZ7s=;
        b=klE0rlSFeLK4ZwU+hsVRWTz08Gq5Q7HPGxHoEcYbZZ+vfDtIxyM8LmAf+V9w1DSt39
         Y/tB6JH7V6p7h9djldtqtae2g49KDN+gG278IEgtGGHCbSTqicmOxTAw7HG1UrsiMemd
         fvl497XVZKCUWx00S+gUaN7a+ttBtcenOff87FyulbBt8fvOb2VRg3orcWrhLJWAr512
         6fd/YJpvA9k5MdjxjPfPcLP2AhzpYu5ZrKjWJim/wsG2Ye5Ma9bzOAn70Yu5YSnHgB60
         v80I5L/wWYka6HBgdSDFJCDQHZGlf4bun3Zmdx9NChhiiAphDnpaaWZEe2MDWErO+oGc
         uC/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qo2a2FYCM3B4yvji8ar02m4bkl+7rjFfnn0WxUwqZ7s=;
        b=DHjbQUAANsJydWjfLZXZ4cO2uR5eRtvq7vSKh0RYS82iLO8IrrITZwEAFM3WyXneVw
         rhFGp8S0N1pu4In8b0xTKK8il72xiOITAiZLuhB75CoGp56qcUuihs0kBJ0KQ/zhSezV
         GzgoUAzyCI0logl67IzqsM/dS22yyGYw7nefcQ1dAr3SsfGzclffeUJXOY/S+37SqDJQ
         gpUyoaHLTTT4ViCzCt2brM6T/lTEyvHuvcIL9qTRM5ld24WIfy8/ou48APTvrkbbRu3m
         su7u0XUpiQ4mtHQ5AmxEWbsuZ/cUHagb+lz2t7/srhbCCvfk1e46cOieQYMuOC9nQsKg
         ZEXQ==
X-Gm-Message-State: AOAM531kZ/iW5RC+5XgoK4jvQcy3LNzunG2lVR2xsytdnKWkYG60hUeG
	96IvXgrvVvSR7+28eiT2iho=
X-Google-Smtp-Source: ABdhPJwKrkowgEH50YYBuvhJOVkT2aSJvhz1Nfg8MKtc9ZnC0mZV4MO/8ShdGIOLqLwDvvcMm0itAg==
X-Received: by 2002:ab0:60b6:: with SMTP id f22mr3136061uam.39.1589555038617;
        Fri, 15 May 2020 08:03:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:7902:: with SMTP id u2ls329793vsc.9.gmail; Fri, 15 May
 2020 08:03:58 -0700 (PDT)
X-Received: by 2002:a05:6102:446:: with SMTP id e6mr2919863vsq.68.1589555038195;
        Fri, 15 May 2020 08:03:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589555038; cv=none;
        d=google.com; s=arc-20160816;
        b=IA1iPCpkW/bb0jLT043dZ5fnJw1b/IdfM4KavyvWi9DIXSmZ6Vmgp46TX+Mfjno/vZ
         DDs9APVyUEHPWnGf9maBQ9lzarZqsuBiTovQtqRb2hYNfhfPAIpqnqAlAw1CS1JLLkr3
         rrdiIlIHx9emGs65aJ3LYv17bDruG3TdgTJ3S6sfB73d5J22ecffjNif56L58DUBexdz
         JmYK/kGwiUqpMoKVzOWXTIj1sEo5mOYUVkMutMxsjo3A884z1wlO+PLDLfhscgOhXANG
         bszWh4WASx8ia4yL3YLW3jkv19xNvSEwW6voAfv3jbdYZzbiXOZXYP/ZmN177e/wjxoU
         W3bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=O66Rrrp+JcFi/5yju5R8rYLztnbdicYxc/HcFiSiC0Y=;
        b=aeEyMmGQPKcwdpMAizT1ri7kyrWqqbN79GBBtklZLttgONaimRG/QruMJigX0I1EvE
         JU0WQ+qJRTbw/ZX02b7NrqZfUI+lETsNMj8BhIsEtDQzMd/56ctkoVaht8KOlht4mNZy
         wN74si4iD6yimSHxzPKcthJoKAqrxJ0RZP6hVG7s36rMaljw+EJz3fQV3cYMnOT5KkNw
         Wiu6k8RYWNwW+9aG07GDtRuI/9dMPuQQCvRI5UwzdaAUMJyTfBkhkbavWa1pXpixzZQS
         N4DVxlGJOPzGkCT3nyKp0FIMllWcWbQvBkBZ6m+S4wv+GRgle3gqv8PD22b8BKP5a0NU
         QKIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SZSlqP2Z;
       spf=pass (google.com: domain of 3xa--xgukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Xa--XgUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id c14si227581uam.0.2020.05.15.08.03.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 May 2020 08:03:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xa--xgukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id k15so2893023ybt.4
        for <kasan-dev@googlegroups.com>; Fri, 15 May 2020 08:03:58 -0700 (PDT)
X-Received: by 2002:a25:874b:: with SMTP id e11mr6243676ybn.23.1589555037606;
 Fri, 15 May 2020 08:03:57 -0700 (PDT)
Date: Fri, 15 May 2020 17:03:33 +0200
In-Reply-To: <20200515150338.190344-1-elver@google.com>
Message-Id: <20200515150338.190344-6-elver@google.com>
Mime-Version: 1.0
References: <20200515150338.190344-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip 05/10] kcsan: Remove 'noinline' from __no_kcsan_or_inline
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, tglx@linutronix.de, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SZSlqP2Z;       spf=pass
 (google.com: domain of 3xa--xgukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3Xa--XgUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200515150338.190344-6-elver%40google.com.
