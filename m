Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS4JY3XQKGQEGALK3XQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id A05F411C114
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 01:07:39 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id o205sf219112wmo.5
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 16:07:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576109259; cv=pass;
        d=google.com; s=arc-20160816;
        b=sOSyydD68gCo+vyX3Xyb+yg95oyPvcxlF1Gbr1CdRPfiaUFYT8oGbdl/ncy/L1i6Hy
         7ufHGGx7LD/SYB10ubB1Up16+GcjBgimtPSqoniBDZCvVBcqIMSjfdWJoQ+bQtNGn342
         DNB2kRYH9yyvtwSbDTK9QrmPZHHy7zeonKJ7zL/9qDT66VjeBqDlEV3P0J45rZoqs7r/
         GgPvsuXdKUY8romwCPWuKNnruAXlYmML8UsOBMq3UW+3QawZyig79FE1TTyhHU1fBoIB
         tjAoxaxx5v9/ccZ2pwRQHvQqjtw8/JmxAmYbIbMEOz7y1/2N9mZ2OAcUjGtuFXBdWmE4
         RynA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=zhdphlcx3XXC/8rgG49CeP3JCHdBo8btPHnyYdR7uYA=;
        b=FIt+d4+wF5KJCUxq+Jc70itmzolVk4qCVo3nMA4eoQds6mOj/tvu1XUD4Sucn5EYPG
         W6EIuJo1N5/iqeF6Jepw8ep0EiqhBHDRKLOgUIM/NJgP0WZ8fJvNz9jjAMa7oJUBCMCS
         GG7UBGLWGc98pCfsf24/cIla1PZadiKK01ZsbRKctvjruJwOR3HfPU9ONqZJVIYrBZ8R
         EXYAbKYrpWlxnr/Qe6EvsfLGCI8VUlAbDw6OFkgfXUV3l+PitUyWi01aWcvZhehDJifK
         mzwwUEaV4UAYopSeYKaQ+eQgLWferOzqLsY86JAkIx5hE0GS5xoq6FvTB/tEFtcqpMxl
         MoXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XfXWPnMa;
       spf=pass (google.com: domain of 3yytxxqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yYTxXQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zhdphlcx3XXC/8rgG49CeP3JCHdBo8btPHnyYdR7uYA=;
        b=c7GIIC+FyuxpxvlDnlKMdkxArvD7zKc7VqGZAZLGjowU2VmzAIcW6uBO6qPlQb8K8k
         1LRME+N4Ycaj3hhszaR11zs4QxGg2GA0HjLD3lUtemCsSq36ACjd10Ji6zK7dQ7ofgup
         5xAPKkSE/utfhJrSTa27FP8JO4jCEl7mAdZ6KfQRQH1Au2nhVU4SwkV+/y9mGCaM9S+c
         SDls0GgMh3//biJ7gNu9RE2HPccEAS6vI+QDwUZAJeroovtSnuEgbYnNfHJb5m2/qFtl
         AZP+Y55SkcKVuHKxuGGKmeQBIo1gmZ56S3wx+0u+pEjnPUATitKP4TGOMf9HOT2ufJEP
         qezA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zhdphlcx3XXC/8rgG49CeP3JCHdBo8btPHnyYdR7uYA=;
        b=R6nnx3KWxdTUW9HSMuGKeHT/GfWKlzatNQwuvg/l+ypX/btGhPRWmKnXWgfieA9YkA
         ya8NVpQYA0UtZhiRxYw/fqniBRnQQZpqkT5767/PsQouZDAAgsvPU5ogyoF2DvlECiVb
         NGRjZYA7F8Us4oACmXE4PF4Yexhzr1PKr9/9oA7i45EP+WRI44xLDsv1dOenpOBZLu/L
         /Og0KOKlrThPFAUDdd5RlctXSlBVgilVqDEdZ0ebMQGtkfKvhnLs0/64IA6DG2wECb+E
         X0BPfnYyxDwWwSrhYOkYQUDPHDYc0Cw6zYuDColBOCXX5GFyGu4VDasvz3aCsYf8wjMX
         SJ+A==
X-Gm-Message-State: APjAAAVNtu3+f0pJ0pIIv61AeQTzTfdi0Syzv24zhS90J+62hahoKvSR
	7Y531br9jwFbzEuY/oaX9lE=
X-Google-Smtp-Source: APXvYqyCm22djUyS1d3vprSaLS62rqSLMXoTFJ6oPpuycdVoV0hDz+KvoZQt+AIQIbdzWlevAiIIVg==
X-Received: by 2002:a7b:c407:: with SMTP id k7mr2957011wmi.46.1576109259309;
        Wed, 11 Dec 2019 16:07:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9ed2:: with SMTP id h201ls2006977wme.3.canary-gmail;
 Wed, 11 Dec 2019 16:07:38 -0800 (PST)
X-Received: by 2002:a05:600c:2254:: with SMTP id a20mr2834054wmm.97.1576109258734;
        Wed, 11 Dec 2019 16:07:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576109258; cv=none;
        d=google.com; s=arc-20160816;
        b=ane0eQVU3pWL8VHFTuJi3+ojDS1fWZS41OPiPf9G7MSDvi0yI4xumc4RsvjUlrmfA/
         ZBccyZYcGnO1yNBUg8veWMtYbNHdOAYwYd3flVk0V/afgFO7PhEjocCMtgU1oJg8Czok
         YaFOu6PKiiCE2MUXcfccqBM6ZrawhHWX2fy4ygF7k3Ql/FmEqp/zjPTxDhvEo/vcMf0b
         9ExxVkB1AGRZGUHAuR81tEInq5iKGFQm16xwhV4b9P03iodRl9wNhJXw68QoDNI9M9fN
         IOzZJ3vH87fw/EocPu3sYz/e1mpL3/Rdjh4caX4rb4F/sDYiV6KQtzMBPf7dBYWbFy9k
         2COA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=tqxzx3Ju5IffICSGxw8fWf7dGguiPyd/gZ03a4SjbqI=;
        b=Ac8Sm9NhO2vqP/AswjR0/KYA7pZmCeWn586ILf7xYawAFlskDXwPXOD9gbpjyS6IxW
         3GMSpo3T+txPiHsE/SjiFicO+g5aEUFk9UwPGON9AJaQQaLCom5N6voGhZBuCVb7uU3e
         2RYdTgg/FwTj+CCFtyIVZR15/JmzYLM//c8wwUqBwFZBgAFnerdRlsda7GaXjbgJaiok
         f9FvWJT9wEg3+jGv4gl1jzj1vVsvKb1IQUM9dNwSSil+f0BV+yDm2yO1ylA1JsQWBTUZ
         1YkN2R2E1Zb9M1D2F0zJKL+PD6xd/bhA3KFhbM1sMHHT+5A+fmuwUwi8BoSbULs//2Z/
         jvHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XfXWPnMa;
       spf=pass (google.com: domain of 3yytxxqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yYTxXQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id m2si138196wmi.3.2019.12.11.16.07.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2019 16:07:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3yytxxqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id f10so280604wro.14
        for <kasan-dev@googlegroups.com>; Wed, 11 Dec 2019 16:07:38 -0800 (PST)
X-Received: by 2002:adf:ffc7:: with SMTP id x7mr2678183wrs.159.1576109257933;
 Wed, 11 Dec 2019 16:07:37 -0800 (PST)
Date: Thu, 12 Dec 2019 01:07:09 +0100
In-Reply-To: <20191212000709.166889-1-elver@google.com>
Message-Id: <20191212000709.166889-2-elver@google.com>
Mime-Version: 1.0
References: <20191212000709.166889-1-elver@google.com>
X-Mailer: git-send-email 2.24.0.525.g8f36a354ae-goog
Subject: [PATCH -rcu/kcsan 2/2] kcsan: Add __no_kcsan function attribute
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: torvalds@linux-foundation.org, paulmck@kernel.org, mingo@kernel.org, 
	peterz@infradead.org, will@kernel.org, tglx@linutronix.de, 
	akpm@linux-foundation.org, stern@rowland.harvard.edu, dvyukov@google.com, 
	mark.rutland@arm.com, parri.andrea@gmail.com, edumazet@google.com, 
	linux-doc@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XfXWPnMa;       spf=pass
 (google.com: domain of 3yytxxqukcy4w3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3yYTxXQUKCY4w3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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

Since the use of -fsanitize=thread is an implementation detail of KCSAN,
the name __no_sanitize_thread could be misleading if used widely.
Instead, we introduce the __no_kcsan attribute which is shorter and more
accurate in the context of KCSAN.

This matches the attribute name __no_kcsan_or_inline. The use of
__kcsan_or_inline itself is still required for __always_inline functions
to retain compatibility with older compilers.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler-gcc.h | 3 +--
 include/linux/compiler.h     | 7 +++++--
 2 files changed, 6 insertions(+), 4 deletions(-)

diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
index 0eb2a1cc411d..cf294faec2f8 100644
--- a/include/linux/compiler-gcc.h
+++ b/include/linux/compiler-gcc.h
@@ -146,8 +146,7 @@
 #endif
 
 #if defined(__SANITIZE_THREAD__) && __has_attribute(__no_sanitize_thread__)
-#define __no_sanitize_thread                                                   \
-	__attribute__((__noinline__)) __attribute__((no_sanitize_thread))
+#define __no_sanitize_thread __attribute__((no_sanitize_thread))
 #else
 #define __no_sanitize_thread
 #endif
diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 7d3e77781578..a35d5493eeaa 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -207,12 +207,15 @@ void ftrace_likely_update(struct ftrace_likely_data *f, int val,
 # define __no_kasan_or_inline __always_inline
 #endif
 
+#define __no_kcsan __no_sanitize_thread
 #ifdef __SANITIZE_THREAD__
 /*
  * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
- * compilation units where instrumentation is disabled.
+ * compilation units where instrumentation is disabled. The attribute 'noinline'
+ * is required for older compilers, where implicit inlining of very small
+ * functions renders __no_sanitize_thread ineffective.
  */
-# define __no_kcsan_or_inline __no_sanitize_thread notrace __maybe_unused
+# define __no_kcsan_or_inline __no_kcsan noinline notrace __maybe_unused
 # define __no_sanitize_or_inline __no_kcsan_or_inline
 #else
 # define __no_kcsan_or_inline __always_inline
-- 
2.24.0.525.g8f36a354ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191212000709.166889-2-elver%40google.com.
