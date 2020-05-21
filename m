Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNE5TL3AKGQEMCQUMCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 82F8E1DCF89
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 16:22:45 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id ba6sf5356307plb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 07:22:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590070964; cv=pass;
        d=google.com; s=arc-20160816;
        b=SwoJnX7G9697miS/v+4TxefrokgACNHQPHYBQ98OBDJ9LqHCmzaN/tt6tI1YrfXX3h
         kZGWWCjNb8GQvlV2ioINtSlw4t5fvuDMqs7znUztG4Ln53Zl8XOxxfUpMQc4E5VtJGDp
         StEVcKZ5b1Yh2BwOYGsjuGZRLVbGSer8WoBuAbFZjlfwYtCU609X2FYFc1/+4KBrlJTt
         g2CgkAnu0OsPNia74D47OAlSzycVnvzbQWoe3hx5IsROfuXi90/OoqoJ4PKgXvLBxj89
         RUOxQqhgzbCdt4cGMCzVh0kvkM9a7zoAfUV1l+nxWsfFordQ2A7/gSj8y+4Z9XER8+xL
         AknA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=HlbHgBXWIw9oKPlvAGFyp61Kn5AGBo8pMT9g47pMKjs=;
        b=cSW4ZVX0qiiL3U8E6Y3ETytPy6t3mxfu6IKXhEQZwl0iX3oIzT2au0/hl6hqMhasXh
         z5kdS/pKkw7WSRHrMTObvHj6bqSWUsrXdsExdQF2UeXt/D7tII8JQmCpDJkSi3MajaLO
         xtt5wpDh1OwXqqj+r5N6cqDcE/2TZqhDhcAQnMpnCCAS+Nt5D33mKZJsJhKpOsuLvnws
         +HuZ4RQvb35TzsMYtLT6X8D1Pp24NI68AUHJX1dix5DHEV+nlIB1Iv9/qhuau2fz3DCP
         /UYdkJFkumtwttrLk8MPgUnyqdZmsTX0gfRzfEyC6b2Qffz80CEJx5+yAF2X8HI2/JhQ
         DYVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ry3yF5S5;
       spf=pass (google.com: domain of 3s47gxgukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3s47GXgUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HlbHgBXWIw9oKPlvAGFyp61Kn5AGBo8pMT9g47pMKjs=;
        b=UNo4dcVPXw1zylcep5dBomTHgio12Myy7ji5eftMTZWfyWigWAcwm7OcGQqmmC06Be
         rAtVIoK+wgIlLxpacv/Prkqzq55h2Q4RTULpjnpSrAhKMJo9VLrO2I21xE+zAEZu6tAk
         0/AT35wlt73Kbgw3MbiOR9q0774ZIJ5pS55WpOGc2v4pbtebAp60PpOqWMcsStA1scuw
         0I0s6LNhzvo8U5WGL1lve/xTgbvYXbCm3HmMUHeNts5rQEJ7e93CucMorfORcZJperg/
         27PtCrsXGajyUFd9CD50i7tI/PRwWIH4wRG8FxzOBMFlKm2iAkMRi+eZ4n/BJ4XtUKhN
         fTFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HlbHgBXWIw9oKPlvAGFyp61Kn5AGBo8pMT9g47pMKjs=;
        b=j0ldGfp54QBnjozJpRisNI8qngejPQozL+1WvzeyxoEFRGYFsHN1s4FFCCvDY+ZuuR
         LufWnCrOzOnw7jG65LiGT3t6nxEAdAshTCp9NASBX9TgniQmC3eInXcOVCRXr9xFzBKd
         VqwvOAmq3gWoAW23EAvbJ6JLcZFzwkgsUVrAB556aCjVLBwl4jEsBSj5jLJH8tm+E4hY
         1itAKsedHSqmnnh4MYQbRDQN0/2CJk3WYTSnnADhMg23u4xhk5gnSckh/gXQrq8nj4tD
         zQitUa2X9QF/qm5HVt5TJoMcwYbOWeX+uS/Ax3ZgNASWTlBhsyr0rfOIcJuLgYhgmuks
         KdHQ==
X-Gm-Message-State: AOAM532oUzUhbo6bFy0ApXNLam3KHtB7K3oqxOm2k2rsba4Dh/Hd+8CA
	QCGppbxjII2cEX6cZuq/WqY=
X-Google-Smtp-Source: ABdhPJx7sj0bT1U32pbpSazmpN49m+3+h7dEDt874Erd4dModLQrSs0h1zkAPt+U75zft9LWGjPaiA==
X-Received: by 2002:a17:902:ea8a:: with SMTP id x10mr9929902plb.220.1590070964201;
        Thu, 21 May 2020 07:22:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e283:: with SMTP id d3ls1237305pjz.2.gmail; Thu, 21
 May 2020 07:22:43 -0700 (PDT)
X-Received: by 2002:a17:90a:9f02:: with SMTP id n2mr12235554pjp.173.1590070963794;
        Thu, 21 May 2020 07:22:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590070963; cv=none;
        d=google.com; s=arc-20160816;
        b=QhgNkZdzumDDH5ndX1nyevodibpGHuUSbA8p6OX7lwT7B60d74pdh7lJLnXy7UNnxq
         H9OVVMgD37g6/Po/o7g6Auc4AVe49IBH18smWJZSFbWQm+k9Pw2V68tr10rSIn5zGLeu
         ReuCvCbWIF324Wv574LrdsxFSnlBFT6ykoxlCOPolf4bp8+h4rhlIz9XTcR5Xb7116vK
         F2ozMI9NsZCTMRNMEEO8JBGgfpdHsICFlAJP2+gDIoaNUmHulKTvUpwlQkPPwRXb+TGi
         RnQ7atSZdTfOnvjrDTvwC5sNmFVe+9ckiQ7saF2/xLkPwI0J+0ao9lSDXQltHC2MF6w9
         fJTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Lmm+/+h5qLO6fUy4Is9S48RQHv+8MyPjNoPxJUCaU88=;
        b=BHqb92VTnu3zH4gx6odl9B1NPzGQvsoOaQX7bDua+PcWom5mVFeA04Y/RlwbeTaelt
         Le8AMgA2P+o+5LhTJ8AxbwzOZ88t86QV0Y8H1a+bLSbgFZTZq5flONbtMNUfIvnnqYyh
         tfMaGeCF2b6qhY39lt0C2N1COzT80Q1Q0ztEptcEbSJFTXJdB8mxZgFZ02ltPS/plxAT
         vb3k9nDP7AlIqULhOQ/XjNegs7M517C0cUncadxKzzxypMMTMf2xXRCdJsIRltZ8TPJ3
         8x8N+mQGKxXjNFafuGIe7u92yD8NXt4wY0fQSwjLqvO78BFTQzc2oRahXppCVB1P/bU/
         GOEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ry3yF5S5;
       spf=pass (google.com: domain of 3s47gxgukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3s47GXgUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id r17si402201pgu.4.2020.05.21.07.22.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 07:22:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3s47gxgukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id d7so5448949ybp.12
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 07:22:43 -0700 (PDT)
X-Received: by 2002:a25:77d0:: with SMTP id s199mr14286095ybc.333.1590070963005;
 Thu, 21 May 2020 07:22:43 -0700 (PDT)
Date: Thu, 21 May 2020 16:20:46 +0200
In-Reply-To: <20200521142047.169334-1-elver@google.com>
Message-Id: <20200521142047.169334-11-elver@google.com>
Mime-Version: 1.0
References: <20200521142047.169334-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v3 10/11] compiler.h: Move function attributes to compiler_types.h
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
 header.i=@google.com header.s=20161025 header.b=Ry3yF5S5;       spf=pass
 (google.com: domain of 3s47gxgukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3s47GXgUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

Cleanup and move the KASAN and KCSAN related function attributes to
compiler_types.h, where the rest of the same kind live.

No functional change intended.

Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler.h       | 29 -----------------------------
 include/linux/compiler_types.h | 29 +++++++++++++++++++++++++++++
 2 files changed, 29 insertions(+), 29 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 379a5077e9c6..652aee025c89 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -250,35 +250,6 @@ do {									\
 	__WRITE_ONCE(x, val);						\
 } while (0)
 
-#ifdef CONFIG_KASAN
-/*
- * We can't declare function 'inline' because __no_sanitize_address conflicts
- * with inlining. Attempt to inline it may cause a build failure.
- *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=67368
- * '__maybe_unused' allows us to avoid defined-but-not-used warnings.
- */
-# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
-# define __no_sanitize_or_inline __no_kasan_or_inline
-#else
-# define __no_kasan_or_inline __always_inline
-#endif
-
-#define __no_kcsan __no_sanitize_thread
-#ifdef __SANITIZE_THREAD__
-/*
- * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
- * compilation units where instrumentation is disabled.
- */
-# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
-# define __no_sanitize_or_inline __no_kcsan_or_inline
-#else
-# define __no_kcsan_or_inline __always_inline
-#endif
-
-#ifndef __no_sanitize_or_inline
-#define __no_sanitize_or_inline __always_inline
-#endif
-
 static __no_sanitize_or_inline
 unsigned long __read_once_word_nocheck(const void *addr)
 {
diff --git a/include/linux/compiler_types.h b/include/linux/compiler_types.h
index 6ed0612bc143..b190a12e7089 100644
--- a/include/linux/compiler_types.h
+++ b/include/linux/compiler_types.h
@@ -167,6 +167,35 @@ struct ftrace_likely_data {
  */
 #define noinline_for_stack noinline
 
+#ifdef CONFIG_KASAN
+/*
+ * We can't declare function 'inline' because __no_sanitize_address conflicts
+ * with inlining. Attempt to inline it may cause a build failure.
+ *     https://gcc.gnu.org/bugzilla/show_bug.cgi?id=67368
+ * '__maybe_unused' allows us to avoid defined-but-not-used warnings.
+ */
+# define __no_kasan_or_inline __no_sanitize_address notrace __maybe_unused
+# define __no_sanitize_or_inline __no_kasan_or_inline
+#else
+# define __no_kasan_or_inline __always_inline
+#endif
+
+#define __no_kcsan __no_sanitize_thread
+#ifdef __SANITIZE_THREAD__
+/*
+ * Rely on __SANITIZE_THREAD__ instead of CONFIG_KCSAN, to avoid not inlining in
+ * compilation units where instrumentation is disabled.
+ */
+# define __no_kcsan_or_inline __no_kcsan notrace __maybe_unused
+# define __no_sanitize_or_inline __no_kcsan_or_inline
+#else
+# define __no_kcsan_or_inline __always_inline
+#endif
+
+#ifndef __no_sanitize_or_inline
+#define __no_sanitize_or_inline __always_inline
+#endif
+
 #endif /* __KERNEL__ */
 
 #endif /* __ASSEMBLY__ */
-- 
2.26.2.761.g0e0b3e54be-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521142047.169334-11-elver%40google.com.
