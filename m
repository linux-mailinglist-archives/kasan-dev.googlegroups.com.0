Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFODTH3AKGQEELF7SBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id C60951DCBC7
	for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 13:10:14 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id y22sf3226586oos.12
        for <lists+kasan-dev@lfdr.de>; Thu, 21 May 2020 04:10:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590059413; cv=pass;
        d=google.com; s=arc-20160816;
        b=kRuCZ3fOZsqpK58yx1mUvY6PahOPAWtC/ICqd1bRIOe7CnnX9WPYlNF93KZbeMkmll
         bkQrdCgCUvEN74H0c59goaE09QlYPMw3JX+Ps+PGehS3kxLgwbRTkYMhc0XX/EnRxdst
         thX4RoGm7g8fGH1ZGlPJBldN34bQ7GuyZVB0AiKJ4nGexzgrA0I/YuEe7UBt442BZXz+
         5iAItd1cWl4HxKIa2k5AywX/cSlVOPZb8c9A8kQihbWR0D2jlCU7WkpRq5FpxwfCA4LH
         /SGoQ6TVVfjRnSWhpcxX4DfJRzcVTzbR9V2ZBbpRWiN/z6maZ/GUk/WPmQ/BnLVR1HSS
         Vulg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=8rCZB0LfU/Itc4+fpL8+nLHa2l+Rrq5WR1L5wVfNqu4=;
        b=Paky1+TKCy0I4qMzynZ5ahoiVkqKoaChbISSVff6QCVsyNUNWJLf+oLOtgDvSEhdCA
         0HkEfIOLOeNmhd37gLxcearU+xLcpABJBnN3OpsLzNPi9J9dXqSa6KNKeDu9OUWfrG17
         0ObR1cOUggebT4jIjiPZAbqe1ihxkF9MennHE7kWPnNHAGOuKuqhy7yr3qakYvWwsa4L
         eFRflfC2jyC0nWwiehrzV23bTYjL4oOyiolN8qzj3sIXs46UNbKTpz+6OInR9AYmfHBH
         wQoqTn/KRV/oPuF3+XRxDBhxxHIqTWK5u/HIb3zg9ubhAjA5Mzuk6R8iRBQ3mGzK6EOg
         QTOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mALz/ryu";
       spf=pass (google.com: domain of 3lwhgxgukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3lWHGXgUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8rCZB0LfU/Itc4+fpL8+nLHa2l+Rrq5WR1L5wVfNqu4=;
        b=Oc5lcWXCS+kYqe3yU/vV9FGkDBa1fMR8TYl3eKDB8EK7jD7V5CbBZ8LMWrgZ9G+3IC
         ObtUry+FQkAXKPqQeyW4jb+wPpJzNH2WDPPQfLJ4v3WdCGqtzjlUeGWz1cUEy0F2w4+9
         1k2GIdng6vk/eOttreuEesOUkBf3GQdmrJ/6zF8A8/HggiuSrwQ2dthOx3+Hh+v0N0j2
         s9hudd+RQF6ha7lU8mmmSkYzei0IGVwnt++As4XF8iQxJgBiYuHd3IJqnx7UlemH/Wc8
         sWEEs1b7SEQfCIQNPLSzGLFKl/XNahcWw+9sPBI8+V211x+p33FsZ8UKTYwrErAnJvke
         7fYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8rCZB0LfU/Itc4+fpL8+nLHa2l+Rrq5WR1L5wVfNqu4=;
        b=hl5dua/tuyxPeGIfZmTQrWschQnkLmK/MZ9sNOfuyISIE712eg0rW4I91hijzScGHO
         F+qEuP3ga2VYWF+x77H2cH6pdydPcvP1c2j1C7QA/qCjVoiFAE0sroT9qlctOvhXolri
         zl8th6yaWlFtvmjj+otz5N9VLgUkO97nUlVjk6YoEYmiKz1i6OYOf/6xgNX6uwcY5/7Y
         5/l2xBZuGj5HMlEeSybjAC78Y6BTX9uLbmqE4hH4NxLtb+9PlPkqCU/VQ6t5/kf6J4RJ
         TFdqcxJUmIvtFWEBJE0hOb4aumJlRyS9wXyKTTmSUdYNE1ZZlJIGsDWA4MAhzndDSxOK
         136g==
X-Gm-Message-State: AOAM530N3A1vWP2sMD6eJpQcTBwT40/zzWz4Z2h6zDBjJAhS0A4BcncI
	xFI/WgKz37LHCW7dvGn+eYE=
X-Google-Smtp-Source: ABdhPJzcCHzQGm9Ji4k6kqeQGZoT9Ry7ev9svFFEzzLmV0DQUAhK+w11F/lmLS8XloYJ5D/Np+8W5g==
X-Received: by 2002:aca:5b0b:: with SMTP id p11mr6426625oib.82.1590059413787;
        Thu, 21 May 2020 04:10:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7d11:: with SMTP id v17ls388638otn.2.gmail; Thu, 21 May
 2020 04:10:13 -0700 (PDT)
X-Received: by 2002:a05:6830:20d7:: with SMTP id z23mr6876770otq.153.1590059413401;
        Thu, 21 May 2020 04:10:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590059413; cv=none;
        d=google.com; s=arc-20160816;
        b=LZMIsMHkKFeN+Qn1q25l8i/djLQ801yfavkXXkGwwbh9W69fDqnh4wNKCJHLavxkXK
         5xgbmPeRS2T90AuCXoTekpsEejaot4pdjnXNfbQTE7kgsEBwwj5TO1yRg2t6+AVpZXd0
         64C1dcVIX/DCtloyNzo0L6BIRbLdHmbNJlPYZLe/OJRda7SoeUMNDLmp7XLy+AdmHhSE
         C1C79CD8vx4oc2AWNwM8xVTGvX9K92rrLjM/yYetI0i4rSt+Yqqzf/AZLHi3FZEegjzZ
         Qdk1ODeMfyUGdEG2qziAgvTe6BJ/87F8g5FYXK0dUbVYqUhq+i5kXWgy+cfz7DZcHvMm
         dfzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=SvajioAcxE9ANa2I2vNqdu1VYDhOobctmex3U6Yh/nk=;
        b=Hq0zDeXsxsqE+5ef05/x8wPazMqg/8TQfguu33ZsCLh5iWojQ5Z7EcX0bOVOpNl/2r
         nuWwSFJGkXcKfr564D/hnrlJGEyujEoz0B/4rRP+6RxZ51gvQFngjAVIcMSK6lS+ChhK
         /g+IaYmj41rDAllcM+jvqiw9G7r4iOBTSHqNXhtvLRGhCNQitBfo0L6fdWILNSPq0XOc
         yYpb5x8II4NM1PqO1emK8Xyb3MftDt83EBFU2h7eH5DgaVgdSGlscmpi+lZze7wZ2a1e
         kttskDkhBTXnvv0t0+5BzqH4YvwaiZOusAvzRGVgVg3AsKNvOyj3Ie8vUDyxN6AfYGow
         H8KA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mALz/ryu";
       spf=pass (google.com: domain of 3lwhgxgukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3lWHGXgUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id e20si416409oie.4.2020.05.21.04.10.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 May 2020 04:10:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lwhgxgukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id k15so4933064ybt.4
        for <kasan-dev@googlegroups.com>; Thu, 21 May 2020 04:10:13 -0700 (PDT)
X-Received: by 2002:a25:f20f:: with SMTP id i15mr14499554ybe.72.1590059413041;
 Thu, 21 May 2020 04:10:13 -0700 (PDT)
Date: Thu, 21 May 2020 13:08:53 +0200
In-Reply-To: <20200521110854.114437-1-elver@google.com>
Message-Id: <20200521110854.114437-11-elver@google.com>
Mime-Version: 1.0
References: <20200521110854.114437-1-elver@google.com>
X-Mailer: git-send-email 2.26.2.761.g0e0b3e54be-goog
Subject: [PATCH -tip v2 10/11] compiler.h: Move function attributes to compiler_types.h
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
 header.i=@google.com header.s=20161025 header.b="mALz/ryu";       spf=pass
 (google.com: domain of 3lwhgxgukcw4qxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3lWHGXgUKCW4QXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/compiler.h       | 29 -----------------------------
 include/linux/compiler_types.h | 29 +++++++++++++++++++++++++++++
 2 files changed, 29 insertions(+), 29 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index 1f9bd9f35368..8d3d03f9d562 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -249,35 +249,6 @@ do {									\
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200521110854.114437-11-elver%40google.com.
