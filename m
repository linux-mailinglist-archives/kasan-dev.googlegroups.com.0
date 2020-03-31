Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEFWR32AKGQEZZTS2SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E0BA199F28
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 21:33:36 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id u16sf10434967wrp.14
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 12:33:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585683216; cv=pass;
        d=google.com; s=arc-20160816;
        b=HWerXOp5DUU8GQf0QGwD6XSy01z9B6V9NqVyeSrCv4jMMZx/I0nlq+LokPS6yGgZzz
         dW0qQmIXYwLdh7Wj+MDfa4sVNHz5QK8/qgPoO/ir+XcNOtWrj8j5jRZ+6UgjuM//O2qq
         SrCiKhe35QkfyAG7XW03aDdjcsqH3WmXq9Q8RDfkAAGiqvJRs9UcJdOK4JyCqntGIf0W
         YW5z2S1zY/vVVI+l3FlCpOpYd78pIPIn6u31GvPQvTPQ6L4xZxUWiIKDyqjpoU+SWt8f
         q+/3yHQDe4+eEKi+ondPKiUlQyWNn/5KjbsNyqC+YKL/i7bI6iSJvrwa2YTwGCoDVVTf
         mSXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=wr/VrP0qXc8eSIbPeA/q1u890lYwMkULK6QJ1f+n5nI=;
        b=F6uqPXoEFKyvMZVQIPoEzg5uy4Gbxp6lHhnMGElAoUKEafd/oKXTrDhJthLEgVDmqg
         yKxDpKqLgFldxaTtlpDySS3NJgjYAVyW0qb+0dhsoXYRwF4VENospNIBMfwtT3H7FW/j
         0NBd/qgj89FdUxzibvErHECigU+/NwtW3TXNHmmQ7/DEdKfIgq22/CG2hBBnwKtcQOxX
         8NOUiR9WWV0uTcH9dmeU7rU2dvw0y5vPIETOtfV8kEKZ9vXJz8IbZDB8kqiDu3KyWvxi
         xBBxDOwZToH5PtAQvEsHh1G5rsr1iMO2OHNihqHhkhtnQOAAlGoMRTjtrHUQB2mLJ0Ct
         m3Aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=niJrPhDL;
       spf=pass (google.com: domain of 3d5udxgukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3D5uDXgUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=wr/VrP0qXc8eSIbPeA/q1u890lYwMkULK6QJ1f+n5nI=;
        b=B9wXRUefVmGDPlgxHXtmAKWqD36v7gsrTc9Ph9DiPDL1Q5w8RFsTSFLcqH8oA11/7/
         3+yWCXuR5foG1dcI8DlQ4adcugvyPnYZp9hw+HOUuOeRRlHB0H9KgOTgLpticdQ354Nu
         IVQdgO9mFDtbki6U2rfdD8FJVkGVCSSmW9pNmBNej29YEH8OolZED2Z4z7JEdPBru8m8
         In7iPk+OaI5ceNAgc3V2DN9K/6uz86ItuXn0bZGLrP2I+1K8e1q21kjq/IUeXeLtLWHS
         lErj/zoJzg069moOQnzyJ9dIh6s2MPpTyu/oMZ0U9FwduQJjE7BBeHmZbGE2YXfC5iMl
         VLeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wr/VrP0qXc8eSIbPeA/q1u890lYwMkULK6QJ1f+n5nI=;
        b=PeCoCrEkItFfulIm52MenbJ4We7De2DIlpuY8PHnFwKYdZrvJKBsg51XYIhBzH61Om
         NRrSIlCd1nDTK1sNfnvaL2Y82FQAXPHlS6Qjr3QUnzAdfH3m6jjY6w2J46HCxrh6SiAk
         aKqYuDBwcZJ27Bd8xf3pK9YGpNjfWnf697dhde6uB3cfbVQtaYQQQW436qofp117mxfy
         dbGJsnEIPnqPZMj8QTU/b7Qdnas95UnQvA1KVNZYEgt96QPpnL7tkxNnBULjRD3wHWbl
         GDCo7NqTSBOUH5q05I3aPSCawFTf7QOalbE2Sz8YxArK3U9H3xV1/T4VOz+Hzl9OlRLh
         jsdg==
X-Gm-Message-State: ANhLgQ3WeFsGkECM5IXgER/k1zHyt/95Tg6f5aFPLg2FUnM3UXqBDZUA
	8D4NG2vsdWLV+BnW116g4O4=
X-Google-Smtp-Source: ADFU+vvlzZW7lcrvZ//DWTte1h6wmLjVyVMCVR1YeJGBUJdeOHg0JUjkFKwsVhr38zktak7QxWVyOg==
X-Received: by 2002:a5d:404a:: with SMTP id w10mr22011542wrp.295.1585683216262;
        Tue, 31 Mar 2020 12:33:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f5cc:: with SMTP id k12ls2264668wrp.6.gmail; Tue, 31 Mar
 2020 12:33:35 -0700 (PDT)
X-Received: by 2002:a5d:6906:: with SMTP id t6mr17716606wru.64.1585683215646;
        Tue, 31 Mar 2020 12:33:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585683215; cv=none;
        d=google.com; s=arc-20160816;
        b=WSEqNNWumeIhGE1MAiA/pcetM7VCn1HuXp54QwWl+VyriCHsvJZmMBFWZy9TmCphZs
         Q51ryeOako2f5fymsHOiB65O5bWl7ybQfBg+G0t/73MxRyzk2+r165/eVmG83Vg4Se6N
         dZSiJXVSv+g+XCBmzAANGVhUIPKaIkp+bZW+iWuT/1LGO9j0258Jg2Ub6WN26jvlY3uw
         fWySImtAi6ZaaOz0jvtNpSPHptG1LmA5IqkOvHQvNdnsxJGsB5jPDbK7/V1H3vDa8cNj
         /gHukfHtth5M2zdKjkv2Lhz6l8f4pYIR/EgJe53M/tQCnl9yTS2p6MO6GnZGhGK1sOjo
         zrzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=qbfJ5ZHXD/KzKrN959jG51gO6gDSc8KmiwmuYQdIsZ8=;
        b=SyZ9saxneb2KOyqhozztU02SNjlfXeXjYC+4btnxXvJNvdweRuV64ddc79TeXA7Xfv
         q0tTaVRoqM8CCWjN8CumNa011gv2rmmv5pOtOGcZgMF1+eIt6Nt0qxcKcOI6AI/hOA9F
         HWHPfHPtBwAe8ApU9xL7++wgtdPQRo4bjMv8nb9c8qnquXMGzsmSMcgrZSKxFSoB5fsL
         zqMOoMxNw01dV93QhCnCI1IZczI77lBQMX1UM0PR51ZMoVq+nNt8R4bktsc/uLUQOQcA
         epp02Gt7D/uabRHjwPfY9LUD81/ClF3tNULHDmwhz1z8nsWERXTI+pwvKcc+s6xC+NQE
         V7Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=niJrPhDL;
       spf=pass (google.com: domain of 3d5udxgukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3D5uDXgUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l8si936657wrr.1.2020.03.31.12.33.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Mar 2020 12:33:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3d5udxgukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id o5so1467045wmo.6
        for <kasan-dev@googlegroups.com>; Tue, 31 Mar 2020 12:33:35 -0700 (PDT)
X-Received: by 2002:adf:f401:: with SMTP id g1mr21276581wro.140.1585683215086;
 Tue, 31 Mar 2020 12:33:35 -0700 (PDT)
Date: Tue, 31 Mar 2020 21:32:32 +0200
Message-Id: <20200331193233.15180-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.0.rc2.310.g2932bb562d-goog
Subject: [PATCH 1/2] kcsan: Move kcsan_{disable,enable}_current() to kcsan-checks.h
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=niJrPhDL;       spf=pass
 (google.com: domain of 3d5udxgukcu4u1bu7w44w1u.s420q8q3-tubw44w1uw74a58.s42@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3D5uDXgUKCU4u1Bu7w44w1u.s420q8q3-tuBw44w1uw74A58.s42@flex--elver.bounces.google.com;
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

Both affect access checks, and should therefore be in kcsan-checks.h.
This is in preparation to use these in compiler.h.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h | 16 ++++++++++++++++
 include/linux/kcsan.h        | 16 ----------------
 2 files changed, 16 insertions(+), 16 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 101df7f46d89..ef95ddc49182 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -36,6 +36,20 @@
  */
 void __kcsan_check_access(const volatile void *ptr, size_t size, int type);
 
+/**
+ * kcsan_disable_current - disable KCSAN for the current context
+ *
+ * Supports nesting.
+ */
+void kcsan_disable_current(void);
+
+/**
+ * kcsan_enable_current - re-enable KCSAN for the current context
+ *
+ * Supports nesting.
+ */
+void kcsan_enable_current(void);
+
 /**
  * kcsan_nestable_atomic_begin - begin nestable atomic region
  *
@@ -133,6 +147,8 @@ void kcsan_end_scoped_access(struct kcsan_scoped_access *sa);
 static inline void __kcsan_check_access(const volatile void *ptr, size_t size,
 					int type) { }
 
+static inline void kcsan_disable_current(void)		{ }
+static inline void kcsan_enable_current(void)		{ }
 static inline void kcsan_nestable_atomic_begin(void)	{ }
 static inline void kcsan_nestable_atomic_end(void)	{ }
 static inline void kcsan_flat_atomic_begin(void)	{ }
diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index 17ae59e4b685..53340d8789f9 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -50,25 +50,9 @@ struct kcsan_ctx {
  */
 void kcsan_init(void);
 
-/**
- * kcsan_disable_current - disable KCSAN for the current context
- *
- * Supports nesting.
- */
-void kcsan_disable_current(void);
-
-/**
- * kcsan_enable_current - re-enable KCSAN for the current context
- *
- * Supports nesting.
- */
-void kcsan_enable_current(void);
-
 #else /* CONFIG_KCSAN */
 
 static inline void kcsan_init(void)			{ }
-static inline void kcsan_disable_current(void)		{ }
-static inline void kcsan_enable_current(void)		{ }
 
 #endif /* CONFIG_KCSAN */
 
-- 
2.26.0.rc2.310.g2932bb562d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200331193233.15180-1-elver%40google.com.
