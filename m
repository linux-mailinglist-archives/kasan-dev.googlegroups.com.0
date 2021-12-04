Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH6MVWGQMGQECSJAAVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id DC87E4684E7
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Dec 2021 13:59:11 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id s16-20020a2ea710000000b0021b674e9347sf2221341lje.8
        for <lists+kasan-dev@lfdr.de>; Sat, 04 Dec 2021 04:59:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638622751; cv=pass;
        d=google.com; s=arc-20160816;
        b=WWVfqDZvep/xWnZ1Ruium8wk88OEgY5Ht2mSQUqn+CGNM2eWhSP8CGXczDZ2QslHAo
         SgxkLt9uHK9IDGzLG9Co4ezzRZPdZKXtFDahgUp10bY5RFyU1hzNBKskWtWtJIs3gfV+
         S/DCGZtm0Hzu+9DQcFrW+otNy66zlCxctGj1/TwV39xnQKE+L7iPqMPxdqh3io2xpyfV
         kaxozsYFqf2gjygrZOqR3FlE3n4kL11HPqiyVGCeHJ/2AEc887GvsWdWwsIazarr+dCP
         +oodphydxEtgTMesi4oHEpZML6LkBzmfzXvyeu61nGp4kjNRPOsZQbeRIPiplAf5NsYm
         w6dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=zQ3rt01aHGpTVaU8+G3sSmOL39apZj2sdh8xJq398U8=;
        b=DlER3P7qZl8FyAwrzZkGLjMFaGvNgasIdLZMC+GIGYrBQnotgwDyYp3cqY5kkteRwE
         KE3f46uwGiUeXWfum9kvDOUzkKbIozO734332e/krU7Jx8CKQGxc4tljrXMQKUvzFkdV
         CdNrh/39TDc02xbSvrPs0y987q6IMUKIUaYibn2Qk5+2IsvlGxwIDUP34YUP5BUvy5k+
         zh87vuwgUCcZwHzKZ8IWyyKfaY9aMbvJ4YZE4KzYYpC0QbCrF5qEyXC8mqvh7paARQKo
         2f33tcgs5w88h3KiaXSH2PHWsLGXHfbnfbJL6nlCtGs20aw2Ra/Tvp+U2uS/3VKrF0NA
         kmCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jdNd5btK;
       spf=pass (google.com: domain of 3hwaryqukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HWarYQUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=zQ3rt01aHGpTVaU8+G3sSmOL39apZj2sdh8xJq398U8=;
        b=FmWyHvTrYTMUoFQ5sOK5gCp8j5hYq51LIskIgoEODZ9M9WKTna9orgNk+Cf6N7qEMk
         NeH/7Cawyr90UMUXeem+4lXYClzcRYhFns6waMaA5cLRDKjENkuRiuSWYAOGYwqqLjrv
         8Py9WoMsLSN/ilbdjwxvOzlAe0zTzm2TOzfpRmQMjEgu3ZHWPNyl294JLWKLKkx1uSy+
         SHtL/Zt1XM/hOSufHYRnUJrQXe4a7gr7OWCD+tJhZqJiU12Jo0hb/DtQXN7Wc3LY2IYI
         JtHbsWZRVcEydAgRXpSiJXiqnuvsVcuWVVWA98WVNKJVQqKp6DJbXiPiKPb8Hy69sM76
         LXsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zQ3rt01aHGpTVaU8+G3sSmOL39apZj2sdh8xJq398U8=;
        b=TGl1ER84bUG0GXnLhiVSpfNg8F+vCr9RDzS/4wERt8SSJ3O5MozWbHyHc370bezNMJ
         aP/E4JSOX3WFdCvd2o5tEsn2NCBCi14L0eF65HRlhUL+Cvs9pLzZZqfueDP5cj+drV0P
         0nQGm917L3jll19KDIlubMcWQLyNb/7upZ133GnaE9pRr+X+RjEOX77dosX9zsHphOwf
         4PD4zwCPrqYzP0dhe/9HPH7qeL0te1k4/IINxvfJ/vKYvSa+xrBPk+joa+Kg2lV+Y/Iv
         bXl2QeP3m5q0WcEpiV/eSvntA9APWDODEso+xBRRrXkvMuyDCCH1EbCcmVkpyxMnsKr5
         HkCw==
X-Gm-Message-State: AOAM530mfYjvwDpL5U0EGQdE1wr0zL5DpjmKD1P8rjboCNSINyh91JYA
	jThk/YSLxvAJigw3VmxR4kE=
X-Google-Smtp-Source: ABdhPJxhbh6/R9TFI+SgA3loAW497DZTPq+FYN3uy/eCfP6uBprG9B8yF0qo50HMU2EeDsDyU9uX7A==
X-Received: by 2002:a05:6512:3a5:: with SMTP id v5mr23546792lfp.250.1638622751410;
        Sat, 04 Dec 2021 04:59:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d9e:: with SMTP id k30ls1644301lfv.1.gmail; Sat,
 04 Dec 2021 04:59:10 -0800 (PST)
X-Received: by 2002:a05:6512:3117:: with SMTP id n23mr23968899lfb.16.1638622750330;
        Sat, 04 Dec 2021 04:59:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638622750; cv=none;
        d=google.com; s=arc-20160816;
        b=qgh2++MOJA7/uTCOW1vxsSJjOZ6WvZzBPMjtS62vyt2SVzCHm+8Udk1GRE0zD+1prz
         YHse1X3p394B+cJvumfjYXNCbFPM1GrzjeRG5ln5ry4s93qAzoKpdPnso4rqTU9e7Z8c
         mL6bYNGD1NL26A1AjGy4XCOA1egRTxGpU214QHaYxBEH+j/IYsovf4eCBd7n5/JBk9Rg
         YXwnu8SYM6kwFkfKsOJ5B4Fcm9LcUUFpjmVsegCxRQ+knMy11e8MydKSJnBN9vr+j8gk
         B70CVXAW/Zfwys+VeAwqs8rEwlJdqrZqQyt1dQ7tVLSPfU03asdaKLsYZzi+1W1txbk2
         2Z2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Ft3q1xFQfL2Ok2lDpTOpcXH+pvRUd7lyPKHQkecVzno=;
        b=moCGrGeWKLKR0SZWFT2aBCUGr14nsiIoInKhxqIaIcaKXNf6jUxW9poBumZGYzKjxq
         KpBof6RUei0RXCC1v0oIyKnm1SqiKH4Xc0Qo+Qxu2wQZ3hXi7WTvwzrr4S7BfzdLMr5M
         vDHPWsD+czDU3hC3DTDbOzgWhBrEEtm9/e/wM6x32xNrTlABJjdvHgGYcuy5O4HqShLr
         UFUcRivL2vOEHwdWWlER2HYuB/JnHKgbobjpFrlVxJlH9CT+zPu3egLZQ9HtExelYWMr
         FRl0xlbL4y0pTmG0jKDQSOsnQQweeCT/qMH+LwpD5sa27q3p7KUyNRYBfUMfGxPNw/mE
         SU4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=jdNd5btK;
       spf=pass (google.com: domain of 3hwaryqukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HWarYQUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id d8si347359lfv.13.2021.12.04.04.59.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 04 Dec 2021 04:59:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hwaryqukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id ay34-20020a05600c1e2200b00337fd217772so2561485wmb.4
        for <kasan-dev@googlegroups.com>; Sat, 04 Dec 2021 04:59:10 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:565a:3964:11db:fb41])
 (user=elver job=sendgmr) by 2002:a5d:6101:: with SMTP id v1mr29662764wrt.598.1638622749825;
 Sat, 04 Dec 2021 04:59:09 -0800 (PST)
Date: Sat,  4 Dec 2021 13:57:03 +0100
Message-Id: <20211204125703.3344454-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.34.1.400.ga245620fadb-goog
Subject: [PATCH -rcu] kcsan: Turn barrier instrumentation into macros
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=jdNd5btK;       spf=pass
 (google.com: domain of 3hwaryqukcaoovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3HWarYQUKCaoOVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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

Some architectures use barriers in 'extern inline' functions, from which
we should not refer to static inline functions.

For example, building Alpha with gcc and W=1 shows:

./include/asm-generic/barrier.h:70:30: warning: 'kcsan_rmb' is static but used in inline function 'pmd_offset' which is not static
   70 | #define smp_rmb()       do { kcsan_rmb(); __smp_rmb(); } while (0)
      |                              ^~~~~~~~~
./arch/alpha/include/asm/pgtable.h:293:9: note: in expansion of macro 'smp_rmb'
  293 |         smp_rmb(); /* see above */
      |         ^~~~~~~

Which seems to warn about 6.7.4#3 of the C standard:
  "An inline definition of a function with external linkage shall not
   contain a definition of a modifiable object with static or thread
   storage duration, and shall not contain a reference to an identifier
   with internal linkage."

Fix it by turning barrier instrumentation into macros, which matches
definitions in <asm/barrier.h>.

Perhaps we can revert this change in future, when there are no more
'extern inline' users left.

Link: https://lkml.kernel.org/r/202112041334.X44uWZXf-lkp@intel.com
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h | 24 +++++++++++++-----------
 1 file changed, 13 insertions(+), 11 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 9d2c869167f2..92f3843d9ebb 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -241,28 +241,30 @@ static inline void __kcsan_disable_current(void) { }
  * disabled with the __no_kcsan function attribute.
  *
  * Also see definition of __tsan_atomic_signal_fence() in kernel/kcsan/core.c.
+ *
+ * These are all macros, like <asm/barrier.h>, since some architectures use them
+ * in non-static inline functions.
  */
 #define __KCSAN_BARRIER_TO_SIGNAL_FENCE(name)					\
-	static __always_inline void kcsan_##name(void)				\
-	{									\
+	do {									\
 		barrier();							\
 		__atomic_signal_fence(__KCSAN_BARRIER_TO_SIGNAL_FENCE_##name);	\
 		barrier();							\
-	}
-__KCSAN_BARRIER_TO_SIGNAL_FENCE(mb)
-__KCSAN_BARRIER_TO_SIGNAL_FENCE(wmb)
-__KCSAN_BARRIER_TO_SIGNAL_FENCE(rmb)
-__KCSAN_BARRIER_TO_SIGNAL_FENCE(release)
+	} while (0)
+#define kcsan_mb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(mb)
+#define kcsan_wmb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(wmb)
+#define kcsan_rmb()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(rmb)
+#define kcsan_release()	__KCSAN_BARRIER_TO_SIGNAL_FENCE(release)
 #elif defined(CONFIG_KCSAN_WEAK_MEMORY) && defined(__KCSAN_INSTRUMENT_BARRIERS__)
 #define kcsan_mb	__kcsan_mb
 #define kcsan_wmb	__kcsan_wmb
 #define kcsan_rmb	__kcsan_rmb
 #define kcsan_release	__kcsan_release
 #else /* CONFIG_KCSAN_WEAK_MEMORY && ... */
-static inline void kcsan_mb(void)		{ }
-static inline void kcsan_wmb(void)		{ }
-static inline void kcsan_rmb(void)		{ }
-static inline void kcsan_release(void)		{ }
+#define kcsan_mb()	do { } while (0)
+#define kcsan_wmb()	do { } while (0)
+#define kcsan_rmb()	do { } while (0)
+#define kcsan_release()	do { } while (0)
 #endif /* CONFIG_KCSAN_WEAK_MEMORY && ... */
 
 /**
-- 
2.34.1.400.ga245620fadb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211204125703.3344454-1-elver%40google.com.
