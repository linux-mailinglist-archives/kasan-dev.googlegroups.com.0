Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF7M6DYQKGQEMU6ZGXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id EDB8D154881
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2020 16:51:51 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id b202sf197897wmb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2020 07:51:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581004311; cv=pass;
        d=google.com; s=arc-20160816;
        b=hPZ8kAEw9sjm3uyF4+TsYG0kKwMijgDl4ayRSzYM0R/sswxnJy7lGvmYD4d3VqadJx
         1Ul4P+tB5WADqByH4qguy1y8j0ylf0lOmj+gGBZu8G6dXGJwSCJpO/eFbreBPsQFQXMr
         2iXZN7LesUp+hVw+mVGpo4nqNlbjBMA01Yz3iD51hT0B86f/ukOEwX/mV2CbhcBAlmGq
         njYck20xl7qRVPVcsjeqnA+BsN6qtZYEjVcbc8NKDRYMZ2aaWnfJYYwPsZsm7tnzgfg8
         bIJC8gcFMmJbCf3WaSiWttveqI1tU/A6DpH2Aa67ZWKSYA73LHNwUuk8UVGgd5gWIScS
         q+sA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=iaZ+HZsdS6+tDy6GkAE7QQPAT4UnoEMRmuXDddmJsoY=;
        b=kqujsmIi1GQ5UU1pTKogDIPzki4Uf3VQD2z20W7+hhi62ZtPeIBh2KgN+TMHhgidxc
         hCEYr96eL+yW+WOrbUMTJi2QEEXID+m4EIG4ayg4K6uXli6qnh+EBhBbB3VgZnQSyXkb
         03KPodECykXnY07idgkdFY+GO3vDA9aACINtV6FhWWZ8TWYP9SdwdNQU08WryPYcMnpu
         rCsvHgisLs3AFiuL5OY4SM2uN2FwtEXT9s+TrnroVs4ccoGZXxCJ5meN4ijSz5TlWOs2
         8zasv/Y9RawuqboCSREmCPFvEA67QaxmQU1Z4HkUuhB02d8CtorizsXRc934rGEjZ6Lz
         3p4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KNc7TEIw;
       spf=pass (google.com: domain of 3fjy8xgukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FjY8XgUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iaZ+HZsdS6+tDy6GkAE7QQPAT4UnoEMRmuXDddmJsoY=;
        b=kovhgbEICpa1A59j70LT7fixUQRRKEdu2K/bTC3QNJE8jPtU6lWUTa9WeCqVJ3GIHY
         +76KIoxVf/fcGllLukTz8ALDQS3m0AuFJI3jsKqLNnxkOf+lSVUKbLqVqW4SyC6IrBYh
         rZ90Iz4/nfvrMYTeIZqdXUjl24HlcuAyt4SYkHJDYId4G+2Iu2nasHLbXhvruBMCzw9v
         7BF44KJ9HIxNw8OKJzIXTZICmVAntXfPJ70BFBBdHGI8hVaJQkyHOCzswXKiFB912fbj
         dXxwc5APTwbNidoii82/Jnq4vB3y97GRGO0wz769SD6afIC2lJKoqgksBdTdvAM1CASx
         U81w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iaZ+HZsdS6+tDy6GkAE7QQPAT4UnoEMRmuXDddmJsoY=;
        b=BKP/BeRrA9TAd5qP7pwFU7tif9GIMx5btuxnlvLHKIPJ/IB2o7vcYiyn3KNbkKpDYH
         sjhbHjn9quNZ0ARjDf5zxEtHz8VrczFbzZopUraYfbjug4COYRR92IK5Vmkki1UagHko
         k1fqEeEpzPO5vhbbUla4Mu8qk8JOrbey/cZz1kwNWIQKP3RtV8p9CO8Qx/7SMEEt1Xl2
         NH2YtwdLktJ2tHulMbbrBPffOemef5lwBMJG/e/c8u55KRh5If47Loxp7Y2f6mCUQqVQ
         DQlUhW04Aq84gZZ3yFn9JwlfUGLPNtIzS9hxyiWXrfnKcslQv+bs/WTxQ2P3RIGHBOnj
         fTJA==
X-Gm-Message-State: APjAAAWZCVw03E3CdWVyxB/8iyrYE+nz+e+q5bqTn0rXvrMb7bFBcS3N
	7LPBfTIfqp/6vIEVv+wruHM=
X-Google-Smtp-Source: APXvYqyl6UzodqAeZUTQheKRuPCiqLvOSnAuII9vTOqte2Y3rg1LZYYkRRRoHHT1es6xnZs21jmicQ==
X-Received: by 2002:adf:cd03:: with SMTP id w3mr4535602wrm.191.1581004311692;
        Thu, 06 Feb 2020 07:51:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:82aa:: with SMTP id 39ls4089238wrc.3.gmail; Thu, 06 Feb
 2020 07:51:51 -0800 (PST)
X-Received: by 2002:a5d:494b:: with SMTP id r11mr4407957wrs.184.1581004310995;
        Thu, 06 Feb 2020 07:51:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581004310; cv=none;
        d=google.com; s=arc-20160816;
        b=jFNoTLL84D9XeN03vbGY0Hs+N5Uhak/RZnTg50ZeaTkIfmAmZm8rqITnc3L3CxE+C+
         FYHIgJ+qiyEzwFgNNvTcEWOoy3dE7dC/1JHwWWmeyBNLmergf/EgTv+mg7dKCA4fkgFz
         nzBt2PHploVXwLPYFWwrEhSJBIXQ3GqnvXQcjwKZnfaWbbzpOh4ZflIPmAhWLN4+pnMX
         CHwHAidNvLjg3+pKA2up8Bx2pDR3Mwux+y8R9/wq0euBR/0lHM1394O2IXDQRgkFr8C5
         HS1IGrqeoGGFslV5SmzSxqXiUtyFdyLQF8YfqVX4qlo2Nlg4mfp64JzMILskEcHaelpC
         Sz8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9ivMm6BzzOGZymLSvHhw6OFUtFZ37ARIsWSjvoe/3Wc=;
        b=NinQEUpvxxFsUPpqx3/mKxkIyKElHdhXJTvktzIf23SvGKlRLtoB7dO4GGV22jxGtc
         Zd8hVIfnGi+Q9Lqnn3toGgRKAaAICRXlzSrPgZsZYVUJQiSfdCzb6sRjzlhZtgVoeKJu
         vR75UK/tkQDsayOQSMXN0keePiGJOsu+kZvT9qhrrHRzb6kKHESgDJ5V2hsDRktEYEh8
         mCaRwsp+bArIGqQGrst7cohuLajapf1I4TK3ZSDAri59cIyWR1vsovZD6FTHjHJmR8TL
         lU0a/czSWaNFyXACWb7ztRuAODItYp0WIL7u7ZKWcROYdmuy4yWy0q3FTWSPfIkVxtlr
         2ktQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KNc7TEIw;
       spf=pass (google.com: domain of 3fjy8xgukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FjY8XgUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id p16si125476wre.4.2020.02.06.07.51.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2020 07:51:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3fjy8xgukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id u18so3604250wrn.11
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2020 07:51:50 -0800 (PST)
X-Received: by 2002:adf:f302:: with SMTP id i2mr4427613wro.21.1581004310493;
 Thu, 06 Feb 2020 07:51:50 -0800 (PST)
Date: Thu,  6 Feb 2020 16:46:25 +0100
In-Reply-To: <20200206154626.243230-1-elver@google.com>
Message-Id: <20200206154626.243230-2-elver@google.com>
Mime-Version: 1.0
References: <20200206154626.243230-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH v2 2/3] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KNc7TEIw;       spf=pass
 (google.com: domain of 3fjy8xgukcwsnuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3FjY8XgUKCWsNUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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

Introduces ASSERT_EXCLUSIVE_WRITER and ASSERT_EXCLUSIVE_ACCESS, which
may be used to assert properties of synchronization logic, where
violation cannot be detected as a normal data race.

Examples of the reports that may be generated:

    ==================================================================
    BUG: KCSAN: assert: race in test_thread / test_thread

    write to 0xffffffffab3d1540 of 8 bytes by task 466 on cpu 2:
     test_thread+0x8d/0x111
     debugfs_write.cold+0x32/0x44
     ...

    assert no writes to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
     test_thread+0xa3/0x111
     debugfs_write.cold+0x32/0x44
     ...
    ==================================================================

    ==================================================================
    BUG: KCSAN: assert: race in test_thread / test_thread

    assert no accesses to 0xffffffffab3d1540 of 8 bytes by task 465 on cpu 1:
     test_thread+0xb9/0x111
     debugfs_write.cold+0x32/0x44
     ...

    read to 0xffffffffab3d1540 of 8 bytes by task 464 on cpu 0:
     test_thread+0x77/0x111
     debugfs_write.cold+0x32/0x44
     ...
    ==================================================================

Signed-off-by: Marco Elver <elver@google.com>
Suggested-by: Paul E. McKenney <paulmck@kernel.org>
---
v2:
* Update ASSERT_EXCLUSIVE_ACCESS() example.
---
 include/linux/kcsan-checks.h | 40 ++++++++++++++++++++++++++++++++++++
 1 file changed, 40 insertions(+)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 5dcadc221026e..cf6961794e9a1 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -96,4 +96,44 @@ static inline void kcsan_check_access(const volatile void *ptr, size_t size,
 	kcsan_check_access(ptr, size, KCSAN_ACCESS_ATOMIC | KCSAN_ACCESS_WRITE)
 #endif
 
+/**
+ * ASSERT_EXCLUSIVE_WRITER - assert no other threads are writing @var
+ *
+ * Assert that there are no other threads writing @var; other readers are
+ * allowed. This assertion can be used to specify properties of concurrent code,
+ * where violation cannot be detected as a normal data race.
+ *
+ * For example, if a per-CPU variable is only meant to be written by a single
+ * CPU, but may be read from other CPUs; in this case, reads and writes must be
+ * marked properly, however, if an off-CPU WRITE_ONCE() races with the owning
+ * CPU's WRITE_ONCE(), would not constitute a data race but could be a harmful
+ * race condition. Using this macro allows specifying this property in the code
+ * and catch such bugs.
+ *
+ * @var variable to assert on
+ */
+#define ASSERT_EXCLUSIVE_WRITER(var)                                           \
+	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_ASSERT)
+
+/**
+ * ASSERT_EXCLUSIVE_ACCESS - assert no other threads are accessing @var
+ *
+ * Assert that no other thread is accessing @var (no readers nor writers). This
+ * assertion can be used to specify properties of concurrent code, where
+ * violation cannot be detected as a normal data race.
+ *
+ * For example, in a reference-counting algorithm where exclusive access is
+ * expected after the refcount reaches 0. We can check that this property
+ * actually holds as follows:
+ *
+ *	if (refcount_dec_and_test(&obj->refcnt)) {
+ *		ASSERT_EXCLUSIVE_ACCESS(*obj);
+ *		safely_dispose_of(obj);
+ *	}
+ *
+ * @var variable to assert on
+ */
+#define ASSERT_EXCLUSIVE_ACCESS(var)                                           \
+	__kcsan_check_access(&(var), sizeof(var), KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT)
+
 #endif /* _LINUX_KCSAN_CHECKS_H */
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200206154626.243230-2-elver%40google.com.
