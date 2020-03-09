Return-Path: <kasan-dev+bncBAABBO5GTLZQKGQE2UXRZTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id D4B2217E7D6
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:28 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id q128sf16945994ywb.8
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780668; cv=pass;
        d=google.com; s=arc-20160816;
        b=gLI9iE7ugn2Gsa3/6LEA6VOETBj6DkjbSBPy7BuuhFtl98Yk3UnOSP+chP8EAdd7q1
         UCVs1lgkPuhglpAPg+gOef3oMUZWpHootYOrbv1riK/LK86veGddkkdRD2manhX5NmER
         TnXTp5ko3841M9thV/MxxUO20wxmG9V50sjNRb9elYGDPkWJYvDWUNf03sMMViOyU52b
         BudeenOjgR1yQvmioxroCx3Ks3KJ/y7lp+01xN6qTdLZgWRJsOmvmRh8lVsxEWxVyol8
         DsEc79+Wuea4LpuJZ6Cqn0zUbX8jjBZd5mykt0mv2t2axdaZS00XPyB8dPxO1vQRCDhJ
         AR5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=GKZFJYQ39nkPcE1+M+LWJZKkihnpDqF70mdHmncOdcA=;
        b=uYI8wDAe0F6F23wLBGSP74K5/8oO53FnjSNCiiYvH0HCgdZ1yixJ0aMoUkv91LvPCw
         QirOKw8I42b/UHi9uA2Nt69s87j7YJfahGL0T77Xu/LwD7FdHwJJ4kb0/alqbqYFvsmZ
         mLwkhIg2G1Iu+hvpL+03cI8fxDqB2n1PaTfdNGgkZNkUbjKvQ0LLNpV28NChGeI1bfxw
         itSsWi3TywIEYgwisyxORA8X01atk5OdaTsdZISvTmMbwmZJAwdOttv5cHhJw1ybt2Eu
         mfn23qo9BJoqbGpcdOVOTLFMPO8vk6ttUjO3UkgmWG5m8dAjMiJ+uY/Nk2GmHFTMWgc7
         G8MA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xdLsRV+A;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKZFJYQ39nkPcE1+M+LWJZKkihnpDqF70mdHmncOdcA=;
        b=O2r/tTO8F5552H2YTp0liUQXfWNMoTLEBfzDNxVEIe8hT5dHvKSXLm50AF9ST2a2vn
         QEXp3yoxT6ml6hP3qqXFgtwlQzTbIbbtVj80rbfsJ9rwL+VgA1n3624x/8//WE6xpGzE
         a7hKNj0pBgavln1l5M0a8Kbv80/cK8nz1EtolTxkITwu/Rs+aA+tkQzf3XaZw9bv/98g
         ACjsitvHFj3xWYdsyQmRoDBi6/9ODlVvaBt40+X6yiQHu1JDHCry8qgFZS7opPvjolfz
         Ex+GauzP4+CGMXuyEgsuK08IW/F+mmH2QX1BM86oHvCe32PzOE8LVr92Ga+fSF+b16of
         xx1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GKZFJYQ39nkPcE1+M+LWJZKkihnpDqF70mdHmncOdcA=;
        b=j+nopdWdJurpb9w9IAHDqFPmEttuP2olea/SzE0MVknrV3I1WckJ8uuTHQ2BAWxgoh
         VBf8paT5GWL8YooTMFDvSa2WuSdG7wDD6P8sMxVCZmQ5TR0wgmwfp4Ijr982t/S1LTFn
         X65c+1mTmk4C5v5q85fvapDHJfHgF7gjhRGq34ZlE1smf3boIBiqLzXIp3CSUOCwy25M
         qaqUm5gzCrBBIlRxlxGLMsE+qgFTqe4jIyTE3LYndkaIHzXP7HErOTzEHvOY5WBtc3o0
         LkJ5oXdYqSqd5nrSwDoGlWj2JiRNgZO/NQAK3MnTVgGY/7hUdXmyArGmt9zjk9m1fjYv
         ZSJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ3eZq7/amhxVQfub1icDOUPj4QNb54osXUbV2JtVPRqxwwkNc9x
	5uMgI087p7OL55u0vp1O3uw=
X-Google-Smtp-Source: ADFU+vtfuFwc74LAmxvlxQmGVa7JV4EXMNbYkI9vO481g9jpPnmAZL7gKi2tQl2mEbbDnG9lqwAA4w==
X-Received: by 2002:a25:69c1:: with SMTP id e184mr18735877ybc.316.1583780667836;
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:284e:: with SMTP id o75ls873009ywo.9.gmail; Mon, 09 Mar
 2020 12:04:27 -0700 (PDT)
X-Received: by 2002:a81:4912:: with SMTP id w18mr19070824ywa.116.1583780667301;
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780667; cv=none;
        d=google.com; s=arc-20160816;
        b=DMHg4Qh6MT5QK8o9aFQVxAcsVkWrUFejjy0RCRyWEE2uqSmi3w+TxxyU1xRlXRmaIM
         E6llygv1Uc7FOcEj3ofhsqnQJocwBZ+o23h01QSAhhrkmotjHk1cNukYZWXdTm7D9RIN
         sRcTZWpipqCz5YRFqz/EpwYoYUtzXXBbW3UGJg8t1EZpB3VzW2+bD7iDMuFXvWng6cQu
         OUay+EOOzsG64A5xncuCAwlNQf2FOWndol7TnBSxdf9XbuOo1w+QmsUjccimWhX504Gc
         8OR4Oc8WoV3biBjRrYPkGCtnOHAFaAsb9OCKKYu7yutYRvqTiF0vCMuYPFTSNlE5njwC
         g1tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=aAeZE7M9XJOgfvuaaTTwmHskOOww/iLu9OR2wxfArPA=;
        b=PVt7IQTiF3FrWLSp7Eo3qbWDwYO80LjCrzwVjApI3ZzNZFsJOGCC4Q47RRT8iniHCf
         9ks7CxLOp4ONQieEdqMU6X079BhRigk1auS/RDwboqaRYoFCONLLoarkLBx8iY8zICyl
         6x/+Y175z1AGzmAsUmAMtZwYjBYK6Fz4PANA/uSIWi4sH1XAYvonqQyTi8e5rfxp5iqU
         Xgk0d7uj+CSn8ychRvB9i+JT4w7ZXiRaKR2G+mFmcSNB/eF5hfAhdIcBI8vCwzSNwM4/
         5bkecy4pCr27XcyIBo6QGJ0noFSvQKjUbTEp0XWYaRrBWvbKJ9UvJd0P+vv0VwJ8IupC
         Tz/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=xdLsRV+A;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id b127si240409ywf.1.2020.03.09.12.04.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 574C424683;
	Mon,  9 Mar 2020 19:04:26 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 17/32] kcsan: Introduce ASSERT_EXCLUSIVE_* macros
Date: Mon,  9 Mar 2020 12:04:05 -0700
Message-Id: <20200309190420.6100-17-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=xdLsRV+A;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

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
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h | 40 ++++++++++++++++++++++++++++++++++++++++
 1 file changed, 40 insertions(+)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 5dcadc2..cf69617 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-17-paulmck%40kernel.org.
