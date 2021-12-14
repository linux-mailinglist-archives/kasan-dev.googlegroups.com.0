Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E0816474D84
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:46 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id y11-20020a056402358b00b003f7ce63b89esf1516145edc.3
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=vOGpGKRSSif2lzJU8pwxhO7E3oG/pq1Nwa0tI69OMtBKkmtIJExIEl1eUE6nnitRxi
         cvKu/AZk2fLSa3cjSGnINUddwT5eJkeICYSqyhItZcEKoxMSycKooY+D0Y4/SadOR70j
         pt3MPhcCmFGq2WkDPscaS14c5RtIl6tYz5H9MlUCV+ZHn6Ywcm90wjknYoZhAjAJJckV
         aLU0Jdof5+oVgiA6Ls0KBCZFNG/QIOTD40CRuvUi6S3XOJLAEko60OJL3JFRLyfzsRUc
         QwnQABNVVNnzMek8ub6Tl/pykGbeYN3TiTJRzJJopPfH6PdfEQrvawL7yY/nzZS8nK24
         0NIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JNFMJaeI8068V0c15xxah9D15BxsaZDd9J1llO3HNLw=;
        b=hI9PhkSOOS2Nr8U+EbRWkRY9uVXQqXwJegJSAgjJKtS2/MwFnbq0Aq5e/1UIkbvNIa
         jLgc7SeyeNhh4hT0J3KKnI6gVxCUO+pVbBtS6RfH++09IkpEuHDG6IfNz5BmZGUpZjdp
         MZqMTXdTOJFvfi2lCqGu/p75+eO3isxjS593ylU6GKaqwLGGEkNP8QwoUwi2ofAUfDdu
         m+lbdqKJjhz3K9v4GHJmj9ZdR1Xq9/DE1lm7I/40m92AE32OJ1ODQTscXNwbLpSQxPnr
         8P5DdgP51soHTXWYHYlSDefNVOvezhfPxamS2e11FtbaPtfjUaZGnbHDN3CRyFUCs+iK
         eMhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bmrs7gGX;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JNFMJaeI8068V0c15xxah9D15BxsaZDd9J1llO3HNLw=;
        b=LThFcqjW81k8oZS7cvxzyw8y/5smp6yj+n1ZzAsH2m+woPA738v1f/+cmYL+yczYbq
         vXE5X9Vn53LLcspx8fZiz35JRc2FJq0gczakRGd3evIxqPpOkCWPcwUTujNHQhKBUzOk
         3jdV2MHjJQ5IHrOAx2PtjT8YSMPF+2Os92OcViYdHBEal5k5HsDgFcNN6FK9ZebM7t7/
         rpKVs+K83L8PnCyzYdOHc0MBoFj6QBzNxddJDTr0QJrvQtAxY5YTyLoBiV82odbbZS6V
         bKZ3VRfG2cX6rczN8HWhYUCT7glpAPBKata4LPSPxgmDYKFPQ3tMcVhldZD6S6B/qVaP
         9jtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JNFMJaeI8068V0c15xxah9D15BxsaZDd9J1llO3HNLw=;
        b=14M9+wp7RNn6fCnjVQMeRzFeoLXoHARpKGbwEDWuvlbvRGGISNyChK6VWjzc0tkg01
         A5AYY4WAauSl3RSwbEmXjrFDgnV3HYFk9PCL2SShyHItFyQDjlinVgNvU2jNr1wRwVF7
         ETrfJcstnA1vQ9WtRXzHXbfECLnHy2TrfV7uMMUxmd5j9jOwQ3UoLpE09W1R6CSHQV9Z
         ex2svi+0BgcPQgosgX5sN1fckFbL8wlrgflri4lb5xGCGjVHxhviJsttpN+F5Ll8Ah7a
         m+MwWUNkvMpCjl/BLyLgQINAqRBWM3QS608cLXIu/8qygi4VDt2abJYZzCI/OkIH/KBl
         fdNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532IOujbb+N+LrhyxYYC42IasUVPyjR0zqnnLlmSAfOeeuiRA2F3
	jYJ07HpCTmMh23lwRXQxvE8=
X-Google-Smtp-Source: ABdhPJxWtf+zBOucozPWkVOyRdH/OT+wmSeyCa5BmyqmpLHxMFnspymNC4t0un/b0V0dSyTblz4Jfw==
X-Received: by 2002:a05:6402:26c8:: with SMTP id x8mr11424211edd.156.1639519486707;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d2c3:: with SMTP id k3ls43128edr.2.gmail; Tue, 14 Dec
 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a05:6402:4413:: with SMTP id y19mr11272935eda.26.1639519485835;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=Dkfd23a5452uSVM+6BCPGWCXgy35wRWRAhq3GALhXYOMOlEFF2rHKrgkBXSHG9GQLL
         0U0KEW+LdUis7DBTADZvaWbr+msm2nfDpqiULxWrELszM8hvP8sGRuCe5t8xsuKxfKIj
         nQ6e+PErKDe9FGTrWWmtA0OeUQ/3heN5eFUa79L76egRd87YnTiC/RCq2DBlJnHbF6P7
         4SJkdtvPjajQXLNlXjGW+u7ry401sqEoUSUTxjS3+fLzKvsFlZgJJyB6LRxCiuY+AsDm
         YFqvHGlEkSfVeNPKB6mmYq/2AmNyj1WT9npsBargYGnnx9uabh2qQ0BJXE9MZEiYEngX
         L0OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+3F64AI964chmpJf1j35sQnm3aE7orljeQwZG7V1Snc=;
        b=gGScNd0MBWsv15wlXMH7hKFwMpwR/VSncCK6j+kSIwqyAGI91etccmFgYSOJ2v16RN
         gQ5tjcKSi+sQG2vhLnOPWnRcGd7jRm0VjiHq9drNE3dkoBsyLm98KMJZfaEGeUHZ0SXb
         KWXulHvzdjVR0d7OpbQhVNG1zyydwxKABmGjR8mmMYsIb6oInX4cYBCt30bu0mUISADc
         KhIVcEvW4Uuj8W9p46DOr6FvUS+4vv7gna+IC8mDsoE2AtuX03byTn6PnwOTqJyQm9oU
         PZ7RS32E209huhB3BFzzQah8TBk3iqMPbmu8NRYjTVT5aDNiHDJOxLGDT2ff8xnJMn5x
         5PLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=bmrs7gGX;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bs25si2734ejb.2.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 78B7161769;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 454C6C34605;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9216B5C2C8E; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	kernel test robot <lkp@intel.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 29/29] kcsan: Only test clear_bit_unlock_is_negative_byte if arch defines it
Date: Tue, 14 Dec 2021 14:04:39 -0800
Message-Id: <20211214220439.2236564-29-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=bmrs7gGX;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Some architectures do not define clear_bit_unlock_is_negative_byte().
Only test it when it is actually defined (similar to other usage, such
as in lib/test_kasan.c).

Link: https://lkml.kernel.org/r/202112050757.x67rHnFU-lkp@intel.com
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 8 +++++---
 kernel/kcsan/selftest.c   | 8 +++++---
 2 files changed, 10 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 2bad0820f73ad..a36fca063a73a 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -598,7 +598,6 @@ static void test_barrier_nothreads(struct kunit *test)
 	KCSAN_EXPECT_READ_BARRIER(test_and_change_bit(0, &test_var), true);
 	KCSAN_EXPECT_READ_BARRIER(clear_bit_unlock(0, &test_var), true);
 	KCSAN_EXPECT_READ_BARRIER(__clear_bit_unlock(0, &test_var), true);
-	KCSAN_EXPECT_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
 	KCSAN_EXPECT_READ_BARRIER(arch_spin_lock(&arch_spinlock), false);
 	KCSAN_EXPECT_READ_BARRIER(arch_spin_unlock(&arch_spinlock), true);
 	KCSAN_EXPECT_READ_BARRIER(spin_lock(&test_spinlock), false);
@@ -644,7 +643,6 @@ static void test_barrier_nothreads(struct kunit *test)
 	KCSAN_EXPECT_WRITE_BARRIER(test_and_change_bit(0, &test_var), true);
 	KCSAN_EXPECT_WRITE_BARRIER(clear_bit_unlock(0, &test_var), true);
 	KCSAN_EXPECT_WRITE_BARRIER(__clear_bit_unlock(0, &test_var), true);
-	KCSAN_EXPECT_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
 	KCSAN_EXPECT_WRITE_BARRIER(arch_spin_lock(&arch_spinlock), false);
 	KCSAN_EXPECT_WRITE_BARRIER(arch_spin_unlock(&arch_spinlock), true);
 	KCSAN_EXPECT_WRITE_BARRIER(spin_lock(&test_spinlock), false);
@@ -690,7 +688,6 @@ static void test_barrier_nothreads(struct kunit *test)
 	KCSAN_EXPECT_RW_BARRIER(test_and_change_bit(0, &test_var), true);
 	KCSAN_EXPECT_RW_BARRIER(clear_bit_unlock(0, &test_var), true);
 	KCSAN_EXPECT_RW_BARRIER(__clear_bit_unlock(0, &test_var), true);
-	KCSAN_EXPECT_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
 	KCSAN_EXPECT_RW_BARRIER(arch_spin_lock(&arch_spinlock), false);
 	KCSAN_EXPECT_RW_BARRIER(arch_spin_unlock(&arch_spinlock), true);
 	KCSAN_EXPECT_RW_BARRIER(spin_lock(&test_spinlock), false);
@@ -698,6 +695,11 @@ static void test_barrier_nothreads(struct kunit *test)
 	KCSAN_EXPECT_RW_BARRIER(mutex_lock(&test_mutex), false);
 	KCSAN_EXPECT_RW_BARRIER(mutex_unlock(&test_mutex), true);
 
+#ifdef clear_bit_unlock_is_negative_byte
+	KCSAN_EXPECT_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
+	KCSAN_EXPECT_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
+	KCSAN_EXPECT_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var), true);
+#endif
 	kcsan_nestable_atomic_end();
 }
 
diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index b6d4da07d80a1..75712959c84e0 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -169,7 +169,6 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_READ_BARRIER(test_and_change_bit(0, &test_var));
 	KCSAN_CHECK_READ_BARRIER(clear_bit_unlock(0, &test_var));
 	KCSAN_CHECK_READ_BARRIER(__clear_bit_unlock(0, &test_var));
-	KCSAN_CHECK_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_READ_BARRIER(arch_spin_unlock(&arch_spinlock));
 	spin_lock(&test_spinlock);
@@ -199,7 +198,6 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_WRITE_BARRIER(test_and_change_bit(0, &test_var));
 	KCSAN_CHECK_WRITE_BARRIER(clear_bit_unlock(0, &test_var));
 	KCSAN_CHECK_WRITE_BARRIER(__clear_bit_unlock(0, &test_var));
-	KCSAN_CHECK_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_WRITE_BARRIER(arch_spin_unlock(&arch_spinlock));
 	spin_lock(&test_spinlock);
@@ -232,12 +230,16 @@ static bool __init test_barrier(void)
 	KCSAN_CHECK_RW_BARRIER(test_and_change_bit(0, &test_var));
 	KCSAN_CHECK_RW_BARRIER(clear_bit_unlock(0, &test_var));
 	KCSAN_CHECK_RW_BARRIER(__clear_bit_unlock(0, &test_var));
-	KCSAN_CHECK_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
 	arch_spin_lock(&arch_spinlock);
 	KCSAN_CHECK_RW_BARRIER(arch_spin_unlock(&arch_spinlock));
 	spin_lock(&test_spinlock);
 	KCSAN_CHECK_RW_BARRIER(spin_unlock(&test_spinlock));
 
+#ifdef clear_bit_unlock_is_negative_byte
+	KCSAN_CHECK_RW_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
+	KCSAN_CHECK_READ_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
+	KCSAN_CHECK_WRITE_BARRIER(clear_bit_unlock_is_negative_byte(0, &test_var));
+#endif
 	kcsan_nestable_atomic_end();
 
 	return ret;
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-29-paulmck%40kernel.org.
