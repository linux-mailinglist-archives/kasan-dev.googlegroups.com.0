Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBHCW2GQMGQEF3OA6GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 265EA469070
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 07:43:17 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id h17-20020a05651c125100b0021ba28cf54dsf3078199ljh.22
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Dec 2021 22:43:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638772996; cv=pass;
        d=google.com; s=arc-20160816;
        b=vldhhLORsDHggYoqt6m+ldpZPoZG9IGqbmnNVcfG1iu+Yak72Uwn6Y0sfv/b+naL9W
         hKoEOJWyjsew2sHcWBzz1Rey7pqgdM3lQhkT9/tkkkIv2rOhhSWdzbMRo4wB2KEZ/KR9
         /+X5nudBHvfA5GHA1t6G5rr9LYXYAfnRPUMiGl8qyxD4gfderk0N27ieSFW3plkTlCqd
         /IUpHW4a/+UxawoPyrpNwWrvCdPZJAqN/WGPrZyLqP2WJ1seRUcV644v8FQ2vZONMIIQ
         YO3tOaUQ2TnFaAJbQjZ23JOQ2dyeKdV6OOen1XueagAsSp3DGoITFtHS/q6oviP2rU77
         L0Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=mjvjDNMNiiM+VbBaAVNA3IrgkqWnuWPd7t+w6MTGrA8=;
        b=ieWhNLdSwSm9WrrzkMEcAJJKDTEcA/jnhtyIOCXt4Q/JXWVKYtz2q8XCNcfb2JnH5/
         hl3H8MLmX3vrjW2HRY+rIiFEin2OaW8qXqKPeS0X8AooAcm+EV8vMgHcD/jlIJXpLPJ5
         PrOFCrif/bCs8qwwbUNc1VlViqz1dqjax06us9i5gW18/WX3bgt+iJcxAHIiEUoO9AVl
         taCGWxYOJJdMDFiKuCrh/z1JMtLFES1Lkd8pG5KnD976RfE4GFvPJJjw7l/otoswHY5c
         uo2H+GGTXn8nbMzbfgkbPLVFkdI2FhNZJVa+WAkipnbkIBRT/Y1HypEwJtbXZMUYS96r
         8y3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=a8sxZOfD;
       spf=pass (google.com: domain of 3argtyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ArGtYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mjvjDNMNiiM+VbBaAVNA3IrgkqWnuWPd7t+w6MTGrA8=;
        b=QRg0AWsemNzlXrvji8mf9rQv9qSjd6Eyd+s5aDmsTpUBihZwFw2uVAnygaJFaH5/bg
         uG28PAXbT9QcvLYPys/e7lzKDr/1E3R04tJY2Wm3yM6rmJWCLzj7IoGjDqWcyqJqeJAy
         p6CQz+tRNMmkLfRQTLkl7BnrI8IvqB7vN0XOcBYx7je/AcbawxKWGe/f4raus4WLY/yA
         phS0HThZ/W2sHZpXk4U3/BpMPbPvspc0sVYzfemKkfAgG3Rct6EIbsza5JzxEPGfd4Ey
         G8/WJDP/u6lAOj69aFM2PQ0ocSGPLA1kfpPDf99UtBSc7d3elcBq/jwbkLycdgbDa67b
         jlDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mjvjDNMNiiM+VbBaAVNA3IrgkqWnuWPd7t+w6MTGrA8=;
        b=x7NQcIsFCjqazXiO3yGije/Hd0Vli0ssSREp2iyF9aSa5KM4ZVnJa4vhLD8EoWTnfo
         QDUckRMPs7Oq9zVUrNVsqUmTLPxUpQvLxOIgAVbtYm6bYEKWJfp4UnzWVJmP0PmzFJTr
         TbDqA+XTAwpGZkb0XJwjtJnx/bTlYnExg+Lm2/uBHtAZ2M9wREfDqtyqxBKx1spnpMan
         1Dnlsj45hsrWu8Oz9yY+SGZH0zYO3gD+mumROcQtnzjvs94ZQuMYlf6M9gDqxXvkPvl5
         AGtoAMmxq4VGaR7ZG/OtJY70mDTqwnf3a2oons8WH5dQ1WUjW3Nj3bxsicYkXAT51t/q
         xFDg==
X-Gm-Message-State: AOAM531wupPv2+TJLIyuuj5X7NnZtzaP7AyolCQgqbJOi5UjimPjO9Hm
	gPKz1B37WMW7X6fTohsoSR0=
X-Google-Smtp-Source: ABdhPJx8lE00YnETZP52LVrWHWYaJ4JWddd+/SuYgH1l8SW4Py8oXJe/ifWLEoVavn7Cz8/H7CnZ+g==
X-Received: by 2002:a05:651c:503:: with SMTP id o3mr34315521ljp.353.1638772996691;
        Sun, 05 Dec 2021 22:43:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:898c:: with SMTP id c12ls2380021lji.11.gmail; Sun, 05
 Dec 2021 22:43:15 -0800 (PST)
X-Received: by 2002:a2e:5852:: with SMTP id x18mr33776474ljd.184.1638772995563;
        Sun, 05 Dec 2021 22:43:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638772995; cv=none;
        d=google.com; s=arc-20160816;
        b=cb6PF7kbGdp/6f2otZaqMSD4ZMRveRAT7QUB0UC3tO20HZFsmKsBjG+9OwMXuV8kJR
         HuNQA6jOyn1LTQ1j+S2j/FkkjXpe8iv0xfpWF8kaoN/8+lgs0jcPNAve/IeVaMDdGpsH
         ug9h454y+3au3tpgnletNL+vfzIeu9vfQTwNpH22RG+hWgr4/6IK1XXbgcNWlsuOxTpz
         1apJty+3ayYL/mKSIJhRbmMDWSbZQqI16sLoYl3iIIXCC5mo39As2g07cfQc40RNCoQA
         Z9/QmlR1/N0kqdq8KsvyQ6U0AkUqj0EDi07BLFvL+9Sf64Ubv+mm1//vxDdb6j3gpXR5
         FHDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=j1fyadDoDslylJdYYaDqOZyJVAR4yBe0dIXXRHGm4Os=;
        b=H6z2gjRyDMrPuHjB6akX+wplVFgBlCMXYrzx0LUwfYKZB825z6oX6RLmyKkvbMhz8V
         Wxxxccrq1p12CxD9gPWSCzn1uGNsGJNNSrouTH4kiiwxLiq2FLu2K1af2Hh6gFtOyocJ
         /wrFLgGkQn9hRAeMf220cykoGPPjco2CM3oeccqeIlm9P6jgdOPfrGtp0CkN367aj5Tm
         oM9iwicLG/SbrXYk7B0oy/N3W8G8m/nd6HvTcF/3qIBGnzJS+2+HjwKplsulD9RSAhUB
         TNwdK+KeFwKsb7kjC2au3UFI060tC2S4RbU9YnQKcydJA3eh0QT865ex4c1P2LWHjE3S
         zS3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=a8sxZOfD;
       spf=pass (google.com: domain of 3argtyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ArGtYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id b29si650541ljf.6.2021.12.05.22.43.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 05 Dec 2021 22:43:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3argtyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id q17-20020adff791000000b00183e734ba48so1691585wrp.8
        for <kasan-dev@googlegroups.com>; Sun, 05 Dec 2021 22:43:15 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:88f3:db53:e34:7bb0])
 (user=elver job=sendgmr) by 2002:a05:600c:4f0b:: with SMTP id
 l11mr3647218wmq.0.1638772994811; Sun, 05 Dec 2021 22:43:14 -0800 (PST)
Date: Mon,  6 Dec 2021 07:41:51 +0100
In-Reply-To: <20211206064151.3337384-1-elver@google.com>
Message-Id: <20211206064151.3337384-2-elver@google.com>
Mime-Version: 1.0
References: <20211206064151.3337384-1-elver@google.com>
X-Mailer: git-send-email 2.34.1.400.ga245620fadb-goog
Subject: [PATCH -rcu 2/2] kcsan: Only test clear_bit_unlock_is_negative_byte
 if arch defines it
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=a8sxZOfD;       spf=pass
 (google.com: domain of 3argtyqukcs8pwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3ArGtYQUKCS8PWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

Some architectures do not define clear_bit_unlock_is_negative_byte().
Only test it when it is actually defined (similar to other usage, such
as in lib/test_kasan.c).

Link: https://lkml.kernel.org/r/202112050757.x67rHnFU-lkp@intel.com
Reported-by: kernel test robot <lkp@intel.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 8 +++++---
 kernel/kcsan/selftest.c   | 8 +++++---
 2 files changed, 10 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 2bad0820f73a..a36fca063a73 100644
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
index b6d4da07d80a..75712959c84e 100644
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
2.34.1.400.ga245620fadb-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211206064151.3337384-2-elver%40google.com.
