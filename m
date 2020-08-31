Return-Path: <kasan-dev+bncBAABBX75WT5AKGQEECDD7KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id B182A25809B
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:08 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id k26sf1128016pgf.8
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897887; cv=pass;
        d=google.com; s=arc-20160816;
        b=i0+zDgp0LzPrsVeoIvUlEs8cUJho/7EeTb4w+RGeFPntg6d4rcHNyacGIcTfkBQrJX
         EfzOAycUjLX5q6VG02Zh7++bxboUp8+rXjdpxhKu7wOqQN9OQzfmfHBcMDrDkunGejeI
         Q5XMPokxDj0jckIuvcVxpuNqbD0Rp8IvGOPF4czGE5Rw0xYvEkEpB92HtlfsJbtYR3eK
         mPZtH4gzFPIH7TEwECPztRQWK4FnQQBt8gCPG2hSbmaoQrQn/Jnk5JW0+6ecXrl858aX
         ohNTGSxom8wvU56z7kgpZia5G7IGVgmVV3wjPcuILvotZldz+vNXPj+rXwISCyHH/D1m
         w4iA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=MbmfAjoPz5EJDiR7mhbS6GQHrgNMRwXI0ZRSHud0yP4=;
        b=nVJzr7pZY2cKorIil/DwSXWUi53HgCu/lO+OIHEoYmo4hG8/NVA16OGPWFmaNy2uMn
         HdCJyqjqp+6jjsJSnb6FFTihxBKgIuBaR9o6OgtM+H+5VoYlmz4olUgh+NeyGfC4BNHm
         4ZaZReqchboDDg7TysiHws4ANm4b6qeajcZykITp3TJsd5xCXj/eaywBM1G52qIP5NmB
         8tiXaWT4gdLhwP7CKqaNdAlaVU1QiKI+cVHJ4plXQlzgl+e5gw/7auAZNQrqOelQsPcI
         H0l0cIMQpUSFX9FdmXZ8Rz1NuwDQfdCjORPzSW2BmWBa0xPgDdvXWNHb8ZRjQzfAqVlD
         aXDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=WrmSEdAk;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MbmfAjoPz5EJDiR7mhbS6GQHrgNMRwXI0ZRSHud0yP4=;
        b=SeIIT1NT6ajJichC+xNhxKNH0mEzp2S/EvImx7twYxRTjVE88bmg6zXgqRX/pgZdiq
         z17OOxt+eCX/GxlyoZysR5/49XLtyebXHxN0bCDKPJep9Z0nirFlmCnvfOWbVlayPCgd
         Vh2ApAkc14EDsARhb/4NycdLATBoMHdj1+0Jww8y9M93ZB4hYu93gaBX5HTmmIeI8Em8
         dsAMzJsKJTUib21H7MATSxff97m73qpeWS2CMwGWyhrbGU7WjqjN7unHTERf6ZJkJejf
         023cd+FOoffng+JDqV9GbzrEddjmynHs5fNMpnTO2tKAXcdIolOpRg4hIsBB5P0N0fzZ
         D6Ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MbmfAjoPz5EJDiR7mhbS6GQHrgNMRwXI0ZRSHud0yP4=;
        b=uUcW7pS5NqIlBWibAO3o6HFcPg23Dr23bVY28rJI0piIt9LL2hFzsTVHJB8kaCPdiN
         D2nh142sl7CkZq1nOYKbEuvH+DTHmsVhfQshYnkdWyjQJqu8vCvSvhNS/rMZRsoXFBhM
         gn20sg4MHM85gXMSBhuGeB+rp5pnpze1UQZ4osvtQZU4EQkkQJIHQ/mu9e5Sb+/E1Tb+
         XhXSEdYpAiLRkCqZel+hceFmE2sBdw2Tt8BEY5mUEAXS51lXiEc2wIXe4efAvX2abdgb
         1rQ82EFqNIjyH0S8+H2Q7eAFpM5rGr27P66qQo0dSUjQRSeCIOcg4dqKuM5J5w+9GRSy
         +Acw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5330TqdYY5EBW5xYCBsYgUj3lMhxULmuRZnzyknzKyDh2LgmDJbG
	GL7V21Xt8uBiqf21GnR6xKY=
X-Google-Smtp-Source: ABdhPJxmmX+O5ZjvNhFUUYxQDSC73raEvhUNFuZBc8CaJhGqX3vSDur6jt2bZw2zXoME4jtEnDrdhQ==
X-Received: by 2002:a17:902:56a:: with SMTP id 97mr2014914plf.130.1598897887372;
        Mon, 31 Aug 2020 11:18:07 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:720b:: with SMTP id ba11ls3866979plb.0.gmail; Mon,
 31 Aug 2020 11:18:07 -0700 (PDT)
X-Received: by 2002:a17:90a:4488:: with SMTP id t8mr530241pjg.191.1598897886962;
        Mon, 31 Aug 2020 11:18:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897886; cv=none;
        d=google.com; s=arc-20160816;
        b=hAQn5Tcwbv0ix4Q3SQcV/nP80o7EV1o7QBpitKSUOYnun3b4GDJ0En0/O0JTxT3+JF
         iasyoabmuWV5OCWMv691EaPW1G6/6UM2As1w0vpkyIzEq2hAtG9OxZGrOSlrcC3Eiq0g
         zMmDgoWjgmFxbrI5KsU+/8RtIrzKHVKAb2O8jD5z23UgDo4JvAz/PltgjG5GvmF2TIqj
         Rd5ODn4N0+Oy3ZKBK1Q1ITKUST4fyXDMapSBhFQfP1BEDxmpJNWVa6iIxodTwvRPMcTZ
         sNHytjZfTjsVGflgD6k6pE8+fwqKGAL58e8eOblDvbA0Wz3lFbFWbCRf3uBwcqAGT8Uk
         4xsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=h5N0rpFA8bbbfbBV3FV2IlHcDiBGdAzaNVP/RLNidsg=;
        b=RVmy02wT/qDLoC1j4uCGuyydo4d+bBo5Kzxf5vZsxDkf1PetTtFdTbR2svEnAXMfOE
         Mjvmr3x2oybHJTvHkHT/aWRLrQ/Z0Aomv69kPZpNT7iVIKScq7hiK1Nxq9IfkPv5HQNk
         Ubem3Q+r2YaEUYViH3LKYly2YkRJ5E1/6FWwTeAwlhlp6ESg3hQf0lyC827AN9yFzCiL
         nBzmkb2D/23TdEgi/PuHOqnsEoerQmL3MswlPpcSr56WFCpvt9PcrMMlJCLpa2mbe1nU
         ojqtAcFpBrg/QpP5rDX6MK8P5A9AYmhXexeRzIJgeNbpyfcecaC1zJOZWFObxhkx7c0f
         X/4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=WrmSEdAk;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n2si577528pfo.5.2020.08.31.11.18.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A2BD92145D;
	Mon, 31 Aug 2020 18:18:06 +0000 (UTC)
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
Subject: [PATCH kcsan 03/19] kcsan: Add atomic builtin test case
Date: Mon, 31 Aug 2020 11:17:49 -0700
Message-Id: <20200831181805.1833-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=WrmSEdAk;       spf=pass
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

Adds test case to kcsan-test module, to test atomic builtin
instrumentation works.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan-test.c | 63 +++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 63 insertions(+)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index fed6fcb..721180c 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan-test.c
@@ -390,6 +390,15 @@ static noinline void test_kernel_seqlock_writer(void)
 	write_sequnlock_irqrestore(&test_seqlock, flags);
 }
 
+static noinline void test_kernel_atomic_builtins(void)
+{
+	/*
+	 * Generate concurrent accesses, expecting no reports, ensuring KCSAN
+	 * treats builtin atomics as actually atomic.
+	 */
+	__atomic_load_n(&test_var, __ATOMIC_RELAXED);
+}
+
 /* ===== Test cases ===== */
 
 /* Simple test with normal data race. */
@@ -853,6 +862,59 @@ static void test_seqlock_noreport(struct kunit *test)
 }
 
 /*
+ * Test atomic builtins work and required instrumentation functions exist. We
+ * also test that KCSAN understands they're atomic by racing with them via
+ * test_kernel_atomic_builtins(), and expect no reports.
+ *
+ * The atomic builtins _SHOULD NOT_ be used in normal kernel code!
+ */
+static void test_atomic_builtins(struct kunit *test)
+{
+	bool match_never = false;
+
+	begin_test_checks(test_kernel_atomic_builtins, test_kernel_atomic_builtins);
+	do {
+		long tmp;
+
+		kcsan_enable_current();
+
+		__atomic_store_n(&test_var, 42L, __ATOMIC_RELAXED);
+		KUNIT_EXPECT_EQ(test, 42L, __atomic_load_n(&test_var, __ATOMIC_RELAXED));
+
+		KUNIT_EXPECT_EQ(test, 42L, __atomic_exchange_n(&test_var, 20, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 20L, test_var);
+
+		tmp = 20L;
+		KUNIT_EXPECT_TRUE(test, __atomic_compare_exchange_n(&test_var, &tmp, 30L,
+								    0, __ATOMIC_RELAXED,
+								    __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, tmp, 20L);
+		KUNIT_EXPECT_EQ(test, test_var, 30L);
+		KUNIT_EXPECT_FALSE(test, __atomic_compare_exchange_n(&test_var, &tmp, 40L,
+								     1, __ATOMIC_RELAXED,
+								     __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, tmp, 30L);
+		KUNIT_EXPECT_EQ(test, test_var, 30L);
+
+		KUNIT_EXPECT_EQ(test, 30L, __atomic_fetch_add(&test_var, 1, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 31L, __atomic_fetch_sub(&test_var, 1, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 30L, __atomic_fetch_and(&test_var, 0xf, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 14L, __atomic_fetch_xor(&test_var, 0xf, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 1L, __atomic_fetch_or(&test_var, 0xf0, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, 241L, __atomic_fetch_nand(&test_var, 0xf, __ATOMIC_RELAXED));
+		KUNIT_EXPECT_EQ(test, -2L, test_var);
+
+		__atomic_thread_fence(__ATOMIC_SEQ_CST);
+		__atomic_signal_fence(__ATOMIC_SEQ_CST);
+
+		kcsan_disable_current();
+
+		match_never = report_available();
+	} while (!end_test_checks(match_never));
+	KUNIT_EXPECT_FALSE(test, match_never);
+}
+
+/*
  * Each test case is run with different numbers of threads. Until KUnit supports
  * passing arguments for each test case, we encode #threads in the test case
  * name (read by get_num_threads()). [The '-' was chosen as a stylistic
@@ -891,6 +953,7 @@ static struct kunit_case kcsan_test_cases[] = {
 	KCSAN_KUNIT_CASE(test_assert_exclusive_access_scoped),
 	KCSAN_KUNIT_CASE(test_jiffies_noreport),
 	KCSAN_KUNIT_CASE(test_seqlock_noreport),
+	KCSAN_KUNIT_CASE(test_atomic_builtins),
 	{},
 };
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-3-paulmck%40kernel.org.
