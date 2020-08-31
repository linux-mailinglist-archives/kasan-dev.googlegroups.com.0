Return-Path: <kasan-dev+bncBAABBYH5WT5AKGQEXAV6IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 76CB12580A8
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:10 +0200 (CEST)
Received: by mail-pg1-x537.google.com with SMTP id 130sf1117582pga.11
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897889; cv=pass;
        d=google.com; s=arc-20160816;
        b=epEqx4P93Yb5gjO9FQuI/mC2B48LTfsYZh/56McUfbcHb1JXEHkf6lB+GCzlv6KjzB
         CY9GysWUzI6WRYH2ml0wtXvUQ6Eo6gXYlBxRs6FXz1zA4in1vtWyl6FkVQOseW8PeDaC
         5NcJdnVbu5SJdS5Th/J1Dbc6HZAvNA7YIHTSpayJ1Hc4ePP08+SntrVJ/vGDgpsys5po
         +0VEVf4Pk99FZH/Re0C+zh4Me7Uwa/+vK5InNNpLaz91beX6Kh9QyDki1b42V53vtg6Z
         9PgWTjlVcHMk+eLERo1MdiRFMEn4yrEfHGjllOcRAz/GjrEvy7e2TOdKDB/yTOex0lac
         5XYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=pKoIS6uv0S/6geEKhAz2M9k0MXM6WxlawOqZc7PrAmE=;
        b=YargfnZO7mkA1Rgfh8gflSATKidinYpOBufUr2DVopR8621fr4U1ankGaGy0lpWfzS
         i8Y5B6YUh1GwRZWvKorr97rgJ9eFqigNf+HLu9kGWNnjJzJ93g9mpDNPX3OStRb55W1L
         jiU8mnq4Vn53kJhMpOAEISnJhOIsB+XcJn8DFyIPCTiYh+ZoWd2Z7/SK2ISp3EKqVCv1
         L1/ojfQsG/zeNWrLd9HpPk3IO6zF+9bafdjGORj0tn5OkU4rBomdGOng+RCmTgOr9HJu
         garZ28buVZ5f+9CFGWRm91uZO6l5K3GoaVY3VfTaPnvnIuNGySO1Lssofu/bLIRjKHLT
         cYbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DpLApWVQ;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pKoIS6uv0S/6geEKhAz2M9k0MXM6WxlawOqZc7PrAmE=;
        b=fVvsGSsIjq//JoEXGmesc5ezImy3LV7jZhdQf70snzETcih7tEjMhu6roVCZUE9Qun
         0ArNeOrKBeoQx8HvTJTDBGhnyrQWWy6v+vxlu6QiHFRBH4XFzGSUzR85Og3DzmR+d4sC
         lVqPgFc+5o2yHRkJB2h0T04RaL0zqtUDXW6nST7YkJRkBfpJAI0ZW3F2m1ororg4KV03
         vDM/a1LQIpMhbCQ67DpO4CdKVAu7J/TyjniHRAmajOzT2lRqBpdlEKofhohcXwPnJbEa
         TTpfIT91XW3fr4iwVS8+CajK8+tq9o/47NHHwp4GFkxpD2Yyq+e0Dmdat8piJD0Joe65
         dLGw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pKoIS6uv0S/6geEKhAz2M9k0MXM6WxlawOqZc7PrAmE=;
        b=gsvBDT1kjJuCmIkVnERdwB5KjPpJ+JrdrCp8XL78eCbFmONUAupiGmb8unScI8cTWB
         pgT692lzwJPIofG7iie9cpWs/YHBm2HDO/IK9GBADZQJQgaZ0A6QaRrg3wGaN1cq2/wz
         TXAk39Je+rfl8vjqv72dIgVqvr6I4EL3X3JnnLCroZM45s9coLXAvJbmA93AYU+4Oxy1
         tCJbj2PeflSmyoDCNa1VG8wARye6st1QoAhsh5k4veuN9LLBBl+rhuEOe6liVaGYVvI9
         RVAho0KnF82Z3qmanZiHOt4nPLV9PBVK/+7OKcWCBQce2yI3kmuoYsnKLzdn5fF7iowL
         xJ3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530i68XUSp40otx7KxAkcBJlnjP8d4t7115/4J5mekYjWTBR/ZwS
	7bT5rQdA8T1ftsIDFGf5CzY=
X-Google-Smtp-Source: ABdhPJzrFIv6I5955xtvWiOPNCVH6WVRQ9a/tYv0PFF/+mo1h9mYetBGmpUsIkJbEKqPVjDnlKgNsw==
X-Received: by 2002:a65:5aca:: with SMTP id d10mr2183982pgt.362.1598897889224;
        Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee0c:: with SMTP id z12ls3852597plb.6.gmail; Mon, 31
 Aug 2020 11:18:08 -0700 (PDT)
X-Received: by 2002:a17:902:ee03:: with SMTP id z3mr2034731plb.68.1598897888732;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897888; cv=none;
        d=google.com; s=arc-20160816;
        b=nH7NMybA/rirBTPSjDjh1Gmd4TLt6wBtqoysckUctEcO6l5Uf7eh1YHFQfWYyjnQjF
         yDiywCUiQmQ/2RDF3GVo6criaJnxLq6NtnaI6qtPLK7wF53PtfpwJFr0ivy3ghoI05b8
         KsbfA4ozFj6XECyXH5fHfMyK+7/mYrPB24DrDlg/XlB3J47f7OonScV39wJn+rk8nNER
         8+mKO4B86kdAGhTujYzSxK9PjGBnxEF5NGE2UoxTVroHY2uBakgTi/Tf5dAk9VYDRx36
         RfgppbKzh4tC0dfvMGVghMDR4/WNIc3Kv4qciwDjkGbIxVNGCAfZ9NN4U+wOw+Ltc756
         9TTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=XHr/GegbpV/hxHsy2VY3K1fwDKTsQQvfVg8hBGzQox0=;
        b=sEsjmqwc/rqcPC2Xjh7qFZCLmTsbjPxC/8ziLDR5qR8XAMOqYokv971efLGlRIj/jw
         NCjFWSceFLTSFTCFof0IaZla7m4JYScwQjwYESIA5mLSqCsw5flb/r92aOlIxRRxX4W+
         xqgItSH22UPChMCUYH0f6QCKIAGe5lOXGE2x04xBX3+BLzl1SDxZtyWJHw1nA3Tv5KhJ
         iYEORaanJ2rlJyEFyqooNTjZjjaY2ron5DWqD43NsWu7XyByludofkEKQn+1y4votTrY
         LClETSrRdsl1dNH8AX/qe0t0pRXRRIZLeSxZA9Ju9iwQmbareDYMOa88NNRCcA9pjsr4
         YScA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=DpLApWVQ;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l2si389858pfd.0.2020.08.31.11.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 6D1FC2166E;
	Mon, 31 Aug 2020 18:18:08 +0000 (UTC)
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
Subject: [PATCH kcsan 14/19] kcsan: Remove debugfs test command
Date: Mon, 31 Aug 2020 11:18:00 -0700
Message-Id: <20200831181805.1833-14-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=DpLApWVQ;       spf=pass
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

Remove the debugfs test command, as it is no longer needed now that we
have the KUnit+Torture based kcsan-test module. This is to avoid
confusion around how KCSAN should be tested, as only the kcsan-test
module is maintained.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/debugfs.c | 66 --------------------------------------------------
 1 file changed, 66 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 116bdd8..de1da1b01 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -98,66 +98,6 @@ static noinline void microbenchmark(unsigned long iters)
 	current->kcsan_ctx = ctx_save;
 }
 
-/*
- * Simple test to create conflicting accesses. Write 'test=<iters>' to KCSAN's
- * debugfs file from multiple tasks to generate real conflicts and show reports.
- */
-static long test_dummy;
-static long test_flags;
-static long test_scoped;
-static noinline void test_thread(unsigned long iters)
-{
-	const long CHANGE_BITS = 0xff00ff00ff00ff00L;
-	const struct kcsan_ctx ctx_save = current->kcsan_ctx;
-	cycles_t cycles;
-
-	/* We may have been called from an atomic region; reset context. */
-	memset(&current->kcsan_ctx, 0, sizeof(current->kcsan_ctx));
-
-	pr_info("KCSAN: %s begin | iters: %lu\n", __func__, iters);
-	pr_info("test_dummy@%px, test_flags@%px, test_scoped@%px,\n",
-		&test_dummy, &test_flags, &test_scoped);
-
-	cycles = get_cycles();
-	while (iters--) {
-		/* These all should generate reports. */
-		__kcsan_check_read(&test_dummy, sizeof(test_dummy));
-		ASSERT_EXCLUSIVE_WRITER(test_dummy);
-		ASSERT_EXCLUSIVE_ACCESS(test_dummy);
-
-		ASSERT_EXCLUSIVE_BITS(test_flags, ~CHANGE_BITS); /* no report */
-		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
-
-		ASSERT_EXCLUSIVE_BITS(test_flags, CHANGE_BITS); /* report */
-		__kcsan_check_read(&test_flags, sizeof(test_flags)); /* no report */
-
-		/* not actually instrumented */
-		WRITE_ONCE(test_dummy, iters);  /* to observe value-change */
-		__kcsan_check_write(&test_dummy, sizeof(test_dummy));
-
-		test_flags ^= CHANGE_BITS; /* generate value-change */
-		__kcsan_check_write(&test_flags, sizeof(test_flags));
-
-		BUG_ON(current->kcsan_ctx.scoped_accesses.prev);
-		{
-			/* Should generate reports anywhere in this block. */
-			ASSERT_EXCLUSIVE_WRITER_SCOPED(test_scoped);
-			ASSERT_EXCLUSIVE_ACCESS_SCOPED(test_scoped);
-			BUG_ON(!current->kcsan_ctx.scoped_accesses.prev);
-			/* Unrelated accesses. */
-			__kcsan_check_access(&cycles, sizeof(cycles), 0);
-			__kcsan_check_access(&cycles, sizeof(cycles), KCSAN_ACCESS_ATOMIC);
-		}
-		BUG_ON(current->kcsan_ctx.scoped_accesses.prev);
-	}
-	cycles = get_cycles() - cycles;
-
-	pr_info("KCSAN: %s end   | cycles: %llu\n", __func__, cycles);
-
-	/* restore context */
-	current->kcsan_ctx = ctx_save;
-}
-
 static int cmp_filterlist_addrs(const void *rhs, const void *lhs)
 {
 	const unsigned long a = *(const unsigned long *)rhs;
@@ -306,12 +246,6 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 		if (kstrtoul(&arg[strlen("microbench=")], 0, &iters))
 			return -EINVAL;
 		microbenchmark(iters);
-	} else if (str_has_prefix(arg, "test=")) {
-		unsigned long iters;
-
-		if (kstrtoul(&arg[strlen("test=")], 0, &iters))
-			return -EINVAL;
-		test_thread(iters);
 	} else if (!strcmp(arg, "whitelist")) {
 		set_report_filterlist_whitelist(true);
 	} else if (!strcmp(arg, "blacklist")) {
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-14-paulmck%40kernel.org.
