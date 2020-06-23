Return-Path: <kasan-dev+bncBAABBONAYX3QKGQENUM4KHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id A3D6C2045FE
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:38 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id l21sf4941424oib.20
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873017; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rl/qAhgFXQO/SN6kvQm5snhg7VHqqFfP/ICAQPux9c1yp8lsDUIZtpatosBoav4rvy
         RCRDiB2aqGymFQH59pnykvmm/A/vzmGv8La3k1OdOaaYyFubMTNtLyZpCwwDZpg/BQ0C
         mq+sdO5h0g7ZF1QvEHs7Mdw0afWTLi3+6TKWykLm4vwr87FliRGp6b9cJPvbpxyyRVF1
         C/JTPi+jZzhHnFz7jmZPXSBzR1eYzi0/eU5eAy0ivy4QrcuHVj5QUkpL3CDtN2VqNS7W
         klUgREd5DEbJ6RowopuZV10GE5go/qPI9/fBvO+TXLN/EkV9r2aM08Z3FDEAp/EL7edj
         NegQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Od3Mue5ZqR1sRxez308NBAfREuSRRxx0puyrgXX51cI=;
        b=b/vjlRxSw/sGoGkJoH/KgdAZb143/md/J9njcEoxns9dIv0eWUyGQGU7lcGhS2r98q
         2AVjw6cbYUH1qrMYKuMd8dqnSRG+YPQJfci4iJmmMHJC7KakVwcd8qZeC5aG/Ct6MqN/
         UwceX5KdeLvsJIQKFLgvIcuquwiy0nw/yI43K9HsMGVzse2ai/V2BdEfumjaOjF92bxa
         PSaH8Hvfa9ExjpzAxtzlXUn2K+QpH3DThbjrmtw7u57RsaCnWljZz+tVi90AhqpjCc6r
         8y6m1XqfI25cYJzfIenvDQWfgnctky11RcIlgXCDIND13fSXig+qKGSEQd6E3X4x5kzJ
         AdKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=zS5iaK9L;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Od3Mue5ZqR1sRxez308NBAfREuSRRxx0puyrgXX51cI=;
        b=QlmIlT6KQDqEN8IzuH+OxNZey3HYS2rXHmADBHlRNwxHze6ZNUdSM8Aa0ORvbphYhO
         4Jt3gHnGpdpxIq4KSKLB4HRbxco9zaoqTAvtueJTTsbkMeFfoiKBvxMLbMIaD6Sz0dgi
         FnF/uPQv5Vq/+UETZ30JB0Ef6/g3G6T8odRE0XQXGeLrdOwQcgS1TBNcUoPBEpUsdKnk
         LFSlCveJoga6pQFecOaVy2vrD25ceyZR8IqNizn6AQGZEVMZHilkuCSjmV/Z5pPE6H57
         6Hz0F9fxuOzko5zP1C0RiwEWHBiypOv5q9axsPcMHuoN50TqcOCNSyK1FRxURuV8v+Yu
         +iiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Od3Mue5ZqR1sRxez308NBAfREuSRRxx0puyrgXX51cI=;
        b=BiXofjiFaCZUukisAzMs5QlZsAiUOav+U5o0r/rX/i7sM0hkTlk5XgYsTg99KJCLv2
         BMfK70yHqvwjS71D93gww2JamJnPpX3H3a7Ow6682BPrL1pGWlGGAoFlmL7RhAPrYmGR
         QM3HKfjTVnrHyiIGz3F0rtd8xJGx4TdK8PX9/MWvpmgT0qTczNOphjrgGloP/cYpdWso
         6h9nIQPSbQTqHR5skV4ZujNtIrZ4iocqf0lCQQyniqxNK9Z+iuc+Fo9WLd8itw5BfXnA
         imDjwMx2yjN06tJQemDwO5Y3rdMZRR2wvCc/JR3pKbip7XS/pVvXtaIPr4K70XYP5u0u
         lilQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530b+P7+IW/3BohKRNF+s7Smoiu65V6q+q3xJYkAcvJRmayy+bhF
	zKErAnctgcbWfjqksVzzRco=
X-Google-Smtp-Source: ABdhPJwhPttRA4/Aft1RYMb5cY0eoBp/AnHwz4GY4b0Qfg1lmuoyFIXaSNpsOkQRbhWkFN3J7FBXiQ==
X-Received: by 2002:a4a:e496:: with SMTP id s22mr16526366oov.67.1592873017637;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1446:: with SMTP id w6ls4005701otp.8.gmail; Mon, 22
 Jun 2020 17:43:37 -0700 (PDT)
X-Received: by 2002:a05:6830:1bcc:: with SMTP id v12mr15750062ota.301.1592873017372;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873017; cv=none;
        d=google.com; s=arc-20160816;
        b=kZR5pzFMhWwy+afBwImF394xBJ7rNWVyv9V10fnjnqAxtb/uEe/gC0KM0xi8GnxUl4
         Qu0NKYbDj65wulYvcEGNhljNmMe+7IByAxkrfy0O27j61lJFMpXk+A6gsJfK4vHW324C
         PmRAri9T409BM6Twckdn6D7+KsP6/WWwhNJ8tA73cGXWGaWuMyScp4Tarxn6Y8C29+/V
         JzrpvkL0yPL10kztUfRZY7vSqOW+Czh0ED/2qj8t5O0DfhP5/+lVDCg90rmYnVCVct4C
         5aBRvXOR0TxmvAXmaebeKZ1wzwBqEGbS6SzzpgXaMuAhbVO5xlqJHU6Xuadc3JENVMHK
         nUiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=No599ZgufHrwHpG3EgkUN6e1YBLdRg38pqML6RTSsIw=;
        b=zOiuh8hXEi/BChum+PzthkfeTLtXVj5/DsQ9wbKhAcYHT4yEr8aX6IyA8IusCw41dm
         D60D65QoU8cn62ELsAMYiM4flQcAQLuJTwFnayudTU53FQsAgfPCE8dXwkl+jfR+g6Yu
         43jqZ0hyzhFzA8dUuKcI+Q//6o4CRO1cyz8GNRItcNlWP+bGxe0N2v6mhMxaHQnJDhJZ
         twpm2BuNCI04UkW7NWrfwzBOiwzLlxuooBkr0YH3btbcgOyI9zkF6eJT2KTGNy9Vntz5
         CBeuHHGLXgVs6Zc2NJVMTOBPhFqQD8ZTh/zAnfzwk7bdaz5GozJkmQQ0zaIP3ifgpUd7
         mQEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=zS5iaK9L;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f133si948567oib.5.2020.06.22.17.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9A159208B8;
	Tue, 23 Jun 2020 00:43:36 +0000 (UTC)
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
Subject: [PATCH tip/core/rcu 08/10] kcsan: Rename test.c to selftest.c
Date: Mon, 22 Jun 2020 17:43:31 -0700
Message-Id: <20200623004333.27227-8-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=zS5iaK9L;       spf=pass
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

Rename 'test.c' to 'selftest.c' to better reflect its purpose (Kconfig
variable and code inside already match this). This is to avoid confusion
with the test suite module in 'kcsan-test.c'.

No functional change.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/Makefile               | 2 +-
 kernel/kcsan/{test.c => selftest.c} | 0
 2 files changed, 1 insertion(+), 1 deletion(-)
 rename kernel/kcsan/{test.c => selftest.c} (100%)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index 14533cf..092ce58 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -11,7 +11,7 @@ CFLAGS_core.o := $(call cc-option,-fno-conserve-stack,) \
 	$(call cc-option,-fno-stack-protector,)
 
 obj-y := core.o debugfs.o report.o
-obj-$(CONFIG_KCSAN_SELFTEST) += test.o
+obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
 
 CFLAGS_kcsan-test.o := $(CFLAGS_KCSAN) -g -fno-omit-frame-pointer
 obj-$(CONFIG_KCSAN_TEST) += kcsan-test.o
diff --git a/kernel/kcsan/test.c b/kernel/kcsan/selftest.c
similarity index 100%
rename from kernel/kcsan/test.c
rename to kernel/kcsan/selftest.c
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-8-paulmck%40kernel.org.
