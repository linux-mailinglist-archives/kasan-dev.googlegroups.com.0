Return-Path: <kasan-dev+bncBAABBONAYX3QKGQENUM4KHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 57A9F2045FC
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:38 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id j16sf14168787qka.11
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873017; cv=pass;
        d=google.com; s=arc-20160816;
        b=X8R8T2EYQx8B3O248qAkmodjksi52jBLYl/L3+zzJwzaGpEb5T1y/g2Q67q3NJNq/E
         uYPyLf0FfXscxPwBz6q4sxuhDw/INfS2gZzbuBFiSJgiu5/L1V35Bh3COBCKlEs71sEq
         8W3R/Hj4iLOJV1WshKGMW006gthcaMgtisxRAw2OEhO7O92HUjIa96qQ1Ehc+wmngb98
         mZ8wUXqBK9OO0frQSlzVlxpLATHl1iGxN6GJrxcG64TdXy4mjorJNydng89vLCNcFmTR
         +1tzhOdXaDWYL3eY4lb49Kyh3PmgVD3NbdJ5Ar0+lssVy9uAFRqT6oikcBqY8Cyw9kqI
         1+9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=deHDEGO9pP4OllVK7CvJ0UsAGFMNuzlo+QJu81m/1NM=;
        b=DIW2AwHub/chJhNTDk+65frS4/7MC9cuOt7tH1wrbUIwq16dVb9PO1RFVzGq+Fy2KC
         3sUrjUny4DI9FGZd6BCODtvKMacw3Szwtk0UlvwGBcZvvSH10MaD7j0uPES3m7LoEoJS
         2Hiu1mZu6+atiDAHRwe2bWREyoY6X63vL04txCjJVNjA5yBdgrCY06EKSlTmaB+a0Lvn
         bya7ixJXqU2WQ4vIG9JVlBz7HAF5/SBVLlYP8MU/LUkArZdOj13Q0FLw1SKQp0L8x8wG
         uEFx6NhSmZ0mYGu8ONXe7NbVnNAPoiFQwNv+WLOPaQe9aTBUK0W9mUiKE39j2KeDAxsS
         fZlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=q5W+mGoc;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=deHDEGO9pP4OllVK7CvJ0UsAGFMNuzlo+QJu81m/1NM=;
        b=m6VmiBj6O2urpc/n2hNJ9bUjeuGLhiVaTK8itBrtuJ6ULlHNltNzmYc6giZgvGhdso
         5GE1T01vdusMHtwssdwkJ1MoRz051O2gXuGZk4PiEtpfVfE4JuV1soJ4rSyVfEinyapb
         EQBXd1R5+9LsOoEHfHCC1PMZPgEYABtNWYqBzAd5zbHMrBEXb6ikGt4ZyuI76gSSh24/
         sjYfyLjuBfbkNr6JhnP70v2c9qGQvAmS62qGulHu2SrA1IOoTboMbPmwbWfxsIkONhD7
         ddpy2eyB5lVL/1o/7DMaHiS3B3pJjv8IWv7sAnpbXJjQh26jto75OU9bpqYWDctwUSo2
         j10g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=deHDEGO9pP4OllVK7CvJ0UsAGFMNuzlo+QJu81m/1NM=;
        b=mWW02JtdI/dmPqCTTDXh67IO661ZtH32HVLRGCLli+eP70cxNCJHSe/8Ng1Py2EyfX
         YFeCy7oYLrgzqCtPOJoyKeesmq3F70fuJo0tsy3UjXP2yf4yv8eKigX4U7JON1+P41sJ
         k6peiCfWrh46SU7DIqLlR2+I2H7ve5D8zy51S1e+zchx0qgxeAhIG1SOoUTbXn3CRyv0
         7rIuMqACtwaP833IVwU1g2p13ZWJvYpFYKDiBayqyrnOkpiF4F7FB6Y1oSYZ/Vo/cCUH
         5ZL3w1BDDurCUC8LwPISfHrpieG6jneaLCosxyc8rALb0Z98sZ66xZsQ1KACrYLdT6Wl
         Hofg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305gsWQ2GBP4kBcIKe4bguIZ+S7n8wUPzEetfZvVrXl1rmU2MCT
	tVqrqnojAzRxakpA73CRvIg=
X-Google-Smtp-Source: ABdhPJwyF0dVgexZ1WXecZDGy5tX+hkoXEdJ7AsNreoWpqno3TTiguaUW9qUy6KMT+PNgfihEAZsEQ==
X-Received: by 2002:a05:6214:848:: with SMTP id dg8mr22716793qvb.152.1592873017448;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:2ac4:: with SMTP id t62ls1365560qtd.7.gmail; Mon, 22 Jun
 2020 17:43:37 -0700 (PDT)
X-Received: by 2002:ac8:1ac4:: with SMTP id h4mr5994180qtk.249.1592873017165;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873017; cv=none;
        d=google.com; s=arc-20160816;
        b=i95FLb0/+dRvFNVY+jUJAOq21TxAtNV+Fz6z7Wgi0g01VMS+nkAyuatneBCOyQGave
         GqJ6l511juafBsRcQNZgv++eVz/oIFOCKzd1vMmHqchqnaDHIr//cXaIFMAADSJ02lGZ
         LtsbvEq1KmUlXI4EVCtLFc7IaRachPg2h2wzpqDpRYrdLw3XxQhv+fXUD/0fHSsc/OP9
         9pHcTF33Ao/WndBHB3b/csovCrlllC1tsZLY4Pe9O2mkgEXGOCIWRuBuHtcbS57maFzr
         LKhb6mgWcdspGiHqOdGSLv2Vzj/pL+f1zz26UTsrQnD5h1gO/ih6soxfapoZfgzmgLAq
         XcRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=LUGFFwF9FlXeldbQGGBIwaBr/eO8So1nxdIPvQvxoxA=;
        b=gvGyr7uIz3ERp7PItlE6JTPYH0bXIKzmeu/HM6A6/tqH1lpDMsAURFitofAhlqAshL
         oIeQVpP1vJDrYpDiOxHAmHygJEKHKqGwY41Vqe6dLSD6rEcIJmB/2k4ho3fTTcH0LTry
         TIVPeyJ//2vP0fFWTGzKlh4AdIxYtBPPrhBlxtQLIbUrYfp74CsUc+xK+yiiGrFEJpNc
         3T1CR/bl2lCEmsfYqjpDt5pTiHyx0dYYODLKtVwSklVtnaLh1zCYyxZAmF3SxgxEkJ0d
         CGIHMuZZAsxZlB6izWfQ/r7+F6rkqMS4kCsMMPEMoKZCv1ZADQCq6IZAkIoaU9jf8kLU
         EKaQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=q5W+mGoc;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m1si1181515qki.3.2020.06.22.17.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 4D099207DD;
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
Subject: [PATCH tip/core/rcu 06/10] kcsan: Prefer '__no_kcsan inline' in test
Date: Mon, 22 Jun 2020 17:43:29 -0700
Message-Id: <20200623004333.27227-6-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=q5W+mGoc;       spf=pass
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

Instead of __no_kcsan_or_inline, prefer '__no_kcsan inline' in test --
this is in case we decide to remove __no_kcsan_or_inline.

Suggested-by: Peter Zijlstra <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan-test.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/kcsan-test.c b/kernel/kcsan/kcsan-test.c
index a8c1150..3af420a 100644
--- a/kernel/kcsan/kcsan-test.c
+++ b/kernel/kcsan/kcsan-test.c
@@ -43,7 +43,7 @@ static struct {
 };
 
 /* Setup test checking loop. */
-static __no_kcsan_or_inline void
+static __no_kcsan inline void
 begin_test_checks(void (*func1)(void), void (*func2)(void))
 {
 	kcsan_disable_current();
@@ -60,7 +60,7 @@ begin_test_checks(void (*func1)(void), void (*func2)(void))
 }
 
 /* End test checking loop. */
-static __no_kcsan_or_inline bool
+static __no_kcsan inline bool
 end_test_checks(bool stop)
 {
 	if (!stop && time_before(jiffies, end_time)) {
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-6-paulmck%40kernel.org.
