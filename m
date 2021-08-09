Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPNBYSEAMGQESFDMPTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B9723E44C2
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Aug 2021 13:25:50 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id d35-20020a17090a6f26b0290178ab46154dsf1880429pjk.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Aug 2021 04:25:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628508349; cv=pass;
        d=google.com; s=arc-20160816;
        b=R1VslzjBMS/aflXg9XeVygVc64Wb4PDIV/uvRKiIAd3KKrGx/Fj6lvnTP0E++p2x+7
         +EkFSjg1BuVVzf7/h/ornvydLJPffRuDlRnuvpsjnVN7aMp6AY1o1sNM6Zwx15JVs+Ob
         c9yYPkJ7Smnpt55TNuphzI3vKxCEiL/P1152ZcMT2wLNE5H0iJWAWkGnQUNDk330ovpI
         XeLXZCK86+Uln+bDIF7yRWbYpy79T44Bd2cdxzRCDZ9EMk6mygNfk7pIfHZ2ml1vKF7k
         bwpEOUqFTOL3t5YJ6w/+xEovwQohBx6GdQEhBZPf9bqrvlsYctB/YH6VL1o+WPtg9/NF
         jzdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=2kOJlTnFxqeOf2o1F5wdg92z2c/dipmmxEZdwgRpeUM=;
        b=xC/DzUrD93xPcst0YQ8tV/MUS0loPnj7V1gYi8VQqE1MhTV38EE/wBJqpadjRwwJiq
         fjoaQDNrakGwFsmhoIdNjYU7Gabhs5Z7y89tp7EUgJfCoHOWX90Q2ccQYlXUHYrGNzx1
         CzthNQJ/gRrWtoWtwgvZ5x/N6ust9b6TBnoJQncskC3BjY56vWzABazQBUgFXST04Caw
         02JuJ/BMclk8+RhHwRprrU9tgyLvZ+R03Hv36ljyZAD+u7vNkgcy9Y/henDuYsZHETSJ
         uiAhGVyHC1thlyWbhUWRJxC3F89QcTWryltaU5Myk0J0v/tPP3cRdURdknpASsTcQv7w
         DC/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vHWSpBBw;
       spf=pass (google.com: domain of 3uxaryqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3uxARYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2kOJlTnFxqeOf2o1F5wdg92z2c/dipmmxEZdwgRpeUM=;
        b=a5FNURlmQI+8SFzLG+Mva9krwpJ73ZkPFqzEWY1DjalLBxx3t4OlirjAh1FrCBZ+sH
         Zu2rEu+IYVzfRTPx2Jx542kOPuPVSOXxGaMO21H7gcQyoudFTVIQcJxhHhMrFcsJU1x6
         hMKYBMWCvoV+ImE9s4Nm5enqfrT7VVml/7d5tOWusKMx6RhW14pSMy3xCMFg+8U7zqMU
         +vvTrnOYwtHBWfzzjhe6wGuE1OWC8cvn4ug/Iy63yobBv+GN7Q4Iz/kpLcwZvYohe+Qr
         YoDyhWUNO3rNKK0K7aYpuWvNfTiVcrXDdAPoK+RMWITNBy7vl/oHwIO5cUmHRgJWeyG+
         xlMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2kOJlTnFxqeOf2o1F5wdg92z2c/dipmmxEZdwgRpeUM=;
        b=OfMpO413FmFQ9d6VBxmAAV6/1WGl1Z8JUByQTkFnQH2UQAEfp0PkKxVQXsz7TsYsF4
         jixF/fjmVF+Wxiu4QkhTruiHpy4LEU6NiK+gfF31LalU08/6PXlAo+z4SpXd/Yy0p7dm
         tLoPWnX6mduJwZ3n2pCcAsup8ssL2efWYHogwNfYtENKJXd5yl6IX6CnpmCPDZmnrNfV
         T1IU/DZoUlLj5ZqBe6+SBic+HOpyPl85Ph4/DQOTzz4zkPBpLIvJgTjCarywpg0rmiyv
         5EclbiJJnWikpOVEVO+4QeJwl1ERorubb6hWDHDCX6ZVFUzq5WBnaLfedNIG200XPeXA
         nREw==
X-Gm-Message-State: AOAM530vT2X7FRMuEhgIXWHtC+CVmxRg09ojIjj24ou8Yoe4tKNzM2pR
	lYuicinegLCH5PgdQiFfhuA=
X-Google-Smtp-Source: ABdhPJzj++LvnZBnWQ55zBQKVdEJU3qaJVqVAGkWgAnuSKAAJbHoCkDfSt7wYp145VeLcO4CeN5qwg==
X-Received: by 2002:a63:7209:: with SMTP id n9mr534990pgc.253.1628508349150;
        Mon, 09 Aug 2021 04:25:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:e643:: with SMTP id p3ls7163199pgj.6.gmail; Mon, 09 Aug
 2021 04:25:48 -0700 (PDT)
X-Received: by 2002:a63:494:: with SMTP id 142mr71207pge.242.1628508348541;
        Mon, 09 Aug 2021 04:25:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628508348; cv=none;
        d=google.com; s=arc-20160816;
        b=hTrta43sjXwNoIKZdwEec93x96oyhjxWfJ6TxfV9wKff5e+nFK1BGjLBtYdW9Wi6zc
         q9JlKQwI6PfrQqBgvnfaTMDgAEwgdb9wKDTYiKOa0Zh+hg4jx42yCzInnpmemZngTyji
         /MKe9/ty7gkhVr37zO9G3Y4Isiuu/6MG3vsKPLRoyCClea5Zpmp/tmf/2la9rqTfJnDN
         8PWQhmmrkan87grtHpUBaBkDe+O3b7ahz7BLxEL1AfHZGzEN45qSe3U9mxhKLuBDVOKn
         9MAYbBGWAKYbbn57jCTASXYe4koXoHfRCtsDS2U7F1m4REJiJoHsybDW7Vmxne74rC1s
         EJ1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=N38MLkGU4ZaJtqmGfMRepocDJIz/MIPtNTpAOH3Apps=;
        b=fp1UVjqHtqfVhcMAWI6RlwNpKPwQ7GvSPLLMEfePcBZ2Yr6iQw3Lsc3vCxpsvx/PKb
         i01ADUGABz1QfcMevNfm5ya4aJimPCPDXNM2DKZjC9O331DnC2vvbaj4N77iVemadg8i
         4NnDHaBHf/Un4wQwsoZiOSuO8vUXWgpqgybt85LeK3Wqa+JFWUdf8UaLVUvWkpy7d5rw
         q4ABriAsIVEimixZoIuB0OjrU9gwx7If3A8UAO/27FDW6HveaFAmoY1dprlyWSh4TjSK
         oqTghgaZqX8wJ+AxzaExmNeX61EDLcSxd8cBYvV5OJuTVgaWK+t9J932JEYxf5yRw3/D
         a01g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vHWSpBBw;
       spf=pass (google.com: domain of 3uxaryqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3uxARYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id i123si157360pfb.1.2021.08.09.04.25.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Aug 2021 04:25:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uxaryqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id y125-20020a2532830000b029058328f1b02eso16896939yby.7
        for <kasan-dev@googlegroups.com>; Mon, 09 Aug 2021 04:25:48 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:e5a3:e652:2b8b:ef12])
 (user=elver job=sendgmr) by 2002:a25:f310:: with SMTP id c16mr28780799ybs.464.1628508347795;
 Mon, 09 Aug 2021 04:25:47 -0700 (PDT)
Date: Mon,  9 Aug 2021 13:25:13 +0200
In-Reply-To: <20210809112516.682816-1-elver@google.com>
Message-Id: <20210809112516.682816-6-elver@google.com>
Mime-Version: 1.0
References: <20210809112516.682816-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.605.g8dce9f2422-goog
Subject: [PATCH 5/8] kcsan: Save instruction pointer for scoped accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, dvyukov@google.com, glider@google.com, 
	boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vHWSpBBw;       spf=pass
 (google.com: domain of 3uxaryqukctaqxhqdsaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3uxARYQUKCTAQXhQdSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--elver.bounces.google.com;
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

Save the instruction pointer for scoped accesses, so that it becomes
possible for the reporting code to construct more accurate stack traces
that will show the start of the scope.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kcsan-checks.h |  3 +++
 kernel/kcsan/core.c          | 12 +++++++++---
 2 files changed, 12 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 9fd0ad80fef6..5f5965246877 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -100,9 +100,12 @@ void kcsan_set_access_mask(unsigned long mask);
 /* Scoped access information. */
 struct kcsan_scoped_access {
 	struct list_head list;
+	/* Access information. */
 	const volatile void *ptr;
 	size_t size;
 	int type;
+	/* Location where scoped access was set up. */
+	unsigned long ip;
 };
 /*
  * Automatically call kcsan_end_scoped_access() when kcsan_scoped_access goes
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index bffd1d95addb..8b20af541776 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -202,6 +202,9 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
+static __always_inline void
+check_access(const volatile void *ptr, size_t size, int type, unsigned long ip);
+
 /* Check scoped accesses; never inline because this is a slow-path! */
 static noinline void kcsan_check_scoped_accesses(void)
 {
@@ -210,8 +213,10 @@ static noinline void kcsan_check_scoped_accesses(void)
 	struct kcsan_scoped_access *scoped_access;
 
 	ctx->scoped_accesses.prev = NULL;  /* Avoid recursion. */
-	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list)
-		__kcsan_check_access(scoped_access->ptr, scoped_access->size, scoped_access->type);
+	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list) {
+		check_access(scoped_access->ptr, scoped_access->size,
+			     scoped_access->type, scoped_access->ip);
+	}
 	ctx->scoped_accesses.prev = prev_save;
 }
 
@@ -767,6 +772,7 @@ kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type,
 	sa->ptr = ptr;
 	sa->size = size;
 	sa->type = type;
+	sa->ip = _RET_IP_;
 
 	if (!ctx->scoped_accesses.prev) /* Lazy initialize list head. */
 		INIT_LIST_HEAD(&ctx->scoped_accesses);
@@ -798,7 +804,7 @@ void kcsan_end_scoped_access(struct kcsan_scoped_access *sa)
 
 	ctx->disable_count--;
 
-	__kcsan_check_access(sa->ptr, sa->size, sa->type);
+	check_access(sa->ptr, sa->size, sa->type, sa->ip);
 }
 EXPORT_SYMBOL(kcsan_end_scoped_access);
 
-- 
2.32.0.605.g8dce9f2422-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210809112516.682816-6-elver%40google.com.
