Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7ABC2474D8E
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-yb1-xb3c.google.com with SMTP id j204-20020a2523d5000000b005c21574c704sf39063964ybj.13
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=BX8wfJz193GSqr/b9XWIkf3mA/Em7T6TBWA5o7rRkPtyum3fNSCZQ+EMtBoRYTXWpD
         GyXUZ/JwMvE2brS3+xAXg4IznSR9NxhOh1epxHrY8kgUIX5uDTFL5aD1+3K9i9Wk1A7X
         yHGH3K3jI6FD/OWw+iPiQo/M3eOSpO5Vk9UY74e4PYSD/bxvAALNBIRW2tUDC2hxrpn5
         t/2zik5s+C6+npLe5bC+3oLozswc/hWkoDLaSxbBholwryYBfSrCQndsT2Sc/uE7dM7U
         i4r5H6AM/emvTQmnOr4fmUsRshYqUPfWcVNr5iQnmOokJfBIpRakVWKTubjqP8zCmfnV
         0KZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yeVMYuHOAtiYuCPU4Ivg2gya8afFeuH170eHAhhrEMw=;
        b=r6dYcWY8cXan7qzkfj0vl0VWpJKuC9aYlSkm7uv4qP7Wou27gZt8REBKJzCIcDbskM
         jlQtQuJzsSmxot4ZXK85OTMaZuGnU4QCZQ958cWqlFga7gbuBHBMoWcvWoUUN7RDbE9S
         x/2BbEQi8MGptDKBvvR1rDGb+xwRlZnCw0S9rddDYXBulmQ77M+QKxfOPJVYJKjCjX1I
         jIxodNQPwKzeHONhidnQaF7zYp0+IuoeNv0TahDhEabzod4TPvh48MhEUv+GscQU0vHe
         dIRjlnctJauJwshNJS+FSmf6W4mZ277buzIOheuf5KU4758QYflm+33WGnsJSomUlUZN
         iGyQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a7nj89vu;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yeVMYuHOAtiYuCPU4Ivg2gya8afFeuH170eHAhhrEMw=;
        b=cGkkq+x4KyG/U7s2QN+/EvD7xH5KQRiVKjFKMYk8QEdmgcnWdg40c6Z6Jlr+M08Egq
         E/FC9k2W/gLlKihZzk+lh22WKL8Z0HJ9BbYFOVabXQtR43KMQe1XWeV64yxFL7NdbmK5
         rz/0eIFD0RfrnBk5Fdift6Ny8OqE51u5I6p/i1Mu6TW+aNDHJOK1J8oiKu8qw8amjrDB
         d3rQ1dd1swzx6kRXqTWCZT1O9by7ua0ISjaMrboTgcgsW6NaEsvSmZHL6rzHv3sPu6zw
         BH2RJty3DYyVirXMLlYyJb1bzSDrihJh0MTvoHEy9exziLmKdNcISWsCLY9hkwc/zniH
         gxPQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yeVMYuHOAtiYuCPU4Ivg2gya8afFeuH170eHAhhrEMw=;
        b=QupDaiGbVTWl8dSaQ3gsZxMU5H+v9eS5UZPowhUwm4ostdtvMFk1R+P4K0eda9luTi
         LSg8wjEi8nTcWzWSCa5YUJKINuX1BI/dxTinJHkZ0lkDmdICntheMgmKr3Chia95c98/
         zRwTa479IQEsdve3nK1VrPxXTMLJofrcGWFK3bX6wTGAlq6YD3k/DWyWoTbigEMTXKg2
         SerBnOqI5ef+P16aF9jOAqZnovQeUlVssZYIYZDGr6QvpGodcYNaIosWD6yxGrXtCh21
         lGk/fA8jN9qCZ+pvtXG4hG+Cgr0NRhlbR6f9F+UMprQ531iZo1YM0pTiOzaiNQv+9k3e
         H5kw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZpoyAZKb/JDWG7D25AzdEePTlOcW/cI9+Gj0oS+NhcmWAkOyh
	5lnAxRN0NurHP/4AjY7ob4Y=
X-Google-Smtp-Source: ABdhPJzntV33OiaRia+Ji2uTWQrRqWTU66A/mXRDR8843RS8IF8mPFcK0OAqw7FA8IgaR3Rb+FCzEQ==
X-Received: by 2002:a25:a086:: with SMTP id y6mr1906291ybh.683.1639519486341;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2c53:: with SMTP id s80ls91433ybs.1.gmail; Tue, 14 Dec
 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a5b:d41:: with SMTP id f1mr2070274ybr.447.1639519485767;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=UFlKO47MmhD1o2FIlWoWcn7ZbWWJCrMjgpBJfYcsCwgYjzNupLnLS2x/vQsIkqd3F8
         215FYQHN7WHE1qiMcSZtOAwsai5J7jx+LyImePTfONaO58l96Fs0g1IJUzMGrUl1cTDc
         HJ/nc9V7w9sA6GbmocINEJhm/tOa2SM9rtP1bC1P4HaeXjQdS8T5C9MidIHKumJukQHy
         J/gECnHqQL0ivsGPf2mv0cUH+4XMUPwWgOOtBNOs7gKUFYZ1OhLqRYd1sGSj4wS/O7TO
         IDO+QS6q9P/WVbGhXPygv3b/ZkHJ5B5N/bcfCnXA/NoDCet48IYci0EaB2/7Lmv2Iz0H
         Ikyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=daq0Orr1gGYNi/L5TcXR+XeOzFYFQWgGgq2sRkp1/cU=;
        b=JyxN1ByqzilqVKUS/EymL+yzyKYUffNL6a7eNXAyKbnw2DTa3Zv1kZi545UOMdjWI0
         LVGPk6PkU3fhac16RcqBiDkAjDuxqvVz4fS8PXiiCDD3jSoU+1fV0PGHgBqTwaLFFVcm
         T6sCfJ9ZH0Gx0N/eyGCJDxogClH7uP3QuOlsg3V1/v1yS4Pkya76nl4ELrSez2LdiKJl
         /IUHB595AoANud/cNCgMX6Kol1wLAjYDfv/J4r35jvciuJTRTsrkM9BuQvuLLQb6l+xR
         dh3AS968NmemWFT9Z0LFYEhqbnZimnstFdgs/dJjcpt0IUfM+kpsripY9gZqMk6rOaTJ
         Julw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=a7nj89vu;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id a38si2016ybi.4.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 6D1E3CE1AE5;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9B2A3C34606;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 5E1BC5C0610; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 03/29] kcsan: Avoid checking scoped accesses from nested contexts
Date: Tue, 14 Dec 2021 14:04:13 -0800
Message-Id: <20211214220439.2236564-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=a7nj89vu;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Avoid checking scoped accesses from nested contexts (such as nested
interrupts or in scheduler code) which share the same kcsan_ctx.

This is to avoid detecting false positive races of accesses in the same
thread with currently scoped accesses: consider setting up a watchpoint
for a non-scoped (normal) access that also "conflicts" with a current
scoped access. In a nested interrupt (or in the scheduler), which shares
the same kcsan_ctx, we cannot check scoped accesses set up in the parent
context -- simply ignore them in this case.

With the introduction of kcsan_ctx::disable_scoped, we can also clean up
kcsan_check_scoped_accesses()'s recursion guard, and do not need to
modify the list's prev pointer.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan.h |  1 +
 kernel/kcsan/core.c   | 18 +++++++++++++++---
 2 files changed, 16 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index fc266ecb2a4db..13cef3458fedf 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -21,6 +21,7 @@
  */
 struct kcsan_ctx {
 	int disable_count; /* disable counter */
+	int disable_scoped; /* disable scoped access counter */
 	int atomic_next; /* number of following atomic ops */
 
 	/*
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index e34a1710b7bcc..bd359f8ee63a7 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -204,15 +204,17 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip);
 static noinline void kcsan_check_scoped_accesses(void)
 {
 	struct kcsan_ctx *ctx = get_ctx();
-	struct list_head *prev_save = ctx->scoped_accesses.prev;
 	struct kcsan_scoped_access *scoped_access;
 
-	ctx->scoped_accesses.prev = NULL;  /* Avoid recursion. */
+	if (ctx->disable_scoped)
+		return;
+
+	ctx->disable_scoped++;
 	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list) {
 		check_access(scoped_access->ptr, scoped_access->size,
 			     scoped_access->type, scoped_access->ip);
 	}
-	ctx->scoped_accesses.prev = prev_save;
+	ctx->disable_scoped--;
 }
 
 /* Rules for generic atomic accesses. Called from fast-path. */
@@ -465,6 +467,15 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 		goto out;
 	}
 
+	/*
+	 * Avoid races of scoped accesses from nested interrupts (or scheduler).
+	 * Assume setting up a watchpoint for a non-scoped (normal) access that
+	 * also conflicts with a current scoped access. In a nested interrupt,
+	 * which shares the context, it would check a conflicting scoped access.
+	 * To avoid, disable scoped access checking.
+	 */
+	ctx->disable_scoped++;
+
 	/*
 	 * Save and restore the IRQ state trace touched by KCSAN, since KCSAN's
 	 * runtime is entered for every memory access, and potentially useful
@@ -578,6 +589,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	if (!kcsan_interrupt_watcher)
 		local_irq_restore(irq_flags);
 	kcsan_restore_irqtrace(current);
+	ctx->disable_scoped--;
 out:
 	user_access_restore(ua_flags);
 }
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-3-paulmck%40kernel.org.
