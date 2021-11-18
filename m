Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGMV3CGAMGQEJI5FPJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id F352F455655
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 09:11:05 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 144-20020a1c0496000000b003305ac0e03asf3996167wme.8
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Nov 2021 00:11:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637223065; cv=pass;
        d=google.com; s=arc-20160816;
        b=m7sF3fEC8XHcKY91lTFAVS+xlauHevDmrXlcnFTZ1sR2s9rPDJg1oGRneG9McKE3Yh
         MXki4ZJcjSoVBRzFlPCl1cj0dd7cSNA1m5eQf1JaKVeQz0ciUe0XEObwaQgB92msWG0R
         xxr9d+JTI54E3b36URbaZAWZMC1kGrONmVrhwtsd0lzkOEyMSXBjKpf+MG59Hn0RxD9P
         vbjhaxTMtjngsE0npFHX9LpYPAe0/8XMh6qMvZ8+oLzhuX9AsAB9IqOs6FvuA9zLkDgP
         TVwOXu/67kBXSDWEFOZ9JdmIoNNFoKWRgH0RUYJp4MGndi9oKtNf9rDWKRsrUULUXuWy
         T3Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Ft6bhCHl/fQPoDt/uq3ijYkHxhU/UAPwRTsKH9ZNqa4=;
        b=rA1vYmfURAPbX+9PbprULRRvil8aCD4asBzBr5o0a8XrYc9ugXDhV/fEa1q4ExOtB8
         5lf+E00VSSSXJ2k3Dnx3PQG81qgEkO9F+PENzRD9wzHGTtgcLjmdDAtsRI9lz05RFjWp
         QkHQ6jzYP+uVn9Y0UJfHqWClSUiF/PdFPagvmyL3TzU9v+rAgKAUiSRRLzdlytlRsVvv
         Du6/E9sr52WiFj1L8gU3MipnEskBBRRHU3jy203m717Y2FUJaLb7r5CzS+dpwVzCD393
         q/nqxEfq81uc2yUscbCCCIzGRhYBdPB5IclTOeERpzcWEmn6tNEUQG5Dg4W3TTHmf01y
         ddzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U6MOwm5Y;
       spf=pass (google.com: domain of 3lwqwyqukcrg29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3lwqWYQUKCRg29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ft6bhCHl/fQPoDt/uq3ijYkHxhU/UAPwRTsKH9ZNqa4=;
        b=o6Hbw0cfBlOOK10UGVeo6D5wOnZy++r5PAIniQQqnfmEjGGnoTo/Oo75Kz38QddD0X
         YVS/wZKv4MfUVnkZRCI9Zf7PqAF2JpEkjfSb48ILaEIMviuLRRzayF/NNgVcyExncKcE
         5JkBt2F2bOXfLS7uiaWT+mx2jJ4Lro0Je62cLDcQ83iiSAzsDIQwz9yRCKHnZEsYKdKK
         Y+cbarKjLb2v3Eb6Ob0oDw3RnKEe9wUZ2Bx6ullyiqW7uXxB5MCd1CJ0zIJYxyYSK7bN
         wjKFJJ6b+w6fcybeIHn4B4Kgsz6U0EUF5fJTFJxUx7p3KHwoxzFBv7McdG89+4hNnm//
         fgVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ft6bhCHl/fQPoDt/uq3ijYkHxhU/UAPwRTsKH9ZNqa4=;
        b=X95GSQjlKsdCICUM1Cp8kl/W6qdHxYHjeHOaOOY2etrK5bCU8E2ssRMLD7b4kbjJmZ
         dzscpLpZHZEAI0s2uKP+LHb6OtGkQpCUYXvd8incJCl//J57zQcA603Se6QPX8Py+atl
         P3ljJIlGZ4S3e9CWLKg5piKu+PBXzrVC5EeadLWanSYvCw20OA+RUmOSqqoV9gUCHYro
         VNOXOd+xBrWJCtQAoROiLjl/oMkV/JgQK9iS0hKXCE+sgp2JkqWG7L8WLBKjHzwdFexD
         s4xdARcFcZn2BlcXbKoxWzAmE4JvbebP52DBdwi8yFJ+GxIVcvLjL0lQhcCqpgwnX/Ac
         IxAQ==
X-Gm-Message-State: AOAM5335nxcdxccHhzul83qEnTNR6TnCy9BGULJEkvtXlhNFYmcNDv6A
	ntEboFUZIn/I1LJ3FYhOdNY=
X-Google-Smtp-Source: ABdhPJz/OJgC0uFL0rTvcdX09JHHjbbDjjvIo1R0jlboHrmE9VWCJAudeHtVwVEJAVHOw0H+463F1w==
X-Received: by 2002:adf:f60e:: with SMTP id t14mr28498085wrp.112.1637223065795;
        Thu, 18 Nov 2021 00:11:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:770f:: with SMTP id t15ls1157559wmi.3.gmail; Thu, 18 Nov
 2021 00:11:04 -0800 (PST)
X-Received: by 2002:a05:600c:3658:: with SMTP id y24mr7849168wmq.161.1637223064808;
        Thu, 18 Nov 2021 00:11:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637223064; cv=none;
        d=google.com; s=arc-20160816;
        b=DPyV8u86Taqwv6RpaT8lRl6bxW1ZGzWoKIfRTiAh8tdseOMGb8C78xoUFCurix7nkt
         zmMy4/XC5gJpaKzrXTBwjWfOK5isJ9gnM/bUtP9vhruBAWX6eNgkUvkVOQHskHLiKztK
         zpia+RsW7HbcYp5CzEPy0eAseMRyayF+sGnWCkHVWw4KIsw1YXQZexbGIxGhRw4yi78K
         Oj9ALmng2N6Pgxe560hFEOg+T2iUvVhCPLt7K2TVm+UZ5wCxpZaCJAJFkAkCIaEVys1W
         DCheqSZ1KP3z9t7K72GdhsSzFMQJ3uEUG6Rxtue9f9gPZ5B1BARC+X7r9cbbz+0stOno
         QfoA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=cCyxJnES0DWyrpQ2J5vRoZu9DlHTb3+fL88VjiCWbjg=;
        b=h8dYqmcZefLC/H7Tiq1jtJhtXcVFb1dPcUrWWN4ZCWA+zMiYxHZW66S2AEdZwZjvxw
         YCha/xJs4ft+dkrX6Ax9HT4SkREPrykGTZI92lcJTtmMmDSLfIlvNGLxjnLiXs3OJO8/
         6RgjOq2MJkweMMSUy+3geBGxK66S5MtVtqPShY4Zq5Rf/RAu0l6FkLYW01m5gaX5Y/e6
         3IdmESw2NpurQburRNJvLJfYnfil/f5yOK3sToSryZMm7+jq0IWoYMAkRoVtCtZsJ++T
         ATQaJ3X46Tko2x2QSchy7MthGj9xYkAXuSJIJJ6vPUuBki+0WKfBXG2MvGrH5dbIoC3t
         SIIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=U6MOwm5Y;
       spf=pass (google.com: domain of 3lwqwyqukcrg29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3lwqWYQUKCRg29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id z64si55878wmc.0.2021.11.18.00.11.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Nov 2021 00:11:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3lwqwyqukcrg29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id r129-20020a1c4487000000b00333629ed22dso3990593wma.6
        for <kasan-dev@googlegroups.com>; Thu, 18 Nov 2021 00:11:04 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:7155:1b7:fca5:3926])
 (user=elver job=sendgmr) by 2002:a05:600c:3b20:: with SMTP id
 m32mr2109203wms.0.1637223063945; Thu, 18 Nov 2021 00:11:03 -0800 (PST)
Date: Thu, 18 Nov 2021 09:10:07 +0100
In-Reply-To: <20211118081027.3175699-1-elver@google.com>
Message-Id: <20211118081027.3175699-4-elver@google.com>
Mime-Version: 1.0
References: <20211118081027.3175699-1-elver@google.com>
X-Mailer: git-send-email 2.34.0.rc2.393.gf8c9666880-goog
Subject: [PATCH v2 03/23] kcsan: Avoid checking scoped accesses from nested contexts
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Josh Poimboeuf <jpoimboe@redhat.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, 
	linux-arch@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=U6MOwm5Y;       spf=pass
 (google.com: domain of 3lwqwyqukcrg29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3lwqWYQUKCRg29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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
---
 include/linux/kcsan.h |  1 +
 kernel/kcsan/core.c   | 18 +++++++++++++++---
 2 files changed, 16 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index fc266ecb2a4d..13cef3458fed 100644
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
index e34a1710b7bc..bd359f8ee63a 100644
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
2.34.0.rc2.393.gf8c9666880-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211118081027.3175699-4-elver%40google.com.
