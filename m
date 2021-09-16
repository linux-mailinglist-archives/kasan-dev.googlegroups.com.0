Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5NARKFAMGQEK4LQ5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 3020C40D0E7
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:51 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id f10-20020a92b50a000000b002412aa49d44sf2132665ile.4
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752309; cv=pass;
        d=google.com; s=arc-20160816;
        b=MtdkN3n/ChvQ2IdPa95GxtRNWqG7C8RcYurHhMo3V772Ubo8kN2SQhxSWgjal+u1gY
         k5eSSVxcRcHESvE9lqXFh/4uE4HPD44gsWTdQ8y7paZq3/eBUuTrlzUARYlvQTP3F3td
         UPT3VCqYmfZN6kliChgHxwNDryngDvSTXeTJCYKGBzdSGKQttM/qg8oDfjROWRY+Ls7K
         zscBkycds5LTLn9UQDRUUhxgxQ52NfqOcIr3BwlNmb/1HnE4gnw7mKtpDz772+56JMg7
         WUz3P2vGDfZj6oeXwbHRA2c3qtm8FW8sIa/Dvu6+2P4eNHb/IfZ+jG/f3LUJV0co22DI
         7i0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=wu3Kbd9A2w4l7XtbD0dbf6ib96DE+hmg0OmU2iE57o8=;
        b=w7q5zO8kH6Mtr6bbtJkVUPHyPcpFk1SujHw0MVYAOHyD+bDPuH/XXpl8bxxvOASHMX
         ftt9WTs97B/sAHP24+l6JGSfUIj31NS+DWdmyWix6aeO8jMm+zbCc/kT8iRLvyvcTCWb
         tb2PS1yfRcITDQjUYoIi+fVuiPmZc8XRjhufxUzdM7ZcwnPCmkNCVUDcvX4BYOwFjI+P
         nCnJQ9Wqs8qLYxjSoGN79E9JVr+fBC1vdMaUfKKhWg10mxJfKyDs3jTjOfz2fKkQ2pnH
         SSpMyNTZNHM1j/s13kmvjCqJig+rdftXQWD1Yvc7tdE9Fcb5mj5Oa65D5RRLBbqK6nHb
         lxgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P2EtT6Tz;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wu3Kbd9A2w4l7XtbD0dbf6ib96DE+hmg0OmU2iE57o8=;
        b=GPu4XhhS1eTonjtQOlatjUtmiqb2zYjyBGyrMQSKB405xDTyAwZ5pDSAwQ8ukSv/b0
         UzOFqKkeHJlGp1thdQAqDUg/rFy12RW5BLhSHZeNpneoEZrYFFmiGekVQZzNlXKU2/47
         4QbonI74Voax1J1UFgZKUHBGZYiNfmYK+b/+f2eFjdfXddPrZF/7CINQ3RH7H9sLdSR7
         rGOaolCt0xlXk3o2kpEL08mBINp6kgUdRzJoOBugHwH/d1/lpTGJsFIz+lIBFn4DKETe
         UhCovp07h5AiV1H67h0TxfiTetu+9wsGTuKU1CP/nqi+nPTlVfYaZxj2Dn11L6xf5bNp
         WMxg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wu3Kbd9A2w4l7XtbD0dbf6ib96DE+hmg0OmU2iE57o8=;
        b=a0y0IjALkvtscDqKEoIroOxTBUWJPlEIenL+1ycobi3b1t726ips+anpRDdPQBiap0
         VThsKKrHWYC75IWudUnzwEMLo0zXSFF4lnuGZIOSDVDldjqcZKZKb/5FHGv3yTzxw1wt
         QlhN92ZECe6XhO6q/sh6a6bfGGroNaYt4S5uM1dgHHpP5MTptBVlX6dVmD5EFZlx0ev1
         Ms0QhhPafC12Betli4PON/oW2cEvvmULL3EUofPsE+IG6XPo8TzrwtSd0c0BITMVvRfo
         dnkSn1JmCQuSP3wp4D6J4DkTJUWq46tgQVhXxQBLN/zB1fHUeC7imYYvfOsZz/fWpm0O
         tVgg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531WHXYV4x4Mpk3Jc/iNc+GtAH4/jRgrKISBdCA0xkdA6tHH8iot
	EFh5ZShV45hJGf6GsXp4esY=
X-Google-Smtp-Source: ABdhPJz7E0jJxv05y2zYN/iOEBkN6vtJsukg7wxj26cLNgTLhwt6vGYrCeEXJgUhqW2zduzqCr6epA==
X-Received: by 2002:a05:6638:3046:: with SMTP id u6mr2186375jak.35.1631752309766;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:198c:: with SMTP id g12ls455224ilf.9.gmail; Wed, 15
 Sep 2021 17:31:49 -0700 (PDT)
X-Received: by 2002:a05:6e02:921:: with SMTP id o1mr1911257ilt.289.1631752309426;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752309; cv=none;
        d=google.com; s=arc-20160816;
        b=hxkC5+0gd40r6xQrqN6ILDvrAXScGtN0pXFguZKfurj9zzL4hqAZ4XolpMsLGquIGt
         M+AqT6W1DbShKEkvwX5uPS9bfiq9TPKg46kVtrWO9DGJTVLP+ebyRW1xVglj0slhSlRO
         kS78Z7+MB9V1pueWVMK3WjucAiThwCLN2Kh6Mut1Gw0WrEyxD/Xb2JUBa7W7rMHqCELM
         Q1CMKWGnWA8U2OXzUWfaUm4t5faOLBh045wfsY0ktnmMKMBS6/cC9czLntdIhsB3S2Jg
         w0Lrr+t4bW8Is/bvmS5/XnF93EvKcWogSC2PiH7rmuSg9t9h5E0yKMrMiaEZML/hSKXl
         rjTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DIUxJJ367Wtil/CNKd7ROZw6IR4DWPS5b6JCCod4Fy4=;
        b=r8DbtmdxKzrQLzO3DYiBLjKJRB1m4itbw8GvcQ08/QK1eDruLoGjZcEZKdmyvl753U
         3owTV9aB3yhsiMLcluFal0F0FXeJknhk7vxh4ryaXg6ZanTP9WVi3B2K889j48TD7U+Z
         ViVce+b4+Sj0DGW0/NfdhOMLx/A9AjVr3mcYD6bpJpjTanHKO6tH8j2mBJtMWrIKskRH
         +1q6ng/aXM3UkorR2zUjKs5utxRyQGqRPCblXVXUHFhPaXWUUVXuWnkkxZ87Eyh8NMck
         oGT1dXNLq4BIKd4PSD6LcKvLboERDC2GXsYxb3kssjHcbb86WQjOhPWIOhbwBBFKFTIZ
         8u2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P2EtT6Tz;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e16si199001ilm.3.2021.09.15.17.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 2188E6120E;
	Thu, 16 Sep 2021 00:31:48 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B9B785C0AD4; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
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
Subject: [PATCH kcsan 8/9] kcsan: Move ctx to start of argument list
Date: Wed, 15 Sep 2021 17:31:45 -0700
Message-Id: <20210916003146.3910358-8-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=P2EtT6Tz;       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

It is clearer if ctx is at the start of the function argument list;
it'll be more consistent when adding functions with varying arguments
but all requiring ctx.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 8b20af541776..4b84c8e7884b 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -222,7 +222,7 @@ static noinline void kcsan_check_scoped_accesses(void)
 
 /* Rules for generic atomic accesses. Called from fast-path. */
 static __always_inline bool
-is_atomic(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx)
+is_atomic(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size, int type)
 {
 	if (type & KCSAN_ACCESS_ATOMIC)
 		return true;
@@ -259,7 +259,7 @@ is_atomic(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx
 }
 
 static __always_inline bool
-should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *ctx)
+should_watch(struct kcsan_ctx *ctx, const volatile void *ptr, size_t size, int type)
 {
 	/*
 	 * Never set up watchpoints when memory operations are atomic.
@@ -268,7 +268,7 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
 	 * should not count towards skipped instructions, and (2) to actually
 	 * decrement kcsan_atomic_next for consecutive instruction stream.
 	 */
-	if (is_atomic(ptr, size, type, ctx))
+	if (is_atomic(ctx, ptr, size, type))
 		return false;
 
 	if (this_cpu_dec_return(kcsan_skip) >= 0)
@@ -637,7 +637,7 @@ check_access(const volatile void *ptr, size_t size, int type, unsigned long ip)
 	else {
 		struct kcsan_ctx *ctx = get_ctx(); /* Call only once in fast-path. */
 
-		if (unlikely(should_watch(ptr, size, type, ctx)))
+		if (unlikely(should_watch(ctx, ptr, size, type)))
 			kcsan_setup_watchpoint(ptr, size, type, ip);
 		else if (unlikely(ctx->scoped_accesses.prev))
 			kcsan_check_scoped_accesses();
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-8-paulmck%40kernel.org.
