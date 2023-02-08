Return-Path: <kasan-dev+bncBCXO5E6EQQFBBDVBR6PQMGQERQZ4VEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B39568F37D
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 17:40:48 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id o24-20020a05620a22d800b007389d2f57f3sf2059891qki.21
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 08:40:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675874447; cv=pass;
        d=google.com; s=arc-20160816;
        b=tB6JRy38JpiB5m+s6GkR8YSCOB6zv9vyj1BdjMhErPD35Q7ZFbU6vAFn9kD9IPLry3
         BDhHWBylqTYHdUVlEeX0cRineYwRbYmyAyeWYc/btVTZjTjSVQBBspKOKbhLcQ4OuHhE
         GYsB6EjoQcFvg0NJx7XHEwpJqmSK4ywiJpe+mpRXGs08fn7lzIwGr71RaiHI1PWkGI1z
         8zQsc6RgkaakZQ5CMD6xvSekORBpwxnzfGjpeO5qjFBkVd1/sjhnXJs2iJTES8UIlHo6
         ignHWGJNVFZgh6N6lTjTpx+yAlmFrmeCyiTa75HU9rmBa5Ujpfzbs+sWNKGMysNbiTUB
         VDqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Bf0YY5k+kQGJTXprms2ds5cPjtSgYquI1p/+8Dx5pdE=;
        b=wd9RYW0CQwpCDBabdzL5BCAwWQs7yBM1nJlQ14lok88lb+6X/ykVs1d9kLyosiXQ6y
         VocnSr2dX3BtyUigY633oGuYZYCTcBHVpdSmUJYLh24OSyA+uWc6Ud5F1MlK80zngz3N
         MrVcrZYO7sIVtf9X5tZRNZL4N1TjRp0GNJwU8UlPc5x4LjXerisAlune/CCvEsT5c7oL
         No9zQXOQjqq+JZ3r8Z879zCeENaq6+14sJtbQaC9gKTHwHpzFBxAj/hl5dUwwFSRHlhn
         +7j8PC00ySo7y1Js/mSTS/Oi55JZkLqt4Q3eRyxzt6GQPAexDQqH/4te1qB2+szc5mPg
         DxXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LFdiQq6g;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bf0YY5k+kQGJTXprms2ds5cPjtSgYquI1p/+8Dx5pdE=;
        b=QxmYH22oZQMBE2P6MAezOVK4RPjyp9/QgEdQVmSiQTPC8SK0z8BVWm5MwxpAdkE+o5
         QdMME3rVy3SwhFAT/cyd9ulJzn7T9N+h73S9/11zHu7sGJ8Vi254Nf651fKRU8/UTTrv
         ncc6bZ9faLkviUVQDEwblTzcNJ0Fv0GDxHPRp9ZOEyTQSaM7z8KVC1+zT73mMrOGLuEl
         sfb/CYAgBKEW3aB47K3zwfTCSxnJ9buwks/pP9ByvLUt5OCM3LtPmJYR0prhrCBzKkJb
         ArFH86CJWlTeCe7NHzhiucz4O6xe8CKyfA5LVGumTxs0qSOOiE8b11cjLEugBRoBAgye
         upmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bf0YY5k+kQGJTXprms2ds5cPjtSgYquI1p/+8Dx5pdE=;
        b=e4YhVZ+go80z+X6E2C34oz2sbHBn5eEHquOZWFx2bTUw/GIRl+Z3IxqQnVkddsXZ9L
         gzL7+a34EY+jz1KtUMMrNFwBsAWbJXwzI1jBAdpyfs3nKaZbeE9uj89gUtGwnu4kmTUW
         apNADyaQ89cu1lJp2e/bWdVT+Wp/TRqmg+QDRtVyk5juPlg467RINNNMvlNSovwAW40o
         TZ9J18UtOzSYDLAx3hlOwosFDT6JYpBwFJ/2CybLEcaIZUueiJYQRs04dxFp7M23BDEn
         sIxNaB58zArQ9SilLOzL7+wEcGTWOpkRh9QEGOmd0sRkwsrduhJoV/37HHjt+SJq2tRi
         qC3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW0Wmlo7uYHDxeiJhkgZ1gfntFxlfHo1bEcsRZQL0eraV+Y+n3U
	5E3WNm1YObzyxZNbHoXWBEE=
X-Google-Smtp-Source: AK7set93UFOostDouT+dRkHSP/Ut0f1FyA1ejQxh0a6nSQg2CeJqnYeP3olGK7W2tN8O0mPw7AplvA==
X-Received: by 2002:a37:4152:0:b0:71f:273d:b794 with SMTP id o79-20020a374152000000b0071f273db794mr786499qka.104.1675874447094;
        Wed, 08 Feb 2023 08:40:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4f8a:b0:3b8:45c4:4b6a with SMTP id
 ej10-20020a05622a4f8a00b003b845c44b6als20206488qtb.4.-pod-prod-gmail; Wed, 08
 Feb 2023 08:40:46 -0800 (PST)
X-Received: by 2002:a05:622a:1824:b0:3b8:6555:342c with SMTP id t36-20020a05622a182400b003b86555342cmr9235339qtc.11.1675874445639;
        Wed, 08 Feb 2023 08:40:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675874445; cv=none;
        d=google.com; s=arc-20160816;
        b=AIubGPAQprrlYJi+97C+ybCDY/U3N+/dVvD6DY+0P/h30NTfhP9sP0PLySAEj+Ea/g
         fUqgs1jCrEHdgpT2w0nJjSvmH6uz4gsTfVCx1EJ3gAGv4QlpgA/UQdYWCaxyK3w4zY5v
         tuUQ9E/6QNfE4W/G/iwHXcDC5DFFou+YoVrxksD/NkuE8T0maL9rV8Mcj1HeAZ5l/Q+T
         2CxkN91N/xQbflgJEAoTvb/sVpe7+OLdQJtp+vx3KC9eumsKQ3AcAIEKulGvfLEEEZk4
         J+gsArKl2/2RDBj71qmkeAw+vapCjAm1/vr9AlwKfrwz7Zi55cjnciDhu9XtBFcGjUgq
         EP7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=643+SwLgNy1RbLG04tqRWPpetLAovg4NxWaY4lJrCag=;
        b=sm1m50udRs3D2GZkKF/+EmTXxD6JddTNbEoB3fLCsd1WgRkR6YEUJ2nuvNNTqXCt69
         +RBpTWH/4rWNC/QEnmRj2bosdQQZY6MBXl2u/stNRYk9GkIzXWaWOyOpftU4Cq6QCUu0
         xVrqKV7z9Vte2mLCj6NR0SS19NuvO2qxtpXkb5FGH8gShZ57bI5utqvkQdB63zpvCIcq
         FOYrRiW5qZt8tB9fdVi6q1Qj+xeYRE/bXOAhrmtISaKC5uT0l/a4m8Tja3dhgnYoYkIM
         0bWVauJYrrkye5SrpidpwlMpCO8DEm8B49KG9w9Tjd5hXS2FjKTzrR6BjtkE+b+9QinP
         bvnw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=LFdiQq6g;
       spf=pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=arnd@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id a3-20020ac87203000000b003b8df60b665si1509773qtp.2.2023.02.08.08.40.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 08 Feb 2023 08:40:45 -0800 (PST)
Received-SPF: pass (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id DCD94CE2246;
	Wed,  8 Feb 2023 16:40:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AFC6DC433EF;
	Wed,  8 Feb 2023 16:40:37 +0000 (UTC)
From: Arnd Bergmann <arnd@kernel.org>
To: Josh Poimboeuf <jpoimboe@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Borislav Petkov <bp@suse.de>,
	Marco Elver <elver@google.com>,
	Will Deacon <will@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>
Cc: kasan-dev@googlegroups.com,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Miroslav Benes <mbenes@suse.cz>,
	"Naveen N. Rao" <naveen.n.rao@linux.vnet.ibm.com>,
	Sathvika Vasireddy <sv@linux.ibm.com>,
	linux-kernel@vger.kernel.org
Subject: [PATCH 4/4] objtool: add UACCESS exceptions for __tsan_volatile_read/write
Date: Wed,  8 Feb 2023 17:39:58 +0100
Message-Id: <20230208164011.2287122-4-arnd@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230208164011.2287122-1-arnd@kernel.org>
References: <20230208164011.2287122-1-arnd@kernel.org>
MIME-Version: 1.0
X-Original-Sender: arnd@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=LFdiQq6g;       spf=pass
 (google.com: domain of arnd@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=arnd@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Arnd Bergmann <arnd@arndb.de>

A lot of the tsan helpers are already excempt from the UACCESS warnings,
but some more functions were added that need the same thing:

kernel/kcsan/core.o: warning: objtool: __tsan_volatile_read16+0x0: call to __tsan_unaligned_read16() with UACCESS enabled
kernel/kcsan/core.o: warning: objtool: __tsan_volatile_write16+0x0: call to __tsan_unaligned_write16() with UACCESS enabled
vmlinux.o: warning: objtool: __tsan_unaligned_volatile_read16+0x4: call to __tsan_unaligned_read16() with UACCESS enabled
vmlinux.o: warning: objtool: __tsan_unaligned_volatile_write16+0x4: call to __tsan_unaligned_write16() with UACCESS enabled

Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
---
 tools/objtool/check.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index e8fb3bf7a2e3..d89ef6957021 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -1200,6 +1200,8 @@ static const char *uaccess_safe_builtin[] = {
 	"__tsan_atomic64_compare_exchange_val",
 	"__tsan_atomic_thread_fence",
 	"__tsan_atomic_signal_fence",
+	"__tsan_unaligned_read16",
+	"__tsan_unaligned_write16",
 	/* KCOV */
 	"write_comp_data",
 	"check_kcov_mode",
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230208164011.2287122-4-arnd%40kernel.org.
