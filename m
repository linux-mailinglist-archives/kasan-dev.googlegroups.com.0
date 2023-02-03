Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBC6B6OPAMGQE4ES7UYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id D727868956C
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 11:23:08 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id j13-20020a2ea90d000000b002904f23836bsf1145024ljq.17
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Feb 2023 02:23:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675419788; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZVYYFfU/actUphlQBGSQj+aJl6KSbaqYULEuVdhdBfMO5JD5/CUNAeAoo3Ow/Sxeo4
         Q1iEgHh+LKa8deId4GW2lZ376hm4gY5fuLWaGYSSVhloZ311TrgfExqVQLVdERZ2plMe
         Vx7CZWmY8BWfzxxOTVqeXGrPu4/+EuwgYaKGvBIZOSq61W0SZWAjWYLpOJXUDTnCZBr4
         DFOROz3+UonVhn2PoJbbZYqNDjvOd2FF/h3mJs41x8S9tAty9KNRC8fKtWSJuEeR/SBE
         O+o1EFDL0foiEJ3YMTRqJTkju06/6anlxGxwzvO3hSDweiMaw0VrBAW+WuzyV1ihuGLs
         f2+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=og6SundOC02CiN41R8Nrlk1NHo4YvcE9C0KpEfJDXgg=;
        b=ztSoQssYpM5xjtG3NBAjibEtkGQwni6jHCshzi1AUbmA7VLT5lcPXxcN1Toq1Cxt71
         i5m02P88a/1UVWyPSl0vpjpMQjsV4BplSHg2JOpTRWncoxY54ww/T/9CRQmD+H2TRMQF
         IVbXzj8E5baYg7qfInUrSKMF7W8DI9WAZlWhVX+qrL3q0Na1Cxedo/yjJwSKxIydsEGl
         ZOV+3/X8AY/nFT2DlNbLAXjjtZ8d6RZEdpFWfOaoG2b0VEpQHxSIq1IkXTsbXVKjjKcU
         6eGclb8HjJBNBxZAfHDnp7rkStj12rL3sRJ13buyz/K+jZP+SeuJsrpAhK+qqY4cRmzJ
         PB/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=KBHhxWWP;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=og6SundOC02CiN41R8Nrlk1NHo4YvcE9C0KpEfJDXgg=;
        b=Uon2ON4CMkxszjScTYIFpHSm15skiwnltpXQ77uDL63VPygmYdNNvarFJGy0Q1UWTT
         DL+F+AJxKlGLLdCVn9vnmux8UbUrrxNF6Ar3rXFnnEy0cWzgrWckIuQzatlqHXxC0XGZ
         BXTKWtN8PGI4slyh5kr2oHfwT3n+avHdn+NDNwd37e024I2LaQa+rGYU+2vJt/+iRwRc
         vedVVsln6+rLceORSysqE5cm2yn2YQ3UnFwEASsquWix1VjYVVEsJND+IsOktG2vAibR
         wZd5PbN4ibV92PYpBia792KxY6/DL9GP0P5HXo5kjkarzWZ+bhMvunxRuOtkLqETpxPW
         zh/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=og6SundOC02CiN41R8Nrlk1NHo4YvcE9C0KpEfJDXgg=;
        b=HtxREeMETizwAw6KxRKuPhx/ece3wJ1J2xHmpslmJMFLsTo3XHCJsGCJlxns6g3C9V
         HL8JLJ+HyIjFQqAerL1nEiqlsm6u57kMFJXePxSx7PRqouoIp3r3xD6lLE4b7qxwPrRV
         qBpGv0Yc80Q4wR6y0c5mi9BjYdRw5p2o3rHBSaaCe7yBg2T7SUNzfRTm51/QuAOmZuJF
         HpfTeS1pYpilF8soVIFNPd+IQ9qN42pxacLmIvmxiMHGAkHb9nMhD56xwBX4ueeXDF7l
         MA9m/XyaEDuoz9nvgXHJWv61aNdbsAlWasoTXWUUKJ6RQowXcJHP1sOl3pQwCCpecIAd
         qi9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKW8o5PjaVBrxPC4ngwPwTbcdhscsNM1rXarYv6lTO9T7g3f0zf4
	/ctQxaWsiY9d5/K4dWm4BjQ=
X-Google-Smtp-Source: AK7set8nVqM78lZdL1gx7+U0CDmj69FOW8irpSsHdeHgoi3FCUM/M5HwDISoXoOgIV7Wpdd3V1V9aQ==
X-Received: by 2002:a05:6512:44b:b0:4b5:7838:6a2b with SMTP id y11-20020a056512044b00b004b578386a2bmr1692950lfk.116.1675419788185;
        Fri, 03 Feb 2023 02:23:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc0a:0:b0:290:6183:37b4 with SMTP id b10-20020a2ebc0a000000b00290618337b4ls694704ljf.0.-pod-prod-gmail;
 Fri, 03 Feb 2023 02:23:06 -0800 (PST)
X-Received: by 2002:a05:651c:221a:b0:292:871c:1b59 with SMTP id y26-20020a05651c221a00b00292871c1b59mr41496ljq.52.1675419786745;
        Fri, 03 Feb 2023 02:23:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675419786; cv=none;
        d=google.com; s=arc-20160816;
        b=DbZQRaiLxi7qlt/7KzXbULbTaNZ71Ynb0APYnaotft9FhW+fV3N0JvDWod9WYkv4/U
         +pxrGhQyGQi66bwJFhmfoeLpWrXhF01pxes5IgqTo9AelJBGZWWrNdOv49UPQ+8StD+H
         2f9TKrH/D/NSvXYAeWfIuLbS6VxOngyTDpIjmbYGu6N1ZdyxK/4AjQD1v/diZgo0rF/5
         U9Lw5Yx4vF1iWN+yGNO1lPEnJAWDePof4lqBTcxXNFaEqhN1l4GNnPcZUHiDGVkjwDCl
         DGJi2I+qyWfs8fLecR2SRmozwtN9Zqi9XIAoKUonwo/vBL3bfZsoVsX+53STYB46tRUa
         g/vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=3WiNzHy+TzzAFPTu+Hq1aQhdGIS8zW+F8KgcJga/A+A=;
        b=QqPNe9u/2j2r5dyvATJeAszu/UUvydqcFl4Oac8druwf6suN3YcPbtRjw/yaGACRDr
         AMcFK6jg4n6DjxLkTq6bXT1GOJhXNMNFWk524X5pe0EM7+13xnDGbPq58CaB05TBrGwS
         3ORIJeuF41/XiATFCk2MtZOtBlJIt9C1q5eDb72wq5hOAyUmwvRMG/efV0mIwJRRn0kR
         8q8nN1iQtZszS7IcBaL7QeEW+ZySqQpb6IDFN1n0nz5kBJLVIy8Iqzv9fhrW5HGkDIOV
         pw6EeN98Qkip7mKUOZmTJk0lfTJrUuGTJcGD67bnAXM7mZfm6ib2nZPfZDN3PnkPODGT
         1aJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=KBHhxWWP;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id x25-20020a056512131900b00492ce810d43si92830lfu.10.2023.02.03.02.23.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Feb 2023 02:23:06 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 50E23B82A6B;
	Fri,  3 Feb 2023 10:23:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7899FC433D2;
	Fri,  3 Feb 2023 10:23:04 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: stable@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	patches@lists.linux.dev,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ingo Molnar <mingo@redhat.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	David Gow <davidgow@google.com>,
	tangmeng <tangmeng@uniontech.com>,
	Jann Horn <jannh@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	Petr Mladek <pmladek@suse.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Luis Chamberlain <mcgrof@kernel.org>,
	Kees Cook <keescook@chromium.org>,
	Eric Biggers <ebiggers@google.com>
Subject: [PATCH 4.19 74/80] panic: Consolidate open-coded panic_on_warn checks
Date: Fri,  3 Feb 2023 11:13:08 +0100
Message-Id: <20230203101018.408088099@linuxfoundation.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230203101015.263854890@linuxfoundation.org>
References: <20230203101015.263854890@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=KBHhxWWP;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

From: Kees Cook <keescook@chromium.org>

commit 79cc1ba7badf9e7a12af99695a557e9ce27ee967 upstream.

Several run-time checkers (KASAN, UBSAN, KFENCE, KCSAN, sched) roll
their own warnings, and each check "panic_on_warn". Consolidate this
into a single function so that future instrumentation can be added in
a single location.

Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Juri Lelli <juri.lelli@redhat.com>
Cc: Vincent Guittot <vincent.guittot@linaro.org>
Cc: Dietmar Eggemann <dietmar.eggemann@arm.com>
Cc: Steven Rostedt <rostedt@goodmis.org>
Cc: Ben Segall <bsegall@google.com>
Cc: Mel Gorman <mgorman@suse.de>
Cc: Daniel Bristot de Oliveira <bristot@redhat.com>
Cc: Valentin Schneider <vschneid@redhat.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: David Gow <davidgow@google.com>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: Jann Horn <jannh@google.com>
Cc: Shuah Khan <skhan@linuxfoundation.org>
Cc: Petr Mladek <pmladek@suse.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Link: https://lore.kernel.org/r/20221117234328.594699-4-keescook@chromium.org
Signed-off-by: Eric Biggers <ebiggers@google.com>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
---
 include/linux/kernel.h |    1 +
 kernel/panic.c         |    9 +++++++--
 kernel/sched/core.c    |    3 +--
 mm/kasan/report.c      |    3 +--
 4 files changed, 10 insertions(+), 6 deletions(-)

--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -327,6 +327,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 void print_oops_end_marker(void);
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -125,6 +125,12 @@ void nmi_panic(struct pt_regs *regs, con
 }
 EXPORT_SYMBOL(nmi_panic);
 
+void check_panic_on_warn(const char *origin)
+{
+	if (panic_on_warn)
+		panic("%s: panic_on_warn set ...\n", origin);
+}
+
 /**
  *	panic - halt the system
  *	@fmt: The text string to print
@@ -540,8 +546,7 @@ void __warn(const char *file, int line,
 	if (args)
 		vprintk(args->fmt, args->args);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	print_modules();
 
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3316,8 +3316,7 @@ static noinline void __schedule_bug(stru
 		print_ip_sym(preempt_disable_ip);
 		pr_cont("\n");
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -176,8 +176,7 @@ static void kasan_end_report(unsigned lo
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KASAN");
 	kasan_enable_current();
 }
 


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203101018.408088099%40linuxfoundation.org.
