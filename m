Return-Path: <kasan-dev+bncBDEZDPVRZMARB6M35WPAMGQE34Q4P3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113a.google.com (mail-yw1-x113a.google.com [IPv6:2607:f8b0:4864:20::113a])
	by mail.lfdr.de (Postfix) with ESMTPS id BA0FC687558
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 06:45:30 +0100 (CET)
Received: by mail-yw1-x113a.google.com with SMTP id 00721157ae682-51ccd655ed8sf10347857b3.18
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Feb 2023 21:45:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675316729; cv=pass;
        d=google.com; s=arc-20160816;
        b=AS0jq69JSSaYlm7UjV+qZerufUxwRxFOaVXrJM/6P7wVDHFw8SHsqgrC8qZaFkX+gN
         RKzpc9UrPcIHb06/2AFbycTlAxMIDFN8GnlXMDsK+zVoF3WpL0n9cDS8XbiIdLPpY8NF
         tzvU4JJ4BrJA3+NLwleUJ9MbBsvjqEUOp2U3XZdi9AdUBZBVe3N8Sl6ivFvDAA8E3j/4
         hMwj3mQ/9IvTfVkpueGtiOoPH4Ycdk2bTSIJ7gQ1DVcKaKAiZRiyEOW00H0Vxq/o+bYv
         AuZDRAo9SFKTG2FvmPSf0ge8rhIPaF/HlIJLLYvuKh6tD+kqkx01wPMOtQ7ZwgM9VW5r
         k2Ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hQ3mpQt6jfUe32nGgn1D7FImgjOL1OwkLwmX5THrfXs=;
        b=QGITx/uEBnGmvNT3w5G90SGPftjFmYyCqLY33lh+z31SUJBPzM92zImqetv81WRQRv
         By5mWLYS16F2jRkGSV3a8eUBPBMeQszaAHZyX+l9JgtcYS/+Ku19Lwde3EC0gqp9BrDT
         KIK3eZlbu9zZFF5WALSxKTvLAo3lALfYprd9K7X2htNIyJh6hporrIidPXrtJS+EnCQk
         ds8HOOXp3oLtgxLek9clwxoFl++OuMq6JfSm1h20chXTS74iTLRRSzGulE7AZtPDoDh3
         x5i/ECaob9J3UgaC3cov5cILyA1ogmPcb2js0PzLhWfp4qvJDPMYpcYmgRrSnytIarTM
         VVcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=I2OnUMEd;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hQ3mpQt6jfUe32nGgn1D7FImgjOL1OwkLwmX5THrfXs=;
        b=OET341cFA659gCJeSiDNPMmzR3k5xolS26Msbb1smAoVvZYAOqlCBpCGJRLwWI8G74
         jF4iulZo4IIM2u0jYP4tVMTIi8jh0TuSbLCjURVCu67eoeboIEfCsk+GnGb2MsPoMcas
         zcB61ciqb9gfrMx947ZzZfYHN9QA68b35vq+qZjW/VYKW+W4ZUQORaLuoJTQfF9CkB+W
         aW9CigXl9gV0ILGl2XgkzvX4u9webPFflIZEZLS8gj+wNVUyRgQegZk+DKjIyO7m1Z6A
         Ytck575dsFu1YzJl8BLIcqaWvbpXKPGhFPWo3VFlt2kXYVww8j82gGTHeK3T4b6TQ1rM
         DUyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hQ3mpQt6jfUe32nGgn1D7FImgjOL1OwkLwmX5THrfXs=;
        b=HHIECaCusYyBGJy2X/u+ITh0kcqlrhOCmCxCVqIXGLN9ypdJ3ENd076BOscMAxgjqS
         abFFLzkIjjjVWy2cufiEmjW4RTrj3M2g3XlYw1mkhQCL1TvysJKVtusiKREsm/9LruZE
         JJ+xCQv//z+B95e5f5Vb1JAQxDU1PmW+Ua+0YqgLQRG8sYZ9kChDvR1TS6R5d5wXG32J
         IJGJBFSgPzc2BDCN2FZD9bmifcB3R4LtJf1asoVwRs8Onbq4+1YIn6juExJoiBPSF9d6
         +LeBRKPXP8OATVnkJH0OuOfHgIFQPzULGugBcu+CYEpVqhxWunSeqGPFv7y9bq1FKSZx
         kLfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU7BouofA0QtyW2JJmSyL2rB90f4ott6PrZHVDG1hjeZZ7ppINw
	/rmP69jeSYvfZmo7kYkdgyY=
X-Google-Smtp-Source: AK7set9o5jJQfW1b3ePmmPdtcWRLczk0msh7hhX1jVnw+48NlCKoAbXdLTaF4QrKkB6mucUlCLsW5A==
X-Received: by 2002:a25:2d19:0:b0:80f:2518:219e with SMTP id t25-20020a252d19000000b0080f2518219emr633651ybt.471.1675316729369;
        Wed, 01 Feb 2023 21:45:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:bfc8:0:b0:80f:54e:d6f1 with SMTP id q8-20020a25bfc8000000b0080f054ed6f1ls445267ybm.0.-pod-prod-gmail;
 Wed, 01 Feb 2023 21:45:28 -0800 (PST)
X-Received: by 2002:a25:9c83:0:b0:82d:c925:802c with SMTP id y3-20020a259c83000000b0082dc925802cmr3256693ybo.42.1675316728699;
        Wed, 01 Feb 2023 21:45:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675316728; cv=none;
        d=google.com; s=arc-20160816;
        b=0u6gjk0YwX0xkcvt2Y7PEDke4SSk7sTkbJBZqkeszzK+T/H/5IW4S1+ea1VGTvE2yH
         RoqjhDuTMytiafwrnmiHY2h/Zztn1HiZZaNLFGNHTR7/68KGev55FFCGfGZxrT7/qmeF
         +eiDfiPwf32aJK22AT+s/0fhtXYTwGY0JbSyrYV21nrl0B8aY7YolgwE/6E4TGoPBdO+
         jDpzvheiyi6PbV/OyCd5UzrLYOU2pp8GluZotLSMF6kNQ17MddKfCHdvEWvLf265qmMj
         yqUNkU0cxJWL75yyY5VHi41+YP/hyVgGfCV99h6jOhTLIspD+nhiDuleh0XN/Qr1vJjd
         YKTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7dTV6hb04ErBeR13uLAuTY/ASGpEdnG4CPpgP5eCoOY=;
        b=A1nN10CeX7W8NeUNNMxzVovDjhlf7OA7LME7vfYyLGhKV6o89H2mJPPG+XqDv+wX/u
         a/fEfxNtVOO/mLm2YMnwH60xdsQRrGRwcMjCzkOnfTTD/WX/10REe5JbLQmB5FeaiUvq
         cNRlcrPGIvI3jms1c/NGzAdLKONbcUXq8khGEISI5Qep60DPMepFg4vaGnPl/2DXvdBG
         zs0SU13JNX00dkO/BraIijQmCOtw4zrHzmiZ3qVpVJI4yNHLterDNqeY//6SKb4uPPDG
         MwNy+2gmq12w3e7BZiFM1HmnGtPqkDiTVJf7tQlzJcK5XIR3Fo6K5EdVRwlt9cXkukMs
         /T5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=I2OnUMEd;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 194-20020a250bcb000000b007ddb8337f72si1503250ybl.1.2023.02.01.21.45.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 01 Feb 2023 21:45:28 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 49BF06188D;
	Thu,  2 Feb 2023 05:45:28 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A535AC433A0;
	Thu,  2 Feb 2023 05:45:26 +0000 (UTC)
From: Eric Biggers <ebiggers@kernel.org>
To: stable@vger.kernel.org
Cc: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>,
	Kees Cook <keescook@chromium.org>,
	SeongJae Park <sj@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Jann Horn <jannh@google.com>,
	"Eric W . Biederman" <ebiederm@xmission.com>,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org,
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
	Shuah Khan <skhan@linuxfoundation.org>,
	Petr Mladek <pmladek@suse.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Luis Chamberlain <mcgrof@kernel.org>
Subject: [PATCH 4.14 12/16] panic: Consolidate open-coded panic_on_warn checks
Date: Wed,  1 Feb 2023 21:44:02 -0800
Message-Id: <20230202054406.221721-13-ebiggers@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230202054406.221721-1-ebiggers@kernel.org>
References: <20230202054406.221721-1-ebiggers@kernel.org>
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=I2OnUMEd;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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
---
 include/linux/kernel.h | 1 +
 kernel/panic.c         | 9 +++++++--
 kernel/sched/core.c    | 3 +--
 mm/kasan/report.c      | 4 ++--
 4 files changed, 11 insertions(+), 6 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 22b9146655958..a4ac278d02d0a 100644
--- a/include/linux/kernel.h
+++ b/include/linux/kernel.h
@@ -293,6 +293,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 void print_oops_end_marker(void);
diff --git a/kernel/panic.c b/kernel/panic.c
index bd7c3ea3bf1e6..8e3460e985904 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -122,6 +122,12 @@ void nmi_panic(struct pt_regs *regs, const char *msg)
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
@@ -546,8 +552,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (args)
 		vprintk(args->fmt, args->args);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	print_modules();
 
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 544a1cb66d90d..5dc66377864a9 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3185,8 +3185,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		print_ip_sym(preempt_disable_ip);
 		pr_cont("\n");
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5b421f8433488..4dc577d7e7494 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -172,8 +172,8 @@ static void kasan_end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
-		panic("panic_on_warn set ...\n");
+	if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
+		check_panic_on_warn("KASAN");
 	kasan_enable_current();
 }
 
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230202054406.221721-13-ebiggers%40kernel.org.
