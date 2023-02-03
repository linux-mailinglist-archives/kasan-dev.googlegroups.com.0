Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBIPZ6KPAMGQE6C43ZFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id C542968913A
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 08:49:55 +0100 (CET)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-163af100c41sf2305765fac.2
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 23:49:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675410594; cv=pass;
        d=google.com; s=arc-20160816;
        b=VseDv2M0H+phXYGogu9zbPT5Bm23+cBu5KRIi803wYyy29/6XOiNFbSpH8sJ5u6LuX
         aRxBjK3DmInLvMmCuD7X5ho9Pvt94no5LYHdXomGQIFthHpYvmVEFcNh2EriFaUMENg1
         aXMvEhLwVK7szaYdwVAqVWrHCbTRPS4GC+ZTOvv2GCL1B9hpfCFbadt3/qMJMAkf6slG
         XqMoqcNymIUm5In6OtfeyQVoKuUdN8sfxCbleNiRWrv35Gm07bWeCgHHQbcAddqX0vz6
         zXlHigLJh8qlWK6U4MXi5zXxC8v7vs+9YqVQbr22YQuCR4OVku5C0EhvogeR6p63mZGG
         A9rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:in-reply-to:date:from:cc:to:subject:sender
         :dkim-signature;
        bh=JrJksexq3oC5N28RUagLT897mZgl3/7YEEamwe8HjJQ=;
        b=xvXgAMC/Ic9e0pIaCgzPuWjTDvTa+pDupl2ZYy4/RWq3f9r60GIWUj8Citta0hzPpg
         2V8inha0KLF0GUewePmPK68Dxt7mUn9yVXJEQ0Tg/DJ7GFweWK2qiZEG5j/snzgewr6o
         hxkBSJx4h6eMhb8woOWVDyJiua5JhEB/opUvTk7ERiTIJbF82SjsgGoMMRNHtmnwpCL6
         r3Qy3iPKhyIVjcNerDwcn22xKSJtbJRhPGdh2kquv7xyJhCwULLuXCZJokSBV/yFI/HM
         w8LX82zXb85OLITUVrRTEhJPQY5bSi3BYDTAkt2fGz11MW1sOz39jj6AWKYJ7GAs4t6Q
         pSsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=neutral (body hash did not verify) header.i=@linuxfoundation.org header.s=korg header.b=c0ou6YWY;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :in-reply-to:date:from:cc:to:subject:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JrJksexq3oC5N28RUagLT897mZgl3/7YEEamwe8HjJQ=;
        b=aHtp5CU9BzWcSXHC95bZhaQ886GrwLCbS7jU8vnbWq49mMqvTNGNIQ+6HqRwUI9tSx
         MCK3wQea9sZ50D7zhkr7pkgI6XG80g1umLgQJ1KmpeR9BjxgzONvEA8zZLSsMldNCAWd
         eG/Um/g3MZ9SyUgqqj7Z7YH9ulJjBE3QXffdRy1V+6tAuThSkfOmNNTidT9NmQzgw/wA
         Ks1aXyNORGlZp1BO3G9YxdkRCduGaqZzqjlJyjuZ47mQnhu0CoFkJGqobZVSh7q8z9ks
         nsbS31e+ZXDTQ03r4jO1LqWcnMvqf2xLi5tmxMf8dzxU4iAemYKkkZL0H7f3ftsLOvOl
         zctA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:in-reply-to:date
         :from:cc:to:subject:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=JrJksexq3oC5N28RUagLT897mZgl3/7YEEamwe8HjJQ=;
        b=JjxqngIrH5lSXl9xHPau1kJx5Dnizk2sO7Z/EWk6GDyPpJxIfJ7G6UDtY28Yu7s7di
         9QAalxTioUg2+p4SctLWEmB+4HHm4yLCjPk4cPaHbdYib4WW08U/RoQQqdvTZlIzjfEX
         Vg44q/APHBh6Yn8sZUCq4JN5SoF5xxwxLjmDFog/rPBgy/3oio/ADQM9LK5PNc+Dr2OR
         A1k5LLZp4EQOKkV9EjCObm0PBNB1+hWlEqpoD/wK9XNSsYhNRwv8UCYd19yIVA1d2y6H
         Xl+Il4v6eUBYXBMksCeQYR0fkJyhB0DfJNFYOaPcpPSID2CO6KcucnfLTsdyuv0Yj56U
         24bw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXtcY5DwZz6ej1tixQ8pCCNCVWbB0J9zshD0S57SKFQec+WI8Kf
	01hmC5daQh7ULFZtLhjwBrI=
X-Google-Smtp-Source: AK7set8iUkMdKg8h4rYW6RosEPKyPaWt3OqzPZ8/+c+x57+zJUsveN+rF4iS47wYvIk+fkOXYl8a3Q==
X-Received: by 2002:a05:6870:13cf:b0:16a:57:ba5e with SMTP id 15-20020a05687013cf00b0016a0057ba5emr57699oat.164.1675410593974;
        Thu, 02 Feb 2023 23:49:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:6114:b0:661:b84b:eb5e with SMTP id
 ca20-20020a056830611400b00661b84beb5els531808otb.3.-pod-prod-gmail; Thu, 02
 Feb 2023 23:49:53 -0800 (PST)
X-Received: by 2002:a9d:7488:0:b0:68d:3fc8:7c14 with SMTP id t8-20020a9d7488000000b0068d3fc87c14mr1917730otk.15.1675410593500;
        Thu, 02 Feb 2023 23:49:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675410593; cv=none;
        d=google.com; s=arc-20160816;
        b=TmnHklzc+S8JKtfHkNNiOav05NatYT6HV09QnzYCMMlSbTBMowQhGMYythP7n3eVy9
         SlMCsNMqM//s0pxoglPo2/tiV1+57kDp9pyPvvO9mHMLg5B2O9LhWrAhsUuT19TbnXTG
         M36/iT93rHj8zWUUtSNl4LCEiwfiTWS5X1z9FdhRYECRWME+vRHuNJacHOrDEmN/r8OL
         96V4lxyDX+869/0J/aK8XE79Lvgx44OnsMrXAG8Z7lvH3LAEc2nfBDazal1wR6MOK1cd
         iZm3ABGzR35BG3QNhazwJ8wfPaErsSQL6oZxEIaLUgGOpv5M/la/xtb0hQ3hJFYV7HtR
         YnoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:in-reply-to:date
         :from:cc:to:subject:dkim-signature;
        bh=YFxT47ukXjy2qLSWPNnxCMHBpGZdd04GUfnKyZMVT3I=;
        b=SBUNGGJS3faeQUM0Oix6S6Kc+Lt926o6KqpQBdYMs6iQKHNPfRR5x4Qsieqhs0x3vV
         izw6GSi9DkesvgleR740uZow0Zal82k5FOpS0CcTi7KFxVw4qeIRXRsem4VCyqkk63Oh
         kpcelCqvjw26JOi0y+uI2E8Fn90gYi6ULbFU1JpfIAgbF68dJWiyulb2VvMzfCs0mId3
         xunLVqoxfqI3NwUPKSfrT8hydl7HjeMEV4efcvkaCDcnPzTMeAW9Qq6L5lsE3LEGFLAq
         SROY104KzI2NwBgTfUwKeC/MPQsczILyEaQpQJBiK+x5Ye17xVlKZpb2aeRTBX2KV/B4
         PgWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=neutral (body hash did not verify) header.i=@linuxfoundation.org header.s=korg header.b=c0ou6YWY;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id r6-20020a056830448600b0066e950b0580si167097otv.4.2023.02.02.23.49.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Feb 2023 23:49:53 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id E4551CE2F1B;
	Fri,  3 Feb 2023 07:49:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A14B2C433D2;
	Fri,  3 Feb 2023 07:49:48 +0000 (UTC)
Subject: Patch "panic: Consolidate open-coded panic_on_warn checks" has been added to the 4.19-stable tree
To: akpm@linux-foundation.org,andreyknvl@gmail.com,bigeasy@linutronix.de,bristot@redhat.com,bsegall@google.com,davidgow@google.com,dietmar.eggemann@arm.com,dvyukov@google.com,ebiederm@xmission.com,ebiggers@google.com,ebiggers@kernel.org,elver@google.com,glider@google.com,gpiccoli@igalia.com,gregkh@linuxfoundation.org,harshit.m.mogalapalli@oracle.com,jannh@google.com,juri.lelli@redhat.com,kasan-dev@googlegroups.com,keescook@chromium.org,linux-mm@kvack.org,mcgrof@kernel.org,mgorman@suse.de,mingo@redhat.com,paulmck@kernel.org,peterz@infradead.org,pmladek@suse.com,rostedt@goodmis.org,ryabinin.a.a@gmail.com,sethjenkins@google.com,sj@kernel.org,skhan@linuxfoundation.org,tangmeng@uniontech.com,vincent.guittot@linaro.org,vincenzo.frascino@arm.com,vschneid@redhat.com,yangtiezhu@loongson.cn
Cc: <stable-commits@vger.kernel.org>
From: <gregkh@linuxfoundation.org>
Date: Fri, 03 Feb 2023 08:49:15 +0100
In-Reply-To: <20230203002717.49198-12-ebiggers@kernel.org>
Message-ID: <1675410555184174@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-stable: commit
X-Patchwork-Hint: ignore
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=neutral (body
 hash did not verify) header.i=@linuxfoundation.org header.s=korg
 header.b=c0ou6YWY;       spf=pass (google.com: domain of gregkh@linuxfoundation.org
 designates 145.40.73.55 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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


This is a note to let you know that I've just added the patch titled

    panic: Consolidate open-coded panic_on_warn checks

to the 4.19-stable tree which can be found at:
    http://www.kernel.org/git/?p=3Dlinux/kernel/git/stable/stable-queue.git=
;a=3Dsummary

The filename of the patch is:
     panic-consolidate-open-coded-panic_on_warn-checks.patch
and it can be found in the queue-4.19 subdirectory.

If you, or anyone else, feels it should not be added to the stable tree,
please let <stable@vger.kernel.org> know about it.


From stable-owner@vger.kernel.org Fri Feb  3 01:29:00 2023
From: Eric Biggers <ebiggers@kernel.org>
Date: Thu,  2 Feb 2023 16:27:13 -0800
Subject: panic: Consolidate open-coded panic_on_warn checks
To: stable@vger.kernel.org
Cc: Harshit Mogalapalli <harshit.m.mogalapalli@oracle.com>, Kees Cook <kees=
cook@chromium.org>, SeongJae Park <sj@kernel.org>, Seth Jenkins <sethjenkin=
s@google.com>, Jann Horn <jannh@google.com>, "Eric W . Biederman" <ebiederm=
@xmission.com>, linux-hardening@vger.kernel.org, linux-kernel@vger.kernel.o=
rg, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, Ing=
o Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, Juri Le=
lli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, =
Dietmar Eggemann <dietmar.eggemann@arm.com>, Steven Rostedt <rostedt@goodmi=
s.org>, Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>, Dani=
el Bristot de Oliveira <bristot@redhat.com>, Valentin Schneider <vschneid@r=
edhat.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <=
glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Vincenzo Frasc=
ino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>,=
 David Gow <davidgow@go
 ogle.com>, tangmeng <tangmeng@uniontech.com>, Shuah Khan <skhan@linuxfound=
ation.org>, Petr Mladek <pmladek@suse.com>, "Paul E. McKenney" <paulmck@ker=
nel.org>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, "Guilherme G. =
Piccoli" <gpiccoli@igalia.com>, Tiezhu Yang <yangtiezhu@loongson.cn>, kasan=
-dev@googlegroups.com, linux-mm@kvack.org, Luis Chamberlain <mcgrof@kernel.=
org>
Message-ID: <20230203002717.49198-12-ebiggers@kernel.org>

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
Link: https://lore.kernel.org/r/20221117234328.594699-4-keescook@chromium.o=
rg
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
=20
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
=20
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
=20
 	print_modules();
=20
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3316,8 +3316,7 @@ static noinline void __schedule_bug(stru
 		print_ip_sym(preempt_disable_ip);
 		pr_cont("\n");
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
=20
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -176,8 +176,7 @@ static void kasan_end_report(unsigned lo
 	pr_err("=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KASAN");
 	kasan_enable_current();
 }
=20


Patches currently in stable-queue which might be from stable-owner@vger.ker=
nel.org are

queue-4.19/panic-unset-panic_on_warn-inside-panic.patch
queue-4.19/objtool-add-a-missing-comma-to-avoid-string-concatenation.patch
queue-4.19/hexagon-fix-function-name-in-die.patch
queue-4.19/exit-add-and-use-make_task_dead.patch
queue-4.19/h8300-fix-build-errors-from-do_exit-to-make_task_dead-transition=
.patch
queue-4.19/panic-consolidate-open-coded-panic_on_warn-checks.patch
queue-4.19/exit-put-an-upper-limit-on-how-often-we-can-oops.patch
queue-4.19/panic-introduce-warn_limit.patch
queue-4.19/exit-allow-oops_limit-to-be-disabled.patch
queue-4.19/ia64-make-ia64_mca_recovery-bool-instead-of-tristate.patch
queue-4.19/exit-use-read_once-for-all-oops-warn-limit-reads.patch
queue-4.19/exit-expose-oops_count-to-sysfs.patch
queue-4.19/panic-expose-warn_count-to-sysfs.patch
queue-4.19/docs-fix-path-paste-o-for-sys-kernel-warn_count.patch
queue-4.19/sysctl-add-a-new-register_sysctl_init-interface.patch

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1675410555184174%40kroah.com.
