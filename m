Return-Path: <kasan-dev+bncBDEZDPVRZMARBG5K6GPAMGQE7WYBMZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E0DA688BBB
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 01:28:13 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id r17-20020a17090aa09100b0021903e75f14sf1606627pjp.9
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 16:28:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675384092; cv=pass;
        d=google.com; s=arc-20160816;
        b=roh4P8APFf7zdGfa9JQ9JEb4d0IdPNphHXW7yVGOFLKhNicktrkoghdy4cEo/lUILb
         Tni5+8WgKrdhyd967/AIR76PmhzRku/3zyKIyn1yYE/AS4UPdcz9X0g4Reilxl8t1lqI
         oiDow0GT1d01bCvqZn3M+niiOqhPjtLh1/lQYYjGLM5RAUzfQ1ef0rVSHKqEp04+ILHs
         Ks5xASg2+dte6E1/w09xvFMNINWZcAetgj7WV7Q5oOZ69AfXyLQ3UKfZoemfaUZVS9Qo
         AYfAcjxPKO9oiddMHtURY4nHp5g4OWpxpWK89BJNYyV5W0Nx9Ak7qMZd04zBOPuqLgrm
         9yVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=o7Ixb28K7PpTE2bHKEnnaBJcMSk872uF3zyAfPXmVl4=;
        b=OzRTO4U9uGXlGgW254DkMcvj/FO0bSb/r4+aZcp4yajueZA+j5I4m2OkLGVliD8+Ry
         OW80ZjmB1CdpYLPMNl1sqVCaXT4wgVIDN6jPLHRvsAxxWD1hAKmyjjjUuuGTrj/yXaNn
         /Qhs2yaPpmqTWwcg21eaNCCY09pVPjh/5KWh4BdG/moJ2L2l+fSXKm9l3o1wfc9AvKdq
         s7Ib3aoZXff3EJlECZhYvdKo7QCn8/Dgto3VgzLkkGA5RDffy7IlV3mAtKVEr/iOQq8l
         /a2VisJYU3HHxi6cmzJ5QB83Yo8BdaaB7DvJYvzP7HmzaaNuipWWZ1S/LNmFXv9qlu/0
         RSrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GrN8c1zq;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o7Ixb28K7PpTE2bHKEnnaBJcMSk872uF3zyAfPXmVl4=;
        b=KQ23+6y9HnguGCF1A9is18IYYkKtDsVhG9/N2sa0KZq5hjPRCMunYDEocJl6LvjDI8
         Y8WgF+XryRJXWwkZNHl1UgyXcGlS68zharVkLJmkz9i853gDRsYjh/HusCzTejWnehBh
         al2LHS156pyCRM2yI2g0+KJZfnIBjS/kqR7EbhcquVHuPecDN6J5yvrdCZMDxxV7xNdU
         U2IPRPyJTx8HWsUj0wbdCvpuJaetrqzIBlQm43hpHrRiukNOc8jsVit/P0TucmYneVBk
         5fSn8CRtse3sr/r56m55SDQmHjSsLxyUR1BkhegglxA1blMoKedLnwV7YotNo1zvhuMd
         xedQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=o7Ixb28K7PpTE2bHKEnnaBJcMSk872uF3zyAfPXmVl4=;
        b=Xok7+gDQ7uyttFRyXxMVgMsrJ6NwsDRtZ1Mj933eFSml3NaLNr0P1li+giRsL66QzD
         xc0j240RYFhkavBQF3RmwVTdguHQMssKpKhnURrakwDCjFlhVNNSpKYqNXlwIK2RgOsC
         Zn1BxE1/iPDQQCpuRKrU8MNRxPAzXVXeW9nDd7+SI/j3OmHNCr632IiSfyBl2o6hp+0l
         etdnvVTroqz+tZ/zOXvfQHFzSxY5HUzhEucsyG1UMnZeeppuYp33Apgnr1Sl4HIDfBHM
         GXOnAVvgjYBhi4SyljxoruqVuz8YOWIVAAb2pv8oSFSc9rXg3bXEPMy/ektpTMYEFUv2
         L22Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVwqgvvk4UnMcRrMClNvWXWyEWz65hGuY3EHsnJfuQg78sTlxhV
	ZpKAfT030mmj9TqS+xuvVVg=
X-Google-Smtp-Source: AK7set+COi1Cshs+YpwVNAq6FbBfMN6vGbIlCOFaV9W+YgxbJC6+u7BeH521BbmP87zVBBSsW2BRdg==
X-Received: by 2002:a17:90a:1b4b:b0:230:204b:4498 with SMTP id q69-20020a17090a1b4b00b00230204b4498mr1064313pjq.36.1675384091643;
        Thu, 02 Feb 2023 16:28:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f705:b0:194:6afa:c3 with SMTP id h5-20020a170902f70500b001946afa00c3ls3469049plo.4.-pod-prod-gmail;
 Thu, 02 Feb 2023 16:28:10 -0800 (PST)
X-Received: by 2002:a05:6a20:a8a1:b0:be:bea0:7139 with SMTP id ca33-20020a056a20a8a100b000bebea07139mr3377738pzb.9.1675384090787;
        Thu, 02 Feb 2023 16:28:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675384090; cv=none;
        d=google.com; s=arc-20160816;
        b=pfcHS10y9R/9KJQRqD4XytugHiKYtTdpRjIennwo5BMLZjWa3ZxxdR/m/8qlvBA0bY
         +hl0vSttK4QHoIKQLAvj1UV8dt4aJfJBVwuivcWNNtd/B7y6X7Px3gtZtqXIQaBOv0tE
         ht0LYLtqLhLxj3tzcXvQCQNaTuhMUFauoF/VDVGNhrM3GYYCsFoXrVw4ehiSXlPuuyMO
         kOfcwSgFnvhiWnXyZZ5151Bmi5DitnsLPw4n7XyyZGkMTP3KPky8g4rdisK2oIL4Sr+T
         aj/u1qfMmyzuzEv7fpa+ya6J+vxreVt9YH2pB46yhGa6VnBEgVRvj47H+7qVr/NdvORr
         w7ZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=P64sEEgdXAcZEgqwS2XBi6yNzsTXCiHZWWCCaDmfkWI=;
        b=vXY4DnO86Vx8dBpavW0A/DATLUkmFOEuiyRrt00KfE8GKNQebLg2ByPcjj1Rm/+luH
         iITaZKrP9WwMKqLX4+qlhilRaSguBAJDBizSJ9WsR/4NsXbzI/0ankg1VTY/WcuuQnWC
         V+OLpKwmtJb+XvxH2UA7DKyuF/ZLPWDWWaswtQZ7A4uLneG95q6Wv+nfqzAsyb4Quk/i
         baOVMroUpXLqsQ1r9gUoJd/JOZgIJNtrHaR7OloQ8Hw+5qnebML37qGHDHOhNovxK1nV
         LJmgSAou0HG+x5CxXQir6UTowZQ49pH54LwfjensjC2DtNapshUFihtuOapsnppYLGN6
         P9Xw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=GrN8c1zq;
       spf=pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=ebiggers@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id x200-20020a6331d1000000b004ac6ba951f1si80034pgx.2.2023.02.02.16.28.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 Feb 2023 16:28:10 -0800 (PST)
Received-SPF: pass (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4073461D48;
	Fri,  3 Feb 2023 00:28:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A6B3DC433EF;
	Fri,  3 Feb 2023 00:28:08 +0000 (UTC)
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
Subject: [PATCH 4.19 v2 11/15] panic: Consolidate open-coded panic_on_warn checks
Date: Thu,  2 Feb 2023 16:27:13 -0800
Message-Id: <20230203002717.49198-12-ebiggers@kernel.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230203002717.49198-1-ebiggers@kernel.org>
References: <20230203002717.49198-1-ebiggers@kernel.org>
MIME-Version: 1.0
X-Original-Sender: ebiggers@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=GrN8c1zq;       spf=pass
 (google.com: domain of ebiggers@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=ebiggers@kernel.org;       dmarc=pass (p=NONE
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
 mm/kasan/report.c      | 3 +--
 4 files changed, 10 insertions(+), 6 deletions(-)

diff --git a/include/linux/kernel.h b/include/linux/kernel.h
index 50733abbe548e..a28ec4c2f3f5a 100644
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
diff --git a/kernel/panic.c b/kernel/panic.c
index a078d413042f2..08b8adc55b2bf 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -125,6 +125,12 @@ void nmi_panic(struct pt_regs *regs, const char *msg)
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
@@ -540,8 +546,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (args)
 		vprintk(args->fmt, args->args);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	print_modules();
 
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index a034642497718..46227cc48124d 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3316,8 +3316,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		print_ip_sym(preempt_disable_ip);
 		pr_cont("\n");
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5c169aa688fde..3ae996824a040 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -176,8 +176,7 @@ static void kasan_end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KASAN");
 	kasan_enable_current();
 }
 
-- 
2.39.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203002717.49198-12-ebiggers%40kernel.org.
