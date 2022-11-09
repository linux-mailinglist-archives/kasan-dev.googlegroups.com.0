Return-Path: <kasan-dev+bncBCF5XGNWYQBRB5MNWCNQMGQECSFLVPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 61E87623411
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 21:00:55 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id h185-20020a636cc2000000b0046fc6e0065dsf9900857pgc.5
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 12:00:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668024054; cv=pass;
        d=google.com; s=arc-20160816;
        b=blBH8lVdz53P2OpjQ7cuV3IHZFCtokzD4YKFaEWGjk5NeKRINpKioUpzBd8rf+O7H9
         LLgHkaRmmNlm7WLoqu3K3J5WbQ+MbdBjE2lFv1emeRKD5y/ZtXd3BivGacuhKjyJYccH
         PoSiSHBausSbsm+ndZgC/HGm8IMnIHoJ+rgJdOKlw4QXDw4q3OkF13rx+gdNANnsXgan
         RNM++5tpysk1Z+Bv1RCg4eunvwNJAgzjxS6RkM3+IhnCb7D1PXxyMWlhxzSpWg4aCFXt
         PZD/A60icc6ImqQSxc10lTrKPt457+1R8IFmSBe+FkUUPHFrtmG4W2sFWkBnouflDg2H
         VqZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WVSSs2v4FmkyfjB+A1Bw/eHWnC5g77XCVG5cYXlEMXE=;
        b=dbM3z9n6RQ+mwx4om0KzqXj46br+EAttIOx1hYrKly4by2ozFIXiRXt2Lql1LHLFVD
         pDu0N0BA1xQWdlUrACh9VBYqDFwqUWG2Qrnk2DOCxKqfms2bvH2EdXVEnXvt5RTrX8Rm
         sDlMxU4aSsLhcEyEBGk1QhCjR/7z5ZlDCJhdq3+B5LxXAltPFi18tN7XNfDT+149X3Ze
         a2KoqwyJzDLPnpb8Ej+ARL8UZqrwtk7csgnucxel4oZoSl9wYK+tNesBc/hsoD8gRHJc
         FXBYXGzR+mnRUm/thK3oZ1BB5GsQK8Vi3gfGtbUex2/ibCwSNmNmIII3/dJgg7fCQ1qK
         UKEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EhVqRQKR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WVSSs2v4FmkyfjB+A1Bw/eHWnC5g77XCVG5cYXlEMXE=;
        b=sCLGvyRfHIoE9XgMmmRjYBZsC/FLriVCP2b/M1y0OpPzc1WtcA/qYl1oVCU2F1DhKq
         f+xH2OCbdi1ySocsHKClhpmmCHQijZqdnkUxKjTQHVrl99SKDt3s4G69fNAXcStOk+dJ
         LpdobBsDVyM52F1tug5GcjxBUkh6LFsHwY/CrzFPEi5Xncf97TjQKZZerKDzySEyiQnE
         /nKru+GhB+ZJojNvwq4y7P9kVhLbwLPhvcHckbJfLD47lGQkPg4A4Xk/hILjhVQp/Eee
         rkXeXaxsYjiy8SY/oyS32LOFPq7b3zFKWPC8chV+BjMXd4wBxfwGLKv8itoXKEp8mHCQ
         ol9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WVSSs2v4FmkyfjB+A1Bw/eHWnC5g77XCVG5cYXlEMXE=;
        b=aYdJ/Aj1A++xCZp22o8+JI/eLNSFmlOdRiE3dsZgRbXyLyV6S3X3dzuRYKthhTzzfk
         rhGssKefDdp2QZ1HNZQuU1vSQfFvjcpOtwTldcKuX0q4XX2o2DgPQuqL/raGtrE/wP9B
         mv6w/cRaRKKxlPeW43D9SS5C8Y43Jtgv/wRlFgFhYpTyLcC2+wn+Mn62qi2NwuhpPS9e
         Xudnsfg4yGFWXRL2L2jOmXrlgIdtnLElVO2jDV2jnxWUIm+5AB0PuAe9v94qRswTFzI7
         9hUWwyb0CrgSsOKuln8grAizXCvVCvkfPvqLqDq1W+yty603xjh9ufxt+mEnTV6IDBCz
         Vfmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2AEaxbSBB+wXgbnye/CA+o8Z009I5Fs8k+m4WKHpd8CpJNoR8O
	jIIoUkz8xdBm+OX1yjon7/Q=
X-Google-Smtp-Source: AMsMyM4g5tzV+lzm3s5oyDTssmvr4G11iBTw1AQY276y7+GILtMbBdXGZl60GqDD6XilDPlxtSl3HQ==
X-Received: by 2002:a65:644a:0:b0:470:f04:5b67 with SMTP id s10-20020a65644a000000b004700f045b67mr32577915pgv.586.1668024053830;
        Wed, 09 Nov 2022 12:00:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2411:b0:187:3028:5d29 with SMTP id
 e17-20020a170903241100b0018730285d29ls13217937plo.8.-pod-prod-gmail; Wed, 09
 Nov 2022 12:00:53 -0800 (PST)
X-Received: by 2002:a17:903:186:b0:187:16d6:f9be with SMTP id z6-20020a170903018600b0018716d6f9bemr56836386plg.93.1668024052892;
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668024052; cv=none;
        d=google.com; s=arc-20160816;
        b=DBORLv3jdF9QXszafWWb3V/b51pz54ylBpHn9dkdxJt7pNwFymrg8YMa2MWEz90Rpx
         Y1zCLUe+w4qo5yGWawTDpZ08EFrR7MGOh05yJaNVXXCnT5wO7GDWFGWfs3OLyBkISeE5
         FnXDkZtMKKOfzSjW5KC9xkaqmAbo3GtccFpYYaZLIiKUMq4H6udNi3jGxdrs1m1Avt4P
         Jhce3ro8SzSDY4foyP2lxAZYSHI16sYMj4o5fFKlRIFUIU2E5WJmjG1yJqhY6frP97ek
         mG2mM44no5/7M43+ZfDk3zX0h1qgVyNpOo2FwGjjhEG/C1uFLN9PMTy66xqTHE8ytja7
         fbvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FoO8Qi1M2kCdIN6zHAfogLzoF2oQxJ0yZB573MhBfxM=;
        b=kPZbgATc+SsquwLFPE5gUam4E1KyqVqwI+1DHjiiyU9uVrT70KJ8K2LlydNSG8s42c
         +ZhFybzMtBuBkXz3+JcWAIHOf1Upj3E5AmxTnJphZ5NQvMSieE8+QGMcxkldG6Tvdyvn
         zv7+W6Wt3fcZAex3QZywY+Tq2WuPJxUHnOlllfGSe33mJTTiftIWKXFNdlJk+IrlIhdo
         kTsVn6DIID0PB/3tCeN95pY2sBoqA22G6NFnUYCBvXwA8dTKM6KCYOgcCZA+5k9jjNH9
         gwlBkbhOyTZ13udpl/qNMGvM8ruDP4ZLrNdspbU3EWv6ymXoNKmACFN3w1AxTG/litS1
         DVpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=EhVqRQKR;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id mt13-20020a17090b230d00b00212bf9345fasi124967pjb.2.2022.11.09.12.00.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d20so17031330plr.10
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 12:00:52 -0800 (PST)
X-Received: by 2002:a17:902:ebc4:b0:186:b32c:4ce5 with SMTP id p4-20020a170902ebc400b00186b32c4ce5mr61507291plg.74.1668024052529;
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id t3-20020a170902b20300b00186a8beec78sm9499392plr.52.2022.11.09.12.00.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 12:00:51 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
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
	Luis Chamberlain <mcgrof@kernel.org>,
	David Gow <davidgow@google.com>,
	tangmeng <tangmeng@uniontech.com>,
	Petr Mladek <pmladek@suse.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>,
	linux-kernel@vger.kernel.org,
	linux-doc@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v2 4/6] panic: Consolidate open-coded panic_on_warn checks
Date: Wed,  9 Nov 2022 12:00:47 -0800
Message-Id: <20221109200050.3400857-4-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221109194404.gonna.558-kees@kernel.org>
References: <20221109194404.gonna.558-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=5558; h=from:subject; bh=VhZyajDguwXIOeRKKSSBP5ZVJr/iLJGDdjMef3dLzMw=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjbAbwCC8IljHAxeFaKkt0TLagUmeHw0bhuvd7ksR8 fg83TzSJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY2wG8AAKCRCJcvTf3G3AJifHEA CxHC8oBdRT9jmscKAq1CLjsng9Xu0W2++MH6aYtXPPh25LnNhXYdV9KUvaJjzFjqRkkI7X5f9hEATv 9nuFwmdAocHRelXYsa4bEIsLo/KYPVXuoagngmb7VfQcwJ84BzZAwvxcPH5Lkn1BJa6niOTpms388R 9rtIAL21U66N//NJHwbMuybr3RL+OGqIYN3Dl1jaggZMneQyFFBzuBDa5QZ0WG20DEvRLXEfPNUXZE byJiHgygyJNN5ng21MQ5yPhekwsLUFIR+9BXrupZBP9NH7lCWAW5a9fKMnIKKwOcG8hhfjcdMaBjb3 il3beRvwO4Fzrrw/8NDh12B5l5nd/fxNQK6bko4ILshXi/05VG308GEXdKecc9Y2EUAJB5aHVrKY0H NOK7XHUBeVeT70pDl7A76wtfe/2/ti5ukPfkzBOlblWr0swqFt210ZL05WDfZuNfRAzyxOtfU3lxnZ am+wMKJDx7OdRfhVEYGLVSaOinlE629WiO8FjhY7Ev3SHPoUOiRB+uJXcApTQYPFBS869SOiPmpt1w gaMKFf8mCAF4tclFqFV9nf9f0ORxE4YzFGmUuzSZFAVALBhH+1o+kbr3IlDU2hn0VyuYC2CDdAcNon 9Nwk+/4iG4f3rNqthjUpAvew2tvHiooY4Lp+2aA8LsYzaf05DNZtDkIKbTng==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=EhVqRQKR;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

Several run-time checkers (KASAN, UBSAN, KFENCE, KCSAN, sched) roll
their own warnings, and each check "panic_on_warn". Consolidate this
into a single function so that future instrumentation can be added in
a single location.

Cc: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
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
Cc: Luis Chamberlain <mcgrof@kernel.org>
Cc: David Gow <davidgow@google.com>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: Jann Horn <jannh@google.com>
Cc: Petr Mladek <pmladek@suse.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 include/linux/panic.h | 1 +
 kernel/kcsan/report.c | 3 +--
 kernel/panic.c        | 9 +++++++--
 kernel/sched/core.c   | 3 +--
 lib/ubsan.c           | 3 +--
 mm/kasan/report.c     | 4 ++--
 mm/kfence/report.c    | 3 +--
 7 files changed, 14 insertions(+), 12 deletions(-)

diff --git a/include/linux/panic.h b/include/linux/panic.h
index c7759b3f2045..1702aeb74927 100644
--- a/include/linux/panic.h
+++ b/include/linux/panic.h
@@ -11,6 +11,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *reason);
 extern void oops_enter(void);
 extern void oops_exit(void);
 extern bool oops_may_print(void);
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 67794404042a..e95ce7d7a76e 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -492,8 +492,7 @@ static void print_report(enum kcsan_value_change value_change,
 	dump_stack_print_info(KERN_DEFAULT);
 	pr_err("==================================================================\n");
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KCSAN");
 }
 
 static void release_report(unsigned long *flags, struct other_info *other_info)
diff --git a/kernel/panic.c b/kernel/panic.c
index 129936511380..3afd234767bc 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -201,6 +201,12 @@ static void panic_print_sys_info(bool console_flush)
 		ftrace_dump(DUMP_ALL);
 }
 
+void check_panic_on_warn(const char *reason)
+{
+	if (panic_on_warn)
+		panic("%s: panic_on_warn set ...\n", reason);
+}
+
 /**
  *	panic - halt the system
  *	@fmt: The text string to print
@@ -619,8 +625,7 @@ void __warn(const char *file, int line, void *caller, unsigned taint,
 	if (regs)
 		show_regs(regs);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	if (!regs)
 		dump_stack();
diff --git a/kernel/sched/core.c b/kernel/sched/core.c
index 5800b0623ff3..285ef8821b4f 100644
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -5729,8 +5729,7 @@ static noinline void __schedule_bug(struct task_struct *prev)
 		pr_err("Preemption disabled at:");
 		print_ip_sym(KERN_ERR, preempt_disable_ip);
 	}
-	if (panic_on_warn)
-		panic("scheduling while atomic\n");
+	check_panic_on_warn("scheduling while atomic");
 
 	dump_stack();
 	add_taint(TAINT_WARN, LOCKDEP_STILL_OK);
diff --git a/lib/ubsan.c b/lib/ubsan.c
index 36bd75e33426..60c7099857a0 100644
--- a/lib/ubsan.c
+++ b/lib/ubsan.c
@@ -154,8 +154,7 @@ static void ubsan_epilogue(void)
 
 	current->in_ubsan--;
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("UBSAN");
 }
 
 void __ubsan_handle_divrem_overflow(void *_data, void *lhs, void *rhs)
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index df3602062bfd..cc98dfdd3ed2 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -164,8 +164,8 @@ static void end_report(unsigned long *flags, void *addr)
 				       (unsigned long)addr);
 	pr_err("==================================================================\n");
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
-		panic("panic_on_warn set ...\n");
+	if (!test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
+		check_panic_on_warn("KASAN");
 	if (kasan_arg_fault == KASAN_ARG_FAULT_PANIC)
 		panic("kasan.fault=panic set ...\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 7e496856c2eb..110c27ca597d 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -268,8 +268,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 	lockdep_on();
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("KFENCE");
 
 	/* We encountered a memory safety error, taint the kernel! */
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_STILL_OK);
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221109200050.3400857-4-keescook%40chromium.org.
