Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBCN66OPAMGQEAABDHNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 96359689508
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Feb 2023 11:16:43 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id 201-20020a6300d2000000b004ccf545f44fsf2403297pga.12
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Feb 2023 02:16:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675419402; cv=pass;
        d=google.com; s=arc-20160816;
        b=zPhfBHX5Y/fUQgUbtBXK1gGsCu7bGiAECpEe8wo8Xz5Cb4WN4j7GTo9fOhFplT0+6U
         0vB1xuhodxIEtgHeqHWIh2vRjjYJypb2EoLtl6hPCL/g4swiPzWXi7ofJgR2Hyx40rO3
         Dwb2Ju3Slp/tsLHEQOlsdvbf3s6aqvGFN9PRGRLimF3Tl30PznBqHz3ZfZy0wWI34VQK
         hMiYdUlWt4KMLv0NVoEZ5MdHL7PlnUiGSw+Aw9gskrc7kKKANPOgU98mAqHnwve1+XDa
         /FD3meZzfB5iX3w2BUF7jB46b7O8EJ0vVX7x1VJ0S3aMMrJSZwIi2Pj5deb6aqUJlAjb
         p1ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=s9f4HD/aT0ER+y5ouMlKOtenVcGQa5DIx3T0UYqa2LA=;
        b=PyYZ80hw1d7cUJyIqtAnaxWBoxf01Rj2M0wYj9QAoAESUohgs7ZXKwCGSEJmJN30Cj
         YpsLgEc3QL1L5YkAE6cvgYMn9h53Wej57OwDQ+tH8ZNC0SdyZxYEi1nSripldIIeAETt
         T9vNCke6Xc8ke4NP9VrzXiEIpf8obBe5nP4c6VisTbKaLdozDnldfuYi3WqZY7zA7zib
         dm95IHaaMVT5E6oO5dvTqv6nPsNCK6P6Le8cqpsX5cjfbzdmcH7Vz3ZSoj3IoK812H+d
         ciZbHPhKUH41ohTPGjN+jjx0mADAINJGwsIo+YmgUB7h09UnAEllfFIMyZH0nK5HpwsZ
         ytyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=1nPcQt5f;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=s9f4HD/aT0ER+y5ouMlKOtenVcGQa5DIx3T0UYqa2LA=;
        b=tTyrEvnEoV1EhhUFSRo+Jmap/wOWw6//lN3Iil1Z6vBxIRV1zPfKJbWBc3TqlMC1uw
         rHHEZN4uE6PFQSs9yYnnQBSpJMnemDKcAPofJ4v77y6aGi2zLI+nvYdqQJqRdvM2isy9
         OToXsqk54m23G9sADExAL2Q/NXmANi/8jbj4FcRWS08rt9hb5aYw/F+63FGb1+i5HKHy
         RXWmIgE/2nqRYCTltDpc/YxGN3SJXH5c08kTGGF4df092EW1AvR1BA8nhI/mIKfpiMRw
         WY4Or2EipImCxnU9MNpXWGwOvrrbSKAZBCUXYYiOxb1k1f/0CHow9oZZWvIP2bj4tZG4
         pISw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=s9f4HD/aT0ER+y5ouMlKOtenVcGQa5DIx3T0UYqa2LA=;
        b=vIX2oOYm1pzIuKdC8S76aTAUKmBcxTGE1tUngK2PaouKr76bW9s+VOFMM9aS58T83c
         M/eG8hh+9IqOTZvPVlKk8dNXz+D7XW4xQ1xUp+vKiGSqw77J/AjA5Kjac+ebN5WQTcwE
         Eq9Toj6bY7US0Bf/Py9IPucKzmV8HAiHG+DSRkDKFjgUqZ8U35TmILooRYv/RPF5T1Ii
         WSw7PrwHhSsesKLS/yZaqjFmpr/n/rhcA5Kd9a42PoZ5RJj7EPXHpPia3BlehGRGQNfk
         c/YoLToEFlAPcTrucZVIYRvjLXZjHjxelYtEK1cQG6EFfaHlYb4fnRYnM/f8nrypspUR
         5pdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUXPpjW9/vsPD61k/AfzXwXUJ/rR+AF1H2gwAh6IpEw81WnRVq/
	dfsFdWhNmTxqNhZ/lsuJiI8=
X-Google-Smtp-Source: AK7set99lgKX0ipVgQnevmanDvqj3FAWKxAzpl5TJAOFeieY3VkfBwB+tou5E+7WBZW+MqThsdfVzA==
X-Received: by 2002:a17:903:482:b0:18c:5dae:6f2 with SMTP id jj2-20020a170903048200b0018c5dae06f2mr2240538plb.24.1675419401648;
        Fri, 03 Feb 2023 02:16:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e881:b0:198:ddfb:494 with SMTP id
 w1-20020a170902e88100b00198ddfb0494ls1852497plg.8.-pod-prod-gmail; Fri, 03
 Feb 2023 02:16:40 -0800 (PST)
X-Received: by 2002:a05:6a20:3d96:b0:b6:c018:7fd8 with SMTP id s22-20020a056a203d9600b000b6c0187fd8mr11901124pzi.11.1675419400764;
        Fri, 03 Feb 2023 02:16:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675419400; cv=none;
        d=google.com; s=arc-20160816;
        b=GM9QtP3PsXaKzwx/53hu4egmhLAODjb4p3jH8LPq+NetOEfciXrGltEV9emGHYPsX2
         mrJzDhIMhUqF8g8ULmlkifN+xWNCG/a6TcE/b3fBFNN8e45e4twwd9D70U1790K2S3lk
         6s8yhtQOvVRTyOI3C9RMsyYMl8ruF2xBDWkO7PFURqJrz64tYRp0L+0neD3a9Ea9VWCV
         J1HlTAHxTSQN/FkQGjktpKeNmN1Sub3W2f+Vt4j573UOlWyjOh+qd2N4rnbdLUvfznCY
         GikFVqmp5TI26zI7GaOS2psl2v95J0bBPArsal4L3KfPWgfcjPZ7LUYM4qFNIv2da/vv
         xsHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=CPkCB3MnuIoX8ckhpCE/S/ALomLNl6p2lvtdVnu6MU8=;
        b=1A4TIuXWlzwFv2Meaz6F4PgVSrGBczXYaakO8KpA2rfm7kkvTwCZ3nnBlKnQzr7J3t
         Xc1sAwOfMmo/hKDJaAWUi5pKINe+TwD0p0vBcP7xlaS23vhK14FnLnj2+LKVYu7T24Yn
         NaYPScUsljoZey2f8yxWUA9wH0WYB62tNNSe/tkUY1lhg0ECRWzh+1cphFUco6hSqIjR
         g7HxnXguqo4n6ooeK/QmyCmkrP1/tZ898Br6v+YyIdPikui6e4BA12OzQV8bGeP3eJ5W
         C2mlWRUSp67F3LX1fJDJLns9Fbq425QENbaOKn+MSzoIJMUMzQMUMVK1El6oTfik3nuK
         A6Tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=1nPcQt5f;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id b34-20020a631b22000000b004e968328928si121536pgb.1.2023.02.03.02.16.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 03 Feb 2023 02:16:40 -0800 (PST)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3174F61E92;
	Fri,  3 Feb 2023 10:16:40 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8ACEBC4339C;
	Fri,  3 Feb 2023 10:16:38 +0000 (UTC)
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
Subject: [PATCH 4.14 55/62] panic: Consolidate open-coded panic_on_warn checks
Date: Fri,  3 Feb 2023 11:12:51 +0100
Message-Id: <20230203101015.317152114@linuxfoundation.org>
X-Mailer: git-send-email 2.39.1
In-Reply-To: <20230203101012.959398849@linuxfoundation.org>
References: <20230203101012.959398849@linuxfoundation.org>
User-Agent: quilt/0.67
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=1nPcQt5f;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
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
@@ -293,6 +293,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
 extern void oops_enter(void);
 extern void oops_exit(void);
 void print_oops_end_marker(void);
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -122,6 +122,12 @@ void nmi_panic(struct pt_regs *regs, con
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
@@ -546,8 +552,7 @@ void __warn(const char *file, int line,
 	if (args)
 		vprintk(args->fmt, args->args);
 
-	if (panic_on_warn)
-		panic("panic_on_warn set ...\n");
+	check_panic_on_warn("kernel");
 
 	print_modules();
 
--- a/kernel/sched/core.c
+++ b/kernel/sched/core.c
@@ -3185,8 +3185,7 @@ static noinline void __schedule_bug(stru
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
@@ -172,8 +172,7 @@ static void kasan_end_report(unsigned lo
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230203101015.317152114%40linuxfoundation.org.
