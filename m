Return-Path: <kasan-dev+bncBCF5XGNWYQBRBI4O3ONQMGQEQJ4XKCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 64B3B62E9BA
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:43:33 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id bw25-20020a056a00409900b0056bdd4f8818sf1959140pfb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:43:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668728612; cv=pass;
        d=google.com; s=arc-20160816;
        b=e8bmU9kpsDegkG+Klq6AwNtHztR6MjAG5J5bGNDh6Se4O6ntyHsNpB6eC6TU2nomwD
         tZKn3/il2uyLrBokRvciu68RAv/LXEioKZik2u1q+fPOJb9arutACN4KaH3Bfkt2G1vU
         wMDuk6SSPojOOxtdQ36JKhIrzPCQ2iWNVSBtBEwkLrdLZ2JWivs6WQ4fSFMepygH+Zut
         ZrntAOvdVOPmG79WvHK0G4MoSa5xKkZJJHM8HFLiw/6/3Fq/8kppUmOnoxLHZ2HmUaGH
         tda+OiimI9/EcrlKHbn0lax9Mb3F+MhRTyiqfB+sf7dG716UqJcbcDyhm+MedLtPNzJu
         8v/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gict+675bfeeeQMUcmKvwo7jz0bDquv/+WFYxyo+UEg=;
        b=IOY89Wvq+A6wzlg1ygHJlQWY0O2r1yStVgju9N/QI3RoCrHKlSoP0eE3a7qWzbYqkZ
         WnM/L/m14E4isC0om40PHzjJHno5VaY54Zf2+1wlYwvQRtz1JUzu/hqZgc4yvsLc178N
         47AlKFQJ5PqgZbVMfmdMtmUsxOkFeY0n32UNbWyAvGyr5QavBu+nAfN7JiyXnUJWV64V
         61Mb+7ICsp4JkxeeR4kp8QcsaN0r9k57jQrYh7lCZZKhwC23io3VlCAQRJ6aSMIEX/J7
         P4YdsuDSIww3A7fAgeLFA6x63C+JL8RcjYZ69uXfE87XeI9jdETx2eTfSQMVXg5L3Dx9
         E4sA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JAmzMP7D;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gict+675bfeeeQMUcmKvwo7jz0bDquv/+WFYxyo+UEg=;
        b=cXYNxeyV3KfCXQynPNRUCYXMabVqOFIHFiGCQCJPGS/9jYbaS1AvR5tX0Co4IRSSum
         zj9aRaY5M7yI8xNzo1fqskR4SBYMPzvuUNdz0eiSM9TMX025y5FtEaVrmm39QSY5DkZk
         jekLz8uehIDHul7aiIQXIB+pg+XXVNxCZryhkFkZVE4cadeVazs+xV4wEyzN+N3rsbz5
         bdY3lljciqFCNmjNpElruLmg2YHcdDFOAVmGVdyjGhZnJcyk8qaemPSNhEEZ696qhiWA
         L8pqKa6Rlh66yrjvzDzeX8ZK7fXvuldg+GqlFraFcHsz8JQC2SZC4E/OH2u8mvAUkrrP
         3Sow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gict+675bfeeeQMUcmKvwo7jz0bDquv/+WFYxyo+UEg=;
        b=x9ClH4bfns9DCT6lSiJOUu08v7BnV8foCjphH7YsGSZUyuKpe8Oq4GbMf0iOsQCsFj
         5yBZvjlrABBWeOUvblVl9Ux7b2iXXvotJ8LLZ6BMAha97pMDtqShw1kOq3Ygb8nx8/li
         L65OJs8KHfYah6ef4s1lS++xPgz8fpU85bYoO8ox1c0MS8Gn1cPCOgTJYe8OQNNPrdtf
         9GxYq9f5RJZy0WjSq6dhnlBQTxIzndqq5+S/pR6BC/DZhk9mCht97rKDQRcdHPYbrXA2
         3q/+dTuuqAp3hOAfVyFvCGRfx54PIWgmuEXs10TvG3C0xrWf3gGL29xnrBIiQsEAPc3v
         GklA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pncozN5uK0lzHM5YnikxULPQDWqgLKkLif/9bZ8+b+TNEymGpio
	50VFDXpVtcqhMyCS2W+plbk=
X-Google-Smtp-Source: AA0mqf6UlDJqVQLmGTGThAXG/MN/pO4J0qnD125KSrG7NBKhdOIq2taQIJRn04gPPOlFHHw3yWIZrQ==
X-Received: by 2002:a17:90a:5c85:b0:20a:92d2:226a with SMTP id r5-20020a17090a5c8500b0020a92d2226amr5055858pji.155.1668728612003;
        Thu, 17 Nov 2022 15:43:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:86c6:0:b0:46e:c77e:ea84 with SMTP id x189-20020a6386c6000000b0046ec77eea84ls1831339pgd.3.-pod-prod-gmail;
 Thu, 17 Nov 2022 15:43:31 -0800 (PST)
X-Received: by 2002:a62:7b47:0:b0:56c:7b59:5137 with SMTP id w68-20020a627b47000000b0056c7b595137mr5115231pfc.74.1668728611301;
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668728611; cv=none;
        d=google.com; s=arc-20160816;
        b=Oqim2F17lnlW/VlHy5AeeDRrwBGMM7w7AFlNQ66/KPr/hURqW0aZOf0QqpKENoxEoJ
         3X/x5w/ohdiVsR3ATu9iI9tneILi3cuE9D9HFUE0b6oFqm10+1/2m+aYs3H68bYD67+R
         khOjnRlJBzJwkeGbQUD0RXDLor2nBu6Y/lrJ3QpTIRumDECSuwNCIwps91DkWG2ojNdP
         7Y1MjIekrjOpR9S/KgA/T5wTwnYH8jkZHQRiOmXAsZKWU6wPgJvC3C5JPLvc+OlLVrEm
         AGdi8WCCJEl3r2yEc7kxU72nUK6nQiJXCQirmUcLMBGJGcPx5QuHvv/JV3HRbLKRrQKU
         mpKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=a4mv3CX5gtAvBGKnmAgdVfBbS+bjuaYuEHlpManO9ok=;
        b=hReblv+X8OqTJ103GxK9l2oC25z038DdwqQ8wsn2SeQZbgNtXKVFxpZSln0gtWT+LA
         AtTcrNt4PRvY3X+F9KuYAvQIHjZ0Nkkj/3aGrTtAVF2L3is9chS/o89LRo4oy8fKkH/2
         r+av6INBzLyfbqwZTOOf6UGZYsHfR4IfrKEhPs6/kXbPqeC+R7pnyDxBo/CsiHA0w2Jq
         rrl4AnMkwummCjVAHMiengawEdlAOlptDO0S9Q4xxpJiD+GRxQ2Vv1bakrE2NvtAeYbc
         DnqHEzelgDLcJvNp9is1C3lOlyut2+gL/9SWo/DVyP8UlkaC+O2kfF79UqV+REtxW7a+
         /XwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=JAmzMP7D;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x432.google.com (mail-pf1-x432.google.com. [2607:f8b0:4864:20::432])
        by gmr-mx.google.com with ESMTPS id l187-20020a6225c4000000b0056bb72479bdsi123101pfl.0.2022.11.17.15.43.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432 as permitted sender) client-ip=2607:f8b0:4864:20::432;
Received: by mail-pf1-x432.google.com with SMTP id z26so3315302pff.1
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:43:31 -0800 (PST)
X-Received: by 2002:a63:165d:0:b0:473:f7cd:6603 with SMTP id 29-20020a63165d000000b00473f7cd6603mr4329920pgw.336.1668728610990;
        Thu, 17 Nov 2022 15:43:30 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id ij27-20020a170902ab5b00b00188ea79fae0sm2006916plb.48.2022.11.17.15.43.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:43:29 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
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
	Luis Chamberlain <mcgrof@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
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
Subject: [PATCH v3 4/6] panic: Consolidate open-coded panic_on_warn checks
Date: Thu, 17 Nov 2022 15:43:24 -0800
Message-Id: <20221117234328.594699-4-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221117233838.give.484-kees@kernel.org>
References: <20221117233838.give.484-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=5647; h=from:subject; bh=sxOIx5raY6nqpOG6YuXQYmflOUxoB4Lnr7UKuKqtC5Y=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjdscd2xOTxn5Fhuk9GHBu0+Cr2QXYwrSk2jHMMYhU hJUbffSJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY3bHHQAKCRCJcvTf3G3AJt2tEA CMAqhij2qsXL2q83Hi+yD1DUdHylf9XtJBUQ9nTL4LZpDtQlwpcXUruFfqc7cO9Qvcgf7Vcd3F9mq8 YnbF7Lw8McfpAWbrUALH/5lHVT6JR3HJ3wqRpcBjjC8j2fVbw+iFzXhufGOSOnI1FVtv3fSOS9wPws xiMYgUYWAvh1hpNRmS1mcy0EPLe4qocZLXb7qAnudPi8jy6RICKkPOoDN3zBnbY3D/4qq6bnoCm8tq MNu8W+hcuSpVh9UuUHw5yY898bSzCo3xS9SyHat8AagX5VORkdI7aB7n2Exm/p7ssIqoMhO4AfEKk1 z4hwroXVI9oMflHVHic//69Bu7Zvy29pGbqdYdssmz6H29qJhoRbU8xDIwVZ2xXJyj3qTtn6fjFKpd SW2d42wsi09rP/x1qiRySqimGVyM0tpM+iFhPXhaHfy+DWxNpdZY8M2qkPLX8D7byj+be1neeh4BPf CvWku0SS6YQDRkhMpQ9r1HlkkluJmJ9PhfLejqKgI+zdl8ihrsRJXRC255MhtnRYVCL+XtYYp4Tx0G qGmtZr8uDxv0TcU0eTgVsEw9ZIjcOAjRrkBaxVkFeqn1Uvfvyr+5jHAsqoaK+R2nov5FpdgxYxiYsZ nhr7fXddGhkxOEhViYRsnjF0kpB02cvImdzarQaeUlm8tOiOdy4EN7l3vHWA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=JAmzMP7D;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::432
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
index c7759b3f2045..979b776e3bcb 100644
--- a/include/linux/panic.h
+++ b/include/linux/panic.h
@@ -11,6 +11,7 @@ extern long (*panic_blink)(int state);
 __printf(1, 2)
 void panic(const char *fmt, ...) __noreturn __cold;
 void nmi_panic(struct pt_regs *regs, const char *msg);
+void check_panic_on_warn(const char *origin);
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
index d843d036651e..cfa354322d5f 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -201,6 +201,12 @@ static void panic_print_sys_info(bool console_flush)
 		ftrace_dump(DUMP_ALL);
 }
 
+void check_panic_on_warn(const char *origin)
+{
+	if (panic_on_warn)
+		panic("%s: panic_on_warn set ...\n", origin);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221117234328.594699-4-keescook%40chromium.org.
