Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FDWDDAMGQEEGCABRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 17392B84FF3
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:50 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-578f6ae374fsf363863e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204409; cv=pass;
        d=google.com; s=arc-20240605;
        b=QZVBjUiodVlyTNukJz09xkayXMnLhPeg7wICfhcCgO9nwYHVG+hmyr6jUIUyJB5hRg
         B4Jiq+FNgR3nv7iHGmRTyGqjQd9FIhZo/q3kJA4eTo/XJMYRm7+XU6tsIQgYpHewM95d
         Ly6sBG/9zLO9ZL/OspMDJ5TLmkjYYOAmB4Z0GKs1ubBu6s9EIOhI1u2eQtqmGims9CYZ
         dmqBgiPvlcSU/rr0wWzYMYitTxqzKFQmhZhuSwqZGaGOtDgVI003rwzAAVXtIfaYZW6C
         nvj9d+fCnlE9uZ85C/uI47bCbn38Be/8pI6vZFQdhk9mfdogjO426mx7OczOdHUiwvkg
         J4hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ep4idzlGBg+HdRJODkinCV0QYJNDTrkhyafFgtG5oo4=;
        fh=qj857ol2AqZRauDzSaGvJJ6HLm0tJr5YNJFad3UyzM8=;
        b=MsWSYr6zMDfLBio/ClnN4du1aARk/TZqDPuFSbNpfiHEKe82TDvkdA+wm07RH2D8Xm
         afKQbNkarzyQkCuSRvFCE9KTzsF8gvJQuHsk2SZjct2lM7i8BnolFRpfFT/rNf0vRyzv
         NaflA6zOqwvQN3iqGQN9EINc87nwgc91xlM50K/j+QNo5aWEbJqAUb7B2nD0RTC+YKuC
         svpXCdAUbbOt5CwLL3XcR3h4l7YgcvbvHc/mbPZYrh40BO3LfepVHW6PQEFsIoU4IRNe
         Bd1Z+nLPv/vwts+DPoeGh4I1XzHBQuy5gkpUtXgtgRjSJk+mGchUWom0adWq3dLqcmgj
         WSZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CZryqzK2;
       spf=pass (google.com: domain of 39rhmaaukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39RHMaAUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204409; x=1758809209; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ep4idzlGBg+HdRJODkinCV0QYJNDTrkhyafFgtG5oo4=;
        b=jsVtQ6hscjVBL2UmblwH1c8GjtOUC9xUunffmLMFzxt9mCSuXsLjF5SAjIr31iGLdC
         R1/H0pbhGnRWbwUdWPL8RPC5IgNYpNDDcPKUbE0AD2QpM+wlg92v99Xt6H9S+ZAROJJR
         8zVDeu4Ak9tcGNNLWN0FsPL4Jk8mDx5yRBaR5sRzsN1weO0v17+v8gJnNGKJafrpUODJ
         Js4E8UycD9i43LyHWijJJh+IcISTkKGId7QXwGnUvvWP8GLtdKYh1joSSb9VLuUFxzd+
         Bt5RvDko82S84yciz5bEGM2rSUBIMKTgyT7C1Eaft4lAeYhDhAUaKoB399jrXiyZEYvT
         PX2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204409; x=1758809209;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ep4idzlGBg+HdRJODkinCV0QYJNDTrkhyafFgtG5oo4=;
        b=ccVUjpJgmPJau/2RB6aBS/qF8s7l+Xu+x/ltbopOBuz/Swl5vm5WHmH6y5M7YxKvke
         XswlhF24kIMQRcWbbngBDTQK+zRMohIXTQ14SeTtxw3faM6RRlHrFaV7kVxRMlan+RZ0
         k15MjMBZOjrHGNqQwC/+yV2c1Idydg7jeR8+DxVh9/sMMillUXSgGO1LL4wKPUQvzXpB
         0CzCtr9TiWIsRdRJCKUGqWdzud1T8gIPAXehUPKvwg6rw8BttCbxZ+2O3trZ6PIZU+5G
         pePWWtohmWGa0KKSuqVSdSgdOtrhbpHeZKokPRzjbzD+w9CwjBMtXgfluCLdeG2CU9qh
         /Keg==
X-Forwarded-Encrypted: i=2; AJvYcCXQKcfnJ67QwfH/wGyuvW/R05QEtCkPtB477IDzSypAXMBHyyzFjXBg3uJ9XKticFtucqyhLw==@lfdr.de
X-Gm-Message-State: AOJu0Ywzm6Bw3J505EA6R1SZCdFJ4cAAqApAq2//KM1SWj9zY/mFxzFY
	kutIgyBZ/KA7rix2/JAXNY7JMMsf1ZSggNSHqvWQP1hSBKLFyAfXxmra
X-Google-Smtp-Source: AGHT+IGv3glHhQAJUG6tVSYM+bE8w/CxlkxjRHNRmhDczBytvqKYfCYKP3v+eblUNJNXFCdF0COXhw==
X-Received: by 2002:a05:6512:130c:b0:55f:3e26:24fa with SMTP id 2adb3069b0e04-5779c29512bmr2030597e87.47.1758204409090;
        Thu, 18 Sep 2025 07:06:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5HrvpyRJCHlANdOsG1F5iN8uoQIMHWEAfj56tQ+EoGmQ==
Received: by 2002:a05:6512:63d7:20b0:579:7beb:325a with SMTP id
 2adb3069b0e04-5797beb3382ls86283e87.0.-pod-prod-07-eu; Thu, 18 Sep 2025
 07:06:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVkfuGaLKfWTf7N3WPdWL4183ksN5zee3PzXdSCLLI5PLyCa7niGTTmIzJ7khn6fi8apOZjHFl6RkI=@googlegroups.com
X-Received: by 2002:a05:6512:398f:b0:561:5465:e69f with SMTP id 2adb3069b0e04-577996f12e4mr1842467e87.8.1758204406102;
        Thu, 18 Sep 2025 07:06:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204406; cv=none;
        d=google.com; s=arc-20240605;
        b=OZl3FBPLKMurYclcPPvoHS0eSbDkCoijZ76ak7KhDvZY7oHq9g8+O2RnXHxkecedyv
         A/8SAQVAcoAKcyM3CwoqBoeQginjZpiNLpAJwsNrXFZ37e+qUEP7ylLmzbi378638JwS
         fkNKUuk0e+0spi5EBdOLeceROEmmrEp0g19GUwEytYeZaqcnAG5KEZt8HoLcLE0ya7Kd
         24dtxHq3eDuGF6niRS6rBeghXbOH1u8exvbwZYZHZP/Gm+ORVNgCboBJBBrvFQuqlshQ
         rsJrL49hORETdGbCvITRiFNiXwB7KoREcnwkVeu8morgb9JAL8kgfLimg9OBbBlmihLK
         FCIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=bAfkPofnq3bpowTJFISAR394BQXpDstNh3Kk+W2FONk=;
        fh=+GjIHe1EzksZm2WUZ425I+Tp4d2xW30vNICDIz0lzhU=;
        b=ajlrjLgWLB2MyQs894OI3VNVM9Z9YVuw+7uMgOoe6i+JBTaz7u/Mk7CpRiDIO3eJjk
         TAOKK1qFDzzcxuBD2lJm3aN4q4eGQjKJ8QFFJp6Lc0PF54nqDBB8eE8BSzKeqWMbLvH/
         0NJF53SD2YetCVqJQeDKoV0ZZHjPczkRqR/yBxFz97SMoiUhsHd/SqOM/Lqxq12PRHVH
         Z/GD1eZEj35yarGxUXqzfbXGYz1a/h4fOEXSvw0Z3L7g49ua43g4rL4859YlU5m+Ihgi
         dLSdl/s8NmScFKi2vQCVLrKo/vhUufisF5qTq/50rWXYQm/cwV/wFCwKFvGUi4cEVx2T
         J5uw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CZryqzK2;
       spf=pass (google.com: domain of 39rhmaaukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39RHMaAUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-578a7a7ff53si48079e87.4.2025.09.18.07.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39rhmaaukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45f2b0eba08so6023965e9.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXLYtpLdpzgjCQLA1yT1+F6da7BDWMxTmYntWT6wxkNiCtz5iZ+ukUuYNVTdQ64kLPCRP8wOuFl7oU=@googlegroups.com
X-Received: from wmbfp9.prod.google.com ([2002:a05:600c:6989:b0:45f:27a7:738d])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:4ed1:b0:45d:dae8:b137
 with SMTP id 5b1f17b1804b1-46205cc86damr55535755e9.22.1758204405297; Thu, 18
 Sep 2025 07:06:45 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:40 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-30-elver@google.com>
Subject: [PATCH v3 29/35] kcsan: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Lukas Bulwahn <lukas.bulwahn@gmail.com>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=CZryqzK2;       spf=pass
 (google.com: domain of 39rhmaaukczy4bl4h6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=39RHMaAUKCZY4BL4H6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Enable capability analysis for the KCSAN subsystem.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* New patch.
---
 kernel/kcsan/Makefile |  2 ++
 kernel/kcsan/report.c | 11 ++++++++---
 2 files changed, 10 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index a45f3dfc8d14..b088aa01409f 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -1,4 +1,6 @@
 # SPDX-License-Identifier: GPL-2.0
+CAPABILITY_ANALYSIS := y
+
 KCSAN_SANITIZE := n
 KCOV_INSTRUMENT := n
 UBSAN_SANITIZE := n
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index e95ce7d7a76e..11a48b78f8d1 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -116,6 +116,7 @@ static DEFINE_RAW_SPINLOCK(report_lock);
  * been reported since (now - KCSAN_REPORT_ONCE_IN_MS).
  */
 static bool rate_limit_report(unsigned long frame1, unsigned long frame2)
+	__must_hold(&report_lock)
 {
 	struct report_time *use_entry = &report_times[0];
 	unsigned long invalid_before;
@@ -366,6 +367,7 @@ static int sym_strcmp(void *addr1, void *addr2)
 
 static void
 print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long reordered_to)
+	__must_hold(&report_lock)
 {
 	stack_trace_print(stack_entries, num_entries, 0);
 	if (reordered_to)
@@ -373,6 +375,7 @@ print_stack_trace(unsigned long stack_entries[], int num_entries, unsigned long
 }
 
 static void print_verbose_info(struct task_struct *task)
+	__must_hold(&report_lock)
 {
 	if (!task)
 		return;
@@ -389,6 +392,7 @@ static void print_report(enum kcsan_value_change value_change,
 			 const struct access_info *ai,
 			 struct other_info *other_info,
 			 u64 old, u64 new, u64 mask)
+	__must_hold(&report_lock)
 {
 	unsigned long reordered_to = 0;
 	unsigned long stack_entries[NUM_STACK_ENTRIES] = { 0 };
@@ -496,6 +500,7 @@ static void print_report(enum kcsan_value_change value_change,
 }
 
 static void release_report(unsigned long *flags, struct other_info *other_info)
+	__releases(&report_lock)
 {
 	/*
 	 * Use size to denote valid/invalid, since KCSAN entirely ignores
@@ -507,13 +512,11 @@ static void release_report(unsigned long *flags, struct other_info *other_info)
 
 /*
  * Sets @other_info->task and awaits consumption of @other_info.
- *
- * Precondition: report_lock is held.
- * Postcondition: report_lock is held.
  */
 static void set_other_info_task_blocking(unsigned long *flags,
 					 const struct access_info *ai,
 					 struct other_info *other_info)
+	__must_hold(&report_lock)
 {
 	/*
 	 * We may be instrumenting a code-path where current->state is already
@@ -572,6 +575,7 @@ static void set_other_info_task_blocking(unsigned long *flags,
 static void prepare_report_producer(unsigned long *flags,
 				    const struct access_info *ai,
 				    struct other_info *other_info)
+	__must_not_hold(&report_lock)
 {
 	raw_spin_lock_irqsave(&report_lock, *flags);
 
@@ -603,6 +607,7 @@ static void prepare_report_producer(unsigned long *flags,
 static bool prepare_report_consumer(unsigned long *flags,
 				    const struct access_info *ai,
 				    struct other_info *other_info)
+	__cond_acquires(true, &report_lock)
 {
 
 	raw_spin_lock_irqsave(&report_lock, *flags);
-- 
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-30-elver%40google.com.
