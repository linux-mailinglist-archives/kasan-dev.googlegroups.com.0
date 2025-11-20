Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK7A7TEAMGQEX6KV53I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1E9B6C74C99
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:49 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5957bd7530asf786796e87.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651628; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dw+AW0r6CGuSFC8moEG5d3rb+zQJCqyFc2aXVkZR5I/OdZ3OjoaHh++xxtJWHX8Ko/
         4k50OeS02+8G4pQU6fjY9Xa7m+QdVono8ucyVb91egto79KgHiU2916H4xjH9i+pHWOD
         d15hVYbHna1+PVWtWtH5io3BnlVHHV9Zov8VyzX4L9dN9V7OwTXyyJKzc0Uf7fOOf1dk
         ub3SFcl8CgXrgKFNlWg0ixJaz6dWGSV0aX+9sokpSLVtYnJrlUxdm2NSKX7tpfCSF1u+
         9Wzos8Ybvcsg6ILifzs4lOAckYWOusWBXhvpZapUyoPpeb2vPcjqdH333EpmFfszN5yC
         ZW2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LAyRI/gQKFvNtMs54M1DsVvQaoAZL7aS0/j65JNnY4I=;
        fh=HlO6eHCrgRVVfWjavzLIoq4sKOgWFd4vSGNsXX3bsWk=;
        b=AB3kOM9NCXEgee/hiC1Cqs5VFBzrqYObGz1vMz3HgZMRh1FdDVYeCavcXZh/RIQJyy
         +tunVTICriM6uuCN0fbcszZ/gcJwruD1Qj8WyDvY/yAymDhF9Or5H3ecYLuYonf4aKyV
         4Ebm+oafAyX6sF6fLzCRagOMGplWprVW3cAbIa4Owz21W6PmbjFsmVIntJjI8NeTmhvK
         mNj3SW87fqdfw3cSI2PhdmH6/rmWUXZwzzQ7dXWXKVHLHhLyydPwJZPiPnpCqgiNzT5H
         DKpDOMm0alFbkXQEboZTZABzFBSWp5MwHUx/vtYBL54cypytuX/wR+x19jSroIrWmfxZ
         2iGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yXpFVVTh;
       spf=pass (google.com: domain of 3jzafaqukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3JzAfaQUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651628; x=1764256428; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LAyRI/gQKFvNtMs54M1DsVvQaoAZL7aS0/j65JNnY4I=;
        b=XQSqrBMlrKXDqGqeoEkz2n7yA/l8df8eZkIsBFJP+kML6NzyhZwcAGkMZFmPkTjHqF
         nq/RLgshhH9GeBdXA7+/Mlp2WFu6vf93UFk28euEni8iB/NX23ufC/si/8nvVpX7QlNr
         vlEH9eUCq7jBXhs667A95FjLim4D7cJhK1ifjErXi/DsClm8jtLapmkKG+rPaFBN/0pW
         Pr2PB+DkC+KBkNuHwOscJL+isx/lwv5TRcdKgMfVEeMRcOwranHn5RcA3w1vRViTi9/7
         4JZOYYDJFyqBOTVhWBktH6RLmAaLQnt+lSONT2+91WhanOVOHOQpMGK/EY1XnQzFQZYo
         TP6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651628; x=1764256428;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LAyRI/gQKFvNtMs54M1DsVvQaoAZL7aS0/j65JNnY4I=;
        b=e9o2WpETR9YftqPte1+O+MQc8h2iBYRoTn9OEer9FmOdlz7EV/O3NTA21EXQEdjuqM
         iBN+oW6uTDdPk4lSIkvAclnH80jdb3feWRVIwGX+O/dq3Pp5dxJHeuQRadEs/dEQB0Ak
         03UIybYzuCJVvCPSxT5HcbKJbuZ1YCiJNIDGtIptoJvec8jeEUZfw8BBaPQymhGULLij
         Tnka7/jES95uKhz/s7JwZ+8qFcxARypSuBAODadKQy4bJJMV69cblwY40ysqI0LeYp7m
         afz614xd8TXiYeTUEr+WkTFaTKOaH1WbT9056NVZJ7uFHzRbOlLigyMZdvF74pTvm+Bo
         da2Q==
X-Forwarded-Encrypted: i=2; AJvYcCUZaekU47N8+Cu6HUyRfEzKqQgmrWa2nAwpEuLeTJk7K3xFW7fFkME8hKUXw6utE2KH+nd+xQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz/Rm0vh/hxAi6zWVsVNlb5YyojkRMtQmaEC5pidEUm7RSxZpvU
	3njY3drQltZ1tBHK0IV4WYiffmdXJhsPrHUsYbVoJVWyZo3dzoxZAGo0
X-Google-Smtp-Source: AGHT+IHrb1dJwcJritsD99DXaLrymVyLVvJwDAFimtd3NkdGwpDTHiHmePepiIwE5c9o8KYftiyhtQ==
X-Received: by 2002:a05:6512:1194:b0:594:34c4:a325 with SMTP id 2adb3069b0e04-5969e320a68mr1184122e87.46.1763651628117;
        Thu, 20 Nov 2025 07:13:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bbSbI0CoEifTts7p2unngAkweeB1+NBHBoDmYK2xIh5A=="
Received: by 2002:a05:6512:250b:b0:595:9685:82bc with SMTP id
 2adb3069b0e04-5969dc94f27ls17452e87.2.-pod-prod-09-eu; Thu, 20 Nov 2025
 07:13:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUvedCP79SnvXT6JzuYKUTKptqggyNegnz6wdD7Rr58dbxXM7VMxt1SYdw1Ap9HG9WEaJoRWRLbs9g=@googlegroups.com
X-Received: by 2002:a05:6512:3b29:b0:595:81c1:c57 with SMTP id 2adb3069b0e04-5969e2d9282mr1133415e87.11.1763651624813;
        Thu, 20 Nov 2025 07:13:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651624; cv=none;
        d=google.com; s=arc-20240605;
        b=ZM8KOn7He4sCGgWAhqMnZqMfG7cWsjhfNWeltc1WH8VEewncrbb4+qyEdA0o4DOynB
         NmRoSxzCv4v8pijHUJXSp30AEw9BSHJyiOd1dezURz4COYss0q6q4KHLzDdVGS8Bfm62
         bHMQye3ddjLD3kvN6etT31vGBV9LYJ9eTeo1h5Ja4eC4VmA+M5d/23A7eW6YuVn0zuQi
         8jfSCQPjDs9v0Bhe4yQKSpSBT/F7t8Bh9vgU/8IQKsyHymP/OLQC70ueq+gzpOm2JXZA
         XscDWLCmTLqj4WITc9LnXblMJyMRiYrDHq7pclq8/pUSTEd3Z96AFVzioJvH3cCwOTF1
         DbXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=P9dnEf98rT3yxtmvLOfZj9VjyyDpDqGX8DLsl5ZbgJ0=;
        fh=PNK4iRJUUz8ife8oNYRWraydA9uu2aC25RX7QuxRNjE=;
        b=DmdqcpGDqe5tedSjuQ4SiAYIgMh/WKUgNuM7o41Oh3Hvhj5y+Q7lzQx1u8brE0xLrc
         i/NLLs/7yo17+SBqt36+qUiVssSacSvSWpj69j7dFZ1sg3MphmXz14/c6MIC7AGm4MYP
         EcStsihuII6K/wb/FGqSXCdzXVso4twb7nn0gbhll7RQ9WysGwCBWUUb3e4CrS9/Uwvk
         jvnLtyF4XXrdlIOc8rHzB91ID1fgH3n6AVskrM7TASXGMVlqdxd+vyAJiZEayJitiIgf
         BKuA7wxtxgmQ+78q922ITn1UP1nAkpDnr4xsFuIttAwwWlmiaiGCfw7JLULrcWHD+Sog
         Nk/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=yXpFVVTh;
       spf=pass (google.com: domain of 3jzafaqukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3JzAfaQUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dbac281si61209e87.5.2025.11.20.07.13.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:44 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jzafaqukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4775d8428e8so7790325e9.0
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:44 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW6F9fMCqirbcQ/SV7MwLZjTnEbAu8yAzwVFcCmDrY5HzrgJrL8Yo5UovL7S+FLOSFIGfNj5PdiuY8=@googlegroups.com
X-Received: from wmpq6.prod.google.com ([2002:a05:600c:3306:b0:477:9976:8214])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:b95:b0:471:21:554a
 with SMTP id 5b1f17b1804b1-477b9dd716fmr25371575e9.13.1763651623805; Thu, 20
 Nov 2025 07:13:43 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:54 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-30-elver@google.com>
Subject: [PATCH v4 29/35] kcsan: Enable context analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=yXpFVVTh;       spf=pass
 (google.com: domain of 3jzafaqukcvq07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3JzAfaQUKCVQ07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

Enable context analysis for the KCSAN subsystem.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Rename capability -> context analysis.

v3:
* New patch.
---
 kernel/kcsan/Makefile |  2 ++
 kernel/kcsan/report.c | 11 ++++++++---
 2 files changed, 10 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index a45f3dfc8d14..824f30c93252 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -1,4 +1,6 @@
 # SPDX-License-Identifier: GPL-2.0
+CONTEXT_ANALYSIS := y
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-30-elver%40google.com.
