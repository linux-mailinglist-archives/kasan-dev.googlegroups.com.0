Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEHHSXFAMGQEIIYTDQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 50439CD09C2
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:30 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-595904df717sf1481384e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159249; cv=pass;
        d=google.com; s=arc-20240605;
        b=Yag/ADup0GGgEAxgL5q546zksF/sEPNbOHOwei7RuobxQudKgj8yEqM37bnJfV67Ze
         PiWDwX5rIToH5nu6rbq1REqjIanvi8SAo+g0oviwbv3PVcGPB9i1vLu+GHNEXD0Ij+Y7
         RgZNNlKobMBOU+HS0+DUL6sBxiSrPGqcPvN66KSwKubOhphAD8vLVuQoBX4oYsyY82ER
         Gs8zbJFO1K51BNWYifhnr9FSiiheogQMAGRyc1r67pdhWzwhUU4Pe90VINqDAV1u3leW
         gLSoekS2+qjHmqKslfMCa3Pa6q+ur59OZ3khfGJYDyjkDKxzF+UjgieLwgxqc2iBR6kF
         L1Cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=rE9l7X71Xuiz+vyVbLQAbNDr84TWWrAFXFMA9O3b9mE=;
        fh=h5hYvXrukN789YuAym5FdJ33kj97TlxTlnbu27XKIDQ=;
        b=INueYTBR/CFp03D07YeSGjGiq+KITOfEIiUm1Jrqm04/GwotBqpF0hbLOQ26uWX9R3
         NN3Vrr2SiXjC9YazeDGMQvDMGTWyiCPMc2vubvdvKpRmjyz363PER/nPf2ZNPdGSookA
         CCmDqE+jJBo68QK9L95fPq9NeI2OXRcu8JLtrxNkZIXOQoKvO2QF9kKrT6X3QLSR6SOw
         b3m3wL8q7fn1Jivzp9uGK5LWfvMltfjT8obSKsehZ0ltFGvYReVQgBrcW/TGmL/COjWU
         nX5UxVolvuxMxbzc9pcr/XQ5dpXw6JNMVt/OYw0t+dwmBzub2uMa/U0ZL1JY/eUf4P2x
         KCIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3rkxLZjq;
       spf=pass (google.com: domain of 3jxnfaqukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jXNFaQUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159249; x=1766764049; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rE9l7X71Xuiz+vyVbLQAbNDr84TWWrAFXFMA9O3b9mE=;
        b=ry+ieUfMpUYtzExkyE4kLT822N11rCR13sndA9iSNddEX3dx2IBoYoa6DtFu2WYfcW
         SK4BlEX2HuSzNM6r6hCKhrgeX0zLsVB8P7aE/DXUYS//HbNQ+6rQNIIPKGzIGl6c16ai
         8nsX5qnxzBITZMIw89gY1FIRljHM9Ow5U3NyKISfj2P2R285iKsZgNtQWGMB2suOrt17
         usN+eQLtpQfWuqvy4oQI/X/RtIwUqm46GKeUUv/5LCLhDQgqB7zLBfNXo1t0a510y7bu
         W41yjAzUthxs2oaInKU43Oi+46wf4umpAcap61iAOQocaOXGIUt6rposyaKebdwPyn1O
         7bCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159249; x=1766764049;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rE9l7X71Xuiz+vyVbLQAbNDr84TWWrAFXFMA9O3b9mE=;
        b=EbPh6W0FUPt/lUgBgrSvVAI5zxPyixu2FZNTJDmGdZCy2IA/PQSt2a2Vy33zsmIYSf
         m9g01psRbBzTdXdnfdnmgbJBif3a2Gv5HczfrI14NbNQXqxqkubbME44RndL927bV41e
         bGcFcvkFN4Hcet8cmw74yU+RmsvqH/NbLm/F+WIGVMY4z4tCnQKuIOb5dtSiUawEW1Qh
         lN9sP9FfV7agIWBAh8lVxOFmyxdznhuAb8BoORSg1oiuhG0kzTMnMhkqOIxdEWCPKuLl
         ZNgLuExLQ3tk5JgDWpDdrRkZuCObKgTMzyUOLZ8v5NcIMgOzuD7udfk/+1DQ8jTqDWDb
         roDQ==
X-Forwarded-Encrypted: i=2; AJvYcCVTtXN369U8n+OpPUNu6wSxAFsbA+wF3+PwnHSKexZA0I5Pg16yoK8/Dst8R8S0paxUKsXEoQ==@lfdr.de
X-Gm-Message-State: AOJu0YxiA4sdBpx9BRYcCQ74BcmoOn6hNlgVV8xIAmra9aaNOrPjM0xM
	IF7XWO61ND9hnEN/mcITRBqt4Q+QcuQlZwHWVWG6tK9ZV5O8Pt462RoK
X-Google-Smtp-Source: AGHT+IGITwO9OegKsaNWMRyLJ+CQioMWUOgodXX+8aDzNUge6nztpH6c185gu5zK/8LiheVJsnc3Fg==
X-Received: by 2002:a05:6512:3408:b0:595:81e5:7574 with SMTP id 2adb3069b0e04-59a17d357e4mr953354e87.20.1766159249353;
        Fri, 19 Dec 2025 07:47:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaiAUw5YAsxmim+Ws6w7YP5+pukGght7VhMld6dgEP99Q=="
Received: by 2002:a05:6512:6c4:b0:598:f954:f66c with SMTP id
 2adb3069b0e04-598fa3efa76ls527171e87.1.-pod-prod-01-eu; Fri, 19 Dec 2025
 07:47:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXcxVRB2thNUqQNYNro9ifET7+7M5D7R1Js6T/tWk1Bm6HKcYHvEoc3ILRrO7mpt7MPM+1hl/D8C6o=@googlegroups.com
X-Received: by 2002:a05:6512:3d91:b0:594:33fc:d52b with SMTP id 2adb3069b0e04-59a17d67bbemr1226300e87.36.1766159246473;
        Fri, 19 Dec 2025 07:47:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159246; cv=none;
        d=google.com; s=arc-20240605;
        b=LSQeQU2nwJ4QBOG/WraXvS+P0XhEg1r2T2nKmEKMnE5ByYZPfs2W7rZN18u7bBBQ9I
         P+n047UF3nCihOS4ryABOLKmW3i26YbJ9006Aa3ZHb1y071a3VXUsvtkHue3hLeTzfka
         spJVqFZlyh6y1868PMvWk+DpJbTbIV6r8s2bNwU32D/72eQAdEb00/vfeWOVUIgLJ6qE
         kM3tr5C5FrAR5eEYa9hh3emkeDxsQdJln0inTYjV+6/qH5J9jhg0JnPAjCouVtAbUrS+
         U0DZK+6JRh99xKgk/1Ba6RTT0pghsM8mDOG4Tw13DA8IQ2yk9vsXlqDMCMYMgn84ik55
         gzaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=OO33/jJhJQVIdzyn/h7cV8sb9potmD4v/pwOWqkGaBs=;
        fh=QeWJbN2HKwSPCJt7qGZB8SqIecNJnZvTC/XschOCgLI=;
        b=kMp1VlkGE+9KwzUcd/0NbtVIMdeUQCWR4otnxFGqjVGlnl0LJ7TQr07cus7iITGFlH
         7lWDkh7Std2lJwW0aG8KYBXyivzeXy0kwjzT17oY87eDvIhQoJlfCL1g1KmcxuOyYvHH
         q3vWFaHq0S/a/muTewB5jIMmPTAuq6qoQyytOYNctmfu8lI6/GJ2N43sww/V3hqlbPdP
         WAN+hoGBY9EcM/rDQW5Nk7K2uu7Ku2aLhgDBMiK+fcmLOYa6ffcxyR13HGL8gTYkQbsG
         HudS2+fRmmGpxoLjLESR4vbBSGhRI2thp7rQoNl2oK9mrbnGaiD4nkTfVpk7kN6Tu5OC
         W4Qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3rkxLZjq;
       spf=pass (google.com: domain of 3jxnfaqukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jXNFaQUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a185d65e2si61308e87.2.2025.12.19.07.47.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3jxnfaqukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-43009df5ab3so1135076f8f.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVjVBHCyvDnNxpUhoamWHsnbfQHWGuBbZSEDm6znVsbE7gSj5oNNJB5j42NqtohfyGx9KZwNvPIqjo=@googlegroups.com
X-Received: from wrbbs1.prod.google.com ([2002:a05:6000:701:b0:42b:2aa2:e459])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2303:b0:429:b9bc:e81a
 with SMTP id ffacd0b85a97d-4324e458883mr2916935f8f.0.1766159245502; Fri, 19
 Dec 2025 07:47:25 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:19 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-31-elver@google.com>
Subject: [PATCH v5 30/36] kcsan: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b=3rkxLZjq;       spf=pass
 (google.com: domain of 3jxnfaqukcdoahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3jXNFaQUKCdoAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-31-elver%40google.com.
