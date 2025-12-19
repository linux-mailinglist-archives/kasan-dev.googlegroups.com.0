Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDHHSXFAMGQEBCRYX2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id DE918CD09BF
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:47:25 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-42fdbba545fsf1522335f8f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:47:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159245; cv=pass;
        d=google.com; s=arc-20240605;
        b=ffUc3TQPzQmj5LDtHqj3nBy2kf23R+V0bb5jFYCWz1R3AL24xrmHPyG5SJhFf+vK/t
         ZqH4SmTBu4KMbaTh5n2NLKgFIJHMr/XLVL9+G9M559TYQgArp6ntwutQFWBxHq9DtpW2
         qSXX3iqZCiaHmCjA/1i6o2rhQxW3QRgSF4Hprb56P5/8f//78P2ty0hRBOKxkq/yB72q
         67J86BPj4tmxXo7R1IpK1Bp329y09xg2mRljc+1u1M3NotcznJuGtee8A4YbQ3aTkg1t
         F4+9wrd5KrtDh3HqgnKVepDgUEX1XVXizw8M4S6YF6429g7y2zpx4lhlnDDULNIgZlqR
         WcSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=uRnhgK/WNv+3440pOfoMVFaZ8Ra5sxZtrvZp02zOpDU=;
        fh=jyK57JuMjpM9vKJoy8ONkA5odOxAD+zH91dt00WvYyg=;
        b=AGthxsxGh+rJiyLg3k+7CvITjBOmmAr3NSD/Tiq61UUWuuAjkDdXK7rUCyJyva5jGV
         Ly0WvZjPsJiPdwtIocd/ICs+//R7cR0fdK5GrrAW4JYhfL+7Dw6G1MEgxwESxg1vqRcs
         GW0OvwTPwI/UShH/CprTIcGdvrMLbghRFKBvn64BcDDx17H1v2jXIzh4o1EpzdhpkMJ9
         hdgwh29bQjj5NDmNNUIXrJ9qlfS8HttfZyIVESH7YGHi+vJBLWthqni1/ULD5IN9nZ84
         SZipJ5bZsMSFLpxuY2ocROp5y0V71P6tn6EdfW1qTMgRupFB7fEsFSzsITtfpKtFH7TA
         AVPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="jXaY/eVX";
       spf=pass (google.com: domain of 3ixnfaqukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3iXNFaQUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159245; x=1766764045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=uRnhgK/WNv+3440pOfoMVFaZ8Ra5sxZtrvZp02zOpDU=;
        b=h0hcwUH1MUPZ9vFX3SCvHqm1tMcAdbWrVpirXItqzFqLZITfhYatbK8TFzcvNA4ACF
         IAhIIhwB8HeB1mYnuUYQqrNKVYnGXgGypvThQfkMJg+tZU8Y9HoR3TEpm6JmqB+70N4o
         xxVZpkY2p441ZKbBBnoQWNm5wGuzTcFGeJ12ny86gadeV2v+uuad7VIoD+FeOl8dCd70
         P1e72xFzFtuf/iZ2WqZP1yn+BVQZL6xKh00lKuXtuhM4SWiPB1N3vfCPQ/sH7XmIbNeb
         i7Mn/EuoKYUvVucmlv3xCYebgHHqPP0mUHgzAmycq+Bdzg4SJBP2iLPz0vT14Lmk9E/S
         4W4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159245; x=1766764045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=uRnhgK/WNv+3440pOfoMVFaZ8Ra5sxZtrvZp02zOpDU=;
        b=PkMTVqMo4E4K2R9Ax+x1RKDMw7o4pawe8JAHzAz/iASeUrfcz0chBhXl3tkq+p35fD
         RXiuCU/OB7p+8j5KyXTT5uEfDh5pLRBbKEJ2cv2mzl20OhQqpGte4FDc88ag42nNpChx
         ruA66PtjfZyXrX9jSgyvVeFWLzRkZhQFuXnaikz6Xu6B2u6OyvDrB11ykRYJe1s05RBl
         C6t7uevWunlB+SHX3uwxMc0OU43jSZkCUH/+FxcxLMecpwI7Jn2qtrpBKZAWT3+INpGt
         D/x+tCwZWK9c8qJorPgMeXf2+3Cj24SC01+KXlJBNdn//iSomudkgQ5Kw+IBkfnZX0vF
         TdWw==
X-Forwarded-Encrypted: i=2; AJvYcCVeAeLtUsd7rC5AimxLc4tK9GinytlR6pttOuBPb0FFQB+AtLoJqvPp+mOMyu93pEPsp6mfcA==@lfdr.de
X-Gm-Message-State: AOJu0Yzsp8hY+QfLywpzsjPGwJICdhyGnOw5tPOwizffC2xw7BbPc33u
	H+qoVdVbOnGRhqBSCmmIxUBmGD3y4a9tP9l46r3ANRHmBOiuDkwTJmG9
X-Google-Smtp-Source: AGHT+IFAId65duojRpTeBlOTnR+8+2BpsqZOvicRvt1VCkpeVZTz7ih3CpzXgubeEugVAJ9znIhxWA==
X-Received: by 2002:a05:6000:1ac9:b0:430:f437:5a71 with SMTP id ffacd0b85a97d-4324e3fd5dfmr3914670f8f.13.1766159245062;
        Fri, 19 Dec 2025 07:47:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZ77NITo0pS9y4qeUg9kEqp8O4EtwuHlPm5RFbQ2Zgcdw=="
Received: by 2002:a05:6000:603:b0:427:208:35bd with SMTP id
 ffacd0b85a97d-42fb2ff2bb6ls1924712f8f.2.-pod-prod-00-eu; Fri, 19 Dec 2025
 07:47:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWdgIf4mjxzxCOuf6HR1I4r4QPyLjrmg8p8hDRivwtukS95HcmyIe7FA64RPC51n+UPrw5f8DTsC5E=@googlegroups.com
X-Received: by 2002:a05:6000:400b:b0:430:f74d:6e9f with SMTP id ffacd0b85a97d-432448b7e8emr8078187f8f.14.1766159242102;
        Fri, 19 Dec 2025 07:47:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159242; cv=none;
        d=google.com; s=arc-20240605;
        b=CmCIPjtEf8tMWQ4tZlz4/5P420w8xLMKIqy46L/Hd628+99f4MgkmCi0dohVmX8pNf
         7T0EDzh5HgQxpkjfFWoYaH2HkPKLqN5txAkJ0Cb8Wvw8ecG3KWf1KD0dXVFFg6/Bqkyq
         u93PJcvAE91lBaqwS65c8BmTPwk3DpPazMNjngS2uaopFEw9rjzGtjOO6b8KoGfUjx7I
         AEFKnomSulik9JJqz2rvK/93olR8H6Vg0K9IFATAl/y84mRQTPt5eD6vO6hmLzbIL/P/
         PrtCRc0ZMAIXfJ0BonBlq8y9jaU/WApx7fgDQnOL+up5jtjS4htv0aVHgXfISsPjUzRm
         SHhw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=cIl6hRG6VWUZ3266tGTJDIxO3xjvOCdXIFgWS7XA8vA=;
        fh=LxoAboBTjNfcfyTVz8c5BQzVSj+QVmIX7j3n5qHr+O8=;
        b=bz93Rd81QBHU16aozrHoFuMr+vCH7aBFzORWxlWwA6pExN19+pQz3yknRubAuFjI0j
         famAWGN7yEGLbjSyEWyGnr96Aj4WcHG7U6z6OcQlNXJavzmL96Jq9ThyckH/eKTxMe3V
         4eRndVKnxSp5LOo5uKLlwIZQ7qa4gso6tK82X0xDcozwYaqu6272nZPDRbQ7bNvziNXz
         YcgWHyPEcsTYzqPHfsz4Xs0/6Nf/zttcmzee7rBUNG/F93fe+gtMdUGXt/welwnpSnZT
         Uq34etCNX1jVxrlGjZmB2zcHomi9eKvl8NQHL4Pe2RdE1i685T7zuvuspU0Ab4EM10or
         ug7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="jXaY/eVX";
       spf=pass (google.com: domain of 3ixnfaqukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3iXNFaQUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4324ea21b1csi39574f8f.4.2025.12.19.07.47.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:47:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ixnfaqukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-477a0ddd1d4so18030275e9.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:47:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUwWERvPSEi/G+nqtfoI9m0tEMQIIAj35yMoWheeTKi2XvPCBtlpE25BelxUgYMhlEKsW1CEmw4af0=@googlegroups.com
X-Received: from wmxb5-n2.prod.google.com ([2002:a05:600d:8445:20b0:477:3fdf:4c24])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:8484:b0:477:b642:9dbf
 with SMTP id 5b1f17b1804b1-47d195c1cebmr30959435e9.32.1766159241428; Fri, 19
 Dec 2025 07:47:21 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:18 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-30-elver@google.com>
Subject: [PATCH v5 29/36] kcov: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b="jXaY/eVX";       spf=pass
 (google.com: domain of 3ixnfaqukcdy6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3iXNFaQUKCdY6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
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

Enable context analysis for the KCOV subsystem.

Signed-off-by: Marco Elver <elver@google.com>
---
v4:
* Fix new temporary variable type.
* Rename capability -> context analysis.

v2:
* Remove disable/enable_context_analysis() around headers.
---
 kernel/Makefile |  2 ++
 kernel/kcov.c   | 36 +++++++++++++++++++++++++-----------
 2 files changed, 27 insertions(+), 11 deletions(-)

diff --git a/kernel/Makefile b/kernel/Makefile
index e83669841b8c..6785982013dc 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -43,6 +43,8 @@ KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
 UBSAN_SANITIZE_kcov.o := n
 KMSAN_SANITIZE_kcov.o := n
+
+CONTEXT_ANALYSIS_kcov.o := y
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 obj-y += sched/
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 6563141f5de9..6cbc6e2d8aee 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -55,13 +55,13 @@ struct kcov {
 	refcount_t		refcount;
 	/* The lock protects mode, size, area and t. */
 	spinlock_t		lock;
-	enum kcov_mode		mode;
+	enum kcov_mode		mode __guarded_by(&lock);
 	/* Size of arena (in long's). */
-	unsigned int		size;
+	unsigned int		size __guarded_by(&lock);
 	/* Coverage buffer shared with user space. */
-	void			*area;
+	void			*area __guarded_by(&lock);
 	/* Task for which we collect coverage, or NULL. */
-	struct task_struct	*t;
+	struct task_struct	*t __guarded_by(&lock);
 	/* Collecting coverage from remote (background) threads. */
 	bool			remote;
 	/* Size of remote area (in long's). */
@@ -391,6 +391,7 @@ void kcov_task_init(struct task_struct *t)
 }
 
 static void kcov_reset(struct kcov *kcov)
+	__must_hold(&kcov->lock)
 {
 	kcov->t = NULL;
 	kcov->mode = KCOV_MODE_INIT;
@@ -400,6 +401,7 @@ static void kcov_reset(struct kcov *kcov)
 }
 
 static void kcov_remote_reset(struct kcov *kcov)
+	__must_hold(&kcov->lock)
 {
 	int bkt;
 	struct kcov_remote *remote;
@@ -419,6 +421,7 @@ static void kcov_remote_reset(struct kcov *kcov)
 }
 
 static void kcov_disable(struct task_struct *t, struct kcov *kcov)
+	__must_hold(&kcov->lock)
 {
 	kcov_task_reset(t);
 	if (kcov->remote)
@@ -435,8 +438,11 @@ static void kcov_get(struct kcov *kcov)
 static void kcov_put(struct kcov *kcov)
 {
 	if (refcount_dec_and_test(&kcov->refcount)) {
-		kcov_remote_reset(kcov);
-		vfree(kcov->area);
+		/* Context-safety: no references left, object being destroyed. */
+		context_unsafe(
+			kcov_remote_reset(kcov);
+			vfree(kcov->area);
+		);
 		kfree(kcov);
 	}
 }
@@ -491,6 +497,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	unsigned long size, off;
 	struct page *page;
 	unsigned long flags;
+	void *area;
 
 	spin_lock_irqsave(&kcov->lock, flags);
 	size = kcov->size * sizeof(unsigned long);
@@ -499,10 +506,11 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 		res = -EINVAL;
 		goto exit;
 	}
+	area = kcov->area;
 	spin_unlock_irqrestore(&kcov->lock, flags);
 	vm_flags_set(vma, VM_DONTEXPAND);
 	for (off = 0; off < size; off += PAGE_SIZE) {
-		page = vmalloc_to_page(kcov->area + off);
+		page = vmalloc_to_page(area + off);
 		res = vm_insert_page(vma, vma->vm_start + off, page);
 		if (res) {
 			pr_warn_once("kcov: vm_insert_page() failed\n");
@@ -522,10 +530,10 @@ static int kcov_open(struct inode *inode, struct file *filep)
 	kcov = kzalloc(sizeof(*kcov), GFP_KERNEL);
 	if (!kcov)
 		return -ENOMEM;
+	spin_lock_init(&kcov->lock);
 	kcov->mode = KCOV_MODE_DISABLED;
 	kcov->sequence = 1;
 	refcount_set(&kcov->refcount, 1);
-	spin_lock_init(&kcov->lock);
 	filep->private_data = kcov;
 	return nonseekable_open(inode, filep);
 }
@@ -556,6 +564,7 @@ static int kcov_get_mode(unsigned long arg)
  * vmalloc fault handling path is instrumented.
  */
 static void kcov_fault_in_area(struct kcov *kcov)
+	__must_hold(&kcov->lock)
 {
 	unsigned long stride = PAGE_SIZE / sizeof(unsigned long);
 	unsigned long *area = kcov->area;
@@ -584,6 +593,7 @@ static inline bool kcov_check_handle(u64 handle, bool common_valid,
 
 static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			     unsigned long arg)
+	__must_hold(&kcov->lock)
 {
 	struct task_struct *t;
 	unsigned long flags, unused;
@@ -814,6 +824,7 @@ static inline bool kcov_mode_enabled(unsigned int mode)
 }
 
 static void kcov_remote_softirq_start(struct task_struct *t)
+	__must_hold(&kcov_percpu_data.lock)
 {
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
 	unsigned int mode;
@@ -831,6 +842,7 @@ static void kcov_remote_softirq_start(struct task_struct *t)
 }
 
 static void kcov_remote_softirq_stop(struct task_struct *t)
+	__must_hold(&kcov_percpu_data.lock)
 {
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
 
@@ -896,10 +908,12 @@ void kcov_remote_start(u64 handle)
 	/* Put in kcov_remote_stop(). */
 	kcov_get(kcov);
 	/*
-	 * Read kcov fields before unlock to prevent races with
-	 * KCOV_DISABLE / kcov_remote_reset().
+	 * Read kcov fields before unlocking kcov_remote_lock to prevent races
+	 * with KCOV_DISABLE and kcov_remote_reset(); cannot acquire kcov->lock
+	 * here, because it might lead to deadlock given kcov_remote_lock is
+	 * acquired _after_ kcov->lock elsewhere.
 	 */
-	mode = kcov->mode;
+	mode = context_unsafe(kcov->mode);
 	sequence = kcov->sequence;
 	if (in_task()) {
 		size = kcov->remote_size;
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-30-elver%40google.com.
