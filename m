Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ7A7TEAMGQECTZS24A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A8624C74C96
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 16:13:44 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-594296f4b23sf586536e87.3
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Nov 2025 07:13:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763651624; cv=pass;
        d=google.com; s=arc-20240605;
        b=dUgizhCrg+YZgAzTi5WeIvZWTjSitEx0McbBHkTd+hbswuQNQZDdGsuflh6J2UPnqx
         tyAsENs0dZ/MpngpTGdST6QNtZ/dU3iZ53fUUcXstXdSL/nBdhGPTPvzpAUzOmTvUx+n
         62zy/U5cU/OtG1Vp+dkgrMIyAKTJdb+iGwsgO5U2lKwuJz4+GeC+p9GALMUXleET3+tO
         N4hNy9dPtBzfkE/yZJMqnkLwNyPG/3unggUWKsKj1l451L3fvOh6qHF5htEe01LcmEQb
         1XH6wMEMbMgZLwx1Jki4Z1DV98sPi9eeH/zBHXK0aKiEOVtkspdStb/Hi0mwdNoiFIaR
         swMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=x5zLU8pWxcgKvFtKSoVz1YP3Ybvgh9CBy4Xr/6/sRvI=;
        fh=rfrULHrykONunjWXoKihUs5LWphZjyBR6ZfcpyG90Ag=;
        b=ZeYyfVYCx34CByeOK8ToncIuluTNjX2oZ2S6XIhFiRC53AAOHjFsZgtHmTrYaxWe2n
         qsr+Sgl3AMQcbxcO30umwRR8dpyN5IJ6Vzcoh0wB2AZuxolyE+grPIn/Asf+vmG9rMiA
         H1gQIpO/GSIiO1ghP1lb/3LgJmm6zpzHzyk+leIjXkZR/KTZxLUB5QLSdwdiDK9WOKSR
         a6NcVBg5OfPHYwpd8xIt68GvhpIVx8harCuNuC1e+r4Cltcwiu4qswnQupxRvHVwwGYe
         k0GeBs1OvM48N9bxwgoORd8DaZz3D32LkF6z89+8GiU92Nyeuly/zZLFM46XpsomMhFC
         Gbfg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JEivHVx5;
       spf=pass (google.com: domain of 3izafaqukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IzAfaQUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763651624; x=1764256424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=x5zLU8pWxcgKvFtKSoVz1YP3Ybvgh9CBy4Xr/6/sRvI=;
        b=pvY5HeQGih88eSGpQqOq18tLV5hQNPCYipLoHTui1MPxNY74z5wYr35n0EOgTeTeIP
         Ik5Q9b1MikxGfm5aa5AsPrD9BbIzo7BKYmzNIWr74W82vsMXgYpzJCJYHTcY1g5ZqHlc
         fm6eX6MnulCc09nnbBCeKGUzH41yN2TfAusNNePQZ2ATWoQTnNXxPC8+R+JbOCDg8zol
         9/YVPnnQgnHaJG76zOi10V+U8EfJaLzSRgvMiZsj2TDhlFchmR1gE1SAdHPiFzSSQFBd
         Jgu7dpCvjV48rI7wmX1ZN3IQBpG4VeowaxKgv4Fx3qQ/coF2zg40ywFdb98HHEfiS5JD
         DGsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763651624; x=1764256424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=x5zLU8pWxcgKvFtKSoVz1YP3Ybvgh9CBy4Xr/6/sRvI=;
        b=PUR704Y3NE/nXRbD8J5QhFAfZBnpyAcgs8vIJ2yAatIHSsJY0zWIE84XetpWP8oAVW
         PD+kMGvRx+PmlFBhO0wB/rNIo0ourZN1Uv0Xrk8+CUeOPDHGcAnlPQZNOLquEr6Fuspl
         QJvPdTaZr6GStDcKp534Q7jv8rhdi+L1GIyXNR2qiK5ie/ij+AlggvORNdNIV8x7oZ1H
         5HuAfLr6Rvz0xybSNsV3aCDDT0rKIHI8T5OPc7WVRA/0Zk7pTtv455/9j/QaWN7alN72
         4ie+MPBIHT5aH5hbJx9VsbUI466uU2uClyHf8acSsng0PDXgbgmbseI2vNbnUJ9RMTZU
         rH+Q==
X-Forwarded-Encrypted: i=2; AJvYcCUosoXBMvj2sVz1+O7h2XQQJrBn3NghziJmTbKTefNHUv0TLUi/m8HDCwkruaM2mutLKa6F7w==@lfdr.de
X-Gm-Message-State: AOJu0Yy63YEKpgyTS2FvHeykkVHDXu/uxJ7SsBSsYrcxWCx10BsArS/m
	w5rkzDZvbSUcqN90t63sPCeSfcjq2yExuDl0cFWqWnlhHVRPtT0XNFkI
X-Google-Smtp-Source: AGHT+IGx2kIUt0oua30B71NW7SvdXoGmrdkug20wn+5yjbR+SOChUfWp4hLRvrXfk9sHGBDf5uR3Hw==
X-Received: by 2002:ac2:4e04:0:b0:594:253c:209f with SMTP id 2adb3069b0e04-5969e30b493mr1126878e87.39.1763651623952;
        Thu, 20 Nov 2025 07:13:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZF/HSxbzMbS4d3jR6xAUWcZiG4dbq8mRglQJqO6lL86Q=="
Received: by 2002:a05:6512:252a:b0:595:85d5:d930 with SMTP id
 2adb3069b0e04-5969dc10975ls343272e87.0.-pod-prod-02-eu; Thu, 20 Nov 2025
 07:13:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXBRSMS6g3aOE3pr6Mmuw/tek4j4htBqMUtfv68UJQz3a3X4M4aI/tEQDOl2zxfEeHFoSK+06dTu9I=@googlegroups.com
X-Received: by 2002:a05:6512:15aa:b0:595:7e01:6b3a with SMTP id 2adb3069b0e04-5969e2cdcdfmr1236948e87.14.1763651621028;
        Thu, 20 Nov 2025 07:13:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763651621; cv=none;
        d=google.com; s=arc-20240605;
        b=bNshylBt8SJnj94xJWyn69nEYdRmsQvasstChdkR0bqT617fRybizrb2H6713V2xhM
         L8UJeC3dnpSkrxOtFA20ewsk2SEpDhAXirDtwTiEhdkU7gmUU5Dpq7ILgw7+VAu/7G4G
         kJBzUs2y2tNop0kR6p3W1IcgplVosUqLYWCk70B2a5fJrKwpOaRqo6ezV7JW2zW306yf
         SIEig/y/6mcswDUFFd+3flAatPowXPJ8nHNWBriXrihT869PnJLoRb5cAbAkAUOv4o+f
         yqrpVIVR1ZL39ASAo15JC63pkrjkn88MVjNSrNatmSf99bTiJHho05wqoY7T5oFKSLKN
         1DvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=pcD6uieBoqcsyDkA1zkurf5hLc/pXwP1OAaVy3DV1GQ=;
        fh=d2xzglsoy6nDsDHPfKiF46XtEjdM7YXgzQ4myu8aZKg=;
        b=QUZMDZetgzGUH0q20Y0vQ4nZXJGtgKjorgRT920rhKv8ZmzkaXmGQSR5p5zVBmYmv2
         dFafP9kqzgOAxhYWGPg9GTfcW8+b9AMH19zvuvzSBvTo8pPOt3wvtrHJFD3mlTvKa1uB
         Sw6OofTV3WH/qSkDSd6yOBwf6UJ3Xs4m/fc+/34sbicFuFBjd0hH1y8zpOb95AsqvCAP
         czXTrGPO9TP1V5KNpuB8f/jT2QOwXQE0ZRz7DaPKfHcton1rTawvL7jmusUzINZr3BqH
         wuU1j4hT7SjWwe39h18KRK/9h0XJPjo/cQOOyTtB1YyDQrPc/LCe/KPwULsAqsdGptEf
         TA+g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=JEivHVx5;
       spf=pass (google.com: domain of 3izafaqukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IzAfaQUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5969dba0852si45679e87.4.2025.11.20.07.13.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Nov 2025 07:13:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3izafaqukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-42b3c965ce5so789098f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Nov 2025 07:13:40 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVXbDPJS0ub34oQ3MbhrT1Oc0aJTrHrjROzKtd4YCp2Ig7H0StCF/h+R9jU8VjFtPOO1ltcEDL5XWw=@googlegroups.com
X-Received: from wrwn2.prod.google.com ([2002:a5d:67c2:0:b0:42b:349a:10f6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:2002:b0:42b:3746:3b84
 with SMTP id ffacd0b85a97d-42cb9a6acd7mr3408354f8f.55.1763651619825; Thu, 20
 Nov 2025 07:13:39 -0800 (PST)
Date: Thu, 20 Nov 2025 16:09:53 +0100
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
Mime-Version: 1.0
References: <20251120145835.3833031-2-elver@google.com> <20251120151033.3840508-7-elver@google.com>
X-Mailer: git-send-email 2.52.0.rc1.455.g30608eb744-goog
Message-ID: <20251120151033.3840508-29-elver@google.com>
Subject: [PATCH v4 28/35] kcov: Enable context analysis
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
 header.i=@google.com header.s=20230601 header.b=JEivHVx5;       spf=pass
 (google.com: domain of 3izafaqukcvaw3dw9y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3IzAfaQUKCVAw3Dw9y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--elver.bounces.google.com;
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
index 9fe722305c9b..82d49723904d 100644
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
2.52.0.rc1.455.g30608eb744-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251120151033.3840508-29-elver%40google.com.
