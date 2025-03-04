Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQMOTO7AMGQEOTKIZMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id EC6DCA4D822
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Mar 2025 10:26:26 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-549566f3505sf2012192e87.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Mar 2025 01:26:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741080386; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q5Z0qzoyEn0S8wABxgOJTphPQ20B/uc3L8q3WwHsU3ATpcbH+oL5iXiuRqaUxa9yB6
         zUkTXJ0HnooxOd+QdUHaJKe3GNsOOwGtj36MFB+96vqaE8OYoZdwZ7xdusxn/nw0BVvE
         I0xroifDkzkHZ82BHCLyRxVVIl0GHYr4byfPe8PFpPZXyRyFL9ju3BZSirjpHtu+4loi
         vhV3mN9TVFz2YwW82Dpcgo3635t6PngjBuZsloVwdPIk5512B6D+2s9ibc71RiKtRq1p
         TMcRq4CJHrUMCKPRPxbGk+ov8A2XsDPTaQOtUdWuoDmRT7Kw/9zxSigPFBWbyC92x/W0
         malQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=W9/JOD8rqxvsdQOKbL0Y3OwLl+1ceihcZCUBwaYRVbo=;
        fh=gXbbavXu009iPiGKSxN//+SWzMgSzxhQfgGcI7uhlZ4=;
        b=aS5VVTjdsxexHcyB5O8+9WismxG8PvJfe6l05wlkt2NEKa6ZUg/QYM1tFz5ki5Z7j6
         eLMD8QqVzJoybMWBBB/hHBzTIv060GoHMGTjDf4SisDCyCFsLe2/EC0AlGoNR+p/H3NV
         NuQFqCu3qpK4Mn9zPCrXOWZIYIgmsFxWOi37L2cnSn9mfPmskLNOrVzCTB/Dn9/WjVkv
         tWkEqFrTDMfmx1CKqVqpE5HmFCoJdPkg+OpaLRAbRrxq/cAt4s5GeMsOw8DSE8lvr872
         aIc+e7IrFvh17p5Yo4tDbOLQL2sUpvdspMRmJ9IgIX6CEveQ6LddFTX+I1yL7KS6MvW9
         9oaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1T9iuitA;
       spf=pass (google.com: domain of 3psfgzwukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3PsfGZwUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741080386; x=1741685186; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=W9/JOD8rqxvsdQOKbL0Y3OwLl+1ceihcZCUBwaYRVbo=;
        b=OQQ1yYeB4Z4bhZ07SNGY/ESKQy7Smsh3eRs1nyoa9NxN5W5d1c/FHVgtdpg1vaLG7p
         u80HHYS3tAWhwm4zbFWDn3bAeRBt2slQLc7fYXGRwOtT+fvL+AGjKqNNflVs1JYoP27L
         JreF9uds/Y343onXKg79AuF4vmZ8vWJAUNQlfyn47OzLHEDsQKTZD20gNXdFXc2yK8hp
         J++Sbhwlc3Ul+4MqJcI+vXcKr45DKrqcMJG0iJBGhh7rp0kJrsmkwrzipFX585MixOob
         VsErJBjmfUGYF4lnuR+ETAqGKzuQPa9xA34RXbdTvuUepas6A6Fk+FCreSU6d3I39gJx
         3VHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741080386; x=1741685186;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=W9/JOD8rqxvsdQOKbL0Y3OwLl+1ceihcZCUBwaYRVbo=;
        b=EL17OblOmmOGRCkw7V+2Oi5R5z6FsrQaruFOBLjogKsbpX7qaHf59yZ/XVzjYJv1lK
         SkSq/L6Rc3ijpnCYLiC5QHE9GkebvgE7JaH/te3xaX3M0mrgvNjMiyQVefUPoowpRW/P
         9UqQ8N0/JfKSuWU7qrwcivfliSC2IwH3F1I5dcQAf8TLTnAcJefJzlYMOtQYKNAThYj1
         nhn1dCQaCi4/F0bhnqpBDhlIXqF79W0A0G5it+19Y7wvTHM+m9WhEx8hCQUq0LPSRIf9
         c65yfiEs0jrzDrcez3JPz3o8R/Hy4jkqxthkFRPJhX74t2yhZzboPkbe6zlBiy/eIzZ3
         1Ypg==
X-Forwarded-Encrypted: i=2; AJvYcCWSSgm20vtOZrvNobo5JG5wVxes1Z4eW1FVLt7kgao39oSpbmm8DDHZrxd4vv0Wc9n5V5zlvw==@lfdr.de
X-Gm-Message-State: AOJu0YwHKVbNuIdnTjoc8u/cbAGPRYu6mUMNmBD5sVsZXJWkza4glp9s
	I7I/WHuU8L1pWiklps8Et/9bLkk2nG2EfRLFWk61XixUEQkQOx6P
X-Google-Smtp-Source: AGHT+IFWgzrROM3mCQFj/Ymg3av1iKws+FhD3QBK44wXGdl0SOYJfkmuWA67wglOZn52Z8M92nf7eQ==
X-Received: by 2002:a05:6512:2313:b0:549:6451:7e76 with SMTP id 2adb3069b0e04-549645180f1mr3269988e87.33.1741080385810;
        Tue, 04 Mar 2025 01:26:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVE1Z42Ajj6J7hYGr70dckTb4cl1bOJF1bCS8Gokr8c8Jw==
Received: by 2002:a19:4355:0:b0:549:5800:fc6d with SMTP id 2adb3069b0e04-5495800fd66ls258584e87.2.-pod-prod-02-eu;
 Tue, 04 Mar 2025 01:26:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXXYcjKN1Nj0oDlbzIYrrZuojNHmZZauwjvr4you0FBFf7Sy1DqsEoQxSVgmRMV/+ATr411zD6MDB4=@googlegroups.com
X-Received: by 2002:a05:6512:281d:b0:545:27f0:7b6f with SMTP id 2adb3069b0e04-5494c129f77mr6187708e87.11.1741080382959;
        Tue, 04 Mar 2025 01:26:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741080382; cv=none;
        d=google.com; s=arc-20240605;
        b=HEn3cvlvqKj6b5ydXIai+vpLMtNUBa8czobSVlrv7XdyyyLFdSxv5F1+28E9Pfq2KQ
         Kpda+tqu1nnEWoRyB2qXlqJPm1gMHfTvH6QY4QVRNXXLHsU7rx3wlMbqO0+M7JqGKg6y
         3ePyms31lrspKWiTLeoxF7NbLUz62wn/+QuLCfiOoGmhn7auE/nKJONQZMDV0lOH2lOU
         zBL+FxEKxohzBT799BKIAWlXScALnHYxyDpNRq7OLdNbuuI0Hh/H7YLfwgrmyUBYbLjt
         Tg+3TyAjS6vFDO5ikcI2jPFOrrkwPkdOwS9CwNJvlS9gOl3ORD/55G2S58CfQCamjQLT
         G1ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=HvhGmPYbdkTfK7RRSri3eLNkf3gftCvKGp0dWVvi1U4=;
        fh=bKNdMjUFY+M1YabzZIOxx1b1OLgNsaGs2LJgEvtDd6E=;
        b=jr5A8v6SgQ+zj1+JUATOYSV4l+M99Z3/acN8gZ65NvgiYR01N/UUZRwiNT5EPwfvUS
         jRglqvxKl8X1JoE9kMUP+ZsksvGKoGwaLI3/iJglqzsBZ0jwWsl72SY1PvjOB2ho4vJZ
         5cGzKjgkSEzDVsKvQvVRpgV8I2WQ+dcpBCsP6jM0E+miLUE4AB6+oNnDAEd4YwSJ6hoA
         Bsa0d0t9/2MCaQCyX6pnf5CGAz74snFwLd4vF+BeqM45qaMcnpF6SUF+rRrSpyNbvxBm
         GeQ+KIEDcVhOZMiVFjn6ur78yTVHcvUzzMYcdZyCEXvEmjKB0jNAeCsgmF/Phx4aevlr
         H2nQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1T9iuitA;
       spf=pass (google.com: domain of 3psfgzwukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3PsfGZwUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5495b280837si70338e87.3.2025.03.04.01.26.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Mar 2025 01:26:22 -0800 (PST)
Received-SPF: pass (google.com: domain of 3psfgzwukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id ffacd0b85a97d-390e50c1d00so4000015f8f.1
        for <kasan-dev@googlegroups.com>; Tue, 04 Mar 2025 01:26:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVqJltxeeqmFnhcx0k/yB68SGjR59fototZRx4tYOu8/R8rJ/VxGuGz6KbIWLubWkE3YKWuWXF0ysA=@googlegroups.com
X-Received: from wmbg5.prod.google.com ([2002:a05:600c:a405:b0:43b:bf84:7e47])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6000:400e:b0:391:1473:2a08
 with SMTP id ffacd0b85a97d-39114732a3cmr2623360f8f.7.1741080382297; Tue, 04
 Mar 2025 01:26:22 -0800 (PST)
Date: Tue,  4 Mar 2025 10:21:26 +0100
In-Reply-To: <20250304092417.2873893-1-elver@google.com>
Mime-Version: 1.0
References: <20250304092417.2873893-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.711.g2feabab25a-goog
Message-ID: <20250304092417.2873893-28-elver@google.com>
Subject: [PATCH v2 27/34] kcov: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Joel Fernandes <joel@joelfernandes.org>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-serial@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1T9iuitA;       spf=pass
 (google.com: domain of 3psfgzwukcs0nuenapxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3PsfGZwUKCS0NUeNaPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--elver.bounces.google.com;
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

Enable capability analysis for the KCOV subsystem.

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Remove disable/enable_capability_analysis() around headers.
---
 kernel/Makefile |  2 ++
 kernel/kcov.c   | 36 +++++++++++++++++++++++++-----------
 2 files changed, 27 insertions(+), 11 deletions(-)

diff --git a/kernel/Makefile b/kernel/Makefile
index 87866b037fbe..7e399998532d 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -39,6 +39,8 @@ KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
 UBSAN_SANITIZE_kcov.o := n
 KMSAN_SANITIZE_kcov.o := n
+
+CAPABILITY_ANALYSIS_kcov.o := y
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 obj-y += sched/
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 187ba1b80bda..9015f3b1e08a 100644
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
+		/* Capability-safety: no references left, object being destroyed. */
+		capability_unsafe(
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
+	unsigned long *area;
 
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
+	mode = capability_unsafe(kcov->mode);
 	sequence = kcov->sequence;
 	if (in_task()) {
 		size = kcov->remote_size;
-- 
2.48.1.711.g2feabab25a-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250304092417.2873893-28-elver%40google.com.
