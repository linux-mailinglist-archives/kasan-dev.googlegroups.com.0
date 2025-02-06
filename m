Return-Path: <kasan-dev+bncBC7OBJGL2MHBBBH2SO6QMGQEWCFU2LY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id AEFCFA2B066
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:46 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id a640c23a62f3a-ab76aa0e72bsf113347566b.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865926; cv=pass;
        d=google.com; s=arc-20240605;
        b=AmgdNl4jXxUAm0AWrYEhkDL49kU7evUBPU6420YHtoaeTGqqB8sjjJXGGX5ViE9h2h
         kXRq4slflt6m78ky5UtsO3vKh1jZX07i9J+RluqLBECUDhiIn0fB/OTsS3vN6Hi/8E4S
         DDMqvp4hgh+C6I6UOga4CzNi+oDqLBdVBdwiZ1925YxxOxMuKeo30RAM7N+reQXg/+iS
         I1TzAmxz03g1MsoEIpcWJZQnlOiYWntDCKhpXVOGSBZZgMxZnJA23eHyIWYm8hJ9/n+n
         D++msV9Y5qSQDy4jwxxX88/F1fsp+NgMns9GbludDMRrUCl0ABwErxxPqLVXEJ8TXLwi
         M91w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=ofSCyxSKxJJityfDn8A3cDX/7+5JsxyRPRYsJJj88a8=;
        fh=zHpoEhrlEhpnqkUHFfHuSl8In8J6m3dNTQmO98Aayo0=;
        b=K8H54xCGg3cyE1Z2vQ3/kLknFnNJMmhHekT/sCwHkYig52c0XcL6WG2TjeMNSn58yw
         ho9DTpQaBsVbX1OWGuEDlouoDlLL779wakIUISBgbm26v1ecJ36eVOWy9scBbTk2Quro
         P0rXmnIlA0NZbi0VFdxFD8A1wn3ZL8LcbnYbmnfu6poJif3ZRrjVzmNx6l3ecXC4Im/E
         uqkS5XHfYr3SVPVV9eYqzlr+BqICwCbU2FKrHrFsmn1jJetSdeGA0t8dz8NRxT3uJN2x
         8K50/TwcTVxqFNgWjvyWCVVY4jEkOwwVRyhflc+VyQjEI2UYiHBBa2DLa0aO0ZbzTqDe
         ut8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Quzq2gDJ;
       spf=pass (google.com: domain of 3af2kzwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Af2kZwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865926; x=1739470726; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=ofSCyxSKxJJityfDn8A3cDX/7+5JsxyRPRYsJJj88a8=;
        b=a61AGxCEhoZaBlcxHpzoAzTjIEm+PSlGuhBKjeP39rAZBl0qFsZa3gVHiSnedJuJE3
         9gYs9Wo01EO/omA4LcZ92uOc6LbPcqht8b8N8tzgJCrKo2wGJYT/fCndgFrA9fOxTOpQ
         2wBSoVlzQ6jZK0b96vIE6M2gZz+/C7cnMOO2GKndUrkJicC/9qUxQdsq8jaQe+vzBm86
         7tcUeoUOLdGSYwYhSgJ70qOSgH+RtFwrrJ9aJd391xEoMtdWDoY3XICIFvTZoxXLW1bK
         NfPjF0j5F9AIqb65cCBDVCJXf69n71xne7Rv5LiRNfUUSiCqW8KQMxDlv8vzzSrwBSAQ
         nt2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865926; x=1739470726;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ofSCyxSKxJJityfDn8A3cDX/7+5JsxyRPRYsJJj88a8=;
        b=K7Vkj2SHLtPqFUWDIPKJUIDA/nKUlUpoTzPWnr7XDjoWgxZKMRrMns/lAuUXlm1bDW
         YFXrlNLjfgdL6e1d+uMHCZ1KD3Ev3bZmZrStnzX+ROZaosRPgSAUFj5nrT6vJmfYmsBV
         O/Zb9x1O7BvSMEzZw4QN/n4Q23ZxuteNny0+QDPRlabkddo5uSkkxAkncBuftwoIGfPc
         NVh9hQ6tW5/2kX3rcCalbgufwKNGc6uek+0ZxICsT+jDAz7DHNE1U4VlLug+VhdnsrBF
         /gAD8q9G/BmoSkF3VVkVzFNJEUWBZK8/NrzHanSs4Ci+T+Zb8jak93WG8TfkyOD8Ii1Z
         ieLA==
X-Forwarded-Encrypted: i=2; AJvYcCX6X+vh3sviIVrvth5wRULZ/ne/VImJDNhg28dueI1CZYwfSWzs+k+YDrnTTrEK2tu/jF1Z3g==@lfdr.de
X-Gm-Message-State: AOJu0Yz69NlaiAc+HiqVeyjetfPbYsp6ilX8OwkI/OeXfmhE9apHjns7
	divcDfwqqrJybpEkcN0mUx93UN60uTjmX2EveuyRP4fIkTR5dsih
X-Google-Smtp-Source: AGHT+IHNrTUyvIkT0OAaN2L75JxVBuQa9b2jhjJTtvgHi7IBjOzKfMXwrsc0EUudB+P6Ef3n6vUC4A==
X-Received: by 2002:a05:6402:2383:b0:5dc:9589:9f64 with SMTP id 4fb4d7f45d1cf-5de450036dcmr969605a12.13.1738865924683;
        Thu, 06 Feb 2025 10:18:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d4cc:0:b0:5dc:e2a1:fc57 with SMTP id 4fb4d7f45d1cf-5de45db15afls19532a12.0.-pod-prod-05-eu;
 Thu, 06 Feb 2025 10:18:42 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUICxgyVIwrzvH9k2diE5Tbqv+tqqykVNOfjzDL3iAsGwwTStxe/Qaw4rrBw5nHxDUTiWzpgTVxuYc=@googlegroups.com
X-Received: by 2002:a05:6402:35cb:b0:5dc:71f6:9725 with SMTP id 4fb4d7f45d1cf-5de4508030emr820803a12.27.1738865921973;
        Thu, 06 Feb 2025 10:18:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865921; cv=none;
        d=google.com; s=arc-20240605;
        b=CA4N9bIjWbRN6ziEjgcFUoxDVPwRSn4iDfGEuPvSvX79eqsjrR8orAWQMO3byvyadv
         2LDu/L9b+px9K9BfJmFpr/K2c0Z+i8d7z1vFCZ0S3aVFxN3x3Nzz7JblybJwLm3D06Sq
         QVr3KtrS+P+iAaNPVBsvAsWjwbiPogNy/zMxjxxMkoNgCLt3vMaSBpL1jvIi0bXeEe4L
         dBR5SsZ6sCxTnUNEUTPeXe6UYXSdSk4Aht+BCWMY1QCB3XoSBJvgaP22kqSt4NW3oRcQ
         oTplNYT51ATnLXuP8RcPpeIeLrQEN3gikfjsCP2QFmmna8oKXFGkVLF/7LzE3qrpw67g
         Uysg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=xc/nsPoKHTE+OnZKDVqwWYhiGzXohY6mN55B1zkjrXo=;
        fh=qZYJQQN0K9BUeMYOZyQ9dzcuAJv7J0C1W7eLj7mfWpk=;
        b=QxGbU7LJafSZL9sNTYGliLA67LAdhmbErOc4bdiCKZIIe4fF3o4/Mfi8oYBdvTZBiR
         Ondqjdu5Ser8Wytzlk/J3GXI5rFUGeJ7G6dNXh7vOsrAlaOd+zq2JUTpe/v/bqC89hy1
         mIWs51uygLYFGNhTOvf8dNOE356M94q3buz3r4qdMstz1qk3xGThL8mIKrHTXld6Gmre
         1xcuG5zu6p5waDlghTfgQpSfs1WCeyW1xAn5XPx5+9CXHvmdMVssF0mUMoCx9DXXoKks
         y0CAsF5/5owOywk8lE948Cq94sINdV03lTWxOwpzL9Lld2uSiRqRAN2Q2oLQUNSEI9Cs
         I/Xw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Quzq2gDJ;
       spf=pass (google.com: domain of 3af2kzwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Af2kZwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcf1b739ccsi43235a12.1.2025.02.06.10.18.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3af2kzwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id 4fb4d7f45d1cf-5d9fcb4a122so1483815a12.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:41 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWJs8aO61sHHxVQWresKLsQPM4F/ExyCh045e9T7jnea1uafTmF/btWSPOCvvZRraHry+gsmQgSCpA=@googlegroups.com
X-Received: from edah39.prod.google.com ([2002:a05:6402:ea7:b0:5dc:92bc:54c2])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:6402:2390:b0:5db:f26d:fff8
 with SMTP id 4fb4d7f45d1cf-5de4508dcc3mr323309a12.22.1738865921739; Thu, 06
 Feb 2025 10:18:41 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:16 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-23-elver@google.com>
Subject: [PATCH RFC 22/24] kcov: Enable capability analysis
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Quzq2gDJ;       spf=pass
 (google.com: domain of 3af2kzwukcdi29j2f4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3Af2kZwUKCdI29J2F4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--elver.bounces.google.com;
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
 kernel/Makefile |  2 ++
 kernel/kcov.c   | 40 +++++++++++++++++++++++++++++-----------
 2 files changed, 31 insertions(+), 11 deletions(-)

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
index 187ba1b80bda..d89c933fe682 100644
--- a/kernel/kcov.c
+++ b/kernel/kcov.c
@@ -1,6 +1,8 @@
 // SPDX-License-Identifier: GPL-2.0
 #define pr_fmt(fmt) "kcov: " fmt
 
+disable_capability_analysis();
+
 #define DISABLE_BRANCH_PROFILING
 #include <linux/atomic.h>
 #include <linux/compiler.h>
@@ -27,6 +29,8 @@
 #include <linux/log2.h>
 #include <asm/setup.h>
 
+enable_capability_analysis();
+
 #define kcov_debug(fmt, ...) pr_debug("%s: " fmt, __func__, ##__VA_ARGS__)
 
 /* Number of 64-bit words written per one comparison: */
@@ -55,13 +59,13 @@ struct kcov {
 	refcount_t		refcount;
 	/* The lock protects mode, size, area and t. */
 	spinlock_t		lock;
-	enum kcov_mode		mode;
+	enum kcov_mode		mode __var_guarded_by(&lock);
 	/* Size of arena (in long's). */
-	unsigned int		size;
+	unsigned int		size __var_guarded_by(&lock);
 	/* Coverage buffer shared with user space. */
-	void			*area;
+	void			*area __var_guarded_by(&lock);
 	/* Task for which we collect coverage, or NULL. */
-	struct task_struct	*t;
+	struct task_struct	*t __var_guarded_by(&lock);
 	/* Collecting coverage from remote (background) threads. */
 	bool			remote;
 	/* Size of remote area (in long's). */
@@ -391,6 +395,7 @@ void kcov_task_init(struct task_struct *t)
 }
 
 static void kcov_reset(struct kcov *kcov)
+	__must_hold(&kcov->lock)
 {
 	kcov->t = NULL;
 	kcov->mode = KCOV_MODE_INIT;
@@ -400,6 +405,7 @@ static void kcov_reset(struct kcov *kcov)
 }
 
 static void kcov_remote_reset(struct kcov *kcov)
+	__must_hold(&kcov->lock)
 {
 	int bkt;
 	struct kcov_remote *remote;
@@ -419,6 +425,7 @@ static void kcov_remote_reset(struct kcov *kcov)
 }
 
 static void kcov_disable(struct task_struct *t, struct kcov *kcov)
+	__must_hold(&kcov->lock)
 {
 	kcov_task_reset(t);
 	if (kcov->remote)
@@ -435,8 +442,11 @@ static void kcov_get(struct kcov *kcov)
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
@@ -491,6 +501,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
 	unsigned long size, off;
 	struct page *page;
 	unsigned long flags;
+	unsigned long *area;
 
 	spin_lock_irqsave(&kcov->lock, flags);
 	size = kcov->size * sizeof(unsigned long);
@@ -499,10 +510,11 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
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
@@ -522,10 +534,10 @@ static int kcov_open(struct inode *inode, struct file *filep)
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
@@ -556,6 +568,7 @@ static int kcov_get_mode(unsigned long arg)
  * vmalloc fault handling path is instrumented.
  */
 static void kcov_fault_in_area(struct kcov *kcov)
+	__must_hold(&kcov->lock)
 {
 	unsigned long stride = PAGE_SIZE / sizeof(unsigned long);
 	unsigned long *area = kcov->area;
@@ -584,6 +597,7 @@ static inline bool kcov_check_handle(u64 handle, bool common_valid,
 
 static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
 			     unsigned long arg)
+	__must_hold(&kcov->lock)
 {
 	struct task_struct *t;
 	unsigned long flags, unused;
@@ -814,6 +828,7 @@ static inline bool kcov_mode_enabled(unsigned int mode)
 }
 
 static void kcov_remote_softirq_start(struct task_struct *t)
+	__must_hold(&kcov_percpu_data.lock)
 {
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
 	unsigned int mode;
@@ -831,6 +846,7 @@ static void kcov_remote_softirq_start(struct task_struct *t)
 }
 
 static void kcov_remote_softirq_stop(struct task_struct *t)
+	__must_hold(&kcov_percpu_data.lock)
 {
 	struct kcov_percpu_data *data = this_cpu_ptr(&kcov_percpu_data);
 
@@ -896,10 +912,12 @@ void kcov_remote_start(u64 handle)
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
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-23-elver%40google.com.
