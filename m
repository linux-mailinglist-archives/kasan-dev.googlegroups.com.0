Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NDWDDAMGQEF26JT5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id A197EB84FED
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:06:46 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-45e05ff0b36sf10451855e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:06:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204406; cv=pass;
        d=google.com; s=arc-20240605;
        b=MPOesNrTSwgt1M+jzfB5ckXCQBDmrOJQFrVRpmTMFPmCZnxEzHg4RxA1DOd2HNHVIv
         pQmB2GmgfQJT9h+0kWMTvtMOhJtgEQonG8G9xZPGomdvwFv3YFhKO+croubNtZNSrzjh
         H7omH/8kxI0zAg1yMWgmYMgiv0F/VIM6sxbxAEnCKlZNHoLqMkKjj+D2qw9pUdmhHt6u
         3XTLxYJUJzkT16ZwhUnFI2Bd76C9vvc7Mrx1P6UVVY8A5BG+j4UdMREk1slv5NOxQmuv
         gyxB4x+TWnfP9ym5vboWqhIQaP7c/QDmoiY1aRPZ17Xr6j1LvVpXJq3MOK2YcCWRE0gw
         geVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=fT1tQp9AMg1QaanSRiWe3ZjRhfPkma7HsqYOpOBjlXQ=;
        fh=G2njrj4m381YVyI+mrafFGaBMmI9VyKFXAOLlL2fJeE=;
        b=CfC+7xb9ij8EyBlMhOlJ+dGCdENtNG4ZN9a9h7teWbKzFMpYhRErOa6WwJ+dtuDaSX
         qLalS8nMDEdXpki2R5msG4jpQGLHbYahRJZdaGGz3S+qF0N1AzsntXQJA7c14roUoQdR
         ZgFkcc62Z86oRuJhPJbOstX1QHl6DlYiex5yCsKJtyxbn1sLufjMRs5hEHDCaKxFBoK4
         lRq4z08aCZFW4OpwYsMYIL8Fn1Y8bCMqdQeYUQkZK1/9caJwSHVt9T0OIIYqGraB0j39
         7OP8tuxjQqgrUBAvXevmv+IiOfmCw1FCHkyCEyUP4vdsxe+MqV5TRa/cmVJ44Bre64Lz
         N9zA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pWHjjduP;
       spf=pass (google.com: domain of 38hhmaaukczm18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=38hHMaAUKCZM18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204406; x=1758809206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fT1tQp9AMg1QaanSRiWe3ZjRhfPkma7HsqYOpOBjlXQ=;
        b=XIuVehBuc9+VhynsRXQ++zmM6VLyMniIe46Tzdu6rdzjIYaxfPv8TaGluVNk9t/KZk
         6moyobL/DdE+AZig7J66htg02/I6gxCsf+9LUaqIa5BmhqE52GxyNz4AMWXoDHlhV8zO
         CRqRIVdvGonfeFYwMAyjJzRMsY+xc6RidsRAGDOZOBiU3A+lkGsWkSs3/XOLh89K+uIj
         b4wFI5/Q+Yux6U0ecbWoTvQtRwNmpL9P1/WluBtZO0qz4yU1Gt5BAvLIB7xGQHfzn36s
         Vq2RQJdPM6wThytvrFvFGxaZFSu6Urn5UpF25x264Q9rwfn7pQZgajeszA8JmfvSyPZB
         VHug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204406; x=1758809206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fT1tQp9AMg1QaanSRiWe3ZjRhfPkma7HsqYOpOBjlXQ=;
        b=ByErfzwKWiI3bZpbvOmzHXHgMtp3fFNXTt1UZJnegHRkmyKPFloZeGt73DkdhtWNWb
         OWXkOBwHyoI+1ImpHSiDgMsDTZagqodQ08zbiHVq304HtbsLjRlDLRe5v+A/g3VbPKK1
         i+IaKHC5CjmuIg+5sygTJucoIKhRXgPrlRD1z1umQ9QRWRp+bJzjRi4X7RFTxoFSX0Hz
         oO9C88aQ2HrK8ZaFjH2/RBnUdJbUGQ1R2xk0+UbZmwrZ2Dy7bnIyClLla159/kt+FD4j
         VQPfR5H6Hw1ptMQEKVJbP+WdZfLt5+pJ77yrw1tgrTKGBIamGqkSj+mr5jPuQwnA68OE
         bZUg==
X-Forwarded-Encrypted: i=2; AJvYcCW6IV/lvhIoTOghP5KVSq+CfvgZf4pqpZFh4+UCmrFinOLZp2CIZAMGLwrvV5gWtRxi0YF2Cw==@lfdr.de
X-Gm-Message-State: AOJu0YyuZaW9M6xh0+N8VDxoxzscBBHFTk2tv4JnA+H/ZmTAUZxeif+h
	XunpQeahGgPbYIZvT0BD7FhJxSQsFHh73GOZcKupt56zeyjz4SGGYyG+
X-Google-Smtp-Source: AGHT+IFFAATEYgWSLDzSJUMgoijGfdzLB/oI0h8TTkgDdjSdf1rZDo3oMt0UpgjmrEq79R4YkM5yFA==
X-Received: by 2002:a05:6000:2681:b0:3d3:b30:4cf2 with SMTP id ffacd0b85a97d-3edd43e22c0mr2495843f8f.19.1758204405961;
        Thu, 18 Sep 2025 07:06:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd73NUeeYSwPohiuBUXQzN/wDIZojR/KROUkfzcz85lmHg==
Received: by 2002:a5d:64e8:0:b0:3ec:83ee:175a with SMTP id ffacd0b85a97d-3ee103008d2ls279999f8f.0.-pod-prod-00-eu;
 Thu, 18 Sep 2025 07:06:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVGAd1dXtpUecebu5LrkaMqDhJX/3IWP8AsZvfI5xPtGhWP0YOyq9KmNqL1751q4FmLXlcCq/aS30U=@googlegroups.com
X-Received: by 2002:a05:6000:1886:b0:3eb:a462:13d8 with SMTP id ffacd0b85a97d-3ede1b733f4mr3318571f8f.17.1758204403275;
        Thu, 18 Sep 2025 07:06:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204403; cv=none;
        d=google.com; s=arc-20240605;
        b=L3NCODqMFyryRECsRkgKb3z8Pmv+m/Wso9NTQwa0/YlKNRdRHihKNVzWYxpC01AX8I
         gowU6qEZuamyJBph851soqLjOkVRWAGzmpMxzxRta0cf5hDMctqQDSRu4E3ccHTXD050
         1AszA6HZ7RQEg/OU2lZXjd56WwkNn/3avFZApL1XrUQxGjBp3R9/FrOmNvyCWOp3zzTf
         GEMteDTeHi9gn/trL8eUTI87+NAAZW1HGlpjU/MWBOYBMobay16RPhdH2Iw8aXwx8dMr
         nFsoO0sEKRJdXEhM1UNRbfR3iAQv0VVf8gIBOFE8IAD63gnOKkLuXeHlXK9R2SwxE+7T
         DsHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sL1ZnB6W2nYw8Er8y4+6suuUwE88jyGa8xAgZKu8urI=;
        fh=sifGWgJhmMW9Ev+SULHWXa7E65DEh+nYvDvhF2Aa69c=;
        b=EHpkIc4o1ICarJAOBEPqWMMkyZ/DSh1As6nbyURJSmZMliIxNTSg8oha6vNSpYXEbl
         XdNupMPez/tN2RC12RvDZRIhpi68fT5ZaoXpVTAMWKsk8qCB+xUI0KE49rmGlmOoEwYL
         UtsMVlrod0SzRSWWD8u2Eizbyn5GEuQIqFwPHuA17AqINHMLYlSTewq4oNdcZPTQNvYs
         UrLkhGXouS4eDraflhEi6KL/FNk++BW8yrj2I8fdp7LBcNewSqkL+aBZMZTnQfYdVEOg
         OgReJoFxId1tP6ncIMkDgSS91fd6O53Mx5IIGlqSlvkNJSgGs1LR2zjJmO2Fqofbsfgi
         FSPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pWHjjduP;
       spf=pass (google.com: domain of 38hhmaaukczm18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=38hHMaAUKCZM18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4662b08d9eesi236985e9.0.2025.09.18.07.06.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:06:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of 38hhmaaukczm18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-45de07b831dso5180675e9.1
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:06:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUd+KizWVkmunZQEylZj73jBcu3Buf2XVw9+zPWrKdPpE2Y8Z77YrdvrVYm6tYZi9w446AGyAnGhPU=@googlegroups.com
X-Received: from wmbec10.prod.google.com ([2002:a05:600c:610a:b0:45f:2d3b:d046])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a5d:508f:0:b0:3ec:e226:d458
 with SMTP id ffacd0b85a97d-3ece226d48dmr3622785f8f.0.1758204402649; Thu, 18
 Sep 2025 07:06:42 -0700 (PDT)
Date: Thu, 18 Sep 2025 15:59:39 +0200
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
Mime-Version: 1.0
References: <20250918140451.1289454-1-elver@google.com>
X-Mailer: git-send-email 2.51.0.384.g4c02a37b29-goog
Message-ID: <20250918140451.1289454-29-elver@google.com>
Subject: [PATCH v3 28/35] kcov: Enable capability analysis
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
 header.i=@google.com header.s=20230601 header.b=pWHjjduP;       spf=pass
 (google.com: domain of 38hhmaaukczm18i1e3bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=38hHMaAUKCZM18I1E3BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--elver.bounces.google.com;
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
index c60623448235..2a2a10c6a197 100644
--- a/kernel/Makefile
+++ b/kernel/Makefile
@@ -43,6 +43,8 @@ KASAN_SANITIZE_kcov.o := n
 KCSAN_SANITIZE_kcov.o := n
 UBSAN_SANITIZE_kcov.o := n
 KMSAN_SANITIZE_kcov.o := n
+
+CAPABILITY_ANALYSIS_kcov.o := y
 CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
 
 obj-y += sched/
diff --git a/kernel/kcov.c b/kernel/kcov.c
index 1d85597057e1..1897c8ca6209 100644
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
2.51.0.384.g4c02a37b29-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918140451.1289454-29-elver%40google.com.
