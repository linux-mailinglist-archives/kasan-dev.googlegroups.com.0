Return-Path: <kasan-dev+bncBCF5XGNWYQBRBI4O3ONQMGQEQJ4XKCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id D616862E9B9
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:43:32 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id y5-20020a056602120500b006cf628c14ddsf1755193iot.15
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:43:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668728611; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nv9lmoiB3OvnbKYXNbfKbI4tmFbuZzhYDyW079LgXKU5uE/zTTGr6pK8DajuZ+Zi3O
         WZ6DskLWZ8NNhY7ZRgVLvIuPT7GMzLAMkmw+onBgs5CiMnSAnEPhxTa300wvHM8duevm
         1ulA7Fd6UQVbF2kst9ZgvCLN+ZwEwDHVXOc8YRENFgpS2HWYy2VP5rFsO5GyWbNSVcPQ
         qJTkP0iLpY4+twJFS4ol4EGWUBNFHmH3fp8++TFCZrJBXpmSTOa15Bzr7xAkk+YIT9sB
         F+Ho4GzXaJluikWshcDyK0KvWfMR3rKGnpOqC9QKSMRx+OpAFzoWmcGm3Ye1nz0zyOZ9
         UDjQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jCarI+eowjgHScI5qSRVJCMJ37pAmzLXTqVRQuQNk3o=;
        b=OHRNHEA0hD9l8YxZIYvhfksD9I0U01knWk1g9WcXWzK55vw8ZE59vHsG4zG4+BvnGe
         ACBBPEuh9S6nNCJBf3X1dntiYaoNAAG7txepoZP/Kwa1jN8c4FkrXqg8kfAgCJCaImWm
         9dmKrN9XWjnbNth1DQMP/zRG20Gn/yeBybPrwCBJKY2Sit9DdQqpI+QEh0peDXHlAWZa
         ssnn+1hZ290drDqB1LGAQLHKL9FM7mcFMxIQwM61lFq43cpa1bao4++uXmboL9bAuwNp
         pnx04cPZdxNHExqrNtaLdmAbSlSOY2adBvMiSZn0QuWih5NJw0IWD4hx0fMHK24TfRuB
         lrGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Yrj5IFrD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jCarI+eowjgHScI5qSRVJCMJ37pAmzLXTqVRQuQNk3o=;
        b=F+MG40+Iri15DOu6U+/y/JfAZGt6peQUlxylLvngzXerJ52ABepZNAMWq/ClL0vWyc
         EboCpGLfweCZqx71ixduzS6hCXxf4jCsrLirz/4SzqLMgAmBGua7Cblmm/3K0VeYq5X4
         NUg2qZ15+rsyoZp4QDr1t81oaRdRWWdO4yxXq3YC1AJOYzffemwGzPeMTTV48iC3IpGH
         OSNFf/IVPQEI43/hJDgAwu7eLOgw7Uhd0Wc3zD4/U9gtPhdhfrdaZEVBsNYbmR4NIlPr
         X1DxwuRVkDieYw7FMrHWGG+Mjw+ByD48U1FkBs7TA+QiWgdRh2Cv4LRtcHVOge5f/5wj
         kv9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jCarI+eowjgHScI5qSRVJCMJ37pAmzLXTqVRQuQNk3o=;
        b=JAFGyuxqMjYuD24MEmwFZsdfMsxpN/xc0MlEtsWaFtb1UUxD1+zK21EYNWNg/OnKMg
         qEEgn6SHa7mYpl+f9/Fnofh5b1B8mTsXG5r5HVf8piR7eU9UTO60RGLQvMx+lL1ZrR1q
         qwDsL81MFVGdLLjc1JTWuXHWTwTuV9+erKRQqqumsUvf7h2lLyQcSz3CUqp9Lu6Xu363
         Sq/Wwy8rzjS8yxx/5q5AEhJ1IlL6wlGVG76FJiW4u4e96LJY/1XtiVoBCxEaLDpCmr9I
         +JUsq4AfjGdWe/tO7MpCO0VLBcWY76b4lzV3Doi1MEMfDgyzzLnvV46i/3uRQgwqA5ug
         qcRw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnj/Z79ylR2ta3m4+0LfTWlNuIDOA5N5a5DXi3owl6UZAv+Dvtz
	pDkxoJM6wWaw3Ji8ki4crxU=
X-Google-Smtp-Source: AA0mqf7I2vQT1bSKZwgSNM7tII3C/ucRKYg71o6GAszB9X8b3qazUvI6zqDtdYwRWMvEgmn4wURFig==
X-Received: by 2002:a5e:9405:0:b0:6a1:48d3:149e with SMTP id q5-20020a5e9405000000b006a148d3149emr2477162ioj.136.1668728611678;
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:18c:b0:6a8:19bf:4f91 with SMTP id
 m12-20020a056602018c00b006a819bf4f91ls379795ioo.10.-pod-prod-gmail; Thu, 17
 Nov 2022 15:43:31 -0800 (PST)
X-Received: by 2002:a05:6602:370d:b0:6dd:809b:74b4 with SMTP id bh13-20020a056602370d00b006dd809b74b4mr2304957iob.177.1668728611276;
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668728611; cv=none;
        d=google.com; s=arc-20160816;
        b=JCgO5j5aZ7uyZyzJwu0ZVrQmGc4wW/6ywZGz2LgwbM5MJlhNKoSdTu3VzmpcbPHlEE
         r6nt+L+l1sAsSEmyGzlU9hp0SLTMT85iicPkgThI8hyoQqdH7obRgtDY8N2G3XcCRFnH
         /67f7zgT36NpRwchSC7dFWMKodbTlYU+qJwj8+BmFJBJaPLD6Ye6cyQAEZyA//vYrY36
         mQanfj4ELwc5k2CHOy7wjAJxNC4fPTT8jkuZdmbGmDFXo9cI+q2Vvmf823x5rBjgrPdA
         3NOxAaBC796OHBhzisYEfkj428krZqduwxnsKRk409k7f/Ig0QaMdzegwADtJEfkH96l
         /Xmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lmIZZc21Vqw+ah0v9NZF0i5NZ6eVMCNaXJnOrpu6AVc=;
        b=Q5TXihCIFmZoyGkokjujUJUGMzEM2fcTUJUJg1fQ2BnszT1eTSBzjFzY5o10qPk9Ed
         BPJYPFJ3sKm3mT28hqZS9TqgishbxNIeKEMPgdlk6sVJ9LUYluFHZU23juOapyVyzKWL
         HzLX1OGqUvkCG5fBs8HCwgR7ILC2qHSNWL2liP6opfAItKg7YueWSauNn8dK1zQra5Kr
         EvsrCFB21DiadJjpCPOkhxJBOQtpvXuIDvIRx1ROMGuJ8taIRP1jcTNBg+5Fgp8D+L+9
         7CNcELuUSInUk5sT8e6TB+cqAvZhHUdmnfXzhtFChlqYnCauV51iq58cCmrv6NprrKIH
         DkPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Yrj5IFrD;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id k12-20020a02660c000000b00349dba16b8dsi90695jac.6.2022.11.17.15.43.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id k5so3019590pjo.5
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:43:31 -0800 (PST)
X-Received: by 2002:a17:90a:710b:b0:218:725:c820 with SMTP id h11-20020a17090a710b00b002180725c820mr5027614pjk.170.1668728610498;
        Thu, 17 Nov 2022 15:43:30 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id r16-20020aa79890000000b005627d995a36sm1726716pfl.44.2022.11.17.15.43.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:43:29 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
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
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-hardening@vger.kernel.org
Subject: [PATCH v3 2/6] exit: Put an upper limit on how often we can oops
Date: Thu, 17 Nov 2022 15:43:22 -0800
Message-Id: <20221117234328.594699-2-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221117233838.give.484-kees@kernel.org>
References: <20221117233838.give.484-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=5376; i=keescook@chromium.org; h=from:subject; bh=bLKz0AsFfkmjD/QLdbw/QzipPdep0rPypPtLzjq9ZTA=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjdsccBvLQ6nT8J4vcb5go4xzTn7/5z8tY/5Q7hcSb zMPNB62JAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY3bHHAAKCRCJcvTf3G3AJpL1D/ oDk0k/qwVU9AOH7rJGYOAx8NIIF3c/+tKzCgbmUMHK8vTPitK9TmPTBdDT8RMWympaOJTlnGEyWEVZ qi89p2iZ/Ly7IkmOAm+XKeqt8Id7PBkvGfQ0S6hOJBU3vL9QiovG/ZBvBdaEjtezeuVa0K/njRUL8P IBXJMNwV1PaowE45g/K64RUmABpgQ6n/KmAcw61aJpDNRZS4WGzG7aXI3ZPYe9Jcrz8omNZM72o0sX lEvUNN1yHpHmGp9fsPIFzkQoW4QVRqRrxy8CUljllnNQzVo/03L4fA+cR1+RaTlnxwHiQ87T/32JP4 EmX6r4WjI21FvqTknthuTLg9BmgmB+TWSDDW/LnEIMcOY1vr4QymYzhycPxn1PK6WGkO8REkW+K1+O 4GwWjG895xklsuozUg/QU/iwbkRsvGxC4vSkT8qQBHVw7MAkISN+OkpAvxQg6gLZvyZlZC2zO2xMF5 VwiQFlFr6vuL9CMz+kBo68TOCs9iXuaYHRt0TnWcIel+zE9fZA0Mq72SGUglEf2cY6nqIlFNuBN8qe Vu1/C460YPWW9/d9EunqPkl3UUbL5qeCuR0jBraE02NNA1ta4jWs9BV7HenTQCni0j+clechmslpPH O1ShX8omxLAY2xC0IUAtMKY7RMIISZYapZnKNO18Lbo0S9i1uvATRGJhFHSw==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Yrj5IFrD;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102f
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

From: Jann Horn <jannh@google.com>

Many Linux systems are configured to not panic on oops; but allowing an
attacker to oops the system **really** often can make even bugs that look
completely unexploitable exploitable (like NULL dereferences and such) if
each crash elevates a refcount by one or a lock is taken in read mode, and
this causes a counter to eventually overflow.

The most interesting counters for this are 32 bits wide (like open-coded
refcounts that don't use refcount_t). (The ldsem reader count on 32-bit
platforms is just 16 bits, but probably nobody cares about 32-bit platforms
that much nowadays.)

So let's panic the system if the kernel is constantly oopsing.

The speed of oopsing 2^32 times probably depends on several factors, like
how long the stack trace is and which unwinder you're using; an empirically
important one is whether your console is showing a graphical environment or
a text console that oopses will be printed to.
In a quick single-threaded benchmark, it looks like oopsing in a vfork()
child with a very short stack trace only takes ~510 microseconds per run
when a graphical console is active; but switching to a text console that
oopses are printed to slows it down around 87x, to ~45 milliseconds per
run.
(Adding more threads makes this faster, but the actual oops printing
happens under &die_lock on x86, so you can maybe speed this up by a factor
of around 2 and then any further improvement gets eaten up by lock
contention.)

It looks like it would take around 8-12 days to overflow a 32-bit counter
with repeated oopsing on a multi-core X86 system running a graphical
environment; both me (in an X86 VM) and Seth (with a distro kernel on
normal hardware in a standard configuration) got numbers in that ballpark.

12 days aren't *that* short on a desktop system, and you'd likely need much
longer on a typical server system (assuming that people don't run graphical
desktop environments on their servers), and this is a *very* noisy and
violent approach to exploiting the kernel; and it also seems to take orders
of magnitude longer on some machines, probably because stuff like EFI
pstore will slow it down a ton if that's active.

Signed-off-by: Jann Horn <jannh@google.com>
Link: https://lore.kernel.org/r/20221107201317.324457-1-jannh@google.com
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 Documentation/admin-guide/sysctl/kernel.rst |  8 ++++
 kernel/exit.c                               | 42 +++++++++++++++++++++
 2 files changed, 50 insertions(+)

diff --git a/Documentation/admin-guide/sysctl/kernel.rst b/Documentation/admin-guide/sysctl/kernel.rst
index 98d1b198b2b4..09f3fb2f8585 100644
--- a/Documentation/admin-guide/sysctl/kernel.rst
+++ b/Documentation/admin-guide/sysctl/kernel.rst
@@ -667,6 +667,14 @@ This is the default behavior.
 an oops event is detected.
 
 
+oops_limit
+==========
+
+Number of kernel oopses after which the kernel should panic when
+``panic_on_oops`` is not set. Setting this to 0 or 1 has the same effect
+as setting ``panic_on_oops=1``.
+
+
 osrelease, ostype & version
 ===========================
 
diff --git a/kernel/exit.c b/kernel/exit.c
index 35e0a31a0315..799c5edd6be6 100644
--- a/kernel/exit.c
+++ b/kernel/exit.c
@@ -72,6 +72,33 @@
 #include <asm/unistd.h>
 #include <asm/mmu_context.h>
 
+/*
+ * The default value should be high enough to not crash a system that randomly
+ * crashes its kernel from time to time, but low enough to at least not permit
+ * overflowing 32-bit refcounts or the ldsem writer count.
+ */
+static unsigned int oops_limit = 10000;
+
+#if CONFIG_SYSCTL
+static struct ctl_table kern_exit_table[] = {
+	{
+		.procname       = "oops_limit",
+		.data           = &oops_limit,
+		.maxlen         = sizeof(oops_limit),
+		.mode           = 0644,
+		.proc_handler   = proc_douintvec,
+	},
+	{ }
+};
+
+static __init int kernel_exit_sysctls_init(void)
+{
+	register_sysctl_init("kernel", kern_exit_table);
+	return 0;
+}
+late_initcall(kernel_exit_sysctls_init);
+#endif
+
 static void __unhash_process(struct task_struct *p, bool group_dead)
 {
 	nr_threads--;
@@ -874,6 +901,8 @@ void __noreturn do_exit(long code)
 
 void __noreturn make_task_dead(int signr)
 {
+	static atomic_t oops_count = ATOMIC_INIT(0);
+
 	/*
 	 * Take the task off the cpu after something catastrophic has
 	 * happened.
@@ -897,6 +926,19 @@ void __noreturn make_task_dead(int signr)
 		preempt_count_set(PREEMPT_ENABLED);
 	}
 
+	/*
+	 * Every time the system oopses, if the oops happens while a reference
+	 * to an object was held, the reference leaks.
+	 * If the oops doesn't also leak memory, repeated oopsing can cause
+	 * reference counters to wrap around (if they're not using refcount_t).
+	 * This means that repeated oopsing can make unexploitable-looking bugs
+	 * exploitable through repeated oopsing.
+	 * To make sure this can't happen, place an upper bound on how often the
+	 * kernel may oops without panic().
+	 */
+	if (atomic_inc_return(&oops_count) >= READ_ONCE(oops_limit))
+		panic("Oopsed too often (kernel.oops_limit is %d)", oops_limit);
+
 	/*
 	 * We're taking recursive faults here in make_task_dead. Safest is to just
 	 * leave this task alone and wait for reboot.
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221117234328.594699-2-keescook%40chromium.org.
