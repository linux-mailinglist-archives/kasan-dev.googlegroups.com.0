Return-Path: <kasan-dev+bncBCF5XGNWYQBRB5MNWCNQMGQECSFLVPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id BE2BE62340F
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 21:00:54 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id c23-20020a6b4e17000000b006db1063fc9asf6552080iob.14
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 12:00:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668024053; cv=pass;
        d=google.com; s=arc-20160816;
        b=hZ9B2m9tmMrEF5yrins9agQs0ktZongJdkPEy8M7LZYIufsBoL02Cbl5sLfCBPq04W
         dcbSn+KdH47Cy9BVBqroa1HCpA+NoxyVhtrc+S3xXaSIjo8x5FN1H6BgsyQ0A+dMcbXQ
         eajhQ4qO6YrxiWPW3STPMNDfFGYtKxvvBqVMevW/K+heWKxBZ/QcEw2yP8+XFsUcWDbj
         Fo4bXttoutcjs+OtNaC5JiCKMigrpYPGGcchmluKzPD1X16zZXyj8Nmpjg8ddmBo0b6q
         PmWNGyitNzv5EuHJpCuZITSk5Ti8tlMlpB2jQV6XILBWmxoAYjJUW9N6H0uQHQVlfkgb
         bKWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yFbDRKHzgeCXffx0UzuxUUbD5m4XrjCnRjTKDW/BHPg=;
        b=IsY+6jhSsWrKo6bV/fb63VLtwUxZ0djWsE70Ak7R2gQCy/JI3JFYm7uza3tZZiuZXK
         uQVIML5+OD78pmhp17onam8ck9AMEy/PINtYxrqLeaFX/hrI3KiQ4DZjGrpfrpPxPRpz
         xJ4dfVaY3HM/QNnWXzfjPVqF3Rk4ibPnvT8E02G0VWaI+iTLPtw+KY2aU+4KaeWN1gMu
         SZQsxGn8DnzhzI/v/8iRlH8zSm9nEWwLFzUE88FIGcrjrSwh7ZFdIC/HU6k2dyY6PWp7
         n82yordcac2NICZK09uN2D0mJ4DLAkPabGh7yC91T7EnU9stPE4dp74RaP6fGn+/veeI
         2jsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Eaj/SO41";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yFbDRKHzgeCXffx0UzuxUUbD5m4XrjCnRjTKDW/BHPg=;
        b=mzJEDp4y8vrSuF99/RbiOCxDwWob4psU3DTMWjailBu/lqUCLOf7T4AqAuRTcuWPCr
         vPR5mkZ1GUlugpuOEFd+0Zgdo6U1/MtMEhvmyMMlYhdM8D/Q0aTUvAS1l9wjYQBAgGAU
         CJlcEQuQ0fHP4LIEviOganiqoe5Jx0fJujdYF08GB370UQwVIFVpUnMylryKyOmhOHSX
         uQ2LPP2ifNZ6NKFH8rWKMZZpvaN0r+WbRu7up5HEDREjlWzr5Y4hlor4cdAhVYsax9RR
         zDZj7gzfMB/fkPaFB02uioDfH2rr4cWSrAilu37CzhsC2Qzq8FpnF7ruuiIXr9C5Iadj
         KFIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yFbDRKHzgeCXffx0UzuxUUbD5m4XrjCnRjTKDW/BHPg=;
        b=g+NCxWx/C8J0GYnnLPIlWoHeaUyXI60q0oxl41X6I7l3Y3uHwkEODq27CnzE7B6+So
         9RP2zbS9mof7qyOlJ9TcGp4ziFjHk3PkuuwutsZbzgBRGks7SznkZUEY7Rd6LVyeuEfz
         opzHYhrXrtm2aAItbEQbqmiQ8CpMOJlZBSEdtxsomPVbGM+WAV/6C+EVaUMKRXj/KZ1R
         NxAsu1UKrA6EeHo9CMtX07RXF2KwfNno2Y2SmSuAkFxqCwdQxY1maQS/xenvu0cLlHH2
         NiYC9LeKi6hPyvvBBGmWoqPeR2jBVjdg3WSkTyhbwNcpKnXcuhLJvKs30ImYZpqRrsHl
         mxYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0CgrtykY3+69h7fkN4KfyycgAET2inAeXR+DgZCiP4JblsiCKA
	x2+9geuoV97+6/FJskGa7aI=
X-Google-Smtp-Source: AMsMyM63iMkgACypJCtPbyC07HMes/zicdjYq2a/gN3AIGNyQItRnCXbyh6mzvA4VdrDWWULP897EQ==
X-Received: by 2002:a5e:c709:0:b0:6ce:20d8:fff3 with SMTP id f9-20020a5ec709000000b006ce20d8fff3mr2162859iop.100.1668024053237;
        Wed, 09 Nov 2022 12:00:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:29c2:0:b0:35a:328c:6cc0 with SMTP id p185-20020a0229c2000000b0035a328c6cc0ls4057776jap.2.-pod-prod-gmail;
 Wed, 09 Nov 2022 12:00:52 -0800 (PST)
X-Received: by 2002:a02:5147:0:b0:375:9c59:7825 with SMTP id s68-20020a025147000000b003759c597825mr16013019jaa.51.1668024052765;
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668024052; cv=none;
        d=google.com; s=arc-20160816;
        b=BlR0NI6T51nkATuGihaempJ7nI3zqKF+XrZntcpuFbO5f87JJRtPiHUH9S06Wie6rb
         S9Zd/QZ2IYgZPh+HOaonGPNlnbaxDHyS//U1j+43lZnQIuy2uOV+ulk+0F+WCBgnuzAv
         402BElUF1bd5G5SPaLwGpZ9X8WbMWINJKkyLhEqmdDl4ZUBk7c7L4LzLyBeoeqXsjD8K
         z3hBM5p3m32ucKCGUnwpjL10QjHjRc8GOxU8fJRkxlVr53ciNqJqTMrk8NIxFZAuDSkg
         NpxCcV7Wj3YasqRsGKsJX7Ks98yy5Hsvb6jIMi+zOAUrY7rsW2dNOlGjeMqRkz7yjISY
         04RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kQKFx/3OVEr8FOcVZmOutyPL+4wZ1FyB719efe5yfh8=;
        b=oRi4juX0gXlHGsKhCv7I6Ha/5V1uj0vBWPI2sm0SDKcombSC1OcLgYHffittxIRGzD
         sucwDRMckafsmACNNIsOm8liNwqr2CskxFLDjJShaUC9mTVx9RrLVPwaikP2DqyGTLxj
         tnpNJQ2dj1QnXJANknNTCVFBWoAlj4QDF0+AfDHXtnVJtiFdPk2yPSvfKXJPx/XTv6wZ
         p62Vtcs4HgkQ1+xCGNrD41oLChr7mVGPDT8v2usgZRYolviegogMU4O5WOPmrQwJS+CD
         vT7DMfTXmv1JtCtlG/t45+7jNBIJ5id4Q1hTnTIUEtCt8/W3SsJhZUxea40XuyMKxA8F
         DPuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="Eaj/SO41";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id k17-20020a02a711000000b0037556a5e914si553426jam.4.2022.11.09.12.00.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id c2so18078002plz.11
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 12:00:52 -0800 (PST)
X-Received: by 2002:a17:902:7283:b0:188:612b:1d31 with SMTP id d3-20020a170902728300b00188612b1d31mr31950444pll.81.1668024052270;
        Wed, 09 Nov 2022 12:00:52 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id bd5-20020a17090b0b8500b0020d9306e735sm1629847pjb.20.2022.11.09.12.00.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 12:00:51 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Petr Mladek <pmladek@suse.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
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
	Luis Chamberlain <mcgrof@kernel.org>,
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
Subject: [PATCH v2 2/6] exit: Put an upper limit on how often we can oops
Date: Wed,  9 Nov 2022 12:00:45 -0800
Message-Id: <20221109200050.3400857-2-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221109194404.gonna.558-kees@kernel.org>
References: <20221109194404.gonna.558-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=5361; i=keescook@chromium.org; h=from:subject; bh=+f/+Dg4RjhhWvYSeTOZHt0meJbZX9qmj9YfRzK8RgiI=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjbAbvj62Q9JcvPPd6ZZiW3RZKbMkJ9KitwgH9cwUs jkYefu2JAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY2wG7wAKCRCJcvTf3G3AJtTYEA Coz/20jIancS/LGuMA+yU7vBUbp90sWb4OB9OEWj+5Z8KSUdedxGwouUYlMeNAAlL/7NDkKSvNpUDC JmGbJON8OKVCS8idIB9lACwcVavVx18L/YCJvzSwTvQTdXDOhMSjrS4Ouyyt2MSQiCpru6xUvwlGCm DOXU4YlA5cqVJ9CA/Uwq1U23IVAQOTldToR9GH19lq+0Kmr19P0jQha/rl5uarCKr5BU0XTqW6QKT2 k4cPF3Fjb65aiz0I3G2gW8SrPW4AANI3jJyhQT1+m32izI7gqs4Dz/h4jq9RSfF9rXjBXmBceJfnnb UmjaXMhmVJvPnAB7UXA5/tUz5h4PnWMb4WIyWqS8K3Rjppw81sgG0S3FEKk317d7y/ucXUDBwAIdbZ QqQI+ijh8zAw6m4pa1PHMgJxjN1nvqzNRip6eiShoPrpJrNKHlVZMseoUe+ytcD0IXZlr5VZgMlSnR MvmYVYavcUj4497v/0Zh4lg22PSKybYSsACuCv/g6jWagGfwMiDf+qOK4fNpn6eI5Jk9v4/vqg9zTj iEwg/2zCSXBGZsM3rMMyuud3hH9sMkmyKANOQvl4zbB3ghuT0gVX9Vt4Sb+innAy0kHTbvs2+F4XSh VvkhTOPJ5bFVFdiIqQFVx3jLysoYcUAkK3oXCThGbXsbm9fTKpWY3lnzNiVA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="Eaj/SO41";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::631
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

[Moved sysctl into kernel/exit.c -kees]

Signed-off-by: Jann Horn <jannh@google.com>
Signed-off-by: Kees Cook <keescook@chromium.org>
Link: https://lore.kernel.org/r/20221107201317.324457-1-jannh@google.com
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
index 35e0a31a0315..892f38aeb0a4 100644
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
+		panic("Oopsed too often (oops_limit is %d)", oops_limit);
+
 	/*
 	 * We're taking recursive faults here in make_task_dead. Safest is to just
 	 * leave this task alone and wait for reboot.
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221109200050.3400857-2-keescook%40chromium.org.
