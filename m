Return-Path: <kasan-dev+bncBCF5XGNWYQBRB6ENWCNQMGQEJHBJOQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B069623415
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 21:00:58 +0100 (CET)
Received: by mail-io1-xd3a.google.com with SMTP id w27-20020a05660205db00b006dbce8dc263sf5805331iox.16
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 12:00:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668024057; cv=pass;
        d=google.com; s=arc-20160816;
        b=GWqontbbLpyZDC7ZHNvEnNPKSAqdnvsytj1sXp2lD++2deB6Ks/lZQsM1VudijlCTP
         ERRklRM5x8PWHHE+1ZNpW5QY+GEgJ+nUSKwwMvuqCwZfyJxUQYxoZ/9wWyVgSB97sqFt
         GeuOwKpRfnB6pH0B9aIxEogHY92O1xlsXzrhkmT99lEOkB7LvkKTWK9SQLYpL85dy1I+
         O29bkDyUyZW5eC1czuCaWL+1oKPUNtlyUHMrVfKNY8hIaEwjBlOcRF5STBpF/MTt2wzl
         5nYNhOE6Umof8+S946fV95omHn1Ge9NeTReZr4WMJER0aBzQyeS+4iOxaGxAtSgZ5oc2
         0m9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tb/pYJII81NLPura28As0PyjoqwXFSqeBBSxZ+6B+g8=;
        b=yGiZ0I93/QzyrWPdBIHSx6uLRGoaqRvWXrFvgeSIGB3W+hZtiu5fnwVFdvWsGz7g38
         3Cc5zDnzJ3VSDmDrDnZz+L7R+l4DrvORIx91Y5Dz2pduLeyIQ2gHdOw2YpbfFGjqtn+6
         s9xcVFbUBME9ZK53R/nGpokHrcQt30pzqX/sduoseC1pdH3kFZ0GhzMP4TukeqIqe9ID
         rf+vqU6gcE1o0XYVOdFNAiutxPHZzdhFvKm9lCVEUU86rXUAK/Ei78iICe5mQr/2oYga
         GdngfsNBzc5E4LY6wE8o09jidE+5HRQN48AnlZeOZJNjP0okHOr4oZ7pGNx5baKrPXri
         3ouw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Bj6yZrGQ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tb/pYJII81NLPura28As0PyjoqwXFSqeBBSxZ+6B+g8=;
        b=WER/XyLMHa+SDGKSaSUJaPuxAcXJI9bHBdzsorodxej9u5O1WeUVj7PUu9T7imKQrJ
         naI4VOUZPd9+kX7CWHlGOL1NBl1oIRfPSKklUB6H+F3MYwUJAa63SV+l7rq8cOBpnJbP
         qRbsko2edTbv26v2TTkxyqzIYrG5FnAVcKrUxMPUKl9BD3dzwS7nvBhl8f1wzwUYSbe2
         P0B6w9v2il57ObvbDg4WjHxSKFXjB5BN4Pyb/2L8JybScSfR+j325xueLHTZ8VQZ/XPO
         gtlIE7ziQTCGDxMeIokN5qQ6V0lwP8LpvocJPk2DvinqYyrzE1KtujS7EyyXBGYKJagT
         CZIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tb/pYJII81NLPura28As0PyjoqwXFSqeBBSxZ+6B+g8=;
        b=RT9UF1df3/Mn5DuJnv10mGxo2xfZDndwjtMBlpGMmIcaamTNCng8DUkRx2Pi9kRl7K
         kE2dLPPdLehr3AuOU4SATB6a2bNlHQtjMPfuZWzd6iwJuEkMQxMthOChxgrn3SaIySqB
         8Lz+oJp9Nur1e5oxIGU18sT6Y5KevndxFlZ+IouPacdYEyYkoxMigRnXEpFlLFwTS7S1
         s0woCkDskIV9hAa9R6JFVJ1otDz6U2gV0xt0+ykCU10DDpQAbR50wyzEJcqhQ3XwmFo8
         CzIKtHiIll+S04o5XargFVb/RkosgpXC50DRon6mubmWTyXN0QNMnfifTYVkXaGSJApf
         RZGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1a7sY1F1WgzVOjVRQb3p0HYHxOeq2mU1z2DMPraQDw4cnu2DJt
	pC7eCH0ui3izRyZuLqfr8AM=
X-Google-Smtp-Source: AMsMyM6FmcfAoru6WlGL3la0KcLpil9KeBc3f9IFrxf20SyYcTIWQksWwAvXMEWbQojq4Py/ZMExAA==
X-Received: by 2002:a05:6602:1402:b0:68a:9d38:8248 with SMTP id t2-20020a056602140200b0068a9d388248mr34971224iov.68.1668024056820;
        Wed, 09 Nov 2022 12:00:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:eea:b0:300:d3c7:ea0a with SMTP id
 j10-20020a056e020eea00b00300d3c7ea0als3884404ilk.7.-pod-prod-gmail; Wed, 09
 Nov 2022 12:00:56 -0800 (PST)
X-Received: by 2002:a92:ca46:0:b0:300:e084:6843 with SMTP id q6-20020a92ca46000000b00300e0846843mr16936120ilo.27.1668024056408;
        Wed, 09 Nov 2022 12:00:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668024056; cv=none;
        d=google.com; s=arc-20160816;
        b=PInQmTqrdzpTqyb0STLxoaq1Kbl+F7q1fwmq4bhflXRx8HKCkzH6Ote9Ge6GMgTwIY
         rdr/626OJKortbJH7c8Hz0BbN4aZyWPjcLB9DmF/ox12LzymmYGf3dOSK7xUinsJUg4W
         uInWIR0zgKr/nl4qeU89wLfyfAk+Dp1ykL6u3Bp8lNXZSsx9/uHdL6L698wGmkh5KfqN
         wkSgalOyxEjBXBaztv3pAh9mkszGa7JC5luuwFvNVyFYBBgDnBB/KxUJeewgp9lbMuzX
         uYSbD3dIV897/P5SVZI6hRuQAMNuXSumm4LY6ntgORmvw7Hisbh6Enhn4q/zyAUNgagW
         w10g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ro0afIwumapgwWvmG1YsaLR3d/PQtiJimII64ZaFtl0=;
        b=Z8SIkLK9fqltTMLuOJ6GoJbYLDaVvCgnu5aD+d2/uMxe4OyxAaY0cWpxIzJDP4XeVq
         aMzEea1H8SagyTRNaW+aTib4zCxhakXQ76xg/36gsNY8q/VessEbKd84JgGd3WEoB2Ev
         SF9p/Uj6C9SMpBrGZp2y1wkc/tBCRU3toot/ktu3qPcCwLje3hHpRq2IGxo6F04htrnk
         zyEYwQs8wZZnRjhIVF2BYzoeqai4XISul/HmTGzjAYvOJM6sxsmaUPvWDugf0Mp3G9b9
         bfVNyATnb6GQNKYMfYH2dkvgGL2bNHqgmZ0sVGmylc3nYBh+UW44p5dZdbNCE8WibKqH
         HmIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Bj6yZrGQ;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x629.google.com (mail-pl1-x629.google.com. [2607:f8b0:4864:20::629])
        by gmr-mx.google.com with ESMTPS id i1-20020a056e02054100b00300ee6fc286si708678ils.3.2022.11.09.12.00.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 12:00:56 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629 as permitted sender) client-ip=2607:f8b0:4864:20::629;
Received: by mail-pl1-x629.google.com with SMTP id p12so12602197plq.4
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 12:00:56 -0800 (PST)
X-Received: by 2002:a17:902:edd5:b0:187:1e83:8b96 with SMTP id q21-20020a170902edd500b001871e838b96mr54187822plk.1.1668024055895;
        Wed, 09 Nov 2022 12:00:55 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id bf20-20020a17090b0b1400b0020ad53b5883sm1639166pjb.14.2022.11.09.12.00.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 12:00:54 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Petr Mladek <pmladek@suse.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>,
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
Subject: [PATCH v2 6/6] panic: Expose "warn_count" to sysfs
Date: Wed,  9 Nov 2022 12:00:49 -0800
Message-Id: <20221109200050.3400857-6-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221109194404.gonna.558-kees@kernel.org>
References: <20221109194404.gonna.558-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3046; h=from:subject; bh=crjf/DqHlmowr17FD7/hL69h8FPT+JeC7P8wT4Sy3y8=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjbAbwTj82NH1mVc/BdwILXJUeaZUer5Kuv1KXHcsT gLf80RyJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY2wG8AAKCRCJcvTf3G3AJqs9D/ 44ACl1LNxgKhWqINCpUTjTgHQ0kvWjIPxs52zdEdrIVDv2BZZ/DhUpxrcC730QQtcJ6F7xe3UlmePB 3hKgSYaj13nxQyS3P9cvMUtbFrQj7cCWQ8v2Q4xYikQw5hnl76PZNNLk9JRzNurPZykchYWXpIrXDt yPp0o/bmBoaDGuwOBGLA3ZcGPZgVtS3734GCjfABnwjPchjreV8dXC7sLPVxx1MAcgHOKuqoYRTcfZ sqZKqkLm9KLO/nZ5dm5UtR/R6AljYC5Y1uxCfYNkicYlrzReWZefDGPaBPR/ZQ68eDwIUiGSi8G9cz 6S9Jy7hFaGQGgsxyLMJQwKOVFoLDLpm6q2HbyNVp2Cenh5utpS6/TVtvR9OqFo+7w1UPBi0z1Hczye 6qKolXHZNNv70gNEN8fXOJGu0vqBZAEaSYp5YvkGnnymFY5tMIOG2FM+dJ1Rh3eFx1KoKh5/8uWgLP zR9Vl5PP3Wi27coL560UkZve06uP7FO8GZnRBiPLpOxZw7AGp1jlCAXOn28uBrDybJAvFxZt1W5emj 6AfqaB0D26hF55T8TAlhjp8jtR0Nk247ofFgCq/h7fshmRCFK94izJo05cL5SWAJFlphsHH6pYPpk/ 9L8qhMC3W+qJVj26D2+kYfHGTR7ruMYJ2UqU1p94HQJ4R8tORQAiouOk+uWA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Bj6yZrGQ;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::629
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

Since Warn count is now tracked and is a fairly interesting signal, add
the entry /sys/kernel/warn_count to expose it to userspace.

Cc: Petr Mladek <pmladek@suse.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: tangmeng <tangmeng@uniontech.com>
Cc: "Guilherme G. Piccoli" <gpiccoli@igalia.com>
Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: Tiezhu Yang <yangtiezhu@loongson.cn>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 .../ABI/testing/sysfs-kernel-warn_count       |  6 +++++
 MAINTAINERS                                   |  1 +
 kernel/panic.c                                | 22 +++++++++++++++++--
 3 files changed, 27 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/ABI/testing/sysfs-kernel-warn_count

diff --git a/Documentation/ABI/testing/sysfs-kernel-warn_count b/Documentation/ABI/testing/sysfs-kernel-warn_count
new file mode 100644
index 000000000000..08f083d2fd51
--- /dev/null
+++ b/Documentation/ABI/testing/sysfs-kernel-warn_count
@@ -0,0 +1,6 @@
+What:		/sys/kernel/oops_count
+Date:		November 2022
+KernelVersion:	6.2.0
+Contact:	Linux Kernel Hardening List <linux-hardening@vger.kernel.org>
+Description:
+		Shows how many times the system has Warned since last boot.
diff --git a/MAINTAINERS b/MAINTAINERS
index 0a1e95a58e54..282cd8a513fd 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -11107,6 +11107,7 @@ L:	linux-hardening@vger.kernel.org
 S:	Supported
 T:	git git://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-next/hardening
 F:	Documentation/ABI/testing/sysfs-kernel-oops_count
+F:	Documentation/ABI/testing/sysfs-kernel-warn_count
 F:	include/linux/overflow.h
 F:	include/linux/randomize_kstack.h
 F:	mm/usercopy.c
diff --git a/kernel/panic.c b/kernel/panic.c
index b235fa4a6fc8..ddf0f8956d6e 100644
--- a/kernel/panic.c
+++ b/kernel/panic.c
@@ -32,6 +32,7 @@
 #include <linux/bug.h>
 #include <linux/ratelimit.h>
 #include <linux/debugfs.h>
+#include <linux/sysfs.h>
 #include <trace/events/error_report.h>
 #include <asm/sections.h>
 
@@ -107,6 +108,25 @@ static __init int kernel_panic_sysctls_init(void)
 late_initcall(kernel_panic_sysctls_init);
 #endif
 
+static atomic_t warn_count = ATOMIC_INIT(0);
+
+#ifdef CONFIG_SYSFS
+static ssize_t warn_count_show(struct kobject *kobj, struct kobj_attribute *attr,
+			       char *page)
+{
+	return sysfs_emit(page, "%d\n", atomic_read(&warn_count));
+}
+
+static struct kobj_attribute warn_count_attr = __ATTR_RO(warn_count);
+
+static __init int kernel_panic_sysfs_init(void)
+{
+	sysfs_add_file_to_group(kernel_kobj, &warn_count_attr.attr, NULL);
+	return 0;
+}
+late_initcall(kernel_panic_sysfs_init);
+#endif
+
 static long no_blink(int state)
 {
 	return 0;
@@ -211,8 +231,6 @@ static void panic_print_sys_info(bool console_flush)
 
 void check_panic_on_warn(const char *reason)
 {
-	static atomic_t warn_count = ATOMIC_INIT(0);
-
 	if (panic_on_warn)
 		panic("%s: panic_on_warn set ...\n", reason);
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221109200050.3400857-6-keescook%40chromium.org.
