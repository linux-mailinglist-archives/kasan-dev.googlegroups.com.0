Return-Path: <kasan-dev+bncBCF5XGNWYQBRB54NWCNQMGQEYZRY55Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5236D623413
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 21:00:57 +0100 (CET)
Received: by mail-vs1-xe3b.google.com with SMTP id 190-20020a6719c7000000b003aa14ac75f5sf4729770vsz.1
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 12:00:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668024056; cv=pass;
        d=google.com; s=arc-20160816;
        b=nbvJ7J2/wnI0SdlUXiifhrDD0yswsDANv4WdGLVNNadL5ZhwOUQpliNU8/C4TkSzd4
         kRUdAuTE9WnVXnmtrkimhs9l5ZWKdQ9VPJ/K8UFJtBsBYwunIAFWr567JesU7UpoxYL2
         G39+H61wRMU6K6ta53DzOPWYozyrHPeHlI7svdihs/aFQJ8QWUf4tZhmOgdmlRs5jON1
         QjSHw7a6DwrPzbBc+dD4WtekPnqLZuEfG2R5jPtU7UPxlajK+80xN/gIC8p+1mJ0+jg5
         yKFakx7rt1xhuYmBJLkQNnbU1SSKN6+Pg3JGunV9Pcc/sq33sDYG011ICs0aoew6P/xB
         zhnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=h92L/CU6g6Ys7QWITQkrm8z8K8mD0PEdr1YgnSsDhTI=;
        b=W+k+H+NvZTNFeywy5Ksk+mL6+HE6LU4PcAWnSI0Y92O1kM54GTJNKmZw6nlw2xpvF+
         u1WD9QJXsSff8Kyx+jCDV3U6f6jSsOm4CG2rkCefm2LYM962hRuCvtr9Ka5cQlgjAgDT
         Rv+kZJpnm+Bg5QUYrhNYae3UaXvvZKYectnKNL+wvmnUgcu26v6esa/5AImiexS3g1bB
         p+loOF3kSq/2vqhGcX1DkogqqAHUyckAXexpVZELWKcJogjOV9csQQRpOvfeKpx02iW3
         ybJVRUKgwiMlZxYh5igyZkOOc4T+//XAX4TxtthqxnzzKxxUD8Y8kkWYRkpmRVeh2ZQC
         lnsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Al9IUPio;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h92L/CU6g6Ys7QWITQkrm8z8K8mD0PEdr1YgnSsDhTI=;
        b=Zo9gJoQ4bXPo5mFN1z15LNvHY9NP9w522Khy5B+b/6Eap8sIrWLwqBXqUGPhacjGCI
         8Jc8teUiJwMy2pf3aJwR24MD9hNH/5c5JRkxviyYaRcJ3a9hgOJUqkrUMLWSmWtmsTcI
         iEU18skKd3dx+QGJECaEfa0JUKRIv5wMIRhXqx0OMFN4kTDMnF40CzzL8MscLbbE10/g
         Our+CiwI1laTWFSE+5FvWZUWKH5iShxPyXStsJKqhAA2wdJTYaautf4H94FHug4qO4ib
         XjlW4PnxdAx2dMXhPaSDy9ZUHYzpnfN9ACtq87WI/kkZE7gl8NMXcp7tcFE8Dhp1RR6S
         rziA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h92L/CU6g6Ys7QWITQkrm8z8K8mD0PEdr1YgnSsDhTI=;
        b=QmXA+UBH3W7I9yaeETi0U47zJ61sxUZbaZpe3U3zL5XfzDSDguP6gmuvNgi4Kyislo
         r6y5c695hy7xG9Ad6prITbP7EhQFzf3gv4bTuQHUc5arczgiBvuapz9TblOHOda8ZYku
         rRx56yrTsapqNNZJNMWZMj9mnYvnYCEAPKzCasvpiVZk1iYsZxhUFUryVqfuXaNRM+JD
         lHz2bwK/lHiirbIc6CZ5MB1GAM9BwuWZrgz4e0vG3i+uVUEUXQWI9s079YbFVB8frPam
         5fmYgh2GhI1m7zD7XXhSkgW+Fz1c5HcsQLWtRS389ZGkw5jDV4A1tTF+2W5jGx7e3jVu
         Tysg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1aVSc9I9UD4Qgk/sGEbCEBuh/mEqLySQtM74wSpS2mNt+/pT1W
	5zRvN+1Fingk1SBXE4XlZDw=
X-Google-Smtp-Source: AMsMyM6lPQO/8QXfR550EEUTlYN/UEGsqu/MmA2tXkPpMQelQbwfqPe4OFeqBqL4qgb3g6L0U2xK8w==
X-Received: by 2002:a67:e0c7:0:b0:3aa:2e89:683 with SMTP id m7-20020a67e0c7000000b003aa2e890683mr33135311vsl.25.1668024056233;
        Wed, 09 Nov 2022 12:00:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e0ca:0:b0:3aa:157d:1864 with SMTP id m10-20020a67e0ca000000b003aa157d1864ls4136677vsl.11.-pod-prod-gmail;
 Wed, 09 Nov 2022 12:00:54 -0800 (PST)
X-Received: by 2002:a05:6102:a3a:b0:3aa:2b15:92c8 with SMTP id 26-20020a0561020a3a00b003aa2b1592c8mr1515491vsb.60.1668024054823;
        Wed, 09 Nov 2022 12:00:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668024054; cv=none;
        d=google.com; s=arc-20160816;
        b=ujWUlOgxgB37HrcN6CzO1x64o6NRPQsP6mozn5t/CEKQYZWt2IKqQiQb+3GJYFJN7P
         Ohu64LJo3HiQA2HNBTmLzIVBKtIPBTjhjyt1YAG1xKw9hREpjqSVhAuJ+QDNlUM1HTrf
         5F2v1GY0O2tKBvIAU0s4LverRL5099CR0e5HhrhVPpNi/HUlYN7ubWhI56hDLt+kigI5
         9uOa9RjYLRuCMB8CaeP/TsOw7PaiDbvaAwjF7xocdP5qZspJSEHGFyZ+UilOgBABfe9p
         iAtUh97IzH8rZJC0y/6V08mq70ydAW011C9q1VwerZ/KjQKkPR/t0b2LOUHUKpuBJOp7
         ol3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/UYGWVP+2kBbzi2iV4I0WWEoZudfeo1pQ1Ba/UKdZ3A=;
        b=sqIG0RlLCHEMtcWus4hZ3u5mXt+ht1384CrIWXjYlrpfB81ihcRZNFUs7cJBjx1cyV
         3uBq48t47fjF6oXu/j22Ohyhxqg4jgSiv+2nkjXnKv7x8Hoc1l6TAbiq3tsJNP3vn6It
         0C1cyx7Oy0DCEcIi+Pmol54onxKOSFxGd/VQVGkB7FmZf+p7E3jWEYiKLXp4d4+6RGVp
         slmZdCK8sHNgcEsKMlu2SLE8puoLIdY+8XLc2VkFE88P/MJhqhUw2lb19ttpJc9DgM1T
         0ucXeCBhuMZRjcJIfm/Rsk+2TQw5z2cJPmRccJLqPm0eHa4ZXG0ntGhcKN6j7t4I2GxD
         M6yg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=Al9IUPio;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x62f.google.com (mail-pl1-x62f.google.com. [2607:f8b0:4864:20::62f])
        by gmr-mx.google.com with ESMTPS id x80-20020a1f3153000000b003b803083c23si680850vkx.0.2022.11.09.12.00.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 09 Nov 2022 12:00:54 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f as permitted sender) client-ip=2607:f8b0:4864:20::62f;
Received: by mail-pl1-x62f.google.com with SMTP id v17so18115777plo.1
        for <kasan-dev@googlegroups.com>; Wed, 09 Nov 2022 12:00:54 -0800 (PST)
X-Received: by 2002:a17:903:1211:b0:178:9353:9e42 with SMTP id l17-20020a170903121100b0017893539e42mr61056479plh.45.1668024053928;
        Wed, 09 Nov 2022 12:00:53 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id jf9-20020a170903268900b001868bf6a7b8sm9480282plb.146.2022.11.09.12.00.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 12:00:51 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
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
Subject: [PATCH v2 3/6] exit: Expose "oops_count" to sysfs
Date: Wed,  9 Nov 2022 12:00:46 -0800
Message-Id: <20221109200050.3400857-3-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221109194404.gonna.558-kees@kernel.org>
References: <20221109194404.gonna.558-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2891; h=from:subject; bh=qMx/IsiWcmyqv4bprAvLa4Z+pu9RdmRiuPSjG1ZzTgs=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjbAbwo1/8yglxqkQYwl/TzoU05jno2OXdm4rO0Khj SNJWKvmJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY2wG8AAKCRCJcvTf3G3AJn+dEA CRtODMqBP7kZcO5j9TwUU+pK8X2SSatj9G4jVKq5CV0wprk1khK5tQp/daoG01CBFuBi8pywh0MToC qWOJ91xSfQ/agiOTbGd07lX6ERIsGg7OnwthRfzrrgbStqJTaL9Ei56cH358dNkLxqP13ai260fQ6r pGCtPIHQ1HKjN+2ZUwXbMdVQSryY9wEfEV0qELbRCKol1wPOJqQI4EF7LMJjAQVqM/5YSDZVWAKoc1 PozfKT/HCo/8/vCKUyH29aaFklAEtl4yqgamCcr97ZuLklQn7lUhd4EMHF5P+iCsqaHKTxW4+2dRbK IZddqBIugKXp5xwXEUgHTjd9CD3spRwYJThUf4qTQjCMTceS+KunCfAMfDs4gvwgiJKXrmfViqcDvj Boo6O8+t+Dx84XTCh4iCcOUuSm/WrgINQCwCQn+kDHxUaVnwIVG7d1EfHIdb9f/3Ipt74/drWWYQLN eMz+nYK3J0JnqPAfoh/QdRk7t2ojlnwEAXhRsS7g2YLDfKIHCLyvaC0SEuynhHyX1umjMm3G5rEsp7 jjFeQESAFmjYAUoak8T6n6jnl0Q0e/0N0/Yi+jTgf5WnBJ27ID/Oqs2EFlBosDJ3WwuxdK4lZEp1q9 5pPeP4jLcdy3SOY/cdO3S74h5jopYa5+mufuWL4X4p7060Tps+iGxoxMR1IA==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=Al9IUPio;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::62f
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

Since Oops count is now tracked and is a fairly interesting signal, add
the entry /sys/kernel/oops_count to expose it to userspace.

Cc: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Jann Horn <jannh@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>
Signed-off-by: Kees Cook <keescook@chromium.org>
---
 .../ABI/testing/sysfs-kernel-oops_count       |  6 +++++
 MAINTAINERS                                   |  1 +
 kernel/exit.c                                 | 22 +++++++++++++++++--
 3 files changed, 27 insertions(+), 2 deletions(-)
 create mode 100644 Documentation/ABI/testing/sysfs-kernel-oops_count

diff --git a/Documentation/ABI/testing/sysfs-kernel-oops_count b/Documentation/ABI/testing/sysfs-kernel-oops_count
new file mode 100644
index 000000000000..156cca9dbc96
--- /dev/null
+++ b/Documentation/ABI/testing/sysfs-kernel-oops_count
@@ -0,0 +1,6 @@
+What:		/sys/kernel/oops_count
+Date:		November 2022
+KernelVersion:	6.2.0
+Contact:	Linux Kernel Hardening List <linux-hardening@vger.kernel.org>
+Description:
+		Shows how many times the system has Oopsed since last boot.
diff --git a/MAINTAINERS b/MAINTAINERS
index 1cd80c113721..0a1e95a58e54 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -11106,6 +11106,7 @@ M:	Kees Cook <keescook@chromium.org>
 L:	linux-hardening@vger.kernel.org
 S:	Supported
 T:	git git://git.kernel.org/pub/scm/linux/kernel/git/kees/linux.git for-next/hardening
+F:	Documentation/ABI/testing/sysfs-kernel-oops_count
 F:	include/linux/overflow.h
 F:	include/linux/randomize_kstack.h
 F:	mm/usercopy.c
diff --git a/kernel/exit.c b/kernel/exit.c
index 892f38aeb0a4..4bffef9f3f46 100644
--- a/kernel/exit.c
+++ b/kernel/exit.c
@@ -67,6 +67,7 @@
 #include <linux/io_uring.h>
 #include <linux/kprobes.h>
 #include <linux/rethook.h>
+#include <linux/sysfs.h>
 
 #include <linux/uaccess.h>
 #include <asm/unistd.h>
@@ -99,6 +100,25 @@ static __init int kernel_exit_sysctls_init(void)
 late_initcall(kernel_exit_sysctls_init);
 #endif
 
+static atomic_t oops_count = ATOMIC_INIT(0);
+
+#ifdef CONFIG_SYSFS
+static ssize_t oops_count_show(struct kobject *kobj, struct kobj_attribute *attr,
+			       char *page)
+{
+	return sysfs_emit(page, "%d\n", atomic_read(&oops_count));
+}
+
+static struct kobj_attribute oops_count_attr = __ATTR_RO(oops_count);
+
+static __init int kernel_exit_sysfs_init(void)
+{
+	sysfs_add_file_to_group(kernel_kobj, &oops_count_attr.attr, NULL);
+	return 0;
+}
+late_initcall(kernel_exit_sysfs_init);
+#endif
+
 static void __unhash_process(struct task_struct *p, bool group_dead)
 {
 	nr_threads--;
@@ -901,8 +921,6 @@ void __noreturn do_exit(long code)
 
 void __noreturn make_task_dead(int signr)
 {
-	static atomic_t oops_count = ATOMIC_INIT(0);
-
 	/*
 	 * Take the task off the cpu after something catastrophic has
 	 * happened.
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221109200050.3400857-3-keescook%40chromium.org.
