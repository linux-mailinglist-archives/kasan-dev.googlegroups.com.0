Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJMO3ONQMGQECEYPTWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0489762E9BD
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:43:35 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id d130-20020a1f9b88000000b003b87d0db0d9sf1067879vke.15
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:43:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668728614; cv=pass;
        d=google.com; s=arc-20160816;
        b=qrr3xVlsXd4WxVs6qzB3S2xIYlqP+0peLEE8xSFE22GbIcsH8EBoFRfD3m5nDFAlWR
         n08auY6oOBdLZjEB1lLDNOgBmVHtc9qO+79168EMXxyUq9bUOCc2tzeyECWk6Bg70zKl
         ORpYEC9wT+500xiAePALh5RwaD9PhEkhIYZUJH/yBkF7jRuH55Y6K9WnwkL6wTUqffWb
         ESOadgsSg04K/pid3XLvpgVXL0FV/3vT7ePoLXS8rpqVf5e6d6amHYL6Xt7IRtUX87FY
         nrAoR0rGIZ0B3G/c7amZKRyGQW9ME8aLXkgYg5vn3FGgjju+BgPXhgRoL8INJw7np/nD
         4q6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Ci7Nzh14WzhPCMXd1D063g1hdi0c7yygwtsbXZOvPXk=;
        b=cXVWAvvjUvXJ+MuroZy1hYt3vxc7nLrtp0FA+aVIGmPR9QR2UUrBbDtOEnEvdQ30xO
         T8BNomlKmrtshU4t2ug8bMn9SHJJwjwSJq2K5QzmK4IpkkTF/Wd+br5o9xjXOlwwBdO1
         HpG+Qja7lG+2Tm+8zBMPxQV16HP+r+Z1KeG2Rj4F/ibqMcdRI0eYNNSxze7Ox0n68KY0
         YRRQ8paVSgrRFnX2rjJeURKEu5qy++L4Z1E7vDGOW86y+R/EMPTT5o4/kMSMPrp7q6SQ
         7MU2v3ABZIoW8bkAxCgQMK/A4pdLBe5u25HOrI43EhugihzIL6njwtQeP+EZVZRjgSAn
         qmLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=CAnKSUlM;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ci7Nzh14WzhPCMXd1D063g1hdi0c7yygwtsbXZOvPXk=;
        b=SaSKEjN+qjWf+gVB/QS1onMMs2qRDmhlM8mkwoEl4eyotCTKuIH7mhjhN45NsYq69t
         M+38MaR8CL3lptOCh/ONzgXWQeVW0EziJpHCsnviRyuXmfcJDc2xUyWqGse8b4c3oy7A
         k6c69+gfY2z0LClPW4jvCVbyst6qArd/OdFGY0jaMgIVAwHGtRQXPPjbcY3wJysp5vDA
         6qHa2l1SE7GS3nTXfHhEJwlYkweR2/BUu3HRjg/klA0BsOqvouiHxI7aHKbzcdZNyRIc
         EEechhDfcfZaiMPRIzbbW6ZKIqIiDaYm1FGLQbruON7pWeoR4VhRNFflLlBUInmxJO0s
         ciUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ci7Nzh14WzhPCMXd1D063g1hdi0c7yygwtsbXZOvPXk=;
        b=Un39mOs4oRJ3XEx+arcrq7LHDXYNynQXyCu3psTvVIcFicqSh2owRdl0wujyRo9onT
         roxX3WZXjYV8hVY3+wkVIHEkZfeT+7iyrELUtSegmyxKoGog2syjsy57aGjjjf2LHCSf
         Liyhe4IUBMzVROOQm63jMg1my3QoyG4Wqzz4Zdid4RFJ/ho1UdNiKJGBm1YDzk0rvDmr
         k1Xs8dV33kLinBK8aVUc6tpLxaf3r2v/BuRuoh2YxmsDxU8QLLmGMrXMeKpQ6Y5ttDiU
         UBKQ6bkWt/g+z1bVEdT4Xj0RK0mMcR0eaV3ptmc14KS8DApblMBQWY1dI4vas26/ekR2
         sVVA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmoBSHahNYOCBNCk/l15Q8C6+p5NyCON7delL6yF3eVmz3mjiZi
	eLKiEH2SgDsvG4Y6RIHVK74=
X-Google-Smtp-Source: AA0mqf7O55oZKFhHbbpURW7ZYbgASJ8LM1f2Mltyuz6N/R5UuFCU1Oo534ubNrkSPxpu8d5gXxi9Uw==
X-Received: by 2002:a1f:f401:0:b0:3af:3445:abc1 with SMTP id s1-20020a1ff401000000b003af3445abc1mr2818753vkh.24.1668728613890;
        Thu, 17 Nov 2022 15:43:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a0d5:0:b0:3bc:2cac:f10e with SMTP id j204-20020a1fa0d5000000b003bc2cacf10els408348vke.0.-pod-prod-gmail;
 Thu, 17 Nov 2022 15:43:33 -0800 (PST)
X-Received: by 2002:a1f:a0c4:0:b0:3ab:85c0:e1e8 with SMTP id j187-20020a1fa0c4000000b003ab85c0e1e8mr3011500vke.1.1668728613360;
        Thu, 17 Nov 2022 15:43:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668728613; cv=none;
        d=google.com; s=arc-20160816;
        b=tngoPq4bhbK7PF5cei3cOGkZE7ihe02sEW83ckv3+UqDoT63I+IjSc7qUssQ2gwTZl
         qiYPdzmo6YDkcNQ5K85TccwTRFLxr154qm1RZNEz/CGxbaNeRTh+gxGdKLoNkrXD3B8n
         8jTWgp2WFfkjn3sPonoCDr+8pwvxjcfV7osbn1rarWoBWO2SMsXy88yDwGE+5pTjCJza
         FdEoL4CgIMt/1v/sh3VSV4oEPKXowrN7a82Z78AseqgVoDNzcegKBciUumj3QwevZA1R
         4hooKK5vROv/2viVPg1DeaB/qjem7TOrSrcXErAEkUSeMukjfoQZCKhByBZlD8oYHRjB
         k/4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LPxyAZmVFIQ+hzeHNDklOMYnt0nT5zaSRXR3AKVl0no=;
        b=CoBrC2lVSvrV3z0l5CuWUgguEosSBJ+2Qh4pl+BEA+BqI3pgOXuWhkgcqP9CykP8oU
         uEv/0ZvfGfvsTtk/F3gKKuPYqdot6BwkPRmkfATnIvzdE7jkOHvDOj2fn69Jjp8zh5VV
         OMN6iit9W6QI89Jqp5UWIxPY9y3QQ2HLa3qP9ph6FCx0Egv8AWqudrc1KgL1yUHtPt6K
         Nk0On84rUXqKWfgJGuY0l7v/Bl4tkk0HHXAhrpzy4pDYB5A09yvajO4MlHGt+K9f8EUo
         xYEGd4NODsAoDPxQRN9bnu9TCT+NDqT2RdxVL1luWEvBXFV39BbFiaTL5eQNh1Pnn3iT
         9gHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=CAnKSUlM;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102d.google.com (mail-pj1-x102d.google.com. [2607:f8b0:4864:20::102d])
        by gmr-mx.google.com with ESMTPS id u7-20020ab03c47000000b004181ba78c01si323620uaw.0.2022.11.17.15.43.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:43:33 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d as permitted sender) client-ip=2607:f8b0:4864:20::102d;
Received: by mail-pj1-x102d.google.com with SMTP id v3-20020a17090ac90300b00218441ac0f6so6967343pjt.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:43:33 -0800 (PST)
X-Received: by 2002:a17:90a:dd83:b0:218:61bd:d00d with SMTP id l3-20020a17090add8300b0021861bdd00dmr8381157pjv.236.1668728612350;
        Thu, 17 Nov 2022 15:43:32 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id w184-20020a627bc1000000b0056bb99db338sm1763850pfc.175.2022.11.17.15.43.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	Petr Mladek <pmladek@suse.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Luis Chamberlain <mcgrof@kernel.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Andy Lutomirski <luto@kernel.org>,
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
Subject: [PATCH v3 6/6] panic: Expose "warn_count" to sysfs
Date: Thu, 17 Nov 2022 15:43:26 -0800
Message-Id: <20221117234328.594699-6-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221117233838.give.484-kees@kernel.org>
References: <20221117233838.give.484-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=3097; h=from:subject; bh=D2z//ezLIcXAbCg09JRiGI8OFvfo+V6hl+TtnONC3LA=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjdsceSurFVH4Xz0byr7qjcNZv7p7TUAKJ01o1LaCS il+61kOJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY3bHHgAKCRCJcvTf3G3AJrZqD/ 0XXgpqckv3Sl3gOzRU8XGOhhTKNCgley3+PyzCJRtiQH47toEntYyvD9vFmODaSLhG1FiyD30a+PUs G7BgQa2k5SXXu1y/m/LEYrgI+Ka82BZRjN3oncSn6Gj1sGbXDiyXNgFu2e7l3f5j0GuuPciyXT5UaC Whh7g6SSpQlWFg6h1VXkWltmzGxJmgVINVIrm35KuAdSyHO3fh2FDZDFbYgC7Zw5VEZQWZGwFRZKlq fZ2NQCYYViH28pOLbjsQelxISmwyjMc+u8Si72QGiSXyQDGontB6hLEn6ri71jOmtQC2fi1PaCVFse OlWZA3mp10sfh98TdxKylYukslvpvusA+K5MQpXzq1tksDtB8jEjaCMbaiVfi0VDO+HWdplKdRZ2+e n0Us8b6qHL08DRQD/d5Iyo3nKHoDU7W22eM6TKwdRh1VOt5OxabohHDHQQAQSKLRmVdRuK4voUVG2z WTiHCwgHCUaqjBbTFhP0qQEkOrInX+5FbG+pTGdqZYZkv2f092vx6VJEu8Z8BO3LF5bC2BFaiheOTK xh8e8bMHCJ2MM9mzid34rIfE7sSTbJVFhVblpoFmXm9S5J9GpgTITDTaHoCWUeeMuoxo3kOaCKuojk rVwdTZGGHPl+RyJg5fYfmDe+KCV0g0DLqAai97luhkgJ180YHwMEsAH3AtwQ==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=CAnKSUlM;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::102d
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
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
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
index e5aab27496d7..d718531d8bf4 100644
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
 
 void check_panic_on_warn(const char *origin)
 {
-	static atomic_t warn_count = ATOMIC_INIT(0);
-
 	if (panic_on_warn)
 		panic("%s: panic_on_warn set ...\n", origin);
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221117234328.594699-6-keescook%40chromium.org.
