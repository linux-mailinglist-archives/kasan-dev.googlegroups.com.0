Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJEO3ONQMGQE4ZZFGSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D17562E9BB
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Nov 2022 00:43:34 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id c207-20020a624ed8000000b0056e3714b62csf1971345pfb.23
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 15:43:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668728612; cv=pass;
        d=google.com; s=arc-20160816;
        b=H2HfSyfHBw3L2zm2fYgr337H2DlYGsgvObu7XRJDrA1s8gWXLRrSwVNxlh3RaBmaOm
         uIFT0BLwy/939AdufnIhFyK/vmfFNIQPGQ5t/twI99I1xyVJida/h9AC/f2f19uIGVbx
         ZcZKxXjfz509leNHPjThxKhHw6d0N0f1210hXIXanFyotKT+ZSlnLGhXXJkS6xaDs0rG
         ki8GFADStNapLNT1EdfoFpoiFG+d/q0wkdQXmU8lgCeVzdZtkml65bOe/ufJ/abHKDvS
         1tc3d2PoxaGjkWF+/Yz2ONrnrMyOW6Qwi4wzFqTGe71CLP3VT+gLIWGq5AiKr+nVdW9j
         srgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rupQk0P7280J/aKNE79Wv82f6zSg8W58sckYd151H3Q=;
        b=Dd6wKz9RU2u6Np33qSIeQoMJTzf2CYZl648gqOashPDVtZ1LIYY6Q5OztLr/GlWQ0W
         1Zb7oW37km9vwXfWYj6qb0S5qo51pi8YiaPvzdupNyt7K8j6cxFVJlz9/2gsSPXQTOdA
         tWGJMa5B6Hsoc19XObsKTB397vsI0RFnFBdaSGuUo6NNLE/hhVU4pz+4J9eYKot3zrp0
         wNSLexTKdgR288l6z8OZHmsNsw2ptuutLfX0ZVkEs4aNUiwjIWUjpccxrw5IhtAWIHjJ
         odxDr9YgSmIioYWjdPWiEPVkI6w6QfvK1cUtbk5Eh3oB3XRG82VAI0+StZDRpUbURuKp
         bDVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="g/cPhiEF";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rupQk0P7280J/aKNE79Wv82f6zSg8W58sckYd151H3Q=;
        b=QFduyUUrOiALnBvKC6ELV+HVzp6AdrH770UZPK4nVfIReHY//Y8z/0EKxA9TAlMv0S
         P7m0sxG+sgbsgo+hMPV/4mSvrQ/SERaCahsNOyXpQvQ/5Mqg6EWziZNGud+mJ3eP6AdH
         j4cEOEuJ0yQL6HCV5bEFDAd6Y6pAJZhwN8z4klnlyxP7HzXvSUn3gpAnj7FtthREjqUS
         FF/QXgxoEw4mUmdI6Zv8Wxa4FrVb8VVoVd5GkI96X26a/pOZiNCPrJglwe6rRnj45i/H
         c1S9n27Pbnxmb6e4HhClGfypElo6Jhw0tGmz+xs6k7IVspOSCznvWgnWOFbd7643sscc
         tq+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rupQk0P7280J/aKNE79Wv82f6zSg8W58sckYd151H3Q=;
        b=mdKnGocGX6JETUlWQ+e/L9te9kwNC8woyY8303QToKXpbVjIiEZ95hsQuxpbqMmhvR
         VAM1jGep6aOIvVh85gkWhrEu7gXPCbU5X+pFO+myUqo7UYvxYLvTu74DNLu1x3s7xPMY
         LxmdVYA5IDem830ilO/pD9NQUhAy3/IfSAKZArpdyPyXwY0oqSWKtDZnUgwtQGIyZrv2
         spdeQScEmUDnZLZXf2wpUOPJgpeQ8Qf9Jj+3CqSnykiZFPVLl1EiSxgUKq80wNrgiWNr
         5JEBqRgN9wEcMEmV0ErlU+zRtaS7msUgZlu4h/rAPfzscUS1TL40cF5/w98xaMft1D41
         A0dA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pme4yiv0P0zGZeOwMxq8+ESnvkxRYXRrfSeInMTpcEBNurYJsT4
	82SbFe0pTiwO3EMyND2aJag=
X-Google-Smtp-Source: AA0mqf5xH87IE0Qbe2xHHCLXlxHwrKbL9yv/SzE6a1PvmNb10C0sIBOzHYpCoso7gTk0Wj7KLi8YAA==
X-Received: by 2002:a63:5f4c:0:b0:450:3c0c:b17c with SMTP id t73-20020a635f4c000000b004503c0cb17cmr4159631pgb.64.1668728612525;
        Thu, 17 Nov 2022 15:43:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2741:0:b0:56b:9d05:32df with SMTP id n62-20020a622741000000b0056b9d0532dfls1679141pfn.11.-pod-prod-gmail;
 Thu, 17 Nov 2022 15:43:31 -0800 (PST)
X-Received: by 2002:a63:595d:0:b0:476:f2b0:b318 with SMTP id j29-20020a63595d000000b00476f2b0b318mr4250422pgm.598.1668728611803;
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668728611; cv=none;
        d=google.com; s=arc-20160816;
        b=Z5yMqOnhgGaOnsKfK0IQxf1SHfs9DC57MB6GiMagcflgyPKxg+6h4Q5rlZbqPRngO6
         itag/k6cwAu6KO+dqEVUpWwt07gajEBMbPRhkpD4xsuKl8w0wA4puEtiuOYV6uM/d5Ny
         lMdshtDKVNKAjMFoSzL7qWwcomfYb89Zd8YZP5jl+N1OnnVw23J9dA3rbkFoZM/B5XyC
         bxjf9LcibdSXNcEsH5pZVrQkXf9mDM2rzFWgTNMOQoHwMuO8UYHtiKubiQRNK67JRoa6
         cTnFz6NrYv4/Ez4SFcN+LGvI9hXQMLwBFgVSUN2CPhocAf+Ob4+zRdFSe3R7GY5r+ReQ
         82sw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jEctX2gK/ElW3R9ceKOIZ71qq6p0GHil0cFCvNxx9OU=;
        b=NYWWhXZ7GTVn5kgowaqWGf3A5ohEhQDgdXxQLhSSd9+vFeGeQlIjsfZS0oAU1Slvss
         C/Nmep7iZMnNSfOwZVhRMCIawexfW+zDbkCzKPU5SKrJhThyp4mzkC/t3my7Vvkz0NsK
         CA7G/qZDBJguJjjJzTVN2atsxaVi++i/igDRU43tmIKHWGzd4HHonDZvjlfkGeP2nlxT
         UffRrqknrrQNm4OwQfrqgTG3Vb1TyDEGyqYaMa/DJGltKOnz1IadbFPb9UH7KEDHSjEv
         TL8Z5q/aSWyjkucLMfFTKum4fN2aJjSG+rdgPB/v0Vyl3BpFufN7/TjIulz57O8STVor
         FzrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b="g/cPhiEF";
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id w203-20020a627bd4000000b0056611e6228dsi141987pfc.1.2022.11.17.15.43.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id 140so3294794pfz.6
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 15:43:31 -0800 (PST)
X-Received: by 2002:aa7:92d3:0:b0:571:fa1d:85b7 with SMTP id k19-20020aa792d3000000b00571fa1d85b7mr5205770pfa.39.1668728611497;
        Thu, 17 Nov 2022 15:43:31 -0800 (PST)
Received: from www.outflux.net (198-0-35-241-static.hfc.comcastbusiness.net. [198.0.35.241])
        by smtp.gmail.com with ESMTPSA id a27-20020aa794bb000000b0056e8eb09d57sm1740441pfl.63.2022.11.17.15.43.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Nov 2022 15:43:29 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Jann Horn <jannh@google.com>
Cc: Kees Cook <keescook@chromium.org>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>,
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
Subject: [PATCH v3 3/6] exit: Expose "oops_count" to sysfs
Date: Thu, 17 Nov 2022 15:43:23 -0800
Message-Id: <20221117234328.594699-3-keescook@chromium.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221117233838.give.484-kees@kernel.org>
References: <20221117233838.give.484-kees@kernel.org>
MIME-Version: 1.0
X-Developer-Signature: v=1; a=openpgp-sha256; l=2942; h=from:subject; bh=6N9/v4YXpaCj0jy2bGs74rqpXsiLoI6QvjFrvLVEdiU=; b=owEBbQKS/ZANAwAKAYly9N/cbcAmAcsmYgBjdscdh2yxsYpUSBCFMx+XWPrp5jq3lGnveBJJoWti eB8Nl9WJAjMEAAEKAB0WIQSlw/aPIp3WD3I+bhOJcvTf3G3AJgUCY3bHHQAKCRCJcvTf3G3AJjt4EA CjpotPoy23FlY4Qe6SzOgM/fewK8Qusqvop3tumZYb1OmUZ3CgaaTE15vdIUaf/nsyYtA1FhiPGV/U YQy1UTWXdQA2wt++NQZfMTdEMdmBItLvn+FAGrDmZpojr50i2xvPqQ4ZlTzhRzMA4NgWg+La/tm6rj rrsKc6k4YwSUes7KJWCF2R81GXMgfp2I13qsOUoqTmeeoWTkj9NQDzd+tbrjQ3C4gdqQUywUnDjZth U2HhrYciP9QXml569OiVFVdJqdk5r06EornXt5+0ffDu464SSxJdveFq11X9OGsM93M1T0Ct0tTfTD jCaFKZm4SdH8BPjWDdZd8WV1oscg2YS+C0ZlJ1IIHmRbDOeyPpsZyHgSzry1ErZrI++9xrESX6Rnk9 WFfS6UoZwKN6RXQFCh8dszPl/D23nHXp0TcN9D352o4kt4QnP8NrMRHB2c4akAbPZVmrBJrWhTFS7A IFJforSkglRfDq1Q4pY+zYhYCHA0IcvyOXU8zHLrw3SiT79IM/ELZb5Vif026dvQAFGc2H2zhqtJsA IPMHAhfLn32+WmGmgb3y8FYwiPnuNtRPq3hPthUqpNGpteOifZBwly3+o0FnPEoLYzAIRHq5tDL10c Sq+p7wxTwnoc9TVGptRmQKHqr92CO9QKe0gKg2UpDHcOAlTJ5znFcTS2wcxQ==
X-Developer-Key: i=keescook@chromium.org; a=openpgp; fpr=A5C3F68F229DD60F723E6E138972F4DFDC6DC026
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b="g/cPhiEF";       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42f
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
Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>
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
index 799c5edd6be6..bc62bfe75bc7 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221117234328.594699-3-keescook%40chromium.org.
