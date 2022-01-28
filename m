Return-Path: <kasan-dev+bncBC7OBJGL2MHBB35OZ6HQMGQEW3IYKOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8620349F89B
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:45:52 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id w5-20020a1cf605000000b0034b8cb1f55esf5792669wmc.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:45:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370352; cv=pass;
        d=google.com; s=arc-20160816;
        b=G3UDugwLN7RU/xo3Hx8z5j6Hj4c1VwAZHkDdWND7mZzBFcesdEurNOUwjJCKGzx427
         zasCuXU53WIUFgNHV+XQnK3jSZUtyTX34ARKOeFBwXCtrTdM/mZeKSHodwDrtdQ49VV1
         aiTwQeNcpw5YiB4atZD9EBFV1xEB07/ScoUynuQtJinlrNZ39hfuZiC9i7/zIaXXPuom
         ambCiyToTrHEr+NCUaboKwAEbfPKFPS2OoDqI2pWe1WCfbcAprm5ADtR3eCX80XmytPg
         XF0cArWf9nbvQiufEgd/KaPFI0CZ+cvs6js8ehrlD5GqTFrps/rifxm+oIMl/vn9FX66
         +WuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=YOdharzBPXgfbMRmnSE7F836uEv9fj1/1B3iDa+/vRI=;
        b=kd2NY4mTm+PvX7K++jtbLaFBX1CUgNX+JoplHxpu41uWReLZdOmFg529njmmMSZLIq
         IYLxYTJaUQIYxjDb/ExltHt6lPC/b27+P97XOe3dsNEPExfxYmtvu9Nsz9gMwLynF6DH
         aovkqvWeP35AmL78ElJJnKaUaA4HMWVKbg4zlP0vVvtjFkXnP2hao9kpJMJmm6mO7VE2
         iivFlNC+dZuF0uf1PVQgPD6ewClggQ7XTqwrNwsi/3WsoVJ6wuPJTIAwCUrTSBMrZJse
         YtB1FBwM5XrX2ty5LR48H6lcVhR3KXxOsoWRGEDEaGAoKavOuOgwYnk7czH3EMbC5758
         rZdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dDfyhR5A;
       spf=pass (google.com: domain of 3btfzyqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3btfzYQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YOdharzBPXgfbMRmnSE7F836uEv9fj1/1B3iDa+/vRI=;
        b=hwoPwGT1lnxIuVwOUp2rO20sSN5dK9eBbhONuz8898ibzOaLAYDbCTiMtXCJUS5dRn
         SQqCqVAi8w5iqryrCPrQEmTk6uSkjR/3vWtBlUcxUDa1AdBxjhaj7Nvh/Xhv1ANxSgga
         O6OX8mgp8SpzGNez+hk/UhxSdD0FZ+W+cuw8Am/3YaoykOOzAKFlaD5wRdWgewxiEBu1
         qC+ZrkuAL8Teh6XURpHTBPzL3srgi35DHpgoSDw3DS0LyqoZgbIp+pnFShjXXDdsy6ka
         hph5rlBQRWuR8RkQeaSHuGMU+JsLRBS7HgR0bgjB/6c9Ln0TdHCUIe7TYDwWcNunAzco
         e7Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YOdharzBPXgfbMRmnSE7F836uEv9fj1/1B3iDa+/vRI=;
        b=C8I+Ni/y/C/orPOC9dxi1ckwEJnQNy2lxkPDsH6vbG5ZXnZs6w1oRnjrzehDe3CRex
         CwB6bWgMLZg2w3N8upouGtdhy3EOAmT1qLya6Qom0/57v+/T4kOyw9dbMpL5qTpUF/ZW
         fr5/BB4JcBjiHp3JN9KRwpF/oMpvQuU7KCQrrCEg3lHSopKyz6Bmt7w26MAWgrg4k0Te
         gElyJcMUnuruHmF8OCXXqm59o7sZ/w07E1KAV/5KNn2cKjWhVVaU96WTkZjnE0gjJNK7
         jf6z9/19nWP0vpJcIQ9h4F3XWR34F9SuM8Zv7hwlcDnhaMy+FdiXUHj1tUkUmsHeZC6Q
         fJVQ==
X-Gm-Message-State: AOAM533fIiae9o8wVkXAwUD2roLbXsG90/W0FUcxYF8PZH9wWeJVcxjo
	BResumaThTJDIoFCNg65968=
X-Google-Smtp-Source: ABdhPJx3oh0YIIgzQhWOoG631ioZxb+gIoUDLBLnVzZwkq1ub5aHCoNTfdN3e8+jIGS8jK6SLZCPoQ==
X-Received: by 2002:a1c:1d48:: with SMTP id d69mr15710751wmd.167.1643370352204;
        Fri, 28 Jan 2022 03:45:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ec88:: with SMTP id z8ls398349wrn.2.gmail; Fri, 28 Jan
 2022 03:45:51 -0800 (PST)
X-Received: by 2002:a5d:570a:: with SMTP id a10mr6850692wrv.449.1643370351182;
        Fri, 28 Jan 2022 03:45:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370351; cv=none;
        d=google.com; s=arc-20160816;
        b=t4hhXnxN9d7/yRXxdQesQCGEJbmgaR5Iu2SEo8j7rBnfO6MvxovFaW3+/UGAqrsfNt
         gRqaqNn/nzI8OEuV9rAf4UfJQdORfi0jOVa4CeifJiyjt4oEAtFJxLkVmWXIAeOR0/Jn
         EML9OyMvNH3Ou1/xFqVIb0nL318TMLefnWryWjebZcbeB52SpTPLNuX8ol/ZXG5QZ0jT
         IQ3oAI7o8FzDTQGjYbcypswfTbt06LXT19E9jfBDxzBFoBLgxE1qXgdJa62ICkBelWWP
         NFoYDgbo2cPAgoqsVvdw5X1KzSLrbiZMySmqNj+SzVUvtp+dGvNBMqPGbAa9V+SzDEWI
         w5Lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=mcBQonq9lXEu3o2avKFSmCAtNtSrD58c9xOTmXyxJbc=;
        b=qkeSH+ZBW5CKnqLDlRGVlpswCWrp4Id9oWpgWWeHZGGGWrU8UwP7YrNJj7C2DEQG/+
         sG5w0cKGhfcK7PZMRhJshexSGI/p/32j2vCWuqDagB8ZXYaIeVl0abStUZhebbavZWZx
         vm8//lldG/on74CkT4NtI1QGvVYWJgiakVIj7MgoYjX6Dt+r/zgQNV26mVingtUTo4WZ
         u77AXMrrvqf8zyh7Er2NFGfQPzv91+3rs8gFdgeKx411woykJIchxKhKbA98J+DFe6Va
         iWNU/nliHkaxeJQSjBMcBnAX+El+r1qhMiy9yU0xi2hrgnA7dNDzGJdBqBj66CdVzNXJ
         pi0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=dDfyhR5A;
       spf=pass (google.com: domain of 3btfzyqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3btfzYQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id m4si882718wru.6.2022.01.28.03.45.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jan 2022 03:45:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3btfzyqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id c7-20020a1c3507000000b0034a0dfc86aaso3606373wma.6
        for <kasan-dev@googlegroups.com>; Fri, 28 Jan 2022 03:45:51 -0800 (PST)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f088:5245:7f91:d730])
 (user=elver job=sendgmr) by 2002:a1c:f413:: with SMTP id z19mr15683197wma.144.1643370350900;
 Fri, 28 Jan 2022 03:45:50 -0800 (PST)
Date: Fri, 28 Jan 2022 12:44:45 +0100
Message-Id: <20220128114446.740575-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.35.0.rc0.227.g00780c9af4-goog
Subject: [PATCH 1/2] stack: Introduce CONFIG_RANDOMIZE_KSTACK_OFFSET
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Thomas Gleixner <tglx@linutronix.de>, Kees Cook <keescook@chromium.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Elena Reshetova <elena.reshetova@intel.com>, Alexander Potapenko <glider@google.com>, llvm@lists.linux.dev, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=dDfyhR5A;       spf=pass
 (google.com: domain of 3btfzyqukcqmhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3btfzYQUKCQMhoyhujrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

The randomize_kstack_offset feature is unconditionally compiled in when
the architecture supports it.

To add constraints on compiler versions, we require a dedicated Kconfig
variable. Therefore, introduce RANDOMIZE_KSTACK_OFFSET.

Furthermore, this option is now also configurable by EXPERT kernels:
while the feature is supposed to have zero performance overhead when
disabled, due to its use of static branches, there are few cases where
giving a distribution the option to disable the feature entirely makes
sense. For example, in very resource constrained environments, which
would never enable the feature to begin with, in which case the
additional kernel code size increase would be redundant.

Signed-off-by: Marco Elver <elver@google.com>
---
 arch/Kconfig                     | 23 ++++++++++++++++++-----
 include/linux/randomize_kstack.h |  5 +++++
 init/main.c                      |  2 +-
 3 files changed, 24 insertions(+), 6 deletions(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index 678a80713b21..2cde48d9b77c 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -1159,16 +1159,29 @@ config HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	  to the compiler, so it will attempt to add canary checks regardless
 	  of the static branch state.
 
-config RANDOMIZE_KSTACK_OFFSET_DEFAULT
-	bool "Randomize kernel stack offset on syscall entry"
+config RANDOMIZE_KSTACK_OFFSET
+	bool "Support for randomizing kernel stack offset on syscall entry" if EXPERT
+	default y
 	depends on HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
 	help
 	  The kernel stack offset can be randomized (after pt_regs) by
 	  roughly 5 bits of entropy, frustrating memory corruption
 	  attacks that depend on stack address determinism or
-	  cross-syscall address exposures. This feature is controlled
-	  by kernel boot param "randomize_kstack_offset=on/off", and this
-	  config chooses the default boot state.
+	  cross-syscall address exposures.
+
+	  The feature is controlled via the "randomize_kstack_offset=on/off"
+	  kernel boot param, and if turned off has zero overhead due to its use
+	  of static branches (see JUMP_LABEL).
+
+	  If unsure, say Y.
+
+config RANDOMIZE_KSTACK_OFFSET_DEFAULT
+	bool "Default state of kernel stack offset randomization"
+	depends on RANDOMIZE_KSTACK_OFFSET
+	help
+	  Kernel stack offset randomization is controlled by kernel boot param
+	  "randomize_kstack_offset=on/off", and this config chooses the default
+	  boot state.
 
 config ARCH_OPTIONAL_KERNEL_RWX
 	def_bool n
diff --git a/include/linux/randomize_kstack.h b/include/linux/randomize_kstack.h
index bebc911161b6..91f1b990a3c3 100644
--- a/include/linux/randomize_kstack.h
+++ b/include/linux/randomize_kstack.h
@@ -2,6 +2,7 @@
 #ifndef _LINUX_RANDOMIZE_KSTACK_H
 #define _LINUX_RANDOMIZE_KSTACK_H
 
+#ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
 #include <linux/kernel.h>
 #include <linux/jump_label.h>
 #include <linux/percpu-defs.h>
@@ -50,5 +51,9 @@ void *__builtin_alloca(size_t size);
 		raw_cpu_write(kstack_offset, offset);			\
 	}								\
 } while (0)
+#else /* CONFIG_RANDOMIZE_KSTACK_OFFSET */
+#define add_random_kstack_offset()		do { } while (0)
+#define choose_random_kstack_offset(rand)	do { } while (0)
+#endif /* CONFIG_RANDOMIZE_KSTACK_OFFSET */
 
 #endif
diff --git a/init/main.c b/init/main.c
index 65fa2e41a9c0..560f45c27ffe 100644
--- a/init/main.c
+++ b/init/main.c
@@ -853,7 +853,7 @@ static void __init mm_init(void)
 	pti_init();
 }
 
-#ifdef CONFIG_HAVE_ARCH_RANDOMIZE_KSTACK_OFFSET
+#ifdef CONFIG_RANDOMIZE_KSTACK_OFFSET
 DEFINE_STATIC_KEY_MAYBE_RO(CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT,
 			   randomize_kstack_offset);
 DEFINE_PER_CPU(u32, kstack_offset);
-- 
2.35.0.rc0.227.g00780c9af4-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220128114446.740575-1-elver%40google.com.
