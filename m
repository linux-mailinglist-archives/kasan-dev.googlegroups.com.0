Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDW7U2FAMGQEDN5N34I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id A077D413149
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 12:10:24 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id b11-20020a17090aa58b00b0019c8bfd57b8sf10036453pjq.1
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Sep 2021 03:10:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632219023; cv=pass;
        d=google.com; s=arc-20160816;
        b=zNfKYXhLT8j0TTw8E1/vETPEUNeAzWIz05Xg72QbCP54tH6pW8Y+5aTT4OcMJupa/L
         ocJe32eFBA4njJrp5+37/v4s6Wicn66C4RQF6j4Dhn3ZLPWOaD/GBTkAYWwhAW4CXTxh
         ZhPZnO4/OANYyqJLTrRLmkigRde8l/qvJuPTECF1ifaXKpLqOrhFM8CHEE4tAYlzjnn9
         haUPVM2Z1+xvvLUdmIxF+QFHq6x/lz8OgaNH8mZfwupuH823WWjZE0YP5LSLNT3Auiwm
         zz3SdOUzeeAz8gajsvkoVKgeniuehRdhDyc3Q25RaAmrRyGVISlEmGh2lJuf8ZjtjTUk
         OK0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=QgECd5XUPfzRUZtYXU4Ah7JXC0jLnDctZ40WdKwk0Pk=;
        b=fFyq+UH9Igb4CBZB3K3Bkrf3cp3rDcZ2U8+XyEOG3o4ZplEomEbFTPWNvKQsSSUSJQ
         XD1gYvT+qXIQf6LRs+8hg+b6O+oTkB2XkG8R+FXbfbo3GIFkseDxqbO/UWO0IX4wEx5b
         V3cAVlCkhy/HlOPKfCy28mjn0RmALbMFUFzYfuvaL2nShilGZAD0jHVbQD5EJUAJ8U2E
         0wtZlEnnnDORAIGx+Ik9B9qH256vcHqsYXX59WoTb5VYt4/rR8DVl2qfkhhf7jMDVFFO
         yH8axbDASiHieS+nalXK6EGhW4jur2ucrG7lJEaKrn/HwCOSSXrUeTnQUDxVhqrqkkKh
         x7DA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=re1MeyZD;
       spf=pass (google.com: domain of 3ja9jyqukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ja9JYQUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=QgECd5XUPfzRUZtYXU4Ah7JXC0jLnDctZ40WdKwk0Pk=;
        b=BUYboP/VSicbtiQ5roAYtT0l3zJ6LzNz5lU5BvEyzV+wpvm4UXNPO906UYxMMSb7Bn
         LYuX+Q0DE4bw6tn3Zr9vaBB30T4CQDKCGjkbsUXx90jmtCUODqVyeDUyIplNiDKzCgB8
         gbQVtgshYf843s9inszT7wuoynEzbext+ahQkoBYiUZNLdwyu9aWgwH3oo+sceDl1JaN
         nTDqzZGleDndvyCX7DnywtCj1huY1vK2aKQ9iV8ZtmSRdxwVw4RAQGJe44lXbrqSQusb
         0dOllTMuZHzRnWswEx6hmltmiuv9cuHJ+9uLaiUcEHX/Ug4XmCgxodnT1sMbDc5YYXNB
         aR9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QgECd5XUPfzRUZtYXU4Ah7JXC0jLnDctZ40WdKwk0Pk=;
        b=qVZYgh+qd2j4deKVENOIu5X5dMRhMdVVawEli3lDE6xG0U6EkzG+bawGp8vz8dVmXP
         2qMuvJqx1iFjDaG9H/XVIATphhGs+/sRyTajf2STBuRmwev7qZ/1hDzOmobYo6EF+XJL
         3AGIgDdd/OHakxGpBo9cgLKefmdgsHxnEnlP7r9lqnOL0efxQ3baZyB+xkPEMI35Q9f+
         7gaUPvFyMi4T17YlX84Xvmkn0lBYxoZqsJgNGcPt0IBxawoegf2on4JFmfn5j+L3SYW8
         bn8pTksfsr+LRBks2e6k9eYa4UJ9EfIo1dzE0CLtx6ninvgZqrAn/rquGcV9eqcEGJJg
         5iPA==
X-Gm-Message-State: AOAM532ZsMqDZAfqeXkIunmFweJMsLXzi+yiN6ubzybKGbzKA3JKpVin
	Mr51d0lBMAARbDclOrmxnXY=
X-Google-Smtp-Source: ABdhPJxPF6M/pwNTUKEz020VicGNnAG/5Rld5cFxH7sJ2mZSuxK4IPzfSt2Co3GUIclMBxwEWbiR4Q==
X-Received: by 2002:a17:902:e88d:b0:13b:67d5:2c34 with SMTP id w13-20020a170902e88d00b0013b67d52c34mr26770357plg.66.1632219022903;
        Tue, 21 Sep 2021 03:10:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac9:: with SMTP id r9ls1508314pje.1.gmail; Tue, 21
 Sep 2021 03:10:22 -0700 (PDT)
X-Received: by 2002:a17:90a:428f:: with SMTP id p15mr4428062pjg.75.1632219022192;
        Tue, 21 Sep 2021 03:10:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632219022; cv=none;
        d=google.com; s=arc-20160816;
        b=nnyoDBnmuoqWo38q8yLVOm9UgFA3zI1bQuedns0dt/AWEf67W//d6yDGUYFH9tQDOS
         FY4E/yODN2wuIuaQld5vq3L7LiYD8hUcPYyFHO6YvE6EvGcEJDQZ+fwwoa00+zZm3K/d
         nAwaJHTEu0kmtNKwQiky+Xxb6rdWW3WC1h7wYs1i73BFKvhxNP85018B5H17o79c8K3d
         Ek+2v+LyTOpOlrvjXiVDjDdqsA4+LigC/gslP72hW1ccH8z5IuDccqlIGs35ptmwczHd
         YZbV63j+jaVEvmPd5mDsr1Z7WZ5i5K+Oj0zJGXfeUtfrtW41xvoLUV+t9zdmZXH8Bw13
         kxpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=5N9Nfc2PvxnVX00ioD06NDULEqZan2ouEAVATALDM/U=;
        b=ZnfAQPFsVWxLr47JcekiZsLDnAeWFkS+HNpsrSO+uoHqpcQETr2RzlxCzIGbQErQ2O
         XcWueuu4c9IrTykGw8Y5NL2y61OMTy/cfrPO2iPioUWnYwZLZXafH9p8rsrDlvCBti99
         Yd7ayIYcsSnOyMVXE5VIhLkCOVN7fGS4jbvCFyUQsnipWT8rHy+j2oJD4xLeh12RWkFc
         hLJ3BTeKe7G5OQw/KxBnSDhcdRiPDRax8N7V018Eg1/zpoAca4v1t8WTVXrt8ryKhDBR
         7m9HhBCWOghob55o/ymtHdH4A0suwAW61bKroAz07ZKxI50i5VhfseSNdwFbmU3Uz8ax
         AyFA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=re1MeyZD;
       spf=pass (google.com: domain of 3ja9jyqukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ja9JYQUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id y2si232468pjp.2.2021.09.21.03.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Sep 2021 03:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ja9jyqukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id w10-20020ac87e8a000000b002a68361412bso122581865qtj.7
        for <kasan-dev@googlegroups.com>; Tue, 21 Sep 2021 03:10:22 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:dd03:c280:4625:60db])
 (user=elver job=sendgmr) by 2002:a05:6214:490:: with SMTP id
 ay16mr30085392qvb.25.1632219021369; Tue, 21 Sep 2021 03:10:21 -0700 (PDT)
Date: Tue, 21 Sep 2021 12:10:10 +0200
Message-Id: <20210921101014.1938382-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH v2 1/5] stacktrace: move filter_irq_stacks() to kernel/stacktrace.c
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=re1MeyZD;       spf=pass
 (google.com: domain of 3ja9jyqukcsqelvergoogle.comkasan-devgooglegroups.com@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ja9JYQUKCSQELVERGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--elver.bounces.google.com;
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

filter_irq_stacks() has little to do with the stackdepot implementation,
except that it is usually used by users (such as KASAN) of stackdepot to
reduce the stack trace.

However, filter_irq_stacks() itself is not useful without a stack trace
as obtained by stack_trace_save() and friends.

Therefore, move filter_irq_stacks() to kernel/stacktrace.c, so that new
users of filter_irq_stacks() do not have to start depending on
STACKDEPOT only for filter_irq_stacks().

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* New patch.
---
 include/linux/stackdepot.h |  2 --
 include/linux/stacktrace.h |  1 +
 kernel/stacktrace.c        | 30 ++++++++++++++++++++++++++++++
 lib/stackdepot.c           | 24 ------------------------
 4 files changed, 31 insertions(+), 26 deletions(-)

diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
index 6bb4bc1a5f54..22919a94ca19 100644
--- a/include/linux/stackdepot.h
+++ b/include/linux/stackdepot.h
@@ -19,8 +19,6 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 unsigned int stack_depot_fetch(depot_stack_handle_t handle,
 			       unsigned long **entries);
 
-unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries);
-
 #ifdef CONFIG_STACKDEPOT
 int stack_depot_init(void);
 #else
diff --git a/include/linux/stacktrace.h b/include/linux/stacktrace.h
index 9edecb494e9e..bef158815e83 100644
--- a/include/linux/stacktrace.h
+++ b/include/linux/stacktrace.h
@@ -21,6 +21,7 @@ unsigned int stack_trace_save_tsk(struct task_struct *task,
 unsigned int stack_trace_save_regs(struct pt_regs *regs, unsigned long *store,
 				   unsigned int size, unsigned int skipnr);
 unsigned int stack_trace_save_user(unsigned long *store, unsigned int size);
+unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries);
 
 /* Internal interfaces. Do not use in generic code */
 #ifdef CONFIG_ARCH_STACKWALK
diff --git a/kernel/stacktrace.c b/kernel/stacktrace.c
index 9f8117c7cfdd..9c625257023d 100644
--- a/kernel/stacktrace.c
+++ b/kernel/stacktrace.c
@@ -13,6 +13,7 @@
 #include <linux/export.h>
 #include <linux/kallsyms.h>
 #include <linux/stacktrace.h>
+#include <linux/interrupt.h>
 
 /**
  * stack_trace_print - Print the entries in the stack trace
@@ -373,3 +374,32 @@ unsigned int stack_trace_save_user(unsigned long *store, unsigned int size)
 #endif /* CONFIG_USER_STACKTRACE_SUPPORT */
 
 #endif /* !CONFIG_ARCH_STACKWALK */
+
+static inline bool in_irqentry_text(unsigned long ptr)
+{
+	return (ptr >= (unsigned long)&__irqentry_text_start &&
+		ptr < (unsigned long)&__irqentry_text_end) ||
+		(ptr >= (unsigned long)&__softirqentry_text_start &&
+		 ptr < (unsigned long)&__softirqentry_text_end);
+}
+
+/**
+ * filter_irq_stacks - Find first IRQ stack entry in trace
+ * @entries:	Pointer to stack trace array
+ * @nr_entries:	Number of entries in the storage array
+ *
+ * Return: Number of trace entries until IRQ stack starts.
+ */
+unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries)
+{
+	unsigned int i;
+
+	for (i = 0; i < nr_entries; i++) {
+		if (in_irqentry_text(entries[i])) {
+			/* Include the irqentry function into the stack. */
+			return i + 1;
+		}
+	}
+	return nr_entries;
+}
+EXPORT_SYMBOL_GPL(filter_irq_stacks);
diff --git a/lib/stackdepot.c b/lib/stackdepot.c
index 0a2e417f83cb..e90f0f19e77f 100644
--- a/lib/stackdepot.c
+++ b/lib/stackdepot.c
@@ -20,7 +20,6 @@
  */
 
 #include <linux/gfp.h>
-#include <linux/interrupt.h>
 #include <linux/jhash.h>
 #include <linux/kernel.h>
 #include <linux/mm.h>
@@ -341,26 +340,3 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
 	return retval;
 }
 EXPORT_SYMBOL_GPL(stack_depot_save);
-
-static inline int in_irqentry_text(unsigned long ptr)
-{
-	return (ptr >= (unsigned long)&__irqentry_text_start &&
-		ptr < (unsigned long)&__irqentry_text_end) ||
-		(ptr >= (unsigned long)&__softirqentry_text_start &&
-		 ptr < (unsigned long)&__softirqentry_text_end);
-}
-
-unsigned int filter_irq_stacks(unsigned long *entries,
-					     unsigned int nr_entries)
-{
-	unsigned int i;
-
-	for (i = 0; i < nr_entries; i++) {
-		if (in_irqentry_text(entries[i])) {
-			/* Include the irqentry function into the stack. */
-			return i + 1;
-		}
-	}
-	return nr_entries;
-}
-EXPORT_SYMBOL_GPL(filter_irq_stacks);
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210921101014.1938382-1-elver%40google.com.
