Return-Path: <kasan-dev+bncBCF5XGNWYQBRBJFD2LXAKGQEOVAZ6VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id A64E91030F3
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:06:46 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id 2sf18113816pfv.21
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 17:06:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574212005; cv=pass;
        d=google.com; s=arc-20160816;
        b=QFJwjxY48twgJWt/Ve0FuMz201orwOhgAvDIq0Km0/bi8BXS3xvc2ewHPppxsAjjpR
         hNVj+EQjcJZ+9QU2i8KtF+dypn4vAxFszoiysXuwxy4huy2YgSamaMArhEUuW4UfG8Oa
         B+apg/OlFMf9jL9I23/IEXnGxPsbIpBna2na7WjHQRMtkr2W7oSPZkGXldbt09IC27Wl
         gaP7Ga/uD91tGpi3P+1OAxYamI+/G1CPADQt5KCVJ/JbiP5tVL4CPLR5+k0OBSvk0DLn
         SYFijwhZoMbMjUB5jZXBF9fYfFFj0f7K/VTTJgXKRqsM9ImZiOeMpDda1yW7hksBla4m
         43jA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=4Euss3ZVP/19yt6uv9VCJ5HIkpYd7jR+EXq+KZhtAxE=;
        b=T9dkrs0SfK3/XSp/Eyu4lDY3awrXaaCH4Gdo5V0e/z7+t9M2Ay/Lge4sNnQ9VRUiqM
         YOtxA3Sa+dOiJ52GsC8930BlZlfIo1UlHCjpc9ScVQyM7X0rltXNZoR3E9DKSoNROMfO
         uU7IwHRO6vakmZPn8bwYsuXvpyRrKafBl9lB/7T1CQaLjcECNI6Fsm32gYweoQIZitCH
         9E3JAhDt1euyOlWazUM8jXlzQPtUXjauj6D7yhvz5JiMgbDWgYN8zVgIDq+ZWji2Scbq
         oHHbxduSPr0vt4zFGt3pCbFMp0nw2YUuY7pT9EvaZNM8VwVUQq/h9L8VTeMPeSNJb+gJ
         wMkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=a82EApFV;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Euss3ZVP/19yt6uv9VCJ5HIkpYd7jR+EXq+KZhtAxE=;
        b=V/uiiok1qOaEdN2qfRqaGtxwzGd1dInei4Iz2TThjHEbaleyzX4G7PGJM0OfsDsFDU
         SHuNtieaM2xtXCkohrMOJUBei0WwRvA9rrAjZ5tsxdDRLCGU8tXLYCrtnd7bljMxtCPG
         FlLPF/+gbATNTWe2IpuXWEqqqm38FwGqu8AF8yPNwCKE5sjoYMylim/1fXk7kJ8rNhNX
         C5De4beCrLTLe1PeduaG0aCNfTViJ/HImQZyPBcOWTeDKKC8UMHkpIK30/s+pw0iZE/W
         fNieLbOu3YFxZJBD4HCLToEtQm9OQlULqQISpvxKtsM7Vuhwu3ilOg+t2WrgVb+84XJR
         HDTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4Euss3ZVP/19yt6uv9VCJ5HIkpYd7jR+EXq+KZhtAxE=;
        b=I9xnkkL/ly1l7e1A9rVpkXbMdxDoazkfNgb4cBh0C+X5vhtX5C1b1fJ7VCjj34x9xw
         +uM84hGaLj/zvPgd0+gnIVJwuuNSor7d7lnTP3uqCgYnZb9TY2cXaJ6l9xMnTzwRJwQZ
         hUDW50JyW5DNwbEe0VAP1YqXIkN+8GniwxtR3q06Ut06p6H+gpZr6pPhiwMi1kA5VUOQ
         FIrKiWj9DvALailux4Qmqx6wYKCyBxCqc9LT3iIPLsgpXSCPj/H05c7VmTjAn84AjK6C
         9p6R9LwBRDBYd00PRj3swZBvRgBHZbd87HVAjuY7o/5MerfKd/JxBcknZ5zGrxiHIPrc
         kCUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXvz+klIuugvBgo+/SPbwZuih9+XinuzKTTxbja2ViH0WYok0pz
	J1VYthdG1bNf699zxDa/eYM=
X-Google-Smtp-Source: APXvYqzw5kdIfV6sQ6iXgkcGvRwY+vHUPZ8xKzNA3HDFNnl9mRIMNIgiJ7h+JTolW5O8h3ZlyjvdpQ==
X-Received: by 2002:a63:9a12:: with SMTP id o18mr55094pge.379.1574212004639;
        Tue, 19 Nov 2019 17:06:44 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1581:: with SMTP id 123ls56275pfv.11.gmail; Tue, 19 Nov
 2019 17:06:44 -0800 (PST)
X-Received: by 2002:a63:f30c:: with SMTP id l12mr92472pgh.354.1574212004175;
        Tue, 19 Nov 2019 17:06:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574212004; cv=none;
        d=google.com; s=arc-20160816;
        b=hz5gKFuuF+JsdS2ZBwN4QMCTmUHbVID5s93SVA2aELAPv1B0Z9TTMD6Ij5a/iKzjbe
         u+DgeCUhG6dISVjjqwSaq976xjMh2udTvo3FA1hnP1QkAhiiDWsrS21SrFfhefpgy19y
         OVQatKdZyoMc7zQ48DQtbT6XvDXD+S6jfrY564sgUcnebjkdfTxwWCe0LZM4WFZoc/Gt
         ydwszMIa9nVsPSr1mgEBD201mpWunyLIE0GTxzo5OH4AmRhFPMoRvcXb61xT2Ms3boeQ
         ULQ0VicxfcAioWMZuu3i4Mcg1VTvKgFzMH3Lafft+q8OchQSOuuNlfPKWcd6YpFlTQo+
         sK3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=0T61AzxnAvwa4rB+CZumfDDidufAJnp+U8GPCQMxTB4=;
        b=bkIkIKfk5S/jISMjVTqdR0WInEzTfZHa5gxsBe9wUSRUoSFeoqPqVAIMqdOYumyFGd
         Am5suAChrPA43kGlteMXiuKqQ0xWDGibPXb+7COxbnCTpNRUAIdDWjMlWQQ244u/pLze
         iP4v6l4a4sYQY+xvBJlfX3h61/oSQVS2b92CO6KIfZYEAuEiMZGgOtsi8fZheaQruY81
         2S2iIjnS14DtYpRvIzMatFckbcrNY16QKLXlAVeFhldrkgjHj07+0iHcEKv9pro8LvnN
         RZ9XfrnDdv1ke8vWvj86/IkvTyBykIl/dKifKkfX1mVUl8Cq+Hdc/i8QY+KLuZcQc2a/
         Rz6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=a82EApFV;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pl1-x644.google.com (mail-pl1-x644.google.com. [2607:f8b0:4864:20::644])
        by gmr-mx.google.com with ESMTPS id g10si919936plp.4.2019.11.19.17.06.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 17:06:44 -0800 (PST)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644 as permitted sender) client-ip=2607:f8b0:4864:20::644;
Received: by mail-pl1-x644.google.com with SMTP id ay6so12959383plb.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 17:06:44 -0800 (PST)
X-Received: by 2002:a17:902:561:: with SMTP id 88mr155318plf.127.1574212003854;
        Tue, 19 Nov 2019 17:06:43 -0800 (PST)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id u24sm24440563pgf.6.2019.11.19.17.06.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 17:06:41 -0800 (PST)
From: Kees Cook <keescook@chromium.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Kees Cook <keescook@chromium.org>,
	Elena Petrova <lenaptr@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ard.biesheuvel@linaro.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH 3/3] lkdtm/bugs: Add arithmetic overflow and array bounds checks
Date: Tue, 19 Nov 2019 17:06:36 -0800
Message-Id: <20191120010636.27368-4-keescook@chromium.org>
X-Mailer: git-send-email 2.17.1
In-Reply-To: <20191120010636.27368-1-keescook@chromium.org>
References: <20191120010636.27368-1-keescook@chromium.org>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=a82EApFV;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::644
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

Adds LKDTM tests for arithmetic overflow (both signed and unsigned),
as well as array bounds checking.

Signed-off-by: Kees Cook <keescook@chromium.org>
---
 drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/core.c  |  3 ++
 drivers/misc/lkdtm/lkdtm.h |  3 ++
 3 files changed, 81 insertions(+)

diff --git a/drivers/misc/lkdtm/bugs.c b/drivers/misc/lkdtm/bugs.c
index 7284a22b1a09..8b4ef30f53c6 100644
--- a/drivers/misc/lkdtm/bugs.c
+++ b/drivers/misc/lkdtm/bugs.c
@@ -11,6 +11,7 @@
 #include <linux/sched/signal.h>
 #include <linux/sched/task_stack.h>
 #include <linux/uaccess.h>
+#include <linux/slab.h>
 
 struct lkdtm_list {
 	struct list_head node;
@@ -171,6 +172,80 @@ void lkdtm_HUNG_TASK(void)
 	schedule();
 }
 
+volatile unsigned int huge = INT_MAX - 2;
+volatile unsigned int ignored;
+
+void lkdtm_OVERFLOW_SIGNED(void)
+{
+	int value;
+
+	value = huge;
+	pr_info("Normal signed addition ...\n");
+	value += 1;
+	ignored = value;
+
+	pr_info("Overflowing signed addition ...\n");
+	value += 4;
+	ignored = value;
+}
+
+
+void lkdtm_OVERFLOW_UNSIGNED(void)
+{
+	unsigned int value;
+
+	value = huge;
+	pr_info("Normal unsigned addition ...\n");
+	value += 1;
+	ignored = value;
+
+	pr_info("Overflowing unsigned addition ...\n");
+	value += 4;
+	ignored = value;
+}
+
+/* Intentially using old-style flex array definition of 1 byte. */
+struct array_bounds_flex_array {
+	int one;
+	int two;
+	char data[1];
+};
+
+struct array_bounds {
+	int one;
+	int two;
+	char data[8];
+	int three;
+};
+
+void lkdtm_ARRAY_BOUNDS(void)
+{
+	struct array_bounds_flex_array *not_checked;
+	struct array_bounds *checked;
+	int i;
+
+	not_checked = kmalloc(sizeof(*not_checked) * 2, GFP_KERNEL);
+	checked = kmalloc(sizeof(*checked) * 2, GFP_KERNEL);
+
+	pr_info("Array access within bounds ...\n");
+	/* For both, touch all bytes in the actual member size. */
+	for (i = 0; i < sizeof(checked->data); i++)
+		checked->data[i] = 'A';
+	/*
+	 * For the uninstrumented flex array member, also touch 1 byte
+	 * beyond to verify it is correctly uninstrumented.
+	 */
+	for (i = 0; i < sizeof(not_checked->data) + 1; i++)
+		not_checked->data[i] = 'A';
+
+	pr_info("Array access beyond bounds ...\n");
+	for (i = 0; i < sizeof(checked->data) + 1; i++)
+		checked->data[i] = 'B';
+
+	kfree(not_checked);
+	kfree(checked);
+}
+
 void lkdtm_CORRUPT_LIST_ADD(void)
 {
 	/*
diff --git a/drivers/misc/lkdtm/core.c b/drivers/misc/lkdtm/core.c
index cbc4c9045a99..25879f7b0768 100644
--- a/drivers/misc/lkdtm/core.c
+++ b/drivers/misc/lkdtm/core.c
@@ -129,6 +129,9 @@ static const struct crashtype crashtypes[] = {
 	CRASHTYPE(HARDLOCKUP),
 	CRASHTYPE(SPINLOCKUP),
 	CRASHTYPE(HUNG_TASK),
+	CRASHTYPE(OVERFLOW_SIGNED),
+	CRASHTYPE(OVERFLOW_UNSIGNED),
+	CRASHTYPE(ARRAY_BOUNDS),
 	CRASHTYPE(EXEC_DATA),
 	CRASHTYPE(EXEC_STACK),
 	CRASHTYPE(EXEC_KMALLOC),
diff --git a/drivers/misc/lkdtm/lkdtm.h b/drivers/misc/lkdtm/lkdtm.h
index ab446e0bde97..2cd0c5031eea 100644
--- a/drivers/misc/lkdtm/lkdtm.h
+++ b/drivers/misc/lkdtm/lkdtm.h
@@ -22,6 +22,9 @@ void lkdtm_SOFTLOCKUP(void);
 void lkdtm_HARDLOCKUP(void);
 void lkdtm_SPINLOCKUP(void);
 void lkdtm_HUNG_TASK(void);
+void lkdtm_OVERFLOW_SIGNED(void);
+void lkdtm_OVERFLOW_UNSIGNED(void);
+void lkdtm_ARRAY_BOUNDS(void);
 void lkdtm_CORRUPT_LIST_ADD(void);
 void lkdtm_CORRUPT_LIST_DEL(void);
 void lkdtm_CORRUPT_USER_DS(void);
-- 
2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120010636.27368-4-keescook%40chromium.org.
