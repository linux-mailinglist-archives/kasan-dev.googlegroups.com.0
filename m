Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBXFHS6AAMGQEZKKIZWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DD192FA8D8
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 19:30:53 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id i143sf7966765ioa.6
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jan 2021 10:30:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610994652; cv=pass;
        d=google.com; s=arc-20160816;
        b=tvc0BJo0L3aBxpbFPMfI87H4KMVbpUuftxLIefPcBACvlW406Ulv/g3/wDhARjAVEF
         ZcBEqaDJ68ZvZHZS+SSar4GdD7ZEEUJcJYsN0s7m7SKrftar/i6s4C8VIhDERMS+GUcH
         WnHm/RdBlR4wNfeV4T7lA/aszhzYxec5w1qOS2uuKK0mvffpM16/mCX61znfYt6rqmLf
         Z/OwpyqaLPQcszhnBYGx67F7C/XFAbgxIFG7pcIFg/VYtl3h28+1xTYViSMO5py+OYqp
         h0cv9skB7PWLqkwz8tnXMSNhxKA9ACWgwOswbFyrSM7Gaf+NDmvtQwj6pPWJN0nCsrva
         sMhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MEBIr5FvYFqDg3/qSqFqha5KMQn8Ff0lo5SVi/KcQsw=;
        b=LdAboAMIbVz9P52WRs7kzgqfynsCh60FRTpmopeDo8RF+APUOYiLor1vU7PG/OdvGq
         i7GAeT4PmC5fDFLTJL2Az165L1qNszmGYYiGBIastRrw5UOVm+rzXgtbt9NTfVmvD1Nq
         6JoxMmhvloiBu39Mng6equ0OM3ODLzH2T1czLjTeSxL+1d59RbD4zv4w3rtGjLFLFO5r
         KS3H5DI7neIyf1Mo0wdwGD7CVPIfnDhcZSGIWMnHexmexVozr8saGiUnVh4XxEtrYXv+
         AVpSe1+zeDh0rxG8bDM0VbiJ1G4Bh7L7PIbVYmP/EtQGTNbilhXkyqKJlshRBRWX9pPE
         0IHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MEBIr5FvYFqDg3/qSqFqha5KMQn8Ff0lo5SVi/KcQsw=;
        b=aanXjaLrntNRY/M1VXr7Vc6+EULB1Cv74fvEERSQRZKerEs7O3A5ckOKXbTh5C+hHM
         j2rQRJ52e10u6sKpycpv53AhG1Xjpf0iJ5E4DFg2bdNYn6SkmGFzhYOtjE0CfgFegrBu
         SIdJmb1VRZIVpDMw/PFS8r6/95dQpPXFwMg91e/yHv5liiqBtvKA+xAKG2Vn2UoOS3OY
         7Vh+QmcD1eTjzV1a19BSH0A5DEOY8t6rqSUA6j8+u+IbQqSl1flx7+JKjqGZbalkmjWN
         0CDPZtWHJT0NvfSvRSj76zsijSFEB3b4MquzgE6zA/ZModyJ9Ub5JoxHMfTtQhAZClEF
         kFfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MEBIr5FvYFqDg3/qSqFqha5KMQn8Ff0lo5SVi/KcQsw=;
        b=LBoBucFdKyOL7wqJqG0l/308Z8XBBCZ9v9MDMpXGrJaKduD4rU11rpKq9VRjAJeJPs
         rmbGn/2mB0p2tAVkRW7iosZQhyWGI01ro52CkRmEf8cMK5h/1HZWIK6k0pz3+JSg8ki3
         Ft8ptWrxq2IEE/Ed0ecZL/HHG0jqgfH3GcBFAsUxw3BUGnqEyR/QxVms5rU82WeXuYxO
         urFYH3xVpjLa1pci2mNHA3Rm7zH8gwSuhY9+zdGDJiQy5UTbIamjuthsRvgPWKUJgPF2
         /4X76r6mt5Kvj9hEnzeQafZ2A23RtEGlcuuVgSNK2NM8LLGZRpab88r6Etdf6nF8zeK7
         pZdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533n8ej7LlAGCMtCOmzcfaNnG5+VvAGcUP7Bp7z6IJ5woMWeCYq3
	1OIsDBGCgwwdkDxJtiGbb/o=
X-Google-Smtp-Source: ABdhPJxBnCotlgQ6ML6iXsotpyKHsvvdhJTN/cbSkD5hQbvQ8pWOSKrTMXKWgIg/hDBwWFXGDP+jtg==
X-Received: by 2002:a92:b011:: with SMTP id x17mr426267ilh.179.1610994652403;
        Mon, 18 Jan 2021 10:30:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:13c4:: with SMTP id v4ls1136105ilj.1.gmail; Mon, 18
 Jan 2021 10:30:52 -0800 (PST)
X-Received: by 2002:a05:6e02:1c05:: with SMTP id l5mr489884ilh.6.1610994652099;
        Mon, 18 Jan 2021 10:30:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610994652; cv=none;
        d=google.com; s=arc-20160816;
        b=08JI+prcEotZM3HpP+NB6OMC5+g1XbVmxh/+MoVsIWDm3ot3+L9a6NE+cwYbAch5gf
         AoVdYHpa7G0Rai3OOvmaJwiXoFOp+ZEg8s6IpjR1J+MeC+C4ArH9YOK71M6Pm2cDBjUX
         ze2yk7iHFgxdo1e98lN76F0H0olg2uYTIGoTRnzJyYPwyG2iF3X4NeUXCInQ3TruHaBU
         QFIC+kzOLbX6C+Ys4IGr7HYvmVIDlgspdHRQMlHCjTeF9FoORK032v9C/zaVcUUlH/rF
         Sm3ppdjnWA+cM+99YA+v4FuBOTEoXitBUVDx3YgsqS9XhBc5fUB9BwDCjaiPIegeVKL9
         xA/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=BMCNPqROnAHx5YcL7iDUDZ0Ua3ztXxHK9fhbpHgHQFo=;
        b=Tl2qUp9QMESDs8F0OW8P3r1zEzGjBTaIA09PgXWzWRLNTxE2gU3ElY1p3S7/6zFODw
         npSMwH0YVf8YpAspCezHUfA5cUgqQbZip+4PSJq9ze0mt1Knm79Fb19IBMoAYJ1CWnET
         uV0PJwGvRDsqwMUbAzif/4OGc7fuJaeM/kpZweHxxqM27EJgb6bQ/duoNV4y913iL4Hc
         tK2oCQ95+fBtyKalwoyuWPJ9p6MCBBUlrbVqBVSxwsB3fcR7aK3LTj5FCwzQatN5gFBq
         krtsHGYeFbj4fJXV9I5aiupuL02Gq3hqQXaVA7TGcasLTMAUe6nEIWbEw5WjaLY8VyzS
         t20A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id k6si491733ioq.1.2021.01.18.10.30.52
        for <kasan-dev@googlegroups.com>;
        Mon, 18 Jan 2021 10:30:52 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D3F77ED1;
	Mon, 18 Jan 2021 10:30:51 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 3555E3F719;
	Mon, 18 Jan 2021 10:30:50 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 2/5] kasan: Add KASAN mode kernel parameter
Date: Mon, 18 Jan 2021 18:30:30 +0000
Message-Id: <20210118183033.41764-3-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210118183033.41764-1-vincenzo.frascino@arm.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Architectures supported by KASAN HW can provide a sync or async mode of
execution. On an MTE enabled arm64 hw for example this can be identified
with the synchronous or asynchronous tagging mode of execution.
In synchronous mode, an exception is triggered if a tag check fault occurs.
In asynchronous mode, if a tag check fault occurs, the TFSR_EL1 register is
updated asynchronously. The kernel checks the corresponding bits
periodically.

KASAN requires a specific kernel command line parameter to make use of this
hw features.

Add KASAN HW execution mode kernel command line parameter.

Note: This patch adds the kasan.mode kernel parameter and the
sync/async kernel command line options to enable the described features.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 Documentation/dev-tools/kasan.rst |  3 +++
 mm/kasan/hw_tags.c                | 31 ++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h                  |  3 ++-
 3 files changed, 35 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 1651d961f06a..60ad73c2a33c 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -162,6 +162,9 @@ particular KASAN features.
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
+- ``kasan.mode=sync`` or ``=async`` controls whether KASAN is configured in
+  synchronous or asynchronous mode of execution (default: ``sync``).
+
 - ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
   traces collection (default: ``on`` for ``CONFIG_DEBUG_KERNEL=y``, otherwise
   ``off``).
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index e529428e7a11..344aeec05d43 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -25,6 +25,11 @@ enum kasan_arg {
 	KASAN_ARG_ON,
 };
 
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_SYNC,
+	KASAN_ARG_MODE_ASYNC,
+};
+
 enum kasan_arg_stacktrace {
 	KASAN_ARG_STACKTRACE_DEFAULT,
 	KASAN_ARG_STACKTRACE_OFF,
@@ -38,6 +43,7 @@ enum kasan_arg_fault {
 };
 
 static enum kasan_arg kasan_arg __ro_after_init;
+static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
 static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
 static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
 
@@ -68,6 +74,21 @@ static int __init early_kasan_flag(char *arg)
 }
 early_param("kasan", early_kasan_flag);
 
+/* kasan.mode=sync/async */
+static int __init early_kasan_mode(char *arg)
+{
+	/* If arg is not set the default mode is sync */
+	if ((!arg) || !strcmp(arg, "sync"))
+		kasan_arg_mode = KASAN_ARG_MODE_SYNC;
+	else if (!strcmp(arg, "async"))
+		kasan_arg_mode = KASAN_ARG_MODE_ASYNC;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.mode", early_kasan_mode);
+
 /* kasan.stacktrace=off/on */
 static int __init early_kasan_flag_stacktrace(char *arg)
 {
@@ -102,6 +123,14 @@ static int __init early_kasan_fault(char *arg)
 }
 early_param("kasan.fault", early_kasan_fault);
 
+static inline void hw_enable_tagging_mode(void)
+{
+	if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
+		hw_enable_tagging_async();
+	else
+		hw_enable_tagging_sync();
+}
+
 /* kasan_init_hw_tags_cpu() is called for each CPU. */
 void kasan_init_hw_tags_cpu(void)
 {
@@ -115,7 +144,7 @@ void kasan_init_hw_tags_cpu(void)
 		return;
 
 	hw_init_tags(KASAN_TAG_MAX);
-	hw_enable_tagging();
+	hw_enable_tagging_mode();
 }
 
 /* kasan_init_hw_tags() is called once on boot CPU. */
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index cc4d9e1d49b1..7db7bd42fe97 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -284,7 +284,8 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #define arch_set_mem_tag_range(addr, size, tag) ((void *)(addr))
 #endif
 
-#define hw_enable_tagging()			arch_enable_tagging()
+#define hw_enable_tagging_sync()		arch_enable_tagging_sync()
+#define hw_enable_tagging_async()		arch_enable_tagging_async()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210118183033.41764-3-vincenzo.frascino%40arm.com.
