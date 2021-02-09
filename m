Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK6NRKAQMGQESTVTFCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id C62A331526E
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 16:13:47 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id x13sf18455006edi.7
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 07:13:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612883627; cv=pass;
        d=google.com; s=arc-20160816;
        b=HsyTaR/eelX8L+yWtAR/ACR4hyTkuFdXFIy93Ol/6kyH05NTBEcAQgEzKx9LxYLxxP
         +qv9W0vJr6yVjDVnxHyDoxBWo++qRj3yXKCK0QYQXL6ohZth5pZb7K34xzfIXOGVWIBm
         RubsrK2Hfqjq2eGw7lQtl1FWBfVsR/uyQo/UJ93uES/NmL5esg5UeEPyNAy2lje5YzWN
         3Jx/L6lbf4PTT5ZpPLRVdG2giqFYAQWF7iTcSp6wcrI9HzZcqsl2kBGf44QUYb6hzKeh
         KfLYaXd0Kb+37bTI0eqBtNEGHRfyX3UtSac2TFW4BgVp12kRZQvmb+4omqdZ4l3SipKE
         IHAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=/ZpFj73B5/IhNS9Ki9mUx2l7cKuCV4X+CruI9sHTIys=;
        b=VM7d6gFteTlGxFTRaSZRVX54F1E0SYbhTo1ud4rwIEIsLh6t8BHYPCwxS9vg304LQt
         YVh270yoR57fn0b1+/uepBqF2/vA5KABJfkBjCgHAMKXCnDzaJZ3x4csSoslWgZwk6rn
         W+1qdeZ6G1y9DvucOYkdlGU0ZTUctJBnFhuvDtDj1kQ1rl9kaZ6sEtNpVpn+Xo69NdRU
         3gvEnRl/wS7by1biEkgRdj1efr+dTM9mhiRLtyTJvY7zxOgza+Ec1YznnmZDxzIf0Pze
         jHKTC29zuwBOsd4AicL/hz7EXhIW5xBVdhrngFrLeGxuf3dmCYPBkf257PxZJopIz7aS
         kpgw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pHK0u1wb;
       spf=pass (google.com: domain of 3qqyiyaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qqYiYAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/ZpFj73B5/IhNS9Ki9mUx2l7cKuCV4X+CruI9sHTIys=;
        b=Z5zkDqk3PvCRo6EH0MWMUrivN5zDOiKYTSyJaj04Nz6LdXAiES6h9S3+j1Ltpga3/9
         gp+UJw2tF5kDIxY5dmNCtfb0hgluybbJWOcSk34/H2J/efFWWqSyqezPJJWxyNlubJ26
         DXeiakoB97nadBrzkU++k7jY/X51svMyRsrtdA6Q16JqvXdoVWawsQGRcEvZHt0ma3A5
         IzpfpBH18VQ4/jiNvAl8kHhjevk7KZBE+vVbalUeaQdA0zB3x9TLUVFNkXZAv2xMg+rP
         DXYChNrfkzp5ZJl45HzrzM4xtj08dB0NjrFFtyVZJnqC6cduiX3JFNyva2z5AeWYANqn
         yp6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/ZpFj73B5/IhNS9Ki9mUx2l7cKuCV4X+CruI9sHTIys=;
        b=uRCSMHXs6LOsbkzal5sPE7VZakxgrWgB3GE90aqThdaq+LcRG+txORx7oWrW8mk9pC
         kpEm04RhEU++8IRvkD81drRZbCoZSn+Zzeuvnhnejex2nOcigqUl2ptrnn4roYOH0u4k
         uuaEoud5w9PCb4UyJjz4jrkYJV/L8d1o6fP1THgARvoI4468hnYL0V0Qmx4Bpp18jZbp
         MAV0r8HGwRvZC8XF+EAPiv6WJKdssc9R6Q/AbMHOkB+3I/ih8cCizJbfCbtXoRsiFrtv
         JUlb6y2cE/qaarhZ22OawCt1wEMQvvpY9BaDKtddOh8Hdul5huExfZ2Piea4MUcAdjuq
         4Rrw==
X-Gm-Message-State: AOAM532dy03b8As4ik2SIaYu9FRpG/suVOh23Xwr90+KmHkExhojU1Io
	+oVvHFLBvEKT5S7KhgGrZWA=
X-Google-Smtp-Source: ABdhPJx6ACKTbtqQ4PyjR5Iz0OMIexZwiZ2NHi110FGc8Iq+EDK7UwDmyFGT3fP6mVu80DiBojL/Bg==
X-Received: by 2002:aa7:cd8d:: with SMTP id x13mr2632972edv.286.1612883627561;
        Tue, 09 Feb 2021 07:13:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520e:: with SMTP id s14ls11637323edd.3.gmail; Tue,
 09 Feb 2021 07:13:46 -0800 (PST)
X-Received: by 2002:a50:d4d9:: with SMTP id e25mr23407317edj.183.1612883626609;
        Tue, 09 Feb 2021 07:13:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612883626; cv=none;
        d=google.com; s=arc-20160816;
        b=XxxlNejpYWcRgK1twZJxIo2mdjCYqzCNxdSaoYJ7tOvlvA2FnQDYXyZPCrN2Z3Au/Y
         JBMTS7hT/v+BcOpIUzpYpUdT3L9h5lY/wo+JulJcMa0lDh0fEh++SfMAAY31XCQeZAoe
         NDLbHBdgYaT+GKMDSc5FHThlgYzCYkVKLaFMwAt3+Ky8Xv+hUgnjujHa3/UY6VmYM8+Z
         rZNUIzXUDzOtWZnOXbb1ZQpXXxVAbKLNoHYcesbSqevt1BDblTl9GqotWhgcJzaKka7Z
         UjHbu8T52sX/acuS7a3DhfShZ4l2fut3+U/5mk89FtmSr46rxFD9pzNv33TXVV7fId2B
         qgcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=SX0HiwfnPZUJT/hHYA0MIVTfSj70h4+JBgQfnaAr/u4=;
        b=dskoI9ABzwCBhG5rzqQldaoHYptC15bKZ341wwliv0CHtoXV5U7uh/wHQyY5GULbqB
         h4rNqMQlr7bJcQP4Gpn7x+AnbupQTNQwEF/TegzW4tIhR/Z8O/DApeEwKQUEcbBVQCM+
         TWNwZhc0rr8Q+pwrxId0RWZCGn4o/MNlo+/eFrQrJyHyk0SX2W41UEwuCaLlf76lGcIH
         JjjoLzQeARPG6cZaXOebXhpujabHVOz9lA3zJr3NzKtZPjCS1oZGYOR/pqSLmeCCZUYz
         as9Sh1siCXtsYRszFXhN8aB2aFggjjs2ToZhKiU7Z8KtKQBMm1m36/yHeKPYH5O7pmFJ
         5q+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pHK0u1wb;
       spf=pass (google.com: domain of 3qqyiyaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qqYiYAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id jz19si1610282ejb.0.2021.02.09.07.13.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Feb 2021 07:13:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qqyiyaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h18so17742811wrr.5
        for <kasan-dev@googlegroups.com>; Tue, 09 Feb 2021 07:13:46 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:51c9:b9a4:3e29:2cd0])
 (user=elver job=sendgmr) by 2002:a1c:64c3:: with SMTP id y186mr3902730wmb.58.1612883626184;
 Tue, 09 Feb 2021 07:13:46 -0800 (PST)
Date: Tue,  9 Feb 2021 16:13:29 +0100
Message-Id: <20210209151329.3459690-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.478.g8a0d178c01-goog
Subject: [PATCH mm] kfence: make reporting sensitive information configurable
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, andreyknvl@google.com, 
	jannh@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pHK0u1wb;       spf=pass
 (google.com: domain of 3qqyiyaukcykry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3qqYiYAUKCYkry8r4t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--elver.bounces.google.com;
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

We cannot rely on CONFIG_DEBUG_KERNEL to decide if we're running a
"debug kernel" where we can safely show potentially sensitive
information in the kernel log.

Therefore, add the option CONFIG_KFENCE_REPORT_SENSITIVE to decide if we
should add potentially sensitive information to KFENCE reports. The
default behaviour remains unchanged.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kfence.rst | 6 +++---
 lib/Kconfig.kfence                 | 8 ++++++++
 mm/kfence/core.c                   | 2 +-
 mm/kfence/kfence.h                 | 3 +--
 mm/kfence/report.c                 | 6 +++---
 5 files changed, 16 insertions(+), 9 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index 58a0a5fa1ddc..5280d644f826 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -89,7 +89,7 @@ A typical out-of-bounds access looks like this::
 The header of the report provides a short summary of the function involved in
 the access. It is followed by more detailed information about the access and
 its origin. Note that, real kernel addresses are only shown for
-``CONFIG_DEBUG_KERNEL=y`` builds.
+``CONFIG_KFENCE_REPORT_SENSITIVE=y`` builds.
 
 Use-after-free accesses are reported as::
 
@@ -184,8 +184,8 @@ invalidly written bytes (offset from the address) are shown; in this
 representation, '.' denote untouched bytes. In the example above ``0xac`` is
 the value written to the invalid address at offset 0, and the remaining '.'
 denote that no following bytes have been touched. Note that, real values are
-only shown for ``CONFIG_DEBUG_KERNEL=y`` builds; to avoid information
-disclosure for non-debug builds, '!' is used instead to denote invalidly
+only shown for ``CONFIG_KFENCE_REPORT_SENSITIVE=y`` builds; to avoid
+information disclosure otherwise, '!' is used instead to denote invalidly
 written bytes.
 
 And finally, KFENCE may also report on invalid accesses to any protected page
diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
index 78f50ccb3b45..141494a5f530 100644
--- a/lib/Kconfig.kfence
+++ b/lib/Kconfig.kfence
@@ -55,6 +55,14 @@ config KFENCE_NUM_OBJECTS
 	  pages are required; with one containing the object and two adjacent
 	  ones used as guard pages.
 
+config KFENCE_REPORT_SENSITIVE
+	bool "Show potentially sensitive information in reports"
+	default y if DEBUG_KERNEL
+	help
+	  Show potentially sensitive information such as unhashed pointers,
+	  context bytes on memory corruptions, as well as dump registers in
+	  KFENCE reports.
+
 config KFENCE_STRESS_TEST_FAULTS
 	int "Stress testing of fault handling and error reporting" if EXPERT
 	default 0
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index cfe3d32ac5b7..5f7e02db5f53 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -648,7 +648,7 @@ void __init kfence_init(void)
 	schedule_delayed_work(&kfence_timer, 0);
 	pr_info("initialized - using %lu bytes for %d objects", KFENCE_POOL_SIZE,
 		CONFIG_KFENCE_NUM_OBJECTS);
-	if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
+	if (IS_ENABLED(CONFIG_KFENCE_REPORT_SENSITIVE))
 		pr_cont(" at 0x%px-0x%px\n", (void *)__kfence_pool,
 			(void *)(__kfence_pool + KFENCE_POOL_SIZE));
 	else
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 1accc840dbbe..48a8196b947b 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -16,8 +16,7 @@
 
 #include "../slab.h" /* for struct kmem_cache */
 
-/* For non-debug builds, avoid leaking kernel pointers into dmesg. */
-#ifdef CONFIG_DEBUG_KERNEL
+#ifdef CONFIG_KFENCE_REPORT_SENSITIVE
 #define PTR_FMT "%px"
 #else
 #define PTR_FMT "%p"
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 901bd7ee83d8..5e2dbabbab1d 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -148,9 +148,9 @@ static void print_diff_canary(unsigned long address, size_t bytes_to_show,
 	for (cur = (const u8 *)address; cur < end; cur++) {
 		if (*cur == KFENCE_CANARY_PATTERN(cur))
 			pr_cont(" .");
-		else if (IS_ENABLED(CONFIG_DEBUG_KERNEL))
+		else if (IS_ENABLED(CONFIG_KFENCE_REPORT_SENSITIVE))
 			pr_cont(" 0x%02x", *cur);
-		else /* Do not leak kernel memory in non-debug builds. */
+		else /* Do not leak kernel memory. */
 			pr_cont(" !");
 	}
 	pr_cont(" ]");
@@ -242,7 +242,7 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 	/* Print report footer. */
 	pr_err("\n");
-	if (IS_ENABLED(CONFIG_DEBUG_KERNEL) && regs)
+	if (IS_ENABLED(CONFIG_KFENCE_REPORT_SENSITIVE) && regs)
 		show_regs(regs);
 	else
 		dump_stack_print_info(KERN_ERR);
-- 
2.30.0.478.g8a0d178c01-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209151329.3459690-1-elver%40google.com.
