Return-Path: <kasan-dev+bncBAABBCEIU37QKGQEKOZDZAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 232852E349E
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Dec 2020 08:06:50 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id f4sf9580507ilu.15
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Dec 2020 23:06:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609139209; cv=pass;
        d=google.com; s=arc-20160816;
        b=0G3oiFrhapKDM3lAP4GDP2wivL8YGPpnljTWSvCt0Wj8e6fqXqKFMrahGFOdVVOMKP
         QMaWG3VRJ4vis6dT4Y+Z6yIQImjqoWVdCkufOL7NLCvkeFzOm6Mejnx0w+CdQmfoJLFU
         eQyN89hqnLXl1hE7tvoY2MoFvnJHvRuuaVtxAoknN/5yjbrm6nX8pL1D/GPAmnvTdf9b
         /4huwquEFkFlEG99TxL5VXGPZlsHWeqNopdoP/CCbIAKvB2YdXtcSOGbSWgIKYfTqWgL
         nqnN6TvOBWKekyqZK7D1lSuB1LKNkzI5M4x1PpPYekrfvrhg7qzqmv5jC/TX7WIrn3RW
         6CJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=eFxAfBXgtheLwbEddMJEbOHpb8xx9qzNF42uTi/pOuw=;
        b=CbAEvl0qR4+FxNMoxKKrtgupN2ijOU91ymhwEFBWH37qBSGvcxGpa3RRo9kLSGA13H
         Q7f63Iyx16ScOdpIIUsPRURnuPASv+7aTwQ1DXBMJkDCI9uSZWTBRCvhWY69Qy6g6muH
         L1L9ofJ1sxAg6HE4jPLwXUCsLmhazFZotdDUhSjkNM3Hc0HNeco58mcQMeM396dDYU4E
         /Rll3K19Riolz139ak+nJ5+rfJ48s9mhT10/7iMTfdV71+L0dIEzaCpwSdEgf4/u4tPo
         VMmWuV4vKBB70ZlIB1Bdr5k2L9hXhfHeqXJwZogHbKuNlEMeudX67tplxakzFiwUoLIm
         97eg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wetp.zy@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=wetp.zy@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eFxAfBXgtheLwbEddMJEbOHpb8xx9qzNF42uTi/pOuw=;
        b=IHLfjCSQ1lAKOoIO0BfcfhQrqsRKQlnHJhCLV5ATlTCsQFPKu0BkDbtviZvZiC85ju
         5eOhSrLG6IeD/Vi9vy6yTidFZoG9u4XOnehzjKZh+fer165MDQD+DugzXFlABoPcrfSq
         iEckjLlAVkhfveEfDHI9+bKxWSWnZFg0mr9AFOFscGd+H2Z7J5/eEJOkzLYUc/TmOZAW
         1lhYoLKquO2ZIXoT6pJRPLwubBxLkspnWgfXe39amMlkvbzUXBqNWDUAaZ3z2dq++ZVM
         xhGEe5HiLlaH+HbUrwYMH7yIyWAWttHDYLlSVMGHlEWhRVgE0sz0vWtxIHJRkt5uBR/u
         Xhhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eFxAfBXgtheLwbEddMJEbOHpb8xx9qzNF42uTi/pOuw=;
        b=GuIHeF6i++cq6KidZ06eNdNZlD1EHUUQ3tfOGcxknYzpE0raJ9X1CMu5fZ2392Zn7Y
         akLDMyqj4siGp7eYLooq4qFAHlcdZxZMhJtrzPqohythfDu93/T6VNCdjPlJtUcdp4RT
         RjH1gat4AsS8tH3ZUFjgF//8amL4WlxIcvxz35UXyTtagx9NQ08gfk7WfWKpETU8L2C/
         e9LgVwxVSYssz55bdB8DVpt5FPzCsBGB2SsFjs7kjit6FQgg6mA0pZ+btCpQ+PF9BlQp
         xOJdQwkFRIuv4Sclj9J9ccMHRzgx/6NUHCadrdCmnOZYAnleFDvLAkVBqyQJEbgDrYCR
         6CgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RbIFRubo4ewApRkjoKMtQq+pgzvN1/Kw9juL+FGszMTLpO7fL
	6m5TMBQM/D//Uernhe8s9N0=
X-Google-Smtp-Source: ABdhPJw5u284D9CstRIfrdagD0dMv2JLRyo6JPqN6XR8ikwSJUdX5YqE1tUL/60Ocg2meE1GErZNbQ==
X-Received: by 2002:a02:b011:: with SMTP id p17mr38373794jah.114.1609139208699;
        Sun, 27 Dec 2020 23:06:48 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca09:: with SMTP id j9ls266780ils.11.gmail; Sun, 27 Dec
 2020 23:06:48 -0800 (PST)
X-Received: by 2002:a92:c0d0:: with SMTP id t16mr42966846ilf.21.1609139208305;
        Sun, 27 Dec 2020 23:06:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609139208; cv=none;
        d=google.com; s=arc-20160816;
        b=YCoyCDwTFIWEGlZfyT2qbKz/7QcfIXncAO5earqt5FhuthpeozMoWuGcIQntdBMK1x
         evQlQmQwQzK1iaCynBNKSC5k7iBBXGjwDCBslxKfHji4LvgQZWwjKdwughFqteVK/Gc/
         vAD2YjenGiOvk16T8G3j1aLZUlRXtacrbmB84PR+C6o3nAaYVkRJypUIow3nPA1pXxDa
         Ff2UvFHq7quIV48iHGsSfqAucjWVVDwUjSTTzbT0hfZua5pJI7DTezh7k93MDjlC6CYY
         1vQgn4a5q1daBfWQsODCPfUZdorVlcI1hLq6oJ7swBPMq3GGBGR5XZ8qhj/2jouPX5jG
         4HWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=kMygIKGle6eY7OpzYy3G1uEf1uXvyKJsZGp51ianoXY=;
        b=uDBMeb+xem16uTZgbTVDMrfge4PJSoT24QusuH2R5yjboyYdiRFDNRwHPXTHAlGvDP
         MlpqrVy1yhlM5CYzvEYwKwj83sJcXnJoBHSIW5jLfXS2cUcOnd3UTpp8mim4KF7MPgNx
         pnZ7HrZjFIgnSbd2O+aprjH9oYC/RCxwBVmdKklX6TfeRSq5xReo45i/V9qi2qh3C6Vp
         fB43tu6yUKMR5Xe+jBYKA+8RcfjuXt/xql/AXsbIaq1MQd0eswhbccJk2XQwlISX0zuj
         atcQsjYBndubegXxDs3P4nYnEP72+3S4epDwnycxxrdLbyQtLAHZc4IasEyekVS1TEZc
         uOPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wetp.zy@linux.alibaba.com designates 47.88.44.36 as permitted sender) smtp.mailfrom=wetp.zy@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out4436.biz.mail.alibaba.com (out4436.biz.mail.alibaba.com. [47.88.44.36])
        by gmr-mx.google.com with ESMTPS id u14si1110296ilv.0.2020.12.27.23.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 27 Dec 2020 23:06:48 -0800 (PST)
Received-SPF: pass (google.com: domain of wetp.zy@linux.alibaba.com designates 47.88.44.36 as permitted sender) client-ip=47.88.44.36;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R841e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04357;MF=wetp.zy@linux.alibaba.com;NM=1;PH=DS;RN=19;SR=0;TI=SMTPD_---0UJzBKuK_1609139175;
Received: from localhost(mailfrom:wetp.zy@linux.alibaba.com fp:SMTPD_---0UJzBKuK_1609139175)
          by smtp.aliyun-inc.com(127.0.0.1);
          Mon, 28 Dec 2020 15:06:21 +0800
From: Wetp Zhang <wetp.zy@linux.alibaba.com>
To: artie.ding@linux.alibaba.com
Cc: alikernel-developer@linux.alibaba.com,
	Jann Horn <jannh@google.com>,
	Borislav Petkov <bp@suse.de>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andy Lutomirski <luto@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>,
	"H. Peter Anvin" <hpa@zytor.com>,
	Ingo Molnar <mingo@redhat.com>,
	kasan-dev@googlegroups.com,
	Oleg Nesterov <oleg@redhat.com>,
	Sean Christopherson <sean.j.christopherson@intel.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	x86-ml <x86@kernel.org>,
	Youquan Song <youquan.song@intel.com>,
	Wetp Zhang <wetp.zy@linux.alibaba.com>
Subject: [PATCH 09/13] x86/insn-eval: Add support for 64-bit kernel mode
Date: Mon, 28 Dec 2020 15:04:55 +0800
Message-Id: <1609139095-26337-10-git-send-email-wetp.zy@linux.alibaba.com>
X-Mailer: git-send-email 1.8.3.1
In-Reply-To: <1609139095-26337-1-git-send-email-wetp.zy@linux.alibaba.com>
References: <1609139095-26337-1-git-send-email-wetp.zy@linux.alibaba.com>
X-Original-Sender: wetp.zy@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wetp.zy@linux.alibaba.com designates 47.88.44.36 as
 permitted sender) smtp.mailfrom=wetp.zy@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

fix #31317281

commit 7be4412721aee25e35583a20a896085dc6b99c3e upstream
Backport summary: Backport to kernel 4.19.57 to enhance MCA-R for copyin

To support evaluating 64-bit kernel mode instructions:

* Replace existing checks for user_64bit_mode() with a new helper that
checks whether code is being executed in either 64-bit kernel mode or
64-bit user mode.

* Select the GS base depending on whether the instruction is being
evaluated in kernel mode.

Signed-off-by: Jann Horn <jannh@google.com>
Signed-off-by: Borislav Petkov <bp@suse.de>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Andy Lutomirski <luto@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: "Gustavo A. R. Silva" <gustavo@embeddedor.com>
Cc: "H. Peter Anvin" <hpa@zytor.com>
Cc: Ingo Molnar <mingo@redhat.com>
Cc: kasan-dev@googlegroups.com
Cc: Oleg Nesterov <oleg@redhat.com>
Cc: Sean Christopherson <sean.j.christopherson@intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: x86-ml <x86@kernel.org>
Link: https://lkml.kernel.org/r/20191218231150.12139-1-jannh@google.com
Signed-off-by: Youquan Song <youquan.song@intel.com>
Signed-off-by: Wetp Zhang <wetp.zy@linux.alibaba.com>
---
 arch/x86/include/asm/ptrace.h | 13 +++++++++++++
 arch/x86/lib/insn-eval.c      | 26 +++++++++++++++-----------
 2 files changed, 28 insertions(+), 11 deletions(-)

diff --git a/arch/x86/include/asm/ptrace.h b/arch/x86/include/asm/ptrace.h
index ee696ef..bb85b51 100644
--- a/arch/x86/include/asm/ptrace.h
+++ b/arch/x86/include/asm/ptrace.h
@@ -159,6 +159,19 @@ static inline bool user_64bit_mode(struct pt_regs *regs)
 #endif
 }
 
+/*
+ * Determine whether the register set came from any context that is running in
+ * 64-bit mode.
+ */
+static inline bool any_64bit_mode(struct pt_regs *regs)
+{
+#ifdef CONFIG_X86_64
+	return !user_mode(regs) || user_64bit_mode(regs);
+#else
+	return false;
+#endif
+}
+
 #ifdef CONFIG_X86_64
 #define current_user_stack_pointer()	current_pt_regs()->sp
 #define compat_user_stack_pointer()	current_pt_regs()->sp
diff --git a/arch/x86/lib/insn-eval.c b/arch/x86/lib/insn-eval.c
index 87dcba1..ec1670d 100644
--- a/arch/x86/lib/insn-eval.c
+++ b/arch/x86/lib/insn-eval.c
@@ -155,7 +155,7 @@ static bool check_seg_overrides(struct insn *insn, int regoff)
  */
 static int resolve_default_seg(struct insn *insn, struct pt_regs *regs, int off)
 {
-	if (user_64bit_mode(regs))
+	if (any_64bit_mode(regs))
 		return INAT_SEG_REG_IGNORE;
 	/*
 	 * Resolve the default segment register as described in Section 3.7.4
@@ -264,7 +264,7 @@ static int resolve_seg_reg(struct insn *insn, struct pt_regs *regs, int regoff)
 	 * which may be invalid at this point.
 	 */
 	if (regoff == offsetof(struct pt_regs, ip)) {
-		if (user_64bit_mode(regs))
+		if (any_64bit_mode(regs))
 			return INAT_SEG_REG_IGNORE;
 		else
 			return INAT_SEG_REG_CS;
@@ -287,7 +287,7 @@ static int resolve_seg_reg(struct insn *insn, struct pt_regs *regs, int regoff)
 	 * In long mode, segment override prefixes are ignored, except for
 	 * overrides for FS and GS.
 	 */
-	if (user_64bit_mode(regs)) {
+	if (any_64bit_mode(regs)) {
 		if (idx != INAT_SEG_REG_FS &&
 		    idx != INAT_SEG_REG_GS)
 			idx = INAT_SEG_REG_IGNORE;
@@ -644,23 +644,27 @@ unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
 		 */
 		return (unsigned long)(sel << 4);
 
-	if (user_64bit_mode(regs)) {
+	if (any_64bit_mode(regs)) {
 		/*
 		 * Only FS or GS will have a base address, the rest of
 		 * the segments' bases are forced to 0.
 		 */
 		unsigned long base;
 
-		if (seg_reg_idx == INAT_SEG_REG_FS)
+		if (seg_reg_idx == INAT_SEG_REG_FS) {
 			rdmsrl(MSR_FS_BASE, base);
-		else if (seg_reg_idx == INAT_SEG_REG_GS)
+		} else if (seg_reg_idx == INAT_SEG_REG_GS) {
 			/*
 			 * swapgs was called at the kernel entry point. Thus,
 			 * MSR_KERNEL_GS_BASE will have the user-space GS base.
 			 */
-			rdmsrl(MSR_KERNEL_GS_BASE, base);
-		else
+			if (user_mode(regs))
+				rdmsrl(MSR_KERNEL_GS_BASE, base);
+			else
+				rdmsrl(MSR_GS_BASE, base);
+		} else {
 			base = 0;
+		}
 		return base;
 	}
 
@@ -701,7 +705,7 @@ static unsigned long get_seg_limit(struct pt_regs *regs, int seg_reg_idx)
 	if (sel < 0)
 		return 0;
 
-	if (user_64bit_mode(regs) || v8086_mode(regs))
+	if (any_64bit_mode(regs) || v8086_mode(regs))
 		return -1L;
 
 	if (!sel)
@@ -946,7 +950,7 @@ static int get_eff_addr_modrm(struct insn *insn, struct pt_regs *regs,
 	 * following instruction.
 	 */
 	if (*regoff == -EDOM) {
-		if (user_64bit_mode(regs))
+		if (any_64bit_mode(regs))
 			tmp = regs->ip + insn->length;
 		else
 			tmp = 0;
@@ -1248,7 +1252,7 @@ static void __user *get_addr_ref_32(struct insn *insn, struct pt_regs *regs)
 	 * After computed, the effective address is treated as an unsigned
 	 * quantity.
 	 */
-	if (!user_64bit_mode(regs) && ((unsigned int)eff_addr > seg_limit))
+	if (!any_64bit_mode(regs) && ((unsigned int)eff_addr > seg_limit))
 		goto out;
 
 	/*
-- 
1.8.3.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1609139095-26337-10-git-send-email-wetp.zy%40linux.alibaba.com.
