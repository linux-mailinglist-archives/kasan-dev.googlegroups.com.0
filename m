Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBRXE5LXQKGQEO6HTDZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 42EC3125775
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 00:12:07 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id b13sf1487600wrx.22
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Dec 2019 15:12:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576710727; cv=pass;
        d=google.com; s=arc-20160816;
        b=LKfVvRVHyz7Pp7iAY4iU351A9x+9ZGYqQRrsUeGTKsRe3gHFx+WsfVF22lTcxBOHvm
         hZ3MI/y/qmH8end2Go0WFrHKVGEx2GtSi3E+1oKS01rNDJyj/eo8X3nljbQocJbwSgoJ
         eVgE9qKJ4QM18kppjL7MI4GahvhfajSyugk2Nd7yWJ+MtZ4S9CM1TxL4Y403zqJaOe8s
         5R25JIZc4nMyhSAiHWxZoxgAsI19rqI4T18IN8r5TKdRCYkCaGz2N1p2Tkjw4ku3emoj
         eU2z+j4gpkAbdQuJ6Z/qcl/dMuqc3KG6sTFhKzSPwdnBm6ysbvbYfWxYZHoJWLDBzMXX
         foow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Wh78I45+lfkyF4aHYXUAmB08kzNVMZ7UXvoi9gpcjY0=;
        b=aXWYIXg43o+N4/HGv6Lfwvj2ThDVUXR1E9wkeqhdpWtPMgdZmUtP1TMTRqGeoKj824
         Q1T5MngMZnHm5NdhEfKzS3gbyhPX/2AADqiYgBChASnErNjqCxG3l8SvxdOs5i3LppHl
         IeAM8anzpZ0ti/qQ+fXPUVqAQHULsmmd0m3IF6dfFIfJ68KWogbTpj9uBP1fgtwplNzW
         ymzlYtLgnkiC0Lsm7kp5wcbZBUDKS7CNruVQcTsiI7X9+mkDKW3iM2ARncWldmtjdq2c
         CSEwhznM13s+2Ia4t9PJ207JT6VVGfK5MpjAhAsin1QmcR3igBiJ8gxAiQ0ZSBzsGOcj
         rIIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cTTdgQH0;
       spf=pass (google.com: domain of 3rbl6xqukcyoxo11vu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RbL6XQUKCYoxo11vu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Wh78I45+lfkyF4aHYXUAmB08kzNVMZ7UXvoi9gpcjY0=;
        b=fet2NURP/ec9m9IvCnx878tOt8ab4Hb3ovSBHntohT6LhqSK9AqYR/GMMZ/N5SyWsZ
         FU7NWzNQFh21B2gxAbjDkaXMs3NKSTvkdqcKhPspU0tnNEFgi2mS2oH75aXztUo/ExQU
         L+hx2zw8dSJWC2JPxNFHekPIZx5kK/KZ/3KnksGInhQpwBf114tse7S1Bm+kNvNsl9kA
         xqMALo0qWU2cn6wFOx6R6RYYBq94yL9HRv3L39q9XH84k4Mge1459EJyl0DBoF/kqwlR
         zh9pusQuCCUtrmKqacqLbDV+d6ZVJq7Bbr2XrpNErDO98rVxvtWbs47qu2YjJELxkKDX
         MkcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Wh78I45+lfkyF4aHYXUAmB08kzNVMZ7UXvoi9gpcjY0=;
        b=Cu8AYAzG82eswuUARyg+DE9msV1DsNZ43D86t2A+tVQPh6ZVIDMTTyrDiofDsxxhGf
         Z4l5PJuXEs88u9ns4toO5QpgvZMtIJausJc8f+6dyv4HFMyOVjaO+Gliq/AFS0s/kzZS
         ueWKjbAJEjT/DqQhQ/O6lkgq7iar3Szxt9pHaFYmGITzElvVkHMbw2bXKr8B0kTLUSNV
         sqJbrI8XlDx+hCk1JRdssoWhOV9JemDkRObC734pCXMUbwahflxqFsGEOlIrJFza2Tpl
         IfhloMfatL1PepsTbNruq4mmmqrA3WT+DuAxuSSi/URMdLtYbOu+04A2RipOIBa5C0E9
         TgkQ==
X-Gm-Message-State: APjAAAWkdj6rFc3+0++v8luIpAeZ58CoJ0TYBqcsRZ+swyp+o+DnQR5Z
	vxWlbMwSetlmpQ29UobBfLY=
X-Google-Smtp-Source: APXvYqynKTPDiDkUaADJej7jkoHj9WyQoLQNxKpS8O6cMagbpilTHedy+H1Bw3x/w/igmvXL4HxEdQ==
X-Received: by 2002:a5d:608e:: with SMTP id w14mr5816987wrt.256.1576710726946;
        Wed, 18 Dec 2019 15:12:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cf15:: with SMTP id l21ls1200953wmg.0.canary-gmail; Wed,
 18 Dec 2019 15:12:06 -0800 (PST)
X-Received: by 2002:a1c:4d03:: with SMTP id o3mr6195896wmh.164.1576710726466;
        Wed, 18 Dec 2019 15:12:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576710726; cv=none;
        d=google.com; s=arc-20160816;
        b=OR4COgWhy6GgDtCZMl6KIprlLbr8lTx5uYIRmqRQI+51PwuzfK6lfMWOmj3hFk06fo
         GLc1VltGxgJRAhaeGC7ONoRXxIaWXBwnaHYLL3AXX3dixrRyEZl8dcpzryhr+slWqzXr
         eh+5VT8kvVM5uCv5kJaejWtBy9TtjND67uWdBAE4zXEX/0i1AzUyLkamiBlC2ujGS9gw
         VuBCm/T3TGiJSPTgpii0PKh5SQBK/KNon9sTCnb+TdyvbwqGsQXxNHX6G5M9pYQIPyg+
         3qmNWUkwRwWep52zZRhLJp2fp2gPrbyQtUhb8177U+om0yss3CI49QBZkvGISup3itfV
         jMGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=XROsw98/jioxNmwaFa5qgGIGTXokTI7dQ4xiPx1pCR8=;
        b=GqxcAouwzt1lhx4AMmbNrF/xLFG4wHLYhtE0eIw9jExmCoe9AKIMDpa4qaYpX5yqXl
         VUkrO+VlV/99f6USOTFZnPGb6XZ/Wrn/TiF9Ef4f8uvyKsPvFA/zmEqM78abLhPJVATn
         Fhrt9gHjCZjrlct9fXt7QwK5Mqcc3StaCvBbhwV5Tx1gRo1I7m6v+p72j/Sr50olq8RV
         gBtr36FKlt6Ka4iZY1yblILFwPzqLdqP8M08XH6hvXcwNCsPQJTngCt1mY0wJDIcNG9m
         yYyDn2VFNssIu6NdKwvHWnoZtBrxOElNQ9IURuHeLpzQNICutAiuPfd+7HUOZfAs9Chi
         E3rA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cTTdgQH0;
       spf=pass (google.com: domain of 3rbl6xqukcyoxo11vu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RbL6XQUKCYoxo11vu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id y185si130532wmd.2.2019.12.18.15.12.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Dec 2019 15:12:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rbl6xqukcyoxo11vu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id t3so796221wrm.23
        for <kasan-dev@googlegroups.com>; Wed, 18 Dec 2019 15:12:06 -0800 (PST)
X-Received: by 2002:a5d:62d0:: with SMTP id o16mr5452607wrv.197.1576710725585;
 Wed, 18 Dec 2019 15:12:05 -0800 (PST)
Date: Thu, 19 Dec 2019 00:11:47 +0100
Message-Id: <20191218231150.12139-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.1.735.g03f4e72817-goog
Subject: [PATCH v7 1/4] x86/insn-eval: Add support for 64-bit kernel mode
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cTTdgQH0;       spf=pass
 (google.com: domain of 3rbl6xqukcyoxo11vu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3RbL6XQUKCYoxo11vu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

To support evaluating 64-bit kernel mode instructions:

Replace existing checks for user_64bit_mode() with a new helper that
checks whether code is being executed in either 64-bit kernel mode or
64-bit user mode.

Select the GS base depending on whether the instruction is being
evaluated in kernel mode.

Signed-off-by: Jann Horn <jannh@google.com>
---

Notes:
    v2-v7:
      no changes

 arch/x86/include/asm/ptrace.h | 13 +++++++++++++
 arch/x86/lib/insn-eval.c      | 26 +++++++++++++++-----------
 2 files changed, 28 insertions(+), 11 deletions(-)

diff --git a/arch/x86/include/asm/ptrace.h b/arch/x86/include/asm/ptrace.h
index 5057a8ed100b..ac45b06941a5 100644
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
index 306c3a0902ba..31600d851fd8 100644
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
@@ -266,7 +266,7 @@ static int resolve_seg_reg(struct insn *insn, struct pt_regs *regs, int regoff)
 	 * which may be invalid at this point.
 	 */
 	if (regoff == offsetof(struct pt_regs, ip)) {
-		if (user_64bit_mode(regs))
+		if (any_64bit_mode(regs))
 			return INAT_SEG_REG_IGNORE;
 		else
 			return INAT_SEG_REG_CS;
@@ -289,7 +289,7 @@ static int resolve_seg_reg(struct insn *insn, struct pt_regs *regs, int regoff)
 	 * In long mode, segment override prefixes are ignored, except for
 	 * overrides for FS and GS.
 	 */
-	if (user_64bit_mode(regs)) {
+	if (any_64bit_mode(regs)) {
 		if (idx != INAT_SEG_REG_FS &&
 		    idx != INAT_SEG_REG_GS)
 			idx = INAT_SEG_REG_IGNORE;
@@ -646,23 +646,27 @@ unsigned long insn_get_seg_base(struct pt_regs *regs, int seg_reg_idx)
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
 
@@ -703,7 +707,7 @@ static unsigned long get_seg_limit(struct pt_regs *regs, int seg_reg_idx)
 	if (sel < 0)
 		return 0;
 
-	if (user_64bit_mode(regs) || v8086_mode(regs))
+	if (any_64bit_mode(regs) || v8086_mode(regs))
 		return -1L;
 
 	if (!sel)
@@ -948,7 +952,7 @@ static int get_eff_addr_modrm(struct insn *insn, struct pt_regs *regs,
 	 * following instruction.
 	 */
 	if (*regoff == -EDOM) {
-		if (user_64bit_mode(regs))
+		if (any_64bit_mode(regs))
 			tmp = regs->ip + insn->length;
 		else
 			tmp = 0;
@@ -1250,7 +1254,7 @@ static void __user *get_addr_ref_32(struct insn *insn, struct pt_regs *regs)
 	 * After computed, the effective address is treated as an unsigned
 	 * quantity.
 	 */
-	if (!user_64bit_mode(regs) && ((unsigned int)eff_addr > seg_limit))
+	if (!any_64bit_mode(regs) && ((unsigned int)eff_addr > seg_limit))
 		goto out;
 
 	/*
-- 
2.24.1.735.g03f4e72817-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191218231150.12139-1-jannh%40google.com.
