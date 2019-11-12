Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBNV7VTXAKGQEVNLQMLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 26D55F9B78
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 22:10:16 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id t4sf8072162iln.6
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Nov 2019 13:10:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573593014; cv=pass;
        d=google.com; s=arc-20160816;
        b=sgmLL4LTuc4Ds0JNvbAc4YgkN7AKqCqVkN3IebKoQKUtfdeDW3bWzDLEXTCTzMUqVV
         QagkVsw1RG3DHrQWWYROlAMZlhXFEozvonQrLwZvl76Kc06KepdLI/jxMJb6X+4HDZiN
         rptnOBEvMfTlcLFlurUNT576EZgmygLemXQIJqODJPjkGNbd3J6GvC6qYNGKw/Me0Z1M
         oAcVFfa/yOaX5uQA/geT0uxVspJ5tZzMlAnNAkHpSX7HFm8pVw6gPE2SRaPZUOK1/xuf
         AL7IEJJFPjIsqcWYMu1JSnPeVB44XDY3O8yKG70+ZhmXIh/1BFeix0eUFMgmHXgc2/+6
         PH7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=sya6HP7jToY7NHDnfUvjLm1DjMQlF3EbNbgEf5wGA58=;
        b=c4XCf5s6RwRDaL54xFOyo8u8ix75kFHLHd8WQiUAPh6ciyJH1OsT9+ijl8RPi80aiT
         pzW1qj9ZMlbzFkbdzHaok/wrix+Gy+FP5u87QiXU7kth86Vo8X7+3lZmYuLiDaLkUXce
         OHtDmkZGRYYHeqoWV644Qoz7mMJMj36wF+JbQ+pFlzUWuBNk2DwTZetF6F+5sExZPyPT
         +cIog9jRkiGHpQgSyGnJ0NlDT8Zli5R9BQVzH+M0TNrbf08M7SjTbGBi9CbqbYobOdrb
         HbZh8odi7id37C/ut3LfH8kuJw9bqXJcCZfOsOTiV5Tb376gCn7CadKCjbmogODysqA+
         KE6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q0MXfhTL;
       spf=pass (google.com: domain of 3tr_lxqukcry5w9932aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3tR_LXQUKCRY5w9932AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=sya6HP7jToY7NHDnfUvjLm1DjMQlF3EbNbgEf5wGA58=;
        b=gDfx0LIhVzZW3PEzi1+fnWt3FUMSiS8afa7GPcUjQVZFDPWZiLrsBXmEPIBif01Rwk
         iO0flP9vAAArCQen3hPOI96wvjbPSI687xlvVoyFu/wEL4iijoanBbH7BiryYJghRd9s
         qEqowapt7dAubgqJPYGkb/bvycSQamj+BDI101uGgZWhbLIV2X0eaEdGEJOYHcv2tPE8
         t9vSWOafPFDKgLI4d/zv81Hu9FVbRlk2cEYLieOJHTNPVwcvBpqdPnMLt0gZRixLNWLM
         bR8Y+P3KmVW8N5TwoGAXAcC2bwmVAWxx0TDRKgfgBP0bDBOZ8yg3amsK/JsxKelo/xc5
         nt8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sya6HP7jToY7NHDnfUvjLm1DjMQlF3EbNbgEf5wGA58=;
        b=PZV4okVZPbCwxIhhWTIKeL1Apn2z0vOgfnUgFQoyww2iwBm9lIFgSVcR/OmAWIlYAA
         mC8aVG+xSLgviDxjNTiEjrQCc92Zwvm8or/z5fk86IMzCh42X2QjfqIN6STkE7hS4lFC
         oHqdZxxs3lcA8wR6oZ/aSvQp+3fj3Rsjv7EnHggmceBmSYihggzP0UKzWN/0nin81HCi
         ooi+uoXkUr78uYMb6ZIHxBiWrBronc3JcrT7fFqfPKoQX+oqsdeHoP2CeAoN9K+WD9ew
         Glr5PmqDGWoeH75NXfAPPv1nivVHuCGvhfxePZVkQS99uQ3YR2Kwn9E/WxVSXup4KEHB
         9PsA==
X-Gm-Message-State: APjAAAWixhIv7Butb1ZwrVE73mTcmCeGpcGky+RCdIPii9/k9BW5R6RI
	dvwkHl84AFbmz/xziY1HLu0=
X-Google-Smtp-Source: APXvYqzW07T4kQBKxgoI2GHT/Cy9bmCnDS2Z1a1c9Dmefhv5LRl+S3LamEDcSlItw8DXmQMEl5qmyA==
X-Received: by 2002:a5e:db07:: with SMTP id q7mr27105iop.49.1573593014626;
        Tue, 12 Nov 2019 13:10:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:c3c6:: with SMTP id t189ls878316iof.6.gmail; Tue, 12 Nov
 2019 13:10:14 -0800 (PST)
X-Received: by 2002:a6b:6a0a:: with SMTP id x10mr72660iog.48.1573593014322;
        Tue, 12 Nov 2019 13:10:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573593014; cv=none;
        d=google.com; s=arc-20160816;
        b=kPGjmB3f17ILXMBmpZ9xe5VCfV29R3z0mW+Pap3pi1kosMj1zyVAaLHEi5lQSl/H5j
         Zme+N8QpOutZTU4YPrrmLtX6JZ7oXz6/DtVuAt7DaH/PBMdwqBnTKoRwE7trSIywSsRl
         WTJLUrvYoL1lkhKzNbIBZ7JjDB1TkQvGQoHgWHzz6HfViupvGQyPtpPEqlzHbqzmJ9Ah
         mEUZPyn35V9qoDNgII1Ous8ZnpXLDRzIDUNXlIi2hnT+tO0Qe7EdjH9m0C/TGS5X+r3p
         rM31hZt84Aep8eyq+rbQaSbrq4Zne55B+RC3tCm2tdilw9Hi2wUt8agrKoMKI1Ivacdd
         2EyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=FOwUUVfTT6z9vrjLTJmhRH+YY0ofvtEBZQqJjtmC+/M=;
        b=x27y4kxMnqCMg1ovJxlxjZ/gH+UFlo85PKruW6MC+XD94D7qQSsY53DiF6p8w3EZ7/
         skBkGJ0BV1JRH+4p805LMwVSOmTibsjY8ojB+6K/OgAEDtv/jBGyb7bQrfhj+QUPKlzg
         jHyogwoEGpZBdCmXsg0ldSlaDTJxjeW/95PoWQrzAaZrxbznnuTJJOdyz490SJdfgtCa
         C9nekFhkehH5l7GNWRZGCmktJGzfDC0Vl/XfOP2nZBpjkZ2NFcgkt6PHrCJAhe2Jbni6
         lAAX0QSjLk8qLWHM0sseakAx3PEbg/GJfqidI7eXCNqcAwqA6l+4WyC604txKEaM6HDS
         fXlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q0MXfhTL;
       spf=pass (google.com: domain of 3tr_lxqukcry5w9932aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3tR_LXQUKCRY5w9932AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id z78si1432624ilj.5.2019.11.12.13.10.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Nov 2019 13:10:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3tr_lxqukcry5w9932aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id 131so53123vkb.11
        for <kasan-dev@googlegroups.com>; Tue, 12 Nov 2019 13:10:14 -0800 (PST)
X-Received: by 2002:a1f:41c4:: with SMTP id o187mr23099614vka.102.1573593013538;
 Tue, 12 Nov 2019 13:10:13 -0800 (PST)
Date: Tue, 12 Nov 2019 22:10:00 +0100
Message-Id: <20191112211002.128278-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH 1/3] x86/insn-eval: Add support for 64-bit kernel mode
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=q0MXfhTL;       spf=pass
 (google.com: domain of 3tr_lxqukcry5w9932aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3tR_LXQUKCRY5w9932AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--jannh.bounces.google.com;
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
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191112211002.128278-1-jannh%40google.com.
