Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBUVVXHXQKGQEDIGUUCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 97129116EEB
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2019 15:31:48 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id y15sf6772690pgk.20
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 06:31:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575901907; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tm1dSCnOTmOo5Oy01lwVd+lUBxx83L3W3G/99rUw8+0v9iy4j/UjC0uO0zRInkvGvK
         4B7qpH3Mo39qGzAEIqHs+JEPvSpP+N9cmd/MTLwFvNWW5YUD09czEgV0TIsN0IUm3siw
         0Qk7y2vBmnAeFGV1ezbIB63+JQvsTfmeLYq5k5FtwS0WOI+B7tvCjJ8GJWdwTsfDK8QB
         F6tL1b/6H02iN9USVAfY76FnBtX+MSYRGDf4yhtRMqMuHw4+VdssdlpTBbqesk/lp99m
         CIqXX2omQahDNsoziNXYnIalMfPxH1JWOD05uvha3YukXKqVw/mRK90B45D8zPmLkjwt
         LeMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=dpNEtPiZrde0Z6ONyK0mIf5mXjZpcfaMrBPw5OD2KAA=;
        b=MMLY1psU8v9vLKJTCZQpFIwGkKU6Ez0oRrI3pff1NO00nog+5aH1rwJexzhmy9kVL/
         rllltQfjugFgZklQ4+UPbcnYg0tRkWJouQTqW/RhpPvGziy0uxpi2/G2rzjfieLxs4/h
         LP2Po3ct8aHRpFrhQyocP2oASjiNay3271y2Gg4NvAV2t0rf1t6y43nJnlEGZSXVklDf
         ezoah9TPGkQJbFEnItwkU5r36G5Nz2rsNYwBVheqZCR1aWpssoaGHOngBM5eKCJub3rJ
         NcuYqDzlS4oS2oEvJi0NfXNGAiW/YQdfGvJeQpcLrOh+uW7pve+p4cLiGOCARUoMuK/B
         AEFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l6KcQXNZ;
       spf=pass (google.com: domain of 30vruxqukctybsffzyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=30VruXQUKCTYbSffZYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=dpNEtPiZrde0Z6ONyK0mIf5mXjZpcfaMrBPw5OD2KAA=;
        b=oaQ00/0GRM3SJ+EPtXSpH0PZCa/gkvC8NwRJYt4Pe3TdiqE0ApjpQerPb6CPxGC+tw
         CYukQIaJC3IGHmDvdf027dV66N0SlWCKcLl27zUDnjA4DfWfMn025S+9M93JUPhQHcm0
         jKYlL2o3hoMFa11zXB+EMMdcZpslHg95vKRJXV+55uzMagCHCkm4/SytepABBkrduEIF
         4sPARB76H9fmwnliyoMZVXL1OIR9ELbo0v//CY+DUpJtVlNfwFolzNTsplQkFwhG7aFV
         0OXVHEhgc+zskOPETnN11Axtbz8dA8OcJRkAvjkCRLVZjUPulBaQY+/mv4Ix8AfqaGaA
         LCAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=dpNEtPiZrde0Z6ONyK0mIf5mXjZpcfaMrBPw5OD2KAA=;
        b=AW3Gj0MV1eg8HuRwxI7auweQIjqlpsGAxUyMS5aG4/3h5G6v+CQks4ydxqcP7+Kf/i
         tbRjiS4W9HLwRA/GHDhNsxmyQ+Sk6msIiAWJw9gOv9Dj5+5pl28N+vupBXU8j75jezns
         nTlzGjBLcgCm9M9/t7eztMJcbetDhCoVdogU/fm7Q3RF6W12t/Te1fsf56ip0HXDuBUJ
         Tl5zI9j9Tx6r5jD0MrVQpPmwtWviSRFVSbFIOXOdd+G6qDGD3QoYXISW+v5vecQvbQwn
         iTbO2N/BsRVxAXOW/uri/6+BcvIwh7mazjsrYf3LrK6i00ltx37RY6eqb7tFiJ7udWVt
         HrxA==
X-Gm-Message-State: APjAAAV+3JSlgiheaWLldW/xp84DZU4JKU5b35rcKXd3/ujXCDyNPmMR
	k7IYQFt0h9YKkxpN79nLJWQ=
X-Google-Smtp-Source: APXvYqwoDbvFW2buq0+JVjWXIeTxFFl/KcJkli5skmBUgM92qKr7JgDQreTHFP85Ic9MHFPOhXsovQ==
X-Received: by 2002:a63:4d5e:: with SMTP id n30mr19012211pgl.275.1575901906943;
        Mon, 09 Dec 2019 06:31:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ac0a:: with SMTP id v10ls3634344pfe.4.gmail; Mon, 09 Dec
 2019 06:31:46 -0800 (PST)
X-Received: by 2002:a63:b64a:: with SMTP id v10mr19303908pgt.145.1575901906476;
        Mon, 09 Dec 2019 06:31:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575901906; cv=none;
        d=google.com; s=arc-20160816;
        b=YAMqC9Yi8cOSVZvzISsjqmeHFF9L1up6kUwPLaoBIcA74rl2Bw6Em4QBaSYVFnnSL7
         GtoXcb+qzWS9ATcQakvv8+iSaT9g9qQ6ngKR0wU72N+3Lge32GmswSQ0xXRNf8oMu+yL
         iC+dK4gnf+nQxKqsFOvV/kxb9UC2DhJPoK9O11bksR5Skr4F+QfhnxAzSn67hEzAGcqS
         J+wOSQYSBbALQT3/XqZ8q6Z8FvwWC8Uw8re1Nk5N23euZzXq/2pCghdQ4xI3JWDOFMLu
         JsgXehBTvt8C8fQo/iKwMdw58v1ANEIqTYC2j/nSXHVCmfLyoPNg5uyj4MfrZ2APgCcM
         hvtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=doQeIN/U+MYu/QD7wqRZp73qNYpHVGdRJwhLC3Y8YdU=;
        b=rMsQwDqxee7ylzSL0UUtkRw6eciSHUfVZRlwFqJi1CbUI2/Rctx1nSb3JlOT3Z6Szg
         4BfkWL3/jr7Tgm1df8XY003s87GNOcoBoQ2N5oqFj1FLezvxACxC1tIrhH+ia0R5YeoZ
         j+TXmDN5VeRunvE8bbqicU7BRmvK82yLNN4tlsl5gz5Hj52fWsmxwsZqClU55g3LSdIf
         ZnZkLrciMgn4V4CELV2a9f63s/6uhrZzdIKf1lqBa4sM1kTfsB4lZbz/5677QbvqkrVI
         XajVPwbF5waWzXRVMYXoomIA/Gocj5BvsCCx+yvIzgL4KO9XQZZ48Wu0c2gWl+SKyhDz
         6RrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=l6KcQXNZ;
       spf=pass (google.com: domain of 30vruxqukctybsffzyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=30VruXQUKCTYbSffZYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-xc49.google.com (mail-yw1-xc49.google.com. [2607:f8b0:4864:20::c49])
        by gmr-mx.google.com with ESMTPS id s103si280006pjb.0.2019.12.09.06.31.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Dec 2019 06:31:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 30vruxqukctybsffzyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::c49 as permitted sender) client-ip=2607:f8b0:4864:20::c49;
Received: by mail-yw1-xc49.google.com with SMTP id q187so11865854ywg.12
        for <kasan-dev@googlegroups.com>; Mon, 09 Dec 2019 06:31:46 -0800 (PST)
X-Received: by 2002:a0d:f003:: with SMTP id z3mr19482463ywe.391.1575901905562;
 Mon, 09 Dec 2019 06:31:45 -0800 (PST)
Date: Mon,  9 Dec 2019 15:31:17 +0100
Message-Id: <20191209143120.60100-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.393.g34dc348eaf-goog
Subject: [PATCH v6 1/4] x86/insn-eval: Add support for 64-bit kernel mode
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
 header.i=@google.com header.s=20161025 header.b=l6KcQXNZ;       spf=pass
 (google.com: domain of 30vruxqukctybsffzyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::c49 as permitted sender) smtp.mailfrom=30VruXQUKCTYbSffZYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--jannh.bounces.google.com;
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
    v2-v6:
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
2.24.0.393.g34dc348eaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191209143120.60100-1-jannh%40google.com.
