Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBN5O2TXAKGQEVFJ7TIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id EE1CD1037A9
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 11:36:39 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id h4sf16111753edq.8
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 02:36:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574246199; cv=pass;
        d=google.com; s=arc-20160816;
        b=GtDyCvBGaGt3wVhURCrdNA3edv3Jot4LQ4/VWYdVhtr3ZICUOPkLCRaLm1P6BIjcKh
         BGNzy/hq4VEMWaQDTqEwcJDQNeE7yc8gHiMlc1EwqarL7snXXvKt10ol+kO1kp3YEHfF
         dmYAkx6VUi63fd4hJ7/HRhcpAP2lLsfgVvaJqEcr/nxxFrzudcBbbONWUef/r19cEufL
         MtyEIqxQ8cBcBsM2DtB5FSkIBzoDEgtJRb28ZbfN7v5JIZNJ82zXo3pa4uFzjhjiTzbo
         ZSxD9Oh3yw3lcp8sTGW1u2GeTPchVeo+3Eq22Z69FDrzPjOeyhHOJ5FU0cNBQTn0BN/b
         9fdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=0gzw6NfMhRxzbDil9kEweYBcVo+aizSRAz3gVc4Z1cw=;
        b=AWTMwAgjbVpK6hln+BiEijbT8euiLjaghVdWnToPYCEaZ1dzSfFZ+wUTpCP0oMLMx8
         Wtt1EDflNP8Yq8lrj6vc4af9u4PG3TT87wpTO82PliC8WoR6TgwV7doFWn/MAPiOyy0b
         K3n+Mo7gSZ5BA90rE9kzrN8xwIgv5ZvJv/mPf/NKCxxpXNNd9LPfvmV0RpFaVhOOKsz7
         CXli56UMujsnOaPQU0XYN4XPodc11m4TD4uUfwJddqVGygUsafAPBfQJt3epElBchQc1
         WZVckPKSEXECqhJLLclAJ+/VI3c4Ncs22wi5tbri5bVi4hTNuWgejbYUteuS7dlofivU
         UlxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ff1RWopg;
       spf=pass (google.com: domain of 3nhfvxqukca0wnaautbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NhfVXQUKCa0WNaaUTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0gzw6NfMhRxzbDil9kEweYBcVo+aizSRAz3gVc4Z1cw=;
        b=OWMBnqax9E+zy9VslvjP8v+3w6sBqubovWpf5cK3iS55scD9RgnIhTdygZj4e7YdMj
         vz4z4Gq3D2zNRsHo5pmEdclfgT8P09CooIzx7LiWfctJZ7JgT9JLIkxA1FAaKzIVIIDM
         yAb7WGZxjluOgeTlAyFF5+YQMffpv85sNbu1aAMoa3UYvihsverK/1JC2f2SiFRu+5jG
         Bm6gvTi+rNKNXLZILmposphx+1xaFMq09zocABvpvw7ZyNmUkHLS2NaYdkF01LkKyAAy
         W/L4p8tjACJ4loewW4g/RDd//9eU2HyyMfDSM4/HobAKbBfWpGx9vtoT7M8reKjobAl+
         +Iig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0gzw6NfMhRxzbDil9kEweYBcVo+aizSRAz3gVc4Z1cw=;
        b=Q/G06zpextMlK9gRFk9Py3BVZ/78rO1uxk9DoMWED2r6h0BTJMlAAxWMs0GKQTzsjE
         +obQJlc5LxmYXMw6nxe/RpXcqP1DxpIT68MIyIR6DB9ziMMx1L2gqExSs5mBFWy8YwjM
         +VrHU3vZc18CVNIcSoYQHUw5fR+bMICIS2pH8WVq+1/RYJTRzOfsxdGlb6nUvA14PCkZ
         RQqvhh29EB1wy57EZWzFlQSrYUn9oC/OvJSYKuR7NxY6aXAniK2OvIvKWyupKJa5njcP
         sTmD0EixG2NDddsuxiym50PyfLqbeBIKbXR/iBqkopttBCiC4TaJnuCTjFDA/rf18lte
         i2+Q==
X-Gm-Message-State: APjAAAXPpcy6rozUk2llr4IHC0KiwkrPOTISX3Po9MiemCNIEJLJqdjc
	hxxcnkvYDkuMXu0ry60ULbQ=
X-Google-Smtp-Source: APXvYqxIrQuHGlwQpI3QjMmg+/xYflYGtJHDit/+V1lhd3c90KBB+Wb197hRFdM0q2QQMOq4p//H0g==
X-Received: by 2002:a17:906:134c:: with SMTP id x12mr4514768ejb.269.1574246199619;
        Wed, 20 Nov 2019 02:36:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1956:: with SMTP id b22ls895434eje.15.gmail; Wed, 20
 Nov 2019 02:36:39 -0800 (PST)
X-Received: by 2002:a17:906:1354:: with SMTP id x20mr4561569ejb.131.1574246199171;
        Wed, 20 Nov 2019 02:36:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574246199; cv=none;
        d=google.com; s=arc-20160816;
        b=Y3PHGA2VvrSqPTi1JFojemiAd0ABO+7HEHjoe5VBWoycN4JjGj61ZrgUHIV3O1KkvI
         /85JZ3FdH8q9GqejHFVfeAMthnkoKd9LiFijonp22SOvonwWKOw3o4b8TdLr2W7bLwfL
         IVr21ssVqRdm2DNFd5DLPcVHMiaPRrCSFObnN+K6LRu1p1rdSC+UKgVtgD+2zybMZ9fx
         5OgsH94LeCM/ee87wT+ZSITa3PT71dDL7l6IJXeX//nCHYavREttPXc5LXuJS2L/Dwpi
         nTqA/qWYM9CFzDR7aP7ot+h9ARb1JoCCqPWomA9axcbEqMvFtH9j+25nJU/AIPlHO/YU
         CWMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=ntSwiwOTp4Ro8rVlXlEHwH+0sIgdpFKmj8FpJOpYIkY=;
        b=vZL9hFa0YCGPrl6AaATH6v97kHehm4mm+MsiFOgsykJz19gNqDIzoRa17DIHnZzViM
         Ccpbw7JMmxbz+VjrXpyZ9NjLJdIPb7iMMMBAaQ5JBUh67yG20BcYF0/wxhbGAtFAW7l5
         KqxNqRT0XY+zJtpryeancmnZHa+VnBFY6mv+/sBeWEIguBXIhhGVU0CM5B4PMpBW2olm
         ZrPgCDLnyPy2uz3Evm3jB/NEBxnBrYGfPBVRzdReliglJJGFjjF0/agRY0TENa93VFct
         Pc6nZ5s0kzzj0ztwqBQqus8OyhwCU7lQRJbxEYeANMe5pPOxXnRta8+IAO5biH0Ossbj
         02jA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Ff1RWopg;
       spf=pass (google.com: domain of 3nhfvxqukca0wnaautbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NhfVXQUKCa0WNaaUTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id x16si172781eds.5.2019.11.20.02.36.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 02:36:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 3nhfvxqukca0wnaautbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id g13so2702645wme.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 02:36:39 -0800 (PST)
X-Received: by 2002:a5d:6702:: with SMTP id o2mr2259218wru.339.1574246198590;
 Wed, 20 Nov 2019 02:36:38 -0800 (PST)
Date: Wed, 20 Nov 2019 11:36:10 +0100
Message-Id: <20191120103613.63563-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v3 1/4] x86/insn-eval: Add support for 64-bit kernel mode
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	jannh@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Ff1RWopg;       spf=pass
 (google.com: domain of 3nhfvxqukca0wnaautbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3NhfVXQUKCa0WNaaUTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--jannh.bounces.google.com;
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
    v2:
      no changes
    v3:
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
2.24.0.432.g9d3f5f5b63-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120103613.63563-1-jannh%40google.com.
