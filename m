Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBVHTXPXAKGQEXZZVRXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DD04FE577
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 20:17:41 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id f21sf6630474wmh.5
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Nov 2019 11:17:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573845461; cv=pass;
        d=google.com; s=arc-20160816;
        b=x77eFpb5f7PramuPA2uMKPVAN6fwInHom99CTtJ66oSPPq0ohvCQh9sjARo73uer00
         WXeajK/iEKn9JfrtCvMK1ZxexeKaugQvcmf3Cq+zmgS69ODlsjg5fHGNphn/SaPisPAP
         ojiuVGmia/kY+99dGdkC1ptu6db9pMAZ7HEOcGsExbebK6naLzcYbkUH7Z5R/iWgUWjs
         7CcEY+xxZvlZoKaL+019M1WLz3uKfT6n2wzTzNt8zaSAUD4ldeyRSn8avOtTRe7FLLlA
         AKLHcGFZpzEnkjX+CBDSYAV7XZybo5KrsnhjleGNgPc/ry0aT3FsRkgtiiFgEUBwN0ra
         8GCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=7Vdz2TWT/yB3G+eiKrG6b6AyORAjz6F2NaVuP+9Z/OU=;
        b=vWySstquL9X9UzhrskeiEG34LZN/bCB9LVRhnhAPukomW1WtGq7tp7aprx5E4SJm5u
         CfhjQZd/WxN5Mexwsp8XyOGFaq6srPb9J4b6u0NQmRhlNsRBpQh7TUdU2misAEAilXq/
         yteCWjqveDoKLQefM+TeOZ+zZetk2gNLCxhO1+sGPq+Zzr13ZaqfMBCceQ81HUQWvGLC
         OXL0MHomZB2D7z5nN2cHkCVbEMJAC0Ug2ccHjiXfksts0rYaFcp8XGKvRoJVa/2xIzTZ
         gmcpKBD6kEzu5ncywHiGg5VvLsqmaS5gk1MvF26r+QebD71ldK/zhP6KixFyHG8mkU7C
         Momw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hfj3euSo;
       spf=pass (google.com: domain of 30_noxqukcfyhyllfemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30_nOXQUKCfYhYllfemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=7Vdz2TWT/yB3G+eiKrG6b6AyORAjz6F2NaVuP+9Z/OU=;
        b=UVWNBLHGYLRW1WKGC2HJL3kC/SbUfq2CB6nAKoBP9FXhnxiJWjtaM1FWJr/QkBi4ki
         VcuLGWo3MBmnTkHnh5ByTJ4icKkh+8BO4Fr3HLc1LLRgyMgjrPqHanUmo6zZew7vC22q
         lFXLm4YTBMl5VdKpexJFc50dOdKB2PHb+J8J5W2zMP5a8BvxNnkdEo9W5bcogIfxM+n3
         +g3W8NoxlCV3fHDXhGnWFGotNE4COjSb9/MRUuvojUYylglXVnoJDP+OqdMHZATMMWa/
         6Yor+ebF+Gm4fgeJnp8IHnbAbl/EzziBTpK2AudJ/OC/v5hFhovFmqHsKj9cx/7/3OuB
         K17A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7Vdz2TWT/yB3G+eiKrG6b6AyORAjz6F2NaVuP+9Z/OU=;
        b=fho9wJ8uCwhLt1T9PcF30KGlBUCGQm/Z5S7W21SJ59gjWh+rPKfvL4qZ8hU/PwrU5K
         I+f/+NmkgYQmKqjQZmhJ1DPJuwZ27SF3GY0Nes/+2/qOdzHgC5wKPAieF57Oa+yR+WTk
         3WfyTyTf5WQUNFj/4v2qrpY9D/HNJDb/AMwymDlMt1Kv9m+aUBlj7Ml3SUhcPscMLtHl
         kxcg4f6viidk8DYo9PQfg+cjFNP1VcIE3NnwMtvWJ49kEdiV9ksYQ+PqL8zgUbXXr+ca
         liOZN1B5ENJGeGVKLk1Qvya3nmJk21Lt4Nslt39bnS6XSaY+50fJfxtjt6UQJPPUua/+
         HOiQ==
X-Gm-Message-State: APjAAAUZTSUa1Yi0YGC8u3wvY557+oriYfG2prdvCOaNneVbWOJb7kjP
	zj5Er4YBhzY+8Tsf6oyJfdI=
X-Google-Smtp-Source: APXvYqzrGjZcjos2JBL3xXjT4R2MT59Ou/4LKtTAe4jvTlk5yNZnk0TEJXJ+Ea5E3HEg2OTd/JGmpA==
X-Received: by 2002:a5d:6351:: with SMTP id b17mr823273wrw.126.1573845460950;
        Fri, 15 Nov 2019 11:17:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:480b:: with SMTP id l11ls15727573wrq.2.gmail; Fri, 15
 Nov 2019 11:17:40 -0800 (PST)
X-Received: by 2002:adf:e506:: with SMTP id j6mr17576496wrm.19.1573845460481;
        Fri, 15 Nov 2019 11:17:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573845460; cv=none;
        d=google.com; s=arc-20160816;
        b=yVkz7o7FXemqYTQ26ZMv55ngZfKo/iw+NuuialsmunZR0rlXXJWTZ/AY/Os3bBvxyX
         TTMjvRpOnx0gUdKomDvupe6HFRYkfNA+GW7oc+pL2USk1ZovkNjSCkAd3CzJkYTLknrc
         e4HBBZaeIQAewihNYI1SqcmDKOF5XGFlMqMquUr9GeioOCoMNGIuUDpeVu9UcdTlSYo9
         ExCoUT1uBUwZk1cTU1Yu9Ci/kofwVIFU/bq/+pHvfqiyEy5PizhHUWiwVErIyOgYee17
         Mb9nxLPfhB1zbtDEW/1Qmqb/2ZEzKb6Is8EB46aDhVytYcpf+GP3yM453YSRIVZPf8B3
         VbqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=sOSahxtVzmMy//+sngzoRwO73Kt/9r0KRyyDuBPBx88=;
        b=FSvCvTdpnXrZ9bWDBYoTtVrtr5PrFZcAz/lcEvc+05pYizOKfbhIAK5FoF4R9BvMLT
         XE0ausZv9VnSfHLjNbsAywgMpBleGRqN+MZDGn3Xc34xARiM0i5HyXI/l3H0v18i7vSv
         R0yUZNqMqMHOdlFLNyDyrIBzT2rVLsbml2UAYNE55DNsxXK+G64cIJUPlAhYbrha0Fcd
         a0RMgbQx3OQUBf2tvQOTrw+/hQGdYng9Cxrpy8JfgVYofXEIi4ZyCVzeABO/w6lf+T18
         DnnA/20Jc8q8oapYIFheroKIJd+AgKBTGKStgmm6AIuxGkdLZ09MeP0apBvU9tjoUzKd
         dYcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hfj3euSo;
       spf=pass (google.com: domain of 30_noxqukcfyhyllfemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30_nOXQUKCfYhYllfemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id d5si627470wrm.5.2019.11.15.11.17.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Nov 2019 11:17:40 -0800 (PST)
Received-SPF: pass (google.com: domain of 30_noxqukcfyhyllfemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h7so8437314wrb.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Nov 2019 11:17:40 -0800 (PST)
X-Received: by 2002:a5d:50c3:: with SMTP id f3mr4836854wrt.14.1573845459506;
 Fri, 15 Nov 2019 11:17:39 -0800 (PST)
Date: Fri, 15 Nov 2019 20:17:26 +0100
Message-Id: <20191115191728.87338-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v2 1/3] x86/insn-eval: Add support for 64-bit kernel mode
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
 header.i=@google.com header.s=20161025 header.b=hfj3euSo;       spf=pass
 (google.com: domain of 30_noxqukcfyhyllfemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30_nOXQUKCfYhYllfemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--jannh.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191115191728.87338-1-jannh%40google.com.
