Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBHHD2XXAKGQEBZOG65I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 7249D1041A6
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 18:02:20 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id s26sf223569edi.4
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 09:02:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574269340; cv=pass;
        d=google.com; s=arc-20160816;
        b=QfORedj89LFT/WZqyYDDPeYWSfbalZjODK0myizaSfr0/01ALiOOJjY1pIoYu5GoKv
         L54wtydf6gXLgIC/QjJuOVCcvl7PxsSG2OsnB4KOjoJWk2uLrTYJQhsYQTkw/0NugqWi
         JyTOwEK4668YCVeuWI3F/gMbQwFL3Izky9rleqiybeibemibivdqH7aOysgvQhKf4dBR
         inThVSOLUP2NZ8ix86YyZhmXdmEGMkdN/QEWsKwGhQZSnj+JSoBcWtfBi1b//f+ftGQy
         8zrm7paH+9ZcdEY0Y0Gm/zZPKCFeeqbe0SxmPSrdfJar/b8YLcsK5H7+brsrrDNnHxnL
         pL5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=RqRQluupOKBz1fo/PO4IfCy4oiNPEvG4gdzH0NY3XvM=;
        b=ElYHtzd1Fu04zJk4MGuWOn6PfZqGNp9rnzCypjs0tzRlqiDNu5K5kW06btr4W/NU/M
         o9bpRWarNCSdqGPMAeBddq7l1LEBeHqjb+dyBPOcTOFcB9hVCvLi15d33L9OAdVQeV6q
         6p4FAs2Ql1OCAnEtj+c8/MnuEd5+BLM0OvD4K5vp83GAuaorCVBLpVPBfdqzQKndTqlR
         +KlRipCIcoZa+3o9R42e5EIkYRivyp5XuyxF+RWwcLxCXf21Fekb86tGAHm0vLRi4rYJ
         9iK+TOvQ3Wshg8+a3RN2rM0QEF3c4PtoFtMi2cCN07pl/sJrzu4wl1aF4j3ByMmyPtt6
         Hwug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Flx4RBYn;
       spf=pass (google.com: domain of 3mnhvxqukcccwn00ut11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3mnHVXQUKCccwn00ut11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=RqRQluupOKBz1fo/PO4IfCy4oiNPEvG4gdzH0NY3XvM=;
        b=cnm277Sojhh2mITMMi9YWe5PLHnolLpYjAc/sf1H3N3rgLIZ4fKTA44QaKrqoYon2+
         DPaS2m6rUVPcHUojzdTs71mkvUl1L6FTkCpiGdvCOqVcJSXppNJU9Aaw/JqYArB97hqY
         mqG1TaecVUr8P6m2aeheMt8pfxwXVFpcm+JVY9LCN48X0c5pJKc6bj0/3BnDzpKIvnm6
         MotkcmnrNkurUrlj3oJZtyt98Rra7Nh4towyXy33x8ijF2pvYmWnedYaEYvbX83C37Rr
         cGq049sWBbV59eY4bX8G/yfJwrJqXE+ojoVBBpZfh9g4iNXMB/zysZ4oxSlahXwZbpuo
         w+sQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RqRQluupOKBz1fo/PO4IfCy4oiNPEvG4gdzH0NY3XvM=;
        b=ID7z0Vc1rpiMnwKJy0sI7+26ky/pvteVdlYnPY1BHXNX7oYlu6mMkF/yheWbGRyXfZ
         LfhYb8c9tRMgU1pP5qua7z5eoBbJbA6A9T0VymXp5dJYDIKzhgA7A4upsERUnARTOrVI
         4fpnEl4AhnRRPn4/nl3rxo8zaJqggCuvBjusVd6/5APt7PhRb1kvDLe3OsJmF8cGAPDp
         22Blj7mTyQX8UnsAKwFqD9Q4Uk4lYcblXyb3OwI2zAndAtY3Mwxa+zGKpq0i62OWwwmp
         APfYz0ndyERXHAXt3VByAnJEIXYS0bHKKDOhk4TBaLTlxkwBBsNWL3brIpGrzMH85Wj7
         ZAZQ==
X-Gm-Message-State: APjAAAWs88VGlsUv8JkJeigLR7U6UMpECYJjdk+Azu3CuUe4mojuJhW1
	QO0tGP+8LFTofrPIPVvA6eQ=
X-Google-Smtp-Source: APXvYqwstWUdxmwMhv9CSLEGD8Pj055TGj3CsuBFHhvF4EoGpf0KYW4JuSpC6S0EEkVOSgzsFyq7Xg==
X-Received: by 2002:a17:906:f259:: with SMTP id gy25mr6236688ejb.297.1574269340073;
        Wed, 20 Nov 2019 09:02:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:590b:: with SMTP id h11ls1370858ejq.10.gmail; Wed,
 20 Nov 2019 09:02:19 -0800 (PST)
X-Received: by 2002:a05:600c:2307:: with SMTP id 7mr4631272wmo.154.1574269339453;
        Wed, 20 Nov 2019 09:02:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574269339; cv=none;
        d=google.com; s=arc-20160816;
        b=r10QgU17uZk7pGGK0AYrUwV8riNh55MMZkd3S69UF/pBV1avhZ1zrw+LGdvyU8tdvl
         HGajOQHD/4I72eyuw8E1dvFLUYFvzQInVqohusx6A3HziSokutyh30E16DOtWH4zFZj8
         vmIZ9zxcjAF1rTJPA1yl414PR9Ne+oihqgVXTf6JXXwcBvv9mKQVFDtxlcR1XBQVOfO9
         tFUhiTvCUMLhlqOs+V12ssjQLf0FAv+vVDTb95lFBeQS8ZBy+FVGO5O4CeI4g5w4Dmhk
         Dj5Venz/AoQaaNU8pxs0Gse28j5NTY0nuI7LFg1iE86oD1l8Jc4yPR+y4GULJhcf4yEX
         8Kww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Tx4RYm+Tzd28YlMwIK1Ooy6fDDS4M3Vck8MQ8QkiYJs=;
        b=o/Mx55ssM4g+lNuryXK2gqber+EjKwS9XowJnnOSkybGNsf2lFFOCC/BCMlOVmhVUh
         iFXffT8VUHgOa1TVbRe/b1qowfpE9rrQLC4mv6AecFGaE3KJCeq6BOy92x00+xMRKsvf
         jELk7iuVyICNBdozpsPVKW9M2aWkMyX1GbnblgKEej4AMtxDGr++I4M/Dw3H/X59SG6+
         YQAVHLtB/005Ql4DZhoN+dGS58OLGZ+mpasqz7PHsirSpCWLgsoX5kOi3rs2T3KmkJBn
         0OzujYb5b1ay/aokFjJurMR84bl4QWjMStrGGFchvpuXYsWhrvgAlDcDqEF8zzVULe4m
         HaPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Flx4RBYn;
       spf=pass (google.com: domain of 3mnhvxqukcccwn00ut11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3mnHVXQUKCccwn00ut11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id q73si199777wme.1.2019.11.20.09.02.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 09:02:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mnhvxqukcccwn00ut11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jannh.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id h191so5676020wme.5
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 09:02:19 -0800 (PST)
X-Received: by 2002:a5d:4584:: with SMTP id p4mr4839096wrq.345.1574269338797;
 Wed, 20 Nov 2019 09:02:18 -0800 (PST)
Date: Wed, 20 Nov 2019 18:02:05 +0100
Message-Id: <20191120170208.211997-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v4 1/4] x86/insn-eval: Add support for 64-bit kernel mode
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
 header.i=@google.com header.s=20161025 header.b=Flx4RBYn;       spf=pass
 (google.com: domain of 3mnhvxqukcccwn00ut11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jannh.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3mnHVXQUKCccwn00ut11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--jannh.bounces.google.com;
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
    v4:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120170208.211997-1-jannh%40google.com.
