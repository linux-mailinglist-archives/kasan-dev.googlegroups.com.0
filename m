Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBQUX7TXAKGQEPI7QUDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8FE9510C0CD
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Nov 2019 00:50:27 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id g142sf11234616vkg.7
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Nov 2019 15:50:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574898626; cv=pass;
        d=google.com; s=arc-20160816;
        b=AD+aEL9U/yOvTTc60TLZfELreJIcFGnfMhvVrT0ee07qH4OsAJgYjuXJnIDacnyypB
         2usUyvkHeC3l+q3m+aNcuLuRKxd/lTjiPy5Xq47mBpPfdCgdz/5ZKq733vFn1OHLT1tj
         +BAc1gM+Nno36nwFaLdlDCpgjqrniHa6Q0TlPmy1S0JU34PDUVBQStMeGeOhJwKBfcJG
         ofk9Ndh+2aACkQiDX4J7CGbccN0rhgIx3OOSieQAc54usLFeOhfv71Isx6ldwVguhqlF
         oVCc2G+cp4l9Q6lDk/sTT+MucKJWxhtv0YwjmRNootP5xAdTe1h0btrqX1rS8Aeoxnnn
         lAiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=Id3lol9eugFC3PVmgsfRgBrAY/ABXpMbu1rGkf6NfDI=;
        b=DqkY5ng6JMZqBmS/gy9oYVVio/94oGVbZMB0AdhNo6JrujWVIJ+9kyEfq9W9tFpglW
         z/wHSDRzR7WJSOyqSZiMUgE8mv5hzKS8yAlVB9PenfzHm20EivyZcWKDc7c3Fn2rFpKs
         nwqW/tRApd+PkFVqua6VUNwpPzSv6izig7hHwmx2QmHatQNpUdEoFcdbEWIcb7ZGWIZI
         MohCZ9Zl4clqEjIHa7yrhqaW/xclacLgyfcDSHTITvz+Qu0E75nt5VQ8x5D2TktafJ6C
         Ux7nVs1WnqOkuRLHdxmYWVSs0TxZpdcZLHwWzNrGLHc9Q2NK97TlUY7Bxxsjif8fSqoe
         kzFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i5Gxn3xz;
       spf=pass (google.com: domain of 3wqvfxqukcuovmzzts00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3wQvfXQUKCUovmzzts00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Id3lol9eugFC3PVmgsfRgBrAY/ABXpMbu1rGkf6NfDI=;
        b=DGOMzafaDK1hqgsF3k5tgQBZx9CzUIWCELQgPOfR8pJzXglDynoLvAZw3e7v9G3DLi
         Mn9CQpzQaHtlnkMKeZMbenJBXKVbe9AiUMTeaHwC2Nm2m483ATG+Dbfie96ou7AJclbZ
         9fTJ1FNFh9ntgrbH/9mPvYCul/gxA2gHGGtJj9EtRdAtGf1Hi28jWHKpiyakMiJpj2Q8
         Nhv3EbqWeGuGhQAIAP+1FMMetcjj85siOuHH/H4OTyTgRgZFtwXBQxRXpOLZnclxj+XK
         HzXN/m0cncZsirOq5KHV6qY3EvNZcVVbNnAqLD2PUjsjW1OI7L67E7wr3ocSW4TKiC1q
         //lg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Id3lol9eugFC3PVmgsfRgBrAY/ABXpMbu1rGkf6NfDI=;
        b=KwQhzqpqHGAK9ki7vLoiJMQwjOq0ZRKqsnjSu27QkOUXk6g/Mb7xYsFJnCxo9GUU20
         RIlCERPGRBuXvqy3yRzurs/OrAsBCC+GSwkr7NkybllU4pBkB3zMibQ41zOHJWmccFrE
         Xa4T5fq+/bvUPhK40BliSO97M28HJI1KtsYYgvT+FENCpXa+APCvunaK3xW4ZlA6bWPz
         9BOY8OPotWz9krS5Lwkt0TEWwXXZHA0B31I1GckRXg2scCwJbWatayaMO7eBzr1tEx79
         jEKrEVg5HEFCSfK98gwEw1Y7CuvfO15JWk/Yb2GhiJappz2Q8WH+gc3uSco9+Gatl2hW
         VhMQ==
X-Gm-Message-State: APjAAAWlCAmV+iTQiWToKep5eS6NGhtyQo9RDskLoUUKGuMbGC6RSXC/
	/NZKj5BO2oCuKc8QhqxlYgE=
X-Google-Smtp-Source: APXvYqzS7yvOfyQJKpx+dhf+vSSWkT44zHKtxtLmqbhpPe4JC2SkAsJpMu8mSURo2mJpacvB0Dqjxw==
X-Received: by 2002:a67:b008:: with SMTP id z8mr28621199vse.62.1574898626538;
        Wed, 27 Nov 2019 15:50:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a397:: with SMTP id m145ls85449vke.15.gmail; Wed, 27 Nov
 2019 15:50:26 -0800 (PST)
X-Received: by 2002:a1f:250b:: with SMTP id l11mr4841206vkl.10.1574898626165;
        Wed, 27 Nov 2019 15:50:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574898626; cv=none;
        d=google.com; s=arc-20160816;
        b=dGq1PRoeLk7nOiZZFeXOAnKRXfUm/7NiixUoOfNCeHXNsbPIJAA2BY+aYh+ou+6V/V
         2i0vd4FtJ//D+iOekLWqBoVWY/c96vVagaEwsdcVqvTBybeTOD0VQwcchsfW5F56nzQb
         acwJxiFJI4tYpCfwJrQNV5moE64597ncxwUpVP4NRgZbS0Oim6gKCKJg56ldEQWx6m0i
         Nddu2LuI4qcXicuJIPSk0dUMA1Ug23CEtA3DsPxpf6UMr0Vv+SlMBioOEINGWQCWFwat
         CzM5VnSSbViqMsGI4MszD/A+U8d4Km24JVqL5D8fA834hE9hPeZyo9sKrBQMW0zMPwcf
         rITQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=sslQZgUjF8mS7PYbCqQtrDtVZrFkyPKopZymkUPtEMY=;
        b=gyC9b0V4Thynm0sRzFiajAto7Sd6Hl7KVH4+raPiFFu/fq0uePOk2A0k7nVQzo+IN2
         CdvhdAQPERvEgR8nwOuCJ8KwU2w3BfgLxw8L5CgUvLdy4WEBRbX2s5HG21K0JtssSzI2
         KcF/O6N/BoPMWLoVxMqIQT18Rumjjs28vuWwkq7SGdf0d8DxvdNtzjvZ2Q+vXCl6E+Yt
         CVE2j2f80UOLOXueJJcv3BCKM24SxkkV4bjH9eU/67q87Yb7qhqD12lRf0q9oaIcWhu/
         arTaAbrxeGi0fETa5k9MTNdbigacqdEyXR4zeqrAMN0GOTgQCyXPzqYGUUqeXF+hcvgn
         MKyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=i5Gxn3xz;
       spf=pass (google.com: domain of 3wqvfxqukcuovmzzts00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3wQvfXQUKCUovmzzts00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--jannh.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id j207si285540vke.2.2019.11.27.15.50.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Nov 2019 15:50:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 3wqvfxqukcuovmzzts00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--jannh.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id a186so14924241qkb.18
        for <kasan-dev@googlegroups.com>; Wed, 27 Nov 2019 15:50:26 -0800 (PST)
X-Received: by 2002:ac8:474a:: with SMTP id k10mr25607125qtp.338.1574898625703;
 Wed, 27 Nov 2019 15:50:25 -0800 (PST)
Date: Thu, 28 Nov 2019 00:49:13 +0100
Message-Id: <20191127234916.31175-1-jannh@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.24.0.432.g9d3f5f5b63-goog
Subject: [PATCH v5 1/4] x86/insn-eval: Add support for 64-bit kernel mode
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
 header.i=@google.com header.s=20161025 header.b=i5Gxn3xz;       spf=pass
 (google.com: domain of 3wqvfxqukcuovmzzts00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--jannh.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3wQvfXQUKCUovmzzts00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--jannh.bounces.google.com;
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
    v2-v5:
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191127234916.31175-1-jannh%40google.com.
