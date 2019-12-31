Return-Path: <kasan-dev+bncBCP4ZTXNRIFBBVPPVXYAKGQEOJQTI4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 108AF12DA58
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Dec 2019 17:31:18 +0100 (CET)
Received: by mail-wr1-x43a.google.com with SMTP id t3sf18504255wrm.23
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Dec 2019 08:31:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577809877; cv=pass;
        d=google.com; s=arc-20160816;
        b=fwn9OlNcofSlKET+AUxdtXn4oHjf8ACF1EtJMT6QMDKUA8J77JX+qK5vVI/OvyZo9q
         SYKHXrk3dl5WF8IN4kBYH8EY+H5Ph3l/BemspUSllHxXK+LHpkGVQXb7jeQuGIKE61Ee
         MIYAy7tvkZ04RaRgxeQTIDyONncF44Smr0JMKVDLZxT5nROWFXSUtEPcMwzOruTOSSy4
         IGFlSwpJnNxGrdLpDpKpDUTOGX/llpt0NDs46nVDAW8Zj1QUyZvLVPftJY70r2Qk0Wd+
         /1RkQhIYwFHk4U6MjwZMArdFuT5FzUOnngFm62zDUEJEcfPfBsLiXfI+wem5xFg4tHsJ
         Hk4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=OHqJOdtwP3S4Cdapuh/SSHlyNalnixjdNcp6QAH6NOs=;
        b=ORXujvvVcnCm7KlJ3r1EziiyU7l71pNA5BiUulQ099MiUgAFKJ2s4ZseldsIJ9rk0C
         XQyaFVgGm+kA3lttndMcN+rspggicBzFa/llTXu3+G5RLkEPBLKUo3RhA6UscjhVica8
         9OzCH4UfW4Fuf2aXIKEUwF/ZXql5Jp/kQmQeNRCxBquNoRuF5U+FJT3p8fWkGlqLRlv4
         LIF5bmrzziSWdYowtU2rUc/+kR/6Drtp7sc14H8EqrczCRgzj1I/Oz+etOScC7rCp+gL
         vqRa0t17eqM4D5/WJm10xQoy+x8B7+HnxCFAa1nAAsZdtghP2n/iY36iM6TFk7zDC+Cc
         hd7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b="aZh/zyjU";
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OHqJOdtwP3S4Cdapuh/SSHlyNalnixjdNcp6QAH6NOs=;
        b=mLRv/ZvmZ+tP3qTMaxunBcXP2+Oa2cbFG9OMkTSZSF0+mUkkf62ZqIT5MXojNGhHki
         vMoTwF7clmwxAEqzmYTgkJSdEJmkTwl9vRHxjj/WGDqBFbdIFJJZonkCgpc+rX20J9BF
         Pv9ouA9yx1FLbji9TfW9lajdudRxbEFoH7fuZID2bDZ5uToZpXE7O/qDGHXfhfZzAPb4
         5rmdixT2bFF9thGvcrOrk+ynTkWiD3hS9Az6OBPHYBT2xbigy8szuxB45moBUZKL7xWl
         M+MAguLwELOnoHj4dKD4IWY+smcDZwVxSiaKT2R7R2nw4byxfm42ENuaz4Xc+Q92C5Iy
         3OOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OHqJOdtwP3S4Cdapuh/SSHlyNalnixjdNcp6QAH6NOs=;
        b=snG//Bqb7dhbnu+87zTDliZFTnH4Xb8ZFAjwiLML1CQAj/xfTU6DcwK+RE/e1fikvR
         AuOmiAqwHo4i7yEfwC9wldvGM8euIn1dFY5GlZXoqBw1JTFgPWyJUiuH6ij4R/uQPO/8
         MM8dPsK8WueTZfjZ+s9h1AGn0VNlYVTkbnlP1MW/Cf78aP90rhCiJZhCUZ/B9mJE/Zo8
         VBVaT09MQRYZpfzyh2qU1cQdnxd3zH3eVgaanfia07DxPlWl6MPawZOx4l7WilAmWtU0
         TRCPGVFiXIu2n0P4TZNkmoZl9ouO2+RIKr9GU1JyTkenC639y9l1OhEcVzGPSboijHlD
         p+rA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXU3SfiEXWrsn8d48qUCImCdHZp9x/NwXRZLLhAyxpxYMPNIV2x
	DTnSZwDPawbD9s1Uov2zcHY=
X-Google-Smtp-Source: APXvYqzOeFc74FUEvGEFYBpEUllEbcJtsJ4rXWYK0TgS6DGhvaN1C0Q4j+0/IfpYsEFq8Z3Q8UNrmA==
X-Received: by 2002:a5d:65c5:: with SMTP id e5mr72748127wrw.311.1577809877720;
        Tue, 31 Dec 2019 08:31:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:ed48:: with SMTP id u8ls9188421wro.16.gmail; Tue, 31 Dec
 2019 08:31:17 -0800 (PST)
X-Received: by 2002:a5d:51c1:: with SMTP id n1mr72130833wrv.335.1577809877185;
        Tue, 31 Dec 2019 08:31:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577809877; cv=none;
        d=google.com; s=arc-20160816;
        b=YuBUlGmNfqZowoo4JJLRWd3FVtVB+vQJG8SRJadunJ6pOKlCSUMSGFW0fTbhWSwdbk
         Wb6sV1LIXnQmReh2nU9xkTKfyyjM38j0C/vv83GRz4YeeLY0lH305N03b0sr/KBSMpo1
         QOJeVjWZzo81DiftyoP/PNftd3zjhOnwJOu+ODp2a7TXvE4YaZFZoJHffzR18B9SKEfq
         vboObuIgnb4QCpMy+0TWuM/z9MH6aOLtBfspT2kZxhjP2aU4C0oiFqDdAHDlT/g+9ecI
         FvPR7kjp4qV2oivjmLsodQrbbrgE3+uyB+YkHX2tRnc16EkWg1U70zsELkqFziSTkvHv
         fccQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XLKvpbF/byz3Z6T7cOCCHGN1ZNPGh/rIhiwmf7WR9SA=;
        b=0mjZz8wSBBX6+lcqG80bvSvXatJ37M9hGj8s+pdnkwEdIaPAvtkCU9DCJh2+a1FiRO
         nCB6BHwB4nMfq9pyUdT4aVo+i3pqs04IKJf2TUN39iDVlJhSGCS9UfpQ9GW2AiOqDDls
         v7ewtffZy1w6dAzkE3Sss6XHX78pvgzpfMknWYHvl6zXEveUC0ozvCar/qWet21yESEf
         hYd4GF4NM2zv3UPYCTdbuvZ/zjSKl952OIGOYtviYMHlMI6maNbddGrylj5sXxBgzc2A
         oKLPnVe7Xk6/XooL7QWWADoPol2Ra2i4v/lB2km3Qpp+CV1L4sON8jaG9kwWmixJqcw4
         8/ig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b="aZh/zyjU";
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id m12si1717903wrq.1.2019.12.31.08.31.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 31 Dec 2019 08:31:17 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F00E7007CEDBF47C01C0A42.dip0.t-ipconnect.de [IPv6:2003:ec:2f00:e700:7ced:bf47:c01c:a42])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 823371EC0273;
	Tue, 31 Dec 2019 17:31:16 +0100 (CET)
Date: Tue, 31 Dec 2019 17:31:08 +0100
From: Borislav Petkov <bp@alien8.de>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	"H. Peter Anvin" <hpa@zytor.com>, x86@kernel.org,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>,
	Sean Christopherson <sean.j.christopherson@intel.com>
Subject: [PATCH] x86/traps: Cleanup do_general_protection()
Message-ID: <20191231163108.GC13549@zn.tnic>
References: <20191218231150.12139-1-jannh@google.com>
 <20191218231150.12139-3-jannh@google.com>
 <20191231121121.GA13549@zn.tnic>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191231121121.GA13549@zn.tnic>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b="aZh/zyjU";       spf=pass
 (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as
 permitted sender) smtp.mailfrom=bp@alien8.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=alien8.de
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

... and a cleanup ontop:

---
From: Borislav Petkov <bp@suse.de>
Date: Tue, 31 Dec 2019 17:15:35 +0100

Hoist the user_mode() case up because it is less code and can be dealt
with up-front like the other special cases UMIP and vm86.

This saves an indentation level for the kernel-mode #GP case and allows
to "unfold" the code more so that it is more readable.

No functional changes.

Signed-off-by: Borislav Petkov <bp@suse.de>
Cc: Jann Horn <jannh@google.com>
Cc: x86@kernel.org
---
 arch/x86/kernel/traps.c | 79 +++++++++++++++++++++--------------------
 1 file changed, 40 insertions(+), 39 deletions(-)

diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index 2afd7d8d4007..ca395ad28b4e 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -567,7 +567,10 @@ static enum kernel_gp_hint get_kernel_gp_address(struct pt_regs *regs,
 dotraplinkage void do_general_protection(struct pt_regs *regs, long error_code)
 {
 	char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;
+	enum kernel_gp_hint hint = GP_NO_HINT;
 	struct task_struct *tsk;
+	unsigned long gp_addr;
+	int ret;
 
 	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
 	cond_local_irq_enable(regs);
@@ -584,58 +587,56 @@ dotraplinkage void do_general_protection(struct pt_regs *regs, long error_code)
 	}
 
 	tsk = current;
-	if (!user_mode(regs)) {
-		enum kernel_gp_hint hint = GP_NO_HINT;
-		unsigned long gp_addr;
-
-		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
-			return;
 
+	if (user_mode(regs)) {
 		tsk->thread.error_code = error_code;
 		tsk->thread.trap_nr = X86_TRAP_GP;
 
-		/*
-		 * To be potentially processing a kprobe fault and to
-		 * trust the result from kprobe_running(), we have to
-		 * be non-preemptible.
-		 */
-		if (!preemptible() && kprobe_running() &&
-		    kprobe_fault_handler(regs, X86_TRAP_GP))
-			return;
+		show_signal(tsk, SIGSEGV, "", desc, regs, error_code);
+		force_sig(SIGSEGV);
 
-		if (notify_die(DIE_GPF, desc, regs, error_code,
-			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
-			return;
+		return;
+	}
 
-		if (error_code)
-			snprintf(desc, sizeof(desc), "segment-related " GPFSTR);
-		else
-			hint = get_kernel_gp_address(regs, &gp_addr);
+	if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
+		return;
 
-		if (hint != GP_NO_HINT)
-			snprintf(desc, sizeof(desc), GPFSTR ", %s 0x%lx",
-				 (hint == GP_NON_CANONICAL) ?
-				 "probably for non-canonical address" :
-				 "maybe for address",
-				 gp_addr);
+	tsk->thread.error_code = error_code;
+	tsk->thread.trap_nr = X86_TRAP_GP;
 
-		/*
-		 * KASAN is interested only in the non-canonical case, clear it
-		 * otherwise.
-		 */
-		if (hint != GP_NON_CANONICAL)
-			gp_addr = 0;
+	/*
+	 * To be potentially processing a kprobe fault and to trust the result
+	 * from kprobe_running(), we have to be non-preemptible.
+	 */
+	if (!preemptible() &&
+	    kprobe_running() &&
+	    kprobe_fault_handler(regs, X86_TRAP_GP))
+		return;
 
-		die_addr(desc, regs, error_code, gp_addr);
+	ret = notify_die(DIE_GPF, desc, regs, error_code, X86_TRAP_GP, SIGSEGV);
+	if (ret == NOTIFY_STOP)
 		return;
-	}
 
-	tsk->thread.error_code = error_code;
-	tsk->thread.trap_nr = X86_TRAP_GP;
+	if (error_code)
+		snprintf(desc, sizeof(desc), "segment-related " GPFSTR);
+	else
+		hint = get_kernel_gp_address(regs, &gp_addr);
+
+	if (hint != GP_NO_HINT)
+		snprintf(desc, sizeof(desc), GPFSTR ", %s 0x%lx",
+			 (hint == GP_NON_CANONICAL) ? "probably for non-canonical address"
+						    : "maybe for address",
+			 gp_addr);
+
+	/*
+	 * KASAN is interested only in the non-canonical case, clear it
+	 * otherwise.
+	 */
+	if (hint != GP_NON_CANONICAL)
+		gp_addr = 0;
 
-	show_signal(tsk, SIGSEGV, "", desc, regs, error_code);
+	die_addr(desc, regs, error_code, gp_addr);
 
-	force_sig(SIGSEGV);
 }
 NOKPROBE_SYMBOL(do_general_protection);
 
-- 
2.21.0

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191231163108.GC13549%40zn.tnic.
