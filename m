Return-Path: <kasan-dev+bncBCP4ZTXNRIFBB7ORZLXAKGQERCMDEGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 05975100742
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 15:21:50 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id s26sf11546581edi.4
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Nov 2019 06:21:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574086909; cv=pass;
        d=google.com; s=arc-20160816;
        b=o6HBfpes5IywNYPXPtcTIP3Ge2O3HuO/2egt8i1vgItcUh5mk+pCd3AUU5SQ55L4kb
         3cJyPELSayY35zWkz1CKF2A9nKVBaKbDnlTdtVmeraLxWpQEbUSsF9gQelOVxbihaFMo
         dcoSU9LTc7ajAwHsfzr5MAseq3KoXTlkRFwwSe+n6dSaZbNEJ1daaYRFceET21il4P6I
         2QpbuZjUzCk8tKuDcQ+LmRcCx91SnAeXKnmRUOi2tP5gU/6U047NXFj6iN+p4xp8vQtE
         nHw1nkSpCcB6hRZ4baEkgh1/DcWBHsYqeIPytABvKmangnUkiMORpKfe6VgUKYbyctjU
         iC6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=arrSKC8iVpaItj9ni/klSu0I7yBC4YluI1qKE+nP2kM=;
        b=oMmZGoJgs+Lx9sPsO64B4KahikCAzeBh7RuRaxySRRKrpV3PNoodEv6GiVpWNvKxY6
         9SXRvCxz1T+cJYD1aJOWwiB0aRUYP4pCp1fBfWDzCSNbJsGCqgz/Hr8R5wW9qZWz0Tpy
         oqQgs+EYMYVzPm/qpaapSnK/CS7biQ3SYy6dR+32ydFqmfK06qcDdCpwYuGK3nvMori6
         HNjgOW95tisA46lW7Rq3smoX4VVxLuk+BnOs/HUN9R8mEqgsHoOMyRw5XNYrVfimETJT
         ruQzKKepVTNbWxQ/uBhT/rsMxbL14+zgw2TSj0BXAg3M0AwwAjiwygaSQ1WRK7YXlUzm
         WpxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=PbmjpkhP;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=arrSKC8iVpaItj9ni/klSu0I7yBC4YluI1qKE+nP2kM=;
        b=GPLRmdada4KQamc08tEahsHrteKH4yxtSJ1KGoY80SfKRMpPj3L+KvoVrS3mW/+WPB
         txvUe5j4D6cWLRGSwFifuODH6Fonx3k+VR6ckKq8BIkI1PCFhW3LDxW2uEgmekB6aAYF
         dTlsaw/IxMtjFOUrQAsilFpiJ5oAP6qjkBQczm9yDgZVgS9eDamWYU6/TpUaYNSMIUQY
         Ab6miuib+srYZ7tA8l/9eUeLoIHDlfhCN3spjAVHXxRtRTEWepnJXJD0IrajCtvB8S0Z
         PuHpxcXucufFbcrjBpgeH5jf/BmbsGBIWI1w6LXVGMWk+yXfqGcypVCttkYQ3h7Eh++W
         dXNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=arrSKC8iVpaItj9ni/klSu0I7yBC4YluI1qKE+nP2kM=;
        b=KafqoGu67qdGmEYIeNnqnvosjKejBFVcEQIEyMWKe9SsQ0l+6y/juK9Wny+CXY6lHL
         SFhEkY5jvAuTp3OQBlQu6C38qXYreBUOHHNseb9lwFoZ1yWmPf/6t0kuYaXw4Tmkj4F+
         fyQkAAPjpWzT78qKi1dJiHr3aCpFY1xv2HdHgqoQIynJNa+OdYj0Z0jDS8AhpfOnA8j8
         O+qYGNRGLnZn9sT4vDv5J9YRfFhtWo1irahnHOffSOKBfTOs17eKh0upCJdgrr1M9IMU
         pj0o4steQWOlWTLLfUdkYxkmpXUhT0cilVeGe7puJ8hfpddLuie8a7tEzf1fI2Rt27Kz
         9p8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWosi/8z6GrXZmLN9/j1xOthNC8J1ZA2wjfog4gcW/BBC+4OGd0
	fkkkVX0AmxuXBUS84gauYmo=
X-Google-Smtp-Source: APXvYqzaTYlVFDuVzqavUNzH9rOc/tpcaTColmxyqDx2w33fxGTy86utfoAZ9s8flH9dmTryg4N8ZQ==
X-Received: by 2002:a17:907:447b:: with SMTP id oo19mr26263586ejb.81.1574086909708;
        Mon, 18 Nov 2019 06:21:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:793:: with SMTP id l19ls5692052ejc.7.gmail; Mon, 18
 Nov 2019 06:21:49 -0800 (PST)
X-Received: by 2002:a17:906:2e52:: with SMTP id r18mr27568969eji.178.1574086909239;
        Mon, 18 Nov 2019 06:21:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574086909; cv=none;
        d=google.com; s=arc-20160816;
        b=mx2gyIDiNAz95otYeNZpFPj0SBYg3L3A3LwNfXkDf6lGLCKBTdUWdw4W4EDYWNhsrT
         c00JfWd3xr8aceioppo8CFqJZCvRCxcoT7u+BB3BOvHLbx2+jRkCCo60FQGB2wbaWvs4
         Ph4fHj+cQiNdjzeIGmYos9RhG/ePZrxP4ol3Gjd2rubw9bGmJ6vxpwK9NmXhFrWC1MNe
         jl/Xxgf0lMuKAr5jX54TgmN4S8AgH4u9LuIKOnB4Nz90ROI8OJRzl86+UfMsm/HHv3Fc
         1PYB71uXzYEC49Wi0+RBvVkcSlaUoXtUzQYmB177Yo/RYmhhpKFRf0VL3mIjk7LWcMte
         IZhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Drk11FQiiBMEtrfW9/M48Q99qTus2Kx6p9Nmb9b9aEw=;
        b=F+4HgiTXQ5s73x4YbCcTwVPNOJm0qLrgL69vuXv8cbjR24EARpYJRgDRjGQ3AVuPSV
         NT0Ysxu8kM9VQM41do7HSRnxMwd/ROz+16HWtYPqKoEqG2cNIOAKlnlrgB+pokv7mAmB
         e9dJhohsdv8aieR6yQT9/66YtOZXYgvPWn6nAUPVtS56udChDWB07qJwAnq0Lj9Vez7b
         icVA6VrNUfe9VpbNg6m8zO7LPedBmrsRgM/h+Bk8kTD/2swUOpuAWKbkZkeTQGmTb+XG
         o8MuC1h6hCC1tvZCj7VHLmS0sx/hOwo44UBYIrbRPikaUQey/MlHWaWHCcP4I6TwmZt6
         pBeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@alien8.de header.s=dkim header.b=PbmjpkhP;
       spf=pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) smtp.mailfrom=bp@alien8.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alien8.de
Received: from mail.skyhub.de (mail.skyhub.de. [2a01:4f8:190:11c2::b:1457])
        by gmr-mx.google.com with ESMTPS id l26si779092ejr.0.2019.11.18.06.21.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 18 Nov 2019 06:21:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bp@alien8.de designates 2a01:4f8:190:11c2::b:1457 as permitted sender) client-ip=2a01:4f8:190:11c2::b:1457;
Received: from zn.tnic (p200300EC2F27B50084A11D83797EBEC7.dip0.t-ipconnect.de [IPv6:2003:ec:2f27:b500:84a1:1d83:797e:bec7])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.skyhub.de (SuperMail on ZX Spectrum 128k) with ESMTPSA id 637F91EC027B;
	Mon, 18 Nov 2019 15:21:48 +0100 (CET)
Date: Mon, 18 Nov 2019 15:21:44 +0100
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
Subject: Re: [PATCH v2 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191118142144.GC6363@zn.tnic>
References: <20191115191728.87338-1-jannh@google.com>
 <20191115191728.87338-2-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191115191728.87338-2-jannh@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: bp@alien8.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@alien8.de header.s=dkim header.b=PbmjpkhP;       spf=pass
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

On Fri, Nov 15, 2019 at 08:17:27PM +0100, Jann Horn wrote:
>  dotraplinkage void
>  do_general_protection(struct pt_regs *regs, long error_code)
>  {
> @@ -547,8 +581,15 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  			return;
>  
>  		if (notify_die(DIE_GPF, desc, regs, error_code,
> -			       X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
> -			die(desc, regs, error_code);
> +			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
> +			return;
> +
> +		if (error_code)
> +			pr_alert("GPF is segment-related (see error code)\n");
> +		else
> +			print_kernel_gp_address(regs);
> +
> +		die(desc, regs, error_code);

Right, this way, those messages appear before the main "general
protection ..." message:

[    2.434372] traps: probably dereferencing non-canonical address 0xdfff000000000001
[    2.442492] general protection fault: 0000 [#1] PREEMPT SMP

Can we glue/merge them together? Or is this going to confuse tools too much:

[    2.542218] general protection fault while derefing a non-canonical address 0xdfff000000000001: 0000 [#1] PREEMPT SMP

(and that sentence could be shorter too:

 	"general protection fault for non-canonical address 0xdfff000000000001"

looks ok to me too.)

Here's a dirty diff together with a reproducer ontop of yours:

---
diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
index bf796f8c9998..dab702ba28a6 100644
--- a/arch/x86/kernel/traps.c
+++ b/arch/x86/kernel/traps.c
@@ -515,7 +515,7 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
  * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
  * address, print that address.
  */
-static void print_kernel_gp_address(struct pt_regs *regs)
+static unsigned long get_kernel_gp_address(struct pt_regs *regs)
 {
 #ifdef CONFIG_X86_64
 	u8 insn_bytes[MAX_INSN_SIZE];
@@ -523,7 +523,7 @@ static void print_kernel_gp_address(struct pt_regs *regs)
 	unsigned long addr_ref;
 
 	if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
-		return;
+		return 0;
 
 	kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
 	insn_get_modrm(&insn);
@@ -532,22 +532,22 @@ static void print_kernel_gp_address(struct pt_regs *regs)
 
 	/* Bail out if insn_get_addr_ref() failed or we got a kernel address. */
 	if (addr_ref >= ~__VIRTUAL_MASK)
-		return;
+		return 0;
 
 	/* Bail out if the entire operand is in the canonical user half. */
 	if (addr_ref + insn.opnd_bytes - 1 <= __VIRTUAL_MASK)
-		return;
+		return 0;
 
-	pr_alert("probably dereferencing non-canonical address 0x%016lx\n",
-		 addr_ref);
+	return addr_ref;
 #endif
 }
 
+#define GPFSTR "general protection fault"
 dotraplinkage void
 do_general_protection(struct pt_regs *regs, long error_code)
 {
-	const char *desc = "general protection fault";
 	struct task_struct *tsk;
+	char desc[90];
 
 	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
 	cond_local_irq_enable(regs);
@@ -584,12 +584,18 @@ do_general_protection(struct pt_regs *regs, long error_code)
 			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
 			return;
 
-		if (error_code)
-			pr_alert("GPF is segment-related (see error code)\n");
-		else
-			print_kernel_gp_address(regs);
+		if (error_code) {
+			snprintf(desc, 90, "segment-related " GPFSTR);
+		} else {
+			unsigned long addr_ref = get_kernel_gp_address(regs);
+
+			if (addr_ref)
+				snprintf(desc, 90, GPFSTR " while derefing a non-canonical address 0x%lx", addr_ref);
+			else
+				snprintf(desc, 90, GPFSTR);
+		}
 
-		die(desc, regs, error_code);
+		die((const char *)desc, regs, error_code);
 		return;
 	}
 
diff --git a/init/main.c b/init/main.c
index 91f6ebb30ef0..7acc7e660be9 100644
--- a/init/main.c
+++ b/init/main.c
@@ -1124,6 +1124,9 @@ static int __ref kernel_init(void *unused)
 
 	rcu_end_inkernel_boot();
 
+	asm volatile("mov $0xdfff000000000001, %rax\n\t"
+		     "jmpq *%rax\n\t");
+
 	if (ramdisk_execute_command) {
 		ret = run_init_process(ramdisk_execute_command);
 		if (!ret)

-- 
Regards/Gruss,
    Boris.

https://people.kernel.org/tglx/notes-about-netiquette

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191118142144.GC6363%40zn.tnic.
