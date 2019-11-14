Return-Path: <kasan-dev+bncBDN5FEVB5YIRB55FW3XAKGQEVOZANWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 21694FCC14
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 18:46:33 +0100 (CET)
Received: by mail-pg1-x540.google.com with SMTP id u11sf5052077pgm.20
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 09:46:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573753591; cv=pass;
        d=google.com; s=arc-20160816;
        b=HI6IgXjmc88GZa34dhUf87UFk0VWfNrHVou5o1V2nLjLH7lSyIBF3IxlKkUAm2+8uA
         ERqGSsjhhkxEyLIUXnAfO3pANYEpd2QU+m8LUbwfHVMSEGpClRSOq9nYVbDcaYEh20tb
         hkt7WJtEe4T5yguM9zZOynOOWFDDKE/bDQgllm03wtZum4+AUKA8dCCAmU4I1njPaLKU
         mZQFSPyQa+hvmb7xpCumvladUKb4w/uMIqKY0PAFpMq1PjH/GXuTIXUvFMdW5XIPUAks
         G5Eu1JhZO0YVAvLfJxYFB6V2OIdt0aFqRf7Irwxvv7pG5yHWFbtmSJWFRdivVgY9zuVi
         1d1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=d5VCAWY5t7Kjgxur3uML3N1E+G/mTF8/TvYHW4d2W+E=;
        b=WIbHpgAG4/1rTMg7drX3dXnkBt8KSluGG7K1QZ+LdK8u1lL7fp9KCsgkLk8BP5aW41
         tyEvBuKvora+zavpG+gDEY7btPk9SFqlV6fCENWmafALr3MiCIJaamPIc47Iu2h0prGF
         Kl2hxcPSsCmxi+9BoONxpJB+c09iVqCQUZX9Uf21rJGt/Y3mHAJPDjE5y4o0P84PPy2B
         f4+zyuqY7nQf7HyQ/0k++pThk1nIzel4/3P2yv4YO9V1a4bBHfQX9EgX9Bk9PkZjj5KA
         Mt4iikUMu10f8CaGtPp5ohTB/DRQf0jU03wpFHBDX14lVHURO64hsAgQINfG/dx77XsQ
         +R3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=d5VCAWY5t7Kjgxur3uML3N1E+G/mTF8/TvYHW4d2W+E=;
        b=UnsSHLBk7D8bV0lHxGHQpR6tFp/+5uvFxkqTifpt4jBvXy49BDHx+0owNBp8nNoyaw
         Su4k2CCcjqFUgzpMND6e1mMLwVIUAowZrcqFqGQyMGszy8qqg3QtfSQObZsGdpH1ALjM
         VDtJh+TcOdB16g7VKs33bkLxY/7Zjf2qjfMrxSKYp3gaCNmnkqjdXwoH19ypsHtz7bdL
         ZmuXQ5r49zaAyi3SA4QY5s981uZFYsR33y+c6n3dVd4QR7y/qAjdXaQnX7oJoCh6jT1s
         hZZzajXru2/YjF0EM2B0u9EWW40m9wTxt1n8G+RkUl9woPS7QEGACI0bVENCw80pdPpT
         VaSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=d5VCAWY5t7Kjgxur3uML3N1E+G/mTF8/TvYHW4d2W+E=;
        b=uI6KSdig0mf4U10bqUdndOh+AQ9BRH6L8EGYSwUuNZwyN0R7idCGzWprrb62lfl97P
         NBS+30caxUnjIXd8E41g1b0BkIDen/TMVoJQKDtjGYbuG2bxpl61P32aUdLd2OlmGa1k
         kTUMBa3rgSsf3uMbyrJ4oJhEPfZtLRqsYrgUm/VCNo9myT32EBMzzU6eQc4Xiiqo2SdO
         DVpKFQX+dAb/mVxkwRJZ7qU185QAYHJomvIKOeO+yqdaAxjBQJj/UI2ya44b80jknfr0
         QJ6b+/TlkA2uTj35x9drW2F4FI07MXxrUN1pcsb7qhC8LkmfZLNnmbpXrpXXQrjakjyL
         0xuA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXV+Gk5GrEa5ByTOOF5fxGDoar0hIRmZ4BdXMbeUuvzmho+2UJd
	F2+YyQGb2KZn0sTgDaNMSyM=
X-Google-Smtp-Source: APXvYqxDWDsrnrZCZROaHt8dND7sF6DOt6g9td516523Ln+m8XltlzVLMYx5F8LozReM0cDGRi6Fpg==
X-Received: by 2002:a17:902:6b0c:: with SMTP id o12mr10770565plk.284.1573753591715;
        Thu, 14 Nov 2019 09:46:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7c8b:: with SMTP id x133ls890491pfc.8.gmail; Thu, 14 Nov
 2019 09:46:31 -0800 (PST)
X-Received: by 2002:a65:620d:: with SMTP id d13mr11752338pgv.64.1573753591189;
        Thu, 14 Nov 2019 09:46:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573753591; cv=none;
        d=google.com; s=arc-20160816;
        b=ADcFbVxsHoSZWlqo1fKAPinD3MRYLDnZAoOZK61UhfdqYJZYeW1gkMK5vXZl6pWFZo
         UgVHtt6nZtKDbcxrjwSDSkimnko7pdzuFE2Jp1PwUtWMBWg3ohB0EYtJNOpsObvEsFUU
         h9Uqf6E0qzxoI1+3Wf4Ku27Aa4s4dv2o4UqiPullh15nwlGOwGOAkoLo7LNmhj2C9UKf
         guAvrF/sQqqnrpuIqK2lOHWxo0JWcpk0U8lk1SGCFf4RJzSXq17JT6V8c2NddnLhqnf7
         ocogxWvmmWLF9bWcBJFdrV+qtSmIF+HlEwbzpu7URf9GVtsd7CYCnCy5OdNM+VRfhSFn
         arWQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=LeoTExE9imsUZ3XsikQnWMnoIA4wifUPviN/O6s6YkI=;
        b=t6enNSUtesvQ5t1XECfEfJ432GY1QcVQ5uzBnH8hrPoR48KrgEURJL+ytSudtINrWN
         /vM2lC9qCvTHBVtFzxa6u6U04tBdCKL+dcf4YroAtZizs2Yw7bcibS7yTgDcAPwqMIgG
         Ssgu9j+zPbE3Rr5DPEP5jrxi89nMFJeU+/7KW8+Os6d3jXJ2FQS/NzvHvfjER/IY+9wb
         HcRUVoI29GKSGZQp8k5C7dDYCP9+bicd6bhrG/RqvWPfopDZ33rsLhwagMVHyRJmJ3Gd
         fT6X0qXhtWNXeSV3jxGG+Zy5Xhk1icTVPmGM7mcsaeIZf+4zZEtPXYqZYfpG2ru+JnYA
         Qw5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.43 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga05.intel.com (mga05.intel.com. [192.55.52.43])
        by gmr-mx.google.com with ESMTPS id q196si235861pfc.0.2019.11.14.09.46.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 09:46:31 -0800 (PST)
Received-SPF: pass (google.com: domain of sean.j.christopherson@intel.com designates 192.55.52.43 as permitted sender) client-ip=192.55.52.43;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from orsmga003.jf.intel.com ([10.7.209.27])
  by fmsmga105.fm.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 14 Nov 2019 09:46:30 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.68,304,1569308400"; 
   d="scan'208";a="207868279"
Received: from sjchrist-coffee.jf.intel.com (HELO linux.intel.com) ([10.54.74.41])
  by orsmga003.jf.intel.com with ESMTP; 14 Nov 2019 09:46:30 -0800
Date: Thu, 14 Nov 2019 09:46:30 -0800
From: Sean Christopherson <sean.j.christopherson@intel.com>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 2/3] x86/traps: Print non-canonical address on #GP
Message-ID: <20191114174630.GF24045@linux.intel.com>
References: <20191112211002.128278-1-jannh@google.com>
 <20191112211002.128278-2-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191112211002.128278-2-jannh@google.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Original-Sender: sean.j.christopherson@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sean.j.christopherson@intel.com designates
 192.55.52.43 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Tue, Nov 12, 2019 at 10:10:01PM +0100, Jann Horn wrote:
> A frequent cause of #GP exceptions are memory accesses to non-canonical
> addresses. Unlike #PF, #GP doesn't come with a fault address in CR2, so
> the kernel doesn't currently print the fault address for #GP.
> Luckily, we already have the necessary infrastructure for decoding X86
> instructions and computing the memory address that is being accessed;
> hook it up to the #GP handler so that we can figure out whether the #GP
> looks like it was caused by a non-canonical address, and if so, print
> that address.
> 
> While it is already possible to compute the faulting address manually by
> disassembling the opcode dump and evaluating the instruction against the
> register dump, this should make it slightly easier to identify crashes
> at a glance.
> 
> Signed-off-by: Jann Horn <jannh@google.com>
> ---
>  arch/x86/kernel/traps.c | 45 +++++++++++++++++++++++++++++++++++++++--
>  1 file changed, 43 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> index c90312146da0..479cfc6e9507 100644
> --- a/arch/x86/kernel/traps.c
> +++ b/arch/x86/kernel/traps.c
> @@ -56,6 +56,8 @@
>  #include <asm/mpx.h>
>  #include <asm/vm86.h>
>  #include <asm/umip.h>
> +#include <asm/insn.h>
> +#include <asm/insn-eval.h>
>  
>  #ifdef CONFIG_X86_64
>  #include <asm/x86_init.h>
> @@ -509,6 +511,42 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
>  	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
>  }
>  
> +/*
> + * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> + * address, print that address.
> + */
> +static void print_kernel_gp_address(struct pt_regs *regs)
> +{
> +#ifdef CONFIG_X86_64
> +	u8 insn_bytes[MAX_INSN_SIZE];
> +	struct insn insn;
> +	unsigned long addr_ref;
> +
> +	if (probe_kernel_read(insn_bytes, (void *)regs->ip, MAX_INSN_SIZE))
> +		return;
> +
> +	kernel_insn_init(&insn, insn_bytes, MAX_INSN_SIZE);
> +	insn_get_modrm(&insn);
> +	insn_get_sib(&insn);
> +	addr_ref = (unsigned long)insn_get_addr_ref(&insn, regs);
> +
> +	/*
> +	 * If insn_get_addr_ref() failed or we got a canonical address in the
> +	 * kernel half, bail out.
> +	 */
> +	if ((addr_ref | __VIRTUAL_MASK) == ~0UL)
> +		return;
> +	/*
> +	 * For the user half, check against TASK_SIZE_MAX; this way, if the
> +	 * access crosses the canonical address boundary, we don't miss it.
> +	 */
> +	if (addr_ref <= TASK_SIZE_MAX)

Any objection to open coding the upper bound instead of using
TASK_SIZE_MASK to make the threshold more obvious?

> +		return;
> +
> +	pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);

Printing the raw address will confuse users in the case where the access
straddles the lower canonical boundary.  Maybe combine this with open
coding the straddle case?  With a rough heuristic to hedge a bit for
instructions whose operand size isn't accurately reflected in opnd_bytes.

	if (addr_ref > __VIRTUAL_MASK)
		pr_alert("dereferencing non-canonical address 0x%016lx\n", addr_ref);
	else if ((addr_ref + insn->opnd_bytes - 1) > __VIRTUAL_MASK)
		pr_alert("straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
			 addr_ref, addr_ref + insn->opnd_bytes - 1);
	else if ((addr_ref + PAGE_SIZE - 1) > __VIRTUAL_MASK)
		pr_alert("potentially straddling non-canonical boundary 0x%016lx - 0x%016lx\n",
			 addr_ref, addr_ref + PAGE_SIZE - 1);

> +#endif
> +}
> +
>  dotraplinkage void
>  do_general_protection(struct pt_regs *regs, long error_code)
>  {
> @@ -547,8 +585,11 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  			return;
>  
>  		if (notify_die(DIE_GPF, desc, regs, error_code,
> -			       X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
> -			die(desc, regs, error_code);
> +			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
> +			return;
> +
> +		print_kernel_gp_address(regs);

This can be conditional on '!error_code', non-canonical faults on the
direct access always have zero for the error code.  Doubt it will matter
in practice, but far calls and other silly segment instructions can
generate non-zero error codes on #GP in 64-bit mode.

> +		die(desc, regs, error_code);
>  		return;
>  	}
>  
> -- 
> 2.24.0.432.g9d3f5f5b63-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191114174630.GF24045%40linux.intel.com.
