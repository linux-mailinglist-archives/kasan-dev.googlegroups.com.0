Return-Path: <kasan-dev+bncBDN5FEVB5YIRBL6C23XAKGQEMNMHHDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A8261044FB
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 21:25:21 +0100 (CET)
Received: by mail-ua1-x938.google.com with SMTP id b19sf231290uak.5
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 12:25:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574281520; cv=pass;
        d=google.com; s=arc-20160816;
        b=0gKhHPqWPlogthO3Zzv0Ca1S7IAiCV96y0bFZOQ/x//C7d8h0l39TaM88tXaP88lfP
         VDos5RcF6Psn4l950TQESpQgFMrDcBAfL4qp1l/RMzr2tby3hjBwEBzODB2snEhsFsVf
         U7KfPaf6o1jY9iOZ7/rcXGWkT+Q9qr16U7Oe7Sc14qMKuQNuLQeylMHg9b8PnY28sPu+
         xP3nAg1wDngk2D6x/LWsRv3xpf5DhaL63xS+v06pW/UugzBavj+lx+WM+cEHmXTIYfH/
         FHNW4L9/K4yjchmBy7Xz9OQH42JHGaVGSy3yaRmJTZ07Mj148Tygsy6KIpPLV0kk89pP
         2LpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=eVe8dVcnBuesToqe2+3gdQN76s3hKwwhxY7ufZdB+iQ=;
        b=g4EOtHe2a9YQv5yGINWvGGjocRVe5Ejsw8slZLWj86JRdeaMZQWMu89uFf1Hz8Xb2A
         Yz8fEdwGN94WURVUdnvoNL5iVcR3ZQPiBy1C2AE9VWH2bkLkrGBhVzu3g0gmL7I0N6Vb
         XOw8C1fBeVGRlzo21OgOgkNS2VOS4e7kHEWDWD+1PRLQ2vkQc0/p5t//xtK4ickikoG4
         /elN2+RweE9ok6ep2+p7qDZJVmOjuzeysUxJapVTzYfbYezTLUDZC8a9ev8Kp4iEu8rK
         sRwUn0esv6ENrnoF3cm9Pa3X8wxgVWNwvev71FS440dVPRgisxfVSRHg7b5B3EseDVfN
         B+MA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=eVe8dVcnBuesToqe2+3gdQN76s3hKwwhxY7ufZdB+iQ=;
        b=LUoDIbGp5XoD/aKp3c2Fv2OofldG6RJno+GzCjDbzDVJKaE2uP4QdLybu8lPILVoco
         8WIagyqM4iZfSsAf3hhQX7cxRxDQw3QY+gmvn6wvVPJYNCy5WE4RSaK6CMLDFXS/n3Ox
         zSpdUkJXgOBxUJyJMZeTvziLxnKWYdaZDvPLUrZoFnrHBcPXRw+IuZIxuHHDkyMAN+E7
         YXmq5GCHToZgn5DsFPTrEYDdItZMABjymRMzh9BYQ5LvWAOt5BOaf6FToadDyOIfZZXO
         NU6xpEMkJTBm79Oc0iGsMnbSiRsrvTZnDxO6HCA3XlO1CA6eyVpQNkiXw1zNRgDdvkk3
         I2fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=eVe8dVcnBuesToqe2+3gdQN76s3hKwwhxY7ufZdB+iQ=;
        b=BKxQQWMN3HQqqxcE2Gmlr2sP5RvbIQitGJstRjWSgYZfdO01bEokBuuGPcbYut5RzF
         odn2bLSpfuOSrF2OQCE3iAeMeT4oYBnrVPkyPmC/KgUF6wJFw325NTVGAfGMrY+5JSND
         BPNkqEx0wovNFI3WBfL5FZaUceFyo0nSjBUlNRM6EadgC1L0AvJ/fswDkn4/iVmlSchw
         7olNwC9n34cfXuPR7FkabYJLOZTvQ7N1PE0DgLdh+krUs7AT/wWsS41z0VCkqqJ5Yc5o
         V/zbnLhlzaKSjHg9imbLcAwvAWMMu3XYh2POx6YwrqyIubI4116ZZU7hbNzjw/WsoNBC
         Jv0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU4xO45YN/oyhLDgcpGM8CLUlzXy5XdmF2QhLOtIWtssPraDuHZ
	rtliiv1dThoRW9GEgQt4oGA=
X-Google-Smtp-Source: APXvYqwqnCG0elxXrSu0jfXLCfwXGHRQau7OgqTnVO77lekKKFiN1jAe8Qy78Lov5UUysXZVXabsiA==
X-Received: by 2002:a05:6102:50c:: with SMTP id l12mr3330783vsa.178.1574281520012;
        Wed, 20 Nov 2019 12:25:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3dc1:: with SMTP id e1ls271915uaj.12.gmail; Wed, 20 Nov
 2019 12:25:19 -0800 (PST)
X-Received: by 2002:ab0:2805:: with SMTP id w5mr3093061uap.7.1574281519638;
        Wed, 20 Nov 2019 12:25:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574281519; cv=none;
        d=google.com; s=arc-20160816;
        b=lMVEP+/cydZ83cZS73L426/rEh88uGROjEpa9ND3Wmyp4x5fFqv1rhD/dtSQChQS+F
         D2mcEcPIRKjh8q0ZUjXKJ2Gnmmr+OtF7uMT68PMNp4xZOGB6DzLiW5VkNJqhXEZWPTz5
         cMMZLDdtaRP4AhNIs6VzkVYv/sXKX4KyxCJFL6NkrqCwqxu6l2IyP4J4IKuWWYndITfJ
         dTPzn1x+2N3WUzy3tnY5vdmIH0RAg61vmm6wmnIxizDWitG8NFCYljaB95zxlJKvY5Ky
         sMRZMgr9Z19WQJ9loRsivjtH5nBG3eJgygTSIKjFnUVEv9u7n3HjW/wCiXUzc9AbxGbK
         1Pww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=/5B74Sfh7NXBwEAmeO0YvZMpwZO1aDqPQjo2fRDe1Lw=;
        b=FTx8VbYjyUYrG+t7semK9eo8PyHmQ5Vvu8BVeHHSbY6DeAyCZ02oF2yiXYws8ViiSw
         Od9cDiO5FMRCisBge28DdmIKb7Af+rij9b4kqXscgJ6bWE9VRDCcawB04/PbEVuVkKHu
         m7zM87PAcgJlojqW2hAbnVbfcYK6x0O7GU8ycwuBEj3oYgEelN0aiwef3Nx0SBMJNvKH
         AXXFKGSXtjcjPVtSNayHhD91KudlarBZsMrhPleqI5RasUotBNsypLMud2HwYule5IWL
         eTNw6O0RhsUCZ3aDfmRde8LcNhwG7QEGmWb45tVm8SpB9TjKWKG3I3H8jKHu1OA757cc
         jbfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.31 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga06.intel.com (mga06.intel.com. [134.134.136.31])
        by gmr-mx.google.com with ESMTPS id p21si27791vsf.2.2019.11.20.12.25.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 Nov 2019 12:25:18 -0800 (PST)
Received-SPF: pass (google.com: domain of sean.j.christopherson@intel.com designates 134.134.136.31 as permitted sender) client-ip=134.134.136.31;
X-Amp-Result: UNKNOWN
X-Amp-Original-Verdict: FILE UNKNOWN
X-Amp-File-Uploaded: False
Received: from orsmga005.jf.intel.com ([10.7.209.41])
  by orsmga104.jf.intel.com with ESMTP/TLS/DHE-RSA-AES256-GCM-SHA384; 20 Nov 2019 12:25:17 -0800
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.69,223,1571727600"; 
   d="scan'208";a="381490714"
Received: from sjchrist-coffee.jf.intel.com (HELO linux.intel.com) ([10.54.74.41])
  by orsmga005.jf.intel.com with ESMTP; 20 Nov 2019 12:25:16 -0800
Date: Wed, 20 Nov 2019 12:25:16 -0800
From: Sean Christopherson <sean.j.christopherson@intel.com>
To: Jann Horn <jannh@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>
Subject: Re: [PATCH v4 2/4] x86/traps: Print non-canonical address on #GP
Message-ID: <20191120202516.GD32572@linux.intel.com>
References: <20191120170208.211997-1-jannh@google.com>
 <20191120170208.211997-2-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191120170208.211997-2-jannh@google.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Original-Sender: sean.j.christopherson@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of sean.j.christopherson@intel.com designates
 134.134.136.31 as permitted sender) smtp.mailfrom=sean.j.christopherson@intel.com;
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

On Wed, Nov 20, 2019 at 06:02:06PM +0100, Jann Horn wrote:
> @@ -509,11 +511,50 @@ dotraplinkage void do_bounds(struct pt_regs *regs, long error_code)
>  	do_trap(X86_TRAP_BR, SIGSEGV, "bounds", regs, error_code, 0, NULL);
>  }
>  
> +/*
> + * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> + * address, return that address.

Stale comment now that it's decoding canonical addresses too.

> + */
> +static bool get_kernel_gp_address(struct pt_regs *regs, unsigned long *addr,
> +					   bool *non_canonical)

Alignment of non_canonical is funky.

> +{
> +#ifdef CONFIG_X86_64
> +	u8 insn_buf[MAX_INSN_SIZE];
> +	struct insn insn;
> +
> +	if (probe_kernel_read(insn_buf, (void *)regs->ip, MAX_INSN_SIZE))
> +		return false;
> +
> +	kernel_insn_init(&insn, insn_buf, MAX_INSN_SIZE);
> +	insn_get_modrm(&insn);
> +	insn_get_sib(&insn);
> +	*addr = (unsigned long)insn_get_addr_ref(&insn, regs);
> +
> +	if (*addr == (unsigned long)-1L)

Nit, wouldn't -1UL avoid the need to cast?

> +		return false;
> +
> +	/*
> +	 * Check that:
> +	 *  - the address is not in the kernel half or -1 (which means the
> +	 *    decoder failed to decode it)
> +	 *  - the last byte of the address is not in the user canonical half
> +	 */

This -1 part of the comment should be moved above, or probably dropped
entirely.

> +	*non_canonical = *addr < ~__VIRTUAL_MASK &&
> +			 *addr + insn.opnd_bytes - 1 > __VIRTUAL_MASK;
> +
> +	return true;
> +#else
> +	return false;
> +#endif
> +}
> +
> +#define GPFSTR "general protection fault"
> +
>  dotraplinkage void
>  do_general_protection(struct pt_regs *regs, long error_code)
>  {
> -	const char *desc = "general protection fault";
>  	struct task_struct *tsk;
> +	char desc[sizeof(GPFSTR) + 50 + 2*sizeof(unsigned long) + 1] = GPFSTR;
>  
>  	RCU_LOCKDEP_WARN(!rcu_is_watching(), "entry code didn't wake RCU");
>  	cond_local_irq_enable(regs);
> @@ -531,6 +572,10 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  
>  	tsk = current;
>  	if (!user_mode(regs)) {
> +		bool addr_resolved = false;
> +		unsigned long gp_addr;
> +		bool non_canonical;
> +
>  		if (fixup_exception(regs, X86_TRAP_GP, error_code, 0))
>  			return;
>  
> @@ -547,8 +592,21 @@ do_general_protection(struct pt_regs *regs, long error_code)
>  			return;
>  
>  		if (notify_die(DIE_GPF, desc, regs, error_code,
> -			       X86_TRAP_GP, SIGSEGV) != NOTIFY_STOP)
> -			die(desc, regs, error_code);
> +			       X86_TRAP_GP, SIGSEGV) == NOTIFY_STOP)
> +			return;
> +
> +		if (error_code)
> +			snprintf(desc, sizeof(desc), "segment-related " GPFSTR);
> +		else
> +			addr_resolved = get_kernel_gp_address(regs, &gp_addr,
> +							      &non_canonical);
> +
> +		if (addr_resolved)
> +			snprintf(desc, sizeof(desc),
> +			    GPFSTR " probably for %saddress 0x%lx",
> +			    non_canonical ? "non-canonical " : "", gp_addr);

I still think not explicitly calling out the straddle case will be
confusing, e.g.

  general protection fault probably for non-canonical address 0x7fffffffffff: 0000 [#1] SMP

versus

  general protection fault, non-canonical access 0x7fffffffffff - 0x800000000006: 0000 [#1] SMP


And for the canonical case, "probably for address" may not be all that
accurate, e.g. #GP(0) due to a instruction specific requirement is arguably
just as likely to apply to the instruction itself as it is to its memory
operand.

Rather than pass around multiple booleans, what about adding an enum and
handling everything in (a renamed) get_kernel_gp_address?  This works
especially well if address decoding is done for 32-bit as well as 64-bit,
which is probably worth doing since we're printing the address in 64-bit
even if it's canonical.  The ifdeffery is really ugly if its 64-bit only...


enum kernel_gp_hint {
	GP_NO_HINT,
	GP_SEGMENT,
	GP_NON_CANONICAL,
	GP_STRADDLE_CANONICAL,
	GP_RESOLVED_ADDR,
};
static int get_kernel_gp_hint(struct pt_regs *regs, unsigned long error_code,
			      unsigned long *addr, unsigned char *size)
{
	u8 insn_buf[MAX_INSN_SIZE];
	struct insn insn;

	if (error_code)
		return GP_SEGMENT;

	if (probe_kernel_read(insn_buf, (void *)regs->ip, MAX_INSN_SIZE))
		return false;

	kernel_insn_init(&insn, insn_buf, MAX_INSN_SIZE);
	insn_get_modrm(&insn);
	insn_get_sib(&insn);
	*addr = (unsigned long)insn_get_addr_ref(&insn, regs);
	*size = insn.opnd_bytes;

	if (*addr == -1UL)
		return GP_NO_HINT;

#ifdef CONFIG_X86_64
	if (*addr < ~__VIRTUAL_MASK && *addr > __VIRTUAL_MASK)
		return GP_NON_CANONICAL;

	if (*addr < ~__VIRTUAL_MASK &&
	    (*addr + *size - 1) > __VIRTUAL_MASK)
		return GP_STRADDLE_CANONICAL;
#endif
	return GP_RESOLVED_ADDR;
}

Then the snprintf sequence can handle each case indvidually.

		hint = get_kernel_gp_hint(regs, error_code, &addr, &size);
		if (hint == GP_SEGMENT)
			snprintf(desc, sizeof(desc),
				 GPFSTR ", for segment 0x%lx", error_code);
		else if (hint == GP_NON_CANONICAL)
			snprintf(desc, sizeof(desc),
				 GPFSTR ", non-canonical address 0x%lx", addr);
		else if (hint == GP_STRADDLE_CANONICAL)
			snprintf(desc, sizeof(desc),
				 GPFSTR ", non-canonical access 0x%lx - 0x%lx",
				 addr, addr + size - 1);
		else if (hint == GP_RESOLVED_ADDR)
			snprintf(desc, sizeof(desc),
				 GPFSTR ", possibly for access 0x%lx - 0x%lx",
				 addr, addr + size - 1);

		flags = oops_begin();
		sig = SIGSEGV;
		__die_header(desc, regs, error_code);
		if (hint == GP_NON_CANONICAL || hint == GP_STRADDLE_CANONICAL)
			kasan_non_canonical_hook(addr);
		if (__die_body(desc, regs, error_code))
			sig = 0;
		oops_end(flags, regs, sig);
		die(desc, regs, error_code);


I get that adding a print just for the straddle case is probably overkill,
but it seems silly to add all this and not make it as precise as possible.

  general protection fault, non-canonical address 0xdead000000000000: 0000 [#1] SMP
  general protection fault, non-canonical access 0x7fffffffffff - 0x800000000006: 0000 [#1] SMP
  general protection fault, possibly for address 0xffffc9000021bd90: 0000 [#1] SMP
  general protection fault, possibly for address 0xebcbde5c: 0000 [#1] SMP  // 32-bit kernel


Side topic, opnd_bytes isn't correct for instructions with fixed 64-bit
operands (Mq notation in the opcode map), which is probably an argument
against the fancy straddle logic...


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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191120202516.GD32572%40linux.intel.com.
