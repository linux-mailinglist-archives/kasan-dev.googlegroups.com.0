Return-Path: <kasan-dev+bncBDV37XP3XYDRBLWL36WQMGQEIRFY6BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8600F84114D
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 18:51:43 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-59a10a15904sf994957eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 09:51:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706550702; cv=pass;
        d=google.com; s=arc-20160816;
        b=LWzp1/ymKq8PJJRsFM4RjzNYkjsATnMGs898fji9Lw+cWqeUaz42MXwTN98Wt/ZXPX
         /VNVCYMbYYg52nSSRQPi0tqhT5e6hqROC2zAZw4gwXCCOlNHHx2tG2dxDHmU7L9dfKrg
         sH5DZuYKvGVhj12dfJ7kQ+q/NaKJXFLPIZ+/mSUo+j8LSxvnanVrc06fJQ+PrCrmHvLT
         ntFbEyJm61Ezy6IxTkvwsAz5+joWJgypBBVYU6l2eyfmfKYJ4LArwEMRLUvdsyLmmV3f
         3aIHV5RxuH2f4BCFzxQWrpXarB89mLDByf9bYH1zvDB6smoZekjLiszMhVNhzD6JuERm
         yvTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=dVk9WoFRxvCnobqQPRpFy+OPQGAS7ikL3zi4lZMjlp0=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=jP7auTZ1VLckiKWQHloW86RbRuDsQuHIhC1CsppPOk6LFZgzws/zPyfI/ip7aywyCm
         Q+N8zf+jCLOJ7Y+q+qoqn3jPi1fOfcSnqxLuu1T2IheFurSI2lgbiw2zEChCZ7EAmlnk
         Bc+YvLnX+vVZnm/9ros59fJ9ArWYagv0fktzZMWk6nZlj4Fy+5lEnPxCJVBeB3+yMSiz
         gh6oPqIol/uyGHnDQ9GV3kZrDKlv2NcoVwRfXrLqIbWJGtxpqNR3cPByft+cTqJAjgSn
         nBRrLc3xTJ/BVpVPUJygrQ5/3rJtmlo7AgcZStAK3NhmOIwugBsUhvkL+2B6abMHvuS2
         Z1Lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706550702; x=1707155502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dVk9WoFRxvCnobqQPRpFy+OPQGAS7ikL3zi4lZMjlp0=;
        b=H/QqqgY2/9gAhP59sIocuXcYvIcdu0ZZbucr6NGi4hV2G7tDMOgR1uhuhsaDw/MPHT
         Fr0sR+hJul6R2EB+Ovimcu3q6bVYwozv5Qaiw/oa0fvffsSzklxAk1i/+vL9rclByIpM
         yTgtz9mH6ob64BdRm786ymY7Mjjuc2D6f9wVTBKkq/hOFpZoZd9M5/uPJjWpMK8wbYGS
         eXWq+OzqqoSELolp/8YmXUUDgXmJET4r1xflsxMqTY8lLkeVGYmEdr9TWoxjfXUeVKt6
         5Bl2cJYwrrQM4meAi1fmFLgIwB/8tYLWHkZga25smdr0CO2xwHc2k67E9V2xDwKaQYKb
         Tp/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706550702; x=1707155502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dVk9WoFRxvCnobqQPRpFy+OPQGAS7ikL3zi4lZMjlp0=;
        b=CELel5rSY04Zv+ypjfKMJmZHEMBDkNcb3POQYpa8AMr4lSXcHRYLuJyemRzoBl92u1
         hnvM+xGhLQY8riUZeH9WNc8RiXqJrwuUz25DhSPfhQT/uPIQDhys9XkirWP+OvlY62a4
         GvcNJd1uQaUL0WhE0+uN0j9YzYsNn/88cFX1vSGkBRPiCqYpOHv4cy1jjQxUW/qtzqMm
         mcn3uT09JS+Ht7WlXSZvMt/ImloKUk6xtA2ASYct3prbhlv5mbMIY8s/0iLM08AnSmfH
         0OrjiJONxokAFshRQlwx4BejBRgjYef/b0uC8fPkBEJs9kZ9qB1GSgxqSNJhFZMdQnoD
         pECg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxVFn3yw81DL4M3DBrm+JEKPPfWXDLqmc1bfpnsBi4dwJ3QXELV
	I02JW8f6z65gIQPrDLUce5RRspqXDWA2hX5ueztWn09h3mZiKm+f
X-Google-Smtp-Source: AGHT+IEKxlfRoAiQRurT/YDWLJlGsl73WlFoKrYq/sHxQyApt29CasZNPMycU7xfkSnvrhCM2wn7gw==
X-Received: by 2002:a05:6870:a2c9:b0:210:d66c:7c27 with SMTP id w9-20020a056870a2c900b00210d66c7c27mr7478756oak.2.1706550702259;
        Mon, 29 Jan 2024 09:51:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:aa0a:b0:210:e69e:e8b9 with SMTP id
 gv10-20020a056870aa0a00b00210e69ee8b9ls2854902oab.0.-pod-prod-06-us; Mon, 29
 Jan 2024 09:51:41 -0800 (PST)
X-Received: by 2002:a05:6870:1f12:b0:218:4bea:dcf2 with SMTP id pd18-20020a0568701f1200b002184beadcf2mr2661366oab.55.1706550701352;
        Mon, 29 Jan 2024 09:51:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706550701; cv=none;
        d=google.com; s=arc-20160816;
        b=oPQ+vPfXNivy3IY3mI49d3Ij+aPQyQhMaus3tK1Oj8lLqjNEGEN/4Sd9oIpJD9tl1b
         +HSH9laj+Ix2VXdU/NgoU7E5yw4bTD6eeW3LHUjVYUm/5l8zHo/PyUTt2zPMAyoyIzl9
         afC4X7x/Gz9kJCJpx1HL+lU5wWD7YELOt/d0tpEWpgEX4c6pN7qAuF5A0Ji0fGwqxkS4
         +pvHbNQqaHrURRjT4evsdyfhsu5ft/F4vJKxl11Tb8+QWII2eqvXyF/UGAtP19edLFsO
         a9KZWG8K6jVyMUSedErVrHv9CXavwo7bli5mtox/AQcnIDcpzc109Jt4shC4b4VWeBMK
         s8JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=I0VIBDd6DfErdAISdojY5I2FhLvS5SkKrjLxLsHHdNU=;
        fh=xeCn5p7qRGCkWwGqNIxKhkXzb8rbqE1yupV31i+mXW8=;
        b=y9BWR5mC3tL2jy0ECUnbErgOKhQZ9OMAZARC+wKLeLcIgIpBlVJ6HtTEiGgtUAFKxa
         voITgB8hXUVesgGQYB0DFvmxT3dvNzFNSdo93lG2jJPVaNd6romePtu6S73ZjS4EEqy2
         bmsBaP+nbuHU8lLHK1qp+vAbg9Et9/iOHDpTDFNdMIWhUeUVlStuF1caMujhElhDfh0U
         Dcdac0weDDXAWv/0l1a/UBNyexpcTchhb/LnshikG8PxXXmyf3XUNrMDMo4K3GrauTgc
         fsg1MysqSiSXLlNEz1TcapUzj+s70wN7Lc8K0Ba9dA4glLxkx2BN8l351j+Vz0ruMI0p
         ulXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id fu20-20020a0568705d9400b00215d04848eesi1037034oab.1.2024.01.29.09.51.41
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Jan 2024 09:51:41 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 58831139F;
	Mon, 29 Jan 2024 09:52:24 -0800 (PST)
Received: from FVFF77S0Q05N (unknown [10.57.48.128])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 529603F738;
	Mon, 29 Jan 2024 09:51:36 -0800 (PST)
Date: Mon, 29 Jan 2024 17:51:33 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>, James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v10 2/6] arm64: add support for machine check error safe
Message-ID: <ZbflpQV7aVry0qPz@FVFF77S0Q05N>
References: <20240129134652.4004931-1-tongtiangen@huawei.com>
 <20240129134652.4004931-3-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240129134652.4004931-3-tongtiangen@huawei.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Mon, Jan 29, 2024 at 09:46:48PM +0800, Tong Tiangen wrote:
> For the arm64 kernel, when it processes hardware memory errors for
> synchronize notifications(do_sea()), if the errors is consumed within the
> kernel, the current processing is panic. However, it is not optimal.
> 
> Take uaccess for example, if the uaccess operation fails due to memory
> error, only the user process will be affected. Killing the user process and
> isolating the corrupt page is a better choice.
> 
> This patch only enable machine error check framework and adds an exception
> fixup before the kernel panic in do_sea().
> 
> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
> ---
>  arch/arm64/Kconfig               |  1 +
>  arch/arm64/include/asm/extable.h |  1 +
>  arch/arm64/mm/extable.c          | 16 ++++++++++++++++
>  arch/arm64/mm/fault.c            | 29 ++++++++++++++++++++++++++++-
>  4 files changed, 46 insertions(+), 1 deletion(-)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index aa7c1d435139..2cc34b5e7abb 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -20,6 +20,7 @@ config ARM64
>  	select ARCH_ENABLE_SPLIT_PMD_PTLOCK if PGTABLE_LEVELS > 2
>  	select ARCH_ENABLE_THP_MIGRATION if TRANSPARENT_HUGEPAGE
>  	select ARCH_HAS_CACHE_LINE_SIZE
> +	select ARCH_HAS_COPY_MC if ACPI_APEI_GHES
>  	select ARCH_HAS_CURRENT_STACK_POINTER
>  	select ARCH_HAS_DEBUG_VIRTUAL
>  	select ARCH_HAS_DEBUG_VM_PGTABLE
> diff --git a/arch/arm64/include/asm/extable.h b/arch/arm64/include/asm/extable.h
> index 72b0e71cc3de..f80ebd0addfd 100644
> --- a/arch/arm64/include/asm/extable.h
> +++ b/arch/arm64/include/asm/extable.h
> @@ -46,4 +46,5 @@ bool ex_handler_bpf(const struct exception_table_entry *ex,
>  #endif /* !CONFIG_BPF_JIT */
>  
>  bool fixup_exception(struct pt_regs *regs);
> +bool fixup_exception_mc(struct pt_regs *regs);
>  #endif
> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
> index 228d681a8715..478e639f8680 100644
> --- a/arch/arm64/mm/extable.c
> +++ b/arch/arm64/mm/extable.c
> @@ -76,3 +76,19 @@ bool fixup_exception(struct pt_regs *regs)
>  
>  	BUG();
>  }
> +
> +bool fixup_exception_mc(struct pt_regs *regs)

Can we please replace 'mc' with something like 'memory_error' ?

There's no "machine check" on arm64, and 'mc' is opaque regardless.

> +{
> +	const struct exception_table_entry *ex;
> +
> +	ex = search_exception_tables(instruction_pointer(regs));
> +	if (!ex)
> +		return false;
> +
> +	/*
> +	 * This is not complete, More Machine check safe extable type can
> +	 * be processed here.
> +	 */
> +
> +	return false;
> +}

As with my comment on the subsequenty patch, I'd much prefer that we handle
EX_TYPE_UACCESS_ERR_ZERO from the outset.



> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index 55f6455a8284..312932dc100b 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -730,6 +730,31 @@ static int do_bad(unsigned long far, unsigned long esr, struct pt_regs *regs)
>  	return 1; /* "fault" */
>  }
>  
> +static bool arm64_do_kernel_sea(unsigned long addr, unsigned int esr,
> +				     struct pt_regs *regs, int sig, int code)
> +{
> +	if (!IS_ENABLED(CONFIG_ARCH_HAS_COPY_MC))
> +		return false;
> +
> +	if (user_mode(regs))
> +		return false;

This function is called "arm64_do_kernel_sea"; surely the caller should *never*
call this for a SEA taken from user mode?

> +
> +	if (apei_claim_sea(regs) < 0)
> +		return false;
> +
> +	if (!fixup_exception_mc(regs))
> +		return false;
> +
> +	if (current->flags & PF_KTHREAD)
> +		return true;

I think this needs a comment; why do we allow kthreads to go on, yet kill user
threads? What about helper threads (e.g. for io_uring)?

> +
> +	set_thread_esr(0, esr);

Why do we set the ESR to 0?

Mark.

> +	arm64_force_sig_fault(sig, code, addr,
> +		"Uncorrected memory error on access to user memory\n");
> +
> +	return true;
> +}
> +
>  static int do_sea(unsigned long far, unsigned long esr, struct pt_regs *regs)
>  {
>  	const struct fault_info *inf;
> @@ -755,7 +780,9 @@ static int do_sea(unsigned long far, unsigned long esr, struct pt_regs *regs)
>  		 */
>  		siaddr  = untagged_addr(far);
>  	}
> -	arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, esr);
> +
> +	if (!arm64_do_kernel_sea(siaddr, esr, regs, inf->sig, inf->code))
> +		arm64_notify_die(inf->name, regs, inf->sig, inf->code, siaddr, esr);
>  
>  	return 0;
>  }
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZbflpQV7aVry0qPz%40FVFF77S0Q05N.
