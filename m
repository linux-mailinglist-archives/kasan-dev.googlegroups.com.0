Return-Path: <kasan-dev+bncBDDL3KWR4EBRBVFMWO6QMGQEU4FSCJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C724A32D0B
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 18:11:51 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2fa3b466245sf27269a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 09:11:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739380309; cv=pass;
        d=google.com; s=arc-20240605;
        b=kUotBNhPeUdQvlIO5xWrziXxhyfYEK2DMXd/fw5RRirU0qMqJ9IiOe72DUi580OYz5
         LrWlKrrnuw78H9Z7H191qDsIJ7OxzXZSElqyAazUhf0gWRy2CfgaJIHsgK3AC3ZIc5V0
         w74Vg4VTLReNl/OOERrpZ+kzZjEDB+Jf8IEne9rnoyfTcpIu/kq6a5Xiwn3y1i+r3Toh
         Hm4fWFNZJgAc+WkW+Kn3emdUtf0awVMV1VUUGOpyJZKR7BP12imPBW9sBiHaJyuF9jOj
         RtrH7A1oW35uCf71qp0PUqPZKfDQo5bvBn5v0wrHPb0k4a18AwUsvaKdYeCSn93bwmGz
         4TUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YUxRXqIWzKobn0dHONmktwYFyVCbwEnL03/x75dWZKc=;
        fh=ZyE+K2t5rGu6tAWFoGrnOjT++ilqwOXOyuhNh+42tHQ=;
        b=RsXUwRHvDaxXE/MTZ0MDRgdr9EzoTttnhUSP/XMo9jayrYyK6eDrIgxSSakK3iZIO8
         E6R3IlNo9sHDUOIZP912X+y6DGCGdn9KqR+/I4Kb+oN71koHSM7z5HA8sTxCGMMwaBO7
         78pgkEV4SpH0SNF8xEpBxK96VmPnTfuzt5U3p0u6bjbeCr5ERdHrdUOggkmdydOR90Ej
         ZsZLuRVBpQwiNnaewwyxRAGfKigKGhA1gnUoBnYfhiiKErPyhUyEEtLsAi/um75gY5Vw
         AzZDNTbwbVB1aHCutqZtAr7qFqD3eTdj4NyUbLZI3bhc/6g9CjgW3qTAP0LiSH73hwT/
         7GfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739380309; x=1739985109; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YUxRXqIWzKobn0dHONmktwYFyVCbwEnL03/x75dWZKc=;
        b=pTmB+dplyZKf3EgM5ckhJHSVRQ59jlBGqnCagMn88PrZ2tF7vaMlMuS733nw6Xj5J2
         SbDuaZ2Kr5fLUKdRIHCtwXqRLsUws+/XQk82zZPsRUbhZlJi3tySeKBo+zrv6cyd6eFz
         ZeauM2Fcw8tKdeu6mlWwEJY6hIkzCmpzwYYjAioWXWuEoYCLCrZlPiz6nPIevXCNKUuu
         hstCJ3cGwVjoIVPFnGuIjq4cVpKIo95zpOKW6vw4+Mg/m5MSYqT2TiNOrCO3Dj6vMZjk
         awE+h8HNUftsPlgLVNWPmepL5W0Hnj5pAIkTAihH2pAdV6clRFhJUBqNV+n2j1RuEA6a
         6waQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739380309; x=1739985109;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YUxRXqIWzKobn0dHONmktwYFyVCbwEnL03/x75dWZKc=;
        b=WIHOp16CTukwSH++PZr9KM5f8QieFp5X8M3VoIPUM6YRgIHyIId9936hAMa7hKgaHW
         roJSirhB9QhZhGFX3+rDiAb0RN/U8mqqq8A0FKHukM/iB5C7BZHcNuZZs1qseXftDpdb
         CeJHi7bvqsQcdJE78nrQEX4uXhIaEiWABSbPjRrz1JDLYfYxGSU3Zgf0+wwKELcfGhoG
         0cvNItKl3Ijs/RHr2ktDuM6yhKd9i4moEdQKtuOTRntN36XZiXrjTmJi0+bAXjpOfBsz
         nAlm0OyB4zRHU7dRa4AOrYEYUos6jtLmMtzAaGFPD38nL4cWX1zdRAXJSsag7obFJfeR
         87ow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXlts4aiPUuAzGZ1wMCPR3AtSm4P0fECkOaQqn5uHGWljGVTvQVu6TXcroBiWw+QVDtR0dq9g==@lfdr.de
X-Gm-Message-State: AOJu0YyQZnMkuiSglTnsDHwEHHjuVdzgDiU+Jgo+t2X8g9UqtNStITiv
	BTkqFveiNOLcQoE9rng/4HZG/FdkeFQi/5kRgvvVPAik/Oal0I8X
X-Google-Smtp-Source: AGHT+IH1A2S8eZFNg/dP0yB8Z8KFLToEF7KhHj5XOhZf99OnbpbTOyXuSA/S6IX2t1UjJfymbAe/jA==
X-Received: by 2002:a05:6a00:2da7:b0:730:7885:d903 with SMTP id d2e1a72fcca58-7322c3768fbmr5727424b3a.5.1739380309002;
        Wed, 12 Feb 2025 09:11:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:4c0e:b0:732:1b75:4317 with SMTP id
 d2e1a72fcca58-7322b204e49ls1465989b3a.2.-pod-prod-09-us; Wed, 12 Feb 2025
 09:11:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVq3C+Roukx2hGNdJw6/b4509qJiRSo5GQoBvqcVBwIHkwtPGBvpHJgHKwWiw0EvminrRqhFasDKbc=@googlegroups.com
X-Received: by 2002:a05:6a00:848:b0:730:8d25:4c31 with SMTP id d2e1a72fcca58-7322c38506cmr6489883b3a.8.1739380306594;
        Wed, 12 Feb 2025 09:11:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739380306; cv=none;
        d=google.com; s=arc-20240605;
        b=PIDsv/R3c8ZMwM97QUawQigmDh23iMCqXnR2kzxsb0lsyOBkq/N5Ju4BRveTpkDb1T
         agrSQ/xl8lTWvpSmfZ1WnzLlrmUf6o3YNSjKP00v5uKqyAgCzNJUZ1y+EBsJsDAGgrRG
         S6SA0cf3Xhy9TXG4dy6wJ8wlYTO1uQAk0EBvVUHtjTQYPwMO5AX6tpbfpuRK1FmlVGmB
         n7DKBhVm/bFxJsPuYordwRxeG2jlUS3uBpduJFC4aHhD0bWWtkeoag2QZhcqNNhBLkiV
         M9sSGvoQxQpOSlIxAUsA7L8Fpcvn6ukhFtQxo5pvfOCmH2b5YohFkIiefDKWKl2DgLn2
         ERww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=UYT8AXeHwSuOZw0yu7hG8Ej/uv+EEusdL0gi3kC7KOg=;
        fh=md3ANKhaGYZbuc9iasr19RDG3GmpFkCH4nzOFRqlDfA=;
        b=GIOrXhqJxKAJ/E59DmwHjUxj3qV70Y6kSiZCs+k07K69CFVdyzT2W0oHA/5+6UOydu
         7SyjUcV7+wRWDIZuhdZ0xHcdyt+5SpHF62nIhm8FLjwnbbrX15L3l8BY2QfAYnC2Bbme
         J1N9PaRas1abiNvnub3h9MRHPUcu8JgskqtNEbLx52wSyD6H2tZP6FfyRhCSdFboHFle
         WTcHDQkf2UEwzk8UpI5J93z5UGjaBekF+unA/fEaD1TmIvOsuASOWRwEZCza6PKkroMn
         QSQalrO0GAjnMDmyVBVcojPeN5JUn3MtuThDnx6Lp4JbIFCvj95C/swghbYWUZOogB1T
         DTIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-732194ee646si197696b3a.2.2025.02.12.09.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2025 09:11:46 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 38FCFA40118;
	Wed, 12 Feb 2025 17:10:00 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 46F24C4CEDF;
	Wed, 12 Feb 2025 17:11:40 +0000 (UTC)
Date: Wed, 12 Feb 2025 17:11:37 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Tong Tiangen <tongtiangen@huawei.com>
Cc: Mark Rutland <mark.rutland@arm.com>,
	Jonathan Cameron <Jonathan.Cameron@huawei.com>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Will Deacon <will@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	James Morse <james.morse@arm.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com,
	Guohanjun <guohanjun@huawei.com>
Subject: Re: [PATCH v13 4/5] arm64: support copy_mc_[user]_highpage()
Message-ID: <Z6zWSXzKctkpyH7-@arm.com>
References: <20241209024257.3618492-1-tongtiangen@huawei.com>
 <20241209024257.3618492-5-tongtiangen@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20241209024257.3618492-5-tongtiangen@huawei.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:45d1:ec00::3
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
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

On Mon, Dec 09, 2024 at 10:42:56AM +0800, Tong Tiangen wrote:
> Currently, many scenarios that can tolerate memory errors when copying page
> have been supported in the kernel[1~5], all of which are implemented by
> copy_mc_[user]_highpage(). arm64 should also support this mechanism.
> 
> Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
> architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
> __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
> 
> Add new helper copy_mc_page() which provide a page copy implementation with
> hardware memory error safe. The code logic of copy_mc_page() is the same as
> copy_page(), the main difference is that the ldp insn of copy_mc_page()
> contains the fixup type EX_TYPE_KACCESS_ERR_ZERO_MEM_ERR, therefore, the
> main logic is extracted to copy_page_template.S. In addition, the fixup of
> MOPS insn is not considered at present.

Could we not add the exception table entry permanently but ignore the
exception table entry if it's not on the do_sea() path? That would save
some code duplication.

> diff --git a/arch/arm64/lib/copy_mc_page.S b/arch/arm64/lib/copy_mc_page.S
> new file mode 100644
> index 000000000000..51564828c30c
> --- /dev/null
> +++ b/arch/arm64/lib/copy_mc_page.S
> @@ -0,0 +1,37 @@
> +/* SPDX-License-Identifier: GPL-2.0-only */
> +
> +#include <linux/linkage.h>
> +#include <linux/const.h>
> +#include <asm/assembler.h>
> +#include <asm/page.h>
> +#include <asm/cpufeature.h>
> +#include <asm/alternative.h>
> +#include <asm/asm-extable.h>
> +#include <asm/asm-uaccess.h>
> +
> +/*
> + * Copy a page from src to dest (both are page aligned) with memory error safe
> + *
> + * Parameters:
> + *	x0 - dest
> + *	x1 - src
> + * Returns:
> + * 	x0 - Return 0 if copy success, or -EFAULT if anything goes wrong
> + *	     while copying.
> + */
> +	.macro ldp1 reg1, reg2, ptr, val
> +	KERNEL_MEM_ERR(9998f, ldp \reg1, \reg2, [\ptr, \val])
> +	.endm
> +
> +SYM_FUNC_START(__pi_copy_mc_page)
> +#include "copy_page_template.S"
> +
> +	mov x0, #0
> +	ret
> +
> +9998:	mov x0, #-EFAULT
> +	ret
> +
> +SYM_FUNC_END(__pi_copy_mc_page)
> +SYM_FUNC_ALIAS(copy_mc_page, __pi_copy_mc_page)
> +EXPORT_SYMBOL(copy_mc_page)
[...]
> diff --git a/arch/arm64/lib/copy_page_template.S b/arch/arm64/lib/copy_page_template.S
> new file mode 100644
> index 000000000000..f96c7988c93d
> --- /dev/null
> +++ b/arch/arm64/lib/copy_page_template.S
> @@ -0,0 +1,70 @@
> +/* SPDX-License-Identifier: GPL-2.0-only */
> +/*
> + * Copyright (C) 2012 ARM Ltd.
> + */
> +
> +/*
> + * Copy a page from src to dest (both are page aligned)
> + *
> + * Parameters:
> + *	x0 - dest
> + *	x1 - src
> + */
> +
> +#ifdef CONFIG_AS_HAS_MOPS
> +	.arch_extension mops
> +alternative_if_not ARM64_HAS_MOPS
> +	b	.Lno_mops
> +alternative_else_nop_endif
> +
> +	mov	x2, #PAGE_SIZE
> +	cpypwn	[x0]!, [x1]!, x2!
> +	cpymwn	[x0]!, [x1]!, x2!
> +	cpyewn	[x0]!, [x1]!, x2!
> +	ret
> +.Lno_mops:
> +#endif
[...]

So if we have FEAT_MOPS, the machine check won't work?

Kristina is going to post MOPS support for the uaccess routines soon.
You can see how they are wired up and do something similar here.

But I'd prefer if we had the same code, only the exception table entry
treated differently. Similarly for the MTE tag copying.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z6zWSXzKctkpyH7-%40arm.com.
