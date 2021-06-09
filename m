Return-Path: <kasan-dev+bncBAABBGF2QGDAMGQEG2T7ZFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B47933A0C43
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jun 2021 08:18:01 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id q4-20020a056e020784b02901e2ee9a8333sf17101393ils.20
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Jun 2021 23:18:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623219480; cv=pass;
        d=google.com; s=arc-20160816;
        b=ygjjcZcBRiQLcNtHGCmMGsl0+k/LZv0qpuNBVcyBd61KENB7Tn4rZvM8+ruJgvlY/N
         XEl9bbSQ8gQ0adNgWcdVTjQ2TYDQ5KiVZdOZkgyhWQl0/h02FGyESoHmTklNZnnYYvMy
         ToovkfFNG1qLOUOiw3NGkbrSd0v7hH1LiT4eay90gzLYuDcbNXhsgwTBAQ4XnRbEc/c2
         NoTqCgK3SYWpubCbHg/QAJFPFs0BGIqtym0XC1HDHlNdsqYXuitTu+LKOzdCOIkFqyiW
         rLr1wNs+zCjqDA0Y1MSxBeAvnZA0DwOlBxd/qe3j9617/7vNa6OBBZRr5SUxy3zaI2G9
         EqbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:mime-version:user-agent
         :date:message-id:from:cc:references:to:subject:sender:dkim-signature;
        bh=luRG5O9asTIs3pvVcL/mZBzdnTOD5uwcpeMHe0Zj0Qw=;
        b=o+if+BMpY0ZYujRJfD1iBekr9wvzffaniv7QNCFxv1X6HfsgBbWK25b2J+oplfWW1U
         TDvhpqNEzvbgw3WpNCwDzNYMVZmZLspbIvgzQD1/1fvfgU5ELeUxOIyX8aJehjJKDPt0
         PXhrxrDrKWuOiCLxavrjdodKRX0LzUa+shJ8ISp/hlAL9UD0cYmvhKcbRCUTChR5vHa1
         /r7hC4P5mhrJc9GSvaXfN2y7w9MIpwV6f7MrR8pQN7+UrkPrG06nC+Eh/ag3USml4ixB
         gAyH8IVW6XYj7yc3wInnIHCbHViNWb9uMh1j1j+3TwdpYobl0AQjkjjA//0spfSP0KzT
         7MLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:cc:from:message-id:date:user-agent
         :mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=luRG5O9asTIs3pvVcL/mZBzdnTOD5uwcpeMHe0Zj0Qw=;
        b=WZktJGA4/EdX5F9GuBB6mG0As3eb4YvYwLoNoRjjAWFk5qr2iRpqOOxWpwY5aXQqGW
         8pKgXXjz4wDI90loTIFt0HJrv9JHM9jyzQN9KDMqT+QAGVLi+jfj1q/rKa3SAe4ciT+3
         wNlqDnuYVZSqyqNzjqf0lc00dqWT+KRHqdyPgPsAngvkql3BSHAkC83hkjg58HfWVh0Q
         mshGsyvF7N7FjaqiTNffzfKexA9eEV1v09GgkglWP3CYs8cjRyOpf32n4uKdu+t3sHzc
         XQkb7EwvjA7sNOefz0lJ/zhnvlY+8CZpJ7SfNd3CbsGnO2dck0TRG/sBQHgapXkcbFUU
         /1/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:cc:from:message-id
         :date:user-agent:mime-version:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=luRG5O9asTIs3pvVcL/mZBzdnTOD5uwcpeMHe0Zj0Qw=;
        b=rC7/b8NljnQVSQ/yjb8j7vkyWny6cdV0S894XcSdb4X0yi35O8lWh9N3g+Wedz6x51
         Ztm7YWeCimfeKVjkCShgPJ3bhKBmJ3nHyFhoXHzFtsB9c9CpJdSs4VEbZbAEASXNMdym
         aD9fazr7+tsc3A2Te1xgXRsTG8jX+insdQ+9U3VgHJIVZmSvzHG2rVtMAYkO+LyUYWdX
         sbDH5xmFZcQfLfBVZwTd1GR46Sqqk8g29pNZ4GOzqRK9dEXglI5vVjKWmSOxUedMGZwW
         jUEAk9w0+GwqWsT+2Sv4oIpNKYz9XW0MVGoh00xCnXBgzEAZiG9zjXcldgfF+sYVoD3X
         RM0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531r9CHbuvSoDfmEcuWMDzk81R0e63k/cJNjPaBFK5vEyLeDzKzg
	xkQzipXbZiZ8ui90jdBIeVw=
X-Google-Smtp-Source: ABdhPJxzxlgGCM1LgAW5cQ9PfXgFi3JxwDhWDOzRqOZ+VA6O8TpMG5Edy5aMp/1T/U5jPqN9Pgud/w==
X-Received: by 2002:a92:b111:: with SMTP id t17mr22825106ilh.208.1623219480489;
        Tue, 08 Jun 2021 23:18:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1201:: with SMTP id a1ls394403ilq.11.gmail; Tue, 08
 Jun 2021 23:18:00 -0700 (PDT)
X-Received: by 2002:a05:6e02:1523:: with SMTP id i3mr23260793ilu.12.1623219480214;
        Tue, 08 Jun 2021 23:18:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623219480; cv=none;
        d=google.com; s=arc-20160816;
        b=WLqKPoKfVWD2zKD4gX1RbfkNGjY9cyelQAJfNo9j08pC8V/2gkpKJttHD2SOSDjaF0
         +3jfwrx0f9Bygodf32SwYwz1cyMtLGQxPExlTTsdPXN2zuCnxMt0HGQ5QCWBZjuTS3Tj
         k1ynHMmvu3poTXJPF/Z6QE6N7CKVUE/4nDnrix2or0RiqSmIWaixEiofeS6T20ASRtuU
         sWtfqPp4RxbpRCjBdHRIaSCUtKvbmxtK5owqqXrtdZGi0vit43JO0fn0zHxZqo7Z4M9m
         RxoX6HLhzhbMOQIv5LXGwwqPnJWOODstNxyOG+5mO9mEJNb+OEx0wjsVYZImtGP4zTH6
         lgxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:mime-version:user-agent:date
         :message-id:from:cc:references:to:subject;
        bh=y7WvU1Hp+BMDwj0RuXidZwwarJYhak0E+r0vml9FG7g=;
        b=mXAQ31dXFJ/pCtOeAwCZjBpEIxwPBYMBFxdM9d6mRKqapsVKzmrfe8mxRV71eZDBSw
         9Faaz1k7VJvrIxVQnROSzkg3cAc9nv4Rn3kbMP3oErVGGAKCU5FGa0Gu2dH6pe6AVr/u
         P1iosbpGyOx3AnO1N+qeEjiNE7eYOM30Pz2nui6kkCGTCfBpDGHubqg/ijGbKgnQLHmm
         8825qGn+LdGo3kbzNnUExYnAMvcWFiGOXNNpGbqi5PjFG255JhH2+yHjnAvrRJ2iRnnZ
         LzaEVz7WMZ736a85JKBa8aY/jfZqUshF9Qo4rdxZif2WUKl45LE1QGDUHXyLKhYQnxzi
         DTQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=liushixin2@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id x13si325760ilg.2.2021.06.08.23.17.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Jun 2021 23:18:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv703-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4G0Gzd5XMgz6wqy;
	Wed,  9 Jun 2021 14:14:53 +0800 (CST)
Received: from dggpemm500009.china.huawei.com (7.185.36.225) by
 dggemv703-chm.china.huawei.com (10.3.19.46) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 9 Jun 2021 14:17:56 +0800
Received: from [10.174.179.24] (10.174.179.24) by
 dggpemm500009.china.huawei.com (7.185.36.225) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Wed, 9 Jun 2021 14:17:55 +0800
Subject: Re: [PATCH -next] riscv: Enable KFENCE for riscv64
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
	<palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Alexander Potapenko
	<glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov
	<dvyukov@google.com>
References: <20210529080340.2987212-1-liushixin2@huawei.com>
CC: <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>
From: Liu Shixin <liushixin2@huawei.com>
Message-ID: <0a3ee489-47db-47f5-6192-794457fc74f8@huawei.com>
Date: Wed, 9 Jun 2021 14:17:55 +0800
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:45.0) Gecko/20100101
 Thunderbird/45.7.1
MIME-Version: 1.0
In-Reply-To: <20210529080340.2987212-1-liushixin2@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.179.24]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500009.china.huawei.com (7.185.36.225)
X-CFilter-Loop: Reflected
X-Original-Sender: liushixin2@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of liushixin2@huawei.com designates 45.249.212.188 as
 permitted sender) smtp.mailfrom=liushixin2@huawei.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

Hi, everybody,

I perfected the patch based on the previous advice. How about this version?


Thanks,


On 2021/5/29 16:03, Liu Shixin wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the riscv64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
>
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the kfence pool to be mapped at
> page granularity.
>
> Testing this patch using the testcases in kfence_test.c and all passed.
>
> Signed-off-by: Liu Shixin <liushixin2@huawei.com>
> ---
> 1. Add helper function split_pmd_page() which is used to split a pmd to ptes. 
> 2. Add the judgment on the result of pte_alloc_one_kernel().
>
>  arch/riscv/Kconfig              |  1 +
>  arch/riscv/include/asm/kfence.h | 63 +++++++++++++++++++++++++++++++++
>  arch/riscv/mm/fault.c           | 11 +++++-
>  3 files changed, 74 insertions(+), 1 deletion(-)
>  create mode 100644 arch/riscv/include/asm/kfence.h
>
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 4982130064ef..2f4903a7730f 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -65,6 +65,7 @@ config RISCV
>  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>  	select HAVE_ARCH_KASAN if MMU && 64BIT
>  	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
> +	select HAVE_ARCH_KFENCE if MMU && 64BIT
>  	select HAVE_ARCH_KGDB
>  	select HAVE_ARCH_KGDB_QXFER_PKT
>  	select HAVE_ARCH_MMAP_RND_BITS if MMU
> diff --git a/arch/riscv/include/asm/kfence.h b/arch/riscv/include/asm/kfence.h
> new file mode 100644
> index 000000000000..d887a54042aa
> --- /dev/null
> +++ b/arch/riscv/include/asm/kfence.h
> @@ -0,0 +1,63 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +
> +#ifndef _ASM_RISCV_KFENCE_H
> +#define _ASM_RISCV_KFENCE_H
> +
> +#include <linux/kfence.h>
> +#include <linux/pfn.h>
> +#include <asm-generic/pgalloc.h>
> +#include <asm/pgtable.h>
> +
> +static inline int split_pmd_page(unsigned long addr)
> +{
> +	int i;
> +	unsigned long pfn = PFN_DOWN(__pa((addr & PMD_MASK)));
> +	pmd_t *pmd = pmd_off_k(addr);
> +	pte_t *pte = pte_alloc_one_kernel(&init_mm);
> +
> +	if (!pte)
> +		return -ENOMEM;
> +
> +	for (i = 0; i < PTRS_PER_PTE; i++)
> +		set_pte(pte + i, pfn_pte(pfn + i, PAGE_KERNEL));
> +	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(pte)), PAGE_TABLE));
> +
> +	flush_tlb_kernel_range(addr, addr + PMD_SIZE);
> +	return 0;
> +}
> +
> +static inline bool arch_kfence_init_pool(void)
> +{
> +	int ret;
> +	unsigned long addr;
> +	pmd_t *pmd;
> +
> +	for (addr = (unsigned long)__kfence_pool; is_kfence_address((void *)addr);
> +	     addr += PAGE_SIZE) {
> +		pmd = pmd_off_k(addr);
> +
> +		if (pmd_leaf(*pmd)) {
> +			ret = split_pmd_page(addr);
> +			if (ret)
> +				return false;
> +		}
> +	}
> +
> +	return true;
> +}
> +
> +static inline bool kfence_protect_page(unsigned long addr, bool protect)
> +{
> +	pte_t *pte = virt_to_kpte(addr);
> +
> +	if (protect)
> +		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_PRESENT));
> +	else
> +		set_pte(pte, __pte(pte_val(*pte) | _PAGE_PRESENT));
> +
> +	flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
> +
> +	return true;
> +}
> +
> +#endif /* _ASM_RISCV_KFENCE_H */
> diff --git a/arch/riscv/mm/fault.c b/arch/riscv/mm/fault.c
> index 096463cc6fff..aa08dd2f8fae 100644
> --- a/arch/riscv/mm/fault.c
> +++ b/arch/riscv/mm/fault.c
> @@ -14,6 +14,7 @@
>  #include <linux/signal.h>
>  #include <linux/uaccess.h>
>  #include <linux/kprobes.h>
> +#include <linux/kfence.h>
>  
>  #include <asm/ptrace.h>
>  #include <asm/tlbflush.h>
> @@ -45,7 +46,15 @@ static inline void no_context(struct pt_regs *regs, unsigned long addr)
>  	 * Oops. The kernel tried to access some bad page. We'll have to
>  	 * terminate things with extreme prejudice.
>  	 */
> -	msg = (addr < PAGE_SIZE) ? "NULL pointer dereference" : "paging request";
> +	if (addr < PAGE_SIZE)
> +		msg = "NULL pointer dereference";
> +	else {
> +		if (kfence_handle_page_fault(addr, regs->cause == EXC_STORE_PAGE_FAULT, regs))
> +			return;
> +
> +		msg = "paging request";
> +	}
> +
>  	die_kernel_fault(msg, addr, regs);
>  }
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0a3ee489-47db-47f5-6192-794457fc74f8%40huawei.com.
