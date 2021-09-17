Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBGPJSCFAMGQEMD6OMDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 66ED240F244
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 08:24:27 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id z127-20020a633385000000b002618d24cfacsf7214625pgz.16
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 23:24:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631859866; cv=pass;
        d=google.com; s=arc-20160816;
        b=PotLaVu6Tf6Uf1GgzUdwMU/EEub9ACJdqa/VaHMdWeeYl/Tk4u8Y6w3KfIY/ipOpKU
         c1O4SFvUFRCjehx+R5oEun6ozpbqMqewaQCs65ib7WAPHr8ZVg4vzxZGuMhrAn7c7z6o
         l5CD/qpFCnPBauXLYV+NeKrwGW0606B0wAC5Hq/asUeVU9GJXMLzJWSFelS4n847GqmW
         hqKlsgP329fblVtSSmsNLtn/KAVL/BS76dGGAcHzzqp+T3rYG4sMfz1p+755DwW8A6LF
         Doa7Rg9ALD4qAA7ewYgSd3pHPqQGBV6VFvvkJd2UST+dVP5eUEKF7qxsYZsn0urxr0Gc
         ZSiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Md7+qILNPYIWHNSmwr8d4Q+EpkBjxeaI5yhXfOwcB0U=;
        b=EuSCE/PBvq2BKNP5+iF8h8lQMt4k+SgqURKrcSGnbjemd0Yx8F5ex4/cmtETVSGX1i
         /kgP/Q5M51w/QdOgQagMU7Uj8zk16S5rMrgazBQ7ySH43tAW1tnKoPl74WkNroNrCA4v
         2Ky+r4jVA7Q66SzeRr1W7AHIvjIx9jDqODY1s57DtxrWduSgp8sgKGQMlFDi/39Rzaq0
         dM6UWDfUviSLXF2g9WyXyM1GzrjJK2m3D7PC22GVEhS4m17ARZvssdFcww3gmmD2zMtw
         mbX2ZrkjX9UNvzAqpha6wSoQwYza/07y8zsXwOr411UWATbXnH8xs60fJaZcwsKKVZNb
         Vreg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=tNzW5LF8;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Md7+qILNPYIWHNSmwr8d4Q+EpkBjxeaI5yhXfOwcB0U=;
        b=tK+3nbnFJzq2M2EJBy20gPF4I/32xo985y8Oxq22tMzcxeu6qP3Tp1ve+g6J3LCRnk
         0RWFU5C9VOoRzXq4w/HVXXOdyF29WscbWIwl5eEj/7f+4n/19bBdAIHS78GGtNh76ftp
         TjEx0CEn8DXJcetYQ2afxTmM+u9S8FYMJVHaorzGE5eBaT/Bbb9BX+6jrWcFUuwOcWpq
         SNMSm8TJZR66KYYAzV2ze6OEwEKV/5Gq0N1hK3s3j9Lpc0VvZb5k/qdaMoRlMV8AAVhJ
         noTm4d8Jcwl8ZGeuyW/up2kXhkeAiUaKv4VqbOPr24K6Rv3u3AKPqIKv6FkLL7IZoDrV
         bgFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Md7+qILNPYIWHNSmwr8d4Q+EpkBjxeaI5yhXfOwcB0U=;
        b=2ZPmRlHQZrqHNlUXr76cW7lyAIWE31sB48WoNUL3b7vEBrRh/qfsIbL5UeQuLKu+/N
         zEx0lEFvAMAojhrcpUEEMzW7gk7qOZKE0Q1jlazY34GoJijsvFNL04/HkLVrEJvMH8fP
         VUypas/1fFYddIADcQyspkAzYQpIpcYLSbtvroW8sW47XX8hKo3zl4QUU0qENwTOSMQd
         MQtHfgzcguNxizl6HHm3r4MnZUGc8pvMh/50NVvnCIrdY0XG6Lw226aZZ8cbn8D9EdcB
         BiJznp71cnaKQBnTqlBaegZDK/0KYqn9XZfyYK/DQf5BQd7RBQMfduXnfIpwd4TAi8ug
         wx+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530efUg9d/7LcbSmSAL4am/LgBB0ipxuFIs3R0o+fLBXLYi778UJ
	tJ/VTEipwoiqLV+akpZFoEk=
X-Google-Smtp-Source: ABdhPJwgnUua9cg30yCxrBEQ/DcrKiQhXvQH6g++E6qC91hdXxhJOB6eWsAy7fGn6+cqhZj3u6Twvg==
X-Received: by 2002:a63:9911:: with SMTP id d17mr8507518pge.111.1631859865889;
        Thu, 16 Sep 2021 23:24:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ac9:: with SMTP id r9ls3377125pje.1.gmail; Thu, 16
 Sep 2021 23:24:25 -0700 (PDT)
X-Received: by 2002:a17:90a:4a8e:: with SMTP id f14mr10513763pjh.169.1631859865291;
        Thu, 16 Sep 2021 23:24:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631859865; cv=none;
        d=google.com; s=arc-20160816;
        b=m6IFDUSTsz2Vi/f2Ac3UlrfcbGFOvjY97pmXjzeQuhAiPyj6ENmdicyDYkNQboLeH4
         KuJuf6KzQEQfzjduv4Yxq5eH3ljTpLPAVWFFBAfdS60XqlqT5Rdt5juR1EBxSYHmMkEA
         sRS2e7inImsutPJdKlEFh1qodm0Y1lSisQokXRF/DkVB+HRk+KduSgG8Ked4fkWI7iwW
         5RTJNcIGFIbAC+Isxwm42CeVA0lmLHX7Q0S2pAVgmgmpO5O0XLAmcQsYA6bKH3J4RA/Z
         MFqNgGSJgH87vCFVxHQe33N+20p7m7zR+MmVemXOi3Hk+ud2OHFm0iaJjobWxT4B00Fl
         62rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=pJxvJK5pINelwNbN9K9yvZcoLrtd4KfqynUK5Hmj6VY=;
        b=S0uVPT0rL3WKsDXWOy+PYaM4Ubq4+M349YLb56mBt5H3LCY8cRMp/hvcu9ma8VTz+w
         M22FtkPG84rAQ9WJJK3292iSswP1AE4B9tdlCi4TILMFmNzbW7T6JjaTO0H+PpjjIljQ
         Qb3YRVFb3JvfIkSk7nWgiE/mmHwRvVuc+ueUm+b0Wqna9ncjN9jjCGhsjkYol1YzfNqZ
         6HHtxW2cLR7JP5THzYEJRmdSkFJdeqUNnWuyu5EYsezRNMilBf/eY/wO7SghS48EKuBf
         0Km9/m9pW6gEZ4aiOysKut0rpDlOInJcg1T9b9ViNuPgjvafe4EOPZjncb8atK2ADMMJ
         +AwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=tNzW5LF8;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w20si570086plq.2.2021.09.16.23.24.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 16 Sep 2021 23:24:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4F37260F4A;
	Fri, 17 Sep 2021 06:24:24 +0000 (UTC)
Date: Fri, 17 Sep 2021 08:24:22 +0200
From: Greg KH <gregkh@linuxfoundation.org>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: will@kernel.org, catalin.marinas@arm.com, ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com, dvyukov@google.com,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, elver@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v4 2/3] arm64: Support page mapping percpu first chunk
 allocator
Message-ID: <YUQ0lvldA+wGpr0G@kroah.com>
References: <20210910053354.26721-1-wangkefeng.wang@huawei.com>
 <20210910053354.26721-3-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210910053354.26721-3-wangkefeng.wang@huawei.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=tNzW5LF8;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Fri, Sep 10, 2021 at 01:33:53PM +0800, Kefeng Wang wrote:
> Percpu embedded first chunk allocator is the firstly option, but it
> could fails on ARM64, eg,
>   "percpu: max_distance=0x5fcfdc640000 too large for vmalloc space 0x781fefff0000"
>   "percpu: max_distance=0x600000540000 too large for vmalloc space 0x7dffb7ff0000"
>   "percpu: max_distance=0x5fff9adb0000 too large for vmalloc space 0x5dffb7ff0000"
> 
> then we could meet "WARNING: CPU: 15 PID: 461 at vmalloc.c:3087 pcpu_get_vm_areas+0x488/0x838",
> even the system could not boot successfully.
> 
> Let's implement page mapping percpu first chunk allocator as a fallback
> to the embedding allocator to increase the robustness of the system.
> 
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>  arch/arm64/Kconfig       |  4 ++
>  drivers/base/arch_numa.c | 82 +++++++++++++++++++++++++++++++++++-----
>  2 files changed, 76 insertions(+), 10 deletions(-)
> 
> diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
> index 077f2ec4eeb2..04cfe1b4e98b 100644
> --- a/arch/arm64/Kconfig
> +++ b/arch/arm64/Kconfig
> @@ -1042,6 +1042,10 @@ config NEED_PER_CPU_EMBED_FIRST_CHUNK
>  	def_bool y
>  	depends on NUMA
>  
> +config NEED_PER_CPU_PAGE_FIRST_CHUNK
> +	def_bool y
> +	depends on NUMA

Why is this a config option at all?

> +
>  source "kernel/Kconfig.hz"
>  
>  config ARCH_SPARSEMEM_ENABLE
> diff --git a/drivers/base/arch_numa.c b/drivers/base/arch_numa.c
> index 46c503486e96..995dca9f3254 100644
> --- a/drivers/base/arch_numa.c
> +++ b/drivers/base/arch_numa.c
> @@ -14,6 +14,7 @@
>  #include <linux/of.h>
>  
>  #include <asm/sections.h>
> +#include <asm/pgalloc.h>
>  
>  struct pglist_data *node_data[MAX_NUMNODES] __read_mostly;
>  EXPORT_SYMBOL(node_data);
> @@ -168,22 +169,83 @@ static void __init pcpu_fc_free(void *ptr, size_t size)
>  	memblock_free_early(__pa(ptr), size);
>  }
>  
> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK

Ick, no #ifdef in .c files if at all possible please.

> +static void __init pcpu_populate_pte(unsigned long addr)
> +{
> +	pgd_t *pgd = pgd_offset_k(addr);
> +	p4d_t *p4d;
> +	pud_t *pud;
> +	pmd_t *pmd;
> +
> +	p4d = p4d_offset(pgd, addr);
> +	if (p4d_none(*p4d)) {
> +		pud_t *new;
> +
> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +		if (!new)
> +			goto err_alloc;
> +		p4d_populate(&init_mm, p4d, new);
> +	}
> +
> +	pud = pud_offset(p4d, addr);
> +	if (pud_none(*pud)) {
> +		pmd_t *new;
> +
> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +		if (!new)
> +			goto err_alloc;
> +		pud_populate(&init_mm, pud, new);
> +	}
> +
> +	pmd = pmd_offset(pud, addr);
> +	if (!pmd_present(*pmd)) {
> +		pte_t *new;
> +
> +		new = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +		if (!new)
> +			goto err_alloc;
> +		pmd_populate_kernel(&init_mm, pmd, new);
> +	}
> +
> +	return;
> +
> +err_alloc:
> +	panic("%s: Failed to allocate %lu bytes align=%lx from=%lx\n",
> +	      __func__, PAGE_SIZE, PAGE_SIZE, PAGE_SIZE);

That feels harsh, are you sure you want to crash?  There's no way to
recover from this?  If not, how can this fail in real life?

> +}
> +#endif
> +
>  void __init setup_per_cpu_areas(void)
>  {
>  	unsigned long delta;
>  	unsigned int cpu;
> -	int rc;
> +	int rc = -EINVAL;
> +
> +	if (pcpu_chosen_fc != PCPU_FC_PAGE) {
> +		/*
> +		 * Always reserve area for module percpu variables.  That's
> +		 * what the legacy allocator did.
> +		 */
> +		rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
> +					    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
> +					    pcpu_cpu_distance,
> +					    pcpu_fc_alloc, pcpu_fc_free);
> +#ifdef CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK
> +		if (rc < 0)
> +			pr_warn("PERCPU: %s allocator failed (%d), falling back to page size\n",
> +				   pcpu_fc_names[pcpu_chosen_fc], rc);
> +#endif

Why only print out a message for a config option?  Again, no #ifdef in
.c files if at all possible.

thanks,

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YUQ0lvldA%2BwGpr0G%40kroah.com.
