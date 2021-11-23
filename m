Return-Path: <kasan-dev+bncBDDL3KWR4EBRBLUJ6WGAMGQEIXFNWWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 505F845ACC2
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 20:44:48 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id q2-20020a05621419e200b003aeeeff5417sf54704qvc.9
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 11:44:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637696687; cv=pass;
        d=google.com; s=arc-20160816;
        b=NANl0KNocSKi/zKC7LpJwrBHGg4LDAdQcuy6n5lrnAtdZN2iSjzc5llwjBT5CxMSMX
         DOiBp4cUdvNGcpQTpLIFMty68TQ40hEFmKowgBJ94rirBabkYtl664zBbTq8HeKL79JR
         BcCvkXy84yvtBr3DJ1cuhb2lYymDof9bZeIMNYN42sORgIRCXP9s1wfvODeJdXZdK1Rq
         AIdVbTCoamzmQg7/Yz/QSXq0IaXDRXiMGh4xg8iai/5O4Oa7BPxaWkXswm14fBnX5sws
         5HLGc6O6PZ5AK5XABy9tBGDlGhOiHu4CNhACMYZt3J3e6tTXkn7onfhcXcu8RCkmM6fW
         wpiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=F756dimHOg5e1voVYHzR+3FgJjDiSMBKXgInK9DpzUk=;
        b=Izeh3JPkkMFzjpTQwA3ewbkeOq7PZER5UKTkmXHzW+Z1B9013ddk7a3t0f2O/sr2W6
         IBZi0hI6V5rgVGb5AUj7lttw/S4ugBCd5lqVHHVgh75yXMlS9S08siA0MhBBl+WClimM
         mG8jq3iH0huvwpQgwYAEvIUBi/3+54jUn0LMDySaQvBs8wB1Yo7l+I1DEhRSjKqsNqiN
         +8mO+DKLqTnl45Vt6yhRDgooI7LvFeH9NN+IqRvrFS1reBsIUrfaeefjd1uLWCNZEki5
         g33b5jnuuGlINuFvLhR1YYRZKDThEtrJ8L80sTN4ua/oNmkh5hojNeFB44ycMlzJ2p1+
         6F0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=F756dimHOg5e1voVYHzR+3FgJjDiSMBKXgInK9DpzUk=;
        b=Cat8wYqwmm9Sd8QD8Yi8AuXJT0mKFw9Z9VJuO1tcnxzMClGQOUJu2DU+ngeFcI2U8c
         +BxS3f9+z6cwxdWyUScc0PP6FXqI6PtJ1c+fHE28EiwT8EjUwjLadCW5+qptYtt7CvM9
         ksOnZdGo4QtW+sYjti8l2X8UeY0W676Mc2GPvRVeHoBqzbvh83uG16jti21pPRBXi8e6
         kfcDk/PBj+0exxvfUiJ6Qz2j1blo/MFoGNkP4wQwCuGCHN2sZW0ttwVNRsHFfpBw9aPH
         iES4EjSxO8ObX4YvuZ/ry1W/N1h5UvH9j+XVnj2ggE9sKaAvvP+VpUQmn8uY5SSYD2yV
         qUhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=F756dimHOg5e1voVYHzR+3FgJjDiSMBKXgInK9DpzUk=;
        b=HHhwc/lm5mJQfad3UGhFnCcvkIqv9LbiwjOGtKELv47v40JatXvwOJO567rwusQMtd
         Fbwt+sITLt32gqBXhbh5PHa2+YKbQBrM9hndzgpAJUe/h0fBZKlqmbqpVcmK7206b2P6
         rr4PXYNLYoPvqni32nhcbD9MkgLYXUWr7Wdy7wIXSs0l6CynytMjjj+htcqOqIkKnks5
         Tkmvg9LDATszWawnnscMPAZdy5MevrX80FrmhluiKMHSe5X82dOH7oE741LBVxCWIbOf
         Wg6tWE1HJASInxjyua3WSQ3ih0I2XSRnnb3sR63Su9SArtQS4lWa9RvyXxZFPdwniLsm
         IQNg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533JgXNhL1GF8p0145LHLR5yaWgOHLP24b9ZUP0h/SMIFGoZClFK
	8iT7IEFEvNBBPrZJfL7QqBk=
X-Google-Smtp-Source: ABdhPJzY8ha2noY0Opy2mL8IW8+mV4/PVdYQA8Zmtt00K6LH9fIPkV57Hg/AsFbWiYMY1CnK4W+jMA==
X-Received: by 2002:a0c:f9cc:: with SMTP id j12mr9073844qvo.2.1637696686895;
        Tue, 23 Nov 2021 11:44:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:bca:: with SMTP id s10ls6534263qki.1.gmail; Tue, 23
 Nov 2021 11:44:46 -0800 (PST)
X-Received: by 2002:a37:a7cb:: with SMTP id q194mr7352828qke.238.1637696686430;
        Tue, 23 Nov 2021 11:44:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637696686; cv=none;
        d=google.com; s=arc-20160816;
        b=Cv7CWho8I/hOYa/WCY1u6TwqSH9hpu0JWRNY85ZzgCPGM4Tg41dBafIHIJrFlt6gDD
         X4mosRDa+xodQurEaoaa+4B9KnXPOml0oPPiZRnmH9FCWg1yr7gBqo3jORkSA4vwr593
         ZA6W1W6uPHKeIZ/zwdli0Q8KVuPbFlTE7iFf2BhpjEExv3LC5MHw8FM44n3oo+k9c+bq
         cxM7wA2A+YsiEuef/P2pkgvKPjXD4VSjj+y9oDq/8RKx1fPY+49nwUpT5+eX5gU3W6iJ
         ch5nUpqX5qZg/O76yiOxrTp1m23QDke5Uk/CItyLRPIEXDR+mjdXUeexlCg3oXjxXXKm
         E9Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=q0c9DSyL4lVUSDcNqiH06RA+fWe/PMB+Q+qazz6UCPc=;
        b=VyzhsdBCtTCo3l37l6uMb+1OFwr5I27IxKE0tVkFbDVnF9drepa2fxOQlZbpGoXrd1
         MkQYvdtHLB3Sxw7O64BpeTdo7PVUKtCf7vZobKHeDAW1G7wfTs/DJvFtIZTOx8s6frg3
         g/uZnvzfFlRKmhEw4Bg/zrF0FkdP/lW5wjo0tggIZAi+UxBD7sgNszk3LrGj6FfhUIBQ
         gLPLdPaU0PG247JjAUp3D3/StQx/PkXesQetAMphPXIg6jy2TwaClEGzKUAGyYTcyInC
         9UVY2EFmGO9YnVX3dNTppe3hq95mHISOanp0fVdYcc+YKsfNFCSmVa60DWp+tE26ZEKm
         Kc+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i6si462741qko.3.2021.11.23.11.44.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Nov 2021 11:44:46 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 0FE6160F26;
	Tue, 23 Nov 2021 19:44:39 +0000 (UTC)
Date: Tue, 23 Nov 2021 19:44:35 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	linux-s390@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, Will Deacon <will@kernel.org>,
	Heiko Carstens <hca@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>,
	Alexander Gordeev <agordeev@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Alexander Potapenko <glider@google.com>,
	Yongqiang Liu <liuyongqiang13@huawei.com>
Subject: Re: [PATCH v2] mm: Delay kmemleak object creation of module_alloc()
Message-ID: <YZ1Eo2m3VKZTfthA@arm.com>
References: <20211123143220.134361-1-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211123143220.134361-1-wangkefeng.wang@huawei.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Nov 23, 2021 at 10:32:20PM +0800, Kefeng Wang wrote:
> Yongqiang reports a kmemleak panic when module insmod/rmmod with KASAN
> enabled on x86[1].
> 
> When the module allocates memory, it's kmemleak_object is created successfully,
> but the KASAN shadow memory of module allocation is not ready, so when kmemleak
> scan the module's pointer, it will panic due to no shadow memory with KASAN.
> 
> module_alloc
>   __vmalloc_node_range
>     kmemleak_vmalloc
> 				kmemleak_scan
> 				  update_checksum
>   kasan_module_alloc
>     kmemleak_ignore

Can you share the .config and the stack trace you get on arm64?

I have a suspicion there is no problem if KASAN_VMALLOC is enabled.

> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 4a4929b29a23..2ade2f484562 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>  
>  #else /* CONFIG_KASAN_VMALLOC */
>  
> -int kasan_module_alloc(void *addr, size_t size)
> +int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask)
>  {
>  	void *ret;
>  	size_t scaled_size;
> @@ -520,9 +520,14 @@ int kasan_module_alloc(void *addr, size_t size)
>  			__builtin_return_address(0));
>  
>  	if (ret) {
> +		struct vm_struct *vm = find_vm_area(addr);
>  		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
> -		find_vm_area(addr)->flags |= VM_KASAN;
> +		vm->flags |= VM_KASAN;
>  		kmemleak_ignore(ret);
> +
> +		if (vm->flags & VM_DELAY_KMEMLEAK)
> +			kmemleak_vmalloc(vm, size, gfp_mask);
> +
>  		return 0;
>  	}

This function only exists if CONFIG_KASAN_VMALLOC=n.

> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index d2a00ad4e1dd..23c595b15839 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3074,7 +3074,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>  	clear_vm_uninitialized_flag(area);
>  
>  	size = PAGE_ALIGN(size);
> -	kmemleak_vmalloc(area, size, gfp_mask);
> +	if (!(vm_flags & VM_DELAY_KMEMLEAK))
> +		kmemleak_vmalloc(area, size, gfp_mask);

So with KASAN_VMALLOC enabled, we'll miss the kmemleak allocation.

You could add an IS_ENABLED(CONFIG_KASAN_VMALLOC) check but I'm not
particularly fond of the delay approach (also think DEFER is probably a
better name).

A quick fix would be to make KMEMLEAK depend on !KASAN || KASAN_VMALLOC.
We'll miss KASAN_SW_TAGS with kmemleak but I think vmalloc support could
be enabled for this as well.

What does KASAN do with other vmalloc() allocations when !KASAN_VMALLOC?
Can we not have a similar approach. I don't fully understand why the
module vmalloc() is a special case.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YZ1Eo2m3VKZTfthA%40arm.com.
