Return-Path: <kasan-dev+bncBDDL3KWR4EBRBZXYTKEAMGQESIFWLFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id E8FD73DCC48
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Aug 2021 17:23:19 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id o12-20020ab01c4c0000b02902a6f6876d72sf5408452uaj.23
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Aug 2021 08:23:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627831398; cv=pass;
        d=google.com; s=arc-20160816;
        b=t+BZHlMdNsLM/DuNYe0rwZM+JSjm2sWFfWd6B+HB9hmeds+jyVaYWdbs31e83/bF7l
         xdt6gJvW8wKy2xZ/ROtzOnQMSnUs3cJfYApxTGM1q4nyyKczPXaukCqpqoDtL1jilmg8
         k1F9SaYhxVjT5g0ngPIOwnR6dRWwZogbpkgKTjT+Dhqhdr2uiiDpylW5G1Iks4KUCdpo
         qTOZ66OJzMoo12+GbG1WEgmnyqBu3Z9OQUJ7BXBvwPNPKSLlbOzv07o4ivWWkdwFrxdh
         Kq51MiKkJJZKVaQ5J08Bx5QPWtkXZ7Dfaqj0+r2+TNZHeiDzBk7vrliFl52XrugcIZGD
         75Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=GiMDiZmO/cbnQJSEpznL2bvdrdL0U0SbesFUTEfy6/Q=;
        b=pWbeHi+Nay87Ifr5LorhtalhaxWM5Ijtw/ecdFx7tkj22MC7u7Mfr9jxcKM6902hYd
         Q+vQkEqxcJXlEQtX1e57M1ysf99oh4SyunXZ59czm1rhXpnuGk2aRCPYo6lKL4llyUNL
         667hl/dHBgt8+WVONcbZ0kFfIm6s0w3wSD77zxJArx/gLEz1lQKtb/UjgYaRzQLUSAkx
         TZll75raHX3QwQhFWWwQlcUlmhRgtMC6RhXHsfXuHa9jlL7xdNp7AwNADNddouuk3pwL
         24kscqIhFfyA4z3bekPvZ1TERo1WNuswk2Gi7DaTgTcEq4rNFsBqjrFYnwfH5Gy7ckmw
         lj7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GiMDiZmO/cbnQJSEpznL2bvdrdL0U0SbesFUTEfy6/Q=;
        b=ObLSosihOpgrx4Po3mF/BVovoPrSZmHMMmX2KlG3OO7sZIs1hujzfywGgNwai15amo
         +FXl7aOqeRDVs6hIgAiLw/SFoen9/NXP+zxLV4ekbzzu4SfMTmQRcTMo7wh8ZC5xCVl4
         29CDZCaembuYncMWvUi6EmsBbnnkxr9dpUDHvL2lNQBskxQNTrAS01RooMmxIumiOX7G
         HEKiQEKuRydcLWB9hFWq14dJtqqyvN9SrkHdO7I9M4N3ckLbQhFZl5bsoeCQ+NbFG5jY
         7VW+j1HzbqWIhIYfVqxdzxx7BVu+nRxzasj+EwzgZ4+x87I0oNlf8NPMqLludgqMW+5k
         4Neg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GiMDiZmO/cbnQJSEpznL2bvdrdL0U0SbesFUTEfy6/Q=;
        b=PjshBORGc2xbZ47Q8fTwBP+vl4nqGnCqumrWN/nEmkGaEBI31R7WVOhuQc/sOQlucm
         a7EdKpZUKvP6MLORkVvOLh7oousWF+ZDPvhyz453k788Bw469Vpe/nCWZVi8U4jKUYb2
         0XYqthGAQuhb6ML0OLREywsFI3kVv6syXmhm18QAApP1DdCuNmNFq9MbuHQjtwoT8BtT
         Mb6ycF/wGqPGlj6Q9KzFEARD7ujaaF6hEKAFTI/FxueLe1NsrLTV6l5xW/MbCJX1Tks8
         wYiffw4Eu7LBJK6e49Dowzgibt5NefmpepxlGfcm929xcoikaDvKXlpowof3P0D6+9HV
         nUOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530PWBvc10kkqVLTcjacnZ2o1405JJxbD+ZMoFdK+2tXnkrMbL4d
	d4BtjsyJBDw4evMYMSIvCWQ=
X-Google-Smtp-Source: ABdhPJy/ojZgJ9nSxy3Jvq68QXqBzABhkAbEGC6ozbveE8T97V/3hDLgTE7K9bje8qy6ulMthpNI/A==
X-Received: by 2002:a9f:21af:: with SMTP id 44mr8322180uac.87.1627831398811;
        Sun, 01 Aug 2021 08:23:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:3889:: with SMTP id f131ls476758vka.9.gmail; Sun, 01 Aug
 2021 08:23:18 -0700 (PDT)
X-Received: by 2002:a1f:9442:: with SMTP id w63mr5991838vkd.8.1627831398315;
        Sun, 01 Aug 2021 08:23:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627831398; cv=none;
        d=google.com; s=arc-20160816;
        b=kaq34yOAAM4MkkpuhRYR9rMYtQ8gQPvAlaiR9T9Wiiy9EJV0PhYPMsnHlZLeiRQ3Rh
         aUThDZc/HKio++Yg5L4oaF6yx/KSzcGBYXIbT4RXJ2Z/ZJQIgMyUoG0weY4t41xXX8EI
         WTlbjpu5OG57U5gVSQzYJprQAokDiC4jaPESZIGcitGIfdP3EwDklUNwAlCoX9lv5HK/
         o2D1vKG/eA2+7fxU8bVU/obqStbkYO+k2K7nEWAckRvl/aJGo4MCK9Hd4e3ccfhy+v8Z
         Kt2kg/GIwg5FK6WNhhgQ+hNAvNPE4Pot8Fr/Ft2f1/q9TTHFDosG5s3YN5drjd7dhMqt
         TiMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=xYUILJ5NmCiCac89WbV/DfGZh1/+yn85p1rwGFxx+UA=;
        b=wZ6nD1sq/y9Yo8JGOebLRq8hxPs3yGHpzgPN9Ighi3TarQlPP3tsbkfr6/v+q25IIn
         dnKATMTTqOUQOpR8ykAgPYqlfzZjGv+Glpy0ZR3gAnf/FWhc1l7pFArxHVVZr4Hd4H53
         7FiJqlAyUlleopii+hBT590rczYly2eo6JNXE1wuNCAfXgoXLZUHKMD6Id7pnOabZjM2
         kSgLPlB7wk7zIPux4upaIy5ZZ6gGh3mKy2pmyQW5CN8rj/XTUExEh2b1dK8v23duF2Lt
         BUI5R69zMmtkqr9w96/0NUYjFvCkP97qJSrh5ZdRsNapXnW7qwEr+/LWFjreDUfUJnVV
         CloQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i21si539897vko.5.2021.08.01.08.23.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 01 Aug 2021 08:23:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 666C560243;
	Sun,  1 Aug 2021 15:23:15 +0000 (UTC)
Date: Sun, 1 Aug 2021 08:23:12 -0700
From: Catalin Marinas <catalin.marinas@arm.com>
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH v2 1/3] vmalloc: Choose a better start address in
 vm_area_register_early()
Message-ID: <20210801152311.GB28489@arm.com>
References: <20210720025105.103680-1-wangkefeng.wang@huawei.com>
 <20210720025105.103680-2-wangkefeng.wang@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210720025105.103680-2-wangkefeng.wang@huawei.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
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

On Tue, Jul 20, 2021 at 10:51:03AM +0800, Kefeng Wang wrote:
> There are some fixed locations in the vmalloc area be reserved
> in ARM(see iotable_init()) and ARM64(see map_kernel()), but for
> pcpu_page_first_chunk(), it calls vm_area_register_early() and
> choose VMALLOC_START as the start address of vmap area which
> could be conflicted with above address, then could trigger a
> BUG_ON in vm_area_add_early().
> 
> Let's choose the end of existing address range in vmlist as the
> start address instead of VMALLOC_START to avoid the BUG_ON.
> 
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>  mm/vmalloc.c | 8 +++++---
>  1 file changed, 5 insertions(+), 3 deletions(-)
> 
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index d5cd52805149..a98cf97f032f 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2238,12 +2238,14 @@ void __init vm_area_add_early(struct vm_struct *vm)
>   */
>  void __init vm_area_register_early(struct vm_struct *vm, size_t align)
>  {
> -	static size_t vm_init_off __initdata;
> +	unsigned long vm_start = VMALLOC_START;
> +	struct vm_struct *tmp;
>  	unsigned long addr;
>  
> -	addr = ALIGN(VMALLOC_START + vm_init_off, align);
> -	vm_init_off = PFN_ALIGN(addr + vm->size) - VMALLOC_START;
> +	for (tmp = vmlist; tmp; tmp = tmp->next)
> +		vm_start = (unsigned long)tmp->addr + tmp->size;
>  
> +	addr = ALIGN(vm_start, align);
>  	vm->addr = (void *)addr;
>  
>  	vm_area_add_early(vm);

Is there a risk of breaking other architectures? It doesn't look like to
me but I thought I'd ask.

Also, instead of always picking the end, could we search for a range
that fits?

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210801152311.GB28489%40arm.com.
