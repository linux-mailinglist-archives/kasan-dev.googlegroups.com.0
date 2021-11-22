Return-Path: <kasan-dev+bncBCRKFI7J2AJRBRUY52GAMGQE44B7LHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 82AF9458E3C
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 13:25:43 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id q12-20020a9f2b4c000000b002ddac466f76sf9377265uaj.12
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 04:25:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637583942; cv=pass;
        d=google.com; s=arc-20160816;
        b=X+AttHsoVbwhdav/59EdAXhRupJ6goKErtMjVlMfQahGoYzkY7ziO++jWnho1BJVGx
         dnH0mKSRU1iesv1Bxs9xlJpLEbaMt4xh9NWaZE1CScDRlJfuuOwfM+QsAQlMIIBkSm0G
         0Aku9tKeGCzRLnk7YgyyOGwryxpytjetK/rlj7GCw987b4uLCNgvCzptFVDn4xAlrSPA
         MgEx3LmoKUbwsCOEmKEVt4bq+Lnev7+QHLqEIhDnaV6lULdf+ezt1597uAwlNR0Fqnhf
         lR58SRYWLuBDIOFshpMx0MRXoLmSyJkY3lzPYtpON3DmR3qsymi3DNxZb49eG/2a2S0k
         iBCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=PRo9muA9LoaGb20khUVtV+6MeImJgN3RNoYaGPBfAx4=;
        b=Mr4fpTBbah0bsLLUIL2j4mRmCIFNKqOqYapt7eWvugERPPCfF8g3wfP+T4Jm4peNZd
         7hpf2HtIX66LRY0IYJVXFm7f0qV2FGHctCMPEMzlPbFB6fn+auVOZzMNaI//+06pI6fv
         gOEIBm+h3kCRv8pEnLZmnga7era+5GWrCUavDVdsHvGz2aKOXAT9RxE/dl/8McSpmgTD
         XsZV95H3OxHEXoLYjwrCgXMEmuiKIWIlhFu2NQEyCVWnVngXwj3V8OEMM2M3m0/unpmi
         kCz+jni579VF09lbJaFe3lNic1SfqrJaVnj3FDydQDk2IpNo962JPxpMFUKEZ4et3zU5
         lxvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PRo9muA9LoaGb20khUVtV+6MeImJgN3RNoYaGPBfAx4=;
        b=BHMV3ts6rIuE2UBK1Hp8N67uHL/a52Ow1cituDpc1DfqKFBjS/TdQNQhOrggdU8py6
         RZ+PvU5S8jrNBOLPdSLouOePcVo3la+hhdXC95myNDlBzqae8LVlrSBzoUNIGAPY3TkQ
         bSKO+W8QqJGIJJhLqwoTmI0WmS1r3BwHg5HepI2GQnTWJIAKRaIygSLDP8EwjqIFc+eb
         Kj3TcNvQ5S0yr5yVVEQ/CfQ70m776Dcf0GHsbPKlq1arKhPAMp2jTd0JQ+LHo0t1366v
         Vqf4hPf+gDCXuEKkyTgp9Xes7jQMTpmN4nAotlDBmfvMgyiYflGApkaeUP25ZoFR7KoK
         ipXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PRo9muA9LoaGb20khUVtV+6MeImJgN3RNoYaGPBfAx4=;
        b=Whu1c3A9ZFIBc7PTLoXQLbhoNF7YYalSVIEgzX0KzSYdCKLIkaUrrac6l2TrjnwmP8
         VUDCvnYcZa6fpRt9pDtVIA3TaTS2gEdKMFcq40p+hhsvOhzy3vq2j8Fd6oXPiRI6Xl/o
         jg/H2Vq9RyoCW3uxTbzScFGQjDd02/C3qM0YxU0g4c1FKYJ/ykwiIc8eTrZ22JlfIHVf
         OklUB1qU141ewvkqsTNAn+Z3rItddJRXP9JNXH80OuCvDZFiaVPPzcEXl1bWKW+oX5+o
         ijEm98+Nd/67BPb88+FKHay2K5/7kGSsL9rhSTIlk8svT5W/hFjM4/9efQQPnmh7SY4T
         XzIg==
X-Gm-Message-State: AOAM531AHWR5x9hs+6A7pTw75UyABhzBzKpSS357Ba5fPI8esgtyDRu5
	AbauYxOWsMCtaXUaepySB6I=
X-Google-Smtp-Source: ABdhPJyo9co3F9ByBCa9wQYXr/cvDxCRARpzC7o7TImtNKlBAQLWJFz/r77th2sZWY7yc5VokJ+dlw==
X-Received: by 2002:a05:6102:418c:: with SMTP id cd12mr132120745vsb.17.1637583942547;
        Mon, 22 Nov 2021 04:25:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e217:: with SMTP id g23ls2504698vsa.0.gmail; Mon, 22 Nov
 2021 04:25:41 -0800 (PST)
X-Received: by 2002:a05:6102:32d1:: with SMTP id o17mr128671858vss.19.1637583941686;
        Mon, 22 Nov 2021 04:25:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637583941; cv=none;
        d=google.com; s=arc-20160816;
        b=ms7A08pV/bku2kDuaZteL0HIHsLMsagEBcqA/DAHQ64pPvOmgIEyKQXJP663ZTdUBL
         Ci4fsw1PVfVBWqLiEU7pF2vRg0AmNBHiddud+x9GmeegdATKlTnb7KMA9PE6xK8zYlw+
         tK67s0qHjhvnqzLIMh9uTM0ZTLdqaQ4awWLcu/Fb+iNH/kkk9orIZ3jo5YnKTloqiH7S
         AdNzQWku/s++ME+udsiMCdrBIMILgcePX4jq07X9RnfLqs67HdhCOAQNII4dPA5GSrwp
         sCiV6Ny+sp8jw7GR5YA0bFluueY3jBVQWxWsdPGMee1p1CF2yZomxxWhWwQMuRa+YW/z
         LAxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=0gJ7gMhdtw5jhdfmJuQEC3lN2OpAlFaAHdAA9DaX3G0=;
        b=TbSSwF7pzuupLMMiE7Q5iHm90yoZqVSQmdrB6aXbOjngHuRB788N8gt75JJwHyiZwa
         c9UhQaR7qQVo0vkmAC7HqtsQ6ZpyBdsKd3SFGFYMK2DNeAT3e+qa1RoPJ5cpzd+k9ILQ
         7BdBeCWNIRoiZVD+gH+uJjzQmJI3QAvga0lAZ21kSkoOm9BhcV8V36aIa6aKM5E7j+LJ
         mr++gnGPoYWjwO6KMU6Sdi+DqFxsL8oZDN0m6QJq2/QDgKz+wg/fQuRln49Ti6vIhP7r
         UzifYPrXZWumBI1tBUlRCohOwgCFnYcAoODXge+8HVom8/EiDUnG+Nu4InSj6mB3x/oF
         vnBw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id q25si711560vko.0.2021.11.22.04.25.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Nov 2021 04:25:41 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500020.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HyRLK6hFsz91H2;
	Mon, 22 Nov 2021 20:25:13 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500020.china.huawei.com (7.185.36.49) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Mon, 22 Nov 2021 20:25:39 +0800
Received: from [10.174.177.243] (10.174.177.243) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id
 15.1.2308.20; Mon, 22 Nov 2021 20:25:38 +0800
Message-ID: <50a584a4-8164-2715-41a4-99468d50a0a0@huawei.com>
Date: Mon, 22 Nov 2021 20:25:37 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.0
Subject: Re: [PATCH] mm: Delay kmemleak object creation of module_alloc()
Content-Language: en-US
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-s390@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>, Alexander Gordeev
	<agordeev@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar
	<mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, Alexander Potapenko <glider@google.com>,
	Yongqiang Liu <liuyongqiang13@huawei.com>
References: <20211122121742.142203-1-wangkefeng.wang@huawei.com>
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20211122121742.142203-1-wangkefeng.wang@huawei.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.174.177.243]
X-ClientProxiedBy: dggeme704-chm.china.huawei.com (10.1.199.100) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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


On 2021/11/22 20:17, Kefeng Wang wrote:
> Yongqiang reports a kmemleak panic when module ismod/rmmod with KASAN
> enabled[1] on x86.
>
> The module allocate memory, and it's kmemleak_object is created successfu=
lly,
> but the KASAN shadow memory of module allocation is not ready, when kmeml=
eak
> scan the module's pointer, it will panic due to no shadow memory.
>
> module_alloc
>    __vmalloc_node_range
>      kmemleak_vmalloc
> 				kmemleak_scan
> 				  update_checksum
>    kasan_module_alloc
>      kmemleak_ignore
>
> The bug should exist on ARM64/S390 too, add a VM_DELAY_KMEMLEAK flags, de=
lay
> vmalloc'ed object register of kmemleak in module_alloc().
>
> [1] https://lore.kernel.org/all/6d41e2b9-4692-5ec4-b1cd-cbe29ae89739@huaw=
ei.com/
> Reported-by: Yongqiang Liu <liuyongqiang13@huawei.com>
> Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
> ---
>   arch/arm64/kernel/module.c | 4 ++--
>   arch/s390/kernel/module.c  | 5 +++--
>   arch/x86/kernel/module.c   | 7 ++++---
>   include/linux/kasan.h      | 4 ++--
>   include/linux/vmalloc.h    | 7 +++++++
>   mm/kasan/shadow.c          | 9 +++++++--
>   mm/vmalloc.c               | 3 ++-
>   7 files changed, 27 insertions(+), 12 deletions(-)
>
> diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
> index b5ec010c481f..e6da010716d0 100644
> --- a/arch/arm64/kernel/module.c
> +++ b/arch/arm64/kernel/module.c
> @@ -36,7 +36,7 @@ void *module_alloc(unsigned long size)
>   		module_alloc_end =3D MODULES_END;
>  =20
>   	p =3D __vmalloc_node_range(size, MODULE_ALIGN, module_alloc_base,
> -				module_alloc_end, gfp_mask, PAGE_KERNEL, 0,
> +				module_alloc_end, gfp_mask, PAGE_KERNEL, VM_DELAY_KMEMLEAK,
>   				NUMA_NO_NODE, __builtin_return_address(0));
>  =20
>   	if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
> @@ -58,7 +58,7 @@ void *module_alloc(unsigned long size)
>   				PAGE_KERNEL, 0, NUMA_NO_NODE,
>   				__builtin_return_address(0));
>  =20
> -	if (p && (kasan_module_alloc(p, size) < 0)) {
> +	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
>   		vfree(p);
>   		return NULL;
>   	}
> diff --git a/arch/s390/kernel/module.c b/arch/s390/kernel/module.c
> index b01ba460b7ca..8d66a93562ca 100644
> --- a/arch/s390/kernel/module.c
> +++ b/arch/s390/kernel/module.c
> @@ -37,14 +37,15 @@
>  =20
>   void *module_alloc(unsigned long size)
>   {
> +	gfp_t gfp_mask =3D GFP_KERNEL;
>   	void *p;
>  =20
>   	if (PAGE_ALIGN(size) > MODULES_LEN)
>   		return NULL;
>   	p =3D __vmalloc_node_range(size, MODULE_ALIGN, MODULES_VADDR, MODULES_=
END,
> -				 GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
> +				 gfp_mask, PAGE_KERNEL_EXEC, VM_DELAY_KMEMLEAK, NUMA_NO_NODE,
>   				 __builtin_return_address(0));
> -	if (p && (kasan_module_alloc(p, size) < 0)) {
> +	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
>   		vfree(p);
>   		return NULL;
>   	}
> diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
> index 169fb6f4cd2e..ff134d0f1ca1 100644
> --- a/arch/x86/kernel/module.c
> +++ b/arch/x86/kernel/module.c
> @@ -67,6 +67,7 @@ static unsigned long int get_module_load_offset(void)
>  =20
>   void *module_alloc(unsigned long size)
>   {
> +	gfp_t gfp_mask =3D GFP_KERNEL;
>   	void *p;
>  =20
>   	if (PAGE_ALIGN(size) > MODULES_LEN)
> @@ -74,10 +75,10 @@ void *module_alloc(unsigned long size)
>  =20
>   	p =3D __vmalloc_node_range(size, MODULE_ALIGN,
>   				    MODULES_VADDR + get_module_load_offset(),
> -				    MODULES_END, GFP_KERNEL,
> -				    PAGE_KERNEL, 0, NUMA_NO_NODE,
> +				    MODULES_END, gfp_mask,
> +				    PAGE_KERNEL, VM_DELAY_KMEMLEAK, NUMA_NO_NODE,
>   				    __builtin_return_address(0));
> -	if (p && (kasan_module_alloc(p, size) < 0)) {
> +	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
>   		vfree(p);
>   		return NULL;
>   	}
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d8783b682669..89c99e5e67de 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -474,12 +474,12 @@ static inline void kasan_populate_early_vm_area_sha=
dow(void *start,
>    * allocations with real shadow memory. With KASAN vmalloc, the special
>    * case is unnecessary, as the work is handled in the generic case.
>    */
> -int kasan_module_alloc(void *addr, size_t size);
> +int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask);
>   void kasan_free_shadow(const struct vm_struct *vm);
>  =20
>   #else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASA=
N_VMALLOC */
>  =20
> -static inline int kasan_module_alloc(void *addr, size_t size) { return 0=
; }
> +static inline int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_=
mask) { return 0; }
>   static inline void kasan_free_shadow(const struct vm_struct *vm) {}
>  =20
>   #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KAS=
AN_VMALLOC */
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index 6e022cc712e6..56d2b7828b31 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -28,6 +28,13 @@ struct notifier_block;		/* in notifier.h */
>   #define VM_MAP_PUT_PAGES	0x00000200	/* put pages and free array in vfre=
e */
>   #define VM_NO_HUGE_VMAP		0x00000400	/* force PAGE_SIZE pte mapping */
>  =20
> +#if defined(CONFIG_KASAN) && (defined(CONFIG_KASAN_GENERIC) || \
> +	defined(CONFIG_KASAN_SW_TAGS)) && !defined(CONFIG_KASAN_VMALLOC)
> +#define VM_DELAY_KMEMLEAK	0x00000800	/* delay kmemleak object create */
> +#else
> +#define VM_DELAY_KMEMLEAK	0
> +#endif
> +
>   /*
>    * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMAL=
LOC.
>    *
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 4a4929b29a23..6ca43b43419b 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsig=
ned long end,
>  =20
>   #else /* CONFIG_KASAN_VMALLOC */
>  =20
> -int kasan_module_alloc(void *addr, size_t size)
> +int kasan_module_alloc(void *addr, size_t size, gfp_mask)
>   {
>   	void *ret;
>   	size_t scaled_size;
> @@ -520,9 +520,14 @@ int kasan_module_alloc(void *addr, size_t size)
>   			__builtin_return_address(0));
>  =20
>   	if (ret) {
> +		struct vm_struct *vm =3D find_vm_area(addr);
>   		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
> -		find_vm_area(addr)->flags |=3D VM_KASAN;
> +		vm->flags |=3D VM_KASAN;
>   		kmemleak_ignore(ret);
> +
> +		if (vm->flags | VM_DELAY_KMEMLEAK)

should=C2=A0=C2=A0=C2=A0 if (vm->flags & VM_DELAY_KMEMLEAK),=C2=A0 let's wa=
it more comments,=20
and will update.

> +			kmemleak_vmalloc(vm, size, gfp_mask);
> +
>   		return 0;
>   	}
>  =20
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index d2a00ad4e1dd..23c595b15839 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3074,7 +3074,8 @@ void *__vmalloc_node_range(unsigned long size, unsi=
gned long align,
>   	clear_vm_uninitialized_flag(area);
>  =20
>   	size =3D PAGE_ALIGN(size);
> -	kmemleak_vmalloc(area, size, gfp_mask);
> +	if (!(vm_flags & VM_DELAY_KMEMLEAK))
> +		kmemleak_vmalloc(area, size, gfp_mask);
>  =20
>   	return addr;
>  =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/50a584a4-8164-2715-41a4-99468d50a0a0%40huawei.com.
