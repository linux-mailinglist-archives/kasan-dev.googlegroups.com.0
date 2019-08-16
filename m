Return-Path: <kasan-dev+bncBCXLBLOA7IGBB7F63HVAKGQEEIROWDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id E89548FCB1
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 09:47:08 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id e9sf2909788edv.18
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 00:47:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565941628; cv=pass;
        d=google.com; s=arc-20160816;
        b=bgjpiyxUmjsfCy2102sdg9kJlFXRwBJ7+mzdnPrC5hg1p50hrVYB3W4M26Tp19Kefc
         xHx4/fUJECNpAHTlpCA24Ij2mdM3EKK6fJwSZ9/hc/gBjeDMgdNH5dGnCQ2NU62BDTu0
         HUxNk79FTUMgI9y3GroPQCsYt2PFnmgDG7p2P8eh+y0unHhOdmR+Y+2C6+TcRiQtvzyH
         kJXRnNsBEfSQaQB53ndeLZsKcfRmdU4aVcuIRLsvm1AU5NKeAGtl7MsHoF5jslKjfF5P
         HO27F/TUOS7G7eO05AeKqAOIZ4JnP4GXagxgguE/GJ+eBRiG4TX7P/Qk1tQuC2wC7beq
         V21Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=xuna2OErop73cW3ZhUofqrGTNw8hYa46J1iK9mWuoc4=;
        b=tn8i62czLGI8aQiDtbqHDBXUxb2B+dh680vxBWARLD5/U6BJhbs37+H+oWH/EXZbW4
         Bc3DBqpUnzAa9iHYVCkKVvcxvKhcYgu54PXrRPFRhbCksJwWTe+VKheaSiTaQxi7SRmR
         NxGzUmSVMdJmBZLCYUc+qk6PR1VAwY7pqJREzlnQmUHAV92a4qD82XT2aPKYPfkDKZQF
         BQxVaQC6lfpd3WpjkxBFcDgDiKnyFKDmaETHqMbi9RjNbXdvNofomXxFj+08Xq1YM9DG
         e4Xv49l715mlfwPbvEf6cuD9WowV0lsXA2N0y8EdR3ieP+J+pWj93VVk8S3PW7ahxlY9
         vmHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=nE1UYvPj;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xuna2OErop73cW3ZhUofqrGTNw8hYa46J1iK9mWuoc4=;
        b=AyyIQGcMQJeNpdr0pVtRKBQYNxg5zCGCw7cnkX27mw4n4rhDl9bdf8Jg8b9zK8+eo7
         GahTBx3e4bVdxHxLtEH9wr1+t6VWdYKjGkSBoZwthF+RQWoRBLnEqXGeo0ZRIZ8fJ3Wz
         xjupVxD5F3ld5AkcHptTixf2Ebn25gtWqcMTqic79xof29KDPV+Hd0m+5B3mfh668b+Y
         6mp1vAuUaIF9lk6SyvjIkCllteRUzjVLXwWvfPSU50rCZct2Mhg8QzHQE0LYBM3ztrYU
         GWIi8DFeY9gYXaVMRhliUD0lXPz4PTTLD+aF/jcqdCSFKA1AoPxUrXY0I4KP+1q6coQB
         cV2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xuna2OErop73cW3ZhUofqrGTNw8hYa46J1iK9mWuoc4=;
        b=e8p/9snyCfLOqGc/fm81AvkySkCo/xb5SsDzF3joxKzBUeKUxD5/LCDXch+LIWIltZ
         7Zzpdp34ppjDxwMg318Rn8Au0esG4EXvFyG6V0ztWT86T/92bUr0s+hIqPH6ussROjgw
         /7XmUoWPt0O0ps/lPxBgT9uHnJ42SdHqrHJfe2M8TSg9usPSndeblR/aa2Wb5wuBDOBy
         DVES+UquDBv4HYMqqG0h+amvWmkUfP+Vpf/NBvX01OrEB1u8fq65r+7zoeQQqqX/4El5
         MgMu7OatizLvaRV3lLkvv0GIVEoqCZgo0/HC0Gdeq/DBwDfl6fIQbw6jBDuX8yguOica
         ivYg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXCV2kTteCMPN6/H+MTwfDdXcoQulQO3wWueI6Pe50nz1DR9Gm4
	jXcvY4Q2w3RR0+pceHCpm6Y=
X-Google-Smtp-Source: APXvYqwlL/AowQ1qDft1bzTU1cRnUWCihjm7XZYkMlB/erbeC74mlfFj6TPy8AYyZ04Q/ugArn8H7Q==
X-Received: by 2002:a17:906:6a17:: with SMTP id o23mr8000088ejr.160.1565941628578;
        Fri, 16 Aug 2019 00:47:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7a05:: with SMTP id d5ls1740512ejo.13.gmail; Fri, 16
 Aug 2019 00:47:08 -0700 (PDT)
X-Received: by 2002:a17:906:7386:: with SMTP id f6mr8072591ejl.116.1565941628005;
        Fri, 16 Aug 2019 00:47:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565941628; cv=none;
        d=google.com; s=arc-20160816;
        b=j7XBF2zY3gvb4by5WGehOmUnvJYU9LYIc8kRQOXhHqdiaXxDrhbi+pEhw8zWP40keQ
         E5hvoODT1eWasqZjBNF5+ACe9JBQC5XnnE4l+kSpWtgi74dcs4RZmi3x9dE8+F7MCQvq
         yWsAfKuogHJONzk4xxdFGkC5hWWUkFzPw9HFL2fkXdw22E5+pTH8qut9sgisDP2dhvtU
         67HEs4+2GczJs8quSywqkOtPxx2mzlE5DNR0OsJehbCCYfL+AN0sUHLWe/KOEMAELo40
         d148uqcprmQm3169bPDU1jD1tLqZSYAdkHrKw2CY2QyKlucEXmMjxFZ6/OuFhBrK2h62
         rc/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=FLGclsWD+VICkoc3SW50SdDV/KFoWrceszkL7sYCVJw=;
        b=OeuDltjpm7nPjUpbqEObDyH5VFzM5uu6OMbuT1d52we2QWUyXRyV9brAlyowHesEiP
         nAW7TdX0RzbUYwsofVWI/2KtmosxwUH96R0ChV9bZ6vwSBwvsdFMRWxxIzois9ocVyar
         YG42WDlYewJ0iuV+Xbqq5DfNITHG/OCn7ahq44uGkeZJOCIMQVCf2n6dMMs90RYsAj0E
         mjq0iB5D38ILmoZACfoCMui7/y/KRfWp+J19M+u5/Trav5acU4KCTW/D/EGtyQ2oMa/x
         90WSiJum/Ha9zdaYXa+IgbAhTopogGW4rWbwvnQE/NNwCUllEv3egHAl7qvxMNUDKWch
         xcSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=nE1UYvPj;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id l17si357969ejg.1.2019.08.16.00.47.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Aug 2019 00:47:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 468wQ22xwCz9tyXb;
	Fri, 16 Aug 2019 09:47:06 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id KeNA4Se779Cq; Fri, 16 Aug 2019 09:47:06 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 468wQ21c3Dz9tyXZ;
	Fri, 16 Aug 2019 09:47:06 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4C86B8B776;
	Fri, 16 Aug 2019 09:47:07 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id fDzcV5G5Vqau; Fri, 16 Aug 2019 09:47:07 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0A6948B754;
	Fri, 16 Aug 2019 09:47:07 +0200 (CEST)
Subject: Re: [PATCH v4 1/3] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com,
 glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org,
 mark.rutland@arm.com, dvyukov@google.com
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20190815001636.12235-1-dja@axtens.net>
 <20190815001636.12235-2-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <15c6110a-9e6e-495c-122e-acbde6e698d9@c-s.fr>
Date: Fri, 16 Aug 2019 09:47:00 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190815001636.12235-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=nE1UYvPj;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



Le 15/08/2019 =C3=A0 02:16, Daniel Axtens a =C3=A9crit=C2=A0:
> Hook into vmalloc and vmap, and dynamically allocate real shadow
> memory to back the mappings.
>=20
> Most mappings in vmalloc space are small, requiring less than a full
> page of shadow space. Allocating a full shadow page per mapping would
> therefore be wasteful. Furthermore, to ensure that different mappings
> use different shadow pages, mappings would have to be aligned to
> KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.
>=20
> Instead, share backing space across multiple mappings. Allocate
> a backing page the first time a mapping in vmalloc space uses a
> particular page of the shadow region. Keep this page around
> regardless of whether the mapping is later freed - in the mean time
> the page could have become shared by another vmalloc mapping.
>=20
> This can in theory lead to unbounded memory growth, but the vmalloc
> allocator is pretty good at reusing addresses, so the practical memory
> usage grows at first but then stays fairly stable.

I guess people having gigabytes of memory don't mind, but I'm concerned=20
about tiny targets with very little amount of memory. I have boards with=20
as little as 32Mbytes of RAM. The shadow region for the linear space=20
already takes one eighth of the RAM. I'd rather avoid keeping unused=20
shadow pages busy.

Each page of shadow memory represent 8 pages of real memory. Could we=20
use page_ref to count how many pieces of a shadow page are used so that=20
we can free it when the ref count decreases to 0.

>=20
> This requires architecture support to actually use: arches must stop
> mapping the read-only zero page over portion of the shadow region that
> covers the vmalloc space and instead leave it unmapped.

Why 'must' ? Couldn't we switch back and forth from the zero page to=20
real page on demand ?

If the zero page is not mapped for unused vmalloc space, bad memory=20
accesses will Oops on the shadow memory access instead of Oopsing on the=20
real bad access, making it more difficult to locate and identify the issue.

>=20
> This allows KASAN with VMAP_STACK, and will be needed for architectures
> that do not have a separate module space (e.g. powerpc64, which I am
> currently working on). It also allows relaxing the module alignment
> back to PAGE_SIZE.

Why 'needed' ? powerpc32 doesn't have a separate module space and=20
doesn't need that.

>=20
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=3D202009
> Acked-by: Vasily Gorbik <gor@linux.ibm.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> [Mark: rework shadow allocation]
> Signed-off-by: Mark Rutland <mark.rutland@arm.com>
>=20
> --
>=20
> v2: let kasan_unpoison_shadow deal with ranges that do not use a
>      full shadow byte.
>=20
> v3: relax module alignment
>      rename to kasan_populate_vmalloc which is a much better name
>      deal with concurrency correctly
>=20
> v4: Integrate Mark's rework
>      Poision pages on vfree
>      Handle allocation failures. I've tested this by inserting artificial
>       failures and using test_vmalloc to stress it. I haven't handled the
>       per-cpu case: it looked like it would require a messy hacking-up of
>       the function to deal with an OOM failure case in a debug feature.
>=20
> ---
>   Documentation/dev-tools/kasan.rst | 60 +++++++++++++++++++++++++++
>   include/linux/kasan.h             | 24 +++++++++++
>   include/linux/moduleloader.h      |  2 +-
>   include/linux/vmalloc.h           | 12 ++++++
>   lib/Kconfig.kasan                 | 16 ++++++++
>   lib/test_kasan.c                  | 26 ++++++++++++
>   mm/kasan/common.c                 | 67 +++++++++++++++++++++++++++++++
>   mm/kasan/generic_report.c         |  3 ++
>   mm/kasan/kasan.h                  |  1 +
>   mm/vmalloc.c                      | 28 ++++++++++++-
>   10 files changed, 237 insertions(+), 2 deletions(-)
>=20
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index b72d07d70239..35fda484a672 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -215,3 +215,63 @@ brk handler is used to print bug reports.
>   A potential expansion of this mode is a hardware tag-based mode, which =
would
>   use hardware memory tagging support instead of compiler instrumentation=
 and
>   manual shadow memory manipulation.
> +
> +What memory accesses are sanitised by KASAN?
> +--------------------------------------------
> +
> +The kernel maps memory in a number of different parts of the address
> +space. This poses something of a problem for KASAN, which requires
> +that all addresses accessed by instrumented code have a valid shadow
> +region.
> +
> +The range of kernel virtual addresses is large: there is not enough
> +real memory to support a real shadow region for every address that
> +could be accessed by the kernel.
> +
> +By default
> +~~~~~~~~~~
> +
> +By default, architectures only map real memory over the shadow region
> +for the linear mapping (and potentially other small areas). For all
> +other areas - such as vmalloc and vmemmap space - a single read-only
> +page is mapped over the shadow area. This read-only shadow page
> +declares all memory accesses as permitted.
> +
> +This presents a problem for modules: they do not live in the linear
> +mapping, but in a dedicated module space. By hooking in to the module
> +allocator, KASAN can temporarily map real shadow memory to cover
> +them. This allows detection of invalid accesses to module globals, for
> +example.
> +
> +This also creates an incompatibility with ``VMAP_STACK``: if the stack
> +lives in vmalloc space, it will be shadowed by the read-only page, and
> +the kernel will fault when trying to set up the shadow data for stack
> +variables.
> +
> +CONFIG_KASAN_VMALLOC
> +~~~~~~~~~~~~~~~~~~~~
> +
> +With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
> +cost of greater memory usage. Currently this is only supported on x86.
> +
> +This works by hooking into vmalloc and vmap, and dynamically
> +allocating real shadow memory to back the mappings.
> +
> +Most mappings in vmalloc space are small, requiring less than a full
> +page of shadow space. Allocating a full shadow page per mapping would
> +therefore be wasteful. Furthermore, to ensure that different mappings
> +use different shadow pages, mappings would have to be aligned to
> +``KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE``.
> +
> +Instead, we share backing space across multiple mappings. We allocate
> +a backing page the first time a mapping in vmalloc space uses a
> +particular page of the shadow region. We keep this page around
> +regardless of whether the mapping is later freed - in the mean time
> +this page could have become shared by another vmalloc mapping.
> +
> +This can in theory lead to unbounded memory growth, but the vmalloc
> +allocator is pretty good at reusing addresses, so the practical memory
> +usage grows at first but then stays fairly stable.
> +
> +This allows ``VMAP_STACK`` support on x86, and enables support of
> +architectures that do not have a fixed module region.

That's wrong, powerpc32 doesn't have a fixed module region and is=20
already supported.

> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index cc8a03cc9674..d666748cd378 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -70,8 +70,18 @@ struct kasan_cache {
>   	int free_meta_offset;
>   };
>  =20
> +/*
> + * These functions provide a special case to support backing module
> + * allocations with real shadow memory. With KASAN vmalloc, the special
> + * case is unnecessary, as the work is handled in the generic case.
> + */
> +#ifndef CONFIG_KASAN_VMALLOC
>   int kasan_module_alloc(void *addr, size_t size);
>   void kasan_free_shadow(const struct vm_struct *vm);
> +#else
> +static inline int kasan_module_alloc(void *addr, size_t size) { return 0=
; }
> +static inline void kasan_free_shadow(const struct vm_struct *vm) {}
> +#endif
>  =20
>   int kasan_add_zero_shadow(void *start, unsigned long size);
>   void kasan_remove_zero_shadow(void *start, unsigned long size);
> @@ -194,4 +204,18 @@ static inline void *kasan_reset_tag(const void *addr=
)
>  =20
>   #endif /* CONFIG_KASAN_SW_TAGS */
>  =20
> +#ifdef CONFIG_KASAN_VMALLOC
> +int kasan_populate_vmalloc(unsigned long requested_size,
> +			   struct vm_struct *area);
> +void kasan_free_vmalloc(void *start, unsigned long size);
> +#else
> +static inline int kasan_populate_vmalloc(unsigned long requested_size,
> +					 struct vm_struct *area)
> +{
> +	return 0;
> +}
> +
> +static inline void kasan_free_vmalloc(void *start, unsigned long size) {=
}
> +#endif
> +
>   #endif /* LINUX_KASAN_H */
> diff --git a/include/linux/moduleloader.h b/include/linux/moduleloader.h
> index 5229c18025e9..ca92aea8a6bd 100644
> --- a/include/linux/moduleloader.h
> +++ b/include/linux/moduleloader.h
> @@ -91,7 +91,7 @@ void module_arch_cleanup(struct module *mod);
>   /* Any cleanup before freeing mod->module_init */
>   void module_arch_freeing_init(struct module *mod);
>  =20
> -#ifdef CONFIG_KASAN
> +#if defined(CONFIG_KASAN) && !defined(CONFIG_KASAN_VMALLOC)
>   #include <linux/kasan.h>
>   #define MODULE_ALIGN (PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
>   #else
> diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
> index 9b21d0047710..cdc7a60f7d81 100644
> --- a/include/linux/vmalloc.h
> +++ b/include/linux/vmalloc.h
> @@ -21,6 +21,18 @@ struct notifier_block;		/* in notifier.h */
>   #define VM_UNINITIALIZED	0x00000020	/* vm_struct is not fully initializ=
ed */
>   #define VM_NO_GUARD		0x00000040      /* don't add guard page */
>   #define VM_KASAN		0x00000080      /* has allocated kasan shadow memory =
*/
> +
> +/*
> + * VM_KASAN is used slighly differently depending on CONFIG_KASAN_VMALLO=
C.
> + *
> + * If IS_ENABLED(CONFIG_KASAN_VMALLOC), VM_KASAN is set on a vm_struct a=
fter
> + * shadow memory has been mapped. It's used to handle allocation errors =
so that
> + * we don't try to poision shadow on free if it was never allocated.
> + *
> + * Otherwise, VM_KASAN is set for kasan_module_alloc() allocations and u=
sed to
> + * determine which allocations need the module shadow freed.
> + */
> +
>   /*
>    * Memory with VM_FLUSH_RESET_PERMS cannot be freed in an interrupt or =
with
>    * vfree_atomic().
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 4fafba1a923b..a320dc2e9317 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -6,6 +6,9 @@ config HAVE_ARCH_KASAN
>   config HAVE_ARCH_KASAN_SW_TAGS
>   	bool
>  =20
> +config	HAVE_ARCH_KASAN_VMALLOC
> +	bool
> +
>   config CC_HAS_KASAN_GENERIC
>   	def_bool $(cc-option, -fsanitize=3Dkernel-address)
>  =20
> @@ -135,6 +138,19 @@ config KASAN_S390_4_LEVEL_PAGING
>   	  to 3TB of RAM with KASan enabled). This options allows to force
>   	  4-level paging instead.
>  =20
> +config KASAN_VMALLOC
> +	bool "Back mappings in vmalloc space with real shadow memory"
> +	depends on KASAN && HAVE_ARCH_KASAN_VMALLOC
> +	help
> +	  By default, the shadow region for vmalloc space is the read-only
> +	  zero page. This means that KASAN cannot detect errors involving
> +	  vmalloc space.
> +
> +	  Enabling this option will hook in to vmap/vmalloc and back those
> +	  mappings with real shadow memory allocated on demand. This allows
> +	  for KASAN to detect more sorts of errors (and to support vmapped
> +	  stacks), but at the cost of higher memory usage.
> +
>   config TEST_KASAN
>   	tristate "Module for testing KASAN for bug detection"
>   	depends on m && KASAN
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index b63b367a94e8..d375246f5f96 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c

Could we put the testing part in a separate patch ?


> @@ -18,6 +18,7 @@
>   #include <linux/slab.h>
>   #include <linux/string.h>
>   #include <linux/uaccess.h>
> +#include <linux/vmalloc.h>
>  =20
>   /*
>    * Note: test functions are marked noinline so that their names appear =
in
> @@ -709,6 +710,30 @@ static noinline void __init kmalloc_double_kzfree(vo=
id)
>   	kzfree(ptr);
>   }
>  =20
> +#ifdef CONFIG_KASAN_VMALLOC
> +static noinline void __init vmalloc_oob(void)
> +{
> +	void *area;
> +
> +	pr_info("vmalloc out-of-bounds\n");
> +
> +	/*
> +	 * We have to be careful not to hit the guard page.
> +	 * The MMU will catch that and crash us.
> +	 */
> +	area =3D vmalloc(3000);
> +	if (!area) {
> +		pr_err("Allocation failed\n");
> +		return;
> +	}
> +
> +	((volatile char *)area)[3100];
> +	vfree(area);
> +}
> +#else
> +static void __init vmalloc_oob(void) {}
> +#endif
> +
>   static int __init kmalloc_tests_init(void)
>   {
>   	/*
> @@ -752,6 +777,7 @@ static int __init kmalloc_tests_init(void)
>   	kasan_strings();
>   	kasan_bitops();
>   	kmalloc_double_kzfree();
> +	vmalloc_oob();
>  =20
>   	kasan_restore_multi_shot(multishot);
>  =20
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 2277b82902d8..b8374e3773cf 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -568,6 +568,7 @@ void kasan_kfree_large(void *ptr, unsigned long ip)
>   	/* The object will be poisoned by page_alloc. */
>   }
>  =20
> +#ifndef CONFIG_KASAN_VMALLOC
>   int kasan_module_alloc(void *addr, size_t size)
>   {
>   	void *ret;
> @@ -603,6 +604,7 @@ void kasan_free_shadow(const struct vm_struct *vm)
>   	if (vm->flags & VM_KASAN)
>   		vfree(kasan_mem_to_shadow(vm->addr));
>   }
> +#endif
>  =20
>   extern void __kasan_report(unsigned long addr, size_t size, bool is_wri=
te, unsigned long ip);
>  =20
> @@ -722,3 +724,68 @@ static int __init kasan_memhotplug_init(void)
>  =20
>   core_initcall(kasan_memhotplug_init);
>   #endif
> +
> +#ifdef CONFIG_KASAN_VMALLOC
> +static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
> +				      void *unused)
> +{
> +	unsigned long page;
> +	pte_t pte;
> +
> +	if (likely(!pte_none(*ptep)))
> +		return 0;

Prior to this, the zero shadow area should be mapped, and the test=20
should be:

if (likely(pte_pfn(*ptep) !=3D PHYS_PFN(__pa(kasan_early_shadow_page))))
	return 0;

> +
> +	page =3D __get_free_page(GFP_KERNEL);
> +	if (!page)
> +		return -ENOMEM;
> +
> +	memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
> +	pte =3D pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
> +
> +	/*
> +	 * Ensure poisoning is visible before the shadow is made visible
> +	 * to other CPUs.
> +	 */
> +	smp_wmb();
> +
> +	spin_lock(&init_mm.page_table_lock);
> +	if (likely(pte_none(*ptep))) {
> +		set_pte_at(&init_mm, addr, ptep, pte);
> +		page =3D 0;
> +	}
> +	spin_unlock(&init_mm.page_table_lock);
> +	if (page)
> +		free_page(page);
> +	return 0;
> +}
> +
> +int kasan_populate_vmalloc(unsigned long requested_size, struct vm_struc=
t *area)
> +{
> +	unsigned long shadow_start, shadow_end;
> +	int ret;
> +
> +	shadow_start =3D (unsigned long)kasan_mem_to_shadow(area->addr);
> +	shadow_start =3D ALIGN_DOWN(shadow_start, PAGE_SIZE);
> +	shadow_end =3D (unsigned long)kasan_mem_to_shadow(
> +		area->addr + area->size);
> +	shadow_end =3D ALIGN(shadow_end, PAGE_SIZE);
> +
> +	ret =3D apply_to_page_range(&init_mm, shadow_start,
> +				  shadow_end - shadow_start,
> +				  kasan_populate_vmalloc_pte, NULL);
> +	if (ret)
> +		return ret;
> +
> +	kasan_unpoison_shadow(area->addr, requested_size);
> +
> +	area->flags |=3D VM_KASAN;
> +
> +	return 0;
> +}
> +
> +void kasan_free_vmalloc(void *start, unsigned long size)
> +{
> +	size =3D round_up(size, KASAN_SHADOW_SCALE_SIZE);
> +	kasan_poison_shadow(start, size, KASAN_VMALLOC_INVALID);
> +}
> +#endif
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/generic_report.c
> index 36c645939bc9..2d97efd4954f 100644
> --- a/mm/kasan/generic_report.c
> +++ b/mm/kasan/generic_report.c
> @@ -86,6 +86,9 @@ static const char *get_shadow_bug_type(struct kasan_acc=
ess_info *info)
>   	case KASAN_ALLOCA_RIGHT:
>   		bug_type =3D "alloca-out-of-bounds";
>   		break;
> +	case KASAN_VMALLOC_INVALID:
> +		bug_type =3D "vmalloc-out-of-bounds";
> +		break;
>   	}
>  =20
>   	return bug_type;
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 014f19e76247..8b1f2fbc780b 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -25,6 +25,7 @@
>   #endif
>  =20
>   #define KASAN_GLOBAL_REDZONE    0xFA  /* redzone for global variable */
> +#define KASAN_VMALLOC_INVALID   0xF9  /* unallocated space in vmapped pa=
ge */
>  =20
>   /*
>    * Stack redzone shadow values
> diff --git a/mm/vmalloc.c b/mm/vmalloc.c
> index 4fa8d84599b0..c20a7e663004 100644
> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -2056,6 +2056,22 @@ static struct vm_struct *__get_vm_area_node(unsign=
ed long size,
>  =20
>   	setup_vmalloc_vm(area, va, flags, caller);
>  =20
> +	/*
> +	 * For KASAN, if we are in vmalloc space, we need to cover the shadow
> +	 * area with real memory. If we come here through VM_ALLOC, this is
> +	 * done by a higher level function that has access to the true size,
> +	 * which might not be a full page.
> +	 *
> +	 * We assume module space comes via VM_ALLOC path.
> +	 */
> +	if (is_vmalloc_addr(area->addr) && !(area->flags & VM_ALLOC)) {
> +		if (kasan_populate_vmalloc(area->size, area)) {
> +			unmap_vmap_area(va);
> +			kfree(area);
> +			return NULL;
> +		}
> +	}
> +
>   	return area;
>   }
>  =20
> @@ -2233,6 +2249,9 @@ static void __vunmap(const void *addr, int dealloca=
te_pages)
>   	debug_check_no_locks_freed(area->addr, get_vm_area_size(area));
>   	debug_check_no_obj_freed(area->addr, get_vm_area_size(area));
>  =20
> +	if (area->flags & VM_KASAN)
> +		kasan_free_vmalloc(area->addr, area->size);
> +
>   	vm_remove_mappings(area, deallocate_pages);
>  =20
>   	if (deallocate_pages) {
> @@ -2483,6 +2502,9 @@ void *__vmalloc_node_range(unsigned long size, unsi=
gned long align,
>   	if (!addr)
>   		return NULL;
>  =20
> +	if (kasan_populate_vmalloc(real_size, area))
> +		return NULL;
> +
>   	/*
>   	 * In this function, newly allocated vm_struct has VM_UNINITIALIZED
>   	 * flag. It means that vm_struct is not fully initialized.
> @@ -3324,10 +3346,14 @@ struct vm_struct **pcpu_get_vm_areas(const unsign=
ed long *offsets,
>   	spin_unlock(&vmap_area_lock);
>  =20
>   	/* insert all vm's */
> -	for (area =3D 0; area < nr_vms; area++)
> +	for (area =3D 0; area < nr_vms; area++) {
>   		setup_vmalloc_vm(vms[area], vas[area], VM_ALLOC,
>   				 pcpu_get_vm_areas);
>  =20
> +		/* assume success here */
> +		kasan_populate_vmalloc(sizes[area], vms[area]);
> +	}
> +
>   	kfree(vas);
>   	return vms;
>  =20
>=20


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/15c6110a-9e6e-495c-122e-acbde6e698d9%40c-s.fr.
