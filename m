Return-Path: <kasan-dev+bncBCXLBLOA7IGBBFGH3HVAKGQENPMAAOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id ACEB38FCEF
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 10:04:36 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id l16sf1086424wmg.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 01:04:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565942676; cv=pass;
        d=google.com; s=arc-20160816;
        b=TyS5HC4Pjc1wt4xdXMKAtX10K6XJeVba7vhj9CcqmqCGB2MaU6bfgZiy+MtN+MJfrQ
         tZgeuQrCYe2W5PcpxRxP8t1fNlW42qMRvWoDhHLZ5sprS5ObIjeCw4+V4EDoTHczrfZY
         ztYqpLsrKdwgfv5syb9sHbaU3w7E63kQgZkLFmPUOkmMNazagXp9vkvZmKIHD1N7QYRQ
         f1w6oHwvMdHeue67Q75+6NnmVGUO7C8eKfoK7WbRfTdmX37WtfVlW7jJh2TaWjhn9d4+
         inuDSctlkX3da/TOtCaVF6Vulp4UrnmWqfgOoCbxaChHG2+gql6oI6/XtjOH3t9QxRMj
         BA9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=l06rXdEgTgR2Dn9Y9a8wkCdWyt0IDoDP/8i/4tRxMww=;
        b=nOoD5DUP9r61vwC3SJE6M6MJ/p4B6YhFf5eRvgrgiebqWbLEUfLNK05Dme9CySpDOR
         kO5fTpTGZEFc/L6hR0YZ/8ZNx5QNozdDMxfOc6etCgrEuiTeHJyRUcnC8ybrHtWiLGld
         3OKaNyvtxT03MDanAEqo7Bkq7O2AejXAK8utgVxLjs5YfQh4NfKVqIbGw/4kZ42RWJEe
         RMAM8m/aYMnHgXy6QWX3uedtRa1dRvkdCZYtk6Sx2zkqZWaYszpXIILrhk0KqzzaiaOF
         iOm5CPiB+4PqSLz8hKvIzazzpd7ac0QmPNOzYyBt6EWJ/2WLAIteTzLVsi9+ghb+XH/t
         7uBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=FEQpuqzB;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l06rXdEgTgR2Dn9Y9a8wkCdWyt0IDoDP/8i/4tRxMww=;
        b=KVfsSs+nH02+85H6WxHStgNVWdpNTK2VMxSAeUXWx9JFvMnAl8OGQZQjRdiumneSZG
         1djDSgVuqnIeAVVsXD68Xhbjbxq9hPBJsLHAX0HgxiBQ1ov10Fr4jvV+t89ULG14f0bx
         25oDbAlB2xVwPNE9BoYpWUT/fhQPg4s+2wfyutpqcEn0hbtpUur8BRADoJ9pWviBck0l
         hv4RjUlS+Ohh0m4QO7XzAfrXvRmTomhzFFmQtcp4EamSsI7UtiI9dquckdEbYWFWhFqz
         CHcHkMaCNqJJBQzzcMwOUhd2YF5Wl09XpXfSNGt1pKhwmXsZlb8+EuWaiFGN5QI2KJZR
         Mj+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=l06rXdEgTgR2Dn9Y9a8wkCdWyt0IDoDP/8i/4tRxMww=;
        b=mbE2aszMCAHmj8HR3zhKsZam0Pej0SFk+U5E+UQPBGRCpnsoHqc9VUB07i+5ix4bI8
         +qniLfUG9kiEctqEbN/OxMKjhBevQTcXML3RAvMqmQfmAfvmbxrbnTaYMJ7PQBUhH7Ls
         YX62eA7jBJAiRecqmP6bRxb7y0/sT69W51wVATZTgd/iH3MhiZ0+3nyUHrW5thiAZ0xR
         jCOf/uCK8gfLTWkxBuhFo+c+3SXXPepv4RTfnUJuziDJ4RkZw/NHIGbGR69WjLEvfE31
         djo86wPNy0WyTwjS9XPnjdDwBQyTIB95xKCKwFx2fTD3m8MbRxikbjfUIg5QOp/rYlTD
         5T+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWg/IGLIXTiaqF7kqhjEbURc61OTVhNVg90qopbOj4BGNTBxanY
	+k54bEuDp7tzrfp2F5jnz9c=
X-Google-Smtp-Source: APXvYqxj82gvAYbucQJuPg3tYieiMVMUI5OB+bHCU5LzDlbl672TCzPN2IHdfX7RNzeGbwhSqf12Aw==
X-Received: by 2002:a1c:c706:: with SMTP id x6mr6108317wmf.104.1565942676268;
        Fri, 16 Aug 2019 01:04:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9d02:: with SMTP id g2ls1331413wme.3.canary-gmail; Fri,
 16 Aug 2019 01:04:35 -0700 (PDT)
X-Received: by 2002:a05:600c:551:: with SMTP id k17mr6032748wmc.53.1565942675836;
        Fri, 16 Aug 2019 01:04:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565942675; cv=none;
        d=google.com; s=arc-20160816;
        b=0yPLYon2A5Jf+gvN0TS+xr6f6Fct3RZAkABnZD2wv9mGf9eSHsRzverEEsUJxp+iET
         oTW5kDyVtiAgGJdD+18nfv+i8dAIgij7sl02b18Zgt3mZaNyhthsP4Y3TgL/WBxdaS3n
         wrV9hcMgK3eAblOfHpcV4VSz2jxJIi+kn28q0DZYXUbqw3uNIJeOkL6zDO3NEfrj5Yux
         ezs0Dcn4SmLg9dBbdn/WcZzgCyiu4ceP7o6YoL8TZ7h6UOtpQO+OhZKdFjsxiC1Peu+4
         l0O4uo2/iq5VeNFBRUDd7EsRyrPB/eemzFYC+t1c4enGuV+4sTe+OfJKOJ/mi2HLfN0g
         A/Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=IwjKUZFfoo6+PRRG4jenIhfB1rMdpLyzjhvMP8dxpr0=;
        b=RG9c3tjxjJsqfbHgtQ4PhKloKAGpd8OX/yJRDFyrdMNIXic0MK0prd4fq94FN5Q9aZ
         9gdo3DLLdE8auteB23r5ZBFeBUnyDV9KGeRkVmZ0mGzR2QAkP+Z1DaMwqW3dxnQBfVLT
         aLSsvgP7/P1mdx8ai9tgruF1vDXu/hjZWBBV6iNGWkUWN9v6eGn3ykA77qTHcbdtDtMo
         ca2qaXhjRGckVmubDU/lmxO58EjUV241YAmQvtGKqv+UlGUGQTqUC7sid8caRwHbLfmd
         6PPRFXFZmDm+xjW9ub6gGrZenXf09PG5ykCKN6bxdL1F8K/rfdd0ChYvQck1Pp2gIcch
         myYA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=FEQpuqzB;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id a10si201038wmm.2.2019.08.16.01.04.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Aug 2019 01:04:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 468wpB2JnLz9tyXh;
	Fri, 16 Aug 2019 10:04:34 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id lA6E5j-wl7KL; Fri, 16 Aug 2019 10:04:34 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 468wpB18g7z9tyXf;
	Fri, 16 Aug 2019 10:04:34 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 4F3288B776;
	Fri, 16 Aug 2019 10:04:35 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id lzTZTjOCDTZS; Fri, 16 Aug 2019 10:04:35 +0200 (CEST)
Received: from [172.25.230.101] (po15451.idsi0.si.c-s.fr [172.25.230.101])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D22958B754;
	Fri, 16 Aug 2019 10:04:34 +0200 (CEST)
Subject: Re: [PATCH v4 3/3] x86/kasan: support KASAN_VMALLOC
To: Daniel Axtens <dja@axtens.net>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com,
 glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org,
 mark.rutland@arm.com, dvyukov@google.com
Cc: linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
References: <20190815001636.12235-1-dja@axtens.net>
 <20190815001636.12235-4-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <d8d2d0ae-8ebc-d572-7a62-f17f28cb1bac@c-s.fr>
Date: Fri, 16 Aug 2019 10:04:27 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.8.0
MIME-Version: 1.0
In-Reply-To: <20190815001636.12235-4-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=FEQpuqzB;       spf=pass (google.com:
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
> In the case where KASAN directly allocates memory to back vmalloc
> space, don't map the early shadow page over it.

If early shadow page is not mapped, any bad memory access will Oops on=20
the shadow access instead of Oopsing on the real bad access.

You should still map early shadow page, and replace it with real page=20
when needed.

Christophe

>=20
> We prepopulate pgds/p4ds for the range that would otherwise be empty.
> This is required to get it synced to hardware on boot, allowing the
> lower levels of the page tables to be filled dynamically.
>=20
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
>=20
> ---
>=20
> v2: move from faulting in shadow pgds to prepopulating
> ---
>   arch/x86/Kconfig            |  1 +
>   arch/x86/mm/kasan_init_64.c | 61 +++++++++++++++++++++++++++++++++++++
>   2 files changed, 62 insertions(+)
>=20
> diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
> index 222855cc0158..40562cc3771f 100644
> --- a/arch/x86/Kconfig
> +++ b/arch/x86/Kconfig
> @@ -134,6 +134,7 @@ config X86
>   	select HAVE_ARCH_JUMP_LABEL
>   	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>   	select HAVE_ARCH_KASAN			if X86_64
> +	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
>   	select HAVE_ARCH_KGDB
>   	select HAVE_ARCH_MMAP_RND_BITS		if MMU
>   	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if MMU && COMPAT
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 296da58f3013..2f57c4ddff61 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -245,6 +245,52 @@ static void __init kasan_map_early_shadow(pgd_t *pgd=
)
>   	} while (pgd++, addr =3D next, addr !=3D end);
>   }
>  =20
> +static void __init kasan_shallow_populate_p4ds(pgd_t *pgd,
> +		unsigned long addr,
> +		unsigned long end,
> +		int nid)
> +{
> +	p4d_t *p4d;
> +	unsigned long next;
> +	void *p;
> +
> +	p4d =3D p4d_offset(pgd, addr);
> +	do {
> +		next =3D p4d_addr_end(addr, end);
> +
> +		if (p4d_none(*p4d)) {
> +			p =3D early_alloc(PAGE_SIZE, nid, true);
> +			p4d_populate(&init_mm, p4d, p);
> +		}
> +	} while (p4d++, addr =3D next, addr !=3D end);
> +}
> +
> +static void __init kasan_shallow_populate_pgds(void *start, void *end)
> +{
> +	unsigned long addr, next;
> +	pgd_t *pgd;
> +	void *p;
> +	int nid =3D early_pfn_to_nid((unsigned long)start);
> +
> +	addr =3D (unsigned long)start;
> +	pgd =3D pgd_offset_k(addr);
> +	do {
> +		next =3D pgd_addr_end(addr, (unsigned long)end);
> +
> +		if (pgd_none(*pgd)) {
> +			p =3D early_alloc(PAGE_SIZE, nid, true);
> +			pgd_populate(&init_mm, pgd, p);
> +		}
> +
> +		/*
> +		 * we need to populate p4ds to be synced when running in
> +		 * four level mode - see sync_global_pgds_l4()
> +		 */
> +		kasan_shallow_populate_p4ds(pgd, addr, next, nid);
> +	} while (pgd++, addr =3D next, addr !=3D (unsigned long)end);
> +}
> +
> +
>   #ifdef CONFIG_KASAN_INLINE
>   static int kasan_die_handler(struct notifier_block *self,
>   			     unsigned long val,
> @@ -352,9 +398,24 @@ void __init kasan_init(void)
>   	shadow_cpu_entry_end =3D (void *)round_up(
>   			(unsigned long)shadow_cpu_entry_end, PAGE_SIZE);
>  =20
> +	/*
> +	 * If we're in full vmalloc mode, don't back vmalloc space with early
> +	 * shadow pages. Instead, prepopulate pgds/p4ds so they are synced to
> +	 * the global table and we can populate the lower levels on demand.
> +	 */
> +#ifdef CONFIG_KASAN_VMALLOC
> +	kasan_shallow_populate_pgds(
> +		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
> +		kasan_mem_to_shadow((void *)VMALLOC_END));
> +
> +	kasan_populate_early_shadow(
> +		kasan_mem_to_shadow((void *)VMALLOC_END + 1),
> +		shadow_cpu_entry_begin);
> +#else
>   	kasan_populate_early_shadow(
>   		kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
>   		shadow_cpu_entry_begin);
> +#endif
>  =20
>   	kasan_populate_shadow((unsigned long)shadow_cpu_entry_begin,
>   			      (unsigned long)shadow_cpu_entry_end, 0);
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d8d2d0ae-8ebc-d572-7a62-f17f28cb1bac%40c-s.fr.
