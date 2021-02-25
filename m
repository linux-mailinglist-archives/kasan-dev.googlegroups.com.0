Return-Path: <kasan-dev+bncBC447XVYUEMRBR5M3WAQMGQENGCENPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id CFB73324B80
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 08:48:23 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id h16sf1466151wmq.8
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 23:48:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614239303; cv=pass;
        d=google.com; s=arc-20160816;
        b=PflCPO2cRNHeUBq+l2oJ0xJ7amt0/z0caB8NhIEqKTOcwTawnpDDlt3nALthK1uZeB
         Own+UrjrBQPysQQkwG9rPTrQyM+vl6EKQRfrxyjNft+h7UlcI4Ybt0jFA/j3n310ESVz
         UZAMaPtKgGHx1EKnNElQkhOc+leKW7NYanQZCZu5GmX0Yj3HTr0XUdrn5pV0t86ecEAX
         kkny7LfOsDk/zrSVIVqtMwNARYCh8dCDy2ly/DkzvrPu88Dt4XgpeQLTsvFfe6qcTjMH
         zzHtyo8La10948nERN6SFJ1qvmHWnM8bscQIJ1QIrfNun7o2Az2qkzTAnQuEHZ1imRah
         S3Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=bBXeb7YQ8qQlbAlt1l/O784qjzRMnbcwSYD0iqg3BrQ=;
        b=JZIC8Xus5d8bXp3DXLo1gKYHTkkRSr7jJ6k7BsV26O6PV7AMaBl3krpnZP9MbhuwP7
         B/oy4dvXVeDbOMcbyDGCIH8Pm0xulr/zCD0oNZ8ech6KAmAjRbEt2jejdnHURy2S6WT6
         q1umj/U4AuHlgDkHf/LmWJ8RgOn/0+H5zETBM1vGrga4IKy6MvLpK1zqfgxrHbYcZFah
         K+BDjR2RzIPE5ISeNYuWiCiFhvZpnjlg8mFU3HmKSjHnj75xN7cluvWzgAxhsSY2Gxfc
         BlgKZtTXVTPYS61fBG2fM3pcCIK3gE8S7pshblMhJB+CwyL4ZgHyezJEPQlJdmN9hKt/
         mrew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bBXeb7YQ8qQlbAlt1l/O784qjzRMnbcwSYD0iqg3BrQ=;
        b=XHF9YXFXYxqpzIhY94caVzWiA0usa+/JvknLW2C/+De1/sg1g1ZEkHsOIqtk3guAC6
         HAQPXLV/bfY7zjg2peu7h0MZgH9RKvOarAtlLYIQoywRIYWv9w6NK8as9xSdEJmoVhlR
         n3BzwsSwHmRkNpV8AOfE3ps+/knt3P1MREB/EFkYr5PrnT34pUoOv39h1g5ebHRy3xSH
         KT7/GP0cF9XimUADXNEAWdcWu223ld7zQq1zcWfsi0/aUE71dtiF9Ez4nlHcNyMYS6gq
         TmgC5pmyJogr22GaEBEQKT78n9uuGox7vD2Co7Mrq0qOylyZUduBUruNe44OAQOkXZ6+
         HzgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bBXeb7YQ8qQlbAlt1l/O784qjzRMnbcwSYD0iqg3BrQ=;
        b=qnj4YBMq6WbUibej+u3J6A90i+9G43LsxtHun8T/lnDc5o8bq7vJdAHrpEpOqrKtHp
         MPxNAdu0mm1fZuLST9rOYXG5Yf2CrHx/jXw9c+zM5N82i1x+wArjvQedS70byuFvcUYd
         82ysrkDFjjkIRkpQuKifcr38Z/91FyS/BC9+F8TSNo1ATtvs62/Fw7ICazRtOozqgafD
         btvAQdxP2AJO7u5ZGye6jDiKxryygm1Q6IzVrlLk55MN0IvA9hO2STJL4nyN+RtkfrAO
         RW7/r+7a+iUlZfRtFKcaFkk1G4VEq+rbN6pp92aIptkvN5ppJKQTvFp7jR5ofuTgdzU9
         bXuw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531DO0imqmCp7cYGBEs66lLjyoyOJo9b+giZa5RyDUrefy7GGAa1
	v7qRIMqNUqRb6RO5gi5QqHU=
X-Google-Smtp-Source: ABdhPJzA1SKsxgX405ep5oVpIWKQn+eweyEEs1m4aEmr+w5C9eX4t2/9Ewdqkf3+kQE7PrE9Lahzew==
X-Received: by 2002:a05:6000:18a3:: with SMTP id b3mr1990062wri.373.1614239303601;
        Wed, 24 Feb 2021 23:48:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5592:: with SMTP id i18ls4280666wrv.2.gmail; Wed, 24 Feb
 2021 23:48:22 -0800 (PST)
X-Received: by 2002:a5d:4ad0:: with SMTP id y16mr1962343wrs.399.1614239302684;
        Wed, 24 Feb 2021 23:48:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614239302; cv=none;
        d=google.com; s=arc-20160816;
        b=wA32qxXB1r4lEcEK6fGdK8+sibSnkmFThf7uYP0nW6JvtOEIAVQ7WH0kmP+zJmhUl2
         sxW68u3iEgZ/lg0k+dAlZh6V/kfP8x2j9fPMoJk00r2uUih0lOTeCetqNROp8fKHUqUU
         EWVxH5gw7DhnONtvVF/fkrqxy4XkThbrfV/l3CiohclcajNek1bTWOVab+9KphXzX6wy
         ly0XE2e6ZbzJ9snKXxsKGN7NNyV7smBLVa0Ip1N2Xx0ruIsd2yRogIMlOQBcECfUB3RV
         eqmF5pkuP5Zoj/jIQpIqE61fjcI9YMUh7720pBZQlNf73gyHT/E2X2fck+MnObQ766lm
         OEaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=kiU34z/6dfIrzGkzds6PWGiPGyCNW+yhDpsz8IjSqlA=;
        b=c/HqBeN1cIOe3vpnvxyfUxY02arVf5mLNZM3duX/WaAu34O6ijsGyHbLdM8ERuvpu7
         U3J2xL60RxaLjNUvgjTdUWqVQVYQhnIxvSDnOThbkf9V0jfaxQ/KuDT+OmoJTy5/q49x
         GH5MFClM/ZB0ZPDnP4hKkVh/+r/pXLhbiJ2mmb2WEw9EMaIEzpKcEp2IusO8QLx+cll2
         0Xnk1ILJ1AtNb/uZotjcQ4rm9cSQqb1qo6MT+qei0K/63q9zZUtP+38Lubn7vNOqsrYj
         qp5JU99m7OdzIHe8q9ZHQElw5mQIk6K4+lGWmBj4rkDNT605Mhja17D6Sq8F/C3incO2
         IWog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay1-d.mail.gandi.net (relay1-d.mail.gandi.net. [217.70.183.193])
        by gmr-mx.google.com with ESMTPS id y12si235874wrs.5.2021.02.24.23.48.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 24 Feb 2021 23:48:22 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.183.193 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.183.193;
X-Originating-IP: 81.185.161.35
Received: from [192.168.43.237] (35.161.185.81.rev.sfr.net [81.185.161.35])
	(Authenticated sender: alex@ghiti.fr)
	by relay1-d.mail.gandi.net (Postfix) with ESMTPSA id 5F65A24000A;
	Thu, 25 Feb 2021 07:48:14 +0000 (UTC)
Subject: Re: [PATCH] riscv: Add KASAN_VMALLOC support
To: Paul Walmsley <paul.walmsley@sifive.com>,
 Palmer Dabbelt <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>,
 Nylon Chen <nylon7@andestech.com>, Nick Hu <nickhu@andestech.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com
References: <20210225074227.3176-1-alex@ghiti.fr>
From: Alex Ghiti <alex@ghiti.fr>
Message-ID: <bdef5309-03dd-6c0b-7d0c-9dd036ceae95@ghiti.fr>
Date: Thu, 25 Feb 2021 02:48:13 -0500
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.7.1
MIME-Version: 1.0
In-Reply-To: <20210225074227.3176-1-alex@ghiti.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.183.193 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

Le 2/25/21 =C3=A0 2:42 AM, Alexandre Ghiti a =C3=A9crit=C2=A0:
> Populate the top-level of the kernel page table to implement KASAN_VMALLO=
C,
> lower levels are filled dynamically upon memory allocation at runtime.
>=20
> Co-developed-by: Nylon Chen <nylon7@andestech.com>
> Signed-off-by: Nylon Chen <nylon7@andestech.com>
> Co-developed-by: Nick Hu <nickhu@andestech.com>
> Signed-off-by: Nick Hu <nickhu@andestech.com>
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
> ---
>   arch/riscv/Kconfig         |  1 +
>   arch/riscv/mm/kasan_init.c | 35 ++++++++++++++++++++++++++++++++++-
>   2 files changed, 35 insertions(+), 1 deletion(-)
>=20
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 8eadd1cbd524..3832a537c5d6 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -57,6 +57,7 @@ config RISCV
>   	select HAVE_ARCH_JUMP_LABEL
>   	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>   	select HAVE_ARCH_KASAN if MMU && 64BIT
> +	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>   	select HAVE_ARCH_KGDB
>   	select HAVE_ARCH_KGDB_QXFER_PKT
>   	select HAVE_ARCH_MMAP_RND_BITS if MMU
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 719b6e4d6075..171569df4334 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -142,6 +142,31 @@ static void __init kasan_populate(void *start, void =
*end)
>   	memset(start, KASAN_SHADOW_INIT, end - start);
>   }
>  =20
> +void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned lon=
g end)
> +{
> +	unsigned long next;
> +	void *p;
> +	pgd_t *pgd_k =3D pgd_offset_k(vaddr);
> +
> +	do {
> +		next =3D pgd_addr_end(vaddr, end);
> +		if (pgd_page_vaddr(*pgd_k) =3D=3D (unsigned long)lm_alias(kasan_early_=
shadow_pmd)) {
> +			p =3D memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +			set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
> +		}
> +	} while (pgd_k++, vaddr =3D next, vaddr !=3D end);
> +}
> +
> +void __init kasan_shallow_populate(void *start, void *end)
> +{
> +	unsigned long vaddr =3D (unsigned long)start & PAGE_MASK;
> +	unsigned long vend =3D PAGE_ALIGN((unsigned long)end);
> +
> +	kasan_shallow_populate_pgd(vaddr, vend);
> +
> +	local_flush_tlb_all();
> +}
> +
>   void __init kasan_init(void)
>   {
>   	phys_addr_t _start, _end;
> @@ -149,7 +174,15 @@ void __init kasan_init(void)
>  =20
>   	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
>   				    (void *)kasan_mem_to_shadow((void *)
> -								VMALLOC_END));
> +								VMEMMAP_END));
> +	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
> +		kasan_shallow_populate(
> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
> +	else
> +		kasan_populate_early_shadow(
> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>  =20
>   	for_each_mem_range(i, &_start, &_end) {
>   		void *start =3D (void *)_start;
>=20

Palmer, this commit should replace (if everyone agrees) Nylon and Nick's=20
Commit e178d670f251 ("riscv/kasan: add KASAN_VMALLOC support") that is=20
already in for-next.

Thanks,

Alex

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bdef5309-03dd-6c0b-7d0c-9dd036ceae95%40ghiti.fr.
