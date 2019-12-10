Return-Path: <kasan-dev+bncBCXLBLOA7IGBBTH3XTXQKGQEEZLWFDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E964118094
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 07:40:12 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id f1sf6584250wre.14
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Dec 2019 22:40:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575960012; cv=pass;
        d=google.com; s=arc-20160816;
        b=jDd9mN1HkoTkeeBznsO4V0sk4lYMOi8Lf6psymZWCAebbd7Ps1o4DiwDoiobvtkBos
         ar1CNmnNF6guvWi0LEerBmgEBw+78jdtrQQrpwnKN4/8DNWCLOHwva4EyBsnDoljS37Y
         LhCr7b+6sj/Bj1M62uzhr5gUIq7kpS+BcTB2m8PKg7lNjF3HmGGyOxywchJrLVoLUQHM
         ty71PdfcU724A0fP7GCT1isG3Js6YrsYOtAWh299MmPPl8F/y74y8Edt6M6RvBGCwrqh
         M1EhnGj1Jnn/T+NcT2gUAktSoat4F43I61bzVnvOwrOkfhVEnpmsGcVPqeG/BFWqYFlI
         FJYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=qHKkjaJIAgGPz5Hyix13nuzrEPFJc6pI9a9WlitLJhA=;
        b=0aLbdn1Cnt91QdwgyiLoVMCM7+X7nedNXLrwwduAI9HKVDkc66S51VIbDdR3h4ssej
         dlzEwdi5k2Rmz+rlWDJ7n2QVa0UQqCAt6YBCM3visXSeEXwZxdRnTZkLfO3iNs1zosGo
         VZ6m5Ez33r3Mpk/+Oq3eQPRWOxKXER2jKJWZes7kKZAhyxApuy2PJn2M67V5jEfflwWi
         c1x4IhIkvnS7r1zoBc0NRtLm27iud8bPTsGLgGGtqsK5d8sN6yceiofwDWkNN9uzgDPI
         9xHGnVAWBhmw6wCH7j/0rtrDiWv9IeUWuRXZT4aiMi5n2F0dPvMtfZztQBYGKnAVxVw6
         KpJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Ae6vJj2Y;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qHKkjaJIAgGPz5Hyix13nuzrEPFJc6pI9a9WlitLJhA=;
        b=PVav73zCnB8Cb4aFgBvvFJGvBkj6D2tbKNlJlbqx+Vn2/2KOotZbnK0zs00PNFoW2u
         CM84yMWBYXafgPO+mtKyv57c9irT3lzVQNBgYgUoYDq/Ea8cZ9eq0EfvKeiDwio1qjaE
         FLSkdilS5se0Gl72S66V8sq3CkdfAUuFJHee+ir56PdPgWD+48K5xOspTB3EzJbI0X/k
         hwcBHyxYnzfZuMj+3MO53FNbibOC3yuFnGRCMxOrv97Ysd4JEGaUGd0m/1JKm2gn8kXm
         SSJQvXq61mTWnyObNaabT0rY2v3/0JarNjfaLkTvbdpnDfQptucUGU7Ch9nbYuezn0to
         emcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qHKkjaJIAgGPz5Hyix13nuzrEPFJc6pI9a9WlitLJhA=;
        b=oPwFfVm1/5VfJp5DqCcHoIN+y/2eNMEA0VNlqBoQoeGoTQ7epTMrUxKxxfKwK8RFZ+
         1xQi9cGxeRs+4DkDMBIie1nMwRkGfwTCwRi1FZBVo6M4oCGUn8UZ6VwuADi4pbasFFWB
         9ye2vz588sjiasa/qH4XDRUxStaDZEt+5cd4qSxBqsoSS7tTLAKjqszpf4Rw+K7WzhYJ
         4qXVwNGNy19m2FGo42NYYMESYG/AKiIl6tbyspIoYbvtO7474ZtYgDiOqSaL96lZLpW7
         1PcXIj8ciwQR2L2SWg6Ig1SoTaEMKaeU9nIxsWbe7eq+XBSK/dNcz1Za8rqn0o2yo2ci
         c3tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXEY1CPRbFceC7LXQBK1cO1etMZ7MCg5mSzwypyN62kQP7UDGzv
	MVfhet2sLyT0hDvQV7n1cq8=
X-Google-Smtp-Source: APXvYqwwf0d+ltnGOTiB1RNMpUJrv/m3See+TOWZTJqT6ThK0rmeQ3VUISLcLswvFsDr545UIamnSw==
X-Received: by 2002:a05:600c:24ce:: with SMTP id 14mr3279109wmu.122.1575960012274;
        Mon, 09 Dec 2019 22:40:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c452:: with SMTP id l18ls333418wmi.1.canary-gmail; Mon,
 09 Dec 2019 22:40:11 -0800 (PST)
X-Received: by 2002:a1c:7911:: with SMTP id l17mr3333071wme.44.1575960011763;
        Mon, 09 Dec 2019 22:40:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575960011; cv=none;
        d=google.com; s=arc-20160816;
        b=uvstPs129Q1fkx1ww0fjlSKQbV6XXK9ztAly+DHzgAMK3jPNBewZLdOShXmlTUDAfm
         tq7NQkUAY1AKcRoBCnO+jkR6Rbl+wnNpPgW7DLbBkgq+mqBZ5ByZzL0v8jpXJeuV8i2z
         fhHOdmp/CqA61thV7fCoRo7PoHcHJc5/lBsS/0MXKqeS4gdZFrT1EH9pIfcqvkusJWem
         BmruDlSuIpCXdkb7xPxgl2sLQtEjPHrX0kHm+VgrM0gpcjF/92vEZIGX88OCJUToHMqd
         pHivTSNxXzt9qnuyn5Vx5AY78Sk+dhatKqLfXuUVzMz4d42nmFJfZne8tOvQ4QB9hFOm
         hVcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=OwdtjKhxdr7/aZ16cXB8T6/F98lgPqZDHw00Knn9Q18=;
        b=KxvOOmEvEgDf/4EEIiTKDxs+fPRSbaXZv+Bei1pTN/rJQPoEFIn6mvjvWdDTzpMR9Q
         vF6csokPu06uRUuZJN6rK4Ou4E/IP1Jyw8tbooSWb4RPmPP7EKIBSov7ejn0BtZeScZg
         JqGuFbGx6oNJD4x2wuj12EWbQI8vdQkeITEokUArqeEYrBv33mUOMq6a9uD+WfftEcsy
         MbVCzhBPRRwATDEu7UjyXpmo7x33REy9JxlYB8oqcj0b44Hkj4y6wz94liObl+3k1UwH
         8sZqwj7gVpUt/+giDcRbhlo07966J0g5UH+NsN+5ZXFNCBjnNIualVCTzoZKN5LbRfkU
         dORw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Ae6vJj2Y;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id a138si60185wmd.1.2019.12.09.22.40.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Dec 2019 22:40:11 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47X9RG3vN1z9vBn0;
	Tue, 10 Dec 2019 07:40:10 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id XNdOmwdsKvbG; Tue, 10 Dec 2019 07:40:10 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47X9RG2WmWz9vBmy;
	Tue, 10 Dec 2019 07:40:10 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1A7218B803;
	Tue, 10 Dec 2019 07:40:11 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id ITyi-BVxuytF; Tue, 10 Dec 2019 07:40:11 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 135468B802;
	Tue, 10 Dec 2019 07:40:10 +0100 (CET)
Subject: Re: [PATCH v2 2/4] kasan: use MAX_PTRS_PER_* for early shadow
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org,
 linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-3-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <de333171-6697-aabc-70da-c9d593adfb08@c-s.fr>
Date: Tue, 10 Dec 2019 07:40:09 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.1
MIME-Version: 1.0
In-Reply-To: <20191210044714.27265-3-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=Ae6vJj2Y;       spf=pass (google.com:
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



Le 10/12/2019 =C3=A0 05:47, Daniel Axtens a =C3=A9crit=C2=A0:
> This helps with powerpc support, and should have no effect on
> anything else.

As explained in previous patch, this patch is based on MAX_PTRS_PER_Pxx=20
existing for every arch using KASAN, allthought all arches but powerpc=20
will define it as PTRS_PER_Pxx.

I think instead of forcing all arches to define that value, just define=20
a fallback in kasan.h (or somewhere else) would help keeping the changes=20
to the minimum, see below.

>=20
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   include/linux/kasan.h | 6 +++---
>   mm/kasan/init.c       | 6 +++---
>   2 files changed, 6 insertions(+), 6 deletions(-)
>=20
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index e18fe54969e9..d2f2a4ffcb12 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -15,9 +15,9 @@ struct task_struct;
>   #include <asm/pgtable.h>

Add

#ifndef MAX_PTRS_PER_PTE
#define MAX_PTRS_PER_PTE PTRS_PER_PTE
#endif

#ifndef MAX_PTRS_PER_PMD
#define MAX_PTRS_PER_PMD PTRS_PER_PMD
#endif

#ifndef MAX_PTRS_PER_PUD
#define MAX_PTRS_PER_PUD PTRS_PER_PUD
#endif

#ifndef MAX_PTRS_PER_P4D
#define MAX_PTRS_PER_P4D PTRS_PER_P4D
#endif

With that you don't need patch 1.

>  =20
>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> -extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
> -extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> -extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
> +extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE];
> +extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
> +extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
>   extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>  =20
>   int kasan_populate_early_shadow(const void *shadow_start,
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index ce45c491ebcd..8b54a96d3b3e 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -46,7 +46,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>   }
>   #endif
>   #if CONFIG_PGTABLE_LEVELS > 3
> -pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
> +pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
>   static inline bool kasan_pud_table(p4d_t p4d)
>   {
>   	return p4d_page(p4d) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_p=
ud));
> @@ -58,7 +58,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
>   }
>   #endif
>   #if CONFIG_PGTABLE_LEVELS > 2
> -pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
> +pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
>   static inline bool kasan_pmd_table(pud_t pud)
>   {
>   	return pud_page(pud) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_p=
md));
> @@ -69,7 +69,7 @@ static inline bool kasan_pmd_table(pud_t pud)
>   	return false;
>   }
>   #endif
> -pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
> +pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE] __page_aligned_bss;
>  =20
>   static inline bool kasan_pte_table(pmd_t pmd)
>   {
>=20

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/de333171-6697-aabc-70da-c9d593adfb08%40c-s.fr.
