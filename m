Return-Path: <kasan-dev+bncBDLKPY4HVQKBBSM2WGFAMGQEHR374LA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id D33B9415B44
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 11:47:53 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id m20-20020aa7c2d4000000b003d1add00b8asf6310732edp.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 02:47:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632390473; cv=pass;
        d=google.com; s=arc-20160816;
        b=BfPeEae9955p8Lr2AiWH1Iwi1GkEQwiadmrdg6KHUlVMK7BqS8OXkFuz00CWJqvBvB
         Fiwoz7ztpfcz83oMmuPc6CkTEFFyeOn0fupj8MmQ+gTugaem3NE1PhByPecCu/inV8SS
         ADG+7VRFOKBH3mi2j/0Qf9BD+ljj5v5oizZFkhxXfEm0TC0EE32Y+jz74hxeJD9PEpqb
         4aaCOXYLlNynKELvu11JacVjLsPXjo8BBnHdTPGLN52WHtLItrs2YaZz8hmdsCm0tWxy
         nyy4ISq38FOrev1WSdeF+ywGXOLnl6u1N3AbVel9GdWrbG+L9KGE65jL67L+hhxTBNQ5
         Hz1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=Y84b/BX/uOSF+BnAEUyFx2C4x+MaXrD5ZDqd18OgOQI=;
        b=QkskdC7YlxZgKZDHC7uW34bsoRNJeAc577+kUgj4MMZww54hZXAmW7LsMWZtOYHEeW
         7W3Zj7ckYu2KWFul+zqbB/3BEZQM8UIIcAOyUkZIx8akVwa9ODcMugy0Kx/X1+8cjg4H
         bFIBETxmm+XF8WTmUWrMWa+BQ0TYb0E75wVTaOJgVuuYBg/rEG3/bkzRc7V2LeP+NCan
         NnvUf/Vc5RHJ9iGxFDATMdzBKr/ZXdTUsfXdswWd92z+yEynbiZVDzTWNdOR1LTMpktE
         xOQTNmjLP1/fWe+r+ly5+t9pmNI1Z5MtjPgO/TJa/fLvq1jz6OBuIqw5MdhRgei1fadC
         u3jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y84b/BX/uOSF+BnAEUyFx2C4x+MaXrD5ZDqd18OgOQI=;
        b=VbawR2N+KCTmtLKt+5hsv8YLH+aR2GoLIBQHhftMlwMnArU8e3f2bFNDLu44MGQnsY
         Oz8aimZUBsSUT0H5LTJClGENcw2MzEMqkK3TxRrN8l/YkaF0Hyse6uC2GjkU+mLjcjym
         MPW1MVdByNbPp6Hn9NuCTuhMe8PIeqkPqrJK/AIKvdRPRYHGSWl11epq20sLa8VfEuqv
         3JCYZbP0Y7korqodhA4LTGWQ+bVC111DzwEPVNBh+Ru2eyQgeymB3u5W2/aa0mAPcjMS
         mnb7RqnLnR11VstuAhrPzQStHlCs1Ot09ezPkDqPdyc2XA8VeXZc9XrpjBy2tw1CIcHB
         BXMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y84b/BX/uOSF+BnAEUyFx2C4x+MaXrD5ZDqd18OgOQI=;
        b=x6nX1RPKKrTOxiychLV7rfXBV6XqIB2Uyg87kNqcpRrZpZrY7ViX7nIYfp/80etNHj
         olFcDOTQLHwSaWZnm6c8ABt8TjwBZYRdu9TiFEoWt0KNSpZffL6GYbOC28t9Y/8wqIcI
         LUZ1a7+DTG8l+PsHnvLGsfJiRVp14kCPDIAKVUuZpIFT5fQ/LpfD9e5msvcZ0qTLLVTs
         Cg5TaiFWr538fVKjj/csgztJgn70Rcg7Q5oeHMhxag+FUwN4oKDZekwlcdOMoubUemxz
         xelNJEH/4hQTmj/6cT0cKD2NMMasY4rwpFFC3kmPRQ2b1wwi/o9hCfY3uSS3484pPsYf
         QlaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KhfcMu/FVlb4QufHmP9CW7wHJUIqHtOzG++oqfRAwJ5sVC9CU
	N+9ON8gPrhaJiunI1RxahjI=
X-Google-Smtp-Source: ABdhPJwfgvmrODK6MpyRIwS83vPsReELZUmOIlRQNXieH4ede9kiFA3JQS/HEoEBiv4T9hGzNsw6uw==
X-Received: by 2002:a17:906:3ce2:: with SMTP id d2mr3991959ejh.410.1632390473561;
        Thu, 23 Sep 2021 02:47:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5941:: with SMTP id g1ls2443759ejr.10.gmail; Thu, 23
 Sep 2021 02:47:52 -0700 (PDT)
X-Received: by 2002:a17:907:2637:: with SMTP id aq23mr3724880ejc.367.1632390472650;
        Thu, 23 Sep 2021 02:47:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632390472; cv=none;
        d=google.com; s=arc-20160816;
        b=L080hNDAOtjahb/TbL5XwZU2LvZNfNSGk/57nzQCbhx+ztWrP2NQfzSuUw9xwFj90k
         CGfQYfeUG32DoFwTpKc1GivnbaHVUzhfKQtl6nuKeGefj0kWfXWWMTwZN6FWJBrJ52Rf
         ZdKxGMNQs7sNlCyEBtK9SYxKeE7oB+wkmsPZNsCVF5faaSkG9Jr93UQyBqSkgguiX6EZ
         q+lFvW80dncG45vcMJvbwhFrcfPvZLO9zhxv6NjP3MlMeqyEPpTRewfUmld05NvPuI0g
         ga3tLLGlGmE46LtmvbHfhAWcZ3NVt+5kTTcrBFSRthnsb/fdiAsecIHcd0oTI+9Sym59
         jDiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=7dkB4YftKEtJxLwwwy0sZKaec62sCoeLdxn2t6GHcyU=;
        b=Aj717evczDM5YpHzUu9YUnbSzKVjInlrqDig9e3N4NlV6iweI6S99S4MVVHMMI9xdO
         kj+1JE8Ac9P2VdE6Z80Y462gIG7mKipy2XPYu7jLp30RuVi1yFq26YVq4ObocRg8hyLL
         mkp0kitGZ5m+tWML9a8RR42eUfm3SFVsVMEupy+j4crn19x2IwGRLmRUUoRx+sCeYFLS
         RnkHmKpO67y2mjEIK3VXFmiNshFowZnRIMZ+4t4PV2VPdYaHsIn1Urm5C9gPNkcV2mhH
         TFk0XQ24AryllD1FagFYWB//qJg0bNW3Ks47vzF4VzgO/eijg+/EyevdL022SvzqZWha
         f41A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id r23si424516edy.3.2021.09.23.02.47.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Sep 2021 02:47:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub3.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4HFVhS1HTcz9sTZ;
	Thu, 23 Sep 2021 11:47:52 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id N2iojAvTUjrW; Thu, 23 Sep 2021 11:47:52 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4HFVhS0G8Vz9sTX;
	Thu, 23 Sep 2021 11:47:52 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E65698B775;
	Thu, 23 Sep 2021 11:47:51 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id HEg50hnqH7U5; Thu, 23 Sep 2021 11:47:51 +0200 (CEST)
Received: from PO20335.IDSI0.si.c-s.fr (unknown [192.168.202.200])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 224928B763;
	Thu, 23 Sep 2021 11:47:50 +0200 (CEST)
Subject: Re: [PATCH 3/3] memblock: cleanup memblock_free interface
To: Mike Rapoport <rppt@kernel.org>,
 Linus Torvalds <torvalds@linux-foundation.org>
Cc: devicetree@vger.kernel.org, linux-efi@vger.kernel.org,
 Mike Rapoport <rppt@linux.ibm.com>, kvm@vger.kernel.org,
 linux-s390@vger.kernel.org, linux-sh@vger.kernel.org,
 linux-um@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mips@vger.kernel.org, linux-mm@kvack.org,
 iommu@lists.linux-foundation.org, linux-usb@vger.kernel.org,
 linux-alpha@vger.kernel.org, sparclinux@vger.kernel.org,
 xen-devel@lists.xenproject.org, Andrew Morton <akpm@linux-foundation.org>,
 linux-snps-arc@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-arm-kernel@lists.infradead.org
References: <20210923074335.12583-1-rppt@kernel.org>
 <20210923074335.12583-4-rppt@kernel.org>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <1101e3c7-fcb7-a632-8e22-47f4a01ea02e@csgroup.eu>
Date: Thu, 23 Sep 2021 11:47:48 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <20210923074335.12583-4-rppt@kernel.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr-FR
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
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



Le 23/09/2021 =C3=A0 09:43, Mike Rapoport a =C3=A9crit=C2=A0:
> From: Mike Rapoport <rppt@linux.ibm.com>
>=20
> For ages memblock_free() interface dealt with physical addresses even
> despite the existence of memblock_alloc_xx() functions that return a
> virtual pointer.
>=20
> Introduce memblock_phys_free() for freeing physical ranges and repurpose
> memblock_free() to free virtual pointers to make the following pairing
> abundantly clear:
>=20
> 	int memblock_phys_free(phys_addr_t base, phys_addr_t size);
> 	phys_addr_t memblock_phys_alloc(phys_addr_t base, phys_addr_t size);
>=20
> 	void *memblock_alloc(phys_addr_t size, phys_addr_t align);
> 	void memblock_free(void *ptr, size_t size);
>=20
> Replace intermediate memblock_free_ptr() with memblock_free() and drop
> unnecessary aliases memblock_free_early() and memblock_free_early_nid().
>=20
> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
> ---

> diff --git a/arch/s390/kernel/smp.c b/arch/s390/kernel/smp.c
> index 1a04e5bdf655..37826d8c4f74 100644
> --- a/arch/s390/kernel/smp.c
> +++ b/arch/s390/kernel/smp.c
> @@ -723,7 +723,7 @@ void __init smp_save_dump_cpus(void)
>   			/* Get the CPU registers */
>   			smp_save_cpu_regs(sa, addr, is_boot_cpu, page);
>   	}
> -	memblock_free(page, PAGE_SIZE);
> +	memblock_phys_free(page, PAGE_SIZE);
>   	diag_amode31_ops.diag308_reset();
>   	pcpu_set_smt(0);
>   }
> @@ -880,7 +880,7 @@ void __init smp_detect_cpus(void)
>  =20
>   	/* Add CPUs present at boot */
>   	__smp_rescan_cpus(info, true);
> -	memblock_free_early((unsigned long)info, sizeof(*info));
> +	memblock_free(info, sizeof(*info));
>   }
>  =20
>   /*

I'm a bit lost. IIUC memblock_free_early() and memblock_free() where=20
identical.

In the first hunk memblock_free() gets replaced by memblock_phys_free()
In the second hunk memblock_free_early() gets replaced by memblock_free()

I think it would be easier to follow if you could split it in several=20
patches:
- First patch: Create memblock_phys_free() and change all relevant=20
memblock_free() to memblock_phys_free() - Or change memblock_free() to=20
memblock_phys_free() and make memblock_free() an alias of it.
- Second patch: Make memblock_free_ptr() become memblock_free() and=20
change all remaining callers to the new semantics (IIUC=20
memblock_free(__pa(ptr)) becomes memblock_free(ptr) and make=20
memblock_free_ptr() an alias of memblock_free()
- Fourth patch: Replace and drop memblock_free_ptr()
- Fifth patch: Drop memblock_free_early() and memblock_free_early_nid()=20
(All users should have been upgraded to memblock_free_phys() in patch 1=20
or memblock_free() in patch 2)

Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1101e3c7-fcb7-a632-8e22-47f4a01ea02e%40csgroup.eu.
