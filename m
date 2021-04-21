Return-Path: <kasan-dev+bncBDLKPY4HVQKBBM5VQCCAMGQEVQWDDGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id B81AC366ACE
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 14:29:39 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id c15-20020a056402100fb029038518e5afc5sf7410978edu.18
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 05:29:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619008179; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vxr6ytbmD7lACotXhb6t382AcYE/Xg6C4dWM+TWJZfnDdKHvMBMDLmnJZkvry3Xi71
         VcYUNwh+/qNbvIHtGlc0wZRjEp/emxHjZ9t0Iw7wp5WNBjKugkLNf8pODw7tTSJWFjTw
         c6fo2ZoWlqh3vEqATDWKkfHPSPOA+W0WiyoQ6vSeQ32oSByH2DSU1K8UAv5NchbC+2Qb
         ShgGM5VWLwqBIUYA2BdVTjSiAyEs6rnoUUvYIMus6N4uuW28NY+v3xNBeymNMJob8dS3
         dQK1NYOfXX6T2Mv+uMdVxX0656zK9H6XjehhDKBR+Y439ErGoTuoNJRRCdhgah7kmjJe
         G0rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=FaU74k/JIArZ6JIVdVxDsmupGowNSrFVpfSPfTB3e7k=;
        b=fbt0UZ6QXkdmqV3WB8+B+/rrhUsmePTSZ0BHUVytsI6pNHgy2BZKKS5WKqj7fJ/f2k
         WJbEQ669jPSO+1dJi7JStAz9gBs0Uekuc7ta/EmSW1ERaReTykUpybsQjtcpKtu4vxAI
         0bJoqr6kUvJmRBUN5Zll+GPslCWAvU7AwgcM/L6gjxIxjHRJfeFPMso3F3XGKfST9Rw5
         f7od6nBwxEIazR/UOkdRkeU3VZu5Ct+CMG3yZYGX4I4AEBgFZD2duOnlik9n7ZnUs9F7
         bmCJoepLPtQsX41MhogUOXifmWPJckHVvPPQvCeprkkC2YRTG1bb/N2TotmRzymgT8ts
         mfAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FaU74k/JIArZ6JIVdVxDsmupGowNSrFVpfSPfTB3e7k=;
        b=DEGuB/OGGIVjFYVO0OmetQHVMruO+ha7UToW1tEJE4vEchddsH8D1FzjA1L4Rru9Ml
         sJ3+4KSKIr6qzZ1vRou+QTkJU4r71xDneOUzzJHsENmmuCGDB2w2uquaHk+SfFau07sE
         2O+8/qS3NgB+2mXvH9SceA4NkcQBLSRUPw/2Og6uyo0DPV3Qz7qdLchEmaOAcYmwrv6T
         eMwLYsH0jLhKjQxZ7qLM197Kws9Qe4Ufmt/Fg4sAqhUvxj19s0jyaqU4JJ+KDKqFgciM
         KNTUeyS2PJnDinV/3goxhWUc/I1ndGQxsXGzC277HXdfGtCEiu8TLBVHw1CxB4zPgi6M
         oHLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FaU74k/JIArZ6JIVdVxDsmupGowNSrFVpfSPfTB3e7k=;
        b=WqIMUZ3CE1ZGKYj5cZbK/ikwTIX8oXWXx5YI1uV33K9UjQofYShuwFAO/VUCxMe7Hx
         x1CtxSoy8/WmIkktcXWOeDu95WSH57CFWb831r1dccGknND8e8DV1vUxM5YWeFBs4NGC
         fQzQCVEuSfUBsphCGWjCvIzFDCKjYkqgsdx+YtiQ/c6jOTm5o+lT76Ps4ECx2ppCj7m0
         2xcFmuRt9jYUML/XDTOvdUGK5+QB+cA48AHKwq5qOA35oBY9eM2qbMugwwapXHy1m6V+
         v7YCYNIzKEy6wIndv0f8xa56xvtb46pwWYTl+6ARtMpDbQVpq/qSlmwe4TDjdq2QXydp
         V2jA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530d5dQ1pSv1acsz7aV2TbLCFqMJ57IZwISxhUn1GRRE5OnwO7zg
	i5d6i1X699/IGZVkl0EZFXM=
X-Google-Smtp-Source: ABdhPJyBK/+8Ycto9f8VCh1G0uCz/evriqwrRa2Ojr6cEp8vgPw2ukK0+qht/YIv2um68vWQ6vRZ3A==
X-Received: by 2002:aa7:c7da:: with SMTP id o26mr38212471eds.244.1619008179477;
        Wed, 21 Apr 2021 05:29:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:db59:: with SMTP id n25ls821225edt.1.gmail; Wed, 21 Apr
 2021 05:29:38 -0700 (PDT)
X-Received: by 2002:a05:6402:42d1:: with SMTP id i17mr37197872edc.131.1619008178443;
        Wed, 21 Apr 2021 05:29:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619008178; cv=none;
        d=google.com; s=arc-20160816;
        b=m97Mc40+peuNV7KzoFt+3tLZQsuJmVvQbG7HMcapQXaJIlLNW77Ppk/kyWl5iFP4d4
         gxtLAg+9gvlIr+sRzEaZeGf+sVxx5Tnq49y2EAaUUdFeF48y+cWm1xP8vdHRPaBquFC3
         AWP4FP7T9s0gzhvJo3O2VLQYbRVGZHhv4pnG14f4lIOIorLMqyFE0pX8baNMrijMNSH0
         QtrEicfRVlBCL3FsnYmnnBgtJ5EiYY6swjEaC4Q/91qDdO+y6Jrs7Vm9el3KetLsX9jP
         W3eUm4GrroJvaLQZsWa6A74HajkIZroslZgXkjT0MVZWsTxaT4ve4E26jySUV2b1HYfv
         1rSw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=Ebg34gZqNyLl2Jtmvw5d8C1DU8g7YMPTijvWmsomwEI=;
        b=dkSYd/cPNLalflxCNvNKRigTiRZzkre5mNYKnlH9bhzKjn7ir26bsuiWgCZ3HtbxrN
         CZmt5FULLPMMVF5/z4VBIUO3kKGZrOtFIROkNcgQXAFlk4dCKymKU10r8DygT8c12/Wb
         n0OgYRpnNmaLkgiTnj0+sbyr4RFw2En4zmAgIB0Mpo2lc01fzjIcy6LuO/O/ZptLOMK8
         auKUHHZ7D9vw4NaUto4r+WqnzLAcDBLIiN2F2PqqFBcfSqmFtHZraiGERDjDO4hKkUnt
         yo5I6eF4oSiFAlMtF+KTUwkohqeI1TEty6YiMNQq5gVCwwAsM7GWll3bRkAzqpv9HkBD
         Ks6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id r21si230188ejo.0.2021.04.21.05.29.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Apr 2021 05:29:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4FQKcc4dPYz9tvqS;
	Wed, 21 Apr 2021 14:29:36 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id CeELRF3p2Hho; Wed, 21 Apr 2021 14:29:36 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4FQKcc3hDwz9tvq9;
	Wed, 21 Apr 2021 14:29:36 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D6FBC8B825;
	Wed, 21 Apr 2021 14:29:37 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id T1yXWHZXlfsX; Wed, 21 Apr 2021 14:29:37 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 62B1F8B770;
	Wed, 21 Apr 2021 14:29:37 +0200 (CEST)
Subject: Re: [PATCH v11 6/6] powerpc: Book3S 64-bit outline-only KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20210319144058.772525-1-dja@axtens.net>
 <20210319144058.772525-7-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <fc849719-e2c0-bbcb-c58e-f4ff3e9c5f18@csgroup.eu>
Date: Wed, 21 Apr 2021 14:29:38 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.9.1
MIME-Version: 1.0
In-Reply-To: <20210319144058.772525-7-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
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



Le 19/03/2021 =C3=A0 15:40, Daniel Axtens a =C3=A9crit=C2=A0:
> diff --git a/arch/powerpc/mm/ptdump/ptdump.c b/arch/powerpc/mm/ptdump/ptd=
ump.c
> index aca354fb670b..63672aa656e8 100644
> --- a/arch/powerpc/mm/ptdump/ptdump.c
> +++ b/arch/powerpc/mm/ptdump/ptdump.c
> @@ -20,6 +20,7 @@
>   #include <linux/seq_file.h>
>   #include <asm/fixmap.h>
>   #include <linux/const.h>
> +#include <linux/kasan.h>
>   #include <asm/page.h>
>   #include <asm/hugetlb.h>
>  =20
> @@ -317,6 +318,23 @@ static void walk_pud(struct pg_state *st, p4d_t *p4d=
, unsigned long start)
>   	unsigned long addr;
>   	unsigned int i;
>  =20
> +#if defined(CONFIG_KASAN) && defined(CONFIG_PPC_BOOK3S_64)
> +	/*
> +	 * On radix + KASAN, we want to check for the KASAN "early" shadow
> +	 * which covers huge quantities of memory with the same set of
> +	 * read-only PTEs. If it is, we want to note the first page (to see
> +	 * the status change), and then note the last page. This gives us good
> +	 * results without spending ages noting the exact same PTEs over 100s o=
f
> +	 * terabytes of memory.
> +	 */
> +	if (p4d_page(*p4d) =3D=3D virt_to_page(lm_alias(kasan_early_shadow_pud)=
)) {
> +		walk_pmd(st, pud, start);
> +		addr =3D start + (PTRS_PER_PUD - 1) * PUD_SIZE;
> +		walk_pmd(st, pud, addr);
> +		return;
> +	}
> +#endif
> +
>   	for (i =3D 0; i < PTRS_PER_PUD; i++, pud++) {
>   		addr =3D start + i * PUD_SIZE;
>   		if (!pud_none(*pud) && !pud_is_leaf(*pud))


The above changes should not be necessary once PPC_PTDUMP is converted to G=
ENERIC_PTDUMP.

See https://patchwork.ozlabs.org/project/linuxppc-dev/list/?series=3D239795


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/fc849719-e2c0-bbcb-c58e-f4ff3e9c5f18%40csgroup.eu.
