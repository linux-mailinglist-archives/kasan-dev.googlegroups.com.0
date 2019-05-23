Return-Path: <kasan-dev+bncBCXLBLOA7IGBBKXUTDTQKGQESOZH7UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id EDDDD275EA
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 08:14:02 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id y12sf7367525ede.19
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 23:14:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558592042; cv=pass;
        d=google.com; s=arc-20160816;
        b=gb+6hPBbKdowD1GUKsz88IbhMl7tmTw1Smr+idoyn1Xtz8ynyWzrMmmYWMyXnm7cFk
         SSBPhoHGka30JhpYiZPyqW5GJEwWPqTno6WAzzzLIs/iXI6zzyW4gASjdjun7yqDWgK3
         fBRy+azKePrVgETNLaPjbDmJCodArs4IDF/a5tWSb3HJHjSAP1bQcFl1SanZiKjfIDtI
         WlOooQFFDn1CesxvXrlsVvF3B+EtbrWxCbwYQnQkBVHJ6DojPZjyQ7OnuZbRG46N0Cg6
         AF7/pOqOyz2U2/5WYqzBYps806IrBDlKP8PXqLLNdKDUZNgQuoxN5txzXW2Yvo9eG1rn
         iqIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=gx/LPVXuaB+Yqknfgr7IHM1IJffXfAbit2hkJGk3wXc=;
        b=sJgju33BzJQcr+S3VroWrhCPnkkXyv/Tfwvs9z+nlQaVPISfNIcH+xwC1+YJjxRxYW
         MZYVTk/eqtQHdEoYleH1eVp0ndM900dgrtmwzeIjZv8gJ1UnkgfGnLE4dfK9qynrqiSB
         7Rhlbr/3WA9zivSsHModb93yxJk9sp2xTGZ5RCeAjdSK+KL4j4N5AXrAOk1PamgMApmU
         QLwV678nSb70W4030xXIBZ7Bo4VkIE2cTA+6jWy4OP9TjLOsKtge07N/9Dnkv+q71LBJ
         DdtSjKkfrtcmxfSmU8EZrnEt66am4qBl1pvGyBuzovSjFsGw6K7+92CKdYr4MHS9Lg/c
         mvGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=tSEQjR2z;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gx/LPVXuaB+Yqknfgr7IHM1IJffXfAbit2hkJGk3wXc=;
        b=oe38HXdY1PwrZSnF8yEtvHpwUBKeb1NqffWH2Cr08rgf/0ZVgEASiBYeOuXmmgwaAU
         nFsDN76FRJZVMpbDrayl+YDHGgB7gh40oONa/kQfSBgpLVkZ05S6QLyhYNX5wleT0WKA
         cB+8TSmj+8JpeKOMLh1TV944vRm6wourCYUfikvoijbV8U7qDkamDzbbDQUMSTirY4eq
         roDcu/oF6A5bBWAbNkM+TRzBovUWFjrWvPU8K/c03+si+5n+EluV238RkCd4AlkEcBWV
         4/kdufbm4PgSDmLmz8VSQFCrDaKyAox2Q3kAReb0H96iT0jtHM/2rtGRyM1vI1QQPUoz
         cTYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gx/LPVXuaB+Yqknfgr7IHM1IJffXfAbit2hkJGk3wXc=;
        b=pg0LGIpGhsA+fbd5V3+9Nxv3fo6kmocVSPYVbbi9LjaYIjwhzN3jbIcc+P+zvorGme
         gkur0byVGTHtHlw6RPYH3hCHmZK9zEGZTGf9ctQnV3EzpH0IXXQL/iNJ47TrFs4zunr0
         Q/typNK1zRxuenaG3mNPvPu5IN5OhAFYDT+7+zwnUYBVeAxuQOOOec0jBTWJRKpNRaxi
         JtlHriCEuWfIQA+F++JiY/HuMdIneGlQxdVNU607b/uZRcRR3vL3GyhlsZMPhOOhoQ8c
         dPT37APkdSwD/k7AkX4mXbUJ5rCnXkXDSuf+PqCSs38wx0oHoELICLcBJZt07h5rbtWI
         z5sw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXgvpUkoh14DwlWRjDON51Ob4vfafxGL00MLeaFCxWIQ4PW02De
	Z4dNlbn09llXQYl+izETLEQ=
X-Google-Smtp-Source: APXvYqw+L/pYBju4PCs2JGHxnlkCtku6mdDQaT4wfW3JUm+er3xQZYtFbu6pqQu2N9yJV0b+Rdo/gg==
X-Received: by 2002:a17:906:66da:: with SMTP id k26mr74435943ejp.292.1558592042619;
        Wed, 22 May 2019 23:14:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:1150:: with SMTP id i16ls1104517eja.11.gmail; Wed,
 22 May 2019 23:14:02 -0700 (PDT)
X-Received: by 2002:a17:906:2514:: with SMTP id i20mr32570230ejb.162.1558592042172;
        Wed, 22 May 2019 23:14:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558592042; cv=none;
        d=google.com; s=arc-20160816;
        b=oMOaUkPZdr2hKwOLWkXV6/EUadg0SamGNiiGye6H5MoanoshrtEeBbDzLnHFYIHpM7
         gZvBh1nHwtemdLNeoTNHyZMXxaJyf0vXwe/BcljDflzpxksX8VyqvuAlCZssBffoT1sg
         v1a9YL+qXxWwAvE+pTqkmm54t8+OFEy9WPVVTIj3CTh28GpyF08f/BPkPUqRRBz7iQ1d
         y9pE8dOXvcP3g8LEu88c4FhwcKtzwXPGdbFJwqY/l70EJbdRBGEke/8Qbh6+WCYMsWL3
         iGRXikeIdPo8HCMpL+f8DXo9tKDfJtIjOT5wfMWHDkrW2Dgdaj84mwnbbvxFJVMcgo/m
         zI8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=bJM0wa5PIChnW6Ph46pdZkFkuJZ6GsPcNIEizvfBwFY=;
        b=drVbClfSnsfB/hthrold+lcj8qAXGUO5LR7Emhjmf1dGh9DMBM96ofa3D2gsP6LJ0q
         J3yCy43xcsaS6CK8U4I/RfqWCOpYiFQ66V3uVioTOfvoqoqGTqjYSDdGa8MYeCEdst80
         UUee7f9ioi7D/rt4b0YafTx3KQBexmJg5fLT+64ZhaNsTaA+0w59ujX4PHZ+elitdIoJ
         juLDPPyKFZtT+GzgpIa/6zxulZH7rjt7m2WaxH5UK4t/Sc6RvsffLMAM1YWRlrdnBAR8
         MYZxDu5bnyWkc+yDYxOKf1+bDZNW2eXSIGfOStAcM1EQ3Qp1hwMl4HS6r7CDMAGGx+Af
         RsvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=tSEQjR2z;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id n9si1479024ejz.0.2019.05.22.23.14.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 23:14:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 458fMr5QZvz9v1QZ;
	Thu, 23 May 2019 08:14:00 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id L1eBFB46FJlu; Thu, 23 May 2019 08:14:00 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 458fMr3sbxz9v1QY;
	Thu, 23 May 2019 08:14:00 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6D69C8B77D;
	Thu, 23 May 2019 08:14:01 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 1sUZdWyEonZB; Thu, 23 May 2019 08:14:01 +0200 (CEST)
Received: from PO15451 (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0DE7F8B75A;
	Thu, 23 May 2019 08:14:01 +0200 (CEST)
Subject: Re: [RFC PATCH 3/7] kasan: allow architectures to provide an outline
 readiness check
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com,
 "Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
References: <20190523052120.18459-1-dja@axtens.net>
 <20190523052120.18459-4-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <cad64ea3-9c7b-6fdd-318a-3d4aae1782fe@c-s.fr>
Date: Thu, 23 May 2019 08:14:00 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.6.1
MIME-Version: 1.0
In-Reply-To: <20190523052120.18459-4-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=tSEQjR2z;       spf=pass (google.com:
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



Le 23/05/2019 =C3=A0 07:21, Daniel Axtens a =C3=A9crit=C2=A0:
> In powerpc (as I understand it), we spend a lot of time in boot
> running in real mode before MMU paging is initialised. During
> this time we call a lot of generic code, including printk(). If
> we try to access the shadow region during this time, things fail.
>=20
> My attempts to move early init before the first printk have not
> been successful. (Both previous RFCs for ppc64 - by 2 different
> people - have needed this trick too!)

I have been able to do it successfully for BOOK3E/64, see=20
https://patchwork.ozlabs.org/patch/1068260/ for the details.

Christophe

>=20
> So, allow architectures to define a kasan_arch_is_ready()
> hook that bails out of check_memory_region_inline() unless the
> arch has done all of the init.
>=20
> Link: https://lore.kernel.org/patchwork/patch/592820/ # ppc64 hash series
> Link: https://patchwork.ozlabs.org/patch/795211/      # ppc radix series
> Originally-by: Balbir Singh <bsingharora@gmail.com>
> Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> [check_return_arch_not_ready() =3D=3D> static inline kasan_arch_is_ready(=
)]
> Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
> ---
>   include/linux/kasan.h | 4 ++++
>   mm/kasan/generic.c    | 3 +++
>   2 files changed, 7 insertions(+)
>=20
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index f6261840f94c..a630d53f1a36 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -14,6 +14,10 @@ struct task_struct;
>   #include <asm/kasan.h>
>   #include <asm/pgtable.h>
>  =20
> +#ifndef kasan_arch_is_ready
> +static inline bool kasan_arch_is_ready(void)	{ return true; }
> +#endif
> +
>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>   extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
>   extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index a5b28e3ceacb..0336f31bbae3 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -170,6 +170,9 @@ static __always_inline void check_memory_region_inlin=
e(unsigned long addr,
>   						size_t size, bool write,
>   						unsigned long ret_ip)
>   {
> +	if (!kasan_arch_is_ready())
> +		return;
> +
>   	if (unlikely(size =3D=3D 0))
>   		return;
>  =20
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/cad64ea3-9c7b-6fdd-318a-3d4aae1782fe%40c-s.fr.
For more options, visit https://groups.google.com/d/optout.
