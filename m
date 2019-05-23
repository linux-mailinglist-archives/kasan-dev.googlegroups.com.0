Return-Path: <kasan-dev+bncBCXLBLOA7IGBBPH4TDTQKGQERODCANA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E407275FD
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 08:31:24 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id c1sf7421168edi.20
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 23:31:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558593084; cv=pass;
        d=google.com; s=arc-20160816;
        b=W7t0AsmIDhBik2DLZToNR451z3arTh0NiGPHt8gU5J5ofSyy5/msrx2yUlTK9poVT3
         0Se0PoUtkpnJDYfXV79BWa3wNoeEHvPGvlg7a3LkY3M5PP5s+3+tpcz9C2UhBtJlEW2F
         Xo5U3AW7p0U3YukojYAxWO969rD6JGNqPrjddcIy165uTERTeoSSwbV85wRr17vn+mvO
         a9KG4dhKRogb33Kx187lS9LdU0216IAF4ZZTvun84/YQF82d8CzXkzZehHS/O9MrcnwM
         AQ6KaEmfTwxbSPnzLWi0x4dRxy0Wsw8nyi67a7/Mmras+Df7syl6BhYHvOAAaNc9WAUX
         Abgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=XX3vjLGukxLKBQfMPWIrSm3OeTsfZbqnFdct7F0W6Ws=;
        b=FKuQLDCBw3gcpJ3IwvpofIH+537o0UF1LbFAKWChah5WlDRNaeMEEnpizIemmgA9S6
         IyGGeVToc8weW86ACvvLKdz2kA/oTgRezQS0Rdgnrty4JFfeklCoLj8WIDyG2M1N8YLu
         ShSzwUuh2q87TkqJL3YfF1pR5DdA6RG7D2dm/kipWB3T6iSdbNctiUKKBe27/mkrQnBc
         24F9ApL6uzx6nO4MqPo2kiNzujHZ3jKkeehtELiSSZDwe4Uh7NkayossucBsaziQboak
         K9kQW7aPcZNy5bZxrnoLvVLPdt6kOx3xo4ZfW09GXxnyeESnbb3grQk8IlYTe7iM4JMJ
         i4Aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=aOw7NxVc;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XX3vjLGukxLKBQfMPWIrSm3OeTsfZbqnFdct7F0W6Ws=;
        b=lYeMg+lEUDwiCDkRaCr2X70nLJ7IhIgdTZD+6kS3wLVCNbMZK7F6rgwOGdHiv+I8Vh
         SNTKUq8XDdyqUeMpRUoi5y6mGUtV48cjBJiOsyqK6kRbbi5Xv/UT2s9xRvcPSXcw65e/
         rkEU/0JZW+/9qKhY/sOCfmjAI6UYWNiKTTAqz+sljvqO6OHfqagCogVZSjj0/7/lBcAf
         VLHNkStLGx1HW+fwIwCgL53PdD20/eazuto40WDEWbyo9+NPoUO15O1LLpau+Z4OG6dg
         0le1u+xoX9sDS3LoJo0f2ODSuomOI7ugSlg+5sfdsQmlV+RuO7+X+P37xSEstfbZWUjR
         UpAg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XX3vjLGukxLKBQfMPWIrSm3OeTsfZbqnFdct7F0W6Ws=;
        b=CX2HTWv0SOBSrV75eepZe7BQRfUJZ+Y0k8Jh7+YDjfPwnV5oLkLDgRkiI9mgA6Ko7l
         lw/irPgZatuv8W2JDQr6Pb6Gg5eeUKhCZwS19zcxGY/bFUmA0Rw08DPKRlD0oov782PG
         qYn5WlPBEyWtm9HQWNGxJSxMs9f2jHuXzfYKR+x0PAL65em3DJ8a5rawLlsShAKcJIRB
         2yGRzq9pjBO45DO8JWcJ8cqFQKm2CD6bhVUda7snAapyLEhhFt+XT+Om5OW2DJaCAZlN
         sUNr1F7POUpfqEOWcQUKChA5xBv0lLjoXQBhhyUnhu5UfQf9w1+v4AC8+Y8F8+0R1h0I
         g1bQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXiarvsZGcM29Hz5vSFtHm2JfuUmjYFiA75rRTYxBQPni9HIPAX
	A7ndv1sf9IrnVhKkajqN544=
X-Google-Smtp-Source: APXvYqzcd8INJ2M2Q/WrWkkKj1nJAnrkPn263TEDydbzp6gZPske4oFUVVB/vv7Mj5jAZ8VptwwW4w==
X-Received: by 2002:a17:906:d513:: with SMTP id ge19mr31380702ejb.222.1558593084362;
        Wed, 22 May 2019 23:31:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:91a7:: with SMTP id g36ls1315190eda.4.gmail; Wed, 22 May
 2019 23:31:24 -0700 (PDT)
X-Received: by 2002:a50:b329:: with SMTP id q38mr83546669edd.246.1558593084001;
        Wed, 22 May 2019 23:31:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558593083; cv=none;
        d=google.com; s=arc-20160816;
        b=gSxwpvbtFqRNzETdr4cmYiAHXamp+COSz6/VptruXytMdh1FwZXmVbvkGEIULWEtRm
         UAwDKZWVZ+SrihV/EcllL2ksz2Rmbv7fYMX8Ab4+vCSFO0EhJSZMwrgOxCkmYkI7Gt2L
         DPYbGulcnNXbix0xesCqF76Ck93iNH5xywRX71JYTsMvgEaRMQ0NAl0PEGObRBBr3P6F
         oODcOjcG8X9A4OASeX+ir0Z9uoEITO9c0a9Qul86TZ7vhsfGd3+M8fybG4kNQdLi63jp
         tDc8G43YyGtvJAghhkWRSN9rbGPmDqrJlV0lD8vP0QjhWOG3jDSFKB4OMCoAaFIwhpHz
         VTjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=iBoSTQJduiJdnBswQSZH7SOr2FcQubFRQAMzBT72zbE=;
        b=vb5pB0eVLzs2VFlRJrEm/FNPKqxWPBQ0nfv7hTTpiJhLR0M7cVFVlP0BT40lkPB33J
         QYOPeJsEfg1FyodENfz8I+rsAnLIJV6iE9o24b8WzMd6r5aciBbnNHiw1dRurq1dxB2d
         a+HwtBrUv/nD9dlqNtTRXE4LOfEMTAvve3FFQ/1yBC3FWy9PgX/6yhzjlkgwKEtj6gwV
         yuV+wU/aYCH6BWQu+7l7spqy5JrG6/ECg08L0Po0EhxkIpvvQbZAVfjRpSAdRl/8HLyF
         KGDPTwmRp4U3F1HmrATy/bPT4v9iGbvAC4iQiGKFg4/7Vpjmm9d2pGKbAOKhFbTday2H
         8BsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=aOw7NxVc;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id l30si2839268edd.4.2019.05.22.23.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 23:31:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 458flt2tznz9txk2;
	Thu, 23 May 2019 08:31:22 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id yb1S7UvGIIko; Thu, 23 May 2019 08:31:22 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 458flt1HD7z9v22s;
	Thu, 23 May 2019 08:31:22 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1D8838B77D;
	Thu, 23 May 2019 08:31:23 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id x9aLulBf7QaB; Thu, 23 May 2019 08:31:23 +0200 (CEST)
Received: from PO15451 (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B5C9B8B75A;
	Thu, 23 May 2019 08:31:22 +0200 (CEST)
Subject: Re: [RFC PATCH 6/7] kasan: allow arches to hook into global
 registration
To: Daniel Axtens <dja@axtens.net>, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
References: <20190523052120.18459-1-dja@axtens.net>
 <20190523052120.18459-7-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <b7f23406-c1dc-de50-d477-86cdf8f0d471@c-s.fr>
Date: Thu, 23 May 2019 08:31:22 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101
 Thunderbird/60.6.1
MIME-Version: 1.0
In-Reply-To: <20190523052120.18459-7-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=aOw7NxVc;       spf=pass (google.com:
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
> Not all arches have a specific space carved out for modules -
> some, such as powerpc, just use regular vmalloc space. Therefore,
> globals in these modules cannot be backed by real shadow memory.

Can you explain in more details the reason why ?

PPC32 also uses regular vmalloc space, and it has been possible to=20
manage globals on it, by simply implementing a module_alloc() function.

See=20
https://elixir.bootlin.com/linux/v5.2-rc1/source/arch/powerpc/mm/kasan/kasa=
n_init_32.c#L135

It is also possible to easily define a different area for modules, by=20
replacing the call to vmalloc_exec() by a call to __vmalloc_node_range()=20
as done by vmalloc_exec(), but with different bounds than=20
VMALLOC_START/VMALLOC_END

See https://elixir.bootlin.com/linux/v5.2-rc1/source/mm/vmalloc.c#L2633

Today in PPC64 (unlike PPC32), there is already a split between VMALLOC=20
space and IOREMAP space. I'm sure it would be easy to split it once more=20
for modules.

Christophe

>=20
> In order to allow arches to perform this check, add a hook.
>=20
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   include/linux/kasan.h | 5 +++++
>   mm/kasan/generic.c    | 3 +++
>   2 files changed, 8 insertions(+)
>=20
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index dfee2b42d799..4752749e4797 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -18,6 +18,11 @@ struct task_struct;
>   static inline bool kasan_arch_is_ready(void)	{ return true; }
>   #endif
>  =20
> +#ifndef kasan_arch_can_register_global
> +static inline bool kasan_arch_can_register_global(const void * addr)	{ r=
eturn true; }
> +#endif
> +
> +
>   #ifndef ARCH_HAS_KASAN_EARLY_SHADOW
>   extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>   extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 0336f31bbae3..935b06f659a0 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -208,6 +208,9 @@ static void register_global(struct kasan_global *glob=
al)
>   {
>   	size_t aligned_size =3D round_up(global->size, KASAN_SHADOW_SCALE_SIZE=
);
>  =20
> +	if (!kasan_arch_can_register_global(global->beg))
> +		return;
> +
>   	kasan_unpoison_shadow(global->beg, global->size);
>  =20
>   	kasan_poison_shadow(global->beg + aligned_size,
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/b7f23406-c1dc-de50-d477-86cdf8f0d471%40c-s.fr.
For more options, visit https://groups.google.com/d/optout.
