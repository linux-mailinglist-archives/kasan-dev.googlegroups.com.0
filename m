Return-Path: <kasan-dev+bncBCXLBLOA7IGBBPXJSTZAKGQEY7SPRMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id A1F5415BDBA
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 12:36:30 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id y8sf4670636edv.4
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 03:36:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581593790; cv=pass;
        d=google.com; s=arc-20160816;
        b=lGjCrWmHFvDES+nYV3bkipxVXBT7P+rEnG/z/bBl6kJ8tcqodnfU/XWQY+cN33v26E
         98kDrfGsRH+VuujAE/XhnqtgNNTxrNmbp73AO5KfNi7QzHwAgbLWfmYwDSTHs4dUuIuZ
         ONvFYc4MLsbOT8edlul0NSRos2hRJSydlHv+8OmEkkjZwuUmpp3+EavGlEwjtctGzR9N
         2SHYKg+dYAloPAnf7Byh/K2ZhqmQdXC0DVi3Npd/2z7B1rV+TVqN4MD+Y0CD+AZ9p9pG
         A3kLUD3HKlqJpQs7hZRc/V2wRfqS8j2vrnBf/KNANw3C1JYKwbc55jtjVgKFMjrReVEy
         Npwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=lWplBIak5TAtPVx2+vUeywrjUZXN6jLTYHcNelYOWJw=;
        b=RqXtiU3IlWHKF9DstEKB0F7WsTEuCcCrWma3e382RnpUFfd7eHMLXohlGHPkRfhHED
         S72i9GRIW1JKkLSqtHPMQXhdCLgAx8d+jRAmKWcdTckTiWgUPM+HZHZBkfSnfiqzMswS
         fJUF58vdmhDWXSeNuEq8pax1z7U9oJ42LW6e9HHWPc3ybT6L5F5gItdZr0LBGO8Yk+w/
         F+NEjTY4S4DIHLmR1Aqifo5QVD0N/3yVjrXWcFexclpDbpzeVAg53kkSethMWy+Tq8QC
         LIAKzWiQkL55J1XxW6dPJi2YHhPCTbCfj6uwaTN0EPRd1hyG49+2I1r55Qe/8Wu9r03+
         l9tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=bNiPg8Ec;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lWplBIak5TAtPVx2+vUeywrjUZXN6jLTYHcNelYOWJw=;
        b=ccczVZUIx/oXkiblMNUONXx8xdEDvkHhPmPQfeVeCPfSeM2IC3CF6SYyFiGV5zz2QI
         HQG+rv/w0i1LdTFel+uzL6ayXeUZpt5xPtgONgjM14fs9YkcEOaBCo4nzRKga2LtUp18
         Sc4REwZ4nrgjH66sdgxOe4dqAhgQyKDziwTv54bR+qadhW6vM1RrW+KRv7be6EXc/BSS
         ngXkI4grAo8tSaIW35gcJR0yfFADREqlUiWGB8AZTrP3zYNE/F1eVEESKp7hwkOUyCBm
         xzKgM3KGdMOScZaBlw2/o57K4CxshPgPbzNhlB4YFvo93f5GOmiwlFqab8t74ROUXNQ7
         Mf4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lWplBIak5TAtPVx2+vUeywrjUZXN6jLTYHcNelYOWJw=;
        b=VJNlHAV5ZxgrfaiAKUoi/gLDTXFx5JtSOylaikHWwajuBb5hduZSUfbQbaQA3gW0hL
         Pb3UebGTQj+qMEgLY6bTe3rUDkMz+EUBaPmxoTwgVpJK3OfWD9g8XBiGS25lkMV2MSbE
         is5tv5PuZweP2wfKB3j03G3V7fDPZ2Ar+1kGbsKmKLljTpKu4K7Bm99BYUScpLADB+XX
         4yqydfRAHpuqFZHnt/drbNkvLc7Nviu03/qwkGGuIW+sY6iWKwgwqMH8/m97YqMUVIky
         /dJWoctFmgCuIZMyODnYtcTVmGvtmdIyZjuE5AU8+4mLuw3mSTcBawTHROIgl1kCMsjd
         s1YA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWBeXqakIQCdo42VuHBlNXa+ur6t3qiF9j9/nAF498XlabZXtkl
	eLWvtN3NLWXdq19j5EAUzwo=
X-Google-Smtp-Source: APXvYqzv21nZXsHHw/z/ibWirSiUjCuAMy8X+lW1WXj7GMJQteJKrGbR6ZqS5bztkSdfzz5JV/x0Bg==
X-Received: by 2002:a17:906:4d87:: with SMTP id s7mr15381402eju.221.1581593790423;
        Thu, 13 Feb 2020 03:36:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c82b:: with SMTP id dd11ls11903146ejb.8.gmail; Thu,
 13 Feb 2020 03:36:30 -0800 (PST)
X-Received: by 2002:a17:906:27cb:: with SMTP id k11mr15885415ejc.301.1581593789823;
        Thu, 13 Feb 2020 03:36:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581593789; cv=none;
        d=google.com; s=arc-20160816;
        b=HSSAX/qeDW7cP7ErQZ7BDObVAFwINNswpPHOQ3Fz41AZBUzuB93bTDanPZaes5d6Hv
         cpDnBcqJkAGSvBgvWtnAVZbwmzHsqwinHlWQigzs3X3qBQw4AGNrRUzDDwLRLoRQ1pV5
         yrgQTzU5RiVUaS//bvpcaTNMtFQZ4922ae3Xz/33AcpqVY5QfTgD43FKdR3cx68asr4u
         /2+27lTZWzxfFPwjhF1HudRl3i4ywARlyhWMxrS8mGfPqxx9ZcwyxyTpR8DvsRxD0Kfl
         domVfWR23fHBapxKbyQlBYrv6/9v7f83Z1i7zHdxvMt4/7ys7SPLr6s1xFaMPLv9h7Ec
         auOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=JI/l0B6oz142zI0BvEjYO3SlgbYPDoynj43XnCUS9yE=;
        b=dUB1K3KqTodFKU9TvNrDoa4/i+xu+HjFs8GcJGGJ/lnBWz10iHGbfj99w0wYf0IOvW
         8rq7TkVBXwFw/2S9Wrvz6Pw9fmsjh9a/pKk/oKvUtEbZAH2knQp3J2VHlCzWz0UkWOTV
         NspcWrQD+PXsM7tctNcHIMIl6e5gTGrBrNlTWioxXmRi3Iy9VmQa0v18Nu8OH+/wJ01i
         EpPooq7MpT0C9w1/CqyrXeTlD5jklBsThc1EflHZBPA3ZKEZkXDw2aBpPmIYNYd0g3wV
         sKyQTT9Nm/5g8fPk35tQobsZoDSO2BQmW7R1tUuoPm6qCgr0W9kAmRESUXE0bRrS2c2q
         pAIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=bNiPg8Ec;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id df10si130006edb.1.2020.02.13.03.36.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Feb 2020 03:36:29 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 48JDx81Mdxz9vC0r;
	Thu, 13 Feb 2020 12:36:28 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id VwdZhkCoNCGT; Thu, 13 Feb 2020 12:36:28 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 48JDx80GCPz9vC0q;
	Thu, 13 Feb 2020 12:36:28 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 3C8578B841;
	Thu, 13 Feb 2020 12:36:29 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id AepsZRA2KoQk; Thu, 13 Feb 2020 12:36:29 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6797F8B83F;
	Thu, 13 Feb 2020 12:36:28 +0100 (CET)
Subject: Re: [PATCH v7 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
References: <20200213004752.11019-1-dja@axtens.net>
 <20200213004752.11019-5-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <abcc9f7d-995d-e06e-ef04-1dbd144a38e0@c-s.fr>
Date: Thu, 13 Feb 2020 12:36:28 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101
 Thunderbird/68.5.0
MIME-Version: 1.0
In-Reply-To: <20200213004752.11019-5-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=bNiPg8Ec;       spf=pass (google.com:
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



Le 13/02/2020 =C3=A0 01:47, Daniel Axtens a =C3=A9crit=C2=A0:
> diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
> index 497b7d0b2d7e..f1c54c08a88e 100644
> --- a/arch/powerpc/Kconfig
> +++ b/arch/powerpc/Kconfig
> @@ -169,7 +169,9 @@ config PPC
>   	select HAVE_ARCH_HUGE_VMAP		if PPC_BOOK3S_64 && PPC_RADIX_MMU
>   	select HAVE_ARCH_JUMP_LABEL
>   	select HAVE_ARCH_KASAN			if PPC32
> +	select HAVE_ARCH_KASAN			if PPC_BOOK3S_64 && PPC_RADIX_MMU

That's probably detail, but as it is necessary to deeply define the HW=20
when selecting that (I mean giving the exact amount of memory and with=20
restrictions like having a wholeblock memory), should it also depend of=20
EXPERT ?

>   	select HAVE_ARCH_KASAN_VMALLOC		if PPC32
> +	select HAVE_ARCH_KASAN_VMALLOC		if PPC_BOOK3S_64 && PPC_RADIX_MMU

Maybe we could have

-  	select HAVE_ARCH_KASAN_VMALLOC		if PPC32
+	select HAVE_ARCH_KASAN_VMALLOC		if HAVE_ARCH_KASAN


>   	select HAVE_ARCH_KGDB
>   	select HAVE_ARCH_MMAP_RND_BITS
>   	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT


Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/abcc9f7d-995d-e06e-ef04-1dbd144a38e0%40c-s.fr.
