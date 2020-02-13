Return-Path: <kasan-dev+bncBCXLBLOA7IGBBXOPSPZAKGQEICZWZNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 70F8615B94B
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 07:08:29 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id s13sf1889682wrb.21
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 22:08:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581574109; cv=pass;
        d=google.com; s=arc-20160816;
        b=VVmrDOUhoi5etL0cF+kjf8uBzAKtxZugA82PJsKyC+MZLXA7sYVzEqBn/OwMoysJFT
         sIE+Soa+npBTRb/TmVtA+zthmx9MBdsXebU9muldjqdQW2pNS/um5ss2LpmhyuhyjXtC
         Oul96v9TKK1HdJjw/XTn2VB83w2WOhole1cFq5a3E+46QJP6Cf4gPy12HGBAPhLaMpQR
         dBwXbcl2kk4Hu7ahhNo2bjnl8DV9lJj49/Jx5DDvSFV8R0vAEPb4ARd9sW1P/54jGwCY
         WCouWmZXmmMYcpU9xjLWwQ19ptAVdN867sYu01hPUt9fuFu7efl3DUF63g0SsJ0IzBgl
         9WZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=WIOKlqXLpImLOYbBWh9YL1PsK1Zkn2e+dnFyPKfg/cQ=;
        b=ig4lGzTYthE5uyDcGvjC9bdl8MsH3P34ykgC/vepV90iabVmsxprqmb+UC5IDU+TwF
         pVJTLYhiHKcMAqi/T2UFY/IsNoklDeZAYwa2aMMKPEWpqdnkmVypyKg+26jyFmPK58U3
         4SlCY5hosj4SgFfRggINMDfDxSuNDBeEJhvvvRLdWL30TsCgfwTSYi79c3sXTdMjNr0O
         b6e2XU5jMCHRDmC2RdREz2P3rmr94a/XCP+i+sneHCcBRwhVRFXdA5i6LjgvP+Fc8aNK
         MGHcfSwdPzPF8uBT9jjk3c+BEd2A9DvL5vnRWolKjNcv1Vt3Qhgerg0rJ2wTi0OZJYk2
         lr9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Bo8PZYyO;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WIOKlqXLpImLOYbBWh9YL1PsK1Zkn2e+dnFyPKfg/cQ=;
        b=hyBjIlg69AkrveT4pZQlsRzZvV4SRIxLchOeUn+GrmcaqpS1Q54lPjkHQD0cAtMBpv
         K3qjLLAzEfhvLlMNqlJeLutUGcvLTVtaDIcOvKBFd0+2LMpS/D8KIu6EJBWYyP0LnXtZ
         3yySaVm3dASQMO2eI8Ot6js48YDR7aL+wwnqW6Ba+d/9d76jO4NERM5ZyhNbNASmJHC9
         4raxo8oZF/GymKbMsT4jlsg5SI6eM5x6/XSqHJcuXMOd0ng2jjpCUUcykZfiVO1rlluc
         0jCEoHz6gqMK8qPZwUJ+N3MlIeUTy4i4RMkK+5OHnBnXrMnbz8pUNRC4xo0L9qVHpRJY
         yWZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WIOKlqXLpImLOYbBWh9YL1PsK1Zkn2e+dnFyPKfg/cQ=;
        b=oW9xxDbfgJwGc9BM0hekSXqnlLVz9/D5Iis/ojtJZiUTRBahsaAEWEUJZsZ1gPeCr7
         UfvbDiirgZ4OcvbIuunpQVTEgEiRDamdNf6aKtMmnKijYqMg77G9P9puXtpgdcHOMBw6
         Sb/HOY/PoGn+XosLVwjAYSn97s7O8zb+I2qVYV0xTzuD9YMURnF/OMN72jYeMFD4r6FJ
         Xti/n+J+sM8CvEJXguu8k3SUgRJsflnwwoAN8UchpbjMbDEBPles6xkUjqXfeWCgT/KA
         gYT3LB+gxrF7AjD1vtLiYE6dJRveRwpfWYQ9T5jyrkT3LgmwBNojOA8OaNC5golrMs9n
         n7qA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX29s3Iy7KiQyNI1t8JrSJTHrafoSZKihfjdFssKZVwbErAOlSJ
	MxoKfpcBiLXH5vlAKu+pCT0=
X-Google-Smtp-Source: APXvYqyBXYB89E1adKQFZcEzlfRT3AuaBvyfukTOO6SiqnxwB88NzZPt3YwVnRWk4h6YgLZ84dpIGQ==
X-Received: by 2002:a5d:51c9:: with SMTP id n9mr20169427wrv.334.1581574109150;
        Wed, 12 Feb 2020 22:08:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:65d0:: with SMTP id e16ls12591882wrw.1.gmail; Wed, 12
 Feb 2020 22:08:28 -0800 (PST)
X-Received: by 2002:adf:e781:: with SMTP id n1mr21023411wrm.56.1581574108596;
        Wed, 12 Feb 2020 22:08:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581574108; cv=none;
        d=google.com; s=arc-20160816;
        b=y5gNP3VsYxxQmkqoDMVjTJMexD0XfXoxhz3SP+Zs9/JpKi+KRlN2q8g/N1xFYvHBaq
         al5k2f8N3JOxwKr6UR6BkfYYsirdaN9UcN+h29i6ZkOKWITIFagCs2FANYCx//0/Fzre
         JJATrPagmueih62KJv4No55YZAPcN0obl07fm3uL00vT+VZ79TDQRxKOweUMX8koJ8U5
         fe7dZ8P4+21KNFdixQlrfqsDHjDkcaRnI/X8mcqtva1kIDv6zhImdvBMbpUDgwNPhiDf
         24tjNQRKWvlgdifXg42QSBOyfH71NtXH9BFRgqvKnhYFBdR8SwTgL33YuNPuou0JSWTp
         Zc5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=AKmjbGNoqXYmXrUzT0AKVVfZXpSdbAFvNtOP0PQkAVk=;
        b=pBe2mAAhtIH+WwJXFEWGBErL6Uxw0jhSzj2VidZWFm1oEdqcOz+HCq6e7qzDDLbilD
         UL2P5sG1Dn/6PbBFMvmC4RHJ8wLRp9/cOblEqU4lfTIQEcKvnzqWdYIhFZle8hlPDVje
         tJihgggvFdMUci9MGpxRtXP8UYeuq1fyUUS1LifBTwthdek49pueoB3cZx7KK3Ktuf9p
         Kmmjbzt6yHEKC5TjjobvnzRFcgipnf2+Tnp0t1yQXNjqEqbZUMfte0L8qsOi63uOXkwf
         ZrDdWywS/0SgFwSHRVLUjwXHfvI2OgwY7kGymHO2Lfxuozxsx0oRGNimoLu/FzFTGyZI
         +ZIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=Bo8PZYyO;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id i15si74961wro.2.2020.02.12.22.08.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 12 Feb 2020 22:08:28 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 48J5fg1vBSz9txqP;
	Thu, 13 Feb 2020 07:08:27 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id W3ooT9PICKBs; Thu, 13 Feb 2020 07:08:27 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 48J5fg0KvXz9txpx;
	Thu, 13 Feb 2020 07:08:27 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id D2FE68B752;
	Thu, 13 Feb 2020 07:08:27 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 5eeoAwa3yMGD; Thu, 13 Feb 2020 07:08:27 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 2F9C88B795;
	Thu, 13 Feb 2020 07:08:27 +0100 (CET)
Subject: Re: [PATCH v7 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Cc: Michael Ellerman <mpe@ellerman.id.au>
References: <20200213004752.11019-1-dja@axtens.net>
 <20200213004752.11019-5-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Message-ID: <67370fc6-8fe8-c5ba-d97a-4a4c399b0ae0@c-s.fr>
Date: Thu, 13 Feb 2020 07:08:27 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:68.0) Gecko/20100101
 Thunderbird/68.5.0
MIME-Version: 1.0
In-Reply-To: <20200213004752.11019-5-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: fr
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=Bo8PZYyO;       spf=pass (google.com:
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
> KASAN support on Book3S is a bit tricky to get right:
>=20
>   - It would be good to support inline instrumentation so as to be able t=
o
>     catch stack issues that cannot be caught with outline mode.
>=20
>   - Inline instrumentation requires a fixed offset.
>=20
>   - Book3S runs code in real mode after booting. Most notably a lot of KV=
M
>     runs in real mode, and it would be good to be able to instrument it.
>=20
>   - Because code runs in real mode after boot, the offset has to point to
>     valid memory both in and out of real mode.
>=20
>      [ppc64 mm note: The kernel installs a linear mapping at effective
>      address c000... onward. This is a one-to-one mapping with physical
>      memory from 0000... onward. Because of how memory accesses work on
>      powerpc 64-bit Book3S, a kernel pointer in the linear map accesses t=
he
>      same memory both with translations on (accessing as an 'effective
>      address'), and with translations off (accessing as a 'real
>      address'). This works in both guests and the hypervisor. For more
>      details, see s5.7 of Book III of version 3 of the ISA, in particular
>      the Storage Control Overview, s5.7.3, and s5.7.5 - noting that this
>      KASAN implementation currently only supports Radix.]
>=20
> One approach is just to give up on inline instrumentation. This way all
> checks can be delayed until after everything set is up correctly, and the
> address-to-shadow calculations can be overridden. However, the features a=
nd
> speed boost provided by inline instrumentation are worth trying to do
> better.
>=20
> If _at compile time_ it is known how much contiguous physical memory a
> system has, the top 1/8th of the first block of physical memory can be se=
t
> aside for the shadow. This is a big hammer and comes with 3 big
> consequences:
>=20
>   - there's no nice way to handle physically discontiguous memory, so onl=
y
>     the first physical memory block can be used.
>=20
>   - kernels will simply fail to boot on machines with less memory than
>     specified when compiling.
>=20
>   - kernels running on machines with more memory than specified when
>     compiling will simply ignore the extra memory.
>=20
> Implement and document KASAN this way. The current implementation is Radi=
x
> only.
>=20
> Despite the limitations, it can still find bugs,
> e.g. http://patchwork.ozlabs.org/patch/1103775/
>=20
> At the moment, this physical memory limit must be set _even for outline
> mode_. This may be changed in a later series - a different implementation
> could be added for outline mode that dynamically allocates shadow at a
> fixed offset. For example, see https://patchwork.ozlabs.org/patch/795211/
>=20
> Suggested-by: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix versio=
n
> Cc: Christophe Leroy <christophe.leroy@c-s.fr> # ppc32 version
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: <christophe.leroy@c-s.fr> # focussed mainly on=20
Documentation and things impacting PPC32

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/67370fc6-8fe8-c5ba-d97a-4a4c399b0ae0%40c-s.fr.
