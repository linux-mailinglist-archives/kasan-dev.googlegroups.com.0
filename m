Return-Path: <kasan-dev+bncBAABBIXITH7AKGQELW752FI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63c.google.com (mail-ej1-x63c.google.com [IPv6:2a00:1450:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F0F12CA89B
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:49:39 +0100 (CET)
Received: by mail-ej1-x63c.google.com with SMTP id f21sf1532945ejf.11
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:49:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606841379; cv=pass;
        d=google.com; s=arc-20160816;
        b=IZNGwY36CiuzhZqXdgmkmeWnfZpyXsuBL1ZNrWL99Fu5P0+Qei8ocCjifEZkLAhEfZ
         ifCSGOBB5K4D2y8TNsxh7Ud+NrfWwsELwWQRwaOi1JdMkBtHF41wurf15nWOaErNk6JW
         3stSckK/kJtTonwyOEauzQw8f22zOPo8StErwJHeD09tXdad3P9XOhXrsQ7W9b3AF79Q
         Ju4MiMEYcyEQXmOdfYTsJNyYoggiYcQj2ezmvJgJh1Sz/q4nFKV8/DuGCNCh3WvL1xFG
         Oi45lA3cNX5swbOUtG2pktUHUe4m5ma3jQIFEE4x73t5XB4m03rgd/IxX/ZPT//InEe0
         d+4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=mKu+CXEOv5utRsn0DNby6g286SfJ4zKcrWmuVgkAXhA=;
        b=ziBwIIQM12SPQXSTGXhp0062c5C3/PimbYFFK+eM5u4Za5K/NRRul8B4jkSwiR2f3Q
         HU8ntr5GJhGOEorfUEEbQmP3LOU/s6NVgKpmzc9HkG0fWMk5wqsiravxoJo310x1Ka7F
         lX/9WvHE9v65v4U2KoZwF8SbYgSlhMzdlZp2jthK5nyYv/rYlyYSqW5/qJejNAfKnl7S
         dzmVrjGxnY33/RoZFb2U+Vp8I2k9Z+dG/7iKu93nXonPTdqh/7MeciD0gMWo9skf+NoB
         +KSZcEBjlWM5w/yBiCncOBdg/eKbZ5uWzVqj6j7Vm2K1gP/AUuXMzgu7cq2y0YsswjNH
         yjPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mKu+CXEOv5utRsn0DNby6g286SfJ4zKcrWmuVgkAXhA=;
        b=Vdu7yeEloLXAq6CfsbXbMyq7qQ6HB1dMZHdH9xhFF+bbPqMKV8XmwA5g0MwiiYL2hM
         oFyv25zqQF248pmAPw/R+8kYE3Dkhz96RadULrvCyTN6wqjaLnYTC34poFukLik3Z3od
         i3oT+sp8Ydvmphg/GzHXs2Mf8M4KjxcBfDPIlMCElVvTE55FNa1wX3a6LainIo8nisyz
         OknJEaZDMZsWIuyyd69DyytAEcmVflbXYxKOvstyY9Itw1lh9WPfPZXKf+PH0NY5s2eW
         te7nOYN23sWpWiyOYJXLBhsDbp5gQetJgnas4/LyldZZyB866LGm+vGm+IxjohQxmiiz
         lSbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mKu+CXEOv5utRsn0DNby6g286SfJ4zKcrWmuVgkAXhA=;
        b=jzMu8Mt06LLVcbK5ZnPO/yQoQaXwZfD4Od+5Dorr/F+iZWVhH82XWR0eFgTZyj+gh5
         r/L5zC5wgYTPfJbY/E/Ar24oomB7i9tc6XDKQR8oVBHcMnf2LZh3C4bAfdaXMr49ZgU8
         s+LEUbfd17jNOZF7sTiA+C4hdt/SG7xXmaNHsWrHS7AZu7rbRLtkUuUsGDyfdWBiH0pb
         dMwnKuruCxVnGIuF8QoBj1T2Vtite78pqrPgD7bYZnlJKO9NodRB/OHaKLKr/I12j+vo
         lP3NER4lDfyK+coB6ChcSln/y6ot2ZEH/eOEBXkMM3F0jRUxk3u0N3F+pl7O+6utdDB2
         dz7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dNXXd1wg+dCMtmbOYJFOseH0p4KK4+khw3nsYhTShsJpkzE8X
	g/kBiovNlcHWzZkt3L5XMn0=
X-Google-Smtp-Source: ABdhPJzyWmWFpSogs5Bp7lsWlfmtSvkzwGOk/yuwxGHnRkOgcVykvdJeft335HraixptrWbXgxyPtw==
X-Received: by 2002:aa7:c542:: with SMTP id s2mr3908124edr.205.1606841378899;
        Tue, 01 Dec 2020 08:49:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:22d3:: with SMTP id dm19ls2804174edb.2.gmail; Tue,
 01 Dec 2020 08:49:38 -0800 (PST)
X-Received: by 2002:aa7:c313:: with SMTP id l19mr4019346edq.293.1606841378134;
        Tue, 01 Dec 2020 08:49:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606841378; cv=none;
        d=google.com; s=arc-20160816;
        b=paX9mmewmeZdCMpuYjFI18CzPb9/MHMJo6Mqkmp/Jt5mtMu1ODJOfECMneek9YHr22
         WDvKr5QPb0kBYvFH+6rr/XZBZ3TBhU/epsAvn3lawLtuPLIiYfsS/VqiS8DN7UJLUUQy
         IWbS0kBZDefuVt5f9j09KUS6x0uAkXdzZ+R7pTRJsxBcC5Bl5Y3MY/59JqnpUViRzgzh
         ye8iWFZf84ryZKm9C+R/aJCL74ULFsX/wuJtFArbsWN92pDyfmpSp63G/m872rNy4iZ8
         LH1fxW4Xiyo2ZfBbb58EislmNLxfb8zFhHqlPutpWCpIcx2ZdWLTw1c8Y+hScwCWTQB8
         xXLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=WoAhr0nSRZvn/b0e6vXAaCs62oeypIJ+/PlDgglPg1A=;
        b=Y6eQzqYiI41byeSE0KYaKEtVAQaeRj8zRY2q3Pw1gBglUrOkrXYl6WEiDiL6YwaOPk
         3UaQjdy9oxO6T55ohjnmwSSIrm6QE7Tg6poTgGBUtRKTPPOyEv5OI1u/Py3pSJn/Ww7N
         IolQkQ14IpGDk/vMom/0yGd0/1SIAFt0nPt/SNu//llOoA8iO3f8QlUhkEjeO0QGRnYP
         P+K7iXxC0CVMhaf57cBTso9kEeR5vzp3FnZctBffPVVCavXe8abADqy0AOsLobCF05vz
         OVSHBpjwjnfrumXAe/1jZGD3zd4JyGWEN41w2HdXwrxuiPqPM1dosadmlOEcPB2E9Ox2
         k9LA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id i6si15229edk.4.2020.12.01.08.49.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:49:38 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4Clp3g5df3z9v3p8;
	Tue,  1 Dec 2020 17:49:35 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id j-uq1QKA259Q; Tue,  1 Dec 2020 17:49:35 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4Clp3g3h6dz9v3nc;
	Tue,  1 Dec 2020 17:49:35 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 419D68B7B9;
	Tue,  1 Dec 2020 17:49:35 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id iO0R35pfVlZL; Tue,  1 Dec 2020 17:49:35 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B2D858B7BD;
	Tue,  1 Dec 2020 17:49:29 +0100 (CET)
Subject: Re: [PATCH v9 1/6] kasan: allow an architecture to disable inline
 instrumentation
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20201201161632.1234753-1-dja@axtens.net>
 <20201201161632.1234753-2-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <c091e596-acfb-2d26-1c27-4388c22988cf@csgroup.eu>
Date: Tue, 1 Dec 2020 17:49:21 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <20201201161632.1234753-2-dja@axtens.net>
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



Le 01/12/2020 =C3=A0 17:16, Daniel Axtens a =C3=A9crit=C2=A0:
> For annoying architectural reasons, it's very difficult to support inline
> instrumentation on powerpc64.
>=20
> Add a Kconfig flag to allow an arch to disable inline. (It's a bit
> annoying to be 'backwards', but I'm not aware of any way to have
> an arch force a symbol to be 'n', rather than 'y'.)
>=20
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   lib/Kconfig.kasan | 4 ++++
>   1 file changed, 4 insertions(+)
>=20
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index 542a9c18398e..31a0b28f6c2b 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -9,6 +9,9 @@ config HAVE_ARCH_KASAN_SW_TAGS
>   config	HAVE_ARCH_KASAN_VMALLOC
>   	bool
>  =20
> +config HAVE_ARCH_NO_KASAN_INLINE

Maybe a better name could be: ARCH_DISABLE_KASAN_INLINE

> +	def_bool n
> +
>   config CC_HAS_KASAN_GENERIC
>   	def_bool $(cc-option, -fsanitize=3Dkernel-address)
>  =20
> @@ -108,6 +111,7 @@ config KASAN_OUTLINE
>  =20
>   config KASAN_INLINE
>   	bool "Inline instrumentation"
> +	depends on !HAVE_ARCH_NO_KASAN_INLINE
>   	help
>   	  Compiler directly inserts code checking shadow memory before
>   	  memory accesses. This is faster than outline (in some workloads
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/c091e596-acfb-2d26-1c27-4388c22988cf%40csgroup.eu.
