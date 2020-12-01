Return-Path: <kasan-dev+bncBAABBYHLTH7AKGQET4J2SRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C83A02CA90F
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:57:04 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id b12sf1263860wru.15
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:57:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606841824; cv=pass;
        d=google.com; s=arc-20160816;
        b=beAo0gpZvmfFQo0GrlXBF2940oJQH8ezk+hOM5V8ctX6hXvvjr0H9DR0Btr/N/Nu5J
         0l75NLQyxwy3cVBV7NrMydYNgCmEXsS/MCG+mWiE+qrQu753aZFx+ubV17gu14we4Bcm
         MLyxNC0xoO6sY3jL3AnEl9uDrYYPVaioRt7SdWVEDEjA9FxgAg47MjoheQSKaHuKZky9
         89aU0efzCAaI7O6fG23DxvrTmgtnEgmJVOD8fs0IVP3kt8p7Sj8kRD/KJ+fsqeMPewz4
         OL4WTYrL/B38vN5/yWQpLJuI6bDmfwrvTRUnbYzOA7v5voie3rWzamz5E3BlOEXzyjNK
         Imlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=QLAXbEuV8RZE1eqDzgZdOh8XDCYqKp6YlPlmFIOi8kE=;
        b=mtFezxLy+JLEuK55se67PpBhGcXspR32lwDXL4NODpfp8+vsD3k0G8zm6w7deE5j9f
         fIYQ68Q0tuwt4lmQyWvU/NGKrFpm4YtmcRQjqSnCudVU37iTKfpRIc4mVxuzWOucELf1
         np3xKrPEWXr0Rg2nl/mMN1LSc1o2FtWIm5kuIU4kTpk/4qu9kZUaeEggUi1cSeRP74rd
         bDeE9R5DBHl+3XmKKRZTBJ142ncJCjbJyLITX6XO3dXEiKSulikmr8VEau3v4Uf8nQC4
         hHJxkYuiOBjqLU+YlNjGLl0AvKBWxWB/rBbRzHXOj/n+VE3R44LVDsIKVoc4N72oAwiK
         MDog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QLAXbEuV8RZE1eqDzgZdOh8XDCYqKp6YlPlmFIOi8kE=;
        b=BI3Q8hdymJUp+f10OEPUSEGqb6wgb76HDb9jJYPmDC++IUN7RLv7oQsq3ys55Kzh7I
         oyFS12w7JHTYn8B6K8KL6nD0OsCt3hsngmhz13xabOhoBdUkJBTbwd9a9nrAAOwMdcWm
         inlet4iIPtguhp/Ij0LlsWVegbYygsUo1UFWnZ9jJU2H3f9IEAkt0maMrwSgaD5KSnfn
         t/VTupLHCpGo+EpTYOjHkJq50lp4yFcU3bsCH5lEgdjxeyXtXMgJowflkLK8H/NkbHgG
         WYVwC7yZ/uB/EkXAplYDHVbGHKQLL7kQN6i/Xw79NgnmkYCqPvDpMe4AnNGsWjegK7wZ
         DKug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QLAXbEuV8RZE1eqDzgZdOh8XDCYqKp6YlPlmFIOi8kE=;
        b=FetCmYHHq/7bDEkYieE7M54KwrbJcNklEXx4YqS7O/jWSbks0eZ0b0PjhpCJk4xz1X
         W0nWVt5ab3TPnfQrw9k+vHFJC8rQB9gG3HIyPoxsXGbtZWRDih2HE2j6lBlrGGGE16qN
         ZqzkaL0m8KEfnt54j1YLgoDAdhpbBOwNbJ26OlbiEVD3g6jO+xSQk+Y7XSPmDtdrEEKl
         jn9WSae70o+zeoV2xB+pL5V5JqQy6bcOW6x1sFjTHU4NXPbJCLJvCtdb+k60r+hpfIQJ
         Bqlw6uT2Z7I0cqRVP+LPir0Sm5SJzMZBwfivCcIEFBFhWiKcFDUY2wSxfWI68elvFiGR
         GswQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532sz91UvwskxURHZGwzYQJrKDac+vYhABufrCqtg+2JIwTJfltN
	kN//VxAEBl6ZulZ9/5mpTn8=
X-Google-Smtp-Source: ABdhPJyQMN9uOFhCg6RpvkHiNWLEXS5Ub2FoL2ggw4cFP3A+L0ojtx11qulHHTnA69CkSE2MET82ug==
X-Received: by 2002:a5d:45c5:: with SMTP id b5mr5206967wrs.14.1606841824606;
        Tue, 01 Dec 2020 08:57:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:a4c2:: with SMTP id n185ls1239035wme.2.canary-gmail;
 Tue, 01 Dec 2020 08:57:03 -0800 (PST)
X-Received: by 2002:a1c:7f43:: with SMTP id a64mr3610821wmd.164.1606841823873;
        Tue, 01 Dec 2020 08:57:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606841823; cv=none;
        d=google.com; s=arc-20160816;
        b=mH2l8bJe8Vqvz5GL+Lk8fE+isayDEr1zTtgD1HHoDJzASVQL8OthfoPA8xx4NP1IBI
         OniLI7AhNK1yXr6MOJfwYvEp/zOdvPE17vnJDx0Vj1lJfAB+b2zYBiN8YBzt+s0PMwik
         dx3xJO3VnxUdhotf1yB4HEa4UeMfxEfsQCVF8lOrZKx6UTwI/nb9RJgywghxO3A7nUy+
         0gU6nW5hKe8zIqJu/62sNyr/LTFA5JMIJZfvOmnigrdWrbM5mFanoiwt2RKilH4SOzU3
         UKz4Un7/sVI8RRIoBzyyd167fqHHr0g7oZnJ9lLqWn9DcZtEmbQGmBpXr4BpfsktrMNe
         k4ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=4M/3/aBeN2YrInS4aUvWW5INTePBunJdOe40LhBgRRM=;
        b=Wn4Q750WFvly4y3d1VeHaw+XfqxQLztKmLHVXKBXHuCynKY2hbf74V2fU15nHidX2u
         fmkt1BH8WsmGbZQe4r2IQu8xu+VyIYKMYR5XGdq2DPCwVuU12K4vniOhgAfZLfbAExxJ
         AMkuXlS6c/MCjdyvFVAkaWierzJ+K0scESmG0NuctLfdNVGv6+/0haIeXeQn7eUFrhKY
         uLYb3rmursaPXs2qhBkdtyejJBHj7vE3bg6UOxN0UVCa/kwv8pAnBevM9s43XjQPjBU6
         x3MsU86IhN/CpeqRTTFa/TQIVIM02CzMu2ffGjW9nXeA4ANqgcJG+GFi68xC0vDs8r5y
         PWZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id y187si65468wmd.1.2020.12.01.08.57.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:57:03 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4ClpDF6nXGz9v3pB;
	Tue,  1 Dec 2020 17:57:01 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id Fw8xU2BzxYW9; Tue,  1 Dec 2020 17:57:01 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4ClpDF5js3z9v3p8;
	Tue,  1 Dec 2020 17:57:01 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 981A68B7BD;
	Tue,  1 Dec 2020 17:57:02 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id EFRlEYXIR7eW; Tue,  1 Dec 2020 17:57:02 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 672CA8B7B7;
	Tue,  1 Dec 2020 17:56:58 +0100 (CET)
Subject: Re: [PATCH v9 5/6] powerpc/mm/kasan: rename kasan_init_32.c to
 init_32.c
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20201201161632.1234753-1-dja@axtens.net>
 <20201201161632.1234753-6-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <459c6cf1-dd76-5d1f-e7c8-432fcbe5eef9@csgroup.eu>
Date: Tue, 1 Dec 2020 17:56:53 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <20201201161632.1234753-6-dja@axtens.net>
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
> kasan is already implied by the directory name, we don't need to
> repeat it.
>=20
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>

My new address is <christophe.leroy@csgroup.eu>


> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   arch/powerpc/mm/kasan/Makefile                       | 2 +-
>   arch/powerpc/mm/kasan/{kasan_init_32.c =3D> init_32.c} | 0
>   2 files changed, 1 insertion(+), 1 deletion(-)
>   rename arch/powerpc/mm/kasan/{kasan_init_32.c =3D> init_32.c} (100%)
>=20
> diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makef=
ile
> index bb1a5408b86b..42fb628a44fd 100644
> --- a/arch/powerpc/mm/kasan/Makefile
> +++ b/arch/powerpc/mm/kasan/Makefile
> @@ -2,6 +2,6 @@
>  =20
>   KASAN_SANITIZE :=3D n
>  =20
> -obj-$(CONFIG_PPC32)           +=3D kasan_init_32.o
> +obj-$(CONFIG_PPC32)           +=3D init_32.o
>   obj-$(CONFIG_PPC_8xx)		+=3D 8xx.o
>   obj-$(CONFIG_PPC_BOOK3S_32)	+=3D book3s_32.o
> diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasa=
n/init_32.c
> similarity index 100%
> rename from arch/powerpc/mm/kasan/kasan_init_32.c
> rename to arch/powerpc/mm/kasan/init_32.c
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/459c6cf1-dd76-5d1f-e7c8-432fcbe5eef9%40csgroup.eu.
