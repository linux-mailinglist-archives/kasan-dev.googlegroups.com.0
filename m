Return-Path: <kasan-dev+bncBAABBR7LTH7AKGQEC4LS4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id C1F032CA90E
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:56:39 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id y24sf1440338ljy.1
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:56:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606841799; cv=pass;
        d=google.com; s=arc-20160816;
        b=jz/EKVMoe13Buh1kyXxyRnZFoySu6sBG5+8ZZB/HaZ0CVxyBcesiFQmth9AayBq9p8
         BcKF6HPkGUraPbhpX793HmN6ehT0EQeQEzeF/Ov8C5aD4cob1uiao/f8frkJnHPlKZAM
         8XT+IMASkil1gPXjCf49Ur3G9Bd4qiFR7JmwDEcXCqZY2X3uvcCCsO9M/2JvBYK4F1Da
         HQYI/V2Tk9BQKJrHxiLe2kPrteqOZHCUUzW/w+HmOOZxB05G5ZuYMn+9AKy8c2tveXFh
         d8qX3XvEjaPkB1XHQt+02+m7rxDYS7+ddqwqXIkctaIs0ZC/pUPTGNnCo6Hcu6YPL34U
         a+cA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:to:subject:sender:dkim-signature;
        bh=x4nUMcLlMC5fHPGpKGIS7+HOc/4D7c4nBNuFChF5VIo=;
        b=CnN/b8m0rta1QTuKxvgmpn61vMLXExHhA+AF9/Neyy/M7kBsHnKeVB6nZPl9kH7mq9
         ZDEcFh6EyvV8fRViB3LT7aXfiIgOqM8CeLksPNH0A1nPlE62Gt4f/teVn8q8R5Fmk1fR
         WJ5etRujwfTzn4kfJbmkf8l4eU9K9ulQOaKseuTA6qhYVZtajRENmA5udm+bA7CcdDje
         4+7V8jfkVfSgp5mELaMwLpqTtYO5/erjQF2WuUpcXNipK4X83pXMP+KMGdgWfwDozrmY
         bO0C6Wjmd31k+UPBhFALesY6EgTGbAPstweOTlSMmCPT2qkkrxE/MTupxqBXDWnr2hhd
         DruA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4nUMcLlMC5fHPGpKGIS7+HOc/4D7c4nBNuFChF5VIo=;
        b=Np4PebwLXMcP3FjbO1U16YHVn52x0Iuuiff39puj4srbLa/xbYexw6vMmgf5MdCflF
         9y6nuRMjhaFou76J2HcEISzwymAoTHUlVr4qfsq4Yl2Ew9cCD/t7UXZ37mwASM0ERhV4
         w6cw7pzJYTy4PK7ZMSSwgAfNoUMly/YY8TtOg7Uku232N6vx56DNuav7SBVO0c4WKBo5
         F5pUX/DGl5R0J9e5aW0kKRWLelmN8GaVIhJgB9d2Eq3dqduqKqHR5EtLun+7fdAU/zRW
         BcNb6YLk4SicK00dqDDLmLWQjQ4r965hZepUi6rJCi4gVSBbGvyubkyHoa2JpQvzqBZs
         6A0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=x4nUMcLlMC5fHPGpKGIS7+HOc/4D7c4nBNuFChF5VIo=;
        b=PMbqeRYD7EOKfaviA4pr1PkIRQr4zAv595WQBtpkoy+4tXjVIaRvnd2uep0hpl5gVR
         gEq3lmMdazCZHI/SBwZHbFFl7eJXX8RTGmScWwyq7dn4lILnaxHpuxwIImkJsbihWa8z
         OKcfoO9jsXmenmuI7/2ZDe/7GZ/jnSfktBArcGNmT4KSfQDCQqgJbRFQ5+JrITaZujSX
         C9e/xmKGsRjNxQMcqb/REM5fhX0bZuoSDkrCxnEEl6MvYXup1Lux9v2rKztgV0SF7ST+
         RnarayZwrNEURzBKiyAOWquiXiuS6yckG8zGu93gCYENUInmKtze/BstftnOauKz/bTv
         QefQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QRwUYgjUrojz+77aR9iOCfD/LY2wcdoJ30eYcjw4gdhHEEVEg
	WAH703la2LFlaTREuLKLiq0=
X-Google-Smtp-Source: ABdhPJyapISt74ADKrD9jHBBaoImhx2QnTFWnAZZ+Zrw4qjm8wJeM36p/iSQ+eIZ7ESuKSCtB/UxSw==
X-Received: by 2002:ac2:4ace:: with SMTP id m14mr1690047lfp.523.1606841799253;
        Tue, 01 Dec 2020 08:56:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls2050793lfg.3.gmail; Tue, 01
 Dec 2020 08:56:38 -0800 (PST)
X-Received: by 2002:a19:8112:: with SMTP id c18mr1584546lfd.455.1606841798320;
        Tue, 01 Dec 2020 08:56:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606841798; cv=none;
        d=google.com; s=arc-20160816;
        b=TZoyeRMkBEI8LgBcGbCZq5ZilKXipRx7Fg573qgHMohiwOZNo+2UpYYQ+WI0ipIS/M
         BPeA0kWG8tBBqKBusQKX8qJDFjhUAzOv/FMN8Zq/cTRYNYUxO88aV/jKrRsEKKxrStrH
         wJ6Ypt2F/0qmgDL70jyDk2GAIro+UG/qpLdv8I1039nTVp7RMmw2ChNIO7BE9Z2eEuBB
         sSw7K7gOhyRgaZcTIuLCq5nSctD/zwLkI98LR/ZpTwT9QHLQWAFc7HXcoOXXO9dCZW9w
         W3Kq8sqyaKRy8fqUSz9FNztYzmCg8lQ85K0WLK8VaYUUHWy6W4PE/k+cXbbI3lcPvnCE
         EmVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject;
        bh=lClxLoo3oQgQuKPlaOUNrqqAI3Qr75+DeTrlndnCdf4=;
        b=Y4JG2FTCl4ezjuuQqcTj6arKRCpFnVGW/aIuG8witEx8pSeh1pjympuUB8XUtUdXub
         gjRPPwXbL9b/byG0tvHFkdV/siakbecEbpPLOaAEZM9Lprz2Z2M78W1p1hXbcb75XcoP
         JHm4owe89rvvFejI9sO0LZYwVp6rzdPSoOi99aWio9jpjuDtHpmt2lloJpq+Lq16u42E
         og4RPZ5i/mTXOXwx4PAH5p02bdHMe5VBSxZT8NbRYNHbj14o+8ikdoH3X/pxheFAwmNB
         6OZBhk3OTvQgNSuuS4ehbCV4PncUNQHuIx++cp/0JSB+csccu/eX3VTB01rLvxZHCIet
         qeeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id i12si14422lfl.0.2020.12.01.08.56.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:56:38 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 4ClpCl6dGbz9v3p7;
	Tue,  1 Dec 2020 17:56:35 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id aAkh48jFRr4H; Tue,  1 Dec 2020 17:56:35 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4ClpCl58BYz9v3nc;
	Tue,  1 Dec 2020 17:56:35 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id C8E668B7C1;
	Tue,  1 Dec 2020 17:56:36 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id ItWmq8r7Upbe; Tue,  1 Dec 2020 17:56:35 +0100 (CET)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 97D2C8B7B9;
	Tue,  1 Dec 2020 17:56:33 +0100 (CET)
Subject: Re: [PATCH v9 4/6] kasan: Document support on 32-bit powerpc
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20201201161632.1234753-1-dja@axtens.net>
 <20201201161632.1234753-5-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <421d8685-afef-eaa8-5207-280d951be594@csgroup.eu>
Date: Tue, 1 Dec 2020 17:56:29 +0100
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.5.0
MIME-Version: 1.0
In-Reply-To: <20201201161632.1234753-5-dja@axtens.net>
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
> KASAN is supported on 32-bit powerpc and the docs should reflect this.
>=20
> Document s390 support while we're at it.
>=20
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>

My new address is <christophe.leroy@csgroup.eu>

> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>   Documentation/dev-tools/kasan.rst |  7 +++++--
>   Documentation/powerpc/kasan.txt   | 12 ++++++++++++
>   2 files changed, 17 insertions(+), 2 deletions(-)
>   create mode 100644 Documentation/powerpc/kasan.txt
>=20
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 2b68addaadcd..eaf868094a8e 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -19,7 +19,8 @@ out-of-bounds accesses for global variables is only sup=
ported since Clang 11.
>   Tag-based KASAN is only supported in Clang.
>  =20
>   Currently generic KASAN is supported for the x86_64, arm64, xtensa, s39=
0 and
> -riscv architectures, and tag-based KASAN is supported only for arm64.
> +riscv architectures. It is also supported on 32-bit powerpc kernels. Tag=
-based
> +KASAN is supported only on arm64.
>  =20
>   Usage
>   -----
> @@ -255,7 +256,9 @@ CONFIG_KASAN_VMALLOC
>   ~~~~~~~~~~~~~~~~~~~~
>  =20
>   With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
> -cost of greater memory usage. Currently this is only supported on x86.
> +cost of greater memory usage. Currently this supported on x86, s390
> +and 32-bit powerpc. It is optional, except on 32-bit powerpc kernels
> +with module support, where it is required.
>  =20
>   This works by hooking into vmalloc and vmap, and dynamically
>   allocating real shadow memory to back the mappings.
> diff --git a/Documentation/powerpc/kasan.txt b/Documentation/powerpc/kasa=
n.txt
> new file mode 100644
> index 000000000000..26bb0e8bb18c
> --- /dev/null
> +++ b/Documentation/powerpc/kasan.txt
> @@ -0,0 +1,12 @@
> +KASAN is supported on powerpc on 32-bit only.
> +
> +32 bit support
> +=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> +
> +KASAN is supported on both hash and nohash MMUs on 32-bit.
> +
> +The shadow area sits at the top of the kernel virtual memory space above=
 the
> +fixmap area and occupies one eighth of the total kernel virtual memory s=
pace.
> +
> +Instrumentation of the vmalloc area is optional, unless built with modul=
es,
> +in which case it is required.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/421d8685-afef-eaa8-5207-280d951be594%40csgroup.eu.
