Return-Path: <kasan-dev+bncBDLKPY4HVQKBBF7GVODAMGQEUOFA3TQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 473723AACE0
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 09:00:40 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id y12-20020adffa4c0000b0290119c11bd29esf2523735wrr.2
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 00:00:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623913240; cv=pass;
        d=google.com; s=arc-20160816;
        b=JBYNrKElhKGbMB3nNyYL0eqvy7bQYakAbFbTTz3/SW7x2H3hYgHVQBoW8aU1jw2TLB
         oKIQ9bDp+gYTLMQWWz4tRsOHa3YrB91k+fC8MD9AjBX0Xu0Ih4aIp8a8oRz9s6Qi8NRN
         fZyB1q1zn09ik/yAi1rs1ZQbpQIMtW51vdm+EXlESfpH8/fYv1wvGdyn34nOX+uteIlo
         qXptPOnauVrrZchEan3DAhecoCKUKgeBVP9MNraPSxlIll2eYvOKdhatiGqFEG9RVvSm
         v+QXRhOQQKMKKjgSQRJTBHBb7aoCHUlwFKJ/O1d/ufQ6rIqYJnnDhKwMHywpCDxXRT/d
         xfhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=mveE8RqZXS68POe1SWJUh5qHa9kTq+fDQ5MXDQogcTM=;
        b=U31Zujz+hoISjW4fL0KdLWoTyTGszNstjzTTHlfgZaJY6pNmCXiXOorW6Nd3+F1OVG
         9S1XKGYOzPT5y3m4zORRT11R219mQfYCtHMpac6ZyNrVp8tXL8aXZF8cmT3Rgz9Zv030
         kCCjkcgtb8s9Q6d3LsCoWdOMc0ARvqX/6i8XBRoDzK+hQfHCAelUV6Bf7a8VyRm9Jy9A
         6kha9Ua5AygjxkjQpdCftkMrBgBY9NcdVvM32eKLBrkXlluS1iam37FBLJqoCitFZyvN
         ybIWcy0j6KX3v9LfrG17WaJYfB/zuNaGPprktJxqKcAQk+oeg940sEZ80kdPcXnAoWtW
         4dWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mveE8RqZXS68POe1SWJUh5qHa9kTq+fDQ5MXDQogcTM=;
        b=oXKVr31qJOXEp3kfrZ+q5oqCvecczHDK5aW6FM3I9oKCPpCTxLtjDNPHZC4wHjFPyV
         75MU9yaY+o9iUURmxdNnOHDwX4/HIPi9mHacE4a988i+G2S5wSv2Qq4dQ9sPHZGEJ8Kb
         UeHSE17vhUkIH7S8p7IiX85BcoDBp0kLUKRY+wt7g1JHGyssQCFeGbvjk5rlQXdD19Qy
         VUkxWAJmr5EsHsgj2fXsO8Mk49E8eeASV/hpfnR+qTxYADCUmfX06qMXEdgi0c/l38kc
         CBZlgA7njqQv8EhR0G/E+PvtWovPPr6rEFXgt/KqKHe3wgQEJC7gZ7Mt6DzireJ5tECC
         UEJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mveE8RqZXS68POe1SWJUh5qHa9kTq+fDQ5MXDQogcTM=;
        b=jpFEKWX2/UfE9pnPOJGJqLLlq3ZhIB6Cd2ciKdPihZHrmuap4UWuX04vU8VOrYt6Mn
         J+lQmzZdG6m/7K7pM17skUwxmc8R4Br08hvZ1l/JvP/WsUxz72qQPVlCCjcovfHEA7Qy
         6TkaY7QLnKa3URm/lAUpiFxc5T1Bo5fCMlwqm8DgSS9FH5qCo+FsturcRF78RHVGX/x5
         wxGvOAxsUgn+j5BFkDV9xIzYKwDa9Tfba44menY+p1wdCdyhHq6ryXk92Vu/+rXLsPEs
         6YchWD/te+rMbi60i7aQl2kaHezLwrVzJEsxP9Ldd2C2m4xDaibyzCOQzjq8ZaoWR2oC
         Un1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JQmq9PebESP6yPnEwNvcziJkjCuSpV422gF6GRdJF12J6QYT6
	lI7bRiUvJGWGK24W7S8uPm4=
X-Google-Smtp-Source: ABdhPJxqezAMOixr+7nR/cG2AY1Kpnsvip/YBuZetBIzrIoj7njO7DKax6HWuD0lhCEdMRSWxgEkWg==
X-Received: by 2002:adf:908d:: with SMTP id i13mr3790343wri.237.1623913240046;
        Thu, 17 Jun 2021 00:00:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1d0e:: with SMTP id l14ls2222297wms.1.canary-gmail;
 Thu, 17 Jun 2021 00:00:39 -0700 (PDT)
X-Received: by 2002:a05:600c:3650:: with SMTP id y16mr3268016wmq.92.1623913239184;
        Thu, 17 Jun 2021 00:00:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623913239; cv=none;
        d=google.com; s=arc-20160816;
        b=eyZZOPj/9Nm48ryi1kiB/e2zK/z4qHI+PNWP2J+EOL4tAP3IhjvhWfKhs8ZmXOO8QK
         I/BD47mJnQIQh9CTW+uEEE01136+s+dtF6ctKdcB9Iv6aOXV9DwD8X71njceHgu3D0mr
         6b/fyby3iA5a+Wb4D6MtMV07ttw1apup6F2Z+0Xu52u/C/9MbtGUcMhR5ojxp0TP1WUT
         ijbQLA5iuwEk67AUWRyj1ABWx8k4c1cgqZm9FdxYCSNB34bqEkm8ve69B3STp9NIx3qz
         pbgelUJHqC4eQ/APIJz2nHePX/U40AZc/Yo8hv2Ses6PbSQ+AteMiL4yNulTKqsud3Pj
         v87w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=cPjXfCVncT7e66ENr+cKq7g1nraEZ1wNZfUR7c+ma7I=;
        b=eJr8aHk4tUhd/kMWAklzh+LA697aiVFFDgrw+yummh/pSSA8BfqFspOgeeClpBLgz4
         TXNW8bZi8LVehxUQTdCFag04b0BW5KIkXX3eAHahIB6KyGucEsaGuh8SgkiZL0FOAE3B
         pxMWk5SILheZN85kHVgApx5dgUSuQLgmuBNkz1noO3+K9F8WvcZxY41xCMVUKMgNi9+A
         A6ZoCyamypPZ63P9uSMzGOna5GzOcy7tAwWNSV3HHN6oXzbZWsYtw5WwPTNFTO5Sj5iq
         GYn5PNIDoztNj0ILOSzo/UJS9j6YkV9nBay30+Soaf2gwVkEQL8/VS/rl4Dnmu1EZsbP
         801g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id t7si221880wrp.5.2021.06.17.00.00.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 00:00:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4G5Cck6knBzB9Kg;
	Thu, 17 Jun 2021 09:00:38 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id QJPdcHdgEBZK; Thu, 17 Jun 2021 09:00:38 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4G5Cck5nnwzB9JP;
	Thu, 17 Jun 2021 09:00:38 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id BB7508B803;
	Thu, 17 Jun 2021 09:00:38 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id v7kr536TYdhu; Thu, 17 Jun 2021 09:00:38 +0200 (CEST)
Received: from [192.168.4.90] (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 0BA158B801;
	Thu, 17 Jun 2021 09:00:37 +0200 (CEST)
Subject: Re: [PATCH v14 3/4] mm: define default MAX_PTRS_PER_* in
 include/pgtable.h
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, kasan-dev@googlegroups.com, elver@google.com,
 akpm@linux-foundation.org, andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org, aneesh.kumar@linux.ibm.com,
 bsingharora@gmail.com
References: <20210617063956.94061-1-dja@axtens.net>
 <20210617063956.94061-4-dja@axtens.net>
From: Christophe Leroy <christophe.leroy@csgroup.eu>
Message-ID: <cbe77a1d-074d-4bc0-0aad-996249a6bf3a@csgroup.eu>
Date: Thu, 17 Jun 2021 09:00:35 +0200
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <20210617063956.94061-4-dja@axtens.net>
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



Le 17/06/2021 =C3=A0 08:39, Daniel Axtens a =C3=A9crit=C2=A0:
> Commit c65e774fb3f6 ("x86/mm: Make PGDIR_SHIFT and PTRS_PER_P4D variable"=
)
> made PTRS_PER_P4D variable on x86 and introduced MAX_PTRS_PER_P4D as a
> constant for cases which need a compile-time constant (e.g. fixed-size
> arrays).
>=20
> powerpc likewise has boot-time selectable MMU features which can cause
> other mm "constants" to vary. For KASAN, we have some static
> PTE/PMD/PUD/P4D arrays so we need compile-time maximums for all these
> constants. Extend the MAX_PTRS_PER_ idiom, and place default definitions
> in include/pgtable.h. These define MAX_PTRS_PER_x to be PTRS_PER_x unless
> an architecture has defined MAX_PTRS_PER_x in its arch headers.
>=20
> Clean up pgtable-nop4d.h and s390's MAX_PTRS_PER_P4D definitions while
> we're at it: both can just pick up the default now.
>=20
> Signed-off-by: Daniel Axtens <dja@axtens.net>

Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>

>=20
> ---
>=20
> s390 was compile tested only.
> ---
>   arch/s390/include/asm/pgtable.h     |  2 --
>   include/asm-generic/pgtable-nop4d.h |  1 -
>   include/linux/pgtable.h             | 22 ++++++++++++++++++++++
>   3 files changed, 22 insertions(+), 3 deletions(-)
>=20
> diff --git a/arch/s390/include/asm/pgtable.h b/arch/s390/include/asm/pgta=
ble.h
> index 7c66ae5d7e32..cf05954ce013 100644
> --- a/arch/s390/include/asm/pgtable.h
> +++ b/arch/s390/include/asm/pgtable.h
> @@ -342,8 +342,6 @@ static inline int is_module_addr(void *addr)
>   #define PTRS_PER_P4D	_CRST_ENTRIES
>   #define PTRS_PER_PGD	_CRST_ENTRIES
>  =20
> -#define MAX_PTRS_PER_P4D	PTRS_PER_P4D
> -
>   /*
>    * Segment table and region3 table entry encoding
>    * (R =3D read-only, I =3D invalid, y =3D young bit):
> diff --git a/include/asm-generic/pgtable-nop4d.h b/include/asm-generic/pg=
table-nop4d.h
> index ce2cbb3c380f..2f6b1befb129 100644
> --- a/include/asm-generic/pgtable-nop4d.h
> +++ b/include/asm-generic/pgtable-nop4d.h
> @@ -9,7 +9,6 @@
>   typedef struct { pgd_t pgd; } p4d_t;
>  =20
>   #define P4D_SHIFT		PGDIR_SHIFT
> -#define MAX_PTRS_PER_P4D	1
>   #define PTRS_PER_P4D		1
>   #define P4D_SIZE		(1UL << P4D_SHIFT)
>   #define P4D_MASK		(~(P4D_SIZE-1))
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 9e6f71265f72..69700e3e615f 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -1625,4 +1625,26 @@ typedef unsigned int pgtbl_mod_mask;
>   #define pte_leaf_size(x) PAGE_SIZE
>   #endif
>  =20
> +/*
> + * Some architectures have MMUs that are configurable or selectable at b=
oot
> + * time. These lead to variable PTRS_PER_x. For statically allocated arr=
ays it
> + * helps to have a static maximum value.
> + */
> +
> +#ifndef MAX_PTRS_PER_PTE
> +#define MAX_PTRS_PER_PTE PTRS_PER_PTE
> +#endif
> +
> +#ifndef MAX_PTRS_PER_PMD
> +#define MAX_PTRS_PER_PMD PTRS_PER_PMD
> +#endif
> +
> +#ifndef MAX_PTRS_PER_PUD
> +#define MAX_PTRS_PER_PUD PTRS_PER_PUD
> +#endif
> +
> +#ifndef MAX_PTRS_PER_P4D
> +#define MAX_PTRS_PER_P4D PTRS_PER_P4D
> +#endif
> +
>   #endif /* _LINUX_PGTABLE_H */
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/cbe77a1d-074d-4bc0-0aad-996249a6bf3a%40csgroup.eu.
