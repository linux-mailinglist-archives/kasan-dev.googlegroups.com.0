Return-Path: <kasan-dev+bncBDGZTDNQ3ICBBF664SQAMGQEYPSK3SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D50E6C2908
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Mar 2023 05:14:17 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id dg8-20020a056214084800b005acc280bf19sf7090688qvb.22
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Mar 2023 21:14:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1679372056; cv=pass;
        d=google.com; s=arc-20160816;
        b=NfbZzl4Ac8zKpzbpr81qTy4wqe/zKa6KnGvD4dejLHasXHtHLfWnCsILePj6w6viNL
         CiiSCdRGOfCnEcl4e/cQKS4h4pcATVRbDYRLo9AIKaxFYcS0rtsdlz5xqFM1zOhDFU4p
         Qc3VdSQcXIrrE1lMlYUqLnoa/27aabgHPVZ1u1uDEaSO65gxIQ4Z9XJ3wXOFo0QQBWga
         VyNz+He2aOsZqGI6FDc2Y3Y5/lm/Hi38Ez/bkYShUCPm/8YFzx+6al9lFKEsxmTb9EjI
         PCVmQsoB6CChfYwYT0G4w6uGwsrYworMNxEz/r7FK+tJ1kmrNjyFMD8U7TbZujoqGJIj
         LEYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=4P1oIOlvfNj0y4NN67NRzKIjjjuSeH05Rw5R8Ufa9II=;
        b=W35mtwigqo+RWn6c3+o+Oz+GD7kNScMztwGHLpRiHh4CHUSez8oWL98+MNYseaNj3D
         4C8GzScuEULph6su/I6weEd2m6fcLf+H6tSDeBUGY3WbaqUmANkzO1I5sBT/H5K7+VUw
         Vu69eEfQlm35xGt82kZ4AXjNP8ur9L/T34hbJAK+9ft3wjc/DzZYy/WCVXgTDdPZq6t9
         tSnkvgCkWMamFBc7hFqwtpFBrU8A4SqI12xljwhDzTc7V55xrlwm9euH0/RNR9byPkvH
         r+tFVN2WRX2Tnh+17u4qFxbc8sIMpODq5V+RxQebvounRzobA835XbdXD7KcQZpQWOsv
         DrNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=Vz4Mi71I;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1679372056;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4P1oIOlvfNj0y4NN67NRzKIjjjuSeH05Rw5R8Ufa9II=;
        b=qxkXYzWOFlBS0nC44uuZMfr9yfcgSk59un+bYX+dJhFM2CrdC9KRjA4uk2kmRplxzL
         91EHq7RWgB1ex6qBDmxWfZNUblUrPaKkN1b282yDQML/BtJ9d5WidW1apey+UxCqmbaU
         m/g3y94/pDFBqFoV60x8d2Tg35fwrJ0sUVwMEJ3fKT1yAUq4mes1AxT2RMx1CqEL1Xtn
         zImOd0/OaynMh8fdl0NTUor5PUbRNhIrhtxHdQcoBRNNwo0JayCzPYGrZ7NByfWKI2sN
         IYgIA4D8PyAh0WHlR26EYqzQG1e5tKT2THsdcJgPUqRv6UWgreCponI8vVLIVlYgg3uV
         LzBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1679372056;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=4P1oIOlvfNj0y4NN67NRzKIjjjuSeH05Rw5R8Ufa9II=;
        b=Vs3w3jYfAQdyEjZN3q4fE16UQJldgm9aO2x57yfGcsey24ZjWp7D3E4Cs6qY3+6xx6
         wUYFA3Q3GwRxSThdLVHJeOYlzmwBt5spXCJ63uJuXMhTPxjXhnI9U2iagIrN7V23zPpN
         gBvmntpsd+Z3Cqf4edwYoJQj7kHB8tbycuTZEIUGReiWOTVOEREL8pK71MW30MMTWHiD
         HU7AhZE/8847M6nP2fO1LYt4ve00BaO0UsRQokZmTcwGfdAna4u1g2qgwS4e5oXTlAtH
         +xk7t+ugng0gV+E+skxPl7aFCAQqa95PvC4X8I82qmbbeDxGa+vTdogsuIGFIxp/Nx2U
         0EjQ==
X-Gm-Message-State: AO0yUKXcuXTWHTOU/xmmjm/1GAXMBDXw7pbWAjkukK/Q3Ifag77rVrpV
	+90hI/IN8ehB8YFU9HWpkBM=
X-Google-Smtp-Source: AK7set8cOv/MwozNqvgBV8dV4U0AP/OQPinjlxsKffU7awgXj18+beMsCTLg/KzUPp+RfnMV9AdWMQ==
X-Received: by 2002:ac8:7f43:0:b0:3d9:d5a3:d3be with SMTP id g3-20020ac87f43000000b003d9d5a3d3bemr593354qtk.4.1679372055889;
        Mon, 20 Mar 2023 21:14:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:12c4:0:b0:3bc:edc5:2588 with SMTP id b4-20020ac812c4000000b003bcedc52588ls13426245qtj.6.-pod-prod-gmail;
 Mon, 20 Mar 2023 21:14:15 -0700 (PDT)
X-Received: by 2002:a05:622a:38a:b0:3bf:e3e8:f24e with SMTP id j10-20020a05622a038a00b003bfe3e8f24emr2397949qtx.62.1679372055312;
        Mon, 20 Mar 2023 21:14:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1679372055; cv=none;
        d=google.com; s=arc-20160816;
        b=SSxSZW+qu9veA0pTenLHnAQuVArJF3Amd9RaS3yjzqzgZzGpf7XgD20AyD5pM5ECsk
         iOBUmtQmCDauYQl71P33ex5Us4jOQre6HZ75vSpPc/J2Vhr+vxiSOdc8bGpcAbofs8Oa
         qbS1vgXxIpfgWrIfXXtYwEUPYYBO7lPMp6B0RfdTa4LT17anWySDDbjqC30ztd7Z/BhH
         UkaKPC52qxIUnghp++PTnsiVjJSCeoOr1lJZYVl7F+QJsqFmRZ6R8AqzD7w9ObFPkmiv
         zfyHyB12b1uEDsL4Ge7y2Qo+vOXj9esL6DkkawO4OAXMoqHlb609OzLLAYqLL5hsxoFM
         2a1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=9ghHN1vnHe3Q9LXpob6M+hS+NoZYTu49dwl+0ycHuL0=;
        b=0xzjPXOSINW7teTkd5qeQKIZ3/O4VzC+lBFxgA927j0oeivfl3Pazg1TC8KvNaxWRn
         C/NOsXP3kAVfUQi1bwlh9HWjPUxWDiXwi3HgGufHb4VgzC4Ti0pljmP4ZIe2fl6FJ2uk
         ARVqtf75osh4Jvegx3ARQjYbVzBALDN+Kj4iPQ385EPgT7B+WeeOHlokcQqP9i+YcYUM
         p4Wga5VQxv8l5B00wXchPQ8IeBgb2s58W2r7btiUdwVUa1Se8FCSFeocLEdJZP1jqjd+
         lhnHHtP4vYfrXntbeyDQwicGuYZTMk0fDcfNi4zef+bw41wS0D5qkhoVwci/iy20FYkV
         tpBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance.com header.s=google header.b=Vz4Mi71I;
       spf=pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id h19-20020a05620a401300b007427cf877eesi499941qko.2.2023.03.20.21.14.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Mar 2023 21:14:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of zhangpeng.00@bytedance.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id bn14so407223pgb.11
        for <kasan-dev@googlegroups.com>; Mon, 20 Mar 2023 21:14:15 -0700 (PDT)
X-Received: by 2002:a62:6304:0:b0:627:a283:5a04 with SMTP id x4-20020a626304000000b00627a2835a04mr823381pfb.27.1679372054389;
        Mon, 20 Mar 2023 21:14:14 -0700 (PDT)
Received: from ?IPV6:fdbd:ff1:ce00:1c2a:1cd4:8b91:108f:bf15? ([2404:9dc0:cd01::1a])
        by smtp.gmail.com with ESMTPSA id 23-20020aa79117000000b005a8173829d5sm5135483pfh.66.2023.03.20.21.14.10
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Mar 2023 21:14:14 -0700 (PDT)
Message-ID: <974ef73e-ab4f-7b24-d070-c981654e8c22@bytedance.com>
Date: Tue, 21 Mar 2023 12:14:08 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0)
 Gecko/20100101 Thunderbird/102.8.0
Subject: Re: [PATCH] mm: kfence: fix PG_slab and memcg_data clearing
To: Muchun Song <songmuchun@bytedance.com>, glider@google.com,
 elver@google.com, dvyukov@google.com, akpm@linux-foundation.org,
 sjpark@amazon.de, jannh@google.com, muchun.song@linux.dev,
 roman.gushchin@linux.dev
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <20230320030059.20189-1-songmuchun@bytedance.com>
From: "'Peng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20230320030059.20189-1-songmuchun@bytedance.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: zhangpeng.00@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance.com header.s=google header.b=Vz4Mi71I;       spf=pass
 (google.com: domain of zhangpeng.00@bytedance.com designates
 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=zhangpeng.00@bytedance.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=bytedance.com
X-Original-From: Peng Zhang <zhangpeng.00@bytedance.com>
Reply-To: Peng Zhang <zhangpeng.00@bytedance.com>
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


=E5=9C=A8 2023/3/20 11:00, Muchun Song =E5=86=99=E9=81=93:
> It does not reset PG_slab and memcg_data when KFENCE fails to initialize
> kfence pool at runtime. It is reporting a "Bad page state" message when
> kfence pool is freed to buddy. The checking of whether it is a compound
> head page seems unnecessary sicne we already guarantee this when allocati=
ng
> kfence pool, removing the check to simplify the code.
>
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Fixes: 8f0b36497303 ("mm: kfence: fix objcgs vector allocation")
> Signed-off-by: Muchun Song <songmuchun@bytedance.com>
> ---
>   mm/kfence/core.c | 30 +++++++++++++++---------------
>   1 file changed, 15 insertions(+), 15 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 79c94ee55f97..d66092dd187c 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -561,10 +561,6 @@ static unsigned long kfence_init_pool(void)
>   		if (!i || (i % 2))
>   			continue;
>  =20
> -		/* Verify we do not have a compound head page. */
> -		if (WARN_ON(compound_head(&pages[i]) !=3D &pages[i]))
> -			return addr;
> -
>   		__folio_set_slab(slab_folio(slab));
>   #ifdef CONFIG_MEMCG
>   		slab->memcg_data =3D (unsigned long)&kfence_metadata[i / 2 - 1].objcg=
 |
> @@ -597,12 +593,26 @@ static unsigned long kfence_init_pool(void)
>  =20
>   		/* Protect the right redzone. */
>   		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
> -			return addr;
> +			goto reset_slab;
>  =20
>   		addr +=3D 2 * PAGE_SIZE;
>   	}
>  =20
>   	return 0;
> +
> +reset_slab:
> +	for (i =3D 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> +		struct slab *slab =3D page_slab(&pages[i]);
> +
> +		if (!i || (i % 2))
> +			continue;
> +#ifdef CONFIG_MEMCG
> +		slab->memcg_data =3D 0;
> +#endif
> +		__folio_clear_slab(slab_folio(slab));
> +	}
Can this loop be simplified to this?

	for (i =3D 2; i < KFENCE_POOL_SIZE / PAGE_SIZE; i+=3D2) {
		struct slab *slab =3D page_slab(&pages[i]);
#ifdef CONFIG_MEMCG
		slab->memcg_data =3D 0;
#endif
		__folio_clear_slab(slab_folio(slab));
	}

> +
> +	return addr;
>   }
>  =20
>   static bool __init kfence_init_pool_early(void)
> @@ -632,16 +642,6 @@ static bool __init kfence_init_pool_early(void)
>   	 * fails for the first page, and therefore expect addr=3D=3D__kfence_p=
ool in
>   	 * most failure cases.
>   	 */
> -	for (char *p =3D (char *)addr; p < __kfence_pool + KFENCE_POOL_SIZE; p =
+=3D PAGE_SIZE) {
> -		struct slab *slab =3D virt_to_slab(p);
> -
> -		if (!slab)
> -			continue;
> -#ifdef CONFIG_MEMCG
> -		slab->memcg_data =3D 0;
> -#endif
> -		__folio_clear_slab(slab_folio(slab));
> -	}
>   	memblock_free_late(__pa(addr), KFENCE_POOL_SIZE - (addr - (unsigned lo=
ng)__kfence_pool));
>   	__kfence_pool =3D NULL;
>   	return false;

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/974ef73e-ab4f-7b24-d070-c981654e8c22%40bytedance.com.
