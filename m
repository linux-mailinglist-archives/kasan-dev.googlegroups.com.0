Return-Path: <kasan-dev+bncBDLKPY4HVQKBB66M6TBAMGQEFBAP6NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 233E6AE9BDD
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 12:52:48 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-553d57646d0sf1052396e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 03:52:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750935165; cv=pass;
        d=google.com; s=arc-20240605;
        b=euCOwx6KMDI06MN4UQTiuStgiz9jV6PtKekrgz2XxpMSeL2bnnZWLczN46CDzEYlqS
         /syH69x4PoYbjeAxDXAVeEijvyFtq2VL8IKDP8+lG5RSxsBdzAwAsM+1EDNLazGhywa/
         QgT/E/0mWKR/M2WwZWIZCu+qLvkgODJVqg6WgXiDpVpcgUmZInT/fni0JPdXR1gWr1JB
         N+h/xYg+yckWY8Y9067tl+gdeb74HB9ByshSztsqcy449u05x1MS6Cmv56eNMK0z/3xs
         ylSaCJUZ8EcapzrCW2rzMakZueRqRPnh1fMIMB7s1SgWEf2/sLjfe+Pler7/XNmaTTtZ
         xEhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=lKroT1S7j2W4b+4iW9d75mFXSdw5jKX3WjcF6fChOaU=;
        fh=BYL5KtyC3YLyM59LzFAaHQLYA46y/ZGulBW+LIoPvAM=;
        b=Ylb90mg0LtkJgFCAhQvHA/BZDVs63AlKaFgoVPMuTxEJIsfttGKfUtQ0dc9aYHjbBI
         I1mIMRv56S0J5VcjonX4+EsU27BY0DxLl9tOMs2JEi1LfPaPSbSjeXnannqWI7gp5VTz
         ddHyG7V0HjPVeo8WdcVdopAVS9yjR5flBvLebPIaxX+o55x1swZUZQzwwKXvK45L9iB5
         5PLPxS6UYzwIC2m7V8Mhg0+xhrMZClvj89RCdoVRv9W9B6pMlvkkVNjgL0do7yvJtcHD
         AYevEqriCrIN6B+emGlAYkXG+4soyTpaJqFXHCfTdNNv3HKEOMErJMkswjITPE/g7bkH
         Ps+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750935165; x=1751539965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lKroT1S7j2W4b+4iW9d75mFXSdw5jKX3WjcF6fChOaU=;
        b=aKRDAULKOVGH8SWdHmnL0Yluhs0imxNA9IfIN1Lv1BM3DtzCjaYYNId08bNmhe9cKj
         xDZwPJtgBp1yAxI2J2ekMB19hVSUdBVcJZYm3b9DWlxeLkvbAc6B9jAEGxpQGqUbUw7R
         Plo4gX8IMcshbvwZVy7FUp+YqqFsUz0ZFNi1Hxi/koRN2IvgSG7lz0qK44sgsTBqYUgd
         I5VuecHp6nNw5xVxaUgDF7oiDRwKjzx0c9MrNyJld1V6HO9q5LgpmRkMwdBkPxmmzTOu
         siL1byWYt0nzJY0/fl8JASB97O1jX6HQ0B6tiCgAEpGsoUbsVbGIwHec/KYuaUkk0DFH
         vt8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750935165; x=1751539965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lKroT1S7j2W4b+4iW9d75mFXSdw5jKX3WjcF6fChOaU=;
        b=Cw81zj8M5w0PxQYEsGFUQ0xUTJXxeB5ZfHbpTnrBeyN1AcIsbsErvafdCZqqsgIiaF
         TtzPqSsuV1GphMPglBtr9yOLvvU5MJBRMHltUsFxmcp+1wTBhdlvmmlKjT3ZOUt9gR/J
         FYD/a8SJmvzs5OPTvRaxXHOpJnkr4k7TZBlimqMJ/fJKQ7Z/G7wpBO801oRIaoDFPUFv
         7m4UeXf1Vr3Vwm6FlzSiElSqnaf4MI52tn8GxXUPkzNOmVJjrvrlXCZS5RnYmuGb3vQt
         SR5KCOCxs7Z/eUQFvuRApP+8q9c9cocOIe1mrU2WIw9J1eExVaRPHflN5aCPGgHR9Yiv
         0/0w==
X-Forwarded-Encrypted: i=2; AJvYcCXQuUb12H/RTKgyGerfG/v00yZrsJQPPuAhblaVQ7+gNksxWUW1TLu3Y7zi62L8uviPN7zvKQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywj5lFSHLBeM1s+Df/yBd+YP9CtgP48C6ZCsYnseQwLKZz2w9Y2
	MBRiNRTTPImaiO0KMIhMrer4HoaeGuBCBXTLSxb6BTO7adMDp/soJglo
X-Google-Smtp-Source: AGHT+IHBtdgluvPzu3OLFZNWay8Towd46MN19VEY4BkwUGmCX1UuJWWNhFJ7Lo5KDN4WK0u56lHcbA==
X-Received: by 2002:a05:6512:2314:b0:553:b054:f4ba with SMTP id 2adb3069b0e04-55502c8979bmr1072348e87.12.1750935164574;
        Thu, 26 Jun 2025 03:52:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZearcpy3TaLa71+YMUs18CKZjJTQ0huGXMdf6aPmI1S7g==
Received: by 2002:a19:5f55:0:b0:551:5195:ea7b with SMTP id 2adb3069b0e04-55502de61ecls197110e87.1.-pod-prod-00-eu;
 Thu, 26 Jun 2025 03:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVN6HMhz1W/p7bNYB9GmggqUJQop/BVus5vfq9dw/gEWjfMsDuraorZXBFPIaI5WBqUN02SmJ62PtE=@googlegroups.com
X-Received: by 2002:ac2:5686:0:b0:550:e692:611b with SMTP id 2adb3069b0e04-55502c9aca4mr1119493e87.16.1750935161074;
        Thu, 26 Jun 2025 03:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750935161; cv=none;
        d=google.com; s=arc-20240605;
        b=DIJ54Yg+ZUuu8t+8G5s/MVQuhFuaV0J4AQvLtpSSs+jfyijwXZyaEHf7i6vd1QZl1/
         vALAXUt/CI5brgxfpGi6TFt1IGVVx4ck6/gtRcbOpskLk9rCfEoJB3WFzOkBI1EApceZ
         cl4UHLkd5P4qrjgPZM5YblyumYtNl/QbxtkI1sDSDlhDDHsc7evqTtaRuG0jct79gu84
         So4uI5cJtEamaXn5YAhupxQeYoE7RGqa3DROS2+wwriQaaQ1YdigM+kN8IRnpf/LBeKh
         ei7/O64I2TubVorhCllcLDjWAh7qeBBWpHJDtFqjvb3xet/Hx8kQxX+NiysQqBywCm9O
         zRDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=JNPRNVa0NXAIt/TPNv1Il9lD8lH58j3TXeT6bKfk/5M=;
        fh=SFdHZR8zxg6TEbE6MgAXQj1yZoKJ36rM9pB/hubh7sU=;
        b=dNf4FWP5CkoSuL4ny7Uzlhert5VKd/oc86brt6J/47NwBUSaRDh+DmAR50B7x1EX2Y
         9AD1TGZAWyhgZppBBHPvwmJAQmuxCNyhlhfOaqFxsUd5s2Eh6OKzQJrM/9TqRviPYSe2
         2sig8JTBQ1y25XDlp8gI7d0xVMTkhfeszZg8spWGDrIkhbOWytQix+b3JANVtZA7WcC7
         AaNkN7tS/s3nrdSkH+onEjsfkcj+SXMkBPQNpm+ds1uWN/dHYVj5Cg3S7TGYTmVwALUj
         xgg4lIR8/Pk+gjtOG5zd8EZ2nNMbwTwGzBAxxyVLYwJ0CoTyM1l9Ho5MIDMAP9kLwmOe
         5UUQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-553e41c0307si488435e87.8.2025.06.26.03.52.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 03:52:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub3.si.c-s.fr [192.168.12.233])
	by localhost (Postfix) with ESMTP id 4bSbB02K49z9vGJ;
	Thu, 26 Jun 2025 12:52:40 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id uDQegORpF3hS; Thu, 26 Jun 2025 12:52:40 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 4bSbB017ZFz9vGH;
	Thu, 26 Jun 2025 12:52:40 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 1B36F8B7B7;
	Thu, 26 Jun 2025 12:52:40 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id 1FFBuvr_5nqx; Thu, 26 Jun 2025 12:52:39 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 8F3C38B7A7;
	Thu, 26 Jun 2025 12:52:37 +0200 (CEST)
Message-ID: <3b6ff3a9-6b88-4a28-a0fd-31f31ae3e84b@csgroup.eu>
Date: Thu, 26 Jun 2025 12:52:37 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 9/9] kasan/powerpc: call kasan_init_generic in kasan_init
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 glider@google.com, andreyknvl@gmail.com, dvyukov@google.com,
 vincenzo.frascino@arm.com, catalin.marinas@arm.com, will@kernel.org,
 chenhuacai@kernel.org, kernel@xen0n.name, maddy@linux.ibm.com,
 mpe@ellerman.id.au, npiggin@gmail.com, hca@linux.ibm.com, gor@linux.ibm.com,
 agordeev@linux.ibm.com, borntraeger@linux.ibm.com, svens@linux.ibm.com,
 richard@nod.at, anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
 dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, x86@kernel.org,
 hpa@zytor.com, chris@zankel.net, jcmvbkbc@gmail.com,
 akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com, geert@linux-m68k.org, rppt@kernel.org,
 tiwei.btw@antgroup.com, richard.weiyang@gmail.com, benjamin.berg@intel.com,
 kevin.brodsky@arm.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250625095224.118679-1-snovitoll@gmail.com>
 <20250625095224.118679-10-snovitoll@gmail.com>
Content-Language: fr-FR
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20250625095224.118679-10-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
X-Original-From: Christophe Leroy <christophe.leroy@csgroup.eu>
Reply-To: Christophe Leroy <christophe.leroy@csgroup.eu>
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



Le 25/06/2025 =C3=A0 11:52, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> Call kasan_init_generic() which enables the static flag
> to mark generic KASAN initialized, otherwise it's an inline stub.
> Also prints the banner from the single place.
>=20
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D218315
> Fixes: 55d77bae7342 ("kasan: fix Oops due to missing calls to kasan_arch_=
is_ready()")
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>   arch/powerpc/include/asm/kasan.h       | 14 --------------
>   arch/powerpc/mm/kasan/init_book3s_64.c |  6 +-----
>   2 files changed, 1 insertion(+), 19 deletions(-)
>=20
> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/=
kasan.h
> index b5bbb94c51f..23a06fbec72 100644
> --- a/arch/powerpc/include/asm/kasan.h
> +++ b/arch/powerpc/include/asm/kasan.h
> @@ -52,20 +52,6 @@
>  =20
>   #endif
>  =20
> -#ifdef CONFIG_KASAN

The above #ifdef must remain, at the moment I get:

   CC      arch/powerpc/kernel/asm-offsets.s
In file included from ./arch/powerpc/include/asm/nohash/32/pgtable.h:65,
                  from ./arch/powerpc/include/asm/nohash/pgtable.h:13,
                  from ./arch/powerpc/include/asm/pgtable.h:20,
                  from ./include/linux/pgtable.h:6,
                  from ./arch/powerpc/include/asm/kup.h:43,
                  from ./arch/powerpc/include/asm/uaccess.h:8,
                  from ./include/linux/uaccess.h:12,
                  from ./include/linux/sched/task.h:13,
                  from ./include/linux/sched/signal.h:9,
                  from ./include/linux/rcuwait.h:6,
                  from ./include/linux/percpu-rwsem.h:7,
                  from ./include/linux/fs.h:34,
                  from ./include/linux/compat.h:17,
                  from arch/powerpc/kernel/asm-offsets.c:12:
./arch/powerpc/include/asm/kasan.h:70:2: error: #endif without #if
  #endif
   ^~~~~
In file included from ./include/linux/kasan.h:21,
                  from ./include/linux/slab.h:260,
                  from ./include/linux/fs.h:46,
                  from ./include/linux/compat.h:17,
                  from arch/powerpc/kernel/asm-offsets.c:12:
./arch/powerpc/include/asm/kasan.h:70:2: error: #endif without #if
  #endif
   ^~~~~
make[2]: *** [scripts/Makefile.build:182:=20
arch/powerpc/kernel/asm-offsets.s] Error 1


> -#ifdef CONFIG_PPC_BOOK3S_64
> -DECLARE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> -
> -static __always_inline bool kasan_arch_is_ready(void)
> -{
> -	if (static_branch_likely(&powerpc_kasan_enabled_key))
> -		return true;
> -	return false;
> -}
> -
> -#define kasan_arch_is_ready kasan_arch_is_ready
> -#endif
> -
>   void kasan_early_init(void);
>   void kasan_mmu_init(void);
>   void kasan_init(void);
> diff --git a/arch/powerpc/mm/kasan/init_book3s_64.c b/arch/powerpc/mm/kas=
an/init_book3s_64.c
> index 7d959544c07..dcafa641804 100644
> --- a/arch/powerpc/mm/kasan/init_book3s_64.c
> +++ b/arch/powerpc/mm/kasan/init_book3s_64.c
> @@ -19,8 +19,6 @@
>   #include <linux/memblock.h>
>   #include <asm/pgalloc.h>
>  =20
> -DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
> -
>   static void __init kasan_init_phys_region(void *start, void *end)
>   {
>   	unsigned long k_start, k_end, k_cur;
> @@ -92,11 +90,9 @@ void __init kasan_init(void)
>   	 */
>   	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
>  =20
> -	static_branch_inc(&powerpc_kasan_enabled_key);
> -
>   	/* Enable error messages */
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KASAN init done\n");
> +	kasan_init_generic();
>   }
>  =20
>   void __init kasan_early_init(void) { }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3=
b6ff3a9-6b88-4a28-a0fd-31f31ae3e84b%40csgroup.eu.
