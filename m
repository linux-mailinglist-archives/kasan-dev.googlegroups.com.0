Return-Path: <kasan-dev+bncBDLKPY4HVQKBBFUM23CAMGQEEMMVLTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id DCEB4B1E189
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Aug 2025 07:07:36 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-55b91d6fecbsf892996e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 22:07:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754629656; cv=pass;
        d=google.com; s=arc-20240605;
        b=DGqaDDhdfSGOeOgWuyBybpPjMemDT/y1wR93VeyVvhs8ymG6LrOFjWOvtZbajx3gb7
         CvVtlgl98R06NDQcQ25fs2MYhu7wdA3bsaAOCzLr8D4QCNQkBYUDoTnbygQetxMgVrG/
         oWUwhXL292nTTlLhFzIUsuyJ0xdx5Hs/bRcZcmaDn1aU5uQf6y0VNL6iIwrBUGqA2g/C
         6ZZ2Z4KxH7XzyqiPLzOkS0uPgC2mCnuFUBstOk9mIjs8+jHeynAX/0oHDVahlfKQ3SjA
         2yNb5ZiwAgpA2UPIpGEOcPk4MQBp2aeo8qY6qeHXRE0D+SShVbvVLKsKT6BbQMsbndwm
         lDOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:content-language:from:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=p0rrP33UadP82gxBfGAtTsz1KoJxOHahZAb1u3LA7lo=;
        fh=uTAC5l8ip2byco4t9WoUtnz69e42vWgFmN7a9bHllPE=;
        b=KeIftpKffV0ugT6qf6HYZax3iguJYICF1yKHDmh9okvWS24GWzub5TpAXS0KKHcbti
         d0XHoWLIkPkmG7zxGcBPr0q7WorumWzkerlfWUGQNcF6umhe7JUUhTd5m1TAcvRSy5V9
         Wmego1r9pc8TSvWfoufuZr0RvyCNYcN6IfrfI7uZPKdYSc5Xx6ehbaeHmRveMjLufZUH
         Hp8yacT6/g4FilfA5pbeV4O8TAPghBG1kyLk153b2xnqfD3c8jvmg8tRBGWvJxwQQcWS
         fN/qUHhptouopUWmkKcMFklURUac2v9UtJdwmo0aQT5CxK5hUJb4gimkt0/bQkPDyMjx
         5eQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754629656; x=1755234456; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=p0rrP33UadP82gxBfGAtTsz1KoJxOHahZAb1u3LA7lo=;
        b=KEtKJ3n+q5xIbHOGxDRoJWSQCdJuw7Djbg/D5qDT4SZB91k44/9HOTJHN5fOCMgqj5
         8t+S52MoB1XBTir3QUI+xqbOI3RV8nFxXosagqkVq8II6wkYqSxJQObk1jtdNArj9gzd
         yT3x4Kb2wY6dmDtXOMs+LvU/jGYBzBLvWJNCMfEw2crNDMWdLtIi4nbNK3uuFhP/MsiU
         WL7G/gXiIXEvquN5nEcaw5Rtr3N0tH//5p0HbGB6wAcZJx2o4/1pauPB02sP/+Nt/sp4
         qZfVSwksfu59gzXhEr2NbMP6YgEuJXfw7pvxaPXxzMMbrtrYljaqtpFA49Kwa21WzHND
         eKUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754629656; x=1755234456;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=p0rrP33UadP82gxBfGAtTsz1KoJxOHahZAb1u3LA7lo=;
        b=KUwijQbfe0Qlxi71nokPa3Cxulvt96LPLKkKhvCPpuHd0tDkEpFlTdLVOQTizbGyoo
         dNHaAvnAJRZMLD+h88xiyFRMxVmhrq6xScrr3p0ftyOj5ajnfA9ovM2d+fT9n+QvCe9w
         fFgdZ2oD1dQEZxS2yhgzhhwd47Xobm0U+ZThCwbFYNbENwF/eq4YTmli/lvl9hc6XHTl
         kn/JtZI/ctO6Hncj/ue+pKdOBhfhoMiCVH47hkEJb3fvPNodaaEw1ccGxgCvt2cIoDFL
         WRuRH8itBhqaIjuPTiAiNOJ8xoBbuxrlViQFdo/lutabFXU/g30rNv9817s3+wsdCCGI
         IHQw==
X-Forwarded-Encrypted: i=2; AJvYcCXUcJV5lyvTa2T9gucHzJCHnEDS0KrkjctauBQVZqnMmPSuk/7tH4XagYZfYTtucU0h6jc+6A==@lfdr.de
X-Gm-Message-State: AOJu0Yy+LLHhlW51QQvMsW6chxC+v+mhBCKJZlZyUb+Y7hzABMp7xBfw
	3IqPxoGVbis6lPeEQ6eZ8TlQFKkoAKWEXCm6fbGNi/KMyL/nZIJuBjbZ
X-Google-Smtp-Source: AGHT+IHER+pRx9UPFMZyYdkQMM93bZ3Cs3LymU9Bk+jwVshx4VtnPqFA8ILivJNqvEKx/lQOZyJvqw==
X-Received: by 2002:a05:6512:15a0:b0:553:a4a8:b860 with SMTP id 2adb3069b0e04-55cbffb7ae9mr374264e87.0.1754629655265;
        Thu, 07 Aug 2025 22:07:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZejcadgeLOY1sc37KLc1+RMBfEHoN+SSL5X5/VL1hZt1A==
Received: by 2002:a05:6512:238a:b0:55b:9f78:10f1 with SMTP id
 2adb3069b0e04-55cb627a813ls430203e87.2.-pod-prod-07-eu; Thu, 07 Aug 2025
 22:07:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXImcIFxQqPU9HMA7A64l1vc2KzqQsKnuOYbm820ubTjadzSpKLVtNBv1Zw7FLjtuOdzKGLt7XTlk=@googlegroups.com
X-Received: by 2002:a05:651c:2115:b0:32c:a097:4140 with SMTP id 38308e7fff4ca-333a1f8290amr3361521fa.0.1754629651901;
        Thu, 07 Aug 2025 22:07:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754629651; cv=none;
        d=google.com; s=arc-20240605;
        b=co1EAwCtuXuJ9tdB8atAfP4+GV0K6qaS/n9ZwOw5/UdS+ApLtAHjqgKiHrXXTF8T9l
         /U1rjPnycFcSs7wUFrh0tH8Fb9yEjw7dt1gkXbjalL5odK9fIHQAJdn8YbQYvdm9VG1l
         Kl2UA6E3V/MOapg3l4hnaOQPrvjjuRghX4eoZl2/12qwYBRqO/Mcx60v9xBXI5wj9glx
         oLUFJWiFOBASXVMetyA/9R6puc3aaKMxPxu71MLq9Gi6UwhBlnZ1S7NSrKsilAJkf0EY
         txUb5atJYS5F9xHzeSNJ/5qK0UCcZLtAOr6j2DsZnwhXtIE/8Sd9H/YMxrLoJ/bdPO/n
         TbZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:content-language:from
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=PR3mXTvm1TEbk8uyyZeqYNJCeZ39LQ5LRG5oWb2m4C0=;
        fh=QOieM/HTo4FZqT+Rm2svox33NTijEtnKnbxUSZqxjg0=;
        b=UlVjft7PPzV7E4pMJLTWJITGGglDE7Fk/tW+iyX1dj6gTuFIDBp6fO2ZqrS3+YoioN
         5DZ3xZJ+UAng6yEwcAzai0j55h0feqHmaCo4g8x2+Xbre/a/327hiVhtZBAEoDZX3QQ4
         1BMxbXpfq8vSl+U7m/jRuF63A86DV0+O+cyFsmTpo0AamMoB+DVP2UlM/E6jSeIzwa0R
         Q+r6SaIbdfDKiifiGRuegvbfeq29SkVpnwtUIb6xWUE+jjKT+Hbw3Ox7Fm/JtZ71O+fd
         noQ5SbgWqb39X5mdRJIOWxIDwMdx4aEtCwuDPat5JrOu8KWQG4juzP4eBS9VPz4koqMG
         kYQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) smtp.mailfrom=christophe.leroy@csgroup.eu;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=csgroup.eu
Received: from pegase2.c-s.fr (pegase2.c-s.fr. [93.17.235.10])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-33237d50039si5369291fa.0.2025.08.07.22.07.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 07 Aug 2025 22:07:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as permitted sender) client-ip=93.17.235.10;
Received: from localhost (mailhub4.si.c-s.fr [172.26.127.67])
	by localhost (Postfix) with ESMTP id 4bysTv1SGvz9sRs;
	Fri,  8 Aug 2025 07:07:31 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from pegase2.c-s.fr ([172.26.127.65])
	by localhost (pegase2.c-s.fr [127.0.0.1]) (amavisd-new, port 10024)
	with ESMTP id 136VSEc6Znrg; Fri,  8 Aug 2025 07:07:31 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase2.c-s.fr (Postfix) with ESMTP id 4bysTv0NP1z9sRk;
	Fri,  8 Aug 2025 07:07:31 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E9F118B770;
	Fri,  8 Aug 2025 07:07:30 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id ibwVE1n70MLp; Fri,  8 Aug 2025 07:07:30 +0200 (CEST)
Received: from [192.168.235.99] (unknown [192.168.235.99])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id E61968B763;
	Fri,  8 Aug 2025 07:07:28 +0200 (CEST)
Message-ID: <07ffb27c-3416-43c9-a50a-164a76e5ab60@csgroup.eu>
Date: Fri, 8 Aug 2025 07:07:28 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 2/2] kasan: call kasan_init_generic in kasan_init
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, ryabinin.a.a@gmail.com,
 bhe@redhat.com, hca@linux.ibm.com, andreyknvl@gmail.com,
 akpm@linux-foundation.org, zhangqing@loongson.cn, chenhuacai@loongson.cn,
 davidgow@google.co, glider@google.com, dvyukov@google.com
Cc: alex@ghiti.fr, agordeev@linux.ibm.com, vincenzo.frascino@arm.com,
 elver@google.com, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 loongarch@lists.linux.dev, linuxppc-dev@lists.ozlabs.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-um@lists.infradead.org, linux-mm@kvack.org,
 Alexandre Ghiti <alexghiti@rivosinc.com>
References: <20250807194012.631367-1-snovitoll@gmail.com>
 <20250807194012.631367-3-snovitoll@gmail.com>
From: "'Christophe Leroy' via kasan-dev" <kasan-dev@googlegroups.com>
Content-Language: fr-FR
In-Reply-To: <20250807194012.631367-3-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@csgroup.eu
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of christophe.leroy@csgroup.eu designates 93.17.235.10 as
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



Le 07/08/2025 =C3=A0 21:40, Sabyrzhan Tasbolatov a =C3=A9crit=C2=A0:
> Call kasan_init_generic() which handles Generic KASAN initialization.
> For architectures that do not select ARCH_DEFER_KASAN,
> this will be a no-op for the runtime flag but will
> print the initialization banner.
>=20
> For SW_TAGS and HW_TAGS modes, their respective init functions will
> handle the flag enabling, if they are enabled/implemented.
>=20
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D217049
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> Tested-by: Alexandre Ghiti <alexghiti@rivosinc.com> # riscv
> Acked-by: Alexander Gordeev <agordeev@linux.ibm.com> # s390
> ---
> Changes in v5:
> - Unified arch patches into a single one, where we just call
> 	kasan_init_generic()
> - Added Tested-by tag for riscv (tested the same change in v4)
> - Added Acked-by tag for s390 (tested the same change in v4)
> ---
>   arch/arm/mm/kasan_init.c    | 2 +-
>   arch/arm64/mm/kasan_init.c  | 4 +---
>   arch/riscv/mm/kasan_init.c  | 1 +
>   arch/s390/kernel/early.c    | 3 ++-
>   arch/x86/mm/kasan_init_64.c | 2 +-
>   arch/xtensa/mm/kasan_init.c | 2 +-
>   6 files changed, 7 insertions(+), 7 deletions(-)
>=20
> diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
> index 111d4f70313..c6625e808bf 100644
> --- a/arch/arm/mm/kasan_init.c
> +++ b/arch/arm/mm/kasan_init.c
> @@ -300,6 +300,6 @@ void __init kasan_init(void)
>   	local_flush_tlb_all();
>  =20
>   	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> -	pr_info("Kernel address sanitizer initialized\n");
>   	init_task.kasan_depth =3D 0;
> +	kasan_init_generic();
>   }
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index d541ce45dae..abeb81bf6eb 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -399,14 +399,12 @@ void __init kasan_init(void)
>   {
>   	kasan_init_shadow();
>   	kasan_init_depth();
> -#if defined(CONFIG_KASAN_GENERIC)
> +	kasan_init_generic();
>   	/*
>   	 * Generic KASAN is now fully initialized.
>   	 * Software and Hardware Tag-Based modes still require
>   	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
>   	 */
> -	pr_info("KernelAddressSanitizer initialized (generic)\n");
> -#endif
>   }
>  =20
>   #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 41c635d6aca..ba2709b1eec 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -530,6 +530,7 @@ void __init kasan_init(void)
>  =20
>   	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
>   	init_task.kasan_depth =3D 0;
> +	kasan_init_generic();

I understood KASAN is really ready to function only once the csr_write()=20
and local_flush_tlb_all() below are done. Shouldn't kasan_init_generic()=20
be called after it ?

>  =20
>   	csr_write(CSR_SATP, PFN_DOWN(__pa(swapper_pg_dir)) | satp_mode);
>   	local_flush_tlb_all();
> diff --git a/arch/s390/kernel/early.c b/arch/s390/kernel/early.c
> index 9adfbdd377d..544e5403dd9 100644
> --- a/arch/s390/kernel/early.c
> +++ b/arch/s390/kernel/early.c
> @@ -21,6 +21,7 @@
>   #include <linux/kernel.h>
>   #include <asm/asm-extable.h>
>   #include <linux/memblock.h>
> +#include <linux/kasan.h>
>   #include <asm/access-regs.h>
>   #include <asm/asm-offsets.h>
>   #include <asm/machine.h>
> @@ -65,7 +66,7 @@ static void __init kasan_early_init(void)
>   {
>   #ifdef CONFIG_KASAN
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	kasan_init_generic();
>   #endif
>   }
>  =20
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 0539efd0d21..998b6010d6d 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -451,5 +451,5 @@ void __init kasan_init(void)
>   	__flush_tlb_all();
>  =20
>   	init_task.kasan_depth =3D 0;
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	kasan_init_generic();
>   }
> diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
> index f39c4d83173..0524b9ed5e6 100644
> --- a/arch/xtensa/mm/kasan_init.c
> +++ b/arch/xtensa/mm/kasan_init.c
> @@ -94,5 +94,5 @@ void __init kasan_init(void)
>  =20
>   	/* At this point kasan is fully initialized. Enable error messages. */
>   	current->kasan_depth =3D 0;
> -	pr_info("KernelAddressSanitizer initialized\n");
> +	kasan_init_generic();
>   }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0=
7ffb27c-3416-43c9-a50a-164a76e5ab60%40csgroup.eu.
