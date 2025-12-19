Return-Path: <kasan-dev+bncBAABBM7JSLFAMGQEHWOJPUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id D5AFCCCE3E8
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 03:13:08 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4ee04f4c632sf23220361cf.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 18:13:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766110387; cv=pass;
        d=google.com; s=arc-20240605;
        b=DFvIDkzfAmwdYPxLu7XpphhhX6bvju2VWOqbzv2jbtMcSlBCPSHcF46h82VxkrfaVa
         E8A83BUaECIS/CVl2PbjgNEq7AH9OSgqcfHHiCVKY1S3FuQLgYiiphj3rBWLokkLR6++
         1GklqHvS0p4BblTUW2/tFv/Guazg4VNDDcE8YWaP3W5jDUP5YRHgFdiPlXW2rJdOPv6A
         s5g20wlHzyMOfsKnh73HG7m3vXheEragUg3HracayUVULI/hj5qp5QVNaIa2bJ++DusK
         GzUaJnWzqOlrdmxw+26BIJEdrHQMCXyvRcdro4sCwLOClUZSevXvdHqgz7FFM01s61gE
         U48Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kW91rMiMG5cyIsCx2aMjXoi/lJchOFyeIF8yEHdAoi4=;
        fh=x6P7DGwTJm/oppljeIv6+hPxCDXGnApnSCnGG/JvZtI=;
        b=ca0fT731Rz0b1dRWC8am/Wcq7X+WmC9cFZOwp+KjrCLLXzuByC1XiDCVFohmpAHxyL
         U0B5pruHsZHDpFRngHbsmfdaIl9hbHK6o5+Ot1r4QsIOz2IQy/4ua1gQpGvbOMH5YwfC
         KUF5gAMtK3TK2bLgbzJvb5DhCkOFxrHgGHOLDy7aAtz12lP0hDDvVxNfpjSWCTUhbpvk
         phGFAXdDi96yuP0iCLVyK0uunYeN10vGod85go/t3TfCxgZ4mwnPBK/67P+Uzu5XzHjV
         esBfM9z9upGi1YN+tJWtiV5TqumXkNm/+GetoRmDtyNpHzgiRQiWnwA1f2WA5QBculTB
         wWBA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cYb2Em5K;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766110387; x=1766715187; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kW91rMiMG5cyIsCx2aMjXoi/lJchOFyeIF8yEHdAoi4=;
        b=OA6U/scnANz5qgH9Wpw9ew+6BPQClH9wP6daL+Bb6jM/2BvgADPf6ymTO0eTpXu7V0
         s53UILADkskaMFiHbxKL5azV3T2GBSakkWm+CO1C6O4KB9yy4eB59IRFjFqwbIvKFR9r
         uqqZYrku/DDWkWh56Q5WNrEqvzQ2P2W12Gh3cqjeWACeZtg2EYG0mGP9xIDd02ev/UI+
         i+OMl3tvFe50QAGcoZcpC9G4n9OD1NM9omAnywzW+4tusZPqy1uh4N6VvDY9A3NoGHlR
         9kqE7EIcsYRd7I8KZg21dzgHzU5fvmnqbXJvbPf80ktdRSu62Z3wTX9AdbDryejo7aKv
         eraQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766110387; x=1766715187;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kW91rMiMG5cyIsCx2aMjXoi/lJchOFyeIF8yEHdAoi4=;
        b=kzkIdL7Mm0dNjWm58jdVc+SxJ84nDUTS7NnbSNZZTJaGxhhiQC8CZ+pmFZOUUAMD7j
         SDCnoJwno1OTusOMi5nl9couTwM2AhDYto4/nNNacQWM9vDjMqYOLoDrxsUI2o6bI6ZJ
         veWhHW5rffyGITEQop6mDvBF0oKWJzyCTWBhDuhlA7xlOlYOLbl/2/J7CFcLYaC4j5+e
         uY8jw+MYI2EOPJUN1iowK8c8b2IX1sTNEiu36TTf39Odp5kfwWP3DOZeCgWzKxMUGHia
         Z0i2SkaMdZIQuoaZK1vohFq2Ti2/2rwcdMM8HI7uyDTet/0JVwmo4WJLlauZjjHjbCq6
         2t7Q==
X-Forwarded-Encrypted: i=2; AJvYcCUMGpBLJE/djo1u8+xlK9diM7pL6rC5AYOj4v2rRLwyHRWEEXXj7DFj4UefRMljqRIiwoK+dg==@lfdr.de
X-Gm-Message-State: AOJu0Yx7hdIsvN+cRJq91aGn0xNY3R37wJscEZHe0a3EvapgvLE3Fyy0
	qXU0q9cQlzxqQ/Z7gp8HuQLEtLGqv9d9XooVyVSvlN68ecJIGBAOlk2x
X-Google-Smtp-Source: AGHT+IHizJk0igFwJATKHD4eRUI3Br3FXWAsZEuUwpbxO/wDg8sgj+R+FG1cR54WOkaefS7K3FVTbw==
X-Received: by 2002:a05:622a:130e:b0:4ee:26bd:13fa with SMTP id d75a77b69052e-4f4abdd147bmr21605791cf.80.1766110387426;
        Thu, 18 Dec 2025 18:13:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZfOWuzgoey3ug55dMgn5XEzSy7JSyoYkyxlBPPjG5BDA=="
Received: by 2002:a05:6214:230b:b0:880:803b:bd47 with SMTP id
 6a1803df08f44-88a525bca84ls51873516d6.1.-pod-prod-05-us; Thu, 18 Dec 2025
 18:13:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUdjAkuGq0m6bE8fz0LEFXu2WlH3VqXCOzaROFUWtoCUiB1dhbCIJ5Bng2hhkAhxrrDmWamqUZ78aE=@googlegroups.com
X-Received: by 2002:a05:6122:3d03:b0:559:6723:628c with SMTP id 71dfb90a1353d-5615bee5a59mr546524e0c.16.1766110386756;
        Thu, 18 Dec 2025 18:13:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766110386; cv=none;
        d=google.com; s=arc-20240605;
        b=kMyynsD8EXKDVMOXxMbpT2mLnm8XsbsrUnb8Vik2Ngc4udPu+urjBAuugpGnlYg8vq
         5gWrshpz+fsIzhJNrnp7nO8GsbCnFlSwphe1ch4Tg4rHrUojURP985xBiSxeG//c4laz
         FKIwwYtCEzcaVyLN+RLkheWWlsRcRV6r+Sg1kXn02IN+Gu2qd5M2L1T4ofTw6CoAbCRk
         pLnuYJhyUKqHNsntCFDNYngqtWDED+8qYWgYkcci8fDuW7U6kBu1REPafItdjrMaV2zp
         pIXHjnUpNl5gBb9sCfyoFWZKZJ52DFQAX9917FMbZNKRDXhHLssmXNDsjK8b7VNacUqA
         RGYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EleYCXTllQ1Ksj0san+UXP+fimOICR25jVAXrgMxFYA=;
        fh=QpExXpzmDBDYAz0IvQU+pffSzD6J3l8QtIvnU4Pkcbg=;
        b=Y1N9g67ermTyxsq5xmIMYolNi23CS4t+db/a3u7hxtZPFN9pSrXMfLfVCfGump0EH+
         3EHQzpxFuUk3N0bsJ2HXo8d7qWJqg8QnW9VS+QJaJpsugP2zKWwpskACJ7duhsE/aauO
         606v3r9jlxG0Cmw9Dp+2PBopunuu9HYE6n/Noi8S9/py+Qp5gndJJ8098zkaCGqpyRU/
         0SyHZoYL7bcQDeJXRcFocV085gmqzyEEGYXQGOKUAwA++kGdZFnv543NTREy4JjbTjVm
         Z1ohMrPzVAXwAO1Wf/hCVZdUhNPPpHLheuKa+QWgExNMZpHUXi9Z5QqrQMPEFUkGvQWY
         OFrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=cYb2Em5K;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5615d225328si20554e0c.5.2025.12.18.18.13.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 18 Dec 2025 18:13:06 -0800 (PST)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id C78774442C
	for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 02:13:05 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9FA12C19423
	for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 02:13:05 +0000 (UTC)
Received: by mail-ej1-f42.google.com with SMTP id a640c23a62f3a-b7ffa421f1bso415945366b.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Dec 2025 18:13:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVgZQNAy/BCepC9BkiOEPNjHmefCNUQog8lycMGizMZ+MFJ7ExFFnyRwn1ibjqNuTgwG2I1sZbKEQo=@googlegroups.com
X-Received: by 2002:a17:907:7e85:b0:b3a:8070:e269 with SMTP id
 a640c23a62f3a-b8035649310mr195334766b.14.1766110384189; Thu, 18 Dec 2025
 18:13:04 -0800 (PST)
MIME-Version: 1.0
References: <20251218063916.1433615-1-yuanlinyu@honor.com> <20251218063916.1433615-2-yuanlinyu@honor.com>
In-Reply-To: <20251218063916.1433615-2-yuanlinyu@honor.com>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Dec 2025 10:13:15 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5n_3Ndk5yRm=S-9WktD9xivVF8-JLaycV8JB-pVuybbA@mail.gmail.com>
X-Gm-Features: AQt7F2qrv-imhdGopLt1MPfdTK-Ic-3FPg_HSxVXBdw9KIsFQZQLPR-6ZFBiyC4
Message-ID: <CAAhV-H5n_3Ndk5yRm=S-9WktD9xivVF8-JLaycV8JB-pVuybbA@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] LoongArch: kfence: avoid use CONFIG_KFENCE_NUM_OBJECTS
To: yuan linyu <yuanlinyu@honor.com>, Enze Li <lienze@kylinos.cn>
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	WANG Xuerui <kernel@xen0n.name>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	loongarch@lists.linux.dev, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=cYb2Em5K;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

Hi, Enze,

On Thu, Dec 18, 2025 at 2:39=E2=80=AFPM yuan linyu <yuanlinyu@honor.com> wr=
ote:
>
> use common kfence macro KFENCE_POOL_SIZE for KFENCE_AREA_SIZE definition
>
> Signed-off-by: yuan linyu <yuanlinyu@honor.com>
> ---
>  arch/loongarch/include/asm/pgtable.h | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index f41a648a3d9e..e9966c9f844f 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -10,6 +10,7 @@
>  #define _ASM_PGTABLE_H
>
>  #include <linux/compiler.h>
> +#include <linux/kfence.h>
>  #include <asm/addrspace.h>
>  #include <asm/asm.h>
>  #include <asm/page.h>
> @@ -96,7 +97,7 @@ extern unsigned long empty_zero_page[PAGE_SIZE / sizeof=
(unsigned long)];
>  #define MODULES_END    (MODULES_VADDR + SZ_256M)
>
>  #ifdef CONFIG_KFENCE
> -#define KFENCE_AREA_SIZE       (((CONFIG_KFENCE_NUM_OBJECTS + 1) * 2 + 2=
) * PAGE_SIZE)
> +#define KFENCE_AREA_SIZE       (KFENCE_POOL_SIZE + (2 * PAGE_SIZE))
Can you remember why you didn't use KFENCE_POOL_SIZE at the first place?

Huacai

>  #else
>  #define KFENCE_AREA_SIZE       0
>  #endif
> --
> 2.25.1
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AAhV-H5n_3Ndk5yRm%3DS-9WktD9xivVF8-JLaycV8JB-pVuybbA%40mail.gmail.com.
