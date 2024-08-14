Return-Path: <kasan-dev+bncBDW2JDUY5AORB6NK6O2QMGQEDTOWUEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 34AB6951F5A
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:04:11 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2f01a8b90b6sf614671fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:04:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723651450; cv=pass;
        d=google.com; s=arc-20160816;
        b=zhLvouudBqIRj/uAxGNtFWpDRWEESXTvokoF5GX3RDkYFZEPpXF/ccylgV3lt4PBC9
         LkloZlPQI4VulY1VzcBlKaQ3tj5bT3Wzshio9Cg6K+0NtcpHrF6LvfH/L0qthqgZnQyN
         GqCr1zSNw6IQGqmOFiJi6JvwWoGxUsq8TeSG/xztFsiC+eYIBWgAvkOr1/08fAP5Kdyj
         MJ32n9fuk8vIr3+MGe0I32dAu4nXmeK4A6LHbnklTgpXRImpiS7YllUOys1YkJFlBkwO
         EHpr92f201ittiKBbmkmAFEPDU0AHGHeS2h0o+VTfdx0Tq6VFbqHeBIZZ66L131tj5zj
         xnww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+Y2y6hZcXONtNs4YbZ43dqyQlRmc/lNd0uda08ZxAds=;
        fh=60TDUEiXb4O3ZQF95e3WWMXRghyeHX6SY1YBWOkmg1k=;
        b=JcT4jYz1k3CaFSchd9BeKdtE4jfLKSAfThg6acMXnIj+4SkjgWYRiemVDMJlpbRxSQ
         zHCYA7b5OqqfzflFfossEPZa9zYuOvaM914GIfSBcVQn10Cf3/2nQV2LFtFYTiRva0BW
         8o8nJFOyhob70HVk6zdgSveAD3Lf8FkJ3DPuIpuBwZw6O74M1bvRAucBWwu4OuqecRae
         C24z4+y8HX9O1EpHH99nyY6syw0xGEjFgn3JN3VIkll2S0rkP9Z5F3dHuE/LBSc34DaQ
         seMfSHYz/GhxWpfDyLDJBPTy1CP6xLpTBPQxSpVSPoxMKHsBxjxJIxsUqS9iGZE0KgZ2
         nAkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cPP7MyCb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723651450; x=1724256250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+Y2y6hZcXONtNs4YbZ43dqyQlRmc/lNd0uda08ZxAds=;
        b=nW53ipj6/BsSGNvp6agcgkpbLrH8BqT7rGQaf89ySMwEUgjJfN3Iz0LsBCnlVyVoZ9
         beBmEZUpGvPGERZ37V/osmFejVjPvliaV5fVyiBZVd9bjMMfaAmTD/sap4y2poH+ErOg
         hfKazMkPg1gqSM6e5XrFQKKOKjlLbV8cYkP4gn9j25mLm2639SpXQoiLeqh4NVRTUkNV
         HCiwRBCMkXc3ekDNFs+9+IpUBdaFq0kJ85ByY6m5DN4ueqmNw3Br3JUzwBcFsAEEYA4M
         2ZGsZTcUQSRhGjoLpFENpKLYQnX2Qtnu02J9RPk9aRkgnnzBmtpMLSFEnaziEn/jJO02
         SW4Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723651450; x=1724256250; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+Y2y6hZcXONtNs4YbZ43dqyQlRmc/lNd0uda08ZxAds=;
        b=A0eDDd4E6Qx6PPGRBgeM2XULf/nHjXRiGafioZF8DLyvAFfE1+pAi+Mwl1onsAJ0vT
         xAsPddekpDFfMYR2Bm3mZ+TxO7cnw8cEUN2VVspfI+g3JUJK8jkY0VX0pyUCjoftFcsL
         7jOAHp0togsnUtXi4rWjTm/OVFNSFe/tKaH3JLDJpZ90Ja3Q62BWjDsqgP9RJ41LsvyV
         zZjQzk74AaFUryRZ8hP6aD/4fz5eWCPW87A8UTGB0UjW14DMMh/YI1qWqsfBQa6+slP3
         eyLCjfejeRPUAeirG+0ftU49HsnvL/0L2U7sm2jgN5gQoLcrh3hmSz4vbHlaVquLdrkr
         OpHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723651450; x=1724256250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+Y2y6hZcXONtNs4YbZ43dqyQlRmc/lNd0uda08ZxAds=;
        b=P6Ua1o4aUyyEP1AbT7Ymb0ZrnkP1MRQ+8NE6LZX3O1qpiGcLj7YFrMRc+UwwxcPble
         9V+FC3s6QivCG28iAvccrYgwMT43/P4Cg6y6PgzR0q+V6XIlcypkFh1hLZTUBGbzezg+
         hhN35pOH/DmVpzQpv8adF+NoQE+/lhPcPeBROtj+02VlIyO/LlyN3LwXgIqAmLay9BDk
         0S3jpJ1ziTYdbRL8Eyd+icLAfIbekNAsPcsjaAxDY/YLtP6222dsDI3LPELJyyrT5c4T
         SPElNUlQr4kbQo99bK7jfQW+ZXSqVhw4WZDDXuUNpImOzJkQHQWTWNG7g3+QSoJ5U6Rn
         8Ufw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVD1vMCX0VUeF3NWUgX95BGCNJoF4sgy3bCHCcmBTFSJMsIT+0XCky24MwdBvjJjIgEUKCvAw==@lfdr.de
X-Gm-Message-State: AOJu0YwqVoPwYq9RyvumIyVua2VXwauyh+rdXeTQg3//0QFEjsi1ws8j
	kD0tFY8471JT6GhT7ogiHI2WHe2eIwNfPl5yiCvV9g4M4JtQpcYR
X-Google-Smtp-Source: AGHT+IHrLGpqT67ceNP5XbHGZY5NqTS8qHU899nWC31EDh3WMshY1Xw9BIa75meCPsaIO2KH/Koxww==
X-Received: by 2002:a2e:801:0:b0:2ef:226e:e150 with SMTP id 38308e7fff4ca-2f3aa2fc40cmr19453271fa.32.1723651449435;
        Wed, 14 Aug 2024 09:04:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a85:0:b0:2ef:1eb3:4749 with SMTP id 38308e7fff4ca-2f3b358456dls611551fa.0.-pod-prod-05-eu;
 Wed, 14 Aug 2024 09:04:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUpZ1otgOWIb8K5uKIzrcpEwFwuALr+0i0BqY9O9YSpLiSubea/dzpHmRwTQerTYbVK1viabztFB3Q=@googlegroups.com
X-Received: by 2002:a05:651c:11d1:b0:2ef:23af:f202 with SMTP id 38308e7fff4ca-2f3aa3014d8mr24409591fa.46.1723651446803;
        Wed, 14 Aug 2024 09:04:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723651446; cv=none;
        d=google.com; s=arc-20160816;
        b=pmud9c/AW9kYcspflQa/4o/xpeALXECPwsw1JGhgcYUJ5yUBkohumMWbUFrDJf+mGU
         n76WIZ/GfiGALWAJ5gRAJ2ZWHOOdkrAW29SlnicznynFThbpNdCd5bh6bW5HZHUJ6reo
         UYQ1UvCOZguIHe74oWEcw5Agcoy0J3Mx+4i2VSKrwbOjz2vRDOfwWL9OD6Ib8m91oxRo
         WAtUwvoLoKhLwBF0LXz3FPGmWhF/tBObwSlylwa9Hgi5ZrZCj6CUQ5DhjH7cHKspFSOL
         8DzpVlAhUkHlURAldfoNwJ6n7l6HFE9GE3OVddlXAJUmRBrikKtA7gNWlM70xfGdQ6Rm
         h/JQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xsVwGbt3gTQjJ2udr1fi33WHUjrTh7/T/FVKigzrowA=;
        fh=/rzzeiLx2+8Xxxasy9YP7CLW2372LqzCK3b/u+MH/j4=;
        b=sls6NY5wO693Ri1nVcZWVJHTT5imvmdVxjarbwIpd5bH+f6xfv/vxTK1bNdrGwF3Ru
         io3zrhzRlXodOipKXUyLzn0SWK+coUJYWQMRY5sulrYHaUC/Pmc68M8yvByRIL3JE3KW
         5VxHczSffhibsPemwYLNiE4QBNeiBRTMEdMoPRuPHyKam0ZDCPqzrkUOQ1tcRgDQ/qj/
         p6qrVkjkYZtWXrkVl0B8VIcqv7NRBIpAF1itmp64+TTmWB/LBirlLu56wAHOOcpFgi+D
         xXHsLT4yp0+fZ2t1500QSAGrHV1FvHC/I40EhWtpVJPYOW6ZkKQQc2eJUIdUvUVAXZ6i
         oxpQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cPP7MyCb;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f29203da18si2086041fa.4.2024.08.14.09.04.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:04:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-3687ea0521cso48079f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 09:04:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWLOX5ANUqnKb8OiVIJXYuaq0G0tKKABhRd6u6xfkhaJK4g316O8R+ceWwFE4nh0NQpm7RNyRZha6k=@googlegroups.com
X-Received: by 2002:adf:cc09:0:b0:36b:d3eb:17a5 with SMTP id
 ffacd0b85a97d-3717778d7cfmr2725194f8f.36.1723651445910; Wed, 14 Aug 2024
 09:04:05 -0700 (PDT)
MIME-Version: 1.0
References: <20240814085618.968833-1-samuel.holland@sifive.com> <20240814085618.968833-4-samuel.holland@sifive.com>
In-Reply-To: <20240814085618.968833-4-samuel.holland@sifive.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Aug 2024 18:03:54 +0200
Message-ID: <CA+fCnZf3U9u1dHBjecT=ZMYHp0OKv00HwObDcpAFwGXF58Vedg@mail.gmail.com>
Subject: Re: [RFC PATCH 3/7] kasan: sw_tags: Support tag widths less than 8 bits
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Alexandre Ghiti <alexghiti@rivosinc.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cPP7MyCb;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Aug 14, 2024 at 10:56=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> Allow architectures to override KASAN_TAG_KERNEL in asm/kasan.h. This
> is needed on RISC-V, which supports 57-bit virtual addresses and 7-bit
> pointer tags. For consistency, move the arm64 MTE definition of
> KASAN_TAG_MIN to asm/kasan.h, since it is also architecture-dependent;
> RISC-V's equivalent extension is expected to support 7-bit hardware
> memory tags.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
>  arch/arm64/include/asm/kasan.h   |  6 ++++--
>  arch/arm64/include/asm/uaccess.h |  1 +
>  include/linux/kasan-tags.h       | 13 ++++++++-----
>  3 files changed, 13 insertions(+), 7 deletions(-)
>
> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasa=
n.h
> index e1b57c13f8a4..4ab419df8b93 100644
> --- a/arch/arm64/include/asm/kasan.h
> +++ b/arch/arm64/include/asm/kasan.h
> @@ -6,8 +6,10 @@
>
>  #include <linux/linkage.h>
>  #include <asm/memory.h>
> -#include <asm/mte-kasan.h>
> -#include <asm/pgtable-types.h>
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define KASAN_TAG_MIN                  0xF0 /* minimum value for random =
tags */
> +#endif
>
>  #define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
>  #define arch_kasan_reset_tag(addr)     __tag_reset(addr)
> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/ua=
ccess.h
> index 28f665e0975a..56a09f412272 100644
> --- a/arch/arm64/include/asm/uaccess.h
> +++ b/arch/arm64/include/asm/uaccess.h
> @@ -22,6 +22,7 @@
>  #include <asm/cpufeature.h>
>  #include <asm/mmu.h>
>  #include <asm/mte.h>
> +#include <asm/mte-kasan.h>
>  #include <asm/ptrace.h>
>  #include <asm/memory.h>
>  #include <asm/extable.h>
> diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
> index 4f85f562512c..e07c896f95d3 100644
> --- a/include/linux/kasan-tags.h
> +++ b/include/linux/kasan-tags.h
> @@ -2,13 +2,16 @@
>  #ifndef _LINUX_KASAN_TAGS_H
>  #define _LINUX_KASAN_TAGS_H
>
> +#include <asm/kasan.h>
> +
> +#ifndef KASAN_TAG_KERNEL
>  #define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
> -#define KASAN_TAG_INVALID      0xFE /* inaccessible memory tag */
> -#define KASAN_TAG_MAX          0xFD /* maximum value for random tags */
> +#endif
> +
> +#define KASAN_TAG_INVALID      (KASAN_TAG_KERNEL - 1) /* inaccessible me=
mory tag */
> +#define KASAN_TAG_MAX          (KASAN_TAG_KERNEL - 2) /* maximum value f=
or random tags */
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -#define KASAN_TAG_MIN          0xF0 /* minimum value for random tags */
> -#else
> +#ifndef KASAN_TAG_MIN
>  #define KASAN_TAG_MIN          0x00 /* minimum value for random tags */
>  #endif
>
> --
> 2.45.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf3U9u1dHBjecT%3DZMYHp0OKv00HwObDcpAFwGXF58Vedg%40mail.gm=
ail.com.
