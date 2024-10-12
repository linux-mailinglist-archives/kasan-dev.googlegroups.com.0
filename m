Return-Path: <kasan-dev+bncBAABBWVYU64AMGQEXJHS2II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id DB6D699B00E
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 04:18:04 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d9443c01a7336-20c8a799e8dsf22304465ad.2
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 19:18:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728699483; cv=pass;
        d=google.com; s=arc-20240605;
        b=LdJoFyfz3CuamDymALyT6HCNzk2Aal6HKSBRpGKp+Yc5hHqZUKHfJvOK+WjX96BvcL
         hXardPK0TQXQFYVZrnxAIEqCPa49NwNqm/i+JHHz80ZoMXoIyB5emQNxwp+fK4Cl4kol
         oWowjMIvpfKg477DaB9vqWGn+E1frFEh73KY2sZ3+64fOmDI5Yb9pGs/4tfN7wDcX+Dv
         6OOvC6MEWDGohzZ5FBpng9EnIHVV/9eh0Jw16qHoUYSa9wcXHJ85PCjY8ZySFyYcajaM
         vGACgxcP3bYoJTIv5IZVxC9meVTtYfuUgpiq2GwYKVMj5sUTjgM1D4cF/j9NPE53XeWb
         p+5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xYm02oZrOLTz9FNeEPT8kl6sbPUHHC/tt3jzDRBGT0g=;
        fh=pQjMA/a2S6jETXrhOdeUMDw5Jxg3N/2FHwoZG6ZmWRU=;
        b=grQbbu4+WbCH0LYt4ptpp57Am+e0oyMvtIGl8pyDtIF8xxtG8dHsAQWfgO0SiJPOac
         it7+DiRG0OYBpXiarsIcxdIe8dAImNhWLks++QjlXQqnHUVE7fQU/58ZsftsB6FVYPRN
         xEhINW7hMiGHUTQNg6x5FcMSLHxRKMfCPxFkgHFIokIdTH9dKnc0w366cbS1Uw1LFfB5
         3lC9KjsvWI6Ua4AZmess8B6H1qrKi+OQEljKIF+lmjgqWuHEzGx80qyaYjHG1mXPHPOG
         dnkY8UqahVlZO6Q82qDbYTspQ3rygCjKNCQZaPgNfQ2seCjSbxgGRaWJQz6i8nRTnApz
         pfQw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=h+CAB8VO;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728699483; x=1729304283; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xYm02oZrOLTz9FNeEPT8kl6sbPUHHC/tt3jzDRBGT0g=;
        b=ogob+y1YOI7+aQ1w2vyt/g8pwoFRxKd/VY7Ifb1XIHU3Z7306hpzEQzxeR9m1oh17A
         8JkVAOhCcn3K/+rGF7sqpRK3x+5WuDOo6iNTL8NQCl/Ze7JHb9kXA4Jl9r/eLU/Xu+18
         BYv7uD3/UZJTMzy5API+we3sq9XLmCaoOTstvH8+K6/NyWYqzHOVJ9UQ/I+BIHoQ3Vnw
         s/d/i30S4jtJMeWUQeiFWiU5pL1SqyNZx1XfnELYODVPXeUNJGjnZQ/kwzjbrOeVfpkG
         56SvSwm+H3q1MdoXLNLbYZ22lYlvl8Ia/thbn9FernUkCksOgSBP44vM4m7Z7s/tU/sy
         suFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728699483; x=1729304283;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xYm02oZrOLTz9FNeEPT8kl6sbPUHHC/tt3jzDRBGT0g=;
        b=e1baBe3yNv+9KvgVt9QIWK7Z37NXEHm2Nfkslf+oksEFUxkyBlj4FQqodkPF4Lz+DC
         0gZkhpLN88daqqt6WVtmQAJ2J3RkllnONWK6YbmQKVSjr3qsdYtohRB4HSGvPFdYYgq9
         B8D4UUTl6vOKXVB9oWuk8DiaTJmutaY2EiAaHnwFNDLKMYpMX9w3ZSt2BLwftfW9OHDr
         oj6d3Vw/eULtm4kzB/WctYClSec8E+Yq9aVZdDXPVLjeIRNzpRW9B+vruqh4wcxWxloQ
         rgUgdJKaaU2aqEX7AgQmN/56qdCFiuW3Ybz4GeFN4ooVMO90xKSOcP0cFfKYz/uFQAKa
         WPdg==
X-Forwarded-Encrypted: i=2; AJvYcCVxDdlxcSwDXYtKOR7mYRgftbHi6Hsi/BaBYyVeo5kjNBW2ct80+XMu7Li9YIzvkhStuu2O0g==@lfdr.de
X-Gm-Message-State: AOJu0YytI2X0NtHgiydy1J7y3B7PUYJlYBWJVDqoNXF9B7E08Cq8pO2t
	mjzpEOjSPBUQpR2WuoMZMUCYxau3/M6j9wzBf5wHMXcgoYHgPDtW
X-Google-Smtp-Source: AGHT+IGiS2Mxh3f3O7H25REZ2gAQuToFa3SD0hYxRqwNKPTmMZ1PMq+bFYXJdj82ErJfM6eDUaQmcg==
X-Received: by 2002:a17:902:cec2:b0:20c:7485:891c with SMTP id d9443c01a7336-20cbb24ca76mr21273405ad.54.1728699482817;
        Fri, 11 Oct 2024 19:18:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ea03:b0:1f7:1d41:9224 with SMTP id
 d9443c01a7336-20c807a4970ls25792035ad.1.-pod-prod-05-us; Fri, 11 Oct 2024
 19:18:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWJ7yiCBsWuCrPjlgTzoRb3hTjo3eX86Rp03+P0NeJFzgVVXPJZ5ON14JduX7vZUMA8J+wgzzYdFac=@googlegroups.com
X-Received: by 2002:a17:90b:2387:b0:2e2:effb:618b with SMTP id 98e67ed59e1d1-2e3152c0683mr1980909a91.13.1728699481781;
        Fri, 11 Oct 2024 19:18:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728699481; cv=none;
        d=google.com; s=arc-20240605;
        b=Ap2TtChIBK7Z9uoibo61S+JXQ38jWEBGklW67Zzxbx/d43xMcZG5WFqLa5Ll5QgepE
         UUCS2TkmRY0mq4W2XGTfgUOzEJQlq/ColtVbkk4h33dhal6DUQn2fjaVtNY09vup9O7C
         8NVxGRaCMl6lZ3S0aqKqQ3HMtQYCOCAoj2ZuBgprSKmD7+MFol7ZRqOcBklZfO6GDLby
         pYf0buuPdYGcFEB7/M124JIal5IEYRp6qsGqXyOoQSBlyqIiF69ZG1oxw5FNqnwIvHQC
         xfIVw74gZ9JnSvmVpl5mRWvOHHyHSNxbW8kUXx4Am3hpWk8MhTEC64ia1dLgTQVAjOve
         yYtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=pqJ/AERVmK6K4aQ02OIzrFrKz5TUyCtyl4z64EExDH0=;
        fh=PxyFEJ3lVv58OoecC7f5K9DzN2uunkx0mEbwoyoCXJo=;
        b=BW493Vf1krovyfH7Jz3a2TPTnV92CWh+r9eIsYRzT85+4XVNhpuKHjgpkBfquvihKm
         S4DBasqccgwxCvFEEhYi9IfvDnEX7o/l5nyS75IC+Gcy+Qq/d5IQefNtdCENg7DEEFqV
         Bsf/NQpwXndiO/Ug7SXDa1lsj5KW3NH/byTlR1NXZ2J2YyA63YyiMBGJ4M0p43gQFk/+
         T+koChS2cOfKwd5DkD2Hx3XEquqHca/8c+8IM1IVJhRO1d49OC6ouqGfpDOD/8BR4GsW
         rvcwwf3+H2HnQRtBP/f0IQ7AJ5TrPepxkSZrwu+HYJ/iPFVRQMbOZBEiYznP8HS3aqXk
         nlWA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=h+CAB8VO;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e2ca44a71dsi536148a91.0.2024.10.11.19.18.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 19:18:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 0F973A45372
	for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 02:17:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1B36EC4AF0D
	for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 02:18:00 +0000 (UTC)
Received: by mail-ej1-f43.google.com with SMTP id a640c23a62f3a-a9968114422so371226966b.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 19:18:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU6YDLtp7oNu68DswQDktHpQNrH9waWOj++oyB9PeFGmur3FcAWIOSVP/JxKlh8LjPFjlC3t7MRFC8=@googlegroups.com
X-Received: by 2002:a17:906:6a12:b0:a99:742c:5c7 with SMTP id
 a640c23a62f3a-a99b9305ed1mr326220766b.10.1728699478702; Fri, 11 Oct 2024
 19:17:58 -0700 (PDT)
MIME-Version: 1.0
References: <20241010035048.3422527-1-maobibo@loongson.cn> <20241010035048.3422527-3-maobibo@loongson.cn>
In-Reply-To: <20241010035048.3422527-3-maobibo@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 12 Oct 2024 10:17:46 +0800
X-Gmail-Original-Message-ID: <CAAhV-H6-m6PhD49X3UyHYhCggAruf=5g9zh=6FvNc5004Z5New@mail.gmail.com>
Message-ID: <CAAhV-H6-m6PhD49X3UyHYhCggAruf=5g9zh=6FvNc5004Z5New@mail.gmail.com>
Subject: Re: [PATCH 2/4] mm/sparse-vmemmap: set pte_init when vmemmap is created
To: Bibo Mao <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=h+CAB8VO;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 147.75.193.91 as
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

Hi, Bibo,

Just declare kernel_pte_init() in header file. Since this series is a
bugfix, we should merge it as soon as possible. The refactoring patch
can be sent after this series.

Huacai

On Thu, Oct 10, 2024 at 11:50=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> wro=
te:
>
> Like pmd_init(), a weak function kernel_pte_init() is added and it
> is only effective on LoongArch system. When pte table is created for
> vmemmap kernel space, function kernel_pte_init() is called here.
>
> It has no any effective on other architectures.
>
> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> ---
>  mm/sparse-vmemmap.c | 5 +++++
>  1 file changed, 5 insertions(+)
>
> diff --git a/mm/sparse-vmemmap.c b/mm/sparse-vmemmap.c
> index edcc7a6b0f6f..c0388b2e959d 100644
> --- a/mm/sparse-vmemmap.c
> +++ b/mm/sparse-vmemmap.c
> @@ -184,6 +184,10 @@ static void * __meminit vmemmap_alloc_block_zero(uns=
igned long size, int node)
>         return p;
>  }
>
> +void __weak __meminit kernel_pte_init(void *addr)
> +{
> +}
> +
>  pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, unsigned long addr, i=
nt node)
>  {
>         pmd_t *pmd =3D pmd_offset(pud, addr);
> @@ -191,6 +195,7 @@ pmd_t * __meminit vmemmap_pmd_populate(pud_t *pud, un=
signed long addr, int node)
>                 void *p =3D vmemmap_alloc_block_zero(PAGE_SIZE, node);
>                 if (!p)
>                         return NULL;
> +               kernel_pte_init(p);
>                 pmd_populate_kernel(&init_mm, pmd, p);
>         }
>         return pmd;
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H6-m6PhD49X3UyHYhCggAruf%3D5g9zh%3D6FvNc5004Z5New%40mail.gm=
ail.com.
