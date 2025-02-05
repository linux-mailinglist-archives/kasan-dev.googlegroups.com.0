Return-Path: <kasan-dev+bncBDW2JDUY5AORBC7QR66QMGQEQOJL4QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 69B16A29DA5
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 00:45:17 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-302325e576bsf1177051fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 15:45:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738799116; cv=pass;
        d=google.com; s=arc-20240605;
        b=TFSH/UlYgvXLRtVEGeNeexKZUXXmYwRd5ZPPl6885pnFq9Ps7evHSKoeGCVaEYAYSy
         oIqH6SVbuphHRjalHpBPVWJ+nLnA7PjtAXLz4Od/rx7hnYYJYsL+4b39agCoMDgvsHKA
         iWEfzkWLwQPDgyRqyoJSEPJyZu54c3I2VyWfUlzwvEg6zPCLOLg4paHfu1gctu5YnHTK
         aY7Jy1X9QTLAzDZgUwnbUBzmeDJrfVsCg38yERby/R35rsW9qci0UWsljGRLyX26+iZg
         N00LOhtgwPgI7XJdVtLdxn3pirMKV8n3gg7hAGf+NRU77fndpHv+6qZPSlHXJT6JjR3+
         ySUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Fa1opskDHvBK1MoNqMzji5bXoqDtZZCdL2yI/zv5XJo=;
        fh=TS+rleLxjP6pGamp5TSfrNUqwupwuwim0cYcjLaifkE=;
        b=QMiKdLsViGn2eD75pnyMs2ILI7a8w1SWarctb/SFDErp0AkIv38zdljx3zM1YAm5Et
         FDAQopJmsTDEQs6l3qlGgWrKn9AfDRFiGraTPkOLyqaPq2N1bMGVqng7D9pBm5EDeB51
         BhfFCMZAZnbvm30wfrBVLsQxfRUgPvxUGxm9qfHvMyRudqCv5+GZgffcbzO+IVcLnDot
         wKIwxyJFOB/BE00gdKSryZX1JVV+lpKDTA7HO25DOksiChre3K0gIaTkbxV/1a3mar8S
         0Fg0FHmcpHrOffabd4cMPSEVeh31kcDStah1FM4cr7rfse2mxf14hquj/BAXab/v6PAe
         fsWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=J+mcBEoM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738799116; x=1739403916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Fa1opskDHvBK1MoNqMzji5bXoqDtZZCdL2yI/zv5XJo=;
        b=bdeQPfaci7X2F5xXKykvY38OXBfxrBuaEOhKcysR8aYn8dMiRT/PKRIKTL5bHK2saD
         PzpusO7QzJA6CGR/NnPoXZJau+2CPNXuVA+B6wI058723eaZFhUeyMBalcrKhyuUmPAu
         q01Rl5OKOLVeY7PVJzqsGYlAZcyp8LXhYc7squ1opPWtXT/EAaq8T4daFEN91GGs7ANu
         pFsBVtzc7fbQ50Pf2GUKcxo7jjqeUvDt2m0mwE1N4yXdc8KR3TywNgHaVIwpRtn7qs4G
         tJC2FxLdHRK8lqLc5s+o9Af0MArtWRcIMHPqMfGqSjSFKUPF16q1aJYk3BwkUMcvC5h4
         l/jw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738799116; x=1739403916; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Fa1opskDHvBK1MoNqMzji5bXoqDtZZCdL2yI/zv5XJo=;
        b=i1nX49cmyo5N0m95oU2uZe2Ytq4F7kzmpRGT4MQKaukOVmHVGLIpBOblCPSl1k5GGJ
         wOYpzC0ZEzER5nDDI8e16Dy1gPpTnPeEB9O5JIjJs96TOh8i5uTQd+AjaD3u9o9MXTgp
         8h2IhYsTBoqTEz2l/l7fV2Mbz98FajIZvEfEbMpwGLiI2fmcjBD61OHL/nYiZbhaTgLA
         bCt2jkiIRvHrZa90pVOyB//PPItiId2/R1F7tlRM3ule3XdgSNUdPPTbLEINLwqvRP9y
         0Shh9bZF4Zm1IltcmDg+5xQ9WfB2IWTeHkp6svCbLKeIfhDvOjJdJRuQiDMVBl6mM3Hh
         fHhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738799116; x=1739403916;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Fa1opskDHvBK1MoNqMzji5bXoqDtZZCdL2yI/zv5XJo=;
        b=W9v36UdGneTOjjfD8j1sCjQ7Xk0s7kPIsHsnJBnjHPsm8D2UIVLaVBo7C6hcRyS3dR
         7Asef9Tw4jUMwgtM94cVf2IGk+60d60STy7pi2o1RhZC1lILc6rwfIVhEMnLRm7y+GgW
         dYMQBOWtK8Lxqh/s4xyMtx/5XkJ8ZVhI5X3fW1a+QBe221DAiBd9bWHxl39hIuHJ5puc
         w6fIA9aci5RlqEregVfWtlMxiEakXDjhtk7TPPTvapk3SjWlzrwqpNSKo/WeKb5rK6tO
         XXFRjzkFMSNrIcMUuS/BQ1UP1+80wSi/MjDsWul+fkTy1DshxcQtleemVXRmltbrGgvh
         FZTQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUcJoFpRYuU6lqMyD8wIJmJmJqKu+ZXf1ZmHG90zgSj13w1+MciNrZvkTEFUWAFubo7Hj8oCQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy1JrqpN/tWmRRy1wQAcCNNiHkB+rZSnJsO/rbV8iyIK2BUO6n2
	rJJf5iV7y2lNpW6C43YyVER9p33Qb+2esagYEhWKVwHDqr7yXTP+
X-Google-Smtp-Source: AGHT+IFyeEkJaJ2iI7OS4yBKGOpZQdNm3nSJSTopQlMWRd8VgzJ9dZrkax5jAsgDN3emX9J9goM5Og==
X-Received: by 2002:ac2:5e35:0:b0:544:fdd:fba7 with SMTP id 2adb3069b0e04-5440fddfd73mr24979e87.15.1738799115508;
        Wed, 05 Feb 2025 15:45:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:484b:0:b0:540:2543:30f6 with SMTP id 2adb3069b0e04-5440daaeadcls91816e87.2.-pod-prod-09-eu;
 Wed, 05 Feb 2025 15:45:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhTCZDAala3KlP+BVV0RHgEBhmnXsJHNGIuVZck2UIIiobVR4Lju+zi9j4gIpeosBvUnsjfwR0mr4=@googlegroups.com
X-Received: by 2002:a05:6512:2383:b0:542:2a0b:cdd4 with SMTP id 2adb3069b0e04-54405a6a9bamr1565571e87.47.1738799112928;
        Wed, 05 Feb 2025 15:45:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738799112; cv=none;
        d=google.com; s=arc-20240605;
        b=F9pzwij90gBNLIhw5jCDi+3hEN9FdVVA+O+g+5u7Y6F0CFs0tzKP8NYge7FgokiFn+
         a+jjEn4WBVvHJ+aLYXLb1/wlT0OrVJLaNBm5r9FrT1LqnmZg3HxwDt3jUVFTEZF6iSqo
         DEkHoFgmcStId0nFOaPG1iq6QN+TfMOnrd6vOx15GnUGc1KhB9P2MEA9yBNPbUZgwfMT
         2hLv1FS/bdzILWG+oSfwfylMPopMHyKt7NhB+Hpq79vLCuwO5Bh5zL8bWfcAEFbwTY2H
         SsgBW+egdVhvkMTd25kZ/Lw/c0ofMFAkoBYNNe3LxTbd2cSVEyv1bglIcyyCarYc1wFY
         34lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=SdQ0hVwmExFQXuENvdvOWkm1J/+EX7f8PfThOUaFEXo=;
        fh=XWyva2uMBA0V3uN63OpJaSPY+2QeeppWWJdfJDlR2t8=;
        b=NNJ0p55qx84uZZ/H8vylBEr5eImn+lsXFNMkHyKKwrL2XFn81SQMFY+EC86ZUvnPAR
         9IeP8Nzl8g6NyJYIVqyYStfNU+aWgcYsM1THr1Nr+opjXE8h0bM+imreIqfZfGL5j1Il
         6wJmLC792ljZmprBPvL6Kmt52/5tUU/ExO0qivZ6JJuuZ+o3m6JqSjT+FRjQJ1yYHGyz
         bxIm4byxpTaoyneR2dXKu/zOxKe1D9Jri8al/A6zHCy6BnusqGQ30Q1yIF0wR3CMi5Je
         fdPebxJEUilm7Bva58rKNltAUIKXpyG9N/hYGBfux8NflRNORm9nKoJbFBczJebs6kVE
         PCXw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=J+mcBEoM;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5440fd934ffsi956e87.9.2025.02.05.15.45.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2025 15:45:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-38db52ccc0fso167776f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2025 15:45:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVSSDcgWKp0kfG1nA7hG657TdmJJ5CdPDfDiJvwpAsJbtefMSjLuq6pL9ouxM0QUScU/nwVzeynu90=@googlegroups.com
X-Gm-Gg: ASbGncsiO2U/7JPTG6aqMxSXfRRxLy2kpZoW7Jr2n61U8IhzlaJaZ5bgVtwsvX8wMoU
	+pmiqJSc3DqwkbokAGhE6KlSUFnw07c12Xu2VcDpTQx0jLvHgoAo8gRZmLAKKp6HerOSDTNtNiw
	==
X-Received: by 2002:a05:6000:4020:b0:38d:b2e4:6da3 with SMTP id
 ffacd0b85a97d-38db485890fmr3579308f8f.9.1738799111940; Wed, 05 Feb 2025
 15:45:11 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com> <8f790bb7e166c1ea2e5003318149eb1d7aba3596.1738686764.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <8f790bb7e166c1ea2e5003318149eb1d7aba3596.1738686764.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 6 Feb 2025 00:45:01 +0100
X-Gm-Features: AWEUYZmiEgjCF8wXgTKLUmOPwZJyA3J8QaYcM7d1IkKeZ18qsMT-vpi9smhb5Jc
Message-ID: <CA+fCnZf20PmUL5Ms7aoGq0CAdaXzcx0yrgSrmvgy89og_PwYMg@mail.gmail.com>
Subject: Re: [PATCH 02/15] kasan: Tag checking with dense tag-based mode
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com, 
	palmer@dabbelt.com, tj@kernel.org, brgerst@gmail.com, ardb@kernel.org, 
	dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
	akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, dvyukov@google.com, 
	richard.weiyang@gmail.com, ytcoode@gmail.com, tglx@linutronix.de, 
	hpa@zytor.com, seanjc@google.com, paul.walmsley@sifive.com, 
	aou@eecs.berkeley.edu, justinstitt@google.com, jason.andryuk@amd.com, 
	glider@google.com, ubizjak@gmail.com, jannh@google.com, bhe@redhat.com, 
	vincenzo.frascino@arm.com, rafael.j.wysocki@intel.com, 
	ndesaulniers@google.com, mingo@redhat.com, catalin.marinas@arm.com, 
	junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com, 
	dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com, 
	dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, 
	peterz@infradead.org, cl@linux.com, kees@kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=J+mcBEoM;       spf=pass
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

On Tue, Feb 4, 2025 at 6:35=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> In KASAN's tag-based mode (arm64) when a memory access occurs, the tag
> stored in the top 8 bits of the pointer is compared with tags saved in
> the region of the shadow memory that maps to memory the pointer points
> to. If any of the tags in the shadow memory region do not match the one
> stored in the pointer an error report is generated.
>
> With the introduction of the dense mode, tags won't necessarily occupy
> whole bytes of shadow memory if the previously allocated memory wasn't
> aligned to 32 bytes - which is the coverage of one shadow byte.
>
> Add an alternative implementation of kasan_check_range() that performs
> special checks on first and last bytes of shadow memory ranges if the
> originally allocated memory wasn't aligned to 32 bytes.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  include/linux/kasan.h     | 47 +++++++++++++++-------
>  mm/kasan/Makefile         |  3 ++
>  mm/kasan/dense.c          | 83 +++++++++++++++++++++++++++++++++++++++
>  mm/kasan/kasan.h          |  2 +-
>  mm/kasan/report.c         |  2 +-
>  mm/kasan/report_sw_tags.c | 12 ++----
>  mm/kasan/sw_tags.c        |  8 ++++
>  7 files changed, 133 insertions(+), 24 deletions(-)
>  create mode 100644 mm/kasan/dense.c
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index ea0f5acd875b..5a3e9bec21c2 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -33,6 +33,20 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
>
>  #include <linux/pgtable.h>
>
> +#ifndef kasan_mem_to_shadow
> +static inline void *kasan_mem_to_shadow(const void *addr)
> +{
> +       void *scaled;
> +
> +       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> +               scaled =3D (void *)((unsigned long)addr >> KASAN_SHADOW_S=
CALE_SHIFT);
> +       else
> +               scaled =3D (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIF=
T);
> +
> +       return KASAN_SHADOW_OFFSET + scaled;
> +}
> +#endif

Any reason this is moved up here?


> +
>  /* Software KASAN implementations use shadow memory. */
>
>  #ifdef CONFIG_KASAN_SW_TAGS_DENSE
> @@ -53,6 +67,25 @@ static inline u8 kasan_dense_tag(u8 tag)
>
>  #define KASAN_GRANULE_SIZE     (1UL << KASAN_GRANULE_SHIFT)
>
> +#ifdef CONFIG_KASAN_SW_TAGS_DENSE
> +static inline u8 kasan_get_shadow_tag(const void *ptr)
> +{
> +       u8 shadow_byte =3D *(u8 *)kasan_mem_to_shadow(ptr);
> +       unsigned long addr =3D (unsigned long)ptr;
> +       int shift;
> +
> +       shift =3D !!(addr & KASAN_GRANULE_SIZE) * KASAN_TAG_WIDTH;
> +       shadow_byte >>=3D shift;
> +
> +       return shadow_byte & KASAN_TAG_KERNEL;
> +}
> +#else
> +static inline u8 kasan_get_shadow_tag(const void *addr)
> +{
> +       return (*(u8 *)kasan_mem_to_shadow(addr));
> +}
> +#endif
> +
>  #ifdef CONFIG_KASAN_SW_TAGS
>  /* This matches KASAN_TAG_INVALID. */
>  #define KASAN_SHADOW_INIT 0xFE
> @@ -73,20 +106,6 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D]=
;
>  int kasan_populate_early_shadow(const void *shadow_start,
>                                 const void *shadow_end);
>
> -#ifndef kasan_mem_to_shadow
> -static inline void *kasan_mem_to_shadow(const void *addr)
> -{
> -       void *scaled;
> -
> -       if (IS_ENABLED(CONFIG_KASAN_GENERIC))
> -               scaled =3D (void *)((unsigned long)addr >> KASAN_SHADOW_S=
CALE_SHIFT);
> -       else
> -               scaled =3D (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIF=
T);
> -
> -       return KASAN_SHADOW_OFFSET + scaled;
> -}
> -#endif
> -
>  int kasan_add_zero_shadow(void *start, unsigned long size);
>  void kasan_remove_zero_shadow(void *start, unsigned long size);
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index b88543e5c0cc..3a460abd4c18 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -5,6 +5,7 @@ KCOV_INSTRUMENT :=3D n
>
>  # Disable ftrace to avoid recursion.
>  CFLAGS_REMOVE_common.o =3D $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_dense.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_generic.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_init.o =3D $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_quarantine.o =3D $(CC_FLAGS_FTRACE)
> @@ -24,6 +25,7 @@ CC_FLAGS_KASAN_RUNTIME +=3D -fno-stack-protector
>  CC_FLAGS_KASAN_RUNTIME +=3D -DDISABLE_BRANCH_PROFILING
>
>  CFLAGS_common.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_dense.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_generic.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_init.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_quarantine.o :=3D $(CC_FLAGS_KASAN_RUNTIME)
> @@ -49,6 +51,7 @@ RUSTFLAGS_kasan_test_rust.o :=3D $(RUSTFLAGS_KASAN)
>  CFLAGS_kasan_test_module.o :=3D $(CFLAGS_KASAN_TEST)
>
>  obj-y :=3D common.o report.o
> +obj-$(CONFIG_KASAN_SW_TAGS_DENSE) +=3D dense.o
>  obj-$(CONFIG_KASAN_GENERIC) +=3D init.o generic.o report_generic.o shado=
w.o quarantine.o
>  obj-$(CONFIG_KASAN_HW_TAGS) +=3D hw_tags.o report_hw_tags.o tags.o repor=
t_tags.o
>  obj-$(CONFIG_KASAN_SW_TAGS) +=3D init.o report_sw_tags.o shadow.o sw_tag=
s.o tags.o report_tags.o
> diff --git a/mm/kasan/dense.c b/mm/kasan/dense.c
> new file mode 100644
> index 000000000000..306bbbfdce29
> --- /dev/null
> +++ b/mm/kasan/dense.c
> @@ -0,0 +1,83 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +#include "kasan.h"
> +
> +static __always_inline bool kasan_check_range_inline(const void *addr,
> +                                                    size_t size, bool wr=
ite,
> +                                                    unsigned long ret_ip=
)
> +{
> +       u8 *shadow_first, *shadow_last, *shadow, *shadow_first_aligned, *=
shadow_last_aligned;
> +       u64 addr_start_aligned, addr_end_aligned;
> +       u8 tag, kasan_granule_offset;
> +       size_t aligned_size;
> +       void *untagged_addr;
> +
> +       if (unlikely(size =3D=3D 0))
> +               return true;
> +
> +       if (unlikely(addr + size < addr))
> +               return !kasan_report(addr, size, write, ret_ip);
> +
> +       tag =3D get_tag((const void *)addr);
> +
> +       /*
> +        * Ignore accesses for pointers tagged with native kernel
> +        * pointer tag to suppress false positives caused by kmap.
> +        *
> +        * Some kernel code was written to account for archs that don't k=
eep
> +        * high memory mapped all the time, but rather map and unmap part=
icular
> +        * pages when needed. Instead of storing a pointer to the kernel =
memory,
> +        * this code saves the address of the page structure and offset w=
ithin
> +        * that page for later use. Those pages are then mapped and unmap=
ped
> +        * with kmap/kunmap when necessary and virt_to_page is used to ge=
t the
> +        * virtual address of the page. For arm64 (that keeps the high me=
mory
> +        * mapped all the time), kmap is turned into a page_address call.
> +
> +        * The issue is that with use of the page_address + virt_to_page
> +        * sequence the top byte value of the original pointer gets lost =
(gets
> +        * set to KASAN_TAG_KERNEL).
> +        */
> +       if (tag =3D=3D KASAN_TAG_KERNEL)
> +               return true;
> +
> +       untagged_addr =3D kasan_reset_tag((void *)round_down((u64)addr, K=
ASAN_GRANULE_SIZE));
> +       if (unlikely(!addr_has_metadata(untagged_addr)))
> +               return !kasan_report(addr, size, write, ret_ip);
> +
> +       kasan_granule_offset =3D ((u64)addr & KASAN_GRANULE_MASK);
> +       aligned_size =3D round_up(size + kasan_granule_offset, KASAN_GRAN=
ULE_SIZE);
> +       shadow_first =3D kasan_mem_to_shadow(untagged_addr);
> +       shadow_last =3D kasan_mem_to_shadow(untagged_addr + aligned_size)=
;
> +       addr_start_aligned =3D round_up((u64)untagged_addr, KASAN_SHADOW_=
SCALE_SIZE);
> +       addr_end_aligned =3D round_down((u64)untagged_addr + aligned_size=
, KASAN_SHADOW_SCALE_SIZE);
> +       shadow_first_aligned =3D kasan_mem_to_shadow((void *)addr_start_a=
ligned);
> +       shadow_last_aligned =3D kasan_mem_to_shadow((void *)addr_end_alig=
ned);
> +
> +       /* Check the first unaligned tag in shadow memory. */
> +       if ((u64)untagged_addr % KASAN_SHADOW_SCALE_SIZE) {
> +               if (unlikely((*shadow_first >> KASAN_TAG_WIDTH) !=3D tag)=
)
> +                       return !kasan_report(addr, size, write, ret_ip);
> +       }
> +
> +       /* Check the middle aligned part in shadow memory. */
> +       for (shadow =3D shadow_first_aligned; shadow < shadow_last_aligne=
d; shadow++) {
> +               if (unlikely(*shadow !=3D ((tag << KASAN_TAG_WIDTH) | tag=
)))
> +                       return !kasan_report(addr, size, write, ret_ip);
> +       }
> +
> +       /* Check the last unaligned tag in shadow memory. */
> +       if (((u64)untagged_addr + aligned_size) % KASAN_SHADOW_SCALE_SIZE=
) {
> +               if (unlikely((*shadow_last & KASAN_TAG_MASK) !=3D tag))
> +                       return !kasan_report(addr, size, write, ret_ip);
> +       }
> +
> +       return true;
> +}
> +
> +#if IS_ENABLED(CONFIG_KASAN_SW_TAGS_DENSE)
> +bool kasan_check_range(const void *addr, size_t size, bool write,
> +                      unsigned long ret_ip)
> +{
> +       return kasan_check_range_inline(addr, size, write, ret_ip);
> +}
> +#endif
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 0e04c5e2c405..d29bd0e65020 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -183,7 +183,7 @@ static inline bool kasan_requires_meta(void)
>  #define META_BYTES_PER_BLOCK 1
>  #define META_BLOCKS_PER_ROW 16
>  #define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
> -#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
> +#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_SHADOW_SCALE_=
SIZE)
>  #define META_ROWS_AROUND_ADDR 2
>
>  #define KASAN_STACK_DEPTH 64
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index c08097715686..ee9e406b0cdb 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -436,7 +436,7 @@ static int meta_pointer_offset(const void *row, const=
 void *addr)
>          *    plus 1 byte for space.
>          */
>         return 3 + (BITS_PER_LONG / 8) * 2 +
> -               (addr - row) / KASAN_GRANULE_SIZE * 3 + 1;
> +               (addr - row) / KASAN_SHADOW_SCALE_SIZE * 3 + 1;
>  }
>
>  static void print_memory_metadata(const void *addr)
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 689e94f9fe3c..1ac5c7a9011d 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -39,7 +39,7 @@ const void *kasan_find_first_bad_addr(const void *addr,=
 size_t size)
>         if (!addr_has_metadata(p))
>                 return p;
>
> -       while (p < end && tag =3D=3D *(u8 *)kasan_mem_to_shadow(p))
> +       while (p < end && tag =3D=3D kasan_get_shadow_tag(p))
>                 p +=3D KASAN_GRANULE_SIZE;
>
>         return p;
> @@ -48,7 +48,6 @@ const void *kasan_find_first_bad_addr(const void *addr,=
 size_t size)
>  size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache)
>  {
>         size_t size =3D 0;
> -       u8 *shadow;
>
>         /*
>          * Skip the addr_has_metadata check, as this function only operat=
es on
> @@ -59,13 +58,11 @@ size_t kasan_get_alloc_size(void *object, struct kmem=
_cache *cache)
>          * The loop below returns 0 for freed objects, for which KASAN ca=
nnot
>          * calculate the allocation size based on the metadata.
>          */
> -       shadow =3D (u8 *)kasan_mem_to_shadow(object);
>         while (size < cache->object_size) {
> -               if (*shadow !=3D KASAN_TAG_INVALID)
> +               if (kasan_get_shadow_tag(object + size) !=3D KASAN_TAG_IN=
VALID)
>                         size +=3D KASAN_GRANULE_SIZE;
>                 else
>                         return size;
> -               shadow++;
>         }
>
>         return cache->object_size;
> @@ -78,9 +75,8 @@ void kasan_metadata_fetch_row(char *buffer, void *row)
>
>  void kasan_print_tags(u8 addr_tag, const void *addr)
>  {
> -       u8 *shadow =3D (u8 *)kasan_mem_to_shadow(addr);
> -
> -       pr_err("Pointer tag: [%02x], memory tag: [%02x]\n", addr_tag, *sh=
adow);
> +       pr_err("Pointer tag: [%02x], memory tag: [%02x]\n", addr_tag,
> +              kasan_get_shadow_tag(addr));
>  }
>
>  #ifdef CONFIG_KASAN_STACK
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 32435d33583a..7a6b8ea9bf78 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -79,6 +79,7 @@ u8 __hwasan_generate_tag(void)
>  }
>  EXPORT_SYMBOL(__hwasan_generate_tag);
>
> +#if !IS_ENABLED(CONFIG_KASAN_SW_TAGS_DENSE)
>  bool kasan_check_range(const void *addr, size_t size, bool write,
>                         unsigned long ret_ip)
>  {
> @@ -127,17 +128,24 @@ bool kasan_check_range(const void *addr, size_t siz=
e, bool write,
>
>         return true;
>  }
> +#endif
>
>  bool kasan_byte_accessible(const void *addr)
>  {
>         u8 tag =3D get_tag(addr);
>         void *untagged_addr =3D kasan_reset_tag(addr);
>         u8 shadow_byte;
> +       int shift;
>
>         if (!addr_has_metadata(untagged_addr))
>                 return false;
>
>         shadow_byte =3D READ_ONCE(*(u8 *)kasan_mem_to_shadow(untagged_add=
r));
> +       if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_DENSE)) {
> +               shift =3D !!((u64)addr & BIT(KASAN_TAG_WIDTH)) * KASAN_TA=
G_WIDTH;
> +               shadow_byte =3D (shadow_byte >> shift) & KASAN_TAG_KERNEL=
;
> +       }
> +
>         return tag =3D=3D KASAN_TAG_KERNEL || tag =3D=3D shadow_byte;
>  }
>
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf20PmUL5Ms7aoGq0CAdaXzcx0yrgSrmvgy89og_PwYMg%40mail.gmail.com.
