Return-Path: <kasan-dev+bncBDW2JDUY5AORBO7QR66QMGQE6QWUU3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 0259CA29DA8
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 00:46:19 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5d9e4d33f04sf308271a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Feb 2025 15:46:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738799164; cv=pass;
        d=google.com; s=arc-20240605;
        b=I0z6BchbqbsuthoOLPpPa0q1BI15CWlxY+7pf2+dTPc6G83xNJx1DHUlT8JGiKUZl4
         N5Zb1wVb1mHG05HfWeqxiNxfFaVTx9GE0jWSz7wWjprxhlA0sniCP5Mh7SKpweLF5V27
         XNcQgCP6rkKAJ7dsLcfCPUUUqxQvA/2MORuo+J6Cq10F5Q/A+2BxxZStyP0dNrYwxaLf
         lrN1oqY9jC9megbkqopKaXMim4OLDh5SiSyvf6lIKdv06jweURA8vmfN2+b3mX6RvGeM
         maMh3S/CbCSLn4AivMyXgvIFVe7bEkKgHfWE0l/N3/ZstA8B80FtYF0HKIvmDncMcVCc
         dqVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=DgYGd4YwIToGsdXnY5OxasF49t1qAS3nm69o948Rn/Q=;
        fh=5HCpqaahWmJpg33WrBH/Y5dBMh4hgTfxBE+CvK/PbCY=;
        b=Xmhz8MHpeKgrKJTsdTdW2tp35iUOr4NLNsMwrgSRjav11ouZAq3PhlXwdlW6iSWz6Q
         BSgEspwOdwLn0Mrdj+3bGqQDnfLc4jPWlhMve6aWEXl4QBAYe4h+UsaT+va9I2GJzS2Z
         RunuV1XV0pLGgN4MR5nYktkw4H+rbotUEly90NF7QB5i607jIg5XURUmzs13QzALPIIc
         PRKeIiBKUHb/MmK4Xh+vj3TX5tnDjXbYFkGht5VN63IgGGx5unS4fBnzW6OBQVNG22bY
         E0MNuTp+UxOi1KQCG4lUP7RZMUyrA1KeH/FzLAmh79pQbOQeAz8dBReUBpHh5OLhk4vN
         MlDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SAakyZ1M;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738799164; x=1739403964; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DgYGd4YwIToGsdXnY5OxasF49t1qAS3nm69o948Rn/Q=;
        b=g/BhX0NxVzX+E7/0MuNgYVXDWLOZsAZvZR2jvZgTZ//1nOdLonF7ojpLH+uSBDrXN7
         Q9J5Cluu8NvG9oY/lSmxDS0A9oxlkbzk03CWMqSX+JefbAahQuEXF6G12cPMOzfNyrcD
         /kaddQhwa29qFCL29CO4d/R2HW7lRP2+4tU23s/hKZEaKhxWllgO4PamFdyt96edyDAF
         O9n98q9TgkRcKWEKDNA9Wdv6tBaOmu+SUtPz+fEsSYGByxMY4qMTka1ENti+geDKembS
         kjBdyDF/1Q/fHLG1uBrdvxXaspEo6oPtubzBdWCTSUMHZvh0QqOIsKDtLRV4Ss+lZUtJ
         dS9w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738799164; x=1739403964; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DgYGd4YwIToGsdXnY5OxasF49t1qAS3nm69o948Rn/Q=;
        b=K/dB2EQLfQQrH4gKsK8Rd2YtjUYYvTX1gN9XE3d1haQcVfly/J2lKMk7O6c5n6T7S5
         YfFcRJ531S2c+g8rPHiGTuPMcOUtRoJw+RkCzXYTStIt5dAnK4aMAxYx/VDjJfeQMGBo
         4iOm+BnN6zSQA7FQQ8RV3TEqNL1uEN9ZYaOvZIw0fzkDHUVQlQD6fc0CxbrG2v6nf7rS
         sTtyv+KiBH4QEPlcnT7f9d/trV1LL+vpH5PgHAL5gitXGGxHu9ftTvtIT2xeAhdfHsS6
         txWmmJC+G5N83lz0LfgraN3EhOhcM4eBD780mOTvgS2spieBxIZXK58iUe93crF30kjK
         J/ww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738799164; x=1739403964;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DgYGd4YwIToGsdXnY5OxasF49t1qAS3nm69o948Rn/Q=;
        b=rXrWluWLgMALU+OU0FdDm5DwcUYSpzuAH5W/HMzfWfbyVZaPn7MynBvm2cZwXWrCpd
         2Q2dGMRcZ6F0lggErXpoMUNyINnR2NlPV8D0N801ZCTU1qN0PkFnRzQKrzFH1Jpv+0fG
         ZO5YADOXYt269I942tvFhjBNeMB1yUtohi+BRaQt/NbeCN1X1x7alVpLROihTC693FBq
         S0m5Kct/skimGCNqIrKsA6HeSIH3Hj6w4P/e0PSNQWLOY4+niOhpu2HEw5QiLP3P+U/3
         q9CY5VX0awyxxXQTg8DpmzNOTqbofAFedKxNWuiicH0TOl6eEmbViXOyDPEOgU1C3rzc
         YZrA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXLWmfZRVG6k48MPr/2uYtaZpoqdHH4JsA01FywexkB1mD/h+2+3ODFjQ649xOZcUZ+e5xEwg==@lfdr.de
X-Gm-Message-State: AOJu0YwnUjSHPQ+WzzAB+f52Vh+bsNohfgR5+4hAjtLVZUZUjSkZhIYU
	WoDRH3y3Gnazt+/ObaxfB7XsutCR0nXDmnz5a08VBjlJ85wU9wYQ
X-Google-Smtp-Source: AGHT+IFMuj2g5ua+JYS8c34NivmX5L33Qxu1+FWjvjmSHkfwbV/sMsEBgDpgINQbOOl7CHmfrYe0JQ==
X-Received: by 2002:a05:6402:51d4:b0:5dc:92c0:281b with SMTP id 4fb4d7f45d1cf-5dcdb7752e8mr4757266a12.22.1738799163423;
        Wed, 05 Feb 2025 15:46:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d541:0:b0:5d9:6a7e:1514 with SMTP id 4fb4d7f45d1cf-5dcebcc55e9ls299711a12.0.-pod-prod-02-eu;
 Wed, 05 Feb 2025 15:46:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWbsaCDxZ0FMe50qze9Nns0o8zKQ/Kt4PkUqThGkCePMf9+DLuS+oXLj3HHujE4JXYf6PHKbDP+gsA=@googlegroups.com
X-Received: by 2002:a05:6402:34c8:b0:5d9:b84:a01f with SMTP id 4fb4d7f45d1cf-5dcdb72d882mr4768252a12.18.1738799160774;
        Wed, 05 Feb 2025 15:46:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738799160; cv=none;
        d=google.com; s=arc-20240605;
        b=D5HiDr9BfUMJAlMGQM9dOfSEmCzbGSTWhXIZxfgmSD6N6UngQVXwK7BZzKUPqIqjBT
         /XsSMmoZO7pTeziX9nrq6nMlt7QhQToahZx6kgmXm2kUS/2zzrtwMvX/UH5MqnWfGavc
         SmW4AnOR/Z5sZXVicACLlJLZIcbw6SmdJ2qh6+qTKEzdBd7TNlHBJU6XotdK/+/P3arp
         uYMsDLDHATOWR9QyrgTzR4fdxr9JSVDDMrg+OkCTX3FnlgEn9uJ5WES6ObAEMQ5OK+WB
         Ar8flRtJyVjePLx4zT0Ej+VKzAGwM17z7EB3Oy6pYCJy6ajvLcRq6I+fHorNelkFf6mM
         dyNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Rz+V1fDyiTyTkm+6v9/Yshk0vlGrK4aQBew/N8UNm8o=;
        fh=e66wVyzdUtyIPMegJoJOUE6ekWVRWB6pcwjenKKGRyo=;
        b=lbqr/ON7cjTFuP/DyLFhL+X0caXwoGyRMWmIjCRG+oQj1/8M/5uWTTxXjpau4uHJ9f
         xH1k3rMqHXxF8r8s5x7oC/1o/hTqE73WR5+3HgMBfutOHuSlGhKh5Qq4xsFr8NOt613d
         Ly30+8lZKh+VarpmIadSSbfHMbqjwi98VM2Kf3iubgy3HQzpsk64lfivv9yoU3t4G4Ov
         LYIm+Yfm0polzUNGR6IMetItZZ9v/XCPFz/YsFth5TA9k8iVrPWYXzP2FjxKvGNZZ+05
         dImHay0pql1CibgQEKyft9Ktq+sjXy157wNajcRjqZTkJingee1JidnkZ7GM03/q6xoy
         Xz0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=SAakyZ1M;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcd9c58ecbsi40488a12.1.2025.02.05.15.46.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Feb 2025 15:46:00 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-38db909acc9so220017f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 05 Feb 2025 15:46:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV1TRtPk2+QOOdN7BSKqM24psQ9bcP4NiPoUn/drFszczvyWf5JW1ulZEBX/dzLukP7IJIAG/7s858=@googlegroups.com
X-Gm-Gg: ASbGncuFP0ZY64Iupx2JXyNL5VIFexLO6eYr2mPDF/e0UhSJ2IhNvSffWj9pl6DxjTe
	M2+YmwY0yeon7kDthdWRhV1aqrbjS5XMjhqlrWR2/8I1sYNIRh6ay5vdkmFMJGPTE9+4qAlPlNQ
	==
X-Received: by 2002:a05:6000:1786:b0:385:f0dc:c9f4 with SMTP id
 ffacd0b85a97d-38db48bdaecmr3897521f8f.20.1738799160206; Wed, 05 Feb 2025
 15:46:00 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com> <28ddfb1694b19278405b4934f37d398794409749.1738686764.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <28ddfb1694b19278405b4934f37d398794409749.1738686764.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 6 Feb 2025 00:45:49 +0100
X-Gm-Features: AWEUYZm-2kNDPAYBLLDAqKKnZZXufvhPekieyoATWEHpiTcF4DB1S0LSkY8umDA
Message-ID: <CA+fCnZfKQwNWbYEhk70ykT1+cnibCBnvZJrhAMvu_b0Y8xZTSg@mail.gmail.com>
Subject: Re: [PATCH 10/15] x86: KASAN raw shadow memory PTE init
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
 header.i=@gmail.com header.s=20230601 header.b=SAakyZ1M;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
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

On Tue, Feb 4, 2025 at 6:36=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> In KASAN's generic mode the default value in shadow memory is zero.
> During initialization of shadow memory pages they are allocated and
> zeroed.
>
> In KASAN's tag-based mode the default tag for the arm64 architecture is
> 0xFE which corresponds to any memory that should not be accessed. On x86
> (where tags are 4-bit wide instead of 8-bit wide) that tag is 0xE so
> during the initializations all the bytes in shadow memory pages should
> be filled with 0xE or 0xEE if two tags should be packed in one shadow
> byte.
>
> Use memblock_alloc_try_nid_raw() instead of memblock_alloc_try_nid() to
> avoid zeroing out the memory so it can be set with the KASAN invalid
> tag.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  arch/x86/mm/kasan_init_64.c | 19 ++++++++++++++++---
>  include/linux/kasan.h       | 25 +++++++++++++++++++++++++
>  mm/kasan/kasan.h            | 19 -------------------
>  3 files changed, 41 insertions(+), 22 deletions(-)
>
> diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
> index 9dddf19a5571..55d468d83682 100644
> --- a/arch/x86/mm/kasan_init_64.c
> +++ b/arch/x86/mm/kasan_init_64.c
> @@ -35,6 +35,18 @@ static __init void *early_alloc(size_t size, int nid, =
bool should_panic)
>         return ptr;
>  }
>
> +static __init void *early_raw_alloc(size_t size, int nid, bool should_pa=
nic)
> +{
> +       void *ptr =3D memblock_alloc_try_nid_raw(size, size,
> +                       __pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE,=
 nid);
> +
> +       if (!ptr && should_panic)
> +               panic("%pS: Failed to allocate page, nid=3D%d from=3D%lx\=
n",
> +                     (void *)_RET_IP_, nid, __pa(MAX_DMA_ADDRESS));
> +
> +       return ptr;
> +}
> +
>  static void __init kasan_populate_pmd(pmd_t *pmd, unsigned long addr,
>                                       unsigned long end, int nid)
>  {
> @@ -64,8 +76,9 @@ static void __init kasan_populate_pmd(pmd_t *pmd, unsig=
ned long addr,
>                 if (!pte_none(*pte))
>                         continue;
>
> -               p =3D early_alloc(PAGE_SIZE, nid, true);
> -               entry =3D pfn_pte(PFN_DOWN(__pa(p)), PAGE_KERNEL);
> +               p =3D early_raw_alloc(PAGE_SIZE, nid, true);
> +               memset(p, PAGE_SIZE, kasan_dense_tag(KASAN_SHADOW_INIT));
> +               entry =3D pfn_pte(PFN_DOWN(__pa_nodebug(p)), PAGE_KERNEL)=
;
>                 set_pte_at(&init_mm, addr, pte, entry);
>         } while (pte++, addr +=3D PAGE_SIZE, addr !=3D end);
>  }
> @@ -437,7 +450,7 @@ void __init kasan_init(void)
>          * it may contain some garbage. Now we can clear and write protec=
t it,
>          * since after the TLB flush no one should write to it.
>          */
> -       memset(kasan_early_shadow_page, 0, PAGE_SIZE);
> +       kasan_poison(kasan_early_shadow_page, PAGE_SIZE, KASAN_SHADOW_INI=
T, false);
>         for (i =3D 0; i < PTRS_PER_PTE; i++) {
>                 pte_t pte;
>                 pgprot_t prot;
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 83146367170a..af8272c74409 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -151,6 +151,31 @@ static __always_inline void kasan_unpoison_range(con=
st void *addr, size_t size)
>                 __kasan_unpoison_range(addr, size);
>  }
>
> +#ifdef CONFIG_KASAN_HW_TAGS
> +
> +static inline void kasan_poison(const void *addr, size_t size, u8 value,=
 bool init)
> +{
> +       if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
> +               return;
> +       if (WARN_ON(size & KASAN_GRANULE_MASK))
> +               return;
> +
> +       hw_set_mem_tag_range(kasan_reset_tag(addr), size, value, init);
> +}
> +
> +#else /* CONFIG_KASAN_HW_TAGS */
> +
> +/**
> + * kasan_poison - mark the memory range as inaccessible
> + * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> + * @size - range size, must be aligned to KASAN_GRANULE_SIZE
> + * @value - value that's written to metadata for the range
> + * @init - whether to initialize the memory range (only for hardware tag=
-based)
> + */
> +void kasan_poison(const void *addr, size_t size, u8 value, bool init);
> +
> +#endif /* CONFIG_KASAN_HW_TAGS */

Please keep kasan_poison() and kasan_unpoison() in mm/kasan/kasan.h:
these are intended as internal-only functions (perhaps, we should add
this into the comment). Instead, add a purpose-specific wrapper
similar to the ones in include/linux/kasan.h.


> +
>  void __kasan_poison_pages(struct page *page, unsigned int order, bool in=
it);
>  static __always_inline void kasan_poison_pages(struct page *page,
>                                                 unsigned int order, bool =
init)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index a56aadd51485..2405477c5899 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -466,16 +466,6 @@ static inline u8 kasan_random_tag(void) { return 0; =
}
>
>  #ifdef CONFIG_KASAN_HW_TAGS
>
> -static inline void kasan_poison(const void *addr, size_t size, u8 value,=
 bool init)
> -{
> -       if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
> -               return;
> -       if (WARN_ON(size & KASAN_GRANULE_MASK))
> -               return;
> -
> -       hw_set_mem_tag_range(kasan_reset_tag(addr), size, value, init);
> -}
> -
>  static inline void kasan_unpoison(const void *addr, size_t size, bool in=
it)
>  {
>         u8 tag =3D get_tag(addr);
> @@ -497,15 +487,6 @@ static inline bool kasan_byte_accessible(const void =
*addr)
>
>  #else /* CONFIG_KASAN_HW_TAGS */
>
> -/**
> - * kasan_poison - mark the memory range as inaccessible
> - * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> - * @size - range size, must be aligned to KASAN_GRANULE_SIZE
> - * @value - value that's written to metadata for the range
> - * @init - whether to initialize the memory range (only for hardware tag=
-based)
> - */
> -void kasan_poison(const void *addr, size_t size, u8 value, bool init);
> -
>  /**
>   * kasan_unpoison - mark the memory range as accessible
>   * @addr - range start address, must be aligned to KASAN_GRANULE_SIZE
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfKQwNWbYEhk70ykT1%2BcnibCBnvZJrhAMvu_b0Y8xZTSg%40mail.gmail.com.
