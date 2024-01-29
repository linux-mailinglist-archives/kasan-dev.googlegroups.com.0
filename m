Return-Path: <kasan-dev+bncBDW2JDUY5AORB5E44CWQMGQELGRPZHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 356808414A2
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 21:45:42 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2d0520f023csf11351811fa.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 12:45:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706561141; cv=pass;
        d=google.com; s=arc-20160816;
        b=GKIKH0WwIL6wmAO4X+UpDYah7LAsGvKWMXFuQD6+ul/FnqyaFmGO+Z7PPE593SOdnK
         eGn6oOi1zxK8G3uWuf8Iap7zsvgPkPm0hvVKfhBKzisiETyYuUY2rzed8qmvdWnSoTqD
         VDxY5TLL2MRt/q3wqmXNBXX3PSRIQU1Zh425+4cgh/oPPafnoBut/tHOMSGQYyymMJx9
         xqS2zU2pLE/9qYNriUhpXWUnPYhxxWTLa1/KNqOcBkeChf01okMCPWAUhSksWzUKAEL3
         ULax3VtbgkPFFFB5vizwCjDRlRhXrv+OevDObCGy8FF6T6uP6Xx9zlW6+qN4nvLxgozA
         8/ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8rN60HqLy5EIcXA97eBP2x51+9GBl/eJm1RMMDusBoM=;
        fh=G5Sf+yA7QFQ+aXjXnbd5GcOuLB66is2XVv5pj4hJoF4=;
        b=Zzsfy4nY3O4O3jGnkLAXqn0/W/gDofLcqNH32EFmxZ7kn+YWp3Lahwa3yXMDwX9hew
         nlU0CdxMM6qo1Ga+STcsBkiYpAIlPpFzfuAVXd6G3aURqMg8o8cKB8jm602EZCET8b2r
         rW1Us2wEQUl2Ez5AuqJfpvVzPmOZDzVMvKlSD2tjzkdJdTBxD/aPsucvTdqhaSMHSSf2
         /o4nRA8xXAkIIqr1EdXWu/QkBc1Whj/BB4NEEAYcTttAVLiHNw/tWhjGIrSxFxlC+ujM
         G/PMRI7q5iYXfKLz+WEkbpxpl0/7Y38Uz3lyYT5r6+pZzNuesFHL0tivAHD5GicpPBjJ
         w4FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M5LfEYHq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706561141; x=1707165941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8rN60HqLy5EIcXA97eBP2x51+9GBl/eJm1RMMDusBoM=;
        b=LtcMbpvPbg7QopudGHqrUAKHZufVdCFOG3q4t+SqhjBrRlyZ+L7h+DjNdD4nBRbykh
         sBlpstAXcBQiTZyGtyMQqdFucxs2Ja8G9grDPhonpbhqNTuBEGK+rix66/EOQdVLTuvn
         4ir6QI8GoPMmznkklfjclpcuAQRY5wRBbh/TU/2URpAZzwrjCROtOTAcw3pxCs1blkBg
         oGuoAUAHVCi72beOPwWCr+zqqhzL10CTiTPOy0mwz3JP3uhvmyU1EMWkIVfgcfOnb9Vn
         8eH+bXYBi6l/8jhDUIUsqf1+WVH5cr4lx6eJVneH9NxSByrmZ+8RSmPf5btsIaDPuLjW
         3KUg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706561141; x=1707165941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8rN60HqLy5EIcXA97eBP2x51+9GBl/eJm1RMMDusBoM=;
        b=kBfNcQDxU+uSzXUpUs1gIyurjnChJGLNZmK/eKv0OsS2hJ2/5baJmXQVZWJL4+44Lf
         wylVOaQjXhqiLPTzCi8oGDVYFfJsOy0P+Xqc5CSBmKFlcxAb6NSxhAa69P52wmcrvxkL
         b0aZpbJhL5TbhL24zPNMgPz/yeDgoTkMtyUH5HZalLBLQc2qTgaGdT9n+ygYOmdP1NEN
         gSTD9xD7Fy3zd/S6kGGVN3T68YYCdukA5T+MN3TrK2xp3bWp6ddoNjX5IkJ3MdCV/Gh8
         d9B5/iJA1d/sg9XoBjl9k7uYH8NIsorrsEdIlQpv7i+LV23Fu83R0mClMcRKI0GZWPSV
         n8JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706561141; x=1707165941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8rN60HqLy5EIcXA97eBP2x51+9GBl/eJm1RMMDusBoM=;
        b=KxxGbAmN/kLGzlJGa05H05mgA5Khfg2LUR3QNMIz+1itObDZkpPNdBdKgW0phuX0or
         3we9CjBjtiDCgK7VrhPM+m+gaq9qbTcpSyjX7YWSP7Y/QrDzZRK0nUa2QkknHMRdqTKz
         WUXFdsXvEc8K+qlLzgWi6Ub+20BQ9wGr1wPWTHcRxCZy2/HoWf1zVabquU1tqZsZhXC9
         6PoFMXOQCjtHz0XeRWEh5U22PcYyq8hE5JXM4tiZaaqkSa6o3s17MvJ5ffpH8OF8mtRC
         pXaaQKOyObqBXv8NmJgKs+Z/kNA2mj8PUpTgw9sg8C7rSqgAJe4xPTiXlnzbcCNOBTRb
         8wUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxW5KwimfqqTO3nMrKNp0ccpbryseFXYBhy5ohQc2O/f/jJnvM/
	rWEjvQSxRqVCrEwp62nTlDnzEXXvHsQAOKPmA7omyt6LxAk9f2ya
X-Google-Smtp-Source: AGHT+IH6hYCFokL2qwpgA3UzBvwDDWl8uKwmiYX3u46wIm5sy5ZmTR3/spOMk2BLwQZ+VYWXumjoMg==
X-Received: by 2002:a2e:a36d:0:b0:2cf:2ef2:87f7 with SMTP id i13-20020a2ea36d000000b002cf2ef287f7mr4668588ljn.53.1706561140514;
        Mon, 29 Jan 2024 12:45:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4022:b0:55f:fba:e5fd with SMTP id
 d34-20020a056402402200b0055f0fbae5fdls379898eda.2.-pod-prod-09-eu; Mon, 29
 Jan 2024 12:45:38 -0800 (PST)
X-Received: by 2002:a05:6402:2709:b0:55d:31f8:920a with SMTP id y9-20020a056402270900b0055d31f8920amr6031356edd.27.1706561138614;
        Mon, 29 Jan 2024 12:45:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706561138; cv=none;
        d=google.com; s=arc-20160816;
        b=nksZvTEiYPjurHUaJ5Z0JjTE6qJN9RMSNKdKrSAH5pgGNSTFyaVMxVvre6+4FafU90
         UnsE0czLDHBRAOUQlyHJCiytQGMgn7KQ4qZxq6dVzgs16NIoGf4wzjseH/kpwzbYMueX
         esmD/JnKV65Wc1Hfp00V/yQH/JFOtRXU7aSZLl9BrhrkziKyVzCaA0OXKm7rcfBktRxG
         AyUGuWY4JhcJtTADP+RA2YfKFCp3MRE86+4iapBRzsQGmu9zwwj34jZlt8CMH5wFj7WN
         i8N4PKZD9OwYb35Ika3ohrl3mSdhdtzB6ksBfQ6mPvt+MIeWIVigBIHCO/mYb2DZPHZV
         /TrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=kKP9s1fPlgpzq7TnTgaJGwWqGuyNQA6clVmR/5qf3Ds=;
        fh=G5Sf+yA7QFQ+aXjXnbd5GcOuLB66is2XVv5pj4hJoF4=;
        b=LXfAnpp0rsfuqTyVeksFyxe8MbEiFkxRiBGiJwStNGsD0Wz0KPG1Gm2QDIMLngUIfU
         k96mkk+a8tBwwotEukUrMtk9GgWwKIrE9um1/nyEwdnU07tMAg7rKfkbWCphVNb4lZWM
         KOffaHnwurKRg4KOyXxshXCEi5RETfwFVvsH6fzVZN/nR3XwJqp7Zw3M6JkyR0QTM7CX
         h/ffpWzWofsUUrniGIOs5zuhATx8FFjMBvk5ktgIm7CW3SipPSlAWmWGeUMyFYcd4GpV
         ZGaL3baI8orJIDs1GR9c0fzmTusicYmGUw0cgV9SVy4x61ORnZpB2dwrcQ+54+lrEPNz
         5OLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=M5LfEYHq;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x32c.google.com (mail-wm1-x32c.google.com. [2a00:1450:4864:20::32c])
        by gmr-mx.google.com with ESMTPS id n17-20020a056402061100b0055c110294basi184762edv.2.2024.01.29.12.45.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jan 2024 12:45:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c as permitted sender) client-ip=2a00:1450:4864:20::32c;
Received: by mail-wm1-x32c.google.com with SMTP id 5b1f17b1804b1-40e775695c6so28444885e9.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Jan 2024 12:45:38 -0800 (PST)
X-Received: by 2002:a05:600c:524c:b0:40e:f62b:eec0 with SMTP id
 fc12-20020a05600c524c00b0040ef62beec0mr4015551wmb.17.1706561137853; Mon, 29
 Jan 2024 12:45:37 -0800 (PST)
MIME-Version: 1.0
References: <20240129134652.4004931-1-tongtiangen@huawei.com> <20240129134652.4004931-6-tongtiangen@huawei.com>
In-Reply-To: <20240129134652.4004931-6-tongtiangen@huawei.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 29 Jan 2024 21:45:26 +0100
Message-ID: <CA+fCnZf-mkSJ+8kMPi+mWOjtYzD+FAKi_ciiHt=yrbksY9W-KA@mail.gmail.com>
Subject: Re: [PATCH v10 5/6] arm64: support copy_mc_[user]_highpage()
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, James Morse <james.morse@arm.com>, 
	Robin Murphy <robin.murphy@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Alexander Viro <viro@zeniv.linux.org.uk>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	"Aneesh Kumar K.V" <aneesh.kumar@kernel.org>, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linuxppc-dev@lists.ozlabs.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, wangkefeng.wang@huawei.com, 
	Guohanjun <guohanjun@huawei.com>, Tong Tiangen <tongtiangen@huawei.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=M5LfEYHq;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32c
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Jan 29, 2024 at 2:47=E2=80=AFPM Tong Tiangen <tongtiangen@huawei.co=
m> wrote:
>
> Currently, many scenarios that can tolerate memory errors when copying pa=
ge
> have been supported in the kernel[1][2][3], all of which are implemented =
by
> copy_mc_[user]_highpage(). arm64 should also support this mechanism.
>
> Due to mte, arm64 needs to have its own copy_mc_[user]_highpage()
> architecture implementation, macros __HAVE_ARCH_COPY_MC_HIGHPAGE and
> __HAVE_ARCH_COPY_MC_USER_HIGHPAGE have been added to control it.
>
> Add new helper copy_mc_page() which provide a page copy implementation wi=
th
> machine check safe. The copy_mc_page() in copy_mc_page.S is largely borro=
ws
> from copy_page() in copy_page.S and the main difference is copy_mc_page()
> add extable entry to every load/store insn to support machine check safe.
>
> Add new extable type EX_TYPE_COPY_MC_PAGE_ERR_ZERO which used in
> copy_mc_page().
>
> [1]a873dfe1032a ("mm, hwpoison: try to recover from copy-on write faults"=
)
> [2]5f2500b93cc9 ("mm/khugepaged: recover from poisoned anonymous memory")
> [3]6b970599e807 ("mm: hwpoison: support recovery from ksm_might_need_to_c=
opy()")
>
> Signed-off-by: Tong Tiangen <tongtiangen@huawei.com>
> ---
>  arch/arm64/include/asm/asm-extable.h | 15 ++++++
>  arch/arm64/include/asm/assembler.h   |  4 ++
>  arch/arm64/include/asm/mte.h         |  5 ++
>  arch/arm64/include/asm/page.h        | 10 ++++
>  arch/arm64/lib/Makefile              |  2 +
>  arch/arm64/lib/copy_mc_page.S        | 78 ++++++++++++++++++++++++++++
>  arch/arm64/lib/mte.S                 | 27 ++++++++++
>  arch/arm64/mm/copypage.c             | 66 ++++++++++++++++++++---
>  arch/arm64/mm/extable.c              |  7 +--
>  include/linux/highmem.h              |  8 +++
>  10 files changed, 213 insertions(+), 9 deletions(-)
>  create mode 100644 arch/arm64/lib/copy_mc_page.S
>
> diff --git a/arch/arm64/include/asm/asm-extable.h b/arch/arm64/include/as=
m/asm-extable.h
> index 980d1dd8e1a3..819044fefbe7 100644
> --- a/arch/arm64/include/asm/asm-extable.h
> +++ b/arch/arm64/include/asm/asm-extable.h
> @@ -10,6 +10,7 @@
>  #define EX_TYPE_UACCESS_ERR_ZERO       2
>  #define EX_TYPE_KACCESS_ERR_ZERO       3
>  #define EX_TYPE_LOAD_UNALIGNED_ZEROPAD 4
> +#define EX_TYPE_COPY_MC_PAGE_ERR_ZERO  5
>
>  /* Data fields for EX_TYPE_UACCESS_ERR_ZERO */
>  #define EX_DATA_REG_ERR_SHIFT  0
> @@ -51,6 +52,16 @@
>  #define _ASM_EXTABLE_UACCESS(insn, fixup)                              \
>         _ASM_EXTABLE_UACCESS_ERR_ZERO(insn, fixup, wzr, wzr)
>
> +#define _ASM_EXTABLE_COPY_MC_PAGE_ERR_ZERO(insn, fixup, err, zero)     \
> +       __ASM_EXTABLE_RAW(insn, fixup,                                  \
> +                         EX_TYPE_COPY_MC_PAGE_ERR_ZERO,                \
> +                         (                                             \
> +                           EX_DATA_REG(ERR, err) |                     \
> +                           EX_DATA_REG(ZERO, zero)                     \
> +                         ))
> +
> +#define _ASM_EXTABLE_COPY_MC_PAGE(insn, fixup)                         \
> +       _ASM_EXTABLE_COPY_MC_PAGE_ERR_ZERO(insn, fixup, wzr, wzr)
>  /*
>   * Create an exception table entry for uaccess `insn`, which will branch=
 to `fixup`
>   * when an unhandled fault is taken.
> @@ -59,6 +70,10 @@
>         _ASM_EXTABLE_UACCESS(\insn, \fixup)
>         .endm
>
> +       .macro          _asm_extable_copy_mc_page, insn, fixup
> +       _ASM_EXTABLE_COPY_MC_PAGE(\insn, \fixup)
> +       .endm
> +
>  /*
>   * Create an exception table entry for `insn` if `fixup` is provided. Ot=
herwise
>   * do nothing.
> diff --git a/arch/arm64/include/asm/assembler.h b/arch/arm64/include/asm/=
assembler.h
> index 513787e43329..e1d8ce155878 100644
> --- a/arch/arm64/include/asm/assembler.h
> +++ b/arch/arm64/include/asm/assembler.h
> @@ -154,6 +154,10 @@ lr .req    x30             // link register
>  #define CPU_LE(code...) code
>  #endif
>
> +#define CPY_MC(l, x...)                \
> +9999:   x;                     \
> +       _asm_extable_copy_mc_page    9999b, l
> +
>  /*
>   * Define a macro that constructs a 64-bit value by concatenating two
>   * 32-bit registers. Note that on big endian systems the order of the
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index 91fbd5c8a391..9cdded082dd4 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -92,6 +92,7 @@ static inline bool try_page_mte_tagging(struct page *pa=
ge)
>  void mte_zero_clear_page_tags(void *addr);
>  void mte_sync_tags(pte_t pte, unsigned int nr_pages);
>  void mte_copy_page_tags(void *kto, const void *kfrom);
> +int mte_copy_mc_page_tags(void *kto, const void *kfrom);
>  void mte_thread_init_user(void);
>  void mte_thread_switch(struct task_struct *next);
>  void mte_cpu_setup(void);
> @@ -128,6 +129,10 @@ static inline void mte_sync_tags(pte_t pte, unsigned=
 int nr_pages)
>  static inline void mte_copy_page_tags(void *kto, const void *kfrom)
>  {
>  }
> +static inline int mte_copy_mc_page_tags(void *kto, const void *kfrom)
> +{
> +       return 0;
> +}
>  static inline void mte_thread_init_user(void)
>  {
>  }
> diff --git a/arch/arm64/include/asm/page.h b/arch/arm64/include/asm/page.=
h
> index 2312e6ee595f..304cc86b8a10 100644
> --- a/arch/arm64/include/asm/page.h
> +++ b/arch/arm64/include/asm/page.h
> @@ -29,6 +29,16 @@ void copy_user_highpage(struct page *to, struct page *=
from,
>  void copy_highpage(struct page *to, struct page *from);
>  #define __HAVE_ARCH_COPY_HIGHPAGE
>
> +#ifdef CONFIG_ARCH_HAS_COPY_MC
> +int copy_mc_page(void *to, const void *from);
> +int copy_mc_highpage(struct page *to, struct page *from);
> +#define __HAVE_ARCH_COPY_MC_HIGHPAGE
> +
> +int copy_mc_user_highpage(struct page *to, struct page *from,
> +               unsigned long vaddr, struct vm_area_struct *vma);
> +#define __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
> +#endif
> +
>  struct folio *vma_alloc_zeroed_movable_folio(struct vm_area_struct *vma,
>                                                 unsigned long vaddr);
>  #define vma_alloc_zeroed_movable_folio vma_alloc_zeroed_movable_folio
> diff --git a/arch/arm64/lib/Makefile b/arch/arm64/lib/Makefile
> index 29490be2546b..a2fd865b816d 100644
> --- a/arch/arm64/lib/Makefile
> +++ b/arch/arm64/lib/Makefile
> @@ -15,6 +15,8 @@ endif
>
>  lib-$(CONFIG_ARCH_HAS_UACCESS_FLUSHCACHE) +=3D uaccess_flushcache.o
>
> +lib-$(CONFIG_ARCH_HAS_COPY_MC) +=3D copy_mc_page.o
> +
>  obj-$(CONFIG_CRC32) +=3D crc32.o
>
>  obj-$(CONFIG_FUNCTION_ERROR_INJECTION) +=3D error-inject.o
> diff --git a/arch/arm64/lib/copy_mc_page.S b/arch/arm64/lib/copy_mc_page.=
S
> new file mode 100644
> index 000000000000..524534d26d86
> --- /dev/null
> +++ b/arch/arm64/lib/copy_mc_page.S
> @@ -0,0 +1,78 @@
> +/* SPDX-License-Identifier: GPL-2.0-only */
> +/*
> + * Copyright (C) 2012 ARM Ltd.
> + */
> +
> +#include <linux/linkage.h>
> +#include <linux/const.h>
> +#include <asm/assembler.h>
> +#include <asm/page.h>
> +#include <asm/cpufeature.h>
> +#include <asm/alternative.h>
> +#include <asm/asm-extable.h>
> +
> +/*
> + * Copy a page from src to dest (both are page aligned) with machine che=
ck
> + *
> + * Parameters:
> + *     x0 - dest
> + *     x1 - src
> + * Returns:
> + *     x0 - Return 0 if copy success, or -EFAULT if anything goes wrong
> + *          while copying.
> + */
> +SYM_FUNC_START(__pi_copy_mc_page)
> +CPY_MC(9998f, ldp      x2, x3, [x1])
> +CPY_MC(9998f, ldp      x4, x5, [x1, #16])
> +CPY_MC(9998f, ldp      x6, x7, [x1, #32])
> +CPY_MC(9998f, ldp      x8, x9, [x1, #48])
> +CPY_MC(9998f, ldp      x10, x11, [x1, #64])
> +CPY_MC(9998f, ldp      x12, x13, [x1, #80])
> +CPY_MC(9998f, ldp      x14, x15, [x1, #96])
> +CPY_MC(9998f, ldp      x16, x17, [x1, #112])
> +
> +       add     x0, x0, #256
> +       add     x1, x1, #128
> +1:
> +       tst     x0, #(PAGE_SIZE - 1)
> +
> +CPY_MC(9998f, stnp     x2, x3, [x0, #-256])
> +CPY_MC(9998f, ldp      x2, x3, [x1])
> +CPY_MC(9998f, stnp     x4, x5, [x0, #16 - 256])
> +CPY_MC(9998f, ldp      x4, x5, [x1, #16])
> +CPY_MC(9998f, stnp     x6, x7, [x0, #32 - 256])
> +CPY_MC(9998f, ldp      x6, x7, [x1, #32])
> +CPY_MC(9998f, stnp     x8, x9, [x0, #48 - 256])
> +CPY_MC(9998f, ldp      x8, x9, [x1, #48])
> +CPY_MC(9998f, stnp     x10, x11, [x0, #64 - 256])
> +CPY_MC(9998f, ldp      x10, x11, [x1, #64])
> +CPY_MC(9998f, stnp     x12, x13, [x0, #80 - 256])
> +CPY_MC(9998f, ldp      x12, x13, [x1, #80])
> +CPY_MC(9998f, stnp     x14, x15, [x0, #96 - 256])
> +CPY_MC(9998f, ldp      x14, x15, [x1, #96])
> +CPY_MC(9998f, stnp     x16, x17, [x0, #112 - 256])
> +CPY_MC(9998f, ldp      x16, x17, [x1, #112])
> +
> +       add     x0, x0, #128
> +       add     x1, x1, #128
> +
> +       b.ne    1b
> +
> +CPY_MC(9998f, stnp     x2, x3, [x0, #-256])
> +CPY_MC(9998f, stnp     x4, x5, [x0, #16 - 256])
> +CPY_MC(9998f, stnp     x6, x7, [x0, #32 - 256])
> +CPY_MC(9998f, stnp     x8, x9, [x0, #48 - 256])
> +CPY_MC(9998f, stnp     x10, x11, [x0, #64 - 256])
> +CPY_MC(9998f, stnp     x12, x13, [x0, #80 - 256])
> +CPY_MC(9998f, stnp     x14, x15, [x0, #96 - 256])
> +CPY_MC(9998f, stnp     x16, x17, [x0, #112 - 256])
> +
> +       mov x0, #0
> +       ret
> +
> +9998:  mov x0, #-EFAULT
> +       ret
> +
> +SYM_FUNC_END(__pi_copy_mc_page)
> +SYM_FUNC_ALIAS(copy_mc_page, __pi_copy_mc_page)
> +EXPORT_SYMBOL(copy_mc_page)
> diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
> index 5018ac03b6bf..2b748e83f6cf 100644
> --- a/arch/arm64/lib/mte.S
> +++ b/arch/arm64/lib/mte.S
> @@ -80,6 +80,33 @@ SYM_FUNC_START(mte_copy_page_tags)
>         ret
>  SYM_FUNC_END(mte_copy_page_tags)
>
> +/*
> + * Copy the tags from the source page to the destination one wiht machin=
e check safe
> + *   x0 - address of the destination page
> + *   x1 - address of the source page
> + * Returns:
> + *   x0 - Return 0 if copy success, or
> + *        -EFAULT if anything goes wrong while copying.
> + */
> +SYM_FUNC_START(mte_copy_mc_page_tags)
> +       mov     x2, x0
> +       mov     x3, x1
> +       multitag_transfer_size x5, x6
> +1:
> +CPY_MC(2f, ldgm        x4, [x3])
> +CPY_MC(2f, stgm        x4, [x2])
> +       add     x2, x2, x5
> +       add     x3, x3, x5
> +       tst     x2, #(PAGE_SIZE - 1)
> +       b.ne    1b
> +
> +       mov x0, #0
> +       ret
> +
> +2:     mov x0, #-EFAULT
> +       ret
> +SYM_FUNC_END(mte_copy_mc_page_tags)
> +
>  /*
>   * Read tags from a user buffer (one tag per byte) and set the correspon=
ding
>   * tags at the given kernel address. Used by PTRACE_POKEMTETAGS.
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index a7bb20055ce0..9765e40cde6c 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -14,6 +14,25 @@
>  #include <asm/cpufeature.h>
>  #include <asm/mte.h>
>
> +static int do_mte(struct page *to, struct page *from, void *kto, void *k=
from, bool mc)
> +{
> +       int ret =3D 0;
> +
> +       if (system_supports_mte() && page_mte_tagged(from)) {
> +               /* It's a new page, shouldn't have been tagged yet */
> +               WARN_ON_ONCE(!try_page_mte_tagging(to));
> +               if (mc)
> +                       ret =3D mte_copy_mc_page_tags(kto, kfrom);
> +               else
> +                       mte_copy_page_tags(kto, kfrom);
> +
> +               if (!ret)
> +                       set_page_mte_tagged(to);
> +       }
> +
> +       return ret;
> +}
> +
>  void copy_highpage(struct page *to, struct page *from)
>  {
>         void *kto =3D page_address(to);
> @@ -24,12 +43,7 @@ void copy_highpage(struct page *to, struct page *from)
>         if (kasan_hw_tags_enabled())
>                 page_kasan_tag_reset(to);
>
> -       if (system_supports_mte() && page_mte_tagged(from)) {
> -               /* It's a new page, shouldn't have been tagged yet */
> -               WARN_ON_ONCE(!try_page_mte_tagging(to));
> -               mte_copy_page_tags(kto, kfrom);
> -               set_page_mte_tagged(to);
> -       }
> +       do_mte(to, from, kto, kfrom, false);
>  }
>  EXPORT_SYMBOL(copy_highpage);
>
> @@ -40,3 +54,43 @@ void copy_user_highpage(struct page *to, struct page *=
from,
>         flush_dcache_page(to);
>  }
>  EXPORT_SYMBOL_GPL(copy_user_highpage);
> +
> +#ifdef CONFIG_ARCH_HAS_COPY_MC
> +/*
> + * Return -EFAULT if anything goes wrong while copying page or mte.
> + */
> +int copy_mc_highpage(struct page *to, struct page *from)
> +{
> +       void *kto =3D page_address(to);
> +       void *kfrom =3D page_address(from);
> +       int ret;
> +
> +       ret =3D copy_mc_page(kto, kfrom);
> +       if (ret)
> +               return -EFAULT;
> +
> +       if (kasan_hw_tags_enabled())
> +               page_kasan_tag_reset(to);
> +
> +       ret =3D do_mte(to, from, kto, kfrom, true);
> +       if (ret)
> +               return -EFAULT;
> +
> +       return 0;
> +}
> +EXPORT_SYMBOL(copy_mc_highpage);
> +
> +int copy_mc_user_highpage(struct page *to, struct page *from,
> +                       unsigned long vaddr, struct vm_area_struct *vma)
> +{
> +       int ret;
> +
> +       ret =3D copy_mc_highpage(to, from);
> +
> +       if (!ret)
> +               flush_dcache_page(to);
> +
> +       return ret;
> +}
> +EXPORT_SYMBOL_GPL(copy_mc_user_highpage);
> +#endif
> diff --git a/arch/arm64/mm/extable.c b/arch/arm64/mm/extable.c
> index 28ec35e3d210..bdc81518d207 100644
> --- a/arch/arm64/mm/extable.c
> +++ b/arch/arm64/mm/extable.c
> @@ -16,7 +16,7 @@ get_ex_fixup(const struct exception_table_entry *ex)
>         return ((unsigned long)&ex->fixup + ex->fixup);
>  }
>
> -static bool ex_handler_uaccess_err_zero(const struct exception_table_ent=
ry *ex,
> +static bool ex_handler_fixup_err_zero(const struct exception_table_entry=
 *ex,
>                                         struct pt_regs *regs)
>  {
>         int reg_err =3D FIELD_GET(EX_DATA_REG_ERR, ex->data);
> @@ -69,7 +69,7 @@ bool fixup_exception(struct pt_regs *regs)
>                 return ex_handler_bpf(ex, regs);
>         case EX_TYPE_UACCESS_ERR_ZERO:
>         case EX_TYPE_KACCESS_ERR_ZERO:
> -               return ex_handler_uaccess_err_zero(ex, regs);
> +               return ex_handler_fixup_err_zero(ex, regs);
>         case EX_TYPE_LOAD_UNALIGNED_ZEROPAD:
>                 return ex_handler_load_unaligned_zeropad(ex, regs);
>         }
> @@ -87,7 +87,8 @@ bool fixup_exception_mc(struct pt_regs *regs)
>
>         switch (ex->type) {
>         case EX_TYPE_UACCESS_ERR_ZERO:
> -               return ex_handler_uaccess_err_zero(ex, regs);
> +       case EX_TYPE_COPY_MC_PAGE_ERR_ZERO:
> +               return ex_handler_fixup_err_zero(ex, regs);
>         }
>
>         return false;
> diff --git a/include/linux/highmem.h b/include/linux/highmem.h
> index c5ca1a1fc4f5..a42470ca42f2 100644
> --- a/include/linux/highmem.h
> +++ b/include/linux/highmem.h
> @@ -332,6 +332,7 @@ static inline void copy_highpage(struct page *to, str=
uct page *from)
>  #endif
>
>  #ifdef copy_mc_to_kernel
> +#ifndef __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
>  /*
>   * If architecture supports machine check exception handling, define the
>   * #MC versions of copy_user_highpage and copy_highpage. They copy a mem=
ory
> @@ -354,7 +355,9 @@ static inline int copy_mc_user_highpage(struct page *=
to, struct page *from,
>
>         return ret ? -EFAULT : 0;
>  }
> +#endif
>
> +#ifndef __HAVE_ARCH_COPY_MC_HIGHPAGE
>  static inline int copy_mc_highpage(struct page *to, struct page *from)
>  {
>         unsigned long ret;
> @@ -370,20 +373,25 @@ static inline int copy_mc_highpage(struct page *to,=
 struct page *from)
>
>         return ret ? -EFAULT : 0;
>  }
> +#endif
>  #else
> +#ifndef __HAVE_ARCH_COPY_MC_USER_HIGHPAGE
>  static inline int copy_mc_user_highpage(struct page *to, struct page *fr=
om,
>                                         unsigned long vaddr, struct vm_ar=
ea_struct *vma)
>  {
>         copy_user_highpage(to, from, vaddr, vma);
>         return 0;
>  }
> +#endif
>
> +#ifndef __HAVE_ARCH_COPY_MC_HIGHPAGE
>  static inline int copy_mc_highpage(struct page *to, struct page *from)
>  {
>         copy_highpage(to, from);
>         return 0;
>  }
>  #endif
> +#endif
>
>  static inline void memcpy_page(struct page *dst_page, size_t dst_off,
>                                struct page *src_page, size_t src_off,
> --
> 2.25.1
>

+Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf-mkSJ%2B8kMPi%2BmWOjtYzD%2BFAKi_ciiHt%3DyrbksY9W-KA%40m=
ail.gmail.com.
