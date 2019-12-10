Return-Path: <kasan-dev+bncBCY5VBNX2EDRBZWNXXXQKGQED2HFBJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CD121183A7
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 10:35:34 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id 140sf1462663ljj.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 01:35:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575970534; cv=pass;
        d=google.com; s=arc-20160816;
        b=iLNxhb9489EyUgM8C9Icy26yg79TUL1PRzfLe86oTjyAKW5x1RdmdNxOBPVmtTyUPp
         S9wjE274Te5jpSk+cqwzV1/TdDHL6UMFpbmaGca0Upz8vxzA2YtItsdjK0+zMFFwPlTv
         guvw0LSBRJ1rF3iy6rb6cRriLCUQm9GC4WtsCyHk5b9rNzCFannpA6Q5grVkOT4kswyj
         tdKpsA5OQuYMlYaoPuzMMIzqWhR5+m6jR9vXd70dg1CY8a9xeOr8di9qQYDUxPRWoz/Z
         z1+Y7ArrIPp/19Zd+SvNItrhVjKeiKCXL3stilmG6OPwLya5Pv1aNLaLtl5BqxEvF/6u
         v3Dw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:to:subject
         :sender:dkim-signature:dkim-signature;
        bh=ZF75aBR0VG5MnlsNHFfCktuoRZyxT3892iSMfXuBjXw=;
        b=XIJNG4CuPrDoipfyCEgMAszD+eosdWkatTameF3lvepoy9+3XmvAxPKmyIzAM2fgo5
         C5ChJEWD0ddK8DxEbGKb0u1OdOFyqKDKLHX8C0eR7ej/n6BGTHu1QoYxwTLrYTHUWdTZ
         Q65V3mukW16VBF978y8QBHTEOF53biG8lxCSyCzuOrNUO3IrqPJlhRUt+6BDUldO2bzI
         8R3ABizYTNMJrYaxErJ2vTbhKUpsX6WZ5d7F5ISLdUbwZTqbYKCBFI5nG2JuQe0DaZGx
         TYu/9nXliTdueaqIK9CxfXnPQV5AbCXIWcWC/qyBJcis9eaqqQDnkYnFNgGgynYXkl2U
         1qbw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ABNDcXBa;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZF75aBR0VG5MnlsNHFfCktuoRZyxT3892iSMfXuBjXw=;
        b=WTOWRiaDSgVr3Bc1BWyEKHg1yoDPevCW7KWnlx6wXvBR53y6uC2R47us2d6U7rd3KL
         ebU5Kp5e1g7QvR40EkYcMloSw9DzwAt9sff3S6fWHESKa8rTSxAF4xzPO8LeKmuxJWCE
         Qqm5YrRLSPxKufyxVLacCO8FX8U7l34mxbZc+rv/QnOz/msVsok060fdZ22Zl2oqZmsU
         JD5NCQdeVYRm7agOvRAR6KhD+hNcpYG0uJK/gWHrt9f6u8jf9O3rP+s/fr9cIPNjI1m4
         SYx87YfVryIQlwI+b//3srULNew3Kap/oSH3aF6ut8f5b7TrYoO269jFihZzGh4EhM9S
         a3qw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:references:from:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZF75aBR0VG5MnlsNHFfCktuoRZyxT3892iSMfXuBjXw=;
        b=tmBj3jPv15fNayKNQ2Q6zPnmSRBePSrJu83825VdQYs0roQz93Rd2ufLO0XkVTvYwX
         pv3/hPq35nGhFcpn5Zi6kRn/U/Y2cQLUWTLL3+wyUckYzItuMssM5MDoyiK8OKVKT064
         CWSHRul+AARbuh8x1OyvVm/6iE7U7MttlmMSxHRSAcSfCn2ZWDhRktq5GokMENJuV8sl
         f9T1O2gZFGRMi5AlD2pkOavE6ZQWyv66nvIBJQ5CuHZPj7MsgqIl9BIHximpjLbQL2Eo
         HKrETMGUY0+YmVhTnvSLQDdY7L7j304MHS+budDq2iKAZak2BJGv1xU0v5iUQMZUSI62
         u/KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZF75aBR0VG5MnlsNHFfCktuoRZyxT3892iSMfXuBjXw=;
        b=icOwSGDyNqg96XJh6uGKB5fvYBq7ZUdMXsLyEjAuzGAJeFTZSSnsydddrNkn1IbLDa
         xd7XKT/LAo08YY3wfKPcosuATP/4KZlt4vWLh6Ea5xCRNWkqNH4rribX6GpirbkDheZs
         NW51ApStq7zRCXridzD+0wNjnL25BWK0ahpvdI2LNQtC2X2DIx4b+9SkEXsiuWFUKL18
         pKf2rJyfRClyDxp+XXBNpg+WKLlpa0EhWOBi3mu0Ui75VCsPWbQDOp99bVQa3/GsProd
         nmVLmuIC9izMyvms2DRq/7XXSUsZ59TTRlRJHgYnqqCDm9yeUMq+N5JCqqhm+0YXfiaq
         kL3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUUUboVHX4ANw7R9yOw19FZVmXQUSU0zR22JNfZQWg3pWjFeb/k
	tsbr85gnRrXnEfg3QNcZE9U=
X-Google-Smtp-Source: APXvYqxQTzQqXIPswyOW32k3MXrvqODGG/JNme0PiTfuzoxzg7zPwruk/ms6mRIAAwwfEjVv9h2/cg==
X-Received: by 2002:ac2:544f:: with SMTP id d15mr19525206lfn.126.1575970534197;
        Tue, 10 Dec 2019 01:35:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9bc3:: with SMTP id w3ls2345788ljj.6.gmail; Tue, 10 Dec
 2019 01:35:33 -0800 (PST)
X-Received: by 2002:a2e:8416:: with SMTP id z22mr18987318ljg.162.1575970533536;
        Tue, 10 Dec 2019 01:35:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575970533; cv=none;
        d=google.com; s=arc-20160816;
        b=xMsge6yZN3htrYXEuP/TyCTmCovzIhd13sZrtkKxA1qnSH7h9Cx4DZDHSod5p2HjSR
         8VdhjKKSXu4V3be/Lv4AfzbsXF41kXGWFUE/WEyJC/nK3U6gdalLvXXzaVvVNs+2LlNG
         qZJpQa1OFWXU4Vx10qWEvLkej3YDGtLkdECBVpTOdrAmYZO8HiLjABQS46Kmc3huYsp2
         oqRn66gBzsJNhu2g6ENMHFBwYZZxWekm6fCYpYgFDFAi3KLu7hX7V8B4vEFLbsZU8tWI
         IepP97zQXGUU+8g2xpPM8e35O6XJbf7T6cxjuWDsku7e8glGawCyocMyaJsPI5Y2OZ66
         VvRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=sPqiW8fjJ6bClKJe5WkINQ65vkoeIkKhHU7yZhPYmGg=;
        b=G6veCKGidbdCm8HW7V8z/FGNdleJZ5CxCxDbfsV8iFqHcU/IK0IvnYqoEo6qRoCEeE
         HmElpIBGurGekJveW3rkjqDMRi3/aDEW/eY7ql5wWM5sw4PV61bNk0eIHwsEnED+Awqy
         8d35+zkjYcwS40jfkWgPFPGaepwOfNmVOxduj+wdVXOAM/aYUx/2t3fNkO4ynHL7WH64
         SkhVptZV7fVgmyfHULpZ+XdHAoZaUwLcd+4L+R9Kp1FuP7A/yUGkjNiqMjcgb2FiTjct
         oprzviTVsr66skDRVjCg4z2Qflxakdm5JhWREt7fDhfUDauNqKpEUf7UZTGSCzqXXsj1
         VGPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=ABNDcXBa;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x143.google.com (mail-lf1-x143.google.com. [2a00:1450:4864:20::143])
        by gmr-mx.google.com with ESMTPS id b5si129518ljo.0.2019.12.10.01.35.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Dec 2019 01:35:33 -0800 (PST)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::143 as permitted sender) client-ip=2a00:1450:4864:20::143;
Received: by mail-lf1-x143.google.com with SMTP id i23so673857lfo.7
        for <kasan-dev@googlegroups.com>; Tue, 10 Dec 2019 01:35:33 -0800 (PST)
X-Received: by 2002:ac2:4316:: with SMTP id l22mr2852226lfh.115.1575970533025;
        Tue, 10 Dec 2019 01:35:33 -0800 (PST)
Received: from [192.168.68.106] ([193.119.54.228])
        by smtp.gmail.com with ESMTPSA id 140sm1193677lfk.78.2019.12.10.01.35.27
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Dec 2019 01:35:32 -0800 (PST)
Subject: Re: [PATCH v2 1/4] mm: define MAX_PTRS_PER_{PTE,PMD,PUD}
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org,
 linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-2-dja@axtens.net>
From: Balbir Singh <bsingharora@gmail.com>
Message-ID: <50ac061a-caa9-ed4e-c9a4-1f86bb0552bd@gmail.com>
Date: Tue, 10 Dec 2019 20:35:22 +1100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191210044714.27265-2-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=ABNDcXBa;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::143
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
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



On 10/12/19 3:47 pm, Daniel Axtens wrote:
> powerpc has boot-time configurable PTRS_PER_PTE, PMD and PUD. The
> values are selected based on the MMU under which the kernel is
> booted. This is much like how 4 vs 5-level paging on x86_64 leads to
> boot-time configurable PTRS_PER_P4D.
> 
> So far, this hasn't leaked out of arch/powerpc. But with KASAN, we
> have static arrays based on PTRS_PER_*, so for powerpc support must
> provide constant upper bounds for generic code.
> 
> Define MAX_PTRS_PER_{PTE,PMD,PUD} for this purpose.
> 
> I have configured these constants:
>  - in asm-generic headers
>  - on arches that implement KASAN: x86, s390, arm64, xtensa and powerpc
> 
> I haven't wired up any other arches just yet - there is no user of
> the constants outside of the KASAN code I add in the next patch, so
> missing the constants on arches that don't support KASAN shouldn't
> break anything.

I would suggest limiting this to powerpc for now and use

#ifndef MAX_PTRS_PER_PUD
#define MAX_PTRS_PER_PUD	PTRS_PER_PUD
#endif

style code in KASAN. It just keeps the change surface to a limited
value, till other arch's see value in migrating to support it.

> 
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>
> ---
>  arch/arm64/include/asm/pgtable-hwdef.h       | 3 +++
>  arch/powerpc/include/asm/book3s/64/hash.h    | 4 ++++
>  arch/powerpc/include/asm/book3s/64/pgtable.h | 7 +++++++
>  arch/powerpc/include/asm/book3s/64/radix.h   | 5 +++++
>  arch/s390/include/asm/pgtable.h              | 3 +++
>  arch/x86/include/asm/pgtable_types.h         | 5 +++++
>  arch/xtensa/include/asm/pgtable.h            | 1 +
>  include/asm-generic/pgtable-nop4d-hack.h     | 9 +++++----
>  include/asm-generic/pgtable-nopmd.h          | 9 +++++----
>  include/asm-generic/pgtable-nopud.h          | 9 +++++----
>  10 files changed, 43 insertions(+), 12 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
> index d9fbd433cc17..485e1f3c5c6f 100644
> --- a/arch/arm64/include/asm/pgtable-hwdef.h
> +++ b/arch/arm64/include/asm/pgtable-hwdef.h
> @@ -41,6 +41,7 @@
>  #define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
>  
>  #define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
> +#define MAX_PTRS_PER_PTE	PTRS_PER_PTE
>  
>  /*
>   * PMD_SHIFT determines the size a level 2 page table entry can map.
> @@ -50,6 +51,7 @@
>  #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
>  #define PMD_MASK		(~(PMD_SIZE-1))
>  #define PTRS_PER_PMD		PTRS_PER_PTE
> +#define MAX_PTRS_PER_PMD	PTRS_PER_PMD
>  #endif
>  
>  /*
> @@ -60,6 +62,7 @@
>  #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
>  #define PUD_MASK		(~(PUD_SIZE-1))
>  #define PTRS_PER_PUD		PTRS_PER_PTE
> +#define MAX_PTRS_PER_PUD	PTRS_PER_PUD
>  #endif
>  
>  /*
> diff --git a/arch/powerpc/include/asm/book3s/64/hash.h b/arch/powerpc/include/asm/book3s/64/hash.h
> index 2781ebf6add4..fce329b8452e 100644
> --- a/arch/powerpc/include/asm/book3s/64/hash.h
> +++ b/arch/powerpc/include/asm/book3s/64/hash.h
> @@ -18,6 +18,10 @@
>  #include <asm/book3s/64/hash-4k.h>
>  #endif
>  
> +#define H_PTRS_PER_PTE		(1 << H_PTE_INDEX_SIZE)
> +#define H_PTRS_PER_PMD		(1 << H_PMD_INDEX_SIZE)
> +#define H_PTRS_PER_PUD		(1 << H_PUD_INDEX_SIZE)
> +
>  /* Bits to set in a PMD/PUD/PGD entry valid bit*/
>  #define HASH_PMD_VAL_BITS		(0x8000000000000000UL)
>  #define HASH_PUD_VAL_BITS		(0x8000000000000000UL)
> diff --git a/arch/powerpc/include/asm/book3s/64/pgtable.h b/arch/powerpc/include/asm/book3s/64/pgtable.h
> index b01624e5c467..209817235a44 100644
> --- a/arch/powerpc/include/asm/book3s/64/pgtable.h
> +++ b/arch/powerpc/include/asm/book3s/64/pgtable.h
> @@ -231,6 +231,13 @@ extern unsigned long __pmd_frag_size_shift;
>  #define PTRS_PER_PUD	(1 << PUD_INDEX_SIZE)
>  #define PTRS_PER_PGD	(1 << PGD_INDEX_SIZE)
>  
> +#define MAX_PTRS_PER_PTE	((H_PTRS_PER_PTE > R_PTRS_PER_PTE) ? \
> +				  H_PTRS_PER_PTE : R_PTRS_PER_PTE)
> +#define MAX_PTRS_PER_PMD	((H_PTRS_PER_PMD > R_PTRS_PER_PMD) ? \
> +				  H_PTRS_PER_PMD : R_PTRS_PER_PMD)
> +#define MAX_PTRS_PER_PUD	((H_PTRS_PER_PUD > R_PTRS_PER_PUD) ? \
> +				  H_PTRS_PER_PUD : R_PTRS_PER_PUD)
> +

How about reusing max

#define MAX_PTRS_PER_PTE  max(H_PTRS_PER_PTE, R_PTRS_PER_PTE)
#define MAX_PTRS_PER_PMD  max(H_PTRS_PER_PMD, R_PTRS_PER_PMD)
#define MAX_PTRS_PER_PUD  max(H_PTRS_PER_PUD, R_PTRS_PER_PUD)

Balbir Singh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/50ac061a-caa9-ed4e-c9a4-1f86bb0552bd%40gmail.com.
