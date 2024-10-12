Return-Path: <kasan-dev+bncBAABB55XU64AMGQESHKS75Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B1FE99B009
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 04:16:25 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7b11316a8fesf492171185a.1
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Oct 2024 19:16:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728699384; cv=pass;
        d=google.com; s=arc-20240605;
        b=GzgEmWbepHrDuf+HIssZrCjvwkn10i8Elrd6Jr7ltR/1cbZ1PKB0Z/MbT1Q04364KW
         IL+ztj/6OR6kY4F01Jet0KZIO8Tkr8jFm4Ky3yxGB2+WKPJ9T0BXm02fVnQ9y24i25C7
         yFYcooQ6BgigxR9s4LO2rq3azi9qynRF1vtMfT7Jvy1mkUK7vbfYaQyiGwL4ha+GnXzb
         A5U19ZTUs3UA4+yINQliWE+x3hRKWk58WxUnKwXGEglXv4kuh7X7vSRf3whsEwBtuaOf
         B4nXZ4T7EYdG3W52dVnNR9QYXXpohjIBsT68CcpwwioTAb4NJDMDMsVb5quejeqe/Gzy
         YmbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UcqPS6ULvqo4Ludgx9+cHhKJOtlxnvRrKf7+OcZ0ySQ=;
        fh=RuJVK3/SyEhwdXPjiBvlixLTk9VX+VPrn/a+N6Tm/Q4=;
        b=NqPfA77HFtPcGe7so6Vnv05FFBuGJkPzpG8oYFdUOIyA6XWaw6PFnrqOAW/Pwj6YAW
         g432OybiAmiDkj0HTq3BvOJ2SpECrCrv2Vk2t28yoVaXEFVuMuyj+VV11mJKCO5kVBdK
         WBRW9+EquQBPF/A2i5D81dp49Y5pXmEDupUpeSfX62e3xicjIVG8W7iUYpODYXdg5FkA
         D5Rmz/BMhMrxG3qSlKCOWafklLTByQBUvf9kDKWfaA58xhx+81imuE/Gctz/w8MBCBR3
         rBKIvzJ7Q5v5LqT+vlZM4FAshNu1v38c0d13YEdrYFUEZ3XzWoGb3278ZO5fjClyuX5h
         rSFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PMIcQXZX;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728699384; x=1729304184; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UcqPS6ULvqo4Ludgx9+cHhKJOtlxnvRrKf7+OcZ0ySQ=;
        b=FnBCexmLk3vGESDksXpL0NZsI9EbOtrhTXykoyVbu07xzPN6pbS2nkAXzgYKrom4Si
         mwnyC7D5dYCWVfJ15kJwV3xCIAb8p0G7YLTbH/Iq0SCgeiean6fUwqxbXNC43WNQTD8F
         rwUo7KIiwRt0oqrvOSf8VxGj119B7RJfsJAPleDpfoBB9gYLcgjDrxDM93HJ/GqvJsAt
         Dw8NsmkW5RIR3u5XmWS+3Z01ooR0SLShKcbDwTSVWdx2zBRzZDwZvs4FRyejRuAfdEYV
         1ywWtkdetVu8vNZbY3FsAWLTwB0hUKz9aacJhcBkWmn+NMGE0DV2+5/0ElxeQ82v5H+H
         yLIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728699384; x=1729304184;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UcqPS6ULvqo4Ludgx9+cHhKJOtlxnvRrKf7+OcZ0ySQ=;
        b=klJdGqBYoo4sV0YvG1ZAxHMRWHgBlczQnlJQgmSD/V6y/hec0ujZ2Mq3rn/URO9xmM
         xR4eJlZmdyZnk36cWqOu2k+INQdbfr1UkAs3VfNGuOiqYCZGkjfp0dX6n14pZUWhUm2s
         arWL6B0UVTtuEXQZQHsgP6DnpF8BzKKh785xmT1qbre9Vw3vbJJgxh3CE4fNxLFvCkNt
         gFqlMApcdQJPOK/HXGHRj9hJ1JJW3tfPGijnMDc6Bb+6KGsrPGqSWpX6kBB1TpOx5YrG
         Pi/TsRcQIqfs9czGp5z80MEKcHCMEcIAAcEzr9n5Jaq2cP6+TbjPqnXEbGzXNrnbrKmA
         5kOw==
X-Forwarded-Encrypted: i=2; AJvYcCUt6xBrOlkWP1zeNWeZ/3GZSe8d0jA3BmmXPhtahZNBPwcbYBJFyiIBw+Z8WDPpAWiWpVRgNA==@lfdr.de
X-Gm-Message-State: AOJu0YxJai3oFw+sF/mhvBOQLW33C6H2UtUJW1YOcp555Zud3MJB7bAw
	kcTx3Efb99qRnZ3AGN99i/Vv7NIyrr+MBC8UAlN4R5lgGk0DxN7F
X-Google-Smtp-Source: AGHT+IE8e82Rgzvk1ZHKEMU/gcdC9NvLEn6FCf2by3Um+M40Xk5K/1upQt7jJT+3NSLsPhycFju25w==
X-Received: by 2002:a05:6214:5f07:b0:6c7:5e3a:7855 with SMTP id 6a1803df08f44-6cbf0006078mr52178436d6.39.1728699383803;
        Fri, 11 Oct 2024 19:16:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:c8d:b0:6cb:c91d:f3d2 with SMTP id
 6a1803df08f44-6cbe54926a0ls42448726d6.0.-pod-prod-09-us; Fri, 11 Oct 2024
 19:16:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3g914cJVbwV6xCTLTn+AN5QH5S+oN9iHv4fmkRJ0Z9NoQhDK9mDVN6NhWHCfagt4XXQRZzJFTrZU=@googlegroups.com
X-Received: by 2002:a05:6214:5e8d:b0:6cb:f6de:3d12 with SMTP id 6a1803df08f44-6cbf6de4035mr39850976d6.36.1728699382807;
        Fri, 11 Oct 2024 19:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728699382; cv=none;
        d=google.com; s=arc-20240605;
        b=GCff1sENPavDQe7AYB5KVh05uHb5wvLLTQW/x8cZK79B3sIyRDrEz0b8jAr4FhTkfP
         2gJbfD0WLzWUIUzFqotfYNNLG3smQ3ttc+wBf75L3bszYQkoLRm5eErwmJipakQoubCg
         1KJNivrCZJ5uVWTB+jo5bFKEGSIxwpt7jiPzh55LBynQEVsv+KcnCEHzmfuCZ6MLf6Qs
         sx4t5vX2MSLwwgiCZl6IzKn13cElZ7cMyXsNK2G5F1UgxxEWFSNSDAW0fmlcl0C7b1az
         aFzyVmyMe3WC8K2CN3Cr/Xd6IcqxK1MQ4Uyfx/voWmBwfblmMSKhMdUnbAG6JeQR7csX
         sPJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=drHMGJm5ahLi/V0BeUnf6hUOITulM1J/wwIzvUYv1Dc=;
        fh=ca+Oxpvw4nFtVxyaeyDLLFg6mVUjOvPh3IligPRXpUk=;
        b=kdRYX7T7ViOfq7WVA7RTsBj+BlJ7MUSKsEwKem4UuYMVRYkjtKTEw6yaIgo29CAfYH
         neIgEDFplp6plc3VxI3ag1SefVAWPpMVDe/4CsqbTzeyQ5CpuxTaaMP5jE7kicxFWk3r
         QlkFBE0cPkN7ddJog4NGoSY0VXLpcl1C5i/ZirKeHR9AVEKnKCX9rDbo55pSH32ZnwPA
         z6bfrMnUs/YDcU8pDaRB4l+m7rF0eMkc0yfJqQ/wi9x8mxgxI+vtBFLadQxtWeZpDVU5
         7uza0j/lp6x8u4Lv0Cf4+rTIJUlXa4/fiMR1CwFY9cmbTYuTVZcbzqXpH3tTQGyjB1JO
         gRbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=PMIcQXZX;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6cbe867c3cbsi1923406d6.6.2024.10.11.19.16.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 11 Oct 2024 19:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 0C75F5C5F73
	for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 02:16:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CA58DC4CED1
	for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 02:16:21 +0000 (UTC)
Received: by mail-ed1-f46.google.com with SMTP id 4fb4d7f45d1cf-5c42f406e29so3115401a12.2
        for <kasan-dev@googlegroups.com>; Fri, 11 Oct 2024 19:16:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXeqCrb4D3psp8ZdiizWNvv5eKebEI7rcIK0aP7k9JxDraGCBtoWzmvG/MdeYbxN7vJX+O0NQ1UhAM=@googlegroups.com
X-Received: by 2002:a17:907:940c:b0:a8d:29b7:ecf3 with SMTP id
 a640c23a62f3a-a99b930e9d1mr358486566b.13.1728699380354; Fri, 11 Oct 2024
 19:16:20 -0700 (PDT)
MIME-Version: 1.0
References: <20241010035048.3422527-1-maobibo@loongson.cn> <20241010035048.3422527-5-maobibo@loongson.cn>
In-Reply-To: <20241010035048.3422527-5-maobibo@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 12 Oct 2024 10:16:07 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5DvHcS+apFthMWNNqvvq+VMu--6bcuyGzdMz66K8Bd=g@mail.gmail.com>
Message-ID: <CAAhV-H5DvHcS+apFthMWNNqvvq+VMu--6bcuyGzdMz66K8Bd=g@mail.gmail.com>
Subject: Re: [PATCH 4/4] LoongArch: Use atomic operation with set_pte and
 pte_clear function
To: Bibo Mao <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=PMIcQXZX;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
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

On Thu, Oct 10, 2024 at 11:50=E2=80=AFAM Bibo Mao <maobibo@loongson.cn> wro=
te:
>
> For kernel space area on LoongArch system, both two consecutive page
> table entries should be enabled with PAGE_GLOBAL bit. So with function
> set_pte() and pte_clear(), pte buddy entry is checked and set besides
> its own pte entry. However it is not atomic operation to set both two
> pte entries, there is problem with test_vmalloc test case.
>
> With previous patch, all page table entries are set with PAGE_GLOBAL
> bit at beginning. Only its own pte entry need update with function
> set_pte() and pte_clear(), nothing to do with buddy pte entry.
>
> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> ---
>  arch/loongarch/include/asm/pgtable.h | 44 ++++++++++------------------
>  1 file changed, 15 insertions(+), 29 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/pgtable.h b/arch/loongarch/includ=
e/asm/pgtable.h
> index 22e3a8f96213..4be3f0dbecda 100644
> --- a/arch/loongarch/include/asm/pgtable.h
> +++ b/arch/loongarch/include/asm/pgtable.h
> @@ -325,40 +325,26 @@ extern void paging_init(void);
>  static inline void set_pte(pte_t *ptep, pte_t pteval)
>  {
>         WRITE_ONCE(*ptep, pteval);
> +}
>
> -       if (pte_val(pteval) & _PAGE_GLOBAL) {
> -               pte_t *buddy =3D ptep_buddy(ptep);
> -               /*
> -                * Make sure the buddy is global too (if it's !none,
> -                * it better already be global)
> -                */
> -               if (pte_none(ptep_get(buddy))) {
> -#ifdef CONFIG_SMP
> -                       /*
> -                        * For SMP, multiple CPUs can race, so we need
> -                        * to do this atomically.
> -                        */
> -                       __asm__ __volatile__(
> -                       __AMOR "$zero, %[global], %[buddy] \n"
> -                       : [buddy] "+ZB" (buddy->pte)
> -                       : [global] "r" (_PAGE_GLOBAL)
> -                       : "memory");
> -
> -                       DBAR(0b11000); /* o_wrw =3D 0b11000 */
> -#else /* !CONFIG_SMP */
> -                       WRITE_ONCE(*buddy, __pte(pte_val(ptep_get(buddy))=
 | _PAGE_GLOBAL));
> -#endif /* CONFIG_SMP */
> -               }
> -       }
> +static inline unsigned long __ptep_get_and_clear(pte_t *ptep)
> +{
> +       return atomic64_fetch_and(_PAGE_GLOBAL, (atomic64_t *)&pte_val(*p=
tep));
>  }
>
>  static inline void pte_clear(struct mm_struct *mm, unsigned long addr, p=
te_t *ptep)
>  {
> -       /* Preserve global status for the pair */
> -       if (pte_val(ptep_get(ptep_buddy(ptep))) & _PAGE_GLOBAL)
> -               set_pte(ptep, __pte(_PAGE_GLOBAL));
> -       else
> -               set_pte(ptep, __pte(0));
> +       __ptep_get_and_clear(ptep);
With the first patch, a kernel pte always take _PAGE_GLOBAL, so we
don't need an expensive atomic operation, just
"set_pte(pte_val(ptep_get(ptep)) & _PAGE_GLOBAL)" is OK here. And then
we don't need a custom ptep_get_and_clear().


Huacai

> +}
> +
> +#define __HAVE_ARCH_PTEP_GET_AND_CLEAR
> +static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
> +                                       unsigned long addr, pte_t *ptep)
> +{
> +       unsigned long val;
> +
> +       val =3D __ptep_get_and_clear(ptep);
> +       return __pte(val);
>  }
>
>  #define PGD_T_LOG2     (__builtin_ffs(sizeof(pgd_t)) - 1)
> --
> 2.39.3
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H5DvHcS%2BapFthMWNNqvvq%2BVMu--6bcuyGzdMz66K8Bd%3Dg%40mail.=
gmail.com.
