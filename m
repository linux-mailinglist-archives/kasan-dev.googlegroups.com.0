Return-Path: <kasan-dev+bncBDN7FYMXXEORBUMD4O7QMGQEYUS5ZNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C5CB9A85541
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 09:16:34 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id 5614622812f47-3feb24cea56sf1281259b6e.0
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 00:16:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744355793; cv=pass;
        d=google.com; s=arc-20240605;
        b=cBvT0uHjuEjAgZZDHzqsVTFe7MDKCyAIXo1z3WLD0q8/2BL5EKORdk1oJBqOdsQn3n
         1J+3TVmvqShqpdnN02v9RDS7RfOXZB7DiwerMHKDxIifh97fw/tVGB3+Er9iohzcQQHe
         kB0wHBetjQW5dO3+njYte3a/H7iZ2dz7o4U6tCXaN0XCbJQRiR8pFJeMiVH9cllPyppO
         brnjcaAIwU4Wfues64qEGa81RoTGMho5fvjfctCwmhZAdf/9RzOKeFyIscjZZFE56xxx
         ts02BD1wuphaDNz17pBWCux7xqG8ex3kj+RFPV45af84CYuzIfJez1YtEb9eK5y22XKz
         ME4g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:to:from
         :subject:cc:message-id:date:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=bXgkTdMd5vdkQYVAewB7hsevas3cmTDiUNGv3bDY75I=;
        fh=ZWxthH1MobX2n8JNxhfM2cN/+vCV4EDqLMNvQEsu4Vw=;
        b=D89MqUehv8dqKAfvvaIVI8jWW5IPUmsphwn7U7aG6TyW5/QnONS5aYBJcwhUkRhFYP
         ALZ2wRyAirJGiwUnupJ5Y/MUSnpGb//x76YoI4NeTJI2fGfrB/t7/O2Tb2GMw40cpn8Y
         CPE0DhJ1JXu0XRZMdWxaEGfzGyTfgkE2kGFfVkaPrRTpnY1DEU+a9bbf4BAtC/5nAVgA
         SZBx5aMPqfxCmJABbKg14hPYwFsHI8Ff3gBSKrUnS/+9dk2zYJ0d867QXdjTAYeinQX5
         Ury2HRjKNVhMhPwnRI5GepY+XsfzmkahBN3NAvZaYD/TTLpFZyAcksat6yIMZA3cykkF
         FB7w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DRLq9kVv;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744355793; x=1744960593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:to:from:subject:cc
         :message-id:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bXgkTdMd5vdkQYVAewB7hsevas3cmTDiUNGv3bDY75I=;
        b=Q2cAzxJp3bFGt+MDe9GIjC5oc33ORj03Ci9lG623l7t5H0UKcHGp9FKu6wj4Zij8oD
         aY/EhLBPc0lfEDylpawj73jDPggLzRBaKPVAl+ThEkV7s254HNFCLHKMIlKlLtvKPlbn
         k+WuR714PrWMoghrG9M04xzD8K7bBxTkT+MhBVnzGZAtdWmz7iNbDM0X60uBeoCFUlxa
         1xpIz1XVSwvh37/UFt0PDrEX+k5xF4JesT86tkK85KcY4R0mSskPpuSeB8A+iwIQgjIY
         aVAuRGzJj1Z76Z3LHNYcpWy8WPAd4uiITzg6J0GhjWIuGKvdvdpaIMNq+ne/eYFx4dkt
         F2ig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744355793; x=1744960593; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:to:from:subject:cc
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bXgkTdMd5vdkQYVAewB7hsevas3cmTDiUNGv3bDY75I=;
        b=OGsSFEhgCUuyVan9zgHdKa9rs8pvsmyEe4pcyhC6CNhKWKcpxUzU1TUdkpXpcndCrc
         H7uOUc22GKOIEzgMeKd2TFJFaTEe4P7hXu9p/LqRfkTTM0SjJDthCy824fUyG2nakHPO
         TBcBN7EJ3cHpH98H2kjzDS0GNyg++9Lr0gQiaUeCTNGsjHRq8eIZ8Y1ytovQu51iFnYb
         J4SoNOO6UHXmHzultgfZgo627SuXY1AvqjXQxPS4Tt/lgZ/+dLwTziP81NsthSAbr6kn
         ImX8hAY3qOPIvaF39k0wfKLXgyc/WgJ7fA+zZuQX71fb0tQ9YN72DHkDS+m2DZElnXtM
         JTFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744355793; x=1744960593;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:to:from:subject:cc:message-id:date:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bXgkTdMd5vdkQYVAewB7hsevas3cmTDiUNGv3bDY75I=;
        b=ggfpgixn6ihPWSbkGVzwBFZOs/ZHJ3JrTuk5oPVl3O7lSUyG36MuNDNMvuKj/f1I5A
         KDMF3xN4Craocy3dq17/D6mbqZbnSlalpbocYJXvAGG+luO8r9J//4yjPcsukoM+rIl/
         vLf93J/ea1x4AZfAZPHdG16XwkJejddQU1sn01VJhx1tc7hW6l9Q6UtJC1Z4IBt8ovMc
         70+T8Ao4Hs3f9XlzlGD1S/QRjA0fQ5O1z7GMvszw8BdLPdFTyh7v33kkFYV2glKDkZWE
         NL6vAwSGD1Mak66f6BKserlvvA5NvxOtkr72ajXEUl2cPvgIvLqrZY3Gr8HH3uJ7vZ0h
         03Vw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJj451BNtRoF6jKrJ8vkcBHBZ3x6UmDpEoaTFbITq8xYOC+cLNWdqDTHncNnR9Z7VkB34Zxg==@lfdr.de
X-Gm-Message-State: AOJu0YyfOuhiYOZS1AzdkpZf7xhrfrZT67OkFMg+9roEBA4HLo6eTs91
	GWQQO4H1x/RzvGwEeXGC3ZriB5KlMELAW5v8Ulxe1WksrHTqcko/
X-Google-Smtp-Source: AGHT+IGfojajl3yd9TzfjGXLDGlM7Cya38StmoUjhyjiv6FKmzmCjIoUxtWsxpey7W8/hcT0Gm96tg==
X-Received: by 2002:a05:6808:1528:b0:3fa:82f6:f768 with SMTP id 5614622812f47-400850d5cefmr761106b6e.27.1744355793328;
        Fri, 11 Apr 2025 00:16:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJhk523tNrDKsLSzb0ZS64bE/2gxIxVFklXrmMSsykgxg==
Received: by 2002:a05:6870:ad8b:b0:2c1:8546:7864 with SMTP id
 586e51a60fabf-2d0ad7e4238ls720402fac.2.-pod-prod-07-us; Fri, 11 Apr 2025
 00:16:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCURZP7cSKQiLLQU28/qyY0bN2+ZPL6f92hwBXlo35J2QCaFGwh6Kx3sPKvGRiWhNnNL3NzssRegSmg=@googlegroups.com
X-Received: by 2002:a05:6830:258a:b0:72b:80b8:8c67 with SMTP id 46e09a7af769-72e863f912fmr1006967a34.28.1744355792404;
        Fri, 11 Apr 2025 00:16:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744355792; cv=none;
        d=google.com; s=arc-20240605;
        b=Y11gSy6UG3JSTeCfEHWmZfelkS/B42S/FthdtfXeVo8Gsu9n+/I1+c5QVOGRBk9jQp
         PkcUsqoC/7rjk4WRAmfQLLw/vmNV5sllxPIiITPjoRk5o1NBJuPCkXznPWwJc1avieWJ
         iSNsYlYPlNazdc7ZUC8I3h7McmUiXmKOCEbZFhfe3oXt/APDbIl1MSBtg4oo00+zywbW
         c7nv10gG/XrGF31qxtG4zaEkb6lg7Gq2pAqA4mL54I4BRFb5Bb1xzZotzLo31XGgDW0b
         08wkIyb4AOFHNUIGsCaPRDHtTso8Sa/m8TMwNtEabWPHpEhrFzFw3iDYRGL7wzggww2N
         XPcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:references:to:from:subject:cc:message-id:date
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=8AZYV1raCKCE7T+GJKC63E8g42JVSDuGR93rMhn9HOQ=;
        fh=+cafoABqASwAY9A1QGBH1+5Ha99VFfgD5+FLHNm6QVg=;
        b=JV4dLtnVfRu7s887izQ+abWFscGOjdMaP4gtwwL+UuISmPICXpGI6wrgMm++O0Bt8e
         YTOWab/AWMfbeCDTTGFq9/qKVVUpCs0BPBzPeRg1b8zUDAo3ST4NPhCJeXfPbCHvS3b6
         o+f9FSEGS/+g978pqHGPM+ehL4iYD7HkjBHbCSTGTvomp+osQtr1tf67JMIfZ6uc51rb
         pA4Q5+sx9eEFRghRs17YTa/7xDaZToK22NfMYy6iU7lVpTXoDvtDHWO+GyOotI5bzluI
         PLplagHRLC4/u9VCCKj6od3ajiU4it3sA85AzRiwMlqYCWWVPj6Jor7jT27Fou0GiEc5
         oMKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=DRLq9kVv;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62a.google.com (mail-pl1-x62a.google.com. [2607:f8b0:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2d096c6b129si36666fac.4.2025.04.11.00.16.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Apr 2025 00:16:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::62a as permitted sender) client-ip=2607:f8b0:4864:20::62a;
Received: by mail-pl1-x62a.google.com with SMTP id d9443c01a7336-22435603572so16297715ad.1
        for <kasan-dev@googlegroups.com>; Fri, 11 Apr 2025 00:16:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVOrBzXIPAg2xZfTudHJ2nybkAPa2eBVfuN6ZOTFSParCNYSFC8UdYeIjfFU0XwwkKd2FbrMKTJVgY=@googlegroups.com
X-Gm-Gg: ASbGncsUdqb+uhgwWbPh+PyaPe4WyLxK8x/2V/dyOeoX9dlB9gO083NW9/zZgc5w6ku
	f6A45IoAGAQmTuUWaW1YA+j/ahryyQKlZ3OOqQ9w/41cyt7gOlO5RB+EyRtV0UZYTZdHyPTGSZk
	ifWZszbIwaOKS3C0pnlqqKiwq7WwlOULZq183ietF0ZyK1XL28apw/wGKR0b2u0PN7Qe1hwCV04
	zHZaCAaIX4nE13dtJTa4SW5VTwDLeo0UmGjLCAH121eESsSF8KFmvtH++9XcHDWQH8iwmxfpCpu
	DzC3eR71rgKTx5o5tIgStR5u49QWMmlWgA==
X-Received: by 2002:a17:903:1447:b0:223:5c33:56a2 with SMTP id d9443c01a7336-22bea4bd57fmr30624525ad.28.1744355791439;
        Fri, 11 Apr 2025 00:16:31 -0700 (PDT)
Received: from localhost ([220.253.99.94])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-22ac7cb5047sm42114385ad.170.2025.04.11.00.16.26
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Apr 2025 00:16:31 -0700 (PDT)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Date: Fri, 11 Apr 2025 17:16:24 +1000
Message-Id: <D93MIOI9YLAD.1WDMNT59MMEM2@gmail.com>
Cc: "Hugh Dickins" <hughd@google.com>, "Guenter Roeck" <linux@roeck-us.net>,
 "Juergen Gross" <jgross@suse.com>, "Jeremy Fitzhardinge" <jeremy@goop.org>,
 <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
 <kasan-dev@googlegroups.com>, <sparclinux@vger.kernel.org>,
 <xen-devel@lists.xenproject.org>, <linuxppc-dev@lists.ozlabs.org>,
 <linux-s390@vger.kernel.org>
Subject: Re: [PATCH v1 4/4] mm: Allow detection of wrong
 arch_enter_lazy_mmu_mode() context
From: "Nicholas Piggin" <npiggin@gmail.com>
To: "Alexander Gordeev" <agordeev@linux.ibm.com>, "Andrew Morton"
 <akpm@linux-foundation.org>, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>
X-Mailer: aerc 0.19.0
References: <cover.1744037648.git.agordeev@linux.ibm.com>
 <5204eaec309f454efcb5a799c9e0ed9da1dff971.1744037648.git.agordeev@linux.ibm.com>
In-Reply-To: <5204eaec309f454efcb5a799c9e0ed9da1dff971.1744037648.git.agordeev@linux.ibm.com>
X-Original-Sender: npiggin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=DRLq9kVv;       spf=pass
 (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::62a as
 permitted sender) smtp.mailfrom=npiggin@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Tue Apr 8, 2025 at 1:11 AM AEST, Alexander Gordeev wrote:
> The lazy MMU batching may be only be entered and left under the
> protection of the page table locks for all page tables which may
> be modified. Yet, there were cases arch_enter_lazy_mmu_mode()
> was called without the locks taken, e.g. commit b9ef323ea168
> ("powerpc/64s: Disable preemption in hash lazy mmu mode").
>
> Make default arch_enter|leave|flush_lazy_mmu_mode() callbacks
> complain at least in case the preemption is enabled to detect
> wrong contexts.
>
> Most platforms do not implement the callbacks, so to aovid a
> performance impact allow the complaint when CONFIG_DEBUG_VM
> option is enabled only.
>
> Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>

This is a good debugging feature independent of how the fix
is done. I would just warn once, since it's not a bug for
the arch and could fire frequently if it fires at all.

Reviewed-by: Nicholas Piggin <npiggin@gmail.com>

> ---
>  include/linux/pgtable.h | 15 ++++++++++++---
>  1 file changed, 12 insertions(+), 3 deletions(-)
>
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index e2b705c14945..959590bb66da 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -232,9 +232,18 @@ static inline int pmd_dirty(pmd_t pmd)
>   * and the mode cannot be used in interrupt context.
>   */
>  #ifndef __HAVE_ARCH_ENTER_LAZY_MMU_MODE
> -#define arch_enter_lazy_mmu_mode()	do {} while (0)
> -#define arch_leave_lazy_mmu_mode()	do {} while (0)
> -#define arch_flush_lazy_mmu_mode()	do {} while (0)
> +static inline void arch_enter_lazy_mmu_mode(void)
> +{
> +	VM_WARN_ON(preemptible());
> +}
> +static inline void arch_leave_lazy_mmu_mode(void)
> +{
> +	VM_WARN_ON(preemptible());
> +}
> +static inline void arch_flush_lazy_mmu_mode(void)
> +{
> +	VM_WARN_ON(preemptible());
> +}
>  #endif
>  
>  #ifndef pte_batch_hint

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D93MIOI9YLAD.1WDMNT59MMEM2%40gmail.com.
