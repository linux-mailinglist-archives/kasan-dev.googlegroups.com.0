Return-Path: <kasan-dev+bncBDN7FYMXXEORB4PY4K7QMGQEHJ7EKWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id B6E4EA854B6
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 08:53:39 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-85b402f69d4sf187675339f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Apr 2025 23:53:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744354418; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dlm3Y72FwHjPkEhK/QFAAudrEhuzUKUmTtNd0a4gKWqSYkzecEvU9+1UeRCBnpIZKi
         IiOFEvoKOlqgjsdhV/lduYv2tbroxPyJ11XpfMmp8qei08AtCmlCr3H99LVRiuz7WCND
         jvk67HS3BibJxdyPEWSEeY/Lcmm9WcCrtbzFYVJq9rE6Ss1LkwC6iGeNhK+hgpW2YzF5
         FZxFvjbfCPEWXlzIaAFJrlh87cgL9HqPnwkGWOBwcd+26jNqT/r54XZs6UafSMPyAA6q
         e04M7HqeBk7cthkYft+65zztZxV6g3vmi1Z+97/54M2H9X4TAqISWj10FVfBw2pRjHUD
         t8kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:subject:cc
         :to:from:message-id:date:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=llhmZrZ5ArjwtK7um1x8OH7fD7n/0iufcyF+i0eo3cI=;
        fh=YoCokLwcSoLU+/NqjiiyEBIOKDbExfM2vbiYP4wC3RQ=;
        b=IBacSHpXw2Hq1eDpYhZPYe4lIBAQPE2bhTluP1LwyDWnh8U3B7eJ0AGeHHw6m0n2Ut
         TGz6f89fbRaMGogR3utHq4PAywB98AcGjDs6ea5Lq3mvQBzjxZeddM5XaCKIOkiax5ek
         aP3PVG3HIOVcsE1efFxp3ut8IGjvxAeZrSd17OIMS7ViKOQLt5GmiOHPK1CN40jKTt+B
         MSUqjRrhOZ7L92HFBf5zWXL5typO9ohR2Moj+uXiX1s9Aldtrw4huBdjWT81gVsK8Daw
         TImfejtrmIXxp4R+qIHTx/av7ix7PoslQu2JEwQovYuOQAojmQ/5V1LW1ZBUgMpQ43Gc
         lyJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZlKBl6Xl;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744354418; x=1744959218; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:subject:cc:to:from
         :message-id:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=llhmZrZ5ArjwtK7um1x8OH7fD7n/0iufcyF+i0eo3cI=;
        b=BJnd2BdLNIBBwBgZsCXbE1jtKr6ZjrU04gXNOORZWG/2nWY7atwFYwNPs0Tfp1ADLm
         d1rqy4jRjCYmUV6GhYsZzADSXFX2NznnZWBJyVQN+QvkBRc/bmxnFIjZ+0RgzgLijNE1
         GzpaBHrqMOID4Ru3bLgaYojhNUcCz2Mnw+O1uB7fjOWl4lkJPK/x//xsjITSq0Ex3wHN
         Y3x4nFFTFX7MM+ttU7yLHXaO2qQtmh66JCBgR5+IBhTVSsFBLDbzEvzwGm9bQbd387v/
         bdgTJbYJGAFP7XLqVGX6MQPkH6f5N+y+EMwkoyxgzGC38URKLmzEc/01dt+TX//7oQk3
         LivA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744354418; x=1744959218; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:subject:cc:to:from
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=llhmZrZ5ArjwtK7um1x8OH7fD7n/0iufcyF+i0eo3cI=;
        b=ikpxFxj/0aGizh6E28BvtbORf4e3rJGQgOfyUAcBoApP/ZxI08F0yWZObG2Argcw6F
         hrH2cxql3tMDQMZdqTmQtCjKu+62lq5G9BpMsCACbRwn9BXHylToKDu8HWzNIOVL8UA5
         uiw3f1F89+C92g+ZxwkqWbJvIYQoPWWuKhVbPOisX6zWh2RWSj1E7W0Ty4zSHgYg/+x8
         585KRAHO9eStu5IoJlSDWp5dlJ3o6qZ8G0EuDdCHMfmG1U+Qm5Tla1qw7mIFQzdPjAag
         gTMbyjDIQH9qLHKM4KV3lI2DazGI8kZbjbBkp+FySs7M2AExvTssXnoW8Gfjd49Qcl2a
         KSQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744354418; x=1744959218;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:subject:cc:to:from:message-id:date:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=llhmZrZ5ArjwtK7um1x8OH7fD7n/0iufcyF+i0eo3cI=;
        b=NSJdwbYUbsuNt/qbQKCJv3hNIdLTD8tNCb+5TZRfgphnNcPEdAMSjGhXly70NKOHfg
         WuCoPM2a16N6ZGMgwG7Z4oRcW+/OaT1rZF/id52SKTCLrqGSFSZJ67lw/sTrxVBK/7MD
         dCtjfRO3GBs+6cNnYe8QiuXE2bkpfJvKuMGxuTiPiN3juZldBkB9CglwWqz6YhUMwHbr
         4isS5Vj3v/jlGvQ0mslSyGGZKzd6W3OhfZoPJULelxfgiZvFxOQmkDEZrCmaCSBqUOoy
         loiJgIKJug7UAzl3psY89cCcZ9LvS7hVVmlWjehFncYULr+u9nHXPZzZEMSOM2KkN7xx
         5N4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW4E8FTc78h6Hy1BJYuzfUiQEllduOBQGVfNVVRM93kXxE7swZBDvmgGXUFwHROY/nFIrmaRw==@lfdr.de
X-Gm-Message-State: AOJu0YxAq20uCDyj4Fx31GNzo+oNNR4vn08wymdA8dDbWuJM47v2SvnC
	qgRaFdJmGAGG9yisPCHbEeegOc3AmEA57g7x0e6yRi4hJWmmcYy5
X-Google-Smtp-Source: AGHT+IEB4iX/q/0+UjPKw9gVHLC+mocxGz8i26paQNROQZ3ZBsbMQFIBFNvfFPBN7xUpos7pjfqMtg==
X-Received: by 2002:a05:6e02:b2a:b0:3d6:d145:3006 with SMTP id e9e14a558f8ab-3d7ec277251mr17452075ab.20.1744354417909;
        Thu, 10 Apr 2025 23:53:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJjeLcdysc48lo5aK8Z+uhhp+bQu4deEMJwriwW7Qw5cQ==
Received: by 2002:a05:6e02:3a08:b0:3d5:de98:b7ec with SMTP id
 e9e14a558f8ab-3d7e3d4da52ls12325005ab.2.-pod-prod-04-us; Thu, 10 Apr 2025
 23:53:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW8kZgaP/KlVFlXPfIP7HI+68UVvoiAaL7pfGgLNm563Nd4OoLA8lqgt79HOtzq29Y/IiXDQriUjF8=@googlegroups.com
X-Received: by 2002:a05:6e02:3993:b0:3d2:b0f1:f5bd with SMTP id e9e14a558f8ab-3d7ec1ca08fmr21150795ab.3.1744354417129;
        Thu, 10 Apr 2025 23:53:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744354417; cv=none;
        d=google.com; s=arc-20240605;
        b=cc92YCAlwq70F7wtcdP0eJsWV0t/OZ/53FMU2LHUzgKphk3xjRPDOeA7uJCAX2nc0z
         +DiODkGvIFSbsrGZ0IjD3Iwn+dGmnUnevOaqqIJk+pRraKJiVQHTyxZ2E2gYfUC44Jvd
         RH0s4pBlkquhkR+mGVt+E68TMfHdtE7CiiG3bOoOXPLIgLCW/ZJLT17NJiKT6RCAbP0c
         RJAD8eYsdypNfV1grPFDKGtw5sxy/03Ck77DLVuQ3STPZB3HH9EZRTwZXLd4Jnbe5fj2
         5S6bmPLoDP3tQHSznrDlNduucqe3R8puKgMbGI8Or6kb7cuMURJziSw7285qNPO6nLxU
         bRLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:references:subject:cc:to:from:message-id:date
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=q0GUgempXeR1Ai6jdCUdrwnFpwuRrrfXxvPcXnoqanQ=;
        fh=L1m7yeEYZyoHu0F1XSAQq0wt09zQY8GxkUPaLPTaGVw=;
        b=J05bnC7jM+/h6B0p7xNr+6URcnQ9CCwK6oKwPzRRjPrgWx1kSh9TCabJQtOHdL2a22
         iENRTwCMXvZxiLMd1Wh5xjAwQ1GtB/ds060Xh1aM5tLEtJsgGFpR4a9XEFJhY9vlICt9
         dhUuZ7prNEW3rwLPu4jIzf534R+qtpDLPX4qOBUK0FfHo4k5ACdOELkmIcvfAe9zwtQf
         WmWBNlEr6s4L+8rA3Swdb6oPbkpynQNHdglqY8hbiu8Qh+higB743lZ04X5kNcZGfsrE
         oX1vK6nMn1eZYF5T34ZeSTocOyMBrkORk2A8OP1E4zYrB9U3qNvWjmIlk9hO7TVYJ60+
         6nbg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZlKBl6Xl;
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d7dba66fc1si201775ab.1.2025.04.10.23.53.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Apr 2025 23:53:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-227b650504fso15887745ad.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Apr 2025 23:53:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPd1yJ3hhIfBInBdh0WI5TE8+CTDyta7aPV46VyGOjFY4IucX2//eGUJUI04/97HMxEWSLlUbL404=@googlegroups.com
X-Gm-Gg: ASbGncuTr2wDokeAqFhR6eJQB21wfJwVzy+g0frrPqoXkIkUVTmbhRFG/r9Tz8JBE4R
	S2d1t7ooBS8XErOCncnC9lgBDpYCmkAlf/J9FB+TvZVKfda52kdReh5ARYE84bXE+v7Y5n9cenl
	yjGZUH32/wd/3B1ELtGVfRdyaX/ZmjkqpA/EyQL6dW0rnmeS8o4RG42KqhZO6T8ulnOA6TzKQ9P
	6dE81f7I27w5FIJGdkO/055T1px/CrvkSLDqcAVqOg5T2VhRwkiX4pHfXlgzEOWWEMbQneC9F/t
	e/meIwSFZb6JcFYiXtjkvyUlwuZAYROjsA==
X-Received: by 2002:a17:902:cec4:b0:224:e33:889b with SMTP id d9443c01a7336-22bea4ade03mr24590165ad.12.1744354416369;
        Thu, 10 Apr 2025 23:53:36 -0700 (PDT)
Received: from localhost ([220.253.99.94])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-73bd2333841sm728200b3a.160.2025.04.10.23.53.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Apr 2025 23:53:35 -0700 (PDT)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Date: Fri, 11 Apr 2025 16:53:29 +1000
Message-Id: <D93M14UCYU7Y.39ZQIH7VON6DG@gmail.com>
From: "Nicholas Piggin" <npiggin@gmail.com>
To: "Alexander Gordeev" <agordeev@linux.ibm.com>, "Andrew Morton"
 <akpm@linux-foundation.org>, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>
Cc: "Hugh Dickins" <hughd@google.com>, "Guenter Roeck" <linux@roeck-us.net>,
 "Juergen Gross" <jgross@suse.com>, "Jeremy Fitzhardinge" <jeremy@goop.org>,
 <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
 <kasan-dev@googlegroups.com>, <sparclinux@vger.kernel.org>,
 <xen-devel@lists.xenproject.org>, <linuxppc-dev@lists.ozlabs.org>,
 <linux-s390@vger.kernel.org>
Subject: Re: [PATCH v1 3/4] mm: Protect kernel pgtables in
 apply_to_pte_range()
X-Mailer: aerc 0.19.0
References: <cover.1744037648.git.agordeev@linux.ibm.com>
 <11dbe3ac88130dbd2b8554f9369cd93fe138c655.1744037648.git.agordeev@linux.ibm.com>
In-Reply-To: <11dbe3ac88130dbd2b8554f9369cd93fe138c655.1744037648.git.agordeev@linux.ibm.com>
X-Original-Sender: npiggin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZlKBl6Xl;       spf=pass
 (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::634 as
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
> The lazy MMU mode can only be entered and left under the protection
> of the page table locks for all page tables which may be modified.
> Yet, when it comes to kernel mappings apply_to_pte_range() does not
> take any locks. That does not conform arch_enter|leave_lazy_mmu_mode()
> semantics and could potentially lead to re-schedulling a process while
> in lazy MMU mode or racing on a kernel page table updates.
>
> Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> ---
>  mm/kasan/shadow.c | 7 ++-----
>  mm/memory.c       | 5 ++++-
>  2 files changed, 6 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index edfa77959474..6531a7aa8562 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -308,14 +308,14 @@ static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  	__memset((void *)page, KASAN_VMALLOC_INVALID, PAGE_SIZE);
>  	pte = pfn_pte(PFN_DOWN(__pa(page)), PAGE_KERNEL);
>  
> -	spin_lock(&init_mm.page_table_lock);
>  	if (likely(pte_none(ptep_get(ptep)))) {
>  		set_pte_at(&init_mm, addr, ptep, pte);
>  		page = 0;
>  	}
> -	spin_unlock(&init_mm.page_table_lock);
> +
>  	if (page)
>  		free_page(page);
> +
>  	return 0;
>  }
>  

kasan_populate_vmalloc_pte() is really the only thing that
takes the ptl in the apply_to_page_range fn()... Looks like
you may be right. I wonder why they do and nobody else? Just
luck?

Seems okay.

Reviewed-by: Nicholas Piggin <npiggin@gmail.com>

> @@ -401,13 +401,10 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>  
>  	page = (unsigned long)__va(pte_pfn(ptep_get(ptep)) << PAGE_SHIFT);
>  
> -	spin_lock(&init_mm.page_table_lock);
> -
>  	if (likely(!pte_none(ptep_get(ptep)))) {
>  		pte_clear(&init_mm, addr, ptep);
>  		free_page(page);
>  	}
> -	spin_unlock(&init_mm.page_table_lock);
>  
>  	return 0;
>  }
> diff --git a/mm/memory.c b/mm/memory.c
> index f0201c8ec1ce..1f3727104e99 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -2926,6 +2926,7 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
>  			pte = pte_offset_kernel(pmd, addr);
>  		if (!pte)
>  			return err;
> +		spin_lock(&init_mm.page_table_lock);
>  	} else {
>  		if (create)
>  			pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
> @@ -2951,7 +2952,9 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
>  
>  	arch_leave_lazy_mmu_mode();
>  
> -	if (mm != &init_mm)
> +	if (mm == &init_mm)
> +		spin_unlock(&init_mm.page_table_lock);
> +	else
>  		pte_unmap_unlock(mapped_pte, ptl);
>  
>  	*mask |= PGTBL_PTE_MODIFIED;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D93M14UCYU7Y.39ZQIH7VON6DG%40gmail.com.
