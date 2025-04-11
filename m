Return-Path: <kasan-dev+bncBDN7FYMXXEORB2XV4K7QMGQED2O36PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id A812CA85495
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Apr 2025 08:47:08 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3d44a3882a0sf16159485ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Apr 2025 23:47:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744354027; cv=pass;
        d=google.com; s=arc-20240605;
        b=e2mhKBaSi9UNsjY+p53e8faP+bPBBM7Bm1nibF1mPI4E451oDgYWrX7jiFVWsBOvrI
         tcSJqms/jDmYBWkp83yf4Nt0Kup4yKuLyJkjJaXP80N2Kjqc9gLmmVtII45rWgrFQ94x
         cfujM3V/nx8l3ByalF8iNbAYBKmXOLOmvNEyKOZgfik2JndnGjLww+TZ4gtq6Lk+4J3N
         7k1dKAsVzkKk6yi4rScTcQTN/Nlm6WnLpj+QEn9yib0fJOuvyFv64d6i2KhDV/PIDkvu
         tVTlmsg+KX3+s27C2TW/0nC/+Ehlix91KQVfu8/ONsV6V5418D6UDsnYoX0QcSo95W5m
         pi5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:references:cc:to:from
         :subject:message-id:date:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=QHfRlA3V4/jA4sJ7GKlzp+FaGR5JflZ9Z4l4lr1V3lQ=;
        fh=Tz6m3zuADP0Zuy0+5xPLet7t5MDTylTm4E2FiDG8bHw=;
        b=AKLaKnw8/tJoocmxYVSdnVlwMokb6TuNrzVWzTWYhAzxJHOJY1vDa8DhoADCTf6o4J
         FiVLVgb+Ng0KHxKP99WGsrqBZm69GUvB0J3iSE1iVbJa0Fkdq2aeoBAhJG7SlrC6bD7m
         EtOI8OlB6aT1VZI0XESWFAD15FV1eXnbRLXnLcl+azM13k6jGkKAOa8xVX9m675Vb8VS
         aRuMua0Ajv9C9TgFKzuIvU4uW+cKFycWlqo5t3ewu3RKd8c/1hUMxIprGMyyakEIHG/m
         EDS+SE+bhczvFn0W0b+IIJ4I5LrF+GqfZesOsYe+QiJWmKFpEkbWP8IYnxri1aVU5GTF
         mGIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="efGh3/Wy";
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744354027; x=1744958827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from:subject
         :message-id:date:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QHfRlA3V4/jA4sJ7GKlzp+FaGR5JflZ9Z4l4lr1V3lQ=;
        b=Al83jjxAAPEiBtNIsYuz2kuq9MeKAO7eCwPPRPTBwPmnXgWYgYUN19B0eI8S3v+E0Z
         ChWLeM5pzJlSqin87pmYgiOlLMq/R/2mM4M9pcWZojVdYqiYQJl1AgKmacmPTQgXU/Ss
         R3wFxoTGF+YHpynvHMgnVSK2PWOr6v8xxRCNQ3VByWNnkFdVC69jLJx5l6S8dYSMWThX
         oFZE0HmT0moiwNqmfsN6rHOdARSnozeucJy7P41PFYJA6L6P9cD7aX7kDXI9MdPndPwk
         tsjTZQItWaCXyI2FzbQ1K8bfxmANnDw1g8wXW2kLud3gP+2SqZzUx3BTFg/69+dKZAG8
         Pzkg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1744354027; x=1744958827; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:references:cc:to:from:subject
         :message-id:date:mime-version:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QHfRlA3V4/jA4sJ7GKlzp+FaGR5JflZ9Z4l4lr1V3lQ=;
        b=MgEhJbjeEoTnA90vRWd/Iu3+qdNzGTDXLJO7EdMFntfPc1ma8iSvu6EdNn+Z6fEwMe
         DtNtcHrW6t29smSYfKqmsoVrXP0m4w2cakJiymvGSlzIOxuUqtf90RsO9mH1i0DVWDjm
         rZeNyoLMDvI30bqrGm+alzznaLxPeUyheFTYuKcm4IoFoh/gZETdaBxpmx9Vvxj/a8N4
         Tt1ss4OAU3ctlBMl3WZZAA/f50/++4ENsTWZ9PD+EdRWwgykKyMJgXVYYvXnRDZc+CWG
         Qg/Ip2O7BZ3vO06CrQBJyPHbTTVbUFIx4f7Jwc51rgLx6jb15a22puzT//hMZPCYiDoS
         ydlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744354027; x=1744958827;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :references:cc:to:from:subject:message-id:date:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QHfRlA3V4/jA4sJ7GKlzp+FaGR5JflZ9Z4l4lr1V3lQ=;
        b=uPTdk1Gg/brcteX2CzF/h4oezKUzMeLr1OE6FHzq+mrVR6BfYmaD5o9J0dRnw8kOjl
         bnbyRO7+OqAtD9wff/ZiK5u8evgNVWjEN0p4uk4l0Ew84eqkzpOpz5onRk2kZqL6yzfR
         dsO102Pk6oxr7CjjHMA+qhZHg/UzjfO23Trwl6ysrE4oLlCLunIBGO5sJ8h0HXRTBMXW
         UXm5YP6oBaMKr884gk/P/Vpush0Pc8xeaVmyn+JJzNu3ZfcwuHk8sDCE1f6QX9LRSKQ5
         E1Xph1NUF0HhvvjHEh/ffJj73a7oAaFzDiDD8/0hg5YA2Cul5j4weDQ2e0vwd9eVT0zL
         hLbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVuGd5tVgC2vI4SYa4aAKTT3VDATMCK+8kXzVBivWSAgalM986ZUB2Aw67zVqvWCqYNpfl7Ow==@lfdr.de
X-Gm-Message-State: AOJu0YwfbEGxOso++8cuBH1zK8da9jgZThUDMLiIgqRSq+BWwXfurt+W
	erA6HfRmH76NSAOTkrBw3Vv4syr2o+WuGcfWmW9xHlMnbzVZprtX
X-Google-Smtp-Source: AGHT+IHqJfBomklxmQKWY/zpFiKQlDN4RRpKc3A8iaD9Mvbfg1oJg56JOy7U1heqIn6ZkWN4TgStcA==
X-Received: by 2002:a92:cda7:0:b0:3d0:26a5:b2c with SMTP id e9e14a558f8ab-3d7ebff0ee7mr16522875ab.8.1744354027053;
        Thu, 10 Apr 2025 23:47:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ1oY24ORRAiqIXEC2kkr3uOw44ZOCiiZZD91f1bo844A==
Received: by 2002:a05:6e02:2412:b0:3d4:58a3:f73 with SMTP id
 e9e14a558f8ab-3d7e3c76744ls13543705ab.0.-pod-prod-00-us; Thu, 10 Apr 2025
 23:47:06 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWd5Rv+sL5aYuqYaLg/fm1bvW6AB6qkYAX86XvzGPxjqgFhqBZnRzTYhW8XC3EdDX/v5m7Mz9aAy+0=@googlegroups.com
X-Received: by 2002:a05:6602:3687:b0:85b:3874:6044 with SMTP id ca18e2360f4ac-8617c154a3amr136474039f.7.1744354026331;
        Thu, 10 Apr 2025 23:47:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744354026; cv=none;
        d=google.com; s=arc-20240605;
        b=TSW/ptSGsl6PDdrB9Z6R7HpHxtTT/tGWr//CpPdf3fn9U47emqxkgbkyIPygdVCocf
         M/beujPa5kksTYQfrY0GVsfJdoSs4FpMDx1iz5iO2yJkw46L+yAZDzzUZ5+o98Y2gXDd
         du+oC0DOMn5husouIWW7Pex2Jyn5E0IN1LlPYDWOHxJnGImfcDnAhQ3oDvZ3wKPKvh8X
         LIynBqBnnASDWvhSJZp+L37/UDwfx9zVqgURYvNtl8tG2OZksIDlT3eRQPHW54FOlBgT
         t5JHot0MPU2RjyNg7jaWYWGqNpuiC1qs3JtC2ws5hl+aP+DDdZu5rR2H3x86q56J5SxY
         TCZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:references:cc:to:from:subject:message-id:date
         :content-transfer-encoding:mime-version:dkim-signature;
        bh=BlT93k3tsOOzLmAYutjlNjX6BFvDuWnFmTQ9IJuMKl4=;
        fh=7Oomtdc/hx5Xy+oTc7R4BXnT3+eWbgfjXvcFfWbzkAo=;
        b=JGkrsZ0U0FekNxHipTFmrJVBOFlflJGJrpfoZ+KRG/clOLapDvnjiZYZ7Qs5pt8NTM
         AlD4I1nZj1i3KN8japZe6ovLZLGNUTxK3/FOiH+fwsKfu7lipOE33Vs3ZbdTpJpLrkcG
         wL91l0yppcThvuuGGJuLWJvXzga5E4vJ6aHp7S3H/Fg5E7GsIwHyqmZlCaFP9HKohmRd
         dAGeBxq0Z55lZjFpAka1yLCqvmEDHuOO5LvplcjY2vZng8vjrLZO+64rpbgpJfawAHDj
         NI8I9xR/TLQ5XI63vjbCkflGVIXcDgNkBIXNXTjpCMKqxr9NqOWfX/DKW03tecpW5pGM
         +ecw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="efGh3/Wy";
       spf=pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) smtp.mailfrom=npiggin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x634.google.com (mail-pl1-x634.google.com. [2607:f8b0:4864:20::634])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-861656c66b3si19677539f.4.2025.04.10.23.47.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Apr 2025 23:47:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of npiggin@gmail.com designates 2607:f8b0:4864:20::634 as permitted sender) client-ip=2607:f8b0:4864:20::634;
Received: by mail-pl1-x634.google.com with SMTP id d9443c01a7336-223f4c06e9fso16728965ad.1
        for <kasan-dev@googlegroups.com>; Thu, 10 Apr 2025 23:47:06 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWpeQr50tlaxEvHLudmwIej/GOLV8FChvbLD+wnvf2MYgnt2+iCv4sEYoIp06/z5NF302txOjTCdqk=@googlegroups.com
X-Gm-Gg: ASbGncuFZ6GXJLRnlw8Lx72iEg8iDmdn1b8jPG1e9ZUIBWn52ohHA1ewz3DaTvqjrqY
	ReNQnyC8EZ7lnSdClV6p3E9enwvfovJyxBkGDgJAihj7AIFGAxm/vq/OTb+lb8hqDmXDW56xsMZ
	SwaixmOCJJ9KUoXfw951pMDYdnadprYBIXIur9mGWpL1m+22Dbl+uq5CLubY/wFNXoSkKNlN4S/
	6tRvjHvVtxfh4X2AZ7RFabGheLKBvzeaETfYi//UB6UtkWlwnWl1k1aLoVZbCHWgDlHDBMzQbCw
	Q8LoDGZ5qvpceGEO3IekjG4QEDLFOk/GWw==
X-Received: by 2002:a17:902:d489:b0:215:58be:3349 with SMTP id d9443c01a7336-22bea05e17fmr25293145ad.14.1744354025413;
        Thu, 10 Apr 2025 23:47:05 -0700 (PDT)
Received: from localhost ([220.253.99.94])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-22ac7b8b2c1sm41872295ad.59.2025.04.10.23.47.00
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Apr 2025 23:47:04 -0700 (PDT)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Date: Fri, 11 Apr 2025 16:46:58 +1000
Message-Id: <D93LW58FLXOS.2U8X0CO2H9H5S@gmail.com>
Subject: Re: [PATCH v1 2/4] mm: Cleanup apply_to_pte_range() routine
From: "Nicholas Piggin" <npiggin@gmail.com>
To: "Alexander Gordeev" <agordeev@linux.ibm.com>, "Andrew Morton"
 <akpm@linux-foundation.org>, "Andrey Ryabinin" <ryabinin.a.a@gmail.com>
Cc: "Hugh Dickins" <hughd@google.com>, "Guenter Roeck" <linux@roeck-us.net>,
 "Juergen Gross" <jgross@suse.com>, "Jeremy Fitzhardinge" <jeremy@goop.org>,
 <linux-kernel@vger.kernel.org>, <linux-mm@kvack.org>,
 <kasan-dev@googlegroups.com>, <sparclinux@vger.kernel.org>,
 <xen-devel@lists.xenproject.org>, <linuxppc-dev@lists.ozlabs.org>,
 <linux-s390@vger.kernel.org>
X-Mailer: aerc 0.19.0
References: <cover.1744037648.git.agordeev@linux.ibm.com>
 <93102722541b1daf541fce9fb316a1a2614d8c86.1744037648.git.agordeev@linux.ibm.com>
In-Reply-To: <93102722541b1daf541fce9fb316a1a2614d8c86.1744037648.git.agordeev@linux.ibm.com>
X-Original-Sender: npiggin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="efGh3/Wy";       spf=pass
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
> Reverse 'create' vs 'mm == &init_mm' conditions and move
> page table mask modification out of the atomic context.
>
> Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
> ---
>  mm/memory.c | 28 +++++++++++++++++-----------
>  1 file changed, 17 insertions(+), 11 deletions(-)
>
> diff --git a/mm/memory.c b/mm/memory.c
> index 2d8c265fc7d6..f0201c8ec1ce 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -2915,24 +2915,28 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
>  				     pte_fn_t fn, void *data, bool create,
>  				     pgtbl_mod_mask *mask)
>  {
> +	int err = create ? -ENOMEM : -EINVAL;

Could you make this a new variable instead of reusing
existing err? 'const int pte_err' or something?

>  	pte_t *pte, *mapped_pte;
> -	int err = 0;
>  	spinlock_t *ptl;
>  
> -	if (create) {
> -		mapped_pte = pte = (mm == &init_mm) ?
> -			pte_alloc_kernel_track(pmd, addr, mask) :
> -			pte_alloc_map_lock(mm, pmd, addr, &ptl);
> +	if (mm == &init_mm) {
> +		if (create)
> +			pte = pte_alloc_kernel_track(pmd, addr, mask);
> +		else
> +			pte = pte_offset_kernel(pmd, addr);
>  		if (!pte)
> -			return -ENOMEM;
> +			return err;
>  	} else {
> -		mapped_pte = pte = (mm == &init_mm) ?
> -			pte_offset_kernel(pmd, addr) :
> -			pte_offset_map_lock(mm, pmd, addr, &ptl);
> +		if (create)
> +			pte = pte_alloc_map_lock(mm, pmd, addr, &ptl);
> +		else
> +			pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
>  		if (!pte)
> -			return -EINVAL;
> +			return err;
> +		mapped_pte = pte;
>  	}
>  
> +	err = 0;
>  	arch_enter_lazy_mmu_mode();
>  
>  	if (fn) {
> @@ -2944,12 +2948,14 @@ static int apply_to_pte_range(struct mm_struct *mm, pmd_t *pmd,
>  			}
>  		} while (addr += PAGE_SIZE, addr != end);
>  	}
> -	*mask |= PGTBL_PTE_MODIFIED;
>  
>  	arch_leave_lazy_mmu_mode();
>  
>  	if (mm != &init_mm)
>  		pte_unmap_unlock(mapped_pte, ptl);
> +
> +	*mask |= PGTBL_PTE_MODIFIED;

This is done just because we might as well? Less work in critical
section?

Reviewed-by: Nicholas Piggin <npiggin@gmail.com>

> +
>  	return err;
>  }
>  

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/D93LW58FLXOS.2U8X0CO2H9H5S%40gmail.com.
