Return-Path: <kasan-dev+bncBCJ4XP7WSYHRB3GXSORQMGQE7BSOUUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BF1A706BEF
	for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 16:59:57 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2ac7f9e64ecsf3973091fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 May 2023 07:59:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684335596; cv=pass;
        d=google.com; s=arc-20160816;
        b=EuVEizHlrRLZxGklNQGRYrqCoC+p49W740qt0zIw7+m+b1hx/Hn0a0mORPECoVY5oY
         z0PgsnT3VERa4Sa555t0iD7xJyZL3DJKzDsQKnr5Ni4OgjZMm3oH6p2UsOEmCDZ39Q/j
         DLTu+FcpMF9C/Q9LQPfX4oJr2dm28YaMx7dY900mYM/DED0IreTu8V2Bga4ZJwfsDWiz
         8EeTEGxFxbJ27ZCYq9QSHqxSHpeLMBAMr8/qslTvEez5Zn/Q7QcsAru5PfE26WCUi3iy
         JJNsC2CcKpHLJ5Jui0TAcH/d7cnoWC3nHguWih1UQRo6xJHqfyAjLVN4LAxlcSJHOZwU
         NQdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=cwT+ughMhw0iCBlFdGaGuOc9zbWHWZ4QJUKY8FRUboc=;
        b=i0LhNybXzXX8SUtzmR3qKUfsLzPXTUlFbd5qVSCxy5FFXovzbqhaDJgW5gloGzU2Ql
         aXMflZMrDnK8Xj3dUmHcmd4uwwFkXNZlowIxZRIjDUCcirdcZ/sVYanGQV59anLXX54N
         Kjm/0a8ZPAgtD52Kt+c/7lsb2PAgL2vgg6xl5x8SWiHkuZZDDIALbqK64J6rH4Ft8gST
         jL+ixXtGwVbraP3yQCa79EKWvH+V8TsW7gMlGyoTIav2kt+DTNMHJukTcEi2crIYA6qd
         4Wb72eJGMrxdESCJUoThu4bBL+cSsYOn9N/WGwpFSj1nVRYiWwNg5LWu1ihyuEt18uE/
         urdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=steven.price@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684335596; x=1686927596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cwT+ughMhw0iCBlFdGaGuOc9zbWHWZ4QJUKY8FRUboc=;
        b=SPkZbgooRzRaP++pib1/j4EGgien1XpMLWWJxr/GsJfRos2D9TWvyS6qT98lkGItkM
         OALubqFUlEsKYSFOGbSYMwleu2ph5EhoDtlpZLJ5uRQTg8sgbJd6IOfBCTXSFjAZfwsM
         KYr3r+HxckJ5Nw4WqTeQmDGoZ275G1d4frVsm3jekQQ2YLZV/Hvd9EZM6d148ElU0v/N
         VApk5G9KWVL+aFSI9Zp9D3YKbtpkTuaIcYqqoKX4Oj68HnQFmWNcBbOw4+RWlXd8zIu5
         sVpAZ4ifl1Irr46Jzx4kw9OLFKf3Jg/cW0o7H1rGNZ5u/KpDqv6w4D+dJvLDq8c0z1cq
         I7xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684335596; x=1686927596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cwT+ughMhw0iCBlFdGaGuOc9zbWHWZ4QJUKY8FRUboc=;
        b=XOLXehswP4piecTkUSvNJWVQ/opgf1ZQkdtT37KzBq0gNp390+u3IXmC8Upvw4lDt7
         Lb3ePtbxGwCpY19zM3p9/KzAse56qHwyz+F5fu7X2GDuhAxMdxIVoMo5l3480sQ+byCS
         Yee9eQxpOefITAFqLN67pNsgtIx9bj7b+9RkatMvfYS/+5DQP78a+PNFIPoUllvd3LBI
         vjT/k79oIR/tjERCOyeSqKE8ulZ5TScJvxh2l2Jnr+sPILqr6ZPyQhBY0ZPiCVhA1vUe
         Gb8PpD8sVLrG1HZWLRjwuRxbLi4L9/btxUCuRQqnqBDfIdsCscG7JFspfSdU50I1Z5ko
         wZmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwBkR2dli2mXP4UyK6y6yk+i+BRs6OdYkWVkl80qbJ8U+8/tbAC
	yfLIxtDPY90lypwU13w91RY=
X-Google-Smtp-Source: ACHHUZ4wnR/usANMu02tpzn7lZzUpF9pT1mY4jyc7SwoOBupegMEoEyPfVeQx8ZK93ZKXJtYDwsKkw==
X-Received: by 2002:a2e:9912:0:b0:299:a9db:95 with SMTP id v18-20020a2e9912000000b00299a9db0095mr7254080lji.1.1684335596423;
        Wed, 17 May 2023 07:59:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1610:b0:2a7:6705:797 with SMTP id
 f16-20020a05651c161000b002a767050797ls456995ljq.1.-pod-prod-08-eu; Wed, 17
 May 2023 07:59:54 -0700 (PDT)
X-Received: by 2002:a2e:978d:0:b0:2ac:8b00:91ab with SMTP id y13-20020a2e978d000000b002ac8b0091abmr9766080lji.25.1684335594704;
        Wed, 17 May 2023 07:59:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684335594; cv=none;
        d=google.com; s=arc-20160816;
        b=SqBIbje+xumXRnwuUO1jyTj2WEM5qI8fXaQGwSvRZWvx5624AWUkTVpHjc4B910wOe
         PAox02QFfXobrp7bud8CWSrUdn2oYJaU63i56Wrkgvm1cu9OdzBYBLVkvfyH0XSyfyPf
         zx4p7e/L6vi9DP3ZGCijavUDX4oSGMeanG/rPdx4jyjJY42OVih4vwrxfYHvF/j5vB+t
         6fkJ1Acbtr73UdKvt5J9f/Dajvy2+Ga5rdwF/AUl6GDBEftv6LxQ1Z5DLDfI84j39UsL
         eltb7rimXksQou/Abp5GRrf+1lwjslBXWCWBVWNV1qxjhbiS+kp8a20kHXtlUU5RvbyK
         jX2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=+b8yoAB8HawSrHfyczl9n+6+ha/R/REJ8rWKalPWC8M=;
        b=w4GLy6W4QAAEwkgnOeyWwiF0Ugzv/AMabxHessDjwtxRpLj1fYmK4/C06Lluj/gNoP
         nU7VJY6dBy+V7ZxRr3jJzQBJV/3y872A7hjRZQuBVUuvUx9Zm9WNCywK/fEQAMQ01Gn4
         3Ozs6RH+PvjaRcbZezmKV90H3cZWu0PcHvMc/d1xxP0xdVUqEYfMBZOFwRW0DvdOWgsh
         kXdC42pZ2p+sDALSPoJ/HClV0GUiRNwNV8RlFinNfHgJFOxValrYCzAlRJNdZZz2uybG
         H4wKfM9HwrZ4qRYmFYVBoMMiitWDQeQKPv61sijZrRlMM9JhOXtJRTZJFeEtIWar6qcV
         IElg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=steven.price@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id o12-20020ac24bcc000000b004edc2bbd25bsi1555083lfq.3.2023.05.17.07.59.54
        for <kasan-dev@googlegroups.com>;
        Wed, 17 May 2023 07:59:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of steven.price@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6E33C113E;
	Wed, 17 May 2023 08:00:38 -0700 (PDT)
Received: from [10.57.58.217] (unknown [10.57.58.217])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A69203F73F;
	Wed, 17 May 2023 07:59:50 -0700 (PDT)
Message-ID: <993ee407-cd7a-ab14-9d66-2e1009e05d3a@arm.com>
Date: Wed, 17 May 2023 15:59:48 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.10.0
Subject: Re: [PATCH v3 3/3] arm64: mte: Simplify swap tag restoration logic
Content-Language: en-GB
To: Peter Collingbourne <pcc@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>,
 "david@redhat.com" <david@redhat.com>,
 =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?=
 <chinwen.chang@mediatek.com>,
 "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
 =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?=
 <Kuan-Ying.Lee@mediatek.com>, =?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?=
 <casper.li@mediatek.com>,
 "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
 vincenzo.frascino@arm.com, Alexandru Elisei <alexandru.elisei@arm.com>,
 will@kernel.org, eugenis@google.com
References: <20230517022115.3033604-1-pcc@google.com>
 <20230517022115.3033604-4-pcc@google.com>
From: Steven Price <steven.price@arm.com>
In-Reply-To: <20230517022115.3033604-4-pcc@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: steven.price@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of steven.price@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=steven.price@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 17/05/2023 03:21, Peter Collingbourne wrote:
> As a result of the previous two patches, there are no circumstances
> in which a swapped-in page is installed in a page table without first
> having arch_swap_restore() called on it. Therefore, we no longer need
> the logic in set_pte_at() that restores the tags, so remove it.
> 
> Because we can now rely on the page being locked, we no longer need to
> handle the case where a page is having its tags restored by multiple tasks
> concurrently, so we can slightly simplify the logic in mte_restore_tags().
> 
> Signed-off-by: Peter Collingbourne <pcc@google.com>
> Link: https://linux-review.googlesource.com/id/I8ad54476f3b2d0144ccd8ce0c1d7a2963e5ff6f3

This is much neater, thanks for figuring out a better way of
implementing it. The set_pte_at() thing always felt like a hack, but it
was always there for the non-swap case and I obviously never figured out
a better solution.

Reviewed-by: Steven Price <steven.price@arm.com>

> ---
> v3:
> - Rebased onto arm64/for-next/fixes, which already has a fix
>   for the issue previously tagged, therefore removed Fixes:
>   tag
> 
>  arch/arm64/include/asm/mte.h     |  4 ++--
>  arch/arm64/include/asm/pgtable.h | 14 ++----------
>  arch/arm64/kernel/mte.c          | 37 ++++++--------------------------
>  arch/arm64/mm/mteswap.c          |  7 +++---
>  4 files changed, 14 insertions(+), 48 deletions(-)
> 
> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
> index c028afb1cd0b..4cedbaa16f41 100644
> --- a/arch/arm64/include/asm/mte.h
> +++ b/arch/arm64/include/asm/mte.h
> @@ -90,7 +90,7 @@ static inline bool try_page_mte_tagging(struct page *page)
>  }
>  
>  void mte_zero_clear_page_tags(void *addr);
> -void mte_sync_tags(pte_t old_pte, pte_t pte);
> +void mte_sync_tags(pte_t pte);
>  void mte_copy_page_tags(void *kto, const void *kfrom);
>  void mte_thread_init_user(void);
>  void mte_thread_switch(struct task_struct *next);
> @@ -122,7 +122,7 @@ static inline bool try_page_mte_tagging(struct page *page)
>  static inline void mte_zero_clear_page_tags(void *addr)
>  {
>  }
> -static inline void mte_sync_tags(pte_t old_pte, pte_t pte)
> +static inline void mte_sync_tags(pte_t pte)
>  {
>  }
>  static inline void mte_copy_page_tags(void *kto, const void *kfrom)
> diff --git a/arch/arm64/include/asm/pgtable.h b/arch/arm64/include/asm/pgtable.h
> index 0bd18de9fd97..e8a252e62b12 100644
> --- a/arch/arm64/include/asm/pgtable.h
> +++ b/arch/arm64/include/asm/pgtable.h
> @@ -337,18 +337,8 @@ static inline void __set_pte_at(struct mm_struct *mm, unsigned long addr,
>  	 * don't expose tags (instruction fetches don't check tags).
>  	 */
>  	if (system_supports_mte() && pte_access_permitted(pte, false) &&
> -	    !pte_special(pte)) {
> -		pte_t old_pte = READ_ONCE(*ptep);
> -		/*
> -		 * We only need to synchronise if the new PTE has tags enabled
> -		 * or if swapping in (in which case another mapping may have
> -		 * set tags in the past even if this PTE isn't tagged).
> -		 * (!pte_none() && !pte_present()) is an open coded version of
> -		 * is_swap_pte()
> -		 */
> -		if (pte_tagged(pte) || (!pte_none(old_pte) && !pte_present(old_pte)))
> -			mte_sync_tags(old_pte, pte);
> -	}
> +	    !pte_special(pte) && pte_tagged(pte))
> +		mte_sync_tags(pte);
>  
>  	__check_safe_pte_update(mm, ptep, pte);
>  
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 7e89968bd282..c40728046fed 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -35,41 +35,18 @@ DEFINE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
>  EXPORT_SYMBOL_GPL(mte_async_or_asymm_mode);
>  #endif
>  
> -static void mte_sync_page_tags(struct page *page, pte_t old_pte,
> -			       bool check_swap, bool pte_is_tagged)
> -{
> -	if (check_swap && is_swap_pte(old_pte)) {
> -		swp_entry_t entry = pte_to_swp_entry(old_pte);
> -
> -		if (!non_swap_entry(entry))
> -			mte_restore_tags(entry, page);
> -	}
> -
> -	if (!pte_is_tagged)
> -		return;
> -
> -	if (try_page_mte_tagging(page)) {
> -		mte_clear_page_tags(page_address(page));
> -		set_page_mte_tagged(page);
> -	}
> -}
> -
> -void mte_sync_tags(pte_t old_pte, pte_t pte)
> +void mte_sync_tags(pte_t pte)
>  {
>  	struct page *page = pte_page(pte);
>  	long i, nr_pages = compound_nr(page);
> -	bool check_swap = nr_pages == 1;
> -	bool pte_is_tagged = pte_tagged(pte);
> -
> -	/* Early out if there's nothing to do */
> -	if (!check_swap && !pte_is_tagged)
> -		return;
>  
>  	/* if PG_mte_tagged is set, tags have already been initialised */
> -	for (i = 0; i < nr_pages; i++, page++)
> -		if (!page_mte_tagged(page))
> -			mte_sync_page_tags(page, old_pte, check_swap,
> -					   pte_is_tagged);
> +	for (i = 0; i < nr_pages; i++, page++) {
> +		if (try_page_mte_tagging(page)) {
> +			mte_clear_page_tags(page_address(page));
> +			set_page_mte_tagged(page);
> +		}
> +	}
>  
>  	/* ensure the tags are visible before the PTE is set */
>  	smp_wmb();
> diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
> index cd508ba80ab1..3a78bf1b1364 100644
> --- a/arch/arm64/mm/mteswap.c
> +++ b/arch/arm64/mm/mteswap.c
> @@ -53,10 +53,9 @@ void mte_restore_tags(swp_entry_t entry, struct page *page)
>  	if (!tags)
>  		return;
>  
> -	if (try_page_mte_tagging(page)) {
> -		mte_restore_page_tags(page_address(page), tags);
> -		set_page_mte_tagged(page);
> -	}
> +	WARN_ON_ONCE(!try_page_mte_tagging(page));
> +	mte_restore_page_tags(page_address(page), tags);
> +	set_page_mte_tagged(page);
>  }
>  
>  void mte_invalidate_tags(int type, pgoff_t offset)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/993ee407-cd7a-ab14-9d66-2e1009e05d3a%40arm.com.
