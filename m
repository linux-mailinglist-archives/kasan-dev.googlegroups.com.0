Return-Path: <kasan-dev+bncBDDL3KWR4EBRB6HE3T5QKGQEAQR3UOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2949D28148C
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 16:00:25 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id a2sf1066294iod.13
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 07:00:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601647224; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nvx8DDPBxdSxnB+jjhK4gT/f32IZeeU2fJsTmyw6BYkskRdSeW8RRWoohv8Rd8hdpG
         A9Q0ALlhjiRuppDLUoU4SYXkKEvjHCUwgA5YfybB9SA6B9cKsjo8IjrpufXul0iaqPjK
         C99xZTAREC20TL6NJfDhklaO7SkvpaSNQbh/8F4TbrMfH3gS+CWwViWVFLXXsAAJGRoM
         WjgGkWGfVhDAFH1td4tyAKkdV+Pi+gCgBl1aFyepTFTY19UetDahnyqZBFu8+ONadLlP
         TfQ+NwW71WJIuISnQnu0PQlS3YIMzh8p5GibTpys8jUGeC85WotTNo2ARTq37sbTezT2
         gndA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=++BqiQKKOee/pMWU0sLrOU6t3bJTvNvwbh88n7XQtXM=;
        b=iV1apZnSj2WQHjheVnzz9EYsuLmrK0VPn3lya9juL2+Rz9nJdohFuCFYpre/QoaKaY
         +PCQ3eIub5ErKm47qPMWgzlmJ6GRFlpym4H9gFpRinDia1rEBOdKg7StjOTtoixq1lEV
         nxT3qp2tzBWBYqOEeegMdDKou/CMq33mBrDot1Z1LEV4tJYnsUuGnJBq+cRiByzUI58b
         J0ldyvWTc5rBdnDBDsLzXwVD0V2c7tJLDny8gRCiPmV4uFtkcc1xa+qFbf+grrE9CyYh
         6/pqitb0lEsj0JylccaOCtr8SdydIXPCtUhMQQ3Rk7i0icoI+sZinRTwp8F26D5uJ0q8
         OsWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=++BqiQKKOee/pMWU0sLrOU6t3bJTvNvwbh88n7XQtXM=;
        b=lAF0vBmPKqjljyczKXCD/04TNTyPS9AOef2nuaoSM/EFASdB/YP92AtLWmmch38Cs0
         djT930HBZyda0tFqQNySROPPhw1YSBVoAu38e5NUgZTMKrKhyrGRykQkQ2/OaHzrUjPp
         hTofRTE8RNE5GUczMUd6aO2Up1ZkTfiCtqM+NtIFcRdcGXT3U7RYMtBUPVPwwmWw98Zw
         AocY1NVsywBDEHOGZEofriKpC8yXDef+JWFQBV70o+2+g5LvX7FEXqxz5JIDo4SyZHiy
         3XYgv3U7cqy1pqe2S7C+Wu1vT2MVu7f2jFWJNK+wnW6CInEmqBt8BOnF/En58HhhbgWe
         8Gcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=++BqiQKKOee/pMWU0sLrOU6t3bJTvNvwbh88n7XQtXM=;
        b=rWL2sVzwk4dPeoESP+KDv7IbxRSDj9EHJUJcBvPVuCptSPRd5/WCwm1UaQw832O9kS
         E1olp4GvebateN9oH3SFIgaK/YDqw6IYy+XH6MwNCNzJM+qaTWITCtlx/Gbo/ZJPp7CT
         SxpiyzQrzUwvZWOmrXLDdyEZpGY4KwGCRDAdX0zCr1Jm0HGZxxtucSh3pFvkYbWRWPXc
         jFQAsh/cLOuLAsatlgF71ZOqGCUJbQNn8s84+WvGIxQqkcq/0hDOlbaFk0WPIXLwjJBR
         NUEfuZK5eKrr+7Gv5nATqgb6yJVsxS1qVyDKNh5x0oa987NfHV1L8hv3rs1OXJdqNmZ8
         RYJA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533bpEDwNf1MZgrPGr22soJeNWfQGsDl23j2tA09p+9QDs71wequ
	1LKRNjq9iPcsxPR0poPusO0=
X-Google-Smtp-Source: ABdhPJyvcwHetjTOYlbXq/eqNFH+D9MhE7Vt8D4YzHkTsSDqR8XPsORoFWof0WsMgWG+KUo6eA19Ww==
X-Received: by 2002:a92:84d6:: with SMTP id y83mr1202442ilk.169.1601647224146;
        Fri, 02 Oct 2020 07:00:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:5bce:: with SMTP id c75ls372096ilg.8.gmail; Fri, 02 Oct
 2020 07:00:23 -0700 (PDT)
X-Received: by 2002:a92:cd49:: with SMTP id v9mr1982956ilq.177.1601647223736;
        Fri, 02 Oct 2020 07:00:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601647223; cv=none;
        d=google.com; s=arc-20160816;
        b=Y5TD9as8k0Ea/jaOOeLZ0yY/NRbY0wVzzk3+CZOotOzXce53/ulpoRBmvQSRwlWV22
         vvy862w2CdS1lqAt8d3iLtQhsW8DQu80Tc/Zhz5kWEj4CkqAfMgSSA3hOWGEx4YS5pnG
         DIZh2fwpcvCa05IHz+YfDQjszF4HdVP1lCL/GPDn/UGwFFIJY3Bx0GTJNxKHxHAZmwUH
         Zibanclw2VlX+1MBZdEbD1Z8qsqJ0O8XnHysc1YwdJNvnRnU3wJnpXPtSFQ8CQn66Vtn
         Wrp2P8f53FQcxOM7+U0+S72ah07+jv8AY4ceFZgq4ebexV38XnWxE794BazQHkV+KnXi
         +gew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=XlC11XvLPqC/odKpFXrOLzumeiqVmyylBxziOoswZTc=;
        b=RQRU3GeWcryo5YexhH34DbVkbdXiEfqDdunfnj2IkKFWPh1kbrms4+BnuBdvewRZfJ
         NVxDKawtf+IGdo6R/R36aqkSrGoc9+lRZN+iIr28XDMcOOnF7IG0K+zGZv47rkYpaOdw
         cW9dOqvuouT5WDUhpgbfY1mE9wa75o0w9guA7w5KrFbYeubwyjQuaKEPG7JmGyPoQNYU
         HLmHpBpQV7OUgw7q9yRkBZM7tPx8CUDqg9rmJAh8dWsdtjGe3kQvh21PPyXqiJo/ahsC
         BW/zA9QFs3x4tSxCWxFIoXKHvWWAjf3yN/LMqmpNiGrmdCL3hPiFlVaKAh9v6IvQ5AlK
         TxNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a13si110144ios.2.2020.10.02.07.00.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 02 Oct 2020 07:00:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [95.149.105.49])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 756C6206CD;
	Fri,  2 Oct 2020 14:00:20 +0000 (UTC)
Date: Fri, 2 Oct 2020 15:00:18 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v4 27/39] arm64: kasan: Enable in-kernel MTE
Message-ID: <20201002140017.GF7034@gaia>
References: <cover.1601593784.git.andreyknvl@google.com>
 <e8d5ed9bc12086670cbde30d390de32730d0371f.1601593784.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e8d5ed9bc12086670cbde30d390de32730d0371f.1601593784.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Oct 02, 2020 at 01:10:28AM +0200, Andrey Konovalov wrote:
> diff --git a/arch/arm64/mm/proc.S b/arch/arm64/mm/proc.S
> index 23c326a06b2d..6c1a6621d769 100644
> --- a/arch/arm64/mm/proc.S
> +++ b/arch/arm64/mm/proc.S
> @@ -40,9 +40,15 @@
>  #define TCR_CACHE_FLAGS	TCR_IRGN_WBWA | TCR_ORGN_WBWA
>  
>  #ifdef CONFIG_KASAN_SW_TAGS
> -#define TCR_KASAN_FLAGS TCR_TBI1
> +#define TCR_KASAN_SW_FLAGS TCR_TBI1
>  #else
> -#define TCR_KASAN_FLAGS 0
> +#define TCR_KASAN_SW_FLAGS 0
> +#endif
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define TCR_KASAN_HW_FLAGS SYS_TCR_EL1_TCMA1
> +#else
> +#define TCR_KASAN_HW_FLAGS 0
>  #endif
>  
>  /*
> @@ -427,6 +433,10 @@ SYM_FUNC_START(__cpu_setup)
>  	 */
>  	mov_q	x5, MAIR_EL1_SET
>  #ifdef CONFIG_ARM64_MTE
> +	mte_tcr	.req	x20
> +
> +	mov	mte_tcr, #0
> +
>  	/*
>  	 * Update MAIR_EL1, GCR_EL1 and TFSR*_EL1 if MTE is supported
>  	 * (ID_AA64PFR1_EL1[11:8] > 1).
> @@ -447,6 +457,9 @@ SYM_FUNC_START(__cpu_setup)
>  	/* clear any pending tag check faults in TFSR*_EL1 */
>  	msr_s	SYS_TFSR_EL1, xzr
>  	msr_s	SYS_TFSRE0_EL1, xzr
> +
> +	/* set the TCR_EL1 bits */
> +	mov_q	mte_tcr, TCR_KASAN_HW_FLAGS
>  1:
>  #endif
>  	msr	mair_el1, x5
> @@ -456,7 +469,11 @@ SYM_FUNC_START(__cpu_setup)
>  	 */
>  	mov_q	x10, TCR_TxSZ(VA_BITS) | TCR_CACHE_FLAGS | TCR_SMP_FLAGS | \
>  			TCR_TG_FLAGS | TCR_KASLR_FLAGS | TCR_ASID16 | \
> -			TCR_TBI0 | TCR_A1 | TCR_KASAN_FLAGS
> +			TCR_TBI0 | TCR_A1 | TCR_KASAN_SW_FLAGS
> +#ifdef CONFIG_ARM64_MTE
> +	orr	x10, x10, mte_tcr
> +	.unreq	mte_tcr
> +#endif

Don't we miss the TBI1 bit here? I think the v3 version of this patch
was better.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201002140017.GF7034%40gaia.
