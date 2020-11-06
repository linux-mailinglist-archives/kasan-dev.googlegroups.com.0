Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBVXNST6QKGQEPD56QTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id F02CB2A9592
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 12:43:19 +0100 (CET)
Received: by mail-pg1-x53a.google.com with SMTP id d4sf750726pgi.16
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 03:43:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604662998; cv=pass;
        d=google.com; s=arc-20160816;
        b=g61+G7VGaOv2Udw44racy8bcQDu8ytJLbMslv95SrsA0AQIHP4DO1k5oabE+68NWXe
         unong5dmEnM/aT1/12CSNYorHIRDRaHe6AatTVt+vOsEwNBcmmbCgsqZUor0pTgjzmWz
         6tIqjhum/TNlL1ckHkYJzePyASA/iZClSA+67Kc89/BCjsy7LcbiDVAZ/BpjfWB+9OPc
         6ZF2Lrc3iSXbp51A8JorvWqay/USRZVlmPgVl1N25VnhxrwinN+ctCsrVhImwKPutE+b
         UqvG9uoqbt0+7oljfpfW7RbO6EwWczgq75izlKMR+8PkQpk3loW/UQzKNtSj3hNIq4Zj
         IhNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=EgcGaSnBwE1gA3HcAoINx7tZWWvFgTYvJh2lr3zVKKw=;
        b=Yddn9eNRPfMQMerGL9z48TmERlLcdXJAiePbpKbDkbHuc555uYYYFWHeNLeekedjxO
         QlktTQHWy37+8tK+l1mTK1Yd0ZNvsA5EU1d2nLCiyc8CKKX2x86UEUu62ALII8eeNFK9
         /yGAyo9yu4m8lxHge3nMg8ar1wpYhk2r8g12HBFRABs5sUy0h1s+vSJUJIN4pfgH4Cg/
         27FEpfmjPDTJpLtr2tbZBGkJTh0dX37Pakd5JIxU2NK3uROEgOUOjNAVQ795WDxsy01N
         FBNBJpRMhGznbyYgqu5zIcUAIEpYlWu1TAzBjR4KPrJMVnEMdGmw40lekTxCf1N/C7yj
         7Mcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EgcGaSnBwE1gA3HcAoINx7tZWWvFgTYvJh2lr3zVKKw=;
        b=USwVL2FgdxWsOUrNEe8Wo/1nEofB+GLuHqpmdfhjDVdwNg1PfKZN2TQjryJEL111wz
         N+i+mD8Za/nE9cmOmsS5tOR3KBOKAhRcPEK7HgUS28K48UxDq0MkwZiLj02KisJ1tzr5
         RhpTUMRzp9BKJH66EalwseK1F89LEGT1iCEA9OehFoNc8jAfYocqzzHMEDEsfdaW2H/e
         aGsKzCQuDBOwdO2Vw+UAxEfmE6aoeJnRXPQDIH8qk/9IjHi+NBCFc1sJ9OnWiFvEB5Kx
         afh24QosQqkFPLAbv58qj38TQySqTWinM5KZvtT1HFULP202iwfThLdlhjojeqsYEBIv
         8QJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EgcGaSnBwE1gA3HcAoINx7tZWWvFgTYvJh2lr3zVKKw=;
        b=LtiUfXJlqGgEc/MeWD02nq+3F3If602N+ZlIhFaUxxEar5ma2c2pbqrFl7gTFKt+lE
         +GMBJaIqYuds7Yv9EcP2OLlRn3T9rEaekc/nGlxm60iF9OeKUrc6kpfdEaAXSIhcfz+b
         l2/JTcRSxsq6N7Jv+UQ16rAgWBHF2WiakjWjMKs6jLOrVyR4X4eoCcZOdDnIP3TZtATr
         u8lzNphEzNNIdJByVTU3WIx30RsH6eQ7uWQccugYqbOMgXBQqdgHSQkFpK8FY4KnSou/
         GxgSGabcHYGrDw9NbQ1VY9gvhKTQholMocGPuQsxoLlyIkJJD8ksgYElED7lWFEe+uar
         SLkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533VhJT7FhUljK9n4Z0zT0LLALWxc47JoWSyHt7Z/SJ7CtfDCq36
	6+1PJc212R1wxkTi2b6iw5s=
X-Google-Smtp-Source: ABdhPJzNWCjz0ToSufNInVtT+xu7/sCOWEk+YSw5Oq7qarubNqxgrTjS054QoS9ln3azmYzJ95cq0g==
X-Received: by 2002:a17:90a:e604:: with SMTP id j4mr1572851pjy.19.1604662998182;
        Fri, 06 Nov 2020 03:43:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:aa08:: with SMTP id k8ls740176pjq.0.gmail; Fri, 06
 Nov 2020 03:43:17 -0800 (PST)
X-Received: by 2002:a17:90b:180d:: with SMTP id lw13mr2127769pjb.149.1604662997651;
        Fri, 06 Nov 2020 03:43:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604662997; cv=none;
        d=google.com; s=arc-20160816;
        b=Z4eEohZ2r4hQ9Fu6l2rD8Ffa6/FBwYGc2i6Zv+GzdPn+eQcoqGwD1Ch0tz/Tbk3gYl
         LaFJq7xryqY9jMSrFGKShbffwiA3fJmcL9mWqDFrIPTTZZ1uyvoy9rKC0eTbY+Q9mQdk
         ENnQ8atbdVFa1mbsvezlFbtos3b++qOz29ECdS+gfyTaSDhdsyokYsUlr8kydi8mQNUb
         zN9qKpHpWfy1Yi7GGALECSbzNGZOU4txS78fNj8I3uxPwGO68/B0guUJrt3kHmHb3bs8
         Ea6GAtpMMpKYGGstz+3QKAooio7nxtrH5ShUTkhotk+T6J7HQAfahzRYsRJ6+4P+hwRN
         G61w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=LXWVMWqxHXyeaEVcRR/kSd+NRmGF1TIzasGUXCnNtdk=;
        b=jKRGk8daOK69Oth1Cce4wk8SwZ/n3XW7zK4T4BysqHYf19yD7134dJ8Kgx+J9P1eu/
         BwwoCdbt3PKK5NP+Hff3355dDwSK/R8VXX7dTHLNyIjpHMOug7A5/1Rrovzzp/Ql5pVV
         hR3kuCI05K0HAzUFw0l9VV/HsV3kvnlBrCWs+mTNzXJLd11bfwYMYbHJ3Zw/g74Ndwno
         ANsXIVvRQcwKX+Ye1Zk/QgdtC9iWb8fJMt4DcGcF07pgCdAzT1+Nmvnu4ALXGIi54IIX
         P7tACehB7CIxAwGUip3PqkyUlj25C2ZwSYrbkCL5WedQmYq7DgUSrvFoJ0+uHTlIX6W6
         9M2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id j63si79796pfd.1.2020.11.06.03.43.17
        for <kasan-dev@googlegroups.com>;
        Fri, 06 Nov 2020 03:43:17 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B9E07147A;
	Fri,  6 Nov 2020 03:43:16 -0800 (PST)
Received: from [10.37.12.46] (unknown [10.37.12.46])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 565C13F719;
	Fri,  6 Nov 2020 03:43:14 -0800 (PST)
Subject: Re: [PATCH v8 28/43] arm64: mte: Reset the page tag in page->flags
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1604531793.git.andreyknvl@google.com>
 <fc9e96c022a147120b67056525362abb43b2a0ce.1604531793.git.andreyknvl@google.com>
 <20201105155859.GA30030@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <01a55e00-0d82-7e62-cc40-c282149dbb08@arm.com>
Date: Fri, 6 Nov 2020 11:46:15 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201105155859.GA30030@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Catalin,

On 11/5/20 3:59 PM, Catalin Marinas wrote:
> On Thu, Nov 05, 2020 at 12:18:43AM +0100, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 8f99c65837fd..06ba6c923ab7 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -34,6 +34,7 @@ static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>>  			return;
>>  	}
>>  
>> +	page_kasan_tag_reset(page);
>>  	mte_clear_page_tags(page_address(page));
> 
> I think we need an smp_wmb() between setting the flags and clearing the
> actual tags. If another threads reads page->flags and builds a tagged
> address out of it (see page_to_virt) there's an address dependency to
> the actual memory access. However, on the current thread, we don't
> guarantee that the new page->flags are visible before the tags were
> updated.
> 

Indeed, and I will add a comment as well to explain why.

>>  }
>>  
>> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
>> index 70a71f38b6a9..348f4627da08 100644
>> --- a/arch/arm64/mm/copypage.c
>> +++ b/arch/arm64/mm/copypage.c
>> @@ -22,6 +22,7 @@ void copy_highpage(struct page *to, struct page *from)
>>  	copy_page(kto, kfrom);
>>  
>>  	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
>> +		page_kasan_tag_reset(to);
>>  		set_bit(PG_mte_tagged, &to->flags);
>>  		mte_copy_page_tags(kto, kfrom);
> 
> Nitpick: move page_kasan_tag_reset() just above mte_copy_page_tags() for
> consistency with the other places where PG_mte_tagged is set before or
> after the actual tag setting.
> 

Fine, I will add it to the next iteration.

>>  	}
>> diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
>> index c52c1847079c..0e7eccbe598a 100644
>> --- a/arch/arm64/mm/mteswap.c
>> +++ b/arch/arm64/mm/mteswap.c
>> @@ -53,6 +53,7 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
>>  	if (!tags)
>>  		return false;
>>  
>> +	page_kasan_tag_reset(page);
>>  	mte_restore_page_tags(page_address(page), tags);

I just realized based on your comment above that we need smp_wmb() here as well.
I will add it with a comment as well.

> 
> There is another mte_restore_page_tags() caller in hibernate.c. That one
> doesn't need page_kasan_tag_reset() since the page->flags would have
> been already restored but please add a comment in that file why its not
> needed.
> 

Yes I will do, I agree on the reasoning, I will report it in the comments.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01a55e00-0d82-7e62-cc40-c282149dbb08%40arm.com.
