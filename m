Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZORRP6QKGQE2VNFMPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D3F92A6BF9
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 18:46:15 +0100 (CET)
Received: by mail-pf1-x43b.google.com with SMTP id a27sf15282879pfl.17
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 09:46:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604511974; cv=pass;
        d=google.com; s=arc-20160816;
        b=YSEL84DDIWtzUj05RqFa2xO7S3dlz/eQQz+fdwFePeypfn0qSayvqI8NNTs/XC8/qA
         7722IIa7LENMND+2zdb9qRRGWp+QZWOVPABv/pJQGeN6XcbLeRob5qCjGk1u+crnSct/
         GRdiZhoEmLGPVt/FIMQKB7k3iN/j5Nfy6DJ4pZA+AVraYAO9D7HmPi0OiG4Jc/o/XxaI
         sYeZ4TrdKB5IXCBNdqmR9qvsgn2eot524IDFEEYZWohZjchenddV4rPYacUDsmMWRZ7h
         7oX0eBS3q+eub/+svOtA3yQxWCpCVTqMVABM4FWHeXknBDL+yFf6fEksBSGCIfriLTGd
         /U5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=aDxLLFPOeCUnizkv5Zxng9KyGd2n60gO4NNN8Nxy7gs=;
        b=xvnIjq+i8uynLoNGBG6GuMbsanKYuDguEoP/vHLUgWNg26vKp9mw1tsLPnByPf+fj7
         3vCmv6q/qv6gnQF878zOIQ+lRZ4bboYd2CNemzGNLB7AG+AwyHTOx0fQqpLHKW04nUqy
         p0SYejWffMxJRfqShS6FhKlgT1gqjJtnYT02/rgtvyh3OTlfpd1eDj6pISW07YooDRWO
         Qio0LYzT2SJzPTcTAiLT4GG0NmHBMOcWvRXAirQn3/kWnUM2RRt62laEuhMekpvMnHVF
         bkwYQRJYjL5FvkPd5HagQJhVyULV8E21caScZibsK4bqD5alcH1GBfe+Ad+Mu4bvGHiy
         1ihA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aDxLLFPOeCUnizkv5Zxng9KyGd2n60gO4NNN8Nxy7gs=;
        b=ZMUlBCARh5+OAG1TehWv/2yL9z3wlH8CCalWRaQjz6MDZA6nqE7TXF/ffSTJU+nn7q
         LqMg1u5SPR1RMuPbu6ro4gwXyL4Hg/FGIaRBclkbQoM4s4I+dPlOohxD1SEbeqxgP2by
         SWu0aIF+Gfou+7YkkQe+Gquz4ROwhdpcHITBKha/lrerVkZ8FZHxZ8xGjgf4qUfyAZId
         KPoRP1m1D3XPUSsTekO4jwQgrjp8iFJamG/SqZVR3Y26R6a09pqrzGzfA1J84BSWFWaN
         rOH1OYc+/EDdQE/3Kc4PQDEOyj5tBeMqjbKSmUBClanI5LB3h0cF5fS+LrFb9zYag17t
         xd1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aDxLLFPOeCUnizkv5Zxng9KyGd2n60gO4NNN8Nxy7gs=;
        b=nw1NK2U5VPMx9BlVI/W1KKC+fvUsewydNACrTngnfSmvztjILeLMgEzZ3EKyDzWLM0
         7HFBrBRIVfsw0tw64KcG/imXc+w3jR+rFrJOmfbSPxkypdHFan8X6tlLpptp6uS1WXaU
         Ok0tF3/aCXt4Hczyj8PYBxJzOx8ujzD1xf56Iu752bwLka8lSMXfV7hU13jgo1TGzHaH
         7QFFE3BL/7vSWxHljaNAypRoV1SiL6WPXaLzG2s9krgTX07TklliCz0a1Xtj5skZA0+1
         PIzxaH5SRWIsI7DAVVos1oCzJBxehQlhzgqNrmmUBsrqEam7NueUzSC+20pefstIUi+x
         3T/A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531qhuNEOrJq6A8KCGakzEvGlNf3z6EBGEnfu+gfiyZjhde1liaj
	LoNGIzK+dhM5GeklVHjcOjs=
X-Google-Smtp-Source: ABdhPJxw0WiXn8M/eDfyPWyeZi6pGCZKY8nE3tDitJeZztQRJP11+BJZRgxLEW8l9B+Nq5TWof0HNg==
X-Received: by 2002:aa7:84d5:0:b029:18a:ae45:54bc with SMTP id x21-20020aa784d50000b029018aae4554bcmr20065781pfn.27.1604511973906;
        Wed, 04 Nov 2020 09:46:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:da56:: with SMTP id l22ls1196773pgj.9.gmail; Wed, 04 Nov
 2020 09:46:13 -0800 (PST)
X-Received: by 2002:a62:2c16:0:b029:15d:8d2:2e6d with SMTP id s22-20020a622c160000b029015d08d22e6dmr31637754pfs.52.1604511973346;
        Wed, 04 Nov 2020 09:46:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604511973; cv=none;
        d=google.com; s=arc-20160816;
        b=KTBZg177IMwaQRgK9TmW9Sop0M0erKT3N8dXgrw/9jNoDzTMBAZ8uJgvcHrbKfV/s1
         /MabEuniFaN2vrgb5f+mdIfaAyUqeTJjOTGhPFGlpjoZmfumIgUfrQeHS30lh+pRL9B2
         iIyqBmo1za9HNCPwF1vOxtnIHWFI9fdNyQkfBwbH2xXSCzPEpVcNvg0Eg62nQCfPDswx
         qm01/mxSybEOQ3px4mbMopg9ecITqcJPUmqRQWeM3CqdTO7LsTHSaoogwFQqr8BRV17b
         /U1ZerBG1odIQ+nHXo+2AmEaRRJXsCppyOT6LJT4DXSArqoYnbxh90DwLQAloVqT7MD7
         I57A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=8TJw62LS6b76uDSkKr2F3IBqwny3MN7E3+jF3OYyHmI=;
        b=0wd2Xdr/+k0mFqWEujWu2HYrXVoIssbpItSBckDn/ZymMjXgxN8dvMi2Yb+UfkdQg0
         dr7d+T2L8yoPhzjto+lSk+o0AlBc/z3PMPrT3IBj/AGuR4jUbfNL+0gqph8iAUQ+IoJC
         eGaQBHTCi+vmD44Ab+8oU6UOecKaiKWspIE9uDgV19XpeuFAGX6zMBB8W6TjwBvcCPQK
         pYRoXvuYOxkaW4f71VnySq14rNUzby1iWo1Ndgjkc+IhAO+4e+Y4eX+o1CPFrlYmzDTx
         alwWFoU5S6KVWBqLexAclwx0qSQYRMDt7oNv0ON7Tj25z8fmj3pyEcTj4/hImcmZMZYr
         5+Vw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d2si227519pfr.4.2020.11.04.09.46.13
        for <kasan-dev@googlegroups.com>;
        Wed, 04 Nov 2020 09:46:13 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8B93A139F;
	Wed,  4 Nov 2020 09:46:12 -0800 (PST)
Received: from [10.37.12.41] (unknown [10.37.12.41])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A09DC3F718;
	Wed,  4 Nov 2020 09:46:09 -0800 (PST)
Subject: Re: [PATCH v5 02/40] arm64: mte: Add in-kernel MTE helpers
To: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, kasan-dev
 <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
References: <cover.1602535397.git.andreyknvl@google.com>
 <94dfda607f7f7a28a5df9ee68703922aa9a52a1e.1602535397.git.andreyknvl@google.com>
 <CACT4Y+YhWM0MhS8wVsAmFmpBf4A8yDTLuV-JXtFYr79FJ9GGrQ@mail.gmail.com>
 <CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <03d63c72-52fa-70e1-ecb9-657b2f300acd@arm.com>
Date: Wed, 4 Nov 2020 17:49:10 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com>
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

Hi Andrey/Dmitry,

sorry I missed this one.

On 10/29/20 4:50 PM, Andrey Konovalov wrote:
> On Wed, Oct 28, 2020 at 12:28 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>>
> 
> [...]
> 
>>> +void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>> +{
>>> +       void *ptr = addr;
>>> +
>>> +       if ((!system_supports_mte()) || (size == 0))
>>> +               return addr;
>>> +
>>> +       /* Make sure that size is MTE granule aligned. */
>>> +       WARN_ON(size & (MTE_GRANULE_SIZE - 1));
>>> +
>>> +       /* Make sure that the address is MTE granule aligned. */
>>> +       WARN_ON((u64)addr & (MTE_GRANULE_SIZE - 1));
>>> +
>>> +       tag = 0xF0 | tag;
>>> +       ptr = (void *)__tag_set(ptr, tag);
>>> +
>>> +       mte_assign_mem_tag_range(ptr, size);
>>
>> This function will be called on production hot paths. I think it makes
>> sense to shave off some overheads here.
>>
>> The additional debug checks may be useful, so maybe we need an
>> additional debug mode (debug of MTE/KASAN itself)?
>>
>> Do we ever call this when !system_supports_mte()? I think we wanted to
>> have static_if's higher up the stack. Having additional checks
>> scattered across lower-level functions is overhead for every
>> malloc/free.
>>
>> Looking at how this is called from KASAN code.
>> KASAN code already ensures addr/size are properly aligned. I think we
>> should either remove the duplicate alignment checks, or do them only
>> in the additional debugging mode.
>> Does KASAN also ensure proper tag value (0xF0 mask)?
>>
>> KASAN wrapper is inlined in this patch:
>> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3699
>> but here we still have 2 non-inlined calls. The
>> mte_assign_mem_tag_range is kinda inherent since it's in .S. But then
>> I think this wrapper should be inlinable.
>>
>> Also, can we move mte_assign_mem_tag_range into inline asm in the
>> header? This would avoid register spills around the call in
>> malloc/free.
>>
>> The asm code seems to do the rounding of the size up at no additional
>> cost (checks remaining size > 0, right?). I think it makes sense to
>> document that as the contract and remove the additional round_up(size,
>> KASAN_GRANULE_SIZE) in KASAN code.
> 
> These are all valid concerns. It would be great to have inline asm
> mte_assign_mem_tag_range() implementation. We can also call it
> directly from KASAN code without all these additional checks.
> 
> Perhaps it makes sense to include this change into the other series
> that adds the production mode. And then squash if we decide to put
> both changes into a single one.
> 
> Vincenzo, could you write a patch that adds inline asm
> mte_assign_mem_tag_range() implementation?
> 

As Andrey said those are valid concerns, this function was originally thought
for the debugging version of kasan, but since we are planning to use it in
production the inline optimization sounds a good approach.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/03d63c72-52fa-70e1-ecb9-657b2f300acd%40arm.com.
