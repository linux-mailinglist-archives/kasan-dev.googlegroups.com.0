Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBB75TOAAMGQE6VEH62A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 664A72FBB81
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 16:45:12 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id j1sf18579325qtd.13
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jan 2021 07:45:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611071111; cv=pass;
        d=google.com; s=arc-20160816;
        b=IPennFhMlDaU6zfAkISt8ZtXLkJ7ynwhNpi080uXHuKQz+yyazXRb4N9/j+k3is3sX
         DoYBWrXBunqln/3NAPupiitRbllM0WYzjxPuf4TLvpJpUvKjx5dGzndI30YXq71O+n4f
         Q4FgJUCkKO0ggGCVP/ayDeD9gEaN7Rcfbxxnc897ep4ROlts7ReKQBuLj+pkYr0/w1zo
         Jw1tmX3AcxWZT/fFf8xc9C8nBHA6rJn/IvtPRRPaUHKxOpLUhGgEY7tzUH8bo2SMLMh/
         3ELdpwU6i6NgTRrjKAjzLlWr46GXZNMs9JtU5QE8ItX962iy7Ydv7gSfJx4w+gbkM9sW
         sjZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=hjircLO2g1LTT+bkkJ/FfrTTZPUzD0c6KC8DObuJt6M=;
        b=KLZrn+u/2/eeBy2lSCCER9aa1Pk8ajQpmwA1YlOKbuncE1AOhkAbscp3/a+tLXsaAi
         mYwpVOFnXE6ueYRSGg4dPXyDQF2Xfg9M6UoasA8deiEeiLcLkbYkPi8KXXtaZF0wsGrK
         FD8Progd2ItIxpOarLifwbuPtLGW1PhQ8WrVuwyoMpX9vQjJ5EK08l2a1TVtCyDjJgf/
         NOA+/jp4DSOsSK2r5lj/vVNJqJBQKskPMQKsvBGwm4ZHD7PnhImPChtSomIRLQ/hANL+
         ZNSI/ogYyz3MCqDzePYT9V2l0rgmkJKZV+uw6FOFnV14318GGwH0aqvZJE77c9K7Tstx
         PxMw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=hjircLO2g1LTT+bkkJ/FfrTTZPUzD0c6KC8DObuJt6M=;
        b=oD+WTa56KxJ9fRkZBIoH875VZOvfXwcbWcvQ4RsTcRMFFSgv7nSFvogr8bXGUewgSf
         y4iTtDly5LPaoV6K3SivYw8MQYw1XmEHZkumo2WAyhiPtkditYgl19P1pzrDr2RSxuYn
         HdaIcYv5c4oCvyIdr9+rpUO7+cu1zNivzHHkJoNbClv2mRQGjU/1TENd+Uc+YXwQFKWu
         wnIRSZX5qjuzgzQ2639Q2QsY8aUq9HXrrQj1dJFtlcVdQT8hYYeP2gTZs80yeoA9WKWZ
         VmKm2sTS8uqVZy+E/NG4ZKnRFgcE8JhJkrfWpRfRtDYaqdH7UfB/empHHT2477h3a88A
         IJ0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=hjircLO2g1LTT+bkkJ/FfrTTZPUzD0c6KC8DObuJt6M=;
        b=eTJ3q9SQMPPp5H3kPn6FwcC0nmqXZT6b6M1iaPM8JGCFYxMhmMwdXo05bxI4n4UhY/
         fSYVSKzz4ugNWEZKZ14a89mVHDFj6vmxKn0ch4NH64ybnmJCv2djj1edmRwSm2bDjZzm
         vbNt8+nEUIPTNuNmfOsKf308p6aav0xH5ECq9zkyjUjhFyhgkiWw98gcuOgb1dhVjiI9
         GPJ/09jaUrfUFjHTQFAMqwDXqmBYaqKM9XRyqrjD5Mam99rH1ruKJPrqcexpnKVgUi7C
         Q6C4MZyKlULUdGaNZD7roa0XSwnngeQ583/HIL16rBdePqlw+xTgQYG77yl3Csu5/+ES
         iVrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5324cdug8PCtKeXAMWYok9fP0HaYT/5uJcvAZ8c1Uri0F/9qO5sV
	qOtJSyXFwzxLAIpAQPjd6JA=
X-Google-Smtp-Source: ABdhPJwa9Wbnb3/QxycIGfXO3NZIoALShbnMEvkhOCo2XKBu1IzMzld7TArTyoVI45zJ24ROkbujYA==
X-Received: by 2002:a0c:fe90:: with SMTP id d16mr5076868qvs.13.1611071111414;
        Tue, 19 Jan 2021 07:45:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:44d:: with SMTP id cc13ls214648qvb.4.gmail; Tue, 19
 Jan 2021 07:45:10 -0800 (PST)
X-Received: by 2002:a05:6214:13a3:: with SMTP id h3mr4692186qvz.5.1611071110891;
        Tue, 19 Jan 2021 07:45:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611071110; cv=none;
        d=google.com; s=arc-20160816;
        b=guhxa7KUslt1Y/gV5g9/IlR/f/glmQ1pP7GgZu3G42g316VHTqvYhyFOM2p8nVmtwV
         uAQ8pMfz2FNESClB0FbP4ycHRUtnKA6pN7p/sYCNQtLGH7RM0hPpD2T0VeGd/Sup/jp7
         HdVTUTGotw5RzaRg843yuygkb6SU1sQyIJhTFNTIWIiwT1yNzgX4GEsaGQ+c45bgPoZW
         ED9gDO+1/89ACkQ2lWZHSHb8LG4LIAO6Xb8i0USkxdsFfbIzEBr3wlgSuca/aRBSB/VT
         V0nIH8maxRspSZfqppuLlTkCSX3aMb8oe5QFYvI3VlTN0QkNzNb/ivNvBQ3aRh0JXAnc
         Op9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=2I16Ow3I9zE4C13eUC0TR58xC2hvKXaS0eotpxfxBY0=;
        b=qstpYK+6g4BSdYscXJzsBREJDEKIPyXJt/UtfBgK9Zk/1/qyAfV1ihcQJV/9loyUuw
         sxtTXRM71AQON/SrJESox6GLzZoUMiyTisoTtBapNRqDDu2WuHC9mloJSBWmIziXoHfp
         zsKasIb+Mg4a+zh7x56nFNGRWURnexZKeSX7q7dOnRHNCZBzE1PES9AJM9kiDK7Zdz5K
         BofRMEZA+3m23ld8pX3uF2GAh3EExfbFovfu/ESNQwt6vQ6c2iPw7PrtBYNeqyjK2Yum
         OZStzaSpcDhpqh1PpHcDpIo6c00T+KXmJ1Tzhpu8KLMrm/hiuYuEBWaMgGoDRWACEvFR
         ncWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p55si2398691qtc.2.2021.01.19.07.45.10
        for <kasan-dev@googlegroups.com>;
        Tue, 19 Jan 2021 07:45:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 42A7BD6E;
	Tue, 19 Jan 2021 07:45:10 -0800 (PST)
Received: from [10.37.8.29] (unknown [10.37.8.29])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id B62A03F66E;
	Tue, 19 Jan 2021 07:45:07 -0800 (PST)
Subject: Re: [PATCH v4 5/5] arm64: mte: Inline mte_assign_mem_tag_range()
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <20210118183033.41764-6-vincenzo.frascino@arm.com>
 <20210119144459.GE17369@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1bb4355f-4341-21a7-0a53-a4a27840adee@arm.com>
Date: Tue, 19 Jan 2021 15:48:56 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210119144459.GE17369@gaia>
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

On 1/19/21 2:45 PM, Catalin Marinas wrote:
> On Mon, Jan 18, 2021 at 06:30:33PM +0000, Vincenzo Frascino wrote:
>> mte_assign_mem_tag_range() is called on production KASAN HW hot
>> paths. It makes sense to inline it in an attempt to reduce the
>> overhead.
>>
>> Inline mte_assign_mem_tag_range() based on the indications provided at
>> [1].
>>
>> [1] https://lore.kernel.org/r/CAAeHK+wCO+J7D1_T89DG+jJrPLk3X9RsGFKxJGd0ZcUFjQT-9Q@mail.gmail.com/
>>
>> Cc: Catalin Marinas <catalin.marinas@arm.com>
>> Cc: Will Deacon <will@kernel.org>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  arch/arm64/include/asm/mte.h | 26 +++++++++++++++++++++++++-
>>  arch/arm64/lib/mte.S         | 15 ---------------
>>  2 files changed, 25 insertions(+), 16 deletions(-)
>>
>> diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
>> index 237bb2f7309d..1a6fd53f82c3 100644
>> --- a/arch/arm64/include/asm/mte.h
>> +++ b/arch/arm64/include/asm/mte.h
>> @@ -49,7 +49,31 @@ long get_mte_ctrl(struct task_struct *task);
>>  int mte_ptrace_copy_tags(struct task_struct *child, long request,
>>  			 unsigned long addr, unsigned long data);
>>  
>> -void mte_assign_mem_tag_range(void *addr, size_t size);
>> +static inline void mte_assign_mem_tag_range(void *addr, size_t size)
>> +{
>> +	u64 _addr = (u64)addr;
>> +	u64 _end = _addr + size;
>> +
>> +	/*
>> +	 * This function must be invoked from an MTE enabled context.
>> +	 *
>> +	 * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
>> +	 * size must be non-zero and MTE_GRANULE_SIZE aligned.
>> +	 */
>> +	do {
>> +		/*
>> +		 * 'asm volatile' is required to prevent the compiler to move
>> +		 * the statement outside of the loop.
>> +		 */
>> +		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
>> +			     :
>> +			     : "r" (_addr)
>> +			     : "memory");
>> +
>> +		_addr += MTE_GRANULE_SIZE;
>> +	} while (_addr != _end);
>> +}
> 
> While I'm ok with moving this function to C, I don't think it solves the
> inlining in the kasan code. The only interface we have to kasan is via
> mte_{set,get}_mem_tag_range(), so the above function doesn't need to
> live in a header.
> 
> If you do want inlining all the way to the kasan code, we should
> probably move the mte_{set,get}_mem_tag_range() functions to the header
> as well (and ideally backed by some numbers to show that it matters).
> 
> Moving it to mte.c also gives us more control on how it's called (we
> have the WARN_ONs in place in the callers).
> 

Based on the thread [1] this patch contains only an intermediate step to allow
KASAN to call directly mte_assign_mem_tag_range() in future. At that point I
think that mte_set_mem_tag_range() can be removed.

If you agree, I would live the things like this to give to Andrey a chance to
execute on the original plan with a separate series.

I agree though that this change alone does not bring huge benefits but
regressions neither.

If you want I can add something to the commit message in the next version to
make this more explicit.

Let me know how do you want me to proceed.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1bb4355f-4341-21a7-0a53-a4a27840adee%40arm.com.
