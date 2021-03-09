Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB2UYTWBAMGQECL7SUII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6AF3E3322E1
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 11:22:35 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id m5sf7413387pgu.21
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 02:22:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615285354; cv=pass;
        d=google.com; s=arc-20160816;
        b=qYzO3nSo8hyHuhQhs0W7zTQ/eDs30jTmQfLVStO4WTSutkN93Ei5tVIODy88pZgAvP
         8zrvEPaoFKU8bOCS5fRi/SwAbmRLVS80vXb0CzkRUeH9X7aOm21vor0W8VpFEdQf1p+F
         B8pSKjr7xrQYbIZejlQtmuLAfQP1u1wyNm8abtstWw2zJElqKUFD+1kiWc9RS1FeyvzB
         +QCLQ4PmsSTz1i17HIvleAM0aKgMdkmBScOnyg0m3o5QE5d7j1BbxBo4erMLvH9zSSi+
         RC5r6i4ldzMi2TupC1dhLfP8p4FjOyXgqWGfInXWV5Jui0PlONlfH6qNYJ4FtcWbgv+3
         OghQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=YFq1mL+nQlSl0Ygg4z9+hFbOou0ctIUnG/kIWptGyZI=;
        b=g4tjarHzR0cnQLlxOIHTlrmOpftprRFBJL/2PhcnwXsaTnzSJ0GZMy8w7SkzxMzLjW
         q5Ypy8KNshimEeKEVfluFfZGVA/bsOJu0+wL4TN1b0kSH8MLfk3CEVxg1/6StSkw1UeH
         ftqOFDUx1r//qfP8EEdM1x+X4CP4pNdJkuIoXGWYhw5whsyKSetIELgtX++E9zHFSgFZ
         F5TNFLkiDPnGhCPtWmqyA+2VcCoUsJeGLXgbVBbbahiLSCPCh4BTAiI3UGceh7uWV65Y
         dDyeOJnSscBY3yaE976zgv5v2ufJDKt0vuprrxag18uX79qv3q9dUP1vcFCaN1NTBqw0
         gTqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YFq1mL+nQlSl0Ygg4z9+hFbOou0ctIUnG/kIWptGyZI=;
        b=ElxPLZi/rmDGGaTBvWe/zBY7pGzJQEUxXeH3XRD6SWSP0oVQ68R9OXTbaaKmhPRtEJ
         3HbwJ8G3pMxJLoqNRWHTMCq9TEMjL7i4+iygx45CSq3wkM/bmLZV0D3iaNsSuCblrhB4
         tG8LTv/qpFVPfd8ld+KGfXvjQR5mTgegN5mR2duE3ilf/FE04n/RT9xzu6MDTrRUfsWS
         N9ZtFbd3Sisc0QO74zUpfK+IA9yOl6tiAlbxZcien97Rjj0uJT32/uhjxHum9j7Z9RJm
         y7/q5IAIdeQKZMebLU66tGyTAlBUUTzNCMIug4mf/RkUbRpxzyHQfNn9lzlOaF70lI3l
         +NlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YFq1mL+nQlSl0Ygg4z9+hFbOou0ctIUnG/kIWptGyZI=;
        b=RUdEu4Zq54/6SWQWTVpmCnmnGZgXLBFXuob3t1yKwNmpMD2g8XlPxVUZ17drrzYe6X
         paeXyMjLWKGiRxU+YMEpuxB4r6B0RdIDZwmGV4uBqRNh1q3oMsXJ+o4aks8ODLeqNkBD
         xZkNJuJQqsrbnuUrez6rCe3KIB9aOaPFooDQRxOLl1MF/liD8y7CO9+Od9NQ4b1hhA1O
         K1ohEEsSieJlXmnHjaAYl1FuhbRjl+ivsRKZ2lec18JjXYxQRQmtlV2j5El9Mh5otQvk
         xAIGEIQ6QQL6fV70fYcFWodYcbNhzlBOBQpeWwAq2cmljevjhuBBKGCuBIv43vH+HnQx
         TsQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RJ9AagpqbYkz6Bcob1xQZTW03O0y2VAGESFizTqOd0R8sKvfB
	BqoJsCeLNgyi9gNeNnUqpWw=
X-Google-Smtp-Source: ABdhPJymQgcRukciuC9dKpHrqglYiSlcrAWKr8SCnYkvg//lsce33tMAx/r6CkfwaAsaNP5Z9i+QXw==
X-Received: by 2002:a63:f950:: with SMTP id q16mr15701870pgk.392.1615285354088;
        Tue, 09 Mar 2021 02:22:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd8b:: with SMTP id z11ls1711203pjr.1.gmail; Tue, 09
 Mar 2021 02:22:33 -0800 (PST)
X-Received: by 2002:a17:90a:d3c4:: with SMTP id d4mr3848093pjw.31.1615285353620;
        Tue, 09 Mar 2021 02:22:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615285353; cv=none;
        d=google.com; s=arc-20160816;
        b=WhTSX/u3bXQ8Ph7VLTLZBgBpQOiQjfR6VuvxH6B+51wGzSaKxXYfqROzAH5wOXv95J
         d8mrYN+OjxgH2+L+zIhKyB/uXBeXAQZg027KXFZJrhhpCyuwdwXIjWdA3F7g+5jtZdzw
         tniD+/Z0n1QYDRvyp8T28V6/lY6MT7wVV39avuuijkZgkJnMM0zGfzVDSbn0j4fq57tv
         7xBjYxSJHbJmYfxbpBTlJVewXRypCZYUeeFF+iLF6wKYr786LnWz2LhPj+V49Iwdfoxb
         B6+boAYzbLrKE3lF5sSUep1KKSySVU9X7/PAw5S7OGJZ2D4Z1nEMXbJK0UXWE+biNTD5
         q8Cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=GpV9Zw+xz80daU7fcuapkYMK1sZozCGnbLQyNp/DzAs=;
        b=aH30TRzptM/bifadzpDJsTPKb1JSV/bHrvSuoMerRkpW4+bWKJgjvtvPIsxWp5C+F0
         tAEOUcPpa+2yzL+v312taqWsaeDe3byv9ALEC0bUSkqNB982aODnzGVVjACxNq+XHTw6
         qDj+fOihYTlp2n4NTT9k3ZBgEDDv4vkI7xwRxK+YGymZ9DGCzxyb8NubLlwF4ZnziWYR
         /DT95qijsPEkjUCUKwOzw7lrg7mpyE0QyU9zSndL8h4jLixxtmkjcAis1XVLRjI5+29R
         lEjiJlfJU/w7r2b27NFxW28SfgdK5XZMJQy3BCCTcroXUYlvhxcl9Ub3Kd8EDWRVtw9o
         qPjA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 145si87968pfb.0.2021.03.09.02.22.33
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Mar 2021 02:22:33 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A70FA31B;
	Tue,  9 Mar 2021 02:22:32 -0800 (PST)
Received: from [10.37.8.8] (unknown [10.37.8.8])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 91BBD3F71B;
	Tue,  9 Mar 2021 02:22:29 -0800 (PST)
Subject: Re: [PATCH v14 5/8] arm64: mte: Enable TCO in functions that can read
 beyond buffer limits
To: Mark Rutland <mark.rutland@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
 <20210308161434.33424-6-vincenzo.frascino@arm.com>
 <20210308180910.GB17002@C02TD0UTHF1T.local>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <42b39ecc-4f97-63bf-cdab-2ba4817b8610@arm.com>
Date: Tue, 9 Mar 2021 10:26:54 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210308180910.GB17002@C02TD0UTHF1T.local>
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

On 3/8/21 6:09 PM, Mark Rutland wrote:
>> +DECLARE_STATIC_KEY_FALSE(mte_async_mode);
> Can we please hide this behind something like:
> 
> static inline bool system_uses_mte_async_mode(void)
> {
> 	return IS_ENABLED(CONFIG_KASAN_HW_TAGS) &&
> 		static_branch_unlikely(&mte_async_mode);
> }
> 
> ... like we do for system_uses_ttbr0_pan()?
>

I agree, it is a cleaner solution. I will add it to v15.

> That way the callers are easier to read, and kernels built without
> CONFIG_KASAN_HW_TAGS don't have the static branch at all. I reckon you
> can put that in one of hte mte headers and include it where needed.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/42b39ecc-4f97-63bf-cdab-2ba4817b8610%40arm.com.
