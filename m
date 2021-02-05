Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBCPP6WAAMGQE22LYGOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 54305310E29
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 17:51:25 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id w10sf4749431plg.1
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 08:51:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612543882; cv=pass;
        d=google.com; s=arc-20160816;
        b=CGNRRA4Gsi8I0fMdVXoocrHW/BPB0oTQE5IMVK+4STPps7bxx2oSMTby+GNhzP7ayc
         0igFetTd3Sa/INIS4OYzb1MfOyHLUD81M29xLCqcCQhC6jz0xVfITuMK9OXM+Ev925B4
         azi8/ILHK9RJ8UGYiRhkgT21b4czjyww9dvxBFfXeWAxypRQhhv1osxGjvH5jCGeBU3Z
         KX4hLB+bf2cQfTLTKs+LH2enxhlgCCW8/2xQ6j4G/iTrqjYLCVAjKzsfUIr3OmiIOw6m
         g2d9bI4SNV5LwwluUDmIfS2ITpQbkJ8i+MYkQRds5icO4igSbjyJGPzTu/PggiA41bUe
         oPuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=GwgQJyBmb6dYQ846Eon+A03ndTzM78c441vzNKFsLMo=;
        b=Ej54jTDCM1aS5KpH3Vtoj2BJwwWP7sLk8Z/zmVtkbUaFAJuHwPa2gdw+nn+0azMc13
         sMUQhL+HkSgr1uWSKSrlD7ub7Vfx2oKuz6iE2w+Tt6nAIVRgjcOqlcZg2A63dFTNLumu
         m2U4MIxgXBsY772l2tGkEe8faw+qB534fQHQ/ZQ7Df+Uoe5pzXBRC2nxncW6iK7MLhxq
         uPR6tRiBkReicDaVFtuHOaQShAwFTeRurgAUKFMXkr0cZj/NRLiv6/WZktXeXQg6XjZx
         o8q28xfoIJgs4/fr5/c7Y6dPGuJssagtlxmvT26WhU2PyNBaJ6O63pNv8sfFDT5jEVFl
         h46g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GwgQJyBmb6dYQ846Eon+A03ndTzM78c441vzNKFsLMo=;
        b=B8ECprN2C0YDHBLGx4fAyQ4IlE4lnEdV/rhyxPlAE+DDh0AdThUSP+qw1ph50/SJtp
         q/7DSobxOUkoNBjuVhTwLollDvZb2ZdIpWcquIrFNl4q35sUVjCYjiAoT5Un58x180OT
         dVSD1MI+cgN4gGT4WTeVXOtlknOeofSQYtbpkLMOFyGsSQk94ETQbByQxC3gEPo+kyDB
         IgxyNyInR6Vrvw+ZAITYVz6MgCkON0WVe/BxDfMQataZVnObH2XM1RkJhBXEVYKgh8hm
         hhqxi1QnZvkdZY0foMkNQiX3QEqFB1tIi5yYcHu5GNsQGby+Na9AwQz/cuPOQ97xEXdE
         SiVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GwgQJyBmb6dYQ846Eon+A03ndTzM78c441vzNKFsLMo=;
        b=b8bhw6IAbQ3wkttY/BqBDXXSOPx8mTXl8lN7dr3XB8Lqmm1bYfvD+qvq8hsxfzxEGr
         +eOvtFNAQXHlfhcOgxSJNx6gP00iOTG+UTlH2QzpqrruHnEniH3izQkEEPOGrn/KbIkT
         7Rj+7pZ/8sm3UwA9ZxSncofNfAawbnAqhvtLP8ACNt5Jsv8MzouhSD2RVVluZTECkVvS
         DplmzYQsWViy69SAwxVMlkcBjgIplfLa/08eh2hKzRwP+gaWb+5VjY/UdDq6AeX+424G
         7Dbs4Fx2N8u8N9tU4Bew47iOzU3mK7uZF0GcKv3YBEG+YI3X8hB4wgfKNgTPYwI8oUZO
         f21w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338oUTjEc+ZmR5kgjKFFqABqAkVqPOoya+nlf4XsY27JhfTclzj
	CFo+S/KXc2OCXMJOXtaud9U=
X-Google-Smtp-Source: ABdhPJyfLnav1APwVINS/GLwBhGrJwl4Ro90OxbHzlpv0tBIFaC8q+aie5nAZxYfggoy8kgSe9wFcA==
X-Received: by 2002:a17:90b:1008:: with SMTP id gm8mr5063386pjb.174.1612543881750;
        Fri, 05 Feb 2021 08:51:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2311:: with SMTP id d17ls4590906plh.6.gmail; Fri, 05
 Feb 2021 08:51:21 -0800 (PST)
X-Received: by 2002:a17:90a:73cc:: with SMTP id n12mr5042661pjk.145.1612543881138;
        Fri, 05 Feb 2021 08:51:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612543881; cv=none;
        d=google.com; s=arc-20160816;
        b=JEjHo6QcCnmrEWpRU0eg9jS8n9JT5DsKXGUIp65JVCD3lMUU7Sj+qdRVU+TlXQPoXD
         voFKIwpXbrCTFepjK9JkqXibyB21lWmZB848pNy25cChpB8lYB3+y0OFKrYWN7Zssc+N
         O9dRzYlNoIJxVzEhSlUYnTv3SaQClpBDSiOkQB8bfJg4anbWC8pSK/pD4cCXMlhs1LTs
         JgqlE0e6JCErBL6eCXOVNzjKjXF5rTIlxnkp1TfQJ4bJixHxUKu51BWDy1KwpDgv6LKX
         4L6RKNhVjNTpIADCpGXtvUQHHBpB7kHYXtB3ZNeKfq0GClWMQpllwattUczQjJpU47f+
         wV7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=rg2gsEXyPSbbzLY0lZuhOJjf3/HkBu5rE7WzMuoAitQ=;
        b=uAFJYeFw9me+yRQVRVkPPUP0J4w/XG0IaKMeKcRZNaLItthKwG6zczEfVhaDWjny0X
         Q/raoMH3AvbYG8Z8s7v2GQ+hJhf4zDXJ6PLIqQEMQMTAKdA1d7+sv2VD7P+1eoHYTlSA
         rnLbhntZqwbD1XIqc7cQxD0d/03QUA1oIYVoFOO6TJKlboIw4E2+dJMllWhoIauwRwvZ
         L46ExRs4AX9UsFBZhCzXKnS1A345sNLoWI9ySHcdL0SX0kBUwRua8uy4U158s0u3ZHw2
         Jvm/slQfeBma/wcqGn+YeQq9AHzHnWSSLeoTpJmwIgzQKpGlnBHj5QoIAfi0Szt5KC0/
         7e/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w2si479889ply.1.2021.02.05.08.51.21
        for <kasan-dev@googlegroups.com>;
        Fri, 05 Feb 2021 08:51:21 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 27E7731B;
	Fri,  5 Feb 2021 08:51:20 -0800 (PST)
Received: from [10.37.8.15] (unknown [10.37.8.15])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5420C3F718;
	Fri,  5 Feb 2021 08:51:18 -0800 (PST)
Subject: Re: [PATCH v11 2/5] kasan: Add KASAN mode kernel parameter
To: Will Deacon <will@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
 <20210130165225.54047-3-vincenzo.frascino@arm.com>
 <CAAeHK+y=t4c5FfVx3r3Rvwg3GTYN_q1xme=mwk51hgQfJX9MZw@mail.gmail.com>
 <CAAeHK+wdPDZkUSu+q1zb=YWxVD68mXqde9c+gYB4bb=zCsvbZw@mail.gmail.com>
 <96163fa8-c093-8c2f-e085-8c2148882748@arm.com>
 <20210205164822.GB22665@willie-the-truck>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <2d039894-708d-6bac-df45-fc68098c2ce9@arm.com>
Date: Fri, 5 Feb 2021 16:55:19 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210205164822.GB22665@willie-the-truck>
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



On 2/5/21 4:48 PM, Will Deacon wrote:
> On Fri, Feb 05, 2021 at 04:00:07PM +0000, Vincenzo Frascino wrote:
>>
>>
>> On 2/5/21 3:49 PM, Andrey Konovalov wrote:
>>> On Mon, Feb 1, 2021 at 9:04 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>>>>
>>>> On Sat, Jan 30, 2021 at 5:52 PM Vincenzo Frascino
>>>> <vincenzo.frascino@arm.com> wrote:
>>>>>
>>>>> @@ -45,6 +52,9 @@ static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
>>>>>  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
>>>>>  EXPORT_SYMBOL(kasan_flag_enabled);
>>>>>
>>>>> +/* Whether the asynchronous mode is enabled. */
>>>>> +bool kasan_flag_async __ro_after_init;
>>>>
>>>> Just noticed that we need EXPORT_SYMBOL(kasan_flag_async) here.
>>>
>>> Hi Vincenzo,
>>>
>>> If you post a new version of this series, please include
>>> EXPORT_SYMBOL(kasan_flag_async).
>>>
>>
>> I can do that, no problem.
> 
> EXPORT_SYMBOL_GPL, please :)
> 

Thanks Will, I will :)

> Will
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2d039894-708d-6bac-df45-fc68098c2ce9%40arm.com.
