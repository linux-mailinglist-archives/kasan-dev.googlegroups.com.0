Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBE4Z2GAAMGQET6FNYOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 56684308BFC
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 18:57:40 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id s7sf10893805ybj.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 09:57:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611943059; cv=pass;
        d=google.com; s=arc-20160816;
        b=BhKhSNOt26g4kl5tuMoJEwVrqtFZ0ErR8ABiR3z//EDJQgKVFu9MNfyjdV0xWTLXpT
         VbPpOtN1QMlTJ55FzQyRaLpMU/NlH7lqaNFSLbShoiFcnpxLXLZc4vNfOkJSTwcLSi4y
         jBwdroW4wK2vnDyQTyz2AVl/w7W9fak3ADkrQUp6G252H7CAAMp9oJ+gDpweAjpkU1Aw
         yDMBZ6x5ayXWx7BFxgc464mPVSOS2elIDJjWxaqCZS3lyWC6mJBDcSl188VqtKP4gX0M
         5LGTFWdsWC+AVi1hmb1eCY48tAu+ZR1R9whwC+9rl56CQ7HAeugdGKDue0URVeh1KmPY
         0tHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=UA8gZmeP1BSEJP2Cs5mLTRvlPTUKHVtrm2UMvT1BfWA=;
        b=yNREWaRWQWcxmDlzbpGSj/LQX4hN7nvWOxYHw8ZrhUehQw8L5oa6ChFjxYeAG7XA7R
         UMuyUIl7GEuw+OqYi3Duidw/i2out4B6lMeiTDBvm55/kVerflmmkLRRTZYbwviqTpD4
         1Jk8X+7ff0lD0Tz+bbQ7GkEXqKvNhUWwYnZ43UBhaY8vA3ZhADgFfVCu0Eem+CV2FOd/
         jilOthDdq8gHuZaGHmjRaXfDH+b23wKyt1QUjJu7SsZoMwA237VT5c+HOLamD50JVebC
         zb6Xon/CHdoj0iHhiqOJ25MKPyi37nScYZ6TZreZH7by+XLlKRwaDwBRBqVPcdToVilg
         rUmw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UA8gZmeP1BSEJP2Cs5mLTRvlPTUKHVtrm2UMvT1BfWA=;
        b=RTL0lPcevV/MBZ1O9qgz1j2AcbQCEIBv6BHTKxZcxvmL3xzowcj3ph/VNGFs9ka3r+
         /BZ+ft1nTw9TEX52XwSO4FvtIeCL7nXhB+Luw3grZZXhz63Xl9HW2C1DxHDq//ZKX9TI
         saPnfISTNbSNEvGoBn6AhagjMjA7bnO2k+FnmtKus0nijZnXLGVxEwqVJKRNSuIW0Eum
         cRhagsuZ8BlZMhvj6VSPnREoJXUTYeCxIhSlwZX6td3aCOB6YMIV5ajoneZQuZuM/us8
         mkLiEvXLdU2xCB9lH9tl+7uQoAHI9mCT9n2DPPgQ5GWnKgUpGJsQuCPyLvEnVtClFdGr
         cEjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UA8gZmeP1BSEJP2Cs5mLTRvlPTUKHVtrm2UMvT1BfWA=;
        b=NabvW8184o6fenYbyG0jQAYAkPY7OK5gXXyFe2Y+qlBc61ItSnmWDo5W1bZxZyffTi
         ltNe1GMRkYFxX/I+3f6c6IRn/Tp7rlss4Arq1oqxc0TAwirFWM/DCxHuX0OR40URvjpG
         KwpntxLpUXFKRx2KlY5tMAglaPRxKeTNrL2RgjQsQgNsUwqTJIM4G0i+a6sbW6uBl5vE
         d8Y8UAFdI9fViJk+LS/Jb3/bfHHje9OYG+0jHRoBRkFKXuKOFrZDpVr7USzFe3k6Ih34
         O3osB2DJiFhH1NLIf6slb2Ycoyyh/uiq8SX7p/+WjBnFMW/xAwroar4n+h6gG3DUd5UP
         +n1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530JqNsIZ+BqgbJhi7BFnm726NIkFGqGhoUnnlEdk5pnbU6ibk1p
	zhBa82kH4DqV4xEWQbEfAOQ=
X-Google-Smtp-Source: ABdhPJxPkJEMPdGfNx/c6MQQM+TIGR+1gvW9iBZJBDIMtsn/l7fuy7nFETbO7/ljqZG5GHOhFgq/sw==
X-Received: by 2002:a25:c244:: with SMTP id s65mr8112452ybf.128.1611943059425;
        Fri, 29 Jan 2021 09:57:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b5cb:: with SMTP id d11ls749283ybg.5.gmail; Fri, 29 Jan
 2021 09:57:39 -0800 (PST)
X-Received: by 2002:a25:d1c6:: with SMTP id i189mr3921324ybg.321.1611943059093;
        Fri, 29 Jan 2021 09:57:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611943059; cv=none;
        d=google.com; s=arc-20160816;
        b=QolEwVdJGMYmvNFZrWS4sC3BFp6X6JwbF4Ub4qdHWqfHpqao8oI7N26wTpoZqc9b99
         dw2N/ADIcVnaWrUutrZP9GEoIJAOKuwBAaRvlJ1EP7bWcl0PSIoIq8rTVDk/ZjuiE1ck
         vYLE7AbXpt0N9D9SR4CLuIeULZjBB0F1yB5C94mBFM9i59yYh+1cqiJnlMcmgXfrkjaT
         DvuoliGen1xAbu2Se1CXalNIe+09caNaX5Lth5h3A+ghL6isi0/lU0CV9ZoF9zprpNrI
         czXsDARZNdCbys4f7OPRKXYdzowsSS8VTOSKCSr4yGQTtMUfjdTV6NQFQvTU6zkuB4VZ
         LAhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=3ioZcsqTLkWATtJ4YFb3L2F4JTbf/fGiKZOXOjZi4eQ=;
        b=RleaDavlaKfvS4INm5QfRVjcG67RltbGneyUvcK+piNc88d1LYzFIHuAO7f88yhlq6
         PLar2cmfw8Q08CcBO1EdVr3bL7hxvnSWHcIz/01Cdfv0uyL+qpryMMABRe1gLckMR+V6
         Gs1JAPAEhS8DOt6EDF6DI38FGIX8pwpeQNk6bU1TJRYN21CjSiY4fNIsgUWXf0O4AkF0
         G0kLK51QiWHbfA2WlmEp7zwzmRHwC10UNYocTniimjmfXJOHAfJabDzFlrKx3HFeTUPW
         o+7LRxnN+PjyGErkUK+poUNJOUI2yMznhp2R2AF6Al5K2T65HfOtJdNM8Vp9y63irDz/
         IeVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c10si634578ybf.1.2021.01.29.09.57.39
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 09:57:39 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id AD3C913A1;
	Fri, 29 Jan 2021 09:57:38 -0800 (PST)
Received: from [10.37.12.11] (unknown [10.37.12.11])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 956A93F885;
	Fri, 29 Jan 2021 09:57:36 -0800 (PST)
Subject: Re: [PATCH v9 3/4] kasan: Add report for async mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210126134603.49759-1-vincenzo.frascino@arm.com>
 <20210126134603.49759-4-vincenzo.frascino@arm.com>
 <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
 <77de8e48-6f68-bf27-0bed-02e49b69a12d@arm.com>
 <CAAeHK+xMWXpfLs6HuKN73e0p61nm+QrZO1-oXphJpjZprKQVKg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <7da762df-6df3-e526-bec1-dc770709c00c@arm.com>
Date: Fri, 29 Jan 2021 18:01:32 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xMWXpfLs6HuKN73e0p61nm+QrZO1-oXphJpjZprKQVKg@mail.gmail.com>
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



On 1/29/21 5:56 PM, Andrey Konovalov wrote:
> On Fri, Jan 29, 2021 at 6:44 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>>
>>
>> On 1/29/21 5:40 PM, Andrey Konovalov wrote:
>>> On Tue, Jan 26, 2021 at 2:46 PM Vincenzo Frascino
>>> <vincenzo.frascino@arm.com> wrote:
>>>>
>>>> KASAN provides an asynchronous mode of execution.
>>>>
>>>> Add reporting functionality for this mode.
>>>>
>>>> Cc: Dmitry Vyukov <dvyukov@google.com>
>>>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>>>> Cc: Alexander Potapenko <glider@google.com>
>>>> Cc: Andrey Konovalov <andreyknvl@google.com>
>>>> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
>>>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>>>> ---
>>>>  include/linux/kasan.h |  6 ++++++
>>>>  mm/kasan/report.c     | 13 +++++++++++++
>>>>  2 files changed, 19 insertions(+)
>>>>
>>>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>>>> index bb862d1f0e15..b6c502dad54d 100644
>>>> --- a/include/linux/kasan.h
>>>> +++ b/include/linux/kasan.h
>>>> @@ -360,6 +360,12 @@ static inline void *kasan_reset_tag(const void *addr)
>>>>
>>>>  #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
>>>>
>>>> +#ifdef CONFIG_KASAN_HW_TAGS
>>>> +
>>>> +void kasan_report_async(void);
>>>> +
>>>> +#endif /* CONFIG_KASAN_HW_TAGS */
>>>> +
>>>>  #ifdef CONFIG_KASAN_SW_TAGS
>>>>  void __init kasan_init_sw_tags(void);
>>>>  #else
>>>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>>>> index 87b271206163..69bad9c01aed 100644
>>>> --- a/mm/kasan/report.c
>>>> +++ b/mm/kasan/report.c
>>>> @@ -360,6 +360,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>>>>         end_report(&flags, (unsigned long)object);
>>>>  }
>>>>
>>>> +#ifdef CONFIG_KASAN_HW_TAGS
>>>> +void kasan_report_async(void)
>>>> +{
>>>> +       unsigned long flags;
>>>> +
>>>> +       start_report(&flags);
>>>> +       pr_err("BUG: KASAN: invalid-access\n");
>>>> +       pr_err("Asynchronous mode enabled: no access details available\n");
> 
> Could you also add an empty line here before the stack trace while at it?
> 

Sure no problem.

>>>> +       dump_stack();
>>>> +       end_report(&flags);
>>>
>>> This conflicts with "kasan: use error_report_end tracepoint" that's in mm.
>>>
>>> I suggest to call end_report(&flags, 0) here and check addr !=0 in
>>> end_report() before calling trace_error_report_end().
>>>
>>
>> I just noticed and about to post a rebased version with end_report(&flags, 0).
>>
>>
>>>> +}
>>>> +#endif /* CONFIG_KASAN_HW_TAGS */
>>>> +
>>>>  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>>>                                 unsigned long ip)
>>>>  {
>>>> --
>>>> 2.30.0
>>>>
>>
>> --
>> Regards,
>> Vincenzo

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7da762df-6df3-e526-bec1-dc770709c00c%40arm.com.
