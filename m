Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBUUOROAQMGQEHJCB5SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 819BE315525
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 18:33:07 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id r206sf4267253oor.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 09:33:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612891986; cv=pass;
        d=google.com; s=arc-20160816;
        b=k+ESBjpLhnYJCBKKX7DfEuxoJ+ET02iahh2xzSFJribfMs3KP7SqpFx6HsY7qmdmjZ
         NCVGFZ3gctfqUDpAi1xtxrF7hKdx/d/x1a7AJ3lb/OucN2P3eOlXvHwJKl3hZZ38QCxo
         Xq8s/YNyUoBA+c+ACz5jrDsRIgCbBCG4eY2Tx9+oVXruAmanGfiT0YdTgR4jlfMvKvsT
         rIiFhN98KP+pMp2x7JPaWLCRV7OSIROrJEO7t2S5VJ2AtcHD1jxmYmjZajjXhlI1jFVk
         A5u1V0TKAyGOAVxDAwxw5eCHFNauaFWs4NvBM7ZE/dxoWRUk8gW3QZYhOR3EiIZ0VxKt
         s30g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=I/0tTzs7omgjeHkINkY1peSeS6o3N6UJ5ULZU1a49nc=;
        b=BtfDzrB2FxbaY82OqYw7c6AThBI+Im12Ck7jTySBbHGBLch/W0I9ZVjQqfT9HwAlo0
         vhafVlWxXgSa7dq2Ug+V4RVHOnOP/Ws+7D9i6a3Y86U5E0CTMR9iv3AUs3zVdbH/pYfT
         SmtkyeHI6+mZ33GgryLVXv0HiWx+KDiIq6f58zR3x5x3tRIJK2mtloVrCaOqvr8fkbA3
         aHJ7c/a2bGbHXsku/Z/oGBAjzVCg2/ZBlhiu5zeSyiDzAtJJxnCrFDMEZaWcad1UIeyM
         AckIXGDEoXvaYFMkrfsueOIZMeAt7d85Q4aNFmscPkY9L3H0cdz4mYXcTawVbmuthupN
         /yAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=I/0tTzs7omgjeHkINkY1peSeS6o3N6UJ5ULZU1a49nc=;
        b=A+8wL0h7Wnqmfp/efGJk6K1eL5trKTZtPAZbUneYx7wfc6uBAVI5caU8liGzFOriuj
         ipMfxTbWDVhkCY6WE6hmKVStQwn4K1UcWTG+KwtbLbaJTRwhXo/7LofOZnd6Jipb6HCM
         XtO0wzfO0gJwCwtuD1prHSY8iP5CakLxg701KIYlhIbmts0VntdBgSqfDuvHvpmJm1Xl
         MwJqyHLcLjfhwoUyWvqgzj5WmtwO7W2MPiUaq3zBavF3ES650/ViVn3LuBQKygvNRM2z
         jS7N7FeWpFAIiqIIJQvccFjV+N3HYz4xh8QX6HXWPgu0cvVKt7tcXCFBlckj6WGra7kj
         KI2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=I/0tTzs7omgjeHkINkY1peSeS6o3N6UJ5ULZU1a49nc=;
        b=sgWdmJUDYhvGYmg4ix29UUNYHEODkS5t1z5Dd71d727LCRDQdXncZeAc84UtvClpTg
         QuIxI2gIgaPRpPE2pBYXmVQYPPEnw/W++fWBp/oAcfHokxFv7/lu/ubcblkCjjC2nI4u
         1s5Of/GQU+lPO1/tn0HCWEoKnngaY7f+IswTy/NKu6g7UpcneHM8MUOQJ46Dl+g7cfyt
         cVSYbsmYO7xq3/idAufqCUXHs0oriPepoYem6owzygEs6hBWyLsa1A+0YYJcLwDdHeIX
         mzvgeFNRpH+qNiykgbavcQswYcgXI1ge8wihP+PFxlfm5U3QfK7VcuXB4tQp2fm2viN1
         nUWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533+7h+gpOWsaQ5QjFKpK/3U9G5YUgubPjqe+iDgsUUWzh3YfTge
	6prl+gxlgTE12UOIXx4183E=
X-Google-Smtp-Source: ABdhPJyeC+0fGfV6a78aQjDvst/2zUOuvhKf6LAIjKksdC3F8FA7rAmJGyYQgEkG+hfN6gOvcjcnog==
X-Received: by 2002:a9d:639a:: with SMTP id w26mr16778516otk.201.1612891986404;
        Tue, 09 Feb 2021 09:33:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d0d0:: with SMTP id u16ls725482oor.10.gmail; Tue, 09 Feb
 2021 09:33:06 -0800 (PST)
X-Received: by 2002:a4a:bd9a:: with SMTP id k26mr16531558oop.62.1612891985992;
        Tue, 09 Feb 2021 09:33:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612891985; cv=none;
        d=google.com; s=arc-20160816;
        b=Kk60sNuskCeFCBdYDV8h/VKUUALiafn2pKX7EqOq+07fPRbvZenxY4YS6DjbbG/Wj0
         ncKNmDso4vX6xQSPNXYAXd8+/8Hi8j2KI6fLJ+7dKMsDpnUPlKfFBAcGi3T1gWCLWFZ2
         nuQpWSVstSaVead9TUrYz1X5U3BSDpfU9+BCAGY4L26NthJRZdo09LnHtwTEAGR+Ctat
         pMjiUq4xtk/3kvOXZuo9tViLRI6DLZpcXA4N9P054GHAp4dAUlyoGraEb/S6jUaE4aYS
         wPgzZ3UHQW293Xb6niR3uYADHDOmXTA1eje0LAuelxUqfb2lHvnfXK6f5eWmO6Pln0NB
         iAPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=zP9VD/z9O0p49fvhGvXeiWHEySMlEV4mvQvNmm3/NiY=;
        b=SGWw49fdZ2czUDvj+A6GiABYqUF43/uGYiQEcI1O3qQVDVlsF1wI78RBhjJcxkzsgM
         4ZJvg8LgKsTx8nukSneLiKJ8KYwpBF9qiwsGQ+Q/JU1yuipjw/xc5AJePDG4T1617KXU
         3UwxEEs16hHWZuOa6pMdmNVssI+8XlF41s8oj14eQUkaYWbbB/jOF7d9dzduyeL+KA5e
         riRdSEE93DXXOSxSjS4Jk3SVgD3UpaUVBy5jskBLnr0AA1A/O4rae2K/s6q9wCk9AcjV
         kTeuh5ToHCNlS8d1M2jlwIrMW3NzTyH70FfAPSqaK1RfZsFnTg6ATEqvRkC2GHuvOKWx
         rk4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id y189si256299oia.4.2021.02.09.09.33.05
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 09:33:05 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B3B90ED1;
	Tue,  9 Feb 2021 09:33:05 -0800 (PST)
Received: from [10.37.8.18] (unknown [10.37.8.18])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id CBEB83F73B;
	Tue,  9 Feb 2021 09:33:02 -0800 (PST)
Subject: Re: [PATCH v12 7/7] kasan: don't run tests in async mode
To: Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-8-vincenzo.frascino@arm.com>
 <20210209120241.GF1435@arm.com>
 <0e373526-0fa8-c5c0-fb41-5c17aa47f07c@arm.com>
 <CAAeHK+yj9PR2Tw_xrpKKh=8GyNwgOaEu1pK8L6XL4zz0NtVs3A@mail.gmail.com>
 <20210209170654.GH1435@arm.com>
 <CAAeHK+wz1LWQmDgem8ts30gXc=SkwZ-HM507=a+iiNpOYM-ssw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <79183efe-ef9e-0a31-cdfa-e1bfae39b015@arm.com>
Date: Tue, 9 Feb 2021 17:37:05 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+wz1LWQmDgem8ts30gXc=SkwZ-HM507=a+iiNpOYM-ssw@mail.gmail.com>
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

Hi Andrey,

On 2/9/21 5:26 PM, Andrey Konovalov wrote:
> On Tue, Feb 9, 2021 at 6:07 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>>
>> On Tue, Feb 09, 2021 at 04:02:25PM +0100, Andrey Konovalov wrote:
>>> On Tue, Feb 9, 2021 at 1:16 PM Vincenzo Frascino
>>> <vincenzo.frascino@arm.com> wrote:
>>>> On 2/9/21 12:02 PM, Catalin Marinas wrote:
>>>>> On Mon, Feb 08, 2021 at 04:56:17PM +0000, Vincenzo Frascino wrote:
>>>>>> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
>>>>>> index 7285dcf9fcc1..f82d9630cae1 100644
>>>>>> --- a/lib/test_kasan.c
>>>>>> +++ b/lib/test_kasan.c
>>>>>> @@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
>>>>>>              kunit_err(test, "can't run KASAN tests with KASAN disabled");
>>>>>>              return -1;
>>>>>>      }
>>>>>> +    if (kasan_flag_async) {
>>>>>> +            kunit_err(test, "can't run KASAN tests in async mode");
>>>>>> +            return -1;
>>>>>> +    }
>>>>>>
>>>>>>      multishot = kasan_save_enable_multi_shot();
>>>>>>      hw_set_tagging_report_once(false);
>>>>>
>>>>> I think we can still run the kasan tests in async mode if we check the
>>>>> TFSR_EL1 at the end of each test by calling mte_check_tfsr_exit().
>>>>>
>>>>
>>>> IIUC this was the plan for the future. But I let Andrey comment for more details.
>>>
>>> If it's possible to implement, then it would be good to have. Doesn't
>>> have to be a part of this series though.
>>
>> I think it can be part of this series but after the 5.12 merging window
>> (we are a few days away from final 5.11 and I don't think we should
>> rush the MTE kernel async support in).
>>
>> It would be nice to have the kasan tests running with async by the time
>> we merge the patches (at a quick look, I think it's possible but, of
>> course, we may hit some blockers when implementing it).
> 
> OK, sounds good.
> 
> If it's possible to put an explicit check for tag faults at the end of
> each test, then adding async support shouldn't be hard.
> 
> Note, that some of the tests trigger bugs that are detected via
> explicit checks within KASAN. For example, KASAN checks that a pointer
> that's being freed points to a start of a slab object, or that the
> object is accessible when it gets freed, etc. I don't see this being a
> problem, so just FYI.
> 

Once you have your patches ready please send them to me and I will repost
another version. In the meantime I will address the remaining comments.

> Thanks!
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/79183efe-ef9e-0a31-cdfa-e1bfae39b015%40arm.com.
