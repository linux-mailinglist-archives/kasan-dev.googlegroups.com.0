Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB75A2GAAMGQEPIGVZYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 19FA7308C2D
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 19:14:25 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id 18sf7064086pgf.19
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 10:14:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611944064; cv=pass;
        d=google.com; s=arc-20160816;
        b=Or9qQEBCutw7d2fbhYrkWIgh4SLiWrYt6yLOIM2ARheFiD5WjcmGLluh+WPxXaxKiq
         DRMLVZ0V281JVsdss/jXm3d067W7+0XU5JkyR145AkOJR4HNNyN6UsZnCsKoLuDeieT1
         YX2NV1/11yXxTFka0V/xvD/KAj0xGu0QF2H4SPnh+52CGE4IfmWbc/XRSKWtJHy9TPML
         ZBbtOJC7u8eXtHAAuCyoEtyLuz1NeIQSHYu8PakKlXt2kwmK8ep635XUCn5V/ydx7czt
         GsfoGbv55fdrWq+ukiwQu/Hjd3WL8RyNtDp3SeV9TUHeHp1Czq6d7T2f7hlh/IpdOPV9
         EfeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=YwXDFXPNMAzLmVkmuyOOhsyyaWa+GYbgdleUyoMehKM=;
        b=eqVjBIgDuadLCHX8txE7ROnbb/ifht39MY+SOdfwLWApTOyrjvLz/LbKMUTrFImElD
         aEnFQ1UNygP7WQCEF93BPZvcqVd8LJAnR+GuBSTwwonaxpvoxL6WcmzSKipiLR/2nWmy
         h7uEh/Ejx3MnMoZXODkMlnhWvXg0Mxi3bj5MJGxiPxaekw2OCvCK5f28HLPBFAIdYKyU
         XMcbEzPTrYvKehzYUdvSYAUfvBAg2/329wR7f4K7tMBw5p/5wHp1UXZdg2sF2xBMhCId
         r/r/YfvsmWCPt8w5Zpx6FwpzksQGdX6X50EV+MyYJuow2r4MAH6mgZjVhbA18YvvoyuB
         tM1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YwXDFXPNMAzLmVkmuyOOhsyyaWa+GYbgdleUyoMehKM=;
        b=QktBP3OnL9SCU32oYolhMhwwSatsky6zhyX9veVvxoWjbZPBSVO+qG8RanK/RNGMEJ
         /OaIhuIomNr4d+uDBzjh3Alau+izeWbc5i36iAvN4q+3xq7f163XZu3yqnbB7T7H3b2d
         9L13zpM6Aw5EafsGgAeRn7ux6Lw5Q/jJWlYu7RNCjS8zdfFoRD4Efm4wqX/2EvU6nyQz
         8TwNrqp5+aZW1GfS+/A+9HhL2ijsDWiI3tKXotMiVAATNUuYL/wN3Pf6RqilgPhc+c0b
         fWXqgYFLu4NrD2HsMfKqhX5exzIT3AT57PrDgEUwMebbKgt7DcULuspUQfQltdll4Rlt
         NGQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YwXDFXPNMAzLmVkmuyOOhsyyaWa+GYbgdleUyoMehKM=;
        b=lo6M/ncp55AHvcVhs2sgJA3tPE/zjq3xNFfLdIiSSzGM3N1NgclUXQi3jOv3nSjmjD
         6BwirgD7+mMLl/JgFHjjt9XVJwtP1d+L/hwhziQKabDwosMc0b1kosUA2GaOSEmMPf9G
         bELp+VHLfGz6VbwLqQr59A/XVwVF3n7/0J8dBIADMd/nSU3Z6vq/w7JUzNNJ6aMVVyvP
         YbSbhwtKISrYXjfa48RzC87MMip53CdV2hc2hNrJalFIevypBr/L10bO6MpSX5L3Glh/
         G/pjW85dUWVJtkdZtrltvF9vlis4om9kfX/TB5/H67fFGfTSKvaxIvsHXHYs3JGN/1LV
         kquA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531fvnlWnx0BdNkYWgHRLFw8bdaAZPR4WAkTMlesKkSKk68x/cAa
	0IsvJ3uXvIaPtUPXov4yC/k=
X-Google-Smtp-Source: ABdhPJx4y44RoXe7TxZc3Hjfhn0woPU8gwdl96HpGVju1pttB8PiUtfCL2QFpXXlGGGQo0tFiw9eYg==
X-Received: by 2002:a17:902:8ec7:b029:e0:a02:3d26 with SMTP id x7-20020a1709028ec7b02900e00a023d26mr5523582plo.24.1611944063871;
        Fri, 29 Jan 2021 10:14:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:3583:: with SMTP id c125ls3945091pfa.2.gmail; Fri, 29
 Jan 2021 10:14:23 -0800 (PST)
X-Received: by 2002:a63:4859:: with SMTP id x25mr5858828pgk.289.1611944063139;
        Fri, 29 Jan 2021 10:14:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611944063; cv=none;
        d=google.com; s=arc-20160816;
        b=niHXaifRrvULRg6O9A7cawf4fpSzIIjUzTVarBS0Gf6HtHMZb0CpBy76Y4DNEIULJR
         DcdGJ7NIR5MiumnrEuyTMNkZ4YksH9h8oSWPQYZ7JFO9vRAbTwUF9ekd66QBo/uZl/h8
         Ll/xFrs3mDJEX5pTxz9nCVmoAtVNTlv1LItIVqQKp59lWqsndcCnf+DyaHZ6QgOu+GOd
         Q69+hHnf4CIprQonFSmrANO3xjAoWENKnrhnBFNL/5nwiurF9MsIC86gr3gLrykJTdGi
         hfeAPcV4U9XRQEE/amAzCUP+xxVRLBBPLn86V8TuthC8zu0qOCsAYfOxQX4qdbkA/FcG
         2uOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=PQF/VBmuZyAmkyQEbTFq8RZ3AqbukEsAbWpwb1fb3QM=;
        b=u56E3bt6q4xNr/ksnnhKQ71xBN7FDaFRo5LJKSouwPr4vKTIzKuwZTg0NMPAjahpjC
         /Gbv1AtQchVM4qxLT8P2Yt3+xwFNTgk2R+OXj3GdDXKDwt38cHbN1o628xjqAk+OlrwO
         IxlqIS8ATI/B5guPIszPYSKQwZ4r9bbJcu8RncAR84tx95v1y5mY0pYSsRyUxM+KuGvQ
         Y0mn3IeY15uksXRCMQaLK+WYp/796EJaNsxfRoJFgUH0SGcjL5TGBu65M1pIKAwTsilG
         iJY3Z8qX6/c79Sonij8qwxu1zBHJfjtGEIYNDHt32gqDIAqkVzO0FNRVy17DJOBlmYQD
         Z3SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id n13si494325pfd.1.2021.01.29.10.14.22
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 10:14:22 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 26ECA13A1;
	Fri, 29 Jan 2021 10:14:22 -0800 (PST)
Received: from [10.37.12.11] (unknown [10.37.12.11])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0FF9F3F885;
	Fri, 29 Jan 2021 10:14:19 -0800 (PST)
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
 <7da762df-6df3-e526-bec1-dc770709c00c@arm.com>
 <CAAeHK+zrkLpOe2aJjWVMPHbvSFMXAEP2+fJVZ-3O4E--4-2KfQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <bbcdc4e0-29a7-d064-123d-a2f7d7dc223d@arm.com>
Date: Fri, 29 Jan 2021 18:18:15 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+zrkLpOe2aJjWVMPHbvSFMXAEP2+fJVZ-3O4E--4-2KfQ@mail.gmail.com>
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



On 1/29/21 6:10 PM, Andrey Konovalov wrote:
> On Fri, Jan 29, 2021 at 6:57 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>>>>> +#ifdef CONFIG_KASAN_HW_TAGS
>>>>>> +void kasan_report_async(void)
>>>>>> +{
>>>>>> +       unsigned long flags;
>>>>>> +
>>>>>> +       start_report(&flags);
>>>>>> +       pr_err("BUG: KASAN: invalid-access\n");
>>>>>> +       pr_err("Asynchronous mode enabled: no access details available\n");
>>>
>>> Could you also add an empty line here before the stack trace while at it?
>>>
>>
>> Sure no problem.
> 
> Just to be clear: I mean adding an empty line into the report itself
> via pr_err("\n") :)
> 

Yes I got it ;) It is late here but I am not completely asleep yet ;)

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bbcdc4e0-29a7-d064-123d-a2f7d7dc223d%40arm.com.
