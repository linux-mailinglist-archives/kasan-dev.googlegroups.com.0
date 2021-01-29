Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB5MS2GAAMGQE7JYZ6OI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C4AF308BCE
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 18:44:22 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id k126sf7682897qkf.8
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 09:44:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611942261; cv=pass;
        d=google.com; s=arc-20160816;
        b=htaEt1iH+VZtp7H9Q1u6ql+J/KD9SZ1ut4lsWsbxhN+rAl2ZiUT8ztCJCBX7YDhNqZ
         KD++TqtJ4DxdmxoQU0u21pVoF/Kp/+A3i2ZuCo/X+UBxcTJxemZgri79MjVgcInAT7ZT
         A86eZ+olGsT1EoOBlvnJVSV2kSKoiTbc5urXmYxWjnCMqkBJSjtHNCAknE+gEmDspb1i
         obQ4d5JsyRDXmIsQ4wmoRGpkDHWIq7a+d+2SSOWhZfsAJIb69za4rKWIIuIW6NQazBcJ
         7A711OaboaPiaaJO92/nC57Us8U5pX8/AEuS+N8hT5HBXoFpIAg9c9HkMpFXJBUXbXu5
         GPiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=K8JxAJa51+REbm2QnH069bumjOSTqsCT+r81YS/agtQ=;
        b=BXBGaTYhPPWakDWI5XzNPLIRHCIcpimmj6xvY0zM7zROvc5x1q5iBp6IVTLIk0Qcq4
         BaiHrlXSlepkr97Vx1XfWHw6AEnrh4+Y2qPDkwXlNQkI+OrMUlVHqOCZi32hh9hLiTYv
         S+PDF12FalOvTkRjUNugZg+SPODzEB2VKWzomxB2gY+OPqAv1NkJa8OQ5fOV14ZvuCgD
         ZooIP5eM+jDUW9VSuCevkkOzlwzHp6mjCtvKJt8N6XoCzOLH7itdVPu7Pa3oWUUlCPQR
         vgmap8tfBOQQDAP7yNzwbZN0U470+uEYmBmj5renJNVHkOQPPH+Xab77pNraVTcVXG9L
         3fFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=K8JxAJa51+REbm2QnH069bumjOSTqsCT+r81YS/agtQ=;
        b=EEKKoR49DPo0hAUijJ9eTduE9kyMAtFCYYLRiuvVw5LDBVJPW3BaT2B9Tkva5VPEwT
         qWY7ggFhDdrjwNPD0xF8AEcCz0H4dQRP9B2T2vUFpPI/CDbs9w0uM6ywHRaqrVv9W9Ve
         ZKAZhUEwMZJEfziJUBAUns4su2VOlXcqyJVTbxnWRMtSsKDc3JWHmt4acYd4IBeBPlAS
         ItA+HguWPfFT4DQs8w5nuedCH7HnJJwGK08XjoeWLUbwW7quW8x94ZLZbj5d6DEd25J2
         mahL4i/XJQDesvdDCBEWMZhX+KCBXt4+KBrWtfJVox9iyX8DXWlkHJxKimw69W9W6S/W
         lMtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=K8JxAJa51+REbm2QnH069bumjOSTqsCT+r81YS/agtQ=;
        b=Gh4TDUe8jLqjta8+Qm4BSsYjFOQjjDsI4IFaKgvI1vGlno3o+on0c8q4KUvF8ALo9R
         7ShFn23lW6HmTQGUqn308KCjcGtvlzZWyadW+7PtDR7IkXEbJ5tPrpIH3dgoh0KonMDD
         7RRw/Gua1tgRCwgtwRSpHc+jJIOHqgCTyp9XwlIVVu7Le2EIw6GtnMrgyrAMty7UEXHU
         jcK65HCg8LJ5psUborKq/5b1YfwevfcA0R9/LNbeKkVRfUqdwzWSrkkzjuqhdQxSGzGr
         AOqn/C99pjgWEXPAAOhkSwizBTfRlPS1CEKcjubgSqnYA0DmfZquHbN8oaqcu88dyDZQ
         hHSQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533qUxJ7tlqp3aTFRS/kDE1hCo+wu98Qem4hMdbuFvqeQkI47R5Q
	NV7r03BkR342FtZmCmKobqs=
X-Google-Smtp-Source: ABdhPJwpPam5NAXcMiLnR6CDbZVJeWaLx1yav6H20dPN/KcAx4s+u9OqFRe9PmQtRQrRKBN+H52uaA==
X-Received: by 2002:a37:c40b:: with SMTP id d11mr5341261qki.73.1611942261493;
        Fri, 29 Jan 2021 09:44:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:6fc6:: with SMTP id k189ls3086937qkc.1.gmail; Fri, 29
 Jan 2021 09:44:21 -0800 (PST)
X-Received: by 2002:a37:4905:: with SMTP id w5mr5362200qka.332.1611942261009;
        Fri, 29 Jan 2021 09:44:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611942261; cv=none;
        d=google.com; s=arc-20160816;
        b=XIazJa3VJ0zqFW/bWLYW5fDqO+8lOzYbp7bAcBBT1cFPbOtpd2Flo9Hdq7VLF3TSpp
         bfisHtCoN0lw8d/i3nMOummTSAF5sKitHpNlZ/UZJeEhFZWyf6E2H/Nw2Bwk6GRDNDsB
         MgrhwO/aG8DJTTtFiH6Ir/NUQR1s85Mtt3q96SnwX58hAPxh9FOn8vEYxO7oCKNzs7Ag
         Y+WocSsbSDAZO5C38DK1ORHP8528ezEIdESu9LMkXqmX85nVSzU/BCV9wN1+xAWpOVB8
         uphHEt43JG9YMw6NHFZsWdgorps9vyCpecqNa3jumvZ2AFvwyjES6EWkYtA3b8e1+E/3
         D22A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=vTfvvOE54+cNKETYbp1mwbctVNyYriy80x7JIIpfUzE=;
        b=LUOIkRjY1j2ViykGmlIByn/sKU2aPC98Q5clJq7VQKpV7j2/NEZbkb5b2Tz7E/FsAD
         Wj3XXq6JJbyC/njowWtxm5TS7zgKqSNOJ+rIE2wtJ5q/POBNmZQROvLKheoczMo0Flyb
         Jp8on5LTv/vMucUJpAD0yNrH4ZKjS9oPuY9PCy3mf6tvh5Gk1pwJIvuFEmlKYdaVp3Hw
         1Qf6p/sPZAJI2xc9bJW356oEepj+w0nd4UbO//10aZupZDqMRaIHniym6rYakuZg7qML
         MJEGOsu1GC2HhdvAS3+0jlxJ+AAyomvA54rzxw3Obnel9hgUqzDwAhOAi5XZ68MqTdl7
         gpfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id x2si91364qkx.7.2021.01.29.09.44.20
        for <kasan-dev@googlegroups.com>;
        Fri, 29 Jan 2021 09:44:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2E54713A1;
	Fri, 29 Jan 2021 09:44:20 -0800 (PST)
Received: from [10.37.12.11] (unknown [10.37.12.11])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 133EB3F71B;
	Fri, 29 Jan 2021 09:44:17 -0800 (PST)
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
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <77de8e48-6f68-bf27-0bed-02e49b69a12d@arm.com>
Date: Fri, 29 Jan 2021 17:48:12 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xAbsX9Zz4aKXToNTrbgrrYck23ohGJHXvgeSTyZy=Odg@mail.gmail.com>
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



On 1/29/21 5:40 PM, Andrey Konovalov wrote:
> On Tue, Jan 26, 2021 at 2:46 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> KASAN provides an asynchronous mode of execution.
>>
>> Add reporting functionality for this mode.
>>
>> Cc: Dmitry Vyukov <dvyukov@google.com>
>> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
>> Cc: Alexander Potapenko <glider@google.com>
>> Cc: Andrey Konovalov <andreyknvl@google.com>
>> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
>> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
>> ---
>>  include/linux/kasan.h |  6 ++++++
>>  mm/kasan/report.c     | 13 +++++++++++++
>>  2 files changed, 19 insertions(+)
>>
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index bb862d1f0e15..b6c502dad54d 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -360,6 +360,12 @@ static inline void *kasan_reset_tag(const void *addr)
>>
>>  #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS*/
>>
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +
>> +void kasan_report_async(void);
>> +
>> +#endif /* CONFIG_KASAN_HW_TAGS */
>> +
>>  #ifdef CONFIG_KASAN_SW_TAGS
>>  void __init kasan_init_sw_tags(void);
>>  #else
>> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
>> index 87b271206163..69bad9c01aed 100644
>> --- a/mm/kasan/report.c
>> +++ b/mm/kasan/report.c
>> @@ -360,6 +360,19 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
>>         end_report(&flags, (unsigned long)object);
>>  }
>>
>> +#ifdef CONFIG_KASAN_HW_TAGS
>> +void kasan_report_async(void)
>> +{
>> +       unsigned long flags;
>> +
>> +       start_report(&flags);
>> +       pr_err("BUG: KASAN: invalid-access\n");
>> +       pr_err("Asynchronous mode enabled: no access details available\n");
>> +       dump_stack();
>> +       end_report(&flags);
> 
> This conflicts with "kasan: use error_report_end tracepoint" that's in mm.
> 
> I suggest to call end_report(&flags, 0) here and check addr !=0 in
> end_report() before calling trace_error_report_end().
> 

I just noticed and about to post a rebased version with end_report(&flags, 0).


>> +}
>> +#endif /* CONFIG_KASAN_HW_TAGS */
>> +
>>  static void __kasan_report(unsigned long addr, size_t size, bool is_write,
>>                                 unsigned long ip)
>>  {
>> --
>> 2.30.0
>>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/77de8e48-6f68-bf27-0bed-02e49b69a12d%40arm.com.
