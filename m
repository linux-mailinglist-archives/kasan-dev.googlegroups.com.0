Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBKG5ST6QKGQE4TVT6XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id D1B912A9503
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 12:08:25 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id 22sf656777qtp.9
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 03:08:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604660905; cv=pass;
        d=google.com; s=arc-20160816;
        b=X70yrMaCsjXElYyOYsr+/ybpAQvhiUop69TGpnKLY7UJr367r+LG0KQt8KOPagEhv3
         rXCK22uOSuR1cqWQfk6hAwtxflU3rXmNjqsi5x1k0LHmILLXVJ1qvDmf36UAJ2e+z6Q8
         qzdGHUHd2p8GQ85+a7hQxidRqYYfMsGW7+mfhj6xOVcMEy0a4bqxCglPF4XwbB13Ns7A
         q6JsoAUjTq9+YWcVbiXaqhfHmB2kpXFCptQodhIcV8nlItBJcnuUNTHFE14qfJRvY7VB
         EA3UnoZjTb4ZfF1SxBgaJPR+apwSti7BTlZVfxGpymtVca+hQox01nxeHcop1J+JVZ2M
         Gf5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=jlDsnjtZNxEEYWddUEya9M4CBgOCoHS3Js3AsbKzzy4=;
        b=MM51ryXeTaccDpcaMK2LAbMf2gNp4x1T5wWB/+C9TdLaP7LERH/XmfwPzjA2YEd/WV
         RyZjf4OFiJ01KaHtRmoUr54EBg/MAbb/L2tPCIryUV1IAsVGBxy9biI9MZQwKOLnTfSM
         WaD+kWmtTa8u+uUMAEoiG5M0D7R2sfnCrOiiR1mKqRVtlIwk+Zq2olPIKwKhp7ZxHrJo
         doKpJ5EOMluTtIVaTvU5uf0jui5Rdmu4j6aANMmbJM1U+mll84WMO0js28yYutlQdc+R
         K4zQGlg/JW5Z5YkrsqNohPbw8RVEbbLJOrOkW+TPOQzH77BakNSW+towCiPvuXfNQYL/
         pniw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jlDsnjtZNxEEYWddUEya9M4CBgOCoHS3Js3AsbKzzy4=;
        b=IS1YDM4dj5CT3hbBHmAk+STTiwuzeSmu10YA1Pmc99XWoxQeaSpfTwsBAy++We43oa
         IEEckJi6oqYK28/a+0HucBTMIo64RjmJpKzSiQVC64Uckf0RpvOKqd+tL5/xnUlFMAPj
         ISTrhF2a+n2NEkn6wwr8dSQ1EXw4qAvW+i/hlI0ytn7+z/Qp3/yGwCrb5Da+JTtsnzFR
         wM5hA9NdP0MPDZYfmITtNfqzJBaY8ER/OUhWBdTF/Tj1TRWjc+vWBZ2sH9HjsNGsW/jB
         r5UXGfWgZM02eFhPEbJrAh82vB3fKEkKCrYdmYI0QFl5/X18cvvhyaSFvcuC4sdCEuLM
         8fkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jlDsnjtZNxEEYWddUEya9M4CBgOCoHS3Js3AsbKzzy4=;
        b=ttHA4/PfLGKD/rWFq8z7LnUCGiYvKqDmUbki2ZlGqUwexxF3l/YJmZsL1a6V5WHJlC
         VLBHFxSxxEv3jE7/7n9K3HfWKGZ7RXz1HoIOZBH122IzEy2a6rQqyz0HWzJTh28SYNp+
         7PnV2qTfluS9b4cgJ6XNYiUspYiNz/6EThirnpd2I5VeuC9eGQc8VxhzqEn10XNNPDlW
         9aW3N+TtAMSx2O0/QQSzZ4a+/YBw+qDBKmpnXexvPWbnISK3xdQsGdPKWt+NYSnxk8Lt
         IMLB3gJu8WGx7XcDVjmBvdmF7ih6XlQiWVT1O9MzV3rEsGOTePua+lDjryxnC7AT4tuR
         ewPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SjVAhokT2EJDE1xLprGjjDV5QbCbwLGb0FayrraJCQjk0QRh0
	aAtL3Pgz6ns51i5f3ZYzHNQ=
X-Google-Smtp-Source: ABdhPJxE0/u6lODmVNHlWFhQ8csZvumS9QZFrypcUtQucdIwhyMo13fPuFxenpJRgFhxeSn5nm4U9w==
X-Received: by 2002:a0c:d40c:: with SMTP id t12mr955522qvh.37.1604660904987;
        Fri, 06 Nov 2020 03:08:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:a389:: with SMTP id m131ls417409qke.8.gmail; Fri, 06 Nov
 2020 03:08:24 -0800 (PST)
X-Received: by 2002:a37:87c5:: with SMTP id j188mr887295qkd.476.1604660904592;
        Fri, 06 Nov 2020 03:08:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604660904; cv=none;
        d=google.com; s=arc-20160816;
        b=R7769q9HK2yWJpog8X0AJ0+5s1xwKFyRvTmf69oJEPN6+Ay00/EQPv8bRAIecJ6R7l
         OFSDueu15qh6Sq0mdSXzcDxNBXuD/lPUqmkkIyToBAMLyRz5f26RVMK+ZtXnu46gxMqa
         e21jL3DaK+VA9OBZ9QWkABzeAlP7wmwl2ud3WCUOfH6LCf06K64ENY8uRDR7DYW1aHdb
         JUWDRcEOaqFNRpSprXRHupBWiNOOKspFlTo3HWANbkaf2KeEgTXfb5NMRH4O+LkQeb+r
         AllMAwyddb8qQOKxDrCTEDSGeLXXy3AS+oS63KllFfSS8AOy+Zug9LR/05Yqd1FwHmKe
         lchg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=v5a4Szf6p6tORd26WYP/gx9J8ug4vHhl3q4STkLfCM0=;
        b=umPejnHo0Guo0th/hI5hBwvS2soPXWjnY84pxT9P25jPUlux0haIUJSfd2FuX9Kk5m
         1SUrsiHRNAmIF0v4JX1f/AWWheJy6MDnl2TMVtXW4j3O0gnjuRJKtmidIL2WrFuIQ/ta
         VGIcCwzR0hLZqTjiG3yCgz3uNyDEg3fMKlhBnMgfocYNDg+DAtHEEwT59/ceETw/qDnt
         TDDKjrbDbgSQnZmYcz7Yttxs9C2UC+kdYi8PfKoKown5wNHXmFmepPkFhpLDFvoxfmdr
         0vbFKaLVYbN0MjdqYlWgxnIfS2m3Rai3X9iRo3CveJdJ92kD8XMf+gdFR+f+t6qpPrQy
         aqpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id h21si61238qka.7.2020.11.06.03.08.24
        for <kasan-dev@googlegroups.com>;
        Fri, 06 Nov 2020 03:08:24 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id E412E147A;
	Fri,  6 Nov 2020 03:08:23 -0800 (PST)
Received: from [10.37.12.46] (unknown [10.37.12.46])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 62E103F719;
	Fri,  6 Nov 2020 03:08:21 -0800 (PST)
Subject: Re: [PATCH v8 30/43] arm64: kasan: Allow enabling in-kernel MTE
To: Andrey Konovalov <andreyknvl@google.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>
References: <cover.1604531793.git.andreyknvl@google.com>
 <5e3c76cac4b161fe39e3fc8ace614400bc2fb5b1.1604531793.git.andreyknvl@google.com>
 <20201105172549.GE30030@gaia>
 <CAAeHK+x0pQyQFG9e9HRxW5p8AYamPFmP-mKpHDWTwL_XUq7msA@mail.gmail.com>
 <20201105173901.GH30030@gaia>
 <CAAeHK+wOyPYP=BkhratZwR=NKyzLWzwTTbyGtqQ75tJyM1D=rg@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <c8a28305-eac6-54a6-3071-9768a9774a5c@arm.com>
Date: Fri, 6 Nov 2020 11:11:21 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+wOyPYP=BkhratZwR=NKyzLWzwTTbyGtqQ75tJyM1D=rg@mail.gmail.com>
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

On 11/5/20 6:09 PM, Andrey Konovalov wrote:
>> Ah, I got there eventually in patch 38. Too many indirections ;) (I'm
>> sure we could have trimmed them down a bit, hw_init_tags ==
>> arch_init_tags == mte_init_tags).
> The idea with these indirections was to make hw_tags.c to not directly
> call MTE stuff and abstract away the underlying memory tagging
> implementation. We won't know for sure how fitting these abstractions
> are before we add another memory tagging implementation though :)
> 

I agree with Andrey, because in future the sparc architecture might want to
support HW KASAN hence keeping a generic infrastructure adds some value.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c8a28305-eac6-54a6-3071-9768a9774a5c%40arm.com.
