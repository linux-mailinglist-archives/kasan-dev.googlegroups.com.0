Return-Path: <kasan-dev+bncBCZOPTGF6YHRBK7H5LVAKGQENPV3X5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CEC0C926CD
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 16:35:23 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id g13sf579146lfb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 07:35:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566225323; cv=pass;
        d=google.com; s=arc-20160816;
        b=tvg39z/8az7YDWznWvOo+wH3uvqbqqP08NPtJKeKcko6Fx/t08sSQGUvM7RYr4MQ12
         T85CvIrcOuREU36NGvD8NygLhV0PJEbl5Kt9UOzT/ALRTMO4S9fbANWL0LDWYUjr1rZT
         3W/9ib9JjVsWzU8w1hqCgLEnGZt46rlHZ7+qNVzpuNMM052W28+yKTIMg84H23zIqpEH
         cAUO6WNPkC65LKARm/sFYNzqWy7UsvVWm0A7HWSnYJHq3KdE14vyzlHs8BfK5qckn3o+
         sUhM0iSU/ahdON7mFtkhtCl/S3gV1SHqIFphVMZohoU+Cb7+twf2tSWPak1i1zg/Cbdj
         5SJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=o8On5QLqJFhuNrz4QDhcQrTN7PIk9qsqIw1CbEcGvWQ=;
        b=FA5kcaNBbvu5+VPXNQZnEv5zL8vFQAezxilgdl7ecjfgrzr1ffRHH/eBYdUTU5jn2R
         /qY4bbh5YYo/HjFrKeRz7fd5iKMivH7iHazKJThCRNMNhJu5HADraSobWXF7/B7eqd93
         I5rPvxDEANJzexufz1gPa2gkObMarAcIQZJrYp4+gw+07Y3I70nr6TBhyHSgHvbuZmVW
         0WMN18Xl4HzwbIBmEmeXLqRFPsFcC7jaiQiWZzRg7sPqO4KRcC7I4Y6d6oVWcvY+CuUv
         G34VvgPkehF9CbQNlxBLEcASQgfk124T550th8TMOhYdKYs5lFGTNiMQEIWk8fb329RX
         2/Lw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=o8On5QLqJFhuNrz4QDhcQrTN7PIk9qsqIw1CbEcGvWQ=;
        b=rwpVFhQnFVsnv9Lo/Edgge3h1cPWYo3pZ7cAmURLEVN4gfbzTk+0gfs+dotUSrGB6X
         pOmO2NWMJ1UmoBL0Ybvse/w9dGCdY+3/++G0l/s6xUkR+Ule4BfgWb8+HPqXZcROZJQk
         i+UnpYSEOl/gVUXwh801cUS1dxSWtLJ6/qFBkP/KY37Z1I4WXmr0sA2pVDrWy5MAeocv
         YQOUq6wc4yYFhtN9WNqs5cQvTDbuZODSHS3lEFnkytN36mqzGNPnHeGV0APWLV9qc05d
         Ax9Rq5NeBvdeahnWPPz8iLQ5fKbEf9W5NE0cEDUfu/S6KhZhoJkr9/d2vbTLYNsv+N+6
         48mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=o8On5QLqJFhuNrz4QDhcQrTN7PIk9qsqIw1CbEcGvWQ=;
        b=TyWcfthmqFSKz7XJjllvQV17KNI/Rh34UGJtRAo1IZGTptzvQC0ij78gBEoo8IjKkt
         dI/RJxqAlACHk2HznyN8LxKhMw6Keq6QykaNq3SEQlzIrsggfvVKrt6diWcqtHGstaGM
         2oULo8fL5EwmHyeg179yQkLxiAsQXJCdrxBx6ujwO/4eE4uTLOr9pnjvzzRvlFdSy2Zl
         C3wJNCYIXrtxpN76kqWJ26keLJ0C2Ggce1G9lDu3z85rStVp1wuhaQSit4TbQBEPWD5l
         b7cD+GosFVz1xk/zlclx8M6AutdApD7gQQY8CxCrmHnyLw3KJz5H+xzeUVE13vCknmYi
         1lUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWazp9C7vd/0QlWFarbg6bczlU2xN0QTK563X618MhOkoi9liRb
	tAVE9coHuDHFkBM6tyk9L7M=
X-Google-Smtp-Source: APXvYqzg4pY4L3Kp78MOlpIFMc5FxicSt83MHNobITNQomtr/AhGa7OYB0RFXXK2vM6I6Avh6sS/jg==
X-Received: by 2002:ac2:5690:: with SMTP id 16mr11967818lfr.43.1566225323418;
        Mon, 19 Aug 2019 07:35:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9445:: with SMTP id o5ls1747252ljh.9.gmail; Mon, 19 Aug
 2019 07:35:22 -0700 (PDT)
X-Received: by 2002:a2e:934b:: with SMTP id m11mr5576885ljh.114.1566225322550;
        Mon, 19 Aug 2019 07:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566225322; cv=none;
        d=google.com; s=arc-20160816;
        b=tPddVyzmIHECjXVbaC4M168/w/s5xIbQpN1sIbNpm3VY7/64PS/C+WDNdspdwAnsYL
         S4xP2hpwvRE6NRizWmk1s+E5giz8UzC0NBFDiLgX2CPkCkBS+IFNu9alic+gQ8oe4V/+
         josHF8x3Be41HPV9tbk/fQWIzIdbd7zKdt+o+tPXnE32xwNhe1qMPLMaiow+cPgluj3G
         TLatlLbOK0s5Zy5uB6hG5er2ixfl1q7K5YOFeElD9CsV9jbawy+iu2buAL35/+ktu1UU
         0rXHF+hqXCI6r7UIbqKIz5VVbwhLrrbcc7Tf9x6KiMAtfDligd5re6e6YCAPJfIyO61T
         qx6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=sIFsnVuxBl/y72Zzf4lBC2bCFvP5/kYc9Ub+QPlp2Tg=;
        b=oQswn1pPieVDFV8nvp4WGHdhgXZI2ALBEAVy1i15IewC/bp9/LEjg+BX9gvd1Wn8mn
         NuIQeKmD6ACuo9RAR7jPeqzKiTH2MxdXsvDTSo/JGn37+0A6qxh6vffALMmfLsJZPKQ3
         +6eMh+mKJDTkfduizpDnbOS6zACPvE/WqieMxYMKlLRsxQHu/8NKJfu3lKhVLQoR75H0
         EdFE39DV+6TtE80jomA3QLMCeZaOcQ9vSpv3JB8MljuYmdf+nFsdovnL/JWSzNer/33s
         DNFkpK293XLVv2kHXA5lsQMRIiBKVF8PpSKMjfqX0PuZk5HXLRP0azFPafdJZ5C56/Jv
         Tg+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=robin.murphy@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id u10si799864lfk.0.2019.08.19.07.35.20
        for <kasan-dev@googlegroups.com>;
        Mon, 19 Aug 2019 07:35:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A1DDB28;
	Mon, 19 Aug 2019 07:35:19 -0700 (PDT)
Received: from [10.1.197.57] (e110467-lin.cambridge.arm.com [10.1.197.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id AC6923F718;
	Mon, 19 Aug 2019 07:35:17 -0700 (PDT)
Subject: Re: [PATCH] arm64: kasan: fix phys_to_virt() false positive on
 tag-based kasan
To: Will Deacon <will@kernel.org>, Andrey Konovalov <andreyknvl@google.com>
Cc: Mark Rutland <mark.rutland@arm.com>, Walter Wu
 <walter-zh.wu@mediatek.com>, wsd_upstream@mediatek.com,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will.deacon@arm.com>, LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, linux-mediatek@lists.infradead.org,
 Alexander Potapenko <glider@google.com>,
 Linux ARM <linux-arm-kernel@lists.infradead.org>,
 Matthias Brugger <matthias.bgg@gmail.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>
References: <20190819114420.2535-1-walter-zh.wu@mediatek.com>
 <20190819125625.bu3nbrldg7te5kwc@willie-the-truck>
 <20190819132347.GB9927@lakrids.cambridge.arm.com>
 <20190819133441.ejomv6cprdcz7hh6@willie-the-truck>
 <CAAeHK+w7cTGN8SgWQs0bPjPOrizqfUoMnJWTvUkCqv17Qt=3oQ@mail.gmail.com>
 <20190819142238.2jobs6vabkp2isg2@willie-the-truck>
From: Robin Murphy <robin.murphy@arm.com>
Message-ID: <1ac7eb3e-156f-218c-8c5a-39a05dd46d55@arm.com>
Date: Mon, 19 Aug 2019 15:35:16 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.6.1
MIME-Version: 1.0
In-Reply-To: <20190819142238.2jobs6vabkp2isg2@willie-the-truck>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-GB
X-Original-Sender: robin.murphy@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of robin.murphy@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=robin.murphy@arm.com
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

On 19/08/2019 15:22, Will Deacon wrote:
> On Mon, Aug 19, 2019 at 04:05:22PM +0200, Andrey Konovalov wrote:
>> On Mon, Aug 19, 2019 at 3:34 PM Will Deacon <will@kernel.org> wrote:
>>>
>>> On Mon, Aug 19, 2019 at 02:23:48PM +0100, Mark Rutland wrote:
>>>> On Mon, Aug 19, 2019 at 01:56:26PM +0100, Will Deacon wrote:
>>>>> On Mon, Aug 19, 2019 at 07:44:20PM +0800, Walter Wu wrote:
>>>>>> __arm_v7s_unmap() call iopte_deref() to translate pyh_to_virt address,
>>>>>> but it will modify pointer tag into 0xff, so there is a false positive.
>>>>>>
>>>>>> When enable tag-based kasan, phys_to_virt() function need to rewrite
>>>>>> its original pointer tag in order to avoid kasan report an incorrect
>>>>>> memory corruption.
>>>>>
>>>>> Hmm. Which tree did you see this on? We've recently queued a load of fixes
>>>>> in this area, but I /thought/ they were only needed after the support for
>>>>> 52-bit virtual addressing in the kernel.
>>>>
>>>> I'm seeing similar issues in the virtio blk code (splat below), atop of
>>>> the arm64 for-next/core branch. I think this is a latent issue, and
>>>> people are only just starting to test with KASAN_SW_TAGS.
>>>>
>>>> It looks like the virtio blk code will round-trip a SLUB-allocated pointer from
>>>> virt->page->virt, losing the per-object tag in the process.
>>>>
>>>> Our page_to_virt() seems to get a per-page tag, but this only makes
>>>> sense if you're dealing with the page allocator, rather than something
>>>> like SLUB which carves a page into smaller objects giving each object a
>>>> distinct tag.
>>>>
>>>> Any round-trip of a pointer from SLUB is going to lose the per-object
>>>> tag.
>>>
>>> Urgh, I wonder how this is supposed to work?
>>>
>>> If we end up having to check the KASAN shadow for *_to_virt(), then why
>>> do we need to store anything in the page flags at all? Andrey?
>>
>> As per 2813b9c0 ("kasan, mm, arm64: tag non slab memory allocated via
>> pagealloc") we should only save a non-0xff tag in page flags for non
>> slab pages.
> 
> Thanks, that makes sense. Hopefully the patch from Andrey R will solve
> both of the reported splats, since I'd not realised they were both on the
> kfree() path.
> 
>> Could you share your .config so I can reproduce this?
> 
> This is in the iopgtable code, so it's probably pretty tricky to trigger
> at runtime unless you have the write IOMMU hardware, unfortunately.

If simply freeing any entry from the l2_tables cache is sufficient, then 
the short-descriptor selftest should do the job, and that ought to run 
on anything (modulo insane RAM layouts).

Robin.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1ac7eb3e-156f-218c-8c5a-39a05dd46d55%40arm.com.
