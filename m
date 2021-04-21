Return-Path: <kasan-dev+bncBC2OPIG4UICBBSWY76BQMGQEENAJBCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CC343667B3
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 11:11:45 +0200 (CEST)
Received: by mail-oo1-xc39.google.com with SMTP id 126-20020a4a17840000b02901e5e0ccc28asf8518586ooe.13
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 02:11:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618996298; cv=pass;
        d=google.com; s=arc-20160816;
        b=la/Ao0oZgGD90iL91bLleRg5ElHkc+JtLmlzOWQUxYhHx9pozYy7hbpwRKVlK2xcNj
         5kQ/LZR4jG39cndCCjDvsjcWXsFSBgvgz+S4nVduSSO5C5s87UXrIb3UmeIAcuCRsZo/
         YjaZ2s31jLVORWaH0soxrvBwJp6mPfNM9FxKQe4C5yPdLw/DGVKJkmzNR9FmoBdc5ouk
         ttlz0UZKwN5OAEPyngrD+361VjyJvrJJFNLhn36OpLVo2PDtyFoErUlRVSNYK5af7CJm
         +GG3+b50hNDRaDC8x+fiAel/3IZ6THk5Y9bN0BP+TV9TkfUUz1TokleYlm+jk7xwnPDN
         T5Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ppseMzw/iE7TGgD7mBjts3+e3NHM/SXFCMXGwOpZoxA=;
        b=XP7yJAqRHXG3xw9moV0DjLtw23cd0OCXnhh7VloDm5bNF/NrYyKnoHvraObHJ+ohqo
         El8ZjOFNKtUBQSjyRnAustoVxQJaPJ+AqN9kUUgvpJ0upkpCTxchSAlareP0igNJtRml
         FQhvNCwMXC3iCEFyQDg6vCvVtW6XM4SwwNx8TEr5GsyX0KOO+MgJTulf+9O0V67CGYv+
         FhJwk1UKj1b3filHiEnpzmcpVijCAC9Y40zfKx0MxKbZUMn8Bp73MoVY0M/QvLVR7M6t
         HrxzJyqaj2vNeN/M9qR/LMJwBmqWIugVVxLKWrbjQoleABkjKeho/yssPvGQlGkmu5By
         2y6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.21 as permitted sender) smtp.mailfrom=hdanton@sina.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ppseMzw/iE7TGgD7mBjts3+e3NHM/SXFCMXGwOpZoxA=;
        b=EiPCJedGYqAFz962ref4RZAEZDieTwYeDMVG9UJ4wgtDL2qpD5asHp+2NqV+GRQ5N2
         w3o6pAgoj531SDgZl27F0QAdIg1D1UmrZ1PPH9fB8Bnqf3MLc2HlYSxWiaDC3DqIYb9/
         Wzf7qoXAj2Gkng76vMq2HKmcH7C9QM/deRsDI2SJ+l1pP/2qU0Tc+iDW/mfWTEqjPPd2
         Rpio89jkteku03S+EJ1pvGvCHYFB/ACi4FDVdXzBcP9jdcejL+zAI68Kf5Xiv2YYY16t
         Ol21Pc4NUrKT/fYro+mwzw/BlacefLzoiUuVQ7HkJJxo5D5inYRmr+rSMq/O1FmwgAyf
         5xRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ppseMzw/iE7TGgD7mBjts3+e3NHM/SXFCMXGwOpZoxA=;
        b=T5paefnl4M61RkxaB54X3DYZRQ6qlEOvOZxFVo6GoalLyqFL002xL1A0nEpPF8LXeu
         9C/ccWg92PIqGvP6GRdiYz0kGuTZdMNdCiZcSpYSkCHZNXfi1O4zFsiPYfd2njaK39vw
         4TgGRPMIs+05IBqXEbAuB5NxbxEpDZps/6NjFZwBVkbE2Es/jCfT/8qCHxuaWvylHQno
         1KrfBfHyxQ4usymCplUT7HOE255wE1a/oUjPFiWdeV15e97v2i0+fmFqSABoHRBEAYUr
         gPtFC5/bxNlOY/aPkJCgtD1Tn4R7CPQ3Wdn2VWAxTHLAfnDvNJZwJHCNifY9sJkjFtag
         GtaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533J5NN21Na1sDtpLcuAffpH21yn4UIqtDr2x8tGRc8TRBjjwa8p
	NPAeW5FR95c8jkvJ3Ll10tw=
X-Google-Smtp-Source: ABdhPJziiRqyDCi3cA2mUpUgjtOJDaLw99arsirvqHc8bigM+3b6XxldtOd84u4+qepFUejnpcXPGA==
X-Received: by 2002:a9d:6056:: with SMTP id v22mr16156965otj.231.1618996298720;
        Wed, 21 Apr 2021 02:11:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:664f:: with SMTP id q15ls409948otm.3.gmail; Wed, 21 Apr
 2021 02:11:38 -0700 (PDT)
X-Received: by 2002:a9d:a2a:: with SMTP id 39mr22586697otg.371.1618996298323;
        Wed, 21 Apr 2021 02:11:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618996298; cv=none;
        d=google.com; s=arc-20160816;
        b=llAGqPuP6ywthQSUjXy1W3ST7s+tRoOEZ8HAHQ1wEePOT1L0ctvSEO/fk9ELLTIk2L
         v3aOB7urK17huKX1lEDAKXTVcF12MdbfLG04WnHEopfodxkdRSBYhtlTkhk4tewuzTpQ
         oGPJg7N88aGfDxekF2rd4cId5MFCwg7KcMthGCT8qwRubqfxEPUeb3ySLoaPksEsCtRM
         EjaXiMjSrhL9kO5am4O2Y3coXS4w5cdud9qua4BzZiI2qIAoLb65SF41YJaGtoVE6J2h
         U5h9B3RI8W7Nd5S96qC62lsEOOjXu+/RhYxkV+SHZel48N75LIUPEj4kPDG/SSzMjFlM
         T2Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=kB7WdMcXhTvU2JGdMzPI2+VWmVZVKvHNIfE0NGlkBxo=;
        b=KuQl7mmzgn1ENp++DYVqq9s/06yWv/FHlqPN/jtrPNrOLBcuF+eRljo8sMyPubCyKW
         8TNa6WYDCRi4USVY/Y+7eYWpSlDX5GG62XjxrJsCwcN25WwIT5xtphjtYDMMrUbXuula
         7nsDfWQLT1JpW5G+AoNhCGrx7Sn7/XKCYjaiC86l4RUiAhSr7j2PLRkjrNZyWelPqhXR
         7PsTRgbxEcXXdZoWIAAk/EOPwfeiYEkpcc0SsgRLb7Tkrba9MhspgcbYSO8QueXbJLz7
         y9TAgv08K+2uUtO7YXAlvlAmnHZuIMQ0nTrXAQg7zNp7ZO2U1o2kLw5+C5m6KHw6pxAk
         KuZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hdanton@sina.com designates 202.108.3.21 as permitted sender) smtp.mailfrom=hdanton@sina.com
Received: from r3-21.sinamail.sina.com.cn (r3-21.sinamail.sina.com.cn. [202.108.3.21])
        by gmr-mx.google.com with SMTP id w4si103001oiv.4.2021.04.21.02.11.37
        for <kasan-dev@googlegroups.com>;
        Wed, 21 Apr 2021 02:11:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of hdanton@sina.com designates 202.108.3.21 as permitted sender) client-ip=202.108.3.21;
Received: from unknown (HELO localhost.localdomain)([221.199.207.227])
	by sina.com (172.16.97.32) with ESMTP
	id 607FEC3F00001E87; Wed, 21 Apr 2021 17:11:29 +0800 (CST)
X-Sender: hdanton@sina.com
X-Auth-ID: hdanton@sina.com
X-SMAIL-MID: 502493628973
From: Hillf Danton <hdanton@sina.com>
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Jann Horn <jannh@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Hillf Danton <hdanton@sina.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/3] kfence: await for allocation using wait_event
Date: Wed, 21 Apr 2021 17:11:20 +0800
Message-Id: <20210421091120.1244-1-hdanton@sina.com>
In-Reply-To: <CANpmjNNO3AgK3Fr07KXQhGpqt6-z7xNJFP=UoODg-Ft=u9cGfA@mail.gmail.com>
References: <20210419085027.761150-1-elver@google.com> <20210419085027.761150-2-elver@google.com> <20210419094044.311-1-hdanton@sina.com> <CANpmjNMR-DPj=0mQMevyEQ7k3RJh0eq_nkt9M6kLvwC-abr_SQ@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: hdanton@sina.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hdanton@sina.com designates 202.108.3.21 as permitted
 sender) smtp.mailfrom=hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
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

On Mon, 19 Apr 2021 11:49:04 Marco Elver wrote:
>On Mon, 19 Apr 2021 at 11:44, Marco Elver <elver@google.com> wrote:
>> On Mon, 19 Apr 2021 at 11:41, Hillf Danton <hdanton@sina.com> wrote:
>> > On Mon, 19 Apr 2021 10:50:25 Marco Elver wrote:
>> > > +
>> > > +     WRITE_ONCE(kfence_timer_waiting, true);
>> > > +     smp_mb(); /* See comment in __kfence_alloc(). */
>> >
>> > This is not needed given task state change in wait_event().
>>
>> Yes it is. We want to avoid the unconditional irq_work in
>> __kfence_alloc(). When the system is under load doing frequent
>> allocations, at least in my tests this avoids the irq_work almost
>> always. Without the irq_work you'd be correct of course.
>
>And in case this is about the smp_mb() here, yes it definitely is
>required. We *must* order the write of kfence_timer_waiting *before*
>the check of kfence_allocation_gate, which wait_event() does before
>anything else (including changing the state).

One of the reasons why wait_event() checks the wait condition before anything
else is no waker can help waiter before waiter gets themselves on the
wait queue head list. Nor can waker without scheduling on the waiter
side, even if the waiter is sitting on the list. So the mb cannot make sense
without scheduling, let alone the mb in wait_event().

>Otherwise the write may
>be reordered after the read, and we could potentially never wake up
>because __kfence_alloc() not waking us.
>
>This is documented in __kfence_alloc().
>
>> > > +     wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
>> > > +     smp_store_release(&kfence_timer_waiting, false); /* Order after wait_event(). */
>> > > +

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210421091120.1244-1-hdanton%40sina.com.
