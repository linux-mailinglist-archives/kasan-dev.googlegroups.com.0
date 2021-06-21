Return-Path: <kasan-dev+bncBC3YFL76U4CRBW5AYGDAMGQE4FSY2ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 46EEA3AE51B
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 10:39:57 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id i4-20020a67f5840000b0290274a00a20d6sf1378864vso.19
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 01:39:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624264796; cv=pass;
        d=google.com; s=arc-20160816;
        b=bwWpIYF4x1rSHyTb3SsxBnuJrcWkJTvc8WKtUzAFXAnzr+boAS0qmUr4RC4wvkqSBm
         UtHXutnQrjX2Ft63EJUrLtSaPWTg6Ixv8S/gHBn2iU1hbZ4EFa5N6nZ4v22J6OhagZ2T
         eaQAEX5bCL8ykKx6rb+HobY4GwgTLnaGgZrbW5Bf8iFOVQSw+6ME5qj8HCXJbn248qBD
         MTVkGHGrzXR7Vdxl+4UO1Es2F7s6a8Z8xRaUuPMWwl4S7JLEOH3gm/P4Apk2LScclOml
         /yXILLuNCGFTb88HufencxgB4Ard+CzV97JeM9sK/T61ngaLgPndc+KFEyqswBaubd4E
         IjwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=QHccBvRqUK46Bf855D1795DkiLDklvKQ7d0hjjkd5NA=;
        b=x7CVWq1Zb7ZTYTxPNNTYkd4j1V+Wc+0HVYbjRl4oAbVdT+1LWBTIXoqINJpC0Xwdi6
         1445K8OTcI+loCoKC/ZsS2P3bs1+3r8+DQCf4fPGYx2UToZTQD4D2NXew5WLysyT8bIJ
         8ZVEnROnpvFcgeBVI9K5vt+W+NW6WkC+0Yo7m/wEUIdjPfwfAR0asOJaeoWkVwIITfTt
         3l7j02JILwg2d+MY20AuUYnYdr1O31ILHqYCQb0FYdUrLH7refZ4RIrUA3+TzNutjAcX
         +ToDQJdTOetNkbVVd+P16eu8n+FM+i0tGtl7PQok+Kwft3qZOq6DWVv+7427t924X4jH
         slYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QPeXb9sT;
       spf=pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QHccBvRqUK46Bf855D1795DkiLDklvKQ7d0hjjkd5NA=;
        b=kpYk5kmnaFnEGg+Q4U46AxCYKpTgUF3HcqtbIN7IjuH3vSuzZ/iX1jaqJZkkAYoHQ9
         MReuFkRGTbyYPoxL8BOvOD0Aq/iZZFSfNuD0o3JAvoJarD0Ra+MRNbU+fV1BvSF24rzZ
         i423znx9BZnlGvYNGS60VsFNHawRjkt9PV9Yxq9/3Vp4AJEmw5PtnTYApitBj2Q5DNL2
         dL7I8Lvz6am+zy5je3BpQC7TgxZEiKj16HabcBy1psrEZZXqh6MlPtqO1UrUJlAuL+A+
         pz+KBehSXZKr2TbujYnzpdekzpHVM86eZSpec/cHNQHee/uMNC5TfCrkeOu/Y9+ekZm6
         LRCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QHccBvRqUK46Bf855D1795DkiLDklvKQ7d0hjjkd5NA=;
        b=mIuRg67/Q3Y73cmMfXRTPnCyaVlMasId3MVASm6gWizw5YQZFULiwUL2k5ImEfmo42
         SPNWNvn+Cz2AiwzpbJWhxFQ/ptG8Bh/fg1UIAlx6t+uIgfHskmgghqEL/znS1wpTaW1F
         vnGjbUDZPEESVsvDNbU7UdZFrhL09h8oJLQH17zCdJOph9LsVjt/X7L/E0mByL4rwpZY
         BY5ALMejHGH50RfK7bBOPnAxgCugRAMsRFEWGBwIjNJq+gRWhP87woL/B+WfbYk4Wf/b
         hUjKXKhl8Xk9b2ptvrsE8gWFIn5E5b1pLz6QKrGxHpsT+OERFokaS9j0A4t+ojdHl6Fi
         kXBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533D/BcFxc3jSEy7ZSvxPcBF0HdDVBkUtxskIaQWIZmONYehHfv5
	7yY5hGiXHwZ2NBwZO5KzwbE=
X-Google-Smtp-Source: ABdhPJxKWH041GgTefp7AdNSr1pdvLaeCCjmp8IQxgucFX5LF7M70gwb4Bj4WWhtzxj2yRpOUkf/XQ==
X-Received: by 2002:a05:6122:2088:: with SMTP id i8mr13290221vkd.11.1624264796037;
        Mon, 21 Jun 2021 01:39:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:32ce:: with SMTP id y197ls1546188vky.7.gmail; Mon, 21
 Jun 2021 01:39:55 -0700 (PDT)
X-Received: by 2002:a1f:1cc6:: with SMTP id c189mr13202469vkc.21.1624264795530;
        Mon, 21 Jun 2021 01:39:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624264795; cv=none;
        d=google.com; s=arc-20160816;
        b=yFv8OUJxuFqC96kIrwc/H5W/E8x9GSX25d6vesgvOdd/MyBWuymNxo42c8lQDCRQZL
         s/sfs0ZD7S00OM2a3Ohizn8tyEQ6xclfTVaygnNKuOoCDvO8dHDKA1NXOYkXbT97iMiI
         qhmnUgiQwA6uFuPjsKx/st7Vj+THNRvrpFft47ughM9peAL4UY9VOfsvhAAzixuKaoGZ
         17ZwdC1ucUVOwlGomcHi9t8NkMpd7VUmNDwmjsLiDU4xJRnGBXJrwpeuM0/N5Girz6Hy
         7l5JPQ6lOxz1ySDHb8DcKFEIjSFD8kq06/TxTa5NOR5tNvNwyi2jNyQOMPIuFqpjEGmE
         FqgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=T0iq4AklK07uhVNnOrMTmioBKAv5sLyv0oWUsUhB/DE=;
        b=e8s6veUYk3JSpuLDoAi6ewklvBORJRT0joQ/kI+sWkcU3uIVgNJ2pLRsYHVKKw9aHf
         c9KAzNoGZpjTf3e8zgZeWe/S+uNLkNngbtPkUJzn4JT/+2JQTe3+cJ334ZPwwpvB4zYf
         34nID4H8c5H/YgX9avKKEwbMUXe8l25C8Ut+o3MhD6EpMaH6kxuDXJG5gcfc6Al/NR6Z
         fkQVKOpzF9aD59X1PapyNbImeNxyURv2IVPoLewuu4DehLjqcsT55G2ZLrB0rLooAsaF
         OzcY+5oB1MhK2HrZQEylOKaHq7gb/a1k6SAHnH0uXDoPNUzgneHl0AE/K2i/wRqSNUDk
         XZVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=QPeXb9sT;
       spf=pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id g20si514169vso.1.2021.06.21.01.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Jun 2021 01:39:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com
 [209.85.208.70]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-359-FZU4YNq2NyicRmoM9Z-CnA-1; Mon, 21 Jun 2021 04:39:53 -0400
X-MC-Unique: FZU4YNq2NyicRmoM9Z-CnA-1
Received: by mail-ed1-f70.google.com with SMTP id v8-20020a0564023488b0290393873961f6so7394219edc.17
        for <kasan-dev@googlegroups.com>; Mon, 21 Jun 2021 01:39:52 -0700 (PDT)
X-Received: by 2002:a05:6402:1d08:: with SMTP id dg8mr1137902edb.299.1624264792061;
        Mon, 21 Jun 2021 01:39:52 -0700 (PDT)
X-Received: by 2002:a05:6402:1d08:: with SMTP id dg8mr1137889edb.299.1624264791917;
        Mon, 21 Jun 2021 01:39:51 -0700 (PDT)
Received: from x1.bristot.me (host-79-23-205-114.retail.telecomitalia.it. [79.23.205.114])
        by smtp.gmail.com with ESMTPSA id qq26sm4466948ejb.6.2021.06.21.01.39.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jun 2021 01:39:51 -0700 (PDT)
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 syzkaller <syzkaller@googlegroups.com>,
 kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com>
 <YMyC/Dy7XoxTeIWb@elver.google.com>
 <CACT4Y+YTh=ND_cshGyVi98KiY=pkg3WKrpE__Cn+K0Wgmuyv+w@mail.gmail.com>
From: Daniel Bristot de Oliveira <bristot@redhat.com>
Message-ID: <8069d809-b133-edbf-4323-45c45a1c3c9d@redhat.com>
Date: Mon, 21 Jun 2021 10:39:50 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+YTh=ND_cshGyVi98KiY=pkg3WKrpE__Cn+K0Wgmuyv+w@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bristot@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=QPeXb9sT;
       spf=pass (google.com: domain of bristot@redhat.com designates
 216.205.24.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 6/19/21 1:08 PM, Dmitry Vyukov wrote:
> On Fri, Jun 18, 2021 at 1:26 PM Marco Elver <elver@google.com> wrote:
>>
>> On Fri, Jun 18, 2021 at 09:58AM +0200, Daniel Bristot de Oliveira wrote:
>>> On 6/17/21 1:20 PM, Marco Elver wrote:
>>>> [+Daniel, just FYI. We had a discussion about "functional coverage"
>>>> and fuzzing, and I've just seen your wonderful work on RV. If you have
>>>> thought about fuzzing with RV and how coverage of the model impacts
>>>> test generation, I'd be curious to hear.]
>>>
>>> One aspect of RV is that we verify the actual execution of the system instead of
>>> a complete model of the system, so we depend of the testing to cover all the
>>> aspects of the system <-> model.
>>>
>>> There is a natural relation with testing/fuzzing & friends with RV.
>>>
>>>> Looks like there is ongoing work on specifying models and running them
>>>> along with the kernel: https://lwn.net/Articles/857862/
>>>>
>>>> Those models that are run alongside the kernel would have their own
>>>> coverage, and since there's a mapping between real code and model, a
>>>> fuzzer trying to reach new code in one or the other will ultimately
>>>> improve coverage for both.
>>>
>>> Perfect!
>>>
>>>> Just wanted to document this here, because it seems quite relevant.
>>>> I'm guessing that "functional coverage" would indeed be a side-effect
>>>> of a good RV model?
>>>
>>> So, let me see if I understood the terms. Functional coverage is a way to check
>>> if all the desired aspects of a code/system/subsystem/functionality were covered
>>> by a set of tests?
>>
>> Yes, unlike code/structural coverage (which is what we have today via
>> KCOV) functional coverage checks if some interesting states were reached
>> (e.g. was buffer full/empty, did we observe transition a->b etc.).
>>
>> Functional coverage is common in hardware verification, but of course
>> software verification would benefit just as much -- just haven't seen it
>> used much in practice yet.
>> [ Example for HW verification: https://www.chipverify.com/systemverilog/systemverilog-functional-coverage ]
>>
>> It still requires some creativity from the designer/developer to come up
>> with suitable functional coverage. State explosion is a problem, too,
>> and naturally it is impractical to capture all possible states ... after
>> all, functional coverage is meant to direct the test generator/fuzzer
>> into more interesting states -- we're not doing model checking after all.
>>
>>> If that is correct, we could use RV to:
>>>
>>>  - create an explicit model of the states we want to cover.
>>>  - check if all the desired states were visited during testing.
>>>
>>> ?
>>
>> Yes, pretty much. On one hand there could be an interface to query if
>> all states were covered, but I think this isn't useful out-of-the box.
>> Instead, I was thinking we can simply get KCOV to help us out: my
>> hypothesis is that most of this would happen automatically if dot2k's
>> generated code has distinct code paths per transition.
>>
>> If KCOV covers the RV model (since it's executable kernel C code), then
>> having distinct code paths for "state transitions" will effectively give
>> us functional coverage indirectly through code coverage (via KCOV) of
>> the RV model.
>>
>> From what I can tell this doesn't quite happen today, because
>> automaton::function is a lookup table as an array. Could this just
>> become a generated function with a switch statement? Because then I
>> think we'd pretty much have all the ingredients we need.
>>
>> Then:
>>
>> 1. Create RV models for states of interests not covered by normal code
>>    coverage of code under test.
>>
>> 2. Enable KCOV for everything.
>>
>> 3. KCOV's coverage of the RV model will tell us if we reached the
>>    desired "functional coverage" (and can be used by e.g. syzbot to
>>    generate better tests without any additional changes because it
>>    already talks to KCOV).
>>
>> Thoughts?
> 
> I think there is usually already some code for any important state
> transitions. E.g. I can't imagine how a socket can transition to
> active/listen/shutdown/closed states w/o any code.

makes sense...

> I see RV to be potentially more useful for the "coverage dimensions"
> idea. I.e. for sockets that would be treating coverage for a socket
> function X as different coverage based on the current socket state,
> effectively consider (PC,state) as feedback signal.

How can RV subsystem talk with KCOV?

> But my concern is that we don't want to simply consider combinations
> of all kernel code multiplied by all combinations of states of all RV
> models.

I agree! Also because RV monitors will generally monitor an specific part of the
code (with exceptions for models like the preemption one).

Most likely this will lead to severe feedback signal
> explosion.So the question is: how do we understand that the socket
> model relates only to this restricted set of code?
> 

Should we annotate a model, saying which subsystem it monitors/verify?

-- Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8069d809-b133-edbf-4323-45c45a1c3c9d%40redhat.com.
