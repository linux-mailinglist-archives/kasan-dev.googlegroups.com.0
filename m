Return-Path: <kasan-dev+bncBC3YFL76U4CRBIEZYGDAMGQEFCX4Y2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0E4913AE4B9
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 10:24:02 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id p5-20020a0ccb850000b029025849db65e9sf13476969qvk.23
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 01:24:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624263841; cv=pass;
        d=google.com; s=arc-20160816;
        b=aBU8ruthhIqHyMphSt/uWKDfJBRnayrXfidXSXpT5B9wSy8AIvXyrGvI77OsZO+irG
         GmDvnoG9fJ1F4IZBaA+DbdJLCta5oZQaB6RjOuTxKY70IPFPF0zcKw17R8OsRL8PjMAa
         EQe5v4FC+SCYuk+VIWBln3Vg8zrbC1hC3fJHe4CFecQwyccZ1EdX46DPMIpTZZi2Rhej
         eVKrtwnu5yhvaF5Ak7/R0QXr8EJ2FpFpR0yHiYXmrwoQKGRIi+1DQR1Lz2RW2QU4OOIt
         CXD9DvdDoxklzmcatPLPz+hldNQAmN43FF/ndaxbOJP509wk5oSfAmlwMXRjj+ZWx1HH
         v6hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=aytVUS/1F8IpGDochJ2dH71ET6RNgODu3Xkpcukcv6U=;
        b=RFXxOxL1+bKs7DPE+TgSeY51GF1voQOkNhXT5uKYtxI5hTUZ5Ks3ftsEEBbQaY7yNZ
         KYJ+9RnxlKq5L7+Col6xx/NI4JRD6jR0760thAWThsftsjoBUcgy5qz2Ksz0xRbQmycV
         NhDP/puyJU1H/CKBxEib5bzM7/gb8OiL9tSOsQY9rkg1N8kH6XE9SOwOPt+nb5sFrnuv
         wNq+y1Q9d+liVtuJ8qa62p6R0FrWV42JTjuxJNVETPYi8iHVVbItj6H45iu0agv6e0UX
         P5YWaaD7+EXSJ54EffSzLtnz2zIZkZnlVVlnH2bo+lLl3VAffRAjkZS2i8mrlENy/0Hh
         zL6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WzN1zGys;
       spf=pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aytVUS/1F8IpGDochJ2dH71ET6RNgODu3Xkpcukcv6U=;
        b=bZlPnoopaYiGbHHJh3isOPbY6mVX33jypUE8uMQGRGvExC5p+IrMUbh2r0abv5rRpj
         qKOI0X0iTB8YivRorcFI0lE2TugVhIcTQvEJ6vNaZRayQstUgDBaozdOuOcK1h+XwKiA
         ww+JrD4NrbukqRoK9rKdLAphWc8GGLlYL5cSMkj++HkyXAwGfTNgfdUXulVYCshusIiL
         52QFqMVrHKHtmz/iTBXqCq8mVMhLo9sjRghYecyqOhkDL5swDIz+xxfJogXr7tZJRhCh
         112lR1MKPAqkyJXdxlWsG8MiaIwHqdhKc2n/akvUm4HAuwEaxCLUUXyyGDQs9T1Rfdkv
         EUiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aytVUS/1F8IpGDochJ2dH71ET6RNgODu3Xkpcukcv6U=;
        b=GVF1Dm756QF2Rl8ELEp5+kHKL8DPNWpH1EAthqwRSMOlTj0D+7QRD933I1fUaBJHyC
         OE6Hw6rTsn9UFlDqdXtnLwfkxf/w0SD2hh4YFiGd1m9+PWQXCxM4wPlMEXLRxn9Newy3
         bgOnuwOu1CkwVVAWNssU9Lzp2c3ETDiartrxqNqS+Rq4z5Xh2r2yskPtzCi26rdGDckb
         3OuyLuC++o72ZyQmeWaobm3+CqVo2sUCYIzIYs9oJkW9Lz0ZG1YVBk5pithoqO0cjvvZ
         BybTknx2CtHy5iYNyfpLoSEa+hK31Wlti7XoH0xj5rNaEB2dubCQ+fR6mVYOUHIrZGI9
         izsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530NSHPZ7yRPerZNdVEqVgMi9WySKpEzrlIDAOPaVF95WKkr6qI5
	lFutEB5cOdRESYjMqKJ73Aw=
X-Google-Smtp-Source: ABdhPJxH8QLmdIGN/hsNIOWuP2yEgF2Ou8Fz5bYygBBQleAUUYgik1ByA6CJly7My7LRg0GsJi27qQ==
X-Received: by 2002:a25:2785:: with SMTP id n127mr29387395ybn.235.1624263840999;
        Mon, 21 Jun 2021 01:24:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2787:: with SMTP id n129ls8723189ybn.6.gmail; Mon, 21
 Jun 2021 01:24:00 -0700 (PDT)
X-Received: by 2002:a25:f81a:: with SMTP id u26mr31807349ybd.389.1624263840481;
        Mon, 21 Jun 2021 01:24:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624263840; cv=none;
        d=google.com; s=arc-20160816;
        b=a3tAWNkgX99pgsb/nicdrsrqwodXT2O77QGzuC0Fa8b2OIwZoqG/92yaIIqrJelrFn
         IkkVEarmxIgAuaXS8G2KnXgzcngg/A2fySs4Yertd6AKTYKKPGTqCy3kEj0q0NZECfRG
         TeoUfaT7lhf+XL4WkDYukZTCgDMi14SWuuhtie1Vx/9Zv7LFhtzdk/Ycb40RP+iB1Lhz
         XwZ9WSgkTAcktWeuSJMBToVvQbG70EJ4gP/1pPTUpSNFS7Nq+KgTJsiKR0E9XcVcN24l
         k2GRPbnb6izSGV5M/QqLJhBYrjtQO8fSfG65GQ5+t3F4GJmm7FsVg2IX/PgWdgiloRdg
         BWFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=2eRyDqU+eiRM4S6L16jfahmN9VAWzXoQKsX2LAlqcH8=;
        b=BFoWBXaOetQNk08nSz9KFDGaLwf5iZRN0yP4wbWGPnnwmwyOvzJJOO3oB14IoqTFC2
         UaX0PGfF11uaYNDeaf9kHoUUukOH7FSM13RWpMTuB7ddtpyKhr/Y/e93HyRR9uAbv4of
         yiHAmJu0PxwGZiauHidRgABLTYTQFvJuQeKXx3Ks1reZMM5f66GRJHQw6w4TvqzrihV4
         BBMt8aeUdsFhM7VB5j+rGU+mrwRzGw9Mljk9O2sctBJhVcs7ox7ztwpVY0tj0g1VR43n
         WrQwC9/E/zPW0kY3v5gHATqMBqQg7qPBjHy/QR21jI9VIJdiyrB7g8iovkQFuu5FEQpK
         DRGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=WzN1zGys;
       spf=pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id o78si733914yba.2.2021.06.21.01.24.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Jun 2021 01:24:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mail-ed1-f69.google.com (mail-ed1-f69.google.com
 [209.85.208.69]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-285-ASZimFh4MeyyIiEFPdcShQ-1; Mon, 21 Jun 2021 04:23:57 -0400
X-MC-Unique: ASZimFh4MeyyIiEFPdcShQ-1
Received: by mail-ed1-f69.google.com with SMTP id r11-20020a05640251cbb0290394ac47875bso1793514edd.10
        for <kasan-dev@googlegroups.com>; Mon, 21 Jun 2021 01:23:56 -0700 (PDT)
X-Received: by 2002:a17:907:3e88:: with SMTP id hs8mr1561483ejc.96.1624263835772;
        Mon, 21 Jun 2021 01:23:55 -0700 (PDT)
X-Received: by 2002:a17:907:3e88:: with SMTP id hs8mr1561472ejc.96.1624263835573;
        Mon, 21 Jun 2021 01:23:55 -0700 (PDT)
Received: from x1.bristot.me (host-79-23-205-114.retail.telecomitalia.it. [79.23.205.114])
        by smtp.gmail.com with ESMTPSA id b14sm4434036ejk.120.2021.06.21.01.23.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jun 2021 01:23:55 -0700 (PDT)
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, syzkaller <syzkaller@googlegroups.com>,
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
From: Daniel Bristot de Oliveira <bristot@redhat.com>
Message-ID: <35852e24-9b19-a442-694c-42eb4b5a4387@redhat.com>
Date: Mon, 21 Jun 2021 10:23:54 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <YMyC/Dy7XoxTeIWb@elver.google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bristot@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=WzN1zGys;
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

On 6/18/21 1:26 PM, Marco Elver wrote:
> On Fri, Jun 18, 2021 at 09:58AM +0200, Daniel Bristot de Oliveira wrote:
>> On 6/17/21 1:20 PM, Marco Elver wrote:
>>> [+Daniel, just FYI. We had a discussion about "functional coverage"
>>> and fuzzing, and I've just seen your wonderful work on RV. If you have
>>> thought about fuzzing with RV and how coverage of the model impacts
>>> test generation, I'd be curious to hear.]
>>
>> One aspect of RV is that we verify the actual execution of the system instead of
>> a complete model of the system, so we depend of the testing to cover all the
>> aspects of the system <-> model.
>>
>> There is a natural relation with testing/fuzzing & friends with RV.
>>
>>> Looks like there is ongoing work on specifying models and running them
>>> along with the kernel: https://lwn.net/Articles/857862/
>>>
>>> Those models that are run alongside the kernel would have their own
>>> coverage, and since there's a mapping between real code and model, a
>>> fuzzer trying to reach new code in one or the other will ultimately
>>> improve coverage for both.
>>
>> Perfect!
>>
>>> Just wanted to document this here, because it seems quite relevant.
>>> I'm guessing that "functional coverage" would indeed be a side-effect
>>> of a good RV model?
>>
>> So, let me see if I understood the terms. Functional coverage is a way to check
>> if all the desired aspects of a code/system/subsystem/functionality were covered
>> by a set of tests?
> 
> Yes, unlike code/structural coverage (which is what we have today via
> KCOV) functional coverage checks if some interesting states were reached
> (e.g. was buffer full/empty, did we observe transition a->b etc.).

So you want to observe a given a->b transition, not that B was visited?

> Functional coverage is common in hardware verification, but of course
> software verification would benefit just as much -- just haven't seen it
> used much in practice yet.
> [ Example for HW verification: https://www.chipverify.com/systemverilog/systemverilog-functional-coverage ]
> 
> It still requires some creativity from the designer/developer to come up
> with suitable functional coverage.

That is where the fun lives.

State explosion is a problem, too,
> and naturally it is impractical to capture all possible states ... after
> all, functional coverage is meant to direct the test generator/fuzzer
> into more interesting states -- we're not doing model checking after all.


I still need to understand what you are aiming to verify, and what is the
approach that you would like to use to express the specifications of the systems...

Can you give me a simple example?

>> If that is correct, we could use RV to:
>>
>>  - create an explicit model of the states we want to cover.
>>  - check if all the desired states were visited during testing.
>>
>> ?
> 
> Yes, pretty much. On one hand there could be an interface to query if
> all states were covered, but I think this isn't useful out-of-the box.
> Instead, I was thinking we can simply get KCOV to help us out: my
> hypothesis is that most of this would happen automatically if dot2k's
> generated code has distinct code paths per transition.

...

> 
> If KCOV covers the RV model (since it's executable kernel C code), then
> having distinct code paths for "state transitions" will effectively give
> us functional coverage indirectly through code coverage (via KCOV) of
> the RV model.

so, you want to have a different function for every transition so KCOV can
observe that?

> 
> From what I can tell this doesn't quite happen today, because
> automaton::function is a lookup table as an array.

It is a the transition function of the formal automaton definition. Check this:

https://bristot.me/wp-content/uploads/2020/01/JSA_preprint.pdf

page 9.

Could this just
> become a generated function with a switch statement? Because then I
> think we'd pretty much have all the ingredients we need.

a switch statement that would.... call a different function for each transition?

> Then:
> 
> 1. Create RV models for states of interests not covered by normal code
>    coverage of code under test.
> 
> 2. Enable KCOV for everything.
> 
> 3. KCOV's coverage of the RV model will tell us if we reached the
>    desired "functional coverage" (and can be used by e.g. syzbot to
>    generate better tests without any additional changes because it
>    already talks to KCOV).
> 
> Thoughts?
> 
> Thanks,
> -- Marco
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/35852e24-9b19-a442-694c-42eb4b5a4387%40redhat.com.
