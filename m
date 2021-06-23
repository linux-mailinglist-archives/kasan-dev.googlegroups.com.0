Return-Path: <kasan-dev+bncBC3YFL76U4CRB7XUZODAMGQEMIX5M4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id A4BF03B1680
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 11:10:23 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id t6-20020ac80dc60000b029024e988e8277sf1988021qti.23
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 02:10:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624439422; cv=pass;
        d=google.com; s=arc-20160816;
        b=hLDRzh0vySho/xUO8vTv9fS+zNVfBacDDzHky8y8DTQ82+5jskAoViU13CYYhpYmnH
         Lomh2yR6SgSOarBrEdwmOI1G/2GoXhBdssVVX3ttyt7hxD8SmaOAe8EPeNi9o13zrP6P
         +krEuhxx5npZHqsC7oeUr5ETEok1gYvpNsqtr7mzfJeNHFZb1tnnD9tY5V98YXL1bRE5
         3hWpgtixwdxj+m6dKTD9ssqUL4qIBM9YcszDcOdy41ArMyGaa9N35bBC3v1Ypd3A8rYJ
         rzjdnb9aNzwF2EQ7KCCwHPLj3YGqlaiYSpqKREIsDPwe/f2gB+EBDycg+mfmrKYPrn8o
         6rZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=qqzvI4LNNmyIgJEKEUJQZUdUVpWlNUiSma+gxVkvSeY=;
        b=Ml+L/DFTfQ9jLyzbbMI6/Mdv+dTXPEed1AITdmANwXdqrPRa6wUC7uONgZokn7NhL0
         TfS9nAOvwW3lvtvFSjHynbsIpmKjAM+0BW+dpK62Oap23TlV8hKLa9UHkv1ziHUEQ2bn
         Lj7nie0Zdo4JzCuq3OtWzoC5Gw9dJj7Mxe244rfw527KB1Kepf+o+wkRJjI1UlnVyIYi
         C6cRxVnZoCm2cstfI//HnGWJIwhJ9G6FsLT1p8JIQ6N1Qe3vOGL/YtT+9ecLOz7ouT/5
         Fb86tzx/901iouuirauAH1uSvlcWNqecRgnYcDP5OGYZf4+oBSgxA/sqZXcukS4YuHdG
         GhrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Um1NE1FA;
       spf=pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qqzvI4LNNmyIgJEKEUJQZUdUVpWlNUiSma+gxVkvSeY=;
        b=TyDYn6zGT3UZMbXUtOyS4BBHzjZdeTlEe8f5lCXaLk5Ve4lMeKfLpRJHXqTFJJouUt
         n4lm16LWjJSEdB4+KU7W/YibaFqd3JLon8wt6zSOtVODDmCpB25IDc/LvJZlYWvOQJCr
         /IfCFNNHYaIfSlyhwhBQZereHBHNzqeIBZybsX73LCK4i2iUw2MRz7hZpeXvY8RxtGmX
         n9NQ/XDDIB0UIOf1YhoXHQVsKDqP5uxXdkbgQVmmXvySimio/HMSeQHFge29vYbvYfYC
         98pIzALbvf/jBZE3AHR4dJncvxeaPAG6RsFndQvkKYDMiwjSQ+AWvOrjIcc6joPMzA0q
         pOxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qqzvI4LNNmyIgJEKEUJQZUdUVpWlNUiSma+gxVkvSeY=;
        b=BNlbs8BBZnmpUwcyeLU4yQ0YdHMEvPYXXxhG5pdh+2hyE8HDfxnPYI2o2I2NVVZdNC
         rXCYTrpRibNO/PRImqDhBKOugY1OoNcPQvmW8jZeTlqj+08CiAOfWj+gurLRuTZWcod8
         OV+cWKI6VdvsRMvQDmgsWeCqMM5MFV7+pDJsoDpHLWV8O+NZVqE8XxQwINj8DsleuX72
         M8sZhh/Z5U76H7lcVPuCUUMjK+dJMZc+WxNnsPnIDH/CiwdfdWildWbo9L9ncTMaIgCV
         wfPExf87l0SZELZYEEdvaaNNeL7U3TisCUnQk+jH7u7ifLEm8mGQzJEkaR0gdlhyUs0D
         p0eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531P5pfgztqt5RThJKrFyIX/58lSLUQZe7vY20xwqSAvI4KZEhTs
	6Hixe8Jiq9boSjiotRzVrTM=
X-Google-Smtp-Source: ABdhPJzUiMMmHm8Kyc44nwWAhnyBsKzu27A/hKgdMiUqLWtT/RcZEqVY6BLj46XKMZD1kvBSs+G2/Q==
X-Received: by 2002:ad4:536a:: with SMTP id e10mr3548686qvv.9.1624439422704;
        Wed, 23 Jun 2021 02:10:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c93:: with SMTP id y19ls123704qtv.7.gmail; Wed, 23 Jun
 2021 02:10:22 -0700 (PDT)
X-Received: by 2002:a05:622a:195:: with SMTP id s21mr3008454qtw.62.1624439422246;
        Wed, 23 Jun 2021 02:10:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624439422; cv=none;
        d=google.com; s=arc-20160816;
        b=DyGr/vHNXHA14BCxFEMBbLypMV/x2/O0R8twZ/FE4qO8wY7R60QuqmFphYQsS2Z9Cj
         6Aki+mfT5JAz7z1dmzsASZe1TiU8BzE1EXq8N2kQbxjCms94ZpLiNpQ8CZqzLIS+e3Dn
         /ZmOJAuDosyMOVlp4C7Pq1X6sdLNmnGsY8oMFdQywZOcQflR8xgwoCiteKgE4TImD8RO
         9z8E0m+3wD6GuODof28KCn0NoFLVg8R1dZp7ZV6cWnsGQ1Ko+fYduhdNJsdZ2YEdYj1I
         pKuHuj7ZjehJqvt47D5SnMcnEyu6rL8NBw/Y3A11H3MbspUK7sXMQjDEUd9BVm3DYnLq
         uilg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=TldL/w6S5dtdX+yYkIXo1zpWU2dmtlChFepScE6V4JQ=;
        b=ckv2l0idPslbHrj38hKtAsW48DNvlsGnRFrTl7HLI/G5RQAIWBAkuIrFqLNmYdMCww
         TGpWBjBue+t9ztXA+lAZQgA2uacAjHYyG5JPK1SvOQ/cc6O2XD+Tlhi2Y/16Kk6QeSq6
         79vjL92L3VGuTGt5Kx0Kgb2FzBoBm72pvemEdPJr/G8c6eOqtNbiAOq4mvIx6Dz//+7C
         fuTR3aFQ9pVK1IfViWEQbkQcheqUCmZFMKoL9ySFbKCmSmyw5+RBBOJ9NZCttCz3XMeq
         kcoR2XmpOEkf6cRLTT/HEGE3DKze660V8swQFNO1bM4XZk0ZYwxmNcQjt7RyZcFIl12I
         vDuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Um1NE1FA;
       spf=pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [216.205.24.124])
        by gmr-mx.google.com with ESMTPS id o23si489692qka.0.2021.06.23.02.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 23 Jun 2021 02:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bristot@redhat.com designates 216.205.24.124 as permitted sender) client-ip=216.205.24.124;
Received: from mail-wm1-f69.google.com (mail-wm1-f69.google.com
 [209.85.128.69]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-257-b0oWJ34yOqydcSI08UiFnw-1; Wed, 23 Jun 2021 05:10:19 -0400
X-MC-Unique: b0oWJ34yOqydcSI08UiFnw-1
Received: by mail-wm1-f69.google.com with SMTP id k8-20020a05600c1c88b02901b7134fb829so125026wms.5
        for <kasan-dev@googlegroups.com>; Wed, 23 Jun 2021 02:10:19 -0700 (PDT)
X-Received: by 2002:adf:eace:: with SMTP id o14mr10541400wrn.159.1624439418412;
        Wed, 23 Jun 2021 02:10:18 -0700 (PDT)
X-Received: by 2002:adf:eace:: with SMTP id o14mr10541375wrn.159.1624439418205;
        Wed, 23 Jun 2021 02:10:18 -0700 (PDT)
Received: from x1.bristot.me (nat-cataldo.sssup.it. [193.205.81.5])
        by smtp.gmail.com with ESMTPSA id f19sm2222698wre.48.2021.06.23.02.10.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jun 2021 02:10:17 -0700 (PDT)
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 syzkaller <syzkaller@googlegroups.com>,
 kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
References: <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com>
 <YMyC/Dy7XoxTeIWb@elver.google.com>
 <35852e24-9b19-a442-694c-42eb4b5a4387@redhat.com>
 <YNBqTVFpvpXUbG4z@elver.google.com>
 <01a0161a-44d2-5a32-7b7a-fdb13debfe57@redhat.com>
 <YNG/8EcdPBfH/Taf@elver.google.com>
From: Daniel Bristot de Oliveira <bristot@redhat.com>
Message-ID: <93e7048a-209f-82f2-8d28-ff8347595695@redhat.com>
Date: Wed, 23 Jun 2021 11:10:17 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <YNG/8EcdPBfH/Taf@elver.google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bristot@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Um1NE1FA;
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

On 6/22/21 12:48 PM, Marco Elver wrote:
> On Mon, Jun 21, 2021 at 09:25PM +0200, Daniel Bristot de Oliveira wrote:
>> On 6/21/21 12:30 PM, Marco Elver wrote:
>>> On Mon, Jun 21, 2021 at 10:23AM +0200, Daniel Bristot de Oliveira wrote:
>>> [...]
>>>>> Yes, unlike code/structural coverage (which is what we have today via
>>>>> KCOV) functional coverage checks if some interesting states were reached
>>>>> (e.g. was buffer full/empty, did we observe transition a->b etc.).
>>>>
>>>> So you want to observe a given a->b transition, not that B was visited?
>>>
>>> An a->b transition would imply that a and b were visited.
>>
>> HA! let's try again with a less abstract example...
> 
> Terminology misunderstanding.
> 
> I mean "state transition". Writing "a->b transition" led me to infer 'a'
> and 'b' are states, but from below I infer that you meant an "event
> trace" (viz. event sequence).  So it seems I was wrong.
> 
> Let me be clearer: transition A -[a]-> B implies states A and B were
> visited.

right

Hence, knowing that event 'a' occurred is sufficient, and
> actually provides a little more information than just "A and B were
> visited".

iff [a] happens only from A to B...

> 
>>
>>   |   +------------ on --+----------------+
>>   v   ^                  +--------v       v
>> +========+               |        +===========+>--- suspend ---->+===========+
>> |  OFF   |               +- on --<|     ON    |                  | SUSPENDED |
>> +========+ <------ shutdown -----<+===========+<----- on -------<+===========+
>>     ^                                    v                             v
>>     +--------------- off ----------------+-----------------------------+
>>
>> Do you care about:
>>
>> 1) states [OFF|ON|SUSPENDED] being visited a # of times; or
>> 2) the occurrence of the [on|suspend|off] events a # of times; or
>> 3) the language generated by the "state machine"; like:
>>
>>    the occurrence of *"on -> suspend -> on -> off"*
>>
>>          which is != of
>>
>>    the occurrence of *"on -> on -> suspend -> off"*
>>
>>          although the same events and states occurred the same # of times
>> ?
> 
> They are all interesting, but unrealistic for a fuzzer to keep track of.
> We can't realistically keep track of all possible event traces. Nor that
> some state or event was visited # of times.

We can track this easily via RV, and doing that is already on my todo list. But
now I got that we do not need all these information for the functional coverage.

> What I did mean is as described above: the simple occurrence of an
> event, as it implies some previous and next state were visited.
> 
> The fuzzer then builds up knowledge of which inputs cause some events to
> occur. Because it knows it has inputs for such events, it will then try
> to further combine these inputs hoping to reach new coverage. This leads
> to various distinct event traces using the events it has already
> observed. All of this is somewhat random of course, because fuzzers are
> not meant to be model checkers.
> 
> If someone wants something more complex as you describe, it'd have to
> explicitly become part of the model (if possible?). The problem of
> coverage explosion applies, and we may not recommend such usage anyway.

I did not mean to make GCOV/the fuzzer to keep track of these information. I was
trying to understand what are the best way to provide the information that you
all need.

>> RV can give you all... but the way to inform this might be different.
>>
>>>> I still need to understand what you are aiming to verify, and what is the
>>>> approach that you would like to use to express the specifications of the systems...
>>>>
>>>> Can you give me a simple example?
>>>
>>> The older discussion started around a discussion how to get the fuzzer
>>> into more interesting states in complex concurrent algorithms. But
>>> otherwise I have no idea ... we were just brainstorming and got to the
>>> point where it looked like "functional coverage" would improve automated
>>> test generation in general. And then I found RV which pretty much can
>>> specify "functional coverage" and almost gets that information to KCOV
>>> "for free".
>>
>> I think we will end up having an almost for free solution, but worth the price.
>>
>>>> so, you want to have a different function for every transition so KCOV can
>>>> observe that?
>>>
>>> Not a different function, just distinct "basic blocks". KCOV uses
>>> compiler instrumentation, and a sequence of non-branching instructions
>>> denote one point of coverage; at the next branch (conditional or otherwise)
>>> it then records which branch was taken and therefore we know which code
>>> paths were covered.
>>
>> ah, got it. But can't KCOV be extended with another source of information?
>  
> Not without changing KCOV. And I think we're weary of something like
> that due to the potential for coverage explosion. -fsanitize-coverage
> has various options to capture different types of coverage actually, not
> purely basic block based coverage. (KCOV already supports
> KCOV_ENABLE_COMPARISONS, perhaps that could help somehow. It captures
> arguments of comparisons.)
> 
>>>>>
>>>>> From what I can tell this doesn't quite happen today, because
>>>>> automaton::function is a lookup table as an array.
>>>>
>>>> It is a the transition function of the formal automaton definition. Check this:
>>>>
>>>> https://bristot.me/wp-content/uploads/2020/01/JSA_preprint.pdf
>>>>
>>>> page 9.
>>>>
>>>> Could this just
>>>>> become a generated function with a switch statement? Because then I
>>>>> think we'd pretty much have all the ingredients we need.
>>>>
>>>> a switch statement that would.... call a different function for each transition?
>>>
>>> No, just a switch statement that returns the same thing as it does
>>> today. But KCOV wouldn't see different different coverage with the
>>> current version because it's all in one basic block because it looks up
>>> the next state given the current state out of the array. If it was a
>>> switch statement doing the same thing, the compiler will turn the thing
>>> into conditional branches and KCOV then knows which code path
>>> (effectively the transition) was covered.
>  
> Per Dmitry's comment, yes we need to be careful that the compiler
> doesn't collapse the switch statement somehow. But this should be
> achievable with a bunch or 'barrier()' after every 'case ...:'.

Changing the "function" will add some overhead for the runtime monitor use-case.
For example, for the safety-critical systems that will run with a monitor
enabled to detect a failure and react to it.

But! I can extend the idea of the reactor to receive the successful state
transitions or create the "observer" abstraction, to which we can attach a
generic that will make the switch statements. This function can be
auto-generated by dot2k as well...

This reactor/observer can be enabed/disabled so... we can add as much annotation
and barriers as we want.

Thoughts?

-- Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/93e7048a-209f-82f2-8d28-ff8347595695%40redhat.com.
