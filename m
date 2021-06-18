Return-Path: <kasan-dev+bncBC3YFL76U4CRBSFEWGDAMGQEKVWOZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 694E63AC58C
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 09:59:05 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id h24-20020ac856980000b0290243c83a3ddcsf2513970qta.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 00:59:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624003144; cv=pass;
        d=google.com; s=arc-20160816;
        b=W1fj2b2zi8EDIcn9aI4UONGOtoF2rIIWGMKwO6MXGSFTt3v3rFx5ilYTlgY7vfgR9P
         hhwaToSKXu5bTxdTq3bobVnajtpuJQY1CnajXiUwokVeFB0aXHlYgj3+EQoPR9QvVDiY
         AJI4Y1jYZRiiLTrx3v33JS3MjL1ZqdcQQcALrMOzSIy5OhdCWOLxkq8WBnsuUnjjmC9n
         TtucuxWjYrAdxeam+GII0ePZOB9YS+po4oSHwIskb0bBeEhWmDvEWIChoI4Mx+AXxXyx
         e7uEnuHKEozjdtFK3qHu0vq2+Bb9EE68m6BS4yVvd3t1KRNxLD2GJCht1t/ZR5gMx/45
         g7nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=rkeORPZPlnDQcCJJMcKg+9YXm5W7LOiBJxYWX0kDIHo=;
        b=sPHOcQ8+encYv44yv/zBwimAt7Rcr5yTRe3+F9FZDKXQm3e5TsfG6do4KV4z+OekCb
         bXXQPDGMbniOCjQzA2A66PJ3rm4obElK9zJ8/RaiQFyZ5ovnyvxEVn7ylYAkspRrNO/8
         1iV8vFq411ft4sroqYFoWBcGkikKGGNmWnaHTxDjYXzXnLDehyaIasohXsNKAGCaFpId
         UqiqUfu8DTq5ddmkF4fh/eThNXZwcpfiQRTDBwlVchKB2QAi+oL667osJOaWZXv3Awi2
         Yc+7z65tPeKt1sVcNjR+l6gtcR/fwT9DjCw7YUSeHn2sutUlvtGNMR5rdaN/cyNJw3Ew
         VwZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HiwVAQbf;
       spf=pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rkeORPZPlnDQcCJJMcKg+9YXm5W7LOiBJxYWX0kDIHo=;
        b=Ie2SHUp9uCeYRG1hjRb5VdWGBdWQNnVJNOzCdEKWyR+KuVeOvsJWMm5S8uwrsxjRbA
         IEm9OKKKb8ExEc314jsHe2XCsCaygoJX8Eedv0QoqXuLfXMyuufAmeYdoBisN4NabT2i
         vD1lrkPGBQDiB3itxDj236SSoQwIgsHjGnS93Pe+mCcdeI0QlWnSYP2m8Z+t9LAlaByK
         KaxNPpth9gtm6cMfCp0/fV+VCuxQKIW6Xc7nq1wvHg+lCLflfSIifn28XiNE04IyNGJD
         ykXYVqIFDmIH/ZlA/b0i0+0kO7dFE6j+lRlpwJ36EYpD/Mt+H3nBjA+g4lEs8WH+7O2W
         ywPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rkeORPZPlnDQcCJJMcKg+9YXm5W7LOiBJxYWX0kDIHo=;
        b=PNmenLVvM5VslFvr5iYJ0XHofv8iImGSGBxAlUT+e/zFY4tE1gczU4zcpAXGLxTg/M
         6wlmqq+hO4V+lsJLIqPntCxa2m5oc3F/GyH4sBjkx50bnIUfXb5TOLNczgsNjzERxlDd
         kFiI1W+xKgEoRAJYHn/O7h3g0vQXHhP9YKASCbbvo8sLy2vKukM0lqrQlSyWKYkhLCmt
         LgVUToJc2+My9rO8clvFJd/+oGdkICtOE/JkwvPHooCcRZrBXMLNRtME1d6TcU5H/sHe
         BDUHPPtPdzeEOPJj39MbeI7nI+C9/e/tatXV1OMrXVLN8E7g0PNyNTjL4iD+eBvDDIss
         Qo2g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531o7Css6Ra/zOuyVq2IKE6eew1Lj3uF/n1pzNKYFljaXErIFgS3
	y/zztNOtc0wzsNSJb9UCVRQ=
X-Google-Smtp-Source: ABdhPJyPTA9Fx0CAQ1A3YIk+Z86WKaAij5Lr1EWzz9CdS6mjCPexJY0nBSdYx+LlxfgTTyQlBRdZ0A==
X-Received: by 2002:a37:a1cf:: with SMTP id k198mr7408873qke.409.1624003144291;
        Fri, 18 Jun 2021 00:59:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1271:: with SMTP id r17ls957802qvv.4.gmail; Fri, 18
 Jun 2021 00:59:03 -0700 (PDT)
X-Received: by 2002:ad4:51cf:: with SMTP id p15mr4359649qvq.5.1624003143810;
        Fri, 18 Jun 2021 00:59:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624003143; cv=none;
        d=google.com; s=arc-20160816;
        b=coIphajNb2jHOARfZk0oPk4Qi/fFzDcOY5a5pUjCaVULE7e860L9qppLBYPHDL0IN9
         y4MpMUl/yrnR9eUz7yBwjo74G2rwGj0jUYOLKJ2FcyqxHY0i+7tdHrRU5ByCBmMDsv/t
         62dddmRl1Z5+vtlhXOPLMuVFtasXrGPCgG0wXypJpOq8cU2CsBYGfkT5WuaH6VzVn+si
         uvjeTBotdK1n4r1AqufMTqwBo6B/aIvglIT90NLT2itZHpjaDYT3wdqDFdt5UWMlW7Ux
         pUfW71bCmnVpjYadEntuKznvsIn19+kXbFGHlADHt3mAsUd+b1fWdCGSBbVX6cT8x4YQ
         wR5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=QB7KMugTullHRvmV8LmfWYhXRlkrxyob1yW5wSk8lIc=;
        b=aVrC3uMm3NxoSRwGBIdOQCZhkWAag3+JZAMMeDJCDHG5QbhGKptLPUbQWXUWD0bTUj
         kcD+HGfjTtmVInLINwQCZ2bKZXfEp38Ez+2p4XomuF8Nes8HnyCcPqVzNiyTHGoxjtwd
         aYjf2nQZ2pRp5nGVStn/x41u2Loy/irbr7Wrh8mGL+oQ+pqRmTGfLREA1HXOWm2BS0hY
         nLjBsuv4jm30d1U1NMjauYrYfVQKbly9lZjt07Xa4uL7/JbE52A1TV1XXqIOobpZkqKl
         xNCcVARf827RIuEVp8uFgNNjcH2rUWcf/sLQo4/cCyggFXcjjPiv/IhQQBR32qiUDqAU
         Yc6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=HiwVAQbf;
       spf=pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id j16si549592qko.3.2021.06.18.00.59.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Jun 2021 00:59:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-ed1-f72.google.com (mail-ed1-f72.google.com
 [209.85.208.72]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-230-4Cs6-Z92O2yquTPyOxDVQQ-1; Fri, 18 Jun 2021 03:59:01 -0400
X-MC-Unique: 4Cs6-Z92O2yquTPyOxDVQQ-1
Received: by mail-ed1-f72.google.com with SMTP id q7-20020aa7cc070000b029038f59dab1c5so3090288edt.23
        for <kasan-dev@googlegroups.com>; Fri, 18 Jun 2021 00:59:01 -0700 (PDT)
X-Received: by 2002:a05:6402:1907:: with SMTP id e7mr2816194edz.186.1624003140221;
        Fri, 18 Jun 2021 00:59:00 -0700 (PDT)
X-Received: by 2002:a05:6402:1907:: with SMTP id e7mr2816173edz.186.1624003139926;
        Fri, 18 Jun 2021 00:58:59 -0700 (PDT)
Received: from x1.bristot.me (host-79-23-205-114.retail.telecomitalia.it. [79.23.205.114])
        by smtp.gmail.com with ESMTPSA id c19sm5756050edw.10.2021.06.18.00.58.59
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jun 2021 00:58:59 -0700 (PDT)
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Marco Elver <elver@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, syzkaller
 <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
From: Daniel Bristot de Oliveira <bristot@redhat.com>
Message-ID: <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com>
Date: Fri, 18 Jun 2021 09:58:58 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bristot@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=HiwVAQbf;
       spf=pass (google.com: domain of bristot@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
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

On 6/17/21 1:20 PM, Marco Elver wrote:
> [+Daniel, just FYI. We had a discussion about "functional coverage"
> and fuzzing, and I've just seen your wonderful work on RV. If you have
> thought about fuzzing with RV and how coverage of the model impacts
> test generation, I'd be curious to hear.]

One aspect of RV is that we verify the actual execution of the system instead of
a complete model of the system, so we depend of the testing to cover all the
aspects of the system <-> model.

There is a natural relation with testing/fuzzing & friends with RV.

> Looks like there is ongoing work on specifying models and running them
> along with the kernel: https://lwn.net/Articles/857862/
> 
> Those models that are run alongside the kernel would have their own
> coverage, and since there's a mapping between real code and model, a
> fuzzer trying to reach new code in one or the other will ultimately
> improve coverage for both.

Perfect!

> Just wanted to document this here, because it seems quite relevant.
> I'm guessing that "functional coverage" would indeed be a side-effect
> of a good RV model?

So, let me see if I understood the terms. Functional coverage is a way to check
if all the desired aspects of a code/system/subsystem/functionality were covered
by a set of tests?

If that is correct, we could use RV to:

 - create an explicit model of the states we want to cover.
 - check if all the desired states were visited during testing.

?

-- Daniel

> Previous discussion below.
> 
> Thanks,
> -- Marco
> 
> On Wed, 19 May 2021 at 22:24, Marco Elver <elver@google.com> wrote:
>> On Wed, 19 May 2021 at 20:53, Paul E. McKenney <paulmck@kernel.org> wrote:
>>> On Wed, May 19, 2021 at 11:02:43AM +0200, Marco Elver wrote:
>>>> On Tue, 18 May 2021 at 22:42, Paul E. McKenney <paulmck@kernel.org> wrote:
>>>> [...]
>>>>>> All the above sound like "functional coverage" to me, and could be
>>>>>> implemented on top of a well-thought-out functional coverage API.
>>>>>> Functional coverage is common in the hardware verification space to
>>>>>> drive simulation and model checking; for example, functional coverage
>>>>>> could be "buffer is full" vs just structural (code) coverage which
>>>>>> cannot capture complex state properties like that easily.
>>>>>>
>>>>>> Similarly, you could then say things like "number of held locks" or
>>>>>> even alluding to your example (5) above, "observed race on address
>>>>>> range". In the end, with decent functional coverage abstractions,
>>>>>> anything should hopefully be possible.
>>>>>
>>>>> Those were in fact the lines along which I was thinking.
>>>>>
>>>>>> I've been wondering if this could be something useful for the Linux
>>>>>> kernel, but my guess has always been that it'd not be too-well
>>>>>> received because people don't like to see strange annotations in their
>>>>>> code. But maybe I'm wrong.
>>>>>
>>>>> I agree that it is much easier to get people to use a tool that does not
>>>>> require annotations.  In fact, it is best if it requires nothing at all
>>>>> from them...
>>>>
>>>> While I'd like to see something like that, because it'd be beneficial
>>>> to see properties of the code written down to document its behaviour
>>>> better and at the same time machine checkable, like you say, if it
>>>> requires additional effort, it's a difficult sell. (Although the same
>>>> is true for all other efforts to improve reliability that require a
>>>> departure from the "way it used to be done", be it data_race(), or
>>>> even efforts introducing whole new programming languages to the
>>>> kernel.)
>>>
>>> Fair point!  But what exactly did you have in mind?
>>
>> Good question, I'll try to be more concrete -- most of it are
>> half-baked ideas and questions ;-), but if any of it makes sense, I
>> should maybe write a doc to summarize.
>>
>> What I had in mind is a system to write properties for both functional
>> coverage, but also checking more general properties of the kernel. The
>> latter I'm not sure about how useful. But all this isn't really used
>> for anything other than in debug builds.
>>
>> Assume we start with macros such as "ASSERT_COVER(...)" (for
>> functional coverage) and "ASSERT(...)" (just plain-old assertions).
>> The former is a way to document potentially interesting states (useful
>> for fuzzers to reach them), and the latter just a way to just specify
>> properties of the system (useful for finding the actual bugs).
>> Implementation-wise the latter is trivial, the former requires some
>> thought on how to expose that information to fuzzers and how to use
>> (as Dmitry suggested it's not trivial). I'd also imagine we can have
>> module-level variants ("GLOBAL_ASSERT*(...)") that monitor some global
>> state, and also add support for some subset of temporal properties
>> like "GLOBAL_ASSERT_EVENTUALLY(precond, eventually_holds)" as
>> suggested below.
>>
>> I guess maybe I'd have to take a step back and just ask why we have no
>> way to write plain and simple assertions that are removed in non-debug
>> builds? Some subsystems seem to roll their own, which a 'git grep
>> "#define ASSERT"' tells me.
>>
>> Is there a fundamental reason why we shouldn't have them, perhaps
>> there was some past discussion? Today we have things like
>> lockdep_assert_held(), but nothing to even write a simple assert
>> otherwise. If I had to guess why something like ASSERT is bad, it is
>> because it gives people a way to check for unexpected conditions, but
>> if those checks disappear in non-debug builds, the kernel might be
>> unstable. Therefore every possible state must be handled and we must
>> always be able to recover. The argument in favor is, if the ASSERT()s
>> are proven invariants or conditions where we'd recover either way, and
>> are only there to catch accidental regressions during testing; and in
>> non-debug builds we don't suffer the performance overheads.
> ..
>>>>>> My ideal abstractions I've been thinking of isn't just for coverage,
>>>>>> but to also capture temporal properties (which should be inspired by
>>>>>> something like LTL or such), on top of which you can also build
>>>>>> coverage. Then we can specify things like "if I observe some state X,
>>>>>> then eventually we observe state Y", and such logic can also just be
>>>>>> used to define functional coverage of interest (again all this
>>>>>> inspired by what's already done in hardware verification).
>>>>>
>>>>> Promela/spin provides an LTL interface, but of course cannot handle
>>>>> much of RCU, let alone of the entire kernel.  And LTL can be quite
>>>>> useful.  But in a runtime system, how do you decide when "eventually"
>>>>> has arrived?  The lockdep system does so by tracking entry to idle
>>>>> and to userspace execution, along with exit from interrupt handlers.
>>>>> Or did you have something else in mind?
>>>>
>>>> For coverage, one could simply await the transition to the "eventually
>>>> state" indefinitely; once reached we have coverage.
>>>>
>>>> But for verification, because unlike explicit state model checkers
>>>> like Spin, we don't have the complete state and can't build an
>>>> exhaustive state-graph, we'd have to approximate. And without knowing
>>>> exactly what it is we're waiting for, the simplest option would be to
>>>> just rely on a timeout, either part of the property or implicit. What
>>>> the units of that timeout are I'm not sure, because a system might
>>>> e.g. be put to sleep.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c179dc74-662d-567f-0285-fcfce6adf0a5%40redhat.com.
