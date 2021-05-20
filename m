Return-Path: <kasan-dev+bncBCXI5NHXRMCRBPP7TKCQMGQEAUXXFQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C134738B7EC
	for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 21:59:57 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id x26-20020a2e9c9a0000b02900eaf62d380esf8049391lji.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 May 2021 12:59:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621540797; cv=pass;
        d=google.com; s=arc-20160816;
        b=RbYNYjnQg/3YbAkB7DBQWR6MOwDiDtsRIOZ24xqlzIFesm+jvO9ulg0izd3OUKkIoQ
         2xJ3u9z/eaWcM7QgZEGcn4FHPvqHS66JK68sId2DCiRucd/lH+eWGXaPwuXP+UUTt7i/
         TAwBZVarBZ/LNo1hZfYqkUuxpWw58+/UWOnGk54byBnPOpdpLvp1byaQorOc+antxsrh
         uWQmXwxtpHDS7aM+0SJciA2xZnqy9TxtbVz1JJs2ePcmW0Ghyd81UnOJVmwNLBspq4Gb
         i83EyU2VL2kKaRgg9C/Wg4Ysc+w74oGepLa2MtHBQrdGSKcbBJRYwbFwDXXXfBryGhIG
         l2uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:subject:from:references:cc
         :to:sender:dkim-signature;
        bh=ZbXks25NX/K0TrTAg07h5cHD8pO8Xmaxk92RCsneZFY=;
        b=qJzvNnNTOnT9VGiT9fRpvUrH0e3sftV/wQCn9lPLewaX+Uto5jdXw/kYM0Il3yM0/q
         0H71+8/9l7wym2HuBL+rz0TRQixbP2Jc1itUEnzkfpzjJEY7EVwbwbYLkSG5ZCe/2COS
         X2hkbmwW+9HW01ySX9D/dJf9Ay1i4bUXnrur6olpCrNwbWRI//y7eEG0amiI/aaqAJZU
         HObKkEoNCHY1BkFZv5c6lrOjFi9E9DTRRRKKBkzkAEx2vzFQfxmfJ5plWZUJB6Nc0kvS
         juZ50hIL5p8V2fllVWLUcsLsPsIY2fD/BRyRV4PBH+smX9VExOAdHkYdi0nnOuecOSHw
         CaMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@albtraum.org header.s=mail header.b=ULsKJtGD;
       dkim=pass header.i=@albtraum.org header.s=mail header.b=AxacfUiv;
       spf=pass (google.com: domain of mathias.payer@nebelwelt.net designates 94.130.183.3 as permitted sender) smtp.mailfrom=mathias.payer@nebelwelt.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:to:cc:references:from:subject:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ZbXks25NX/K0TrTAg07h5cHD8pO8Xmaxk92RCsneZFY=;
        b=RZVV77dCgo1HqlEWxsUrqgjHAluDo9oH1ifk6sdclxTxesZVkWm5BPbXZGds3IpsB+
         wA/wYuJ/oBcjBn4DNb/G6/OJgmagY+RPew5fLXXWHpS1FUelMmB1fl+BBmTxX2HYbcqd
         +8HP6osfDEMtVCH777ldnwd7+u9lhuXV1VrTP8WM80hN+356QkB0qE4d8EFb+XdNuu/I
         WXJmof0YLtRl6SF+zoVgU+hDWrURu+J95fiTJt0YvP60rd11USndII/FeUhM6Bv6NJyO
         6cwsvUKq2KW28nYkTNsBfq6d7G0lokVLvWgAG1cf4VWGMckDF0wFlAEDf9OplLdsiOIz
         Taeg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:to:cc:references:from:subject:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZbXks25NX/K0TrTAg07h5cHD8pO8Xmaxk92RCsneZFY=;
        b=J7N6w/qN1wtbgBmdBy19ear+5Cx+cocpmLdfp0f9baGw7y/MYcArYyEkGFXFZHlQJK
         L9yIiPcfbA1GnsPoziKLG/aePK8w9KHD2WwOY55uKdyCENAm8oOLHXlk6OV9bneN0KIW
         Ff7ZJc1epV938cufNOuupIZajNHl6hQbjL541kUqpe/oYjkcJoTNz3InQH9XTNCWfl08
         olPAg+ZGgKBHJNBcgsbHn8gLCrjLQ0gC594EPkWsw9OSDxgPfZjf0QpviP2/fJUmiaiY
         DXCWsziOb+scXl3DRJt8CdNx2RPwPuF2erGTfYaFgwu9InLEvR7ibzP2oK8qL0Pge1zH
         UWyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5312/aMSazwvw1a6CnsK4yGNuLNgI5Jwo4I2p+Kn6niCqFOWrlk7
	AQfrykzphFr9uZ7riNAwNSs=
X-Google-Smtp-Source: ABdhPJziHEKphEpsCoQnJiweQfPLxRCLBXLCfQLEnufhnlR8eXIUk4mlmhizkC8glyI5/+t8oW1cOQ==
X-Received: by 2002:a05:6512:ad2:: with SMTP id n18mr4433190lfu.608.1621540797216;
        Thu, 20 May 2021 12:59:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5592:: with SMTP id v18ls744159lfg.0.gmail; Thu, 20 May
 2021 12:59:56 -0700 (PDT)
X-Received: by 2002:a05:6512:3e26:: with SMTP id i38mr4311022lfv.283.1621540795977;
        Thu, 20 May 2021 12:59:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621540795; cv=none;
        d=google.com; s=arc-20160816;
        b=l35WsmN4FOtbMPNYBKgoY4zUFbVd/syn93FnIulA5USuQ9+JMdnHmZEHxB1BcEZW3z
         aT+J2eGtx5HNi+SZGH2FtHu6rzuRPMfgVQ4a9/R4+prxcHQhvafh3X9U8ahiBvYUvHWj
         +UTuBOPKF1yaNgFTgDB3wG5Qnv/PwoHzaF/JePhEd73yN1QZy+kaIRIZJtg8sFmdZvMS
         +NnMBYLF7DZt0PeryVGoMXJQWCAGtD5lPWxZCcGLzGAwh7urYPoxWrL9DS5/6t/W5Xjc
         Ivo0A8pAoGlwoRVhDj4qPkxmzq/hw1osw0Scc4t8796U+JLJHEzTMu+Aqv6FmtKUE8xn
         Hupg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:subject:from:references:cc:to
         :dkim-signature:dkim-signature;
        bh=ExtMZCKx20ijYR5oBstRuyvNEqabS2ctRi4sPz7S/g4=;
        b=QHZb8C9crCfT5ND10M1UOsbkLpGjN4aU2TieJ7lf3mwuN4cLbMT29sS6DNM0jZ/0xv
         1b8C+z2xCKzMkGTl/I/8gQljcUJqigo1LdL3htK6o4jXVsmJPmhS3WZuX1sUR+xOBhkN
         f1Qz9j2NlQlrXp9tmymeOhZLXuRNTxsfZwzIVhf+NEyIK9UJCnjMJ+hBSM4V7K5GISW+
         2FHV5m4umugHECm99RcRtP/gZlzIYkdVvwq0mwJrh3X9EY18PFhzrCSwX4PPnts3lh4k
         t3HUz0UZjRPB2FSSQIKIOzltimr9N9TP+/Qxdbh853IiWUA746aH08quphPobHym17ki
         JKmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@albtraum.org header.s=mail header.b=ULsKJtGD;
       dkim=pass header.i=@albtraum.org header.s=mail header.b=AxacfUiv;
       spf=pass (google.com: domain of mathias.payer@nebelwelt.net designates 94.130.183.3 as permitted sender) smtp.mailfrom=mathias.payer@nebelwelt.net
Received: from mail.albtraum.org (mail.albtraum.org. [94.130.183.3])
        by gmr-mx.google.com with ESMTP id c38si87106ljr.2.2021.05.20.12.59.55;
        Thu, 20 May 2021 12:59:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of mathias.payer@nebelwelt.net designates 94.130.183.3 as permitted sender) client-ip=94.130.183.3;
Received: by mail.albtraum.org (Postfix, from userid 113)
	id 3619425A8E; Thu, 20 May 2021 21:59:55 +0200 (CEST)
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on ghul
X-Spam-Level: 
X-Spam-Status: No, score=-2.9 required=5.0 tests=ALL_TRUSTED,BAYES_00,
	DKIM_SIGNED,DKIM_VALID,NICE_REPLY_A,URIBL_BLOCKED
	autolearn=unavailable autolearn_force=no version=3.4.2
Received: from [192.168.178.31] (unknown [81.221.194.231])
	by mail.albtraum.org (Postfix) with ESMTPSA id D4FD725A84;
	Thu, 20 May 2021 21:59:52 +0200 (CEST)
To: Dmitry Vyukov <dvyukov@google.com>,
 Vegard Nossum <vegard.nossum@oracle.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20210512181836.GA3445257@paulmck-ThinkPad-P17-Gen-1>
 <CACT4Y+Z+7qPaanHNQc4nZ-mCfbqm8B0uiG7OtsgdB34ER-vDYA@mail.gmail.com>
 <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <5650d220-9ca6-c456-ada3-f64a03007c26@oracle.com>
 <CACT4Y+Z9DuS6aKQdTb1mD6sVbnz_KPFeRK01zmutM1bmG9zSVQ@mail.gmail.com>
From: Mathias Payer <mathias.payer@nebelwelt.net>
Subject: Re: "Learning-based Controlled Concurrency Testing"
Message-ID: <e7654527-74fb-a5b5-885d-b9f8a26c1055@nebelwelt.net>
Date: Thu, 20 May 2021 21:59:52 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.0
MIME-Version: 1.0
In-Reply-To: <CACT4Y+Z9DuS6aKQdTb1mD6sVbnz_KPFeRK01zmutM1bmG9zSVQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: mathias.payer@nebelwelt.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@albtraum.org header.s=mail header.b=ULsKJtGD;       dkim=pass
 header.i=@albtraum.org header.s=mail header.b=AxacfUiv;       spf=pass
 (google.com: domain of mathias.payer@nebelwelt.net designates 94.130.183.3 as
 permitted sender) smtp.mailfrom=mathias.payer@nebelwelt.net
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



On 5/19/21 9:19 AM, Dmitry Vyukov wrote:
> On Mon, May 17, 2021 at 8:15 PM Vegard Nossum <vegard.nossum@oracle.com> wrote:
>> On 2021-05-17 18:44, Paul E. McKenney wrote:
>>> My hope is that some very clever notion of "state" would allow
>>> coverage-guided fuzzing techniques to be applied across the full kernel.
>>> Here are a few not-so-clever notions I have thought of, in the hope that
>>> they inspire some notion that is within the realm of sanity:
>>>
>>> 1.    The current coverage state plus the number of locks held by the
>>>        current CPU/task.  This is not so clever because the PC value
>>>        normally implies the number of locks.
>>>
>>>        It might be possible to do a little bit better by using the
>>>        lockdep hash instead of the number of locks, which could help
>>>        with code that is protected by a lock selected by the caller.
>>>
>>> 2.    #1 above, but the number of locks held globally, not just by
>>>        the current CPU/task.  This is not so clever because maintaining
>>>        the global number of locks held is quite expensive.
>>>
>>> 3.    #2 above, but approximate the number of locks held.  The
>>>        question is whether there is an approximation that is
>>>        both efficient and useful to fuzzing.
>>>
>>> 4.    Run lockdep and periodically stop all the CPUs to gather the
>>>        hashes of their current lock state plus PC.  The result is a set
>>>        of states, one for each pair of CPUs, consisting of the first
>>>        CPU's PC and both CPU's lockdep hash.  Combine this with the
>>>        usual PC-only state.
>>>
>>>        I could probably talk myself into believing that this one is
>>>        clever, but who knows?  One not-so-clever aspect is the size of
>>>        the state space, but perhaps bloom-filter techniques can help.
>>>
>>> 5.    KCSAN-like techniques, but where marking accesses forgives
>>>        nothing.  No splats, but instead hash the "conflicting" accesses,
>>>        preferably abstracting with type information, and add this hash
>>>        to the notion of state.  This might not be so clever given how
>>>        huge the state space would be, but again, perhaps bloom-filter
>>>        techniques can help.
>>>
>>> 6.    Your more-clever ideas here!
>>
>> Somewhat tangential in the context of the paper posted (and probably
>> less clever), and not based on state... but how about a new gcc plugin
>> that records which struct members are being accessed? You could for
>> example hash struct name + member name into a single number that can be
>> recorded AFL-style in a fixed-size bitmap or kcov-style...
>>
>> The fundamental idea is to just ignore everything about locking and
>> concurrent accesses -- if you have the data above you'll know which
>> independent test cases are likely to *try* accessing the same data (but
>> from different code paths), so if there's a race somewhere it might be
>> triggered more easily if they're run concurrently.
> 
> Hi Vegard,
> 
> Interesting idea.
> Also +Mathias who was interested in dependency analysis between syscalls.

Thanks for the include and hi everyone! I'm running the HexHive research 
lab at EPFL, we develop techniques to find bugs and also target the 
kernel. So far, we focused mostly on spatial/temporal memory safety and 
type safety.

As I'm late to the party, I may be missing some context. I assume the 
goal is to develop fuzzers that explore more complex kernel state and 
find unsynchronized concurrent access to the same state.


> A similar analysis can be done statically as well... I can't make up
> my mind which one would be better... both have pros and cons..
> However, again, I think we are missing some lower hanging fruit here.
> The current collide mode is super dumb and simple, I added it very
> early to trigger at least some races. It turned out to be efficient
> enough for now to never get back to it. The tracking issues for better
> collider with some ideas is:
> https://github.com/google/syzkaller/issues/612
> I think we need to implement it before we do anything more fancy. Just
> because we need an engine that could accept and act on the signal you
> describe. That engine is indepent of the actual signal we use to
> determine related syscalls, and it's useful on its own. And we have
> some easy to extract dependency information already in syscall
> descriptions in the form of /resources/. Namely, if we have 2 syscalls
> operating on, say, SCTP sockets, that's a pretty good signal that they
> are related and may operate on the same data.
> Once we have it, we could plug in more elaborate dynamic analysis info
> that will give a much higher quality signal regarding the relation of
> 2 exact syscall invocations in the exact program.

There were a couple of static analyses that applied to the whole kernel. 
K-Miner from NDSS'18 comes to mind:
http://lib.21h.io/library/XHEQU6AX/download/SLDEJFQG/2018_K-Miner_-_Uncovering_Memory_Corruption_in_Linux_Internet_Society.pdf

Now, such researchy approaches may be a bit too brittle (and imprecise) 
if we do it static only due to the potentially large amount of false 
positives. IMO we can profit from a combination of static and dynamic 
analyses: dynamic analysis to get an idea of how control flow connects 
different parts of the kernel (due to the massive amount of indirect 
control flow transfers which would make static analysis next to 
impossible) along with a marking technique such as the one proposed by 
Vegard. Then, based on "matches", follow up with a static analysis that 
tracks state along this observed control flow state to see if the target 
state is feasible. Not sure if this is already too complex though...

Best,
Mathias

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e7654527-74fb-a5b5-885d-b9f8a26c1055%40nebelwelt.net.
