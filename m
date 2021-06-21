Return-Path: <kasan-dev+bncBC3YFL76U4CRBSGPYODAMGQE6MAEARI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 160F13AF619
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 21:26:02 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id o11-20020a62f90b0000b02902db3045f898sf9809443pfh.23
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jun 2021 12:26:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624303560; cv=pass;
        d=google.com; s=arc-20160816;
        b=l24W5plLywFHXGPZ0B57BQjgQf5P9nITCwZgx1c5HCQoLfviiFzgw7w/TGTFA4WNVZ
         gemz8HX9s+qoJuMS8lv/i9fPqF52Rh+B+jVAJHbQCwbrwdBw41SYQJmYApJDEWuOQo60
         /5aSgJ4MtpI4JZkFVb+VHRIyU6NvchkKIUi0LjpnhRv/4x/7BH3LMTHv4/7vn1blvYj1
         WHE9DVHtnBNkhjA2LuRmXq/NRjf/AqX1iQcTLbTNYp3UWMq/z4dReUkFDYT+t4u+vGZ9
         PZ+BxQM4i6V0F1XeBJ8myl995OppFXFHaI9Fi3h3cH7PzfuBfUd/vSqpQsweauifGhV4
         nK7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=j622RP36rin+ftDT1pGActn3DVm9ihAdesX2UumhBDw=;
        b=MGBpwRaILQyPzjLZflAndV41d5nWeEC2NdJBeY8/ajh5IBMxhfALwAMIW7AOQP+QU7
         z+4Qvti9P9Po+VaeXToOXoeTKjSvQN+0dpyJrCn2TWQIf1HfbmJzgeah/JZ2bc9tLlUA
         cN5qEBa3o9NC1BIT/2WONbHrL0adKEolRUnqaDDHt9eoo6Afs9QUDtMaXK2s8xOxDFsr
         9nBpwPfBkX4IvuX9jgxKdY5PizC/hLoSlCIXPXSqMAg/5I2fkM6bdVLRxcYytjGrPd1J
         q4n1+v8F9GEJfpykjocfzdZt1y2DQARJRHfvdkCAzyFLd1OMZFKt+68nfaL34U3EA7Lv
         yJVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=aV3aXIO7;
       spf=pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j622RP36rin+ftDT1pGActn3DVm9ihAdesX2UumhBDw=;
        b=DRgjsyedwpnJE7LKfsJ4EKFb9rThABSfqijHH65Htf5GZMYshVCkKpgjY26pYDmOSx
         7ZnGsXILKBPmsAy+MpQp7PlfkK9805FDmWLFp/qy2Vb4K8VFnOasWRNbTLAGU8GuVCFw
         7ewIDDKrMr9ZiP7h91hBCFPg/kuqPJsAx2qUiFEFr0KwT54pHChu39RnJldUP6w8E6QD
         qCTc6MpbvygfzhwGzar8tjswIxnZHs8GC82Zx6E+TGMSPrV5/Xvv9Qlgc0AcQAZ0yErG
         ez2QrblNobMM5mKLzNPNwus8nR11L79kiiZXUZaroOkf16ufvvxKLeFvULOAfriM8gHt
         cTdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=j622RP36rin+ftDT1pGActn3DVm9ihAdesX2UumhBDw=;
        b=r0pK//mTRAlQbx3MeJqSMyZAAWHFnWsXEsARK3xQPWC9wey5Fe+QMun18eVErjb2dt
         nHZlHNRMOsteoX23a6tKQudfDULvQ8afdFQ3JAJsC8DX5gBiD7hIjheTkX9Qav+uq+oD
         Y8D24HiPtLGfqleVgErEGUfbQdB9pAVqr5hSvn/xanNaQWamAJVzsZKluU73FFWunlUS
         w1NcWOUiHgX+5ZvaP3eRzDvRovo8OCg5/EMLe+IGGBxbzD7orZbouay9mfQMGVBjH3sB
         8sXebmdZbLOuFYoRQXsw/4uiEviGFAyuRh42D276EywKHgPHBP4lyfWNCjY80CBFi0HT
         nYJg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533W6fSXmhkIYLf/iFONFAfbn9g/4eeZEgHmSwhsR+Q5x4kNtqhq
	kzMcZK1+9Kd1ZQuOs7hRqkA=
X-Google-Smtp-Source: ABdhPJxwQKDQX17nDWTGrbGTetLZG5/QTmW9V38VW56njgBEo9ahq5OB6gznl2BTsAnb2swKlNJ/Eg==
X-Received: by 2002:a63:338c:: with SMTP id z134mr85201pgz.167.1624303560450;
        Mon, 21 Jun 2021 12:26:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:228f:: with SMTP id b15ls5307635plh.8.gmail; Mon, 21
 Jun 2021 12:25:59 -0700 (PDT)
X-Received: by 2002:a17:902:d694:b029:103:ec01:12d5 with SMTP id v20-20020a170902d694b0290103ec0112d5mr19375587ply.19.1624303559812;
        Mon, 21 Jun 2021 12:25:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624303559; cv=none;
        d=google.com; s=arc-20160816;
        b=CDeUELTpiz+xUtEn9jiEF8HP7uugx8tcyxPKCIFD7+93FqebjaylDafba1PyNpAQkQ
         5aoq9j4Tnhap3xILW5ryV+8t1QGV0pjczTOeNNp1bBR+CjF9ZwX6je7v8Uhfo4FRfDcJ
         ZsAanRcJhQQwPhh81c4+E6OfrQ/AQ5uNbYYZes3nuIonLiSqZ9KE9W0HsMKHB3Cl0ekX
         Q2icTgftp/t1oNDEXAO7YjNLm3x5lm9VKadgezZZEfCdv7DVExn9VsLhs5x3wFJFAH74
         MQehLQnLOj1qhi5HHvcuEm2L5Vu9FNla2fwbHG+GXfA98fRUtzEe37Zmp4W3MimBtevh
         O6DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=Il1Ony6YcK5r8ns4t32hJT8Wa7X//GQ16ngzusYt4pM=;
        b=Qu0GuKE8Sva4XUE3l8nZlrR7E/ttjO8fbLFllT4D+Ow2DfFLV6IE4cJeHAwnI4H4GD
         7KJbxNslpycb/oqim/DVtds851iHQDDtpUPz7bNjuhu97cvOxqyx4DKryNnfJlpHbfVQ
         iGIpk/QFet/HXBMF8L6xKLjFURBPLfsjiIjJWGInxQTvOYRolfaY864dQnWKoUTeu33M
         eybI3EcqVanfnqNeZU9Qbm+VcF8+3piwzCT+OgPw961WlHLQxqSgoGFNBWCZ2VfYivGh
         VA/3mHH8KmLpiEZFZUzYFS5KUct2LP643YYlFy+gnOVyRxhDOW9fxraPnyjxCMWQ7C+M
         6y7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=aV3aXIO7;
       spf=pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bristot@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id nl18si42587pjb.0.2021.06.21.12.25.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Jun 2021 12:25:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of bristot@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-ed1-f71.google.com (mail-ed1-f71.google.com
 [209.85.208.71]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-298-2hB6GIKNNIKa1AZOAu2iVA-1; Mon, 21 Jun 2021 15:25:51 -0400
X-MC-Unique: 2hB6GIKNNIKa1AZOAu2iVA-1
Received: by mail-ed1-f71.google.com with SMTP id x12-20020a05640226ccb0290393aaa6e811so8265609edd.19
        for <kasan-dev@googlegroups.com>; Mon, 21 Jun 2021 12:25:51 -0700 (PDT)
X-Received: by 2002:a05:6402:17d3:: with SMTP id s19mr22794032edy.222.1624303550519;
        Mon, 21 Jun 2021 12:25:50 -0700 (PDT)
X-Received: by 2002:a05:6402:17d3:: with SMTP id s19mr22794017edy.222.1624303550320;
        Mon, 21 Jun 2021 12:25:50 -0700 (PDT)
Received: from x1.bristot.me (host-79-23-205-114.retail.telecomitalia.it. [79.23.205.114])
        by smtp.gmail.com with ESMTPSA id u4sm5494718edy.60.2021.06.21.12.25.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jun 2021 12:25:49 -0700 (PDT)
Subject: Re: Functional Coverage via RV? (was: "Learning-based Controlled
 Concurrency Testing")
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, syzkaller <syzkaller@googlegroups.com>,
 kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
References: <20210517164411.GH4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNPbXmm9jQcquyrNGv4M4+KW_DgcrXHsgDtH=tYQ6=RU4Q@mail.gmail.com>
 <20210518204226.GR4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNN+nS1CAz=0vVdJLAr_N+zZxqp3nm5cxCCiP-SAx3uSyA@mail.gmail.com>
 <20210519185305.GC4441@paulmck-ThinkPad-P17-Gen-1>
 <CANpmjNMskihABCyNo=cK5c0vbNBP=fcUO5-ZqBJCiO4XGM47DA@mail.gmail.com>
 <CANpmjNMPvAucMQoZeLQAP_WiwiLT6XBoss=EZ4xAbrHnMwdt5g@mail.gmail.com>
 <c179dc74-662d-567f-0285-fcfce6adf0a5@redhat.com>
 <YMyC/Dy7XoxTeIWb@elver.google.com>
 <35852e24-9b19-a442-694c-42eb4b5a4387@redhat.com>
 <YNBqTVFpvpXUbG4z@elver.google.com>
From: Daniel Bristot de Oliveira <bristot@redhat.com>
Message-ID: <01a0161a-44d2-5a32-7b7a-fdb13debfe57@redhat.com>
Date: Mon, 21 Jun 2021 21:25:49 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.11.0
MIME-Version: 1.0
In-Reply-To: <YNBqTVFpvpXUbG4z@elver.google.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bristot@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=aV3aXIO7;
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

On 6/21/21 12:30 PM, Marco Elver wrote:
> On Mon, Jun 21, 2021 at 10:23AM +0200, Daniel Bristot de Oliveira wrote:
> [...]
>>> Yes, unlike code/structural coverage (which is what we have today via
>>> KCOV) functional coverage checks if some interesting states were reached
>>> (e.g. was buffer full/empty, did we observe transition a->b etc.).
>>
>> So you want to observe a given a->b transition, not that B was visited?
> 
> An a->b transition would imply that a and b were visited.

HA! let's try again with a less abstract example...


  |   +------------ on --+----------------+
  v   ^                  +--------v       v
+========+               |        +===========+>--- suspend ---->+===========+
|  OFF   |               +- on --<|     ON    |                  | SUSPENDED |
+========+ <------ shutdown -----<+===========+<----- on -------<+===========+
    ^                                    v                             v
    +--------------- off ----------------+-----------------------------+

Do you care about:

1) states [OFF|ON|SUSPENDED] being visited a # of times; or
2) the occurrence of the [on|suspend|off] events a # of times; or
3) the language generated by the "state machine"; like:

   the occurrence of *"on -> suspend -> on -> off"*

         which is != of

   the occurrence of *"on -> on -> suspend -> off"*

         although the same events and states occurred the same # of times
?

RV can give you all... but the way to inform this might be different.

>> I still need to understand what you are aiming to verify, and what is the
>> approach that you would like to use to express the specifications of the systems...
>>
>> Can you give me a simple example?
> 
> The older discussion started around a discussion how to get the fuzzer
> into more interesting states in complex concurrent algorithms. But
> otherwise I have no idea ... we were just brainstorming and got to the
> point where it looked like "functional coverage" would improve automated
> test generation in general. And then I found RV which pretty much can
> specify "functional coverage" and almost gets that information to KCOV
> "for free".

I think we will end up having an almost for free solution, but worth the price.

>> so, you want to have a different function for every transition so KCOV can
>> observe that?
> 
> Not a different function, just distinct "basic blocks". KCOV uses
> compiler instrumentation, and a sequence of non-branching instructions
> denote one point of coverage; at the next branch (conditional or otherwise)
> it then records which branch was taken and therefore we know which code
> paths were covered.

ah, got it. But can't KCOV be extended with another source of information?

>>>
>>> From what I can tell this doesn't quite happen today, because
>>> automaton::function is a lookup table as an array.
>>
>> It is a the transition function of the formal automaton definition. Check this:
>>
>> https://bristot.me/wp-content/uploads/2020/01/JSA_preprint.pdf
>>
>> page 9.
>>
>> Could this just
>>> become a generated function with a switch statement? Because then I
>>> think we'd pretty much have all the ingredients we need.
>>
>> a switch statement that would.... call a different function for each transition?
> 
> No, just a switch statement that returns the same thing as it does
> today. But KCOV wouldn't see different different coverage with the
> current version because it's all in one basic block because it looks up
> the next state given the current state out of the array. If it was a
> switch statement doing the same thing, the compiler will turn the thing
> into conditional branches and KCOV then knows which code path
> (effectively the transition) was covered.

[ the answer for this points will depend on your answer from my first question
on this email so... I will reply it later ].

-- Daniel

>>> Then:
>>>
>>> 1. Create RV models for states of interests not covered by normal code
>>>    coverage of code under test.
>>>
>>> 2. Enable KCOV for everything.
>>>
>>> 3. KCOV's coverage of the RV model will tell us if we reached the
>>>    desired "functional coverage" (and can be used by e.g. syzbot to
>>>    generate better tests without any additional changes because it
>>>    already talks to KCOV).
>>>
>>> Thoughts?
>>>
>>> Thanks,
>>> -- Marco
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01a0161a-44d2-5a32-7b7a-fdb13debfe57%40redhat.com.
