Return-Path: <kasan-dev+bncBDAOBFVI5MIBBW7NWOGAMGQEEM7FYQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id CB93244D563
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 11:56:27 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id x17-20020a0565123f9100b003ff593b7c65sf2550239lfa.12
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 02:56:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636628187; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kr4u+nzk6pemx+/H2LnA+Y7S/8Lkbk7z05hxxtURtXA6kTSR8zkPIHylRN8ojGBzLv
         LKOk473cGyg/tKdQEAu2/Qc7/7vjplvprRRU1YKre5BziYFfQVzl/a4RTG5IoyN306X/
         PxJKy2iHTcOKvqNrtpr6wBdT5t8OHKTI44tTTjEKJfXlbJDLptqRgY/PcQJ9Dr5Xrku1
         WCuwhNxu80toP3QymODIBgHxV527/9s3ALJkHeYaF4VNIfZLotizPJaNXA3Tin+x5jml
         oXkPv+eGvsDvif+nuaRASwOBmq16MBMgG7GzuDfKuqDcuWtxn58e7d4GOPkL5GBymWJl
         9Lug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=V2eVe1QzdcDVME3uBYOz6mBYALE5xF3cv8j2lHwPoHM=;
        b=kvIX2MEiSREypWUhRTX60IjXD7w3pL91Wg2VkAK3KpE85djmXDMLUXNlGzER4yYV4c
         T8B0GP0uawHY4aFzL1SvraJU7lMn/aDKh3liEX7IMvaFsTmaeN6yieBGARHTCGmJ0kSf
         4fJpLbtvUYralY2qRb8YRsIgrhcKaz8jwYKT1oJlHtRQndChG9IlKAkQPwf7yOlyQHPx
         SdEIDCDIae07CjdkHR+gqAohMPVolRQsZ8tUi4EQFXRcJHl6H488ufS7CmdXoCu1YXAr
         qZMz6GvtNweO5uNTIJfjyjvzJ9cTaK1fUtxmZV2TGff8/jXlRU+tsepPJifdyOlwNVmx
         NNqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V2eVe1QzdcDVME3uBYOz6mBYALE5xF3cv8j2lHwPoHM=;
        b=I+P8m6Sqo7AsPehNOuxX7JK8m2WGBJDkyzcCce+rT1Y71heyjvF+ahsaUqEtZ8OHDJ
         G9tYsfPFFblSoHtpBBaHIDqJRrfDibPDMYZsjQsHG7SsULsTOuqe3S9gqzst1L/ZVoui
         pOyUOQroR36RCYnXar67UJnphNFTwdstTyvEquwNKpl3MARJwky8Q4+kLomvqUyQHauV
         kweYUJ6Koz/8k3haHvGBBJKXK04h+gJSPBn4arvm7wC6FSPiKtZ9Qk0VIIsiCASpK2Ce
         WJuDZ6ddrAYM6Tk1TLRm9Pnw00AwlJ4rMhXKC0KmpMk6wiwkPXXLDB4sUJFiwPc+v/AY
         Uosg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V2eVe1QzdcDVME3uBYOz6mBYALE5xF3cv8j2lHwPoHM=;
        b=W8L8g67AWzGnWDZSxTyEEzUM6ECF1iCwyyHZNhGne9ms817KM2HLeBHORe9hCwvFoy
         KVKnEqpMnrLcA/uK7jca5Y9n/RJj0l8v7WGpUlWMIgvwr/iYDJbf0ro/TTOH484QdGvP
         eZNRAcQAZmzz6hukWkOWRr49FmWm40eii2v/qp5LDh6xw+tuf5bibaSPI3kf1nOjZ1bA
         TrV+aPUN/7xMT03jZtGqnat3C9XC0C0NJdoLY0S0Hl597AkStevo7XND/HPvPAY2+ZKW
         Df0VZ/STx5+G45p9ULdnXKj7WXw0xLjYWg7t7/7vjb2+2fbb8YMIUJPn3QX2xFr1qkVe
         Up5A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ActU6QUnDwzWy7fs876VpRDJj0GHDuoHKLqD4QtIr+vsc2fFn
	y2fXXKj0neMs4CNDhqPY0QU=
X-Google-Smtp-Source: ABdhPJwrB7GGvfnv4Quj2IQn4MsFXBtuSrIBjtWm4lHsmhDEOYTzxWbryABFEA+v7VsELKWD5G7+bw==
X-Received: by 2002:a05:6512:92d:: with SMTP id f13mr5483691lft.63.1636628187335;
        Thu, 11 Nov 2021 02:56:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2610:: with SMTP id bt16ls292337lfb.2.gmail; Thu,
 11 Nov 2021 02:56:26 -0800 (PST)
X-Received: by 2002:a05:6512:108a:: with SMTP id j10mr5646016lfg.557.1636628186361;
        Thu, 11 Nov 2021 02:56:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636628186; cv=none;
        d=google.com; s=arc-20160816;
        b=v2Q91QgFe7EiKXdPVY9TkxSUxXrO4iVqZGjcrgOYFyd6PiL0yQqsTWhdSFQ0NjONnT
         LyxXpLWi8RasiCa8akbtcqgQX2rav4tbZMaQv+EW1HkJ2VB5Dzs7dd+wZswiJoGXzXIW
         69RXu3jkmhol0hF6LOBC1yUW1z9nMiTdKSSz9T+pLRPfYws/HiuRj1f5bzNnkV74ugKi
         /2ZMfJjHMJDahgNiUqPV9/RqAeU1r3YGCdbifAaLlolTyFduMQDGur00mUn9gOrjjK/r
         gKQsQIhQVvTQH3h+8mffwVE7Db3d+Df68K8Qh8q0vOGae3m6ZNIoPMOnbhnw8tP4sxbv
         Mofg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from;
        bh=NKU8MpxypkzTs67X3CizYrIQ7AsTXYqc/tNXCE6pYHs=;
        b=lfH6c1Hbnq+aCF+5KquVFFKZQiwGSkKmDAYKsU0gwrbgXW/EroK2x09+eOvxHwn8EP
         jNo4I7Fm0ue4F1H6Q3oIEpjc+w/UVikJ8wpyaufmC02G8e8PlWFMGARYyN3pz4Y9FaSu
         4j9zDJCeDHUewBTIijmMo0v4XVd5ti0KcDxbfY3qP6bAEB8rbnLezjzul3XpgWafTDUo
         ggc45auvCak1u/aKYw+LjiMdRFR0kQkpOwyGEVrFO9IZ0KhK1cL1dYVdvWGqiNHzqJGU
         Shs7QIVEKsHbzqIKA7o8/vRzm+OvDi16ZLj+tgxRgQwutmfeo2Oh0eUobZK0QNuP1C31
         VBPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id i16si219695lfv.2.2021.11.11.02.56.26
        for <kasan-dev@googlegroups.com>;
        Thu, 11 Nov 2021 02:56:26 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2B718101E;
	Thu, 11 Nov 2021 02:56:25 -0800 (PST)
Received: from e113632-lin (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 1099C3F70D;
	Thu, 11 Nov 2021 02:56:22 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: Mike Galbraith <efault@gmx.de>, Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, Frederic Weisbecker <frederic@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>, Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, Nick Desaulniers <ndesaulniers@google.com>
Subject: Re: [PATCH v2 2/5] preempt/dynamic: Introduce preempt mode accessors
In-Reply-To: <26fd47db11763a9c79662a66eed2dbdbcbedaa8a.camel@gmx.de>
References: <20211110202448.4054153-1-valentin.schneider@arm.com> <20211110202448.4054153-3-valentin.schneider@arm.com> <a7c704c2ae77e430d7f0657c5db664f877263830.camel@gmx.de> <803a905890530ea1b86db6ac45bd1fd940cf0ac3.camel@gmx.de> <a7febd8825a2ab99bd1999664c6d4aa618b49442.camel@gmx.de> <CANpmjNPeRwupeg=S8yGGUracoehSUbS-Fkfb8juv5mYN36uiqg@mail.gmail.com> <26fd47db11763a9c79662a66eed2dbdbcbedaa8a.camel@gmx.de>
Date: Thu, 11 Nov 2021 10:56:20 +0000
Message-ID: <8735o3rmej.mognet@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
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

On 11/11/21 11:32, Mike Galbraith wrote:
> On Thu, 2021-11-11 at 10:36 +0100, Marco Elver wrote:
>> I guess the question is if is_preempt_full() should be true also if
>> is_preempt_rt() is true?
>
> That's what CONFIG_PREEMPTION is.  More could follow, but it was added
> to allow multiple models to say "preemptible".
>

That's what I was gonna say, but you can have CONFIG_PREEMPTION while being
is_preempt_none() due to PREEMPT_DYNAMIC...

>> Not sure all cases are happy with that, e.g. the kernel/trace/trace.c
>> case, which wants to print the precise preemption level.
>
> Yeah, that's the "annoying" bit, needing one oddball model accessor
> that isn't about a particular model.
>
>> To avoid confusion, I'd introduce another helper that says true if the
>> preemption level is "at least full", currently that'd be "full or rt".
>> Something like is_preempt_full_or_rt() (but might as well write
>> "is_preempt_full() || is_preempt_rt()"), or is_preemption() (to match
>> that Kconfig variable, although it's slightly confusing). The
>> implementation of that helper can just be a static inline function
>> returning "is_preempt_full() || is_preempt_rt()".
>>
>> Would that help?
>
> Yeah, as it sits two accessors are needed, one that says PREEMPT the
> other PREEMPTION, spelling optional.
>

Per the above, I think we need the full || rt thingie.

>       -Mike

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8735o3rmej.mognet%40arm.com.
