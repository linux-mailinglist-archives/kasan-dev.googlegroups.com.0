Return-Path: <kasan-dev+bncBAABBTF3WT4QKGQEJEP22KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 9731223EA4B
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 11:24:28 +0200 (CEST)
Received: by mail-wr1-x438.google.com with SMTP id b8sf518618wrr.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 02:24:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596792268; cv=pass;
        d=google.com; s=arc-20160816;
        b=AQWSvdDs7O7DLa7Y7SsaTd6jFRQb1Njs6WADKLD578EnDQt9Li9YzobE4Tb55puVmy
         8dxS7kLFrHW4AnaWsEzvRV5mto/62bRAeCp+1EBlU2kapxBN6JhiGk3NIKgB6118qoks
         D4EBWbadUr7fOEzDQD6g50vxjj6HLacpnGvRk7EitphokZ73GmWevRUuaCcSIOPHpz/y
         1HcI6cyNEKqzDXfnxxtaglCIGwlicVVD0gticnHGqjFwpOOxUc6ZsIV/7pfcer/9gT+v
         b9C8rZ80NxkxGj+zr8fomj5A8Sy02KNL0L2hBMkCvSvvFOKZm3TfED7aPikAtdIsCpXS
         QEsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=32qY+6EbWB8OhlSvwUrMe+DYvYLIxDF7vECP8fv3f+U=;
        b=w5xCMZPeEYFe6Uy2+bnE0Tt/cg4f0fTWrRkRa/i/fVy4nEDoz8l2WPTS1MQPbzxIya
         gEvmvr2e35DruYcnJ4OcXt8HjhkAPH0Cz4wDf2YxrpvQUXHU7JfgGKQqJwW5OKSpJexz
         LuLxju4/d+9OcTEoAR1fUyxd7867N+meICX9wRwh06l+S8rlt47iPWBqCcE9feEe6KXD
         JhZk3uK/RIG2ZDcLLNO8x8ETBOz36yQPK78y2RQDtZ+KMI2kedbvTr4S/h5Blidovhts
         Wk+oXalGTWTwm4owa03ozcrX5I9DQ4PWSrfpJLlEAE9RovRpSDBdquuBp4m7AtsEaZUj
         A/Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=32qY+6EbWB8OhlSvwUrMe+DYvYLIxDF7vECP8fv3f+U=;
        b=E5gtCNRRVWBiuJHlRVsob8J80L2uPax/0qJeahTigIXYiyoTm2WL5l+AghYh5SttCC
         GLt8V+mLxhlv3fZomyeryQbzKPFt1reYaVvh0fzMqJKLyCTgG9NPSZvGjCFVJpP0fucH
         bxVM7bBoON/r92ZiyAWiIN8P6+8Dluh3lp4taime5YhsfgMqOAfg/gv2nL1CG5nuaB4U
         k8Sxv/eyCjGl+CkSIH7Uuf1/Y7X3vbk9dBBy43BPWUP8OBuTHG+N/kyScaIy5CyjJgJe
         ztQdbsxO5vh5PRJ/y647nuj4RiCTzmj7tHlhNmMlsOIU4hW9MEgeGhNTarL3p9j/8D+M
         XFRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=32qY+6EbWB8OhlSvwUrMe+DYvYLIxDF7vECP8fv3f+U=;
        b=IZZ9kKNUaOgmIctJQWkw4JZ/UbeeHKDx1YttVLi/fJfutghuQLPXInPuZfzLqOmbfz
         2aw23hHd5zJmLdUVJQoxOzBd1G/Av7+hVndZ5RlTSJrwLz3sDhPcrEVcQ7OCh6vKYyPk
         CI2ykQw07FUd10twUYTAV7MVje1pxSDsYtTI5WpuA1q9N8EzxqhyvOHfrm/kMdeCTxOF
         XstAdeaV85Z/QsgpnnOKHgf4Hnzh+/uuTpI1xufb54e1HNYNWBeTHkrT2BrDH9tCNiw+
         OoTnzedMcu8LA7sTwX95q33e0vPiHncfo1z75Ml08KZxhgiqw6h/tAGqgcsACWEvHvSZ
         0cUw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531hxqT29nOkFEbYmaaoWGrayAAPU/5zR+jOo2Q7ugJ9/HP89Qo3
	N7cRx2J2ozQZZa9gTjF7ZVs=
X-Google-Smtp-Source: ABdhPJzClwZjMItJriiiqCKcr1qU77anRvYzsr3whqYZeyLvQu0pdLgliWeinp4hU4D/+7Pd8KdY7A==
X-Received: by 2002:adf:f64f:: with SMTP id x15mr12071318wrp.180.1596792268283;
        Fri, 07 Aug 2020 02:24:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2049:: with SMTP id g70ls4128943wmg.0.gmail; Fri, 07 Aug
 2020 02:24:28 -0700 (PDT)
X-Received: by 2002:a05:600c:2302:: with SMTP id 2mr12239148wmo.151.1596792267961;
        Fri, 07 Aug 2020 02:24:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596792267; cv=none;
        d=google.com; s=arc-20160816;
        b=udvTNzWq2+jrwpPwNNRa84a4NSQRs82T9Mv0HTYsUiIgKMnRqTeINY9c2tZyM3oLGB
         Pr+vqSeYUWbY7E3bNb9Tu0WCFBUE5NEgnMl5zIO9cLAk1XSAF2Y+d4IN3WSjwqrWmbvd
         nQRnquAJdeEvXmveyVEtG6OVmD2wBxoGnBp0KnmF6DacgpaBkKUHB51M0Rizhn5slpc2
         HrvctCe3YyRiqbWobe5zjkoxzOXNDMGLS+xkOrPlZheZ7P0dw6q3u7awoWroOJJWroBO
         MzFbHThBPNKKu21+QwxyOj0rK7/Dw0mmoggjb+udhvAQRN1LKtJgHAGiDnF12DGjnur0
         ch4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=VQgKwFNvqs9fGowcPc8swQqkbq8N0bf3Fo7DaJIBwtA=;
        b=mSv2xmIGlo0SPk+X0XEB9aOf4aERz+oNvaxABkWaAl7myJfePjWVh9GD4gyR1xdo4c
         PcH3h2636JKJHjkBk+qIzXMJxSSnVRL4h7rkt6fiZX8D6wqzwTx+NI1DPH95UiJxCOyz
         LVb3YhTwX/WuCTio+p1IQ2o7NSSOSBIYv3ygXf3IZ8wZxWIkC43A+HQb2jkxAq0pKUqK
         K9TIkXAVUnkJ7AL9ZgWb8hfkxeV1qhhXilXgoC+aILOOCCqp6ikbvFRwYRDLfHtrXGec
         utLGJn+XrXd/eg7naEHZNeoR1i6JXve3jyhm84ifLnD9gKJhD5sVyryaqBphGlZ3f2nc
         be0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id a67si370354wmd.2.2020.08.07.02.24.27
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Aug 2020 02:24:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 5CA28AC55;
	Fri,  7 Aug 2020 09:24:45 +0000 (UTC)
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>
Cc: Borislav Petkov <bp@alien8.de>, Dave Hansen
 <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
 "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>,
 Ingo Molnar <mingo@redhat.com>,
 syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
 Thomas Gleixner <tglx@linutronix.de>, "Luck, Tony" <tony.luck@intel.com>,
 the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
 sdeep@vmware.com, virtualization@lists.linux-foundation.org,
 kasan-dev <kasan-dev@googlegroups.com>,
 syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
 "Paul E. McKenney" <paulmck@kernel.org>
References: <0000000000007d3b2d05ac1c303e@google.com>
 <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net>
 <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net>
 <20200805141709.GD35926@hirez.programming.kicks-ass.net>
 <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com>
 <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com>
 <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
Date: Fri, 7 Aug 2020 11:24:26 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: jgross@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=jgross@suse.com
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

On 07.08.20 11:01, Marco Elver wrote:
> On Thu, 6 Aug 2020 at 18:06, Marco Elver <elver@google.com> wrote:
>> On Thu, 6 Aug 2020 at 15:17, Marco Elver <elver@google.com> wrote:
>>> On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wrote:
>>>> On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
>>>>> Testing my hypothesis that raw then nested non-raw
>>>>> local_irq_save/restore() breaks IRQ state tracking -- see the reproducer
>>>>> below. This is at least 1 case I can think of that we're bound to hit.
>>> ...
>>>>
>>>> /me goes ponder things...
>>>>
>>>> How's something like this then?
>>>>
>>>> ---
>>>>   include/linux/sched.h |  3 ---
>>>>   kernel/kcsan/core.c   | 62 ++++++++++++++++++++++++++++++++++++---------------
>>>>   2 files changed, 44 insertions(+), 21 deletions(-)
>>>
>>> Thank you! That approach seems to pass syzbot (also with
>>> CONFIG_PARAVIRT) and kcsan-test tests.
>>>
>>> I had to modify it some, so that report.c's use of the restore logic
>>> works and not mess up the IRQ trace printed on KCSAN reports (with
>>> CONFIG_KCSAN_VERBOSE).
>>>
>>> I still need to fully convince myself all is well now and we don't end
>>> up with more fixes. :-) If it passes further testing, I'll send it as a
>>> real patch (I want to add you as Co-developed-by, but would need your
>>> Signed-off-by for the code you pasted, I think.)
> 
> I let it run on syzbot through the night, and it's fine without
> PARAVIRT (see below). I have sent the patch (need your Signed-off-by
> as it's based on your code, thank you!):
> https://lkml.kernel.org/r/20200807090031.3506555-1-elver@google.com
> 
>> With CONFIG_PARAVIRT=y (without the notrace->noinstr patch), I still
>> get lockdep DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled()), although
>> it takes longer for syzbot to hit them. But I think that's expected
>> because we can still get the recursion that I pointed out, and will
>> need that patch.
> 
> Never mind, I get these warnings even if I don't turn on KCSAN
> (CONFIG_KCSAN=n). Something else is going on with PARAVIRT=y that
> throws off IRQ state tracking. :-/

What are the settings of CONFIG_PARAVIRT_XXL and
CONFIG_PARAVIRT_SPINLOCKS in this case?


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe2bfa7f-132f-7581-a967-d01d58be1588%40suse.com.
