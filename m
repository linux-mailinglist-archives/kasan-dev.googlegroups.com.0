Return-Path: <kasan-dev+bncBAABBSEGWX4QKGQEM7GG7PY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id EB7FB23ED0C
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 14:04:24 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id i6sf521807lfd.13
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 05:04:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596801864; cv=pass;
        d=google.com; s=arc-20160816;
        b=biOwCjuZY/dAhzGpRS1HtW60GhxDPodClPmC/Tc20hIgJZHV1FBgS3USkk8cGSCYDG
         K7jMJV5qxG8XL13iabFKWjELNMJAEgtYJnPwLjZmkMTuvUP3C5qIQzv0Jdq58j28E4qp
         uDtL2LTFm2xNPyNeOdXm/ukvlTcBbNTC/fhwfj9Vw72xEzLRLHeKpHDvgcZsI96b2ogd
         biw7l/cUfra4RAZYSybqOUIp7JFRdCcvLSQ5RtEvq/LZllTHX4c18mmOq+ec03/6/z29
         8atFK3j1hRF+laegyXDrHrCAR8z2oc4dbHbiBzFrceCvpsPeiRfjWpxEE9Zo6F/NA/Gw
         GF7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=XSc+W6BQGuqcVQwgtRlP4E7mq0rx5aTQkhFZt5U2mms=;
        b=OHKj9Qf02TvV9EPTcIlXkseKlkEQjn9KS1DOC8NI1Q1gtuBj5tC3NTNnVuJwI4DDeL
         v+eZFw7pU5LcLxVdm+ZeT6jOpiJGpx4jVCiREeDnaEtiZ6dFQJ9pGvLVfvtPtsw7xlQZ
         w2dz+BdSUC1Ezm3zn78Wg8AB0JTxLhhULL8iynMzHsDnKvzFeiPJGADme53rwFdpmTTO
         zLTUsGMUgo6iJ5eBz6LNb2TrLfoiv4VH/58etNYS3A3Bxq12aPbri6tSvhTL9TX57eN0
         WG3iqIy0ALLcT3/ZpOG/6Y/jaUzscr3iXnIjDR37IYVLLBRswr61eGf198Zfd/VhV+Q5
         ZYCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XSc+W6BQGuqcVQwgtRlP4E7mq0rx5aTQkhFZt5U2mms=;
        b=ZruUJB9NFg9Zqw4VexATpzaIzzqBbdX/Vji6QKeOuHz8ULwuBxqSZ0LMHTqGXPe86A
         uxIoSjdrnye1Ztk9FGXxcqkCBGIQfWxxAG23MwkKle8iJmmPHa9GUbimivgC/nDsaTzH
         V7G9SI2QIIovj/nvd8xr3XKeBjQHfoHZbOHPJFKZCcrlSdsQTe2jMbso5VTegZefNSHQ
         cGhq+8//V94fphThV2ZLEZHult8jCiOTB+QKFTrXEkV3rknn/GYrXBVuSOkDlaEjeUcq
         9skc3u7aja8+rmEtC9iH0NB3JWFsBI8RdSDHuqlIMh0zf00kZL8XAHLx3pIpAkePGiTJ
         9ifg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XSc+W6BQGuqcVQwgtRlP4E7mq0rx5aTQkhFZt5U2mms=;
        b=PYkVF/RYqscjTgwD4ro6Ko0wyAKAUfDHX4zxdWVtH2w1plKMQcXkgKTYdLHkq/3N5F
         DlTAFYDzUh9ADhljkUof+1V69hZfkq3ocYMTJkt09c6qNVQxmdV36oFNzHXPbpmpCM39
         MnvbZNyLVow1Yus8gvG6gYsFf2cXiwhVeuCdP373GIlMckDRuQhm1uAxoCBNMLqQ2A/c
         M97yKs8X/IoiL9STl1okzbOHD/UAnp/ci5HC9lINJ7wseHxp/2GUhaQYrI/hToN+X9pa
         C1Osu0M1e/nyLaQ+9KJxmKyQkvKFz1GwP+xRGV7oKFKRIH3quX3sqe19veroPnpGlNiC
         zu3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530laVaHaVfS8+tma1Drf5w7h+Tmwni4pirLMFnkQKZ96RhsS7fc
	ufuxnm3nVGp6IuSpdmRUFRA=
X-Google-Smtp-Source: ABdhPJxTKg2oU91oucIWhHNLBXmKDLJ7GCoyylHoNirPX5/JPIrjYVZ1Hw+0qJR8hs3WhMBBjwg5aw==
X-Received: by 2002:a2e:b5b3:: with SMTP id f19mr5900090ljn.210.1596801864352;
        Fri, 07 Aug 2020 05:04:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a482:: with SMTP id h2ls37578lji.8.gmail; Fri, 07 Aug
 2020 05:04:24 -0700 (PDT)
X-Received: by 2002:a2e:9a82:: with SMTP id p2mr6214665lji.129.1596801863956;
        Fri, 07 Aug 2020 05:04:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596801863; cv=none;
        d=google.com; s=arc-20160816;
        b=buQH6uzh+BwWsL2yuCl58ZSncj0W7DCpgY6qdW5vN+BGj0nKZtFKea7+39+MWsmO8L
         03xn361mCPmeVemoMs8hIj60C5fLKOu+cHvIsp+I9Qq8K0Wa/l6unRDYd4rKuzUVqnV8
         guYDfjVvy4uSk2TuzsIJrgP4abP6QzNK1fyXPCOOTBsihYB5VIVIjPmMWTWVLclJDEtm
         TPpHdt38SeXNbOf8opgMxl8ydZk92fP17ntdWxLx2ZVAF79/tSIB+HAeQJUrjGiW7m08
         MNIKNXiboSHQtZgjC1TLMKr9yR3f04mlA/YTgdr4ylvx5ebX371jV3uaLuAcphBvPFJw
         Az+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Tvurq/IlAZS2EVJQfILXciDIKIaYUAarK2IfEYMOwEM=;
        b=CSO+Jc5RX4y47dr+qYRljcz2KRUHLgA8FdQMMyvoIkr3FWPD7z3Ea6azfQXFqJRw0P
         Zx+a0K8DKXxm6Ya97E6LOeS15CAHTc0QKdICTtas48urGKvSRR0dn9ADJhOeRLZ9jlU1
         fndD0fTaReRBya3vCVM/VPZJW4UMSk0kAYqRr74Ms9OqocTmtqmG3iszifFHJnT06R1u
         c0cvYaYGYu/T6ourt6VcWJJM97qyiN2mZ6XZ1IrJpxd/xSUi+Rj++xncWLb8ANqFv2Nc
         jww8vbPy0ht7QAYqsPg3ILN6oF94vAod4byiIQ7x55ldt2fNdslxHoJroFkwCYYLjYqR
         ZDAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id 141si411136lfh.4.2020.08.07.05.04.23
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Aug 2020 05:04:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 2B4E4AF4E;
	Fri,  7 Aug 2020 12:04:41 +0000 (UTC)
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
 "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>,
 Ingo Molnar <mingo@redhat.com>,
 syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
 Thomas Gleixner <tglx@linutronix.de>, "Luck, Tony" <tony.luck@intel.com>,
 the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
 sdeep@vmware.com, virtualization@lists.linux-foundation.org,
 kasan-dev <kasan-dev@googlegroups.com>,
 syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
 "Paul E. McKenney" <paulmck@kernel.org>
References: <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com>
 <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com>
 <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
Date: Fri, 7 Aug 2020 14:04:22 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200807113838.GA3547125@elver.google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
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

On 07.08.20 13:38, Marco Elver wrote:
> On Fri, Aug 07, 2020 at 12:35PM +0200, J=C3=BCrgen Gro=C3=9F wrote:
>> On 07.08.20 11:50, Marco Elver wrote:
>>> On Fri, Aug 07, 2020 at 11:24AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
>>>> On 07.08.20 11:01, Marco Elver wrote:
>>>>> On Thu, 6 Aug 2020 at 18:06, Marco Elver <elver@google.com> wrote:
>>>>>> On Thu, 6 Aug 2020 at 15:17, Marco Elver <elver@google.com> wrote:
>>>>>>> On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wrote:
>>>>>>>> On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
>>>>>>>>> Testing my hypothesis that raw then nested non-raw
>>>>>>>>> local_irq_save/restore() breaks IRQ state tracking -- see the rep=
roducer
>>>>>>>>> below. This is at least 1 case I can think of that we're bound to=
 hit.
>>>>>>> ...
>>>>>>>>
>>>>>>>> /me goes ponder things...
>>>>>>>>
>>>>>>>> How's something like this then?
>>>>>>>>
>>>>>>>> ---
>>>>>>>>     include/linux/sched.h |  3 ---
>>>>>>>>     kernel/kcsan/core.c   | 62 +++++++++++++++++++++++++++++++++++=
+---------------
>>>>>>>>     2 files changed, 44 insertions(+), 21 deletions(-)
>>>>>>>
>>>>>>> Thank you! That approach seems to pass syzbot (also with
>>>>>>> CONFIG_PARAVIRT) and kcsan-test tests.
>>>>>>>
>>>>>>> I had to modify it some, so that report.c's use of the restore logi=
c
>>>>>>> works and not mess up the IRQ trace printed on KCSAN reports (with
>>>>>>> CONFIG_KCSAN_VERBOSE).
>>>>>>>
>>>>>>> I still need to fully convince myself all is well now and we don't =
end
>>>>>>> up with more fixes. :-) If it passes further testing, I'll send it =
as a
>>>>>>> real patch (I want to add you as Co-developed-by, but would need yo=
ur
>>>>>>> Signed-off-by for the code you pasted, I think.)
>>>>>
>>>>> I let it run on syzbot through the night, and it's fine without
>>>>> PARAVIRT (see below). I have sent the patch (need your Signed-off-by
>>>>> as it's based on your code, thank you!):
>>>>> https://lkml.kernel.org/r/20200807090031.3506555-1-elver@google.com
>>>>>
>>>>>> With CONFIG_PARAVIRT=3Dy (without the notrace->noinstr patch), I sti=
ll
>>>>>> get lockdep DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled()), althou=
gh
>>>>>> it takes longer for syzbot to hit them. But I think that's expected
>>>>>> because we can still get the recursion that I pointed out, and will
>>>>>> need that patch.
>>>>>
>>>>> Never mind, I get these warnings even if I don't turn on KCSAN
>>>>> (CONFIG_KCSAN=3Dn). Something else is going on with PARAVIRT=3Dy that
>>>>> throws off IRQ state tracking. :-/
>>>>
>>>> What are the settings of CONFIG_PARAVIRT_XXL and
>>>> CONFIG_PARAVIRT_SPINLOCKS in this case?
>>>
>>> I attached a config.
>>>
>>> 	$> grep PARAVIRT .config
>>> 	CONFIG_PARAVIRT=3Dy
>>> 	CONFIG_PARAVIRT_XXL=3Dy
>>> 	# CONFIG_PARAVIRT_DEBUG is not set
>>> 	CONFIG_PARAVIRT_SPINLOCKS=3Dy
>>> 	# CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
>>> 	CONFIG_PARAVIRT_CLOCK=3Dy
>>
>> Anything special I need to do to reproduce the problem? Or would you be
>> willing to do some more rounds with different config settings?
>=20
> I can only test it with syzkaller, but that probably doesn't help if you
> don't already have it set up. It can't seem to find a C reproducer.
>=20
> I did some more rounds with different configs.
>=20
>> I think CONFIG_PARAVIRT_XXL shouldn't matter, but I'm not completely
>> sure about that. CONFIG_PARAVIRT_SPINLOCKS would be my primary suspect.
>=20
> Yes, PARAVIRT_XXL doesn't make a different. When disabling
> PARAVIRT_SPINLOCKS, however, the warnings go away.

Thanks for testing!

I take it you are doing the tests in a KVM guest?

If so I have a gut feeling that the use of local_irq_save() and
local_irq_restore() in kvm_wait() might be fishy. I might be completely
wrong here, though.

BTW, I think Xen's variant of pv spinlocks is fine (no playing with IRQ
on/off).

Hyper-V seems to do the same as KVM, and kicking another vcpu could be
problematic as well, as it is just using IPI.


Juergen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/e5bf3e6a-efff-7170-5ee6-1798008393a2%40suse.com.
