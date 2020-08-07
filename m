Return-Path: <kasan-dev+bncBAABB264WT4QKGQE5PXIBOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id A9E3E23EB96
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 12:35:23 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id p7sf599344edm.5
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 03:35:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596796523; cv=pass;
        d=google.com; s=arc-20160816;
        b=meL0DH+j0KQcMNPtaUi9aajudC1QBO0A98pTJ2qOoyy59gfZsDWOACTXEVRrq34o8s
         shZS0zE5AWleFCwwwu3YO6uq/3jO0kLTP8RURJ7ek+Yk6HzPZkpzuqJPNC4p9xNaR9pW
         c3a3v5ILuz9Zj56SMs4tPKgHzjOMnKr4E7UEQGzvipWQwEpjnnKYxiGLB9G8hLww4uw1
         fZcrymX8dQ/nH/7N2RAeRPXCeGAF1EszXKZpQ9KocYzeJOrmGv85lr4Gv9xOOjjyq0kW
         0FLKJjnd413V21VaxbPKkl/Tlofwbhui7sZ70xTW1zVPCHOfysLJTOWMBgfqmFefdNnS
         qsjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=TtlKumhHno88srsBqEbaW9ova+CnSn+6tDAUUqDDYuA=;
        b=jcgKraZ6iltGnXIfDoeOuC4jlLwu72pUHLMhJZiRNMEViqmbtLsdfdf05IlgFxcmuD
         7XvWjtRTb8nR9yOP1SavcFViz4uNYmtGTvB6LUV/MsNZqqxaiwP/ZwUur7OogXKp5H8B
         uLOPe3/7ZCB7YFBme/F5aLdNCjrYE5E7xBJxxS2b5CegnXbo+sqEK2iimTPO7LBtl2Y8
         /4Do+8hP3xEbDHyW9ejAgM+LSFSrtjet3v41LnmJEqJBH50gjdQux5lvBOKvPIUiri2o
         ittwQS/EIjmtMqGrhNVn6tyiJICX5k64pYqnCGk800BCSdhHaqcTQJEU++Ofja4/1Dk3
         VnfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TtlKumhHno88srsBqEbaW9ova+CnSn+6tDAUUqDDYuA=;
        b=XFSrxn57OlHznQmriiQmAbN+GU5+LFv8XDg4NpaJLs8A2DSrWU+bgeYavFBnHKO3eF
         wLNwwg29zlsU4Dl0AYDJYv9gdp5YUQ2bgba/gub/o3+f96bpwEfTI0O7vtODHAb+8s/t
         AKevnqst5ljlmQonsVBvUSf9qfAIfOnlXVDUugJzjwHY0DfiG+jVJyvTj1Zfipp/1zOr
         /0yGBxagNKsHuUZtbO75V2YRrsyYK4PKMCzV8IiT04sOA6iUvwB3aszaLK06nOM67zYi
         64FNoMflSKHvkZBbzq+jnGRlPjUDIOHldOyt5/BIaRiyqArMLMqOrGaBpSGHh3bH9NI6
         RfBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TtlKumhHno88srsBqEbaW9ova+CnSn+6tDAUUqDDYuA=;
        b=Dh6YBKnSnUyXWwiNaPgjwAlG4tO88bxDr4FHmeV/lB7/cmoo669QD1SjQqRZlqOYoI
         /y7yfFghMgU6THhK6/ARbmcGZTFZDwF5aBzdv0YEqpPfUMJzvt7q4UIwFXnPdsdvLQyw
         NzekTLNzGwTMLFnb2WCH2lVZhp0gvIBna+LJVvf0kaP42Ot4cRIV05PMSbJeQMYHhdDe
         3/aJMWCd+pVDp6cTSDuA2eNQ7HP3TVXvFcuFu0m9T1+RFpILvVJ9ja2gdqepkYz+LyET
         G+wHIqtsehD6gyg77OSgll7xfvd72cNXc/Dz3XOck4nDNVqgUwzl1ru3K6Zj9tSXoq15
         05SQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rCRPlm1hmbxYdeo1/29Q7++3WxZ/W5XrFogPL3Vm+yrG9smrm
	0ocXR43uM8Dxo7lIK2h/YtE=
X-Google-Smtp-Source: ABdhPJyWAvEO99klvnE8qwveZPlqd+nOaBz6MBEtGg302Vt4N2N0JO8JIIfyg7zfciP7tYjWNcKP+A==
X-Received: by 2002:aa7:c6c2:: with SMTP id b2mr8450155eds.173.1596796523430;
        Fri, 07 Aug 2020 03:35:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c40c:: with SMTP id j12ls8694245edq.2.gmail; Fri, 07 Aug
 2020 03:35:23 -0700 (PDT)
X-Received: by 2002:aa7:cd07:: with SMTP id b7mr8562113edw.172.1596796522933;
        Fri, 07 Aug 2020 03:35:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596796522; cv=none;
        d=google.com; s=arc-20160816;
        b=ftn/lUxSYyMaDgroRK8TqrO2VbCZCok2ChPwWO4q3oVRA4UPEs2yWt4sQY5gLAeprK
         6/m30ldZh/pOPlPBLuIl/sEQlMyhuM5Sqrww2BloZuhosqSDC7Wq45A9QjktmUAGkV3y
         YzF11cxKbdc1pQC6j1r7ptzp9BxQnX6Dtgq6nD68ijGq7TJ10bYH2aLJ1B48YWVEqgIv
         Irk8/pgRxxO08sJC5AFTWUJ3+p3wnlpRnESnXeTjstUKMQYOggsWqchH8MPhAoYNw1we
         xUFojlbZO/U0EG5Mc5WKN2oPb8eUYDpHRry6ghsHen/+Uplkl99/9JNzKLqznTZt1pkc
         Pp3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=zNH/689zeEfH2+57pgEpRXSBtKNCvqsel4/oaTcJIVI=;
        b=NpxrvB9irMa+XKh78/GLWPoCM/3RfiPmOeXM2B+t0WcL5ARRSckMdhoL1f7MMw1X5V
         ajXepJZVW7EPdNfHUmbhElU3QVp4tnZq5XSYlNicdsGDRsc0I5jC0eQDT7aEFUaLuhTx
         iN334EWKpJ96y6Qwgn0wLhOIR/kBp2nMowopc+6W4aYLZ4s0YTnxHBeAiAVMFsJBznxf
         /a+jhv0cJBE1wTec8lsKTf0LxCJ8DuES7Zf9ny6agzgE/UC6WVOrATxBb/wz49kuG4+I
         AqKXyILtEOq4FCYp0PbRvENXr0qcD7JDHjL7SDcrHYaL6sTyNIZ8JD7a1NZMWpEAKWhh
         NDig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id q14si454381ejo.0.2020.08.07.03.35.22
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 07 Aug 2020 03:35:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 4E006AE53;
	Fri,  7 Aug 2020 10:35:40 +0000 (UTC)
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
References: <20200805141237.GS2674@hirez.programming.kicks-ass.net>
 <20200805141709.GD35926@hirez.programming.kicks-ass.net>
 <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com>
 <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com>
 <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
Date: Fri, 7 Aug 2020 12:35:21 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200807095032.GA3528289@elver.google.com>
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

On 07.08.20 11:50, Marco Elver wrote:
> On Fri, Aug 07, 2020 at 11:24AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
>> On 07.08.20 11:01, Marco Elver wrote:
>>> On Thu, 6 Aug 2020 at 18:06, Marco Elver <elver@google.com> wrote:
>>>> On Thu, 6 Aug 2020 at 15:17, Marco Elver <elver@google.com> wrote:
>>>>> On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wrote:
>>>>>> On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
>>>>>>> Testing my hypothesis that raw then nested non-raw
>>>>>>> local_irq_save/restore() breaks IRQ state tracking -- see the repro=
ducer
>>>>>>> below. This is at least 1 case I can think of that we're bound to h=
it.
>>>>> ...
>>>>>>
>>>>>> /me goes ponder things...
>>>>>>
>>>>>> How's something like this then?
>>>>>>
>>>>>> ---
>>>>>>    include/linux/sched.h |  3 ---
>>>>>>    kernel/kcsan/core.c   | 62 ++++++++++++++++++++++++++++++++++++--=
-------------
>>>>>>    2 files changed, 44 insertions(+), 21 deletions(-)
>>>>>
>>>>> Thank you! That approach seems to pass syzbot (also with
>>>>> CONFIG_PARAVIRT) and kcsan-test tests.
>>>>>
>>>>> I had to modify it some, so that report.c's use of the restore logic
>>>>> works and not mess up the IRQ trace printed on KCSAN reports (with
>>>>> CONFIG_KCSAN_VERBOSE).
>>>>>
>>>>> I still need to fully convince myself all is well now and we don't en=
d
>>>>> up with more fixes. :-) If it passes further testing, I'll send it as=
 a
>>>>> real patch (I want to add you as Co-developed-by, but would need your
>>>>> Signed-off-by for the code you pasted, I think.)
>>>
>>> I let it run on syzbot through the night, and it's fine without
>>> PARAVIRT (see below). I have sent the patch (need your Signed-off-by
>>> as it's based on your code, thank you!):
>>> https://lkml.kernel.org/r/20200807090031.3506555-1-elver@google.com
>>>
>>>> With CONFIG_PARAVIRT=3Dy (without the notrace->noinstr patch), I still
>>>> get lockdep DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled()), although
>>>> it takes longer for syzbot to hit them. But I think that's expected
>>>> because we can still get the recursion that I pointed out, and will
>>>> need that patch.
>>>
>>> Never mind, I get these warnings even if I don't turn on KCSAN
>>> (CONFIG_KCSAN=3Dn). Something else is going on with PARAVIRT=3Dy that
>>> throws off IRQ state tracking. :-/
>>
>> What are the settings of CONFIG_PARAVIRT_XXL and
>> CONFIG_PARAVIRT_SPINLOCKS in this case?
>=20
> I attached a config.
>=20
> 	$> grep PARAVIRT .config
> 	CONFIG_PARAVIRT=3Dy
> 	CONFIG_PARAVIRT_XXL=3Dy
> 	# CONFIG_PARAVIRT_DEBUG is not set
> 	CONFIG_PARAVIRT_SPINLOCKS=3Dy
> 	# CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
> 	CONFIG_PARAVIRT_CLOCK=3Dy

Anything special I need to do to reproduce the problem? Or would you be
willing to do some more rounds with different config settings?

I think CONFIG_PARAVIRT_XXL shouldn't matter, but I'm not completely
sure about that. CONFIG_PARAVIRT_SPINLOCKS would be my primary suspect.


Juergen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/16671cf3-3885-eb06-79ff-4cbfaeeaea79%40suse.com.
