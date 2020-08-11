Return-Path: <kasan-dev+bncBAABBHFSZH4QKGQEDFEMBIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id CA1BD241858
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 10:38:52 +0200 (CEST)
Received: by mail-lf1-x140.google.com with SMTP id w24sf3869008lfl.6
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 01:38:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597135132; cv=pass;
        d=google.com; s=arc-20160816;
        b=HK3FdiuVcj1ONI+ZEOL4KUYIoNZZKZFXsrudYN6hrCeOpvxuGffooo8C8P9SIR+JLW
         3dmEQDPZR2MvGtZPhidUt/Ece8M0qjfeoId056NGc69NRL7CXaoCGWt7NdPIkniumao+
         rmn8A8FM4O7OIWJDxrKrLWyMVEF3N940QU2w3xhBbq3/+3XcY0PMKtjgcBn6qoyH6EGi
         WfHGcJhyiNY5Z4G1PnI7Jg6jIzBwKjxYjINEZ9V66SexwCl87yeJ3XTasnCRRr6LcfAI
         o6WcG+bppF8jyiaEVVti9p0JMB2dc1dLPiv8sALewctLdpZYODeejI/SXcLn1HqNkr/3
         i1MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=2vlKRpqe8IrpT7hxXi8pkOmsfgGtah066Czh/4B51z4=;
        b=OIiG1kF1H+IotjBosRwSzV1FTswz8PgfeAO7I5YqqK7Gjp+iBbHlzZXsaRQrlVfM7g
         DVwtq0ikPgCKIjpF0ejl0BO2jz5GTAPfOImkxWaGyEd44Ng6oZBBTBEwUbKeVt94RXem
         16+R4KOophfgsA3Z/2cuSKnCs7dCV0K6L6lurohw+3UKuWw5Ns2liZlwhLtDM+svs8i2
         0lnjO4SVB6Q4KgdC3dCmWoGlj9AF/XZAvdVMBmTBY9ys7vWqhl4qPfMVeY9u2akij0pt
         rGYr/IGE8TPjlJGKyki24lM80OpDrpCqGiogtTO+6FYD7bmQ4UlIa28AsmRZQt21n0jM
         inVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2vlKRpqe8IrpT7hxXi8pkOmsfgGtah066Czh/4B51z4=;
        b=lbl64hREM9NCr6ITedG6VeXzLw+quv72JvMYufVTXUXz0DB+q2XMZlh6F21kBXYoCI
         l//CzDO9cL1aTvbbGkQnTeiOAJeVih+xujMfZXZMistt7bJvtFDbJKYxuLamZkPUuam1
         rZJXa4dwuMcIfQjEha89iwBVllmX6IIYaRhhoZzsEZDEiPw3t0xQaWo1gmrN9KTXqmJn
         a1CKGcWbPIXT7RqVNw6597somzuTS60UzuQ76YdddXTAUa91cmou1NNPtT6Flq4RS5o5
         APaZ2i0eGeWZcaJVL8SF2cSDQto35xYOCNvdCv1BAr1dYovMpnI9aKpRv1fwvfmeOujJ
         crYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2vlKRpqe8IrpT7hxXi8pkOmsfgGtah066Czh/4B51z4=;
        b=Eu/QXEpOSRW7QJ0c4t5VpRrShtKPj4h2SKKtdeYk7JfINaQS7w9vj6XJ5KLApL03+n
         SanvqQtyMZ5ahMR9NzayV0vfmW7kFdQWc0JVRfR4wuYUL9mPQ2AyAcjuH3XJXxQu5x8o
         JWebOF/C9fpxWo4uEAeW8JjHLbjsfqq7VCi/rqE2+Zy8ZYRUsEua3n+9I2KJnFCKq/o4
         rIuYQEQLMgA1i6FfusxNM9Rb7mpnhyMvq/EUI9WTnS7bZpZxzUIL0hfi457KkhX3kse9
         Jj/0mIdga5Zbe5H6IAWB4k4D7O0zyJdna7zlBistj4v+ZhjOrDtddacV8mTd9JUt5R3V
         A1Sw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530VWcZEuykLVqoWgXPr54eVJkVk093yb+LYzDzUcogAL18U1QDt
	JGFCsA53GpSpaS7FUHNsstI=
X-Google-Smtp-Source: ABdhPJx4xqeXtbbSCG1DFdC2Kn5yBlXT3/280kqC1sB7CDHmZt+WibFK1sMgNnk+JNF5vbAPwWAaew==
X-Received: by 2002:ac2:5ded:: with SMTP id z13mr2651504lfq.213.1597135132136;
        Tue, 11 Aug 2020 01:38:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:294:: with SMTP id b20ls3446146ljo.9.gmail; Tue, 11
 Aug 2020 01:38:51 -0700 (PDT)
X-Received: by 2002:a2e:8612:: with SMTP id a18mr2564407lji.149.1597135131720;
        Tue, 11 Aug 2020 01:38:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597135131; cv=none;
        d=google.com; s=arc-20160816;
        b=K+22BI9UeqT6lf7XghgHAjXxwTPXMSdZebsOP3mxNDzrYQLeflHCI/Nrz6XRPSwsBu
         CXuAKOjaaLn5tTCmDDk2aq2EwfsZuI8idoTLUeYCLhlsXNFn6mfoCSi1qWwKQExIYSH9
         y7ufl3o+B0fpwnY05kqDqnm6MZ8kxRUqV68X8mExfini+OpWozWuavHi12KDeyZ5/2R4
         Xi3W1PcYuIXB/lvb+qFADidybQmKaEwag6T5X5Ukx3UAhb53vwB/wzRcnIH2HQv4l/9S
         /rJbxSlk1nx3F+Qz3GIdcdUFXZeRJymUXMHIPjFU+rjwRnQ54xg3IiqF+McJ+hcc7Ntu
         jzcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=nttRUR34YjjvEXsSJERiTg77UUmJ3cfGUWriYdGXEew=;
        b=w+tHy1/lSW/1+O1o9h/1y6P7bICpOIZWMuiOlKxbPG9t94laDFAnmgfgQRdxyRQzf0
         F2APxH+jtYbVuA1uF4/PmOnSiWLdUMkysScEb91M59WZoHs3jrbrrHIRB5TUBBBHuP+b
         Jk9DgkhJKa7u3v9tXUeBRccTZ+zYv8IpunR5IeHlDDOcLa+kpRIuYO7n29aVSM5ozw7i
         jLqfXd35iZMQXho93U7RYG9Wj6WYccA99I+25hobAvDYZkuGMdRa4LExV6nfIfJGq+K6
         cYy/ot7A5E44c2GFGsQ9beAZ6z5TBoG/6y385lZ76WWE7ARao1CkN3lFvxUTidCmWU+8
         LVeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id v3si756328lji.6.2020.08.11.01.38.51
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Aug 2020 01:38:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 9C3F0B1ED;
	Tue, 11 Aug 2020 08:39:11 +0000 (UTC)
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Borislav Petkov <bp@alien8.de>,
 Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
 "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>,
 Ingo Molnar <mingo@redhat.com>,
 syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
 Thomas Gleixner <tglx@linutronix.de>, "Luck, Tony" <tony.luck@intel.com>,
 the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
 sdeep@vmware.com, virtualization@lists.linux-foundation.org,
 kasan-dev <kasan-dev@googlegroups.com>,
 syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
 "Paul E. McKenney" <paulmck@kernel.org>, Wei Liu <wei.liu@kernel.org>
References: <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
 <20200811074127.GR3982@worktop.programming.kicks-ass.net>
 <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
 <20200811081205.GV3982@worktop.programming.kicks-ass.net>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <07f61573-fef1-e07c-03f2-a415c88dec6f@suse.com>
Date: Tue, 11 Aug 2020 10:38:50 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200811081205.GV3982@worktop.programming.kicks-ass.net>
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

On 11.08.20 10:12, Peter Zijlstra wrote:
> On Tue, Aug 11, 2020 at 09:57:55AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
>> On 11.08.20 09:41, Peter Zijlstra wrote:
>>> On Fri, Aug 07, 2020 at 05:19:03PM +0200, Marco Elver wrote:
>>>
>>>> My hypothesis here is simply that kvm_wait() may be called in a place
>>>> where we get the same case I mentioned to Peter,
>>>>
>>>> 	raw_local_irq_save(); /* or other IRQs off without tracing */
>>>> 	...
>>>> 	kvm_wait() /* IRQ state tracing gets confused */
>>>> 	...
>>>> 	raw_local_irq_restore();
>>>>
>>>> and therefore, using raw variants in kvm_wait() works. It's also safe
>>>> because it doesn't call any other libraries that would result in corru=
pt
>>>
>>> Yes, this is definitely an issue.
>>>
>>> Tracing, we also musn't call into tracing when using raw_local_irq_*().
>>> Because then we re-intoduce this same issue all over again.
>>>
>>> Both halt() and safe_halt() are more paravirt calls, but given we're in
>>> a KVM paravirt call already, I suppose we can directly use native_*()
>>> here.
>>>
>>> Something like so then... I suppose, but then the Xen variants need TLC
>>> too.
>>
>> Just to be sure I understand you correct:
>>
>> You mean that xen_qlock_kick() and xen_qlock_wait() and all functions
>> called by those should gain the "notrace" attribute, right?
>>
>> I am not sure why the kick variants need it, though. IMO those are
>> called only after the lock has been released, so they should be fine
>> without notrace.
>=20
> The issue happens when someone uses arch_spinlock_t under
> raw_local_irq_*().
>=20
>> And again: we shouldn't forget the Hyper-V variants.
>=20
> Bah, my grep failed :/ Also *groan*, that's calling apic->send_IPI().

In case you don't want to do it I can send the patch for the Xen
variants.


Juergen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/07f61573-fef1-e07c-03f2-a415c88dec6f%40suse.com.
