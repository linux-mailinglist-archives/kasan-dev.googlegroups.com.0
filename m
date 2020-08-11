Return-Path: <kasan-dev+bncBAABBEUGZH4QKGQE26M4VDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id BAF092416DB
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 09:04:50 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id c186sf590167wmd.9
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 00:04:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597129490; cv=pass;
        d=google.com; s=arc-20160816;
        b=N1EDokSqyvpV87rFV0sNwhMSoFzJWshD/Cv+Iachiw3RbDWg2jjqkS7hNv56jRCWdz
         gTBeHYTzCp6SJS1Jw4N7GVjb5Q21SQvyJiym6p7WH4CCi+FpFziXyDA9H5ow5RCC3cHW
         YXOTXyvgs0D5vmJCkIo2ADj219ATIi2KYiSRhthFvtW9dxysrMBgPXx4l6OSjJgOs9bu
         +MTNLwSqNKj5+aIpd7xETi5/fQviqHca/64jvTuc4aj4va7IZGRwHuBY97w9GMuxH2Lr
         neOB0ZwXn5JTPYK/9UMmiV7B7fISEjp6TFMOvwUQYclQ+OrP2YJrt29QjsMKxNvm1L42
         knWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=r1ecKr6BT6fkfmwOt672ocqT3Q53uXhi5XZlp0xekIM=;
        b=BPK7M/HMta1/1qjhMPtcSr095VXTLUxybei2ojkI1c7KXWjJNfYDFTNNF7fwu0TKdm
         Ge+w9F3qEgJxSqucpnw4+joIKVc0Ktvv9cjWzVvpy8sPubsird33ecgvCo4mlJhEY4bR
         jAg+Mx1s4Y6uHMHt/OBxJonB8C3eO7HSzULDB9bL9SXhjCThb44Kd45nwN9Mt6A0pSar
         RAD08m2IknFqQW4kkehEfqiZ8t1hRO1ZSpoFyuXV0eVJwsIKofkqj3IRHuQIWjcfAzkO
         MwQBYqce+sN16gcNzFyQ2t+HeH3lIHikTiyfckzKGeC9KEAmoB0oBrsClTET+OIWnRof
         RWYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r1ecKr6BT6fkfmwOt672ocqT3Q53uXhi5XZlp0xekIM=;
        b=Hx1dsNpFEIaiCB5IB4hbqkbMrt0fwzGSaCvQpGIvP0du01mg4ysRIQACcZDziho59u
         QM4OzeQuUJVCKBwTCos+dPFYcrYAqmNKY3m6TiU9SOz2++cX9NlWNciBV7KQfJw4A8A/
         1XKrhcx62cO6kRxVvcOq+djQLXPJbPdbmo50/pf/sKwd+BZiwpOnBAxmVpsCsljPlL2X
         kaMqVIKgw7xmV8K/2cNUaWsGF8GhcqgvuO8nU1hIkCyAsS8KfWJML4QsNXPDSM8d9VQ4
         zqNpYmJuyDe4aYKuvUztLu9XTFkucM4cQhx7QmLmKcg8sTUP3lglqMECgP9cS5EnvKoW
         eymg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r1ecKr6BT6fkfmwOt672ocqT3Q53uXhi5XZlp0xekIM=;
        b=d22gFlJ60uki7m1wG7S/aL5rpxRzI61/bXzDlO3o7jHSyaSX7Z2rpDGlRJ55uADfOk
         P/hIyWzUQFpPej0C0YT2KBEH0q4FogfTE49K8oTYhW1sZ7INltJtZ8FgfW1G+lKi2FDx
         osYMoemBrfcr0wMPn4hQE5U0PZxYIYbsPbPVg49g5wFGL3DpduiuNVXiKTyTtbtKdFn5
         s4ARfZyX+gD86ywu9KfEFT7ZWw+2YOJGAfj2kst+ndylkj3IGvEFVBH1EK7YB0l/usyn
         fHCxkdbxXkNctqE46GtExsAdRHfZ5TpLE94CmrcpUnuu8y48oi7LjWeoi9CgY4C/djI+
         ibzA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531JlDCEEYEkl6LnoxSfGsSspYZgIzCcdxJiXyxb8hy3xf5LgQVQ
	qeezl3zX2Ib08xTvuzxYz1c=
X-Google-Smtp-Source: ABdhPJyp0q3FUauUEBDIFkyl1QeI7j6vZbiypKvBG1kaA539Q7TpKJrUIKOSwfWx6Tva4WKA4a0ljg==
X-Received: by 2002:adf:ea85:: with SMTP id s5mr30144734wrm.55.1597129490436;
        Tue, 11 Aug 2020 00:04:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:804f:: with SMTP id b76ls474013wmd.2.gmail; Tue, 11 Aug
 2020 00:04:50 -0700 (PDT)
X-Received: by 2002:a1c:7407:: with SMTP id p7mr2684395wmc.117.1597129490129;
        Tue, 11 Aug 2020 00:04:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597129490; cv=none;
        d=google.com; s=arc-20160816;
        b=xGI5XZizieIoImnYvFRa0nnTMAg8xtwCsTmsh+cxLuCH04pNtcEVf8m4mc4HMII6lI
         szT86bWPFkGAoebKNV5zLTkYhxrQbyYI0MI/LmoVvr16X863gRzLoG+gUcjQBVDtr++d
         ue6KAQLaDuJ7Onzqt60ADNTkPa/a0PfIeYSwj/a25WSs/9FFnxm/pmxbr6UtgJK2+4Jg
         63sBGJ+JMsBiCBg4QAV6D8y0WWRR5cXjWw7Zff+VAhWU2g5+e6S/CFkdA78yE7ukrgUR
         jRx/5uOt0mIfYt6tahoHWk/i/Jg6nvPrWFsQ/OJGd/z3pH8JM5De5mbmjspuDGU54/pi
         srfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ZhNUIj6rmGABNgZ7/zudkw64aC6gy4gsxotgHFPqbo0=;
        b=gLZAEHQWf0G1LTeMPsoPYSCBBQdWi0bvJzY2HLRf9a8yCf9rKS7Cx4rJ12lTupwefX
         IQDWx6+enOcys8w2eHdZoeaKI+tY4ja9QLd3/7cB4K4hi67Ty2uxc21vxi9Z/K86CGN9
         aa2yJxsJE5ZY6SLpolES5urB9qRyoeK/fwtx/TPFedFG08KXlXYfc7Xii68UpVwN+SeU
         m6egwdshwtieJRAvbs3wVNVHA0jfft138+4w5RUKq41aWUTnbL8oIBDh9Kw9rxOvuhpp
         Nroe5YyrGtB3TJWwTwfR0KSHiFjQ0w0kHL1VW8451rt3bh/+JoO6leUNkq22ljdeBdwE
         xiPg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id j16si931924wrs.5.2020.08.11.00.04.50
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Aug 2020 00:04:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 588C8AC7D;
	Tue, 11 Aug 2020 07:05:10 +0000 (UTC)
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
 "Paul E. McKenney" <paulmck@kernel.org>, Wei Liu <wei.liu@kernel.org>
References: <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com>
 <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
 <CANpmjNM1jASqCFYZpteVrZCa2V2D_DbXaqvoCV_Ac2boYfDXnQ@mail.gmail.com>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <26c3214f-7d8a-7b1f-22fc-e864291f50ce@suse.com>
Date: Tue, 11 Aug 2020 09:04:48 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNM1jASqCFYZpteVrZCa2V2D_DbXaqvoCV_Ac2boYfDXnQ@mail.gmail.com>
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

On 11.08.20 09:00, Marco Elver wrote:
> On Fri, 7 Aug 2020 at 17:19, Marco Elver <elver@google.com> wrote:
>> On Fri, Aug 07, 2020 at 02:08PM +0200, Marco Elver wrote:
>>> On Fri, 7 Aug 2020 at 14:04, J=C3=BCrgen Gro=C3=9F <jgross@suse.com> wr=
ote:
>>>>
>>>> On 07.08.20 13:38, Marco Elver wrote:
>>>>> On Fri, Aug 07, 2020 at 12:35PM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> ...
>>>>>> I think CONFIG_PARAVIRT_XXL shouldn't matter, but I'm not completely
>>>>>> sure about that. CONFIG_PARAVIRT_SPINLOCKS would be my primary suspe=
ct.
>>>>>
>>>>> Yes, PARAVIRT_XXL doesn't make a different. When disabling
>>>>> PARAVIRT_SPINLOCKS, however, the warnings go away.
>>>>
>>>> Thanks for testing!
>>>>
>>>> I take it you are doing the tests in a KVM guest?
>>>
>>> Yes, correct.
>>>
>>>> If so I have a gut feeling that the use of local_irq_save() and
>>>> local_irq_restore() in kvm_wait() might be fishy. I might be completel=
y
>>>> wrong here, though.
>>>
>>> Happy to help debug more, although I might need patches or pointers
>>> what to play with.
>>>
>>>> BTW, I think Xen's variant of pv spinlocks is fine (no playing with IR=
Q
>>>> on/off).
>>>>
>>>> Hyper-V seems to do the same as KVM, and kicking another vcpu could be
>>>> problematic as well, as it is just using IPI.
>>
>> I experimented a bit more, and the below patch seems to solve the
>> warnings. However, that was based on your pointer about kvm_wait(), and
>> I can't quite tell if it is the right solution.
>>
>> My hypothesis here is simply that kvm_wait() may be called in a place
>> where we get the same case I mentioned to Peter,
>>
>>          raw_local_irq_save(); /* or other IRQs off without tracing */
>>          ...
>>          kvm_wait() /* IRQ state tracing gets confused */
>>          ...
>>          raw_local_irq_restore();
>>
>> and therefore, using raw variants in kvm_wait() works. It's also safe
>> because it doesn't call any other libraries that would result in corrupt
>> IRQ state AFAIK.
>=20
> Just to follow-up, it'd still be nice to fix this. Suggestions?
>=20
> I could send the below as a patch, but can only go off my above
> hypothesis and the fact that syzbot is happier, so not entirely
> convincing.

Peter has told me via IRC he will look soon further into this.

Your finding suggests that the pv-lock implementation for Hyper-V
needs some tweaking, too. For that purpose I'm adding Wei to Cc.


Juergen

>=20
> Thanks,
> -- Marco
>=20
>> ------ >8 ------
>>
>> diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
>> index 233c77d056c9..1d412d1466f0 100644
>> --- a/arch/x86/kernel/kvm.c
>> +++ b/arch/x86/kernel/kvm.c
>> @@ -797,7 +797,7 @@ static void kvm_wait(u8 *ptr, u8 val)
>>          if (in_nmi())
>>                  return;
>>
>> -       local_irq_save(flags);
>> +       raw_local_irq_save(flags);
>>
>>          if (READ_ONCE(*ptr) !=3D val)
>>                  goto out;
>> @@ -810,10 +810,10 @@ static void kvm_wait(u8 *ptr, u8 val)
>>          if (arch_irqs_disabled_flags(flags))
>>                  halt();
>>          else
>> -               safe_halt();
>> +               raw_safe_halt();
>>
>>   out:
>> -       local_irq_restore(flags);
>> +       raw_local_irq_restore(flags);
>>   }
>>
>>   #ifdef CONFIG_X86_32
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/26c3214f-7d8a-7b1f-22fc-e864291f50ce%40suse.com.
