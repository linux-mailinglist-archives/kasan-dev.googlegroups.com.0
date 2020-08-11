Return-Path: <kasan-dev+bncBAABB3NIZH4QKGQETE3R57I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C552624181D
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 10:18:53 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id x13sf3858661lfr.15
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 01:18:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597133933; cv=pass;
        d=google.com; s=arc-20160816;
        b=LlC767tQCZ65Pku9K5yRUxwx2P2XbZu0XgD9Q2QZ64MW10U+TWyxf5jKYos4FpM4Sq
         JNGfnR8Xxsc632iv7CYwK6K+jgUxyxOaOPdAuLbS5HDVC7Yt3lLu4in22u2MLBEInvUj
         2r0v+OgAjj3bGCsQDJWdKMONyhcnZcrKuiZNAVAqtAv1pQXIzB/tddiSckrTRqHMj+dT
         xIVH/uBNVDgIN2yPKF2jG2dgGjz/VGqvjILsfwmJCIw95vgYd6OniWdiv5DTpQEntOD3
         49m9bUKSQTJTsRl/wgLAPqCHWdhYmK6PW7pFb227B3YKq3/Cvk+b/NamWcjDavUdy9f4
         T2Sg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=/RjQv9MoSCB+LqEeRiNJB+IIsrQo3dQg9VM6uGuDOvQ=;
        b=q2acETNvbrX/tUtlTy4Affo0JvFDi+AXnejVcc3KHW4v0IGVKG1OfKnCK9sAxYSOWd
         dahtWHvIRQvrrxMVmRpFHmNBhHdypRy/m3fBmGsieFI2rs84/qLj7nUuOckYUrSI1Xeb
         YNiGWXnVzA6AelI7ySFkynezN08MElLSKKxkLuNx6wyFoNPTFNDPBqQxiLHa7v5OHk5a
         /OF6lX6utWJgBO3HX+mQ/SiyILokc3lcKnF8ftLqueQLZx+XZ1s5n6JN8MRZvwSHYH9i
         3iyx7qyt86imd+U8ThPm8mRcNlKJ14WZBDbrhZO3c+Rsa+mzzwXaOnO4Milvld8PX6JM
         qflA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/RjQv9MoSCB+LqEeRiNJB+IIsrQo3dQg9VM6uGuDOvQ=;
        b=Dq7lHsHHcXedySOwmTJ1xOe3UXwFEC+8eJgLJPIIaOmKldG6c6vnJYxiq0aZcwl1Kg
         rcIlxUvunWZ8qJGeuCNbHJ9qUA4einSdf4RV7HBb0j+KLNWLkiN2srhiJbuzJGXYb/5F
         LnIaBLUKr5yq+RzBrhI18E1Cqx+g8v5n47Y3dnuybFTkD8W8EaCfrnJAAPpjdE6kGSy2
         s6eVIIGlh2jiMURI/xqSxYFzfByZtyNPClITi7/hROr4RRH0SueOh0xTIscWxD0/cSRY
         NmVw+36BTS0NfiHEzEzJ4AR2b+hs7Ew7YmPIayk0kpDqgnL1G8tPDgB4q+HVURJZUNrv
         eWGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/RjQv9MoSCB+LqEeRiNJB+IIsrQo3dQg9VM6uGuDOvQ=;
        b=eoUh+M2fasQVLRORvBN+wPvaVLcGnQzeTf8+sS0YzwmZM+Ji7m4jcd7CrvZ/9DsErj
         SpW0TVnrL9CAc7WXc2UoShwGgPeJtDCuQHbPFhOygj3Bu8BQWaeFhXzDA6j/mugDQvFw
         QXM2WaRkoMX2VXynKgKIRxOMfMzu8Ac+Tk7EDAtuMucRX6Os26Qia0xHBsueWfgVtj8p
         1OoLts5rJk4eBoKjX5piBCIE0CXfADsUfg68anKSVDMuEBDyOuNgopH+EElAQMSCdMhZ
         ja7lXWFd3ON4tNNtx938lF0bAufVuLv4vyE4RwDGTlIe2zhdJIhJrsx4+FwFk4EFRGjB
         LH+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532R/iJXaLxcReuBpbPDcCMKOdDamqLqbpyHx22E40Qgy6NVPJzg
	y+kJLFOYHLrs1MI7Zj47U80=
X-Google-Smtp-Source: ABdhPJw7TA35oy0xYX6zum5dtSwKetOHGsGyaHygtqw/mDQmyY2cPlga2X/KvHUBoJzB2KXIm9flKg==
X-Received: by 2002:a2e:5852:: with SMTP id x18mr2344026ljd.132.1597133933216;
        Tue, 11 Aug 2020 01:18:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a482:: with SMTP id h2ls1926706lji.8.gmail; Tue, 11 Aug
 2020 01:18:52 -0700 (PDT)
X-Received: by 2002:a2e:90e:: with SMTP id 14mr2554600ljj.293.1597133932790;
        Tue, 11 Aug 2020 01:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597133932; cv=none;
        d=google.com; s=arc-20160816;
        b=gcbRqCEirKTiuJBPlDk4U/ZYDQlIh7v787HdKyUAYF8QLL55JsZuzIQg3pjWSBKlO5
         KkRfaK7Zbbi1v0Mpt62a9ofBA1XATWhpP2M3W2ysBgC5VpF7c6y89vTMDMkrDQJ+YXbQ
         AhZoRp19iFzzbULSiYeoVCAwpI8igVO2G3xpDYxWVq13wzRpSgxg97095orG3QzA9E4f
         66l5PaE71gA8K+rkh4V+qkIcDaD4vApZyiyJR7NT+j4wI9z1In242vw1+QivNua2KKDE
         vMzgjc8ih6sHEX6dueDMK3/O9QrFW7sHrp6MdjGTvrhk+nqrWrJ0ZyEg8Yy/aBBB9TKN
         YvEw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=RScswWnw/qNlvSa8Xz67HdiMzgQxG00qnyCN/ffkGEo=;
        b=I9xHQm4i4iSOyV3uDz5mIHk5zW2KcECmMYOMXKYkRcZwHecsc0iq9Mmam1II7g5EWF
         25NqqwX9dWv8kLHBHjJKHQtzig17rz5YMluS3zAJfzkhkQ1jG7VD8Y/yuFtNrfrOh/E/
         ezik3BSa0P7KC+g1Z6eMyE3JxOtz7+iYeAcgmEVvEHAyyii+IfHkPyEWeq1YvEDbTA2g
         N3upau/Wsgk8XhOyoA+qORpLl8juTzN48l8A2PT7Zg0vrnO6C15Xm/W0GgAr/wt4PjX+
         SOfkquijWMrjBarygB5a03td1DFnMh2cjaSZ3Hz2A0eL/fEdSmx3jYkjpPnZsR4N8d8o
         58oA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id o13si859806lfc.0.2020.08.11.01.18.52
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Aug 2020 01:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id A84E9AB8B;
	Tue, 11 Aug 2020 08:19:12 +0000 (UTC)
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
Message-ID: <ad08e473-bf61-b876-5de1-9e8bfd8b8911@suse.com>
Date: Tue, 11 Aug 2020 10:18:51 +0200
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

Ah, okay.

>=20
>> And again: we shouldn't forget the Hyper-V variants.
>=20
> Bah, my grep failed :/ Also *groan*, that's calling apic->send_IPI().

I've seen that, too. :-(


Juergen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ad08e473-bf61-b876-5de1-9e8bfd8b8911%40suse.com.
