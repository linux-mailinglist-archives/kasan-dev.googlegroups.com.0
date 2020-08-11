Return-Path: <kasan-dev+bncBAABBBM7ZH4QKGQEOD3TK4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id B586F2417AE
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 09:57:57 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id z10sf553873wmi.8
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 00:57:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597132677; cv=pass;
        d=google.com; s=arc-20160816;
        b=bRmccVwhgHavHZlDV9G4IVIin+NLTeiAqyIQ28vqv48jL4t3sr3hFkW01fq9Vw1IG0
         6wYzHM8F7eXmqfVato+ou9l5omr/Q08xwku6WXpLy5NFEpac0dlX5k04parOUnhlrlmw
         yaL8+mrbpsHcmehI2gvGHUhKqxCJKfovjbAqHKUB6652JI1i/dH7Cu83MB2RZAh++VUc
         PM2h6HGR3njHHak6kxPUtywKKlYWkPbb5iiEgf1NKl4cKzqj3YtUwTPebfZ3NWFz9qmo
         R471acyQ6oCA9A4ZYN5uLQUkUwMeU4fiqW0LFcKQX/aVgIfey5yc/ZM3eLvWiGrw4JhM
         esJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=6IdIlv6vJZPWAMQzJEeqqY0znf++1a65Znc6qFNYZig=;
        b=daAhjPD5EhXtPR9PvbpvGjcfCCIXe7gXwjvqawNVMbc3Pyc7GS6g/mDl7vOuffJ5B6
         +dESY+jRHJvRRaQn9slmt6FzBzQXBqUJCc334D5VIjINImfL2EGlZPOVMdXHaLlp9CWB
         2FT8R83jsEGdy6oQl+LLvuSXqp0cPRAyuiIQ3ss74A9DWACYdAe5r4T1iN6gjiPUkIm0
         ve7BjfxnRKhgxsh6P/MYwp0v23XIjir2jFUyOhYzgBV7aPpwAZkTHqcpfi7wJBkyeKZA
         cYqRfwecAk7nF/9LNseK42Ir4bbi324EuZf5VI8BRhtdWsAaiaC0un3DjFq/vM3ZOcVX
         Ns2Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6IdIlv6vJZPWAMQzJEeqqY0znf++1a65Znc6qFNYZig=;
        b=RWWaD9zouEeQfUSFDximpB6DvRzBC8GRKgLvop05IfslFcvlCEzVVTbtnBvQDg6rvx
         65qwxn6+X+bh9SVz9W1QdaA6KNY7ZaKngPYKs896AzoIni0nBuNbO9w91V2RJYjIow+Z
         mruesNa6P+kWsFiNpDCjCrdNmfdLtTTbKMPT3QhG34mKdlbfwvRh8smI/8DhijHJ6ZBz
         ToRKiAf2x26TlfuyZLOO9T0xFpu/Bb82DWkr6mV5I8HzgcVBukfGfLOR1QMY8yAviPW4
         CqRLZidvia6ICDnD0ZXo/Pq9HqWBPiTqqKjePylLr1QlPtzZmutpTE3LhxJA/cDF5c4g
         Yk/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6IdIlv6vJZPWAMQzJEeqqY0znf++1a65Znc6qFNYZig=;
        b=je/Z4/QovqCx67j/vUIfmf3CfSPZxbH8sIkTdY59AmFywJWRqJ3QjDrjzzxcxnSkSI
         KnObi52t4DkJB5HxRYsTDHcjK+eMzMo7jCIUTLeVF7imkZjGMP7lr5F1ifEu9USNc6FR
         Wiss0qfN5jQ4DHBhhJuWKjCR38cKWWgwjQAVekMIqNLfopr+5qQ4RnBy21Yz7nYlirDm
         olo4DU22vAa49/15cL7JU1gZGDQbeanV9ez4S4deOq9jyFeb3y4Oi4ApdEfIpGQnzr3t
         5fp3FmlCeUkW5Vnbaw+WPx6c1jeWz4KZWX2bpvNbkbqRMrZGyAm0rxI0rmwGTartALao
         oPGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53169D0yWrJzeNbgtIWMo8vNQaS9nF3o5ThFGjlK3gguWNordOZ4
	J/1z6fq+xISjiyuTBvsWBW0=
X-Google-Smtp-Source: ABdhPJzDW9cf1vyrP3h9u2DRuYyOnqC937fVp7PTEwQNELyVuGKRwdVrrSuNol7jhnyaYTv9g5fI8w==
X-Received: by 2002:adf:f388:: with SMTP id m8mr5130040wro.338.1597132677506;
        Tue, 11 Aug 2020 00:57:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e78f:: with SMTP id n15ls1276844wrm.1.gmail; Tue, 11 Aug
 2020 00:57:57 -0700 (PDT)
X-Received: by 2002:a5d:4109:: with SMTP id l9mr29020452wrp.398.1597132677206;
        Tue, 11 Aug 2020 00:57:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597132677; cv=none;
        d=google.com; s=arc-20160816;
        b=rJgKwUjXAW1FuSTmo2mVOeBOfFbFvdtoakR/0X2pAp9cTRELVHOi6XmyVtwpA9ek4m
         VjS8FmwL3JnCCTDJI2pBtPZ+k1QI5KhMwgAq4Amtys0EuxeFA37GsviMyLQYVpguJ26Z
         gjiLIGCrkb7K4dLuz1vyzDyqsWl3l1PVqnrzxGvjtDLPGabDk47y7DK0l0RGbtS06E/4
         YoYAv/CyXUVZ1bByvh9CHMQMVVV4QgtZLNUPw7KJjWBee7cIhuOkOwnjOAD5EpwWMVq9
         PhRQen2HVgXmdoGbx6bch7SMXP8U6ZRIKf6RWGZetFTJdNNqI/IdXfepDQfv+YHjfvXp
         PJzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=5sX/HjEDp2d9Meg+CTnFToKT/7T2d0OShMy8iRaooHY=;
        b=tQCQn4Kmm5x5eT1tlallIntByDQ0r1LgzAsF+YH7q4kp7z759iFvTbyH3MPjF7ZaN7
         tDBWwrkd+sPbLWrsVAOWvFHY+gR8JJAqe1huhiMh8qzyeeOhRFxaU8a44JY6+c62VgPq
         Chbz8RfOLBNpwb/fy4cmMLToiGEF20hrxxC7/D3aRh/+OQVbxl+OvYMfcwTR+4oy4vM/
         nQcNf9PBvvxqrnrtATwOsEab3GtQ2CX4mBW/4MlssUV7qO39cyzFOV0VzUBe5eM457Ol
         emtoppK6g4ZtMohq4mDcTqrhtvshEQNuqnEFYN6iPV7wP8ViCuP4b3rQKBVzh5cgq83i
         5oTA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) smtp.mailfrom=jgross@suse.com
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id f134si90343wme.4.2020.08.11.00.57.57
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 11 Aug 2020 00:57:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgross@suse.com designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 66B9BAB9F;
	Tue, 11 Aug 2020 07:58:17 +0000 (UTC)
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
To: Peter Zijlstra <peterz@infradead.org>, Marco Elver <elver@google.com>
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
 "Paul E. McKenney" <paulmck@kernel.org>, Wei Liu <wei.liu@kernel.org>
References: <20200806131702.GA3029162@elver.google.com>
 <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
 <20200811074127.GR3982@worktop.programming.kicks-ass.net>
From: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Message-ID: <a2dffeeb-04f0-8042-b39a-b839c4800d6f@suse.com>
Date: Tue, 11 Aug 2020 09:57:55 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200811074127.GR3982@worktop.programming.kicks-ass.net>
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

On 11.08.20 09:41, Peter Zijlstra wrote:
> On Fri, Aug 07, 2020 at 05:19:03PM +0200, Marco Elver wrote:
> 
>> My hypothesis here is simply that kvm_wait() may be called in a place
>> where we get the same case I mentioned to Peter,
>>
>> 	raw_local_irq_save(); /* or other IRQs off without tracing */
>> 	...
>> 	kvm_wait() /* IRQ state tracing gets confused */
>> 	...
>> 	raw_local_irq_restore();
>>
>> and therefore, using raw variants in kvm_wait() works. It's also safe
>> because it doesn't call any other libraries that would result in corrupt
> 
> Yes, this is definitely an issue.
> 
> Tracing, we also musn't call into tracing when using raw_local_irq_*().
> Because then we re-intoduce this same issue all over again.
> 
> Both halt() and safe_halt() are more paravirt calls, but given we're in
> a KVM paravirt call already, I suppose we can directly use native_*()
> here.
> 
> Something like so then... I suppose, but then the Xen variants need TLC
> too.

Just to be sure I understand you correct:

You mean that xen_qlock_kick() and xen_qlock_wait() and all functions
called by those should gain the "notrace" attribute, right?

I am not sure why the kick variants need it, though. IMO those are
called only after the lock has been released, so they should be fine
without notrace.

And again: we shouldn't forget the Hyper-V variants.


Juergen

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a2dffeeb-04f0-8042-b39a-b839c4800d6f%40suse.com.
