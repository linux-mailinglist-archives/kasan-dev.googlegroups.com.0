Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBQ5P335AKGQEUN3R6FA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 477A22612D3
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:40:04 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id v128sf1003385lfa.5
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:40:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599576003; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dusxy9zp0MjhyHSNZHwcF+0ReuT3I6Nf1t2baxphBE5sf//E4F8XXHQYkfBGuxNvMu
         4r4g0aVGYPclrpF2iZiuAi1OmGS8vmYxZVFkO2eAPjrYMXlZC8JSg9MQzdSD1bn5Vra4
         XE/WKG5UIx8VTBXFwgTXCvNPn9m3KqXzZ0woSQeasyxlBy0KuUHvOVGAQBnh/3rWL8U1
         JGiGN+OgNCfAMMc4GO3S60Ki47JZPxayZ1RU0nZE4N3p9/sALkRWj+5o/U8SbKGympbl
         oBdfZKbQ8449qRpLodHnZ7ajq/97fT4pKx37evs57n9Yic6T+1zU2cGb76soCKIxADha
         BEGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=3s3scCD8LDpJJbSGJBvCPrMWRsTaoWgLBIuGOO4ji+4=;
        b=BwhN9C9M6PN8QmC5nSdpVg78VRIcx7add794brLw0OSWEqqGYg9sM09nT635nQaKA8
         mxmqxFbMhX1xw/h2j8dWGPofSHbpcBBCiJe21o6kK6KQmCPd61UEYzqnC51muWQpxawH
         Y86HnuqgDN//sPinB849Y8TiN1QmB4fVAZoxyjyK6nzcKZ6IE/a03jweWj5JQPDZH/P4
         601Pxc8HJdKcXHZ+ykZKJarGJRJLmOlzr6HIXVrlpukk28V0qovmt3tJ+o1YW2lWc+JL
         5oHOUZ9qA1S8HGmw/8AFrVj5Uu6RUq7vAlFAw9N9T3buVvwaYYXatNtMMDu4uEo3yUXV
         2CmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3s3scCD8LDpJJbSGJBvCPrMWRsTaoWgLBIuGOO4ji+4=;
        b=XBJfzvsfdY60Z2n0K9KXF8hgkqsDO/YUqOBjzuoMMa1uNfeMgAyt90XAZE7svBdcmu
         fFh6WDaKHitAyS4lHTq+bQ93fRs24Xsg/ihFyfH6ad2fn920H5WjCbqhp0xu9eDkteaJ
         I+5cBp/DrxdDk1B8QLM625WM4akWo5NO1lY74dulObl1RBs3/C5IK1gY0xhh/13DY6ni
         x315Nskdst/uMLpsDFGIWT+VtpHHXHDhiceveThzDNSwUG8QBw+nGU9R+Zg8Wi4jN//V
         rFKdCGU3+HpWtYweQzUqyCct+StkIr4N/rVm2hlMNLkuCijb9B9RsAO+yq1WC4ZEsKzN
         kV/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3s3scCD8LDpJJbSGJBvCPrMWRsTaoWgLBIuGOO4ji+4=;
        b=n515aMnEOQABUfh3Zr/rVh3YgirNLonrm9IhcXxyBVXTTVfrAkqNa4zqR7icWXcVxi
         43bHD1tdE2OIa4rr6WshvEODlbGz9Qh2TSEq6NXMD5Ky45dQIKF2WX8aTjVVK40GAKov
         TcyHk2VR7GrU/S6VOUhbLg84yDQGXjVcbekexcPQTO821cbam6crD2EjFCXUHi/n2Sdo
         lgWdMpBOx2pZ122pZzRXkQ6da8VtOApDdllb3AyR1JEXV5BEuq8T5Ccn2hqObyEnfTvq
         JXuhVcHvlfJfeRoSl43r9I8Grt9Xk+c4Ow4+PcHRb+xvDMchKT+ZYh7flCY0TjzaUMyx
         1KLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dTybr4/FCeHg/3v7EOYCBb69/5pbprXDVYJ48W7mo68os4TiR
	AG413jTuxk3MliMITISorHk=
X-Google-Smtp-Source: ABdhPJyqzFvLPslYU+8EZfSQh9mkhmuoKHmjwCPhbtzuPUnZYziarTPx5QCrVx4hRMIFxOo1N5TTWw==
X-Received: by 2002:a2e:7404:: with SMTP id p4mr2779899ljc.360.1599576003732;
        Tue, 08 Sep 2020 07:40:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b0e9:: with SMTP id h9ls3926672ljl.5.gmail; Tue, 08 Sep
 2020 07:40:02 -0700 (PDT)
X-Received: by 2002:a2e:9b02:: with SMTP id u2mr4724951lji.303.1599576002670;
        Tue, 08 Sep 2020 07:40:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599576002; cv=none;
        d=google.com; s=arc-20160816;
        b=qaagbTNyu8n9nv8qpHQXZ0Mun9zqEGpxl1wkzmGyujXf1AaUT0xCgZc3vP83AyGkab
         klbSGaw/89BnIbW3QpGtbKQ+BxVWgsEyWOmCcOS2scu+GsjWg8SJ9MPLsv4FSQLJIn9I
         fygqJ6c3kTNeS+JAaRW51+wo1wj1bR4bxpJ5uVPULIkDAuFoa2VirTOJgTp+2Uoyejav
         ZDD/ka3J/XLMQZvhzJAaW+LU0m5CCKcIk9P81/EooG/EP+jVawUk8nHp0X+1c6FPS6l9
         wb53Ii51mIAKQmsPx7Kvgg7h+PDdgT6aCFuqZprLjxy4arlTWtxZN10IwxCeuuKf0ArP
         tSBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Vdc8uc9SfKTgxdo6rO00DgjGI4oExQlqd/MXbT/t1qs=;
        b=BBnDBh+71w3ftFqIL/Vujd/bc+vzBWmLRaig7EQL5u/bIMGxpjceGbAvT9sW5djfeP
         ySQO0OSbC8pgLpeA+/zptGhvaNd8z3tXKM9IHdqPB4pSk4u6NhOZjl8HRr2gWT9iX+s1
         wTojMYE/NaZDyDCE921bufl9USkljhXgJani4afj2cKcrxrezps4hlwQZQCTUJTYUC6I
         qNtNl39lLYq8OXM/J4NcV/Iu9V857PttiE3xE9cULmmA8YLoUWiQ9R2H4kt+QZxLejt3
         CyN+J9AyIFS/tCY/uRL+SOvymxUOpjr6EZjzxyskIom1qTQwZcuR6jeAAuMHx61pU64J
         56eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id r16si417900ljg.1.2020.09.08.07.40.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:40:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.221.27])
	by mx2.suse.de (Postfix) with ESMTP id 5F5BBB605;
	Tue,  8 Sep 2020 14:40:02 +0000 (UTC)
Subject: Re: [PATCH RFC 00/10] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton
 <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>,
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>, Mark Rutland <mark.rutland@arm.com>,
 Pekka Enberg <penberg@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>,
 paulmck@kernel.org, Andrey Konovalov <andreyknvl@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski
 <luto@kernel.org>, Borislav Petkov <bp@alien8.de>,
 dave.hansen@linux.intel.com, Dmitriy Vyukov <dvyukov@google.com>,
 Eric Dumazet <edumazet@google.com>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>,
 Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>,
 Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>,
 Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>,
 the arch/x86 maintainers <x86@kernel.org>, linux-doc@vger.kernel.org,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 linux-arm-kernel@lists.infradead.org,
 Linux Memory Management List <linux-mm@kvack.org>
References: <20200907134055.2878499-1-elver@google.com>
 <4dc8852a-120d-0835-1dc4-1a91f8391c8a@suse.cz>
 <CAG_fn=UdnN4EL6OtAV8RY7kuqO+VXqSsf+grx2Le64UQJOUMvQ@mail.gmail.com>
From: Vlastimil Babka <vbabka@suse.cz>
Message-ID: <1c4a5a6e-1f11-b04f-ebd0-17919ba93bca@suse.cz>
Date: Tue, 8 Sep 2020 16:40:00 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.11.0
MIME-Version: 1.0
In-Reply-To: <CAG_fn=UdnN4EL6OtAV8RY7kuqO+VXqSsf+grx2Le64UQJOUMvQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

On 9/8/20 2:16 PM, Alexander Potapenko wrote:
>> Toggling a static branch is AFAIK quite disruptive (PeterZ will probably tell
>> you better), and with the default 100ms sample interval, I'd think it's not good
>> to toggle it so often? Did you measure what performance would you get, if the
>> static key was only for long-term toggling the whole feature on and off (boot
>> time or even runtime), but the decisions "am I in a sample interval right now?"
>> would be normal tests behind this static key? Thanks.
> 
> 100ms is the default that we use for testing, but for production it
> should be fine to pick a longer interval (e.g. 1 second or more).
> We haven't noticed any performance impact with neither 100ms nor bigger values.

Hmm, I see.

> Regarding using normal branches, they are quite expensive.
> E.g. at some point we used to have a branch in slab_free() to check
> whether the freed object belonged to KFENCE pool.
> When the pool address was taken from memory, this resulted in some
> non-zero performance penalty.

Well yeah, if the checks involve extra cache misses, that adds up. But AFAICS
you can't avoid that kind of checks with static key anyway (am I looking right
at is_kfence_address()?) because some kfence-allocated objects will exist even
after the sampling period ended, right?
So AFAICS kfence_alloc() is the only user of the static key and I wonder if it
really makes such difference there.

> As for enabling the whole feature at runtime, our intention is to let
> the users have it enabled by default, otherwise someone will need to
> tell every machine in the fleet when the feature is to be enabled.

Sure, but I guess there are tools that make it no difference in effort between 1
machine and fleet.

I'll try to explain my general purpose distro-kernel POV. What I like e.g. about
debug_pagealloc and page_owner (and contributed to that state of these features)
is that a distro kernel can be shipped with them compiled in, but they are
static-key disabled thus have no overhead, until a user enables them on boot,
without a need to replace the kernel with a debug one first. Users can enable
them for their own debugging, or when asked by somebody from the distro
assisting with the debugging.

I think KFENCE has similar potential and could work the same way - compiled in
always, but a static key would eliminate everything, even the
is_kfence_address() checks, until it became enabled (but then it would probably
be a one-way street for the rest of the kernel's uptime). Some distro users
would decide to enable it always, some not, but could be advised to when needed.
So the existing static key could be repurposed for this, or if it's really worth
having the current one to control just the sampling period, then there would be two?

Thanks.

>> > We have verified by running synthetic benchmarks (sysbench I/O,
>> > hackbench) that a kernel with KFENCE is performance-neutral compared to
>> > a non-KFENCE baseline kernel.
>> >
>> > KFENCE is inspired by GWP-ASan [1], a userspace tool with similar
>> > properties. The name "KFENCE" is a homage to the Electric Fence Malloc
>> > Debugger [2].
>> >
>> > For more details, see Documentation/dev-tools/kfence.rst added in the
>> > series -- also viewable here:
>> >
>> >       https://raw.githubusercontent.com/google/kasan/kfence/Documentation/dev-tools/kfence.rst
>> >
>> > [1] http://llvm.org/docs/GwpAsan.html
>> > [2] https://linux.die.net/man/3/efence
>> >
>> > Alexander Potapenko (6):
>> >   mm: add Kernel Electric-Fence infrastructure
>> >   x86, kfence: enable KFENCE for x86
>> >   mm, kfence: insert KFENCE hooks for SLAB
>> >   mm, kfence: insert KFENCE hooks for SLUB
>> >   kfence, kasan: make KFENCE compatible with KASAN
>> >   kfence, kmemleak: make KFENCE compatible with KMEMLEAK
>> >
>> > Marco Elver (4):
>> >   arm64, kfence: enable KFENCE for ARM64
>> >   kfence, lockdep: make KFENCE compatible with lockdep
>> >   kfence, Documentation: add KFENCE documentation
>> >   kfence: add test suite
>> >
>> >  Documentation/dev-tools/index.rst  |   1 +
>> >  Documentation/dev-tools/kfence.rst | 285 +++++++++++
>> >  MAINTAINERS                        |  11 +
>> >  arch/arm64/Kconfig                 |   1 +
>> >  arch/arm64/include/asm/kfence.h    |  39 ++
>> >  arch/arm64/mm/fault.c              |   4 +
>> >  arch/x86/Kconfig                   |   2 +
>> >  arch/x86/include/asm/kfence.h      |  60 +++
>> >  arch/x86/mm/fault.c                |   4 +
>> >  include/linux/kfence.h             | 174 +++++++
>> >  init/main.c                        |   2 +
>> >  kernel/locking/lockdep.c           |   8 +
>> >  lib/Kconfig.debug                  |   1 +
>> >  lib/Kconfig.kfence                 |  70 +++
>> >  mm/Makefile                        |   1 +
>> >  mm/kasan/common.c                  |   7 +
>> >  mm/kfence/Makefile                 |   6 +
>> >  mm/kfence/core.c                   | 730 +++++++++++++++++++++++++++
>> >  mm/kfence/kfence-test.c            | 777 +++++++++++++++++++++++++++++
>> >  mm/kfence/kfence.h                 | 104 ++++
>> >  mm/kfence/report.c                 | 201 ++++++++
>> >  mm/kmemleak.c                      |  11 +
>> >  mm/slab.c                          |  46 +-
>> >  mm/slab_common.c                   |   6 +-
>> >  mm/slub.c                          |  72 ++-
>> >  25 files changed, 2591 insertions(+), 32 deletions(-)
>> >  create mode 100644 Documentation/dev-tools/kfence.rst
>> >  create mode 100644 arch/arm64/include/asm/kfence.h
>> >  create mode 100644 arch/x86/include/asm/kfence.h
>> >  create mode 100644 include/linux/kfence.h
>> >  create mode 100644 lib/Kconfig.kfence
>> >  create mode 100644 mm/kfence/Makefile
>> >  create mode 100644 mm/kfence/core.c
>> >  create mode 100644 mm/kfence/kfence-test.c
>> >  create mode 100644 mm/kfence/kfence.h
>> >  create mode 100644 mm/kfence/report.c
>> >
>>
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1c4a5a6e-1f11-b04f-ebd0-17919ba93bca%40suse.cz.
