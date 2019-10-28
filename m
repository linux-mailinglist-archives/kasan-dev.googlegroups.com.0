Return-Path: <kasan-dev+bncBDQ27FVWWUFRBRMH3HWQKGQEYXAT7NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 949A6E6A77
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 02:26:30 +0100 (CET)
Received: by mail-il1-x13d.google.com with SMTP id j68sf8086770ili.15
        for <lists+kasan-dev@lfdr.de>; Sun, 27 Oct 2019 18:26:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572225989; cv=pass;
        d=google.com; s=arc-20160816;
        b=wGK1b2JifZQ5TkgGUUM/Pay9x+Gq6eL4PZgzsGUyco04B25Kkp8BWjqhVE5QD7ivaj
         kreQDvXJYVI9g85p0MMbI4UtpVTuJrB596JRDp3c760zcysZdh2VG7yY966zt+WlFHJo
         BASgSDyKbp4IuUh6lAo/ufSoB5c24RQqLOk1cHomZFKIUzLd1zkEeR5XUCpQmpok/2WJ
         ToFfiZi8IJCQKmR5h6cG3cg9eySJkT4vsB/4G2d/XgKSXsTmwIxMCbMFWpLLYvQ8UM6X
         rMH3DfmlTRpRUCHDGRbntFfq97v4GNpjDaUDkaFcKTfos3Sg0G9Z+yS5pmwfYz3e4wOX
         2PXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=Z/3FT/DQEy0KOnSU2eXzF4W7stUM2t6xAiJwK5VU1XA=;
        b=Un46gUABcUxkQo5BhuAWGYmtZvkAUPi41siooCxWx/5w3oj4wnfuPSAGKJAOmpZuB4
         NdC9K2faPqqWfTMP6qpAs5pZXMamtLXFk7fvMPVU+TIabGRmMeZHaMNlQLg9hbV8HoyG
         maKkNGNSzAXZOK41zcF840mcztAodiUPF9c5sU3bPnJAvVrHpikHQbVbKLBFpYBKrNga
         vaW+ogrTohuQYnYsAJ8pjT2S8SgedewJD1ZpqwELiqkRC2eVKjxTUGZhTs6uyEi+OXLf
         pWfP3L04gbthHMYI05LGoqkVSRuH1tW22m4QAd4Ueg87lTuemWF6Nf57+sCGL39HgtzN
         xMgQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=G8EDPx8d;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z/3FT/DQEy0KOnSU2eXzF4W7stUM2t6xAiJwK5VU1XA=;
        b=STG1pXkvU0RaxT8oNAgL/l9XIh2KWYEttV8/uz3fm2ykNr0Dawq6yj+/bQwT+1xMwK
         mx2TnCtwQp8DebjDmRbAd4gP3TZbp3pjJaHXEk2C/5qyyIlRIQt3XhE4S33Lxrn3y34Z
         ODcqlCmwW24NN4VV/GXrX5ruq3WExaqriZ0QfBV32T2R3ZPYePB+cychrMYuHzzZcoHP
         bK6T32soMQO+FIfWxQOoxsxVahjIuIFYAqeoWhjVp8MrOh2TayMY5JKFbt/TZzKw9x5V
         8NOFajWDmGE1+jCbWRyMALo/cRE6RxRD1XqlBtI2JSabcFTVGEQIcItdq9xEUjVDk5Wi
         uYww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Z/3FT/DQEy0KOnSU2eXzF4W7stUM2t6xAiJwK5VU1XA=;
        b=aLgCSIopP4v0GXKmw5Zj5qXHLCazKigAdMaHyZr+WjGDEzInqwR+XK758iGsDmZsxt
         m3oH0pkGzPPDpwIiwVRWlANk+r8VXB3r9w02eYXGP7YlJ+xw/qCwZSZmd6SbcL+LIvHp
         rs7PqHphvx87QQJBc+HQk3ex6EGlHo5/R+R1i7Ipdou5p2SO8c+2nQ2SbL9uumE+RfQj
         0zHgw6y9LLiKGL6AHztvJIkJ0wGzjWBNPmZWTJORYtW2/W4xxMq4x2vGbXTNb0MX3ZQi
         ro3ecS0GkS4RfvDqhaLIZWLN/lNTSyqWPEqs0gZLiz7gfD5kdG19aPIwBYunKaJ9U/Gh
         HvYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVrG8hhMwvpl8p0VYjeliDyfrJaKonpk9DNvtXiqolIodsgYgfN
	2uUsSEVURVLivdG69bFBvuc=
X-Google-Smtp-Source: APXvYqx9rxMBqCrgkXZqzLkqs6sfqb44jCDqNRinfGyI+BEJEvuiwiLW4qgCRMJ6nwBTawzttPQ8ew==
X-Received: by 2002:a92:b105:: with SMTP id t5mr17718764ilh.299.1572225989284;
        Sun, 27 Oct 2019 18:26:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c142:: with SMTP id b2ls1846348ilh.9.gmail; Sun, 27 Oct
 2019 18:26:28 -0700 (PDT)
X-Received: by 2002:a92:d78f:: with SMTP id d15mr15877497iln.294.1572225988850;
        Sun, 27 Oct 2019 18:26:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572225988; cv=none;
        d=google.com; s=arc-20160816;
        b=j3P/2X4k7PNG3JtJ4N3JvOSagQiRSeYNZBD3OF6iK/9uyODBmM1fH3bXU4XEX7Aj8a
         QUHVtsSLGi0lXh9zKX1RQm6UMJW8fljRmG/5u/JD5f+sGrJxNxrJ74et/tCC4/HeD62T
         DgXLmpkFLJWZi+vjNsbGiiaWYekQPESjyzWiLDixBsFO0LZA/Gw4ImWqTv847Aayydgw
         3yoPaK4G/XK2t0e/da+FoKZTvkRiBZiLk8AXHNrfHEOgbaCmphzmD2RBjt0MWjSlROH9
         DySBTi1+e7EC6Tk48/wU9ckN69eUn6yueRwBnwLYKecXQJT+m1rWfD7DOjUq2BSWuUg3
         jTDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=ritRVlb0ULtaryMtuft6JkNqY9ganMcK1V8vqfjCnBA=;
        b=IdZAQV7JmonG7lMq6nmwut22moROc6RYLiaIe3CBTKvcp6uyzk+UuJm03q00z58LDH
         fYDmDc+XiAefjpWzb7WRmKUXGlTj0lkGqhRxGWFB2NwRcEUho8mg/1iiWqhYstOTZ6Ea
         GWn0RgOeZHuj0LW2Tzkcfzs3//1gxMJtJIKrHo46lg6Hjm+v3HXjDFoOmFQyXeAvJ9x5
         2bKAwW88cBOTGOsXctTT5sZFxscD3bpmcHUkhEfJtgfYZkbcNVQHPpWfh0gcvw6nHnYx
         Rd3JALrIh7B/sZsSZG1fgvK3y8lmLCqr1DrwNmeQMUCw4iHY2LztknrT+xV8BPFWCo+5
         RH0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=G8EDPx8d;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id f5si32543iof.4.2019.10.27.18.26.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 27 Oct 2019 18:26:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id q26so2052913pfn.11
        for <kasan-dev@googlegroups.com>; Sun, 27 Oct 2019 18:26:28 -0700 (PDT)
X-Received: by 2002:aa7:9f86:: with SMTP id z6mr17999776pfr.102.1572225988198;
        Sun, 27 Oct 2019 18:26:28 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id w27sm6775067pgc.20.2019.10.27.18.26.26
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 27 Oct 2019 18:26:27 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com, christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20191016132233.GA46264@lakrids.cambridge.arm.com>
References: <20191001065834.8880-1-dja@axtens.net> <20191001065834.8880-2-dja@axtens.net> <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com> <87ftjvtoo7.fsf@dja-thinkpad.axtens.net> <8f573b40-3a5a-ed36-dffb-4a54faf3c4e1@virtuozzo.com> <20191016132233.GA46264@lakrids.cambridge.arm.com>
Date: Mon, 28 Oct 2019 12:26:23 +1100
Message-ID: <87eeyx8xts.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=G8EDPx8d;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Mark and Andrey,

I've spent some quality time with the barrier documentation and
all of your emails.

I'm still trying to puzzle out the barrier. The memory model
documentation doesn't talk about how synchronisation works when a
page-table walk is involved, so that's making things hard. However, I
think I have something for the spurious fault case. Apologies for the
length, and for any mistakes!

I am assuming here that the poison and zeros and PTEs are correctly
being stored and we're just concerned about whether an architecturally
correct load can cause a spurious fault on x86.

> There is the risk (as laid out in [1]) that CPU 1 attempts to hoist the
> loads of the shadow memory above the load of the PTE, samples a stale
> (faulting) status from the TLB, then performs the load of the PTE and
> sees a valid value. In this case (on arm64) a spurious fault could be
> taken when the access is architecturally performed.
>
> It is possible on arm64 to use a barrier here to prevent the spurious
> fault, but this is not smp_read_barrier_depends(), as that does nothing
> for everyone but alpha. On arm64 We have a spurious fault handler to fix
> this up.

Will's email has the following example:

	CPU 0				CPU 1
	-----				-----
	spin_lock(&lock);		spin_lock(&lock);
	set_fixmap(0, paddr, prot);	if (mapped)
	mapped = true;				foo = *fix_to_virt(0);
	spin_unlock(&lock);		spin_unlock(&lock);


If I understand the following properly, it's because of a quirk in
ARM, the translation of fix_to_virt(0) can escape outside the lock:

>   DDI0487E_a, B2-125:
> 
>   | DMB and DSB instructions affect reads and writes to the memory system
>   | generated by Load/Store instructions and data or unified cache maintenance
>   | instructions being executed by the PE. Instruction fetches or accesses
>   | caused by a hardware translation table access are not explicit accesses.
> 
> which appears to claim that the DSB alone is insufficient. Unfortunately,
> some CPU designers have followed the second clause above, whereas in Linux
> we've been relying on the first. This means that our mapping sequence:
> 
> 	MOV	X0, <valid pte> 
> 	STR	X0, [Xptep]	// Store new PTE to page table
> 	DSB	ISHST
> 	LDR	X1, [X2]	// Translates using the new PTE
> 
> can actually raise a translation fault on the load instruction because the
> translation can be performed speculatively before the page table update and
> then marked as "faulting" by the CPU. For user PTEs, this is ok because we
> can handle the spurious fault, but for kernel PTEs and intermediate table
> entries this results in a panic().

So the DSB isn't sufficient to stop the CPU speculating the
_translation_ above the page table store - to do that you need an
ISB. [I'm not an ARM person so apologies if I've butchered this!] Then
the load then uses the speculated translation and faults.

So, do we need to do something to protect ourselves against the case of
these sorts of spurious faults on x86? I'm also not an x86 person, so
again apologies in advance if I've butchered anything.

Firstly, it's not trivial to get a fixed address from the vmalloc
infrastructure - you have to do something like
__vmalloc_node_range(size, align, fixed_start_address, fixed_start_address + size, ...)
I don't see any callers doing that. But we press on just in case.

Section 4.10.2.3 of Book 3 of the Intel Developers Manual says:

 | The processor may cache translations required for prefetches and for
 | accesses that are a result of speculative execution that would never
 | actually occur in the executed code path.

That's all it says, it doesn't say if it will cache a negative or
faulting lookup in the speculative case. However, if you _could_ cache
a negative result, you'd hope the documentation on when to invalidate
would tell you. That's in 4.10.4.

4.10.4.3 Optional Invalidations includes:

 | The read of a paging-structure entry in translating an address being
 | used to fetch an instruction may appear to execute before an earlier
 | write to that paging-structure entry if there is no serializing
 | instruction between the write and the instruction fetch. Note that
 | the invalidating instructions identified in Section 4.10.4.1 are all
 | serializing instructions.

That only applies to _instruction fetch_, not data fetch. There's no
corresponding dot point for data fetch, suggesting that data fetches
aren't subject to this.

Lastly, arch/x86's native_set_pte_at() performs none of the extra
barriers that ARM does - this also suggests to me that this isn't a
concern on x86. Perhaps page-table walking for data fetches is able to
snoop the store queues, and that's how they get around it.

Given that analysis, that x86 has generally strong memory ordering, and
the lack of response to Will's email from x86ers, I think we probably do
not need a spurious fault handler on x86. (Although I'd love to hear
from any actual x86 experts on this!) Other architecture enablement will
have to do their own analysis.

As I said up top, I'm still puzzling through the smp_wmb() discussion
and I hope to have something for that soon.

Regards,
Daniel

>
> Thanks,
> Mark.
>
> [1] https://lore.kernel.org/linux-arm-kernel/20190827131818.14724-1-will@kernel.org/
> [2] https://lore.kernel.org/linux-mm/20191014152717.GA20438@lakrids.cambridge.arm.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87eeyx8xts.fsf%40dja-thinkpad.axtens.net.
