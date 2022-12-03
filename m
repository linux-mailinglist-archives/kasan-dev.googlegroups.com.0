Return-Path: <kasan-dev+bncBCII7JXRXUGBBJG2VWOAMGQEP6V7PQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 9718E64178A
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Dec 2022 16:37:09 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id e15-20020a05651c038f00b0027740a4e92fsf1645088ljp.16
        for <lists+kasan-dev@lfdr.de>; Sat, 03 Dec 2022 07:37:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670081829; cv=pass;
        d=google.com; s=arc-20160816;
        b=ETjPaQYAdJx9aouZ6RgZoWG346ZfqjqKT25JygT7wBsz255fuauYw2c2HjzguCg2G2
         g8+vu3mcW5PRrUuYfuUXTf0LMYpJP4nzgcXWeubhZ+JXw3f5GjJdb/MaYjV79/JsGrJi
         ATA7zUdYm/gecE92oOMOfXddLJJ1Yvsjk9rrW+o146Nok490iiw+FJFIBlyYiLwS9dQC
         Gypm+bZHpwQ0NdoRe9N7m+MF2I/XWyGvkGvNeWOENMDrF7rTM/UUbdq1hBOaHp/jr242
         JwbxOzCtk3GYIXiqi+FOO/Cf7xQ1cXG7xWKCCKgZL/ssgytnQUfgtOrl5DJjZTy/eiq1
         lTsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=/46lRvSNNSCOjMW2zo/k0ChBuI0BMsyaDeRqExnheTg=;
        b=LMNFvTKxFP3DTtPs1UM6IWXOI1f4H5bQORwiXQ1Spb5qpMNYDG9m8sgq4/UBtDWmLV
         rvYT7P588tYReYmyLWrW5EVIksksl79V0qcu9d83nf1xxgqeGMAWgX0KKzOT/2xSRElk
         tIvWXL50aFFODgKWcBCc0uHXu0v+NinDNTMfJzwwr7QqKD1L6tlzv82P1Xjclp1ukK01
         u5QuQU1JkW1pfk6WqeEgPW9plGUPJCqGQXsuYfeHxjCGXvjgiqXf5CLfX13mg970tDrr
         GwaKROqpC7bxD8n9zVoNyyqlA+CZuIs82XSmHneTdkCAzXOi9D4OCoQPvgW9gU/EpvaQ
         zXKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=WriWQeJs;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=unUT9ds9;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=/46lRvSNNSCOjMW2zo/k0ChBuI0BMsyaDeRqExnheTg=;
        b=LOHbyVwYSnKcSnFPeYCHk49THDddmOKtp1PKIVu+1i9U+H5/u0ZUukavwzpYTZ/jCM
         lnOgdHLTyYh1eD9s7wYwjmR3FsYkxdYtN5BOzxtYR6i82XDm+gBxsnB+C9OpZ7ftHut5
         RaLvF5+qBk51bvbdfyOEWmc3hOxZxBqXrkuwpclwNJVEs9qGX6MlCYuZ/rmvwcuSNiQW
         YUhkqitDXQI/NurLtDJIlaO1Y7DOrbZ5RHbMeXwYbOLexzzuSfRt2kccjC3KBPHxCjvz
         P50ktlh9i8ZdwtMSK4ffXmAkuaCoheMG3GOsb5ZZlZEPvveGqbrmXN8cdUGFeOGhlGtO
         9dZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=/46lRvSNNSCOjMW2zo/k0ChBuI0BMsyaDeRqExnheTg=;
        b=MDQ25jLr//V4g0ck9Fa1ozQ4JcEFAw+RadaUfrPgEWXB2o5HS2kMqR4yHRutZDNs9B
         SNoLCFR6bvEp0UtAikIKKOnMYpKj8gYJyhK5/8igvZVFcsx0cH4iOOT1UnUa6vxQvoWC
         Z3nMA12B1wqFQem0xU+doery0/zC/dfmiCXuiAbRJcd8FkfsP5cJO/GJ0MKAgkFs/iqa
         1FEF+nGDSPDxsO3IjOeRWdWm6YnWLq3ktiz5XVy4Q7wvmxx49N+0tB/HsxqIYAiDazNE
         rANb0yABp/pNahJUMxUx3qTXU9o2TRJlP9l9fDtjEPiCH/4sqD0JuY9FRmsCrNcYu8ge
         b79Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pm5QRluNzoGJ1XjjMD0sVHWQPQYWKxR6XEQl8+x/2/NEi0k15Ej
	4yqEdzJf7wmDtg/dsFTaZvw=
X-Google-Smtp-Source: AA0mqf4NQZwyInNjF8ELm2JotyPXIx2K/cEcmhHsthS9wElxGF9rpVTuYRSuPl9om8fuVlXUjeVVyA==
X-Received: by 2002:a2e:a265:0:b0:26d:ee99:93b4 with SMTP id k5-20020a2ea265000000b0026dee9993b4mr19313669ljm.329.1670081828661;
        Sat, 03 Dec 2022 07:37:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a26b:0:b0:277:22e9:929f with SMTP id k11-20020a2ea26b000000b0027722e9929fls196978ljm.5.-pod-prod-gmail;
 Sat, 03 Dec 2022 07:37:07 -0800 (PST)
X-Received: by 2002:a05:651c:503:b0:277:dba:2f65 with SMTP id o3-20020a05651c050300b002770dba2f65mr19746701ljp.201.1670081827240;
        Sat, 03 Dec 2022 07:37:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670081827; cv=none;
        d=google.com; s=arc-20160816;
        b=KDvVmSt40zUpyJ1KrFLAc2TvgnUr7saWohyYzUdC5iMbuXN12uAGRKqbFc9asZ4EBy
         RrIubcqJtsLy+cV23BLO0ow2eqvy9InMMqQkV6bV/MJUNFLOF1zO1723R3HDHHuBm4eZ
         AXzOLoTXdMs/oXX3vsQjFxfd+WQuVGkRUyf0uOaI9Bw/jBwZinDArA+a1YImgb9oIbx/
         8kgN6ZxnIl1eOkr3NrznW9BB8KGqOQA6O9ve/xbUT+WCCSxVeIrOPSQ0gbyFQsqWCZUy
         vxGo3TvnYdKhJMGePLOryoZ4kJYNT0PyYkbbKnBzYUGGHXH6sOlNpEMSpv/cXBoV4vz0
         2/Ww==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=8+/C65NBDY0v0RW89Yk+KvRuOiE5ckvyFprjWMjz5YY=;
        b=0anfxT5RmhA53U6+g2SdhotdWqsJDHuvcpWAVD1Pcn9WbovAirUK+hqTD8GEXDsLIV
         dHpBEGc+aszeisHXoJ+QJ6ICfyt2pdxGJRetgCZFVco6bApGQylznJD8vGTW1Fv47dZe
         dJi+YJwXWYmoaguXC3DCHV5hvOrGaJ4KYtWeusd0o8oHmTOs9CpCp8Ln0OgkSHHdCWYc
         AFo1t3SDtekvLywOVrvR97MzcX0j3RjRu5HfVu1L9swkYFlnfgzMBZQ2snHqFSe780eu
         vOByXyR+XJy4d8UfvYqlwHKlFdWjQlCN3Y3BdGEWen4g4Gas93evAW8DnFclmQeRZWX6
         Pjfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=WriWQeJs;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=unUT9ds9;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
Received: from nautica.notk.org (nautica.notk.org. [91.121.71.147])
        by gmr-mx.google.com with ESMTPS id p14-20020a2ea4ce000000b0027760dd5b20si411568ljm.3.2022.12.03.07.37.06
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 03 Dec 2022 07:37:07 -0800 (PST)
Received-SPF: pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) client-ip=91.121.71.147;
Received: by nautica.notk.org (Postfix, from userid 108)
	id 78299C01C; Sat,  3 Dec 2022 16:37:15 +0100 (CET)
X-Spam-Checker-Version: SpamAssassin 3.3.2 (2011-06-06) on nautica.notk.org
X-Spam-Level: 
X-Spam-Status: No, score=0.0 required=5.0 tests=UNPARSEABLE_RELAY
	autolearn=unavailable version=3.3.2
Received: from odin.codewreck.org (localhost [127.0.0.1])
	by nautica.notk.org (Postfix) with ESMTPS id 2E939C009;
	Sat,  3 Dec 2022 16:37:10 +0100 (CET)
Received: from localhost (odin.codewreck.org [local])
	by odin.codewreck.org (OpenSMTPD) with ESMTPA id 2ef2e6a7;
	Sat, 3 Dec 2022 15:36:58 +0000 (UTC)
Date: Sun, 4 Dec 2022 00:36:43 +0900
From: Dominique Martinet <asmadeus@codewreck.org>
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: Marco Elver <elver@google.com>, rcu <rcu@vger.kernel.org>,
	open list <linux-kernel@vger.kernel.org>,
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Netdev <netdev@vger.kernel.org>,
	Anders Roxell <anders.roxell@linaro.org>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb /
 p9_client_rpc
Message-ID: <Y4ttC/qESg7Np9mR@codewreck.org>
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
 <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
 <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com>
 <Y4e3WC4UYtszfFBe@codewreck.org>
 <CA+G9fYuJZ1C3802+uLvqJYMjGged36wyW+G1HZJLzrtmbi1bJA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+G9fYuJZ1C3802+uLvqJYMjGged36wyW+G1HZJLzrtmbi1bJA@mail.gmail.com>
X-Original-Sender: asmadeus@codewreck.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=WriWQeJs;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=unUT9ds9;       spf=pass
 (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as
 permitted sender) smtp.mailfrom=asmadeus@codewreck.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
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

(reply out of order)

Naresh Kamboju wrote on Thu, Dec 01, 2022 at 01:13:25PM +0530:
> > (You might need to build with at least CONFIG_DEBUG_INFO_REDUCED (or not
> > reduced), but that is on by default for aarch64)
> 
> Thanks for the suggestions.
> The Kconfig is enabled now.
> CONFIG_DEBUG_INFO_REDUCED=y

It looks enabled in your the config file you linked at, I don't
understand this remark?
Did you produce the trace the other day without it and rebuild the
kernel with it?
In this case you also have CONFIG_DEBUG_INFO_SPLIT set, so the vmlinux
file does not contain enough informations to retrieve line numbers or
types, and in particular addr2line cannot be used on the files you
provided.
I've never used split debug infos before, but digging old threads I'm
not too hopeful unless that changed:
https://lkml.iu.edu/hypermail/linux/kernel/1711.1/03393.html
https://sourceware.org/bugzilla/show_bug.cgi?id=22434

(...a test build later, it's still mostly useless...
normal build
$ ./scripts/faddr2line vmlinux __schedule+0x314
__schedule+0x314/0x6c0:
perf_fetch_caller_regs at include/linux/perf_event.h:1286
(inlined by) __perf_sw_event_sched at include/linux/perf_event.h:1307
(inlined by) perf_event_task_sched_out at include/linux/perf_event.h:1347
(inlined by) prepare_task_switch at kernel/sched/core.c:5053
(inlined by) context_switch at kernel/sched/core.c:5195
(inlined by) __schedule at kernel/sched/core.c:6561

split dwarf build
$ ./scripts/faddr2line vmlinux __schedule+0x314
aarch64-linux-gnu-addr2line: DWARF error: could not find abbrev number 860923
__schedule+0x314/0x780:
aarch64-linux-gnu-addr2line: DWARF error: could not find abbrev number 860923
__schedule at core.c:?

I'd tend to agree build time/space savings aren't worth the developer
time.
)

Anyway, address sanitizer used to have a kasan_symbolize.py script but
it looks like it got removed as no longer maintained, and I'm not sure
what's a good tool to just run these logs through nowadays, might want
to ask other test projects folks what they use...

> > If you still have the vmlinux binary from that build (or if you can
> > rebuild with the same options), running this text through addr2line
> > should not take you too long.
> 
> Please find build artifacts in this link,
>  - config
>  - vmlinux
>  - System.map
> https://people.linaro.org/~anders.roxell/next-20221130-allmodconfig-arm64-tuxmake-build/

So from the disassembly...

 - p9_client_cb+0x84 is right before the wake_up and after the wmb(), so
I assume we're on writing req->status line 441:

---
p9_client_cb(...)
{
...
        smp_wmb();
        req->status = status;

        wake_up(&req->wq);
---

report is about a write from 2 to 3, this makes sense we're going from
REQ_STATUS_SENT (2) to REQ_STATUS_RCVD (3).


 - p9_client_rpc+0x1d0 isn't as simple to pin down as I'm having a hard
time making sense of the kcsan instrumentations...
The report is talking about a READ of 4 bytes at the same address, so
I'd expect to see an ccess to req->status (and we're likely spot on
wait_event_killable which checks req->status), but this doesn't seem to
match up with the assembly: here's the excerpt from disass around 0x1d0
= 464 (why doesn't gdb provide hex offsets..)
---
   0xffff80000a46e9b8 <+440>:	cmn	w28, #0x200
   0xffff80000a46e9bc <+444>:	ccmn	w28, #0xe, #0x4, ne  // ne = any
   0xffff80000a46e9c0 <+448>:	b.eq	0xffff80000a46ecfc <p9_client_rpc+1276>  // b.none
   0xffff80000a46e9c4 <+452>:	mov	x0, x25
   0xffff80000a46e9c8 <+456>:	bl	0xffff800008543640 <__tsan_write4>
   0xffff80000a46e9cc <+460>:	mov	w0, #0x2                   	// #2
   0xffff80000a46e9d0 <+464>:	str	w0, [x21, #88]
   0xffff80000a46e9d4 <+468>:	b	0xffff80000a46ecfc <p9_client_rpc+1276>
   0xffff80000a46e9d8 <+472>:	mov	w27, #0x1                   	// #1
   0xffff80000a46e9dc <+476>:	mov	x0, x23
   0xffff80000a46e9e0 <+480>:	mov	w1, #0x2bc                 	// #700
   0xffff80000a46e9e4 <+484>:	bl	0xffff800008192d80 <__might_sleep>
---

+464 is a write to x21 (client 'c', from looking at how it is passed
into x0 for other function calls) at offset 88 (status field according
to dwarf infos from a rebuild with your config/same sources)

So, err, I'm a bit lost on this side.
But I can't really find a problem with what KCSAN complains about --
we are indeed accessing status from two threads without any locks.
Instead of a lock, we're using a barrier so that:
 - recv thread/cb: writes to req stuff || write to req status
 - p9_client_rpc: reads req status || reads other fields from req

Which has been working well enough (at least, without the barrier things
blow up quite fast).

So can I'll just consider this a false positive, but if someone knows
how much one can read into this that'd be appreciated.


Thanks,
--
Dominique

 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y4ttC/qESg7Np9mR%40codewreck.org.
