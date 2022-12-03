Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHH3VWOAMGQER7QRS5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id C07E56417DA
	for <lists+kasan-dev@lfdr.de>; Sat,  3 Dec 2022 17:47:26 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id p7-20020a631e47000000b0047691854a86sf6929937pgm.16
        for <lists+kasan-dev@lfdr.de>; Sat, 03 Dec 2022 08:47:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670086045; cv=pass;
        d=google.com; s=arc-20160816;
        b=gyoE6CiwxOkkknMwD/FHQyz2na+L9d0GUHH5mfG46NMbWCOXSTxFLF2GprBCP4ZSAI
         Eu/6UCecNwQcT7/i7KLkOV+Li5thg/VUVkpRc1Cf0QZxlxqIRCoH6hZpUhe4N6pJd82U
         1OzIqJ4QA6AHIXqgmnfDmHMlD0hDApXZ833dV8o9y6+QT2KtCtNfa86Zn8V0qy4ysogl
         0sehsHdjuB8NPorNs88YnOwSn/jGcuhO+7xpYZeVDGeosctDzss7zzrIxKjI4n0tpLsl
         Z6xIgZVcVQ2cQUS4FZakqcnJVd1TBW50C4MM1shMRy0d9OQiIevn2TmlIEGJyuAeRxAn
         n2SA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=uilKdIcRybj4gz036yAo73/FHSv8wvxutinxSTBWllg=;
        b=t/U33zKWkWK29WSF54axNEOI6QpKHQa1wyvBmCzwO+iuQK7+Cm0Ymi3mhc7XWF+rwr
         bpnpse8z4FaOE3ZIuFw6s5uc5mzu0RInketBRv9BAC2OmYLeyPE3oYG8Dn2HPyqZjPme
         4V2ynveNdjNL9gHd05NnA1RDHkalO0jvXSRZKjLezWfjSmbtD4/I+TzLf93sP4vpjqMG
         tgjQlg+TLc62LF2F2QEcjCtQRSmh7zyTZFQmI6OtVW+Du4+wk8iYAMRbklSdUExCIG8T
         IjPrxXlEc4qDece5tAg+oRtecDGO8ej9j0KyO0T2V1zRGwBXStnvy6gnT4O/2Qg+l6vi
         NuJQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tNkAN9J6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=uilKdIcRybj4gz036yAo73/FHSv8wvxutinxSTBWllg=;
        b=QMbcKqpvNp9ny0lZbXNNEsEjxchspBvEsWV37Iw5Nuak8zR9BOrNHL1lfUj9+Hegos
         3Inodmzp5UTjpCf/reFn+M8T2fNVA4RvtEUEjYyoq+gyv7hHuzWWhES7YBZPx6xJRnkX
         WDpynciif8bkzs2Gh8DQ+X4d09fgukqRPpmsR5pit5tAFJsWmFrYKbeUTUTbagOBF+xi
         WX60CpveM8oDhq4HY6TiURZO2750m7V5Of6rrjK/xH8hCtSjhjd/DuawgErMp3UQNRit
         PDV0TT1FsjE/evbaMMgLJQn8RDtOWr3Sj17/lc1xZENtPfqag+9Lpro+3pztootLfP1f
         8pjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=uilKdIcRybj4gz036yAo73/FHSv8wvxutinxSTBWllg=;
        b=jMjUfEbu2ZeSHC6av29h85WgRXav6wy+vq64mMmwf62yCxS87mmjv1PM27M4mHdB0s
         WA9wAaHrCWoc54/ISVEeRWGovRoBsrah+p1uKL3tTTkPIs8xzoFDCS7J99EB648lB+H0
         M0TNyTdWPWbWnyonLIqOrsWFIyF0r0xG5w+4+kxwpBzo0FuH1n4QGrUhZmXKy9rkRhdf
         bXKdWXPE7eTcNDNo+gMmtReniKYqdBxVVU6EmWZe2K3T1uf+L17NGCfQsOXXVPeyF1Kl
         nOpXBN6ZdOoLnaUxhYrQwiCDBBAZryoQYWFXIJxGMDc83KXLiI+O+ycUlvpn3zUcZM7n
         HXEg==
X-Gm-Message-State: ANoB5plv1y5cbyQAtCn6h3tOtb1IGafi15InAEuaYadX8qkWOkWStUES
	cFA1GiUwTF/R+JLdzOkH/wA=
X-Google-Smtp-Source: AA0mqf6QJ1geT+1mRPYt77BHT8o5Cl67oHR0nmTQ4cdqDFjtF1vIAP6RuqKPdVk2z5AvAFedUjZSow==
X-Received: by 2002:a17:902:f78c:b0:187:a98:7ee5 with SMTP id q12-20020a170902f78c00b001870a987ee5mr59544940pln.142.1670086044872;
        Sat, 03 Dec 2022 08:47:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2c97:0:b0:477:480a:16c0 with SMTP id s145-20020a632c97000000b00477480a16c0ls819804pgs.8.-pod-prod-gmail;
 Sat, 03 Dec 2022 08:47:24 -0800 (PST)
X-Received: by 2002:aa7:8d06:0:b0:576:8015:8540 with SMTP id j6-20020aa78d06000000b0057680158540mr5589146pfe.26.1670086043903;
        Sat, 03 Dec 2022 08:47:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670086043; cv=none;
        d=google.com; s=arc-20160816;
        b=02Al7i0m0kcfsRV5Xyq4xCYo9NeNyP0sgZ9ziRg6KWCbTyzAyuyRaKfoEfjz2XTgid
         Q6+s6zhyqSzeF94yz2g+1AxDU9k6MHlGqrpLJirTqpkpOH7s1e6WwcHC3B7XNxctm2WE
         6XnzZz4Zp7z2N5u9cqM3NWKfKO74b1ti8T+2u4Vp6WQ8Elsa2QmLY7/bDE0ctNXPZaCJ
         r+PtF5G8+TVNceYH7Q4bIkSgVnTeJsMQeci3OStsFzQlugITVkYDESr1aC73cT30r543
         heYqbQ6cWKyp55huBlO6QONNLb/UwjkYnGwmNv1XqF/tKHXEYrmJNDk638TTHw9NBkEj
         Owmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qn9rzwOPoUgx3KNCikSZW0olrpEdB8fhdwL7QqLBi74=;
        b=tbcD3jldPTu167FJ1pKzNinKaL3Gs+K3XZ8D8MjdXcg4dE/M6hBekDzM71GdgH+tYd
         OfZ8dB2i+DIoa7s62qPoiV7KZcBqwBXXRTKsIty6Vnv/RlzMh8sTSrDO9frVwlJdWpWR
         kqucViNhgnejcBQaXABpXep9htbO6qVtDMdnycSeH+e8y4oXxJz7ay9NsjT6ViXHx4W0
         ehOHnf7kkIH7ZkGbPfUt1uh7OfTvG9r062Omq+T8PbkafI9164bz/xCA9vFTa4n2iqui
         mtcVZbD4BFkKMZ7YtvG4rjLbqIYfoRmi8eeAALWdOZJpgPb0mVfBTSbKOk9/At3Xjs1R
         GfNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tNkAN9J6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id c5-20020a170902d48500b00186b3b9870fsi643331plg.11.2022.12.03.08.47.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 03 Dec 2022 08:47:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-3b10392c064so78474737b3.0
        for <kasan-dev@googlegroups.com>; Sat, 03 Dec 2022 08:47:23 -0800 (PST)
X-Received: by 2002:a05:690c:884:b0:37b:4a21:f86a with SMTP id
 cd4-20020a05690c088400b0037b4a21f86amr58483902ywb.465.1670086043315; Sat, 03
 Dec 2022 08:47:23 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
 <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
 <CA+G9fYs55N3J8TRA557faxvAZSnCTUqnUx+p1GOiCiG+NVfqnw@mail.gmail.com>
 <Y4e3WC4UYtszfFBe@codewreck.org> <CA+G9fYuJZ1C3802+uLvqJYMjGged36wyW+G1HZJLzrtmbi1bJA@mail.gmail.com>
 <Y4ttC/qESg7Np9mR@codewreck.org>
In-Reply-To: <Y4ttC/qESg7Np9mR@codewreck.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 3 Dec 2022 17:46:46 +0100
Message-ID: <CANpmjNNcY0LQYDuMS2pG2R3EJ+ed1t7BeWbLK2MNxnzPcD=wZw@mail.gmail.com>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
To: Dominique Martinet <asmadeus@codewreck.org>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, rcu <rcu@vger.kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, kunit-dev@googlegroups.com, 
	lkft-triage@lists.linaro.org, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Netdev <netdev@vger.kernel.org>, 
	Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tNkAN9J6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Sat, 3 Dec 2022 at 16:37, Dominique Martinet <asmadeus@codewreck.org> wrote:
>
> (reply out of order)
>
> Naresh Kamboju wrote on Thu, Dec 01, 2022 at 01:13:25PM +0530:
> > > (You might need to build with at least CONFIG_DEBUG_INFO_REDUCED (or not
> > > reduced), but that is on by default for aarch64)
> >
> > Thanks for the suggestions.
> > The Kconfig is enabled now.
> > CONFIG_DEBUG_INFO_REDUCED=y
>
> It looks enabled in your the config file you linked at, I don't
> understand this remark?
> Did you produce the trace the other day without it and rebuild the
> kernel with it?
> In this case you also have CONFIG_DEBUG_INFO_SPLIT set, so the vmlinux
> file does not contain enough informations to retrieve line numbers or
> types, and in particular addr2line cannot be used on the files you
> provided.
> I've never used split debug infos before, but digging old threads I'm
> not too hopeful unless that changed:
> https://lkml.iu.edu/hypermail/linux/kernel/1711.1/03393.html
> https://sourceware.org/bugzilla/show_bug.cgi?id=22434
>
> (...a test build later, it's still mostly useless...
> normal build
> $ ./scripts/faddr2line vmlinux __schedule+0x314
> __schedule+0x314/0x6c0:
> perf_fetch_caller_regs at include/linux/perf_event.h:1286
> (inlined by) __perf_sw_event_sched at include/linux/perf_event.h:1307
> (inlined by) perf_event_task_sched_out at include/linux/perf_event.h:1347
> (inlined by) prepare_task_switch at kernel/sched/core.c:5053
> (inlined by) context_switch at kernel/sched/core.c:5195
> (inlined by) __schedule at kernel/sched/core.c:6561
>
> split dwarf build
> $ ./scripts/faddr2line vmlinux __schedule+0x314
> aarch64-linux-gnu-addr2line: DWARF error: could not find abbrev number 860923
> __schedule+0x314/0x780:
> aarch64-linux-gnu-addr2line: DWARF error: could not find abbrev number 860923
> __schedule at core.c:?
>
> I'd tend to agree build time/space savings aren't worth the developer
> time.
> )
>
> Anyway, address sanitizer used to have a kasan_symbolize.py script but
> it looks like it got removed as no longer maintained, and I'm not sure
> what's a good tool to just run these logs through nowadays, might want
> to ask other test projects folks what they use...
>
> > > If you still have the vmlinux binary from that build (or if you can
> > > rebuild with the same options), running this text through addr2line
> > > should not take you too long.
> >
> > Please find build artifacts in this link,
> >  - config
> >  - vmlinux
> >  - System.map
> > https://people.linaro.org/~anders.roxell/next-20221130-allmodconfig-arm64-tuxmake-build/
>
> So from the disassembly...
>
>  - p9_client_cb+0x84 is right before the wake_up and after the wmb(), so
> I assume we're on writing req->status line 441:
>
> ---
> p9_client_cb(...)
> {
> ...
>         smp_wmb();
>         req->status = status;
>
>         wake_up(&req->wq);
> ---
>
> report is about a write from 2 to 3, this makes sense we're going from
> REQ_STATUS_SENT (2) to REQ_STATUS_RCVD (3).
>
>
>  - p9_client_rpc+0x1d0 isn't as simple to pin down as I'm having a hard
> time making sense of the kcsan instrumentations...
> The report is talking about a READ of 4 bytes at the same address, so
> I'd expect to see an ccess to req->status (and we're likely spot on
> wait_event_killable which checks req->status), but this doesn't seem to
> match up with the assembly: here's the excerpt from disass around 0x1d0
> = 464 (why doesn't gdb provide hex offsets..)
> ---
>    0xffff80000a46e9b8 <+440>:   cmn     w28, #0x200
>    0xffff80000a46e9bc <+444>:   ccmn    w28, #0xe, #0x4, ne  // ne = any
>    0xffff80000a46e9c0 <+448>:   b.eq    0xffff80000a46ecfc <p9_client_rpc+1276>  // b.none
>    0xffff80000a46e9c4 <+452>:   mov     x0, x25
>    0xffff80000a46e9c8 <+456>:   bl      0xffff800008543640 <__tsan_write4>
>    0xffff80000a46e9cc <+460>:   mov     w0, #0x2                        // #2
>    0xffff80000a46e9d0 <+464>:   str     w0, [x21, #88]
>    0xffff80000a46e9d4 <+468>:   b       0xffff80000a46ecfc <p9_client_rpc+1276>
>    0xffff80000a46e9d8 <+472>:   mov     w27, #0x1                       // #1
>    0xffff80000a46e9dc <+476>:   mov     x0, x23
>    0xffff80000a46e9e0 <+480>:   mov     w1, #0x2bc                      // #700
>    0xffff80000a46e9e4 <+484>:   bl      0xffff800008192d80 <__might_sleep>
> ---
>
> +464 is a write to x21 (client 'c', from looking at how it is passed
> into x0 for other function calls) at offset 88 (status field according
> to dwarf infos from a rebuild with your config/same sources)
>
> So, err, I'm a bit lost on this side.
> But I can't really find a problem with what KCSAN complains about --
> we are indeed accessing status from two threads without any locks.
> Instead of a lock, we're using a barrier so that:
>  - recv thread/cb: writes to req stuff || write to req status
>  - p9_client_rpc: reads req status || reads other fields from req
>
> Which has been working well enough (at least, without the barrier things
> blow up quite fast).
>
> So can I'll just consider this a false positive, but if someone knows
> how much one can read into this that'd be appreciated.

The barriers only ensure ordering, but not atomicity of the accesses
themselves (for one, the compiler is well in its right to transform
plain accesses in ways that the concurrent algorithm wasn't designed
for). In this case it looks like it's just missing
READ_ONCE()/WRITE_ONCE().

A (relatively) quick primer on the kernel's memory model and
where/what/how we need to "mark" accesses:
https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNcY0LQYDuMS2pG2R3EJ%2Bed1t7BeWbLK2MNxnzPcD%3DwZw%40mail.gmail.com.
