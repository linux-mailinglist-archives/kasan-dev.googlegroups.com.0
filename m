Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NX6DXAKGQEOCOYDEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 46C6A109370
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Nov 2019 19:22:47 +0100 (CET)
Received: by mail-ot1-x33a.google.com with SMTP id a10sf3147602oto.14
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Nov 2019 10:22:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574706166; cv=pass;
        d=google.com; s=arc-20160816;
        b=E1ufiXx40M2cXsZOIcQcITNNbVKU/Ow1mvBCPa3h9DrxTzrB+9ixbwbrwJxjbHVnbA
         0hPKI+dBPvq8/D+opUczlhJBdLSZHKACXBuGiI6DrEhbjTMKzLp2zsKGujryspNwMAao
         d/EG8nwTy04voHkIxHCOdd/M2xGIWRd1vCXCA9UWPVItJ76rk+kReT+uoeT32DByWddf
         3mOerug0dR4uBpzMEYVc1JqEbPcQb6pbse2dV9cG3u+ivQasG2q1fHQ4GvAleLeunklW
         zrwRzurv9j35dGeLwDbdyfymDURy/WRt5QIIGxmPtrzkJNS8820DIvtO9Wmp3u9IlsiC
         Z+hA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Jm7pQguobTQL5wTKK7PB26pmBbsOOpzQY3M5dgtSH/M=;
        b=IMaaUEKrC5uwAILBysjr/wdcD6EVTft0RyIuM/DUMLx0S96D78iL5prPsO+ZyxhRPi
         dSHE2ijyBY/yLAZdDjU1rOtR8QY6wIpZjJHez2r4Zdi+m7SkBS45HvM/S8wS2ypjIR5g
         YPaBTpb15/avrsD0OM8P4CPWK2w7nyYtyDU+M4/2ZVLXMCTRS24knVYXbHmYT61JHaat
         wXl3n01SIc0oLsEmex1pbNsisKVrayyvPYB/CyaAIZ8YagVdjlcqTizu3wLX3Gb1X2b6
         RHCTXaqdrKJHWuAztzAbElpJ138GBXDuM8AB01YONx+vcsNfEfk69Ydd/9N0U50ryDEh
         uO6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W+isNVQp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jm7pQguobTQL5wTKK7PB26pmBbsOOpzQY3M5dgtSH/M=;
        b=f5F2BGLVKxbcZTH4MThZgNW1noYappuZC6uwOQ+TDJo6KM1sSGNY51O1yRw1u4knoK
         GU4cWQ8FFBieYfJ5oseRMBZUs472IcvOpNh5vCc7L+2DAdZVIomBWb5CIpnFNEApmd72
         8mwXi42RJ8dENdiTmKNMk6PcghQ3V/MoivtgYIBxDIshRuQlKvzsQZoDeMqJsxWbXwya
         l39bLUWHp8ixe8IMORb+z7P7z0C4ALh/oufoCxsRvbpqT6JZrJF1R45/7pnWON1W/Rqs
         Rp3zVONV6v/zMYGw7gpPoNAT8DNvDI+D3V3xMU16vENeVaXPgO/2p/L44rIrp+A8H81Y
         bPYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jm7pQguobTQL5wTKK7PB26pmBbsOOpzQY3M5dgtSH/M=;
        b=nj6o9M961bgQYoqyJSwAzfvumBOco3OlZlL5APoz3GecCckL0sHxnTS10g96O7T0Cq
         wvWyGH5090nwbun6X2LFqlvLlIfvVj+vOPymcbWehKRj13l+PsRQRJF/W0/CtBvR2hKC
         XTazVmy3Lltjwny2D5mc0JL+rt68yZ7IpT3nsSQ0BrDezUqSlebLaFiXY4ZOdVkaRE0G
         OQ4RizhB1AIkyPRXEw1hp5/p/3jxJEikuZ2kRx67G8chYAhSDLZ/eE4c07Ei7WSDlWW1
         e62XqIfm51+8UNdEyk9pzioBR2JZdGn0O2EJX3BC8tiWQtTlL81FKI9CR9EdlF1dV7Y4
         Ao+Q==
X-Gm-Message-State: APjAAAWmdFgwcNeWMqITz99PN9Jg8Oi0SCfJaao2v/dEYdW9/cL0e3uF
	xHNKNjrT54ST2SxcdT3Ndxw=
X-Google-Smtp-Source: APXvYqxUEYrxZxCgqg2/VHctQ4fTXzZ0XLwx0EH7yVKtEZ5fSDRetCywN+4BKFlLCHv9jXvAD78UvA==
X-Received: by 2002:a05:6830:1e4a:: with SMTP id e10mr20321205otj.354.1574706166029;
        Mon, 25 Nov 2019 10:22:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4793:: with SMTP id u141ls2831941oia.10.gmail; Mon, 25
 Nov 2019 10:22:45 -0800 (PST)
X-Received: by 2002:a05:6808:901:: with SMTP id w1mr172326oih.57.1574706165589;
        Mon, 25 Nov 2019 10:22:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574706165; cv=none;
        d=google.com; s=arc-20160816;
        b=EV5J7dDYrOD4BJtUmeYEid/GWfxgaYACAhwPWhm5thUQJ9ijacjoM8l4tVEFEz2Tx3
         3hsIDE1CndZLGWKeVjG2zRr14Q05XQZVxMj+0qoBraHUjoDyzuxHleKwh5iEWgNZzdHg
         Ly/UBNNZVnvAvf54glrg7JSH4UCWxJJMSVt4S/XjW729UswnnJ29aW02elRi2op/gMZ3
         mjtCy4pQblz7pQej9iIkiGYHfCROKTXT5zoKLDEB/nNFJkJvAbwK7niwgiG1N7tbcjRV
         rbs8xevuB9VDmD83UAnoRQm0y7B75zfAk0uYLpQb+v78gYEirBqvcUgsRONVk38eVYjK
         kKBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d3f1B+bHfH90fvGHAmWwv4t4e/DGz9pyOLoZyxejttE=;
        b=CHh41nEXvqfIFqjQBkZaCDLJr6w8vSVhO0v8Kx82FiMCP2oYcDwfXMnVTJqJbju/9S
         fhzTpyTI+ZPR5tlV0a6QJO/yOueyhrh5dIGpu/sjvyQMLEaaB904+lN6zh1iFKRqazF4
         uEQiLB0Aj8Onq3XQNDhDf1mP1WEplnesmF5kYGEupwekaFlpq95PI0o/QGABT5VwvaQH
         Jke0qsF0jEGv5g6xzLD40zoDckz9bUQUMtnwG0nxt233EOwB2WMl1yulIl4kuSZ/LoLA
         NcGErzZLTfY6z9sp2DYiAkMBUIFWq8yOWBtWmc8xS1NUJKxsZJ8HWC1kl1Ud3JDTHp/5
         jZnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W+isNVQp;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id p16si408247ota.3.2019.11.25.10.22.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 25 Nov 2019 10:22:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id l202so14057168oig.1
        for <kasan-dev@googlegroups.com>; Mon, 25 Nov 2019 10:22:45 -0800 (PST)
X-Received: by 2002:aca:618a:: with SMTP id v132mr136789oib.155.1574706164774;
 Mon, 25 Nov 2019 10:22:44 -0800 (PST)
MIME-Version: 1.0
References: <20191122154221.247680-1-elver@google.com> <20191125173756.GF32635@lakrids.cambridge.arm.com>
In-Reply-To: <20191125173756.GF32635@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 25 Nov 2019 19:22:33 +0100
Message-ID: <CANpmjNMLEYdW0kaLAiO9fQN1uC7bW6K08zZRG=GG7vq4fBn+WA@mail.gmail.com>
Subject: Re: [PATCH 1/2] asm-generic/atomic: Prefer __always_inline for wrappers
To: Mark Rutland <mark.rutland@arm.com>
Cc: Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Randy Dunlap <rdunlap@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W+isNVQp;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Mon, 25 Nov 2019 at 18:38, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Fri, Nov 22, 2019 at 04:42:20PM +0100, Marco Elver wrote:
> > Prefer __always_inline for atomic wrappers. When building for size
> > (CC_OPTIMIZE_FOR_SIZE), some compilers appear to be less inclined to
> > inline even relatively small static inline functions that are assumed to
> > be inlinable such as atomic ops. This can cause problems, for example in
> > UACCESS regions.
>
> From looking at the link below, the problem is tat objtool isn't happy
> about non-whiteliested calls within UACCESS regions.
>
> Is that a problem here? are the kasan/kcsan calls whitelisted?

We whitelisted all the relevant functions.

The problem it that small static inline functions private to the
compilation unit do not get inlined when CC_OPTIMIZE_FOR_SIZE=y (they
do get inlined when CC_OPTIMIZE_FOR_PERFORMANCE=y).

For the runtime this is easy to fix, by just making these small
functions __always_inline (also avoiding these function call overheads
in the runtime when CC_OPTIMIZE_FOR_SIZE).

I stumbled upon the issue for the atomic ops, because the runtime uses
atomic_long_try_cmpxchg outside a user_access_save() region (and it
should not be moved inside). Essentially I fixed up the runtime, but
then objtool still complained about the access to
atomic64_try_cmpxchg. Hence this patch.

I believe it is the right thing to do, because the final inlining
decision should *not* be made by wrappers. I would think this patch is
the right thing to do irrespective of KCSAN or not.

> > By using __always_inline, we let the real implementation and not the
> > wrapper determine the final inlining preference.
>
> That sounds reasonable to me, assuming that doesn't end up significantly
> bloating the kernel text. What impact does this have on code size?

It actually seems to make it smaller.

x86 tinyconfig:
- vmlinux baseline: 1316204
- vmlinux with patches: 1315988 (-216 bytes)

> > This came up when addressing UACCESS warnings with CC_OPTIMIZE_FOR_SIZE
> > in the KCSAN runtime:
> > http://lkml.kernel.org/r/58708908-84a0-0a81-a836-ad97e33dbb62@infradead.org
> >
> > Reported-by: Randy Dunlap <rdunlap@infradead.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/asm-generic/atomic-instrumented.h | 334 +++++++++++-----------
> >  include/asm-generic/atomic-long.h         | 330 ++++++++++-----------
> >  scripts/atomic/gen-atomic-instrumented.sh |   6 +-
> >  scripts/atomic/gen-atomic-long.sh         |   2 +-
> >  4 files changed, 336 insertions(+), 336 deletions(-)
>
> Do we need to do similar for gen-atomic-fallback.sh and the fallbacks
> defined in scripts/atomic/fallbacks/ ?

I think they should be, but I think that's debatable. Some of them do
a little more than just wrap things. If we want to make this
__always_inline, I would do it in a separate patch independent from
this series to not stall the fixes here.

What do you prefer?

> [...]
>
> > diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> > index 8b8b2a6f8d68..68532d4f36ca 100755
> > --- a/scripts/atomic/gen-atomic-instrumented.sh
> > +++ b/scripts/atomic/gen-atomic-instrumented.sh
> > @@ -84,7 +84,7 @@ gen_proto_order_variant()
> >       [ ! -z "${guard}" ] && printf "#if ${guard}\n"
> >
> >  cat <<EOF
> > -static inline ${ret}
> > +static __always_inline ${ret}
>
> We should add an include of <linux/compiler.h> to the preamble if we're
> explicitly using __always_inline.

Will add in v2.

> > diff --git a/scripts/atomic/gen-atomic-long.sh b/scripts/atomic/gen-atomic-long.sh
> > index c240a7231b2e..4036d2dd22e9 100755
> > --- a/scripts/atomic/gen-atomic-long.sh
> > +++ b/scripts/atomic/gen-atomic-long.sh
> > @@ -46,7 +46,7 @@ gen_proto_order_variant()
> >       local retstmt="$(gen_ret_stmt "${meta}")"
> >
> >  cat <<EOF
> > -static inline ${ret}
> > +static __always_inline ${ret}
>
> Likewise here

Will add in v2.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMLEYdW0kaLAiO9fQN1uC7bW6K08zZRG%3DGG7vq4fBn%2BWA%40mail.gmail.com.
