Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCWLQSBAMGQEIS4YZYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3898E32D95D
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 19:23:07 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id a5sf5106196oiw.21
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Mar 2021 10:23:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614882186; cv=pass;
        d=google.com; s=arc-20160816;
        b=tEa0KDX67ay+Muds07tmtifXoLt22gsr/Dtb5puMYFLtJx++9XFBJXOYsWklq/WX4l
         wisoo9iL9y7pwEyPsM6WaYJDpvBwvCNu/8PG2OgUkhJtt2HJSUFO81Z7DctZGnDr+Oje
         +gwcW/POfgETWEZcFh+kBLg00WtoewZMpCgnSezg+yryw+qjdY/eEQF2/esgzHpufbGz
         opID2QEyrYOIdsN0cUZ12EF+h1rc/KP+2fG63BBvMQ5w4Vf89ACkit4VOSc1kihcRYoh
         IxkWuWD6Ul3dfeiDNT/j0e8qRnPSSmsy8q8T7tVSX+V6WLKCLHyWvrRq4BvhP4MJ+T1o
         Ejnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=o9rM5rFXHJiFtKidGPK6aEV4ZcUp9seNyi3R+3xqiC0=;
        b=DametbpkI7+F/XyXW5HGLbyJ0lc/TsProYJWwaTehg85pOFymM79MVIWEwW+YsxYa7
         5NVL0kr+qc6ohf84AEPEjOLrE/PWy2f5wb89UUXVfbsLXKJokl3ykSBHX0WjIfcM2cf/
         jmSkTqJU2O3t7DbEyhsTWRqEvnswcFoukQtoDl7Dv5oYvFeCQ1VFo55w/YVmanDrYbQf
         vzDpJkKHj8dXAwv+ARxAJRFeK89YaC8m0pSNps1tRivEzdDZTNsrLm4BV/ShdErXeZZb
         Z2KyOHSFA7jxAxTRLTmgZX3U9D95luYMpk3RNRYD5EKRtXqofBuQeeLEm48P+zxXeH0I
         t/7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QLchrPEA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o9rM5rFXHJiFtKidGPK6aEV4ZcUp9seNyi3R+3xqiC0=;
        b=kUMw2tq9npHMImepjYbvNq9d9Ac36S1xzzjr/ESVl7YO1eZGCzfq45KK+ZYXhE1Gye
         7JPhdBUf9JJ6G6praIfY59s9qDG/XvWLJM3K1ZwsRJsaXJsjB6S/LIS8qWam8CszhJS8
         uzscGorevQ4FplUEF6iH17Vf4dGzpjK8NHuVE6XJhU1CC4bccd0VRn/b7lzXqt53RgGS
         X17OIvYy+3M45cWKSllkn+Qf6UVNlTNFGNUfrm1XbizTL8F33o94Jx+un2IvbkPT0itr
         R04Wb/U7wcdStGImJhnDcFhlxErnIuIiLdS8eclMEDjHIUpOx8fc21TaADOOO/p5lPwW
         bjQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o9rM5rFXHJiFtKidGPK6aEV4ZcUp9seNyi3R+3xqiC0=;
        b=CLzGIDPzBk+VYhmIXOKihiqPxeGRB2EZT87rEPSCTDKqa0WOdeiWqJDM9nE1gvwW6X
         fF3+RkdVzae94bIYf0DLZaExcielxUGOJ5RC7Bb0tPi+EA2b8f+6K4SY8ex+FG7vhFuY
         Act8T9S3KNiMEUjMwrmxXLfk2wDu+FXeQ5iiYI3SOAOsoW53Qb0fL17PeByvv8zi2R3o
         R/OlmH0xNWrLYFS050v+cL7SdboICL7j6cAb6KElkcEiGXymCpzxpjbXV7ixAAc1GMN1
         6HVb3TGJKvCLYwFDryf5MC9ZTUFaX0kW1BmLcgbOHrzUftRyFvjOAGQd9j44ZE9PiuBy
         tQGA==
X-Gm-Message-State: AOAM531eMs0S7ASbz/P9aXuAvqAQSYaWl/Awx1j94ybBjs7H4DuoUn7Q
	sQF4w5G5tg71gTinuLbDeSM=
X-Google-Smtp-Source: ABdhPJzf7MNTrVIf2omZFzDCkJFo/KZN3Qd2ccIh1NByOc9ZeNQYnjJEyC8EgoJkFDHxzjD04sgh7A==
X-Received: by 2002:a9d:6416:: with SMTP id h22mr4291797otl.193.1614882186228;
        Thu, 04 Mar 2021 10:23:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:827:: with SMTP id t7ls1769580ots.8.gmail; Thu, 04
 Mar 2021 10:23:05 -0800 (PST)
X-Received: by 2002:a05:6830:90a:: with SMTP id v10mr4541987ott.364.1614882185834;
        Thu, 04 Mar 2021 10:23:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614882185; cv=none;
        d=google.com; s=arc-20160816;
        b=SGOknmBSPMXmN5eeuiYUXZjR/YuV7fLJ4zMuQGNNTYL8wyDOpn8D3AANe9GPbp5zKB
         +u9Q7NUVpbfjMcbhjoPKTKITDytVfScR0qrNvCYovEOC292q6gWnF8IUClTzAOlRIfKA
         juvg+DhUeA+Rsd+0oB8c4STZ6ExS6kubu98uahYGxGvsUjmR92cbl9ug8zo3P716MAZs
         7b6kjAbwkR+jsvAeMcv0dMQOdrV7lRAOuj5IA3ACxEIOGw2zId6PDC281QQ0Z4W5im6H
         mAEnpcdU9IGD9ag2xXUZKjIq9sJJG3vqZBw4oj6MA6L3QJ/cSa/3C/T6xvqEl4iJxyJz
         Unwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Lkt+RxNv+povx5RrP6jzx52eKkPT/gfUP+i0E22Jg6A=;
        b=ndNUB/we4jNScSwHYqkdM5yge9XENN53tkw7IPgJyb7jzKwU0V4GgYS/N3TRtOZfr4
         +NxgSQtG0yAuh7CYpigNet6tycR4ziCruv5E6yWrxfpmvku2J2Z8CaurekdjtF4aw3I1
         KQV6DAnWcisYpda28mOWFJTNbb8y1Rb/+lfUlOIFvereGrLlye2d8eZMtmWxV2IWi5Al
         86TRjK/Iv0s9G9l/LwcTHkcaovKcIs5nD1Fxvt7FH4DLeu68HU3prX1r538GleiI5OAG
         rUVQ8KElxTGXUg8gMF2fmZbpF53ncZMenBOS96/k3OQyHwckkTLrsMSfX+jOrmoVENeA
         YHWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QLchrPEA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id q10si33645oon.2.2021.03.04.10.23.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Mar 2021 10:23:05 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id f3so31104093oiw.13
        for <kasan-dev@googlegroups.com>; Thu, 04 Mar 2021 10:23:05 -0800 (PST)
X-Received: by 2002:a05:6808:10d3:: with SMTP id s19mr3999250ois.70.1614882185258;
 Thu, 04 Mar 2021 10:23:05 -0800 (PST)
MIME-Version: 1.0
References: <e2e8728c4c4553bbac75a64b148e402183699c0c.1614780567.git.christophe.leroy@csgroup.eu>
 <CANpmjNOvgbUCf0QBs1J-mO0yEPuzcTMm7aS1JpPB-17_LabNHw@mail.gmail.com>
 <1802be3e-dc1a-52e0-1754-a40f0ea39658@csgroup.eu> <YD+o5QkCZN97mH8/@elver.google.com>
 <20210304145730.GC54534@C02TD0UTHF1T.local> <CANpmjNOSpFbbDaH9hNucXrpzG=HpsoQpk5w-24x8sU_G-6cz0Q@mail.gmail.com>
 <20210304165923.GA60457@C02TD0UTHF1T.local> <YEEYDSJeLPvqRAHZ@elver.google.com>
 <20210304180154.GD60457@C02TD0UTHF1T.local>
In-Reply-To: <20210304180154.GD60457@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Mar 2021 19:22:53 +0100
Message-ID: <CANpmjNOZWuhqXATDjH3F=DMbpg2xOy0XppVJ+Wv2XjFh_crJJg@mail.gmail.com>
Subject: Re: [PATCH v1] powerpc: Include running function as first entry in
 save_stack_trace() and friends
To: Mark Rutland <mark.rutland@arm.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, broonie@kernel.org, 
	linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QLchrPEA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as
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

On Thu, 4 Mar 2021 at 19:02, Mark Rutland <mark.rutland@arm.com> wrote:
> On Thu, Mar 04, 2021 at 06:25:33PM +0100, Marco Elver wrote:
> > On Thu, Mar 04, 2021 at 04:59PM +0000, Mark Rutland wrote:
> > > On Thu, Mar 04, 2021 at 04:30:34PM +0100, Marco Elver wrote:
> > > > On Thu, 4 Mar 2021 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > > > > [adding Mark Brown]
> > > > >
> > > > > The bigger problem here is that skipping is dodgy to begin with, and
> > > > > this is still liable to break in some cases. One big concern is that
> > > > > (especially with LTO) we cannot guarantee the compiler will not inline
> > > > > or outline functions, causing the skipp value to be too large or too
> > > > > small. That's liable to happen to callers, and in theory (though
> > > > > unlikely in practice), portions of arch_stack_walk() or
> > > > > stack_trace_save() could get outlined too.
> > > > >
> > > > > Unless we can get some strong guarantees from compiler folk such that we
> > > > > can guarantee a specific function acts boundary for unwinding (and
> > > > > doesn't itself get split, etc), the only reliable way I can think to
> > > > > solve this requires an assembly trampoline. Whatever we do is liable to
> > > > > need some invasive rework.
> > > >
> > > > Will LTO and friends respect 'noinline'?
> > >
> > > I hope so (and suspect we'd have more problems otherwise), but I don't
> > > know whether they actually so.
> > >
> > > I suspect even with 'noinline' the compiler is permitted to outline
> > > portions of a function if it wanted to (and IIUC it could still make
> > > specialized copies in the absence of 'noclone').
> > >
> > > > One thing I also noticed is that tail calls would also cause the stack
> > > > trace to appear somewhat incomplete (for some of my tests I've
> > > > disabled tail call optimizations).
> > >
> > > I assume you mean for a chain A->B->C where B tail-calls C, you get a
> > > trace A->C? ... or is A going missing too?
> >
> > Correct, it's just the A->C outcome.
>
> I'd assumed that those cases were benign, e.g. for livepatching what
> matters is what can be returned to, so B disappearing from the trace
> isn't a problem there.
>
> Is the concern debugability, or is there a functional issue you have in
> mind?

For me, it's just been debuggability, and reliable test cases.

> > > > Is there a way to also mark a function non-tail-callable?
> > >
> > > I think this can be bodged using __attribute__((optimize("$OPTIONS")))
> > > on a caller to inhibit TCO (though IIRC GCC doesn't reliably support
> > > function-local optimization options), but I don't expect there's any way
> > > to mark a callee as not being tail-callable.
> >
> > I don't think this is reliable. It'd be
> > __attribute__((optimize("-fno-optimize-sibling-calls"))), but doesn't
> > work if applied to the function we do not want to tail-call-optimize,
> > but would have to be applied to the function that does the tail-calling.
>
> Yup; that's what I meant then I said you could do that on the caller but
> not the callee.
>
> I don't follow why you'd want to put this on the callee, though, so I
> think I'm missing something. Considering a set of functions in different
> compilation units:
>
>   A->B->C->D->E->F->G->H->I->J->K

I was having this problem with KCSAN, where the compiler would
tail-call-optimize __tsan_X instrumentation. This would mean that
KCSAN runtime functions ended up in the trace, but the function where
the access happened would not. However, I don't care about the runtime
functions, and instead want to see the function where the access
happened. In that case, I'd like to just mark __tsan_X and any other
kcsan instrumentation functions as do-not-tail-call-optimize, which
would solve the problem.

The solution today is that when you compile a kernel with KCSAN, every
instrumented TU is compiled with -fno-optimize-sibling-calls. The
better solution would be to just mark KCSAN runtime functions somehow,
but permit tail calling other things. Although, I probably still want
to see the full trace, and would decide that having
-fno-optimize-sibling-calls is a small price to pay in a
debug-only-kernel to get complete traces.

> ... if K were marked in this way, and J was compiled with visibility of
> this, J would stick around, but J's callers might not, and so the a
> trace might see:
>
>   A->J->K
>
> ... do you just care about the final caller, i.e. you just need
> certainty that J will be in the trace?

Yes. But maybe it's a special problem that only sanitizers have.

> If so, we can somewhat bodge that by having K have an __always_inline
> wrapper which has a barrier() or similar after the real call to K, so
> the call couldn't be TCO'd.
>
> Otherwise I'd expect we'd probably need to disable TCO generally.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOZWuhqXATDjH3F%3DDMbpg2xOy0XppVJ%2BWv2XjFh_crJJg%40mail.gmail.com.
