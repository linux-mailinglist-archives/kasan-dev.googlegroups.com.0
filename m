Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUVB4D4AKGQEFRXCPAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 826542295B9
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jul 2020 12:11:31 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id w125sf911927oie.22
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jul 2020 03:11:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595412690; cv=pass;
        d=google.com; s=arc-20160816;
        b=iGA41Etqu712cAtzJWZSbBuZnO0hCABr2iNdHjWVtvJ0ejRDYN6FUvVOUpUa9WuTip
         cSAoDFVJqs98xTouN+PaE0V7CEzjUjt3uWv2/TdQrDuDiBpkQOaRwmEQLDClr9loJcir
         5orIZSWuWriL5HyRY39s3xYmqgFus4zOa98wLmDyt8cvGBB0UrYuDoesim+7yrMsdU+X
         VcLk0NJaug1myPv2OIjkAQ06yKcmQ9OishPJdNKV/GsspT8lIAoUTz2kyfSp/EoIF8eo
         1zfhl1qAYK5nfOhbBTmlpvcEPshlqb/64oZw5ChRZvmisToF0bA56+d2wq8/yLvL4P2J
         1FLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4UcbcJkRnkZDRRo1zz8kBZaPDuGIl09OTz1OJ296NVU=;
        b=Y04JRZuwjBNOa9cVy0ZiZ2OoCLpwNLbId202YIHX9nryCp/FfeHVew/bCIXd4pP+kQ
         6h6603ulc4w7TKJAwXmLVCLMp/v8JUfWHEFyhZhmPb+ruD9RkQvhvmfOJM9zkUeR8DVS
         1i9WL1BbhccbLvqXUkGLxiszibbULhr1/HqOr++ozKHj5/4cipHPn3vFmIAvxM19EwEe
         +dqEKSO8MBOXjaPmAJc+9iN5c9biyyyLpob0rMCwldeqDK3Vy5frr1bpCIFHjV7bbPrD
         FzDxJoMHJ7gqmmJOzEk9xXqZKY3MZZc91apW4vDYzOXmYOjDvUTfV3mPSE3HCemPwhg+
         iQkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s6BRFBxB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4UcbcJkRnkZDRRo1zz8kBZaPDuGIl09OTz1OJ296NVU=;
        b=i8hmFFhW2YmVDBiT8ozno7DxJC7S0gnCuz0EMCyE82L2B3bBjA6YPsRfQ2peTv7btp
         6ciYVMDzMCJ6aBRK4Ro76lTeImqK/dm5il/e5iZ13jOwbN5xSSvMfEaSGV2WzP7X/BNe
         HuAEa4ICf4kd8vZx7nGP8FGfrNA65sEeb/Q3QgdckoMBzXWsZlhO1+UV4K3d2g7Rg9gr
         OGxo+EbGSOu6WwogKLvnF570wYAyh3Ub+Q5K8k8Te+GFQKL5ox1RoZQ/21ddI6t93NpU
         jU0x0eFYFaYKwwDsFhF7HyevlVduGNpVqo8rwbhucoOU9E7jG/RIY4Rnvbbo6ym/9VfM
         2Ikw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4UcbcJkRnkZDRRo1zz8kBZaPDuGIl09OTz1OJ296NVU=;
        b=MR/KbQywWKTGAN9AD9/waZ+oOV6z2flDi4KjyUiVFMHUTsjci1dg8VKwMC3dh1l0/J
         a1OUAvjZBUhJgZure2oZsSmqeshDLiUuUZ5reA5GqtCscwW2m8uH2oLYml6F8CTFR07m
         rsleYu6bqHRugy5XoLvwNz0gBihsAMjYWZM1F6PhXwQQ0aSA8bkvzpBbqpvS5+InekI/
         pT7E+ZnHmcaOT/euoy+eGl/EZMZshO2tWsZ+nOa29J0ByhvRloins+rgLlDUOpQV6zbT
         OI5a5NvZUqEFOoDmgr8KgN2b58HcBcVRsVlKOxTGJdrvw0MUgwfXTf7/zJy6Dx7TG1Ka
         9t2Q==
X-Gm-Message-State: AOAM531jSGKTZz8zgHzLRIDrgLp3mxBGyNyH904NH9fMp1OszIH6/n4D
	4hHFAtGFTEuS1Cjv3Lxezwg=
X-Google-Smtp-Source: ABdhPJyygJcOYVqHelicY7xvunfI/IQMy5EIr1qYfXvxVTM0IeN+TMKdl8KiUgOkH50ph2nreMaobA==
X-Received: by 2002:aca:52c6:: with SMTP id g189mr6667223oib.38.1595412690345;
        Wed, 22 Jul 2020 03:11:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1599:: with SMTP id i25ls290540otr.3.gmail; Wed, 22
 Jul 2020 03:11:30 -0700 (PDT)
X-Received: by 2002:a9d:1b0d:: with SMTP id l13mr28579685otl.261.1595412690027;
        Wed, 22 Jul 2020 03:11:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595412690; cv=none;
        d=google.com; s=arc-20160816;
        b=dN9FL+gNLO6tv4LqR/nPcykjvl+TtbGBBLjXOXcMF5YvCuv85F/FaEboPszQOZ1fsX
         qr8uuUSJkcSPlPCEJovj2bJCEdSRHDzE5llFfXhdzP08hx8qSwgW4ApagwVy1mmvfdB7
         DHVCGcsp4USJS5flL+7DtwErMrirosvrmF9etWsDyM/oWrk2ylwEIDT7i3zqh+zVkxsU
         pvgTkNqdwiWBCT0bTQXDz9cGlpY7VrIMl35+ZEqFgiaAsazfYvn3Wf2BZvca7hC6U3F/
         je5dCLzc8KgDkBnrDnTfFZSJrwBX2TDEiudyAH3pxnuG9Q66T9CcHV0MntkJ1JZA0o7b
         eJaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=aEtrJgbpsOebCukpCmfFytmRqvmav58R9V8W1bUHwwA=;
        b=qW7biqUdEq3Nnmh0w0z70VAy6nFXjQKpMovB4q/IoH4Bz03qRed43r2dO7VG65/uc3
         2gHfjs7NDxZ40a/ttSvzySCPHE8qnYHXprQ1r1p6jcp+YG2dIfBW34JeI3755VmCii/+
         uZW0EcDw9rxPdCmGLwY6MGhNFxt9P5JIe9+nIHMr6cUjV2l6S9oAvF4+rbs7rJDkqyKe
         4Hxbfj0Tyt1XNH+ztHQpAusSH4QmzYz0B6wyq5udmgkR3aQOw+dyUyd8uHy9Vzc9eL17
         9ywkhGCWyGVl5UuigzY7AZNlzhClhY2xZomKg7YD5KTEDKtQAf/ZSdnt1Amd+pvddnIL
         i7Pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=s6BRFBxB;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id d65si1045072oib.2.2020.07.22.03.11.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Jul 2020 03:11:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id r8so1389372oij.5
        for <kasan-dev@googlegroups.com>; Wed, 22 Jul 2020 03:11:30 -0700 (PDT)
X-Received: by 2002:aca:cf4f:: with SMTP id f76mr6563659oig.172.1595412689438;
 Wed, 22 Jul 2020 03:11:29 -0700 (PDT)
MIME-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com> <20200721103016.3287832-9-elver@google.com>
 <20200721141859.GC10769@hirez.programming.kicks-ass.net>
In-Reply-To: <20200721141859.GC10769@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Jul 2020 12:11:18 +0200
Message-ID: <CANpmjNM6C6QtrtLhRkbmfc3jLqYaQOvvM_vKA6UyrkWadkdzNQ@mail.gmail.com>
Subject: Re: [PATCH 8/8] locking/atomics: Use read-write instrumentation for
 atomic RMWs
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, 
	Mark Rutland <mark.rutland@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=s6BRFBxB;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Tue, 21 Jul 2020 at 16:19, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, Jul 21, 2020 at 12:30:16PM +0200, Marco Elver wrote:
>
> > diff --git a/scripts/atomic/gen-atomic-instrumented.sh b/scripts/atomic/gen-atomic-instrumented.sh
> > index 6afadf73da17..5cdcce703660 100755
> > --- a/scripts/atomic/gen-atomic-instrumented.sh
> > +++ b/scripts/atomic/gen-atomic-instrumented.sh
> > @@ -5,9 +5,10 @@ ATOMICDIR=$(dirname $0)
> >
> >  . ${ATOMICDIR}/atomic-tbl.sh
> >
> > -#gen_param_check(arg)
> > +#gen_param_check(meta, arg)
> >  gen_param_check()
> >  {
> > +     local meta="$1"; shift
> >       local arg="$1"; shift
> >       local type="${arg%%:*}"
> >       local name="$(gen_param_name "${arg}")"
> > @@ -17,17 +18,24 @@ gen_param_check()
> >       i) return;;
> >       esac
> >
> > -     # We don't write to constant parameters
> > -     [ ${type#c} != ${type} ] && rw="read"
> > +     if [ ${type#c} != ${type} ]; then
> > +             # We don't write to constant parameters
> > +             rw="read"
> > +     elif [ "${meta}" != "s" ]; then
> > +             # Atomic RMW
> > +             rw="read_write"
> > +     fi
>
> If we have meta, should we then not be consistent and use it for read
> too? Mark?

gen_param_check seems to want to generate an 'instrument_' check per
pointer argument. So if we have 1 argument that is a constant pointer,
and one that isn't, it should generate different instrumentation for
each. By checking the argument type, we get that behaviour. Although
we are making the assumption that if meta indicates it's not a 's'tore
(with void return), it's always a read-write access on all non-const
pointers.

Switching over to checking only meta would always generate the same
'instrument_' call for each argument. Although right now that would
seem to work because we don't yet have an atomic that accepts a
constant pointer and a non-const one.

Preferences?

> >       printf "\tinstrument_atomic_${rw}(${name}, sizeof(*${name}));\n"
> >  }
> >
> > -#gen_param_check(arg...)
> > +#gen_params_checks(meta, arg...)
> >  gen_params_checks()
> >  {
> > +     local meta="$1"; shift
> > +
> >       while [ "$#" -gt 0 ]; do
> > -             gen_param_check "$1"
> > +             gen_param_check "$meta" "$1"
> >               shift;
> >       done
> >  }
> > @@ -77,7 +85,7 @@ gen_proto_order_variant()
> >
> >       local ret="$(gen_ret_type "${meta}" "${int}")"
> >       local params="$(gen_params "${int}" "${atomic}" "$@")"
> > -     local checks="$(gen_params_checks "$@")"
> > +     local checks="$(gen_params_checks "${meta}" "$@")"
> >       local args="$(gen_args "$@")"
> >       local retstmt="$(gen_ret_stmt "${meta}")"
> >
> > --
> > 2.28.0.rc0.105.gf9edc3c819-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM6C6QtrtLhRkbmfc3jLqYaQOvvM_vKA6UyrkWadkdzNQ%40mail.gmail.com.
