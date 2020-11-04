Return-Path: <kasan-dev+bncBCCMH5WKTMGRB3ULRP6QKGQEAU4IG5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C45F72A6741
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 16:17:02 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id y129sf3526000lfa.17
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 07:17:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604503022; cv=pass;
        d=google.com; s=arc-20160816;
        b=a6bFTv/dM1E/WOXnNM0d8q+FHKM/p6Z9ChrE0/GtseR9B4Yx8+7+JV7MH4oGv30BQa
         I1H0RlO1i6vuaeU7VtLE3YKdsg4BcdqlfKq5IuujXoIpUXmkeyP7bUJvXSlCQMu0cXpK
         nTCb7tcJ11oHK3tsxvAQQUWIM2pZ00G7UxtcepBbZ+6xfYB5SNntkJAu1gKht+n15rqM
         HfAAxz+kvbgnkcnx6F6bsjU6xnwzY6cSD6FJwojcko2Db0ZHmixURWo40ajQVud7XHTs
         +Fxcnc5z1SinTUB95sZXXMJ2rnjgU+xiZP1U6cJfB6pl38ewljHKM68RhyiTIdSJB0rs
         TQkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0ZXiiCauK2l5ovae4iAtNgBHozkEetv+F+3lgtOry3A=;
        b=w0XU+UnBpOPDqX28F2cCb+QHsF1Gh1KyDh/4lRX+HpKtOK3xBDhaGE0kW2lVrho28j
         +zQ7i65fZOwKDUgqypQeDtfX8o2OZiLIHGkCjzpFdlqPYRstw/Y/aGZVZLp219SeMkk4
         h/fRfpRDZ13pptkZ/ra/TCtxKd+DXAKg6UkXEKr+x9Pg3fSRm7sL7GUuoea8y5EyDxit
         Hfqkahq+AJAO7c+Gl7jnZG+ggcUh4ate1uogMwx/tYJ5mEWwJSedCVDHYL9yKilHAA+E
         RW1/JK9l8hEIS9SGurwFM/KdQKmMTvKyZCHOczDj+Tau9phyLIbUnaPpTVFiVoirqEOQ
         PVxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H4vUVRsl;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0ZXiiCauK2l5ovae4iAtNgBHozkEetv+F+3lgtOry3A=;
        b=s6yWU7ruPm+6ZcDacYpZQWeyKUaa8MkRN/PhLbban9WLl+s/AIM5RtuP/tHJYqaRZO
         ydytS5JEYRmPagl6lAQAHBRdAGY1ODhygzeo5BfIY7gHafpJVpTPfIsT2EgNFXjXBwaT
         1Mn3qkdf6MkbBEjHchbTUEpkHSUfxQN+LJVvffwAA5wnSX4FpfUb1ZbTSTjNSbhHWyQk
         H2nFCW6/y8vyDyhkmqJeKTLcs2ztVh7CSWz/bD674iIt8VUwYVLkfNrm+ceJMqawiW+2
         LehTeue6HMtesxZ8Dt0UyG6WK3AG5TbK6UTDwLbxWccICaQKTRZ8eUmRzVQU4kKC3cEC
         vRGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0ZXiiCauK2l5ovae4iAtNgBHozkEetv+F+3lgtOry3A=;
        b=dpIqyEgYF7b5q//yGv4jnCSkEHh+BxqaFSItI+Ldd2NAMoSQqRHKsiEhzr5/3xoW8j
         FAWUCmb0QnhH+lZm7++zvypuiMGIMqLYTbQh+rzbuTGBaoLONITdnQi6z14ZAxuFB7/A
         KugzoobqtaVVxr/uiHbQhACrNI5pnt1mOyP/9OeKguGjL70Ck8SpmetDi+WXesi/M5eY
         ApyK/FywQiVTpqbO/C+nCenyAT8f65GquyF6kRO0LOt99z6Y2jH6WH346R6nLfPc/pTx
         0v7aMpxxEGEwAMPSg+lXvsdht75WvkgJY161FCHmlY+p4KAO0vVvlMCPedF8hFGmTKiT
         tIAg==
X-Gm-Message-State: AOAM530qYz3sgjPN33anBo3Bgd3KVcYck8SNd/CuIpTwPSt8MkPGsUAQ
	475AR/DNHbvZX0l9RJCxUGo=
X-Google-Smtp-Source: ABdhPJxavCzxZaqjgzd+19Ik21ltPoCVqa9BMkMfJLirhh6DiWUpv0iQH8Lru2r8E+n2dT2ahkCrHg==
X-Received: by 2002:ac2:5b52:: with SMTP id i18mr10381811lfp.227.1604503022312;
        Wed, 04 Nov 2020 07:17:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:586:: with SMTP id 128ls1479561lff.1.gmail; Wed, 04 Nov
 2020 07:17:01 -0800 (PST)
X-Received: by 2002:a19:ef07:: with SMTP id n7mr9314392lfh.482.1604503021249;
        Wed, 04 Nov 2020 07:17:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604503021; cv=none;
        d=google.com; s=arc-20160816;
        b=cJUR+0PsZnzqDHW8sQKEy/Cf3qvFMZ+/7OvokFT01aPl/GcTuJ5s7Q32wvio1IfaLH
         jSryjnlRfIcUb4JfwhtDdwu6uUvtHxwQNaWNfLxRlD35ZmYXXoAeKp0o+QlVFK7Aj2oO
         CgJEsZXVwMTahh26+MunIrXov5trHGS8+sZXIneYtP1CiLUje4yQxs1G/N/qTAk/oVo6
         u2XgSbJBGdhdFAxOXkfAWKxgB4Q2V0Oa54cxjlawbdpsrBYVnIPGBrhtHjwCdLfLJdRj
         rNikXV7v4eEChrOlWB+YvNT8QSHy2SZMhLwtDjBgj0pId+xlwjyygwwZWUYk6Xm7Wb+R
         qWGw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3oz+jge3s+KLxPkjd9JJaeKDtMt4BIAKRrZrd3MFLg0=;
        b=hVROrde6S29/BmxlKYvTFKveXmY7vSgPpnWyMBbGwp77BdQqpMyNKiFGSKUcGaDkQm
         Uez5WlU+y6K9N+LJil8qVbSfq7H068w0QPOatVCRbjS/wqmBv9l8EIY1ON+grOCSIhUA
         2VrfnrpGaBGgEefhCZZosDaUdLqjmhknMl6dEZqvcmz0ncOwndPf6TeLfr3FmcKzffU3
         NU1mz65aSqGaJZXqTIBKZCAIXu/foAfOcn6Lis2zN4XS6ZVxylKn54dNMypoJExU0SbF
         mhFWrA7d5fjf1M4Jgp1xtA7bVt4e2FF7+hxG4+qa+x2nT4gTGfnAYLyAs118Z8vpQqwT
         ISQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=H4vUVRsl;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id l28si85339lfp.11.2020.11.04.07.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 07:17:01 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id c17so3081026wrc.11
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 07:17:01 -0800 (PST)
X-Received: by 2002:adf:e486:: with SMTP id i6mr32693599wrm.397.1604503020514;
 Wed, 04 Nov 2020 07:17:00 -0800 (PST)
MIME-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com> <20201103163103.109deb9d49a140032d67434f@linux-foundation.org>
 <CANpmjNM1HQ_TwqJ6Ad=Mr=oKVnud-qzD=-LhchPAouu1RDHLqw@mail.gmail.com>
In-Reply-To: <CANpmjNM1HQ_TwqJ6Ad=Mr=oKVnud-qzD=-LhchPAouu1RDHLqw@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Nov 2020 16:16:49 +0100
Message-ID: <CAG_fn=UJJqPiVi-rfih0XTSQOqQ15Pn+c5Ecj-4QKyoT8pRqdA@mail.gmail.com>
Subject: Re: [PATCH v7 0/9] KFENCE: A low-overhead sampling-based memory
 safety error detector
To: Marco Elver <elver@google.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>
Cc: "H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>, 
	Jonathan Cameron <Jonathan.Cameron@huawei.com>, Jonathan Corbet <corbet@lwn.net>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=H4vUVRsl;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::443 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Nov 4, 2020 at 1:36 PM Marco Elver <elver@google.com> wrote:
>
> On Wed, 4 Nov 2020 at 01:31, Andrew Morton <akpm@linux-foundation.org> wr=
ote:
> > On Tue,  3 Nov 2020 18:58:32 +0100 Marco Elver <elver@google.com> wrote=
:
> >
> > > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE i=
s a
> > > low-overhead sampling-based memory safety error detector of heap
> > > use-after-free, invalid-free, and out-of-bounds access errors.  This
> > > series enables KFENCE for the x86 and arm64 architectures, and adds
> > > KFENCE hooks to the SLAB and SLUB allocators.
> > >
> > > KFENCE is designed to be enabled in production kernels, and has near
> > > zero performance overhead. Compared to KASAN, KFENCE trades performan=
ce
> > > for precision. The main motivation behind KFENCE's design, is that wi=
th
> > > enough total uptime KFENCE will detect bugs in code paths not typical=
ly
> > > exercised by non-production test workloads. One way to quickly achiev=
e a
> > > large enough total uptime is when the tool is deployed across a large
> > > fleet of machines.
> >
> > Has kfence detected any kernel bugs yet?  What is its track record?
>
> Not yet, but once we deploy in various production kernels, we expect
> to find new bugs (we'll report back with results once deployed).
> Especially in drivers or subsystems that syzkaller+KASAN can't touch,
> e.g. where real devices are required to get coverage. We expect to
> have first results on this within 3 months, and can start backports
> now that KFENCE for mainline is being finalized. This will likely also
> make it into Android, but deployment there will take much longer.
>
> The story is similar with the user space version of the tool
> (GWP-ASan), where results started to materialize once it was deployed
> across the fleet.
>
> > Will a kfence merge permit us to remove some other memory debugging
> > subsystem?  We seem to have rather a lot of them.
>
> Nothing obvious I think. KFENCE is unique in that it is meant for
> production fleets of machines (with ~zero overhead and no new HW
> features), with the caveat that due to it being sampling based, it's
> not so suitable for single machine testing. The other debugging tools
> are suitable for the latter, but not former.

Agreeing with everything Marco said I can only add that it would be
nice to have a separate discussion about the existing memory debugging
subsystems and the need to remove any of them.
Having many tools in a toolbox does not hurt, but we need to ensure
that all the tools in question are visible to the users (so that
people know when and how to use them), can find important bugs and do
not duplicate each other.


> Thanks,
> -- Marco



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUJJqPiVi-rfih0XTSQOqQ15Pn%2Bc5Ecj-4QKyoT8pRqdA%40mail.gm=
ail.com.
