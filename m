Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBUXJ2TXAKGQERLMI5KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 123D0103A42
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 13:43:00 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id y64sf18545933ybf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 04:43:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574253779; cv=pass;
        d=google.com; s=arc-20160816;
        b=lxpOm2/Vv3qPgoG+R22fqMCyNNwBY9P1F/2I1FLBCK4laoqQtmynHScif+pyGl18QA
         w0CeVdrCZauex1zbj4JgqnPO3H9mPTWcanOq2uMSNkwb7nVirvlHtfycw+8ZD0bkERtq
         0z1hqDC8KcIC8dXu6FRiIuJFmMxzX1Vh+VrmEMr3VTvq1nid0m2Q+KSLyXnXqAV00O+s
         Dqp7b/ltMacnNRM5iNx1vuMkXqklCoWnq8Nj8tNF4rUsuKiZsmtESccTVnKbUMU+gkG+
         4Zyz+gJL2UDRvIH+ckK7VDBFYEPQQsZd/PrCRZ5GJgxKEY4Cpy/Yq+IkUUXW06SII8Rn
         cwtQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wjI1S0DSDNID13eJbYpiKLm8yF/k80ezEufctg3ifPY=;
        b=N86PGt/f64KA9aTxynzeZSS5hAGdvv5x3RIvDIvh4Ut2Bh8ewUDzRL30+cephSbrLY
         eAfAv1JX10j3Z0to0FuJcUIXRiAES3NsHY2JF7xqYv3gB9Z0HobPq9KPUGQYXsDkdraG
         fJ8DykwLSpXJnyS/zC2zmNCKldTaeXhaah0rEFlNY1dM8dSIouGEHsmdlOj7hS/G2mfi
         0FGL9X1G0wGgR+3x3E1MhaMeOUz4bO0ORSI4q2SH0Drm2CrPkiIO1dBFiP0ePEWsopYw
         NoMOfaIvziAoOwILA78J97iEUdZv4BQ/hArZfr1BLPSeOucgVbw4ntp1CiFmpd9aplEa
         LxVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XqkMWRLF;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wjI1S0DSDNID13eJbYpiKLm8yF/k80ezEufctg3ifPY=;
        b=TUaeSJVGkMLk6Z038qqK8V/1uDBUKtSU/K/ByNKjxxJMCV1CX0l1VvRycYx+GhG9zx
         y/mnJX4zxW4n83Eiyuq0RaDE8N5Nbvfa1ngwMqe1bMOqsLtUK4yxTFIZ9t/rAROP5TY8
         ShuCydkGx+tCol7Hc0mVwaQnwVBINi8AbsOV7xOTtxmpJBprus+HDEPNQO+33W6ssiwf
         VvrhF6MlgArWJ6IvYuCSmJb9EvlgDXm7jEKzhnWrYbCqp7QVe3ifanpQI3Snfzifo+kV
         Siw79Tj8lnSNJLwNJyqet5D555CNulThU3WvXVMOXI/paMflhON/MO2DJsnlsZHTX1px
         J+Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wjI1S0DSDNID13eJbYpiKLm8yF/k80ezEufctg3ifPY=;
        b=lxwn1DRJ+hEn69APhNJro1rmCHHNH/ppExzWyHDaM0lX+MWvB5+ACYnpPDIBLZkR9G
         +d3pPi/gCWyB4I8UaaZMXG7GKfDdHo6l0Js9K8seboEugV4G6x3ovTWjHOuWL+YCAtjA
         npseYOHxD/AwpdzZWoemoMBBdw4fwwqLZxReD7G5kv5i5RzkBRx3Q8iYKUBeFKFzztKR
         PNx9EZSrAr9/+KHCP0wYblUof4U+AzvslW3CpfbIjJ9uXTzztdBe+tCT7Qh285CDtUvQ
         DOUED5dqjSNGa+05cN5PoFFdQ4v2EQemlQOWjv15mO4rbBPjNuzkUOaIG6Z8r/psUq4Q
         8lXw==
X-Gm-Message-State: APjAAAV8fzDZLVliKputWwtr8SQJE8QIr483MJ5ZZdMMd7ArOD2u1A8W
	phSrWoA3eBYLodYiDNn7yo4=
X-Google-Smtp-Source: APXvYqziJOar7MzQGJpYUh4QIXWK1esQoHfsICtNPQq7+n4Nae8iGnzLEZViL8KKzLqbqe55Dx/N1w==
X-Received: by 2002:a25:e015:: with SMTP id x21mr1697794ybg.73.1574253779010;
        Wed, 20 Nov 2019 04:42:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8406:: with SMTP id u6ls347720ybk.8.gmail; Wed, 20 Nov
 2019 04:42:58 -0800 (PST)
X-Received: by 2002:a25:6ec5:: with SMTP id j188mr1807330ybc.207.1574253778620;
        Wed, 20 Nov 2019 04:42:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574253778; cv=none;
        d=google.com; s=arc-20160816;
        b=HQHnw0AxKAntnICbAJ47shibZXnQnxI60mjyPLoYY960MUdV/NCEqlKo2b5UzL5mLs
         qqlUD8kMF9js+TzoUMoDTw2OBwAvGHrUiV7viGt6RyPLYjHn9EHKoHZ/6qG9HBJvUYbE
         aPLFFtNLraQZrKq+3R7W3G+KSuE20DIjhKgdl+uY9srVJyAdN/bdeM1KViZLkCoeYQKg
         gtOpOOiH85gUQs/pwEJkBM3mozKNKReD2/xhM8RYDtq8vNI4D0ko44YOvXUJentq4vD2
         Bl4lUtAcw2cSPlNckUdPkJbpR/x5QIfUZ9cm7T4YuKXpull43+tGfRkcLE5r5BxBNhuA
         D0PQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B1kvKePgmOlp312ylkyBxDZhjYmUB28WgRyVChV+Gis=;
        b=RZhU6yCMWSSolP+aZ/GUu55xXFjXRRkbC+0Se2v2BRE+xHZR6OOFvodRENuFG1i9qe
         EZdjruy8zhQZ2XYPunPY112q6bgTeI3mL2eyffvdD5Ds+s4y7KFahk4NxThVub0uzMPv
         ihA2blaeR1kxsDTmG1d9xBFgxvrB3gfcE8GsjuyQAHwU8E37rHJrcQiP1wlF3+eyAoQk
         ErCV9s9OhuOH1WHmePwU6zxPqJ02YOeo6F/ZO1IbwhWn0xXxkRGfkU3mhn+s717vciqn
         uNNzWYitZ/yxKASsoMmvlAK72KiGOqI5+J6XNvNFH/5PPYUgJwZy2esbF+wNf8UTP3Fe
         aBPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XqkMWRLF;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id f11si1437848ybk.5.2019.11.20.04.42.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Nov 2019 04:42:58 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id d22so15408426oic.7
        for <kasan-dev@googlegroups.com>; Wed, 20 Nov 2019 04:42:58 -0800 (PST)
X-Received: by 2002:aca:4d47:: with SMTP id a68mr2666979oib.68.1574253777810;
 Wed, 20 Nov 2019 04:42:57 -0800 (PST)
MIME-Version: 1.0
References: <20191120103613.63563-1-jannh@google.com> <20191120103613.63563-2-jannh@google.com>
 <20191120111859.GA115930@gmail.com> <CAG48ez0Frp4-+xHZ=UhbHh0hC_h-1VtJfwHw=kDo6NahyMv1ig@mail.gmail.com>
 <20191120123058.GA17296@gmail.com> <20191120123926.GE2634@zn.tnic>
In-Reply-To: <20191120123926.GE2634@zn.tnic>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Nov 2019 13:42:31 +0100
Message-ID: <CAG48ez11KVxQoSDM2GmMAxU=1jNZNYKcLFkvpkeq74p+yxeefw@mail.gmail.com>
Subject: Re: [PATCH v3 2/4] x86/traps: Print non-canonical address on #GP
To: Borislav Petkov <bp@alien8.de>
Cc: Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel list <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>, 
	Andi Kleen <ak@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XqkMWRLF;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::244 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Wed, Nov 20, 2019 at 1:39 PM Borislav Petkov <bp@alien8.de> wrote:
> On Wed, Nov 20, 2019 at 01:30:58PM +0100, Ingo Molnar wrote:
> > * Jann Horn <jannh@google.com> wrote:
> >
> > > You mean something like this?
> > >
> > > ========================
> > > diff --git a/arch/x86/kernel/traps.c b/arch/x86/kernel/traps.c
> > > index 9b23c4bda243..16a6bdaccb51 100644
> > > --- a/arch/x86/kernel/traps.c
> > > +++ b/arch/x86/kernel/traps.c
> > > @@ -516,32 +516,36 @@ dotraplinkage void do_bounds(struct pt_regs
> > > *regs, long error_code)
> > >   * On 64-bit, if an uncaught #GP occurs while dereferencing a non-canonical
> > >   * address, return that address.
> > >   */
> > > -static unsigned long get_kernel_gp_address(struct pt_regs *regs)
> > > +static bool get_kernel_gp_address(struct pt_regs *regs, unsigned long *addr,
> > > +                                          bool *non_canonical)
> >
> > Yeah, that's pretty much the perfect end result!
>
> Why do we need the bool thing? Can't we rely on the assumption that an
> address of 0 is the error case and use that to determine whether the
> resolving succeeded or not?

True, that'd work, too. I didn't really want to special-case an
integer here - especially one that has the same value as NULL - but I
guess it's fine.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez11KVxQoSDM2GmMAxU%3D1jNZNYKcLFkvpkeq74p%2Byxeefw%40mail.gmail.com.
