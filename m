Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT52373AKGQEM7OMBIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id E38761ED4F1
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jun 2020 19:26:40 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id c18sf2535430pls.5
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 10:26:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591205199; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bw89zgK/HTsWEe3xLfZi0Ial81E4Ufl7Wm6N1zH8gn6alc9gUmdYEDUmrGUD79XuN8
         0qvxjDFobhiGrp0cUDxZwu2/J80ni0wdbxNDtPbyIb4qQHGjqyDj+fJhp9YSaxjpsI0U
         kVon1Xf2FUvSJF0LJF9LVdohwULlOJdXMl+wcqIaoOhE7UjCHueefaD4yp1EX0Loe9kd
         e6HrtfJSkr2q78tjJeKuumBLqQAaD1lzbFTrsbmObQBR7zU4WibFUbHhtCHaguw6pt7E
         vrwqLV0/cNIZU0gbyuz6fo0ietxRAZuawX0TGXnSx9aAfqpP9XauUebHTVdBgxjn5FU7
         0H8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aISMly9BoRidP/tOFSfDIrrO+bX4mFdGd5oFXgfj/bk=;
        b=QdWBtZphWuF4r5Pbx8dD1Ba1CpTQAOOiYAH4knQqrzVcWLiTbcBOjfQwM5x/CHqy3M
         FuU+iUwuxrYPQfvqYmnovkWEj4oFgVf2UekXsu0CUIM2LSG6O36bflRLXo33/dnSiD2+
         Uozj2pi7lKx+54cKynczwLT0nv0H6BAch3UzvX0u7zuasBBZrKKKnzilkseK5zxfjwwH
         VUJ4aXqWbcnIZyoPqhJvJ8+9Hb5FJranB8U2DsjeN0jiGXILx2ZEfJgg8BTf4qCahcQO
         gL/5JIl/ytiYjtM4EktkUPMOSfjjNV76ylYK1sDFI8so+68+PmSBVly9onbfNZQVE2ju
         5IaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A5dMEFz+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aISMly9BoRidP/tOFSfDIrrO+bX4mFdGd5oFXgfj/bk=;
        b=SnNmTAs+2tvRJ/dz8Zyj3b66Ne4tJYQjUmEYfWuty3z/5QZXpHEzvVfMCZSvB+Smqb
         Iw1f34/agK288afNwhVPji21pXkWU3JTF7IYv5v0QyUOCIEXssPXOnkGonKZwwQ20d0j
         zvgPh0HlSe0Zi4G+SA1In5+o6tBMHc7ViZ1Q4CDCmREqdbp+K8Glsr82QAd+Lhl95p9o
         Ay1rAEGWLt/pmBmPqdY+PvS+DLksOfD6C4m2P0+8RWymhYBpgHG3mFDoUEU5r0phSife
         khTxbctvfZX1uatN4LWb+1ShIS0Eh7J2srFMR2WZ0wpD4+KQQLJ7tsrcacu24mTnwLMD
         kYLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aISMly9BoRidP/tOFSfDIrrO+bX4mFdGd5oFXgfj/bk=;
        b=T2Pgb5YVzbnxOIF1BhZY3D3vFbRNmKgIgoEOaTibXur+P9cCDRjFNt0cWIv1LA3tal
         BRPjxQ0GOUkepq2A2VojHgye0n9vT4UDCIKzMjiA6xfxhhcRCAfqgP4sCC+98UUXSwuf
         H5HHVi7VTEub07Q6NT+NW0EKOechZ0VLpRJ4uUpRLXAOW7J+pD3VDQOWkLqY6gy8SdKJ
         KHIKSpO0I5SjS1Nkvr151kOhU/9WX0S9EOWs4OSkfGBTMZdQ/Rt7YovewO1DwxPFtKvq
         dVFixn6vE/O4DqL0PHkehZm52eVOUdcnVkx8DE8sTTtQNohOYQvaU1Ypwk38JmQeI1I2
         4eLg==
X-Gm-Message-State: AOAM531HHDwtW1n6484IrkqOFxM0MfNpgupfgYCvlsSFJNXNSpK9897I
	lq6W6TatLjXXanUmFBdBidY=
X-Google-Smtp-Source: ABdhPJyAe8mXvfqW30qH/fdaZR9JF3sVSpP2rDkLFYrLO6ZE+JWAbJd5CyV+8Y7WdpP4Cp9sxJDOeg==
X-Received: by 2002:a63:4563:: with SMTP id u35mr427176pgk.163.1591205199459;
        Wed, 03 Jun 2020 10:26:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:384c:: with SMTP id nl12ls1915470pjb.2.canary-gmail;
 Wed, 03 Jun 2020 10:26:39 -0700 (PDT)
X-Received: by 2002:a17:90a:e98e:: with SMTP id v14mr1075723pjy.70.1591205198945;
        Wed, 03 Jun 2020 10:26:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591205198; cv=none;
        d=google.com; s=arc-20160816;
        b=cBCGCjcYFG+Z/MTNBVzft0sdhkIY7RPqxB3p79NsHxIF8Xm+iOQA5zX9qC0kiAGmcT
         gvZI1y/hbyYtV04QTtoJZjhu+sEZqQnIHUnksUKrDNNGESgowIa2MGf9msh9YsCp0Oqg
         eFBN2qGmlFR8rHPUPzQj+DQU5JqOGsDfLX75iZ16IOxtii8ETYwAWsYwJu+S+aQ3fGlF
         QjegZ71p5wVXWsA+AoDQHmbTnESEiyhByCvhn5VvX1KzeI5iIqbiFYthtjHikOFbJ/As
         fL71M+BAYLxJqG2JrZ7130A5Fjp3a9iDLvZLBGB0eKsmOvnHrSvQfjg8+YnHERluSihf
         G2mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VUrXAxbaK8qdUKcp3CbtwChnwnIyrE0At9MXTdrVxtQ=;
        b=ebOzsv1uU/jgCOt6rz+Y+pIi20lGx/vZdJnXshbGmBXRXfCpArG6MRl2XcOi0G3w8g
         vp470qrAlHE84CSpS356wgxZQ4qUGPojgdMXP92ZHEmlhLi9hFhYyzPvi0+dFRLJSEqO
         84OnAqJ9lCFgkQWwJ0CGQ9BCALiINXeNu7leOmdXIaDbGquTt6lxTle2jzzjN7d6NTtv
         h8413UOajb7ydoV3dIVlvfHlA4EKv/QMYCGsilyLzBEk2prDlQw2b5NZLOpGuyM7bjVQ
         eeQTLSDymaTTG3g6TLkJULrL/NQU9qT8IVYFSSBjWEjbsiFkoU10Y5v3bPl6M9mHJVNK
         DW3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A5dMEFz+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id r17si147651pgu.4.2020.06.03.10.26.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 10:26:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id a137so2527103oii.3
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 10:26:38 -0700 (PDT)
X-Received: by 2002:a05:6808:3ac:: with SMTP id n12mr545955oie.172.1591205197996;
 Wed, 03 Jun 2020 10:26:37 -0700 (PDT)
MIME-Version: 1.0
References: <20200603114014.152292216@infradead.org> <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net> <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
 <20200603121815.GC2570@hirez.programming.kicks-ass.net> <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
 <CANpmjNPzmynV2X+e76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ@mail.gmail.com> <20200603160722.GD2570@hirez.programming.kicks-ass.net>
In-Reply-To: <20200603160722.GD2570@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jun 2020 19:26:25 +0200
Message-ID: <CANpmjNMCAv4JS1Go0KUoCgc5y17ROTbaEGFy=tAYosE9sOAnAg@mail.gmail.com>
Subject: Re: [PATCH 0/9] x86/entry fixes
To: Peter Zijlstra <peterz@infradead.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A5dMEFz+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Wed, 3 Jun 2020 at 18:07, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Wed, Jun 03, 2020 at 04:47:54PM +0200, Marco Elver wrote:
>
> > This is fun: __always_inline functions inlined into
> > __no_sanitize_undefined *do* get instrumented because apparently UBSan
> > passes must run before the optimizer (before inlining), contrary to
> > what [ATM]SAN instrumentation does. Both GCC and Clang do this.
>
> That's just broken :-( You can keep it marked and then strip it out at
> the end if it turns out it wasn't needed after all (of course I do
> realize this might not be entirely as trivial as it sounds).

Eventually we may get the compilers to do this. But adding even more
ifdefs and Kconfig variables to check which combinations of things
work is getting out of hand. :-/ So if we can make the below work
would be great.

> > Some options to fix:
> >
> > 1. Add __no_sanitize_undefined to the problematic __always_inline
> > functions. I don't know if a macro like '#define
> > __always_inline_noinstr __always_inline __no_sanitize_undefined' is
> > useful, but it's not an automatic fix either. This option isn't great,
> > because it doesn't really scale.
>
> Agreed, that's quite horrible and fragile.
>
> > 2. If you look at the generated code for functions with
> > __ubsan_handle_*, all the calls are actually guarded by a branch. So
> > if we know that there is no UBSan violation in the function, AFAIK
> > we're fine.
>
> > What are the exact requirements for 'noinstr'?
>
> > Is it only "do not call anything I didn't tell you to call?" If that's
> > the case, and there is no bug in the function ;-), then for UBSan
> > we're fine.
>
> This; any excursion out of noinstr for an unknown reason can have
> unknown side effects which we might not be able to deal with at that
> point.
>
> For instance, if we cause a #PF before the current #PF has read CR2,
> we're hosed. If we hit a hardware breakpoint before we're ready for it,
> we're hosed (and we explicitly disallow setting breakpoints on noinstr,
> but not stuff outside it).
>
> So IFF UBSAN only calls out when things have gone wrong, as opposed to
> checking if things go wrong (say, an out-of-line bounds check), then,
> indeed, assuming no bug, no harm in having them.
>
> And in that regard they're no different from all the WARN_ON() crud we
> have all over the place, those are deemed safe under the assumption they
> don't happen either.
>
> > With that in mind, you could whitelist "__ubsan_handle"-prefixed
> > functions in objtool. Given the __always_inline+noinstr+__ubsan_handle
> > case is quite rare, it might be reasonable.
>
> Yes, I think so. Let me go have dinner and then I'll try and do a patch
> to that effect.

Very good. Yes, UBSan inlines the check and the __ubsan_handle
functions are just to generate the report.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMCAv4JS1Go0KUoCgc5y17ROTbaEGFy%3DtAYosE9sOAnAg%40mail.gmail.com.
