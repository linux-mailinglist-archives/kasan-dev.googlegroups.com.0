Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2HPS3YQKGQEDGFHK6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id D4638142D47
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 15:23:37 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id c31sf10923893pje.9
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 06:23:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579530216; cv=pass;
        d=google.com; s=arc-20160816;
        b=wLxfzK1a78KIsPzrTN7o6xUJ7ELu5atEl1xRqsJ0v0MaWyGjN+07j9JkvIhDkPobz0
         4PvaJBMDXKm5Q7+HIElEj7n8PAh/ZsWKNV9YV7HvgV49/oteT6YdAWeT5nVJiGUKJ87B
         DPstUAg1TdmraO8vT+m8tgH7frq3zWmZ+jJglG40iGN1poFYH0ajjTuP4D5zXz9jzGo7
         NluTCOY1yiYIOjFnHVjvg7WjAlmQA45XGt32hMgBWhlaJ55CsunjtQEAt0mLmbKIUHan
         6xr2l4v4tbkzd+BXvN4/uexNz2bqxZeq87FeamTYE70Ckc5kDHCthwMcZ2AnmurqMcrW
         SNDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ym7oMWWlgSpRaShs6/H9RuDvVrRD+EyBI/uol61S1WM=;
        b=P4lQEelD9eAR3isHKeRU/+A3W7rywGteY89nWlwqlKmCKHsVcoccE+LffE9mcQe/oy
         BzZvVvNEg/nYl9xjOhvuPFBz5jrNZqWe+1yqmokUePj+3tXMd0B1nAWlIMVFBuxwob/m
         I1j9XaIdeNU1bk1kLJHppD8/9aXhhEVbMN3VSbxu7prsNUggBtcZKpkgLbb/Dbq2bry2
         VARqq7iKqxvKPt1EMrWRJjdrI6/ohWbV/upu8nzg4+XVF9CP20KNP/hmRX0KpPGXZab+
         fWQ6SsLWrUd3Yyc11dK9ak7O8rFiolhRBwllSoadaE7WwhT2b/BCXL47MeMIehMP0lKq
         YlxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Z/QAqXKh";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ym7oMWWlgSpRaShs6/H9RuDvVrRD+EyBI/uol61S1WM=;
        b=F5xGDqK04sXIlfTwDq5JUFs61HR37mYQivOvI5DcQv05ohMTObknkcncs8QYCQi/v/
         yGBlUANuZMtS8wE/a7FzKGd3tY/5CBtFkZB0p9SXysN3WS6jsFhHwH3U3+i3mdt2mYkJ
         VBvVdbN97m9vMr3Lleg46BUSBvXytwQHkceUJOfcrCuisHOC5zL1qwJYKgs/axIwDvpf
         rfRbT/RmuUkUTJVeciQi0R+/fMT9CkCtLsxHn8hIsokj3pha+7xYFe/hL4oPfn7jnJmC
         OvZ/Iqa7/UdiSDPUQenavxj71uNVg6Odrq+HlH6S2rpoABrBWRCKlqK7Hvdt9DHWN+LG
         4n4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ym7oMWWlgSpRaShs6/H9RuDvVrRD+EyBI/uol61S1WM=;
        b=U/dD+x6TSdqtwUEU+eJj/dabaIJy23vy3kHvXpCQCNlvHJMb3fW04Xfif0QB/3gFy9
         MDIeEbjChhlLjdslbGcPuwtPhITlEKO11WuDd66LbyXHay/cP/mvb/10PnDBOnr57Vbd
         +f0ADbIkUDCGYAgv8LYg271RSY4jYaMq85qRHTjPfpPV32RAhpF6prE35QB00w0Rfx4w
         aJw4dssq1rGAhYy2dyTjSrElW4Bh20YdQgoPPQGJr+NbgFBYOvMyZmw9inGmi5kE4Z8J
         CY4/7u4vTvuLRHDo5wJ/hxsVOxyIupi5qT6jFSM9Xeunk5nnUDjAOIPX0+9raB3D2JHR
         2YWQ==
X-Gm-Message-State: APjAAAXa/WSQoIz1OGY8biLlYhY8didvwVFgr4DNvXjuS2RAkqhQUpB8
	y7ALWJo2Wb9x73/sHI6KHwg=
X-Google-Smtp-Source: APXvYqwyii41o4y8TONICNUt/vur08MyjqB1jJQq1/a57KqYEl7UmIkPT96XV9Hvw/WBUIGDiE8Nmg==
X-Received: by 2002:a63:4824:: with SMTP id v36mr60460713pga.343.1579530216463;
        Mon, 20 Jan 2020 06:23:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:208:: with SMTP id 8ls9863351pgc.16.gmail; Mon, 20 Jan
 2020 06:23:36 -0800 (PST)
X-Received: by 2002:a63:1945:: with SMTP id 5mr62042696pgz.310.1579530215883;
        Mon, 20 Jan 2020 06:23:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579530215; cv=none;
        d=google.com; s=arc-20160816;
        b=M+y0BC8leaKYPU51iXkeJjYuNHNo3dq4+597U34remv4hVuwGHzbGgrxsKbX2n+Hbm
         ipoqZL5xNr0XPbL0wnGPH4CIlC4II8Dat6VEI/NjT18j1o7o8NgZbR6e39GJ6cZHtQgZ
         DkAcqqUxitq4h1RK3ViLyanO5CJqpNrRi9aa1jSs1QFCnYsRcVo8iHhXXn6lqtJBQzWb
         IytKZ2Mv8goGyv2bsC61QdOGX5p37S3BBSEvKWxHCvzUuP+hsyQLTV42z+OdIfPZY5h4
         W9M7402WulLW/Hk/xsQKU+ehpo9ig35xuMiS6t6MkZ2K/lY4e3LdIrqJHhY4CsjLDet0
         +Snw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nnn4KKkHt1EljhMT9CxicHtKv9oSHz/LL7W2XJ6R4BE=;
        b=TCjmiU00xIM615PhbcaMZ7D/OTVquBy5P2+3DpITWq8ru5Ulz0lxc9VqrkwAZ7kxnX
         Tk5tlbLFasy3fmHs7MDbwA/bI+CaY0AhMGgcv0hU3ktF/2/e4NdMai0iqx+pF+QD/lT1
         lm6G4d2PclQYRc8A6Uv+cWc5KrfPzcB+TwR1KSKv8R6dpBHvVRgzvigvm79as235J8JI
         na+9ypMykI3FS3AtTvMhug7nz+tUnWp2Qz+121Ft7Yci3FMu/7arAZtmd76og4WapTpU
         XFLZMMVs+BhCOvCDcVizNx6rKb/NqQuRHEjBoXLca7dlwJHfykV+i09YqiQKwJ9I80m+
         hsQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Z/QAqXKh";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id c24si515606pjr.2.2020.01.20.06.23.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 06:23:35 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id a15so28817152otf.1
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 06:23:35 -0800 (PST)
X-Received: by 2002:a9d:7f12:: with SMTP id j18mr16933059otq.17.1579530214919;
 Mon, 20 Jan 2020 06:23:34 -0800 (PST)
MIME-Version: 1.0
References: <20200115165749.145649-1-elver@google.com> <CAK8P3a3b=SviUkQw7ZXZF85gS1JO8kzh2HOns5zXoEJGz-+JiQ@mail.gmail.com>
 <CANpmjNOpTYnF3ssqrE_s+=UA-2MpfzzdrXoyaifb3A55_mc0uA@mail.gmail.com>
 <CAK8P3a3WywSsahH2vtZ_EOYTWE44YdN+Pj6G8nt_zrL3sckdwQ@mail.gmail.com>
 <CANpmjNMk2HbuvmN1RaZ=8OV+tx9qZwKyRySONDRQar6RCGM1SA@mail.gmail.com>
 <CAK8P3a066Knr-KC2v4M8Dr1phr0Gbb2KeZZLQ7Ana0fkrgPDPg@mail.gmail.com> <CANpmjNO395-atZXu_yEArZqAQ+ib3Ack-miEhA9msJ6_eJsh4g@mail.gmail.com>
In-Reply-To: <CANpmjNO395-atZXu_yEArZqAQ+ib3Ack-miEhA9msJ6_eJsh4g@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 15:23:23 +0100
Message-ID: <CANpmjNOH1h=txXnd1aCXTN8THStLTaREcQpzd5QvoXz_3r=8+A@mail.gmail.com>
Subject: Re: [PATCH -rcu] asm-generic, kcsan: Add KCSAN instrumentation for bitops
To: Arnd Bergmann <arnd@arndb.de>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	christophe leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Z/QAqXKh";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Fri, 17 Jan 2020 at 14:14, Marco Elver <elver@google.com> wrote:
>
> On Fri, 17 Jan 2020 at 13:25, Arnd Bergmann <arnd@arndb.de> wrote:
> >
> > On Wed, Jan 15, 2020 at 9:50 PM Marco Elver <elver@google.com> wrote:
> > > On Wed, 15 Jan 2020 at 20:55, Arnd Bergmann <arnd@arndb.de> wrote:
> > > > On Wed, Jan 15, 2020 at 8:51 PM Marco Elver <elver@google.com> wrote:
> > > > > On Wed, 15 Jan 2020 at 20:27, Arnd Bergmann <arnd@arndb.de> wrote:
> > > > Are there any that really just want kasan_check_write() but not one
> > > > of the kcsan checks?
> > >
> > > If I understood correctly, this suggestion would amount to introducing
> > > a new header, e.g. 'ksan-checks.h', that provides unified generic
> > > checks. For completeness, we will also need to consider reads. Since
> > > KCSAN provides 4 check variants ({read,write} x {plain,atomic}), we
> > > will need 4 generic check variants.
> >
> > Yes, that was the idea.
> >
> > > I certainly do not feel comfortable blindly introducing kcsan_checks
> > > in all places where we have kasan_checks, but it may be worthwhile
> > > adding this infrastructure and starting with atomic-instrumented and
> > > bitops-instrumented wrappers. The other locations you list above would
> > > need to be evaluated on a case-by-case basis to check if we want to
> > > report data races for those accesses.
> >
> > I think the main question to answer is whether it is more likely to go
> > wrong because we are missing checks when one caller accidentally
> > only has one but not the other, or whether they go wrong because
> > we accidentally check both when we should only be checking one.
> >
> > My guess would be that the first one is more likely to happen, but
> > the second one is more likely to cause problems when it happens.
>
> Right, I guess both have trade-offs.
>
> > > As a minor data point, {READ,WRITE}_ONCE in compiler.h currently only
> > > has kcsan_checks and not kasan_checks.
> >
> > Right. This is because we want an explicit "atomic" check for kcsan
> > but we want to have the function inlined for kasan, right?
>
> Yes, correct.
>
> > > My personal preference would be to keep the various checks explicit,
> > > clearly opting into either KCSAN and/or KASAN. Since I do not think
> > > it's obvious if we want both for the existing and potentially new
> > > locations (in future), the potential for error by blindly using a
> > > generic 'ksan_check' appears worse than potentially adding a dozen
> > > lines or so.
> > >
> > > Let me know if you'd like to proceed with 'ksan-checks.h'.
> >
> > Could you have a look at the files I listed and see if there are any
> > other examples that probably a different set of checks between the
> > two, besides the READ_ONCE() example?
>
> All the user-copy related code should probably have kcsan_checks as well.
>
> > If you can't find any, I would prefer having the simpler interface
> > with just one set of annotations.
>
> That's fair enough. I'll prepare a v2 series that first introduces the
> new header, and then applies it to the locations that seem obvious
> candidates for having both checks.

I've sent a new patch series which introduces instrumented.h:
   http://lkml.kernel.org/r/20200120141927.114373-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOH1h%3DtxXnd1aCXTN8THStLTaREcQpzd5QvoXz_3r%3D8%2BA%40mail.gmail.com.
