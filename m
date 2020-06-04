Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC444L3AKGQEHE4WCZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 763151EDCDF
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jun 2020 08:00:44 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id v10sf3895446ybj.16
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Jun 2020 23:00:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591250443; cv=pass;
        d=google.com; s=arc-20160816;
        b=rZtrJ0uO5wK65Mrz9Td2Va/a8KeHhMbzjyE+vzQBYXmnkEp7wlMNrwUKHpTk7UGPdv
         Mvh0NAEtscLZt7nAbufvnK3U8LVFpKHNbhf0iDG9M1Qkd4JWC9+6e4zZU1s4QdYESsbe
         lmiTeKUqllvDtexYApMTVIMI4k2cxS8X0m7gMIW2rtEzFDA5O33QaPSc5j0L9P2OSR4X
         Ad+BoxmuEssYHvuXjYhsrGGnms+y0RH6hD8kQC65AgZab0T8T/ji6NLKItvTYbGKNL6Q
         rnNgaJtqAw+qvvAY+5ElyGmjtwah6jtOnxzKsczgp88a2hEIvRbGZSY+D0URJWTGdpEj
         FBNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YNNix/mk7tfZBS+LpJJ0zEcdV/iUXaxNLsDBfNQ59xs=;
        b=lVmegDp0SOxBHX2OtpM5uVRgg6jIlcCVMysjUAJQas7qFDKw/A101Tyv6nPMFA61sd
         AKr0zQd443dw8kCKZuA+JmPOgILAVP2udOJ9fbrBdtXLqGI+L6KGbkyObkWGoyuAUST0
         aKFWDxBGTN5dixBCUj758+DtYB5g5vX7dTh13HgMXnr9/nGOiMVwfBZMpfAhdTuk+Vvr
         Cizi1UQM1MqPX8oDSshOMV/Jj30NHBdb6E10c/MdM3TziYfOTibzWNIx0R6YcAxRcmCq
         nYkmNzAxkSPDWIUumadJZM7cH8ddLcAhGBTrLFcSIUqVtyNDB+deoeki0fLh+I1ASIkv
         nzEw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SVZ0fEb+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YNNix/mk7tfZBS+LpJJ0zEcdV/iUXaxNLsDBfNQ59xs=;
        b=OgV/lycNq5hTqlpl5/Okgih7SDhWp9v8kh02mQTjW8G2f3XxLr6y2ND534FcxBcw28
         4lDDF3Q1CBQA8nQ3jrtaQkMG6GMwuKQmG/Hq1NMVROBtoEcSq4gwQC0kzofFM/n1gacr
         MHmvqWcwHPfCKYl9CT4ma6wjCVUCIkq/+4oLZ00qy+K2E5JPqVatB4vFPG9AN0U8/00q
         yf/n8fvh8N+I6Xcbqhzw4/o/H2rMD8X4TtyhTsS19xGBzdHL7NKq74331fo1mgMjhKRp
         BoxVLoe6nyW8j3gWGew5CeWtqzzignpjRAhvh7WMSOYVwYU5wlDe0mU+UZRAtCXo+tAX
         1d7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YNNix/mk7tfZBS+LpJJ0zEcdV/iUXaxNLsDBfNQ59xs=;
        b=iShITt0BrfEhjWaU33aefHSJXvYZpHSaYJx3raqHCzY6cXYUZX985BY7SvwIczhiHj
         TsmKJGnAcpIJFpDrXmOOSSEar/jQTwyiFKcB9L/Jtx2JOWJN6Nru32g90re6LJV6ZJI4
         NfQsZ9PpmGGQJ5qzFoxHp08PJi7s+8jeWg9r6H66rLJ7isTFLz5kpOmhJpBHCGR8kOrv
         aklBYjh7M4yPqqtmY1Sa67YcypYiSZSx2rChbo1zosTWGAuVJ5zAhjAcSuKZpqSqmshg
         bHUQitUh3Qo/5eG0UfzJOgE4QtgCTIIG3nuZFLfEvNSHYPwYuD8jsaU9s/LSMVqJQPn+
         685w==
X-Gm-Message-State: AOAM532WrY6OPztcCIDvOosEBFWrBan2xbrUz5e6gdAGKM7SGsH0vxVb
	9wG7LOQHdYzpUAVCDcbhaDQ=
X-Google-Smtp-Source: ABdhPJwqMt60WJFVxvNdhWXI/2VtS1kPmo7aIOvjvoOuhu9+gUorzqgNW/092AXV3g89MGTe7Oje2g==
X-Received: by 2002:a25:cf85:: with SMTP id f127mr1889719ybg.319.1591250443325;
        Wed, 03 Jun 2020 23:00:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4d42:: with SMTP id a63ls1365283ybb.10.gmail; Wed, 03
 Jun 2020 23:00:43 -0700 (PDT)
X-Received: by 2002:a25:aa70:: with SMTP id s103mr5594305ybi.492.1591250442983;
        Wed, 03 Jun 2020 23:00:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591250442; cv=none;
        d=google.com; s=arc-20160816;
        b=G+ql1tvdY6NKjLMB84/8DtAH3A3xsjzJchDsOcZG5gwVcNMp/wVp+QAyOi3FCITxB9
         hgkIXkz99IKcqV4OWOywIMjDhLexHFGlS7U7pqZzZuvd7ZSALQZZ0HnTTPsgY6ir45nr
         j3VqtPTBOAXcFdY2ORgZmM4uTJIuUeUrHZryIzKHSTktEUhFZfisACQcqjWEXMTp1tcx
         1KzwS6DEF5wHaTUsrOHjGqx6m/SzNUj2rnoa4BK0kVn9GJWOzK/IGQm5Vig8P+ut0GOq
         PAc3eGX0Qb4Bh5ahUTLJMGbXPlz75ktXg6QltO72FnlyHr68EpIj/TTD+AbcDn0EViIQ
         Mlcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rSb0nNv2rpcsYD2Qo3eCh6ya1OcS6/RmNcjB/qUbXrc=;
        b=hgbpse++YC67FvPYu+NRUKXsxXEfZbvrUK8FNj1RaF+0ZtnnNzueqzlVdi2Zv7vRgL
         UbxSq8R2AfsaY9VytoMYtFNiUojB6xMXjqGfWs4aLkuaqyUY81oFz2H+8CeUI0zzyJNP
         Bzwx60i2P+yJHx7mAs0t+g1ZiqaiBgRBV70Ay7qU38MGHKBCWul6iO0dcW1GrCQ6e9nN
         kmlaXb232drJ2avYWuqmyrxlZt6p004QFwJFHJDsFHjORcYfKvnddRzmmAnwu2LX3LXY
         3Tk7PkMgUI/Kkq5LTTAk2QxitF82Uip+WuDHCWCqg+AyFoOfMB4PFtPsYHHNfjMTxsO6
         IV4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SVZ0fEb+;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id r143si253239ybc.5.2020.06.03.23.00.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Jun 2020 23:00:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id o7so3867635oti.9
        for <kasan-dev@googlegroups.com>; Wed, 03 Jun 2020 23:00:42 -0700 (PDT)
X-Received: by 2002:a9d:7dc4:: with SMTP id k4mr2386984otn.251.1591250442319;
 Wed, 03 Jun 2020 23:00:42 -0700 (PDT)
MIME-Version: 1.0
References: <20200603114014.152292216@infradead.org> <20200603120037.GA2570@hirez.programming.kicks-ass.net>
 <20200603120818.GC2627@hirez.programming.kicks-ass.net> <CANpmjNOxLkqh=qpHQjUC_bZ0GCjkoJ4NxF3UuNGKhJSvcjavaA@mail.gmail.com>
 <20200603121815.GC2570@hirez.programming.kicks-ass.net> <CANpmjNPxMo0sNmkbMHmVYn=WJJwtmYR03ZtFDyPhmiMuR1ug=w@mail.gmail.com>
 <CANpmjNPzmynV2X+e76roUmt_3oq8KDDKyLLsgn__qtAb8i0aXQ@mail.gmail.com>
 <20200603160722.GD2570@hirez.programming.kicks-ass.net> <20200603181638.GD2627@hirez.programming.kicks-ass.net>
 <CANpmjNPJ_vTyTYyrXxP2ei0caLo10niDo8PapdJj2s4-w_R3TA@mail.gmail.com>
In-Reply-To: <CANpmjNPJ_vTyTYyrXxP2ei0caLo10niDo8PapdJj2s4-w_R3TA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jun 2020 08:00:30 +0200
Message-ID: <CANpmjNMyC+KHTbLFSxojV_CTK60t3ayJHxtyH4AckeMD2hGCtg@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=SVZ0fEb+;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Wed, 3 Jun 2020 at 21:10, Marco Elver <elver@google.com> wrote:
>
> On Wed, 3 Jun 2020 at 20:16, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Wed, Jun 03, 2020 at 06:07:22PM +0200, Peter Zijlstra wrote:
> > > On Wed, Jun 03, 2020 at 04:47:54PM +0200, Marco Elver wrote:
> >
> > > > With that in mind, you could whitelist "__ubsan_handle"-prefixed
> > > > functions in objtool. Given the __always_inline+noinstr+__ubsan_handle
> > > > case is quite rare, it might be reasonable.
> > >
> > > Yes, I think so. Let me go have dinner and then I'll try and do a patch
> > > to that effect.
> >
> > Here's a slightly more radical patch, it unconditionally allows UBSAN.
> >
> > I've not actually boot tested this.. yet.
> >
> > ---
> > Subject: x86/entry, ubsan, objtool: Whitelist __ubsan_handle_*()
> > From: Peter Zijlstra <peterz@infradead.org>
> > Date: Wed Jun  3 20:09:06 CEST 2020
> >
> > The UBSAN instrumentation only inserts external CALLs when things go
> > 'BAD', much like WARN(). So treat them similar to WARN()s for noinstr,
> > that is: allow them, at the risk of taking the machine down, to get
> > their message out.
> >
> > Suggested-by: Marco Elver <elver@google.com>
> > Signed-off-by: Peter Zijlstra (Intel) <peterz@infradead.org>
>
> This is much cleaner, as it gets us UBSAN coverage back. Seems to work
> fine for me (only lightly tested), so
>
> Acked-by: Marco Elver <elver@google.com>
>
> Thanks!

I was thinking that if we remove __no_sanitize_undefined from noinstr,
we can lift the hard compiler restriction for UBSAN because
__no_sanitize_undefined isn't used anywhere. Turns out, that attribute
isn't broken on GCC <= 7, so I've sent v2 of my series:
https://lkml.kernel.org/r/20200604055811.247298-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMyC%2BKHTbLFSxojV_CTK60t3ayJHxtyH4AckeMD2hGCtg%40mail.gmail.com.
