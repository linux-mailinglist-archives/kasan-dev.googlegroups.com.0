Return-Path: <kasan-dev+bncBDW2JDUY5AORBZ6D3GMAMGQEARGRZDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 755295ADA71
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 22:54:00 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id u64-20020ab045c6000000b0039f7d5b5aecsf1664519uau.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 13:54:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662411239; cv=pass;
        d=google.com; s=arc-20160816;
        b=cjIo8R2moA33FwSU/kggTT1TGrBiBSSqDoDP/XxMhvGadadPdP9VZ08MEdxso0VHzc
         22RS5l28oY/L4Mmv/d8oAB8KiaxSXnPg8jQMN3nTAW1sJhi05fguxgqR1t1f4I88XCdK
         nAA0ev8oAYEy8G9klXbIYEwm3Y4b9vtQJPaiNjawMDuG17IaeHpC4vb033nqDlg8ONfv
         kh4H14IGIA/Qij3HGKvzUA3jg8p28lgMLv1S0HcaGei+FXJKGs+gRPUQ8M3+N1KasSB9
         lI9GgStTz8meAq5X0c59v2AX+jBMlp2GVjFREw7sH5vSrqqzZGPN+EeBI+YXeuJFekvz
         KfRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=kl/h3GkbjLM+KlVzUgYKVUIzZzWA/fICrm/AsgCFNQs=;
        b=aW+dhJOhjqD2F9IbuBLrZ3VvBRbJ68BlDiKu4r8i9rJP0DOiDD8rp9Clorau27UH/R
         oslC2oWT12Kpld4QvCOvxj1rG14kLWpYvu6If6pWaUTZ4+1kknVvmc/1ENdJBIqq6f0n
         y+jTAvb6goikgKNnEoTN/71QOFfJ7DuW7dcuQ5a3lmCnchCfJV0kuVZEHpbOXpc4jTTu
         6IsM4kaxk0AWgqbA+33oL5eYqxUg4hO6gnJxTKfGE7m/R4IBMsJr29pWaDhuuoDXy/nv
         fiszwR0zwl+IjKjkoAOpLwlWFsWZX+KDAKmCAMOV46sc9AnnwzAYUflgGZ06S/J/NCKF
         4j9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G9z+EvS2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=kl/h3GkbjLM+KlVzUgYKVUIzZzWA/fICrm/AsgCFNQs=;
        b=Cpx+OTts1yi+4TxyMAJat2wSyE/tQKQfWpdznuXQj4lQIs95RdFf/ndmWkmjPP/Wf0
         kuTIC3bAd4FGnuRhOEfWSk3k/KHSET3kjka67GdgNZB1OFH8ntLud6hUQVMttd2EnDem
         WUd3TpAuLe5vFakV4ylyyawaG17ddh4jlY9lrYgeeG2iVELtmTg5fj95hH8JlALO/OHh
         LhHOmjppmmnQf5GqC9ogp4KRYQQBn626tPuLWyacsLS7xn/1nVmgfyXSW+gcEXv/Xi+l
         hh9AbMKqOusYZHSAZMlTR6H6j8iixy5jMv+YSvLhrqc43APEvwQKNTX23jruUOHy2Lj9
         4ZTw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=kl/h3GkbjLM+KlVzUgYKVUIzZzWA/fICrm/AsgCFNQs=;
        b=qKABEeZo/8zkpxtjiptLKf2VyEmH1YYXMEKKkUqRRjPqlmz2O7TiBjluVIqXR+Crxf
         QiIf3f+PV62weeO1hgNU2Dpjgad+qBRIASCR0g9Nps8A2uHiWvRqLoJfjuw7n5wD03CU
         IvfHflXraw/TBVZ01ax494Dr+BJ6+sNA0QS2sB5g+7nFR5foAoQDXyGnZHl1Ewiki4ar
         DyUAB6A1eBYw52oheKjEVeM5cKZCCllAWBQW5Zw1CES5HhTtLzY5kwa1c8hehkiFesnf
         gFTicuDHEw+1T1oYae2nYQ7P07iVFsGok9aYwwIaO5dsyPgwtLmCC7uo1psfgpmT4C8s
         wpAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=kl/h3GkbjLM+KlVzUgYKVUIzZzWA/fICrm/AsgCFNQs=;
        b=eL7FVQtw04hKYC1vEkFP1F/rk1AOCW9ei9s6kY+QB2POmg+pUjTyde4ModCL2+FaG2
         PT3qu8/ap6iXCsZGev037YqD7soE0BwSlIW4RBfK3KpecXfZRnkXdWhBglEOF+nnmkal
         2x8GKno3a0pqcQlMmFFP4MZ9V+2FSK6pkDwlurearemN6fBUidi/SmWsh7FGhJWOmT4B
         JwDGhoYSyvG7m+089FIFWR2CqXqKtlsyTD6co3lEbDd0F78UW07DFuViQ+s21qdoDfrG
         xDANm23D7FG+sVAFlV+hnXxXvyk3CcCPLiz1jb5L+j1+FYmKB4jbU8X0mHXHH+Bmm7l6
         hDOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1a8reWwlJL9xXo495dYh7OLdScLcGNrcweFx0fbT/teZt5uhyb
	cekDRT+Ynz35i/NB64AXCio=
X-Google-Smtp-Source: AA6agR7DG/f9xbDcQS2P6BE6tDiTltkSION3G3+2pRiGDmQ3glsbSKWYKQKTzFLz+qsWKJSycP4enQ==
X-Received: by 2002:a1f:9d09:0:b0:377:8b21:a865 with SMTP id g9-20020a1f9d09000000b003778b21a865mr13839476vke.26.1662411239261;
        Mon, 05 Sep 2022 13:53:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:c39d:0:b0:390:b9b2:c61a with SMTP id s29-20020a67c39d000000b00390b9b2c61als1975228vsj.4.-pod-prod-gmail;
 Mon, 05 Sep 2022 13:53:58 -0700 (PDT)
X-Received: by 2002:a67:c19d:0:b0:390:ecd8:4617 with SMTP id h29-20020a67c19d000000b00390ecd84617mr12844504vsj.36.1662411238711;
        Mon, 05 Sep 2022 13:53:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662411238; cv=none;
        d=google.com; s=arc-20160816;
        b=Xj6pxZj6EnYtpMvqhSr5UO+XVsflnNO7yBdEJA6gp9064sFlbp12A+aHV6SyP4BJkh
         yDviVveWGvGbdi4bIy12+Wkzx37b4lDR2lJLajasSnBz++ntypTzyMgWH9SVLWYVnFi6
         JfdK+zbJHzMAkLVDVXwh106SFTOYGkA0usN+ds0usDDFnYn7YETFFaTdnM7vmFk7DFlS
         wK/qXQVRymRw3yjdeklu4h+wX2XvrqRavnndm/YmGjGZ9tpiKrxohD9QvI5/+N+prNvg
         VphZ7jWEkXr2c1NxFMQ50bDpwQ63mTuev6rJjXUjidk/hT2dax0dZxxIxDLBTQTW6K+L
         uIYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3/RM6NI1xD0KfggIAxAiR262mP+cF5baa1PLRg4NH9k=;
        b=l0c9eCDXTUV1YEhNB09zww5hcipnzHpsA+jNPmvtcnAalUgewpO6J0ylx9TpIHwlXb
         ZOSQKR7GTYYQeQ0ea3neazaE/Hc6aUQ+ELtdh0iAymYLUIza6J9fsMcNUx3e6Iffx43f
         HQ3uJXF1J5YtjLHKbDkebyeR1q2kjx1/y4cvtOxiJDJJJMq0sbQ8CX85WAofqR0woocy
         e3MwtmNPCmU3bxBxHV50nYNgszwVY2tw9RQa82WiixfBVb66sfZNUSgqyCLCnOtsELOM
         HICBzQAppPe3MNgkFtsEcLM6AzDTQ7w79yYanlhfWMII7E4mD4abFqtqAukd2h5vLH15
         Lf5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G9z+EvS2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qk1-x736.google.com (mail-qk1-x736.google.com. [2607:f8b0:4864:20::736])
        by gmr-mx.google.com with ESMTPS id s2-20020a67ce02000000b00390eab10614si377344vsl.2.2022.09.05.13.53.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 13:53:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::736 as permitted sender) client-ip=2607:f8b0:4864:20::736;
Received: by mail-qk1-x736.google.com with SMTP id b2so6904425qkh.12
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 13:53:58 -0700 (PDT)
X-Received: by 2002:a05:620a:843:b0:6be:86a8:4099 with SMTP id
 u3-20020a05620a084300b006be86a84099mr28542817qku.386.1662411238391; Mon, 05
 Sep 2022 13:53:58 -0700 (PDT)
MIME-Version: 1.0
References: <20220901044249.4624-1-osalvador@suse.de> <20220901044249.4624-2-osalvador@suse.de>
 <YxBsWu36eqUw03Dy@elver.google.com> <YxBvcDFSsLqn3i87@dhcp22.suse.cz> <CANpmjNNjkgibnBcp7ZOWGC5CcBJ=acgrRKo0cwZG0xOB5OCpLw@mail.gmail.com>
In-Reply-To: <CANpmjNNjkgibnBcp7ZOWGC5CcBJ=acgrRKo0cwZG0xOB5OCpLw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 5 Sep 2022 22:53:47 +0200
Message-ID: <CA+fCnZckFNqDA2SJSMjM7gpUF_U7Ps_3u+JzvN_cKvskz0FuOQ@mail.gmail.com>
Subject: Re: [PATCH 1/3] lib/stackdepot: Add a refcount field in stack_record
To: Marco Elver <elver@google.com>, Oscar Salvador <osalvador@suse.de>
Cc: Michal Hocko <mhocko@suse.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vlastimil Babka <vbabka@suse.cz>, Eric Dumazet <edumazet@google.com>, 
	Waiman Long <longman@redhat.com>, Suren Baghdasaryan <surenb@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=G9z+EvS2;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::736
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Sep 1, 2022 at 11:18 AM Marco Elver <elver@google.com> wrote:
>
> On Thu, 1 Sept 2022 at 10:38, Michal Hocko <mhocko@suse.com> wrote:
> >
> > On Thu 01-09-22 10:24:58, Marco Elver wrote:
> > > On Thu, Sep 01, 2022 at 06:42AM +0200, Oscar Salvador wrote:
> > [...]
> > > > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > > > index 5ca0d086ef4a..aeb59d3557e2 100644
> > > > --- a/lib/stackdepot.c
> > > > +++ b/lib/stackdepot.c
> > > > @@ -63,6 +63,7 @@ struct stack_record {
> > > >     u32 hash;                       /* Hash in the hastable */
> > > >     u32 size;                       /* Number of frames in the stack */
> > > >     union handle_parts handle;
> > > > +   refcount_t count;               /* Number of the same repeated stacks */
> > >
> > > This will increase stack_record size for every user, even if they don't
> > > care about the count.
> >
> > Couldn't this be used for garbage collection?
>
> Only if we can precisely figure out at which point a stack is no
> longer going to be needed.
>
> But more realistically, stack depot was designed to be simple. Right
> now it can allocate new stacks (from an internal pool), but giving the
> memory back to that pool isn't supported. Doing garbage collection
> would effectively be a redesign of stack depot. And for the purpose
> for which stack depot was designed (debugging tools), memory has never
> been an issue (note that stack depot also has a fixed upper bound on
> memory usage).
>
> We had talked (in the context of KASAN) about bounded stack storage,
> but the preferred solution is usually a cache-based design which
> allows evictions (in the simplest case a ring buffer), because
> figuring out (and relying on) where precisely a stack will
> definitively no longer be required in bug reports is complex and does
> not guarantee the required bound on memory usage. Andrey has done the
> work on this for tag-based KASAN modes:
> https://lore.kernel.org/all/cover.1658189199.git.andreyknvl@google.com/

To be clear, the stack ring buffer implementation for the KASAN
tag-based modes still uses the stack depot as a back end to store
stack traces.

I plan to explore redesigning the stack depot implementation to allow
evicting unneeded stack traces as the next step. (The goal is to have
a memory-bounded stack depot that doesn't just stop collecting stack
traces once the memory limit is reached.) Having a refcount for each
saved stack trace will likely be a part of this redesign.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZckFNqDA2SJSMjM7gpUF_U7Ps_3u%2BJzvN_cKvskz0FuOQ%40mail.gmail.com.
