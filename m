Return-Path: <kasan-dev+bncBDW2JDUY5AORBD6D26LAMGQE4WX3JHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D9CA578DA4
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 00:41:21 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id e14-20020a9d63ce000000b0061c6ca80c54sf7104632otl.0
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 15:41:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658184079; cv=pass;
        d=google.com; s=arc-20160816;
        b=h5t9jmTIoUEJ1UMPHztShUeVukmHbH8S1ukpCtFLU97ljP3FseYGVRQuQGLgtpOemD
         aMclCnkK0ReYE1/0oftb3Dd+80xoSjBeC1OlwcplDOumKS+60xqy1EPvkJ/k/pRyMqzF
         AoQEiYebo63t5ZBO7CoyhCVP9fuC0CIMl51oMlnA7b04vGaptHDPlYaC4MOf7aG5hikV
         Yo80/FOkHdPVC4REe6OK8VN6PbNip758nBxxVxYfJA/wtF9BAto3xY/acGL11eWoaIDE
         QWGxOnln3vbZ9I8udN7mQlGv4ceIUcGPEuF8KZs0+v9d4aI5yYtEFakMc/ZpNWq43doj
         vR8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=1ZlRZhuLA/926i6kvK30G4PTE/mNxJtT+rq+g3BXUQ4=;
        b=PYJEfpPjQMDpgsggKrMiS6FnsZ6/qJ6wOQ2LfiRK98qYAlTcNHxKmBiPFZBb8ID1BK
         a6wV8jUtdm2yBIFYGTW36noQqaNDm1sefzVUFyqW33bZhZ/XOcckm3wrbsPLu8eUob+b
         VSfzD3bVwQV6s0WiN4CsTMp2QFRWbGsKE79bpZnnzQUZOi5808gMYZ5CGRPqkBUhPmhC
         Qfs3J401H2nm48Gs9VN2yDDAFetKMSj10jbyFex5Mh7bvVIBFUDbs3EC4WVK+P9W/Zpc
         GR7f0zWHPVw3Yvb62B/v/MYFTICb+b3e0pfH0F4tdySwDJ8Sz8UjJrzohMLum/XIkDUV
         886g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IROMFuz2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ZlRZhuLA/926i6kvK30G4PTE/mNxJtT+rq+g3BXUQ4=;
        b=iTVbNKsqSlwgtFwomiVrnupYCEBbZAazfD9eKrhwK0yncPltch2u1QTwBUeIoWF+w2
         SV0j4h3GKWxIkEcFcSslJZPh7htBF5PE2Ntkuw1lfajd4RhMzjLGw6B99druwGq4OsPN
         FxH9xpRuKRsKMH/dPiIgjCuA+4GgqZvfK52nvWZ3iixp0mkW4B2SpDrmXjq2bV6Lnmyj
         XseG4Yd37D0tVo5RnRWYm9beBk4vWVAa6w5gK6tb3jS0H45wFugc5z3Eq1IgpyD66h23
         IqYTHEtZwL/GGEx8gm9xitTHeAgTvPjWAg9mrOTcPmV976GmX8a0guFzj6gryRVMiNEU
         YtUA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ZlRZhuLA/926i6kvK30G4PTE/mNxJtT+rq+g3BXUQ4=;
        b=CldabDR3bBNnGXfB5bjDp6zf536jwNPMGzut/sBNhMpmlXEQdvJ46kl2A6koEBMag4
         5qO42SK/bQSLavqjb0+dGOnNl2HoEOF8lri1t8mOrmiR66SWnQsDDX/wf78cY59A1JOY
         KLwLNxkKhtDa9xtymkK1SbpjqkLk3tZ58oYxvzSJR08xlqFy13RY5wAOydl0YkK3LWtm
         npv/5K0TSCZZlIjEcXfA2q2NzqBbe+31LH87rFfXD0snschZqt1vy2FXP4EEFFuEofaG
         ykvc0Q3+C7piAviQ7wmICHYzqLml3TndImjNcQTPZpUt1tgfLaZQrdYIZaC06QSfN2F3
         Lmvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1ZlRZhuLA/926i6kvK30G4PTE/mNxJtT+rq+g3BXUQ4=;
        b=Qv1UhGNBC7+fpKsxZdiRevgu/jK+0uaM3J9XgoBoNOdLv/74ZMzAb3ZQuI0AHqvxeO
         hdlyS5cgnWbTtAZFUZU+cPVwgvZsumIcyHtrfDorS6zIUO3xC7b+OIISzthJnGshq+A9
         4DGClhhYH7sI8TqzAdLuOvLiaFHC2kmeB4/yafcnUeGJuA+WuDrm8O0ELkLMR0dEuDQE
         rnY8bhu2xeHCj6rxJY1K4lEXIvL6WSjJ+JLSNMVF29BgkP9NS/vp+CXmwDYb6APsQPI/
         7sVhGxAyXGReX+J6RVelWnWCgJ7YW4fjJER+9kIsRiIWJSYLLvfNKGdqFSYvSL0ZNUbI
         Nj+A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+B+IyGmDvrZRQUWqHsEfLiqrqSImx55dQP74cUNxiaZhbTtqsn
	asIc3R7jsUR7MgvZFnbn6Fw=
X-Google-Smtp-Source: AGRyM1t7cvjMivRxTg+zKk0Nk8m/TfuM2E5xLgNSeV8aP0RCYAx7ambvSppk+nX4K+KWTVWiKObzNg==
X-Received: by 2002:a05:6808:1153:b0:337:a486:f1ca with SMTP id u19-20020a056808115300b00337a486f1camr16525243oiu.264.1658184079684;
        Mon, 18 Jul 2022 15:41:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:7a7:b0:10c:2137:38ad with SMTP id
 o39-20020a05687107a700b0010c213738adls64280oap.1.-pod-prod-gmail; Mon, 18 Jul
 2022 15:41:19 -0700 (PDT)
X-Received: by 2002:a05:6870:580f:b0:10d:8ba:ab4c with SMTP id r15-20020a056870580f00b0010d08baab4cmr10230138oap.125.1658184079301;
        Mon, 18 Jul 2022 15:41:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658184079; cv=none;
        d=google.com; s=arc-20160816;
        b=FmkDLTwh0zSqXHqumJ7aHWOZLO1cRCdcmbMdHQ9p2uFxpeGAk/yEBGTZ6hh0ffEanE
         55hZy0/cL35M6c0EJUF5zjJP0Bz7Nx0GTehOOUHfzb3wvScSciEu3nTEkqeiMpaWWuT9
         y2mdOeMiS6DfeVOCcZKfb/azDguHuHrwflpmGFyCU/+r/AsnYy7BaNUQVAo1tJoQTLBI
         ckipirP8ycpqxnjJ9nebLtilX/Nr9/MDIQII/KKymNWpJoEmucGN6kgevLCjcqWNeFMI
         48aqVYeHiwZaIeet+J/uDKCOPhX3RIHhumqOURnoMZCl/JLiQmymkseW9thgs0Ac46oN
         9RaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hV04gJeXIMaTZ1Jk1N+nIbNrqJFTcRn2y0JfEOihkw8=;
        b=wWWlfCjvAfMN6BIHulkGpdCI4olpqvF1t755vQPSBFa4woLHQC15HAJJCalTY5ySi+
         ks8XA28vezTYSCi1vZwt96KlW+ZxvxjiHHFCdeCSAvCK4Syay+EfiGjWJUgTixoNT5gv
         FTIXoi90ayLcXELk9GWa4UrsuW5aHMsBnfoNk0l+pGNzDB6LrqWgiZjB1431JS+gVPKh
         AdoLiCd/hjHaSzpryJWXMoTBpM2q0CsZXZ91+ecSaH8HegWsBC8g5N+Jbx+Zz8V6Rou5
         pk3WYlu7qudEyfycavNbr2iZdkA+oXue4iEFt+KUSP/uwChGBkV6ZaWpdj6CUa5AHjpI
         3LyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IROMFuz2;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id h4-20020a056870170400b0010c5005e1c8si1459412oae.3.2022.07.18.15.41.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Jul 2022 15:41:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id c20so9856075qtw.8
        for <kasan-dev@googlegroups.com>; Mon, 18 Jul 2022 15:41:19 -0700 (PDT)
X-Received: by 2002:ac8:7fc1:0:b0:31e:c575:a56c with SMTP id
 b1-20020ac87fc1000000b0031ec575a56cmr22857594qtk.11.1658184078807; Mon, 18
 Jul 2022 15:41:18 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1655150842.git.andreyknvl@google.com> <YqxKQpjJMwUCpbTt@elver.google.com>
In-Reply-To: <YqxKQpjJMwUCpbTt@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 19 Jul 2022 00:41:08 +0200
Message-ID: <CA+fCnZdsn1yRR9Ekzg9vpWjUw7F2E16RSo4B0cXbAb7PYo0SiA@mail.gmail.com>
Subject: Re: [PATCH 00/32] kasan: switch tag-based modes to stack ring from
 per-object metadata
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=IROMFuz2;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82e
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

On Fri, Jun 17, 2022 at 11:32 AM Marco Elver <elver@google.com> wrote:
>
> > The disadvantage:
> >
> > - If the affected object was allocated/freed long before the bug happened
> >   and the stack trace events were purged from the stack ring, the report
> >   will have no stack traces.
>
> Do you have statistics on how how likely this is? Maybe through
> identifying what the average lifetime of an entry in the stack ring is?
>
> How bad is this for very long lived objects (e.g. pagecache)?

I ran a test on Pixel 6: the stack ring of size (32 << 10) gets fully
rewritten every ~2.7 seconds during boot. Any buggy object that is
allocated/freed and then accessed with a bigger time span will not
have stack traces.

This can be dealt with by increasing the stack ring size, but this
comes down to how much memory one is willing to allocate for the stack
ring. If we decide to use sampling (saving stack traces only for every
Nth object), that will affect this too.

But any object that is allocated once during boot will be purged out
of the stack ring sooner or later. One could argue that such objects
are usually allocated at a single know place, so have a stack trace
won't considerably improve the report.

I would say that we need to deploy some solution, study the reports,
and adjust the implementation based on that.

> > Discussion
> > ==========
> >
> > The current implementation of the stack ring uses a single ring buffer for
> > the whole kernel. This might lead to contention due to atomic accesses to
> > the ring buffer index on multicore systems.
> >
> > It is unclear to me whether the performance impact from this contention
> > is significant compared to the slowdown introduced by collecting stack
> > traces.
>
> I agree, but once stack trace collection becomes faster (per your future
> plans below), this might need to be revisited.

Ack.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdsn1yRR9Ekzg9vpWjUw7F2E16RSo4B0cXbAb7PYo0SiA%40mail.gmail.com.
