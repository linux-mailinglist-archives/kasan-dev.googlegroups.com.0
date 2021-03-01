Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJGP6OAQMGQEVP3F7KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 32EA9327F08
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Mar 2021 14:09:57 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id n141sf8537132oig.16
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Mar 2021 05:09:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614604196; cv=pass;
        d=google.com; s=arc-20160816;
        b=aUiiV6b6k5WCU2daTIiRkDKs6wRRznbzuQu0xgZxVGvUMRiQHJS3nZHISiIXrlnmRb
         C408zSHCAiGoTgWiNoP8MsVXVJTc7DMFO665W7AyXVIsFQQln5tBnkyPtBrJnrhBCjxh
         8fVrC9hqRpJa84fMgDnkPHWPzUQPnnB2QGhYae1AhImARxx/56oxaGKCQpWCA+s13AVJ
         D3b5+2U83FPtpVoT/1jXRmFp/xX4jFvFpRsLELcJRRXQZ2+RFTB7IC5L7ZrIJcsZge+6
         Iuy5nYWd70KBllrixan6Fq+o0AySw+x/dd9mK8aK+Q9uwmw2Yxrh+XG5z2G5/THQalGU
         6UiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lRG9Q95dzFNPFRd3rvjFhfpYdPomaz8Si+h2gb6qsdA=;
        b=ktmVrrWv0niF8O940xlUNIbcohWO7Ja88g1OVeC5ZtB4Up2EPxNWYrBn9RrL8RKBHV
         D3vPYrCJSFEJCJNsM9+M5k/93OJtJUJJNkRzVR2S+ksANEaITtJmBF4DUZ5pMK4Go9E6
         UIme8+S+nCnxT/7BuVIMXs1NPJErE1w4eYnjR5u/GIhm66dAwFIJMnAj8mXaNH3BJPRs
         mnOredepDw+86mzIE5//XcsJuHiuUWSgkCDmRiLpm+mHM7IK6bgF16+Rjlgc4tievMkp
         EvPufrAuPLLkwhWuPqi4Uzz4uYdpDyk3XanzAAy4jc+Xn2gAZJimF6DQjrlzPPmM3f9V
         vynA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N9UswwOM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lRG9Q95dzFNPFRd3rvjFhfpYdPomaz8Si+h2gb6qsdA=;
        b=fV4BEjI8GzCAgColQn4QxN/QXHAUAisSrmZRbcXtPgDYiQreqt2DNV5BrCIen+kYjY
         9OjiC743AvYkCJqeFvl6elxyyLM4BUM+2pncoe6skTktqqIIIqjXCZpYs4+97ksBJw+2
         pGyzAApHvZzi/rwuJgAUGXFM+WkfMgs6BM7Vzpr0ocNp3UVwT86L03JwMZwtlbE5GMMV
         kT5dQmnvtJtabjJivaEOJmWy75LFwDIFKykTgltMy/4bV9aWd68GF2lcqEjYI/XydOXN
         HpPxPpb0b3NYbT2ZRZJ/92+NvTS/9hi2/HPyl7cEzJ+5SeZ8rqEZLMKcFl7oPyThe7ts
         k7+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lRG9Q95dzFNPFRd3rvjFhfpYdPomaz8Si+h2gb6qsdA=;
        b=HUz31skGGCM0NwssAAEdN4lt2bm4WfUzicf/KZo+am7fEeBmXPXy1C5X71qRAhirMz
         xM48qBLZzBUgYNIuOb1JKaFG2sS5AWhgpP3K+1yRynOvZ2kKVSdCiK4ryGn6U2JghaZQ
         vjpq37n+oNKCv5DP/Nk4iod58IdkvuFEUv0tvDb6ML+T+xKR8SUVSKLP+pyUjP9iMk86
         cl0PnJ48DTkga5oKy3b9JBqXKg+xkkqf0IAE1R+ztq3Nd/8qARIOTtMomvv5+GVD1+w2
         VlKjBzgDBjHmkfc5MmKBUu2wOPYlcsu3w9evoESxFVFluyfAG33KqsycT5zDYAzOXdpV
         DI+w==
X-Gm-Message-State: AOAM530mlEG1RetM3v2TdyRxDT/zU1lUm4mgggSJZKeC2tX3jVe2vJnN
	LthK9V1+Px6LeLnarfwUBOs=
X-Google-Smtp-Source: ABdhPJxyzWKyC7jDTD8vuavdzeZOApRr0HXej26NkRsXdcS4r969FJUtW7BYM5iIcT7OzT14HGJhbA==
X-Received: by 2002:aca:170f:: with SMTP id j15mr11414794oii.155.1614604196183;
        Mon, 01 Mar 2021 05:09:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:75d8:: with SMTP id q207ls4236530oic.3.gmail; Mon, 01
 Mar 2021 05:09:55 -0800 (PST)
X-Received: by 2002:aca:4a4d:: with SMTP id x74mr11716150oia.110.1614604195793;
        Mon, 01 Mar 2021 05:09:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614604195; cv=none;
        d=google.com; s=arc-20160816;
        b=dlj0X8mmB8JJDhNhFz3LXmSt6mxW4eRV6ui6WYUl8psb5yFqC3Fx00tDSqTu1YlPuu
         vEJgaouf2QcjKO00WsRQBIUZfOeKEIbE/wXvhn+lc2hw2X92/897reN/GDJFKPXwcSQZ
         prg+rCY88Ed3kk812c9kAorPiIwJCjaEBJwpm405cQPcV1XqSCaTzOp5EIxb/GKafUhp
         9wtInhYaP0SMEkNE/nd/6cCNPKpdnd0eobeHd1IjpgWyM6MCglqPUlGoxGnXHjcqCtIY
         pVl4cjGVUpFgLnnM5JtaVv7xUpf+3YSI26VWTY9xZ0wSjO11SrM7pjSMQzPHKXuwzRt2
         ItMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JE/WOX7Fgq+LbsFTLEswR+Vht+S0CD5m/Xd62AG1yLA=;
        b=Hnr5vm3vbFDCFNmo83i5Tm7LpdcK428SSgW0+munvzrY5lTZ9h0PWeOvAS/kUNsUOa
         1+HxTIr0NRMIDKS8pW00JTvwJeNoecKMC6UA5V1e2VWsV4bvClQdXD8E5xNayJcrT6Wt
         rhUI7aTyDDUYUmHEQ7apU2nrNWGkj00F+2TxpNK50+tfd4X2Diwg2no4GDHpXLO9b9Gz
         gn21SJU6lxVlezk/WhjrAqHXfM5Wm9NpS3N2Zj5zZqzT06MchxnovTn5NPZeeiM5Rtei
         mfGvDwBCmdrB5DwUZhUq4dF9XX7GqLhLcceaC0+/7zCNwYjvgv4PBNSxcZEdJM68ZGzD
         C3wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=N9UswwOM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id v26si933372otn.1.2021.03.01.05.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Mar 2021 05:09:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id o3so17928593oic.8
        for <kasan-dev@googlegroups.com>; Mon, 01 Mar 2021 05:09:55 -0800 (PST)
X-Received: by 2002:a05:6808:10d3:: with SMTP id s19mr11729523ois.70.1614604195332;
 Mon, 01 Mar 2021 05:09:55 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org> <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local> <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
 <20200710175300.GA31697@C02TD0UTHF1T.local> <20200727175854.GC68855@C02TD0UTHF1T.local>
 <CANpmjNOtVskyAh2Bi=iCBXJW6GOQWxXpGmMj9T8Q7qGB7Fm_Ag@mail.gmail.com>
 <000601d6909d$85b40100$911c0300$@codeaurora.org> <20200923114739.GA74273@C02TD0UTHF1T.local>
In-Reply-To: <20200923114739.GA74273@C02TD0UTHF1T.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 1 Mar 2021 14:09:43 +0100
Message-ID: <CANpmjNNk8MHXNsHdyWqcO1VxREv+LP0sxid9LZOy+2Pk8i9h+w@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: Mark Rutland <mark.rutland@arm.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=N9UswwOM;       spf=pass
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

It's 2021, and I'd like to check if we have all the pieces in place
for KCSAN support on arm64. While it might not be terribly urgent
right now, I think we have all the blockers resolved.

On Wed, 23 Sept 2020 at 13:47, Mark Rutland <mark.rutland@arm.com> wrote:
[...]
> The main issues are:
>
> * Current builds of clang miscompile generated functions when BTI is
>   enabled, leading to build-time warnings (and potentially runtime
>   issues). I was hoping this was going to be fixed soon (and was
>   originally going to wait for the clang 11 release), but this seems to
>   be a larger structural issue with LLVM that we will have to workaround
>   for the timebeing.
>
>   This needs some Makefile/Kconfig work to forbid the combination of BTI
>   with any feature relying on compiler-generated functions, until clang
>   handles this correctly.

I think https://reviews.llvm.org/D85649 fixed the BTI issue with
Clang. Or was there something else missing?

> * KCSAN currently instruments some functions which are not safe to
>   instrument (e.g. code used during code patching, exception entry),
>   leading to crashes and hangs for common configurations (e.g. with LSE
>   atomics). This has also highlisted some existing issues in this area
>   (e.g. with other instrumentation).
>
>   I'm auditing and reworking code to address this, but I don't have a
>   good enough patch series yet. I intend to post that prework after rc1,
>   and hopefully the necessary bits are small enough that KCSAN can
>   follow in the same merge window.
[...]
> > -----Original Message-----
> > From: Marco Elver <elver@google.com>
[...]
> > Let's see which one comes first: BTI getting fixed with Clang; or mainlining GCC support [1] and having GCC 11 released.

If Clang still has issues, KCSAN works with GCC 11, which will be
released this year.

Mark, was there anything else blocking?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNk8MHXNsHdyWqcO1VxREv%2BLP0sxid9LZOy%2B2Pk8i9h%2Bw%40mail.gmail.com.
