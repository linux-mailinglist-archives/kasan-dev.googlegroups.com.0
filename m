Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXXMRCBAMGQEVAHPBDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5697332EC72
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Mar 2021 14:47:12 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id w15sf1937740ioa.17
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Mar 2021 05:47:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614952031; cv=pass;
        d=google.com; s=arc-20160816;
        b=0p3I/nOrF7nDdNBHTchhaCZrDwlAdLpVOBwQ6on2HQa7/fhH6dCWbbwPE/urLkVrIo
         3Aj8p3qSXQriHycVnU/FX4GB/r95WE3yI/1ohV8YEejwxUMkFGlFx6T3vy0YztrkOhAQ
         Hfy0tF4QWxUmDZ2WDGpPntd92oOzcWCmXZdYl18IbJVjdUHR8GE9H1r+4DJSwl48yDON
         WOfauVleNBpldTnHEN291QsfKdPUB5KVapS06BssVLS0H2Kb7lX2tMCGMB3qIoMXo8Tf
         Zfrq9fUAsgXfk0PdFoxVtcXvDUSCj5Dpr9TqZRRfDfUNxeeb0z6AeQSTmK/Zvrt3VJ4A
         1XYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eGlCkS9/fTsGeTmNCCcxNNCkCkrtpM+ACEwSBJrT1w0=;
        b=bn6NSXOU0h0aFLKx3Eadqvk1LXkyGZhUMvrja+zWHRlg6VTunWARvDYEKhkfev4Wse
         Vxh46wM/zpH5BBppbhhYUVSTr6IIgc68L60vCRJA1O5S4TCXXb2ZZm6P5bmrPSZF95P1
         ApkmE7RUx7R4+z7lJd6+RwtSnnqLbSroOLx25ZW3TsUhPgVkp+/fbL61wEZWhRKvcani
         /bs8fBb23UGUkZmpYGYlOpwLpEyszv53TIQ+/tgYh/jo2oYWWGwn7YMlvf8AWBL6t1Ek
         cDYHtsq+5R55X3Aq4vm1xQTmUY5kdEB0CDsiX2hAqpDZyUiKn8v8Ku05+uRb+bb+IVhc
         AvUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DhVOTTeN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eGlCkS9/fTsGeTmNCCcxNNCkCkrtpM+ACEwSBJrT1w0=;
        b=a2YO0tfaccafHK7OQ5VrFXJYnBFdB2sk/phkHv50tYrb0UqiOxsQokk7NVn3uUEycj
         3A+L5jWEM4FRQkhkXW5MV2PZu2ZrqMTHeFY2s8gRM+BvIrQscRcXl30tISGDHmXmtQLp
         /fmhSmH8hzHryPOyJzlrIP4a7UUf/MkC8twrLDmlgniDLkSscAKLO2C1rO2mNcd5PL82
         rq3M5GbxXrnB09Pyhf0LYAhZdPsCb1uD98pYJDd/g/5tNxW2baNIYOP82NkSSzkUeHZ8
         yvUvCfuCXoiXQcIDuShzmvCKgSQ+IKl/cly5jXNfgKeBeakDF7VYfYy9Sf6dhy6xbOO0
         818g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eGlCkS9/fTsGeTmNCCcxNNCkCkrtpM+ACEwSBJrT1w0=;
        b=ttDsRB0RmHxfz8Dp7KnI+X2HBjghxP3+w5tvQDSgFfJ/eiDAokUUrFRk0N2l8pP2T5
         PPIu7i9J5RmjXOYzSVbehMjal4yIqk+OihWvZA5QSkRnPkXhuC1w6vvOIssDcdwpyVww
         VLYPUbHp8bKTk6wXrm5PgVL65DkOBytwwUBnVz+SgjIw7ZXHRiZ+gauyVVc2bWB1LQlR
         dVHiEh3rZYFG8TLN4/bzy1teHTc76dNSeEt5/ED1Iye+dQ31QgDdGCthK1cg/Az1/5il
         8XsW70rgIwr9i968uDJBiW0TwoRpwcgHQNsFua3wwIk6/8qdiD507Okc6xfpnVtw66rS
         Gffw==
X-Gm-Message-State: AOAM530nF59Yaqw75zB/tD5p/aDberrEz4Tb8eKcrQwChL7gGJJIJnSh
	8TVduwrw3YOhwAH9sSU9MoY=
X-Google-Smtp-Source: ABdhPJyYBVG2c8XmDNH3SrGzQ7iRLcVfCxTpeqzYCePRUSbloph9Uj6U77h2eni9tqcieErbLegZaA==
X-Received: by 2002:a02:970e:: with SMTP id x14mr9972222jai.127.1614952030951;
        Fri, 05 Mar 2021 05:47:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1032:: with SMTP id o18ls2463953ilj.5.gmail; Fri,
 05 Mar 2021 05:47:10 -0800 (PST)
X-Received: by 2002:a92:b70a:: with SMTP id k10mr8602466ili.23.1614952030355;
        Fri, 05 Mar 2021 05:47:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614952030; cv=none;
        d=google.com; s=arc-20160816;
        b=uZodXHd+GuXeI7hy5zBGVsh6Gd67knrVS7HnMTMm8Hd7hfVpkevsDwM0j6mX39YWw7
         24rzKeDDZkYS7lSkKxh5u35qhVaoz437cr2fPni+AMtitNSiW7OvUUZ9iscIBGxSitx3
         nCIkkxSz/UpCiqaDXY9eWAWKuuLv6SPJiqm+eRLcTYsGS8lEreK+f5ZDdtPoUfJ4tRaC
         ED9ToaJVCWfwd7U/BzZZXq9zaWU6ot5Xs0HGbTvXjE8WxhOvoWt2JKfNKekYWNShxcc6
         Vo6A4NRQbJsc0zrwFAi9TQHRf5FS2nViEBkb1oaztFkkijcnSZLGmQPaierZNPYqhavj
         jMgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SInNMXqsGtA9/hulueI4v7s5Z4FGO7USmnkW6ykDyNk=;
        b=zbbDyuF0NO+1Ey9VxEAcDFDoyR+gCdEBtkdigA5bWB9KZIbA5Oy8vx8Q6MWyVUCD6L
         Km3p/hbjBA4uW/o1H7aqNyc4R5dQ1mOubge9jF7K4O3RHQ3LX8aKtc56bwgC9fiscWWt
         Sw5oLVzXBKBtFdZLIRUKGsZhqpxkUC7aoVtWCoLDo2QFXNORn10OgTnX8Z98iz6M4Ocr
         mRullsUOsPnsqoMXmE4LWxr/ckvFC6RpE8A65/Nn3MaBe79Ej8/z/CQRC7X8HX39HZCz
         Ve2Y3h64z+rnYp55Ra1UyFHNNlh1fDqot7GDr6cIs/O9teUGWlTlqCuBlP3tlLDwvcfV
         vDMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DhVOTTeN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22b.google.com (mail-oi1-x22b.google.com. [2607:f8b0:4864:20::22b])
        by gmr-mx.google.com with ESMTPS id y8si209505iom.1.2021.03.05.05.47.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Mar 2021 05:47:10 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22b as permitted sender) client-ip=2607:f8b0:4864:20::22b;
Received: by mail-oi1-x22b.google.com with SMTP id o3so2532425oic.8
        for <kasan-dev@googlegroups.com>; Fri, 05 Mar 2021 05:47:10 -0800 (PST)
X-Received: by 2002:a05:6808:10d3:: with SMTP id s19mr7309520ois.70.1614952029845;
 Fri, 05 Mar 2021 05:47:09 -0800 (PST)
MIME-Version: 1.0
References: <CANpmjNPGj4C2rr2FbSD+FC-GnWUvJrtdLyX5TYpJE_Um8CGu1Q@mail.gmail.com>
 <08a96c5d-4ae7-03b4-208f-956226dee6bb@csgroup.eu> <CANpmjNPYEmLtQEu5G=zJLUzOBaGoqNKwLyipDCxvytdKDKb7mg@mail.gmail.com>
 <ad61cb3a-2b4a-3754-5761-832a1dd0c34e@csgroup.eu> <CANpmjNOnVzei7frKcMzMHxaDXh5NvTA-Wpa29C2YC1GUxyKfhQ@mail.gmail.com>
 <f036c53d-7e81-763c-47f4-6024c6c5f058@csgroup.eu> <CANpmjNMn_CUrgeSqBgiKx4+J8a+XcxkaLPWoDMUvUEXk8+-jxg@mail.gmail.com>
 <7270e1cc-bb6b-99ee-0043-08a027b8d83a@csgroup.eu> <YEDXJ5JNkgvDFehc@elver.google.com>
 <874khqry78.fsf@mpe.ellerman.id.au> <YEHiq1ALdPn2crvP@elver.google.com>
 <f6e47f4f-6953-6584-f023-8b9c22d6974e@csgroup.eu> <CANpmjNM9o1s4O4v2T9HUohPdCDJzWcaC5KDrt_7BSVdTUQWagw@mail.gmail.com>
 <87tupprfan.fsf@mpe.ellerman.id.au>
In-Reply-To: <87tupprfan.fsf@mpe.ellerman.id.au>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Mar 2021 14:46:58 +0100
Message-ID: <CANpmjNMzY-Jmd9v9MHYqeQ934V91D25vtj85HwJkYuXS2a+4Yg@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Michael Ellerman <mpe@ellerman.id.au>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>, Alexander Potapenko <glider@google.com>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DhVOTTeN;       spf=pass
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

On Fri, 5 Mar 2021 at 12:49, Michael Ellerman <mpe@ellerman.id.au> wrote:
> Marco Elver <elver@google.com> writes:
> ...
> >
> > The choice is between:
> >
> > 1. ARCH_FUNC_PREFIX (as a matter of fact, the ARCH_FUNC_PREFIX patch
> > is already in -mm). Perhaps we could optimize it further, by checking
> > ARCH_FUNC_PREFIX in buf, and advancing buf like you propose, but I'm
> > not sure it's worth worrying about.
> >
> > 2. The dynamic solution that I proposed that does not use a hard-coded
> > '.' (or some variation thereof).
> >
> > Please tell me which solution you prefer, 1 or 2 -- I'd like to stop
> > bikeshedding here. If there's a compelling argument for hard-coding
> > the '.' in non-arch code, please clarify, but otherwise I'd like to
> > keep arch-specific things out of generic code.
>
> It's your choice, I was just trying to minimise the size of the wart you
> have to carry in kfence code to deal with it.
>
> The ARCH_FUNC_PREFIX solution is fine by me.

Thank you -- the ARCH_FUNC_PREFIX version is already in -mm, so let's
keep it. It's purely static vs the other options. Should another
debugging tool need something similar we can revisit whether to change
or move it.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMzY-Jmd9v9MHYqeQ934V91D25vtj85HwJkYuXS2a%2B4Yg%40mail.gmail.com.
