Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4UCUKDAMGQEYEISGRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id F323E3A7BEF
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 12:31:15 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id l13-20020a9d734d0000b02903db3d2b53fasf9098858otk.6
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:31:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623753074; cv=pass;
        d=google.com; s=arc-20160816;
        b=wY+VBt65MmdATMO7XLeXIFwLbdV3PBRc9OZJcq87V+MSi3DT6Jk9iTojAZo84a+5PR
         dweuijmUmNMTEUdDttv5I2nMxvEM+FtNIL/WL88nHG0zGkGXTw6zcLGO3XQjlXVOuEUJ
         CeEkijkFtA2zL7P2RQDbGXZdZ+W5VZXyt4R9+295Hzf29ExkbB4odwKTCar16673+Xio
         3Wbul6r3Vfj4OiYOw1eESPfYhwF25BEnAQQGdgaZ8Ehcr8CzFXdwxe7NYkhs94n6MCCB
         viM8URdb026xIhiD3exnZ7+9TYq2axqyOPnN3xVcz0jK7CruaHhlJ2n/rDToCvPwnGQ0
         Cvog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1pwdZyXbNsXjBjQDCfkfzYi9ysrZuWvgKOEshy81FTg=;
        b=h+sWYLZfhA8Q+erfj5cTsrwU+9bN9dfL4xl6mYjA8H8XFqwraUPKrIwerd0LY3RgEV
         2z/Cc4iEuaqUohya6QLV8Q4K5qyjMwHU1Seo4siBeyTPKoBdg0nliyy1TnBRYZjxaiA9
         5AgMwFqnz06jtlMJ2YLmpVKpK3acriecWUI2bOHBgcPoFcUqgq1BEUOj51OTwU9el/r+
         KbqEkxmjoKlN3nHRSFJDOxwqMXI/Q8SA7YlKVOBV7yodS6AuanF8IYLvceE2zLK/2qoS
         lOufWzU3DpDOysHo4Ts0CnGVdtpGMxYBeMlmedEpRMLo0sd/8R20YaMFd7YfsS7C5rtP
         8Y9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YHM+AxYL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1pwdZyXbNsXjBjQDCfkfzYi9ysrZuWvgKOEshy81FTg=;
        b=Fa1kmWz7fJuCJCXVOOflwxogB1xkqqxGpQWqlvbFv4KbMbOu256MxRSpuLUqqafXvQ
         oH4ZU6yBOMtuFs+Zq+n5szYelvVxNTPUu39PBM5wQuB5YB0QBhf02b5hoaMk+x9U5xKw
         LBe3eQPiODrOC9F+btKsITSbqwcrwLDCIhzCT98Ny9LXbYamKfpbfh+6qD8MqOU/GPnt
         sI0CJAqxwyaIZjonVFpMHhqhA4YGENy0ptwq34Cg9Yry4vNGzhDnyQ6+sO3ELLHdr5gM
         fVFidxqtvGSR+cHDOuIvOJLBoBCYD9TnKuemMm4a3edOeTlpDYj4lXeAQEzd00WdZ6gW
         FatA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1pwdZyXbNsXjBjQDCfkfzYi9ysrZuWvgKOEshy81FTg=;
        b=Z10N9Zj8hp9KilGbZbpVIBW/4j/UNV5JfG2NFne3zTwv87/w4wzq9t1ANQsLyIXgsm
         S2reNd7OKodCvIVNG/sdi0HSOCc6Kabm8VtXgTltRlNQCgEWdGAb3LhJezbE0PCxiwdL
         mEwpRk+cJHGNe27SJFzZUGTBmrT9pBkX5nwb6k8rgLGc97AHcaG2sIM52VFnwjyejfnQ
         4Q6668aBGZdCKRB3DjBgxd/lRDWa4xDAXp37t3GjJ0dR5FtKu6ImleSlhp5GlJBVeCl0
         ESfaTH3/u2MaB/cLM+jj/Caseq+udU7PWrCHAipzQBBhfe1KdP6MxC2/68dFGpWBJ4O+
         R2Jw==
X-Gm-Message-State: AOAM533Grpm0rKNoLA/g08bUJzAnlw1Pg5a2ooKYAH/+GL2q7/HZsDY4
	FLg0a7dt3jX9AbdlFXPuSs4=
X-Google-Smtp-Source: ABdhPJzG6YCs8Xo1CZibIBFPz7oqvtbVn3OF41FwjRfUXkiG63imKn488IoN/c3kU9fbk3wj4RnJaA==
X-Received: by 2002:a05:6830:22ec:: with SMTP id t12mr17486003otc.243.1623753074549;
        Tue, 15 Jun 2021 03:31:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:30c1:: with SMTP id r1ls7200162otg.5.gmail; Tue, 15 Jun
 2021 03:31:14 -0700 (PDT)
X-Received: by 2002:a05:6830:154b:: with SMTP id l11mr17654394otp.66.1623753074214;
        Tue, 15 Jun 2021 03:31:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623753074; cv=none;
        d=google.com; s=arc-20160816;
        b=WyQawezCwDxIMRN/apiER9hZUBAU0AP29+ytK4DtqEoQ9eXTndFtMYVvKWtrlAPiWq
         tITgi7pqF35naPR0UDbHLzkkVuLIebubHOu0SJVr+vfU68dtSUmMAkDg68udHIgpjm9p
         b8/ZvlSut00S0YPMGigrHju3pmKjsiinGM6xkn3LxkQDEs+5ag82qfy3lp3kpP05XmhS
         YOHrrcczHYcdBFoFApYIyV/dD7XNmcheeRCua5fLVH5F8ohbeNf0ExG8iQmZLI0bBFNe
         T2tYX4mfSYcAIsC6xUhEsyficAuVAsX1AEvvFv02O6mktD05MeqbaP+T/9F7jmmTVxMx
         WGnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QY2/939t5WrgTBjBlWlTUN2kXiGUMSX5srdzV+Tkpzg=;
        b=bNji4ktqrnkAnubnc4JiMZQqGVC59XQCEJyTnIuPDntoyt5wQYrHU9eDNgSpbXDVcC
         YM0T/eJ/iRSU3pgUdPCz4STWpDRDQOjl3L8QaJfZ2LvDYZ1pGysvwrqJaieWr8n+UGJY
         D/f7I0M+56BGuhH7sVKfmcOmoKbYS9B+emkT8CQ4en/mFbT5syjPmHTYIJSRjKzCkPwz
         t6d7D97UQdLLQXyxgEaHLixGFjlWsfiu2zD9stK6XyvZxJkDSuq9Tm33qxz+ywdvwRba
         tLvyRIl7yV1awN31B8CS3RAAvPFswE95KmtOilAxw13QbsgaNj6P2KqOAZivpKjJgly5
         OiRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YHM+AxYL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x330.google.com (mail-ot1-x330.google.com. [2607:f8b0:4864:20::330])
        by gmr-mx.google.com with ESMTPS id c22si210706oiy.1.2021.06.15.03.31.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 03:31:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as permitted sender) client-ip=2607:f8b0:4864:20::330;
Received: by mail-ot1-x330.google.com with SMTP id 7-20020a9d0d070000b0290439abcef697so8341477oti.2
        for <kasan-dev@googlegroups.com>; Tue, 15 Jun 2021 03:31:14 -0700 (PDT)
X-Received: by 2002:a05:6830:93:: with SMTP id a19mr17226203oto.17.1623753073778;
 Tue, 15 Jun 2021 03:31:13 -0700 (PDT)
MIME-Version: 1.0
References: <20210615014705.2234866-1-dja@axtens.net>
In-Reply-To: <20210615014705.2234866-1-dja@axtens.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Jun 2021 12:31:02 +0200
Message-ID: <CANpmjNO9EdwPEiNPu630a2kgsxMXYiNU_phKH2=7Z5YFRCSR1A@mail.gmail.com>
Subject: Re: [PATCH v12 0/6] KASAN core changes for ppc64 radix KASAN
To: Daniel Axtens <dja@axtens.net>
Cc: LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, linuxppc-dev@lists.ozlabs.org, 
	kasan-dev <kasan-dev@googlegroups.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, 
	aneesh.kumar@linux.ibm.com, Balbir Singh <bsingharora@gmail.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YHM+AxYL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::330 as
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

[+Cc Andrey]

On Tue, 15 Jun 2021 at 03:47, Daniel Axtens <dja@axtens.net> wrote:
>
> Building on the work of Christophe, Aneesh and Balbir, I've ported
> KASAN to 64-bit Book3S kernels running on the Radix MMU.
>
> I've been trying this for a while, but we keep having collisions
> between the kasan code in the mm tree and the code I want to put in to
> the ppc tree. So my aim here is for patches 1 through 4 or 1 through 5
> to go in via the mm tree.

I think this is reasonable. I'd suggest just sending non-ppc patches
separately (i.e. split the series explicitly) to KASAN maintainers,
and ensure to Cc Andrew, too. Just point at this series to illustrate
how it'll be used.

I think the patches are fine, but I'm not entirely sure about the
current placements of kasan_arch_is_ready(), so hopefully Andrey can
also have a look.


> I will then propose the powerpc changes for
> a later cycle. (I have attached them to this series as an RFC, and
> there are still outstanding review comments I need to attend to.)
>
> v12 applies to next-20210611. There should be no noticable changes to
> other platforms.
>
> Kind regards,
> Daniel
>
> Daniel Axtens (6):
>   kasan: allow an architecture to disable inline instrumentation
>   kasan: allow architectures to provide an outline readiness check
>   kasan: define and use MAX_PTRS_PER_* for early shadow tables

^^ Up to here could be a separate series to go through -mm.

>   kasan: Document support on 32-bit powerpc

^^ The Documentation changes are minimal and not just confined to
kasan.rst it seems. In fact your "powerpc: Book3S .." patch changes
Documentation more. So you could just take "kasan: Document support on
32-bit powerpc" through ppc tree as well.

>   powerpc/mm/kasan: rename kasan_init_32.c to init_32.c
>   [RFC] powerpc: Book3S 64-bit outline-only KASAN support

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO9EdwPEiNPu630a2kgsxMXYiNU_phKH2%3D7Z5YFRCSR1A%40mail.gmail.com.
