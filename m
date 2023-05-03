Return-Path: <kasan-dev+bncBC7OD3FKWUERB66FZKRAMGQE4SHGVUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A60FD6F5D8E
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:07:56 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-61b7313c804sf7674066d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:07:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683137275; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZY0p0p5U8ZmacraRDmwc4woyWmw7ChjrlNO/egUdilSgLKC5NrggS+5a8629DCczh3
         flpuLmW2QTvhspE09H6rlOgwVXlvTTVIMHWeFkRkf8AOQPhis1to80tXuisecX/6lCfe
         nLdHi9WqNfU3NEkzkFUulmU0Sqawsr3Ku2UThb/ZoPYcgYFzpKxg4sqvc2on9shlBCS6
         o9WKgjKdg6Jmr+nRnqcKB4smd3pqbvHHhqbZGmON5ymA5CtxjFfU5EbzOw0bM2G912ym
         XGH3qkPYa6GiJLqAIQVS1J9tMOd/qzwFsn8xjrqjIkHuGsL167mf2Z5ezul9htYEtmwP
         UsYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=spKyo6Xm4GH0rFDTm+hZVUlwAij0gdrvCBfvQHN/8gA=;
        b=PUohtLm7L1n0rJPNhemgMQ2DWP0nQIxBrZaHrKCWHFETJgDAN3SXj+/gz+E3BPibtO
         jiVMSnFlwtyNCfWSZrHSLbrYoA47AmEcnI+AtWWfOh4/x6AIaiEM/Sh1xhoEJqWnD3Lz
         6RheTwYw2Ax8DQju3eQH6c4n6qx5L1Fg83sABeWCB8tLhVprd3WfFp3Rs9/BhraR7tr/
         U7ItcDJwCwGKZC+sNQ++sRgXasqsuokTP9zLSCHq67aMDrN8xVIRp4R35MAmR86b/yCP
         a6pyoBz1fWzXTsanNq9oqfaIpUu21ZM5P37sVYZTc4XxhTI3eMhZE3KE6kLPc4B/Q46J
         wbaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=CiPRLrpS;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683137275; x=1685729275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=spKyo6Xm4GH0rFDTm+hZVUlwAij0gdrvCBfvQHN/8gA=;
        b=LlSAppwHkzDCA0b+UX31Ih4S6eN5Un/I+T7XTeZqYj8UKM9t35ZwBayRhGS4LWFVz+
         jKcKzKXlBRvRhAhDxONOFr8LxEEqyaoqCNQdJnfkXVhv9MLtsUWp0wmvjK45N/8GXBU8
         V6WWTMRq185VvdGICK9BR5tET3YQi1P9xnhkFgrL+qBFhQ8iuZXaXEsQFMZ1CB/DdRS3
         o/jbX/cmKDYWrIjO5Mv3LckXyTIIYFrgMe+UJiX779dWHERRDGn4xrBXRBPeFH+NCILY
         5aB6U+8Sp7+kyYcrwEKArneZyq7tDrVtahtYbzbstwPcXMhT2FePggziF8ZKt5uRogrL
         Kdhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683137275; x=1685729275;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=spKyo6Xm4GH0rFDTm+hZVUlwAij0gdrvCBfvQHN/8gA=;
        b=J2ElPuRh+doSqgCbeGPvHJfV7qulg9x7nETsN0EJRoeIEzaduDx3B0JV5YF7AL0kuL
         L/GWkdvupxJfo0/8t8vfh0PEbPCjvPg7zQSQH8Ly0V2XQyBw8Lea9Zo6xRLrvgAvqhVc
         yZSKgp5yohYj8EoljcLQ3W/RZi1G9P2RTVCsW5nc5iArxaHBass4yivXlXgDGdLtrFIn
         hHT7ggVrGkrZWRji6dwsDXz1JFJE+8L/SOqz3+yRTKKjtft4pU8093AnyIVbNILAElbR
         NviFpXoLyxPCJyW8JVBdUyFBZjifAa5rGB5/eI9hIJg0gpZFcV6tTV74qSTfG3htlRR7
         WCmw==
X-Gm-Message-State: AC+VfDw2BMkCpuIL5ktYxeG3K8TTH4u3043TTVgof6Vke/dydENvK4MO
	xxGwxptBIiNMz/lEFDWIDes=
X-Google-Smtp-Source: ACHHUZ54cHcud/ajU9Dw8nVxwTKgs0gmU3Z5eE2mFGnuvxTPNdVr5Kv3rxtaX4kLSo0gUZ+G9Ai94Q==
X-Received: by 2002:ad4:57ad:0:b0:61b:5ea2:4a0a with SMTP id g13-20020ad457ad000000b0061b5ea24a0amr1606359qvx.5.1683137275682;
        Wed, 03 May 2023 11:07:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4d03:b0:3f2:9818:98f9 with SMTP id
 fd3-20020a05622a4d0300b003f2981898f9ls2681748qtb.4.-pod-prod-gmail; Wed, 03
 May 2023 11:07:55 -0700 (PDT)
X-Received: by 2002:ac8:5f09:0:b0:3ee:8baf:29bf with SMTP id x9-20020ac85f09000000b003ee8baf29bfmr1198338qta.42.1683137275196;
        Wed, 03 May 2023 11:07:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683137275; cv=none;
        d=google.com; s=arc-20160816;
        b=yYotd/hPmkuplcskNAfSmqc58FeL/5WnNP7M2Bdgx6+im7fenIzl23CwizccREVAUV
         z8WwPjf+q/vqjuwQ3sAdddIHxHT6JuTHETpCN/s9gbo0ZxuA/2fY0AwkTjCXbuYFyZdR
         GmNeXJjcSKUTOgjmoH0Q5a9xDrTNHcUzFJVe7UB/0sFqKT/38SEldNdERyzMkb5LkpNn
         DtQ9Oi0R5dHVykjoHUwPDNSjATM9LLQ6QBUCk2hgUYMkjecMrYTMxgjCXC8Jo/jMWmkH
         xbP0W/sa6LZuEzaqjy9xGxnxL1fyw6X601IIZBA8SfvOKk4TmjKCNW3MTBbZ89xoFWmI
         h0hA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lYpn5fAZ9k+tc7itapEv1evmei0G939nEHfVs4IvTnU=;
        b=aa8wwAEzEuUaoGpLcHNFlE0H5FT16Mk1H5thfA+6Vk9PJhbHpxUIIHXUFv2Aw962EM
         Eo54Xy/C/oofiyZRxMbAlfLHqTOcvwjGVzzU2URtuUgIX6F0arxD4PqjMG8bje1UIQFm
         kY9uD1zGbbF1FzTudDZTZvV4ZqDivlnJIlBCmB/bZhLIiUtOYmJHN244Qttt30k9PsW4
         /quhfd/dRwpjJqJ3YrxobiBzUlyZEipuWOsWl37Ap5tFYq211PcgQ8z8C+f55meRKT+2
         bYwtqoKgNu7uxEf1cKXMHZP8/ypAi0LVvuE7L0h1vZX87MxFpFw3rO6BOLZGwqQpKcEr
         gDTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=CiPRLrpS;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb34.google.com (mail-yb1-xb34.google.com. [2607:f8b0:4864:20::b34])
        by gmr-mx.google.com with ESMTPS id ra22-20020a05620a8c9600b007537d2c1128si109906qkn.7.2023.05.03.11.07.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 11:07:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as permitted sender) client-ip=2607:f8b0:4864:20::b34;
Received: by mail-yb1-xb34.google.com with SMTP id 3f1490d57ef6-b9e27684b53so3221630276.0
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 11:07:55 -0700 (PDT)
X-Received: by 2002:a25:160a:0:b0:b9e:2697:9d96 with SMTP id
 10-20020a25160a000000b00b9e26979d96mr9339675ybw.3.1683137274526; Wed, 03 May
 2023 11:07:54 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <CAJuCfpHxbYFxDENYFfnggh1D8ot4s493PQX0C7kD-JLvixC-Vg@mail.gmail.com>
 <20230503122839.0d9934c5@gandalf.local.home> <CAJuCfpFYq7CZS4y2ZiF+AJHRKwnyhmZCk_uuTwFse26DxGh-qQ@mail.gmail.com>
 <20230503140337.0f7127b2@gandalf.local.home>
In-Reply-To: <20230503140337.0f7127b2@gandalf.local.home>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 11:07:43 -0700
Message-ID: <CAJuCfpFZsPibxrj163ypZQFOMmRTQe+=qJbZ8=o2kd1g0p=QQw@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Steven Rostedt <rostedt@goodmis.org>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, kent.overstreet@linux.dev, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=CiPRLrpS;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b34 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Wed, May 3, 2023 at 11:03=E2=80=AFAM Steven Rostedt <rostedt@goodmis.org=
> wrote:
>
> On Wed, 3 May 2023 10:40:42 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > > This approach is actually quite common, especially since tagging ever=
y
> > > instance is usually overkill, as if you trace function calls in a run=
ning
> > > kernel, you will find that only a small percentage of the kernel ever
> > > executes. It's possible that you will be allocating a lot of tags tha=
t will
> > > never be used. If run time allocation is possible, that is usually th=
e
> > > better approach.
> >
> > True but the memory overhead should not be prohibitive here. As a
> > ballpark number, on my machine I see there are 4838 individual
> > allocation locations and each codetag structure is 32 bytes, so that's
> > 152KB.
>
> If it's not that big, then allocating at runtime should not be an issue
> either. If runtime allocation can make it less intrusive to the code, tha=
t
> would be more rationale to do so.

As I noted, this issue is minor since we can be smart about how we
allocate these entries. The main issue is the performance overhead.
The kmalloc path is extremely fast and very hot. Even adding a per-cpu
increment in our patchset has a 35% overhead. Adding an additional
lookup here would prevent us from having it enabled all the time in
production.

>
> -- Steve

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFZsPibxrj163ypZQFOMmRTQe%2B%3DqJbZ8%3Do2kd1g0p%3DQQw%40mai=
l.gmail.com.
