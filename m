Return-Path: <kasan-dev+bncBCCMH5WKTMGRBXFN2CZQMGQE26P2K4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id B159891034E
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 13:47:41 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4410367c230sf7555231cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 04:47:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718884060; cv=pass;
        d=google.com; s=arc-20160816;
        b=pX/ofg3Oc2RFa/Tw/L45YivlKSMafC1YbHqyNXJb6KkRz+2ldz44V9/ppL5BQ3gUtl
         m7R+wn5G64ddeGjrMuwU0QsFOgZNXzyM95jB5uzaqmu/nDSOk5n6/Q/Kgv8yD5FBva8A
         Atws2TSujyA7KLO7jQIUnMnOPbTgHVNvWY75SAXpwl5+GHDDMxFqiszFTQB2OS374jc9
         cw8qkqBtMuvlHff/ePNdzvnMaOaJx22z65Ypr4DbxtZugWJpzb7sdjTBuieyX7oG8Fjq
         MJ6/NM53vC7V2xQMcV5DcZ/FtMLloXZS5P1hpNEoomu5xQ2qcl2lrvjByIMkBqeR8Rty
         xi+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QB7fIA48GvP6bs0L9fFu75jwUsSwiCw0kDHXt5wbA2Q=;
        fh=3kI/ybpjqpgbBOVWumzmkFQhG3Jd7dqUNImwfghMmVw=;
        b=b9rlAkI2TUbjOy8Wtq2eahCKWrzhydlghjr/2nT7rpnUpQgHDZorEOHgaB3tIWAJwz
         hC4KaThamq4t9GLPMQeolRcNcxb85/RjmHbE2bNjwkdTRyzQ6rFlRhpODgWNaEddgjHG
         hyVJtNLOFWHWMkrDaN1BYugmqQT7iHeIGWkOvVRs5SUekOblxjr8hUFHkrRjYCCa1oE3
         7KdskBbmUgTScQzxykaX+CxF28Sy4jFM1YBBROMTn7HKSF2ugoxIn2OsXCxJgr0XxpDl
         wgcNWXduG6IO1uFfBqOigx3ou4+nnROWchIIowE1vbJGfM1fJeq4GQj2uSSnyvL4aEsE
         xvJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xpRhOv8b;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718884060; x=1719488860; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QB7fIA48GvP6bs0L9fFu75jwUsSwiCw0kDHXt5wbA2Q=;
        b=ghuBaVCbjvzFfo1y3bb0aFoVRituePE3dB/4NgFV+4h06sEEQio1YHVcUMvaIDNbIy
         jcbsa0/Fi4tXtL9KBbmsP0AxOuXesnGVNoHyhv05KNDDbwdRYIJJHZTj8V2I5sGuz6Sc
         jS5YhyMRacSSq3MVeTQzQcAcdx/JwwiVQIR0X+AUSAJcn7d+OTOBSLHhdKmmqFx/VDGM
         czBqQyR7hh+t1EBMm97SLs8JzAjYcksl7whF5SvdrSWjmmtPPlwowJUDfXZA3a0vPJMc
         pdYQVizXfXEKpsdYG4lF7/dHH9jnPAlFggDg2Cr7Mr8KXNwoadc2QVOoxejK38mMWiK2
         Q9iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718884060; x=1719488860;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=QB7fIA48GvP6bs0L9fFu75jwUsSwiCw0kDHXt5wbA2Q=;
        b=wV8ya8fggUyiL4q0piuM/5VI8Wkjkkt3MoUfelEMnqU7SiQIFaA0xs8UflYEH5B6BS
         a67s7D6GiL+E/8u9WoU/trTDoaAQfsI/ngpTT5/L/XWkzxAK0cyiDag8bk1TtwPihYtA
         ypK/QC8JBPsTvqfVRu+7C1OWnfQWdI2ZaXnFzQA6Y4Vx5FKLxapMJprWrVXaEy+ui4l/
         Y5JgWRJgdcXRriSdqHDDWsqB71G0O8IuCAWI+EMUNygcTkgJlU6nWKOmhVLDtD9le1v/
         AhOJqaW5Vbl+H++kngFZACssesqlJH+qNlYFNRWfBWd0MuJ1FqjymrHCj3uv1royzVU5
         1bnQ==
X-Forwarded-Encrypted: i=2; AJvYcCXstK3dZjG8Up3hBxqaq7VXCXnzrJ19+V21IQ1ufxfBx9hRIjegZn1ZRtqsKk1xl6i/00u/OQz1I/9HC5VEQ7pjym6/wevY4g==
X-Gm-Message-State: AOJu0YysAIREFit1+NiDbueLRebvHqBpuyP+diAXPHVeQAraI07vQxeR
	GrIY6eRTisI5f5PfjuvcmWPZRDa75Y0Ir9qScVcK23fYvDfRkgsX
X-Google-Smtp-Source: AGHT+IEkw580fZRqNzzxZp80zooYxiNyiLE5YtSo6kz9mApFPaSUCpZaIzT8xJPo7nFAEXQQoqFZkg==
X-Received: by 2002:ac8:7d88:0:b0:43d:f8ce:5c3 with SMTP id d75a77b69052e-444a7ac0c56mr55877521cf.42.1718884060384;
        Thu, 20 Jun 2024 04:47:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d0a:0:b0:440:ff43:c1cf with SMTP id d75a77b69052e-444b4bd8fb4ls8908611cf.1.-pod-prod-08-us;
 Thu, 20 Jun 2024 04:47:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxo3sv3lqroNLGZQ8dUWG1Ss8YL+eOBEcvtb2l7nfpiMG41kObqm5ysJeer6813Vpqi8lBlJvoVUchkVF0HDzAo77AAk12WSSC0A==
X-Received: by 2002:a05:620a:2403:b0:795:5f71:b190 with SMTP id af79cd13be357-79bb3e57dcbmr609140785a.37.1718884059741;
        Thu, 20 Jun 2024 04:47:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718884059; cv=none;
        d=google.com; s=arc-20160816;
        b=Uo1i1M0Jim1O/svZfFhkeTpaT0dorzGjEMTep0ucGJclbr1PtzybEa8DJ35kT855BN
         QGLB1UuzYAs/nFebmVG4LIfY1nTs2uldiRNWYew5iq8q2VPqadylAZtUHxxhP9YIFHxf
         FaH2O8GZ4PCbWhy6E2JKQjYNIlHslIR4SJREfCtnWJUDZm953M3/FFa/IJgzynzsmjgA
         NrsJTRw/xQmNLAImS315TAFH93H0PynQ53uvLvWp1zYPO2K1LbwLj0b1WVKAIjh0+gzI
         UytgXUwCuBr+xfH3NbWPvEybfPnTagrnb4gufICuSux/lzxWUUvUkHwGPYbFh1HhTHi3
         z+Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uDwdH5z/zkL6+tbqxf8Riv9fVhDg6OuGLlTLaC/xubk=;
        fh=MFiSY5zOpOI1AeKVx7deTZDXQV0/57GV1n3MgEyFiBA=;
        b=DehhJ+66ZjhLcitwmzw1XU4NwRN68uy4Y4lWWsfYvF/vSeoxHZVhfcZ2dD9yE0W+4/
         UdxEChouI5r9z9ltlcyHlW832Usm05kMb900OD+HOz6Z7tZJKnU7kZxVpcLkc2UA1A6B
         PXTCHjXZPyjiCpsgYMCuWYQE0PEEC81Fm/wJ1cavaO8GkF0k4ZZoZ7glMyEjWGRqMAyW
         QA1nk42LgCQtgDuP4OUxecrmZqlvyowIUEaV8LkRaRXWZ6EOAd4Zgb8guh8gTi4dKiej
         c+vkfuiWo9EXQ87Ba6HknUShMF5ug2LPLuhY86H4wtOAjLW8IAE4UpNRpGzg6GkzbTcu
         1fYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xpRhOv8b;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-798aac9e6fdsi64548585a.1.2024.06.20.04.47.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 04:47:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-6b05c9db85fso3989546d6.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 04:47:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXTFJvd0nCjkwX9Nm9nzjw7MstzJGsxHosClrsJhq84RSr48JKFboSatV4nItmNPd9d4l3b/PNw29iopfWFuMrUsyvCdXHLFvxj4g==
X-Received: by 2002:ad4:5a4e:0:b0:6b2:cb24:f395 with SMTP id
 6a1803df08f44-6b50b2a314dmr32156226d6.39.1718884059087; Thu, 20 Jun 2024
 04:47:39 -0700 (PDT)
MIME-Version: 1.0
References: <20240619154530.163232-1-iii@linux.ibm.com> <20240619154530.163232-34-iii@linux.ibm.com>
 <CAG_fn=V8Tt28LE9FtoYkos=5XG4zP_tDP1mF1COfEhAMg2ULqQ@mail.gmail.com> <aaef3e0fe22ad9074de84717f36f316204ae088c.camel@linux.ibm.com>
In-Reply-To: <aaef3e0fe22ad9074de84717f36f316204ae088c.camel@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 13:46:57 +0200
Message-ID: <CAG_fn=ULC+vUH2d9bPhFg9xQDnm6fUmsaDkiPFauw8WhWoMzLw@mail.gmail.com>
Subject: Re: [PATCH v5 33/37] s390/uaccess: Add KMSAN support to put_user()
 and get_user()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xpRhOv8b;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 20, 2024 at 1:19=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> On Thu, 2024-06-20 at 10:36 +0200, Alexander Potapenko wrote:
> > On Wed, Jun 19, 2024 at 5:45=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm=
.com>
> > wrote:
> > >
> > > put_user() uses inline assembly with precise constraints, so Clang
> > > is
> > > in principle capable of instrumenting it automatically.
> > > Unfortunately,
> > > one of the constraints contains a dereferenced user pointer, and
> > > Clang
> > > does not currently distinguish user and kernel pointers. Therefore
> > > KMSAN attempts to access shadow for user pointers, which is not a
> > > right
> > > thing to do.
> >
> > By the way, how does this problem manifest?
> > I was expecting KMSAN to generate dummy shadow accesses in this case,
> > and reading/writing 1-8 bytes from dummy shadow shouldn't be a
> > problem.
> >
> > (On the other hand, not inlining the get_user/put_user functions is
> > probably still faster than retrieving the dummy shadow, so I'm fine
> > either way)
>
> We have two problems here: not only clang can't distinguish user and
> kernel pointers, the KMSAN runtime - which is supposed to clean that
> up - can't do that either due to overlapping kernel and user address
> spaces on s390. So the instrumentation ultimately tries to access the
> real shadow.
>
> I forgot what the consequences of that were exactly, so I reverted the
> patch and now I get:
>
> Unable to handle kernel pointer dereference in virtual kernel address
> space
> Failing address: 000003fed25fa000 TEID: 000003fed25fa403
> Fault in home space mode while using kernel ASCE.
> AS:0000000005a70007 R3:00000000824d8007 S:0000000000000020
> Oops: 0010 ilc:2 [#1] SMP
> Modules linked in:
> CPU: 3 PID: 1 Comm: init Tainted: G    B            N 6.10.0-rc4-
> g8aadb00f495e #11
> Hardware name: IBM 3931 A01 704 (KVM/Linux)
> Krnl PSW : 0704c00180000000 000003ffe288975a (memset+0x3a/0xa0)
>            R:0 T:1 IO:1 EX:1 Key:0 M:1 W:0 P:0 AS:3 CC:0 PM:0 RI:0 EA:3
> Krnl GPRS: 0000000000000000 000003fed25fa180 000003fed25fa180
> 000003ffe28897a6
>            0000000000000007 000003ffe0000000 0000000000000000
> 000002ee06e68190
>            000002ee06f19000 000003fed25fa180 000003ffd25fa180
> 000003ffd25fa180
>            0000000000000008 0000000000000000 000003ffe17262e0
> 0000037ee000f730
> Krnl Code: 000003ffe288974c: 41101100           la      %r1,256(%r1)
>            000003ffe2889750: a737fffb           brctg
> %r3,000003ffe2889746
>           #000003ffe2889754: c03000000029       larl
> %r3,000003ffe28897a6
>           >000003ffe288975a: 44403000           ex      %r4,0(%r3)
>            000003ffe288975e: 07fe               bcr     15,%r14
>            000003ffe2889760: a74f0001           cghi    %r4,1
>            000003ffe2889764: b9040012           lgr     %r1,%r2
>            000003ffe2889768: a784001c           brc
> 8,000003ffe28897a0
> Call Trace:
>  [<000003ffe288975a>] memset+0x3a/0xa0
> ([<000003ffe17262bc>] kmsan_internal_set_shadow_origin+0x21c/0x3a0)
>  [<000003ffe1725fb6>] kmsan_internal_unpoison_memory+0x26/0x30
>  [<000003ffe1c1c646>] create_elf_tables+0x13c6/0x2620
>  [<000003ffe1c0ebaa>] load_elf_binary+0x50da/0x68f0
>  [<000003ffe18c41fc>] bprm_execve+0x201c/0x2f40
>  [<000003ffe18bff9a>] kernel_execve+0x2cda/0x2d00
>  [<000003ffe49b745a>] kernel_init+0x9ba/0x1630
>  [<000003ffe000cd5c>] __ret_from_fork+0xbc/0x180
>  [<000003ffe4a1907a>] ret_from_fork+0xa/0x30
> Last Breaking-Event-Address:
>  [<000003ffe2889742>] memset+0x22/0xa0
> Kernel panic - not syncing: Fatal exception: panic_on_oops
>
> So is_bad_asm_addr() returned false for a userspace address.
> Why? Because it happened to collide with the kernel modules area:
> precisely the effect of overlapping.
>
> VMALLOC_START: 0x37ee0000000
> VMALLOC_END:   0x3a960000000
> MODULES_VADDR: 0x3ff60000000
> Address:       0x3ffd157a580
> MODULES_END:   0x3ffe0000000

I see, thanks for the clarification!

> Now the question is, why do we crash when accessing shadow for modules?
> I'll need to investigate, this does not look normal. But even if that
> worked, we clearly wouldn't want userspace accesses to pollute module
> shadow, so I think we need this patch in its current form.

Ok, it indeed makes sense.

Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DULC%2BvUH2d9bPhFg9xQDnm6fUmsaDkiPFauw8WhWoMzLw%40mail.gm=
ail.com.
