Return-Path: <kasan-dev+bncBC7OD3FKWUERBAF2ZKRAMGQENTCAOOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 220636F5D26
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 19:42:26 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-19297b852cfsf6205022fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 10:42:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683135744; cv=pass;
        d=google.com; s=arc-20160816;
        b=lZc3fIAxmIOe9xLX5jS9PZg5ssvMz6EyvPPFSCtN71m+0sPkeXkNR8xa6Azw+T6eNB
         h9N+J5WIla4ZMeUxUhuXX0UQZW3+7d52fFGwC3Sjg7ICglLzjf3FYQgake1E6SypiJAf
         JtIJS+Hv6PoHTX1mji6NoBqsAOosMmpsShu7N+pL+7Jl6Fn9Rc9DJBgAcld87KTyB2IH
         PNRMv7GqMU/7U7URONecqBeg5LReCI6LzyqPEOgXSI/5SnYbJqc/JGmwIbGc3NA3nPzg
         MS7iEnZhnaKK5nQfoQssOWle8gWRM+vfR5q0Bpauxaz3SDT3Z5K2c894hhDV35ISm/cl
         3S+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PrfxurNt6LNwqmyyrwM0XBPpjHFj0KtcLkKFmje0qYo=;
        b=sHh/RZRuQCr+60wOlfT/tjtjM4V7vDaFMf7juGwM+8hB8Rewq8pPuc8KAK7lBcu8r2
         lCeuJC0kbHt0Zc/sLWsSr4nE0hNkdXbLDTN1fDAl1IwnPGjzRZdzg3eMiRDiHdeIjw9k
         MiINDdYJaQqfcITmNomYSG/g+XqoBi86r6zet45iG3FVRnTwSFASt0nxiKbcekqH6LoV
         3eAPAXqxRNCrFDbzt37As0KWJ53WVyaSdSNoOR/NCHz+Zq1ePGKHph/1w3i8DsNTFwlv
         x79gw3p/CH8Z5LqrNSVf5nfFm4+r54oUpjmHZaRSvFVkaLOlI5UZsOgSicW6eO++VfOm
         ew4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=lILby+6O;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683135744; x=1685727744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=PrfxurNt6LNwqmyyrwM0XBPpjHFj0KtcLkKFmje0qYo=;
        b=kYHgsKVtVZE3BtcT1BGW8yH/6XghqtoosGBpa5cBRfEsTvoMQdVX4wR6EPrNBlqpok
         WFcyx+9gsl6RE756GhpAksK1LAdcl4+FsEIZhwMa3Tl6/s8T9i41y+hYG/PT1zZgEnAo
         d14VID2kz+4m5dJ2cJ9grL/fjdmvKQUSUtFgHeTT9bHP4gibrLq8e/Sop2mJdAqwUCP1
         WXLFolbMFvn0TjzUNmto1IRTQT/8w035lKRjxHHtlrK4ivWEQS2nMy8dGsF6gYSUZiPl
         egf3UACzDK8S9LDVDVH90Da32ZSNdwhZZ7OAIVksa9bHmi+F5naC3pA5he3c8kI/IP0v
         PEpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683135744; x=1685727744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PrfxurNt6LNwqmyyrwM0XBPpjHFj0KtcLkKFmje0qYo=;
        b=Xzqu8wwzZxAWTjMyqeHk6uHT5lYrvH2WCbn4FIwsTFHPSY64X0HEnM16bcGUJxndnJ
         WMcEIcxncP+ty/P+cob1yICOTFxTwAXOhdmWCMPFxnVJ9z+JcKLgcF6FT77mdJUQOSGm
         NRFH8qFnoT85WfQmlDyr5Rsh9DedcOkb55XzQ4G2Q14fK7tTEeQdj5l34Kplwtub3iUE
         CetrUUvOafa32N0xPJaRgGMgQuTMu29Ymj0qSjjDg7U6sVjc6msPWt5ZK/VAAQ2pqr4W
         ZcwortfoSVN1AA/Ld45OrEx1B2/Rq3vEQE8qlqQ5crh+zCor8DwMsuD6+bxrekYEA9IO
         IyHQ==
X-Gm-Message-State: AC+VfDxE6PBKFgtKhNNYvaS3x/NOoV23UXBv5rJ+F9pTzNuDitdvIS3N
	RRHgWSKqh2QqnjXg+L0LbqM=
X-Google-Smtp-Source: ACHHUZ7KsG9La0jbtxBtC+ENswTCd+nk68M5wRKoApGcFWBkNcHUf5j96MhNMZyx8PxcTF+iqDdOqw==
X-Received: by 2002:a05:6870:2a41:b0:184:5497:53e6 with SMTP id jd1-20020a0568702a4100b00184549753e6mr1174834oab.3.1683135744550;
        Wed, 03 May 2023 10:42:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4994:b0:192:7463:c900 with SMTP id
 ho20-20020a056870499400b001927463c900ls2154892oab.1.-pod-prod-gmail; Wed, 03
 May 2023 10:42:24 -0700 (PDT)
X-Received: by 2002:a05:6870:a607:b0:192:8cd6:b8b3 with SMTP id e7-20020a056870a60700b001928cd6b8b3mr2583306oam.32.1683135744102;
        Wed, 03 May 2023 10:42:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683135744; cv=none;
        d=google.com; s=arc-20160816;
        b=B4NmIavOTfjlT1vqma9/hxZO/e3NVfzP/rrPYPAFSCJ582/vxUrwPoL6MYcEBvY0lL
         TuzM4/mmGyXN5+vT+6GPTcxeuSDe90gncp0M2pcB0vA3oEeEM6bwtLgjKOKlJQZmkAhz
         h/iQDi3c/FIEiyEMibeObRoVCP9M/UJmLRdUzdyKdbNCC7Yxv/06SXHio5GYkBs7AGVG
         0GmV5E69iNuYetfwAFJ8D4MaHi2EPH/cUhsiDmtwkdcx9bRx841mfyZTYdYngt7ok8LG
         7DUHEGRtKESN/ACaHf4SNrv++N+6zmf8TNma9n5NkT/F93wlinkT7/1SXVUrByX+fmB1
         t0ew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CyWASKhXrRNVBOOq8h+mxQvWE1hyBqHS7EnIBAfoYzo=;
        b=Z3BW6oObR2ceZxpyQQ6mzhBUxUk9SzXOUGe2cCIBfZQEd8HX/BdxkEVhyj8LhTvWAD
         USdTziYKX5elfh7JGLmk2weOk2wAU0vKjX9x7FRW28YxClb92c9TIA5w9WlUf7Zyp27p
         BK1R6i0kSamWKNHJJ4EDMbz7ghUA1l9PEhTG78HalllIE6bfEulumfi3ZnLL1Mu67BsF
         p9pQoVInh4dyumTXkgcmI6pDtxmFQdJ1YRVNNtTg8ckkPxE9NQ3DyeZsCnqbuPRddxqv
         Ds1bqwwOLeQR2SeT0YploMhXkVv7XKYXsxGTttKOSxMBWu7gjfkiYg8Tz7j3jiWcutpG
         za/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=lILby+6O;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id pa7-20020a0568701d0700b00187820f810dsi130859oab.5.2023.05.03.10.42.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 10:42:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id 3f1490d57ef6-b9e66ce80acso3430122276.3
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 10:42:24 -0700 (PDT)
X-Received: by 2002:a25:b782:0:b0:b95:2bd5:8f86 with SMTP id
 n2-20020a25b782000000b00b952bd58f86mr19664721ybh.26.1683135743488; Wed, 03
 May 2023 10:42:23 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <ZFIMaflxeHS3uR/A@dhcp22.suse.cz>
 <ZFIOfb6/jHwLqg6M@moria.home.lan> <ZFISlX+mSx4QJDK6@dhcp22.suse.cz>
 <ZFIVtB8JyKk0ddA5@moria.home.lan> <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
In-Reply-To: <ZFKNZZwC8EUbOLMv@slm.duckdns.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 10:42:11 -0700
Message-ID: <CAJuCfpEFV7ZB4pvnf6n0bVpTCDWCVQup9PtrHuAayrf3GrQskg@mail.gmail.com>
Subject: Re: [PATCH 00/40] Memory allocation profiling
To: Tejun Heo <tj@kernel.org>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, Michal Hocko <mhocko@suse.com>, 
	akpm@linux-foundation.org, vbabka@suse.cz, hannes@cmpxchg.org, 
	roman.gushchin@linux.dev, mgorman@suse.de, dave@stgolabs.net, 
	willy@infradead.org, liam.howlett@oracle.com, corbet@lwn.net, 
	void@manifault.com, peterz@infradead.org, juri.lelli@redhat.com, 
	ldufour@linux.ibm.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, pasha.tatashin@soleen.com, yosryahmed@google.com, 
	yuzhao@google.com, dhowells@redhat.com, hughd@google.com, 
	andreyknvl@gmail.com, keescook@chromium.org, ndesaulniers@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
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
 header.i=@google.com header.s=20221208 header.b=lILby+6O;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b36 as
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

On Wed, May 3, 2023 at 9:35=E2=80=AFAM Tejun Heo <tj@kernel.org> wrote:
>
> Hello, Kent.
>
> On Wed, May 03, 2023 at 04:05:08AM -0400, Kent Overstreet wrote:
> > No, we're still waiting on the tracing people to _demonstrate_, not
> > claim, that this is at all possible in a comparable way with tracing.
>
> So, we (meta) happen to do stuff like this all the time in the fleet to h=
unt
> down tricky persistent problems like memory leaks, ref leaks, what-have-y=
ou.
> In recent kernels, with kprobe and BPF, our ability to debug these sorts =
of
> problems has improved a great deal. Below, I'm attaching a bcc script I u=
sed
> to hunt down, IIRC, a double vfree. It's not exactly for a leak but leaks
> can follow the same pattern.

Thanks for sharing, Tejun!

>
> There are of course some pros and cons to this approach:
>
> Pros:
>
> * The framework doesn't really have any runtime overhead, so we can have =
it
>   deployed in the entire fleet and debug wherever problem is.

Do you mean it has no runtime overhead when disabled?
If so, do you know what's the overhead when enabled? I want to
understand if that's truly a viable solution to track all allocations
(including slab) all the time.
Thanks,
Suren.

>
> * It's fully flexible and programmable which enables non-trivial filterin=
g
>   and summarizing to be done inside kernel w/ BPF as necessary, which is
>   pretty handy for tracking high frequency events.
>
> * BPF is pretty performant. Dedicated built-in kernel code can do better =
of
>   course but BPF's jit compiled code & its data structures are fast enoug=
h.
>   I don't remember any time this was a problem.
>
> Cons:
>
> * BPF has some learning curve. Also the fact that what it provides is a w=
ide
>   open field rather than something scoped out for a specific problem can
>   make it seem a bit daunting at the beginning.
>
> * Because tracking starts when the script starts running, it doesn't know
>   anything which has happened upto that point, so you gotta pay attention=
 to
>   handling e.g. handling frees which don't match allocs. It's kinda annoy=
ing
>   but not a huge problem usually. There are ways to build in BPF progs in=
to
>   the kernel and load it early but I haven't experiemnted with it yet
>   personally.
>
> I'm not necessarily against adding dedicated memory debugging mechanism b=
ut
> do wonder whether the extra benefits would be enough to justify the code =
and
> maintenance overhead.
>
> Oh, a bit of delta but for anyone who's more interested in debugging
> problems like this, while I tend to go for bcc
> (https://github.com/iovisor/bcc) for this sort of problems. Others prefer=
 to
> write against libbpf directly or use bpftrace
> (https://github.com/iovisor/bpftrace).
>
> Thanks.
>
> #!/usr/bin/env bcc-py
>
> import bcc
> import time
> import datetime
> import argparse
> import os
> import sys
> import errno
>
> description =3D """
> Record vmalloc/vfrees and trigger on unmatched vfree
> """
>
> bpf_source =3D """
> #include <uapi/linux/ptrace.h>
> #include <linux/vmalloc.h>
>
> struct vmalloc_rec {
>         unsigned long           ptr;
>         int                     last_alloc_stkid;
>         int                     last_free_stkid;
>         int                     this_stkid;
>         bool                    allocated;
> };
>
> BPF_STACK_TRACE(stacks, 8192);
> BPF_HASH(vmallocs, unsigned long, struct vmalloc_rec, 131072);
> BPF_ARRAY(dup_free, struct vmalloc_rec, 1);
>
> int kpret_vmalloc_node_range(struct pt_regs *ctx)
> {
>         unsigned long ptr =3D PT_REGS_RC(ctx);
>         uint32_t zkey =3D 0;
>         struct vmalloc_rec rec_init =3D { };
>         struct vmalloc_rec *rec;
>         int stkid;
>
>         if (!ptr)
>                 return 0;
>
>         stkid =3D stacks.get_stackid(ctx, 0);
>
>         rec_init.ptr =3D ptr;
>         rec_init.last_alloc_stkid =3D -1;
>         rec_init.last_free_stkid =3D -1;
>         rec_init.this_stkid =3D -1;
>
>         rec =3D vmallocs.lookup_or_init(&ptr, &rec_init);
>         rec->allocated =3D true;
>         rec->last_alloc_stkid =3D stkid;
>         return 0;
> }
>
> int kp_vfree(struct pt_regs *ctx, const void *addr)
> {
>         unsigned long ptr =3D (unsigned long)addr;
>         uint32_t zkey =3D 0;
>         struct vmalloc_rec rec_init =3D { };
>         struct vmalloc_rec *rec;
>         int stkid;
>
>         stkid =3D stacks.get_stackid(ctx, 0);
>
>         rec_init.ptr =3D ptr;
>         rec_init.last_alloc_stkid =3D -1;
>         rec_init.last_free_stkid =3D -1;
>         rec_init.this_stkid =3D -1;
>
>         rec =3D vmallocs.lookup_or_init(&ptr, &rec_init);
>         if (!rec->allocated && rec->last_alloc_stkid >=3D 0) {
>                 rec->this_stkid =3D stkid;
>                 dup_free.update(&zkey, rec);
>         }
>
>         rec->allocated =3D false;
>         rec->last_free_stkid =3D stkid;
>         return 0;
> }
> """
>
> bpf =3D bcc.BPF(text=3Dbpf_source)
> bpf.attach_kretprobe(event=3D"__vmalloc_node_range", fn_name=3D"kpret_vma=
lloc_node_range");
> bpf.attach_kprobe(event=3D"vfree", fn_name=3D"kp_vfree");
> bpf.attach_kprobe(event=3D"vfree_atomic", fn_name=3D"kp_vfree");
>
> stacks =3D bpf["stacks"]
> vmallocs =3D bpf["vmallocs"]
> dup_free =3D bpf["dup_free"]
> last_dup_free_ptr =3D dup_free[0].ptr
>
> def print_stack(stkid):
>     for addr in stacks.walk(stkid):
>         sym =3D bpf.ksym(addr)
>         print('  {}'.format(sym))
>
> def print_dup(dup):
>     print('allocated=3D{} ptr=3D{}'.format(dup.allocated, hex(dup.ptr)))
>     if (dup.last_alloc_stkid >=3D 0):
>         print('last_alloc_stack: ')
>         print_stack(dup.last_alloc_stkid)
>     if (dup.last_free_stkid >=3D 0):
>         print('last_free_stack: ')
>         print_stack(dup.last_free_stkid)
>     if (dup.this_stkid >=3D 0):
>         print('this_stack: ')
>         print_stack(dup.this_stkid)
>
> while True:
>     time.sleep(1)
>
>     if dup_free[0].ptr !=3D last_dup_free_ptr:
>         print('\nDUP_FREE:')
>         print_dup(dup_free[0])
>         last_dup_free_ptr =3D dup_free[0].ptr
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEFV7ZB4pvnf6n0bVpTCDWCVQup9PtrHuAayrf3GrQskg%40mail.gmail.=
com.
