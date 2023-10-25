Return-Path: <kasan-dev+bncBC7OD3FKWUERBMPI4SUQMGQEBLWMNJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id B54D87D70C0
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 17:28:50 +0200 (CEST)
Received: by mail-il1-x13e.google.com with SMTP id e9e14a558f8ab-357ce7283d3sf1029575ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Oct 2023 08:28:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698247729; cv=pass;
        d=google.com; s=arc-20160816;
        b=SKeNbz+MmH2ISlBsaBiP2csnLzAF8wDaUzDe2Cj7eigGznuvhK9Q2Z5IJSKj5nsTu/
         +jdr76AOtiIAZ8rV29/9ppXU4qBjPyiaIhL7wmYPb6CBMOt7Pt4lNs1nvsgfSZAYj8Su
         TgCGVMgjooH73+U8zLdvgDjhTaZoazbW7v/V8Rn0e2rX+935wKctf1qxuaZpLirF8t45
         NG50A2A4ATMH8h1TIcBPMdM5CmlZxW36MgbZG/XbwbRH0ZYKHe+tXNAivuMjzBpyFG0+
         PHRTdaPhu+EZcnzeNyUdzGafjXoTofCeexwmPyb6Qzb1Mdiajm3l5YHCmzGlc1uAST9i
         Y5DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9fU6oGHKNxgb8Ambva/atsMuWvGRLcwy+N2LvCfFWbc=;
        fh=usgaYvrONOYyRsl4Ga2j2zE19rakNAnb2l5blenKwN4=;
        b=omXHdgZeJLQaKr5Bilyg5HABMBMI/tJynSgNMMwePz37zQ55acLv8acKSfc+H7NEhH
         do5KoQaRykYV53jcEDMqFwpUC9NjdeMcxjajC1GncvOXeh6RE/D2iQUIUCNwKw4UvB+s
         C6WrXjaGoclJsUIMyL1YcUVZhz80tmGqbVKDYBD3qW364gTMskPkRjXJuBx23Y1YSuvX
         63cfCUcxzluias8JReQghvhw5FHJepXFDK+fFuFtlTUyQMdbkrp9IwpL16vtofqmyqGN
         tF8uFR91s2NvDMbU7+EJVi8o0EVq6SpE7wJTFdpEWR45ZEY8ZhG3gC3gSc1kbc2zTTQQ
         pcUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=u56UyU8w;
       spf=pass (google.com: domain of surenb@google.com designates 2001:4860:4864:20::2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698247729; x=1698852529; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9fU6oGHKNxgb8Ambva/atsMuWvGRLcwy+N2LvCfFWbc=;
        b=aOQVsef02uUWKbW3iW33olvqiLC+3Vn2HAiNqZ/RSJJyv8XOpYGDW41jOEnBPtBAsf
         xWddt4ySNDKJJSlQ9OXclXqnT8YidyoSTZP7HWhkVq6quaVhxgyUOMFUzyQcIUoxUal8
         LmUE4wXgC+7ifeHrdm8TXAv5eQ1vDdUX+lHiz9Sz3hZWteCitzJWnFudIFRZYMoBTjZ8
         x1ViUKNX5UpOhYNzTNdNf/JhExGPjcMvvFtAdMexZbvhVmsFyYezqhSeSvp/operexYR
         jg4a+eB8ykkgIfO/A5oQ/Q5+34wKjwUNgsEPU9uINtPGKf0E6K6CEXmLBue7ZykeTu83
         Uv2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698247729; x=1698852529;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9fU6oGHKNxgb8Ambva/atsMuWvGRLcwy+N2LvCfFWbc=;
        b=UwAOHlQ4xWwAPlggcDMRneNcywTNoZRe2r32fM6CqZKigI7wRvpYVRWX+9ET61Eb0h
         UneFXKwTSUlrYs70P/zP7LQG/TpTAhdKnkke6w3WXz+GnajOOvzomUESmOV7qOjSoxUy
         HNk5xWwjdLdcF/GuW8x2vblcgn+hrZ+T8n0WEs9i3QfpjekJ9gnodZgqlOvArE2xfuKX
         ZgrvbbQFV9dVFZj1ehTQP0T0vN6/X7wDoODjtYD8xmW25s8A9UbuCwi8OIDnbYGIhf2p
         rQmcOG52k+t0bJ/QEQN4RBxnrwicyDOSd3y2SdapfcSyJWo5TKmvXbmKYc5YXrCTMVLX
         JaLQ==
X-Gm-Message-State: AOJu0Yy45gaK/bFYhsaxDD6EYa1VVamoK+rFkEtFdUn5dD23KNZHFiE1
	RpufsOE8sMewzvG0fCd5xuA=
X-Google-Smtp-Source: AGHT+IEWqj5ZAik3BLTU9EFZnsTTKPCxt0D82aBAoPRndt5bVj+vnq5Ab/NJfXUju7u8RCDPIayisw==
X-Received: by 2002:a92:c642:0:b0:357:f5d2:994d with SMTP id 2-20020a92c642000000b00357f5d2994dmr222063ill.4.1698247729242;
        Wed, 25 Oct 2023 08:28:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:4ce:b0:34b:ae4b:a965 with SMTP id
 f14-20020a056e0204ce00b0034bae4ba965ls3190180ils.1.-pod-prod-03-us; Wed, 25
 Oct 2023 08:28:48 -0700 (PDT)
X-Received: by 2002:a05:6602:1613:b0:7a9:5e03:a785 with SMTP id x19-20020a056602161300b007a95e03a785mr9892103iow.15.1698247728152;
        Wed, 25 Oct 2023 08:28:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698247728; cv=none;
        d=google.com; s=arc-20160816;
        b=wF+TWoghGU2zfKfkkdk8FBxmvjJ7b0eMKakiGWU/eu81OkCCTD9h0lFcJGzq4Edv/c
         R3uxp4ZCf/Nfa4tYm4pDrRBfOjGrmHaFoDItPXDIlf2admkKof6w/CRLYO5oKRo+UBiz
         I//ZHqzMgryLnc2sKQvVbLFbXkwJ61sn9tiM9JE63A/kuM0kGtlvLhvZE9KWSrMLZzoD
         CZt8q30qCfkbSTowjtRKL7xirJk/7DLDIopEGFYDxsrh4tHGOwSBnC38ghD3viBFuJST
         p1/RtZCnRPYC14gW9cDiEJQmiEkfIJf7NaQckIYLno40OBMkTJe0tQjUYnpdvPaaSR6g
         ztWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FLJnARkfIBMUfgquTTGlj0tPN4MXFqJ8fdXtHqq+8bA=;
        fh=usgaYvrONOYyRsl4Ga2j2zE19rakNAnb2l5blenKwN4=;
        b=J/tOzWE4GNS0GN4QF/0SJBisRt9Y5qpTYo/zkZuP1TsiOMPpyU6boczpc/o6lTbaL4
         x+10P2jijy7cy9ptymu8RUU8ogVLWVdhByoUWrYBamfxejmhvK1D5ztMbvzyXAW6h3Qi
         oB3tAWZCMtOVHaRxGp8Lz93zcScB9Wi2RWwlXJygYGaXc3EOaB4cz8+LInFjEbbmcnV2
         6uKqM21gT2BEtN9gdkJA631sXmvlNCNSo1Qy883GnQftoElmI68FotqiCo9fj2Q3t88f
         g1UXkX7znkBiHhFAZ6pVILnPq0Ez5v4Xio5hEvyDhN8I3c5uYmm+OsKTEnEBdNqhilv4
         0zhA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=u56UyU8w;
       spf=pass (google.com: domain of surenb@google.com designates 2001:4860:4864:20::2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oa1-x2f.google.com (mail-oa1-x2f.google.com. [2001:4860:4864:20::2f])
        by gmr-mx.google.com with ESMTPS id n7-20020a6b5907000000b0079f955fa823si7108iob.1.2023.10.25.08.28.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Oct 2023 08:28:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2001:4860:4864:20::2f as permitted sender) client-ip=2001:4860:4864:20::2f;
Received: by mail-oa1-x2f.google.com with SMTP id 586e51a60fabf-1e5bc692721so3711650fac.0
        for <kasan-dev@googlegroups.com>; Wed, 25 Oct 2023 08:28:48 -0700 (PDT)
X-Received: by 2002:a05:6870:1157:b0:1da:ed10:bcb with SMTP id
 23-20020a056870115700b001daed100bcbmr15750180oag.31.1698247727385; Wed, 25
 Oct 2023 08:28:47 -0700 (PDT)
MIME-Version: 1.0
References: <20231024134637.3120277-1-surenb@google.com> <20231024134637.3120277-7-surenb@google.com>
 <20231025074652.44bc0eb4@meshulam.tesarici.cz>
In-Reply-To: <20231025074652.44bc0eb4@meshulam.tesarici.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Oct 2023 08:28:32 -0700
Message-ID: <CAJuCfpHS1JTRU69zFDAJjmMYR3K5TAS9+AsA3oYLs2LCs5aTBw@mail.gmail.com>
Subject: Re: [PATCH v2 06/39] mm: enumerate all gfp flags
To: =?UTF-8?B?UGV0ciBUZXNhxZnDrWs=?= <petr@tesarici.cz>
Cc: Neil Brown <neilb@suse.de>, akpm@linux-foundation.org, kent.overstreet@linux.dev, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, 
	liam.howlett@oracle.com, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, ldufour@linux.ibm.com, 
	catalin.marinas@arm.com, will@kernel.org, arnd@arndb.de, tglx@linutronix.de, 
	mingo@redhat.com, dave.hansen@linux.intel.com, x86@kernel.org, 
	peterx@redhat.com, david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, 
	masahiroy@kernel.org, nathan@kernel.org, dennis@kernel.org, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=u56UyU8w;       spf=pass
 (google.com: domain of surenb@google.com designates 2001:4860:4864:20::2f as
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

On Tue, Oct 24, 2023 at 10:47=E2=80=AFPM Petr Tesa=C5=99=C3=ADk <petr@tesar=
ici.cz> wrote:
>
> On Tue, 24 Oct 2023 06:46:03 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > Introduce GFP bits enumeration to let compiler track the number of used
> > bits (which depends on the config options) instead of hardcoding them.
> > That simplifies __GFP_BITS_SHIFT calculation.
> > Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > ---
> >  include/linux/gfp_types.h | 90 +++++++++++++++++++++++++++------------
> >  1 file changed, 62 insertions(+), 28 deletions(-)
> >
> > diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> > index 6583a58670c5..3fbe624763d9 100644
> > --- a/include/linux/gfp_types.h
> > +++ b/include/linux/gfp_types.h
> > @@ -21,44 +21,78 @@ typedef unsigned int __bitwise gfp_t;
> >   * include/trace/events/mmflags.h and tools/perf/builtin-kmem.c
> >   */
> >
> > +enum {
> > +     ___GFP_DMA_BIT,
> > +     ___GFP_HIGHMEM_BIT,
> > +     ___GFP_DMA32_BIT,
> > +     ___GFP_MOVABLE_BIT,
> > +     ___GFP_RECLAIMABLE_BIT,
> > +     ___GFP_HIGH_BIT,
> > +     ___GFP_IO_BIT,
> > +     ___GFP_FS_BIT,
> > +     ___GFP_ZERO_BIT,
> > +     ___GFP_UNUSED_BIT,      /* 0x200u unused */
> > +     ___GFP_DIRECT_RECLAIM_BIT,
> > +     ___GFP_KSWAPD_RECLAIM_BIT,
> > +     ___GFP_WRITE_BIT,
> > +     ___GFP_NOWARN_BIT,
> > +     ___GFP_RETRY_MAYFAIL_BIT,
> > +     ___GFP_NOFAIL_BIT,
> > +     ___GFP_NORETRY_BIT,
> > +     ___GFP_MEMALLOC_BIT,
> > +     ___GFP_COMP_BIT,
> > +     ___GFP_NOMEMALLOC_BIT,
> > +     ___GFP_HARDWALL_BIT,
> > +     ___GFP_THISNODE_BIT,
> > +     ___GFP_ACCOUNT_BIT,
> > +     ___GFP_ZEROTAGS_BIT,
> > +#ifdef CONFIG_KASAN_HW_TAGS
> > +     ___GFP_SKIP_ZERO_BIT,
> > +     ___GFP_SKIP_KASAN_BIT,
> > +#endif
> > +#ifdef CONFIG_LOCKDEP
> > +     ___GFP_NOLOCKDEP_BIT,
> > +#endif
> > +     ___GFP_LAST_BIT
> > +};
> > +
> >  /* Plain integer GFP bitmasks. Do not use this directly. */
> > -#define ___GFP_DMA           0x01u
> > -#define ___GFP_HIGHMEM               0x02u
> > -#define ___GFP_DMA32         0x04u
> > -#define ___GFP_MOVABLE               0x08u
> > -#define ___GFP_RECLAIMABLE   0x10u
> > -#define ___GFP_HIGH          0x20u
> > -#define ___GFP_IO            0x40u
> > -#define ___GFP_FS            0x80u
> > -#define ___GFP_ZERO          0x100u
> > +#define ___GFP_DMA           BIT(___GFP_DMA_BIT)
> > +#define ___GFP_HIGHMEM               BIT(___GFP_HIGHMEM_BIT)
> > +#define ___GFP_DMA32         BIT(___GFP_DMA32_BIT)
> > +#define ___GFP_MOVABLE               BIT(___GFP_MOVABLE_BIT)
> > +#define ___GFP_RECLAIMABLE   BIT(___GFP_RECLAIMABLE_BIT)
> > +#define ___GFP_HIGH          BIT(___GFP_HIGH_BIT)
> > +#define ___GFP_IO            BIT(___GFP_IO_BIT)
> > +#define ___GFP_FS            BIT(___GFP_FS_BIT)
> > +#define ___GFP_ZERO          BIT(___GFP_ZERO_BIT)
> >  /* 0x200u unused */
>
> This comment can be also removed here, because it is already stated
> above with the definition of ___GFP_UNUSED_BIT.

Ack.

>
> Then again, I think that the GFP bits have never been compacted after
> Neil Brown removed __GFP_ATOMIC with commit 2973d8229b78 simply because
> that would mean changing definitions of all subsequent GFP flags. FWIW
> I am not aware of any code that would depend on the numeric value of
> ___GFP_* macros, so this patch seems like a good opportunity to change
> the numbering and get rid of this unused 0x200u altogether.
>
> @Neil: I have added you to the conversation in case you want to correct
> my understanding of the unused bit.

Hmm. I would prefer to do that in a separate patch even though it
would be a one-line change. Seems safer to me in case something goes
wrong and we have to bisect and revert it. If that sounds ok I'll post
that in the next version.

>
> Other than that LGTM.

Thanks for the review!
Suren.

>
> Petr T
>
> > -#define ___GFP_DIRECT_RECLAIM        0x400u
> > -#define ___GFP_KSWAPD_RECLAIM        0x800u
> > -#define ___GFP_WRITE         0x1000u
> > -#define ___GFP_NOWARN                0x2000u
> > -#define ___GFP_RETRY_MAYFAIL 0x4000u
> > -#define ___GFP_NOFAIL                0x8000u
> > -#define ___GFP_NORETRY               0x10000u
> > -#define ___GFP_MEMALLOC              0x20000u
> > -#define ___GFP_COMP          0x40000u
> > -#define ___GFP_NOMEMALLOC    0x80000u
> > -#define ___GFP_HARDWALL              0x100000u
> > -#define ___GFP_THISNODE              0x200000u
> > -#define ___GFP_ACCOUNT               0x400000u
> > -#define ___GFP_ZEROTAGS              0x800000u
> > +#define ___GFP_DIRECT_RECLAIM        BIT(___GFP_DIRECT_RECLAIM_BIT)
> > +#define ___GFP_KSWAPD_RECLAIM        BIT(___GFP_KSWAPD_RECLAIM_BIT)
> > +#define ___GFP_WRITE         BIT(___GFP_WRITE_BIT)
> > +#define ___GFP_NOWARN                BIT(___GFP_NOWARN_BIT)
> > +#define ___GFP_RETRY_MAYFAIL BIT(___GFP_RETRY_MAYFAIL_BIT)
> > +#define ___GFP_NOFAIL                BIT(___GFP_NOFAIL_BIT)
> > +#define ___GFP_NORETRY               BIT(___GFP_NORETRY_BIT)
> > +#define ___GFP_MEMALLOC              BIT(___GFP_MEMALLOC_BIT)
> > +#define ___GFP_COMP          BIT(___GFP_COMP_BIT)
> > +#define ___GFP_NOMEMALLOC    BIT(___GFP_NOMEMALLOC_BIT)
> > +#define ___GFP_HARDWALL              BIT(___GFP_HARDWALL_BIT)
> > +#define ___GFP_THISNODE              BIT(___GFP_THISNODE_BIT)
> > +#define ___GFP_ACCOUNT               BIT(___GFP_ACCOUNT_BIT)
> > +#define ___GFP_ZEROTAGS              BIT(___GFP_ZEROTAGS_BIT)
> >  #ifdef CONFIG_KASAN_HW_TAGS
> > -#define ___GFP_SKIP_ZERO     0x1000000u
> > -#define ___GFP_SKIP_KASAN    0x2000000u
> > +#define ___GFP_SKIP_ZERO     BIT(___GFP_SKIP_ZERO_BIT)
> > +#define ___GFP_SKIP_KASAN    BIT(___GFP_SKIP_KASAN_BIT)
> >  #else
> >  #define ___GFP_SKIP_ZERO     0
> >  #define ___GFP_SKIP_KASAN    0
> >  #endif
> >  #ifdef CONFIG_LOCKDEP
> > -#define ___GFP_NOLOCKDEP     0x4000000u
> > +#define ___GFP_NOLOCKDEP     BIT(___GFP_NOLOCKDEP_BIT)
> >  #else
> >  #define ___GFP_NOLOCKDEP     0
> >  #endif
> > -/* If the above are modified, __GFP_BITS_SHIFT may need updating */
> >
> >  /*
> >   * Physical address zone modifiers (see linux/mmzone.h - low four bits=
)
> > @@ -249,7 +283,7 @@ typedef unsigned int __bitwise gfp_t;
> >  #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
> >
> >  /* Room for N __GFP_FOO bits */
> > -#define __GFP_BITS_SHIFT (26 + IS_ENABLED(CONFIG_LOCKDEP))
> > +#define __GFP_BITS_SHIFT ___GFP_LAST_BIT
> >  #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
> >
> >  /**
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHS1JTRU69zFDAJjmMYR3K5TAS9%2BAsA3oYLs2LCs5aTBw%40mail.gmai=
l.com.
