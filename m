Return-Path: <kasan-dev+bncBC7OD3FKWUERBGVCX2XAMGQEURY2H6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id DE69D8582DE
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 17:45:15 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1dbbd6112d1sf320175ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 08:45:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708101914; cv=pass;
        d=google.com; s=arc-20160816;
        b=TKgFdMEUOHDv1FumL1K6j7DABKdrDMPMYS6S6SCdr+uxwnx5EV/pnEbQYt28uh7UqT
         fXpUF+GTkKm5einBqa4NE1D1ITMmfNH33jF6eSs2FLaCueKjB3an2cRTQH59CmWteh/i
         dpqeSEArKYdJAPD7FjMKg5hg556ui5gC9WB/+qGKs6jG4IRG5G1gi6XxtJN1SRwFTtkB
         RqZJHZrTvi+460H14Db4cR6Zd95FQkORs7hNHcHC2kqK7KgiRFVJlJ1K9z880CjYajP5
         fPWD60u4OuIbv4XTkJDoeHWGx8tCSas2ICRNZgbfHPGz36sg4nrjnc6rn3vViRGuENWD
         k+DQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=I5sJhBsPOockw8k9k6OVPPGf3NQ8MVnpb04jetxjoHA=;
        fh=uhqA3PPJW1iibVKFXfWLXveN7Afr5quOzNtV/altYGI=;
        b=X6ndx8Fpl7755irxJcrT0pQGCXt+uOydO7Uhn18nkMwtXFMHMcKcbLBH3BRaAyDDPS
         z8rW64feFGKE81NnTzW9Lgv+g0JrKNPE1bJTkcvu4KAe9U/NpjppdAHStq2H8RGtxwix
         KrNWrv4Drj0qCKVWt34/k7/Srq1CdMPdGLxhRETQsS7FAcTqwD0rSE8mosRo3HhHapon
         55pjmy0kqEkMLLWzFthfKqheRA7N+Sj+GZxETkOxOFcCQDhNpQTgXnOzIY5aTJXSmNaO
         fo8FUHCCrTstmmgOeThIqVePDSTmpvyG3KbR8SDmYQRynvieYy/k/jTNKbBcCSN62ym+
         PwnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R2irb8FE;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708101914; x=1708706714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=I5sJhBsPOockw8k9k6OVPPGf3NQ8MVnpb04jetxjoHA=;
        b=HcyoLyeM5pUnVtFqL0/kJ5muCP8tRDx4oxNFPyCGFT8sqTM78bhiKjeDd06Jys7OTH
         m8TI+gLpD/tmNO8DwXhqA1qiMT3leuiH8q9OscGaQG+zserQ30FGqimnLuecxN7JIgeZ
         beAoej8r1b7IeWnrLF4oTmfm6YbNjeuZenSfJHSK1RgLItQ9WTFCQwuBav8Aqjxu/arO
         mUzssx/Dew7FTwPXHfToWrG8zjPYpi/QxxDV3tHUGPPL0siqrRbcwYGpBxzojHYU0eEs
         JTO8YnSAkf9T44l2267Dmsg6jfFHvKhk+Ce84gBFgs8ud1JjrxbZdmVEoj14j61l3huf
         /TKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708101914; x=1708706714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I5sJhBsPOockw8k9k6OVPPGf3NQ8MVnpb04jetxjoHA=;
        b=Wut/jg7a4+2dDTRPCeM16FD/1/ffT7w9jUPPY9Z3fivHjZELWijsrsZ0CZbJzNpgoE
         STFwVobknmYEXTffHDM+e0mW2o7HxEFmroeMAE4kiSIrxK9T9vYITtGT++1z+vRkCO3q
         qcUgHOp5JPobdkJ4flBY1vwuZK+Rm3luoREVXlcNK0Hhko6Qkd7pThDluelUtZiWx+jF
         nJdC0LaTS/g3eOW3K5K+WEW93H/XcqHvbocuzoQg1QndBW1EMSfjof3lQcXlzB/rvdXq
         Dlh1fbsEteTvOcFXf+/yslBk8RAbH1nuk3Q6FWxOEqgB5wN2ceRXySd5CElVsjC731DF
         aAQQ==
X-Forwarded-Encrypted: i=2; AJvYcCU9rXSCMaUKKFz5VzyeeXDFfPBM+jeyUy5707WoFoxW3SAmyhHK7q03/9In6+FMFi6/rT92793PZeDjzQqsOcIMri9RwcWbkg==
X-Gm-Message-State: AOJu0YxEyPaQDAdnLQlfx4J+fPTgsUbamfzJhmO5FHaoi3LEHNuOFfot
	dT7WefFeGm34GHzbxXdCyr8XSKrgV6l+rai/s5W77hTtsKCGVPZi
X-Google-Smtp-Source: AGHT+IHkM7XE08rFqQMwWY7pjkwefssmUYqepvt/PIBkF+DpVuJuSdUvr1ZvdOXmEDqNJ6/3G693vg==
X-Received: by 2002:a17:903:23d2:b0:1d9:f4c5:6322 with SMTP id o18-20020a17090323d200b001d9f4c56322mr261325plh.4.1708101914285;
        Fri, 16 Feb 2024 08:45:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:316:b0:21e:4aab:bcf4 with SMTP id
 m22-20020a056870031600b0021e4aabbcf4ls1259680oaf.2.-pod-prod-09-us; Fri, 16
 Feb 2024 08:45:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWIYcjAacwQAAJyBDBO6xelzwIlABX4UEbufp+uFGK7/DU9KLVOfkqEVnfy72dlmMPB8BlPzzgkV0TqJ9v5OVJatZOFq9h9IWcaCA==
X-Received: by 2002:a05:6358:d26:b0:17a:c976:c143 with SMTP id v38-20020a0563580d2600b0017ac976c143mr6475895rwj.12.1708101913434;
        Fri, 16 Feb 2024 08:45:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708101913; cv=none;
        d=google.com; s=arc-20160816;
        b=Qu4SP57MQTQsUVUj3h1wiLx5btjfFXWwY31PFGVx06lSDZlP47HQmcLrHcauXgqH+r
         kNBwbclvNHIycYbk54BCt9hkyv3gGPiknO4Hr7Bvv5ccTfI6QCrxKvOsVhp7XR2hWnHS
         k9SkfxFdUuh77yk+3pzo8bwX4jOgNawgugvO5pMKe2FU6n1byj39LIoy1JnVSNX7Szqt
         SV3IkBqZLfD0vHt6eoZ6okJ/9AdRqlb5vD70m2s/vn0PoTA4TSvDlevniStPkFyS3Lty
         DZ+b9OpL+dPJQ+eERkONmTmXqjuBsbAzZE/Z25hxjKrOYf4KoD9F9u6w4K8OnIM+Q3Mz
         CabQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=yqMJBdmCbC/RM9PRo3lm7SAMuIGxpy4kB2I1M6Qh1Sw=;
        fh=uIY5DtZ78ci7HuvF+ePId6ccGdnhmKo3Y/R1ySAz57k=;
        b=dMgTo3OV8MIkaBdh3Ozv/SqUv7u6qNUR6EnNDbZDJjKmBjy4vaxflf5f/eSTQvTU5L
         FrIX/RLiJUsq6uE9f+2s0+4myHsryOGcosYMS1gTcvjYUFrulHiARRLXB85iHoMPv0fU
         /8yHD8vTjiC1pvpJEGF36fN2mx1Z0wLfMwFoDtkHFNq/UjE5umbJcN7xz/rhI2URAYoY
         hZ10ip/N7gUmCN56ZMiOv7O8JpITfMqroagqOAKAA1CTNeKcynPZu3xZ1IqbhFGOV/In
         Nr0tcbdzDvL8Mm4B4aslOzKKHYVz3SbXCPeuauiOeG33TtRJO4IVOTO8gLcy8+3jr7Kt
         YVxg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R2irb8FE;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id w10-20020a056a0014ca00b006e03ac13daesi44590pfu.4.2024.02.16.08.45.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 08:45:13 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-607e707a7f1so17163757b3.2
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 08:45:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXoo36xi3WYeaKVzVsWW9S9Pz2jO0AYsgx1MQ5bvQOSGEFbL7Nf0lfQuUrtu90PudIcbEnPdTNLxUg06x8T+95ljyCyuUJr8CBrvg==
X-Received: by 2002:a0d:d489:0:b0:607:d02f:3587 with SMTP id
 w131-20020a0dd489000000b00607d02f3587mr6663621ywd.4.1708101912180; Fri, 16
 Feb 2024 08:45:12 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-15-surenb@google.com>
 <039a817d-20c4-487d-a443-f87e19727305@suse.cz>
In-Reply-To: <039a817d-20c4-487d-a443-f87e19727305@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Feb 2024 08:44:58 -0800
Message-ID: <CAJuCfpE_JUmLWJwbiJh1qX-YMCwgVvUthrF30o=sY_YtaVvgjw@mail.gmail.com>
Subject: Re: [PATCH v3 14/35] lib: introduce support for page allocation tagging
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b=R2irb8FE;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Feb 16, 2024 at 1:45=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/12/24 22:39, Suren Baghdasaryan wrote:
> > Introduce helper functions to easily instrument page allocators by
> > storing a pointer to the allocation tag associated with the code that
> > allocated the page in a page_ext field.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > +
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +
> > +#include <linux/page_ext.h>
> > +
> > +extern struct page_ext_operations page_alloc_tagging_ops;
> > +extern struct page_ext *page_ext_get(struct page *page);
> > +extern void page_ext_put(struct page_ext *page_ext);
> > +
> > +static inline union codetag_ref *codetag_ref_from_page_ext(struct page=
_ext *page_ext)
> > +{
> > +     return (void *)page_ext + page_alloc_tagging_ops.offset;
> > +}
> > +
> > +static inline struct page_ext *page_ext_from_codetag_ref(union codetag=
_ref *ref)
> > +{
> > +     return (void *)ref - page_alloc_tagging_ops.offset;
> > +}
> > +
> > +static inline union codetag_ref *get_page_tag_ref(struct page *page)
> > +{
> > +     if (page && mem_alloc_profiling_enabled()) {
> > +             struct page_ext *page_ext =3D page_ext_get(page);
> > +
> > +             if (page_ext)
> > +                     return codetag_ref_from_page_ext(page_ext);
>
> I think when structured like this, you're not getting the full benefits o=
f
> static keys, and the compiler probably can't improve that on its own.
>
> - page is tested before the static branch is evaluated
> - when disabled, the result is NULL, and that's again tested in the calle=
rs

Yes, that sounds right. I'll move the static branch check earlier like
you suggested. Thanks!

>
> > +     }
> > +     return NULL;
> > +}
> > +
> > +static inline void put_page_tag_ref(union codetag_ref *ref)
> > +{
> > +     page_ext_put(page_ext_from_codetag_ref(ref));
> > +}
> > +
> > +static inline void pgalloc_tag_add(struct page *page, struct task_stru=
ct *task,
> > +                                unsigned int order)
> > +{
> > +     union codetag_ref *ref =3D get_page_tag_ref(page);
>
> So the more optimal way would be to test mem_alloc_profiling_enabled() he=
re
> as the very first thing before trying to get the ref.
>
> > +     if (ref) {
> > +             alloc_tag_add(ref, task->alloc_tag, PAGE_SIZE << order);
> > +             put_page_tag_ref(ref);
> > +     }
> > +}
> > +
> > +static inline void pgalloc_tag_sub(struct page *page, unsigned int ord=
er)
> > +{
> > +     union codetag_ref *ref =3D get_page_tag_ref(page);
>
> And same here.
>
> > +     if (ref) {
> > +             alloc_tag_sub(ref, PAGE_SIZE << order);
> > +             put_page_tag_ref(ref);
> > +     }
> > +}
> > +
> > +#else /* CONFIG_MEM_ALLOC_PROFILING */
> > +
> > +static inline void pgalloc_tag_add(struct page *page, struct task_stru=
ct *task,
> > +                                unsigned int order) {}
> > +static inline void pgalloc_tag_sub(struct page *page, unsigned int ord=
er) {}
> > +
> > +#endif /* CONFIG_MEM_ALLOC_PROFILING */
> > +
> > +#endif /* _LINUX_PGALLOC_TAG_H */
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 78d258ca508f..7bbdb0ddb011 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -978,6 +978,7 @@ config MEM_ALLOC_PROFILING
> >       depends on PROC_FS
> >       depends on !DEBUG_FORCE_WEAK_PER_CPU
> >       select CODE_TAGGING
> > +     select PAGE_EXTENSION
> >       help
> >         Track allocation source code and record total allocation size
> >         initiated at that code location. The mechanism can be used to t=
rack
> > diff --git a/lib/alloc_tag.c b/lib/alloc_tag.c
> > index 4fc031f9cefd..2d5226d9262d 100644
> > --- a/lib/alloc_tag.c
> > +++ b/lib/alloc_tag.c
> > @@ -3,6 +3,7 @@
> >  #include <linux/fs.h>
> >  #include <linux/gfp.h>
> >  #include <linux/module.h>
> > +#include <linux/page_ext.h>
> >  #include <linux/proc_fs.h>
> >  #include <linux/seq_buf.h>
> >  #include <linux/seq_file.h>
> > @@ -124,6 +125,22 @@ static bool alloc_tag_module_unload(struct codetag=
_type *cttype,
> >       return module_unused;
> >  }
> >
> > +static __init bool need_page_alloc_tagging(void)
> > +{
> > +     return true;
>
> So this means the page_ext memory overead is paid unconditionally once
> MEM_ALLOC_PROFILING is compile time enabled, even if never enabled during
> runtime? That makes it rather costly to be suitable for generic distro
> kernels where the code could be compile time enabled, and runtime enablin=
g
> suggested in a debugging/support scenario. It's what we do with page_owne=
r,
> debug_pagealloc, slub_debug etc.
>
> Ideally we'd have some vmalloc based page_ext flavor for later-than-boot
> runtime enablement, as we now have for stackdepot. But that could be
> explored later. For now it would be sufficient to add an early_param boot
> parameter to control the enablement including page_ext, like page_owner a=
nd
> other features do.

Sounds reasonable. In v1 of this patchset we used early boot parameter
but after LSF/MM discussion that was changed to runtime controls.
Sounds like we would need both here. Should be easy to add.

Allocating/reclaiming dynamically the space for page_ext, slab_ext,
etc is not trivial and if done would be done separately. I looked into
it before and listed the encountered issues in the cover letter of v2
[1], see "things we could not address" section.

[1] https://lore.kernel.org/all/20231024134637.3120277-1-surenb@google.com/

>
> > +}
> > +
> > +static __init void init_page_alloc_tagging(void)
> > +{
> > +}
> > +
> > +struct page_ext_operations page_alloc_tagging_ops =3D {
> > +     .size =3D sizeof(union codetag_ref),
> > +     .need =3D need_page_alloc_tagging,
> > +     .init =3D init_page_alloc_tagging,
> > +};
> > +EXPORT_SYMBOL(page_alloc_tagging_ops);
>
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
kasan-dev/CAJuCfpE_JUmLWJwbiJh1qX-YMCwgVvUthrF30o%3DsY_YtaVvgjw%40mail.gmai=
l.com.
