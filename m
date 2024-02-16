Return-Path: <kasan-dev+bncBC7OD3FKWUERBFNLX2XAMGQE42TD4KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 24831858361
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 18:04:23 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-680b48a8189sf30578826d6.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 09:04:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708103062; cv=pass;
        d=google.com; s=arc-20160816;
        b=oJZtIEFfcya0zZWol+X6yl8naTnRJ0H2DS7wH5KDcCWUMVtP2wYhKU45N20M9PjqBO
         2e2ylM0Erm+ancGezt3VtNC1WNEJgoPIf7S3Sa/bO+rb0UDYHJTVmYvacYjZRbVLalct
         liqcmraPu95kTw1pLyvFSh38DB+ZTsJXUlfl2EG0rGDL/Qq0nWOgC1orVHUoEdu5tite
         WUK2ALNfGjDkNQJFmT2EHjU6O/y3wnoz/+qDpJcKokC850M1UBwkoU70EFMmnjQlsk+8
         f1NXAGq6egjU0YebJG9wXHkhervLKlvfhE3+zdPemyuZjdeA0KGZI0617oDIoWKQLOPV
         271g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=dyd+7cINJ13cbj+6gelA6Ev8CXB8r1SE+icm0L/AY6Y=;
        fh=ttf2/pfDNeCPUNnlPtwEjnLnuVNhB1HFM5kJq5umtbk=;
        b=P53cZkKvvcp3GN9fXBTiMHI8+Ovi6wsGsGA0sWORcXqhWFgo3g2cZU1X+Php+Dty6a
         irq9lgCenEbR8P21M24XqlejrszZ0jRKcF20E2c8vMlSXruh2Wn1pzstjBZWNz3GKU/Z
         DREPvJvOVAaeN67Rrn91WpjS8jOuVDGhOQo+T6kN6Cn351XL5FC/4JIGsXnnpg4RsGlA
         QDzmTxBkKchZsJtOwsRYZ+FH077A0ZZqmS4agKjb5xTyHWyQXCjoiIBRXoT1CbbhQxPz
         qbR8JvSoCpD3JFZSCg9OUAQQnkT3SUafC7f45z+iddBflk1IPtPL2c8SB806aqeaaPwB
         OFVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h26obDJo;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708103062; x=1708707862; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=dyd+7cINJ13cbj+6gelA6Ev8CXB8r1SE+icm0L/AY6Y=;
        b=az1vTAjqmVFqDHwxZl6sGJ4kv711KOyXxNr8q/dlh8b2CULHWZFLXmIQmINnZ/KFPt
         GPRhfOSif3xIcteDoWYGoBO3X9PqUfcLCc6hUOzImv3j+cX7uFRbKUbC1JOJEvwwtuQ1
         G7tfUZQOq0sq72KybWA/JzzW7Oz/3zNq9TZMfj4PZju+wQ/QRxM3i8d6c7PwQeeJK/SF
         jCCGbsLOvIzuLzunDuhnPOVu9/SJg/IN+ThB3QgWRZwgYX69lY30KmTkXxdiGWxnAVQt
         GkI2dnEBuL95mulBq3ywHoVkBkBdeosOBj6hUC2kN66alx3jg3PczIEjSLuh7MigGub3
         Vm7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708103062; x=1708707862;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=dyd+7cINJ13cbj+6gelA6Ev8CXB8r1SE+icm0L/AY6Y=;
        b=gcUGG/M/kjD5LiXx8Q3TRf0ELGJVvLHC8tmlvT4HQcyqq92TbspniAXQaeYMYB9G1R
         3kgs9Yv5ymwXURcA5uyuWQcYfr3uetYcO9uK8od2Pi+lYYsRT02OCq1Qa0jBN6x9CN7n
         IdP83UjSFo67JTIW3d1VTNASLMvekV5zSVZlptlEwuoyHZTsmnCTksvURiH/yJLDL99K
         47z+FYgyIEh+TIBSKT/ljlk3VzuVPQ7gxqBU+LQBHqql0sKwgUZZbUqXCVBVsCPp6te8
         kNJuhXZ1f5E+jdP1jEsddtYxUcDkdGzEtyBQZozG+v8FZLy8HUgXDS0TNgDhzyzAtA8k
         926Q==
X-Forwarded-Encrypted: i=2; AJvYcCWtaI5rDokDof6FimkOa9ZuhMjvFP7ttT4VPrOEk9bQGEiey5VNiS7qkv0djVeHguYZx9D1uRlmTvV1F0rBfc7j4TxBzvKixA==
X-Gm-Message-State: AOJu0Yw65vfHKBrCeoX5/3/0+sZcXrC57/PWBgw2JmkGVnXD/hApMQwx
	woxHpfUFculHkEK24dTlSyivUdyYgZGNUudA1pog0uIJvQE1dBZG
X-Google-Smtp-Source: AGHT+IFrI/xXsyJFBu7tmJhCvRnhnMapnIqG1Qw3byKZ6rndPyLJ375WevX/oYZQAMHsjKpqeYRntg==
X-Received: by 2002:a0c:e24b:0:b0:68c:5027:4cf9 with SMTP id x11-20020a0ce24b000000b0068c50274cf9mr4880462qvl.62.1708103061795;
        Fri, 16 Feb 2024 09:04:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3015:b0:68c:d864:e37c with SMTP id
 ke21-20020a056214301500b0068cd864e37cls1455201qvb.0.-pod-prod-02-us; Fri, 16
 Feb 2024 09:04:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV3q+Hz71+ZsrNHcnVbyD9KrwbguogDtk5HbzmQUSIlMadDteVobtxr8YELLibtUanWgCXZ7o60n8qW1mWiK9KGwe6kPOgLDlFMlg==
X-Received: by 2002:a05:6214:4119:b0:68d:15bc:dfde with SMTP id kc25-20020a056214411900b0068d15bcdfdemr6010215qvb.52.1708103060948;
        Fri, 16 Feb 2024 09:04:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708103060; cv=none;
        d=google.com; s=arc-20160816;
        b=odrj6WqsXigDCrTxxZZAOb3JQIDeAD00CBxPUlKSIpjykhRGIeI4fGZKmR/kM4a+ZH
         mtV4p9f4As3AzbgNNGI8a4iWpWOdXGLZpRk9Snwkbyu1jKF6TCnA0MoEvkH7iTsSl79A
         SNAaJyBihzp0/yqryPvtEWku+lSS6wVFEvhRRYL3m3SMX1/ZVE7+Ksz69yfRwurVPZKu
         r9JrxYY4X/eHSsvRn7J4rWCPM9E2T3uCNlRF3ETjpQ3opWMTr2PW6vasz1Z/bTt+swqb
         9mYVvV9wj0UqRTJQsO/LTPbzm+d9M45JFt3SuI1zraEZH3iE1b+8Yn1LBFH1vCFMvz2j
         fQug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AONf6Rwt70Y/InxvAsZm9qasH+QAXmnPb6exgsQbAn0=;
        fh=6pv62TFPtA2pw/SIosNGEcG8TdyUbFJD5P53KUz34LI=;
        b=pgo2Cvyt7Ov7tubGOKj1HHzDfPRbOekZ976B68pGaB9o5PAvbQ7pz0HcKXhEluMh6z
         1MJW/SkZLDQvQ6Vtppc4SvhvqTDnJMXqurlVQFGExPW1CONGugtir/81dXikYZMon+su
         ef5TFrt3RTRomBhnhcbVCRVISDi6PhHvDLtKeT7m7Ia4ouh0XcIYvca64T7rHu7YH8QW
         aMEPjKAP5fiOgIsEgPimVYXGRXzLznQdkrbxqvHKWikI3MQCdQnbqgJMWY9CAAW4tAz2
         s3le1VepoM8SS7LfIDCSGeEHokAyU2jF0KUsZzrJ7CcIEdYsEcMePZTnRplHZf1ZsrHB
         5xOg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=h26obDJo;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id mn20-20020a0562145ed400b0068f337572ecsi12794qvb.0.2024.02.16.09.04.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 09:04:20 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-60806c3523aso3384597b3.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 09:04:20 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVcpYoCFurXQr6aCqwAbVProPJHwjt5RJxeghbmxq+IcQimcY4LPBpxxmx2/cxBUD63YxarrRxu00TDSdn2EHxwO5ZyIDKTyAXLWA==
X-Received: by 2002:a81:71d6:0:b0:604:a75:4274 with SMTP id
 m205-20020a8171d6000000b006040a754274mr4969437ywc.51.1708103060160; Fri, 16
 Feb 2024 09:04:20 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-21-surenb@google.com>
 <e845a3ee-e6c0-47dd-81e9-ae0fb08886d1@suse.cz>
In-Reply-To: <e845a3ee-e6c0-47dd-81e9-ae0fb08886d1@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Feb 2024 09:04:06 -0800
Message-ID: <CAJuCfpGrVM6DieUZPAoxNNx2zfR9cWeC1-7NboatGEQ4qPbckw@mail.gmail.com>
Subject: Re: [PATCH v3 20/35] lib: add codetag reference into slabobj_ext
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
 header.i=@google.com header.s=20230601 header.b=h26obDJo;       spf=pass
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

On Fri, Feb 16, 2024 at 7:36=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/12/24 22:39, Suren Baghdasaryan wrote:
> > To store code tag for every slab object, a codetag reference is embedde=
d
> > into slabobj_ext when CONFIG_MEM_ALLOC_PROFILING=3Dy.
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > ---
> >  include/linux/memcontrol.h | 5 +++++
> >  lib/Kconfig.debug          | 1 +
> >  mm/slab.h                  | 4 ++++
> >  3 files changed, 10 insertions(+)
> >
> > diff --git a/include/linux/memcontrol.h b/include/linux/memcontrol.h
> > index f3584e98b640..2b010316016c 100644
> > --- a/include/linux/memcontrol.h
> > +++ b/include/linux/memcontrol.h
> > @@ -1653,7 +1653,12 @@ unsigned long mem_cgroup_soft_limit_reclaim(pg_d=
ata_t *pgdat, int order,
> >   * if MEMCG_DATA_OBJEXTS is set.
> >   */
> >  struct slabobj_ext {
> > +#ifdef CONFIG_MEMCG_KMEM
> >       struct obj_cgroup *objcg;
> > +#endif
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +     union codetag_ref ref;
> > +#endif
> >  } __aligned(8);
>
> So this means that compiling with CONFIG_MEM_ALLOC_PROFILING will increas=
e
> the memory overhead of arrays allocated for CONFIG_MEMCG_KMEM, even if
> allocation profiling itself is not enabled in runtime? Similar concern to
> the unconditional page_ext usage, that this would hinder enabling in a
> general distro kernel.
>
> The unused field overhead would be smaller than currently page_ext, but
> getting rid of it when alloc profiling is not enabled would be more work
> than introducing an early boot param for the page_ext case. Could be howe=
ver
> solved similarly to how page_ext is populated dynamically at runtime.
> Hopefully it wouldn't add noticeable cpu overhead.

Yes, slabobj_ext overhead is much smaller than page_ext one but still
considerable and it would be harder to eliminate. Boot-time resizing
of the extension object might be doable but that again would be quite
complex and better be done as a separate patchset. This is lower on my
TODO list than page_ext ones since the overhead is order of magnitude
smaller.

>
> >  static inline void __inc_lruvec_kmem_state(void *p, enum node_stat_ite=
m idx)
> > diff --git a/lib/Kconfig.debug b/lib/Kconfig.debug
> > index 7bbdb0ddb011..9ecfcdb54417 100644
> > --- a/lib/Kconfig.debug
> > +++ b/lib/Kconfig.debug
> > @@ -979,6 +979,7 @@ config MEM_ALLOC_PROFILING
> >       depends on !DEBUG_FORCE_WEAK_PER_CPU
> >       select CODE_TAGGING
> >       select PAGE_EXTENSION
> > +     select SLAB_OBJ_EXT
> >       help
> >         Track allocation source code and record total allocation size
> >         initiated at that code location. The mechanism can be used to t=
rack
> > diff --git a/mm/slab.h b/mm/slab.h
> > index 77cf7474fe46..224a4b2305fb 100644
> > --- a/mm/slab.h
> > +++ b/mm/slab.h
> > @@ -569,6 +569,10 @@ int alloc_slab_obj_exts(struct slab *slab, struct =
kmem_cache *s,
> >
> >  static inline bool need_slab_obj_ext(void)
> >  {
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +     if (mem_alloc_profiling_enabled())
> > +             return true;
> > +#endif
> >       /*
> >        * CONFIG_MEMCG_KMEM creates vector of obj_cgroup objects conditi=
onally
> >        * inside memcg_slab_post_alloc_hook. No other users for now.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGrVM6DieUZPAoxNNx2zfR9cWeC1-7NboatGEQ4qPbckw%40mail.gmail.=
com.
