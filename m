Return-Path: <kasan-dev+bncBCS2NBWRUIFBBGUGY6YAMGQEPYC6X5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 9360389AD22
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Apr 2024 23:48:11 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-34563e7ccc6sf251985f8f.2
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Apr 2024 14:48:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712440091; cv=pass;
        d=google.com; s=arc-20160816;
        b=HajxvkrWxO1DbTfOfNLVWIP7OsxVQhHiEXLu+MQICJk32DzQPbhkIcuZN7uMiDT744
         i+Y4R8FQbzhP3jQG6Kqvcmg67f5e7LPjlQwNOBf7i0WzXqhUA+OhQW/EQcy9trK+z26Y
         UtU0M35bnczoFWaoZugOl6WoGoWewhxB3+H/vrej4aXq18Qd60h+ehi/CeugElKZvHJC
         LiRTVMLL8ET1/MFXElybOjX91+PL9dftvoEUapH9R3mgNXZtEW+sqNS0e3MuzNKKwd/5
         GY1mJHaNunwc92XolytZO90eq+OHltWWWTQUKE21j8uNLJi+r11qeAg4G79tUQCZUcGC
         oYmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=DFFC3YLXzO6TH/+SsANpluRXIt4kA1Jbonm8+XddMcw=;
        fh=pWO7jw/AwPLKs4JlId0hYnZb9Mra99wj6EfNlMwXHxM=;
        b=DgNEYepczw6oYLCOfWX3K7lDwLLidTfnczj+uzg8OsUW+6nPNtpN6uzbp4EeDozLPa
         PiomNSBAho2axb/WwePh6cySPMNmzDX7gvd8gdVvgiZjZEIh9kTLtY+Y0gnT6aqzQhM7
         rUE1NqFGy9SavvQFt9W7BC1ll18xFCTn6blJMuC/BnDAxZ+WCTk3aqpfNTUslThgOiBp
         5Oo43dL1b+6hb2DRiwVZyGhmebv/ZOrrApcjaOEW7+h5SQuFzIfgrLVFEOg8vk+LCmpJ
         R64guxDw0rrutbqisVAAeB1bkMAUKOMcgPvBGpPpbHwypdyrVscc4/gWQjcVx1kIwLYS
         nArg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="N4KxHh/O";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.170 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712440091; x=1713044891; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DFFC3YLXzO6TH/+SsANpluRXIt4kA1Jbonm8+XddMcw=;
        b=bjee7xiAXRaW3zhbbHYyaAopWhn9sqB0pn295h8adoXYZrs5ZRsu0bpjMu4X/gLWoc
         M+iUrPLgjfZrA1R1gLoYBemf2XrfgQI3pzoEiFDl7i3gCh/ROK/2xyvfrEUD9XQccLDH
         7qwC1oPmsdNQfiINisnAobp3tkLctnzvprsVTfdNrb+DNXgdn2h20mfSYE0xZyqieHAq
         hPKpXx+bJtg1qQzfiFYKom6WBAN1AMnnYWwbxJrkFfzdeB/zOXxYnIHImfFhWTzveyAe
         q7k4pwbL3DFJXl7/r1IvbAwEMca0wSUhevgE5iL0wuCA5gW4/78NANuqSMtsCRcRj7VV
         t8uA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712440091; x=1713044891;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DFFC3YLXzO6TH/+SsANpluRXIt4kA1Jbonm8+XddMcw=;
        b=j+CgN9AS4n4aQo+hb8+a293yhx37H59D/T50P1uHjfdPbyDhvQ9I3nHzbG42fQQajx
         Ecmz9MesK9pCtS/zkld24aq3dSiV+5sdLwlhJFE1P114SiLsBhHB7vZus4T5sb/gYwIO
         7kPYrK/MyVyVU4XMP7mDzqhCinexhcKaJcAdXq9xGmDSuh4V9Drs3lsJ6WwTADZUGtWO
         BWueP4r9xGq3SYcS3P7yPjG9Di6Ot5RocwJbFUFAOrRMwZp06JIAfDs/n3YDEIWO+SFl
         WqzKgwQ/d+qDvGiHugbM1SGBGZjARdeTFXVmJDuW31MwJuqj9vJzROtb+rTOdsN8jN/D
         X7Og==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXggpX137XewbES4vGk+jbnUcZfWzqj5LEIrQw2cyql5pdr05jUtypNn8qY1IfMugyH5oO51IILN06LUaq3wanAeMhiuHYMFA==
X-Gm-Message-State: AOJu0YwppagygsA+mju+WDdLm4NdbkDfsUbuevdMdvJDNOBs8y72PJpe
	jCCh8AAD6N1hq+ldFLk5TXaipIg9dXz0237DoEcs+LqazXBGDRea
X-Google-Smtp-Source: AGHT+IGPfeaUbSQuCIMGoY+6wQaw1PQvqMjdzroJqn8Xv53nQgb6K4IsafY/ahbWfHkbQc2OGD4k0g==
X-Received: by 2002:a5d:43ca:0:b0:343:5e64:ea54 with SMTP id v10-20020a5d43ca000000b003435e64ea54mr3332442wrr.61.1712440090605;
        Sat, 06 Apr 2024 14:48:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4404:0:b0:343:a494:5dea with SMTP id z4-20020a5d4404000000b00343a4945deals1136569wrq.0.-pod-prod-06-eu;
 Sat, 06 Apr 2024 14:48:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMIvQRAXRTylxIH8tNwiV+o9ew4x9fjBe1SB04y8orKlVfawgLpMWZ5ZBOJ2dvuNS3Vs9G1ajzB/1azNxDknyJw8IfUg63c9LC4A==
X-Received: by 2002:a05:600c:4e0c:b0:416:3ff5:e369 with SMTP id b12-20020a05600c4e0c00b004163ff5e369mr1384900wmq.37.1712440088716;
        Sat, 06 Apr 2024 14:48:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712440088; cv=none;
        d=google.com; s=arc-20160816;
        b=GPulTF80o3YyNg9zsb/JFQV8xfbqLyzCr52P3PsDsxebN/oyb+FVJqxer/UdVdG8ag
         2dbiLhTEhyXnhRDMoBl9B6sOLKv0NPm9+23mcjmwNqbaeIrKUJZX6/ByuFuN4lsuCETU
         3FKZMj3gT3eDgGn9Q1gH5sEDV0OkvX8oHh3y8xtDzegEa27GMpbt3cghO7xsFy3BuD0o
         usEFrvwH8/ONlMa1RZ0oH5C3MO4B/S2K/W5FbBYbaDtHcGHkE7QMqXckulu/bOGzTn+X
         oAtGwgh9f+Ce/xmpo0CjFvtMEAVgWU9Drf1ukaFMgsTpH+XuOVYxNDnxKnWNmCV+GcOY
         NmmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=zidy/ZuQ9llHF4A0yXUONl+ELs1p92Ps6Z+2FVfH0JQ=;
        fh=SdcM2SL5FYkejuJZDUi40z0skiNK/+AeQsv4HugHKJ4=;
        b=YnZHE3HNHXKYWXV2rbuDx+BXuP6wguC6TnykS3BkM9d6ogeVsOBzT1IiDxevK/3izT
         NqeW1jpqebPGNBZS3qYtqGGNbhtvGSJiN4TziFcKvPrGtX6irI4WHTV1fU9DsRvO40C0
         zNBjhKbw6ZAsF5ZJRba19OseaLYw/n3TmWwPkrWrtQEP703BKh+EyQhPvm9dlkgJ/nkf
         3uaL+0eu/dHlBuWVUhbahIW1E0Wo19m0b1fFS/F9dj6bLkhR0ETfbTOP0Uum5skHtCq1
         PzOMiToVTLRzIdqtjxoTRoipI9U1OE8W7jmTnVK9/W3b52/y7Ln3k0bDknePk8NrJEIy
         aXAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="N4KxHh/O";
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.170 as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta0.migadu.com (out-170.mta0.migadu.com. [91.218.175.170])
        by gmr-mx.google.com with ESMTPS id ay37-20020a05600c1e2500b004162bb8804csi555711wmb.0.2024.04.06.14.48.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 06 Apr 2024 14:48:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.170 as permitted sender) client-ip=91.218.175.170;
Date: Sat, 6 Apr 2024 17:47:57 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Klara Modin <klarasmodin@gmail.com>
Cc: Suren Baghdasaryan <surenb@google.com>, akpm@linux-foundation.org, 
	mhocko@suse.com, vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, 
	mgorman@suse.de, dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, david@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	Nathan Chancellor <nathan@kernel.org>, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, David Howells <dhowells@redhat.com>, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Subject: Re: [PATCH v6 13/37] lib: add allocation tagging support for memory
 allocation profiling
Message-ID: <76nf3dl4cqptqv5oh54njnp4rizot7bej32fufjjtreizzcw3w@rkbjbgujk6pk>
References: <6b8149f3-80e6-413c-abcb-1925ecda9d8c@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <6b8149f3-80e6-413c-abcb-1925ecda9d8c@gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="N4KxHh/O";       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates 91.218.175.170 as
 permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Fri, Apr 05, 2024 at 03:54:45PM +0200, Klara Modin wrote:
> Hi,
>=20
> On 2024-03-21 17:36, Suren Baghdasaryan wrote:
> > Introduce CONFIG_MEM_ALLOC_PROFILING which provides definitions to easi=
ly
> > instrument memory allocators. It registers an "alloc_tags" codetag type
> > with /proc/allocinfo interface to output allocation tag information whe=
n
> > the feature is enabled.
> > CONFIG_MEM_ALLOC_PROFILING_DEBUG is provided for debugging the memory
> > allocation profiling instrumentation.
> > Memory allocation profiling can be enabled or disabled at runtime using
> > /proc/sys/vm/mem_profiling sysctl when CONFIG_MEM_ALLOC_PROFILING_DEBUG=
=3Dn.
> > CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT enables memory allocation
> > profiling by default.
> >=20
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>=20
> With this commit (9e2dcefa791e9d14006b360fba3455510fd3325d in
> next-20240404), randconfig with KCONFIG_SEED=3D0xE6264236 fails to build
> with the attached error. The following patch fixes the build error for me=
,
> but I don't know if it's correct.

Looks good - if you sound out an official patch I'll ack it.

>=20
> Kind regards,
> Klara Modin
>=20
> diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> index 100ddf66eb8e..1c765d80298b 100644
> --- a/include/linux/alloc_tag.h
> +++ b/include/linux/alloc_tag.h
> @@ -12,6 +12,7 @@
>  #include <asm/percpu.h>
>  #include <linux/cpumask.h>
>  #include <linux/static_key.h>
> +#include <linux/irqflags.h>
>=20
>  struct alloc_tag_counters {
>         u64 bytes;
>=20
> > diff --git a/include/linux/alloc_tag.h b/include/linux/alloc_tag.h
> > new file mode 100644
> > index 000000000000..b970ff1c80dc
> > --- /dev/null
> > +++ b/include/linux/alloc_tag.h
> > @@ -0,0 +1,145 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +/*
> > + * allocation tagging
> > + */
> > +#ifndef _LINUX_ALLOC_TAG_H
> > +#define _LINUX_ALLOC_TAG_H
> > +
> > +#include <linux/bug.h>
> > +#include <linux/codetag.h>
> > +#include <linux/container_of.h>
> > +#include <linux/preempt.h>
> > +#include <asm/percpu.h>
> > +#include <linux/cpumask.h>
> > +#include <linux/static_key.h>
> > +
> > +struct alloc_tag_counters {
> > +     u64 bytes;
> > +     u64 calls;
> > +};
> > +
> > +/*
> > + * An instance of this structure is created in a special ELF section a=
t every
> > + * allocation callsite. At runtime, the special section is treated as
> > + * an array of these. Embedded codetag utilizes codetag framework.
> > + */
> > +struct alloc_tag {
> > +     struct codetag                  ct;
> > +     struct alloc_tag_counters __percpu      *counters;
> > +} __aligned(8);
> > +
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > +
> > +static inline struct alloc_tag *ct_to_alloc_tag(struct codetag *ct)
> > +{
> > +     return container_of(ct, struct alloc_tag, ct);
> > +}
> > +
> > +#ifdef ARCH_NEEDS_WEAK_PER_CPU
> > +/*
> > + * When percpu variables are required to be defined as weak, static pe=
rcpu
> > + * variables can't be used inside a function (see comments for DECLARE=
_PER_CPU_SECTION).
> > + */
> > +#error "Memory allocation profiling is incompatible with ARCH_NEEDS_WE=
AK_PER_CPU"
> > +#endif
> > +
> > +#define DEFINE_ALLOC_TAG(_alloc_tag)                                  =
       \
> > +     static DEFINE_PER_CPU(struct alloc_tag_counters, _alloc_tag_cntr)=
;      \
> > +     static struct alloc_tag _alloc_tag __used __aligned(8)           =
       \
> > +     __section("alloc_tags") =3D {                                    =
         \
> > +             .ct =3D CODE_TAG_INIT,                                   =
         \
> > +             .counters =3D &_alloc_tag_cntr };
> > +
> > +DECLARE_STATIC_KEY_MAYBE(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_DEFAULT=
,
> > +                     mem_alloc_profiling_key);
> > +
> > +static inline bool mem_alloc_profiling_enabled(void)
> > +{
> > +     return static_branch_maybe(CONFIG_MEM_ALLOC_PROFILING_ENABLED_BY_=
DEFAULT,
> > +                                &mem_alloc_profiling_key);
> > +}
> > +
> > +static inline struct alloc_tag_counters alloc_tag_read(struct alloc_ta=
g *tag)
> > +{
> > +     struct alloc_tag_counters v =3D { 0, 0 };
> > +     struct alloc_tag_counters *counter;
> > +     int cpu;
> > +
> > +     for_each_possible_cpu(cpu) {
> > +             counter =3D per_cpu_ptr(tag->counters, cpu);
> > +             v.bytes +=3D counter->bytes;
> > +             v.calls +=3D counter->calls;
> > +     }
> > +
> > +     return v;
> > +}
> > +
> > +#ifdef CONFIG_MEM_ALLOC_PROFILING_DEBUG
> > +static inline void alloc_tag_add_check(union codetag_ref *ref, struct =
alloc_tag *tag)
> > +{
> > +     WARN_ONCE(ref && ref->ct,
> > +               "alloc_tag was not cleared (got tag for %s:%u)\n",
> > +               ref->ct->filename, ref->ct->lineno);
> > +
> > +     WARN_ONCE(!tag, "current->alloc_tag not set");
> > +}
> > +
> > +static inline void alloc_tag_sub_check(union codetag_ref *ref)
> > +{
> > +     WARN_ONCE(ref && !ref->ct, "alloc_tag was not set\n");
> > +}
> > +#else
> > +static inline void alloc_tag_add_check(union codetag_ref *ref, struct =
alloc_tag *tag) {}
> > +static inline void alloc_tag_sub_check(union codetag_ref *ref) {}
> > +#endif
> > +
> > +/* Caller should verify both ref and tag to be valid */
> > +static inline void __alloc_tag_ref_set(union codetag_ref *ref, struct =
alloc_tag *tag)
> > +{
> > +     ref->ct =3D &tag->ct;
> > +     /*
> > +      * We need in increment the call counter every time we have a new
> > +      * allocation or when we split a large allocation into smaller on=
es.
> > +      * Each new reference for every sub-allocation needs to increment=
 call
> > +      * counter because when we free each part the counter will be dec=
remented.
> > +      */
> > +     this_cpu_inc(tag->counters->calls);
> > +}
> > +
> > +static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_=
tag *tag, size_t bytes)
> > +{
> > +     alloc_tag_add_check(ref, tag);
> > +     if (!ref || !tag)
> > +             return;
> > +
> > +     __alloc_tag_ref_set(ref, tag);
> > +     this_cpu_add(tag->counters->bytes, bytes);
> > +}
> > +
> > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)
> > +{
> > +     struct alloc_tag *tag;
> > +
> > +     alloc_tag_sub_check(ref);
> > +     if (!ref || !ref->ct)
> > +             return;
> > +
> > +     tag =3D ct_to_alloc_tag(ref->ct);
> > +
> > +     this_cpu_sub(tag->counters->bytes, bytes);
> > +     this_cpu_dec(tag->counters->calls);
> > +
> > +     ref->ct =3D NULL;
> > +}
> > +
> > +#else /* CONFIG_MEM_ALLOC_PROFILING */
> > +
> > +#define DEFINE_ALLOC_TAG(_alloc_tag)
> > +static inline bool mem_alloc_profiling_enabled(void) { return false; }
> > +static inline void alloc_tag_add(union codetag_ref *ref, struct alloc_=
tag *tag,
> > +                              size_t bytes) {}
> > +static inline void alloc_tag_sub(union codetag_ref *ref, size_t bytes)=
 {}
> > +
> > +#endif /* CONFIG_MEM_ALLOC_PROFILING */
> > +
> > +#endif /* _LINUX_ALLOC_TAG_H */

> In file included from ./arch/x86/include/asm/percpu.h:615,
>                  from ./arch/x86/include/asm/preempt.h:6,
>                  from ./include/linux/preempt.h:79,
>                  from ./include/linux/alloc_tag.h:11,
>                  from lib/alloc_tag.c:2:
> ./include/linux/alloc_tag.h: In function =E2=80=98__alloc_tag_ref_set=E2=
=80=99:
> ./include/asm-generic/percpu.h:155:9: error: implicit declaration of func=
tion =E2=80=98raw_local_irq_save=E2=80=99 [-Werror=3Dimplicit-function-decl=
aration]
>   155 |         raw_local_irq_save(__flags);                             =
       \
>       |         ^~~~~~~~~~~~~~~~~~
> ./include/asm-generic/percpu.h:410:41: note: in expansion of macro =E2=80=
=98this_cpu_generic_to_op=E2=80=99
>   410 | #define this_cpu_add_8(pcp, val)        this_cpu_generic_to_op(pc=
p, val, +=3D)
>       |                                         ^~~~~~~~~~~~~~~~~~~~~~
> ./include/linux/percpu-defs.h:368:25: note: in expansion of macro =E2=80=
=98this_cpu_add_8=E2=80=99
>   368 |                 case 8: stem##8(variable, __VA_ARGS__);break;    =
       \
>       |                         ^~~~
> ./include/linux/percpu-defs.h:491:41: note: in expansion of macro =E2=80=
=98__pcpu_size_call=E2=80=99
>   491 | #define this_cpu_add(pcp, val)          __pcpu_size_call(this_cpu=
_add_, pcp, val)
>       |                                         ^~~~~~~~~~~~~~~~
> ./include/linux/percpu-defs.h:501:41: note: in expansion of macro =E2=80=
=98this_cpu_add=E2=80=99
>   501 | #define this_cpu_inc(pcp)               this_cpu_add(pcp, 1)
>       |                                         ^~~~~~~~~~~~
> ./include/linux/alloc_tag.h:106:9: note: in expansion of macro =E2=80=98t=
his_cpu_inc=E2=80=99
>   106 |         this_cpu_inc(tag->counters->calls);
>       |         ^~~~~~~~~~~~
> ./include/asm-generic/percpu.h:157:9: error: implicit declaration of func=
tion =E2=80=98raw_local_irq_restore=E2=80=99 [-Werror=3Dimplicit-function-d=
eclaration]
>   157 |         raw_local_irq_restore(__flags);                          =
       \
>       |         ^~~~~~~~~~~~~~~~~~~~~
> ./include/asm-generic/percpu.h:410:41: note: in expansion of macro =E2=80=
=98this_cpu_generic_to_op=E2=80=99
>   410 | #define this_cpu_add_8(pcp, val)        this_cpu_generic_to_op(pc=
p, val, +=3D)
>       |                                         ^~~~~~~~~~~~~~~~~~~~~~
> ./include/linux/percpu-defs.h:368:25: note: in expansion of macro =E2=80=
=98this_cpu_add_8=E2=80=99
>   368 |                 case 8: stem##8(variable, __VA_ARGS__);break;    =
       \
>       |                         ^~~~
> ./include/linux/percpu-defs.h:491:41: note: in expansion of macro =E2=80=
=98__pcpu_size_call=E2=80=99
>   491 | #define this_cpu_add(pcp, val)          __pcpu_size_call(this_cpu=
_add_, pcp, val)
>       |                                         ^~~~~~~~~~~~~~~~
> ./include/linux/percpu-defs.h:501:41: note: in expansion of macro =E2=80=
=98this_cpu_add=E2=80=99
>   501 | #define this_cpu_inc(pcp)               this_cpu_add(pcp, 1)
>       |                                         ^~~~~~~~~~~~
> ./include/linux/alloc_tag.h:106:9: note: in expansion of macro =E2=80=98t=
his_cpu_inc=E2=80=99
>   106 |         this_cpu_inc(tag->counters->calls);
>       |         ^~~~~~~~~~~~
> cc1: some warnings being treated as errors
> make[3]: *** [scripts/Makefile.build:244: lib/alloc_tag.o] Error 1
> make[2]: *** [scripts/Makefile.build:485: lib] Error 2
> make[1]: *** [/home/klara/git/linux/Makefile:1919: .] Error 2
> make: *** [Makefile:240: __sub-make] Error 2


> # bad: [2b3d5988ae2cb5cd945ddbc653f0a71706231fdd] Add linux-next specific=
 files for 20240404
> git bisect start 'next/master'
> # status: waiting for good commit(s), bad commit known
> # good: [39cd87c4eb2b893354f3b850f916353f2658ae6f] Linux 6.9-rc2
> git bisect good 39cd87c4eb2b893354f3b850f916353f2658ae6f
> # bad: [cc7b62666779616ff52d389a344ffe2c041e36e2] Merge branch 'master' o=
f git://git.kernel.org/pub/scm/linux/kernel/git/bluetooth/bluetooth-next.gi=
t
> git bisect bad cc7b62666779616ff52d389a344ffe2c041e36e2
> # bad: [d6b7dd0f8d84f9fdf2af65fceb608e3206276e81] Merge branch 'for-next'=
 of git://git.kernel.org/pub/scm/linux/kernel/git/qcom/linux.git
> git bisect bad d6b7dd0f8d84f9fdf2af65fceb608e3206276e81
> # bad: [ad6a31687713a8f12165e730e0eb6e0de3beae56] Merge branch 'mm-everyt=
hing' of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
> git bisect bad ad6a31687713a8f12165e730e0eb6e0de3beae56
> # good: [59266d9886adb5c9e240129ccc606727fd3a881d] Merge branch 'fixes' o=
f git://git.kernel.org/pub/scm/linux/kernel/git/riscv/linux.git
> git bisect good 59266d9886adb5c9e240129ccc606727fd3a881d
> # bad: [085e5fe7388cf36ab5c02d91022229e5fade5b30] mm: merge folio_is_secr=
etmem() and folio_fast_pin_allowed() into gup_fast_folio_allowed()
> git bisect bad 085e5fe7388cf36ab5c02d91022229e5fade5b30
> # bad: [f6a61baa9139d174170acdae8667b3246ce44db6] lib: add memory allocat=
ions report in show_mem()
> git bisect bad f6a61baa9139d174170acdae8667b3246ce44db6
> # good: [302519d9e80a7fbf2cf8d0b8961d491af648759f] asm-generic/io.h: kill=
 vmalloc.h dependency
> git bisect good 302519d9e80a7fbf2cf8d0b8961d491af648759f
> # bad: [e6942003e682e3883847459c3d07e23c796a2782] mm: create new codetag =
references during page splitting
> git bisect bad e6942003e682e3883847459c3d07e23c796a2782
> # good: [ed97151dec736c1541bfac2b801108d54ebee5bc] lib: code tagging modu=
le support
> git bisect good ed97151dec736c1541bfac2b801108d54ebee5bc
> # bad: [95767bde5020afefef4205b60e71f4ebf96da74e] lib: introduce early bo=
ot parameter to avoid page_ext memory overhead
> git bisect bad 95767bde5020afefef4205b60e71f4ebf96da74e
> # bad: [9e2dcefa791e9d14006b360fba3455510fd3325d] lib: add allocation tag=
ging support for memory allocation profiling
> git bisect bad 9e2dcefa791e9d14006b360fba3455510fd3325d
> # good: [0eccd42fbf9d7c4ae0cbec48cce637da89813c2c] lib: prevent module un=
loading if memory is not freed
> git bisect good 0eccd42fbf9d7c4ae0cbec48cce637da89813c2c
> # first bad commit: [9e2dcefa791e9d14006b360fba3455510fd3325d] lib: add a=
llocation tagging support for memory allocation profiling

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/76nf3dl4cqptqv5oh54njnp4rizot7bej32fufjjtreizzcw3w%40rkbjbgujk6pk=
.
