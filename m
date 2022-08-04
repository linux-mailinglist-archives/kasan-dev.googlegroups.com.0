Return-Path: <kasan-dev+bncBCMIZB7QWENRB3GHV2LQMGQEXO2R54I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 2452C589A8B
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Aug 2022 12:48:13 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id u17-20020adfa191000000b0021ed2209fccsf4690089wru.16
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Aug 2022 03:48:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659610092; cv=pass;
        d=google.com; s=arc-20160816;
        b=sEDBRKKcC7H0b/kWULTa4mvQLGawpULHH+xLmfkvhQqe0FQBrcNCELQnYBDGx1wyWd
         B+AcilYpKjpgioGvMjtRNTUQp5A0MBn6SCKkY3cxn8hN25APDeT1TdHrcqxhVt4iXnxQ
         ryhPcpAzCZOEeD8RU3f6YzRsfVB9FLKNv2rqp3/nGCy7l55cU807p6U4HmZpyiRzXmzS
         IokhV9L0hDdRbbp3ixD/o/SSH7ip9+He0yS//lR95YuH9RewVKV+o1Z7xVa1PhpwKs3w
         9WXjL6CDcMgEbsbYSkiakp4S+RTLESXkyRTdTfR6Lmt0wmfrSCCPEiKD3aEeisvfw3k7
         8XOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5LT+Vb02qfh8b5twRK7NRFNzJUD93WiLUtGY0JTz6sg=;
        b=k4xjDKZkITYJzBM/mNgjgQ5k+1gKsv++uknTeDI5AfndZBE+2Tnu4GnvF47rM7EHky
         RtEq03ka1CG8xSrYywfRHOaVSwt0A5U3zLQ1d9sGdh+WDel/87cTTbTvlryMbp6CHpKX
         6mEnA5cBxm+f/7KN0B5nHRw0k/oWVFhhPCQU0WKZtza6jcICG/LPBAruVIwthzHolsZ+
         fupV6GOQ07T4UozZ/Wwi7ogJBwCMegunHLLRTS6ss2WrxCSNs3jCaxit8W6ZICjUToSB
         NnwLaS/E+Yq5JPKlWB5exc/6DqP38E2JmYJVUi9sJSahFgQu8wB7Hl7G+lt6Tn/aFjzo
         Mw9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LBXwMho0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5LT+Vb02qfh8b5twRK7NRFNzJUD93WiLUtGY0JTz6sg=;
        b=NJqAO0aapbfLs6IggYEIYqA5YDTnFajjuKyncYSdEfmlMY9C3E6LmwDglp7CvpIHcG
         5s+thR1WBhkaILVcJk7lPiS7Ziz6URp/bRLjtOc2A8B1MaGkP8QiPKYzhRH5D21tqtrH
         GF3oED8vnF/unjcITU51B7wpSXiTN6HGwg1m1F1lsmeQ62rYWEqENZN+qM9xEVdJSFNp
         P3YaFkMQ2V5W9uT+uQJDHLvNGtbOVfsR5jm0BCguVfUQ+06mmS3Ukmp04ZheERmLq9ML
         O0aur8CcAQ9XaE3ih/GnEgLkA09WoMyIlONpWfnXGfsw0OOjYIUp8qyV7WuFDmpePwpt
         wj6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5LT+Vb02qfh8b5twRK7NRFNzJUD93WiLUtGY0JTz6sg=;
        b=YrGyxFk80YI+Pt2Pd5NVVVMQxb4vaDFb9uCYaOXtIPGR4dP2YlC9Mu04Cmei9xq+Ux
         hPpdlYM3lNj92yFEXhAIRPXXz13n5AEZYVeX7SNpGEGGBehyh3aaZ2I46+eXq0hP6wrS
         zY/lHzbmQemBhMIa71ifG5j8tof6nzt49XbT+GxCdXqc378LD4o5K8VLld9mkw4wrWnk
         GVqYN00eUV1vEywj6K9KIg+1NUGhTPMbTPoTnR+bUP0QMCeSV5/7CWEBjkU8/Iy2xQJE
         nMjHN+d5Yryn0fJBqWc3XKZjRi19PAcrpUhE8JLc/UlZq46s6QbyxjKFjFG0HFdOe37i
         7giw==
X-Gm-Message-State: ACgBeo1YsQyf8U/O6wFObMPd8E4mW3QPahqx/iNi4izjLV6sHzFTnXUy
	AI84na+tNJ/H/mNAHxPpvNA=
X-Google-Smtp-Source: AA6agR6yZEBFQqC3FwjAQ+RRDUWtHQFIB4y0IXwWfZRqUno7RBcJNURL0hMxr/r6iOBbKosZ15P7GA==
X-Received: by 2002:a05:600c:3d93:b0:3a3:3a93:fb16 with SMTP id bi19-20020a05600c3d9300b003a33a93fb16mr6082403wmb.190.1659610092684;
        Thu, 04 Aug 2022 03:48:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5a90:0:b0:220:80cc:8add with SMTP id bp16-20020a5d5a90000000b0022080cc8addls2184575wrb.2.-pod-prod-gmail;
 Thu, 04 Aug 2022 03:48:11 -0700 (PDT)
X-Received: by 2002:a5d:4ad2:0:b0:21f:af5:8dc7 with SMTP id y18-20020a5d4ad2000000b0021f0af58dc7mr1033441wrs.575.1659610091361;
        Thu, 04 Aug 2022 03:48:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659610091; cv=none;
        d=google.com; s=arc-20160816;
        b=BIZ/7HCw99uAwuAOt8koMG7GdEyReOLR+ecF29VGIXS9ZTxeaw8N1x3Nt7QoKQPtyL
         uNQ6pX5kNLlrzSxy2ivktrHXQx/lGiw48czunZ/AISQzrzabq4R+wR5BRy4J8OtGyadO
         AWwLOCORoz7QXziM9MyW+y9IFpQasZLHauuWh1u/5gPkCEwBUE9rUHg08bCDlzHfATOt
         SpgsLogPVp+310c/4WJY/ZnLsHgRgmyoeDGJQYt7+JzxVl+jnDGx+HOKQ7NaSXkMa4oY
         fU3bf1UZX0pFUhM7tfjHy0vg1JwraDBJJ2CWSWoLzuD24FWf5UkLWSxC2NmNMqW1vVhi
         CBDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eegZBp28eQmH3OhuZfCVY16Y84OTpGQZtSHItuJdUI0=;
        b=vvv/jdZN7J7tl32imYnZuLYXcInoL+PxzDZHnIbMVaeuisXzfBDdgWBWrUmPXe24dZ
         PhdXEF7RIWIVtQ12Ccp/0D4bidr9gDkE3eC3iiKaF7B4TxxcEKbB6p3M7i11TYHatrLb
         lCH682jC0J6Rn25lDRyhz9crxfiQaKTZvX3xfkBdPYrFR6KK1toXRquwa3MSAhydGR0W
         3K9RjxLmFPj0ocU+26bkaVjkjRLRaAy5Xg6hIxjI/s3ovBK45NQ/mlJExxvbFyBopnuj
         jR+fqmA/W3fMjlp8xztMYxhKBvVrRPaBhQ7jMecvR2N/z9ceqF7/vDkVZa4lfYLMkbp+
         cJvA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LBXwMho0;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12b.google.com (mail-lf1-x12b.google.com. [2a00:1450:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id d12-20020a056000186c00b0021d9f21dd58si20071wri.6.2022.08.04.03.48.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Aug 2022 03:48:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12b as permitted sender) client-ip=2a00:1450:4864:20::12b;
Received: by mail-lf1-x12b.google.com with SMTP id t1so30205029lft.8
        for <kasan-dev@googlegroups.com>; Thu, 04 Aug 2022 03:48:11 -0700 (PDT)
X-Received: by 2002:a05:6512:1086:b0:48b:27a4:5059 with SMTP id
 j6-20020a056512108600b0048b27a45059mr492779lfg.540.1659610090741; Thu, 04 Aug
 2022 03:48:10 -0700 (PDT)
MIME-Version: 1.0
References: <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020> <YuY6Wc39DbL3YmGi@feng-skl>
 <Yudw5ge/lJ26Hksk@feng-skl> <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl> <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
 <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz> <CACT4Y+asjzrBu8ogRDt9hYYaAB3tZ2pK5HBkzkuMp106vQwKWQ@mail.gmail.com>
 <YukoZEm4Q6CSEKKj@feng-skl> <CACT4Y+Y6M5MqSGC0MERFqkxgKYK+LrMYvW5xPH5kUA2mFh5_Xw@mail.gmail.com>
 <YutnCD5dPie/yoIk@feng-clx>
In-Reply-To: <YutnCD5dPie/yoIk@feng-clx>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Aug 2022 12:47:58 +0200
Message-ID: <CACT4Y+Zzzj7+LwUwyMoBketXFBHRksnx148B1aLATZ48AU9o3w@mail.gmail.com>
Subject: Re: [mm/slub] 3616799128: BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
To: Feng Tang <feng.tang@intel.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, "Sang, Oliver" <oliver.sang@intel.com>, lkp <lkp@intel.com>, 
	LKML <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"lkp@lists.01.org" <lkp@lists.01.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, "Hansen, Dave" <dave.hansen@intel.com>, 
	Robin Murphy <robin.murphy@arm.com>, John Garry <john.garry@huawei.com>, 
	Kefeng Wang <wangkefeng.wang@huawei.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LBXwMho0;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12b
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

 On Thu, 4 Aug 2022 at 08:29, Feng Tang <feng.tang@intel.com> wrote:
> > > > .On Tue, 2 Aug 2022 at 11:43, Vlastimil Babka <vbabka@suse.cz> wrote:
> > > > >
> > > > > On 8/2/22 09:06, Dmitry Vyukov wrote:
> > > > > > On Tue, 2 Aug 2022 at 08:55, Feng Tang <feng.tang@intel.com> wrote:
> > > > > >>
> > > > > >> On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
> > > > > >> > On 8/1/22 08:21, Feng Tang wrote:
> > > > > >> [snip]
> > > > > >> > > Cc kansan  mail list.
> > > > > >> > >
> > > > > >> > > This is really related with KASAN debug, that in free path, some
> > > > > >> > > kmalloc redzone ([orig_size+1, object_size]) area is written by
> > > > > >> > > kasan to save free meta info.
> > > > > >> > >
> > > > > >> > > The callstack is:
> > > > > >> > >
> > > > > >> > >   kfree
> > > > > >> > >     slab_free
> > > > > >> > >       slab_free_freelist_hook
> > > > > >> > >           slab_free_hook
> > > > > >> > >             __kasan_slab_free
> > > > > >> > >               ____kasan_slab_free
> > > > > >> > >                 kasan_set_free_info
> > > > > >> > >                   kasan_set_track
> > > > > >> > >
> > > > > >> > > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> > > > > >> > > tracks: alloc_track and free_track, for x86_64 test platform, most
> > > > > >> > > of the slabs will reserve space for alloc_track, and reuse the
> > > > > >> > > 'object' area for free_track.  The kasan free_track is 16 bytes
> > > > > >> > > large, that it will occupy the whole 'kmalloc-16's object area,
> > > > > >> > > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> > > > > >> > > error is triggered.
> > > > > >> > >
> > > > > >> > > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> > > > > >> > > conflict with kmalloc-redzone which stay in the latter part of
> > > > > >> > > kmalloc area.
> > > > > >> > >
> > > > > >> > > So the solution I can think of is:
> > > > > >> > > * skip the kmalloc-redzone for kmalloc-16 only, or
> > > > > >> > > * skip kmalloc-redzone if kasan is enabled, or
> > > > > >> > > * let kasan reserve the free meta (16 bytes) outside of object
> > > > > >> > >   just like for alloc meta
> > > > > >> >
> > > > > >> > Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> > > > > >> > enabled, we bump the stored orig_size from <16 to 16? Similar to what
> > > > > >> > __ksize() does.
> > > > > >>
> > > > > >> How about the following patch:
> > > > > >>
> > > > > >> ---
> > > > > >> diff --git a/mm/slub.c b/mm/slub.c
> > > > > >> index added2653bb0..33bbac2afaef 100644
> > > > > >> --- a/mm/slub.c
> > > > > >> +++ b/mm/slub.c
> > > > > >> @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
> > > > > >>         if (!slub_debug_orig_size(s))
> > > > > >>                 return;
> > > > > >>
> > > > > >> +#ifdef CONFIG_KASAN
> > > > > >> +       /*
> > > > > >> +        * When kasan is enabled, it could save its free meta data in the
> > > > > >> +        * start part of object area, so skip the kmalloc redzone check
> > > > > >> +        * for small kmalloc slabs to avoid the data conflict.
> > > > > >> +        */
> > > > > >> +       if (s->object_size <= 32)
> > > > > >> +               orig_size = s->object_size;
> > > > > >> +#endif
> > > > > >> +
> > > > > >>         p += get_info_end(s);
> > > > > >>         p += sizeof(struct track) * 2;
> > > > > >>
> > > > > >> I extend the size to 32 for potential's kasan meta data size increase.
> > > > > >> This is tested locally, if people are OK with it, I can ask for 0Day's
> > > > > >> help to verify this.
> > > > >
> > > > > Is there maybe some KASAN macro we can use instead of hardcoding 32?
> > > >
> > > > kasan_free_meta is placed in the object data after freeing, so it can
> > > > be sizeof(kasan_free_meta)
> > >
> > > 'kasan_free_meta' is defined in mm/kasan/kasan.h, to use it we need to
> > > include "../kasan/kasan.h" in slub.c, or move its definition to
> > > "include/linux/kasan.h"
> > >
> > > Another idea is to save the info in kasan_info, like:
> > >
> > > ---
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index b092277bf48d..97e899948d0b 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -100,6 +100,7 @@ static inline bool kasan_has_integrated_init(void)
> > >  struct kasan_cache {
> > >         int alloc_meta_offset;
> > >         int free_meta_offset;
> > > +       int free_meta_size;
> >
> > Storing it here looks fine to me.
> > But I would name it based on the meaning for external users (i.e. that
> > many bytes are occupied by kasan in freed objects). For some caches
> > KASAN does not store anything in freed objects at all.
>
> OK, please review the below patch, thanks!
>
> - Feng
>
> ---8<---
> From c4fc739ea4d5222f0aba4b42b59668d64a010082 Mon Sep 17 00:00:00 2001
> From: Feng Tang <feng.tang@intel.com>
> Date: Thu, 4 Aug 2022 13:25:35 +0800
> Subject: [PATCH] mm: kasan: Add free_meta size info in struct kasan_cache
>
> When kasan is enabled for slab/slub, it may save kasan' free_meta
> data in the former part of slab object data area in slab object
> free path, which works fine.
>
> There is ongoing effort to extend slub's debug function which will
> redzone the latter part of kmalloc object area, and when both of
> the debug are enabled, there is possible conflict, especially when
> the kmalloc object has small size, as caught by 0Day bot [1]
>
> For better information for slab/slub, add free_meta's data size
> info 'kasan_cache', so that its users can take right action to
> avoid data conflict.
>
> [1]. https://lore.kernel.org/lkml/YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020/
> Reported-by: kernel test robot <oliver.sang@intel.com>
> Signed-off-by: Feng Tang <feng.tang@intel.com>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

I assume there will be a second patch that uses
free_meta_size_in_object  in slub debug code.

> ---
>  include/linux/kasan.h | 2 ++
>  mm/kasan/common.c     | 2 ++
>  2 files changed, 4 insertions(+)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b092277bf48d..293bdaa0ba09 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -100,6 +100,8 @@ static inline bool kasan_has_integrated_init(void)
>  struct kasan_cache {
>         int alloc_meta_offset;
>         int free_meta_offset;
> +       /* size of free_meta data saved in object's data area */
> +       int free_meta_size_in_object;
>         bool is_kmalloc;
>  };
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 78be2beb7453..a627efa267d1 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -201,6 +201,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                         cache->kasan_info.free_meta_offset = KASAN_NO_FREE_META;
>                         *size = ok_size;
>                 }
> +       } else {
> +               cache->kasan_info.free_meta_size_in_object = sizeof(struct kasan_free_meta);
>         }
>
>         /* Calculate size with optimal redzone. */
> --
> 2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZzzj7%2BLwUwyMoBketXFBHRksnx148B1aLATZ48AU9o3w%40mail.gmail.com.
