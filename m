Return-Path: <kasan-dev+bncBCMIZB7QWENRBEPOUSLQMGQEM4RMRAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 50682587E3B
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 16:39:14 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id p12-20020a05651211ec00b0048a43993b48sf4310557lfs.2
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 07:39:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659451153; cv=pass;
        d=google.com; s=arc-20160816;
        b=yFvbYjsMruE1L79R48YB5GBhifMk8loqNL0OQ+iFz92h2jpVzgg6Iy03uctPFWPr6t
         y4w+3++KaytBeHkPYVCinkeyCkIVQRKkUs4fA5UXCVc1eWRK60Aaah/tVCJkEvOuENLK
         6NXkIRAfrfhVlKOqG3KtLhaaVLiNLO8x/3wCuvTT+8/sc740vEGC0gUOXs5Hpj9wsmbs
         nyaJJgQUXuRTBTfbl4ZZc0bcg5hJV6lU0tNCsUtwfmn0OLQdPOhipzOSYo6CTzJUbdlV
         SxggNU2981RXGVjsZrkoOVp7Fb8icTtiukjqXR+tP5H8VpPxd19ZItCE+N46fUy8GHwI
         Li+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Uc6zj4FV+KA/0UIkJNEqOt1eIvL6Vm5AQljTt9my+3Q=;
        b=Foyz1CGBCNlT4busW/oxFpzJB1ugjhKftSbPeQGZV73eHk0pSuMD5Sg5I1+hgoIBDj
         CCoaWXOTdLNkTfTJESPh9sRWKAL5xjuPdRpiWFC3fdBgtrgvKxRXZuzxAjaDpw0IUu/d
         aNh1ITGBjVeSgg2COn9PdZh+QcNBH2NsgnZrAk0AJy5Q3QZdlL3qKOqqbN9BxS6zudLz
         tgfHqvcVP8HeXXfOXqtICz+XNfBkqrpaavgfDg5f0CuklpitlmpgNtN2df0Rtdf1j9n9
         5V9ucjO4dNnc6PFiRiBA1BNS22t0xb9n5R5fIHJ2l5xtCNuifAK4K4u3susBxbplMAF6
         2OHw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=In4Gth7u;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uc6zj4FV+KA/0UIkJNEqOt1eIvL6Vm5AQljTt9my+3Q=;
        b=hhWHJxF5eTgvjxkutPjchT7Q5eG3zvV7ptTN6EAWioU+/J5I4DNhvznOR7iIyekjFh
         +7Etl8iRvcPewjFjEsiQWrkw06HDmPiijRxcBE8w0V7bO2ySsNx2897t6+UPvXQvK3i0
         UJ7Kj4iYJ46AdEagWnmKj9yWJWiQGuFs1gK9WKe896bU1g0q7k4mdCDmrPpAl+81EPCz
         8G8pvKfBybE3mTqNMkMYD+FCoWHXGPtvlWilVQt9NSStafiJMfSxKi9jbeAt66XgQuMo
         uE90kSRJzJFLgCJiOlhl03eEzW8fNWaIVutBhA1DbFjzjMzWnz/PTSY+cumGQ0Coyds7
         cw9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Uc6zj4FV+KA/0UIkJNEqOt1eIvL6Vm5AQljTt9my+3Q=;
        b=lUibVk9GYDptXQMimk37URbIj2M+lssDvOSvShM47kVwYwoK0Lt7ISvD3czVOtLv8B
         JSkShCXxzYH+BWz9/bNYBKQgDgwmFfcmpBLvlk2rQLCKBn+N2ehoIu8dw5QlRqfry28g
         hq9b8pdC/oj4lsc4eeHO5aDLtuG7Erbfi5Z+IbvWf9hmTD4v5rhz9WOPC8kQTYe88FMy
         9ftIYsQi9wvlRt48nWms7QpMvcyxlvdUuHUcPLaMCUVKU7Tel78K07983Z1zi8jqneQp
         ICTChcDf3phB08vmL4lzDuvLGCOXBMIRDiUnfyXGz5yzKwRtuiDG3kXrToFlsTCkRn6j
         95qw==
X-Gm-Message-State: AJIora/MQ3qearZ3bgbJv8oMQaTT/JzGIOHbaklyjGw0lD936pEJnDPG
	LTR4YFQ4OOOHWAOAyQBrfcc=
X-Google-Smtp-Source: AGRyM1uwhdr8My29+gjvagE/uZU/Db+6H1ZP18H2HKEM0uOLqzaNhUK3oM1Q9VlgE0g+gzdU9e9bqQ==
X-Received: by 2002:a05:6512:11c3:b0:48a:d0fe:7285 with SMTP id h3-20020a05651211c300b0048ad0fe7285mr7116317lfr.125.1659451153529;
        Tue, 02 Aug 2022 07:39:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3695:b0:48a:833c:c687 with SMTP id
 d21-20020a056512369500b0048a833cc687ls122757lfs.0.-pod-prod-gmail; Tue, 02
 Aug 2022 07:39:12 -0700 (PDT)
X-Received: by 2002:a05:6512:1584:b0:481:31e4:1489 with SMTP id bp4-20020a056512158400b0048131e41489mr7259765lfb.509.1659451152350;
        Tue, 02 Aug 2022 07:39:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659451152; cv=none;
        d=google.com; s=arc-20160816;
        b=E14BQbJqfV4/H+H2dn3Sz7zj2dPj0cQM8o/mypecB5BpPLBstMxSy/vrQ9tROVb4QA
         h1X50coq/Zs5gmJr0ozHPWhthCdZDkOipJe0tNJFKLZT3C4N2+RME5HoNFB1BkG2bnB3
         9dKO+TiCXbiL+hkGXg8UVyCGj5PBOGn5bAfL9zjTmSBv47kC1wpGLkgWnu5dkVlqIcju
         rLHXyygGX9uJ/8rPxAeTZurHBG9me639zGcO0uYAvnDolxT/yWLhX8/T/jQWNIihbt0g
         XPjURasXMWutpt2g4gzjvuQhaL5JLNf5VaNH+aXo2pTAXmfGqSjcDJNzoHBn1MAcHflc
         /guA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QZohr85P+ue0277oQoXbNYepoltTriUZ0lDtYLukdEI=;
        b=sXYDyzPcq5FOStL8WjGYxMLkQDgzmpTWoJgQTY2m3c3YBYlbhtrboPtElSMe1eXnTD
         OH6ULQN4WjcKF2qTklnZTDW20xllamNMLRgZO00nIIMU3Hm4cB9PGtxoE+CcwfAYbic0
         RV7VU1pk2CzFUe7K3KOJmjSOdxOUCrBh02Fv6ajxuyduEfIIqB8+JQU9O6qS7Pkp9a0G
         uRlghQ3kvoxraBimHFqjPts3BxAGy2xhkJZONR+BuER+fQz5nneTwq3fVIvvqbhuGdM7
         lrj7uVPvpYuvZPEgKIQ9TnDQV0qsbc8knVuQ7vPa5vCqRuKHc6Osq2K9WW2UtKAtDg8T
         k7MQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=In4Gth7u;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id p13-20020a2ea4cd000000b0025e45cef262si351000ljm.4.2022.08.02.07.39.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 07:39:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id f20so15032056lfc.10
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 07:39:12 -0700 (PDT)
X-Received: by 2002:a05:6512:1287:b0:48b:7f3:658 with SMTP id
 u7-20020a056512128700b0048b07f30658mr1547028lfs.417.1659451151874; Tue, 02
 Aug 2022 07:39:11 -0700 (PDT)
MIME-Version: 1.0
References: <20220727071042.8796-4-feng.tang@intel.com> <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl> <Yudw5ge/lJ26Hksk@feng-skl> <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl> <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
 <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz> <CACT4Y+asjzrBu8ogRDt9hYYaAB3tZ2pK5HBkzkuMp106vQwKWQ@mail.gmail.com>
 <YukoZEm4Q6CSEKKj@feng-skl>
In-Reply-To: <YukoZEm4Q6CSEKKj@feng-skl>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 16:38:59 +0200
Message-ID: <CACT4Y+Y6M5MqSGC0MERFqkxgKYK+LrMYvW5xPH5kUA2mFh5_Xw@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=In4Gth7u;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::134
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

On Tue, 2 Aug 2022 at 15:37, Feng Tang <feng.tang@intel.com> wrote:
>
> On Tue, Aug 02, 2022 at 06:30:44PM +0800, Dmitry Vyukov wrote:
> > .On Tue, 2 Aug 2022 at 11:43, Vlastimil Babka <vbabka@suse.cz> wrote:
> > >
> > > On 8/2/22 09:06, Dmitry Vyukov wrote:
> > > > On Tue, 2 Aug 2022 at 08:55, Feng Tang <feng.tang@intel.com> wrote:
> > > >>
> > > >> On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
> > > >> > On 8/1/22 08:21, Feng Tang wrote:
> > > >> [snip]
> > > >> > > Cc kansan  mail list.
> > > >> > >
> > > >> > > This is really related with KASAN debug, that in free path, some
> > > >> > > kmalloc redzone ([orig_size+1, object_size]) area is written by
> > > >> > > kasan to save free meta info.
> > > >> > >
> > > >> > > The callstack is:
> > > >> > >
> > > >> > >   kfree
> > > >> > >     slab_free
> > > >> > >       slab_free_freelist_hook
> > > >> > >           slab_free_hook
> > > >> > >             __kasan_slab_free
> > > >> > >               ____kasan_slab_free
> > > >> > >                 kasan_set_free_info
> > > >> > >                   kasan_set_track
> > > >> > >
> > > >> > > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> > > >> > > tracks: alloc_track and free_track, for x86_64 test platform, most
> > > >> > > of the slabs will reserve space for alloc_track, and reuse the
> > > >> > > 'object' area for free_track.  The kasan free_track is 16 bytes
> > > >> > > large, that it will occupy the whole 'kmalloc-16's object area,
> > > >> > > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> > > >> > > error is triggered.
> > > >> > >
> > > >> > > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> > > >> > > conflict with kmalloc-redzone which stay in the latter part of
> > > >> > > kmalloc area.
> > > >> > >
> > > >> > > So the solution I can think of is:
> > > >> > > * skip the kmalloc-redzone for kmalloc-16 only, or
> > > >> > > * skip kmalloc-redzone if kasan is enabled, or
> > > >> > > * let kasan reserve the free meta (16 bytes) outside of object
> > > >> > >   just like for alloc meta
> > > >> >
> > > >> > Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> > > >> > enabled, we bump the stored orig_size from <16 to 16? Similar to what
> > > >> > __ksize() does.
> > > >>
> > > >> How about the following patch:
> > > >>
> > > >> ---
> > > >> diff --git a/mm/slub.c b/mm/slub.c
> > > >> index added2653bb0..33bbac2afaef 100644
> > > >> --- a/mm/slub.c
> > > >> +++ b/mm/slub.c
> > > >> @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
> > > >>         if (!slub_debug_orig_size(s))
> > > >>                 return;
> > > >>
> > > >> +#ifdef CONFIG_KASAN
> > > >> +       /*
> > > >> +        * When kasan is enabled, it could save its free meta data in the
> > > >> +        * start part of object area, so skip the kmalloc redzone check
> > > >> +        * for small kmalloc slabs to avoid the data conflict.
> > > >> +        */
> > > >> +       if (s->object_size <= 32)
> > > >> +               orig_size = s->object_size;
> > > >> +#endif
> > > >> +
> > > >>         p += get_info_end(s);
> > > >>         p += sizeof(struct track) * 2;
> > > >>
> > > >> I extend the size to 32 for potential's kasan meta data size increase.
> > > >> This is tested locally, if people are OK with it, I can ask for 0Day's
> > > >> help to verify this.
> > >
> > > Is there maybe some KASAN macro we can use instead of hardcoding 32?
> >
> > kasan_free_meta is placed in the object data after freeing, so it can
> > be sizeof(kasan_free_meta)
>
> 'kasan_free_meta' is defined in mm/kasan/kasan.h, to use it we need to
> include "../kasan/kasan.h" in slub.c, or move its definition to
> "include/linux/kasan.h"
>
> Another idea is to save the info in kasan_info, like:
>
> ---
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b092277bf48d..97e899948d0b 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -100,6 +100,7 @@ static inline bool kasan_has_integrated_init(void)
>  struct kasan_cache {
>         int alloc_meta_offset;
>         int free_meta_offset;
> +       int free_meta_size;

Storing it here looks fine to me.
But I would name it based on the meaning for external users (i.e. that
many bytes are occupied by kasan in freed objects). For some caches
KASAN does not store anything in freed objects at all.



>         bool is_kmalloc;
>  };
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f..7bd82c5ec264 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -178,6 +178,8 @@ void __kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
>                 return;
>         }
>
> +       cache->kasan_info.free_meta_size = sizeof(struct free_meta_offset);
> +
>         /*
>          * Add free meta into redzone when it's not possible to store
>          * it in the object. This is the case when:

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY6M5MqSGC0MERFqkxgKYK%2BLrMYvW5xPH5kUA2mFh5_Xw%40mail.gmail.com.
