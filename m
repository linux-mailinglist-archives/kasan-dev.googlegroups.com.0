Return-Path: <kasan-dev+bncBCMIZB7QWENRBYPZUOLQMGQEEAWJ3YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id B6D6C587AB8
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 12:30:58 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id k1-20020a2e9201000000b0025dd56bd7a4sf3037065ljg.17
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 03:30:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659436258; cv=pass;
        d=google.com; s=arc-20160816;
        b=opYBG3Mmxutxz8/iVAunFgysoawlmpJLvuRO4Vyph7ktSCU3Z3ethr2lY+PPVvbOOi
         HVLs/BHaE2+qx3lZvRACKqMH18IQ+rmQjxWuadulJyfNPuP+uI4y0722aqc9pnrDV0L2
         am1g6l1JQUPVJcy1dsk2InAK+YitHGqZagGlGOSdT8fSHblIQaWJnEXqTO5dn6NDAzC5
         IKlDBeg6tsHNuEhJXM3Y6EV9UUXs/tE09y4hmSfpwnMYXQUQGdqZjPdUxJnpAYO5vqs1
         nh4GeAoGefb91BELFApc6IE1dy4bA+w4Zq1oaRUN83seXpxFcSsC6nPftVGh6ztZWDrn
         GPyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AHYhvu1qjAzP6mkLwJDKlyAfNPy6EeBREnvA5koUpL0=;
        b=BY0vkgqJTdK3v4uU+5FSXwsXWHgsfZ1sSY6SQOZhHlurCM2WrCaZlkHMFRj5B9tAxG
         hDrkCtjqb1om5w5R3eOQBZLFbfyScraQT9dcOHs78a9rIv9Mzsps0n+Jg6NvSjIP1bfC
         b10jQ2SOGA/dkbQeNnXIMnIPP2c/F57assxgngq5bDQk6JAgrJ1sOXiFP7r+mMRGiquW
         XdipBT9HlH+BHhGSeN6ew92/6Jr+2/hMw0QcWLpgUnr6dR6n8HtHZMa77AgM31fl2qeR
         XsJRGr3ms9Ekrfxh3G0I3bIgCnC57ZzHFJ5LfuVmhSDmK8+fZEgoIISpfjNL4cz45BSB
         3nTQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TVjyaQFk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHYhvu1qjAzP6mkLwJDKlyAfNPy6EeBREnvA5koUpL0=;
        b=ppMT6d8qHVhvXOKaZrtY35KoeIEsKljqTm2+2tYr1Ui39vkA0AOkt3YLIgjQf7lKPG
         UtvwPMfcPNzsQxFGzmCdilMmit3Mwan8C/kjs4+huvf+BACOg2Myy0vC7HbPeV8FkvIf
         26gHG/Gn0+YpQf7mDnhNPuJuod0fabDXz5AFpipEw/egyXuV5LYxCpO6XuQsjSvS34gA
         /s3C4x3VI/VeUEpujpFYbWS/kg8U5JsOEORPRi/U9ZdoAl+1AmfA1QoVpOSu3Hqxb7jd
         gOreBoq98xdZdiMvIQ2vvJHsovTpi2QzMYtunNB7Ajz9KrfmGOrIggphxmYVXjCSkPa4
         51EA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AHYhvu1qjAzP6mkLwJDKlyAfNPy6EeBREnvA5koUpL0=;
        b=s9ohtb64IUAQ/0xDDb87YHVNV160LQm9LEd2L7uTvz2BT/DEGTwXe1bdkw3D9Ou2oy
         gO+m11c7hU6Wgx0IMgSN1R6tdBKCOus1dtyVTf2j/fBjbgupWYZ/gIAQuDtMD/RMk8nd
         nP54BL1tIx1mFg/osvN2t7nZCjTlPqaXA/3oSNj1r29sCEiTn3Sd/pmgVPUVJ6Vkbq75
         LrNukWuw7qzuyIvllqZ1QCh7fxJCP1kqoKw/105AL+k8MNOQOhmO55tpYpV+pWQzHQO4
         GT46RqBgsqcMUUHrXO55uMRljhgyNxZStkmnMflUHfyPdTz84OMsFEhwxH+ffUNih195
         YNuQ==
X-Gm-Message-State: ACgBeo3uO39JlYGDgicHkl5AlUKx4EMHcn5nBc0eEI47L4lzbjvn7smK
	P8SDHvB1byLspSEa3rVguK0=
X-Google-Smtp-Source: AA6agR7BJULwHL9p6qgNivUE5k34rOuRu3+sRotaFaJxExvSdExsfnguZyUCWxjxhomM9mjVuP0hwg==
X-Received: by 2002:a05:6512:20ce:b0:48a:ee84:b364 with SMTP id u14-20020a05651220ce00b0048aee84b364mr5483180lfr.356.1659436258205;
        Tue, 02 Aug 2022 03:30:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:97c8:0:b0:25e:5594:253d with SMTP id m8-20020a2e97c8000000b0025e5594253dls762859ljj.3.-pod-prod-gmail;
 Tue, 02 Aug 2022 03:30:56 -0700 (PDT)
X-Received: by 2002:a19:7717:0:b0:48a:eae8:35d with SMTP id s23-20020a197717000000b0048aeae8035dmr5564468lfc.276.1659436256748;
        Tue, 02 Aug 2022 03:30:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659436256; cv=none;
        d=google.com; s=arc-20160816;
        b=l7O6qcPWbK1c8QQKB51UNe7AjYA2gx5ZsvX0EPZIOb6eypruQVSL7HIMbagAI9sQIG
         LvToVGP3Tp/P4EzQaJybNcIwAWkSYyq53JtLIM6hBqi3z0MHjDWx9gIRAOyEUJdnPJl5
         dEDLqLYrQlRO881xg+E5gkeTU6+WI0IshJy4BmNKgiQUuP4XTEtoLL5H15GtbDtigqop
         mqdcyHkvxv8zHRjcVTqz64c6uK3IsfnGe15AsWO5gzDTkasTgn1Z2dcvgBy8apBC1cqx
         3fBclnGYh3EGMWUE5rD6xma8BnRT7DMZrs2/LjCHgwVdEO8DGIV2iYxr9HrPVFQxwx22
         dDRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VJWkHF0viqAGmvAeKO165ehfCthiYYzBnEziZnfhmHU=;
        b=yAtvio63Vadp771i+/Kuj8G25fsH+JCxD6j1UOFGE2utNEI9IQWuFRqL2FYUiRfH9G
         bBrEprDNo9cdCQ9mXgkSjAfoynQfqFJgChKiR6kx20XNGV9YeE/ZD9HAsZwaO218Iopb
         pOcJyX6m6cLRg/Ev5LZ69xNu5wjx+2FN9/O2L0epsUSxMLyGtelemz+HS6M0yrRuYUVV
         yWOw2qoENJ1AL5CFibwrbdcNczAVUf8w3USkHvDvoRYKth7e/eZpuY6QXZiP+BGoY3A/
         wBdd49U8QNrLFNn1L7aTJYt6YzI7c+YH8cNOhN+Lc6FNtJHBJ1JVQkUe38n4cglU0niA
         mWOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TVjyaQFk;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id p11-20020ac24ecb000000b0048a9a4dd9b3si576610lfr.3.2022.08.02.03.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 03:30:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id m22so9487728lfl.9
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 03:30:56 -0700 (PDT)
X-Received: by 2002:a05:6512:250b:b0:48b:2c5:fe1e with SMTP id
 be11-20020a056512250b00b0048b02c5fe1emr2470061lfb.598.1659436256267; Tue, 02
 Aug 2022 03:30:56 -0700 (PDT)
MIME-Version: 1.0
References: <20220727071042.8796-4-feng.tang@intel.com> <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl> <Yudw5ge/lJ26Hksk@feng-skl> <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl> <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
 <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz>
In-Reply-To: <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 12:30:44 +0200
Message-ID: <CACT4Y+asjzrBu8ogRDt9hYYaAB3tZ2pK5HBkzkuMp106vQwKWQ@mail.gmail.com>
Subject: Re: [mm/slub] 3616799128: BUG_kmalloc-#(Not_tainted):kmalloc_Redzone_overwritten
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Feng Tang <feng.tang@intel.com>, "Sang, Oliver" <oliver.sang@intel.com>, lkp <lkp@intel.com>, 
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
 header.i=@google.com header.s=20210112 header.b=TVjyaQFk;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f
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

.On Tue, 2 Aug 2022 at 11:43, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 8/2/22 09:06, Dmitry Vyukov wrote:
> > On Tue, 2 Aug 2022 at 08:55, Feng Tang <feng.tang@intel.com> wrote:
> >>
> >> On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
> >> > On 8/1/22 08:21, Feng Tang wrote:
> >> [snip]
> >> > > Cc kansan  mail list.
> >> > >
> >> > > This is really related with KASAN debug, that in free path, some
> >> > > kmalloc redzone ([orig_size+1, object_size]) area is written by
> >> > > kasan to save free meta info.
> >> > >
> >> > > The callstack is:
> >> > >
> >> > >   kfree
> >> > >     slab_free
> >> > >       slab_free_freelist_hook
> >> > >           slab_free_hook
> >> > >             __kasan_slab_free
> >> > >               ____kasan_slab_free
> >> > >                 kasan_set_free_info
> >> > >                   kasan_set_track
> >> > >
> >> > > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> >> > > tracks: alloc_track and free_track, for x86_64 test platform, most
> >> > > of the slabs will reserve space for alloc_track, and reuse the
> >> > > 'object' area for free_track.  The kasan free_track is 16 bytes
> >> > > large, that it will occupy the whole 'kmalloc-16's object area,
> >> > > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> >> > > error is triggered.
> >> > >
> >> > > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> >> > > conflict with kmalloc-redzone which stay in the latter part of
> >> > > kmalloc area.
> >> > >
> >> > > So the solution I can think of is:
> >> > > * skip the kmalloc-redzone for kmalloc-16 only, or
> >> > > * skip kmalloc-redzone if kasan is enabled, or
> >> > > * let kasan reserve the free meta (16 bytes) outside of object
> >> > >   just like for alloc meta
> >> >
> >> > Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> >> > enabled, we bump the stored orig_size from <16 to 16? Similar to what
> >> > __ksize() does.
> >>
> >> How about the following patch:
> >>
> >> ---
> >> diff --git a/mm/slub.c b/mm/slub.c
> >> index added2653bb0..33bbac2afaef 100644
> >> --- a/mm/slub.c
> >> +++ b/mm/slub.c
> >> @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
> >>         if (!slub_debug_orig_size(s))
> >>                 return;
> >>
> >> +#ifdef CONFIG_KASAN
> >> +       /*
> >> +        * When kasan is enabled, it could save its free meta data in the
> >> +        * start part of object area, so skip the kmalloc redzone check
> >> +        * for small kmalloc slabs to avoid the data conflict.
> >> +        */
> >> +       if (s->object_size <= 32)
> >> +               orig_size = s->object_size;
> >> +#endif
> >> +
> >>         p += get_info_end(s);
> >>         p += sizeof(struct track) * 2;
> >>
> >> I extend the size to 32 for potential's kasan meta data size increase.
> >> This is tested locally, if people are OK with it, I can ask for 0Day's
> >> help to verify this.
>
> Is there maybe some KASAN macro we can use instead of hardcoding 32?

kasan_free_meta is placed in the object data after freeing, so it can
be sizeof(kasan_free_meta)


> > Where is set_orig_size() function defined? Don't see it upstream nor
> > in linux-next.
> > This looks fine but my only concern is that this should not increase
> > memory consumption when slub debug tracking is not enabled, which
> > should be the main operation mode when KASAN is enabled. But I can't
> > figure this out w/o context.
>
> It won't increase memory consumption even if slub_debug tracking is enabled.
> It just fakes a bit the size that was passed to kmalloc() and which we newly
> store (thanks to Feng's patches) for statistics and debugging purposes.
>
> >> Thanks,
> >> Feng
> >>
> >> >
> >> > > I don't have way to test kasan's SW/HW tag configuration, which
> >> > > is only enabled on arm64 now. And I don't know if there will
> >> > > also be some conflict.
> >> > >
> >> > > Thanks,
> >> > > Feng
> >> > >
> >> >
> >>
> >> --
> >> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> >> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> >> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YujKCxu2lJJFm73P%40feng-skl.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BasjzrBu8ogRDt9hYYaAB3tZ2pK5HBkzkuMp106vQwKWQ%40mail.gmail.com.
