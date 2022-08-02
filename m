Return-Path: <kasan-dev+bncBCMIZB7QWENRBUNSUOLQMGQET2CKVTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C2957587881
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 09:59:14 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id by17-20020a05651c1a1100b0025e54bda6c7sf1034982ljb.22
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 00:59:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659427154; cv=pass;
        d=google.com; s=arc-20160816;
        b=L+dSpSNMm0SOnlBrUvUsD52tjB1cIo4QlAG4vv/rNb8/yNEYe/7Q+wJBaY6ko62bHL
         xuZw1q5tVhK+yRoIYxXHfHhXJS4q/4KngW8tpV2HyhHy0J3yVgJBXejNebfeAhITceb/
         BMCYwZdFcnPKGga8g8UOrWmDYSkdOsSn1Btc9rl5/OoS1L71RAy2Ozs4ZaYnjjN7PCYt
         7Bqu2rM1a4qcvFh0/MLtr35LU6/C5PzsUgKQVxOiL9+W15/RA70dzyI5EhEN29m8D7d1
         TpJPxpnCdLE5AF15eswZzB/1CbFe20LJ9AMWB3BAoFPFjjfRSMkAtXiFl+o2H64hK6M8
         DfGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r7wL5gmb07C9f7aiXh0IbDmd0hcFwpkb0mVCRNyG6DE=;
        b=oZ6DPNaiGzHNSr+3FUTnalRVxRDoIrLA0Vd8mMM/R/2OxXIv+1PxMI7BFuALIx5ahU
         eo6Y21PKlydF65zZuTeqFum5KNjCsE692e+ivKy/kOzraR82szP0l4ISMngm0Dv9eNKc
         HompdKonU0sN5bWZE9cugLGdLSVbS5Hx91hqznbsjvNkoCWctnkJ1HN0vEToTj2n+dQw
         ZVwhtSU4gsyX/u3uXwTc14URtpJ617F6CqTf4J/Qtk8d9MXO3wnvv8C6UyD16AdkdnGp
         +2o9+WV8cPpBfaqTFvzueY0NyjC+6jOybm7YA+IbNCZo8IBZCOUV3sWVyeIlQ1iBYfmV
         XJCQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TLafKFi1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r7wL5gmb07C9f7aiXh0IbDmd0hcFwpkb0mVCRNyG6DE=;
        b=frI2nfnB3454tT/YkZuDZHLih2DCYnF/PGxWyOTPfCXph3IxDDVcvpYelyX57AE0/n
         S8QpANNpsq35+R/ppfPEBfAoUpLmu1BNlu22CXBiXh7jM7Ncy7BToF8hI+BhOIGQQECT
         quNdTZFIOyK3ttBMlLbt0GbMLFJyH5DnwCM4HYIzzSMx+xAJjPagZWCJc3LU1q5xS9mx
         AyuaTrBmaU5ZilFMiY1ny21ip4NhTSN0RVq3fN2/UvLwzH4O+piaoIAW8X5NKJ4JwX/w
         qG6tM3Qu+SsqB1ISMBwF6E7RxO6309+kxc1NvvpA0ZE374kufKvjntFgyDE90KIT7X8a
         K9Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r7wL5gmb07C9f7aiXh0IbDmd0hcFwpkb0mVCRNyG6DE=;
        b=tjZ64b/PFbyVgDJ2/eaTNzcfTVrdeTzmZkYlKh2qq6NStO8fsfC8AVwCEYVanjeyVm
         1RgCEhjroKUpnET05HKtWlwWHH6Vqgm3wDoqNnI7+hVh5w+F9IL4KOXnDUKcQdixZAoJ
         Ai0GFhWwqM5cbfOxqGVYOC+r08EG9/U34RnuTurdenc4U6zF2x5NtEZuNJdYwfRlpTPm
         fGqTYtxXnuJY386K1KrUiLf+6/UoarO062typ4YHnctyG0eT2yaRL+7uzWpPjfnktzFU
         IN+U6tQt+gLOfQx0wcRN0xaMWpS9/4drXWf0KIotamRsrjEjN2mB4hbd1QKCdi8eZFcT
         AFoQ==
X-Gm-Message-State: AJIora9AqkUhex2fz4zBEj+M2vUm3CE7hzm+gZXX0DOiI56zRrnq5w3P
	OBfWJuNLy2wnrJRPPyTdlIA=
X-Google-Smtp-Source: AGRyM1uQRxw/kLXV9HpMeGFjcrQhZr07qSWUDCzLEpNKBeaCRsLfOOAieP5kBR1Qfgj0puoEUD6zIg==
X-Received: by 2002:a05:651c:897:b0:25d:e574:b64 with SMTP id d23-20020a05651c089700b0025de5740b64mr6205315ljq.203.1659427153964;
        Tue, 02 Aug 2022 00:59:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8803:0:b0:25e:5272:6478 with SMTP id x3-20020a2e8803000000b0025e52726478ls753817ljh.8.-pod-prod-gmail;
 Tue, 02 Aug 2022 00:59:12 -0700 (PDT)
X-Received: by 2002:a2e:9dc6:0:b0:25e:5604:6f37 with SMTP id x6-20020a2e9dc6000000b0025e56046f37mr1916844ljj.352.1659427152828;
        Tue, 02 Aug 2022 00:59:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659427152; cv=none;
        d=google.com; s=arc-20160816;
        b=OeXmmcFoIrSaXsaPqeu6tDo0k5rrntSo0HhTRpags2VYgY5lrSFWXCqEeUFqMMzk/x
         x07s4sJRW4gQEf46OOTVrr9xv6O71osY+TpZz/s1fQqha+uvMdDvDEsUdXm8iI/eqvdI
         oN2DsQfn0w60eopiIWPHtFnHERPBawUgAJaWRUaYmo92sMPap2fpZ88Lspbf1RFgCzQt
         vRWCg1S/alS+Pi+/WGy2iyDsps0iNKzTb7SOLg9CRrH+x9FDmWw3PjR7oplOZOdhd+86
         3agSzOHErZljkOifS87JFgzHL+DEXTD1ZbOTm3AmdNplDTz/V8W7yIKJbf6hp2Iq/4HX
         7xfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8MAHi8SKNFAO7ew3d8bZkDJYG24nzfwsdp/alQmmw3o=;
        b=IFXwwsrD0yq3wJsps/4zrp9aGpF3Gm8hm+2lGbfPeJ4b5In2IhdXLIdvFcZzA+EdQy
         h6ZFiUgsCrTcDmnZrXXlt3XernaiQABoaffw1ADGRJo1tF6mwI4peWBxuXRFxLgiaakp
         GPxv+7IFOLkyPgJ8wUmXy98ZHhq63cKIdj4isEcq41ymutAOdhK4CV2CXPsAZuAqeyDL
         kF5F7NIrpzIMb5++VWDwhisZyEffFPCE9X1hxgQf4UHhSZMFIyIOO2YPo9kA2ZmYqBOE
         PInLe0FdcoNcgVVixGnlBvxlSJKmWNfa/Zu2fkIChcYn2FB7eADTvNlS40IKOFxftle2
         1YSA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=TLafKFi1;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id p11-20020ac24ecb000000b0048a9a4dd9b3si562097lfr.3.2022.08.02.00.59.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 00:59:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id e15so10780235lfs.0
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 00:59:12 -0700 (PDT)
X-Received: by 2002:a19:710b:0:b0:48a:cf83:7551 with SMTP id
 m11-20020a19710b000000b0048acf837551mr7412233lfc.137.1659427152271; Tue, 02
 Aug 2022 00:59:12 -0700 (PDT)
MIME-Version: 1.0
References: <20220727071042.8796-4-feng.tang@intel.com> <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl> <Yudw5ge/lJ26Hksk@feng-skl> <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl> <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
 <YujWZzctbp1Bq25N@feng-skl>
In-Reply-To: <YujWZzctbp1Bq25N@feng-skl>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 09:59:00 +0200
Message-ID: <CACT4Y+YEtmvR2KOW5P0VtbHatxdY7MT22hp9FrUOyjZiKR+BJw@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=TLafKFi1;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12e
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

On Tue, 2 Aug 2022 at 09:47, Feng Tang <feng.tang@intel.com> wrote:
> > > On Mon, Aug 01, 2022 at 10:23:23PM +0800, Vlastimil Babka wrote:
> > > > On 8/1/22 08:21, Feng Tang wrote:
> > > [snip]
> > > > > Cc kansan  mail list.
> > > > >
> > > > > This is really related with KASAN debug, that in free path, some
> > > > > kmalloc redzone ([orig_size+1, object_size]) area is written by
> > > > > kasan to save free meta info.
> > > > >
> > > > > The callstack is:
> > > > >
> > > > >   kfree
> > > > >     slab_free
> > > > >       slab_free_freelist_hook
> > > > >           slab_free_hook
> > > > >             __kasan_slab_free
> > > > >               ____kasan_slab_free
> > > > >                 kasan_set_free_info
> > > > >                   kasan_set_track
> > > > >
> > > > > And this issue only happens with "kmalloc-16" slab. Kasan has 2
> > > > > tracks: alloc_track and free_track, for x86_64 test platform, most
> > > > > of the slabs will reserve space for alloc_track, and reuse the
> > > > > 'object' area for free_track.  The kasan free_track is 16 bytes
> > > > > large, that it will occupy the whole 'kmalloc-16's object area,
> > > > > so when kmalloc-redzone is enabled by this patch, the 'overwritten'
> > > > > error is triggered.
> > > > >
> > > > > But it won't hurt other kmalloc slabs, as kasan's free meta won't
> > > > > conflict with kmalloc-redzone which stay in the latter part of
> > > > > kmalloc area.
> > > > >
> > > > > So the solution I can think of is:
> > > > > * skip the kmalloc-redzone for kmalloc-16 only, or
> > > > > * skip kmalloc-redzone if kasan is enabled, or
> > > > > * let kasan reserve the free meta (16 bytes) outside of object
> > > > >   just like for alloc meta
> > > >
> > > > Maybe we could add some hack that if both kasan and SLAB_STORE_USER is
> > > > enabled, we bump the stored orig_size from <16 to 16? Similar to what
> > > > __ksize() does.
> > >
> > > How about the following patch:
> > >
> > > ---
> > > diff --git a/mm/slub.c b/mm/slub.c
> > > index added2653bb0..33bbac2afaef 100644
> > > --- a/mm/slub.c
> > > +++ b/mm/slub.c
> > > @@ -830,6 +830,16 @@ static inline void set_orig_size(struct kmem_cache *s,
> > >         if (!slub_debug_orig_size(s))
> > >                 return;
> > >
> > > +#ifdef CONFIG_KASAN
> > > +       /*
> > > +        * When kasan is enabled, it could save its free meta data in the
> > > +        * start part of object area, so skip the kmalloc redzone check
> > > +        * for small kmalloc slabs to avoid the data conflict.
> > > +        */
> > > +       if (s->object_size <= 32)
> > > +               orig_size = s->object_size;
> > > +#endif

I think this can be done only when CONFIG_KASAN_GENERIC.
Only CONFIG_KASAN_GENERIC stores free meta info in objects:
https://elixir.bootlin.com/linux/latest/source/mm/kasan/common.c#L176

And KASAN_HW_TAGS has chances of being enabled with DEBUG_SLUB in
real-world uses (with Arm MTE).


> > > +
> > >         p += get_info_end(s);
> > >         p += sizeof(struct track) * 2;
> > >
> > > I extend the size to 32 for potential's kasan meta data size increase.
> > > This is tested locally, if people are OK with it, I can ask for 0Day's
> > > help to verify this.
> >
> > Where is set_orig_size() function defined? Don't see it upstream nor
> > in linux-next.
> > This looks fine but my only concern is that this should not increase
> > memory consumption when slub debug tracking is not enabled, which
> > should be the main operation mode when KASAN is enabled. But I can't
> > figure this out w/o context.
>
> Yes, the patchset was only posted on LKML, and not in any tree now.
> The link to the original patches is:
>
> https://lore.kernel.org/lkml/20220727071042.8796-1-feng.tang@intel.com/t/

Lots of code...

This SLAB_STORE_USER seems to be set on all kmalloc slabs by default
when CONFIG_SLUB_DEBUG is enabled, right?
And KASAN enables CONFIG_SLUB_DEBUG, this means that this is stored
always when KASAN is enabled? Looks wrong.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYEtmvR2KOW5P0VtbHatxdY7MT22hp9FrUOyjZiKR%2BBJw%40mail.gmail.com.
