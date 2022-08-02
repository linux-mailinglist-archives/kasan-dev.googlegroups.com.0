Return-Path: <kasan-dev+bncBCMIZB7QWENRBG72UOLQMGQEO637OUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 128EF587AC2
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Aug 2022 12:31:56 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id d27-20020adfa41b000000b0021ee714785fsf3388800wra.18
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Aug 2022 03:31:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659436315; cv=pass;
        d=google.com; s=arc-20160816;
        b=CRxzVyCzxQOuvhspPyml53YVWy90ibp/tM3OEtOPbyOIATu5FXoSE1Bi1SHTKoi2GM
         x6b7RwmqO1IlTe9ZoOyK4lcBWk9r7W3uq8kgS1EqM/MKU58It1dkQA4AAQxFGOI40s4K
         Jo1+a8vnguKKOvVD+tHBHX9CMNZo9lR5rKHik3NeZUHQvxBPemWFo4tvX626W8C6aQJ+
         yHnKX4SUirSrbA6zSzpbdNu4ZUdo0BEmHiDnSMSgG3lhslJFtowTEyOlE4yCi3UGcQ1G
         /0oZai4Es8ld1en6Z4rZPGXPIoxghxKK06tgwx+rKrl6EfjBytlv5+T+K4Y2t32kK6zp
         uW3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aH9fbuUUhIl+ZdBX/m1YxnQ7OKS6HGsdGnqywfyYzhA=;
        b=J026io4sP2K6XHa+urOWYVZZhl3JsUF0Jtn8Ev6BO4V3YFfpJ7oI55H2ZHIZ2AZKRF
         N2KwO5Mf/AQRgDbU/wZDPTxBfA0WK5g3eNMhtYp9GDEpXfAx9zYEIrOmcg/rvE33d4Et
         6fMAM+f8oDYfetejKmppt0DnBck5J8y84SRJtlAD0Z4bLpTbWEphul3Tw15etZyZVO3F
         tYE2PNCW8SAGa3KlkyO8NJ2mxd1+f48C1vBlS6mJiY2xMJsuq382BwpP/OeXH+0aAlOu
         0oCgpn6IymAUEYVog+q6eyAPi3bg032eLdi8blNwvTLVEbHDC6sNaIioekBIrPFMsqAT
         H5Mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o4RrJRr+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aH9fbuUUhIl+ZdBX/m1YxnQ7OKS6HGsdGnqywfyYzhA=;
        b=sREy3s7jjYz9zUlr33f1IquUy9qvtp+SrlpNGHwo4gVIx1ZoMUe00CtKu+8EwcuLdW
         aZAHjPHbCU5ZvHC86iRuzhfpMazGY1SudV3UXY5FOZMnR9aRDLyOPhYy2ssiFnLV+4nJ
         V3dmg9ZsmMnJ2g07HsgFsNmuqHGBUzEI0MFUlhrStCNp6jyum1++pejc5aQTNWI9oIc+
         /OJemIw21VJF6e/z6KU84Ps33DopRo46zp423l1C/qDMhecs5iGkPqdlgWLEg4pgP8Vm
         3H/Y7GwZcqDNBWEt8w88KGUpy8fChAEWvX/1xEOAR3E24m3rI52UoAr4MD3F1feb974c
         Kxgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aH9fbuUUhIl+ZdBX/m1YxnQ7OKS6HGsdGnqywfyYzhA=;
        b=yMAmq5+MlsEno9SPq+aDu4/bZfMbQKZz8MsS5i/Jy0c4g2YTw7+DlZNtK+5OVD64dv
         aRqZ8AGJDJIWEU5HANFMCDcNmGNwXLaa1FeopogurBqcKpEPb8xT1ow0XZEEfTbCUhqs
         VWb+vmQEs4eCuMjuIzJi+bXAuhtCfompQzb0sCEz65uTj4HLH406lRTszWnpfozKizQj
         PsoGheRhsJRacf3TKvZFN9TMjG3dNYn9j4HKWdwsRgr5zZ+jUnJsZYwqbBO82EMIjYCE
         HsE+nKZujQ38L/ZQZX/RLoICXFc1MFGkUuEAYY9C01VGGqZEDd51in1hPlOFlcwC5s5O
         VNOQ==
X-Gm-Message-State: AJIora8Zky07r6tjTcCUhSm5fM3xUbUW5QWhayz0hAb7AeEanQAFJxG3
	3S1pXDSogDdFfGDTGbNCJGo=
X-Google-Smtp-Source: AGRyM1uIQUOzu0NcCCXztrM4ckxrU6prLcHIquoiejE2zXGx7b9wZn3thUskFX0utrvuJrliqeHOoQ==
X-Received: by 2002:a05:600c:3652:b0:3a3:7f1f:ac61 with SMTP id y18-20020a05600c365200b003a37f1fac61mr13728443wmq.124.1659436315583;
        Tue, 02 Aug 2022 03:31:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:253:b0:21d:a0b5:24ab with SMTP id
 m19-20020a056000025300b0021da0b524abls16544541wrz.1.-pod-prod-gmail; Tue, 02
 Aug 2022 03:31:54 -0700 (PDT)
X-Received: by 2002:adf:f5c7:0:b0:220:6871:de96 with SMTP id k7-20020adff5c7000000b002206871de96mr4217651wrp.516.1659436314562;
        Tue, 02 Aug 2022 03:31:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659436314; cv=none;
        d=google.com; s=arc-20160816;
        b=d/wxhT7Ejbw9umyFngr033bkKhKFVGUmwHHcBxwWklRZVoKovcdIpoxldIY7LCvJxJ
         glL+pCTQadrU8nllLS38FTr513+U7otXZ/XIGOe7ygt+q1PTnADfiNIqFrznrXg3ilKp
         1XcZ/JnD5GzgVW6EeUeyrRefsueON9d+3PSVeYNC43YGz5+DkAg/2ON4Z09EIYAIBGU9
         oWldgkeNvMlLlwJGwODK7WK+8Ea+6UIIs+56rdim8SkwucFPcObQhbCWu4UbKsM22gT8
         LJgeKOAevWB/6AQYpdkxnvDIIYLjwf2wZiqZkkxVq1j13BgQzuZ+sYirijUaJU9Vi6lM
         x7sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RK5pl1uOPXDiR845YvQnUJkdblCt/aXef4YDWk2HeBk=;
        b=edOdOsTxJHlflaQAYFS++bb4hAjDWUCBfyiOpj6iAG9suPgrUw6L6htidaDn368TR3
         +8DQnhC8pNGALDQ85rYYdBfh/FFZRzoNXl6W1eDVQMghjjAeFdM4WFcxoIYJZrRsBmQJ
         1Ao+J9wg2sOWsWk5Rd1SxYHd9cFB6TsxJligp33Bw2q7IKcO+QpIlfcRkCaYlRFKOZQU
         YYdpRXWf0fcp/jZcJ1suje51yuAV5Xz7gyodzXbeOKZsiuGD+rgWswQHidDQs11VcEwO
         BCcBvdHnixTcmOfd1E4uAr9c06gKpAXdhKXWaPFT++5Cd10RqFzNkkUCaMrVq+46wyMP
         cQwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=o4RrJRr+;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id l5-20020a5d6685000000b0021d9f21dd58si517685wru.6.2022.08.02.03.31.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Aug 2022 03:31:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id z25so21343405lfr.2
        for <kasan-dev@googlegroups.com>; Tue, 02 Aug 2022 03:31:54 -0700 (PDT)
X-Received: by 2002:a05:6512:1095:b0:48a:f9b5:a566 with SMTP id
 j21-20020a056512109500b0048af9b5a566mr2864785lfg.540.1659436314088; Tue, 02
 Aug 2022 03:31:54 -0700 (PDT)
MIME-Version: 1.0
References: <20220727071042.8796-4-feng.tang@intel.com> <YuYm3dWwpZwH58Hu@xsang-OptiPlex-9020>
 <YuY6Wc39DbL3YmGi@feng-skl> <Yudw5ge/lJ26Hksk@feng-skl> <0e545088-d140-4c84-bbb2-a3be669740b2@suse.cz>
 <YujKCxu2lJJFm73P@feng-skl> <CACT4Y+Zwg8BP=6WJpQ5cCbJxLu4HcnCjx8e53aDEbTZ5uzpUyg@mail.gmail.com>
 <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz>
In-Reply-To: <85ec4ea8-ae4c-3592-5491-3db6d0ad8c59@suse.cz>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Aug 2022 12:31:42 +0200
Message-ID: <CACT4Y+aJOLZpdHhYLQEwzmUkLTCDSQWDqs3wN_J_ZcTouGqO=A@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=o4RrJRr+;       spf=pass
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

On Tue, 2 Aug 2022 at 11:43, Vlastimil Babka <vbabka@suse.cz> wrote:
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
>
> >
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

Then it looks good to me. Thanks for double checking.


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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaJOLZpdHhYLQEwzmUkLTCDSQWDqs3wN_J_ZcTouGqO%3DA%40mail.gmail.com.
