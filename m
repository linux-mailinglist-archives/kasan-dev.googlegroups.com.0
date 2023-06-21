Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHXHZOSAMGQETLN52JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D329738428
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 14:57:05 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-62ff6a6b4f4sf69177626d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 05:57:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687352223; cv=pass;
        d=google.com; s=arc-20160816;
        b=sr8PME+rC4O7f/ujnBLyAZzIo5KhTVhJf/4jI6KM6Hyb1OKxO95+wexFBl7D2E8Rhz
         Qposnct7c0z4/Ce8vRAu/p7yI70niBjO/LQmaQazKTsYBWpFRR5iaJ9RLiOfubdZ+rk4
         CI96xh4YjOnUgbiOjAG9J7vpM6xQI529dNNoE6U2iVTGJQLOc2YwuhJnAxakCghzefKH
         85lWfCCkNKeWf05wyjcBtipPjLP1JP6HrRsChZC9O7MIduwal5J4XQTc8WpqVrY97YTZ
         RugdUZRhQysmQ7CcHB0Zezp48l61kj9eHwt4gsvox9p9ARClbK/QiqrB9chPTOKTAgG7
         O0Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zQKjw/FCsmbyixhT9tfC0yRARo+zYG4KnfqI5y3Zxg0=;
        b=UmeqokmqbwrE+tAj9MwiTuXhdwdVIkSRvR9q06WSukk3kWidK5utPpp8u/WpSOViOo
         XzLCWGherZBRzqu16spo3qHDrw6kSE/Hj/Odph+a3IhYCR8gu0+k5vBiHXuuV/tcBeUs
         QAS4ZefgsNzpK6sxnp7mM8P0SA/p62ihb4+25qESg4/rdhGR1fxIL0hA0plJHkpIlVkV
         f3ihAeexOajfl/NoSf1m9w95pUCgD+OTPb1hvqhYX+TxcXEXL+Igo7eDuJv7SQ6nDsFi
         xWpie8pZRSRW9JDGR5niO32P/S8Y1qnd6g2/B7N4W3IeeGtzcgGOroTsu35zSR5L2VJO
         MILg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=HguHzfhH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687352223; x=1689944223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zQKjw/FCsmbyixhT9tfC0yRARo+zYG4KnfqI5y3Zxg0=;
        b=I4LYMJSnL0ARMIa40Iq5nXATaMLqs5/spwE6KBbnG15zraVKDbAh7EOKqS4z0HRrNo
         oxdMLaK+giAtqaIz3QK2epkksooN+Lk5EIbHkGK8VXQ3Vs8qoDJ3otrKhkQxv7zFm3o6
         y2zgNwzhnT4y9vLfroCiMdf9gZW+KaX0MGCHPmP/ichH9rrGg8iP5px000gvirIXNH+9
         VVHrUQX0A4TXDiZ4aO2rccN8hY7YUMd6MduOSj5VasqvAGeESrMt/jUqpIpY5M9aU1TK
         8niP+WZjtr2s8dPik/3qrxUCdWwXj0uQGcPg2i4KXtkrP9DLvQ8jA1aS5DPnSGeVBuUZ
         szHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687352223; x=1689944223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zQKjw/FCsmbyixhT9tfC0yRARo+zYG4KnfqI5y3Zxg0=;
        b=Fq/anqbgRY6QVShCCgQovRBZNThcAdduGypnJevsObOB/+3dlmdc2h96aeKSUGbFmi
         yx1k84vCNy30tK+3eTBhw0CADVS+fD85JDxkHF2uWYQSooeyzoUIc+NcWg7Qoej4xEsg
         bR+oSV8yVyYYqc3RfG2EVejTjzVaQy+3wKIbVTDQrLCQUrgfu9rD4pNH9n5X2ngds77Z
         GgOFMGy2Nlv7VuUJmWHAPHMEV67ehbKrPu7eN+8oyCLuok7e0POcum5NUdlAkJfmI/05
         uI+1afeWaFaAWbZvdxgzmHXaMPmuu1tS8fb32UGxXOjTdtKilwja93rq41iOc6Wrpnhx
         22lw==
X-Gm-Message-State: AC+VfDy1zkdC5jFuOYeTZ8aBPwyFaGFybFHnB58Lz3U3uSGEMIf84iAb
	wy7M6z7X65qKaWNzj8Jd64c=
X-Google-Smtp-Source: ACHHUZ5G4S9x95FGavJ3oRhD0A4+KdS3fvwO9xiWgVwvb6EzR0U4RW4fM75BX/1+42BlSCNQLBHG4w==
X-Received: by 2002:a05:6214:212e:b0:62d:edb2:b42a with SMTP id r14-20020a056214212e00b0062dedb2b42amr19057615qvc.45.1687352223090;
        Wed, 21 Jun 2023 05:57:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:b0d:b0:632:628:f73e with SMTP id
 u13-20020a0562140b0d00b006320628f73els491428qvj.2.-pod-prod-05-us; Wed, 21
 Jun 2023 05:57:02 -0700 (PDT)
X-Received: by 2002:a05:6214:1bcb:b0:632:15e6:a75e with SMTP id m11-20020a0562141bcb00b0063215e6a75emr1275353qvc.46.1687352222388;
        Wed, 21 Jun 2023 05:57:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687352222; cv=none;
        d=google.com; s=arc-20160816;
        b=f8eJ1wwuITt9TMHt3Rn58x8uZiCvLWrSyRurz2VRz5lh5Bj5CCe/igY8+kUIucq54R
         SFMrDvpAuP31Vwy0gBdKmm0qWBoF1jwulE2UZm1XsbgNd15jc/Xse6cEZbY6Q7sJJyXB
         PG9Qqpe1TpMeclaHm5tX6u7mplgcXuie91DZnPWi+1mmR8aybzgsbUoFe36qbIEJKVoS
         HLLVoCxHIwVFiXkDbMsZ+1sa6UnYzjzXZLQNbI5w/UO7fCd2YCQYLR9xURR4SrcDBWsn
         ZEOunBXWItaqv6bEiL980zUjYItT01wutjTdRpphAunRAaSbbhyMDkuerepgOZyU8zyO
         frYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=evIj23C5RuYH7l01ysd2yt+gQqbHOQ1C3V6W2tREipI=;
        b=zSLIL1qqG60vZiou7ZUeWEweczukxgrJlZ2vadmJTVvNp+d3cdHo93cp3dDV2k257n
         J3lhU+/uCBmVvhcbP4yFZnf5Q4jaUYqor2ppd/MbkB6UmLhUXrPz3EswT/eXbk4Yw50s
         12kaxJ6gqmdf3uimkIEFhHPfb/aNOZf8zEvncNNPe6fD4sKBT7K240ZqDcpGY9Yb8hL8
         YLmnkRyOUt+AtwM9YSIe6T6nEqOlpGbl9bOVCV05Xr3glmYO4ARCfqZl5yITe06r9QJt
         OyR3OKQVMSx4UkBr+4QcBlaCuIM2u8DrbiI54tzsdU4RSeMgzpx6cEQBGw1KIVvAM5xw
         LKqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=HguHzfhH;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id og5-20020a056214428500b0062625273f69si366785qvb.2.2023.06.21.05.57.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jun 2023 05:57:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id ca18e2360f4ac-77de8cc13b4so281937239f.2
        for <kasan-dev@googlegroups.com>; Wed, 21 Jun 2023 05:57:02 -0700 (PDT)
X-Received: by 2002:a05:6602:399:b0:77e:3d2f:d1f8 with SMTP id
 f25-20020a056602039900b0077e3d2fd1f8mr8694965iov.10.1687352221671; Wed, 21
 Jun 2023 05:57:01 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000cef3a005fc1bcc80@google.com> <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
 <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com> <CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
 <20230609153124.11905393c03660369f4f5997@linux-foundation.org> <19d6c965-a9cf-16a5-6537-a02823d67c0a@I-love.SAKURA.ne.jp>
In-Reply-To: <19d6c965-a9cf-16a5-6537-a02823d67c0a@I-love.SAKURA.ne.jp>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jun 2023 14:56:25 +0200
Message-ID: <CAG_fn=XBBVBj9VcFkirMNj9sQOHvx2Q12o9esDkgPB0BP33DKg@mail.gmail.com>
Subject: Re: [PATCH v3] lib/stackdepot: fix gfp flags manipulation in __stack_depot_save()
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Andrew Morton <akpm@linux-foundation.org>, "Huang, Ying" <ying.huang@intel.com>, 
	syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>, 
	syzkaller-bugs@googlegroups.com, Mel Gorman <mgorman@techsingularity.net>, 
	Vlastimil Babka <vbabka@suse.cz>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=HguHzfhH;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d2c as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Sat, Jun 10, 2023 at 1:40=E2=80=AFPM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> syzbot is reporting lockdep warning in __stack_depot_save(), for
> __kasan_record_aux_stack() is passing GFP_NOWAIT which will result in
> calling wakeup_kcompactd() from wakeup_kswapd() from wake_all_kswapds()
>  from __alloc_pages_slowpath().
>
> Strictly speaking, __kasan_record_aux_stack() is responsible for removing
> __GFP_KSWAPD_RECLAIM flag in order not to wake kswapd which in turn wakes
> kcompactd. But since KASAN and KMSAN functions might be called with
> arbitrary locks held, we should consider removing __GFP_KSWAPD_RECLAIM
> flag from KASAN and KMSAN. And this patch goes one step further; let's
> remove __GFP_KSWAPD_RECLAIM flag in the __stack_depot_save() side, based
> on the following reasons.
>
> Reason 1:
>
>   Currently, __stack_depot_save() has "alloc_flags &=3D ~GFP_ZONEMASK;" l=
ine
>   which is pointless because "alloc_flags &=3D (GFP_ATOMIC | GFP_KERNEL);=
"
>   line will also zero out zone modifiers.

Good catch, we indeed do not need the GFP_ZONEMASK line now.
But looks like you'll need it at least in the __GFP_NOFAIL branch?

> But why is __stack_depot_save()
>   trying to mask gfp flags supplied by the caller?
>
>   I guess that __stack_depot_save() tried to be as robust as possible. Bu=
t
>   __stack_depot_save() is a debugging function where all callers have to
>   be able to survive allocation failures.

This, but also the allocation should not deadlock.
E.g. KMSAN can call __stack_depot_save() from almost any function in
the kernel, so we'd better avoid heavyweight memory reclaiming,
because that in turn may call __stack_depot_save() again.

>
> Reason 2:
>
>   __stack_depot_save() from stack_depot_save() is also called by
>   ref_tracker_alloc() from __netns_tracker_alloc() from
>   netns_tracker_alloc() from get_net_track(), and some of get_net_track()
>   users are passing GFP_ATOMIC because waking kswapd/kcompactd is safe.
>   But even if we mask __GFP_KSWAPD_RECLAIM flag at __stack_depot_save(),
>   it is very likely that allocations with __GFP_KSWAPD_RECLAIM flag happe=
n
>   somewhere else by the moment __stack_depot_save() is called for the nex=
t
>   time.
>
>   Therefore, not waking kswapd/kcompactd when doing allocation for
>   __stack_depot_save() will be acceptable from the memory reclaim latency
>   perspective.

Ack.

> While we are at it, let's make __stack_depot_save() accept __GFP_NORETRY
> and __GFP_RETRY_MAYFAIL flags, based on the following reason.

Looks like you're accepting a whole bunch of flags in addition to
__GFP_NORETRY and __GFP_RETRY_MAYFAIL - maybe list the two explicitly?

> Reason 3:
>
>   Since DEPOT_POOL_ORDER is defined as 2, we must mask __GFP_NOFAIL flag
>   in order not to complain rmqueue(). But masking __GFP_NORETRY flag and
>   __GFP_RETRY_MAYFAIL flag might be overkill.
>
>   The OOM killer might be needlessly invoked due to order-2 allocation if
>   GFP_KERNEL is supplied by the caller, despite the caller might have
>   passed GFP_KERNEL for doing order-0 allocation.

As you noted above, stackdepot is a debug feature anyway, so invoking
OOM killer because there is no memory for an order-2 allocation might
be an acceptable behavior?

>   Allocation for order-2 might stall if GFP_NOFS or GFP_NOIO is supplied
>   by the caller, despite the caller might have passed GFP_NOFS or GFP_NOI=
O
>   for doing order-0 allocation.

What if the caller passed GFP_NOFS to avoid calling back into FS, and
discarding that flag would result in a recursion?
Same for GFP_NOIO.

>   Generally speaking, I feel that doing order-2 allocation from
>   __stack_depot_save() with gfp flags supplied by the caller is an
>   unexpected behavior for the callers. We might want to use only order-0
>   allocation, and/or stop using gfp flags supplied by the caller...

Right now stackdepot allows the following list of flags: __GFP_HIGH,
__GFP_KSWAPD_RECLAIM, __GFP_DIRECT_RECLAIM, __GFP_IO, __GFP_FS.
We could restrict it further to __GFP_HIGH | __GFP_DIRECT_RECLAIM to
be on the safe side - plus allow __GFP_NORETRY and
__GFP_RETRY_MAYFAIL.



> Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.co=
m>
> Closes: https://syzkaller.appspot.com/bug?extid=3Dece2915262061d6e0ac1
> Suggested-by: Alexander Potapenko <glider@google.com>
> Cc: Huang, Ying <ying.huang@intel.com>
> Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
> ---
> Changes in v3:
>   Huang, Ying thinks that masking __GFP_KSWAPD_RECLAIM flag in the caller=
s
>   side is preferable
>   ( https://lkml.kernel.org/r/87fs7nyhs3.fsf@yhuang6-desk2.ccr.corp.intel=
.com ).
>   But Alexander Potapenko thinks that masking __GFP_KSWAPD_RECLAIM flag
>   in the callee side would be the better
>   ( https://lkml.kernel.org/r/CAG_fn=3DUTTbkGeOX0teGcNOeobtgV=3DmfGOefZpV=
-NTN4Ouus7xA@mail.gmail.com ).
>   I took Alexander's suggestion, and added reasoning for masking
>   __GFP_KSWAPD_RECLAIM flag in the callee side.
>
> Changes in v2:
>   Mask __GFP_KSWAPD_RECLAIM flag in the callers, suggested by Huang, Ying
>   ( https://lkml.kernel.org/r/87edn92jvz.fsf@yhuang6-desk2.ccr.corp.intel=
.com ).
>
>  lib/stackdepot.c | 5 ++++-
>  1 file changed, 4 insertions(+), 1 deletion(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 2f5aa851834e..33ebefaa7074 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -405,7 +405,10 @@ depot_stack_handle_t __stack_depot_save(unsigned lon=
g *entries,
>                  * contexts and I/O.
>                  */
>                 alloc_flags &=3D ~GFP_ZONEMASK;
> -               alloc_flags &=3D (GFP_ATOMIC | GFP_KERNEL);
> +               if (!(alloc_flags & __GFP_DIRECT_RECLAIM))
> +                       alloc_flags &=3D __GFP_HIGH;
> +               else
> +                       alloc_flags &=3D ~__GFP_NOFAIL;
>                 alloc_flags |=3D __GFP_NOWARN;
>                 page =3D alloc_pages(alloc_flags, DEPOT_POOL_ORDER);
>                 if (page)
> --
> 2.18.4
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXBBVBj9VcFkirMNj9sQOHvx2Q12o9esDkgPB0BP33DKg%40mail.gmai=
l.com.
