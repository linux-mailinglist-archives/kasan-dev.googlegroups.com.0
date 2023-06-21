Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7EYZSSAMGQEXRRLM3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD7AA73875F
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 16:43:09 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6237c937691sf50592736d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 07:43:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687358588; cv=pass;
        d=google.com; s=arc-20160816;
        b=pxsOYuuXtVpsrrnYdUrHZyXRfcbtI8/x6GOBQej3flNTRb7kZwGBUUnznLp/RhSrHQ
         na4yFu5MIV9T5GC/nGzSBnBNHcNrHB1AxOqNi3TmFVx4bfMEVQnZywCtq9/E6uBU/o0V
         R5F62ZZS5tVRKhCIGOold0JZYcUvGEZfNXIE2S6uRXj7Wzu5o5sqELQ0gGGNHRW6yv1q
         buivKbwFiQSS4Xfbd/398aRdwMeOiEYoS/OKwFJx7GNSMI97BvelvlA+LXkdSJn7zgHz
         gHeF6dDK5rJ6y8O5gs0/ptKXe1/QHtGdSrf1cmG7nLGl4/hACKwVOoVTX7O7mY1epmOk
         VgKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UYG9775lFIDnEw1GHz1BfSSEw+Pwzoo380l6npR4C0A=;
        b=T54aWu9qNgihqaQp91orhQfdl2wARHQQOc+ukqbZKItXpoCfpKydC1ynK6LZ0snPuL
         E7TnZveK+luBMEa38cMf4CO3dFArwzFR1E7RBZJ198gziQm33o5kGyWpPLpuKX8zGPE3
         zOWvy3jh/V1q0XXD0k8FKIWBqmtRACo4Ae0nHPajbpWwSwnvqFSsY7kfhPD/aTQJpbp1
         wSI4dlE0gOZ2/3uv44EV0cl8quxtpmhpOIFtZ0rHozoPByzQ7icoxZOHSdhJJsJrURUs
         ZHnoKn8cEhkzXfbnZoOf1XYX+mcFZt2CO35xzXt4KYeghbL5nRv83U94cZTgdXSFWgcp
         /d7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=jtApsSkZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687358588; x=1689950588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UYG9775lFIDnEw1GHz1BfSSEw+Pwzoo380l6npR4C0A=;
        b=gwa0gAeVzbOkP7XMXyWJhA7a40trVcmUSIL9bSpNK7XIgPibZWX6ZYZgUGtzY/5e27
         YOkMSSfpZMA8ceE1e+FC0WbhtWD3Hf4HNcHz1h54jEL3mftSBV2am8+P5B63AGO41sfE
         LMoKIQ7IZCZwgm7699djAoP5si2pY7mRGSUHOgU1SUnEgejbR6t2t11uDVNYGtOws5NL
         jCsaVA0PDA4VqWdz4mO86A0y252NAl9EOg2Yh9G6ocqJ1TfOXzwBRrFQmtGXucKJmLfJ
         fk44rD6QHIc3oLeuGOfHttCyOit9G8S9AxDWAJDGC94FdnZgnrGU9ODN6bo1CajTT32c
         0ZJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687358588; x=1689950588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UYG9775lFIDnEw1GHz1BfSSEw+Pwzoo380l6npR4C0A=;
        b=ZMzg/2rpDlD0bhpuPbcOKEW5Iw3UKA7IiSuqw1YdCPBShZGph2HcoJtxDha525tFFF
         XPXPC4tRdLyTnnQua5WfbrdJbXJRmL3uWc8lVcm+3eJuuRtYEwfKhuud5oqPUzl5Crp3
         +E2jPGRJ78jHDnEoRNYsvv7KBB3yZ7qX647OjRdB0cV9kptRWAX+tWEWaCJrhbLUC1KE
         DfBMW1dpbGeZcFwWmf5cVsL7hTiCHNhQgpwC2RhJF9D6BCZWqmh11d70qq8XD2pHXlpM
         b0yFYYDekZZ5q2S3KpmAVQi3r9fzluLXgaU1cSmj4clOJNSYNCQnDvAwEmCcKr545+Ju
         VVSQ==
X-Gm-Message-State: AC+VfDxnoP38WNi8tOGJTrOej7UcThf80wFkHPVrai0SwG0yeKMHePGf
	2TbMx/DwbuJ9F2ocCQ5lLbc=
X-Google-Smtp-Source: ACHHUZ6iZBoS3DJ17RUNI1qpuNM152qP03JyIV4ZWJgkeysTQdyPUsT0PD1KGuqmrRvUV4Ko4BbvTw==
X-Received: by 2002:a05:6214:c64:b0:62d:ed86:154b with SMTP id t4-20020a0562140c6400b0062ded86154bmr14041510qvj.5.1687358588579;
        Wed, 21 Jun 2023 07:43:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5912:0:b0:62d:ed98:f6ba with SMTP id ez18-20020ad45912000000b0062ded98f6bals618035qvb.1.-pod-prod-00-us;
 Wed, 21 Jun 2023 07:43:08 -0700 (PDT)
X-Received: by 2002:a05:6102:1516:b0:43f:34a0:cc92 with SMTP id f22-20020a056102151600b0043f34a0cc92mr4193699vsv.1.1687358587911;
        Wed, 21 Jun 2023 07:43:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687358587; cv=none;
        d=google.com; s=arc-20160816;
        b=fbP7K+h+p2Dufx48ahvqNqRl/HByIb5CIcNGcf+tdNJnLpUDp3mVpI7jUz/ToOT0LT
         0Vc4P3CsobGIGbxJL2FKnJa7AuVynqmn/xkhnlBAn5gnHPPwSA5Rb5g6fRFFDpluqvRX
         iZnBvnx7WOfZXOnhTB/smMty6gbjQgrNdEcgpXeFvkIeHOdoEh1bJYlAQlUSIR9Ip+u+
         NVplRQK+OCIloKX1jhgO0G9UYyiFANTyljSABGFCzPGEXgcDW5dFV1epJodomMkaUjR8
         80tT/GvMhnvT8YQ7mfYEKIMuCfiUXHpf8CCB5aY5wqHcOd7919KhUW2dAAgQ/vESU7ob
         cddw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YUu7+2/X84Xh+mwVKsmAtu1KtwVmCcdcD5w3fkw4k3M=;
        b=JxUnWwvJRjylfmEN9btOkkaljOIZZDVmcR/l1bI4qOB+2BHK80xLEgRSPXq668wnYr
         XurAtYiS9u5VmeHTVzyQk2Cd6Z/ThMTnXJOZTy6LTNDAroYaIjy7N5MbI86E1LrDv7Vn
         SGwS31XX1Y5yEMHi8kh24dNKkuVdB917jdL/qoDcQbVYuQdw1ydXfY+GSP44ZUSQZu8W
         5wepzv4g+dri20NcrQDvljmQMVF4gyBFRDGWR/3Oa03WfBlWfC1ORN5KNIrnx8ag/vew
         U+es8jcXH2xfRKPEDOrqZpa8KOoUAhU8NLSt16rn9YeEqeeJ6j0pd0CK/3JIoW1NiocW
         0s6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=jtApsSkZ;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id s11-20020a056130020b00b007876a39a37dsi487492uac.0.2023.06.21.07.43.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jun 2023 07:43:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id ca18e2360f4ac-77e3f25446bso93134139f.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Jun 2023 07:43:07 -0700 (PDT)
X-Received: by 2002:a05:6602:218a:b0:77d:b45f:ee2d with SMTP id
 b10-20020a056602218a00b0077db45fee2dmr10009832iob.0.1687358587111; Wed, 21
 Jun 2023 07:43:07 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000cef3a005fc1bcc80@google.com> <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
 <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com> <CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
 <20230609153124.11905393c03660369f4f5997@linux-foundation.org>
 <19d6c965-a9cf-16a5-6537-a02823d67c0a@I-love.SAKURA.ne.jp>
 <CAG_fn=XBBVBj9VcFkirMNj9sQOHvx2Q12o9esDkgPB0BP33DKg@mail.gmail.com> <34aab39f-10c0-bb72-832b-d44a8ef96c2e@I-love.SAKURA.ne.jp>
In-Reply-To: <34aab39f-10c0-bb72-832b-d44a8ef96c2e@I-love.SAKURA.ne.jp>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jun 2023 16:42:30 +0200
Message-ID: <CAG_fn=X4qxdbfm-8vcbN2F-qr-cCPBG+1884Hnw5CXL4OgRT8Q@mail.gmail.com>
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
 header.i=@google.com header.s=20221208 header.b=jtApsSkZ;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as
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

On Wed, Jun 21, 2023 at 4:07=E2=80=AFPM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2023/06/21 21:56, Alexander Potapenko wrote:
> >> But why is __stack_depot_save()
> >>   trying to mask gfp flags supplied by the caller?
> >>
> >>   I guess that __stack_depot_save() tried to be as robust as possible.=
 But
> >>   __stack_depot_save() is a debugging function where all callers have =
to
> >>   be able to survive allocation failures.
> >
> > This, but also the allocation should not deadlock.
> > E.g. KMSAN can call __stack_depot_save() from almost any function in
> > the kernel, so we'd better avoid heavyweight memory reclaiming,
> > because that in turn may call __stack_depot_save() again.
>
> Then, isn't "[PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from
> kasan/kmsan" the better fix?

Perhaps you are right and I shouldn't have insisted on pushing this
flag down to stackdepot.
If other users (e.g. page_owner) can afford invoking kswapd, then we
are good to go, and new compiler-based tools can use the same flags
KASAN and KMSAN do.


>
> >>   Allocation for order-2 might stall if GFP_NOFS or GFP_NOIO is suppli=
ed
> >>   by the caller, despite the caller might have passed GFP_NOFS or GFP_=
NOIO
> >>   for doing order-0 allocation.
> >
> > What if the caller passed GFP_NOFS to avoid calling back into FS, and
> > discarding that flag would result in a recursion?
> > Same for GFP_NOIO.
>
> Excuse me, but "alloc_flags &=3D ~__GFP_NOFAIL;" will not discard flags i=
n
> GFP_NOFS / GFP_NOIO ?

But not for the other if-clause?
Anyway, I actually confused GFP_NOIO (which is technically
__GFP_RECLAIM) and GFP_NOFS with __GFP_IO/__GFP_FS, thinking that
there's a separate pair of GFP flags opposite to __GFP_IO and
__GFP_FS.
Please disregard.

>
>
> >>   Generally speaking, I feel that doing order-2 allocation from
> >>   __stack_depot_save() with gfp flags supplied by the caller is an
> >>   unexpected behavior for the callers. We might want to use only order=
-0
> >>   allocation, and/or stop using gfp flags supplied by the caller...
> >
> > Right now stackdepot allows the following list of flags: __GFP_HIGH,
> > __GFP_KSWAPD_RECLAIM, __GFP_DIRECT_RECLAIM, __GFP_IO, __GFP_FS.
> > We could restrict it further to __GFP_HIGH | __GFP_DIRECT_RECLAIM to
> > be on the safe side - plus allow __GFP_NORETRY and
> > __GFP_RETRY_MAYFAIL.
>
> I feel that making such change is killing more than needed; there is
> no need to discard __GFP_KSWAPD_RECLAIM when GFP_KERNEL is given.
>
> "[PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from kasan/kmsan"
> looks the better.
>

I agree, let's go for it.
Sorry for the trouble.

--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX4qxdbfm-8vcbN2F-qr-cCPBG%2B1884Hnw5CXL4OgRT8Q%40mail.gm=
ail.com.
