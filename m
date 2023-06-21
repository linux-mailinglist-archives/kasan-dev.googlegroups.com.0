Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2FSZSSAMGQEECI2WDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id AB1727389AC
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 17:38:17 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1a6ba8c60b9sf4956158fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jun 2023 08:38:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1687361896; cv=pass;
        d=google.com; s=arc-20160816;
        b=N0eoIQg3JuO2smhCLTarByFEnCsKiOIOd7/jJiTYNyy1p96HUCfBuIbp3h4yR8Yxp7
         E6Tw5PPGs8OgF017tVnVq6/Ml9slrfFwY7NmGDabz5J/gWMaTRAZrWPsVTq9izSMRGZZ
         +Bx6i0UisxY2ZytjmBgJYEUuD8ygIOkveWnivPxKjIyzsM9yRaJPTY1s94LdFT8cdcua
         NhZ6rbxdFrEN0EHSSKqjkRx6s7xnzzJQJamdhtSqdKDpVLbYxf+ffLEtDIbY/12jnds1
         S/8VF9/om3FSmvcOzoqcwg5bzxEOotRQ6R0nTdBsYtINzT74Cu7OScFFUYQXEwOrOcD5
         h9Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ayKl0VT31yUv0bCV5LwwQf6DcJiN5LOQsKDJpreyeSo=;
        b=l319UxLr1mtByluL2bCBw/TBa0Lvx1q0eRSjatUOafghKOnluudL5Ta7hkpI9Az/KB
         zHxQ6qdtdQ4jwxJmPpL5UKqInKWabup7NqW0xtEEjaYI5u+bn3Et1dHkufcAlsuMumZS
         Bolz/qjj15llhBGOYBZTEVofGicstj0JBH4WU4oRHBC4NUZT9M8b4LzztGJL9B7f1Iiq
         zXVhOmknIimrjpkY9ouGGudP/4YKNjgRcnyz6GPAvhFtKSDRwFA9mBEiybIMClzIV9OB
         FIcG2bwYTCp+RX9GuQDq60gv4kzlImLDGSXYNQXPtZ0hRUOl03Xivzt098aVRuSkd5XW
         cE4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=NlxpJTc9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1687361896; x=1689953896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ayKl0VT31yUv0bCV5LwwQf6DcJiN5LOQsKDJpreyeSo=;
        b=Zk1tnAExLcxFc6f4jDziFOJxfwpvWP26x+XOAekN5jfQZPAjYs3uHDK9NPMrYavlNr
         /+3q29Qt6vujRYMN2JcuZKidEZ6DiWnzvYMlLg/2edTU8iC8aRXPDLBNdB/sgLJH8jCK
         YKQ26/tbuTBu/+JPhOM8RyYsN6MmhMK3o2x0DpVRCLuYa7ICZq9cjxqLwpkLd+LZvhIw
         8H1hj4pVWagdBicyT616HzAmVy5z4WlmhNosIqMgsqxhTqLQXEPMCOT66uYml8l0hCUQ
         1fhZJPP1SlyA25W/G7W8WcOZBu+VJ3K79m7GiUeVronP9GbhJND84nJ7UO3Mrvy7FhcN
         3Kvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1687361896; x=1689953896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ayKl0VT31yUv0bCV5LwwQf6DcJiN5LOQsKDJpreyeSo=;
        b=CP/h4hg/zcgqv70fIM3/oUmzgVniA8VsuouY/YnufbRuEsCxu/kajhCvvvERja9l8q
         CxSTvtZvYl3oyZAimO1SPjzK2sxrd29iUETccgyx0YB+NyfpYbsIw3Ilk+3+5Ouk2ctD
         yTD076z6IhM1I7shkNot1tXXq/ZqjoyuD2hkwbcQg0tEUKt8ehfplrEamuNYSXU9ZkzY
         RooiPXfpy0RVjbfIlDwKmcH/heJeDUhbSrCGXiX8Kaehzkq8gh1j7NI/XwDZeXd1DXtT
         B7Jh6yWCG8pisgDJWXBrpRdM19QB9eb/acbD6iADAHMkxkrp3nq2Px5ysnzTg6g53mUh
         CCdQ==
X-Gm-Message-State: AC+VfDy1JkK23LvfmK/zds4y8xV8y3kEmMw2+EjhPA3bGfgsCrc+8d8L
	c9xxGB9yweRoWNoB9sSmXB4=
X-Google-Smtp-Source: ACHHUZ4vVCYorShMQX9vYRu8XXEg45Q5WEr0UYiKpt0D/QguQIgjXK3/tcmK1NlIIkg0D83PmURH/A==
X-Received: by 2002:a05:6870:9d9c:b0:1a6:614c:aa00 with SMTP id pv28-20020a0568709d9c00b001a6614caa00mr14315518oab.47.1687361896173;
        Wed, 21 Jun 2023 08:38:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:1f05:b0:19a:71fb:1d9b with SMTP id
 pd5-20020a0568701f0500b0019a71fb1d9bls1688727oab.0.-pod-prod-01-us; Wed, 21
 Jun 2023 08:38:15 -0700 (PDT)
X-Received: by 2002:a05:6870:d897:b0:1a6:d702:f03e with SMTP id dv23-20020a056870d89700b001a6d702f03emr12229660oab.1.1687361895750;
        Wed, 21 Jun 2023 08:38:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1687361895; cv=none;
        d=google.com; s=arc-20160816;
        b=ak2uqB9D5bot9redjJFdc9OuHZqptokXSU3+YwfwO2ya3D5RibYh2syaqNO4GBgTBa
         84Omem4pqvFJm1QoBmUyJ5ScwadRsq6i+R3chOsH+KBM1nDZYm9qlczkuPn2iNaBGWWt
         mGHawTYhD/ZzDXzu0wuWBphwccP3qTZEH82+pUcYq4bFhGI0GQPcxGS3dbaP9tuAzrr9
         8ZHSB0iKbEaAhnFzPfAXdGeiH8oYJQKDqdMLaI0hqPkJJbvB9wwlWz9qvPOq7b8Ti3jy
         m7o/kIaBhV8sNvdiAG+be09ZQ7J6fIwMd7iPguvB7EKMCspDnKinTryXVrFGqiWrBm/u
         X4ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=y5kxm8AmUyv0LNgmCEGT8IbGfv7bD38A6oy8gwVbxdo=;
        b=OSjtq9CwxRyltpsWc7MvUlJEzaPuSrIWdI0cUCbhuNfs5zr2PFBe4Jb4sjrxoDyAjB
         2mcXSnVP/fXhXauenHgpXPGUN5ln+mTlEbOHzOcVUvwsa5lik83f/VrmtbZs9CEbwODC
         /B0AB4H7lPiZKI80lNOuyaL9O0cw9kkdN909Zi8L8fYyjGxWMG+jIrSnxcy6s65z3QwT
         rvM3rJd/A7ONzcR1b91DKkMcpv12ptDcxdAkuvyCQYwkPnPTe6UIAShMzsSp4oboYWXv
         vsZbQMqnZfWSdC2qLMbXIQFfn6D98e6XafHe+2THtDDAlIRDNPjpQFK6gCV0S1+lUVy9
         PYMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=NlxpJTc9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id gr14-20020a056870aa8e00b001aac095ffb3si619800oab.2.2023.06.21.08.38.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Jun 2023 08:38:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id 46e09a7af769-6b45e465d4fso4100281a34.3
        for <kasan-dev@googlegroups.com>; Wed, 21 Jun 2023 08:38:15 -0700 (PDT)
X-Received: by 2002:a5d:9404:0:b0:774:8b28:6c34 with SMTP id
 v4-20020a5d9404000000b007748b286c34mr16293533ion.8.1687361881753; Wed, 21 Jun
 2023 08:38:01 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000cef3a005fc1bcc80@google.com> <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
 <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com> <CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
 <20230609153124.11905393c03660369f4f5997@linux-foundation.org>
In-Reply-To: <20230609153124.11905393c03660369f4f5997@linux-foundation.org>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Jun 2023 17:37:09 +0200
Message-ID: <CAG_fn=W5-+3Xz2LcJW=kbbV+91U8W5MLfAFtR+eNLYXG0v=zKQ@mail.gmail.com>
Subject: Re: [PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from kasan/kmsan
To: Andrew Morton <akpm@linux-foundation.org>
Cc: "Huang, Ying" <ying.huang@intel.com>, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
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
 header.i=@google.com header.s=20221208 header.b=NlxpJTc9;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::335 as
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

On Sat, Jun 10, 2023 at 12:31=E2=80=AFAM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> On Wed, 31 May 2023 15:31:53 +0200 Alexander Potapenko <glider@google.com=
> wrote:
>
> > On Mon, May 29, 2023 at 3:08=E2=80=AFAM Huang, Ying <ying.huang@intel.c=
om> wrote:
> > >
> > > ? Handa <penguin-kernel@I-love.SAKURA.ne.jp> writes:
> > >
> > > > syzbot is reporting lockdep warning in __stack_depot_save(), for
> > > > the caller of __stack_depot_save() (i.e. __kasan_record_aux_stack()=
 in
> > > > this report) is responsible for masking __GFP_KSWAPD_RECLAIM flag i=
n
> > > > order not to wake kswapd which in turn wakes kcompactd.
> > > >
> > > > Since kasan/kmsan functions might be called with arbitrary locks he=
ld,
> > > > mask __GFP_KSWAPD_RECLAIM flag from all GFP_NOWAIT/GFP_ATOMIC alloc=
ations
> > > > in kasan/kmsan.
> > > >
> > > > Note that kmsan_save_stack_with_flags() is changed to mask both
> > > > __GFP_DIRECT_RECLAIM flag and __GFP_KSWAPD_RECLAIM flag, for
> > > > wakeup_kswapd() from wake_all_kswapds() from __alloc_pages_slowpath=
()
> > > > calls wakeup_kcompactd() if __GFP_KSWAPD_RECLAIM flag is set and
> > > > __GFP_DIRECT_RECLAIM flag is not set.
> > > >
> > > > Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotm=
ail.com>
> > > > Closes: https://syzkaller.appspot.com/bug?extid=3Dece2915262061d6e0=
ac1
> > > > Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
> > >
> > > This looks good to me.  Thanks!
> > >
> > > Reviewed-by: "Huang, Ying" <ying.huang@intel.com>
> >
> > Sorry for the late reply, but maybe it would be better to mask this
> > flag in __stack_depot_save() (lib/stackdepot.c) instead?
> > We are already masking out a number of flags there, and the problem
> > seems quite generic.
>
>
> Tetsuo?

Reviewed-by: Alexander Potapenko <glider@google.com>

Andrew, please accept this patch. As noted in the other thread, no
changes to stackdepot are needed.

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
kasan-dev/CAG_fn%3DW5-%2B3Xz2LcJW%3DkbbV%2B91U8W5MLfAFtR%2BeNLYXG0v%3DzKQ%4=
0mail.gmail.com.
