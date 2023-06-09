Return-Path: <kasan-dev+bncBCT4XGV33UIBBPWQR2SAMGQEBTK2ZVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B0E372A645
	for <lists+kasan-dev@lfdr.de>; Sat, 10 Jun 2023 00:31:28 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id 46e09a7af769-6b0f6e05ad7sf1258197a34.3
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Jun 2023 15:31:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1686349887; cv=pass;
        d=google.com; s=arc-20160816;
        b=ELWPX0c8rUHlME477cA9j5aFt91f0fk9QYXLXNmnRnWVlRGCX5PJJZjXV1KaK/df0I
         YtiZ4BUNG/F5hWtQcO5tQjBAT5JJ7qLd1ukzxEszRIV9kpcd2f/4EUoQ83p2VPLWdf0P
         l9ayWBkg5rlqhSLZCPYX6WID3FMl8KmKoVQklROPPzOiOVyIMdxw7Rj4KfKvc1dnT8L0
         KETyo9RoQeyExiJdo/MUo1Baqe3iehUIUzyPjXpKZa1/W4BrLK6sVE1jHoq/w2kenRAN
         1whaxQUXAYtBktzH5wtk6FGfcNfUHottu1nHlYvJ4tlM/3ldAHpkyv6EihufiAvJMtEM
         1xgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=iGRQRFo4TMVf603G8Vtv+rIV3k6GWjDrDZ8sCfZVZk4=;
        b=FPghuhgD6J/bcpSOT0waXMwufOsq5Fl7H58OUwUn+bd+g8VSEsge/li/qNQEqxSZQM
         eAYZo+8Z0qRvexs7xFX9/27U04D6jKKNwODHegXhl+ofmfY2vJJU6c5L7k1WWj7xTBNK
         oUMw2SemNe8kysxnjDkDNOVDd/69ntNEMK0dPWR4wGBkynD/s63EcX4RA6sGdIdKKx1U
         aJ2P9W04SrO4DQMpxgch2JTcIjuORCxMMu8k/7bBh+70EdC2ylwfOXaP9vU+FTFPiFIb
         sq3e0q72WdXd+RoijsJw7mhJTUvlmuG/MKIXmUA3nWwb3ESPrpfo/ry+lOUP8dxAzpvG
         114g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=VF3DiryE;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1686349887; x=1688941887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iGRQRFo4TMVf603G8Vtv+rIV3k6GWjDrDZ8sCfZVZk4=;
        b=rrz5X9qkDaKsS9KY7XvjMjwR5S3BIZFOKft83+GrRvo8vAhI1LuGsVHufL8pApPA2J
         9vZ6Rq3MubGm//hltgLG0UTL9PLw/mTMoyUxtXvYGFsLdst7SV5+vuoC3VoDYKmRZ+pd
         4Ji6LlrL1VOWTLmBC9+Z8yyqdiaWsT/8/gl0/5cs8YbX+AdeT5P684yxj9xmiVPg3GUY
         E3KqgAAQay/r7RZHgcHibQIi7yTiBYyzgc0pZRbntfcj0aulCcDkqd3uARl6XmusQky/
         8JqPvB9QVrFpqavQBmjned5ro3UEgYcdGfK49bgboYaviIhu9aR1X8y7Kx39MjHLx//S
         xvCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1686349887; x=1688941887;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=iGRQRFo4TMVf603G8Vtv+rIV3k6GWjDrDZ8sCfZVZk4=;
        b=hE3smPRNwKC2C/jZaU/EvVK87J3SMoM/I5ESHvaOc1cN/cDBW/JuAjFQJF7nxwpJ6x
         hsQQ3rcbkSN0oWAjiK3GGjtBSWb7EvYlYzjAOagvRzuG8ajz8/P8v4H0DOPQqQbklRpo
         iVD4DvhEHnewZK0LeevAodyrx5qgumtHy+0ZbTyf7G1157lcgg6I84ZwwBvO0wQpwVui
         uLUsnPTMmpOjr8PYKtME8OkSWxaL/DmIDkumPbm7zGAUIwlRT45advwWxZahDxE/O1Qy
         fF1wYvI7Sah3jESMhQP7V9yNm0Oe03+dDwosNk5dhY6GIZm+fRjRd/kfeM5vlkfgeTPO
         7sNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzb1k4sSdXTB7dMdamQ0x1CQC1qzErF68EHsrtATWaWz4H35gvV
	EdC8D/+st32ozyUGzYNw5mc=
X-Google-Smtp-Source: ACHHUZ5a1a0u0wPvXqSvB7EvpONFPPTnpmzfwfTYoqwt/TDtkQh7UAh/piLoAq7DqHcNpODDkMVAfw==
X-Received: by 2002:a05:6870:c808:b0:19f:4696:323a with SMTP id ee8-20020a056870c80800b0019f4696323amr2221781oab.15.1686349886877;
        Fri, 09 Jun 2023 15:31:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:f80f:b0:19f:3563:ef77 with SMTP id
 fr15-20020a056870f80f00b0019f3563ef77ls32329oab.0.-pod-prod-07-us; Fri, 09
 Jun 2023 15:31:26 -0700 (PDT)
X-Received: by 2002:a9d:7843:0:b0:6af:83cb:aa95 with SMTP id c3-20020a9d7843000000b006af83cbaa95mr2573427otm.31.1686349886236;
        Fri, 09 Jun 2023 15:31:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1686349886; cv=none;
        d=google.com; s=arc-20160816;
        b=AmoBtui87zdS1whFrRUYDSMHz24QmJkeySdV5QqwzcvIO4xhlK3jq9lsAv9DUlKyqZ
         QoJpaPpJzHnpIyzYdRU9bB991qUyVLfyHzWcLin+bnwDnDZDbpUmSg1SeeJIOrEzT9Dc
         P/WwQ5pEBaz0A1Tbh5VkmDFDZaHVkQ/GzouyArvSmL4Q7x3YK0yZM/ID6Ly/z8WJk2/G
         5QQ/wwBVusPtXwuxJX2xDolSjHJLuFLkdUB4ok6W6I9P7kbLWatOxwFvdAWGCa8lCO13
         jJTAB18PegQ2QWNT28RY3h9J1huO3Mrlgemwmi9GeMDo9PxVFq1qswePprCsyQhM3bEK
         b3Bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=l2nQuWEiehJpvaj44imNiSzpT1YQoWxdcreKRudZFxA=;
        b=XuVxhajtzSjCOBwUmYnMQOvb+Haaegut+WOncMRjCa8o5lDi2P/8xVM0v49mxdZQI1
         wyvWZIz4OrtRUStHJrgmbyivhNfrBI6ldg8L8J8y6s/YwNQHsqmNPumkeRnI65WPeCm3
         TRXQK/h7A7Y10aXBrXHrsBvIUfRyvPG/peD3pJuebEy6QJAd4FfP5+wbQgvOBBRw0wFx
         +g0c5S1ozKp6363Sxiqh98pCKYxw9S/QW61pdCcPsQ03RyImPy+Rl1yjAf8EE3ue47LE
         fxtv52nWbwECUy8ErhLvjpB+2VMXPG8L5jqzq9+NugOP/BVOiOgPKViWZnM1lx6ReVIq
         DIJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=VF3DiryE;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bq21-20020a056830389500b006a5f12c714bsi660241otb.0.2023.06.09.15.31.26
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 09 Jun 2023 15:31:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D92D46587A;
	Fri,  9 Jun 2023 22:31:25 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CFAA7C433D2;
	Fri,  9 Jun 2023 22:31:24 +0000 (UTC)
Date: Fri, 9 Jun 2023 15:31:24 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: "Huang, Ying" <ying.huang@intel.com>, Tetsuo Handa
 <penguin-kernel@i-love.sakura.ne.jp>, syzbot
 <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>,
 syzkaller-bugs@googlegroups.com, Mel Gorman <mgorman@techsingularity.net>,
 Vlastimil Babka <vbabka@suse.cz>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 linux-mm <linux-mm@kvack.org>
Subject: Re: [PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from
 kasan/kmsan
Message-Id: <20230609153124.11905393c03660369f4f5997@linux-foundation.org>
In-Reply-To: <CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
References: <000000000000cef3a005fc1bcc80@google.com>
	<ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
	<ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
	<656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp>
	<87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com>
	<CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=VF3DiryE;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 31 May 2023 15:31:53 +0200 Alexander Potapenko <glider@google.com> =
wrote:

> On Mon, May 29, 2023 at 3:08=E2=80=AFAM Huang, Ying <ying.huang@intel.com=
> wrote:
> >
> > ? Handa <penguin-kernel@I-love.SAKURA.ne.jp> writes:
> >
> > > syzbot is reporting lockdep warning in __stack_depot_save(), for
> > > the caller of __stack_depot_save() (i.e. __kasan_record_aux_stack() i=
n
> > > this report) is responsible for masking __GFP_KSWAPD_RECLAIM flag in
> > > order not to wake kswapd which in turn wakes kcompactd.
> > >
> > > Since kasan/kmsan functions might be called with arbitrary locks held=
,
> > > mask __GFP_KSWAPD_RECLAIM flag from all GFP_NOWAIT/GFP_ATOMIC allocat=
ions
> > > in kasan/kmsan.
> > >
> > > Note that kmsan_save_stack_with_flags() is changed to mask both
> > > __GFP_DIRECT_RECLAIM flag and __GFP_KSWAPD_RECLAIM flag, for
> > > wakeup_kswapd() from wake_all_kswapds() from __alloc_pages_slowpath()
> > > calls wakeup_kcompactd() if __GFP_KSWAPD_RECLAIM flag is set and
> > > __GFP_DIRECT_RECLAIM flag is not set.
> > >
> > > Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmai=
l.com>
> > > Closes: https://syzkaller.appspot.com/bug?extid=3Dece2915262061d6e0ac=
1
> > > Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
> >
> > This looks good to me.  Thanks!
> >
> > Reviewed-by: "Huang, Ying" <ying.huang@intel.com>
>=20
> Sorry for the late reply, but maybe it would be better to mask this
> flag in __stack_depot_save() (lib/stackdepot.c) instead?
> We are already masking out a number of flags there, and the problem
> seems quite generic.


Tetsuo?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20230609153124.11905393c03660369f4f5997%40linux-foundation.org.
