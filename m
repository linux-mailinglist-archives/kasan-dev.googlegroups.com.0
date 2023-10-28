Return-Path: <kasan-dev+bncBCLL3W4IUEDRBL4G6WUQMGQET6U4FPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 739007DA835
	for <lists+kasan-dev@lfdr.de>; Sat, 28 Oct 2023 19:21:53 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id ffacd0b85a97d-32de39ce109sf1762825f8f.0
        for <lists+kasan-dev@lfdr.de>; Sat, 28 Oct 2023 10:21:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698513713; cv=pass;
        d=google.com; s=arc-20160816;
        b=JC9/aGwDxMMXHfnX9e9hnfXn470IDzM4vj0rnZ23jCfe07BEWw9AybOkqMZmpuOvvL
         8rbwBjRmPDnTWNxGg5/2ksgK1Hx2oR26nQOKUqhLVOW6NZe7LP5KmlT9Vi5xn+xgD13G
         SagG5tltvfru2//vz3qujiAwaJ9O8+00PTOPKrUkX8QdWo5WcYZ8GxlcjA0nYGUQFIUw
         vaT6p/slhxAt7wqxKi8s9J3PExVpj+c9L5RoiN5Ych+KlbLFIs4k7s3tgwj6M44M+a7g
         r7wsKEt/ZoRnFN8nDc7CftOaPvjCtBkEMPK67GqeI1OfshkdRTdLjVlW4EmzsJvF+65a
         wHfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=ilrPGDDyQLt+gVInbUolz0MBRKMivA8FHj9aunNY8ro=;
        fh=lZZODSKDUlWrUwe2E2s9ctvJbSS3jEvDc6Z5IxtDLXM=;
        b=fiHK61oWnbw1Jzb87bLJJhVs5qY0sXBPb0tc4QbBXt7ymN3X36R9CM7EPsshgcxWYJ
         jlCUQ23vtoKCyli1EMc/NOITVtkNSQuwW0IJM0Qejby1WgnMSrqz6pgiqvqt7SEIi9U3
         awjK2CG+k+nBpraoi89Fm+jfUcsjBa/CkcxEoQzPtV50FTPPN1idMtr8nPcO77fblVhP
         dZcwbVkPqxzlVmOo+jz0uMrOW79Xt2O556Srp9hbAmYOjaUpx1hFsFQDtv+yohHygd+i
         efyv5ZmXAjeXg2iE30HMXsUB6vMGqx2SlVSCOMsJDjoROliobzesC23X3B/IL+cAjdJH
         nhFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=NEf36SYo;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698513713; x=1699118513; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ilrPGDDyQLt+gVInbUolz0MBRKMivA8FHj9aunNY8ro=;
        b=e4AlfQscomN8TTFZiQqlRsR0SbcyLxmgZNKVA9YmOFskRTZuV7It+9it7pHkSf4z0x
         LsAGePCAqxJo4sIQ91skC3lq+PCOr448RdHQ7g8hqeymTtYorEwL/BTmAm18516CQN3T
         RH8QMzSTzHHzA1GaNY6+F5WcelpTTyim9O/chXcrK1wg40IdODiAKbZUde2MRMGYGJ8p
         TtNNfMsFRK5zjfvxzTJ4+5I4n7Q2zPNqtgUot85LCQsWj2DhEpIB1Wk7oO+1Lh06ktX8
         INFA9wYtTOKGG5D3YmAvnn4G5Ojp3qF7DVDzyV4UOG9/RH8+b7wrqPSyT2AIT6iB0TnR
         kYIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698513713; x=1699118513;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ilrPGDDyQLt+gVInbUolz0MBRKMivA8FHj9aunNY8ro=;
        b=EGjdUpgvuFqp4OQY2jdceSSZHG9JQadd6CoeTA1Ko1IO9ZrlacvHS+iLiAkjpvqLYZ
         43ics97mHj/iyKn8REJ+h2/Z3Rk+mQpvP8a+3JzGqOKJCLsA9R0X32wWFgdDVdijT0S3
         JiqDHhAUaeNwrgkPhweS0YyqecFq/byBEYxpZcQ76x8rMgvL7i/jdfW09jWrojdhg5sM
         PJjAC7u+8BtdGOVONC/fmlYc7pHdDxrP5nAgzbi8iZHHW4aADntsJbpVKilq076KFjZu
         KlApmVPlXOkyjs0m0FIJBJkhBY1e60v+Usa2SYCWUSdv7zBgZCjoMoVd7eutl/i98RCA
         vR5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YzAWcNs3bDjwhnCQlCM/+XmWWx0ShH5O8NBIN903hyHgEHYHEs3
	ZqfNx48dRE1iLmlqT0Qoh5s=
X-Google-Smtp-Source: AGHT+IFvL8m6w//2BzniBawLrGEVgyrUaZx4WYovQk1oHNSxx5MvC0tJykbXI++FcBETbstQv3PLfg==
X-Received: by 2002:a05:6000:1864:b0:32f:7c4d:8746 with SMTP id d4-20020a056000186400b0032f7c4d8746mr1800389wri.12.1698513711839;
        Sat, 28 Oct 2023 10:21:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5846:0:b0:31f:edbf:7fa with SMTP id i6-20020a5d5846000000b0031fedbf07fals857971wrf.2.-pod-prod-05-eu;
 Sat, 28 Oct 2023 10:21:50 -0700 (PDT)
X-Received: by 2002:adf:f910:0:b0:323:15d7:900e with SMTP id b16-20020adff910000000b0032315d7900emr3615401wrr.53.1698513710229;
        Sat, 28 Oct 2023 10:21:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698513710; cv=none;
        d=google.com; s=arc-20160816;
        b=v3MrrsstrekqN5PVimwaNHwt7VeqCgrqGlNU7peuTAkGMKSxWs0XSucdC6aNi3uwYx
         dZeyD1K7iYUFjTTqKlfWgAvl+6YFMxS7thIhCXu+QfesdG15qQmqcNykswTIo1oRFqhx
         l05hEQxh2ffcKxEyVhZTi55FL/gr0u/SDS+kDxxEWiX/nGSWmjoVELKQRn73EHcyqB1r
         xyurCsZpapm1KJjj9tBO+hYD1VHNg2AL3YwGSP8cikpat5j3fzlx4+i84uTJIMg8DkRI
         kQPS3WqJZAueJis/lSSmRP5u6MZQhYYI17O5VOqwQBsg6ZUrQibvvAUkteZDvXzTNgKl
         glZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=u+JLg2QmPDcViOqS6qLOyCWZFP03tmRHrfLCBCa+RxY=;
        fh=lZZODSKDUlWrUwe2E2s9ctvJbSS3jEvDc6Z5IxtDLXM=;
        b=NkmPEwhKEx0+XNfbDRzPJ8FnSfZf2xfOXKr5M5QxmMF6GyDfHnST6EoEvlZAbardSi
         1yjkS30uelado4MbNQGjqaVWvN7hBHogGOUUSkuPTfBGLJIRjKsQ924MWypGz04uq5GV
         dOtam9Z7qZVA9DL1OYzm9YY7hqO3Fy2dbASUWAVBqFewwXiY4D6rZZrgm7aZOgBavKON
         k1npqXtnzqXTHgKmIjU6IuH9s9xdhgpoRPhtXNP/+MIXcwlcTTkn81H68msx7cQQ7lyu
         ViKf2OwMRBseQooioB+gpX+SWB1TtEiwniU0cmb5iAovwpB4NMeayzVprQ3v+Spmagb4
         Lwtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tesarici.cz header.s=mail header.b=NEf36SYo;
       spf=pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) smtp.mailfrom=petr@tesarici.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tesarici.cz
Received: from bee.tesarici.cz (bee.tesarici.cz. [2a03:3b40:fe:2d4::1])
        by gmr-mx.google.com with ESMTPS id m3-20020a056000180300b0032d8f0b5663si244260wrh.7.2023.10.28.10.21.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 28 Oct 2023 10:21:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as permitted sender) client-ip=2a03:3b40:fe:2d4::1;
Received: from meshulam.tesarici.cz (dynamic-2a00-1028-83b8-1e7a-4427-cc85-6706-c595.ipv6.o2.cz [IPv6:2a00:1028:83b8:1e7a:4427:cc85:6706:c595])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by bee.tesarici.cz (Postfix) with ESMTPSA id 1794B183AEA;
	Sat, 28 Oct 2023 19:21:48 +0200 (CEST)
Date: Sat, 28 Oct 2023 19:21:47 +0200
From: Petr =?UTF-8?B?VGVzYcWZw61r?= <petr@tesarici.cz>
To: Suren Baghdasaryan <surenb@google.com>
Cc: Neil Brown <neilb@suse.de>, akpm@linux-foundation.org,
 kent.overstreet@linux.dev, mhocko@suse.com, vbabka@suse.cz,
 hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de,
 dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com,
 corbet@lwn.net, void@manifault.com, peterz@infradead.org,
 juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com,
 will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com,
 dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com,
 david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org,
 nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev,
 rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com,
 yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com,
 hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org,
 ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org,
 ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org,
 dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com,
 bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org,
 iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com,
 elver@google.com, dvyukov@google.com, shakeelb@google.com,
 songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com,
 minchan@google.com, kaleshsingh@google.com, kernel-team@android.com,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 iommu@lists.linux.dev, linux-arch@vger.kernel.org,
 linux-fsdevel@vger.kernel.org, linux-mm@kvack.org,
 linux-modules@vger.kernel.org, kasan-dev@googlegroups.com,
 cgroups@vger.kernel.org
Subject: Re: [PATCH v2 06/39] mm: enumerate all gfp flags
Message-ID: <20231028192147.2a755c46@meshulam.tesarici.cz>
In-Reply-To: <CAJuCfpHS1JTRU69zFDAJjmMYR3K5TAS9+AsA3oYLs2LCs5aTBw@mail.gmail.com>
References: <20231024134637.3120277-1-surenb@google.com>
	<20231024134637.3120277-7-surenb@google.com>
	<20231025074652.44bc0eb4@meshulam.tesarici.cz>
	<CAJuCfpHS1JTRU69zFDAJjmMYR3K5TAS9+AsA3oYLs2LCs5aTBw@mail.gmail.com>
X-Mailer: Claws Mail 4.1.1 (GTK 3.24.38; x86_64-suse-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: petr@tesarici.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tesarici.cz header.s=mail header.b=NEf36SYo;       spf=pass
 (google.com: domain of petr@tesarici.cz designates 2a03:3b40:fe:2d4::1 as
 permitted sender) smtp.mailfrom=petr@tesarici.cz;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=tesarici.cz
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

On Wed, 25 Oct 2023 08:28:32 -0700
Suren Baghdasaryan <surenb@google.com> wrote:

> On Tue, Oct 24, 2023 at 10:47=E2=80=AFPM Petr Tesa=C5=99=C3=ADk <petr@tes=
arici.cz> wrote:
> >
> > On Tue, 24 Oct 2023 06:46:03 -0700
> > Suren Baghdasaryan <surenb@google.com> wrote:
> > =20
> > > Introduce GFP bits enumeration to let compiler track the number of us=
ed
> > > bits (which depends on the config options) instead of hardcoding them=
.
> > > That simplifies __GFP_BITS_SHIFT calculation.
> > > Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > ---
> > >  include/linux/gfp_types.h | 90 +++++++++++++++++++++++++++----------=
--
> > >  1 file changed, 62 insertions(+), 28 deletions(-)
> > >
> > > diff --git a/include/linux/gfp_types.h b/include/linux/gfp_types.h
> > > index 6583a58670c5..3fbe624763d9 100644
> > > --- a/include/linux/gfp_types.h
> > > +++ b/include/linux/gfp_types.h
> > > @@ -21,44 +21,78 @@ typedef unsigned int __bitwise gfp_t;
> > >   * include/trace/events/mmflags.h and tools/perf/builtin-kmem.c
> > >   */
> > >
> > > +enum {
> > > +     ___GFP_DMA_BIT,
> > > +     ___GFP_HIGHMEM_BIT,
> > > +     ___GFP_DMA32_BIT,
> > > +     ___GFP_MOVABLE_BIT,
> > > +     ___GFP_RECLAIMABLE_BIT,
> > > +     ___GFP_HIGH_BIT,
> > > +     ___GFP_IO_BIT,
> > > +     ___GFP_FS_BIT,
> > > +     ___GFP_ZERO_BIT,
> > > +     ___GFP_UNUSED_BIT,      /* 0x200u unused */
> > > +     ___GFP_DIRECT_RECLAIM_BIT,
> > > +     ___GFP_KSWAPD_RECLAIM_BIT,
> > > +     ___GFP_WRITE_BIT,
> > > +     ___GFP_NOWARN_BIT,
> > > +     ___GFP_RETRY_MAYFAIL_BIT,
> > > +     ___GFP_NOFAIL_BIT,
> > > +     ___GFP_NORETRY_BIT,
> > > +     ___GFP_MEMALLOC_BIT,
> > > +     ___GFP_COMP_BIT,
> > > +     ___GFP_NOMEMALLOC_BIT,
> > > +     ___GFP_HARDWALL_BIT,
> > > +     ___GFP_THISNODE_BIT,
> > > +     ___GFP_ACCOUNT_BIT,
> > > +     ___GFP_ZEROTAGS_BIT,
> > > +#ifdef CONFIG_KASAN_HW_TAGS
> > > +     ___GFP_SKIP_ZERO_BIT,
> > > +     ___GFP_SKIP_KASAN_BIT,
> > > +#endif
> > > +#ifdef CONFIG_LOCKDEP
> > > +     ___GFP_NOLOCKDEP_BIT,
> > > +#endif
> > > +     ___GFP_LAST_BIT
> > > +};
> > > +
> > >  /* Plain integer GFP bitmasks. Do not use this directly. */
> > > -#define ___GFP_DMA           0x01u
> > > -#define ___GFP_HIGHMEM               0x02u
> > > -#define ___GFP_DMA32         0x04u
> > > -#define ___GFP_MOVABLE               0x08u
> > > -#define ___GFP_RECLAIMABLE   0x10u
> > > -#define ___GFP_HIGH          0x20u
> > > -#define ___GFP_IO            0x40u
> > > -#define ___GFP_FS            0x80u
> > > -#define ___GFP_ZERO          0x100u
> > > +#define ___GFP_DMA           BIT(___GFP_DMA_BIT)
> > > +#define ___GFP_HIGHMEM               BIT(___GFP_HIGHMEM_BIT)
> > > +#define ___GFP_DMA32         BIT(___GFP_DMA32_BIT)
> > > +#define ___GFP_MOVABLE               BIT(___GFP_MOVABLE_BIT)
> > > +#define ___GFP_RECLAIMABLE   BIT(___GFP_RECLAIMABLE_BIT)
> > > +#define ___GFP_HIGH          BIT(___GFP_HIGH_BIT)
> > > +#define ___GFP_IO            BIT(___GFP_IO_BIT)
> > > +#define ___GFP_FS            BIT(___GFP_FS_BIT)
> > > +#define ___GFP_ZERO          BIT(___GFP_ZERO_BIT)
> > >  /* 0x200u unused */ =20
> >
> > This comment can be also removed here, because it is already stated
> > above with the definition of ___GFP_UNUSED_BIT. =20
>=20
> Ack.
>=20
> >
> > Then again, I think that the GFP bits have never been compacted after
> > Neil Brown removed __GFP_ATOMIC with commit 2973d8229b78 simply because
> > that would mean changing definitions of all subsequent GFP flags. FWIW
> > I am not aware of any code that would depend on the numeric value of
> > ___GFP_* macros, so this patch seems like a good opportunity to change
> > the numbering and get rid of this unused 0x200u altogether.
> >
> > @Neil: I have added you to the conversation in case you want to correct
> > my understanding of the unused bit. =20
>=20
> Hmm. I would prefer to do that in a separate patch even though it
> would be a one-line change. Seems safer to me in case something goes
> wrong and we have to bisect and revert it. If that sounds ok I'll post
> that in the next version.

You're right. If something does go wrong, it will be easier to fix if
the removal of the unused bit is in a commit of its own.

Petr T

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20231028192147.2a755c46%40meshulam.tesarici.cz.
