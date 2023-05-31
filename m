Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4EY3WRQMGQEW45HCFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 229C67181EC
	for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 15:32:34 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-4f4c62e0c9esf3563565e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 31 May 2023 06:32:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685539953; cv=pass;
        d=google.com; s=arc-20160816;
        b=CzgLJJ7g6MwdCLCt4CUvIca7HvAPBCVilFtGpj04jxvjwsYuvOR+BV8512fdbrRerm
         fntqCilKIa9gPPQssWlKCXMrZ/uk3vd0bV35t0FNlPId9tLrvKc9JMGgHT+Nhjf3aku5
         UlIBsRX2NK1mRnX0OvjGH4xQ50MdeUlbpEzvHzO4HUfD7SOvCg4mVDi25WE8NQu/1Dh6
         MRt10QtmgQG69Gnj2Uw+NgyHNbHLNn3D19/OUPSy3mKHjMPe/JTy5UzuUAYnjS5NiFdK
         kD6mJDhNsBM70+lrflGGeEtYM7TEayiJBdiWm96SXjKg1MYLdHH/crR7vfteGO3F4adN
         GvwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nUpVU0I+W3NhY58ygn3Q+qbhnrQ2MeRFFbrE5mvXNPo=;
        b=kGrahKbOKOphRKSjFMKHLzkJXXra/DjWlSsGtU9NMbRfMBTDr3xmq/QgUBU0FUVo6V
         X7p/nrXDKV0O4dfv5UZg5q6CoMKsBickjyXbHlpq9Wr780JRSSVa9BkY8mt7E4GVGuWu
         AeV1OXnVglBpsWcGMuRJv5+SUBx1/y77fhJNW9q7hbfVm8z0AgCyJ6SqCEcOmyJYJ4EM
         G4bLDVrbz9aRLw6LLh76D46HGiULy9BQVfoA1WJy8b1C4v4CqdUAd+CGbCZwMmdz3iI6
         dkUnbUwkRX767vGacmg9wRiYTKmyAOwsrPCH3e1KVuWixqVo8XaiuNlcJkAdEhQNoy2C
         od0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=eALIl38K;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685539953; x=1688131953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nUpVU0I+W3NhY58ygn3Q+qbhnrQ2MeRFFbrE5mvXNPo=;
        b=Un6WInbwbniwg/7s3Y1v4iumsI7QbPUZPAXfJb4YYWTDQ7bvgQE22Kd7o0F+6c75xz
         Qyr9OdZ+gCMRcXaujRJr8qV1C31a3R2JRapGrgFj36LG3qCJwQHPGKcHcILohfEVDMhs
         UiRUnbzivki3YJX5sApV4ONuPOZ21EsDdZt/KccJFRKjeRqXyMjyn8YmYyYrEsb4p2iz
         BGyz0no0DkJmciP/EFMdZKdVZRB251KiruqNJuYGYsloX3UKSnl+a4SlIjdiO1Y+tthu
         IQWzokgo0+3Ufl6T/uw1wN62aC2l+eRy307X5wP4PZNt/VII7o0NdF6wdMv/NYWRU1qj
         IEwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685539953; x=1688131953;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=nUpVU0I+W3NhY58ygn3Q+qbhnrQ2MeRFFbrE5mvXNPo=;
        b=BfoZ1aiFVFJVbUilOyA28zk6KA0S6oFY/EsLf78s2I7xwQMi+j58z2RprPn1KAF+5d
         m3vMGfQUWsajW9TnvGYTOYshnDWMO338rTn9ZwV4yX5eo4budZdnjRMQqyGCfKG6YE86
         AFPXSnFiAPVB+Gh6OM8muGtQ7fLrr5XDxnJi4QerTczgKeXOxgcZZOvd/+x/UPZJKkOc
         qCjPhPvWHzwGDTM5uDuD+YL6t+YJOHUn9PyKzY9NGHpd6ZQJhRsz7iriIPDscuUVzN0/
         SRcIif1jgUkJGib/yYx0tcA5S7bkH4B//jp+QYd4AkXVTDgEGwGQyE4xNtfPKJi9toDc
         9jVQ==
X-Gm-Message-State: AC+VfDyEpdpqNgq1qAQVluzWtZ+Hrb03JDc+BT+epJny4R3g8Ydg7v8+
	QHPaZ+uVUucPlmXTo6ApQzM=
X-Google-Smtp-Source: ACHHUZ5ZNEn/2SUVc00SdxSGughdBM7z8jf0o0ZbGTF3w3bMjGaeI6GF1LqHyDKWXhyKlvSnu3QM9A==
X-Received: by 2002:ac2:4959:0:b0:4f1:4504:2679 with SMTP id o25-20020ac24959000000b004f145042679mr2876864lfi.41.1685539952881;
        Wed, 31 May 2023 06:32:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:311c:b0:4f3:b4d4:13d6 with SMTP id
 n28-20020a056512311c00b004f3b4d413d6ls227130lfb.1.-pod-prod-01-eu; Wed, 31
 May 2023 06:32:31 -0700 (PDT)
X-Received: by 2002:ac2:5452:0:b0:4f0:181:5a14 with SMTP id d18-20020ac25452000000b004f001815a14mr2545293lfn.21.1685539951390;
        Wed, 31 May 2023 06:32:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685539951; cv=none;
        d=google.com; s=arc-20160816;
        b=raga7rniy4LH/yMvsRx/FOzbkTAtfjmQoxnR+4kB5XcBFXuA0uOgIBCnw0SxcmgxOY
         Xxnc0L/sRgW8HFCAqBwOuPYTQCy+QeLsI6fLitAdEUId/OMwQ74p1EO5MHza3YP6e5kp
         vilor5olWDjJo6aUu6Pmgfd9OjijKKOu72DQFsu3Gty7PAOf1ECJEJ7jIRSPCrsiBP2R
         v9lfinQyyCzh3AVBf0bRbVHEkvcDvPOQ4XqsRFpZ21xyodIXKpO+RHWefOYAKZbKVVhT
         Z7LnEkZ0aH6TZAjouJPM6rJk/g6O7/2Q3KynfZxqSGtyiq5bOf+agTU6xqnWh3cabM2H
         YhJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FC5ZHQYhVGruRZzu25rwbdk8lIo1ZkShJ8yWfi2XGG0=;
        b=AoS9QORqqFanulf11U+FTrFD/Hm2XNvrq6EHqobEK9kkLgUoDdwqg17KG+xFSFsGud
         LRwFderuWI79h3vdlD2LibQA69qJdHI3Bz0A84X8wCmwjlDnKhViN12oL5UJqig/4vj6
         FK7UKazXfvIyGRWrSwaBU5M2QWUcXIoMSEVGYCtJSFDDrZjkYCuQX2RTufpk1mT4zUWv
         +tWURl78AvfWxOG7fICzoBuhJY71vgWf9NkKj/lxA8YVfanRbtfuXLDawOU5yF1H1dnj
         0oMJU7Cq6bSkvZTuQTyP+Fy/Wz8N7n0acomhCFCClkSxJH2TKUo2tV1tEQH7z1VxOsGl
         n7aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=eALIl38K;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id b19-20020a056402279300b00510cd4eed58si857613ede.2.2023.05.31.06.32.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 May 2023 06:32:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-3f60b3f32b4so42630045e9.1
        for <kasan-dev@googlegroups.com>; Wed, 31 May 2023 06:32:31 -0700 (PDT)
X-Received: by 2002:a05:600c:2941:b0:3f6:174:8c32 with SMTP id
 n1-20020a05600c294100b003f601748c32mr3696783wmd.6.1685539950854; Wed, 31 May
 2023 06:32:30 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000cef3a005fc1bcc80@google.com> <ecba318b-7452-92d0-4a2f-2f6c9255f771@I-love.SAKURA.ne.jp>
 <ca8e3803-4757-358e-dcf2-4824213a9d2c@I-love.SAKURA.ne.jp>
 <656cb4f5-998b-c8d7-3c61-c2d37aa90f9a@I-love.SAKURA.ne.jp> <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com>
In-Reply-To: <87353gx7wd.fsf@yhuang6-desk2.ccr.corp.intel.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 May 2023 15:31:53 +0200
Message-ID: <CAG_fn=UTTbkGeOX0teGcNOeobtgV=mfGOefZpV-NTN4Ouus7xA@mail.gmail.com>
Subject: Re: [PATCH] kasan,kmsan: remove __GFP_KSWAPD_RECLAIM usage from kasan/kmsan
To: "Huang, Ying" <ying.huang@intel.com>
Cc: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.com>, 
	syzkaller-bugs@googlegroups.com, Mel Gorman <mgorman@techsingularity.net>, 
	Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=eALIl38K;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::332 as
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

On Mon, May 29, 2023 at 3:08=E2=80=AFAM Huang, Ying <ying.huang@intel.com> =
wrote:
>
> Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp> writes:
>
> > syzbot is reporting lockdep warning in __stack_depot_save(), for
> > the caller of __stack_depot_save() (i.e. __kasan_record_aux_stack() in
> > this report) is responsible for masking __GFP_KSWAPD_RECLAIM flag in
> > order not to wake kswapd which in turn wakes kcompactd.
> >
> > Since kasan/kmsan functions might be called with arbitrary locks held,
> > mask __GFP_KSWAPD_RECLAIM flag from all GFP_NOWAIT/GFP_ATOMIC allocatio=
ns
> > in kasan/kmsan.
> >
> > Note that kmsan_save_stack_with_flags() is changed to mask both
> > __GFP_DIRECT_RECLAIM flag and __GFP_KSWAPD_RECLAIM flag, for
> > wakeup_kswapd() from wake_all_kswapds() from __alloc_pages_slowpath()
> > calls wakeup_kcompactd() if __GFP_KSWAPD_RECLAIM flag is set and
> > __GFP_DIRECT_RECLAIM flag is not set.
> >
> > Reported-by: syzbot <syzbot+ece2915262061d6e0ac1@syzkaller.appspotmail.=
com>
> > Closes: https://syzkaller.appspot.com/bug?extid=3Dece2915262061d6e0ac1
> > Signed-off-by: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
>
> This looks good to me.  Thanks!
>
> Reviewed-by: "Huang, Ying" <ying.huang@intel.com>

Sorry for the late reply, but maybe it would be better to mask this
flag in __stack_depot_save() (lib/stackdepot.c) instead?
We are already masking out a number of flags there, and the problem
seems quite generic.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUTTbkGeOX0teGcNOeobtgV%3DmfGOefZpV-NTN4Ouus7xA%40mail.gm=
ail.com.
