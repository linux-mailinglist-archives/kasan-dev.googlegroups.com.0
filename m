Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCHY52LQMGQEW52MAXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id EF231595F8E
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 17:47:21 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-10e8118cb3fsf2770349fac.22
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 08:47:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660664841; cv=pass;
        d=google.com; s=arc-20160816;
        b=lN7kRPX3wTNbYOZ7Rkeg9E32+OxQJ4+MTlDLLm2cRN8p+0AaKBM+N9SG/U82wEVm1+
         Yxm9rD1hwQt9ns1ZwjK2guE8pBKATgZockC/u213eKWpT6B8S+RyAW9YsGfOQllB30uj
         1cZUIYkTXQnZAAjKmLy0tk2teZVOT60ZcNEH0F52QkwbxnppwtuMiG4PqRi26UBd8Tlf
         nP1sxmexvrxGNNCjotvTcx3061qil9D4GH3VH0yItYlAOACvZbENH+j+DQN9Wq2w/MmN
         /sLwyFe77tLxbplpa+OoHOC2UGxMroL7PSKh5UIBj3LtwMieogsCs8fKgLS6NnfDyH2o
         haTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9F1wzFfSfdNrPLdNAKtPdRPevkel5wM2k/Ro4dec0Hw=;
        b=mZfaBEPtO9T/66scXiflWMs1GJ6q9bV3jWOT7tAq/M9Pp1qA0Gls222xX4FW+V7KAA
         R7ZK0/3T9RGmQvTWeleCFLtAAxPSqawjYFEGMxN6y4JY2SaBDkWDohGJNYWSeMKLsQkd
         3WTG1inoV/7c0bGycES/vW12sx+C4gXAARnkbBtMiH1JsSbv/fEakpDgH3AIjl6XGyNq
         7KPJFIG4jWbcD8S99+Kq8umUt29FF+59Dxy07eIXjZDbM/rJv5mfCJFe0RxuUzOf85hX
         2DzY2UBoZMk7lHr23IoNOMtz9Yy4XV45hqt8ADu0nHXEMgyKRZ3yjA6kyqNrE3xsICNe
         EB9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pinUxBh0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc;
        bh=9F1wzFfSfdNrPLdNAKtPdRPevkel5wM2k/Ro4dec0Hw=;
        b=APiStECXoO/8stxaQRU9BdUjub+V4qpHfFL+F1kOgWM/CWgQWzHS1I23gcYaDikuAU
         PJT5alk8D92LvUmsFHD2y9gJTUY9R7ZzlHLSJqyd19JrpbCs1+YOtL69QD4SG92WudwV
         jWaM/H/6CVpc5rAo0u5wstcNfBLi0hXkPxkn8X4cdUlRreuNyrWs2MTxtBdVAJDEDqaZ
         A1mIttPH3UuK0QReQnQ33a1SdQGV7CCcm8uu7xZDzacL9uKJGaWsiEKU81xJeR54z+Bf
         tuWavoC7SaUkUZpz6gqXeZ9crN0X54sPDHL8T4egjzkWuoDZV17E2x3fEURxxPjVVDZB
         JvWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc;
        bh=9F1wzFfSfdNrPLdNAKtPdRPevkel5wM2k/Ro4dec0Hw=;
        b=xr2/sd2FpB4hnLLY+HPgVS/ZXh3QzspwrnrwumTA/TlC64SjgwhwXlS/Xpj/CXjlfo
         7GmtWfiLgdmxbReDii3DR+7eK7ZaBcN6TGnRvMy4OIRbrI93h5+YZ0KGx1Jv58cAVy3c
         aIAXXorJCu676jmPTKW9wm7HtVedMZvyymu9mGN9rnyFYFGS/jLVeJjzGvaJmgz+OtII
         mSiVIrRtxwOkSQ9TD3bdPF8XThuJbsYCl7Q/TfilsxlDQHL2MVDVpPG7tG9kwjGwLG/M
         qXan7A3sKl+gHrFDKovu0U4rJ/dNapwE0YPVfjYlBqsUfqs/Y0j49/w/reYj4jHI8TkT
         l92w==
X-Gm-Message-State: ACgBeo1e3BsJYJp48IH1s3llkKu6YVD8Eb98uXkV8TNz5ehx3tWUoIJe
	smySQjNCh61Vp93zAI1Dg9E=
X-Google-Smtp-Source: AA6agR7izIgCvhyIvaXlM4qrjzevG9+FWh/cRC3h7DzmphBDynoQJ6L5qxFYm/EzbTaAqiJUblMF1A==
X-Received: by 2002:a05:6830:168b:b0:638:a825:d290 with SMTP id k11-20020a056830168b00b00638a825d290mr3642638otr.372.1660664840788;
        Tue, 16 Aug 2022 08:47:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:d347:b0:11c:2185:2ead with SMTP id
 h7-20020a056870d34700b0011c21852eadls328769oag.1.-pod-prod-gmail; Tue, 16 Aug
 2022 08:47:20 -0700 (PDT)
X-Received: by 2002:a05:6870:c151:b0:10e:d255:7b19 with SMTP id g17-20020a056870c15100b0010ed2557b19mr9604360oad.122.1660664840332;
        Tue, 16 Aug 2022 08:47:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660664840; cv=none;
        d=google.com; s=arc-20160816;
        b=kAp/h7Tmzo4KdbrylHSJAURxP6trF4wqoApp8/2oWRdza0lrMR5VxgAT4OimsKJWRG
         olt7zFG2bDR+J/QcZlp/cQyz3VfAMARzhfrsUF9/Nyb4WdFlhfcN6H0z1nmJ8+EJx+QA
         gnreVYskQ21vqZ863mFI8K6u3PyiIzYDQOggO9MkDTmYCN/2q0f26VUnTUvVzzgUv7gS
         UUCyH5xo4lXxoponHpLWhSzxD3wBqwNGKmeUYWTsaQdq6+7DzzlMWsjU8R5khb0oBg1I
         Riru3/9HoxkXNsJnbIRXH31ilZ00AU5Ob9qev9MwN4Kt4zOBwzVfryfCK2zjCKKZDkY4
         lbjw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=u1/23E4Gc0pjOPCMF8c+vKFDgysK5yteTwVdISNhov8=;
        b=Pkrjyn7GoJYm4XG/qC6AveZvnZr8peU/ZM2WV7jzFiXLsvAOoBXwXLBXOgaZyIXUqb
         lq/SYjY1/B39SNoW8P7W2rUKBap9x3n/9HTy5jdYmYXoaoOvv59++8VBvF5cHeg/1GeO
         BTPVW6gpZgxf8cK2/EzpZevUWQJH7YJuaRL1pwEf1a2IiG6MIo96j5v5dnImY5bRBAaM
         LGF0CcuduQcYjOez6gVcx+cmDtvCNgB9nYGSwbzEgxOmZ5eAV99LiT+RTvaAT4wK6Fyr
         ziwReo9bZ/UMFhNsGhG0xdcKAeAYrkT3kq5pPfTcOLEBLgfSOmGPQABooSGKn289R5da
         0RCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pinUxBh0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id h128-20020acab786000000b00344d0712829si232123oif.5.2022.08.16.08.47.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Aug 2022 08:47:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-31f445bd486so161950987b3.13
        for <kasan-dev@googlegroups.com>; Tue, 16 Aug 2022 08:47:20 -0700 (PDT)
X-Received: by 2002:a5b:c8b:0:b0:688:ebe9:3d05 with SMTP id
 i11-20020a5b0c8b000000b00688ebe93d05mr8442135ybq.553.1660664839915; Tue, 16
 Aug 2022 08:47:19 -0700 (PDT)
MIME-Version: 1.0
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck> <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck> <CANpmjNMd=ODXkx37wqYNFhivf_oH-FSo+O4RDKn3wV14kCe69g@mail.gmail.com>
 <Yvu4bBmykYr+0CXk@arm.com>
In-Reply-To: <Yvu4bBmykYr+0CXk@arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Aug 2022 17:46:43 +0200
Message-ID: <CANpmjNMwUKwmOh86p3HnXiU7zLiXvrc8FF5bFHtVAHn=GdaX0g@mail.gmail.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object search
 tree (overlaps existing) [RPi CM4]
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>, =?UTF-8?B?WWVlIExlZSAo5p2O5bu66Kq8KQ==?= <Yee.Lee@mediatek.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, Max Schulze <max.schulze@online.de>, 
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"naush@raspberrypi.com" <naush@raspberrypi.com>, "glider@google.com" <glider@google.com>, 
	"dvyukov@google.com" <dvyukov@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pinUxBh0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::112d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, 16 Aug 2022 at 17:32, Catalin Marinas <catalin.marinas@arm.com> wrote:
[...]
> > Right, looks like the kfence fix didn't need to be in 5.19. In any
> > case, this patch I just sent:
> >
> > https://lore.kernel.org/all/20220816142529.1919543-1-elver@google.com/
> >
> > fixes the issue for 5.19 as well, because memblock has always used
> > kmemleak's kmemleak_*_phys() API and technically we should free it
> > through phys as well.
> >
> > As far as I can tell, that's also the right thing to do in 6.0-rc1
> > with 0c24e061196c2, because we have the slab post-alloc hooks that
> > want to register kfence objects via kmemleak. Unless of course somehow
> > both "ignore" and "free" works, but "ignore" just sounds wrong in this
> > case. Any thoughts?
>
> Since commit 0c24e061196c2, kmemleak has different namespaces for the
> virtual and physical addresses and there is no risk of overlap. So the
> comment in your proposed fix can be confusing in 6.0-rc1 (but fine in
> 5.19).

Makes sense.

> In general, if an object is allocated and never freed,
> kmemleak_ignore*() is more appropriate, so I'm more inclined to only
> send your kmemleak_free_part_phys() fix to 5.19.x rather than mainline.

So it sounds like we should just ask stable to revert 07313a2b29ed
then, if the patch switching to kmemleak_free_part_phys() should not
go to 6.0. Is that the most reasonable option? If so, I'll go ahead
and send stable the email to do so.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMwUKwmOh86p3HnXiU7zLiXvrc8FF5bFHtVAHn%3DGdaX0g%40mail.gmail.com.
