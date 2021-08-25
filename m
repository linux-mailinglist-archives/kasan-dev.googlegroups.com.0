Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5NITCEQMGQEL4K4TEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 175683F7270
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 11:59:18 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id a133-20020a1f988b0000b029028407337128sf4396808vke.22
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 02:59:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629885557; cv=pass;
        d=google.com; s=arc-20160816;
        b=Bxjc8bBuic3Dyzr11Uxmi5TkxRgEmoHNY//hRM8S5p/BXTOJZFu819eNmYC24knJRL
         GlYpg9x5OUjkxCKsu31EgIOA5Kp3bOBD1qbbnF1g4f8VU/qLprpga8WRknk621jEuDX+
         bEcpy0KhojoFFF4vPmdybIIVyCT03IwHVuh5IJCZn/fSpPG+UP8ccvTOjszUUdiZZDFe
         4cC2OYusfg35J+HsEgGPTzr6Y0dXenf8jIIzrzBC3nw1K/hNw+/0zVhIixDcOVoj+YDZ
         TgAwYLprJVhVSjUUPNUR3QP5oc/wWfeILBaFtCm2n8yLV7Mzp8l0OJj+SdZFCsaoS/iz
         g4BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9GOCIYd13J+L19UswgCyZGHefjYqxLz3dQxmiU1fopY=;
        b=RGz73tCK6EQwGl6Zw/S7DtYIuRSRMcONKjfuahHj+HzQRLWYi+rPk2BurLwW+lbynX
         hwB82XUhT9DOx1ZJV8lb20aOIHs8jYhud5QElATFTFy+wIq20fYdf2yyC+pVTibcVHpE
         WiQHZrhYHEldSlw+WZ32fnQieDD1930kum+vc65Av85SrYyRmfsnmK3ee8f0WiPi43nQ
         MzepX1tbzDO59nVcgz/WarAiB18TFHcyO38hAuNhr32q0zvaDgW6b8iZ8J5vtFk74UT6
         w3ulqg4XNBLL7nHeGEPqD+SFjqsEB3St14DomI0c3jY+J3NOn4eE3vcCTe30q0eqfqn8
         4dkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kH94v5Zx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9GOCIYd13J+L19UswgCyZGHefjYqxLz3dQxmiU1fopY=;
        b=DHHg4qksSBcidFiR/kyW7DHpPeMfqDBa1tVlI3Aao/hEuWTHB3FG0bfeVBxLR0MdhD
         H9Ijv0phGAFzLyuomMELRJoA/n9oUaWZIdt/GiQNLqtmB8sagBvTSQwGD/kYyfV/pgCo
         trGgq81ys0i2kKS8aSQ0oQQYM3qUE0tkKl7Fr6w/9xE7s51dL3AIYkMirxzC6W0XXx6w
         RGZX7wsxme8DqjisV2irIJCuEeI1yQv2sLqI0oC/jVG6gLwf4yGXGjB1Yjqu6KPTcOW1
         6766x/4emrnZNgTqFjf9gJ900GHgD0uyWH/mB6DhNWIUq/XmqsaHP9RyGdicow8xxjGl
         cBVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9GOCIYd13J+L19UswgCyZGHefjYqxLz3dQxmiU1fopY=;
        b=ueZkh/vSCViAeKuCa5pmdqofD2+tNA718rvqIaaPxJ/QVA57c0mL7Qf4f039a2oTSh
         uo/Anp1Cf2TOIGxsFOQ+EOtVR98Znxe64IjFKpACeWF5X0F3GK9tA4KfV47H4O0wB8Uh
         7podvJE6IM/j2c2DxSb/yi/e0qhoFMBFYgWq4JhvXwiDTB5E7r1hP+5ySldVwgle/icY
         ocIPBn8JJ5TYq91lF4192ttLIHOnUogxbIOEgJjFwTPEfdtcsman3cgjNRttEO89qigG
         gPtKT78GQWNiCSewGU+SeX+tRwIBfdd8zV/j5Kk3Ns1fPinKMjvmc5mE+R4UKvA86GJe
         xtdQ==
X-Gm-Message-State: AOAM5337KoTkqKmy5gecRnijf8jQj+gpkwi/sktD5AQ98JitUtyqx2+G
	pylxC8xO4ezGCx6zeuQtmwg=
X-Google-Smtp-Source: ABdhPJxbHQOD0XLbK/PYU4u6pL57gSlobh9rN1euGJY0mAVntazlLvk6meSWewQEdRRqkny39BFKsQ==
X-Received: by 2002:a05:6102:662:: with SMTP id z2mr17357028vsf.14.1629885557120;
        Wed, 25 Aug 2021 02:59:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:b246:: with SMTP id s6ls249757vsh.1.gmail; Wed, 25 Aug
 2021 02:59:16 -0700 (PDT)
X-Received: by 2002:a05:6102:531:: with SMTP id m17mr9387984vsa.1.1629885556565;
        Wed, 25 Aug 2021 02:59:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629885556; cv=none;
        d=google.com; s=arc-20160816;
        b=m4VWUbupQqdCj0vvD4Pr3rNkf4VlWcOvaaAwuxhHLQNJVa6STLu7luyw4U+crGxBMI
         6/T+MyBlt+1k773NLnTzAwvmMJs19zL7qkYNgYofOns7HP23mYnW/MyDqn12G64Gv5Zc
         JS7egHXQZB9p3X9b7yeP92yd+nre7sm+KeDk4yFVQI0r95V4hflnb/SxGUWcpNXvvfDL
         gBjEaC4ZIZ4QMr2MHN/2bMvkjk/TWWsZKcCkVsU/YZ2dg2F5P/YiKAgsXFDozd+ShmAI
         oq191KeVS9piIi240YMJHwXB0kdNn4s/2G0eEXY7ue7K2o61s7oqFmD9rLO3DNfD9MWf
         1aKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RT/ruHmEJSYewLcThfyctJrU8xPbr8Cf1G+FiOsvBbc=;
        b=ibNfHUqBLPU21RZiyGpshQuf8B+UpyK9TKoTBmKwdhUSKQx/oTtXjqGuyTqpAAFUnk
         ecK5cTybh48eHGNXTK/n6vifhFbv1OtCEG6fYgH+OdTsXSdF+l4o7Z/4njrSKjiDqko3
         LCe7WsCNsnpXeW97r7jHTauloqCdC3g909Fk1gsDEgV5u1D8quKmlxqJMNqoMcwLvBB2
         PKSG17TYDoM7jZrykBfQxZlfsA4HxAN5PnnR8LXMZgiDglKChWz531dXlSaC8x7UC6/M
         2foqLwEzu/jK8WVfscpk7Zvww1am2mIGiTQLsteKTiXsA8Ej1FHoK2FK8GYY3tKuzej2
         oBYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kH94v5Zx;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id w131si12506vkw.3.2021.08.25.02.59.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 02:59:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id g66-20020a9d12c8000000b0051aeba607f1so45563147otg.11
        for <kasan-dev@googlegroups.com>; Wed, 25 Aug 2021 02:59:16 -0700 (PDT)
X-Received: by 2002:aca:4589:: with SMTP id s131mr6136352oia.121.1629885556155;
 Wed, 25 Aug 2021 02:59:16 -0700 (PDT)
MIME-Version: 1.0
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
 <20210825092116.149975-5-wangkefeng.wang@huawei.com> <CAG_fn=X9oaw0zJrcmShNcvd3UsNSFKsH3kSdD5Yx=4Sk_WtNrQ@mail.gmail.com>
 <99daf260-76af-8316-fa9a-a649c8a8d1ab@huawei.com>
In-Reply-To: <99daf260-76af-8316-fa9a-a649c8a8d1ab@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Aug 2021 11:59:04 +0200
Message-ID: <CANpmjNMZ-kNVkCRWDfgEjrR4BT1B0gVNnvao_w3nEM9pA3Epbw@mail.gmail.com>
Subject: Re: [PATCH 4/4] mm: kfence: Only load kfence_test when kfence is enabled
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Alexander Potapenko <glider@google.com>, Russell King <linux@armlinux.org.uk>, 
	Dmitry Vyukov <dvyukov@google.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kH94v5Zx;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as
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

On Wed, 25 Aug 2021 at 11:55, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> On 2021/8/25 17:31, Alexander Potapenko wrote:
> > On Wed, Aug 25, 2021 at 11:17 AM Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> >> Provide kfence_is_enabled() helper, only load kfence_test module
> >> when kfence is enabled.
> > What's wrong with the current behavior?
> > I think we need at least some way to tell the developer that KFENCE
> > does not work, and a failing test seems to be the perfect one.
>
> If the kfence is not enabled, eg kfence.sample_interval=0, kfence_test
> spend too much time,
>
> and all tests will fails. It is meaningless. so better to just skip it ;)

But what is your usecase?

I'd like to avoid the export of a new function that is pretty much unused.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMZ-kNVkCRWDfgEjrR4BT1B0gVNnvao_w3nEM9pA3Epbw%40mail.gmail.com.
