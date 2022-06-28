Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFW25KKQMGQESCXIAKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5022955BF0C
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 09:26:16 +0200 (CEST)
Received: by mail-oi1-x23f.google.com with SMTP id bf2-20020a056808190200b0032ea485bb7dsf7450688oib.8
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 00:26:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656401174; cv=pass;
        d=google.com; s=arc-20160816;
        b=UNXIywph8AOA4kGsFjjk42nUDg8v7cM+joce8qqE199l1iYBwSA2VHl1ilblfufOMK
         dLFMiqfxCGwL6ApFZeO58p+p8fKEJDdUskGkqMbqRwSFSAJJTO0qIBFb/mZ+n/klvyy+
         vajA5A8PefSRhs92T3jSmUWpXjtMkwVgp3MhFV/l7ud9a1MvF13TGux7M695YQk1e4dj
         Xnchd4MfDlmZYYNdvoIU0prMX7xn2zsgURqWc80NkKUMbxDRtEuMBoZFsjE5QtLcBZ9m
         Usbx9RiDfiO0lmhpos7CaAhh/pEWQHZ0xkc8p5jQ8ogltxluburfljWwXBkDdvOYmvD6
         z1gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7/drCezzMiKjqO2I5kvPToaTRhfzXH3Gk9M1BOaiNng=;
        b=0DX/8qWiJ03EsbkcYLr5/jYYdXU4L4mtX7caxVaZI8jKPMgRPrnv6oejIbAe++5Q2C
         sGnpgVsV6k2eRCg1Ca+CfTBrDk2Ph7QwZ7j9CXl0F5JjuhkjJZvIZmv/BWWnfxHZYCgz
         Mr8JYteHSkuZ/YYRDVXp9opOp09a67L1m/3lXZVNpxSA/G/EFFbD1hQgCLUBLeAAxu7e
         a/mYXxKNl1U01JUfiVX8Izev0gwNbPEVQwT+7kAESEJHVgUH2MmOVcv/QgNm+sdlXv7T
         w3W+ZFLYxiT5ezdzB36xGr588tKIe1/wovlJyw4UPVwmOf1JayUyPbYoo+GA/EnBW7pi
         2Y6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Zz5NixJh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7/drCezzMiKjqO2I5kvPToaTRhfzXH3Gk9M1BOaiNng=;
        b=Y80Ch2tnwnejbULgoIt0aFWQWtq0ptCkhEjZb3c5TYG8AQA+lmjbGKsuNbK+x/yL/R
         rZhC/eTboT2T7SfLHQYhC3TZB6+xWZMiBqgHcsCbChGer42fPvi2sS5mdYuORwTSGpyE
         KZ8w3mtQiPO1f6cBOmVhoqIvHB8reBcdsaznlsGmKxIZt3nVavzzCFmQ3G7KDiXFy/8u
         j3PjdkU/uuhKkWUZ7kHhNf0ErfmfCcTb3Df6Vnu3v298Acb4mOGmSuJUWHRGAonU8NUb
         I4O0of6a1hfKdUE4Vua65XENIHLFAJiIeCxYrs0hkfqFZIFDbgcbtLd1KgpHj5qx5km9
         DrIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7/drCezzMiKjqO2I5kvPToaTRhfzXH3Gk9M1BOaiNng=;
        b=s/izoZUcqt3dwX1136Js0iAhy/RS1zp+4x5gUXkOlt4MeTmLNbq/OcSSfy0Q7DHjFl
         SlZmBkU/8JajedhWZY/UOlYp5ilBr7v5LXmDrxfq8nCiSIpSJfi5F1KxsxeuOKAjfIkX
         sj+0O2ca6+GweD+aKm2EbHm0HgaTOVCdAizZWvcMZxo1BWreHfpboYqASNHdX3Nb9ipq
         F/qz/eV4eQQrKcqLJHUEt3he72lQBrsJRnR68PCk/j7lJYNoKH86soUzlK7DZ7Gmab5l
         GHfqumjtd7EvCG2OrIBCghvh3eztlqrvaVNGJ0vjOAsb4XirfV/hiqs7SZqLxfRgBxLP
         Dm8Q==
X-Gm-Message-State: AJIora+DiY+EzpRKadDpS0dbzC/LR8vEn1M1xm6YbUGYJm9Mv8GgKb8V
	hMehOvXMNXNuuF3Bd7dJEO0=
X-Google-Smtp-Source: AGRyM1tqhrqRp8lQjot2lloj0uBgSnO+IyV3CgjWhHZQ1uWPXPTLAB3yhMTXtPrR5mi9/t/FhqRgGA==
X-Received: by 2002:a05:6870:5809:b0:101:ce10:b267 with SMTP id r9-20020a056870580900b00101ce10b267mr12798660oap.83.1656401174691;
        Tue, 28 Jun 2022 00:26:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:6a85:b0:101:9aec:f460 with SMTP id
 mv5-20020a0568706a8500b001019aecf460ls11495116oab.11.gmail; Tue, 28 Jun 2022
 00:26:14 -0700 (PDT)
X-Received: by 2002:a05:6870:d1cc:b0:100:e9ba:f14b with SMTP id b12-20020a056870d1cc00b00100e9baf14bmr12907461oac.256.1656401174300;
        Tue, 28 Jun 2022 00:26:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656401174; cv=none;
        d=google.com; s=arc-20160816;
        b=SZxK7ZJj7gilbjrxRXB48PdsXh9MRNwHrZgUi+sJbDCG/IlqizKCpCuWSuxApO/mGX
         8QIPQ3ic46s3LNg6W2cEd34gKpISUhAQZAsHAsn3HLb304aoi/ohfV/fpcworhbkp1QQ
         xqhTRJuu2dtP9R3c9AH52SJNEhpzYWjUCbZ9cN7OzBQbzFZxy/8CB3LEgkEWWrD52V5L
         ygUiE/jUo0yqyCej5bVNksqKHWmK2X+cNpt0dVfS2S8iLZPKMOMHeOk+lCI9GLQyN4yI
         90us1ubPpTstFv3y2SeFsQzxz2VoLRSmMxtqhYv9+4iTo3KALtr6L9xo7/R6nG7M7jVO
         5w6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=uto9EobkP0WojhVEjYvx1l88xfjdKMI1uMfZ8YaCROA=;
        b=TDlpV2wXB15doZMfWkFgwzfJqXb0sdt3Fcc5sRDqdtMA5oEksbEhh00eiRfn5psdhf
         UWvrnHZRoWlSzbf4TGV/d6EiCPg+L8L3MkXL+/1jVEw5fueFpK5RDPMeIWgihNtZWyXM
         0EWV/L4jLqZEBMswo6KhaGTbQCiInqBG3aZKkQCgb8JxtEETNwfF7qa2ftSep0iIOjvB
         R8LktctJo1gT2giRaI/gGaZpraMWINpps3Qo4ruP6hUoe5PREr3d5+2EzK2MjMHvukmn
         7jMlrsEY4ipAqybM8OXMc10W1HW7LycbMfkFKslGDcRbNPrlZ5ooDAeEuVM4ywd9rtcA
         zCmQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Zz5NixJh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id e13-20020a9d018d000000b0060c76b16536si463869ote.4.2022.06.28.00.26.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 00:26:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id v185so11214641ybe.8
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 00:26:14 -0700 (PDT)
X-Received: by 2002:a25:3497:0:b0:66c:c013:4bea with SMTP id
 b145-20020a253497000000b0066cc0134beamr10903346yba.625.1656401173876; Tue, 28
 Jun 2022 00:26:13 -0700 (PDT)
MIME-Version: 1.0
References: <20220623111937.6491-1-yee.lee@mediatek.com> <20220623111937.6491-2-yee.lee@mediatek.com>
 <CANpmjNN-jsZoVmJWD2Dz6O3_YVjy0av6e0iD-+OYXpik1LbLvg@mail.gmail.com>
 <bdfd039fbde06113071f773ae6d5635ff4664e2c.camel@mediatek.com>
 <CANpmjNPfkFjUteMCDzUSPmTKbpnSfjmWqp9ft8vb-v=B8eeRKw@mail.gmail.com> <9c6fcb1c178a923f2406466a3f9f2345e4e7a1c1.camel@mediatek.com>
In-Reply-To: <9c6fcb1c178a923f2406466a3f9f2345e4e7a1c1.camel@mediatek.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 09:25:37 +0200
Message-ID: <CANpmjNOADG3UqC+6aGEmfh5kzaiaqjGTFieUonC=_XwOophJ+g@mail.gmail.com>
Subject: Re: [PATCH 1/1] mm: kfence: skip kmemleak alloc in kfence_pool
To: Yee Lee <yee.lee@mediatek.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "open list:KFENCE" <kasan-dev@googlegroups.com>, 
	"open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-arm-kernel@lists.infradead.org>, 
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>, catalin.marinas@arm.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Zz5NixJh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
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

On Tue, 28 Jun 2022 at 08:41, Yee Lee <yee.lee@mediatek.com> wrote:
>
> On Fri, 2022-06-24 at 10:28 +0200, Marco Elver wrote:
>
> On Fri, 24 Jun 2022 at 10:20, 'Yee Lee' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>
>
> On Thu, 2022-06-23 at 13:59 +0200, Marco Elver wrote:
>
> On Thu, 23 Jun 2022 at 13:20, yee.lee via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>
>
> From: Yee Lee <yee.lee@mediatek.com>
>
> Use MEMBLOCK_ALLOC_NOLEAKTRACE to skip kmemleak registration when
> the kfence pool is allocated from memblock. And the kmemleak_free
> later can be removed too.
>
>
> Is this purely meant to be a cleanup and non-functional change?
>
> Signed-off-by: Yee Lee <yee.lee@mediatek.com>
>
> ---
>  mm/kfence/core.c | 18 ++++++++----------
>  1 file changed, 8 insertions(+), 10 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4e7cd4c8e687..0d33d83f5244 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -600,14 +600,6 @@ static unsigned long kfence_init_pool(void)
>                 addr += 2 * PAGE_SIZE;
>         }
>
> -       /*
> -        * The pool is live and will never be deallocated from this
> point on.
> -        * Remove the pool object from the kmemleak object tree, as
> it would
> -        * otherwise overlap with allocations returned by
> kfence_alloc(), which
> -        * are registered with kmemleak through the slab post-alloc
> hook.
> -        */
> -       kmemleak_free(__kfence_pool);
>
>
> This appears to only be a non-functional change if the pool is
> allocated early. If the pool is allocated late using page-alloc, then
> there'll not be a kmemleak_free() on that memory and we'll have the
> same problem.
>
>
> Do you mean the kzalloc(slab_is_available) in memblock_allc()? That
> implies that MEMBLOCK_ALLOC_NOLEAKTRACE has no guarantee skipping
> kmemleak_alloc from this. (Maybe add it?)
>
>
> No, if KFENCE is initialized through kfence_init_late() ->
> kfence_init_pool_late() -> kfence_init_pool().
>
> Thanks for the information.
>
> But as I known, page-alloc does not request kmemleak areas.
> So the current kfence_pool_init_late() would cause another kmemleak warning on unknown freeing.
>
> Reproducing test: (kfence late enable + kmemleak debug on)
>
> / # echo 500 > /sys/module/kfence/parameters/sample_interval
> [  153.433518] kmemleak: Freeing unknown object at 0xffff0000c0600000
> [  153.433804] CPU: 0 PID: 100 Comm: sh Not tainted 5.19.0-rc3-74069-gde5c208d533a-dirty #1
> [  153.434027] Hardware name: linux,dummy-virt (DT)
> [  153.434265] Call trace:
> [  153.434331]  dump_backtrace+0xdc/0xfc
> [  153.434962]  show_stack+0x18/0x24
> [  153.435106]  dump_stack_lvl+0x64/0x7c
> [  153.435232]  dump_stack+0x18/0x38
> [  153.435347]  kmemleak_free+0x184/0x1c8
> [  153.435462]  kfence_init_pool+0x16c/0x194
> [  153.435587]  param_set_sample_interval+0xe0/0x1c4
> [  153.435694]  param_attr_store+0x98/0xf4
> [  153.435804]  module_attr_store+0x24/0x3c
> [  153.435910]  sysfs_kf_write+0x3c/0x50
> ...(skip)
> [  153.444496] kfence: initialized - using 524288 bytes for 63 objects at 0x00000000a3236b01-0x00000000901655d3
> / #
>
> Hence, now there are two issues to solve.
> (1) (The original)To prevent the undesired kmemleak scanning on the kfence pool. As Cataline's suggestion, we can just apply kmemleak_ignore_phys instead of free it at all.
> ref: https://lore.kernel.org/linux-mm/YrWPg3xIHbm9bFxP@arm.com/
>
> (2) The late-allocated kfence pool doesn't need to go through kmemleak_free. We can relocate the opeartion to kfence_init_pool_early() to seperate them.
> That is, kfence_init_pool_early(memblock) has it and kfence_init_pool_late(page alloc) does not.
>
> The draft is like the following.

Looks reasonable - feel free to send v2.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOADG3UqC%2B6aGEmfh5kzaiaqjGTFieUonC%3D_XwOophJ%2Bg%40mail.gmail.com.
