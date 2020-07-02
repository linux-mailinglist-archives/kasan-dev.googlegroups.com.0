Return-Path: <kasan-dev+bncBCT6537ZTEKRBWUF7D3QKGQE6F454SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 068832128A9
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Jul 2020 17:52:59 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id p15sf10800601lji.5
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Jul 2020 08:52:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593705178; cv=pass;
        d=google.com; s=arc-20160816;
        b=kDGymzf9wiVhyTPIjxO1kcB8dRydOnL15z02r0N17knPHBf2l3LjokERRHLWuf5GNf
         duYCbxepOxNtNgvoP1SVr7g7CEHCgZBBl1leA5mC1p9OMbfrukkHRQf1NmekcZWCISOX
         XVY7HodGEZLbIpINhRblKSPLBh1T/ofpuxGxxmui3Pns2FD8WfKbZpbW4z0gjLVZ2Q2U
         6yB/tJIv4iaE8Cqycft+Khv+HuR+7Ev6pJfmFLG/Za/oRw0qrI47ALnQN03dxQoeng+W
         F6xtwIShYl2rNWG7Za7eWpQVCvP/Inn4Gym5X/0+OAChPaPRBDasuHPJFG2NHFqQtD5b
         lf9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=4P4zt8blqJS3mX6k1VDcQuaLWFb6h19nE6Q7ajYy/4k=;
        b=e9LgxpYWttjpAllRIXDzJPrQ2/mVUs8arCA1avvgPGkPKu34/NkY6lBMYo+0NiZlHF
         Wq7svPejDdmReFMYim0nCwyNg04DbWKK7RivveSGXjctaNnSpUiEIXyIrAPk5YC8Hj1X
         ZjsCIJQ5eR0QM4unTHQBiYT8aMkozYAs7yQtrDeQXye5Q/uoviuMrVRiAGhrzaMVZ30P
         524/PbyyfyeHXATg986bgFCmEN/SWx0YtwQdfMyJEMLaGwoXBoFcrGtfBM4yj+AtQAwh
         et8qTyyojBWQ0tRKxRwE8a9cXz0JrLBLZHAXG+31CIbAsS5S9bFv9il0GkgmCNb5EHXd
         qoqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="KwW+/U9f";
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4P4zt8blqJS3mX6k1VDcQuaLWFb6h19nE6Q7ajYy/4k=;
        b=TkEHQgQmE/VdEQDnCMYQTg7O26S4vINo7FRFKAnRmbcHFXKHazxuDLsY05vRk+7aJz
         na/pVGKqmfS/TUFMQGFbjsO1jPNGmvYOps8fulXPPcc1HjiKK3NKMpo/IU/vkUWUxtQu
         dUymqY7ecxz/jYEUxGoSEcEgo8rg//B9ZuQxuyU9gvBhdwc3/K5PdOc7uGPPRfwUu2wK
         ZcJ7T+cNae6MtP/Ps8msXYOkmUTyTQMe7+Q1BQrtyaqVKIzvgW0sJPcc3nNZE/TBZ/CG
         iUkJ6YXwU1+64VP+BuDvouXg7m/yXm/cTKogycQ4mbf99Hls59SWxeuPD9qXtkA7mZ4U
         AUhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4P4zt8blqJS3mX6k1VDcQuaLWFb6h19nE6Q7ajYy/4k=;
        b=fkl9xPl6IWOpkHBGgHRycgurvb6Kn8Cq5j3oIN+K+hFhzXkx0oo3rTxZvykLEetjI8
         879rFtpQ8UKbvm1qmN/NzLaBD8w+jEYvFPzgwx1bk2TgyXAZuH7aCDHxZ7qbRp13xHSN
         5FpgcIM4elIHD2E842RiFOMt3E4bulNnK6KC60y3bzTuC1bX6I6H+6/KChPoIQXD3uHo
         gERaYabR4nHNtSPuwwpPfFV5zlFKm5iQaLqmSFOUbpLPCIw4GjPxzZZNpMmyV17YzBVS
         TLbpIcCPN7Wt4TGz+fHaVczcPU4rewcadL8v+Br9EqQiKlVILwmF4VXhqqRAXT9Baubj
         Sr8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5305bX54jL6hwH2Xz8rq35Lx6/IebqIJ5syjFNDxPNFPMOCfbGHL
	gB4P+rk+ZNF6t2b7+mpFtCI=
X-Google-Smtp-Source: ABdhPJw25itqjJ4MQgLkqebLwGWWhDm8TIh41pVB7kCODlH6xgdVT7kLEbcniLLuLqqQT2bONvWvvQ==
X-Received: by 2002:a2e:8855:: with SMTP id z21mr12153042ljj.325.1593705178517;
        Thu, 02 Jul 2020 08:52:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7102:: with SMTP id m2ls1414323ljc.6.gmail; Thu, 02 Jul
 2020 08:52:57 -0700 (PDT)
X-Received: by 2002:a2e:4812:: with SMTP id v18mr17197123lja.353.1593705177855;
        Thu, 02 Jul 2020 08:52:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593705177; cv=none;
        d=google.com; s=arc-20160816;
        b=xZkwaQZRsDjWT7lF5BbMP+zDXghUSB0Uxa3z6Le56sE+O8HRLnNvVf3imF93HicpxC
         OeQAr7wdywtjQqD4/9YXy4ZfUWNH7L7dKP/fAi4+2cmbVOcn85xfaSg2kEIy7XkIGvkq
         KmHpRy2rwLcR+PTOrZHR7TQA0Ygyj7ANUUk5sobFNE9CSXeq9mQ296W2dXGojPct/oUR
         zUXg45caYtr89Qeb6WI9sdRZCOwG+wa5/aLAP352OurjMz5h4Fr/cFVJmQRrdYfnRJ6/
         SXtVLaS7+Tz/c/2yocbn+ZOyjPb+qhDnA4TxBKNcDEiS6m8wuEE86B1RHsgIz8/8xoWT
         NDsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X1hZZYHT2jx0soQwDY2Nw4ZNux9TK2TS4ou5sFWlySY=;
        b=zK8+30bTItVU5B/Y/3aLNC6QBcNsies4VDZe6krqUtSaWlfG81PqG6MapJpilQQdR1
         JwqVm13jxZtEAyoor6Hyk5TVzHdVJpqjHQ1ihL7eIZ+QdLaeYHwvFtVABliWIcbmepER
         Qw1AIakuLsk8s91gl+SPez0jWTPrls6e90TchvnM7oMd6FRKJqvcrO2RGdf6JXxrwEIE
         jMludHAOW0vIf0NBn8QC2Liz5bFxaZ7Fuf29MEBroD2uu2YGt7Eh1pPlDJFIbC1VAYFz
         Ztyn+Rv/pUtQbFkxjIyYDprU/pOJm+1kLjOOe4S4YkerGDsO/FmwgdR0MuOvxDHnYOoi
         CMHw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="KwW+/U9f";
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id o10si576534ljp.3.2020.07.02.08.52.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Jul 2020 08:52:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id q7so19620438ljm.1
        for <kasan-dev@googlegroups.com>; Thu, 02 Jul 2020 08:52:57 -0700 (PDT)
X-Received: by 2002:a2e:b88c:: with SMTP id r12mr16463205ljp.266.1593705177353;
 Thu, 02 Jul 2020 08:52:57 -0700 (PDT)
MIME-Version: 1.0
References: <20200629193947.2705954-1-hch@lst.de> <20200629193947.2705954-19-hch@lst.de>
 <20200702141001.GA3834@lca.pw> <20200702151453.GA1799@lst.de>
In-Reply-To: <20200702151453.GA1799@lst.de>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Thu, 2 Jul 2020 21:22:46 +0530
Message-ID: <CA+G9fYv6DfJB=DeQFVptAuaVv1Ng-BK0fRHgFZ=DNzymu8LVvw@mail.gmail.com>
Subject: Re: [PATCH 18/20] block: refator submit_bio_noacct
To: Christoph Hellwig <hch@lst.de>
Cc: Qian Cai <cai@lca.pw>, Jens Axboe <axboe@kernel.dk>, dm-devel@redhat.com, 
	open list <linux-kernel@vger.kernel.org>, linux-m68k@lists.linux-m68k.org, 
	linux-xtensa@linux-xtensa.org, drbd-dev@lists.linbit.com, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, linux-bcache@vger.kernel.org, 
	linux-raid@vger.kernel.org, linux-nvdimm@lists.01.org, 
	linux-nvme@lists.infradead.org, linux-s390@vger.kernel.org, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="KwW+/U9f";       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Thu, 2 Jul 2020 at 20:45, Christoph Hellwig <hch@lst.de> wrote:
>
> On Thu, Jul 02, 2020 at 10:10:10AM -0400, Qian Cai wrote:
> > On Mon, Jun 29, 2020 at 09:39:45PM +0200, Christoph Hellwig wrote:
> > > Split out a __submit_bio_noacct helper for the actual de-recursion
> > > algorithm, and simplify the loop by using a continue when we can't
> > > enter the queue for a bio.
> > >
> > > Signed-off-by: Christoph Hellwig <hch@lst.de>
> >
> > Reverting this commit and its dependencies,
> >
> > 5a6c35f9af41 block: remove direct_make_request
> > ff93ea0ce763 block: shortcut __submit_bio_noacct for blk-mq drivers
> >
> > fixed the stack-out-of-bounds during boot,
> >
> > https://lore.kernel.org/linux-block/000000000000bcdeaa05a97280e4@google.com/
>
> Yikes.  bio_alloc_bioset pokes into bio_list[1] in a totally
> undocumented way.  But even with that the problem should only show
> up with "block: shortcut __submit_bio_noacct for blk-mq drivers".
>
> Can you try this patch?

Applied your patch on top of linux-next 20200702 and tested on
arm64 and x86_64 devices and the reported BUG fixed.

Reported-by: Naresh Kamboju <naresh.kamboju@linaro.org>
Tested-by: Naresh Kamboju <naresh.kamboju@linaro.org>

>
> diff --git a/block/blk-core.c b/block/blk-core.c
> index bf882b8d84450c..9f1bf8658b611a 100644
> --- a/block/blk-core.c
> +++ b/block/blk-core.c
> @@ -1155,11 +1155,10 @@ static blk_qc_t __submit_bio_noacct(struct bio *bio)
>  static blk_qc_t __submit_bio_noacct_mq(struct bio *bio)
>  {
>         struct gendisk *disk = bio->bi_disk;
> -       struct bio_list bio_list;
> +       struct bio_list bio_list[2] = { };
>         blk_qc_t ret = BLK_QC_T_NONE;
>
> -       bio_list_init(&bio_list);
> -       current->bio_list = &bio_list;
> +       current->bio_list = bio_list;
>
>         do {
>                 WARN_ON_ONCE(bio->bi_disk != disk);
> @@ -1174,7 +1173,7 @@ static blk_qc_t __submit_bio_noacct_mq(struct bio *bio)
>                 }
>
>                 ret = blk_mq_submit_bio(bio);
> -       } while ((bio = bio_list_pop(&bio_list)));
> +       } while ((bio = bio_list_pop(&bio_list[0])));
>
>         current->bio_list = NULL;
>         return ret;

ref:
https://lkft.validation.linaro.org/scheduler/job/1538359#L288
https://lkft.validation.linaro.org/scheduler/job/1538360#L572


- Naresh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYv6DfJB%3DDeQFVptAuaVv1Ng-BK0fRHgFZ%3DDNzymu8LVvw%40mail.gmail.com.
