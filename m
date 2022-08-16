Return-Path: <kasan-dev+bncBDDL3KWR4EBRBZX252LQMGQEQ656ZXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 515FB595FA4
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 17:53:11 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id r67-20020a1c4446000000b003a5fa79008bsf684219wma.5
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Aug 2022 08:53:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660665191; cv=pass;
        d=google.com; s=arc-20160816;
        b=g1zozQmq/H1RnZmXPy4T6PLih4Yp2ROdcQXbnqQKuZPL9CqwvTg1XaFWGWhViUSbC1
         MjlZNajWP3S/+J0hq2aNE1Zmln+uU0Xvqe/BqX1VP1HVcgFB/lMXj3bZBEvateeecVkg
         koTx/TAn6Hu3W/gR7gJWR93aKFPToHJA8uPXaNlbvp3dWfM+zf5HUZsBkaT7kAVUK3DY
         ZiFuSrK2NxsT+4oar46b4iZXKglyXE9TG5FV92jS+BSIbt+YayliVRj78L37L2xNu1td
         0RGPKTVt4qGXa6co3K4RS5gbVHhoPQFqSShvFfEZSZ+I8qfy1L536tNP9HWj3bP4gfOX
         DkmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=HCoEn1HrA4CrucWysXVVRnCuFZPiqqXL6T/q1Bja93k=;
        b=PJnFIqfPKq71w0fL2HiMDs/EGTTVZeJ/XFwKF9phJ0ZfGrYLPfmC8ZMnM5LODj8Coo
         eBA9MFklsGdIRa0Xk+k/5xyO4cGAUHh7+DvM+rweH6QppTrpVttQY5cTp50aqKh7LEyM
         8e2dwDfGJyCXBpBeN1aeLAUTnzsZcrbeWNUIrsv3tMP7JvUdWQL2ITLFISom5dx2a07Y
         ZgArTCBy7f8T94PliCYMhbI2kABeOqsD/KC+5hKMUo08kaJPABjR2zkC4/Ah53c4y8+T
         JX2vbMUkXSJGWwe2mloqBUVePGX6t6PCUqf0mH7ke//wc82azEYSvH2aOGHXFFMoBMov
         AZug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=HCoEn1HrA4CrucWysXVVRnCuFZPiqqXL6T/q1Bja93k=;
        b=FZ4rt3nW16rlx4Zbot1ZbH+MY+8NFMdmOWF1k1CUHKqxOuKg2wwuJykJEJWNEp6aD4
         W9dT3yEvQjy/FyoGZE2ndcAE4QDV/4LKvFEgraDWlqqAYBI3jc2anHvdNLjF9h0kVAVh
         nFDO/vWhRHka9BqtFPGo40Q3tqSKvWU9caWl/ts6NSCJN6E608Rm6JlANhTrAVXeRNQH
         jKQqo8n1soZI04N0nWiCHOGZg6jx9PmzobdtBjjj4wW4/Rchyc/McdSfk3VhqAezQUOS
         InCyIdIAeNFY+Kj1guk+1xzA9iSGaAErNykngk7cK9xpNDSlLtusU9nDnJZgvcx821eH
         gUyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=HCoEn1HrA4CrucWysXVVRnCuFZPiqqXL6T/q1Bja93k=;
        b=yOY+deH7k767HtANeMr4wplZeUEUmIBIr6pes7FPIiIxD0Rs6+PeF1qreIahz5LMeR
         mgNFgYiKhAwc8dF2UChAO7MxehLnU07yI8q9nwf2xwmYr3i1CY0AicrcJxYUhF8yYfIu
         R/e5TFK/w5Kr8qqvKz1hrTnFTMvjbEF0l63ZW+Fgip/6vMvKTpxRlI8C8jkpQrHZzEdz
         EEGZzYzviLkjZGiCsYcLKl5eH82qMcNq0FPRp539Yigm2Th2rBd+SGwa4EUVRF0aXimX
         Re2P5xaCuiDu18J0PyGKfpwaEv8kkBKXDOeaU0DDUlmLK6l08mDF1q0gch8zFTcg3nWa
         DhZQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2iUEELhzgA9bpci+FkLb2WwarWKiB8QmSOOR5TMYhTl9RAd6fA
	9tH6YitczNCLzNyoxaFgRYM=
X-Google-Smtp-Source: AA6agR6X0vM6wWT0IyRLrTICGFcCGCVEPnOgt9OxwzcYgpqsmNrxbSl08GEscW4TXyvCgJJKvBsJmw==
X-Received: by 2002:a5d:6882:0:b0:225:20a0:99cb with SMTP id h2-20020a5d6882000000b0022520a099cbmr648900wru.368.1660665191044;
        Tue, 16 Aug 2022 08:53:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:3c1:b0:220:80cc:8add with SMTP id
 b1-20020a05600003c100b0022080cc8addls20140956wrg.2.-pod-prod-gmail; Tue, 16
 Aug 2022 08:53:09 -0700 (PDT)
X-Received: by 2002:a05:6000:1d8e:b0:225:142d:285d with SMTP id bk14-20020a0560001d8e00b00225142d285dmr2884615wrb.199.1660665189823;
        Tue, 16 Aug 2022 08:53:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660665189; cv=none;
        d=google.com; s=arc-20160816;
        b=YQymSf5J9khCyiDvtZgNKubdmqka+QBcP0E3O6xUdMASL+V+GA+dmgmOYVCakFF8cb
         k1uIoV9waBnooofsZq1UOiCOiAeWO6urqeBidWcAovZqQRbhHNs5H2zJx9BeVJ7NDU00
         xq/cLbIlrT2qIAAj5c+ilNe0cBDgFPZyRfFPEROp3q2XVtb2m3LsA/lqDM6LEksleNX6
         RpmVboNGi2viATrrKhHXBJQuPWRW9XaFBMzNmXVgJwsJfcXz4r29T601DzXGeKPiBdye
         pkyvirrCM5b6tuqqn36Mxk5vLlbGiJv51xy9x53Is4I9gOxhSzucB9AWlvJboq7IvDns
         AuFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=eEHh4vW3Bhqp5/cFSVweoDEYX5zKo0CMKVx7RyPJ30Q=;
        b=RAwDdYSgwsMNudQwNp9SKvu5HKe3/zXXlWxUKG0QehmobMszzMjKGH7nPnbQBpd+Ey
         gwd3yqLOtVjg1sctcUiV1stxfRc+3oa5pAyaMTj8BNg0+BXfEkyp4LJhfBqARiwRdjED
         BBpLYq2Yfp3X4OBbOOF6FFmytdwTWiSsyKATYuauZ30NqGbaALhUAAsNCsaQuWAr7tpD
         4Yt/2RGXHq8IMZ3sexaw498u8KTjMqHuTtPu7CVQzGDVE3rQiU51YnkWoMKHHtX0lxNH
         rBVbux84zwNKXLXhpaqEnI0fS7NAIhhTIW6gPSThm6kmwtbmWkhCHlHhxJ6sEfBl37Pf
         J4Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id 10-20020a05600c25ca00b003a5ce2af2c7si755830wml.1.2022.08.16.08.53.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 16 Aug 2022 08:53:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 7FC89B8188C;
	Tue, 16 Aug 2022 15:53:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4C1ABC433D6;
	Tue, 16 Aug 2022 15:53:06 +0000 (UTC)
Date: Tue, 16 Aug 2022 16:53:02 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>,
	Yee Lee =?utf-8?B?KOadjuW7uuiqvCk=?= <Yee.Lee@mediatek.com>,
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>,
	Max Schulze <max.schulze@online.de>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"naush@raspberrypi.com" <naush@raspberrypi.com>,
	"glider@google.com" <glider@google.com>,
	"dvyukov@google.com" <dvyukov@google.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: kmemleak: Cannot insert 0xffffff806e24f000 into the object
 search tree (overlaps existing) [RPi CM4]
Message-ID: <Yvu9XsVPXBKLTT7k@arm.com>
References: <b33b33bc-2d06-1bcd-2df7-43678962b728@online.de>
 <20220815124705.GA9950@willie-the-truck>
 <CANpmjNPrDW5FRf3PdzAUsjEtHgaWVTJ2CNr0=e732fEUf4FTmQ@mail.gmail.com>
 <SI2PR03MB57530BCDBB59A9E2DCE38DCA906B9@SI2PR03MB5753.apcprd03.prod.outlook.com>
 <20220816142628.GA11512@willie-the-truck>
 <CANpmjNMd=ODXkx37wqYNFhivf_oH-FSo+O4RDKn3wV14kCe69g@mail.gmail.com>
 <Yvu4bBmykYr+0CXk@arm.com>
 <CANpmjNMwUKwmOh86p3HnXiU7zLiXvrc8FF5bFHtVAHn=GdaX0g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMwUKwmOh86p3HnXiU7zLiXvrc8FF5bFHtVAHn=GdaX0g@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Tue, Aug 16, 2022 at 05:46:43PM +0200, Marco Elver wrote:
> On Tue, 16 Aug 2022 at 17:32, Catalin Marinas <catalin.marinas@arm.com> wrote:
> [...]
> > > Right, looks like the kfence fix didn't need to be in 5.19. In any
> > > case, this patch I just sent:
> > >
> > > https://lore.kernel.org/all/20220816142529.1919543-1-elver@google.com/
> > >
> > > fixes the issue for 5.19 as well, because memblock has always used
> > > kmemleak's kmemleak_*_phys() API and technically we should free it
> > > through phys as well.
> > >
> > > As far as I can tell, that's also the right thing to do in 6.0-rc1
> > > with 0c24e061196c2, because we have the slab post-alloc hooks that
> > > want to register kfence objects via kmemleak. Unless of course somehow
> > > both "ignore" and "free" works, but "ignore" just sounds wrong in this
> > > case. Any thoughts?
[...]
> > In general, if an object is allocated and never freed,
> > kmemleak_ignore*() is more appropriate, so I'm more inclined to only
> > send your kmemleak_free_part_phys() fix to 5.19.x rather than mainline.
> 
> So it sounds like we should just ask stable to revert 07313a2b29ed
> then, if the patch switching to kmemleak_free_part_phys() should not
> go to 6.0. Is that the most reasonable option? If so, I'll go ahead
> and send stable the email to do so.

Yes, I think the revert is probably better.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yvu9XsVPXBKLTT7k%40arm.com.
