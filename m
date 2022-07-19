Return-Path: <kasan-dev+bncBCT4XGV33UIBBNXV3SLAMGQEX63F2EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E1D457AA50
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Jul 2022 01:14:00 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id a8-20020a25a188000000b0066839c45fe8sf11968210ybi.17
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 16:14:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658272439; cv=pass;
        d=google.com; s=arc-20160816;
        b=CJyY/jBDlhxvfrZDemWCsg8SVucOv1vr9IKheNpo1KD7oSeVLC8nf2adG0sin+HkMt
         kWn7ndp2pkbqetcHJAKkzi0Zdj2NfY71RldXF+gEp2edtGCwkdn68LMvLtktvQSLf5Hi
         CnLy5E0nZRYzh+xGMPkvq5baYV3hWhHCYi7l4gEIPt0dAoioZ561w2uA0mwplN/SXX5O
         9CujOejY8ZB36mEiUO1UntiSnvFA3NQPtBC2zIqiWF+ZIzYADtGlMX4eFFXjQZoBmVU/
         bg11MQHDiD3IIoqvL+wwcNlre+oGCYKEKXkwFKrbsQeWXyObozkGest/eCex8btkEz2M
         cMYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=bpdo5AG4MW3X3tAZG1Z8qJtqm7M6uNmstcHiMDPuJNw=;
        b=TRwdrdAjfLnnDVEo11gy4hq/K9z+ItnPM9UNoiw1iCB393nF6Jkl6uiu+6ykjhiJzs
         Z9JM3yeWtXgsRxqcWY+LV9UQoGYc8jI+TwZ6co/BfxjG/LwUDfT9peSOYCpMCT62IqKL
         ifmCgjxK5qpnCAP+G7rT9hksWX1Q720vY1SyU4qBNq7Lyiml7UTdPfRK3H5f8yeysUTw
         z989Ehw27HZxVA4Xq9OnPlwboTuxpQWm00Li8aqrnjT9KIWgPKENnm/X1pECVznjemCu
         PJUpKoPFtIDpX+pQHkN0EGdXP6maHA3oYcQrncpkzvt0l3D/89JyZ0NxyC2zY+DP3BMD
         jy+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=vS3AUKty;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bpdo5AG4MW3X3tAZG1Z8qJtqm7M6uNmstcHiMDPuJNw=;
        b=pyfLlpqhmiBVmn2tD+JSwTggXGAXN4oRt8WjIh9uIyzD9/s2y28AlMVMyVgNLmJ5+G
         dEBugZryLvFBpAzLFAN7yshyGlFFTsLrahqLewJpW+Y6SZ4tXfNZ0Zs0Q4Du9lY7AffA
         i1prNm3cC20wX3+b/Rav5t6iItmOymD26XTHhvefX+eBAuSHcsjMj0xPnNn4iM2u7fBG
         UCxmnIc64iwllcNU7w0W9sKXY9v0GQR6Mrff7yJ5qfkTsMNHBbVlecYgZk7aFMIBMPOm
         h1/qMIndOCWiwFYuoZlCt50MDb0BMxxDqNN3OOLuVlmf6ULdxy1uuth1Sr16yXcaxX7o
         nsmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bpdo5AG4MW3X3tAZG1Z8qJtqm7M6uNmstcHiMDPuJNw=;
        b=WQ/dWc7UF0hOoKKStKwGc2M1dCaNS2Ko7CKLVHWK1uNOS0W7j2yDH9Wh2a3FyfW6tR
         D6rtuFOFyD219zsNsU2ziuYSnnCuMUwQpaFFMlBIjxRsB6xSvRkTXd+hlIvZ1w1nQ9HD
         pagB1FudpQg5QsI0/qnB7IoV4p/cQiPd7PXI47HHVnhQXbqgZ7H3791uvZTeI+TbP/2m
         OV6KCFfgtUs9WLbTmgxXpoAKv+/wa2rRqdwRkHmjVGOUxB1Txt3ZwsXUW/+2ancawyb4
         Dtgumkb59vFg1iBp0NkkbEQeZ+cmtFYmoDBVIw+JFOARZ6wcdVl+OJbS3p8HPvPgbRMe
         kdSg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora//Rx+dS/l0+cqlhbzX6XKPaTPVSiLPJxSIgXbCbea5M4Ljb/Go
	wEI3N576A7fbMOrBcYkr1Zk=
X-Google-Smtp-Source: AGRyM1tL+mMW5/rRtXz9Reh3tu8O4wcYDsLJQlxNXYoUKKfk+fCkRihZSCh5xv6uddsVEjLnPAFwmA==
X-Received: by 2002:a05:6902:110e:b0:66d:e6dc:5f31 with SMTP id o14-20020a056902110e00b0066de6dc5f31mr35159159ybu.628.1658272438875;
        Tue, 19 Jul 2022 16:13:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:a101:0:b0:2ff:2e35:3394 with SMTP id y1-20020a81a101000000b002ff2e353394ls63557ywg.9.-pod-prod-gmail;
 Tue, 19 Jul 2022 16:13:58 -0700 (PDT)
X-Received: by 2002:a81:f82:0:b0:31c:f1ae:1ed6 with SMTP id 124-20020a810f82000000b0031cf1ae1ed6mr38471776ywp.249.1658272438321;
        Tue, 19 Jul 2022 16:13:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658272438; cv=none;
        d=google.com; s=arc-20160816;
        b=gGKktUX0sHd913DCo0qmoGe3Nrs50B2rPc4ooVXssDU0M9J49tdh5WfwtFVAHLeo5/
         y/B5WjQoq9ZMTNl0Xw9gjn7WAraw7GSJNFI7kPfVGe6G2d/g5nBWcjCVHipEEKpy8aLh
         YrXrD/0xg4yf1mqCMg7/r0zLW2AF6iTvge4tk+obOwx1LMyRMsNZ5IyPxyJ4kSkRaZbS
         IF3LSvlrHbCsIHqfceJGP7dFShyKLzeO/60dbYAbzMFAryEJV0qysttMndW/+5hMfruR
         JR/W+JDvXxb/loYXKqSIGvUngqpFUqk4pIN9WloG2+YacNS1+nyKrcQCpoRP6c7UzHy8
         r+SQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=uAsVG6vHuHUdQms58NLVb9AElblSH0zMsR0cP5n0bt4=;
        b=GGZ1N11ziHv9LJ9CjV9k4b1/DaHGNj1g4ZNfQbGutbMRshNWWBYb05E3nIAUNIZqaR
         iEuSHOtl49YxmgUOQ2Ti8duwZB+U8v6VeUM2muFNm+RnJQMWWaZawvbHKEH0Ls2RCaAz
         3vZD6KPQB6BeyXGVhTNkesy6q8c49fO2Y3csaXAz569f4x81/SGDclvTCcjkkxciiyJQ
         o+vN+z5em2LMXa3uXAZaJdn1h6sWFhaFo14Zrhf03HWx3R7Txc+VHH2luS84Tn4jCeX7
         HaDHyJFC0vx4RAhfeMY0itpfKGo+NFqCA7sOo8u+zKRgw1QV9x1s9PVm/E4cUTtwFSmJ
         W0dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=vS3AUKty;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id bp12-20020a05690c068c00b0031dc9797edasi543594ywb.0.2022.07.19.16.13.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 19 Jul 2022 16:13:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DF39C60E08;
	Tue, 19 Jul 2022 23:13:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D6B1FC341C6;
	Tue, 19 Jul 2022 23:13:56 +0000 (UTC)
Date: Tue, 19 Jul 2022 16:13:56 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Marco Elver <elver@google.com>
Cc: Geert Uytterhoeven <geert@linux-m68k.org>, yee.lee@mediatek.com, Linux
 Kernel Mailing List <linux-kernel@vger.kernel.org>, Catalin Marinas
 <catalin.marinas@arm.com>, Alexander Potapenko <glider@google.com>, Dmitry
 Vyukov <dvyukov@google.com>, Matthias Brugger <matthias.bgg@gmail.com>,
 "open list:KFENCE" <kasan-dev@googlegroups.com>,
 "open list:MEMORY MANAGEMENT" <linux-mm@kvack.org>,
 "moderated list:ARM/Mediatek SoC support"
 <linux-arm-kernel@lists.infradead.org>,
 "moderated list:ARM/Mediatek SoC support"
 <linux-mediatek@lists.infradead.org>, Dave Hansen
 <dave.hansen@linux.intel.com>
Subject: Re: [PATCH v2 1/1] mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool
Message-Id: <20220719161356.df8d7f6fc5414cc9cc7f8302@linux-foundation.org>
In-Reply-To: <CANpmjNPhhPUZFSZaLbwyJfACWMOqFchvm-Sx+iwGSM3sxkky8Q@mail.gmail.com>
References: <20220628113714.7792-1-yee.lee@mediatek.com>
	<20220628113714.7792-2-yee.lee@mediatek.com>
	<CAMuHMdX=MTsmo5ZVa8ya3xmr4Mx7f0PB3gvFF42pdaTYB6-u5A@mail.gmail.com>
	<20220715163305.e70c8542d5e7d96c5fd87185@linux-foundation.org>
	<CAMuHMdWSsibmL=LauLm+OTn0SByLA4tGsbhbMsnvSRdb381RTQ@mail.gmail.com>
	<CANpmjNPhhPUZFSZaLbwyJfACWMOqFchvm-Sx+iwGSM3sxkky8Q@mail.gmail.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=vS3AUKty;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Mon, 18 Jul 2022 16:26:25 +0200 Marco Elver <elver@google.com> wrote:

> On Sat, 16 Jul 2022 at 20:43, Geert Uytterhoeven <geert@linux-m68k.org> wrote:
> [...]
> > > - This patch has been accused of crashing the kernel:
> > >
> > >         https://lkml.kernel.org/r/YsFeUHkrFTQ7T51Q@xsang-OptiPlex-9020
> > >
> > >   Do we think that report is bogus?
> >
> > I think all of this is highly architecture-specific...
> 
> The report can be reproduced on i386 with CONFIG_X86_PAE=y. But e.g.
> mm/memblock.c:memblock_free() is also guilty of using __pa() on
> previously memblock_alloc()'d addresses. Looking at the phys addr
> before memblock_alloc() does virt_to_phys(), the result of __pa()
> looks correct even on PAE, at least for the purpose of passing it on
> to kmemleak(). So I don't know what that BUG_ON(slow_virt_to_phys() !=
> phys_addr) is supposed to tell us here.
> 

It's only been nine years, so I'm sure Dave can remember why he added
it ;)

		BUG_ON(slow_virt_to_phys((void *)x) != phys_addr);

in arch/x86/mm/physaddr.c:__phys_addr().


This kfence patch does seem to be desirable, but we can't proceed if
it's resulting in kernel crashes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220719161356.df8d7f6fc5414cc9cc7f8302%40linux-foundation.org.
