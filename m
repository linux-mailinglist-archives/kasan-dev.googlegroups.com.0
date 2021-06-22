Return-Path: <kasan-dev+bncBCII7JXRXUGBBHFAZGDAMGQEJV4VNSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EA853B0F2E
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 23:03:25 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id e17-20020ac254710000b029031b81f01389sf84989lfn.14
        for <lists+kasan-dev@lfdr.de>; Tue, 22 Jun 2021 14:03:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624395805; cv=pass;
        d=google.com; s=arc-20160816;
        b=T89+IEF5eU85jP+hPnCNYERQnsmlR2Q6F00vwCntaGshlqT5lnM8rWQjFzhE3nWE7t
         1bMupvwVFPBjdhYWkhbg8BarNxOyNnFy2afl5sIHudRE9ASglbzIezWFmVfjr1YsDold
         9oCDKMXvCBKcPLAT+JAI2jxXXoKxVsWdR9+0PtkFzCU7ccmFYLiiJJfOFnvbNHDfHStA
         hmBNYgiW/Sg+v8WSUZG5b+wCTVaFFFTUQOksY23ETEDe8krZPCfs1ULuAO5r0cpBLCta
         1gLU1RI03OTglFbPBFLXx+A5orx2ELvgWSPBuc7OT2xQIlYhNuklvkPlI3uSlYb9o/nV
         NIXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=S6QqxH/F9ZRSU+yxbpm4RV8m3BKPEAgDaJTO7TzhweE=;
        b=uTc+oXOksW2LYRRm3tNEdyRjCT6WYbkH+6R//n++fxy5kk2ByBPMhENnlVdk9RehZ3
         +YA2sVG2cZ0qGlU2ktnE2rs5/OzCBe3ZnBI17NszPBP8aPWeqX4pthrRKDCo6WzM/1rf
         lwYiqIcPCGQsVRZ2S1ZXr5Bwj9cSanbg/YQ277swiW8DDy4oHgW4TgA/FzX8RTnAT27P
         OMQzFgkj6/Q9u70UzgVw/jl/fUxSRcBK0iHASpzOVr9gvEraH2nlkyfFb+28hluQTslk
         rdFZuf0YxqXUzR8o5KUQVE8j8smvScXEsUHABH3miXeMdE5eZi6qkjsFyMYD3PZiApKj
         6hIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=TXisU0e1;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=TXisU0e1;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=S6QqxH/F9ZRSU+yxbpm4RV8m3BKPEAgDaJTO7TzhweE=;
        b=nJ5zp0KcZJv8bdip0dPlqdi6YstS+UBPQhdfqmm3qL93GivDmZTB2ZqrGkMt0F1+4n
         mWnhR+E34tQTqQw8nB8kQ9J1HP4ILJiEpSTUHaDPSv8mGWXHu6kvEBAk9svdNukF9EPe
         2XhC+bz04nh/rBtp5vuLdRcFoZXVLc59MhI4AsrFMaZiEETGBbN3Y1zQg5r3IxSei0t+
         XrOOZx/lsyQG1F16I8H1l6IRl0ea9MuMzYLHKhAWqfu4N7PHGv6x/BFRQhtNR3P5T9NH
         lZqWCItCqJyy/hrzSf68DmmcZ5vtwpOZlsUg+JcQYyO5WrtjQqVnW/q/1cdTglWi1jqg
         rs/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S6QqxH/F9ZRSU+yxbpm4RV8m3BKPEAgDaJTO7TzhweE=;
        b=UE7eEySEPcu6hBqfjG+N1+zx/ExDxC0XzXof6YPIOlVE1GATKccWsIGE2HhCBMEM25
         CFn+9trwOCcYHE8XxapCrkHajHt2nbfZAAyn9okFAFWoY8fgQ1IvaszXHkToNFI6cPQ9
         uc8yln0qygL++7k5E3cvsuNpzjO0+21kiMnO1uvyMVtjBO5R35iwPTnC3dcRcq4uL1Zv
         Sq7UnWsbqBFtqmqJOA2jremk484ixD38VJ6qU9/XQ2PYmeJqfy30az4VueyMN75JS21m
         SaQYq7wOLqhcZmoxjXXTGeCXxtrrOcnEQTRtrgBQHEbWHOltJ8VmSHew5c5i+mYW+ocR
         Wkdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ATATObae5X0yFqmRW1lQnLQT27fePpVfKLOvi7gyx4K3kQ9dZ
	hwRqGzDZe58v68rstqLIkjg=
X-Google-Smtp-Source: ABdhPJzrpPZchLp5KvpPMnL32DmxTZvU+RYV30diJ5Z1h2Nnzje9BBqLB6fj6/eBM+Rwp5z98Kf0bw==
X-Received: by 2002:ac2:4aca:: with SMTP id m10mr4335568lfp.56.1624395805069;
        Tue, 22 Jun 2021 14:03:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b09:: with SMTP id u9ls1436lji.9.gmail; Tue, 22 Jun
 2021 14:03:23 -0700 (PDT)
X-Received: by 2002:a2e:9e41:: with SMTP id g1mr4852531ljk.471.1624395803637;
        Tue, 22 Jun 2021 14:03:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624395803; cv=none;
        d=google.com; s=arc-20160816;
        b=FTry6jsCWRYAZbZViLQcWo2xx+YVdlC42yu9H+LS3J/3rKLzPzrfVUlsKU2DXeqEh/
         UzHYr0ZGfbY3Io00bqRmDDA7sMGSaBFQ+MK/EmmW0lfUq+2p/hV5dxoTb7MoogQFZbdd
         RMBkEWq4OBIj4uJ5lxTzcbVZs1KKdmSPV4nV8O+H+0Ozmt3rsvt9bSmMY7Rqns1hmWl3
         ifBCi7g5vWjVpjZpZIeF+txmg13HKN0c/B4Jba8alC1ACtvVmiEoYBfQDW84ZSyWtjJm
         6agSwVMKphVAfAb2YlwsOJgUAVOMYIJmr5m0SlKJLhrsuNIxXQKlVA+flp2hC+vLuCbl
         tVFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature:dkim-signature;
        bh=HMR4unNIvosEkM7YP6TmchXmd0KH3uqdRi9sNvieci0=;
        b=dJan6ccg0c7P4xbEy9sqsqlUcPW/paWEiiLwtNIhLhn2gx5G5PQmk2Ke+kYTYY2s1W
         kSFts4QEmBOgO0ULAJJJd1njGIrpXQSg6WU6OvPQ9Vyg5Eab8bUTljfH0NUbgFv4E/7Y
         g9HQFqjSZiS63Pl7LOyjER1oandFSM3s32Y729ZBvV1DHV3iMlrUsecg9un5eoOnvxlL
         3F6ax6HwbNtD4T3bElsIgMvcjaAgPU620fOpg+a+7fJhLuxj+cy6eJ+jcpf8SoVkMHW1
         7YSwPjfbjaOMI5pOj8AU3ZBQuWFoq646tcGz5gdxRpHI5Qk2OHjFbICof4aol+fyueAz
         BsKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=TXisU0e1;
       dkim=pass header.i=@codewreck.org header.s=2 header.b=TXisU0e1;
       spf=pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) smtp.mailfrom=asmadeus@codewreck.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
Received: from nautica.notk.org (nautica.notk.org. [91.121.71.147])
        by gmr-mx.google.com with ESMTPS id d7si148288lfn.7.2021.06.22.14.03.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 22 Jun 2021 14:03:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as permitted sender) client-ip=91.121.71.147;
Received: by nautica.notk.org (Postfix, from userid 108)
	id BA736C01D; Tue, 22 Jun 2021 23:03:22 +0200 (CEST)
X-Spam-Checker-Version: SpamAssassin 3.3.2 (2011-06-06) on nautica.notk.org
X-Spam-Level: 
X-Spam-Status: No, score=0.0 required=5.0 tests=UNPARSEABLE_RELAY
	autolearn=unavailable version=3.3.2
Received: from odin.codewreck.org (localhost [127.0.0.1])
	by nautica.notk.org (Postfix) with ESMTPS id C7643C009;
	Tue, 22 Jun 2021 23:03:20 +0200 (CEST)
Received: from localhost (odin.codewreck.org [local])
	by odin.codewreck.org (OpenSMTPD) with ESMTPA id 963b3b99;
	Tue, 22 Jun 2021 21:03:16 +0000 (UTC)
Date: Wed, 23 Jun 2021 06:03:01 +0900
From: Dominique Martinet <asmadeus@codewreck.org>
To: jim.cromie@gmail.com
Cc: kasan-dev@googlegroups.com, v9fs-developer@lists.sourceforge.net,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [V9fs-developer] KCSAN BUG report on p9_client_cb / p9_client_rpc
Message-ID: <YNJQBc4dawzwMrhn@codewreck.org>
References: <CAJfuBxxH9KVgJ7k0P5LX3fTSa4Pumcmu2NMC4P=TrGDVXE2ktQ@mail.gmail.com>
 <YNIaFnfnZPGVd1t3@codewreck.org>
 <CAJfuBxywD3QrsoGszMnVbF2RYcCF7r3h7sCOg6hK7K60E+4qKA@mail.gmail.com>
 <CAJfuBxw-JUpnENT9zNgTq2wdHqH-77pAjNuthoZYbtiCud4T=g@mail.gmail.com>
 <CAJfuBxxsye593-vWtXz5As0vBCYEMm_R9r+JL=YMuD6fg+QGNA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAJfuBxxsye593-vWtXz5As0vBCYEMm_R9r+JL=YMuD6fg+QGNA@mail.gmail.com>
X-Original-Sender: asmadeus@codewreck.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=TXisU0e1;       dkim=pass
 header.i=@codewreck.org header.s=2 header.b=TXisU0e1;       spf=pass
 (google.com: domain of asmadeus@codewreck.org designates 91.121.71.147 as
 permitted sender) smtp.mailfrom=asmadeus@codewreck.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=codewreck.org
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

Hi,

let's keep the lists in Cc :)

jim.cromie@gmail.com wrote on Tue, Jun 22, 2021 at 02:55:19PM -0600:
> heres a fuller report - Im seeing some new stuff here.

Thanks, the one two should be the same as p9_client_cb / p9_client_rpc
and p9_client_cb / p9_virtio_zc_request are very similar, and also the
same to the first you had, so the patch didn't really work.

I thought after sending it that it probably needs to be tag =
READ_ONCE(req->tc.tag) instead of just assigning it... Would you mind
trying that?

> Im running in a vm, using virtme, which uses 9p to share host filesystems
> since 1st report to you, Ive added --smp 2 to my testing, it seems to
> have increased reporting

I'm ashamed to say I've just never tried KCSAN... I can give it a try over
the next few weeks* if that patch + READ_ONCE doesn't cut it

(*sorry)

Thanks,
-- 
Dominique

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YNJQBc4dawzwMrhn%40codewreck.org.
