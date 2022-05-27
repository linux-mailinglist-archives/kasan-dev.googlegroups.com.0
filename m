Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBQFDYOKAMGQECTMJB6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C4B7153634C
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 15:27:28 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id r186-20020a1c2bc3000000b00396fee62505sf3210175wmr.0
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 06:27:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653658048; cv=pass;
        d=google.com; s=arc-20160816;
        b=LuR8JevHbf+fJCKcgbxKeshSM5WZAxOs0Z3Lnkst3ggqZLocJH2f+Bf+WrglL/EBU7
         2rrKe0/zMFeIE5QubEmUBofcgxg2zZh73IrX+IbXymE98W4m3A3fgdwIxFWn+U1Uva2G
         MYMczDnz+5gDxQNGBdC82UCF4i/VeIrJdsKVyACLSJRa5kQMOvtTSnhZIXXnfzGfKfK9
         KJs9j/8jA1UWB6R4V+V6RZXIfBThP3GMqavBqqqgCXb670ngXNBKqG9ZsyGtiJt+W9s5
         gqCEIQu76BoCS4MlShazadNq7sJUzxvy1sgRxa25D7F5Dd0a/tJogsu95rOLQT5Zki8x
         E1BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=trSfZxb6UcihS+YSaEOjRb0JNb6gfTrYEcAgyXnEJtU=;
        b=yyygd6VImDZkMei8C6kwGIRckS0WpijRca2W0M1hw8MPcfMqYFroo6ygRQvrAhuI8m
         FyHDc0dUKT3W4MNYL+PZEDDhx+KfgOhYAHP4X/KlR2zIJbP+qn3VqS31G4WtHXSQu2bL
         iVbNriu+Yu2C6H3LUwo7Hz0SgCVSW09WHTwgJPfdqqdRlcWBX4RkpuoDA9+uq4T4/g25
         rPePvKQ2u3+N+NYpbDM638BQjwyIcSw+9VvjyYn/+MW5Vx2SOiOfgLG1Y2Us88TehKTX
         a2M7akhZqNVSl/N1w0ZqEB8Sd/nfJHzNZeS3aKZf37jL4fJ1BjMhjXR7KDDnZ7RPh0Ze
         SdKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=eCtkbn6u;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=trSfZxb6UcihS+YSaEOjRb0JNb6gfTrYEcAgyXnEJtU=;
        b=e5NL8C09d9LHt69V9ckYz56Ryaf80naS2F48ODKMJsLLGMkOWb/LUI8YQnxU/kg+eu
         /QpfaIUnXeTBDU7v9GxDVfzoeiC76oO9RtOrscIRBmuJx9QfCTyQNQKesWeQVWUTguQa
         /k56lonhAe8NNyn83SDloN3bk0SraM86XbKOuGL/xVRyzGSuOx1TI2sZuaDV9ka6FJ/I
         Wa9UlUmPGtk2ijkOMbnjmEQi6gusEVi0zYkOfSbv/ly70sXnpA0RYk05ZfNUZQwKv2tA
         0BxxBgLemtBnEVzShzw5GP0oqDmY2g6f4PdyUq9ladrAObJUBOULTMrnzTVk0qyS+0qV
         Nn3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=trSfZxb6UcihS+YSaEOjRb0JNb6gfTrYEcAgyXnEJtU=;
        b=HI0VEWBF2uL3T71ZuTB0CGhYzETL44oQb/Zvy8rasWBYclZARyVtkjFEx5debaBorr
         +JRS1rA9d1PqSfm2GiOigMlfGMtaDNSLFnBiKAwEoNepN+Z7DXxvzTZkkeqQj8v4CErO
         O9rkxv02lg3aYxm7oR9zdMGDae+gAJgJyxT46QIo0G/tsrKEbDA4asyffo+2k5kpRlM9
         fWXAjeburh1lo3iDT4i1tLqGOn2SgnCDFGiUASd7ymdg7mm3Ns9YF5cHngazbCkZmVB3
         12z/3EjyzRZ7iNMHaf1H/QGN9I7YbF+M4COfI61jou4g1ODNR6WgI06lV8oCghftKIXO
         ORsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Lrtcmf2gHAdWuSHSvkCfuVsyFAd+tlPQxWeWpON51hqHSHzni
	xk8Z5FaeWz0MjLOzeOgak50=
X-Google-Smtp-Source: ABdhPJyRM/hXDRKaPL63/PH/mnJgxouByu2yee3Vl7V2vTrYIYPqjhpuTYuHw8kGjKtW4pfShggoIg==
X-Received: by 2002:a05:600c:268a:b0:397:48d4:f6ad with SMTP id 10-20020a05600c268a00b0039748d4f6admr7173113wmt.134.1653658048379;
        Fri, 27 May 2022 06:27:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f0e:b0:396:fee5:f6f1 with SMTP id
 l14-20020a05600c4f0e00b00396fee5f6f1ls5992625wmq.1.gmail; Fri, 27 May 2022
 06:27:27 -0700 (PDT)
X-Received: by 2002:a1c:acc4:0:b0:392:9dd4:fbcc with SMTP id v187-20020a1cacc4000000b003929dd4fbccmr6888246wme.78.1653658047425;
        Fri, 27 May 2022 06:27:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653658047; cv=none;
        d=google.com; s=arc-20160816;
        b=PkJU1XVM3UxC0W8EXdhE+lh9wiVGtO8gfhksep76n4x4c0xH+ENqce5ZHWw0jD7tc6
         Rg3bbgvv9od45caXuArz6WxDWEpLdmanP24l3K8bZGs8ZCN092R5njMbiD76LCN8e6Dj
         K3ktxXEQN/0YEcaiNmfQnybN2iNj07P/NkCiqxWRH7ZXe+juWDM97HZupliCbTtEIYep
         Zsuh4fv3mt9LJxkugu4hZB8NhCg5j8yMOe6s6d6mWTnCS3m0mJWdUpCdrJUMqq8qK6tk
         JgVoK3MJFTzl9m5K5KucKWYv9RfvurWCrC87HySnKFBtRM/2sOEqY7yoCEeO1QPD/j9W
         wJcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=dJg7G2nPL/gjA12rwYq4JM6XgoNicJnOgK9xyJkk0Gg=;
        b=ZaIsH6Yx+yoMf561OT5X0ws3RsY6aM30Sekr5zgJJPmkiV99u/0J24vFPsIz45C/uO
         ZbFtxvJcfoTKZGS+Rsb/2zfxJ3hNPgp+7gb2+nr1HfCT+Y0XJMD+84sajssj69dlridC
         dr0m/vg8yfdP3GsvUECGYge2S7fSRO2JWW44iB4pPa3g1BhaWYhYS/ZY9fSZvslm/TBB
         NU2KRx5qb3pnifoVbK3Tpp3XbBklmSsHmbNFG9U38Nm0aIwVZvK/x+f2vYat4zIEyTf4
         4j7QZuPB1lGkM9b+l320uxk5/t/0iixLRQ5jVx6v53+fWpb1IbRJg8da0966XO77pj+L
         oXuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sipsolutions.net header.s=mail header.b=eCtkbn6u;
       spf=pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id u9-20020a05600c19c900b0038e70fa4e56si558771wmq.3.2022.05.27.06.27.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 27 May 2022 06:27:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.95)
	(envelope-from <johannes@sipsolutions.net>)
	id 1nuZzw-0063Un-KX;
	Fri, 27 May 2022 15:27:24 +0200
Message-ID: <134957369d2e0abf51f03817f1e4de7cbf21f76e.camel@sipsolutions.net>
Subject: Re: [RFC PATCH v3] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: David Gow <davidgow@google.com>, Vincent Whitchurch
 <vincent.whitchurch@axis.com>, Patricia Alfonso <trishalfonso@google.com>, 
 Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com,  Brendan Higgins
 <brendanhiggins@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
 linux-um@lists.infradead.org,  LKML <linux-kernel@vger.kernel.org>, Daniel
 Latypov <dlatypov@google.com>
Date: Fri, 27 May 2022 15:27:23 +0200
In-Reply-To: <CACT4Y+bhBMDn80u=W8VBbn4uZg1oD8zsE3RJJC-YJRS2i8Q2oA@mail.gmail.com>
References: <20220525111756.GA15955@axis.com>
	 <20220526010111.755166-1-davidgow@google.com>
	 <e2339dcea553f9121f2d3aad29f7428c2060f25f.camel@sipsolutions.net>
	 <CACT4Y+ZVrx9VudKV5enB0=iMCBCEVzhCAu_pmxBcygBZP_yxfg@mail.gmail.com>
	 <6fa1ebe49b8d574fb1c82aefeeb54439d9c98750.camel@sipsolutions.net>
	 <CACT4Y+bhBMDn80u=W8VBbn4uZg1oD8zsE3RJJC-YJRS2i8Q2oA@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.44.1 (3.44.1-1.fc36)
MIME-Version: 1.0
X-malware-bazaar: not-scanned
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sipsolutions.net header.s=mail header.b=eCtkbn6u;       spf=pass
 (google.com: domain of johannes@sipsolutions.net designates
 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=sipsolutions.net
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

On Fri, 2022-05-27 at 15:18 +0200, Dmitry Vyukov wrote:
> On Fri, 27 May 2022 at 15:15, Johannes Berg <johannes@sipsolutions.net> wrote:
> > 
> > On Fri, 2022-05-27 at 15:09 +0200, Dmitry Vyukov wrote:
> > > > I did note (this is more for kasan-dev@) that the "freed by" is fairly
> > > > much useless when using kfree_rcu(), it might be worthwhile to annotate
> > > > that somehow, so the stack trace is recorded by kfree_rcu() already,
> > > > rather than just showing the RCU callback used for that.
> > > 
> > > KASAN is doing it for several years now, see e.g.:
> > > https://groups.google.com/g/syzkaller-bugs/c/eTW9zom4O2o/m/_v7cOo2RFwAJ
> > > 
> > 
> > Hm. It didn't for me:
> 
> Please post a full report with line numbers and kernel version.

That was basically it, apart from a few lines snipped from the stack
traces. Kernel version was admittedly a little older - 5.18.0-rc1 + a
few UML fixes + this KASAN patch (+ the fixes I pointed out earlier)

I guess it doesn't really matter that much, just had to dig a bit to
understand why it was freed.

johannes


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/134957369d2e0abf51f03817f1e4de7cbf21f76e.camel%40sipsolutions.net.
