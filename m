Return-Path: <kasan-dev+bncBD2NJ5WGSUOBBT6GQ32AKGQE3QH3MOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E43971975E9
	for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 09:44:15 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id t22sf6757441wmt.4
        for <lists+kasan-dev@lfdr.de>; Mon, 30 Mar 2020 00:44:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585554255; cv=pass;
        d=google.com; s=arc-20160816;
        b=f/vuWJGm9ZwCQntHcCYFPKdN9GiCW3sKx1isgXAPMq0Fs5YeL3Ig2swbRqAXMi4JIE
         Yw9yk601bLgE2LBBepBd5YqlaTu0Ulrn8qGpxFSWXhSIq88VpczQk57VWbPxIsz5zuvy
         Ufj1NoGNO5OGRDBtFAi0MjSFJNWK13Q++WoGWyv82vlT5DVMhZtLl/uWEfxIaE0FIN4x
         Aag/5v0szElUDX+ns8k4j9B4LLEfPPxRRhBz6380Qi84+VAYH6rLTL0EIf0TSohVOjB5
         Bbq9DGdZmPUR127DVIj/POlEV2ig52iOOZ36fOra8leBQkzfBwGtMLvuVg5Ds/QHxhgj
         DKDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature;
        bh=r0e0/qRyFRIo0Be0M3TfNYr/UyMInaNjZHdFqSV5YTg=;
        b=AhTGzB1xwHL4hz6co5N+/7jywn4RSz7kNj6KkPz7M/UNsrI4ywKFQ/v4j4DN4fLalc
         Sgv/yHjGJN/IqLv8ypC+gMU6xGIGepFBWRXmDPADwBdoDn0Wpq7QeE091o0EmxEWXp6U
         QaAKRwBVgS4LRz3n2PRWWmHDNW26aCOhRjXYP1hlV/mg1n+ZJGeGNpn8Ltn4k6WXE3lc
         bsBlowiB1jXS6xFxDlZ9IyysGYRmZNQgqBoVU8l4qBqrapkcRGLm57ybxNeRISHxxKZN
         BhRDXoXXwyIgmYq4brSjv3mL45hlhYislA+hrkavVhpnL7WYhrCdi1mB6x4pGg/kfswp
         Fzdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r0e0/qRyFRIo0Be0M3TfNYr/UyMInaNjZHdFqSV5YTg=;
        b=DcehFiaVYhgcOgRinB9vq8aHJxvJIYs0KgHvhFhZfuFJoin2HdZVGzKOfJznMe1w0t
         arikvEYQQ4VrmqM4rhOwVOq7PVhRVYQwrDoTo6ts1czq1843jYgcGQiYx4Cw9Oojki8q
         RynA55xt9muT4q60IgIBoORXX4/ge81pX14Xk78ZIYEjeGzDL6QaazoQ4E4f8+taUoY8
         mTbT2hyWMa5vPIsZUitndAUwhMH3iQGJ2As0hWlEiMAvdkMckmSxkiwHMQRhoWDRZbQY
         Cbp+xqAl7XTXZZqLSlv3Dp5kfzhfr82PrbYqwMO/hk+mhySyy55C3RO65wonXmppK2j9
         OgPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r0e0/qRyFRIo0Be0M3TfNYr/UyMInaNjZHdFqSV5YTg=;
        b=LMZgSnyWXWY8E0pbDrxAC/xLBKi1qG6/gkph4BFzFTJpfD3h1YJaf0PmRQZYEuZ+BD
         u6zmawZqPLlOcCYRPK0T4q8yJQmhZhuSNe1VoJfszgl/FX8UuQlEcen/aaWH6ury6qXL
         XQbrZrHdrmkQUp+0n5r7m/ictv1Perfhk/kuq6Mh8qBGawa+dA2N0o7zz1+UAgrmia24
         hBchb3SSbD2/IcayZe9sFn6kZE+STzV0OyNLNRHwdn9kzO3C8engm03FDoqRPG0s4C1k
         2dTWBlf+CWWn3Ft9W+RgsGFTfSVSKI1uOTehE8r4EnlpP0KYLetmPeAci//JsLCz5BpG
         nRyA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1MKbCVjVeudhR0V/xhw2HszBkyYuDlulyKMF2KE20VcTosxkc5
	B3iLxsuXric/9MNbMwZo1IY=
X-Google-Smtp-Source: ADFU+vvExbSovt8x60iyzwOHXKB/oJXf23A3JBQmKEoB+I28x2Qxi8E6DyiqrL7ttuXOV8ursFUEpA==
X-Received: by 2002:a05:600c:a:: with SMTP id g10mr12002299wmc.153.1585554255629;
        Mon, 30 Mar 2020 00:44:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6302:: with SMTP id i2ls88506wru.4.gmail; Mon, 30 Mar
 2020 00:44:15 -0700 (PDT)
X-Received: by 2002:a5d:5704:: with SMTP id a4mr13963622wrv.95.1585554255057;
        Mon, 30 Mar 2020 00:44:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585554255; cv=none;
        d=google.com; s=arc-20160816;
        b=kLEeluh6+P5w63wPaeokwbUmjcamsRjYkPfxXlNxTpOrGgM3wAm4NsIm/r9xvbl8I4
         nXuxu2zsepx86spC8AduYmVtWfUl+14ecqbJ3zov0OyHf2XfR+W9AlAe9hgnGk553wTJ
         qYAKvmPXWNLI9H6bMzGxH+uYkp18XSO3tjqKeK5WW7vpOpPqeh7EJ8MHIorXnmj4VQRn
         wlCC4HBLHnOagok001+ILqlCCuThgIOMcXxzTXb4Pg3a2MXYzaCg6vqe1thVOOSAbUZg
         0RYdXk93tyol2DpscuZ3w+PFSJ+0PdQOaKDUR31NRm0EQymsGfiW99S+5JXPlhqFWRsy
         TqzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id;
        bh=yc8KTHIdvQBfHogvNTgmM53/K3cJ/2E75+k3B6XCLq0=;
        b=ctJORon2jp0UpEFtBCd06wv5jtfqtZUvfP4FUlGU+KpCboZvL4yyNraUVqKObtEk5B
         L2Umr2pQXJJYM/UeTM82JkEyAXTcQKYpCQkncq+BJQCzRV/Rwo60dlXc/oYhRbC0ktXb
         Az9vkzV9xCDS67ql4PkO7xyLEyhorAwQxL00nOTJHJC/gLhQmrk3vfdPRYoUYz6vShX5
         gklGDo2yBOdjo9CYC0iB9BoDK4CLaixx3qjoi/heCf88gt8v0ROJWb57xFWzAp//tlQC
         FRTmL1XXpXqJJkwVCFdSpfJrUF9Ci3h+IFLcWQVrnfVT+2CQs8NPe2H47I0H+KQ8hl4+
         qAHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
Received: from sipsolutions.net (s3.sipsolutions.net. [2a01:4f8:191:4433::2])
        by gmr-mx.google.com with ESMTPS id a18si626063wra.0.2020.03.30.00.44.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 30 Mar 2020 00:44:15 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of johannes@sipsolutions.net designates 2a01:4f8:191:4433::2 as permitted sender) client-ip=2a01:4f8:191:4433::2;
Received: by sipsolutions.net with esmtpsa (TLS1.3:ECDHE_SECP256R1__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.93)
	(envelope-from <johannes@sipsolutions.net>)
	id 1jIp5V-005JU9-00; Mon, 30 Mar 2020 09:44:01 +0200
Message-ID: <2cee72779294550a3ad143146283745b5cccb5fc.camel@sipsolutions.net>
Subject: Re: [PATCH] UML: add support for KASAN under x86_64
From: Johannes Berg <johannes@sipsolutions.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Jeff Dike
 <jdike@addtoit.com>,  Richard Weinberger <richard@nod.at>,
 anton.ivanov@cambridgegreys.com, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Brendan Higgins <brendanhiggins@google.com>,  David Gow
 <davidgow@google.com>, linux-um@lists.infradead.org, LKML
 <linux-kernel@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
Date: Mon, 30 Mar 2020 09:43:58 +0200
In-Reply-To: <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com> (sfid-20200320_161845_514535_9A0BEF71)
References: <20200226004608.8128-1-trishalfonso@google.com>
	 <CAKFsvULd7w21T_nEn8QiofQGMovFBmi94dq2W_-DOjxf5oD-=w@mail.gmail.com>
	 <4b8c1696f658b4c6c393956734d580593b55c4c0.camel@sipsolutions.net>
	 <674ad16d7de34db7b562a08b971bdde179158902.camel@sipsolutions.net>
	 <CACT4Y+bdxmRmr57JO_k0whhnT2BqcSA=Jwa5M6=9wdyOryv6Ug@mail.gmail.com>
	 <ded22d68e623d2663c96a0e1c81d660b9da747bc.camel@sipsolutions.net>
	 <CACT4Y+YzM5bwvJ=yryrz1_y=uh=NX+2PNu4pLFaqQ2BMS39Fdg@mail.gmail.com>
	 (sfid-20200320_161845_514535_9A0BEF71)
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.34.4 (3.34.4-1.fc31)
MIME-Version: 1.0
X-Original-Sender: johannes@sipsolutions.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: best guess record for domain of johannes@sipsolutions.net
 designates 2a01:4f8:191:4433::2 as permitted sender) smtp.mailfrom=johannes@sipsolutions.net
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

On Fri, 2020-03-20 at 16:18 +0100, Dmitry Vyukov wrote:
> 
> > Wait ... Now you say 0x7fbfffc000, but that is almost fine? I think you
> > confused the values - because I see, on userspace, the following:
> 
> Oh, sorry, I copy-pasted wrong number. I meant 0x7fff8000. 

Right, ok.

> Then I would expect 0x1000 0000 0000 to work, but you say it doesn't...

So it just occurred to me - as I was mentioning this whole thing to
Richard - that there's probably somewhere some check about whether some
space is userspace or not.

I'm beginning to think that we shouldn't just map this outside of the
kernel memory system, but properly treat it as part of the memory that's
inside. And also use KASAN_VMALLOC.

We can probably still have it at 0x7fff8000, just need to make sure we
actually map it? I tried with vm_area_add_early() but it didn't really
work once you have vmalloc() stuff...

I dunno.

johannes


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2cee72779294550a3ad143146283745b5cccb5fc.camel%40sipsolutions.net.
