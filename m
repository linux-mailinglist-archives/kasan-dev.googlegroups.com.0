Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKP4Y6MQMGQECMLT2JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id D74FF5EB15D
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 21:31:54 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id k3-20020a4a8503000000b0047463a13402sf3499814ooh.2
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 12:31:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664220713; cv=pass;
        d=google.com; s=arc-20160816;
        b=qB3XNhPTcswKhDUkhIUPi+NyZt6p4GTcTZUfiYGDsmn898E8jtZjhV5VvBse+3sETg
         XNPFDhNFTK7SSkKdgKsbepgaDfBt1xaRkxakK7zxLTdiOdmzDk5Uk3qVBF/31Kmk/RKq
         uoEbawB4/KJuK14l2ygQZuE47FaTOD+SCJIxTRzsYAUzHOQliYtijuLHXs6QQxd/HwbV
         V/RT9r8ryYqKAbcwaGT5/t4UfQEop+q9/6tNnStq+3zjTMsOH2Ykb7YAy+MSuJVTrW0q
         JR9LoLOX3nH7kIZMhnRasaXr0qKXrbUThAzPw6BKo5nhwXqwN+F86F6GyAGoiH3cp/mP
         KsXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=USq9qLssRnS9205S/F2daNqaVDkfCemGX6hDKQKq9mI=;
        b=M1hETIiHlBb35/Rm4369zSYkDRzzhVC2hB0agkGeuzOEyA3w/tcKLnEtpSgZV39m3k
         IT9M926/9RTC+ApXiHesi0T3qRZUcUpwiXgjCDi6w3gvE9DLTofq/wZTZ3O4XBPvlM6k
         hbcP50wOoK5yEtmnhUJosZuK5QiCye7PyZThI+2CdB/WlOBZb6/al+ZtA0LSEedAI0TO
         PiNZf2h+/klJ0tsBh8NjWjhSj3VyE2E+8QMJtLAAkhR+3dCqa5vzplfwoY6o3lkf9nka
         IIwfYtUrqJK+SWUTl0rsTixTdBFJI01AIzGNS8xFasorqnIt2ERY7V0QTwlvhjELVAcH
         vV1A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CEkZbAGX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=USq9qLssRnS9205S/F2daNqaVDkfCemGX6hDKQKq9mI=;
        b=edGuF74MiPPbrujexF37lA14L+LV/Nl6RdRqkHCqUTesDcROUPERybLWQOxs5dFw4C
         g5oFE6+lqOXhvHcaoZQQbnSly3GEjqVY+IR6RYvGXsUbY4eQPnkCfiRnaO3U2ZsQdgxf
         AUa7E2+66OlTB7z/N/Dokf0bo0JLfRd3fSs4xXbUpmOQcQkELsP6lh9hmh5LBRwcmF9N
         Q9MvzjWm9dm9bcBBK0SvndOpK1JzxyvKP0crNRfi3altCpQhTlI6h0kRo/jqcpdvcRYj
         yTL38R2LvJxqtAk86maS+2I8l1jzG7QU/Ox0++TJnxri7+Bj4MlYh8lUMFiaHsvmeE6W
         rlHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=USq9qLssRnS9205S/F2daNqaVDkfCemGX6hDKQKq9mI=;
        b=ICwQmFP8T/D1sT0eu9g0/UhRtMVbT1sN+5ZIGPx8BoKBUNFevOfgTuZFgrvkOedKca
         K7LBJ4ca72T+aS6OVoYLp0YrywxR6dYLFtGAORkfYF5eXmd4yaye85qKBIf1rYQSDBsq
         AjqpoqoZIGhsFHjVjErCwr05ZO+Fwf2Kw7fItEbdPxo2gC32XPuV4kWGgnPrcnLN+Sul
         deV/X4Nf1ThRmyyz7ASk0Jm6Uce7eZhYch/V1WgiDGRiri4MJTZinR/F+C8PWlYetphT
         +hGfkkyVUters0kXNgQzxBgH4EddFLh2Tujaj78H4aXrpSeNdMoYfB5Gsa9DmjK6wcke
         4xtQ==
X-Gm-Message-State: ACrzQf2kDSdXsCvbBaKSl1HsfgURFyZcocbxjYclW3NvKKrJWr8nmQ0F
	lG/iXEs2Tr5c5Pg8s1hPXX4=
X-Google-Smtp-Source: AMsMyM7tONkWCX3qPLuxdW3dnQyNhqJ1r5QFp1HeufcUIur3hxJ+4lk2VL0zdgZoiN7VR5KtE1c0Ug==
X-Received: by 2002:a05:6830:1692:b0:655:eb37:257a with SMTP id k18-20020a056830169200b00655eb37257amr10835777otr.241.1664220713647;
        Mon, 26 Sep 2022 12:31:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:db88:0:b0:345:9a88:c799 with SMTP id s130-20020acadb88000000b003459a88c799ls99173oig.5.-pod-prod-gmail;
 Mon, 26 Sep 2022 12:31:53 -0700 (PDT)
X-Received: by 2002:a54:4096:0:b0:350:65c7:35aa with SMTP id i22-20020a544096000000b0035065c735aamr165211oii.118.1664220713202;
        Mon, 26 Sep 2022 12:31:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664220713; cv=none;
        d=google.com; s=arc-20160816;
        b=XhSV9bqd/cw0oU2tk8czhT4nbxgcnkm7EYtOV/hDCYTay1Nv5uLk9A7cVvrOX0cNvj
         BSHPqVHosBh8Kil9EQPLdcr7ORIfjzdj8Obog0QmTurAOv7mJcmEiBV1CuNWP+mEjmHc
         yEF6WHFH/34H+oGD5CjH9086Gg6giWRToxpRf0/1dyfmCInnQUZMbDd/Q3MuUpSEHUp5
         EFaNADiKX3QQu1U2XPvq0WOWAcmDx5L3WA56+AaG4QXur1tKqDRtUsA83yDZA/7WxXAi
         VuLSRUxALirJUjFqGYLr0Czk0oqrpebP0b6yZ5jOEpjkrpjEOrqhCN4KyKbJfORZ30uy
         vqUQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=e2ogqpW9GNo4d3kOVij+kRUl5qTp8QW1SoOU7kiSzKM=;
        b=NyMy0URDjYLukpLYou/zeqVN+/MZzyfoNGigMWfLtQJmj0YJkZ/OJs8q9W5iu5UGuJ
         YBzdQAxnpfeLH7RR4c9PuGfFk8nz3x/mvy2b7r6DUmIhkdJnAShJrr3Y4Ud6haVG+971
         2/WKwtWIAuxqJO8Vw9Y9XkZhyqvbJ94IIqAlwcvZRRo81JIRmOzgmpUy0O8c9zkPdLTd
         OB/Iojz+uSldJ+rd/LFtIHEM9nG6g3wXBFQgYxg4djGn38vp1I1vxfAkneyPz84Q8n8K
         0v+sUJ3RsPC+ybDwRvsErZ5lbAVS/fSlRslRGIgAdkAWi8sTDLvK9DS4s+a6xR3CjApN
         zfEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CEkZbAGX;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id 33-20020a9d0824000000b0065bf4fec7ccsi642186oty.5.2022.09.26.12.31.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 12:31:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-3450990b0aeso79151567b3.12
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 12:31:53 -0700 (PDT)
X-Received: by 2002:a81:9c2:0:b0:345:4830:1943 with SMTP id
 185-20020a8109c2000000b0034548301943mr22754855ywj.86.1664220712647; Mon, 26
 Sep 2022 12:31:52 -0700 (PDT)
MIME-Version: 1.0
References: <20220926171223.1483213-1-Jason@zx2c4.com> <CANpmjNOsBq7aTZV+bWW38ge6N4awg=0X5ZhzsTj2d3Y2rrx_iQ@mail.gmail.com>
 <CAHmME9owU8bXSUa9Hi_j_xebMYN53a8yT4RgtV=01b1Lt3U7ow@mail.gmail.com>
In-Reply-To: <CAHmME9owU8bXSUa9Hi_j_xebMYN53a8yT4RgtV=01b1Lt3U7ow@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Sep 2022 21:31:16 +0200
Message-ID: <CANpmjNP2FskJ4-pArVd=pT0MFokafPOYZiEg3tspGtjQ5OtuCg@mail.gmail.com>
Subject: Re: [PATCH] kfence: use better stack hash seed
To: "Jason A. Donenfeld" <Jason@zx2c4.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CEkZbAGX;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1136 as
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

On Mon, 26 Sept 2022 at 20:01, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> On Mon, Sep 26, 2022 at 7:35 PM Marco Elver <elver@google.com> wrote:
> >
> > On Mon, 26 Sept 2022 at 19:12, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> > >
> > > As of [1], the RNG will have incorporated both a cycle counter value and
> > > RDRAND, in addition to various other environmental noise. Therefore,
> > > using get_random_u32() will supply a stronger seed than simply using
> > > random_get_entropy(). N.B.: random_get_entropy() should be considered an
> > > internal API of random.c and not generally consumed.
> > >
> > > [1] https://git.kernel.org/crng/random/c/c6c739b0
> > >
> > > Cc: Alexander Potapenko <glider@google.com>
> > > Cc: Marco Elver <elver@google.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> >
> > Assuming this patch goes after [1].
>
> Do you want me to queue it up in my tree to ensure that? Or would you
> like to take it and just rely on me sending my PULL at the start of
> the window?

kfence patches go through -mm, so that's also a question for Andrew.

I'm guessing that your change at [1] and this patch ought to be in a
patch series together, due to that dependency. In which case it'd be
very reasonable for you to take it through your tree.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP2FskJ4-pArVd%3DpT0MFokafPOYZiEg3tspGtjQ5OtuCg%40mail.gmail.com.
