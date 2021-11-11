Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4WJWOGAMGQEIW4H4IY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 07D5D44D434
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 10:40:04 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id w13-20020a63934d000000b002a2935891dasf2975728pgm.15
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Nov 2021 01:40:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636623602; cv=pass;
        d=google.com; s=arc-20160816;
        b=NylcFcQtBitVkMHmp2MW+S1Rw8xjRaBOwZEYCCmk4smrilIUy2DRBm36EiT1cyvD2C
         0xpdAYUreCi8V8feWCQ7l4lV1lECe4DH1PlBOCzCLc/XZ3H34uUUCNIVI3QQgWlt9TB7
         8aAcglF07YhrOvkrFx7fHRP1/yhFYPjcndgHd2hlx7nSrloLCmpTDoq3Z61DweOOrcrX
         pPx0ZymX3L+V5fa7F1MbkHKVOJyi0Mev+Gp9K/gw0sWQM0VPmaFuaWpcwWq4Pv3Hhm74
         TUsk9i7+1y/Rp7lsTUx538JL5f+6xGLmkbkvoUzkRlhP02oXHBqz6YUMi8esRgwqYhWC
         zMKw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aahL559JUz5olwJWuDZR37ETVffrAmubctdzhjAe6wg=;
        b=OcZxvqJgJKHHepQb7wW7lh183cKo6gZT9BspnBIist0YsHRJ/w+0I7Hp9Ct2z/Vl2d
         WqEBAg0DUNbpnVPcKDBepzKsnEjBk7ACKAA0zvn6dB0D1meMjk6wb8Z7LQHYjvBKP3RE
         BADAWatNf2Um4LETUlASXin8N0reefAIQnGYk3pMJllRShjFvYroEsnlf7EwUSpPBc2O
         /uSfJo/ego5t7+ku4bm1/H7swPdF82xM9dXM4UUqS1rGtMg2aYF2tVtIXRe9W/NnYHVw
         QNYkpP/K4uLyVFa5Ds881uv23mcGWq5B3nlc9puRvxAiYVtUg2GjyPn3Oz3b+GKSr11/
         Dq/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gkiWiOX8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aahL559JUz5olwJWuDZR37ETVffrAmubctdzhjAe6wg=;
        b=sb4+TjsKOS8YZE9RmPsD3S50hxZN/8BRhkNzqCBtOJdenhqO3CNKU42KxMghyhFpSR
         k9VNXE6ZYyTuK+oaJS9Bt/Keb9SHNxzfIu42rmxSrjFWUc2jwJedXaizOTy3QmTyVLAL
         cqBJFSLdAJBQPnkfMI/9dLdPRYUHI18JZztmA4kwplAPwYkXYqgLKsFSdeaeAniEIFZP
         aHiQ2JL9h23z5+ttJwPX2L0Xcw00esv9qfp+KR2xeuWGwRc9Rr9qfe8ycSfj17/AzyhN
         qbrUfx3a+hv1ugBM5xFzBkaRh23dQY2k7PUKNKT4Ttvi+XQ87bkmHf84bNrP9xziveJc
         XaDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aahL559JUz5olwJWuDZR37ETVffrAmubctdzhjAe6wg=;
        b=mXT9CiB6MahdQPiwQs7q22zfLBiGhu+rgCtWhgjPoctfwCyv0F1lHM2mO8ZOCplWak
         hphDMOivlyjY8v2Mb5yKlFM6tTUwp03nk6OLn18psOz5vxouB+zEZ47TC1mK487oHol5
         wq0QcgHIxp2Ble+LFsfmjrj2ar9aVHsxsw5rpg3uDDFblPsdCwNzjZQMCvVSN2UhP+CS
         oh4Vzs0Xz5lyp0oUpQk19VS9rtB8lqICiBGRVh5aokbyUz3RnufQkBXvV1GGrKhy/4MX
         xb2YQ0C7jkAExtJ1Bg8ADmgDHSlw8gOSJWHzyzNXmWZfFoZw+TJ5WWQsoY38dKpRpQ2N
         6NXw==
X-Gm-Message-State: AOAM532cR57V9R4iThkF3ZinOfNIc7QRRPFuV9WDi8VXxH1uNAJ+bK+j
	2dDRa/PXYS2IKbX1rq8A16A=
X-Google-Smtp-Source: ABdhPJzmMBXywqCcIsx2XwkkXsMj+0jt5BBKXdMa/x2fZRaUxuRzl4aW9NQWWijDQLxpO5hyhhwWvQ==
X-Received: by 2002:a17:90a:e005:: with SMTP id u5mr24898859pjy.17.1636623602367;
        Thu, 11 Nov 2021 01:40:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3704:: with SMTP id e4ls773558pga.2.gmail; Thu, 11 Nov
 2021 01:40:01 -0800 (PST)
X-Received: by 2002:a05:6a00:2283:b0:49f:dea0:b9ba with SMTP id f3-20020a056a00228300b0049fdea0b9bamr5568201pfe.56.1636623601775;
        Thu, 11 Nov 2021 01:40:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636623601; cv=none;
        d=google.com; s=arc-20160816;
        b=KqQEUREtm9DBxLeeiBnwV3TR5WVT5COp+JaTKBTJ+V24ztaEpcL2OxI9ORGb2QlN55
         5xfRzB1frydquXjkLGRFDiH7lnA3/JOUrns0pmY9t0BpyB6o+AyskIvZjjrgrfs5N6xP
         /k4DTeRq5+lYZgc61q52t3LvCNtowLIrH/FTF/0k1HWRBYGjyfgvtu9G5wUjsoKBbvc6
         S3Rte4k8BS4y88Zy/Bs+nHAtRj9J3VrgpkY0guWHzgu7b08AnYOwCqpAXazx2TtlROYx
         KJCKKRfwvumxR61P9rEnMncfF9exXY9nCASEfmqttRd8pVREGpShyo396tcP1q3bPRp6
         kenw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6/bKopAPmkHa57hfJnxgSr31+HwEgFYE/Py/TQAdG68=;
        b=e+EoH7vFc4TqJkcx/il2LL+d9vWpMRaIx6qNUkVMdgseMfP8Mx6LntgKFzNnOSI/3u
         LsM8pQ991Bi+A2nMnQ7cZoKgSgnErZyt9hvC9RKtzGEiZ4NiJJ7yuYmi3uLhxQh6lRrp
         CAP/3cSgQfyp1hVZzdrNshMeN3iHHKowemc2rgI143lgWdpAKtfU/bhqMYoQp8RuCV7T
         vv9xpZthcWx8MxJSkv/IuJe1yQi0bnhf1vX35rimvLniliOfFaWPpeNPOFJ9F7+mB7P5
         3JFNkvyyLLHov+YBRN0Faz5KgTN1RzVlYDpkbxZVvjx3aGHI1zaABI9xcLUogLV4G1th
         6mQg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=gkiWiOX8;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id e6si359082pjm.0.2021.11.11.01.40.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Nov 2021 01:40:01 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id g91-20020a9d12e4000000b0055ae68cfc3dso8079645otg.9
        for <kasan-dev@googlegroups.com>; Thu, 11 Nov 2021 01:40:01 -0800 (PST)
X-Received: by 2002:a9d:77d1:: with SMTP id w17mr4805850otl.329.1636623600901;
 Thu, 11 Nov 2021 01:40:00 -0800 (PST)
MIME-Version: 1.0
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
 <20211110202448.4054153-5-valentin.schneider@arm.com> <YYzeOQNFmuieCk3T@elver.google.com>
In-Reply-To: <YYzeOQNFmuieCk3T@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 11 Nov 2021 10:39:49 +0100
Message-ID: <CANpmjNPvYZSSLnsg_BGfzb=Yu4bTvCp+N14FHcJfUDjDgzrywg@mail.gmail.com>
Subject: Re: [PATCH v2 4/5] kscan: Use preemption model accessors
To: Valentin Schneider <valentin.schneider@arm.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linuxppc-dev@lists.ozlabs.org, linux-kbuild@vger.kernel.org, 
	Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Mike Galbraith <efault@gmx.de>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, Michal Marek <michal.lkml@markovi.net>, 
	Nick Desaulniers <ndesaulniers@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=gkiWiOX8;       spf=pass
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

On Thu, 11 Nov 2021 at 10:11, Marco Elver <elver@google.com> wrote:
>
> Subject s/kscan/kcsan/
>
> On Wed, Nov 10, 2021 at 08:24PM +0000, Valentin Schneider wrote:
> > Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
> > preemption model of the live kernel. Use the newly-introduced accessors
> > instead.
> >
> > Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
>
> Reviewed-by: Marco Elver <elver@google.com>
>
> Though it currently doesn't compile as a module due to missing
> EXPORT_SYMBOL of is_preempt*().
>
> > ---
> >  kernel/kcsan/kcsan_test.c | 4 ++--
> >  1 file changed, 2 insertions(+), 2 deletions(-)
> >
> > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > index dc55fd5a36fc..14d811eb9a21 100644
> > --- a/kernel/kcsan/kcsan_test.c
> > +++ b/kernel/kcsan/kcsan_test.c
> > @@ -1005,13 +1005,13 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
> >       else
> >               nthreads *= 2;
> >
> > -     if (!IS_ENABLED(CONFIG_PREEMPT) || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
> > +     if (!is_preempt_full() || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {

In case you introduce the 5th helper I suggested
(is_preempt_full_or_rt() or whatever you'll call it), this one can be
switched, because this check really does want to know if "at least
full preemption" and not "precisely full preemption".

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPvYZSSLnsg_BGfzb%3DYu4bTvCp%2BN14FHcJfUDjDgzrywg%40mail.gmail.com.
