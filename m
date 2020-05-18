Return-Path: <kasan-dev+bncBCMIZB7QWENRBEXORH3AKGQEBDMB4KI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 72F3C1D77E7
	for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 13:52:51 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id m15sf3454618otl.11
        for <lists+kasan-dev@lfdr.de>; Mon, 18 May 2020 04:52:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589802770; cv=pass;
        d=google.com; s=arc-20160816;
        b=iYJUCxuH2Msgq4PSLgtFV5elZKQh5Y89TVrcE4FSentIPAN20kHzLLKQXlHN7KYIXw
         QxW+R5MxQg7APwcu41NlVLqv1RN3lsknwlzuv7WbvzDsqFJaKoOULDo82WITzemBcG8j
         IxmuVU1JWXcB+mK2CKVsi7elqefzR9hHmc5/nDKLZeEzAWsoXbZydubYF4gOUfDW4Ay0
         XYQWNNxwku0ZGhKl07vsdQabGqDFJo8/m6sNmVxIy9bpajYkTFTf3kcFJrT6NvWtfT1F
         VkLsoRy/1V4iuPJ/3eYkws3Qly/1sYFESqJUKj70iQYD8hdXnnFvRMUoMZHf3BPmaRD+
         da5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CvB7cWenZqYy2+SFvaj8wyTZVe5F9p6euMHKCdDEYW4=;
        b=qKj9Nacf90QQks6WTWB8aeekytmBEaJmHB/YwPKlEZ+FiHHwwDzFMRglJ1A4d0mFmU
         kK7HGdoS8PyECkgVA73Ow6puIDDwvPUPw7MHkGqsYx622rC/OrbtDfPbNy9WdNosNH6C
         rtWpcXnKJ+lfwY/t5SicHOYGOs1B/aH4p2DYMDm7H9PsNNd8u9ohvr3VBsHtmOR9C/06
         cefoma3FaK/kwbiLex1GkPqi6p6XdvemUVeNaRPLHzRkYphjOx3TZs4jWW1/0fSChEgm
         aQ3vAvdiX0rN/IKO9HkP/OFcxwI+NVg9pA0lUtg3F5A63dqldqRYPgFS9oBMDUuAhOuJ
         IsYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jmuU8AB5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CvB7cWenZqYy2+SFvaj8wyTZVe5F9p6euMHKCdDEYW4=;
        b=l2fGP9pxpVrbbNNlY3Ub7Jikn19S6ZuCH6ofhG40fOyEqldZ7h9TK06j8rGya/7xxO
         ru0fblDbkzCpW1BVg//m2mbiS5MzTwIY6V17bnw9R0uO418vLeF1HYyrM31abvcaWIyg
         JOS9seqXF/uAxE+V08Wsj5StFBgCEnX6nuAmYDEH2wgoEQRImgfopm07R0xQH+zhbMro
         yYSk8IE0zfNyacoLjnaM0YK9DK2NmB71zAN4ruHxdtihm49ZgDq39LL122d9fp6ivWEy
         kxRzakBsFyfHwLOzx4sky+eHFlsVYohQQkph53621HzZlBFqOrCqe0wrEiatEKGJ6IBF
         BJFg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CvB7cWenZqYy2+SFvaj8wyTZVe5F9p6euMHKCdDEYW4=;
        b=EJ5kf/8BGusvGMJbHK7wFkVdlQCQrIREUD3ffI3AfttWOM+MwmKLj7EZqSR2AClq0U
         fO/wOO66d1o2Vm5mGls4MZ0j/UxHjIVt5ZRDDjBga/DbwpGmT9vTYaU0z5u64qYluWiA
         z+9Qwbbi1va62uqJB2MSb0prDbgT5j3xuxSGGZHlcTdDowe1WoZexGGACYirQpJkErUI
         +rSrczcRitO15eUckbV0yiF5QAb9easSgyQbTs//eJAsmqDFRxHWQ8zL54gX5NbRYXTi
         Le+2Zxog3rtEAMaIr7LiI7GM+R8eq61EJzsW6t+F5sMiwRGztSxlEyuLQ78eaw3YeBqc
         3tKg==
X-Gm-Message-State: AOAM530oYZU3cnLNLhBO1IiA7GisyvLSU3opzHwReh40BY6JeCcpUYtA
	K3M8Z0u+f2Il30zSABJt91g=
X-Google-Smtp-Source: ABdhPJymLsf9acVQqhtnBbVn66U0MkCynIr/bInaZqk4QYLTPm7HPUXmU+/kwhgBw8gCrPQFp3iEwA==
X-Received: by 2002:a9d:68d5:: with SMTP id i21mr12857191oto.280.1589802770436;
        Mon, 18 May 2020 04:52:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:1c34:: with SMTP id f20ls1435037ote.1.gmail; Mon,
 18 May 2020 04:52:50 -0700 (PDT)
X-Received: by 2002:a05:6830:3149:: with SMTP id c9mr948176ots.302.1589802769987;
        Mon, 18 May 2020 04:52:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589802769; cv=none;
        d=google.com; s=arc-20160816;
        b=n73LrKrQfTkdMA8rxU2/gpIQ5sVolhQRURrWeTgYQeenQv9v+wnDbMolmB0cQbRxq9
         NGMeeVGtdBBj6eL4Re8KAWzjBAd5cbsMpyUAJaGK0LBI+H87ULBm/Mwmje4umGJIcLy0
         3+CMOpzosuMIMaORs8AQEHqRt49BlFvvZFHpX8UQd9CBPeRq4xGt789OZMeHHp6JYa5s
         bNSlwlw/EIz7paSLrSoAAU5lV6mBUOXdJXMb/LrSiIFYd/jzYq0CZvk6Qa5kPsZj3XqE
         Y6TAIL9Bvx6wwdxUUwH3GAMLWYXEkvOIsP0x0pHmTGRMabOq5pVVdys0NG+fMmK8FScE
         RYCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qr0GzXMaZeNK3ak0XV7svOkKLTqG4mGtizYZaJhBSxc=;
        b=Zk03dQtVUWpcxqH5luSHc5/vtiPx5q92xsfgBWg7JAz7POGKIvVEZRoFo+eI5/vlbV
         nFm+CzMQ54M9w+q1V4sAYIXmc2/P9jqCUNWGWXu+7VpNot7POmrmJfjeMhhuUHbSnrY+
         vpCXA5pbCCmjd/2jWzMGSo2zxkLpcXG7JwDr2qIpBrGEKr0NXhw2BoHfwK9mdi/Npu2x
         /Z/Q86Q4On6r+5ecRQrUQhkASn62Z5+ZL9g2M6pJtz955FQkd0O3coGpq6dYK6ba0S1D
         Q+X5ZHbqhk+ZaTh+8aPRJktv+Kfu8o75KUIJFuLxNtZC8CCXgp4VBiltyBTwIVoFt8Ip
         +dsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jmuU8AB5;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id p22si4618otp.4.2020.05.18.04.52.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 May 2020 04:52:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id z80so9749204qka.0
        for <kasan-dev@googlegroups.com>; Mon, 18 May 2020 04:52:49 -0700 (PDT)
X-Received: by 2002:a37:9d55:: with SMTP id g82mr13678165qke.407.1589802769113;
 Mon, 18 May 2020 04:52:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200423154250.10973-1-elver@google.com> <CACT4Y+arbSpBSwNoH4ySU__J4nBiEbE0f7PffWZFdcJVbFmXAA@mail.gmail.com>
 <20200428145532.GR2424@tucnak> <CACT4Y+YpO-VWt5-JH6aLBc3EeTy4VHc4uBc33_iQNAEkw0XAXw@mail.gmail.com>
 <CANpmjNOYx7s9EJ56mdwyGyTzED-yq3B0UvkiZ11KmCe+QMt47w@mail.gmail.com> <CANpmjNNzkcddHMMucH9CxpUeHoee9g5ViMLUuRPBvepo7TBHXA@mail.gmail.com>
In-Reply-To: <CANpmjNNzkcddHMMucH9CxpUeHoee9g5ViMLUuRPBvepo7TBHXA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 18 May 2020 13:52:36 +0200
Message-ID: <CACT4Y+Y7aDUrcMgo=u_Nrt2a57e=1w1958XLT8wLm0S7H7nNtQ@mail.gmail.com>
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: Marco Elver <elver@google.com>
Cc: Jakub Jelinek <jakub@redhat.com>, GCC Patches <gcc-patches@gcc.gnu.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jmuU8AB5;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, May 13, 2020 at 12:48 PM Marco Elver <elver@google.com> wrote:
> > Hello, Jakub,
> >
> > On Tue, 28 Apr 2020 at 16:58, Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Tue, Apr 28, 2020 at 4:55 PM Jakub Jelinek <jakub@redhat.com> wrote:
> > > >
> > > > On Tue, Apr 28, 2020 at 04:48:31PM +0200, Dmitry Vyukov wrote:
> > > > > FWIW this is:
> > > > >
> > > > > Acked-by: Dmitry Vyukov <dvuykov@google.com>
> > > > >
> > > > > We just landed a similar change to llvm:
> > > > > https://github.com/llvm/llvm-project/commit/5a2c31116f412c3b6888be361137efd705e05814
> > > > >
> > > > > Do you have any objections?
> > > >
> > > > I don't have objections or anything right now, we are just trying to
> > > > finalize GCC 10 and once it branches, patches like this can be
> > > > reviewed/committed for GCC11.
> > >
> > > Thanks for clarification!
> > > Then we will just wait.
> >
> > Just saw the announcement that GCC11 is in development stage 1 [1]. In
> > case it is still too early, do let us know what time window we shall
> > follow up.
> >
> > Would it be useful to rebase and resend the patch?
>
> So, it's starting to look like we're really going to need this sooner
> than later. Given the feature is guarded behind a flag, and otherwise
> does not affect anything else, would it be possible to take this for
> GCC11? What do we need to do to make this happen?
>
> Thanks,
> -- Marco
>
> > [1] https://gcc.gnu.org/pipermail/gcc/2020-April/000505.html

Jakub, could you please give some update. Do we just wait? That's
fine, just want to understand because there are some interesting
discussions in the kernel re bumping compiler requirements.
Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY7aDUrcMgo%3Du_Nrt2a57e%3D1w1958XLT8wLm0S7H7nNtQ%40mail.gmail.com.
