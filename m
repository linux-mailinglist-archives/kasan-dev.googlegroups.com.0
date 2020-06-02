Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNWB3L3AKGQEPOJJ6RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6767F1EC234
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 20:55:51 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id f1sf16959231ybg.22
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 11:55:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591124150; cv=pass;
        d=google.com; s=arc-20160816;
        b=cuikMESawde+NQLpuKRq+pm/G90pRMeWFlYdiKOlS9qGgHA7ur7hxe3XEpVVDKBBmg
         BSb/s4E41OqYBYV7117NFjFPE2eXBBFeEcR40grTEVS07o19ex+ZiTayyupfaWSXegrS
         Jk8D0ChJAvEpeYfigrK5EJWLuimWs8ySAI5vL8Da2/epllP2wuDPZ3tQXJ8I965HfUqm
         flH84eVyDjL6VWrZ4BW951EwpdzyVAe+kw4wKe18c/djbgCpExjD2SznhYmRJdLWIwWv
         KV2+jQmClXf/ZcQvBrTQvN5mb48ZJhyjWaoDOS2wtCBGD/yaJALrEHWIi8yeE85AK9Dx
         EtmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=s3v80/TXE8sK4ZMFJoYFiXgt9glxz7v6cyouyy7+RQc=;
        b=wcOmZRwNqP5EKu2Moul0rRfrg4FHFVVyjf7Lj2sZxKA+TqKP36f0tLbOSf5kuZrbHh
         hYiOCocRQkhX1zpKjyGxt5gQkNF/7kOC9UVA7BF2k6KjFPzs3vs7hCqBRkYwgxygoV6h
         nOnFeKV70Lcl3khs29Reag6q+nRmaxBQP1ga+pnqcg4FYU9wq4cYYPlI7g14HYuZLtRi
         TfUjayUb8/axEnXzIfPtCc0Fnh7Gj2bX/RJ3h6H0p5jN4ric1tHQu5PQL1Y5sXDULufu
         ODB2QxIlAFTwa+AlI4l5VXoM+CFmn6DQiTIZxB8ThX4sngfeASSXELn+VrQHXekpDfOm
         DH3A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=thUds+DS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s3v80/TXE8sK4ZMFJoYFiXgt9glxz7v6cyouyy7+RQc=;
        b=YSZejUVAGusAEKLK5d/Lo1vxaTu56e6mqQXVo82nIb9Vbl6yZ4CkcxYNvijtKUZQmq
         DwKz0n8I0b9NsrOYiJsd0EBDG2K4zuB/I0Zk2/LgkH26cJJM4TTOkICICQrupu1Nd/It
         1v3VdY7BFPRJEmccSBHj0UXONBOlil2bklJDuChFcm0Vj838D/zmetsIYPQs1Ctc5Hx4
         Em6/TISwQ3vXjzrdMcuHKMAxOn9t5n3os45sNQU4J2Q2GTSf7EWtKCHOSlhLbwE5jw1J
         tcVqbIyrrWtuIMsKZebEz65t+MB+fRLVqCZ2GHPTnmVJYog6UWpADJEZenzbXVnL22fi
         dlNg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=s3v80/TXE8sK4ZMFJoYFiXgt9glxz7v6cyouyy7+RQc=;
        b=A1zthU1Cb/jbbLPNYiv7JhPyBR6RlnMGbXMitEnqBtTNtDcz5KGqAsX/jmsBmLO6Ct
         GVUOiP7jP4q8WyKU/kXw4KMKxJyNftfFDVIBd99uQ4Vzw+zWCxMqrtUu9c2iGS6TT5gf
         qXqOpQgf+KXIlB6BapmtlhsAL5adJFQZxAKiqhXOFjXo9GWewc5wA6WXbFtahx0HoOAC
         aH0n+O4myntzkL39klNCxFHPKAh+7QGhAscMYhpjGdzF6skNK8uhcbAXs2KQ1gF2aE5P
         SWPEO+NYSoSC7FIeWPDoQ1+GfTRZKDjASTeK9U3QClrYznaMgcZMrO/maw7n0LjwaCkC
         qobg==
X-Gm-Message-State: AOAM530D8rtxQdrpHZkCLOn3uGdCGsvNfyO2AIqcSZQ6C42ZP3EQsgqW
	NWErafHIDauJFfck5SRraGM=
X-Google-Smtp-Source: ABdhPJxsE68jn4gzMiNeIIW4agkQEc0xk6h1OY/Q3N72XGbIXPSLOn6dbRdAab7ex3ApdCt4+5A6ow==
X-Received: by 2002:a25:c054:: with SMTP id c81mr29162370ybf.76.1591124150372;
        Tue, 02 Jun 2020 11:55:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2057:: with SMTP id g84ls7203021ybg.7.gmail; Tue, 02 Jun
 2020 11:55:50 -0700 (PDT)
X-Received: by 2002:a25:3489:: with SMTP id b131mr45195639yba.224.1591124149958;
        Tue, 02 Jun 2020 11:55:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591124149; cv=none;
        d=google.com; s=arc-20160816;
        b=D86puEpqr89IBnngnPnfovhMdd/v26lcTKQtxCVUVd2+Wz/yT7FSjsDwP5Em5WH0A/
         XJeAXUKod5wnhBmNiWjrxoFUsDupX43eruIiHgSkQCcX8/7d2acFY7Fzh9MkYGZhRlaQ
         DcaP5ngGNBH6t0pYuskrimOcmzxGLkwgnvFi9e+gMZZKPkPfhjvDqU3EjpCQG7v/51CH
         ofzS06YWNPa6aEGkbgAwvLWyzyfCMwnNAlGdfSOhvP9NkD2pKkStl8VC008F39/UvzKA
         KePJ/bjBDNtMxzqKT9FlxuccboV8TqN07rhkBbZAldUhOGWnRbxFLeyGdFkSJQDeRiU7
         Pjzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rz+wRL+qx3pugwQiXrCHQNne2iVcMp5nHos/ewO2Exg=;
        b=c8XO4FJES7lsan8e90dXDZxpwo+k5KjDA6QRgJL1q6/EtuZMbDEq3D82PNO5uPTcCq
         2D0SPxwJwr0smQ4rpLM4obNahp+GdIqXd6MEnU6cv84+1o3SMq2GrDclsygw2W8m4AAn
         jgVRwgUgwRKcOL8G8yH1H9yqS6Q/2O1gf2Omz7kld6uUUEDsAdzzaHT4GTxm6i9rW39L
         nq6zZPwWyywSMKZXjmzIwdXQI1CzowrP0+AvC3PnH7LUnL+mGEq2iBnGRo9OdM1W2y9r
         mXhF7tGRccrNfou/kdkJSKzUCnzc37cgHUawyza6S9BgA4EqhHOlnE727KNxA4/GvNw+
         mJxQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=thUds+DS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id n63si278602ybb.1.2020.06.02.11.55.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Jun 2020 11:55:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id j189so5491765oih.10
        for <kasan-dev@googlegroups.com>; Tue, 02 Jun 2020 11:55:49 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr4013382oih.70.1591124149338;
 Tue, 02 Jun 2020 11:55:49 -0700 (PDT)
MIME-Version: 1.0
References: <20200602184409.22142-1-elver@google.com> <20200602184409.22142-2-elver@google.com>
 <CAKwvOdkXVcZa5UwnoZqX7_FytabYn2ZRi=zQy_DyzduVmyQNMA@mail.gmail.com>
In-Reply-To: <CAKwvOdkXVcZa5UwnoZqX7_FytabYn2ZRi=zQy_DyzduVmyQNMA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Jun 2020 20:55:37 +0200
Message-ID: <CANpmjNMeAhS9vemP=OOPBmj_9dDnmQ=nxXARHeOQnw8z-uZS7Q@mail.gmail.com>
Subject: Re: [PATCH -tip 2/2] compiler_types.h: Add __no_sanitize_{address,undefined}
 to noinstr
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	syzbot <syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=thUds+DS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

On Tue, 2 Jun 2020 at 20:49, 'Nick Desaulniers' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Tue, Jun 2, 2020 at 11:44 AM 'Marco Elver' via Clang Built Linux
> <clang-built-linux@googlegroups.com> wrote:
> >
> > Adds the portable definitions for __no_sanitize_address, and
> > __no_sanitize_undefined, and subsequently changes noinstr to use the
> > attributes to disable instrumentation via KASAN or UBSAN.
> >
> > Link: https://lore.kernel.org/lkml/000000000000d2474c05a6c938fe@google.com/
> > Reported-by: syzbot+dc1fa714cb070b184db5@syzkaller.appspotmail.com
> > Signed-off-by: Marco Elver <elver@google.com>
>
> Currently most of our compiler attribute detection is done in
> include/linux/compiler_attributes.h; I think this should be handled
> there. +Miguel Ojeda

GCC and Clang define these very differently, and the way to query for
them is different too. All we want is a portable __no_sanitize, and
compiler-{gcc,clang}.h is the right place for that. Similar to why we
define the other __no_sanitize above the places they were added.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMeAhS9vemP%3DOOPBmj_9dDnmQ%3DnxXARHeOQnw8z-uZS7Q%40mail.gmail.com.
