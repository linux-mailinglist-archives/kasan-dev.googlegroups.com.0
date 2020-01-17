Return-Path: <kasan-dev+bncBCMIZB7QWENRB2EMQ3YQKGQE5GXLOXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5483E140744
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 11:03:22 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id x16sf3745986pjq.7
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Jan 2020 02:03:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579255400; cv=pass;
        d=google.com; s=arc-20160816;
        b=RVZbMZUWXhrnufOaXBUtF1HuKjUe/rFbMVxF6g+UCQIKuRc4G2t8R5BKxEXeplbo61
         OyLcUs9Vx29nTnlSzFdeCyfJJwezCdmkms4a2QJpvNxi/xzq65yRRwGCHRKeqObVH7Wp
         B0dfFI7Lnhzb4+8udQktxiE3Q5Id6fv/mNYDxRSEvq8Vm7+nNLg18cdeXBCZGhzU716g
         ygttDzX6TLixCj8v0cCDo+4h8b0MY6HpkQhHHnnVnY5saQfVUH5IgPN8/JDssSnybpj6
         IugE3k+7NoCHcAqgordDthVtvNqQM5QUwm1w77/PT+4WpOUXBwQcpucFT9TqEGloPQRF
         lTGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IJe2cEPwE+yBcTDV2EDCggcg/QkobnVq78w8hrPncLU=;
        b=Tl3W+i75XzFnnnPrL2ZEz3TJ5221n0B3niEcxP/DmPs0eDocDjqFeLvU/Ih/pXxRkQ
         27BT8y4etKSpbTJa9WouhHZlr3eCYcgte+TKcXsp0Et7tGT4gdoOKGqSv9AwK1gkHAgD
         2EpCJkgnhgXPKe0LKL/lqnJn2iLxzIPSD6WVt7HmJTEzsYe/dblXT1SgraTxdo/Etp8m
         BFrJghi03bwh5eUNfDQ6CqNgGswjGO7RcHLVhmHZ+UIL94uURbbHPpgetIZIgZDCg/se
         f8kSI8f13UsMzApIJaNaVSsXKMlBGOSVY0bGY7Em96MouO/j/i3CAZvEGuN7p1EVHmHG
         nfnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uMUCEpzD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IJe2cEPwE+yBcTDV2EDCggcg/QkobnVq78w8hrPncLU=;
        b=p2jlEMy850dJxCzkVxBTfO5Xft15hY665Wf+SdzF9tEGbmdVhXR1eZg5XNMRTc+CmY
         7eQt6PIBx/7M5Hm6abZguyM7c14e3ykng5muM88W02+8G3jPky5Jzt4gw5YWmcb48BVd
         mUyryBK8xwC4UftDl0GbazgoxDx/PgFzdWlliDhC2fVsM+KEE73WBNgJbStMR2mHx9eI
         W0Esv0Tsg7ljPssL4XEQ+YI+H/ycKmYDrLHtr7J3CcKAQ8KdfbNYotQ2qbCjDMt3EGlb
         xacZ4jA790PLNHhydtWae4hVdn0nc/dunEpq6E7ILRRofrl7SCrD8kkJH6KBEwjIsb5X
         wOfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IJe2cEPwE+yBcTDV2EDCggcg/QkobnVq78w8hrPncLU=;
        b=itykk0s4KPysbYojfV+Mh/dNBtF1E+zcwk6Km21zp0ZQHtttrQvcOLJess6gg+/VZc
         E5pQBix+3g1lQcwznXKg+YXtlJlzJ9aTQwW/DOo1EQValGht07PdZMCgLSprE1X7nc/x
         DlxcpxYxVI6NGqAenGyDq+tdbPlDBjARRZM0Lp5RzSOlJimM9LIuNN86w+kbzSINS1EU
         X6MkwIra90S7Ie3Sxcgc0EdPJzWVAFjUzWDZvbmWY1kNC5y2k9du2OeHCioxNTgLLY+w
         dn9gF53/APMbniXLm7GS4W35KFM/UYOphI7O1u608Ge1F6kJHcp0nEJfvZc123tfyx1r
         1Itw==
X-Gm-Message-State: APjAAAVZ8Ow9FkYCjgD+K59R3opvg91pq6LmofgsmCQIBgQTlwevcl8P
	oigVz7+ILB3ibrcJPLAGZxA=
X-Google-Smtp-Source: APXvYqzCM0vw219u3FEjOAslfxl9q1N6rZlS4SGeti70HfhYfyNEfPV7dLuBtYcJ4CXxeld7/YxRkA==
X-Received: by 2002:a17:90a:c214:: with SMTP id e20mr4610037pjt.98.1579255400652;
        Fri, 17 Jan 2020 02:03:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d352:: with SMTP id i18ls2181277pjx.4.canary-gmail;
 Fri, 17 Jan 2020 02:03:20 -0800 (PST)
X-Received: by 2002:a17:90a:a48c:: with SMTP id z12mr4759703pjp.38.1579255400264;
        Fri, 17 Jan 2020 02:03:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579255400; cv=none;
        d=google.com; s=arc-20160816;
        b=FCaYFT+Zhgq3dIr6QByU+81VE+wHunv6o/nhPMyDoRUtqpzc1JI7/j2nDRi40rWK33
         DhVuny2hUFC/TWpgrzfRuT8sWz85jrqegmxQ0QXLPLO7bxwBSMyAaANxWY1ViaI0Sp1W
         hIcf6rF9vW4U+7QWR+hcPyaK1bmi/OblQnHG1skPpyD7CcX5ZLUXuddPd0xdAKpB1Vyi
         d6Kn26miJrVopl9f3uaB5PIyAvPYy2Ug1IdLuRmSpuYmvc80KqKA6LzgLR9utoKpfIyD
         HWD12F9/kKmJdOKiO8ZtAkTuOTnFw7LHb2Ff7KzJ3/pD8uXMZ1nPtxzZlvnIREKQhNlS
         eJZQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kN9jFTsuucSemoNqf4dJLa9bNAFNxkxyRhdletZB1KA=;
        b=I3Jdhe3BzG+Cjx1uoLNv88m4e6QP9b0l9EZz5nWdVrGVjgAzgs0dt+cs8m/2N3tiMF
         zlbigTrN2sVfd79TQ9MwtyvQB1RZbffMBgY1fDMSgDSVnTnWJ/Z3MiumU1LmpGh+sUcC
         sHyRRxh4enOZ0HH7dW8liEAs/vaH83W6b0HBcJcjuB3uhkFN5IAIBZtLzYrZCo1nij5L
         WhiKVP+glNZYMCKBAdVQ/CR82ZzDifCWxuBRBQNq2aBjue8hC3h7bNCxHdU1qcJMNhPH
         H5s2q1H9UHIlUiV1Cs/VTr8u8M9KXeUHwNz6xg5ucqg2xOA0MDC7qMUVEkIFZoG/CZ51
         m+jQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uMUCEpzD;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id cx5si186949pjb.1.2020.01.17.02.03.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Jan 2020 02:03:20 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id e5so21335310qtm.6
        for <kasan-dev@googlegroups.com>; Fri, 17 Jan 2020 02:03:20 -0800 (PST)
X-Received: by 2002:ac8:30f7:: with SMTP id w52mr6677250qta.380.1579255399591;
 Fri, 17 Jan 2020 02:03:19 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
 <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
 <CACT4Y+brqD-o-u3Vt=C-PBiS2Wz+wXN3Q3RqBhf3XyRYaRoZJw@mail.gmail.com>
 <2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel@sipsolutions.net>
 <CACT4Y+b6C+y9sDfMYPDy-nh=WTt5+u2kLcWx2LQmHc1A5L7y0A@mail.gmail.com> <CACT4Y+atPME1RYvusmr2EQpv_mNkKJ2_LjMeANv0HxF=+Uu5hw@mail.gmail.com>
In-Reply-To: <CACT4Y+atPME1RYvusmr2EQpv_mNkKJ2_LjMeANv0HxF=+Uu5hw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Jan 2020 11:03:07 +0100
Message-ID: <CACT4Y+bsaZoPC1Q7_rV-e_aO=LVPA-cE3btT_VARStWYk6dcPA@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Richard Weinberger <richard@nod.at>, 
	Jeff Dike <jdike@addtoit.com>, Brendan Higgins <brendanhiggins@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, David Gow <davidgow@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, anton.ivanov@cambridgegreys.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uMUCEpzD;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Fri, Jan 17, 2020 at 10:59 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Jan 16, 2020 at 10:39 PM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> >
> > On Thu, Jan 16, 2020 at 1:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Thu, Jan 16, 2020 at 10:20 AM Johannes Berg
> > > <johannes@sipsolutions.net> wrote:
> > > >
> > > > On Thu, 2020-01-16 at 10:18 +0100, Dmitry Vyukov wrote:
> > > > >
> > > > > Looking at this problem and at the number of KASAN_SANITIZE := n in
> > > > > Makefiles (some of which are pretty sad, e.g. ignoring string.c,
> > > > > kstrtox.c, vsprintf.c -- that's where the bugs are!), I think we
> > > > > initialize KASAN too late. I think we need to do roughly what we do in
> > > > > user-space asan (because it is user-space asan!). Constructors run
> > > > > before main and it's really good, we need to initialize KASAN from
> > > > > these constructors. Or if that's not enough in all cases, also add own
> > > > > constructor/.preinit array entry to initialize as early as possible.
> > > >
> >
> > I am not too happy with the number of KASAN_SANITIZE := n's either.
> > This sounds like a good idea. Let me look into it; I am not familiar
> > with constructors or .preint array.
> >
> > > > We even control the linker in this case, so we can put something into
> > > > the .preinit array *first*.
> > >
> > > Even better! If we can reliably put something before constructors, we
> > > don't even need lazy init in constructors.
> > >
> > > > > All we need to do is to call mmap syscall, there is really no
> > > > > dependencies on anything kernel-related.
> > > >
> > > > OK. I wasn't really familiar with those details.
> > > >
> > > > > This should resolve the problem with constructors (after they
> > > > > initialize KASAN, they can proceed to do anything they need) and it
> > > > > should get rid of most KASAN_SANITIZE (in particular, all of
> > > > > lib/Makefile and kernel/Makefile) and should fix stack instrumentation
> > > > > (in case it does not work now). The only tiny bit we should not
> > > > > instrument is the path from constructor up to mmap call.
> >
> > This sounds like a great solution. I am getting this KASAN report:
> > "BUG: KASAN: stack-out-of-bounds in syscall_stub_data+0x2a5/0x2c7",
> > which is probably because of this stack instrumentation problem you
> > point out.
>
> [reposting to the list]
>
> If that part of the code I mentioned is instrumented, manifestation
> would be different -- stack instrumentation will try to access shadow,
> shadow is not mapped yet, so it would crash on the shadow access.
>
> What you are seeing looks like, well, a kernel bug where it does a bad
> stack access. Maybe it's KASAN actually _working_? :)

Though, stack instrumentation may have issues with longjmp-like things.
I would suggest first turning off stack instrumentation and getting
that work. Solving problems one-by-one is always easier.
If you need help debugging this, please post more info: patch, what
you are doing, full kernel output (preferably from start, if it's not
too lengthy).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbsaZoPC1Q7_rV-e_aO%3DLVPA-cE3btT_VARStWYk6dcPA%40mail.gmail.com.
