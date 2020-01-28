Return-Path: <kasan-dev+bncBDYNJBOFRECBBI7YX7YQKGQEFNNTZLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DB7514B1A2
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 10:17:23 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id o24sf670370wmh.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 01:17:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580203043; cv=pass;
        d=google.com; s=arc-20160816;
        b=WZgpLCrHcJb+/WecHlekyYsVe50kSZwxwKJaXnJCGVfjKIUximkCxvdf7vjaHF1Ar6
         /2Mh+VH5oEAlgQVuC1mcQz+LLoaMD41DOijBe4SpDG4Dsc58lwZF9W4c7NLxkpOOlol3
         IfdRcYFXQqsAaBljgwdjulgY7ryVQgAIPtKCun4puJzlHvVQm4S9K+FYiHkICCLW1q1g
         25gipAsR1HCGhfUWYmwhS2rp/topdBZbHY6AZZsNmEesxPxxl1q0L458oVxgZWavfk6W
         W5zhPBJ7BNe2bmq1/pRHCkwcqSH5qepvwYcTmx3L43DDefSPUdYwp752+JPJFmrARoaz
         eeMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=bQbiY9bN/yyPYKLvVYEcGwNHQh47S9V8b4JLhe566Zo=;
        b=mLTAbLAd3r1VOejaIFK+GPvR0qOZDWuNp7A9h00a6XJf6b2zoYmT5Px6jHJ0+GEM1X
         OyH6uBGLK3//PVvpuUdd2DDT7GrFVDMViIFmnctLUnQvYAen4MVwSv97S4NCSwO08JbQ
         gQ3C51S28xqTKsFay9JE1YuSqNpBjVoDHlRsW+StKpZ/RkZGSei/obinWU8ru/HTnN5O
         i4m83KgouG5rNURB1ia11z2t8va5NUWHOfRZzvGS/6SQ9x1e76B7iSwHLAlparJs1JXV
         pUAP03W9iPMxNVRzoH1cbzUfcJTG5ACvR90+7n0L1lDCoR04tIq8QxkYNEBdnIyC8oX7
         MZFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=dv17cOT0;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bQbiY9bN/yyPYKLvVYEcGwNHQh47S9V8b4JLhe566Zo=;
        b=i2FKrIs194OpiCMwc4Fjs3sEM00dCZZNUZ+lXy/kAm0plM2B/J38zDFcBHs/VaJC8T
         3j0vfVioX9UjD0k+QgmT6OmQnp6m2ECcSb+9mThg2k0oH+Zc28nxjOMgEC7hshAF7FUE
         WZM094z9iv1+1a0rnRZOHytrGFRwxj8tbQqaaqGqWK9aWkuSyZfGhC0+kuBOgnO+ulY2
         vcOEKdACYXo1pROASwRKkZ4YPZGLoAILQS1usqEA0eDB/nzkakLQA3ujxEWNvxbDvPL4
         9qyay7ZsF0d17H7mt4g2h1SHuqx0VrhkfPoo3SL0AY6+Hv8fLvhR6idXtQlFycM149MM
         i1Tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bQbiY9bN/yyPYKLvVYEcGwNHQh47S9V8b4JLhe566Zo=;
        b=cpLjPdcfA/tMix/RaO0vGQ8LlL82dndqvCOuE9ohDG3XT0DfpAjcgtvUUDXX7fuCc1
         jD2Ww72Mr8XCYTFkRnJQgFCW3W6QjOLga/5NaZxe5hfCKpBjDjn+hL1a+7WThfFWeEFi
         lKHeIGoOjidocoNUOizcYsHlDW0LxzcFzMF9VAEm532W0Q+GJoCsUGYnwFf1fBw4HlVL
         9MIX6cqycdlYEeKYzsT+Om5TXNSJ7nhB0o7xkpl9mxTyxrKBBNqqW1WOGQ6lat9Lu8Lr
         2/cavMWlIN1FOYrFqAyWTL0MwESjUudfMoKiwhYYrOUT2kSseIP6dfs4OCRmO9famno5
         8h6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVr0VNNO0KqZ3O4tWfwJI7Kkun91VqFtdaf4EGwN+zYTQgKL7pS
	/hwyBCvnvf0619pE3NDNFv8=
X-Google-Smtp-Source: APXvYqwr9T+NZ3A7zhUL5+DhbDCh4ODb8W3bgwCuT2eb3OIAvSokhN4+vlDYB6Uk9bcsh6a6q+47Vw==
X-Received: by 2002:a05:600c:22d3:: with SMTP id 19mr3929888wmg.92.1580203043170;
        Tue, 28 Jan 2020 01:17:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:9d13:: with SMTP id g19ls1815677wme.1.gmail; Tue, 28 Jan
 2020 01:17:22 -0800 (PST)
X-Received: by 2002:a1c:6308:: with SMTP id x8mr3900181wmb.80.1580203042614;
        Tue, 28 Jan 2020 01:17:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580203042; cv=none;
        d=google.com; s=arc-20160816;
        b=L0jvNpeHXzPw7KiD/TVSl3sZ9m0JPz+XS1GEhc8gwtj5CNdV+J9i3rhPKtGoiZDsrz
         XMoNdmR1LRXLOy6+doUklHlZr3NpPTCzjixeQYFJwblZQPZq4EOd5SO5BjSi7Oy6koyz
         Ur4JVEUD6AnSeAPRiJWz8hQywM4E/Vx8e9pTh4bLwtgFqyME3dEfRrw6Pz9Jq6r9j8hl
         Iz5nCGFnFqTikVJcUHly91vM68dwxhHTh7OWBol+nE4LEuOMDH9lECEAtkaRmm+uh9hp
         C9z753wQ0+bnOXAbXZw4o0JLMUoZkpTUYiDbbx3iT16vcZbNGmtGFpJvoTh7ZFxpTcdc
         5+0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/eguvHwOu0sO1sY9Y2sGUaUw1z+hAiiwi7HS5TszeM0=;
        b=WH2EYGsDVGXurtTJlELS6l4tMnBk0f6J5TKt+6noxCe0kzxUa5Zj+lP1lw6o10PM7P
         4KF61sWCSeyOgDS1UFtl8M8tTFIwD4PZpLhxVJhpx7ByAFdLb2OzoxtyKqVvDhFGSDGk
         sp25nAG6FiMbalJ/ht0b8gw458+X3KPM080tKM7f1qsVGxGN3tgZYFmJPjJe81ZhHz5h
         LeCv6nQqe/leUqjg+bw5fOmbrRNCHyfq0PeGc78jzJwMcv0Wl72b96eJ+PjLRk0mP1u0
         HdENrwWHzx3188s+vN3rjEpIqPeOizSNiwK4UKY3Kb5IsME4Qw/1pCNets7aaIwpiLOC
         eafA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=dv17cOT0;
       spf=pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-wr1-x442.google.com (mail-wr1-x442.google.com. [2a00:1450:4864:20::442])
        by gmr-mx.google.com with ESMTPS id t131si40889wmb.1.2020.01.28.01.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jan 2020 01:17:22 -0800 (PST)
Received-SPF: pass (google.com: domain of ard.biesheuvel@linaro.org designates 2a00:1450:4864:20::442 as permitted sender) client-ip=2a00:1450:4864:20::442;
Received: by mail-wr1-x442.google.com with SMTP id c9so15100046wrw.8
        for <kasan-dev@googlegroups.com>; Tue, 28 Jan 2020 01:17:22 -0800 (PST)
X-Received: by 2002:a5d:50cb:: with SMTP id f11mr1884084wrt.252.1580203042186;
 Tue, 28 Jan 2020 01:17:22 -0800 (PST)
MIME-Version: 1.0
References: <CAKv+Gu8ZcO3jRMuMJL_eTmWtuzJ+=qEA9muuN5DpdpikFLwamg@mail.gmail.com>
 <E600649B-A8CA-48D3-AD86-A2BAAE0BCA25@lca.pw> <CACT4Y+a5q1dWrm+PhWH3uQRfLWZ0HOyHA6Er4V3bn9tk85TKYA@mail.gmail.com>
 <CAKv+Gu8ZRjqvQvOJ5JXpAQXyApMQNAFz7cRO9NSjq9u=WnjkTA@mail.gmail.com> <CACT4Y+Z+vYF=6h0+ioMXGX6OHVnAXyHqOQLNFmngT9TqNwAgKA@mail.gmail.com>
In-Reply-To: <CACT4Y+Z+vYF=6h0+ioMXGX6OHVnAXyHqOQLNFmngT9TqNwAgKA@mail.gmail.com>
From: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Date: Tue, 28 Jan 2020 10:17:11 +0100
Message-ID: <CAKv+Gu8-LxoYNCtwG76UkUkNC_7XrRSfwfRm9=6WdZy=C_buJw@mail.gmail.com>
Subject: Re: mmotm 2020-01-23-21-12 uploaded (efi)
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Qian Cai <cai@lca.pw>, Randy Dunlap <rdunlap@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Brown <broonie@kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Michal Hocko <mhocko@suse.cz>, mm-commits@vger.kernel.org, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Ard Biesheuvel <ardb@kernel.org>, 
	linux-efi <linux-efi@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ard.biesheuvel@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=dv17cOT0;       spf=pass
 (google.com: domain of ard.biesheuvel@linaro.org designates
 2a00:1450:4864:20::442 as permitted sender) smtp.mailfrom=ard.biesheuvel@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Tue, 28 Jan 2020 at 10:08, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Tue, Jan 28, 2020 at 8:33 AM Ard Biesheuvel
> <ard.biesheuvel@linaro.org> wrote:
> > > > > Should be fixed by
> > > > >
> > > > > https://lore.kernel.org/linux-efi/20200121093912.5246-1-ardb@kernel.org/
> > > >
> > > > Cc kasan-devel@
> > > >
> > > > If everyone has to disable KASAN for the whole subdirectories like this, I am worried about we are losing testing coverage fairly quickly. Is there a bug in compiler?
> > >
> > > My understanding is that this is invalid C code in the first place,
> > > no? It just happened to compile with some compilers, some options and
> > > probably only with high optimization level.
> >
> > No, this is not true. The whole point of favoring IS_ENABLED(...) over
> > #ifdef ... has always been that the code remains visible to the
> > compiler, regardless of whether the option is selected or not, but
> > that it gets optimized away entirely. The linker errors prove that
> > there is dead code remaining in the object files, which means we can
> > no longer rely on IS_ENABLED() to work as intended.
>
> I agree that exposing more code to compiler is good, I prefer to do it
> as well. But I don't see how this proves anything wrt this particular
> code being invalid C. Called functions still need to be defined. There
> is no notion of dead code in C. Yes, this highly depends on compiler,
> options, optimization level, etc. Some combinations may work, some
> won't. E.g. my compiler compiles it just fine (clang 10) without
> disabling instrumentation... what does it prove? I don't know.
>
> To clarify: I completely don't object to patching this case in gcc
> with -O2, it just may be hard to find anybody willing to do this work
> if we are talking about fixing compilation of invalid code.
>

I don't mind simply disabling KASAN altogether for this code if nobody
can be bothered to fix the compiler.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKv%2BGu8-LxoYNCtwG76UkUkNC_7XrRSfwfRm9%3D6WdZy%3DC_buJw%40mail.gmail.com.
