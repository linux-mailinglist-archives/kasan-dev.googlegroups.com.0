Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCFJS7YQKGQE457AO5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 493B9142F83
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 17:25:45 +0100 (CET)
Received: by mail-vk1-xa3e.google.com with SMTP id s4sf67155vkk.7
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Jan 2020 08:25:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579537544; cv=pass;
        d=google.com; s=arc-20160816;
        b=dURs4eR4KSW5MRTpJzAv+rPLxRQMWgc5kN6AMlo4Q/8bumT5+EZaLJyCF/5dg/ftXe
         RMbaPpoBAk2AlZfNfsAnv0vZcM4UFgVheH11JMglsWHDPP14dE0yejfx4XrQX7axP89v
         3ULAiAJ22IcEfvPiuxGS7Q9mNNCxBmRMV2MZ7j8TGoqXXqGd6KfSyWNizqxo3C1PcSvz
         qkhJ5iENvY4IoqKQ/3qLUp5cnkpbNH6TYhEz1RisVnN0wLYorfLHqLSro2edD/58skfI
         I1skV0P3WQubSxW8LLCueQwRtxpGIjh5rBpd4Mi0Y/WbOkvBTtUJO53Y7fOlVtKASYRf
         saZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=6u6a+qaKYEFpI5za5lnX7d/FsUnO2qMiWaizuxXgDgo=;
        b=wOBiMTdqUVF2f9L92WeCwnNs7FQkGGercW3FREhIpI51SNwufxei8sJEZcqZ7zuBjE
         a0TgZ3NA55Tv/K55gph6ZZhaKEBGr2vaeWxaZaMtGCc5sJylmtnY3pvP2KhHwmZyc2Lt
         S1AGNuAVVpP7cIYlv8zCzprmOhulzBokePntdppX9xwqpZO1ImNshRp9eYibMmPJ9zgj
         KRtw92O2UJph8Ofmrou7EQBpPsE6c6buR3RGMSybJSztA/MheuogM3l82lohy0Vd9Qb4
         mkWUOJbtRTXopWzqmtQYyX6M1RvxzeV6027cmzfu4ITfK3kskZrIzMIM7EuN1G7t54ml
         Z3tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A1XqDsGu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6u6a+qaKYEFpI5za5lnX7d/FsUnO2qMiWaizuxXgDgo=;
        b=UMZEMEauOqEX0RNbYihO/ELeP4niv2gBrfPc0j8UZd6F6v4Wqp7A1GS+c6kr+RPTKj
         Ib8wXtFs87paZIm6fFdOXxsX1Egapj7/O0WBB8A//FtBQbPAdW1ChvVrTjfs1MrOxXAQ
         QaxEA2CfKcRAAEdPLnBh3+aFGS/FAl61s4B5KePeMZEXm8MZA0g/1Vem3lf9Key7Ayv3
         0G5e0mUBg/A4ir8wjSPf808RbPCaRoO5xU3vxrPRwdocd1dOdSAhfcJFsjDTeh64pVg7
         fF5dBNGPBVd09CffKBE1sE8+Kjp3AGW4K3NbzHwlATEC2DeUz+cqNoJ5v70LiaBzDFwN
         y49w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6u6a+qaKYEFpI5za5lnX7d/FsUnO2qMiWaizuxXgDgo=;
        b=oBoItUy5N/M0zYeCVQSAFdTHmt5cXj7B3DJc5ZWgitzgrI3PjJnUH6qQjI1J1Yn33K
         HxWlzlOd4dt6GAN8UwyyvEOMSvH3m6ijBYyu/gxyRCB1UsD8r4NCG8GCr4DybhosS9pW
         sW5ozMnUoaJHExnwxDgI/gO7AXHq8duzcPpU1o1ZSihVDYYo0Fzv0/+bHxPdG3szbtf+
         PF4ieWrx4BOkctoeUWVrJYfQ51vprHQi7RAUJBuf7GGdq6E0Aitu/wo3F7WrdUHQxZPB
         je3NBP/a4EOsGEmDJSvTNdw0t1u06eTQEyZnZ1WrdmVDJmhVPkTTS0eScX+a8Bva5YtL
         JVeg==
X-Gm-Message-State: APjAAAWxSHYe2U3dy1nlyG6vU/D+ZaZRpQw+f/pSdGEumG4Q7RBGskuj
	yKnLWOshU2ZwTZcA41YG9uQ=
X-Google-Smtp-Source: APXvYqzUExHG4/i5kkAgRAsPrxsgnz4Ex1Tk17tlOMIeJw943IbqFCGZ9xFL0kpTugKpbTaFhg4jeA==
X-Received: by 2002:a67:f057:: with SMTP id q23mr13049777vsm.5.1579537544293;
        Mon, 20 Jan 2020 08:25:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a4d2:: with SMTP id n201ls1366466vke.12.gmail; Mon, 20
 Jan 2020 08:25:43 -0800 (PST)
X-Received: by 2002:a1f:1fd1:: with SMTP id f200mr253170vkf.21.1579537543730;
        Mon, 20 Jan 2020 08:25:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579537543; cv=none;
        d=google.com; s=arc-20160816;
        b=MjQkEPFnZnVgb9u8cpDmVgSX1GHqvTxPHJ2qy5JbjqBEFLga/LrEUMybvXsBzPfgpN
         jBaKa9QN2k5dENE4K9Lg6WJUN8jmb2hGf/G6lmijWu0kbG3DZ7I6C7dQCS+gHvBxMyO8
         6Z7Cti7N183pMoXBIy7G4Zqn0b1ZBAGkOPLcS6yhrrgYUcppSAiy/D9qDeOJQXf/phec
         5kc5ZnfEe4atMYB25GxQkz1SFJXEQpGiJno1yheHnoDSlxkILZNFsnxHNWCiZE7x96BW
         dlSFwcNOZXm6slwsO1riU8crzm1FG4Fr3/okasmFZsjYRJO3e0D/vMnR0RuS56u0xcZU
         LmIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7cSDWZohrZmB4Lsh7kYAZSQYpOg12wvWZ6eMxNAuFio=;
        b=w6K58gW3CMNNCnrLu3gVz4c3SvCPSWW0Sg2A6xvxhZ8I5NEsPm10yQ2WtUlmdHnDr7
         1Zjd1MbkC8Bo0upQKT8qBZpCR0Dt9LDMNk/TahgKut5D48+0fv3ymRKsCDu2VtV/OZy0
         afcQasbxjpT9Nqj82iIvNm2Gm+0CF+SLzfbBC0fhjvPuPCEqTItRsCXHObr8OuWlvZBh
         LtvGaiRVZUU0+CP1puf5uJtEEZf3g5rffSkK1hDdHP76lPrUjFjg466TR7IdnLSIPgce
         EVrXh9VXlAwFfhoWX01uLZr84Rfruzuz7v1RmaHJYrA/Ob0jPJD44l9+9sVkc5u5XDMc
         guNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A1XqDsGu;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id o19si1580922vka.4.2020.01.20.08.25.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Jan 2020 08:25:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id z9so255767oth.5
        for <kasan-dev@googlegroups.com>; Mon, 20 Jan 2020 08:25:43 -0800 (PST)
X-Received: by 2002:a05:6830:1d7b:: with SMTP id l27mr136144oti.251.1579537542903;
 Mon, 20 Jan 2020 08:25:42 -0800 (PST)
MIME-Version: 1.0
References: <20200120141927.114373-1-elver@google.com> <CACT4Y+bnRoKinPopVqyxj4av6_xa_OUN0wwnidpO3dX3iYq_gg@mail.gmail.com>
 <CACT4Y+YuTT6kZ-AkgU0c1o09qmQdFWr4_Sds4jaDg-Va6g6jkA@mail.gmail.com>
 <CACT4Y+acrXkA-ixjQXqNf1EC=fpgTWf3Rcevxxon0DfrPdD-UQ@mail.gmail.com>
 <CANpmjNNcXUF-=Y-hmry9-xEoNpJd0WH+fOcJJM6kv2eRm5v-kg@mail.gmail.com> <CACT4Y+bD3cNxfaWOuhHz338MoVoaHpw-E8+b7v6mo_ir2KD46Q@mail.gmail.com>
In-Reply-To: <CACT4Y+bD3cNxfaWOuhHz338MoVoaHpw-E8+b7v6mo_ir2KD46Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Jan 2020 17:25:31 +0100
Message-ID: <CANpmjNN-8CLN9v7MehNUXy=iEXOfFHwpAUEPivGM573EQqmCZw@mail.gmail.com>
Subject: Re: [PATCH 1/5] include/linux: Add instrumented.h infrastructure
To: Dmitry Vyukov <dvyukov@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Will Deacon <will@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Arnd Bergmann <arnd@arndb.de>, Al Viro <viro@zeniv.linux.org.uk>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, Daniel Axtens <dja@axtens.net>, 
	Michael Ellerman <mpe@ellerman.id.au>, Steven Rostedt <rostedt@goodmis.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Ingo Molnar <mingo@kernel.org>, 
	Christian Brauner <christian.brauner@ubuntu.com>, Daniel Borkmann <daniel@iogearbox.net>, cyphar@cyphar.com, 
	Kees Cook <keescook@chromium.org>, linux-arch <linux-arch@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A1XqDsGu;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Mon, 20 Jan 2020 at 17:06, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Jan 20, 2020 at 4:40 PM Marco Elver <elver@google.com> wrote:
> > > > > > This adds instrumented.h, which provides generic wrappers for memory
> > > > > > access instrumentation that the compiler cannot emit for various
> > > > > > sanitizers. Currently this unifies KASAN and KCSAN instrumentation. In
> > > > > > future this will also include KMSAN instrumentation.
> > > > > >
> > > > > > Note that, copy_{to,from}_user require special instrumentation,
> > > > > > providing hooks before and after the access, since we may need to know
> > > > > > the actual bytes accessed (currently this is relevant for KCSAN, and is
> > > > > > also relevant in future for KMSAN).
> > > > > >
> > > > > > Suggested-by: Arnd Bergmann <arnd@arndb.de>
> > > > > > Signed-off-by: Marco Elver <elver@google.com>
> > > > > > ---
> > > > > >  include/linux/instrumented.h | 153 +++++++++++++++++++++++++++++++++++
> > > > > >  1 file changed, 153 insertions(+)
> > > > > >  create mode 100644 include/linux/instrumented.h
> > > > > >
> > > > > > diff --git a/include/linux/instrumented.h b/include/linux/instrumented.h
> > > > > > new file mode 100644
> > > > > > index 000000000000..9f83c8520223
> > > > > > --- /dev/null
> > > > > > +++ b/include/linux/instrumented.h
> > > > > > @@ -0,0 +1,153 @@
> > > > > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > > > > +
> > > > > > +/*
> > > > > > + * This header provides generic wrappers for memory access instrumentation that
> > > > > > + * the compiler cannot emit for: KASAN, KCSAN.
> > > > > > + */
> > > > > > +#ifndef _LINUX_INSTRUMENTED_H
> > > > > > +#define _LINUX_INSTRUMENTED_H
> > > > > > +
> > > > > > +#include <linux/compiler.h>
> > > > > > +#include <linux/kasan-checks.h>
> > > > > > +#include <linux/kcsan-checks.h>
> > > > > > +#include <linux/types.h>
> > > > > > +
> > > > > > +/**
> > > > > > + * instrument_read - instrument regular read access
> > > > > > + *
> > > > > > + * Instrument a regular read access. The instrumentation should be inserted
> > > > > > + * before the actual read happens.
> > > > > > + *
> > > > > > + * @ptr address of access
> > > > > > + * @size size of access
> > > > > > + */
> > > > >
> > > > > Based on offline discussion, that's what we add for KMSAN:
> > > > >
> > > > > > +static __always_inline void instrument_read(const volatile void *v, size_t size)
> > > > > > +{
> > > > > > +       kasan_check_read(v, size);
> > > > > > +       kcsan_check_read(v, size);
> > > > >
> > > > > KMSAN: nothing
> > > >
> > > > KMSAN also has instrumentation in
> > > > copy_to_user_page/copy_from_user_page. Do we need to do anything for
> > > > KASAN/KCSAN for these functions?
> >
> > copy_to_user_page/copy_from_user_page can be instrumented with
> > instrument_copy_{to,from}_user_. I prefer keeping this series with no
> > functional change intended for KASAN at least.
> >
> > > There is also copy_user_highpage.
> > >
> > > And ioread/write8/16/32_rep: do we need any instrumentation there. It
> > > seems we want both KSAN and KCSAN too. One may argue that KCSAN
> > > instrumentation there is to super critical at this point, but KASAN
> > > instrumentation is important, if anything to prevent silent memory
> > > corruptions. How do we instrument there? I don't see how it maps to
> > > any of the existing instrumentation functions.
> >
> > These should be able to use the regular instrument_{read,write}. I
> > prefer keeping this series with no functional change intended for
> > KASAN at least.
>
> instrument_{read,write} will not contain any KMSAN instrumentation,
> which means we will effectively remove KMSAN instrumentation, which is
> weird because we instrumented these functions because of KMSAN in the
> first place...
>
> > > There is also kmsan_check_skb/kmsan_handle_dma/kmsan_handle_urb that
> > > does not seem to map to any of the instrumentation functions.
> >
> > For now, I would rather that there are some one-off special
> > instrumentation, like for KMSAN. Coming up with a unified interface
> > here that, without the use-cases even settled, seems hard to justify.
> > Once instrumentation for these have settled, unifying the interface
> > would have better justification.
>
> I would assume they may also require an annotation that checks the
> memory region under all 3 tools and we don't have such annotation
> (same as the previous case and effectively copy_to_user). I would
> expect such annotation will be used in more places once we start
> looking for more opportunities.

Agreed, I'm certainly not against adding these. We may need to
introduce 'instrument_dma_' etc. However, would it be reasonable to do
this in a separate follow-up patch-series, to avoid stalling bitops
instrumentation?  Assuming that the 8 hooks in instrumented.h right
now are reasonable, and such future changes add new hooks, I think
that would be the more pragmatic approach.

Thanks,
-- Marco

>
> > This patch series is merely supposed to introduce instrumented.h and
> > replace the kasan_checks (also implicitly introducing kcsan_checks
> > there), however, with no further functional change intended.
> >
> > I propose that adding entirely new instrumentation for both KASAN and
> > KCSAN, we should send a separate patch-series.
> >
> > Thanks,
> > -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN-8CLN9v7MehNUXy%3DiEXOfFHwpAUEPivGM573EQqmCZw%40mail.gmail.com.
