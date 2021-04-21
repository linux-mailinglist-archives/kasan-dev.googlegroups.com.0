Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQV476BQMGQEJPGBMWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 736C83666CA
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 10:11:48 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id d29-20020a17090259ddb02900eadb61377asf16591459plj.22
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 01:11:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618992707; cv=pass;
        d=google.com; s=arc-20160816;
        b=wfZZi6V6opZAqkQWgMxB+Oa0nNRlgzCN3iy62FHCSS6ubcCwl3jhi4E1xMNblkrkha
         NWgX+WXLiT4L2qQu9dDe2ovEbPUuUVVv2OvDXxb2oJ1WpNMlR43I0ba2AKRe0Prr3cTR
         /T73PSxLnJKBTf8AnJf/2PkoiV/mrQbwa3zitVMSkP7PiYaXzwo2K7QQZiJwrfe5TgqX
         psgnFWHhkN1U40vR/928U0zDm34jljFTZi/Nxo06IbChU+j6UcJ+hRCITAfZQ2j9rAyr
         dNa5t6iuM0Czding+m/IKd1buODIw9BAXuyKNcjR7Cjs4/62/uYFvHqO2sgkKJ8ic1Ws
         8Dqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LxBfVBXwfndsGqf2q+wXHVVYoSqRwXVz8Zt718tT3eU=;
        b=cnuZR9EyA8MNzM5Uoegks4E06Wct4+h4dPh6yTjAjbf1JDauxC4kP/0tVtNzD1sCJB
         VD+GlyCCjbMGz2SzdYeFanHC9PPUxVcBjiMJgD84+9Hyeoozy9HvBj1vEduTIGewn0CU
         l7QidwMxsPSywIxK3pReeTiGi1yOV9j1T0qqP8LtU7owzMlewy7+OADb/wF4xyl5bRat
         oQX/w9hzrfz9nY9d+s88b9H24iq7eB13h7ukXn54TvxYf6Ma1EfhfWkyGY6Z3mkmftV6
         EITmFdfnP1R9wAxA5fr2DxmEc7sy3NItzO7d4uy2axuJ1vmYMc5DvKnn6Xs4tZay7TZe
         zdGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pmcZpnXr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LxBfVBXwfndsGqf2q+wXHVVYoSqRwXVz8Zt718tT3eU=;
        b=LAkprPOka/7JxotpnoA3lqdc9mI1MoW0+SzRQ6ttGKTYG05Go/hAsivPp6SvxgJLQA
         P4KfarW5Wt2vN9mrBaU1+vWY2a0/tM9B5vLVmvwb0WrhRE3UhMdyhVcNIH3GVv7nMVJN
         VgEqtzOHXRPywXENPOHbbt+e+qd9nWOX8opKsiyOf619obRZpm1qwfQM+0C1PgRrSjOA
         Cd5/mnSuvCN1WHgvz/om0uybtDV3UuGT2xkEn4gMkTSjpP80+xUpUmyRxkupMxM5K3Ju
         romhbLno73abhUB8tvxk7FzE9/jkrf2Kh9jjgB9qBWpa1mOyBz1dn4pKxDCUnTv+NrBs
         BY6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LxBfVBXwfndsGqf2q+wXHVVYoSqRwXVz8Zt718tT3eU=;
        b=nY2kwi0jmau4SWbzs9eRXdumc8KBCyfaDNK/rpVPU53eM3Gm1jZRfF8f0/jhcB4/g6
         CSppGCiCv7/NY8gFuyTCtXYMcrCLIyKYwCq6jRSIpTbePeFNP0qTsb1GdE72/lm2Ylnc
         3Jv4HbsiizpkMsVsiiy3DiqzQc/P9QjydvqvW1qpRNQqy4khbO8XZNx1taATbZofGEr4
         uIwGx73ODh9J/QJORrZaLXp84305NUbkfQJAaiTi6UkH24ROJTiGNez1Ub7W/+pe0HXW
         PGRFqSpFF7razLeODWRr2CDoWXmDImShEzkn7iB0+lN8nkrSNHH4ipBZa96JSI3mOgHq
         mqmA==
X-Gm-Message-State: AOAM530WeSzBSUbuAXeGSISWgfAo9K/pOJSk55pDyuk7U9EG8RWP+prP
	9O0NVKhQdENUEN6My696Joc=
X-Google-Smtp-Source: ABdhPJxju9PKrGS1862aczgioffZkvoMz6yrXSVQ7tm3BoSGv2O5W068CPVl4ICHo5wIcEsRnfVieg==
X-Received: by 2002:a17:902:122:b029:e8:bde2:7f6c with SMTP id 31-20020a1709020122b02900e8bde27f6cmr33226097plb.29.1618992706831;
        Wed, 21 Apr 2021 01:11:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ba08:: with SMTP id s8ls1034793pjr.1.gmail; Wed, 21
 Apr 2021 01:11:46 -0700 (PDT)
X-Received: by 2002:a17:903:2c1:b029:eb:3000:2984 with SMTP id s1-20020a17090302c1b02900eb30002984mr33412338plk.15.1618992706186;
        Wed, 21 Apr 2021 01:11:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618992706; cv=none;
        d=google.com; s=arc-20160816;
        b=tDz8WIOywdANFvXiVnbBMoV/BBlinEJuYiIGGKFFy0lnBg/a4YqBSXGNAmieNw4gxV
         gTZF5KLuMgjxY4upo/pHm9KXfltsiyUjTG7VXyERbPDsvvhlMUJyVk28ow+1brdj7mBS
         JixT9B7DvqbGxsmzO7XT9saG8eg8qEYwT0rMAkTvlt8mB8MBUHUKScBT+V+DhN6sIotT
         1MjQ47leQDBM+I6AfxCwceYJ/bGlrjDP92Rdw4bKMaqfoI33vU+r1bVdsRbTw/6/gTS6
         d2rSoDBZhWWsJNCpnLMaDpOHhjP9YT5xlnvYTWLtATtuOilZD+DNDJQLSqkhETtVBMB3
         0oCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=msdAKUkaozlyVVqcOzRUhmh/jucXO4phsOtdu8kld0Q=;
        b=LKkRSUOEzgZXLrQS2e3f59hTcyXeE+3v7AKvBE/t+FmSSYiCeRoMNjEoteLfRIvg+V
         GfMVuVHDBVmQLIy84/Rpe7tElBtRW/oeI4AsRGsuaS/gkRRFn98JHtvk+tgf4ZNSqS2r
         2C/r2uYbaP0DXZ6XaqHgxE9ePvs3iY6UWFfDf0sXtnpqwGnRcbPPeJENSWOaTspINX2d
         XevFnUyOP98Yb45aRM/2IqzJvOyRkaZGDAZ3i81g9/fmROZJAXG+Hy/40LM8S0czL+7L
         NI1B2KXtPs6GeIHd2+rUxS9C0TrQzu/IaTd9hx6/C2ZaEI+s2saFaB+4RzcY+Kp8d+Ol
         grrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pmcZpnXr;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x235.google.com (mail-oi1-x235.google.com. [2607:f8b0:4864:20::235])
        by gmr-mx.google.com with ESMTPS id x3si819250pjo.3.2021.04.21.01.11.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 01:11:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as permitted sender) client-ip=2607:f8b0:4864:20::235;
Received: by mail-oi1-x235.google.com with SMTP id u16so24335127oiu.7
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 01:11:46 -0700 (PDT)
X-Received: by 2002:aca:bb06:: with SMTP id l6mr6066042oif.121.1618992705356;
 Wed, 21 Apr 2021 01:11:45 -0700 (PDT)
MIME-Version: 1.0
References: <20210408103605.1676875-1-elver@google.com> <CGME20210420212618eucas1p102b427d1af9c682217dfe093f3eac3e8@eucas1p1.samsung.com>
 <20210408103605.1676875-6-elver@google.com> <1fbf3429-42e5-0959-9a5c-91de80f02b6a@samsung.com>
 <CANpmjNM8wEJngK=J8Lt9npkZgrSWoRsqkdajErWEoY_=M1GW5A@mail.gmail.com>
 <43f8a3bf-34c5-0fc9-c335-7f92eaf23022@samsung.com> <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
In-Reply-To: <dccaa337-f3e5-08e4-fe40-a603811bb13e@samsung.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Apr 2021 10:11:33 +0200
Message-ID: <CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ@mail.gmail.com>
Subject: Re: [PATCH v4 05/10] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, Matt Morehouse <mascasa@google.com>, 
	Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, Oleg Nesterov <oleg@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pmcZpnXr;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::235 as
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

On Wed, 21 Apr 2021 at 09:35, Marek Szyprowski <m.szyprowski@samsung.com> wrote:
>
> On 21.04.2021 08:21, Marek Szyprowski wrote:
> > On 21.04.2021 00:42, Marco Elver wrote:
> >> On Tue, 20 Apr 2021 at 23:26, Marek Szyprowski
> >> <m.szyprowski@samsung.com> wrote:
> >>> On 08.04.2021 12:36, Marco Elver wrote:
> >>>> Introduces the TRAP_PERF si_code, and associated siginfo_t field
> >>>> si_perf. These will be used by the perf event subsystem to send
> >>>> signals
> >>>> (if requested) to the task where an event occurred.
> >>>>
> >>>> Acked-by: Geert Uytterhoeven <geert@linux-m68k.org> # m68k
> >>>> Acked-by: Arnd Bergmann <arnd@arndb.de> # asm-generic
> >>>> Signed-off-by: Marco Elver <elver@google.com>
> >>> This patch landed in linux-next as commit fb6cc127e0b6 ("signal:
> >>> Introduce TRAP_PERF si_code and si_perf to siginfo"). It causes
> >>> regression on my test systems (arm 32bit and 64bit). Most systems fails
> >>> to boot in the given time frame. I've observed that there is a timeout
> >>> waiting for udev to populate /dev and then also during the network
> >>> interfaces configuration. Reverting this commit, together with
> >>> 97ba62b27867 ("perf: Add support for SIGTRAP on perf events") to let it
> >>> compile, on top of next-20210420 fixes the issue.
> >> Thanks, this is weird for sure and nothing in particular stands out.
> >>
> >> I have questions:
> >> -- Can you please share your config?
> >
> > This happens with standard multi_v7_defconfig (arm) or just defconfig
> > for arm64.
> >
> >> -- Also, can you share how you run this? Can it be reproduced in qemu?
> > Nothing special. I just boot my test systems and see that they are
> > waiting lots of time during the udev populating /dev and network
> > interfaces configuration. I didn't try with qemu yet.
> >> -- How did you derive this patch to be at fault? Why not just
> >> 97ba62b27867, given you also need to revert it?
> > Well, I've just run my boot tests with automated 'git bisect' and that
> > was its result. It was a bit late in the evening, so I didn't analyze
> > it further, I've just posted a report about the issue I've found. It
> > looks that bisecting pointed to a wrong commit somehow.
> >> If you are unsure which patch exactly it is, can you try just
> >> reverting 97ba62b27867 and see what happens?
> >
> > Indeed, this is a real faulty commit. Initially I've decided to revert
> > it to let kernel compile (it uses some symbols introduced by this
> > commit). Reverting only it on top of linux-next 20210420 also fixes
> > the issue. I'm sorry for the noise in this thread. I hope we will find
> > what really causes the issue.
>
> This was a premature conclusion. It looks that during the test I've did
> while writing that reply, the modules were not deployed properly and a
> test board (RPi4) booted without modules. In that case the board booted
> fine and there was no udev timeout. After deploying kernel modules, the
> udev timeout is back.

I'm confused now. Can you confirm that the problem is due to your
kernel modules, or do you think it's still due to 97ba62b27867? Or
fb6cc127e0b6 (this patch)?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP6-yKpxHqYFiA8Up-ujBQaeP7xyq1BrsV-NqMjJ-uHAQ%40mail.gmail.com.
