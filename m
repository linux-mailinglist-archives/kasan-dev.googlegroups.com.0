Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ6AU6PQMGQECQZ6U2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 09D26693E94
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Feb 2023 08:00:57 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id g22-20020a05620a13d600b00726e7ad3f44sf6922521qkl.8
        for <lists+kasan-dev@lfdr.de>; Sun, 12 Feb 2023 23:00:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676271656; cv=pass;
        d=google.com; s=arc-20160816;
        b=0X9xSNr0z8reXgv9SWxOITtytuyO6qzHbjJ7zUwpP3rlaRC8xxoTAV6aj3f0tMCqXF
         E1mU3B5dwpHB5/nG0ZsIf6RgftX+Ix8bL5C/Y4e75AUdxKI8KkDSHGw3wME1V2WfQzwl
         RoE2N8WDsjoi8vGhgrIROLcDc3K6N+9vwrX7pmlqHo+MblO+GWIGB071m2VhWiscU2x5
         AqUT1Uodll4nRpW49IfxDVTKId592qp9NyjQ+JfQ8EYIzkVLN4WVQJxw6o4W0oLchmAf
         S99L4Xr+xWuF5+JV/FQApbHgyf4B5bY7bqm/446F7azlrGFqPmnHlqZLCsbZipE5vXqO
         Z64g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dUqRUZNJ9Yp4WgBdA+PmFlHeShlD+Goz1K840S7ZWcA=;
        b=E69PnXieDQ1m+9k6x3hJMIYKQcJGD8E6efUqlsJWqia0a9LRsaxXhyPC38g8RPjfbJ
         3OizMw7EwC0D5mSj4LBL/UTp5czRAiP3L5sMZabOQZCY2DfJHo2odOoXrZGrbnAfCbF/
         I/Pqj8U7Go54JfEHZ/O3YQxXab6/G2vCDPICXjA4VkvZ5Q1Fp/9rdqpruFNgazYAQrnV
         ymsvas5QQuO8qhq78B9xZY+UM04KBCjQDMXrR8IWONqm0+aiMMVvLfkdd/CCV3nluxn9
         JnoZmGBuarAwDI8Ua6kZiioqtmgdf1ty6Y4dvBYJ2FNCsoFsarhfxprkZsAdFP7TRKHj
         6vdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qXgprL15;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=dUqRUZNJ9Yp4WgBdA+PmFlHeShlD+Goz1K840S7ZWcA=;
        b=fO34PSzmZPw7YafWcvJ2qES5/s9FtnMsffYcImKYTONd51ZhLhzOjNk8UugQZ/S0fd
         lDyQSh8GJuWVYhwH6mGrhvq7AYwJduslFfFLDsGQ3DLmGDjVfp5PK5ZAgWQfsDx3fAeL
         I9pUuycubgjMJH2HbxMvL2LWXx3M4+NYXCLYXJ4imBlCthB5o1q4biS+vSfz07dF7weG
         kgQHUbEsLLi46AT90T7xLR/gzZn7h/dxFtlFX9eqmBSC3Zl18b9L5scX1ip3cwZD7o65
         NWPlxgm2yjDImVWvOrGsTJvhxWuLlOdZfvqZnl1W/il9jLBq82zutCZkx7xDTQxIroi/
         2/hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=dUqRUZNJ9Yp4WgBdA+PmFlHeShlD+Goz1K840S7ZWcA=;
        b=0uObLW5Y8Gqcy2DuOH9W6+q9x8AWE7TzElIv+8DziCeMFesh4MNFcP7MWwvPERQSD6
         g5UUobBiQKZGOfJKJjxKxW9NUiXhDPfAxXSgm2DG6X1pNDnCXlK/ttnXqd01ObC2q24K
         yBHFaNzJboxNv49QW0WVaoj9OXPdEjFlzxZhRH0znAkVR7MQ/nRvj0pqaRgCg3jdFtS9
         e5VK1ScpplXlSq2sJdzO86xnXDpWdtAkbq++n5UDJF4kuPqo3ekWy+gTIjfJ7ZfYoPk4
         hFS+utMuOB6vKrmtc/8F2pb6bhbDUEHQb1iEeDqLKK+z93XKQCOaz0RarK0eo49tJJhy
         FEHA==
X-Gm-Message-State: AO0yUKUUIKswbNQ2gGVf7jVPBgs0JGanZRaWwP3L/6PdfBaeV0c3Hna3
	eHAjoFxxW53mZwk0X+V13iQ=
X-Google-Smtp-Source: AK7set+UkVHL08NyhVwKrI9uIllyQxlAIK+y50jLPceTHuaHuZzlk3sEaqPVytK2zjFmMrohMvDW6A==
X-Received: by 2002:a37:bcc5:0:b0:722:e22f:f9ac with SMTP id m188-20020a37bcc5000000b00722e22ff9acmr1799148qkf.263.1676271655832;
        Sun, 12 Feb 2023 23:00:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:50b:b0:56e:97ee:a1df with SMTP id
 px11-20020a056214050b00b0056e97eea1dfls4767889qvb.7.-pod-prod-gmail; Sun, 12
 Feb 2023 23:00:55 -0800 (PST)
X-Received: by 2002:ad4:5dea:0:b0:56e:bd59:40f1 with SMTP id jn10-20020ad45dea000000b0056ebd5940f1mr56684qvb.48.1676271655191;
        Sun, 12 Feb 2023 23:00:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676271655; cv=none;
        d=google.com; s=arc-20160816;
        b=qCcVp38eOcg4FWuw1wAr7SsDrAeEY/QxaDL0h78GFNFk5Qz/qgeKTI2EmXI70gvF9J
         H0YcdTosdTmzDGBPSC0wzZadNuofqLbjCsSId9ZKv6/O6jnvnyIC6gKGiNUBphkBj0wm
         c1NuKFe1hegIcKSbeEKy8EK/Lm7Y2YCEjBIJbH+yhQzubJKFAHbqmANdo80+JYyHIRl4
         t7OlpaSeyAtPjPmYngzEMmbFf77FUuHjfefiD/siZribsUZnR+OtlFHr6PU4R2NgsYLR
         cGj9PIMZwrEq/O3EtpZuzyuz91KCQmolYZ7R44veh/VYtgkSdyUmiPm0RZtJvmVln24J
         lXmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Cw3Q2nDkJ9Bv8PVsAGDCbfG6m5PVGNiCmox+HLaI3GE=;
        b=BlVfxisoR6fCKGwgBscZfe7OzhRf75YhVyMIe0chmsj5Q5Qom4hjdSbVVqQk067D85
         GP8vZdn5Ndr/yccyHytrg7ulNmskroYuq3lDf/XhfkXdygenwdBIWzHh8mkx1wIe1dXo
         r2iDpFI1/w+ykosbpf6IkpUG35lzNVTVK71n1ZXuL6jj68Y0YXa/NtNf+zXcn/LdVWJW
         uLXPzR71DpVXrtQQXE7jS/wI/hiMRxhPrlnzp+VA/48cr/VsQVEGSS33Rm1LZUw8wsAc
         sV2UmAlQDtNqFz1tepX5kl+z8PPFhnzDk6GrfW+zTWMScsfsZkxqqoZBTzlHYz3w1Pgs
         vPQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qXgprL15;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa30.google.com (mail-vk1-xa30.google.com. [2607:f8b0:4864:20::a30])
        by gmr-mx.google.com with ESMTPS id z2-20020a05620a260200b0072ceb3a9fe4si963733qko.6.2023.02.12.23.00.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 12 Feb 2023 23:00:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as permitted sender) client-ip=2607:f8b0:4864:20::a30;
Received: by mail-vk1-xa30.google.com with SMTP id b81so5786731vkf.1
        for <kasan-dev@googlegroups.com>; Sun, 12 Feb 2023 23:00:55 -0800 (PST)
X-Received: by 2002:a1f:284e:0:b0:401:42f3:5659 with SMTP id
 o75-20020a1f284e000000b0040142f35659mr1000487vko.44.1676271654615; Sun, 12
 Feb 2023 23:00:54 -0800 (PST)
MIME-Version: 1.0
References: <20230208184203.2260394-1-elver@google.com> <CA+fCnZeU=pRcyiBpj3nyri0ow+ZYp=ewU3dtSVm_6mh73y1NTA@mail.gmail.com>
 <CANpmjNP_Ka6RTqHNRD7xx93ebZhY+iz69GHBusT=A8X1KvViVA@mail.gmail.com>
 <CA+fCnZcNF5kNxNuphwj41P45tQEhQ9wX00ZA4g=KTX4sbUirQg@mail.gmail.com>
 <CANpmjNNH-O+38U6zRWJUCU-eJTfMhUosy==GWEOn1vcu=J2dcw@mail.gmail.com> <CA+fCnZcaNpX6f9fWU2ZU-vMRn1fQ9mkr4w1JyOn3RmmoBK4PmQ@mail.gmail.com>
In-Reply-To: <CA+fCnZcaNpX6f9fWU2ZU-vMRn1fQ9mkr4w1JyOn3RmmoBK4PmQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 13 Feb 2023 08:00:00 +0100
Message-ID: <CANpmjNMdX9gzYEtUpESnFLT-0tPmZhU_GcK-6apW1yA0R2or0A@mail.gmail.com>
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable memintrinsics
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Nicolas Schier <nicolas@fjasle.eu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-kbuild@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Ingo Molnar <mingo@kernel.org>, Tony Lindgren <tony@atomide.com>, 
	Ulf Hansson <ulf.hansson@linaro.org>, linux-toolchains@vger.kernel.org, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qXgprL15;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a30 as
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

On Fri, 10 Feb 2023 at 22:37, Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Fri, Feb 10, 2023 at 7:41 PM Marco Elver <elver@google.com> wrote:
> >
> > On Fri, 10 Feb 2023 at 17:13, Andrey Konovalov <andreyknvl@gmail.com> wrote:
> > [...]
> > > > Probably the same should be done for SW_TAGS, because arm64 will be
> > > > GENERIC_ENTRY at one point or another as well.
> > >
> > > Yes, makes sense. I'll file a bug for this once I fully understand the
> > > consequences of these changes.
> > >
> > > > KASAN + GCC on x86 will have no mem*() instrumentation after
> > > > 69d4c0d32186, which is sad, so somebody ought to teach it the same
> > > > param as above.
> > >
> > > Hm, with that patch we would have no KASAN checking within normal mem*
> > > functions (not the ones embedded by the compiler) on GENERIC_ENTRY
> > > arches even with Clang, right?
> >
> > Yes, that's the point - normal mem*() functions cannot be instrumented
> > with GENERIC_ENTRY within noinstr functions, because the compiler
> > sometimes decides to transform normal assignments into
> > memcpy()/memset(). And if mem*() were instrumented (as it was before
> > 69d4c0d32186), that'd break things for these architectures.
> >
> > But since most code is normally instrumented, with the right compiler
> > support (which the patch here enables), we just turn mem*() in
> > instrumented functions into __asan_mem*(), and get the instrumentation
> > as before. 69d4c0d32186 already added those __asan functions. The fact
> > that KASAN used to override mem*() is just the wrong choice in a world
> > where compilers decide to inline or outline these. From an
> > instrumentation point of view at the compiler level, we need to treat
> > them like any other instrumentable instruction (loads, stores,
> > atomics, etc.): transform each instrumentable instruction into
> > something that does the right checks. Only then can we be sure that we
> > don't accidentally instrument something that shouldn't be (noinstr
> > functions), because instead of relying on the compiler, we forced
> > instrumentation on every mem*().
>
> I meant to ask whether the normal mem* calls from instrumented
> functions will also be transformed to __asan_mem*() by the compiler.
> But following the godbolt link you shared, I see that this is true.
>
> Thank you for the explanation!
>
> So the overall negative impact of these changes is that we don't get
> KASAN checking in both normal mem* calls and the ones formed by
> transforming assignments for GENERIC_ENTRY architectures with GCC and
> with older Clang. This is not great. I wonder if we then need to print
> some kind of warning when the kernel is built with these compilers.

Since these changes are already in -tip, and by judging from [1],
there really is no other way. As-is, KASAN on x86 is already broken
per [1] (though we got lucky thus far).

Printing a warning wouldn't hurt, but I think nobody would notice the
warning, and if somebody notices, they wouldn't care. Sooner or later,
we just need to make sure that test robots (syzbot, etc.) have new
compilers.

> If these changes move forward, AFAIU, we can also drop these custom
> mem* definitions for non-instrumented files for x86:
>
> https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/string_64.h#L88

Yes, I think so.

[1] https://lore.kernel.org/all/20230112194314.845371875@infradead.org/

Last but not least are you ok with this patch? This patch ought to be
applied to the same tree as 69d4c0d32186 anyway, so this patch lives
or dies by that change.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMdX9gzYEtUpESnFLT-0tPmZhU_GcK-6apW1yA0R2or0A%40mail.gmail.com.
