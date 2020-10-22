Return-Path: <kasan-dev+bncBCMIZB7QWENRBN6EY36AKGQE4SY2ZCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7485229618A
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 17:16:09 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id a12sf1405610pfo.5
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 08:16:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603379768; cv=pass;
        d=google.com; s=arc-20160816;
        b=reazBVvMfjxUvn3w71hw0JcTsBP1hy8RUyVjGTjG3794/XwBNo6vqR2RoohMosL5EM
         RtLgWw85o/ltb/1TssHEsYnY1epxp4fEnd5XYMQE9CFic/MiMZekPqagroYCflRvmeZt
         pvxL7WzksjFPZ04WKYq3KCEw3PPwsCQHhDNrkwrsGIqx+OIMvNAXZ+7/QbQfbA8rlgbj
         JUVg5cqxeijnLluxpTFyyfksJ9EssVDRiTHcQGZWfF69Lgc36CEeP0Fbaa8jjOANQ0oz
         FMQwGAlzhiyGaz2f+WY1e1fohTF4KgNHoL3l+jgCr4k6urBd8bIdqjHqahMjZ0gl2uLa
         CQlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/EsYcVlDx+bgEC92dudqwW09KpKXgzQn96jgKvQplN4=;
        b=wVsPF2jC56FiWKFyvBmTAw4em1VkWAgABBzybro1df7Jv2poc8SZYCEu3ZAHSmXE25
         2VG0wE6St80hJ1MdvjEyslgSfWDm+t8OhtFbRUp/CyuqjPmE+8BX3lsBtCzCj/xh1FRi
         kNwPnwacl0CZ9+VMtkCKxJsVKBKF+uIiRLfVkvgiG4xJ+AILGaNqv9Ksv5/KLk6x0KXC
         ozPeZSAtHDwEa7gX0fRnunLkQPOzAxgojgm0A5m3+yFi+vAEPMmUaW6SaRAx5SyfHnO5
         9Plo8QrE/8QLNvIM4z6gjQNAu0PWai2XfE+jFXr1B7vkQbpNUTvgSgHJYfop0BgGCs6s
         Ul1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="pu4/oIE9";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/EsYcVlDx+bgEC92dudqwW09KpKXgzQn96jgKvQplN4=;
        b=R9hXgq2OtJQpAHDUCPOt1s4BrHucANj/tTtURnycfzlZcwJmokn2P5iKrZsVxK/Q4x
         AMhrxksB2ST1TLz+Vlx+yLmI0nv5auyhU7K8hFJELBTROZirAd2s2xtKtMbPIuLdwie4
         IpqbfDSGzh/n3plrlz1bops2ktCF6AJwx8bzvNVx1AaGufPgcPoSsZ/Iw46r+whkpc9C
         aO34Uw/HlgaaBcfejB3OQ7TUb5i6UoEizw/EeEw1ItyHeXv8P1GKJJlWIdhz9FPUgrjz
         1pNs3q2+b2V3Gyq3ITrsKDQOiLxwICXoec5St0CcuiK76kfeIDX+KmUFw3XBaxjJ6eql
         QAjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/EsYcVlDx+bgEC92dudqwW09KpKXgzQn96jgKvQplN4=;
        b=UFZ4QFakn3GvtnqEgzTRsbDIhbKYlqt1JEkh8nZe3FBaqQQ4RoeraFr4aSzBqRFfL5
         OltMtp5hz+3dyL9xjWnuPe1i2YLBnpaJtvNeizzqE6D30OdVydpE2r+n4bQvVm33GwGq
         0B1eb58kzT6LCdZLi2DaP9vQWoH/xRn6t5rwvNmrPzgCm7HicoAFkEKkHAAuuLhdO3mm
         MukpeuxPNka0Kq69H8t08RQjX62GKVdO+QkIiDm7vt0flEKrG6D3+B4umpAcBa5pYamt
         0dHfzVJRfy+83NMczZPL15AocpOK3wawWKQAGMZ7bBc0rKyXbDPWar26bY6Egcgyehef
         AuVQ==
X-Gm-Message-State: AOAM532UYZkI9EwsYal64Nh9uxOh9y+MT/8Rr18skRIJgqfyMXUsw6jV
	0VK8u1hPFvYP7FB8gwYpxcc=
X-Google-Smtp-Source: ABdhPJybRfom6IdKxG/1wleWTmNXxdYM4XLt7BZNubLsssnL86wM6CVaCi5ahFXnehYZxTuWJBzGTw==
X-Received: by 2002:a17:902:c40a:b029:d3:d448:98a8 with SMTP id k10-20020a170902c40ab02900d3d44898a8mr3169514plk.29.1603379767970;
        Thu, 22 Oct 2020 08:16:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3c5:: with SMTP id 188ls776136pgd.4.gmail; Thu, 22 Oct
 2020 08:16:07 -0700 (PDT)
X-Received: by 2002:a63:e502:: with SMTP id r2mr2679397pgh.362.1603379767469;
        Thu, 22 Oct 2020 08:16:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603379767; cv=none;
        d=google.com; s=arc-20160816;
        b=LebN1Pzy6FuZpw4R44Cp2Mdzp/ZN+J1jRrmUkP9XYdAUkkPdaqR4MOitBp/lk5X2GP
         P0Tw7bf32phjEMS8mZ11YmEX/SOyaA08RZtMoGiqX4k6Wu1L/FTp4v8x4bQW+ac0k39j
         CRhrCX1fcwfC4POj1KKNbiVC2OuYbeaWHdaTr5cU1xw4L9jz76uPdj16SmPrnHmPEoI9
         2IAc85NcACwWeOSKlWFH08BoQL2BmYwORq8ILF2rKJ4WT39Hchm41QniHKUQyylazJdG
         R+BZZ3RdPSC4vBa3nC1XOou8mPGUvzBHRRR6rMM91MzwoTJXBKq99XpjDgZQJDeI0FOl
         l4Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Z3vmtV0NaowwAl/bkuJPmHs13M06Kmq+h1vxwA4hLas=;
        b=YNYxjgi1Mv3hcZQBi89dcZPBWpGY9FRdjxEOILQqmjoN96VSPxfEctzTe5y6wGKfpm
         dIjzerPiRltudtKPssz7V/9hbQ8l6VQ9k3vjOH1GH8Liv98q98yMbKYVBSJ9OoIYPC7Q
         mkQGenLpnAJv9fTfH9MvZ00uTnFoMftfQ+jWD0ydwIgJEepfCpMyA99gXdJe/8SJ8Ptn
         Cmh7ZK/Lgx7eI1/Jy7hb+9n4NkN2+IY6//ESRcfbe4QaRIA42PAN3LE6gRSqTdlYgafT
         N9fIeSNCMKwoYSbPCK8yQjUfezz+o0WgZLn/jhNNYNB3uxqSTF27ZvvJih8hYMnF1jcP
         oM8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="pu4/oIE9";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id u192si154266pfc.6.2020.10.22.08.16.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 08:16:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id t9so1272393qtp.9
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 08:16:07 -0700 (PDT)
X-Received: by 2002:ac8:928:: with SMTP id t37mr2588192qth.67.1603379766837;
 Thu, 22 Oct 2020 08:16:06 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Oct 2020 17:15:55 +0200
Message-ID: <CACT4Y+bVCADgzweb_gmC9f7m_uc5r73scLPy+D3=Tbf2DFqb6g@mail.gmail.com>
Subject: Re: [PATCH RFC v2 00/21] kasan: hardware tag-based mode for
 production use on arm64
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="pu4/oIE9";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> This patchset is not complete (hence sending as RFC), but I would like to
> start the discussion now and hear people's opinions regarding the
> questions mentioned below.
>
> === Overview
>
> This patchset adopts the existing hardware tag-based KASAN mode [1] for
> use in production as a memory corruption mitigation. Hardware tag-based
> KASAN relies on arm64 Memory Tagging Extension (MTE) [2] to perform memory
> and pointer tagging. Please see [3] and [4] for detailed analysis of how
> MTE helps to fight memory safety problems.
>
> The current plan is reuse CONFIG_KASAN_HW_TAGS for production, but add a
> boot time switch, that allows to choose between a debugging mode, that
> includes all KASAN features as they are, and a production mode, that only
> includes the essentials like tag checking.
>
> It is essential that switching between these modes doesn't require
> rebuilding the kernel with different configs, as this is required by the
> Android GKI initiative [5].
>
> The patch titled "kasan: add and integrate kasan boot parameters" of this
> series adds a few new boot parameters:
>
> kasan.mode allows choosing one of main three modes:
>
> - kasan.mode=off - no checks at all
> - kasan.mode=prod - only essential production features
> - kasan.mode=full - all features
>
> Those mode configs provide default values for three more internal configs
> listed below. However it's also possible to override the default values
> by providing:
>
> - kasan.stack=off/on - enable stacks collection
>                        (default: on for mode=full, otherwise off)
> - kasan.trap=async/sync - use async or sync MTE mode
>                           (default: sync for mode=full, otherwise async)
> - kasan.fault=report/panic - only report MTE fault or also panic
>                              (default: report)
>
> === Benchmarks
>
> For now I've only performed a few simple benchmarks such as measuring
> kernel boot time and slab memory usage after boot. The benchmarks were
> performed in QEMU and the results below exclude the slowdown caused by
> QEMU memory tagging emulation (as it's different from the slowdown that
> will be introduced by hardware and therefore irrelevant).
>
> KASAN_HW_TAGS=y + kasan.mode=off introduces no performance or memory
> impact compared to KASAN_HW_TAGS=n.
>
> kasan.mode=prod (without executing the tagging instructions) introduces
> 7% of both performace and memory impact compared to kasan.mode=off.
> Note, that 4% of performance and all 7% of memory impact are caused by the
> fact that enabling KASAN essentially results in CONFIG_SLAB_MERGE_DEFAULT
> being disabled.
>
> Recommended Android config has CONFIG_SLAB_MERGE_DEFAULT disabled (I assume
> for security reasons), but Pixel 4 has it enabled. It's arguable, whether
> "disabling" CONFIG_SLAB_MERGE_DEFAULT introduces any security benefit on
> top of MTE. Without MTE it makes exploiting some heap corruption harder.
> With MTE it will only make it harder provided that the attacker is able to
> predict allocation tags.
>
> kasan.mode=full has 40% performance and 30% memory impact over
> kasan.mode=prod. Both come from alloc/free stack collection.
>
> === Questions
>
> Any concerns about the boot parameters?

For boot parameters I think we are now "safe" in the sense that we
provide maximum possible flexibility and can defer any actual
decisions.

> Should we try to deal with CONFIG_SLAB_MERGE_DEFAULT-like behavor mentioned
> above?

How hard it is to allow KASAN with CONFIG_SLAB_MERGE_DEFAULT? Are
there any principal conflicts?
The numbers you provided look quite substantial (on a par of what MTE
itself may introduce). So I would assume if a vendor does not have
CONFIG_SLAB_MERGE_DEFAULT disabled, it may not want to disable it
because of MTE (effectively doubles overhead).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbVCADgzweb_gmC9f7m_uc5r73scLPy%2BD3%3DTbf2DFqb6g%40mail.gmail.com.
