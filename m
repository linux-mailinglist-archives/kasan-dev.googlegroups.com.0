Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN57UH6AKGQEZO65XUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 96A5F28F4EE
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 16:42:00 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id o7sf2198302iof.18
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Oct 2020 07:42:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602772919; cv=pass;
        d=google.com; s=arc-20160816;
        b=gXqClX+CF0VrQ6W9zOTGF+AHnuihxB4NOVaAJ0LJDUe81OdlFoUfPyrcek+FN6FPcF
         aQ7j/DBYTkokjvcPQtOa8QNR0fBSrhblBwSPjbXwxFH6fyeP/IakBdH1sBnMGwKyeKW5
         /Q+bWoTH5ZsmU5PE1T137MGdG53pl1kZVXjUAppga5CDWzD07j72i/9qJa/c7i5uiLLf
         LlnxIkxbsQnNrhgtoXuYCHVnqndUhfU5+MMNLOJvaxLly1M1s+RXiy9JS4YwYmHtcwVT
         JVRsY1AhceeqLJVIUV4t4YaLYZBcsJE2H4uNgkJSORWjoXNFMoT4MM6mlZw+v/FMzVTb
         BXTw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fHaDRbc4u5/kery1jkMNu6FhiU7rGknaFA+TNBT0NUg=;
        b=hWOer5NghbU56U8PyMpoDo96+j4e1hzfIVGzVfR9+xPWk4EAmErMXc9szr7jcbkRjs
         h9k1WwB2Aqoh+V7sH0wK55XczKbwrx8aJAHX9wIC9WpqDHNwGYi1XZFnXzVAA2FT6sb6
         BxTkovf3cmIuVxOINriTEgiYfm1rYMWLSrryl/Ftlrupa51nTaF86Npj2ceR0Y093SOW
         oNBnnclm2uRddfW7AfQG0so2DTGXclQ4aHJk2LhnQPGq1FC97xYWepWVQhUh3Qc8MiYz
         U+gdvGwAL0MXZF8oMLBrKHyVu+Tn4yTYEHzhdFNviHgPF5i2t4aHznesQ+IdZGkrj5mu
         nuGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vE0eTPBn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fHaDRbc4u5/kery1jkMNu6FhiU7rGknaFA+TNBT0NUg=;
        b=SO4ACH/sZKahXU3U2XFLsuLxL2prmB7BmSt6Zdxz7MU5iJZX3wmB+eq5XtSR431LrV
         nwEgbs1G0VNrbbur53unqZIw4pU2OiOcZbOBFJxxKfKDqKxDWAvOU8I5/5CguIEQG3A6
         sNgnd9rg4AH1Q1Xpzkyejj7UsEkpU3LtvkycD5ZRLdxQIMvO5699jwUJA2gVyaMP3GDo
         t+559cU7ule1OwTmeoPTPw70iqsvzLghLrEdS0baeCnWG5ItzMrlsl++wQcc+YSkXsu8
         mWkon/fZdlq7zoKysLA4pSuu8nhqANw7Kf3/Bhf7+vL0+QRNP8lRGN1Yf7+keTyM5bUp
         J5Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fHaDRbc4u5/kery1jkMNu6FhiU7rGknaFA+TNBT0NUg=;
        b=UBwe16w0ihBwqIw1n6NPZdkQbreNkY2Ez4FZR2/w4cRVcc2dljoPkO/3aSlA0AXmVt
         +MdnJl3aN2Cm4ZP/ArGIx7Mys5kpZqvU/v0t6QtbEC/1BsZRP4ZMCti9ZiMm8Loq41nb
         hWkfY9h0nVGk4QUVZgk5dyQ2innMZb1vL+/mHJNu+J0Y3J3bv2E9znNfogrepmYWwiy0
         xI9pjYzKKEvQxczrkQNvUdbE043FyL95kFzoTs0W/dEXGPp27KQvqo8XFN5X6AXxfnnG
         dm7K4s6samvLV+NwQBJ6+TUIh1tBj0lDIAhb/1L0hLS4y60kscIsYVlayzNEvFocMSY9
         4htQ==
X-Gm-Message-State: AOAM530ZJtjtk6SKhwBDr6Z7rKXkLD5qI+pNnLJe3zLy1n81Gw7p3bSG
	RCYdJicSBA/jtR28mYLjX8U=
X-Google-Smtp-Source: ABdhPJzYDbYfpq6Y6C9TVgeg1slTK+ZoQ7ueVUnuqi6seAaAY1o3PugMM19srculm06cNqI/8b5VQg==
X-Received: by 2002:a92:9408:: with SMTP id c8mr3158493ili.61.1602772919310;
        Thu, 15 Oct 2020 07:41:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:890a:: with SMTP id k10ls419336ioj.4.gmail; Thu, 15 Oct
 2020 07:41:58 -0700 (PDT)
X-Received: by 2002:a6b:b413:: with SMTP id d19mr3507901iof.10.1602772918912;
        Thu, 15 Oct 2020 07:41:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602772918; cv=none;
        d=google.com; s=arc-20160816;
        b=mm8dLYhEvmCEP/fp60JxJpYRjUlqyNPbcTDRaHQyta0fUOpycRVeGLmNMpW0q0rVxM
         J08xqKgpaWwt7SeIJIijInqDauf+sEpptURUxHvQJWuTf/Vt8Ve+QeIm8S9y4YzbDBRf
         y0NDoacdgRcb4dgc70x198KHOdDeFG6Q6SzYWZq/yigzsjC27U4/D+FXtk/fUTaSHz+1
         IiOO/mGsnimm+KUv5TSkBboiEJ+ABlSIfvpo5M+erji5/oImRUfaPOLD/I2v2VCrsbXY
         RDBdKDRlWlrbhZ0wqz3baA9ShdntCKqGroDiJExMEkUh6u984KwCSxFaYGxKSoNAwqxZ
         EE2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P881tWlvRdjOUKzZkLHYnQuoFJ//OFLM6pqz5XqJ0Y0=;
        b=WqYvWDwW9Pm+9E+DtSPQumIk9bW6pFb5NYQdheYPIRn0m7d3eEajROEZIVZUFC00jG
         YZm6a04ZhZBAs5q8Hzca+QgNEdTa9hgzLdkEM34vieqG+JoTNDikJYmsGgfu7u/X/+qd
         qiirl/0Nz4v8NFAJT4PL+wCP0AgnMSpwQx6h20oMe8+3p90e1Ib7e8EwLis3Uhb5RRfH
         iG1QNebP+7L7+xGfezkPcm7fX6lfifzvkMKAOtihi4PqJY+9ifI4Hz3uKC4pplzTXJvg
         vMtokxkOohacpBZjc/9N11HmY0AmLbYtS/4OMmiWyerfMRHBvdGQPUmOSpI7alqO5RwG
         haxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vE0eTPBn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id d24si159832ioh.1.2020.10.15.07.41.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Oct 2020 07:41:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id e20so3075710otj.11
        for <kasan-dev@googlegroups.com>; Thu, 15 Oct 2020 07:41:58 -0700 (PDT)
X-Received: by 2002:a9d:649:: with SMTP id 67mr3039830otn.233.1602772918284;
 Thu, 15 Oct 2020 07:41:58 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Oct 2020 16:41:46 +0200
Message-ID: <CANpmjNOV90-eZyX9wjsahBkzCFMtm=Y0KtLn_VLDXVO_ehsR1g@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vE0eTPBn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Wed, 14 Oct 2020 at 22:44, Andrey Konovalov <andreyknvl@google.com> wrote:
> This patchset is not complete (see particular TODOs in the last patch),
> and I haven't performed any benchmarking yet, but I would like to start the
> discussion now and hear people's opinions regarding the questions mentioned
> below.
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
> The last patch of this series adds a new boot time parameter called
> kasan_mode, which can have the following values:
>
> - "kasan_mode=on" - only production features
> - "kasan_mode=debug" - all debug features
> - "kasan_mode=off" - no checks at all (not implemented yet)
>
> Currently outlined differences between "on" and "debug":
>
> - "on" doesn't keep track of alloc/free stacks, and therefore doesn't
>   require the additional memory to store those
> - "on" uses asyncronous tag checking (not implemented yet)
>
> === Questions
>
> The intention with this kind of a high level switch is to hide the
> implementation details. Arguably, we could add multiple switches that allow
> to separately control each KASAN or MTE feature, but I'm not sure there's
> much value in that.
>
> Does this make sense? Any preference regarding the name of the parameter
> and its values?

KASAN itself used to be a debugging tool only. So introducing an "on"
mode which no longer follows this convention may be confusing.
Instead, maybe the following might be less confusing:

"full" - current "debug", normal KASAN, all debugging help available.
"opt" - current "on", optimized mode for production.
"on" - automatic selection => chooses "full" if CONFIG_DEBUG_KERNEL,
"opt" otherwise.
"off" - as before.

Also, if there is no other kernel boot parameter named "kasan" yet,
maybe it could just be "kasan=..." ?

> What should be the default when the parameter is not specified? I would
> argue that it should be "debug" (for hardware that supports MTE, otherwise
> "off"), as it's the implied default for all other KASAN modes.

Perhaps we could make this dependent on CONFIG_DEBUG_KERNEL as above.
I do not think that having the full/debug KASAN enabled on production
kernels adds any value because for it to be useful requires somebody
to actually look at the stacktraces; I think that choice should be
made explicitly if it's a production kernel. My guess is that we'll
save explaining performance differences and resulting headaches for
ourselves and others that way.

> Should we somehow control whether to panic the kernel on a tag fault?
> Another boot time parameter perhaps?

It already respects panic_on_warn, correct?

> Any ideas as to how properly estimate the slowdown? As there's no
> MTE-enabled hardware yet, the only way to test these patches is use an
> emulator (like QEMU). The delay that is added by the emulator (for setting
> and checking the tags) is different from the hardware delay, and this skews
> the results.
>
> A question to KASAN maintainers: what would be the best way to support the
> "off" mode? I see two potential approaches: add a check into each kasan
> callback (easier to implement, but we still call kasan callbacks, even
> though they immediately return), or add inline header wrappers that do the
> same.
[...]

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOV90-eZyX9wjsahBkzCFMtm%3DY0KtLn_VLDXVO_ehsR1g%40mail.gmail.com.
