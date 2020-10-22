Return-Path: <kasan-dev+bncBDT63BOBRQFBBM47Y76AKGQEZOZUCSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id F3EAE2964AA
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 20:30:12 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id m62sf2651252ybb.6
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 11:30:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603391412; cv=pass;
        d=google.com; s=arc-20160816;
        b=kdrCgTtpGHo3QaiRE/330dSEQ1VF8vQFztqYrBi1xXOukLor+VQmrw2MVagL8hmWsz
         soDWVMO8CjmZJmi5xyEHJoZmWYZhpO5J9DNUGv8uokfdJSbSLzJxWuJhNCJveYWn3OdD
         p9El8rh08DEzndN5s57ogrSAyF94gNDlds8rKjb0ZYLzZJVHv3p/ucC1djNQ0j5DCrtn
         wN6q9wt/LRgOb1iN8i2l1+jGEXdmIRqQbo1V1Nq0E8A0aNP5hxgN9U+q3tnS5NAEymA0
         gwFBg7KEaPdMHsIqppKW1jqceuk2faDKUHDGY/z1ZT5pYujFnFy7LbSBTvJflEKYMZRg
         rBjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2HhBjy0Yp+IZ/xxa6Fr15VZWdTa3mZYWzsczOhNuRw0=;
        b=RdRut2MwMEmky4KJaqKJWHzNDgm4Rv9jP4ADnWqJSv64OVr7jNBvCdPfpLbygDSmVn
         4T0E60hGduW2VJpwf5VNXWh2ygC0tN8F686RNABfNcUWF/dlEMc9xXPMShxTWorGo854
         XNk0+8hByAmzJG6ivO53bzPnkUQqVETSFtDNN7r1uZClzH5hf4noHuOXxSiEI+my8Tpn
         bq6TJeWbGk+r+uXtVBL1W9ScLrFa2GssNEdEatXQOh0tglZLYU6NDXg/Y6OBOkTXxbAx
         5QrE7wmcE3XicTbFjJVp1fidjwjTOtaCcN2S7a1bAxD/Cl5j0F/9e7658MKR0eBlHUvY
         j42g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kamEeDWG;
       spf=pass (google.com: domain of kcc@google.com designates 2607:f8b0:4864:20::a44 as permitted sender) smtp.mailfrom=kcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2HhBjy0Yp+IZ/xxa6Fr15VZWdTa3mZYWzsczOhNuRw0=;
        b=TnBEZ7Tfdj0wNm9ARsjTc4NZSvtYcvH94hNvDReUKswzzUumGV3HNSSy8TnDmnOaAf
         OKb6O7o75oYY2ylhsI/ch9Jsp0C/C+EWkkWv0B+U8/HJ0e5jTvjpK84aaXv7ChRx2w/X
         JJBF1yD7GsAqq+HHSyBaBzM6FAa6sZuQGk7/5esIvvY4bV6jcdlhRaBQ/vBZnaJGAd8i
         pDC7BMLEXaFHAEfXAMFLB+D8N7tZzVXKKx050Y69uDnOZ8spDgPJmZO7FNGRUiEOPWU7
         395WqfSgzPPJXB1m5xkdXca+w1ylMfBljBuRzHcPdFCi3lDieO/31HCtettgRsV3Gme0
         TZ+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2HhBjy0Yp+IZ/xxa6Fr15VZWdTa3mZYWzsczOhNuRw0=;
        b=EVKjoEb6i9U/b+Rsr6NzolyvO0ZZiI2uSEEoBNkL0/ihpz2WMDIaDzMeX5IqIRtc43
         N9lLjKy6ZYEONU6LimNtb8sqNIfG8xQUsMXuC0VKpcbSWOWQrlty6qnerkm/EDhRtRRA
         4QxX4Bf+YQ4bmgNCAWkoEAWrYLZWK3lg8MKG9VO1DQpCiErKbdKwuuqTx4D3RASvAEgD
         Aw6r05/ErBZ7MmiG/6JUyze46MWemErzJEP5z5smqApXeTrgFBLpoCWf7qNquT2Y7J7U
         7SL2muxzzIHRra0H8d8mpsdQI00hhqIBbRkOx5uovGezPrRdDzi8e924BFRagii4zSBk
         pHkw==
X-Gm-Message-State: AOAM532cm6M8aOHDD8OC1mldcfpWDXol69ztVE1+kBv/KTOYq3uRqAlZ
	hQkk6g8WLFeWSZCz3sh89ro=
X-Google-Smtp-Source: ABdhPJx2BcTaW0J3HOMyJ5NhAcM1a0nVDcwpztldBef11zU90DUybmsT99XuIM8LDI1Dm5gt2iqPwg==
X-Received: by 2002:a25:d342:: with SMTP id e63mr5044667ybf.167.1603391412002;
        Thu, 22 Oct 2020 11:30:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2a0b:: with SMTP id q11ls1260483ybq.8.gmail; Thu, 22 Oct
 2020 11:30:11 -0700 (PDT)
X-Received: by 2002:a25:6892:: with SMTP id d140mr5182092ybc.492.1603391411540;
        Thu, 22 Oct 2020 11:30:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603391411; cv=none;
        d=google.com; s=arc-20160816;
        b=TnQxFjiEuE/0l15IxtX3gyuGdGYbCEJI79ov+O7S+vG9rTMHsoefbkNmvLvDHXZWJy
         HsJs5FG3WyTxt35UPeWZxvvnBOKh3JNHgHb66sBXv7XCX5WRZ8uF6Xh/YuXuS9bRc7Jo
         ZT5mp9VrUB/4OkEiF3JcCUwTje8uGQoDUSM/7ZKvLpB+vLhNngpyqJwlxtU6i6CSSM28
         3jnReE34B3h70lKWJnXqi0yGBgQJYT9OumIEwGEVlnPoW0Z7jfqN+a5Brgnp7Lr3rgKa
         ekLv+LhcUzLNTPW7sM6ovECmyqwfggMgxwT1UZSkbWpXBhlCEUS9JeHPjWpdm0+n8EHj
         dvxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=q4v8Ha3TFg3az8pkly9JegXyIbM/38NHzQoTOXoHd1s=;
        b=W27T+34nGiNHmWkg3lRgHDNOq4Oscmx8ak6JFuHjyF+Pk4k6Tejr86S9Qch1gfBN0/
         iG/rL8Som0gCLE9FiJ2rIjFIezT9aZoiVTDlg+nrHgbfl/k8R8zgXwg1r2ApuIPSZP5D
         N5Wn1dH7UzYnmv0ZXNtaOOBvK1at5xIJeslo3wZhbKg1gr6ENWBjbncVf8Sco4uxej+H
         c+MIUduMUWmIh78o6uSxH8XeK54ALG3Xqmi5aZ6MZMxp8x6T28tvhK7+UkCYRHlY0Nk/
         R/hTIN2Jk5MvpgwgtYZHjhmh6fM5aG8WBzbKkrz92GKpLCG8WuHcCHns04uJOl4g9P1Q
         +M1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kamEeDWG;
       spf=pass (google.com: domain of kcc@google.com designates 2607:f8b0:4864:20::a44 as permitted sender) smtp.mailfrom=kcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa44.google.com (mail-vk1-xa44.google.com. [2607:f8b0:4864:20::a44])
        by gmr-mx.google.com with ESMTPS id h89si245097ybi.5.2020.10.22.11.30.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 11:30:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of kcc@google.com designates 2607:f8b0:4864:20::a44 as permitted sender) client-ip=2607:f8b0:4864:20::a44;
Received: by mail-vk1-xa44.google.com with SMTP id a8so606774vkm.2
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 11:30:11 -0700 (PDT)
X-Received: by 2002:a1f:d844:: with SMTP id p65mr2842445vkg.23.1603391410889;
 Thu, 22 Oct 2020 11:30:10 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <CACT4Y+bVCADgzweb_gmC9f7m_uc5r73scLPy+D3=Tbf2DFqb6g@mail.gmail.com>
 <CAAeHK+xEQ2krRDrPPFmOvp-pR+jR179VDg1iwd+mB0hVZ9rsgg@mail.gmail.com>
In-Reply-To: <CAAeHK+xEQ2krRDrPPFmOvp-pR+jR179VDg1iwd+mB0hVZ9rsgg@mail.gmail.com>
From: "'Kostya Serebryany' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Oct 2020 11:29:59 -0700
Message-ID: <CAN=P9piWK0Wk7LzLv3j1SQrR4=ifOv+e2KawCLLNftErZQzLww@mail.gmail.com>
Subject: Re: [PATCH RFC v2 00/21] kasan: hardware tag-based mode for
 production use on arm64
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kamEeDWG;       spf=pass
 (google.com: domain of kcc@google.com designates 2607:f8b0:4864:20::a44 as
 permitted sender) smtp.mailfrom=kcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Kostya Serebryany <kcc@google.com>
Reply-To: Kostya Serebryany <kcc@google.com>
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

The boot parameters look great!

Do we use redzones in kasan.mode=prod?
(I think we should not)

Please separate the work on improving the stack trace collection form the work
on enabling kasan.mode=prod, the latter is more important IMHO.

Still some notes on stack traces:

> kasan.mode=full has 40% performance and 30% memory impact over
> kasan.mode=prod. Both come from alloc/free stack collection.

This is a lot. Right?
Please provide a more detailed breakdown:
* CPU overhead of collecting stack traces vs overhead of putting them
in a container/depot
* RAM overhead depending on the number of frames stored
* RAM overhead of the storage container (or redones?)
* How much is 30% in absolute numbers?

Do we perform any stack trace compressions?

Can we collect stack traces from the shadow call stack, when it's
available (default on Android)?

As we discussed offline, I think we have a way to compress reasonably
long stack traces into 8 bytes,
but it will take some effort and time to implement:
* collect the stack trace as usual (with shadow stack, when available)
* compute a hash of the top N frames
* store the hash, discard the stack trace. On trap, report the hashes
for allocation/deallocation
* Offline, analyze the binary to reconstruct the call graph, including
the indirect calls
* Perform DFS search from kmalloc/kfree up the call graph to depth N,
compute hashes for all paths,
report paths with the hash that matches the hash in the report.
My preliminary investigation shows that we can do it easily for N <= 10.
The trickiest bit here is to build the call graph for indirect calls,
but we should be able to do it.



On Thu, Oct 22, 2020 at 10:00 AM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 5:16 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > This patchset is not complete (hence sending as RFC), but I would like to
> > > start the discussion now and hear people's opinions regarding the
> > > questions mentioned below.
> > >
> > > === Overview
> > >
> > > This patchset adopts the existing hardware tag-based KASAN mode [1] for
> > > use in production as a memory corruption mitigation. Hardware tag-based
> > > KASAN relies on arm64 Memory Tagging Extension (MTE) [2] to perform memory
> > > and pointer tagging. Please see [3] and [4] for detailed analysis of how
> > > MTE helps to fight memory safety problems.
> > >
> > > The current plan is reuse CONFIG_KASAN_HW_TAGS for production, but add a
> > > boot time switch, that allows to choose between a debugging mode, that
> > > includes all KASAN features as they are, and a production mode, that only
> > > includes the essentials like tag checking.
> > >
> > > It is essential that switching between these modes doesn't require
> > > rebuilding the kernel with different configs, as this is required by the
> > > Android GKI initiative [5].
> > >
> > > The patch titled "kasan: add and integrate kasan boot parameters" of this
> > > series adds a few new boot parameters:
> > >
> > > kasan.mode allows choosing one of main three modes:
> > >
> > > - kasan.mode=off - no checks at all
> > > - kasan.mode=prod - only essential production features
> > > - kasan.mode=full - all features
> > >
> > > Those mode configs provide default values for three more internal configs
> > > listed below. However it's also possible to override the default values
> > > by providing:
> > >
> > > - kasan.stack=off/on - enable stacks collection
> > >                        (default: on for mode=full, otherwise off)
> > > - kasan.trap=async/sync - use async or sync MTE mode
> > >                           (default: sync for mode=full, otherwise async)
> > > - kasan.fault=report/panic - only report MTE fault or also panic
> > >                              (default: report)
> > >
> > > === Benchmarks
> > >
> > > For now I've only performed a few simple benchmarks such as measuring
> > > kernel boot time and slab memory usage after boot. The benchmarks were
> > > performed in QEMU and the results below exclude the slowdown caused by
> > > QEMU memory tagging emulation (as it's different from the slowdown that
> > > will be introduced by hardware and therefore irrelevant).
> > >
> > > KASAN_HW_TAGS=y + kasan.mode=off introduces no performance or memory
> > > impact compared to KASAN_HW_TAGS=n.
> > >
> > > kasan.mode=prod (without executing the tagging instructions) introduces
> > > 7% of both performace and memory impact compared to kasan.mode=off.
> > > Note, that 4% of performance and all 7% of memory impact are caused by the
> > > fact that enabling KASAN essentially results in CONFIG_SLAB_MERGE_DEFAULT
> > > being disabled.
> > >
> > > Recommended Android config has CONFIG_SLAB_MERGE_DEFAULT disabled (I assume
> > > for security reasons), but Pixel 4 has it enabled. It's arguable, whether
> > > "disabling" CONFIG_SLAB_MERGE_DEFAULT introduces any security benefit on
> > > top of MTE. Without MTE it makes exploiting some heap corruption harder.
> > > With MTE it will only make it harder provided that the attacker is able to
> > > predict allocation tags.
> > >
> > > kasan.mode=full has 40% performance and 30% memory impact over
> > > kasan.mode=prod. Both come from alloc/free stack collection.
>
> FTR, this only accounts for slab memory overhead that comes from
> redzones that store stack ids. There's also page_alloc overhead from
> the stacks themselves, which I didn't measure yet.
>
> > >
> > > === Questions
> > >
> > > Any concerns about the boot parameters?
> >
> > For boot parameters I think we are now "safe" in the sense that we
> > provide maximum possible flexibility and can defer any actual
> > decisions.
>
> Perfect!
>
> I realized that I actually forgot to think about the default values
> when no boot params are specified, I'll fix this in the next version.
>
> > > Should we try to deal with CONFIG_SLAB_MERGE_DEFAULT-like behavor mentioned
> > > above?
> >
> > How hard it is to allow KASAN with CONFIG_SLAB_MERGE_DEFAULT? Are
> > there any principal conflicts?
>
> I'll explore this.
>
> > The numbers you provided look quite substantial (on a par of what MTE
> > itself may introduce). So I would assume if a vendor does not have
> > CONFIG_SLAB_MERGE_DEFAULT disabled, it may not want to disable it
> > because of MTE (effectively doubles overhead).
>
> Sounds reasonable.
>
> Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAN%3DP9piWK0Wk7LzLv3j1SQrR4%3DifOv%2Be2KawCLLNftErZQzLww%40mail.gmail.com.
