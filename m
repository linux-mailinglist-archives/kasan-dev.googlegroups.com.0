Return-Path: <kasan-dev+bncBDX4HWEMTEBRBY4CU76AKGQENQUYRVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 381C22908DA
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 17:51:03 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id g10sf1592620plq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Oct 2020 08:51:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602863461; cv=pass;
        d=google.com; s=arc-20160816;
        b=0DPhrvYEran74x06wnXOd4BpApUl0jLv24OiLUJmHEFOS31D/nRrTsspbd4hHY2SUC
         J93PkroHVyo4wYGUYMdsfSiRGc8OPuwqzqPISooXx4prbojSHTr9xV/Ia7uXjPCRsqnD
         bKT1/mLP6fDNKvnQDZgbZ+0X/P61Y3frB+vgd3n7+584+Az++Bv4a+55Gm1u/6fiyUiL
         VS0BqKVBetuW2wGG+CyB7/vbLO8n7a/dWRS8/6zifsm9wJ0fwItDR/CCVpIr+YsdW3uZ
         BryNWzjG6VASZtcFgQGgyMnWX1yzZ3mkS3v0tZ4zzeslhK7GtuOrOyqCzqUtqXb4nHt0
         bo5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zLDU8DNNnHhDum2FJbwTSIIEIf1HMmrsbsdGOWKZa1I=;
        b=Nh/wWlr+Mq6Wt9WOvnrmRYJUBP3XIWRIZSxHW7iyU9JYjSwobHUvUCAFrvELEnQRVJ
         3rPNAgHCI3iG+YDfkVJYxGaGnqvDPjtBXZ6WX1/1woPIOA78C/eCnCQLakSosoiMI6ZV
         pEyuA3vUDY70PwKlWK6YnCVWnvUlOvy8Y9umDPLZR7mkhJ5UnGqyclsFhZJl4tf14pFW
         tRtllTQ99C3/52AiC1LZrzPlBVuPbn4YbRitkGz1Yq8Fp7Yp5HWWpcXT+YeiRDa3dtY2
         HVdZ7dPEDQp+KoJUOOVGGurdQn1aslnw7Yo5FYe1/ayXzRNPhWhRm/iB31ayQbftvA2M
         tdRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cRZGgrF2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zLDU8DNNnHhDum2FJbwTSIIEIf1HMmrsbsdGOWKZa1I=;
        b=hRcZoPvUKZ6x76TqcITBUttfDUvzd9IZG9ZuDe/tFZoG5H4S7G2b+E6yo825obXya0
         QlfufrixprAmCwwG8sx/vqjCQPT2rJzXUJv/X3zYn7vHmHP6LGeeyGY1hGGjzUKe0Xgx
         ZeKdrXZRYzBT6S5OKn+fm2vgYNgPYH6EkObLFemIDH7jKrW8UfOQ3hIWgZpOtub5FhbC
         ZRJJ+FqapJ7ZhRcTa+qgTNGFeMQ9gJka9mlfrORu2y8UlvvGI3GqWkk9HW2hcqOkivM3
         1neodxRlYt378zeT7FtypZnW5TRJm0urpa+Ng3JVmOS2+GDa9KfPNhyTSeYIEt61doK9
         PNcA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zLDU8DNNnHhDum2FJbwTSIIEIf1HMmrsbsdGOWKZa1I=;
        b=UDhcZsROsp36h4rv93g/yQOui9AiJndZuXpv6mvXcoHmkQ2UVD611L3o5hP8JAnn2w
         v2KRFkexM9qOqKkqHckl180DqhUtw+zdrgqE+pj5taaGXYtw5wVTaaSNUhXkD3+NmJLR
         a92sJkrXZXHhj66uSGxTgHqWYy0KV2OwiXBTBRaVZ+bmplyNoVVJO1bnlOIjVbQ4aZBC
         q/9xz6BLEky0q9BSd1IuqlZaLaObFQKZNjJOUiTlqkwBpogSdlL6C300zF3syqFf4OMa
         taw8pi1122zyN/pxWgSvRszGr0d4JLXi68H2lDJhk6ZWi0/13Nlu1EgAWuoaC/xYe4KJ
         Pe2w==
X-Gm-Message-State: AOAM530IGHOSCqZFpSB3mMf/IxAckemMiuQwozs+0witAhDSPhCvEpZ0
	N5TpsI42uE4TnvxU+H+JWa0=
X-Google-Smtp-Source: ABdhPJwuzmNUaArusEM7AB/GbqQCuEVT51AiR2RvBrXnIxvgU25BWhq8WnLKlMyfYaGwGiqhnVq7pQ==
X-Received: by 2002:a17:90a:468b:: with SMTP id z11mr4618109pjf.157.1602863459596;
        Fri, 16 Oct 2020 08:50:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7b05:: with SMTP id w5ls1023417pfc.11.gmail; Fri, 16 Oct
 2020 08:50:59 -0700 (PDT)
X-Received: by 2002:aa7:868f:0:b029:155:dcd2:7320 with SMTP id d15-20020aa7868f0000b0290155dcd27320mr4350404pfo.53.1602863459006;
        Fri, 16 Oct 2020 08:50:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602863459; cv=none;
        d=google.com; s=arc-20160816;
        b=iJ6pDVyIrLy4TILD0nyNJrSfuL09TseSwHQzva1qxncTz8bt9NO8MisCB9ftuI0dAp
         uHWoDswC8UhIXlzPgddsiUv2xBN1G32gK7ZOmevvHZPU69Bq88WPvP5TYVRNTCPIvxW2
         EenlseS5GV2lX4CsF7btbrPUe7q9DnIkHcCkTdc3qx3rGXg0DONcFfOfXyyVAUlsTpH3
         gHS9VU2fBgbb4XaTFhg/oA6LpSLy1U0hSltYELsNSisZo+KPGa2BaiiDd+rpnby2Nt3l
         wugonMe1xVdS19BJFvgIHYjmThI/3wMt9cVy/r5sEh1sMukP2QywxFWxO5FVXueSo+xc
         sbtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9AggGaVcXWrDt7LOaJ51+MlVSwgTWD/C/vq9jiJpyPk=;
        b=L3NkdAlX9/OwGgGLQge4NDoDloml2V4+xxMyaBeWZIZ13FhLtwHBLKYZZNyfCLdrUB
         Gfvt5J5umlpGGFIf6eP1ax0rwrHjqI8QU3XgcL3twpHOSILN3H63tzh3fiPJU6Ac2Kmz
         UwtdigpJraT/Wd4TJU3L2gXuT6Uf8JR5xS68JxaBpPDihqlVbVgd2YdDFVt+DbexQFqH
         qVhHFL1lDlVZ5trfrBV7Jtjf0ZaXF3y1wGzU+K6qK5yl1658ZurtYENNZIFCoKWLidBz
         I3O0x40MCnyvuzmnJVbRKwPEQYPROWsLbdcbb+sEASf9XWyjcT81wcT5qjnfUzm5Zdgi
         J3KQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cRZGgrF2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id e22si205181pgv.5.2020.10.16.08.50.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Oct 2020 08:50:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id g16so1604642pjv.3
        for <kasan-dev@googlegroups.com>; Fri, 16 Oct 2020 08:50:58 -0700 (PDT)
X-Received: by 2002:a17:902:9681:b029:d5:cdbd:c38c with SMTP id
 n1-20020a1709029681b02900d5cdbdc38cmr947918plp.85.1602863458402; Fri, 16 Oct
 2020 08:50:58 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Oct 2020 17:50:47 +0200
Message-ID: <CAAeHK+wxqe9bdJm6o914=_GqsArVOGazYEQRt6FQbXHCOduJOw@mail.gmail.com>
Subject: Re: [PATCH RFC 0/8] kasan: hardware tag-based mode for production use
 on arm64
To: Kostya Serebryany <kcc@google.com>, Serban Constantinescu <serbanc@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cRZGgrF2;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Oct 14, 2020 at 10:44 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
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
>
> What should be the default when the parameter is not specified? I would
> argue that it should be "debug" (for hardware that supports MTE, otherwise
> "off"), as it's the implied default for all other KASAN modes.
>
> Should we somehow control whether to panic the kernel on a tag fault?
> Another boot time parameter perhaps?
>
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

CC Kostya and Serban.

>
> === Notes
>
> This patchset is available here:
>
> https://github.com/xairy/linux/tree/up-prod-mte-rfc1
>
> and on Gerrit here:
>
> https://linux-review.googlesource.com/c/linux/kernel/git/torvalds/linux/+/3460
>
> This patchset is based on v5 of "kasan: add hardware tag-based mode for
> arm64" patchset [1].
>
> For testing in QEMU hardware tag-based KASAN requires:
>
> 1. QEMU built from master [6] (use "-machine virt,mte=on -cpu max" arguments
>    to run).
> 2. GCC version 10.
>
> [1] https://lore.kernel.org/linux-arm-kernel/cover.1602535397.git.andreyknvl@google.com/
> [2] https://community.arm.com/developer/ip-products/processors/b/processors-ip-blog/posts/enhancing-memory-safety
> [3] https://arxiv.org/pdf/1802.09517.pdf
> [4] https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Security%20analysis%20of%20memory%20tagging.pdf
> [5] https://source.android.com/devices/architecture/kernel/generic-kernel-image
> [6] https://github.com/qemu/qemu
>
> Andrey Konovalov (8):
>   kasan: simplify quarantine_put call
>   kasan: rename get_alloc/free_info
>   kasan: introduce set_alloc_info
>   kasan: unpoison stack only with CONFIG_KASAN_STACK
>   kasan: mark kasan_init_tags as __init
>   kasan, arm64: move initialization message
>   arm64: kasan: Add system_supports_tags helper
>   kasan: add and integrate kasan_mode boot param
>
>  arch/arm64/include/asm/memory.h  |  1 +
>  arch/arm64/kernel/sleep.S        |  2 +-
>  arch/arm64/mm/kasan_init.c       |  3 ++
>  arch/x86/kernel/acpi/wakeup_64.S |  2 +-
>  include/linux/kasan.h            | 14 ++---
>  mm/kasan/common.c                | 90 ++++++++++++++++++--------------
>  mm/kasan/generic.c               | 18 ++++---
>  mm/kasan/hw_tags.c               | 63 ++++++++++++++++++++--
>  mm/kasan/kasan.h                 | 25 ++++++---
>  mm/kasan/quarantine.c            |  5 +-
>  mm/kasan/report.c                | 22 +++++---
>  mm/kasan/report_sw_tags.c        |  2 +-
>  mm/kasan/sw_tags.c               | 14 +++--
>  13 files changed, 182 insertions(+), 79 deletions(-)
>
> --
> 2.28.0.1011.ga647a8990f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bwxqe9bdJm6o914%3D_GqsArVOGazYEQRt6FQbXHCOduJOw%40mail.gmail.com.
