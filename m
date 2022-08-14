Return-Path: <kasan-dev+bncBAABBRVP4GLQMGQE5GOMGPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B8B2591D86
	for <lists+kasan-dev@lfdr.de>; Sun, 14 Aug 2022 04:02:47 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id i5-20020a05640242c500b0043e50334109sf2811168edc.1
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Aug 2022 19:02:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660442567; cv=pass;
        d=google.com; s=arc-20160816;
        b=hbxzm+0ccIkdTOgK5MXb53/5CKnwanJvZzosmp/lF48YJVupXqxa5az9IxXMaYxnxQ
         uR1P+K0tIWhKLmDj3hGvU9PzwI2gS0oiaZ4yiwCZk9nOlcic0qiH/6Y94Zduj75JmZ0f
         T+DXdMlj5i4OUX/pV4w9YFzwpD0sfFMLHgPVc5phleFFap7mrxQAm9LKY9hvXFXlws9K
         YQuAKVlAapr2YxZNzS6FJojB8bYUYZRE6j5MI1ZBL8P3Hvu/0HrU6drb04TOosqAG8qJ
         tDKaTk51gdnS3UtglW9JPT1mJZ9SdW53ih83asvvE6AYMihgKvENQT1vcsA8M+KDI7iG
         oalQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=57z9HWKL5jBubxPabnjZfEEkKX/mDS//KfeISBmqPWo=;
        b=NmBlyQb8Oi6uZH6wVpTuxzfSzdCclSbTOI07eFGz4BzuiEvdpD2Sa16ZVGNqNZSNwF
         hePks6dxjho2E6xlL7I0d9Ilm5uo/CQo2xiGkPLXmDdZWyGWhZySoeLhEPeb4I2To0Zn
         8RS9M7QeZY9A1QiMwwyPc7Xow4LF+iTJIoALP8XraZl2+X9pAEz5q7SwrhUGOUgz4Jh6
         vZM7KSplSjXGM0CBpru8JsBvuZi8zh6bkaWkT0/QwULgjb+qWstxBYDMnETwKQQvJwFK
         JFz+gY/z+1qHob4qnRYyf8hdQ5kJE8pszeBE4sA0w+ssNMF0FPJcJigJPQnrZPX8R9JN
         kzFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aqQK9izi;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=57z9HWKL5jBubxPabnjZfEEkKX/mDS//KfeISBmqPWo=;
        b=T0LbkrUe2HvvOCU4W/VcDNNtlcAp70Tuef1GFju/MkLQAtdkuet7BRnggpZmo7AJLm
         pp4Mtkho0dJzF+khgfzu76Pf9ImmnAXF4aVORssg+DIqZzbrqVcPNI1TETeaFQT8nzig
         H39SJ6QkJHAev4fwT3JsLmN93EcITxU6gp92SBWG2+Pu9A/Ozy4yRq3GylWSZqSg7iLw
         BpIGTPf4TjRS3h0iMBF8cY+Qis9yDngZ/Ts2Dumy1q4XzkjhfJ/0Sm46+SIxLjguUbtU
         KhiAzEdybMjCIIloRxxs04+xKXRKawGYpztHC/nouqr+xoLRgeXfOrP+SYkUJDdk436n
         qNbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=57z9HWKL5jBubxPabnjZfEEkKX/mDS//KfeISBmqPWo=;
        b=ttrpuErANlzqVZuYKn31tFCu2rP1V4go83Z+KfZu7FAd4HacDB5l7hnXrLCYY2LnSQ
         3c5YppjSOL5NLp52le2u3QUPsL7drm/x22VS3qbPYfNXMuqRcEIQp0W5Q78Dc63IqepK
         Gsc2TvwOxApWNfFzb9BEDsy46leLhgCtJWBIxuAEFgiIe87n6OinyuewKViWcIMPCJh2
         iNR6fd/QuqCfmr/4W7DXoUpj1N/xWJtbtpwK1SB0wc0ApYmZfxb49yIDft1DQ6xYDs6Y
         Hf2DYJ86Yv3v0nFMjnF6agowz0LxwpVdkBftgCQtpwtcyTiZ1hkqO+HKoXD/RVrDifm1
         Kqww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2xcjS77YGY0d0mDyoazLDqH6gDVN1s99z7Ljwx6HbMUDQIIFG4
	zjnuSaYt73eMEDL7OMMPWFE=
X-Google-Smtp-Source: AA6agR4GojPW1tsMxUBIUSP1wcBO1juPIDthCEEgEBnyaiBjlrbYu50GVHLbSZUtriUdGwAy6+eckg==
X-Received: by 2002:aa7:d58e:0:b0:443:9d64:5877 with SMTP id r14-20020aa7d58e000000b004439d645877mr1045764edq.18.1660442566610;
        Sat, 13 Aug 2022 19:02:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:5f90:b0:731:366b:d9a8 with SMTP id
 a16-20020a1709065f9000b00731366bd9a8ls1928118eju.3.-pod-prod-gmail; Sat, 13
 Aug 2022 19:02:45 -0700 (PDT)
X-Received: by 2002:a17:907:3f95:b0:733:1e1f:d75c with SMTP id hr21-20020a1709073f9500b007331e1fd75cmr6736607ejc.727.1660442565615;
        Sat, 13 Aug 2022 19:02:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660442565; cv=none;
        d=google.com; s=arc-20160816;
        b=Urc8YE0LJsEQ8gkbaQZ66+2b8AZFHrT+k/2KwHpz8rgzNzmBi/3Iqyoh6wWmlunDf5
         FJ1Ei/acjVhTFOoOXsOofhM33fX9l72wJyXtYg2g07Qi4R74cbuToEU+E5kqgR9wrk73
         gYS+86mEI7sUilqwYeV7MnV4y2jB350A5jdw2o4E1ll6NBWSh6j0WmDDaHn3wk1IbqAL
         s3jJI2O5T9CSEMib1IrM0FyDlAMJ+P7ix/eFAMBBSqluRUypw6Hdey+1TJNGBO3CC5xp
         KAtTC2HdaBsnolGTO+dBAbtmSwzLIZ/5T8kLWGkY4VjCb79Wc/a5PRYsxd/pWybzjhSx
         oV1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=efxEO8QJyWuyc0/izYjWpVcA35ahuLbrMiOZSWMRYGo=;
        b=kLXStgRwLLEZ3s1Ng8MhFIglw9jQbpQxl/OdlxEt+JI9THW1NlMJFZEaJDa07wRhDz
         UP7M11/RS4vV6N3wQbe/4W2mx2nmXrKahTjgVAXazN9KSbYY0kPOIy5fgYmPZ5hwuyKS
         KXuslEXBbuR2lHfwJCWkwbI3lz1MQIvjYX5Hbypg7LYNgF67eGEe86/PKiZIIfTsGQ90
         uWuBBkyPxCOLadOM0i6wOZUMLj3Kt+WeXC34BCZnxm7pC/XHv4yi25WLqmX70RUaEj0f
         UmGNBBjFBiiBKKCZXydG40AePjupttEiUOFoQsnyNwBgJPB+26YDAQ3Fy9CLeFoNvosx
         +1mQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=aqQK9izi;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id b23-20020aa7df97000000b0043dc5dd9a71si488223edy.2.2022.08.13.19.02.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 13 Aug 2022 19:02:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 4216BB80AD0;
	Sun, 14 Aug 2022 02:02:45 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id F09F6C433C1;
	Sun, 14 Aug 2022 02:02:40 +0000 (UTC)
Date: Sun, 14 Aug 2022 09:53:22 +0800
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Emil Renner Berthing <emil.renner.berthing@canonical.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH v6 0/2] use static key to optimize pgtable_l4_enabled
Message-ID: <YvhVktaSeK0vLmhB@xhacker>
References: <20220716115059.3509-1-jszhang@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220716115059.3509-1-jszhang@kernel.org>
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=aqQK9izi;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Sat, Jul 16, 2022 at 07:50:57PM +0800, Jisheng Zhang wrote:
> The pgtable_l4|[l5]_enabled check sits at hot code path, performance
> is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
> boot, so static key can be used to solve the performance issue[1].
> 
> An unified way static key was introduced in [2], but it only targets
> riscv isa extension. We dunno whether SV48 and SV57 will be considered
> as isa extension, so the unified solution isn't used for
> pgtable_l4[l5]_enabled now.
> 
> patch1 fixes a NULL pointer deference if static key is used a bit earlier.
> patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
> 
> [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t

Hi Palmer,

I see part1 and part2 were sent out...
What I can do to make this series merged for 6.0-rc1? I'm afraid this series
may miss anothe round of merge window again.

Thanks in advance

> 
> Since v5:
>  - Use DECLARE_STATIC_KEY_FALSE
> 
> Since v4:
>  - rebased on v5.19-rcN
>  - collect Reviewed-by tags
>  - Fix kernel panic issue if SPARSEMEM is enabled by moving the
>    riscv_finalise_pgtable_lx() after sparse_init()
> 
> Since v3:
>  - fix W=1 call to undeclared function 'static_branch_likely' error
> 
> Since v2:
>  - move the W=1 warning fix to a separate patch
>  - move the unified way to use static key to a new patch series.
> 
> Since v1:
>  - Add a W=1 warning fix
>  - Fix W=1 error
>  - Based on v5.18-rcN, since SV57 support is added, so convert
>    pgtable_l5_enabled as well.
> 
> Jisheng Zhang (2):
>   riscv: move sbi_init() earlier before jump_label_init()
>   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
> 
>  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
>  arch/riscv/include/asm/pgtable-32.h |  3 ++
>  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
>  arch/riscv/include/asm/pgtable.h    |  5 +--
>  arch/riscv/kernel/cpu.c             |  4 +-
>  arch/riscv/kernel/setup.c           |  2 +-
>  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
>  arch/riscv/mm/kasan_init.c          | 16 ++++----
>  8 files changed, 104 insertions(+), 66 deletions(-)
> 
> -- 
> 2.34.1
> 
> 
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YvhVktaSeK0vLmhB%40xhacker.
