Return-Path: <kasan-dev+bncBDFJHU6GRMBBBCFV4KJQMGQEYAQ7SWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id A558051F381
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 06:37:29 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id bp17-20020a056512159100b00472631eb445sf5292231lfb.13
        for <lists+kasan-dev@lfdr.de>; Sun, 08 May 2022 21:37:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652071049; cv=pass;
        d=google.com; s=arc-20160816;
        b=kmmoF6jKu33/JkIt16BMmwJ1JBK25U/ruzEYeioh9YlVieXj8aD1g40VU7AwSoyu2i
         0pC1fbJ+yAFnFPbFuwYQ1S2izf1ZP+u7tsoI8PEQ8l9Os5/Lk4gzbJ4Zit3QPzIjuyiW
         U46r4X220gqdYsNI2WlU2pHWGFU80F15HP8amqLQ0J4NO3mBbM2k/IEbbVMpw09s4L2t
         XEweUOO3UMqCQfSrEBqjFueJYGG9UOeRtQNBVgqWoOpC79b9Q0IO0ZbMhNMWxsywkbAw
         3BNANGVFx5V9gA9rA+SBq9VauIafeMGPvUMGEENIkmILf92wxw5OW0fpg6kVB0Gvb/6j
         Q4tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=oq7KsbEv8KERxXpWlLOn4ngUcAedLkoMDcfGe+B7QPc=;
        b=cBwkNJZAhwupczIdqaVjSCSne1srKkfYDpPgsuwtuOQNQuuU1USCf9+8nP5cJEjiEq
         LyoLAiijcHX1eNdkXlVwx9NVlCOODTkGqrYWfGx3xZ6mediauEs1xTSV05H/y6a4xiBv
         /T2/sxwNhnDqkwtBDNK78xpacdBOEOR6jDHlcm9xlfkCx3MFSIUhXL2qAoUQKJaOvUR2
         uxc4XfZcP/HUuyAQ2tb4dozNsoJGJsLUcqlYB0XiDunCg4/JCqbaBaPpgRzIwGh9I/V7
         V3KZJOm7XPqp/5JHfNsEad0eIwNoNee22w3sHwKggy7YIvEuANbmcC3h+VUTYKskWZuo
         qdzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=CIUvEXQy;
       spf=neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oq7KsbEv8KERxXpWlLOn4ngUcAedLkoMDcfGe+B7QPc=;
        b=Z4u3m03dL+Xl1cisc3bDdjJXA89KqaGvaLm0ILBY8pd2L/3vLN7XVQ11UykpfKHvVW
         maf7Hso8v7hq9ZJQRw/l9IMxTgr79VoxN3Iy2ma+4JI0f/lrdZP041a7Amt37rlTDtJF
         ZfUn06mNJHuju8C0L+99e3xaZdS42SErooZqYxodoEqnHH9SEDxYjMeNbHHpX+dtdf1p
         nhwBT4qjKbCuQNcsPLVzjXCCjuF9i7xvx9zN5KbpKRWAz+/SE3EwKf917fT4FPRWPzvI
         lJFCiPRfL/mlP6LbMQI0UUo8VIQ0gztjX2Bwkd4VJO4BcvCSiKjnSvCbgAYiN/YeCTLS
         qreQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oq7KsbEv8KERxXpWlLOn4ngUcAedLkoMDcfGe+B7QPc=;
        b=Jap4A7lKciUyQ7degRWBInNkWJy86cps6Ei8OcK1BCIKz0vlXBmymYzJW1Xo6qarjA
         rkV5Jg6xWnxr3HgXm34f48hrocaTKL2pfNOh0kBE3lESVkK4Qm+tYjboGmAPkCsi20Wy
         BIlJD8fhL/N4dihDVbJw6oDd7/jCkP2HBZQc4nXMX+GiSsxd7OKnckuFcagoCKQxGrE7
         /DY5FdDXn63I/GK1s1drrpIS5rTPfFNMFzPoFfuI51W7QZyLwmdch0TxB5aM6b1dPCZn
         J7FsGrHfeU5Voup/dovM9+y5hAYWFGRQEBJ6vwz0M+YDXkFOPK+MVrxIQaq50KxbA2kO
         uYQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530SGKFkG+NMLsXNW4MOA2rgc6/ZBoXLmuZrz1I+zZ14dUBcfZHH
	sbE4XQ8TLhn2diAfKxMjxLo=
X-Google-Smtp-Source: ABdhPJzf78QCOMnyI4ZQLMMJEGGKR3PhjvNGAumVSmXj86SF36tqepIm57hyA681ffXkI0EPKYWH3A==
X-Received: by 2002:a19:500e:0:b0:472:2b9c:7471 with SMTP id e14-20020a19500e000000b004722b9c7471mr10907801lfb.209.1652071049052;
        Sun, 08 May 2022 21:37:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a596:0:b0:250:5d3e:5653 with SMTP id m22-20020a2ea596000000b002505d3e5653ls2608995ljp.9.gmail;
 Sun, 08 May 2022 21:37:28 -0700 (PDT)
X-Received: by 2002:a2e:9108:0:b0:24f:1301:6697 with SMTP id m8-20020a2e9108000000b0024f13016697mr9372225ljg.94.1652071048043;
        Sun, 08 May 2022 21:37:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652071048; cv=none;
        d=google.com; s=arc-20160816;
        b=EhSg0929mdbGC1+Flxe41MBiFiKdU78gle4EbT9gsyhi/DcIOYVYzuaOkCMezMEFFR
         wyQMljsEEy2IBnQ4rKnP7y2SxPFFupWuXJK6bX4DwK+2hRGr5gdKUFYX4ZD3664m4MwJ
         BzgHVZgz9U2tqfWkrDI3GKZN6MqxqxwW/diz/GtjL88FIZBesRetzSkQ+oZCDpZc813K
         XHk8DMbp/NKs19Hz69QOzdOn8sJJ9YLPxW0lKtbLRWooZB7YCdXUVVAJw0zF/y2VVNYg
         5Jed37n48waZQFfBo+xG8i0DhJ6xsN+QsqjOoEZ7IelqDrao+/BW78qs/CdG60qtNsx6
         e2bw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ov4p0XX7tQqCu3BT1O07xpESNC6AFz/oTsF1DSF1DeY=;
        b=qpGIiYjS6ADUGLxfDcRapd+hxdGxy9diq/3QAPzrP/aFrIXCju7GhfcjaFhDVYhttm
         jOm1mJ1M1UIqSxksrZ1J4LJXxA8dlBBcVj4WOt+HRfnLBrTOFbVPtSon4Voe0JdX3FrS
         6+u8ctLE1KN783ItmvDUVbBw8wa3Z8HvKcHCiZsV791GFW/xHMync2XVwUaQw3uHdbS2
         DVonqFDBAAnotXzPqhTh5BmDROfwcvUax9gIAV4HthhmMJzK/fyuEoRKrr5oe96NK7Fu
         gou8l/GVeWvURY8l4FpDUfaBfl1CyPYQA00zRPh84WFlm6D+AQ/RLeAGV8/LvqaAor52
         686g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=CIUvEXQy;
       spf=neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id s1-20020a056512214100b00471902f5be2si509071lfr.3.2022.05.08.21.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 08 May 2022 21:37:28 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id m62so7672675wme.5
        for <kasan-dev@googlegroups.com>; Sun, 08 May 2022 21:37:27 -0700 (PDT)
X-Received: by 2002:a05:600c:1d08:b0:394:54ee:c994 with SMTP id
 l8-20020a05600c1d0800b0039454eec994mr13927419wms.137.1652071047349; Sun, 08
 May 2022 21:37:27 -0700 (PDT)
MIME-Version: 1.0
References: <20220508160749.984-1-jszhang@kernel.org>
In-Reply-To: <20220508160749.984-1-jszhang@kernel.org>
From: Anup Patel <anup@brainfault.org>
Date: Mon, 9 May 2022 10:07:16 +0530
Message-ID: <CAAhSdy1qri5L9pVcZO8areB=TXMSJBg2+cTNMZGQ3g+3Qhxmfg@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] unified way to use static key and optimize pgtable_l4_enabled
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b=CIUvEXQy;       spf=neutral (google.com: 2a00:1450:4864:20::336 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Sun, May 8, 2022 at 9:46 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> Currently, riscv has several features which may not be supported on all
> riscv platforms, for example, FPU, SV48, SV57 and so on. To support
> unified kernel Image style, we need to check whether the feature is
> suportted or not. If the check sits at hot code path, then performance
> will be impacted a lot. static key can be used to solve the issue. In
> the past, FPU support has been converted to use static key mechanism.
> I believe we will have similar cases in the future. For example, the
> SV48 support can take advantage of static key[1].
>
> patch1 is a simple W=1 warning fix.
> patch2 introduces an unified mechanism to use static key for riscv cpu
> features.
> patch3 converts has_cpu() to use the mechanism.
> patch4 uses the mechanism to optimize pgtable_l4|[l5]_enabled.
>
> [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html

Overall, using a script to generate CPU capabilities seems a bit
over-engineered to me. We already have RISC-V ISA extension
parsing infrastructure which can be easily extended to support
static key arrays.

Regards,
Anup

>
> Since v1:
>  - Add a W=1 warning fix
>  - Fix W=1 error
>  - Based on v5.18-rcN, since SV57 support is added, so convert
>    pgtable_l5_enabled as well.
>
> Jisheng Zhang (4):
>   riscv: mm: init: make pt_ops_set_[early|late|fixmap] static
>   riscv: introduce unified static key mechanism for CPU features
>   riscv: replace has_fpu() with system_supports_fpu()
>   riscv: convert pgtable_l4|[l5]_enabled to static key
>
>  arch/riscv/Makefile                 |   3 +
>  arch/riscv/include/asm/cpufeature.h | 110 ++++++++++++++++++++++++++++
>  arch/riscv/include/asm/pgalloc.h    |  16 ++--
>  arch/riscv/include/asm/pgtable-64.h |  40 +++++-----
>  arch/riscv/include/asm/pgtable.h    |   5 +-
>  arch/riscv/include/asm/switch_to.h  |   9 +--
>  arch/riscv/kernel/cpu.c             |   4 +-
>  arch/riscv/kernel/cpufeature.c      |  29 ++++++--
>  arch/riscv/kernel/process.c         |   2 +-
>  arch/riscv/kernel/signal.c          |   4 +-
>  arch/riscv/mm/init.c                |  52 ++++++-------
>  arch/riscv/mm/kasan_init.c          |  16 ++--
>  arch/riscv/tools/Makefile           |  22 ++++++
>  arch/riscv/tools/cpucaps            |   7 ++
>  arch/riscv/tools/gen-cpucaps.awk    |  40 ++++++++++
>  15 files changed, 274 insertions(+), 85 deletions(-)
>  create mode 100644 arch/riscv/include/asm/cpufeature.h
>  create mode 100644 arch/riscv/tools/Makefile
>  create mode 100644 arch/riscv/tools/cpucaps
>  create mode 100755 arch/riscv/tools/gen-cpucaps.awk
>
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy1qri5L9pVcZO8areB%3DTXMSJBg2%2BcTNMZGQ3g%2B3Qhxmfg%40mail.gmail.com.
