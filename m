Return-Path: <kasan-dev+bncBDW2JDUY5AORBTGI3SJAMGQEEQW2NFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id DE4224FFF41
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 21:28:13 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id s13-20020a9d58cd000000b005f2caecdeeasf447647oth.20
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 12:28:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649878092; cv=pass;
        d=google.com; s=arc-20160816;
        b=L2TU9Xmj2CKE7vxn5NKG2h017UtAUByWs3OC+w2baP8In1kSP8q73xaIy6dUaZU+BA
         VPyECggbdq2Xf2h62CFHWEY4F01kU3EinuCbcIhtUsKMzn3GJGDADrJ0jgfLIIWeTlQD
         VxqAMkL79VfGu1/vk2+KZGi6YnVbB4wxMGdSMJkLRRwQONVOGxpaK6Qb4QujNG6CZ80V
         aZI+/rwsaeMQzJPgEHnj6No6fj1kKkd4EMXwL/vz+zecXb27SQOOB0FDtTOhePpfLDEW
         OF1rI0j96Q1bYtRS+0ZOtit9tlj0xxEGF+vBC1zLh6oS4ar55YwtaWd35Bs9xMzgX6NU
         tk/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=rr9tG7oxY7dGwnfsKatfFSjWY5T583eGgWxQ4y+THoo=;
        b=Kk1A4Njavl94PyYLW1/NOeq0pYkqJFFyd/SnVoGXGOzE6xwhxQe8tGcm9x/4U9leMt
         XLK/GsZxv85lGsb6KtUy9GKWZAViNKIzhtHotu7r25KMjZoPfjtd61r/UFBIoQAuO4/k
         NRh9bY5Qxtz7si9VsqvxwCg5PfF9Q1y1gutDcsCk7zM5Y+Dh9E1SGDTrxIL6cKe36L40
         vwQR4+n6VnXuYr8mopT0X6UpuX9mb1je/KE3867sFHC2ZQyOwbrrteGljBNEBN1qDnSD
         DIx7OY70V/ciSKyADBGP8RB5vqvc9rgQPOFhHxP740asYBXnLbmEAQaroyl4+27T5TAm
         DtNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="ZL69/Zor";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rr9tG7oxY7dGwnfsKatfFSjWY5T583eGgWxQ4y+THoo=;
        b=kjA62wWb7Tl1IdX5dWXZuSuNO30ex0K8IGs4liRuwHFEc3+EcD1NEZ7Ws7rGihmP31
         oG77HIJI0ilzJJfY4bU/yjl8/jFcBhxCK+HWCA13swyLF9vDqdrTdDvu9kvLfqHp1k33
         sPa4LAo9SK8Y2XVmyhtxF15Ya9I0/HL34C0ZhWz4rqeXjzYyjasYkslEbmpXwexxiey4
         b4ozsylZrqIZiO1S9QPRiwpy7cdrS6OEfPxQp7aBRsqGmYyMwlRV9S7QiMoSMBIVk7Ac
         lvP2CGHTNsDSPLLWb1tHjnOYdNp04BnPeoE9FgLCWuW9inHJVaxBvgCrXI3IKt292gMJ
         pNYA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rr9tG7oxY7dGwnfsKatfFSjWY5T583eGgWxQ4y+THoo=;
        b=UfUwYitNFatULBoWoqLm0/PAeMFL8V9UNP1QiFSbhjtwya1d37Oeyxxus+Yc5T35wX
         T8JMR/Ca3WKc5U7va52tw2cdxfUKX0Wyog7bnB5apqFo9ABz8xpq/78lQro0z0yj3z1D
         jUf0ihQw32QZzD38/LebKcH3+YrUqOi9xdsfEfCG5zN8xCGvylcIcmHZx39U9uEFGNik
         JMT7POKELbdmADi+XuQlnA+b2GgPvkyL7zrI8ZF7VswmRN531XnsyvgoMBd2VeI3O6GP
         /7r00QRVpa2khfXbAseyLE0fUVhktQlFsS6pqvr9HneQpWON3BXZHpOCeh3WcguKUt8+
         6JOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rr9tG7oxY7dGwnfsKatfFSjWY5T583eGgWxQ4y+THoo=;
        b=qiu+iby6A7vPtPEg1AbZwbyws/IyAlGVPQE3r6WZygoviS1D0b6nc1UGrHA6aBwsoh
         x+CpPuYG7m02ENBb7Yx16LHusVl/pWGhv7+Q1CQ+q81GVOOYQlrNw6+qkLtanuZ5SxSR
         Xj4Lsf73Uyn0PdmqIllMc/fFf2CJKGx3mGOpN1wEs85tBGfGAkmEx2WVsClK1yGZj2h1
         07Af6bvfq64lBBy5iNJfr0Pg+xD/BWZ4t44EMYrA/MZgUhm/SR8nqhGsEPfVeH4CYYjg
         Fu0/A7K4aFEVUL1EDPW2tUYD9rtdwsnucfJjS+ORR6LYRbwoLVoBIaNaQTTPnWjTIFQK
         x68w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531FPBZouk3kXRy8BqU9ZyedWsdzgpqiRruWkac2npqpPVzsEHUv
	xAdamb+8TFS5bnyrGtwgyQk=
X-Google-Smtp-Source: ABdhPJy8pmglRV3e6uEe9N6M+ASlcYs0444j8S5BhZy3BVHe4LRCHnW3KGIbCnUOVHwJp2wRsPpVfQ==
X-Received: by 2002:a05:6870:73cd:b0:e2:c762:da6b with SMTP id a13-20020a05687073cd00b000e2c762da6bmr120991oan.282.1649878092487;
        Wed, 13 Apr 2022 12:28:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3489:b0:5cd:c661:8d79 with SMTP id
 c9-20020a056830348900b005cdc6618d79ls995291otu.1.gmail; Wed, 13 Apr 2022
 12:28:12 -0700 (PDT)
X-Received: by 2002:a05:6830:2b13:b0:5c9:467b:3d8 with SMTP id l19-20020a0568302b1300b005c9467b03d8mr15323584otv.13.1649878092120;
        Wed, 13 Apr 2022 12:28:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649878092; cv=none;
        d=google.com; s=arc-20160816;
        b=cS7Cq/iJbhm1QV9LHkaJRJdQg35BBPlIKTy4C40ahhRCC4mI349evmkzlWorykTLJ9
         SFxl4kVFSHxNco1I8/uurLHL3N3whOpL/vkuuIL6aLSu4oRrXfi1tlQn/FXJSzFCqxFl
         qiNTv0v/lvh/SYIS/MhIFmF2ZlY13GvoA61eeXRfQu3DHI+u0dgMP3+v7ZrmxzEZi1tZ
         L5OSQUCQTa4sgBXdalZoU9jnSzXFBqqqg8kvWzP6oYssHCx5rzo0cQrPdizxx5XKSnin
         hJZaEwx9vOt3mv4PRzps4CK6b0IbIeQMbQEZ6r8eekjrmQxdsTZufewjVS5uHhJQNnUd
         +MUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hGxcoipwWUtIXq1n/IgG8Z+lNTNMbXErzkobqsYlE2I=;
        b=CEEcb5Yvj5Sm+lM20pwieuyNMkk9TICZUXAQ/Gg6M4+je5NwFmGp7lFpD+8dj6us0C
         Lqp825EfFUbL5GzdTckXwd5ffENabFY2GJ4C/UEWvlzTh26tnEPIXkY8vGWuEOvzFXMe
         y1GKNd8P5gaEM+/O6QGYoR9cNXe9J8PABHz6GmbKP/7eq2GtjLORFGoUAqfavRW8E3Sy
         lR+hUYIKSIoZ6ej6eXIyYSWaGxbgXebcJeukUXtPLVa1WA+wfMU3e9yxPEBVGNl+6Hy8
         kFhSMpxBiGJtXcZQySzUuS6U6vDp8BIKwks0tJI4Ik1/1uOqimGpfDXaCOLN8lUJMW68
         T6nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="ZL69/Zor";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id bh31-20020a056808181f00b002f9e6687adesi2078915oib.5.2022.04.13.12.28.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Apr 2022 12:28:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id p21so3056457ioj.4
        for <kasan-dev@googlegroups.com>; Wed, 13 Apr 2022 12:28:12 -0700 (PDT)
X-Received: by 2002:a05:6602:2b8e:b0:5e9:74e7:6b01 with SMTP id
 r14-20020a0566022b8e00b005e974e76b01mr19051650iov.127.1649878091766; Wed, 13
 Apr 2022 12:28:11 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <YkV6QG+VtO7b0H7g@FVFF77S0Q05N>
 <YkWg5dCulxknhyZn@FVFF77S0Q05N> <CA+fCnZeQ6UnpM9qEQ4q5Y95U3XVwrsD-g7OX=Qxr1U1OR_KCsQ@mail.gmail.com>
 <Yk8wbx7/4+9pMLGE@FVFF77S0Q05N>
In-Reply-To: <Yk8wbx7/4+9pMLGE@FVFF77S0Q05N>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Apr 2022 21:28:00 +0200
Message-ID: <CA+fCnZcv6PtR5eT-hbJ54hkH7Kr+CUM4DU2S5nbU4Lp2OnG8dQ@mail.gmail.com>
Subject: Re: [PATCH v2 0/4] kasan, arm64, scs, stacktrace: collect stack
 traces from Shadow Call Stack
To: Mark Rutland <mark.rutland@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="ZL69/Zor";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d33
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Apr 7, 2022 at 8:42 PM Mark Rutland <mark.rutland@arm.com> wrote:
>
> I'm afraid from local testing (atop v5.18-rc1), with your config, I still can't
> get anywhere near your figures. I've tried to match toolchain versions with
> what was in your .config file, so I'm using clang 12.0.0 from the llvm.org
> binary releases, and binutils from the kernel.org crosstool 11.1.0 release.
>
> I took baselines with defconfig and defconfig + SHADOW_CALL_STACK, with console
> output completely suppressed with 'quiet loglevel=0':
>
> | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-defconfig/Image
> |
> |  Performance counter stats for
> |  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> |  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> |  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-defconfig/Image -append
> |  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> |
> |        0.512626031 seconds time elapsed                                          ( +-  0.26% )
> |
> | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-defconfig+scs/Image
> |
> |  Performance counter stats for
> |  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> |  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> |  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-defconfig+scs/Image -append
> |  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> |
> |        0.523245952 seconds time elapsed                                          ( +-  0.18% )
>
> Then I tried the same with your config, without your patches:
>
> | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image
> |
> |  Performance counter stats for
> |  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> |  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> |  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image -append
> |  loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> |
> |        1.994692366 seconds time elapsed                                          ( +-  0.05% )
>
> Then with your config, without your patches, with the stacktrace hacked out:
>
> | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image
> |
> |  Performance counter stats for
> | '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> | -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> | /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image
> | -append loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> |
> |        1.861823869 seconds time elapsed                                          ( +-  0.05% )
>
> If I use those number to estimate the proportion of time spent stacktracing,
> with the baseline SCS number discounted to remove the hypervisor+VMM overheads,
> I get:
>
>         (1.994692366 - 0.523245952) - (1.861823869 - 0.523245952)
>         ---------------------------------------------------------  = 0.09029788358
>         (1.994692366 - 0.523245952)
>
> So roughly 9% when I try to maximize that figure. When actually poking hardware
> and doing real work, that figure goes down. For example, if just using "quiet":
>
> | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image > /dev/null
> |
> |  Performance counter stats for
> | '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> | -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> | /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config/Image -append
> | loglevel=9 earlycon panic=-1 quiet' (50 runs):
> |
> |        4.653286475 seconds time elapsed                                          ( +-  0.06% )
>
> | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image > /dev/null
> |
> |  Performance counter stats for
> |  '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> |  -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> |  /home/mark/kernel-images/andrey-unwind-v5.18-rc1-andrey.config-nostacktrace/Image
> |  -append loglevel=9 earlycon panic=-1 quiet' (50 runs):
> |
> |        4.585750154 seconds time elapsed                                          ( +-  0.05% )
>
> Which gives an estimate of:
>
>         (4.653286475 - 0.523245952) - (4.585750154 - 0.523245952)
>         ---------------------------------------------------------  = 0.01635245964
>         (4.653286475 - 0.523245952)
>
> ... or ~1.6% time spent backtracing:
>
> FWIW, applying your patches do show some benefit, but not as drastic as I was
> expecting:
>
> With console output suprressed:
>
> | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -s -k ~/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image
> |
> |  Performance counter stats for
> | '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> | -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> | /home/mark/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image
> | -append loglevel=9 earlycon panic=-1 quiet loglevel=0' (50 runs):
> |
> |        1.920300410 seconds time elapsed                                          ( +-  0.05% )
>
> ... down from ~9% to ~4%
>
> With console output merely reduced:
>
> | [mark@gravadlaks:~/repro]% taskset -c 64 ./vmboot.sh --perf-trials 50 -q -k ~/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image > /dev/null
> |
> |  Performance counter stats for
> | '/home/mark/.opt/apps/qemu/bin/qemu-system-aarch64 -m 2048 -smp 1 -nographic
> | -no-reboot -machine virt,accel=kvm,gic-version=host -cpu host -kernel
> | /home/mark/kernel-images/andrey-unwind-v5.18-rc1+scs-unwind-andrey.config/Image
> | -append loglevel=9 earlycon panic=-1 quiet' (50 runs):
> |
> |        4.611277833 seconds time elapsed                                          ( +-  0.04% )
>
> ... down from 1.6% to 0.6%
>
> Given the above I still think we need to understand this a bit better before we
> consider pursuing the SCS unwinder, given the issues I laid out in my prior mails.
>
> My hope is that we can improve the regular unwinder or other code such that
> this becomes moot. I'm aware of a few things we could try, but given it's very
> easy to sink a lot of time and effort into this, I'd like to first get some
> more details, as above.

Hi Mark,

I'm about to publish v3, where I'll include a detailed description of
how I measured the performance.

Perhaps we see different performance numbers because you're using
KVM-enabled VM on an Arm host and I'm using QEMU on x86-64 host.
Although, it's suspicious that the difference is so drastic. I'll try
to get my hands on some Arm hardware in the next few days and do the
measurements there.

This new version also will not be making any changes to the entry
code, as these changes add unwanted additional slowdown. That would be
great, if you could check the performance impact of v3 with your
setup.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcv6PtR5eT-hbJ54hkH7Kr%2BCUM4DU2S5nbU4Lp2OnG8dQ%40mail.gmail.com.
