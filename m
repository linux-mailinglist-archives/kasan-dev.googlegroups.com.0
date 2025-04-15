Return-Path: <kasan-dev+bncBDCPL7WX3MKBB7EJ7O7QMGQESM3OVKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AE08A8A980
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 22:43:42 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6e8f99a9524sf170411726d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Apr 2025 13:43:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1744749821; cv=pass;
        d=google.com; s=arc-20240605;
        b=f2Tfi6A/t7Kn4mv8dLwONUlNfwaN9AKZFZVOunP5/67v4SoZWD+FRPKh7bITda1dMf
         tq3joIam9s/q4O6FhXebKQPkTt6abto56ryl6Hdg8JrprwPewvdcIg3zwieZEEjdXtFi
         qsdoJ7b6tBZBXdMn1d1hw74ko6AbBMc4oVsgTTx1Qv9Dc7RbgIz23c4vIn6OsIeda4cI
         CldoonzzfmUWjtQIRKzbBP1lamLXEi3aY4ZH4BdFE90gEdPGep31GUpiErhfMlaJuYgg
         NbIHpaFQRnHjwqyvTM9D14FvgYUjhYPg/xXfeCmAD5P2zAXKJ5uu8ABfgDt1xqBMMcuc
         5bEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=UfycFMXzgGUytdOjoJEHdCmCUJalE9nlRVYMc8oa2Vc=;
        fh=AZIx9eE5o0+p04M9da5tx6owUjoC1S5IDwjL30SAuiQ=;
        b=SanjXzgaK8Y9i2kul/noEFJr0MWHtrE4EVpK1QHhg2C23ArZgjto/GOk7HxTBLRYyU
         7JeiVNfa7FcFs7YYVkFVsa3pyJyIb6Y8dgzE8gk3Pww4P+CuNZ+Mujn8XP50SnJFl5wN
         /vuz6Gd3FRk2s2bpm6iXx7S+VFL7gkJkId80hQ3WFtRHwmU327FRPjvinN6quOLH0n4R
         u04o04FEJAb+u9r07AA4YkQPQcEyorhvYR7TrV6z/zxtM44upobjePWNsSA5V7JcaLuy
         CZ280/K4SMd8oWgv0XloSF+Mmd3vPVXvzmMTNVT02fPlZupxqhYJcir2NWR4G8BtQA2V
         GS/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yntpc1eL;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1744749821; x=1745354621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=UfycFMXzgGUytdOjoJEHdCmCUJalE9nlRVYMc8oa2Vc=;
        b=AU/IAUOmoKqDqxQUpuEU9LcTuAnQK5A8WDke48FOGEy3lHSEzk2j4c54xuILHdXVTL
         Z12nBCHBTtLJzGLmptzMUL5XprpHzZpHQkNPDronvhbsrc6p/D7XZZ/LBEtA3m6yGClg
         bCLtsxq9H/HO4SlkKjVXCbFlMPt8hc+oGjx6Fl45RdiWiPwmZeCCLRmjCfwRzIpOVALW
         xexD70wkpI3++/436zyZ7eQN6wSBK+5Zf6bKxhzCMVQaGUzelOWlHQaw44vsKJvg4fIg
         r6B0v+TTeg/p7HFT88gA6H6VTS79s9SMr1TzaJkmcEpO7Y6RUSlLDiZE3NsfVy7Xw9it
         46JA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1744749821; x=1745354621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UfycFMXzgGUytdOjoJEHdCmCUJalE9nlRVYMc8oa2Vc=;
        b=PhmiGqnijM+BKe/MJgH0QPG0A0fmXHIELcCl03TTwTSpr00z0q70U1R9IQ3c1XqAKq
         1TXjqN2nSScky9PrgYfVN+wAr0BJ8VxvkHcQq8HWOME2jOQ1UBifEy1PoOhvdgB5kV2X
         l11rzPlejCay18RXkbAJgRpLaORmmM3oJ65aiNiW0WQwAh7BoZn/o7Ph0j/nrcBBC8Lf
         H7yfuUEtYr6YCzZoJQt25adnNSAhTcUX4VORQyDJ++TXmRc3fLhvaEbTFX1Di0+6Z76h
         LKCt0+GsKt1i2QCZrIFb8CpCUAOSqS3PmtZOVh2EEgkiRVeI9qsdPy4eMNx74p/HtC3y
         Ta4w==
X-Forwarded-Encrypted: i=2; AJvYcCXjKLIjIc7INT9VeXsQs9P4hdEufBpNaEuHHP4VOkR290k1mk4+kD2M72IZ7+FhXewLMDwyWg==@lfdr.de
X-Gm-Message-State: AOJu0YxGRCNXxzSxD9DjvbscuxlMlwvlsHPwc3J4vhHVHvSi4QYGsahm
	KMR2j3CBydYKuqIKrdmobIqbYe4JLKx0dUIUJKjN6NsuR/2mTNNn
X-Google-Smtp-Source: AGHT+IGpXVznJLam3H8+XeU0auEIb0EScxEoaHDP+8IB2ubuw+AxFOPThqfmmNcfpuwDanZ/KHDMjQ==
X-Received: by 2002:a05:6214:2402:b0:6e8:fbe2:2db5 with SMTP id 6a1803df08f44-6f2ad9e8a62mr17737666d6.35.1744749821004;
        Tue, 15 Apr 2025 13:43:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKqEp0cH+3cR5WzSfEUCmwWXGgGJe73UZdc6MoSQTzV3g==
Received: by 2002:a05:6214:2f89:b0:6e8:93c9:3e8 with SMTP id
 6a1803df08f44-6f0e4ac97c4ls17182596d6.2.-pod-prod-04-us; Tue, 15 Apr 2025
 13:43:40 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVN6wVqbktX+XyPWhCWmAkp1sXWCwx4v6gzkLP/qKIy8f0qsez53vfG7M87Ya0oenfwmR/QBysF2JA=@googlegroups.com
X-Received: by 2002:a67:f091:0:b0:4c4:dead:59a3 with SMTP id ada2fe7eead31-4cb528a080cmr701923137.2.1744749819944;
        Tue, 15 Apr 2025 13:43:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1744749819; cv=none;
        d=google.com; s=arc-20240605;
        b=IftSsASuUjGj250SkUIv24S39hnB4tfw11jOviUN/ky3i1RjDWleAdUWstkjRbTuT8
         1dYwK4TzhLvjuzMKTaflLlkCkRRHjclwy7gvtciBwNwjwP3J8QUnrrqS4U8dPkexOt09
         lzNjvTPoCGn3Zkg3nV3lpqmUte3Mhw8rHpl9gdJGaRLVNeap1/7Q5Y8DdJvpJH9I7ksT
         2o1d+n5lm6z/iiC10cTAIBaa2DbNzkXOhjPt9Arh2sExeXtAMMdBjSCTxX7iv2tv6MCr
         XeB+eZU5L9yemNBxIA++rLC1NL0sJtxt+s/kY1CCICZYi8CZq3FSk40QFQHbWM02nNOb
         xksg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=t9UgdpPldVMVZgUSiwLYUuQZCoYzoJMEr79wd8fzjq4=;
        fh=cN/Jf8O3JRMHwtF0oogxcfNsQtT5IEZr+suzEaXQZoA=;
        b=fkbS7ChBplFDfmKnonIJYulkK/oi+7oQqCIVhmU5LuPlCVJ8I5lZJ3g8Zn75tb7zCB
         BNpJMA3RCp60I35KFlO+KU6EwuYYUx00xOgfUddvIGWUqwZT0V46ypr3KrBpUuVu1/Wf
         P6dWSU2eV4+LmN3ZKBeZ0DFtMnz7EKJN6meYNzmYp39oeZ3JKK6gqyCtu4XQu1PurZZf
         bH2IOHUdsHradFdtuNmoE6TlsDbjN0S53FPuMAK/A4une51sZTPTJzTPTVZZ/uF7/Jfn
         WpHb0+DC3JJPSa0y9gIx9ssFkC5K3qTzDPhGeHeI5HmqCOOK1Da+qwC3G+Ahae+aAo4E
         TsaA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Yntpc1eL;
       spf=pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4c9c97332basi155302137.1.2025.04.15.13.43.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Apr 2025 13:43:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 35655A4A68B;
	Tue, 15 Apr 2025 20:38:11 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3DED9C4CEE7;
	Tue, 15 Apr 2025 20:43:39 +0000 (UTC)
Date: Tue, 15 Apr 2025 13:43:36 -0700
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mostafa Saleh <smostafa@google.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org, akpm@linux-foundation.org,
	elver@google.com, andreyknvl@gmail.com, ryabinin.a.a@gmail.com
Subject: Re: [PATCH v2] lib/test_ubsan.c: Fix panic from
 test_ubsan_out_of_bounds
Message-ID: <202504151343.794CF53@keescook>
References: <20250415203354.4109415-1-smostafa@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250415203354.4109415-1-smostafa@google.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Yntpc1eL;       spf=pass
 (google.com: domain of kees@kernel.org designates 147.75.193.91 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Tue, Apr 15, 2025 at 08:33:54PM +0000, Mostafa Saleh wrote:
> Running lib_ubsan.ko on arm64 (without CONFIG_UBSAN_TRAP) panics the
> kernel
> 
> [   31.616546] Kernel panic - not syncing: stack-protector: Kernel stack is corrupted in: test_ubsan_out_of_bounds+0x158/0x158 [test_ubsan]
> [   31.646817] CPU: 3 UID: 0 PID: 179 Comm: insmod Not tainted 6.15.0-rc2 #1 PREEMPT
> [   31.648153] Hardware name: linux,dummy-virt (DT)
> [   31.648970] Call trace:
> [   31.649345]  show_stack+0x18/0x24 (C)
> [   31.650960]  dump_stack_lvl+0x40/0x84
> [   31.651559]  dump_stack+0x18/0x24
> [   31.652264]  panic+0x138/0x3b4
> [   31.652812]  __ktime_get_real_seconds+0x0/0x10
> [   31.653540]  test_ubsan_load_invalid_value+0x0/0xa8 [test_ubsan]
> [   31.654388]  init_module+0x24/0xff4 [test_ubsan]
> [   31.655077]  do_one_initcall+0xd4/0x280
> [   31.655680]  do_init_module+0x58/0x2b4
> 
> That happens because the test corrupts other data in the stack:
> 400:   d5384108        mrs     x8, sp_el0
> 404:   f9426d08        ldr     x8, [x8, #1240]
> 408:   f85f83a9        ldur    x9, [x29, #-8]
> 40c:   eb09011f        cmp     x8, x9
> 410:   54000301        b.ne    470 <test_ubsan_out_of_bounds+0x154>  // b.any
> 
> As there is no guarantee the compiler will order the local variables
> as declared in the module:
>         volatile char above[4] = { }; /* Protect surrounding memory. */
>         volatile int arr[4];
>         volatile char below[4] = { }; /* Protect surrounding memory. */
> 
> There is another problem where the out-of-bound index is 5 which is larger
> than the extra surrounding memory for protection.
> 
> So, use a struct to enforce the ordering, and fix the index to be 4.
> Also, remove some of the volatiles and rely on OPTIMIZER_HIDE_VAR()
> 
> Signed-off-by: Mostafa Saleh <smostafa@google.com>

Looks good; thanks!

Reviewed-by: Kees Cook <kees@kernel.org>

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202504151343.794CF53%40keescook.
