Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIED4P7AKGQENIVAQZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 60EA12DAE75
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 15:01:05 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id t8sf16485033ils.17
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Dec 2020 06:01:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608040864; cv=pass;
        d=google.com; s=arc-20160816;
        b=G3bmYIfSjx7+QQIF7+X+faPzuSgtLMlIoJawW3iXYW3oIvtdz/S/O7PRmMVNBR0qEJ
         3eIpFCESw1H0yNqHn23BuBfI9VyWLDjvWwnOlpEpp/EYWrq66tSqGu1fKBrVb3L1zbiu
         sZMoVhZ/9Zov0nCpYJooWVAaBvCzwPomVzIUVfVypzKMEuAvgzQY435oPgX6HaAZEeF1
         gvsIwEett1Xm202pDU6pA5X0+OF6U3YFs0MXUqcjNwI1zow8mYfUUQ+KCl3ZqjSRBmG3
         MD0eKSqifU5NQf5LlSjxXa51O89V+CVtxsHbzhE1bQuOyp4uEPJkyKvUydgo6dzpgfD9
         jdeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AO0wesSGl/BEEQULZszHlx6ZB/bNJDyM5xnnZxhZmQg=;
        b=lo+VF8M+fDKy7nvWEOhSRvLjo5nznEKOftiqb0EekmgrYOx5P0bK/pwDx5HuIUNJz5
         cTRqPgsnNAiJQFEQwgf52S2qkrJHqj3GnatvOVPL6/wHPRCrNP5EIlhCj5LSZT/GJjgy
         WczzeKmirv20YH5lxhlOsMQ6T4IYlYA/hkknxanvwIKaixcGxPEZc9y02tOBzdJBykgC
         0tHxoHVFunc7r8f/XZEEHghK8K9krsFX17vlrY9qUtyUFbUMAr7r5VwofCexK3hnPMFs
         j3yGBdTiz07rY7nNAtckZMyZBc02SkbkBNwiKxLgIgiKHrzV10NadZRlXlYkbXRypUzX
         F19Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sASorQfN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AO0wesSGl/BEEQULZszHlx6ZB/bNJDyM5xnnZxhZmQg=;
        b=a0mG8mInN2IlEZWoNmCZZNoskdRRDVnglWgBSAZq7AJGRe18eaewkCUs/P4fm54NLr
         +04Xw0KHckqSM1+pnE6LZ+8PQsma64EhxBUXd8CGuP78M05/v/koSzBrmQk92nd0xnAL
         RJlZ/6WZoA/1IO5h8hnJYgDvmYwjJ6qgjZA7PouBdpUa6bBnMbyY3KayuDUQJvqOo2xe
         e5L1Q8HODlTsrwiSQ0MGlncmjRRIhx/kANW1bfBE8OefONLX64CmbnuaoVzlZ3jriTWv
         xJawNrWcHfIIdqPK0JAviuqOOpzKvGsEBJqPjEs9WrhPH0w3yVIrOk7TfLBfEQGwhPbf
         t3HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AO0wesSGl/BEEQULZszHlx6ZB/bNJDyM5xnnZxhZmQg=;
        b=FanO5qhcJgsG/zIpwXwleXlJJ6CrPM4ChRvS3CPWy1PvZkIJJXszyrNFqvZnHfqgjA
         IpknE86Fc+kvvusxx4SYZIinsOCA6sSBtBSEhZ3ehajp/xurV5tEACmNpnnOWc15zoiP
         E7I2bMq1QRbSjI6ZecWBprAadR0V9W2AokyJD3XY623N5k2aiaDnaVc91CtryOQJ6fZn
         cVUzhWyS+DE3p9J0lXh2lnqztPQbtoTp3UvsBnqQ2S0SAai3QlMqpZsxV+PHlgRG9pEC
         AahtQAxcoQ0kKoUUWvYdc43RosJtmCO3c537Cqy2pGa2nV852NNsaK87Rziz6+01rb5V
         4Zpg==
X-Gm-Message-State: AOAM531vz+eBxb7Kvlv+BQEUJKNkDsDuDgTIzlWHAWnWxl28Z2wkk7j4
	mLOROYJbAnFWUz90Dct7y/I=
X-Google-Smtp-Source: ABdhPJxXCdm9jsVOq+UntZKPi974vhNnCIf+v367QAkwF7+mvwaGa9aZXMX6wYwUKVneaCUyi6m6sA==
X-Received: by 2002:a92:d0cc:: with SMTP id y12mr40253057ila.202.1608040864425;
        Tue, 15 Dec 2020 06:01:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:170c:: with SMTP id u12ls1489452ill.9.gmail; Tue,
 15 Dec 2020 06:01:04 -0800 (PST)
X-Received: by 2002:a92:c942:: with SMTP id i2mr1669160ilq.227.1608040863981;
        Tue, 15 Dec 2020 06:01:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608040863; cv=none;
        d=google.com; s=arc-20160816;
        b=bWNHDf6IH0NgjH22+LA4ywu1gkfScVwx+T7vruawvAbuCbDS99P6JnTvbed2ecwAJY
         WpaVRQjP/AuMh6b95DRD7+draPda/RpCMbMXjaA52PoRx5ochD2pzRiIwpINEJN+Q/pA
         g7lHAuO04mQCirni5trewur3gZQrfJYDoRVPC77q4LBUQRP5c1Sf3nsZbxahCwHcUOk0
         njD5J8pO8TAUfDg03ofnm0pRXpKO6V4bFV4HRj181Xn50tp8y5fFb0hM3Qce4vG5qEWg
         bzHFR7waY82KKXKircAQwCYpKOMRBKDHwrOJlmZWPBC1BUSJp4Yyni+067hHw3dPPzI1
         1ccw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A+G1WfxuzopjSGXsyyh6fV+cm5tzdzFwJFw7K7WHVUE=;
        b=g5dC1iVvQgo3e+VW9uD7itADdUQCO5xwhUYchw1RFxwz4DzM93JqPGAMSnTw7biv2c
         FntGHuFTWBhK7shB1j3gx52glWKjvaw3+Hh/TsKOqjAqWIOSAX0/HG1CFXf5/b27/Mfx
         Xf0RG19a7PUn2DCrOH5YrjwdDtTWiKYey3XgBLI299U1QZg5M3L1FAVzNFNxaH39qUJg
         ZY0kobqG02SwEgx0vP9Vq/yNQaSbw37rJ2LUXWuWTa9K6KcT5fJOr01J5NTQJErLlOTl
         PDWoTNGM6IGVhpgTV6LAuUMGmNVsk1w7R3//WhoteRZaQmlJM/q8C9WJgqImtnJpXFOD
         K+Sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sASorQfN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id q4si1480446iog.3.2020.12.15.06.01.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Dec 2020 06:01:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id w4so15246793pgg.13
        for <kasan-dev@googlegroups.com>; Tue, 15 Dec 2020 06:01:03 -0800 (PST)
X-Received: by 2002:a63:5d3:: with SMTP id 202mr23746844pgf.286.1608040863307;
 Tue, 15 Dec 2020 06:01:03 -0800 (PST)
MIME-Version: 1.0
References: <20201214191413.3164796-1-elver@google.com>
In-Reply-To: <20201214191413.3164796-1-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 15 Dec 2020 15:00:52 +0100
Message-ID: <CAAeHK+x3w=rw3Jk3Zg-Q2H6iboWH3dqGvgm9ZXxsCaBGGzR9JA@mail.gmail.com>
Subject: Re: [PATCH] lkdtm: disable KASAN for rodata.o
To: Marco Elver <elver@google.com>
Cc: Kees Cook <keescook@chromium.org>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Arnd Bergmann <arnd@arndb.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, clang-built-linux <clang-built-linux@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=sASorQfN;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Mon, Dec 14, 2020 at 8:15 PM Marco Elver <elver@google.com> wrote:
>
> Building lkdtm with KASAN and Clang 11 or later results in the following
> error when attempting to load the module:
>
>   kernel tried to execute NX-protected page - exploit attempt? (uid: 0)
>   BUG: unable to handle page fault for address: ffffffffc019cd70
>   #PF: supervisor instruction fetch in kernel mode
>   #PF: error_code(0x0011) - permissions violation
>   ...
>   RIP: 0010:asan.module_ctor+0x0/0xffffffffffffa290 [lkdtm]
>   ...
>   Call Trace:
>    do_init_module+0x17c/0x570
>    load_module+0xadee/0xd0b0
>    __x64_sys_finit_module+0x16c/0x1a0
>    do_syscall_64+0x34/0x50
>    entry_SYSCALL_64_after_hwframe+0x44/0xa9
>
> The reason is that rodata.o generates a dummy function that lives in
> .rodata to validate that .rodata can't be executed; however, Clang 11
> adds KASAN globals support by generating module constructors to
> initialize globals redzones. When Clang 11 adds a module constructor to
> rodata.o, it is also added to .rodata: any attempt to call it on
> initialization results in the above error.
>
> Therefore, disable KASAN instrumentation for rodata.o.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  drivers/misc/lkdtm/Makefile | 1 +
>  1 file changed, 1 insertion(+)
>
> diff --git a/drivers/misc/lkdtm/Makefile b/drivers/misc/lkdtm/Makefile
> index c70b3822013f..1c4c7aca0026 100644
> --- a/drivers/misc/lkdtm/Makefile
> +++ b/drivers/misc/lkdtm/Makefile
> @@ -11,6 +11,7 @@ lkdtm-$(CONFIG_LKDTM)         += usercopy.o
>  lkdtm-$(CONFIG_LKDTM)          += stackleak.o
>  lkdtm-$(CONFIG_LKDTM)          += cfi.o
>
> +KASAN_SANITIZE_rodata.o                := n
>  KASAN_SANITIZE_stackleak.o     := n
>  KCOV_INSTRUMENT_rodata.o       := n
>
>
> base-commit: 2c85ebc57b3e1817b6ce1a6b703928e113a90442
> --
> 2.29.2.684.gfbc64c5ab5-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Thanks for taking care of this!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx3w%3Drw3Jk3Zg-Q2H6iboWH3dqGvgm9ZXxsCaBGGzR9JA%40mail.gmail.com.
