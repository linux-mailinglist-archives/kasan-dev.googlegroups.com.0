Return-Path: <kasan-dev+bncBCQJP74GSUDRBGUG2WAQMGQE6EN7JLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 77008323025
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 19:02:03 +0100 (CET)
Received: by mail-ua1-x93a.google.com with SMTP id e15sf7716138ual.19
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 10:02:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614103322; cv=pass;
        d=google.com; s=arc-20160816;
        b=e3X1tkKklUVZ+8RiAcR5YR0eolPKVePangXxiT0isnstwmlN/DmApvXnn/46cHnLbo
         jamPs3Ozm6iagA2hJoown7/R5531JKhvObb824zJxKkC5tmxrmsH5OsXCSuH950W104L
         hURYK8ld+YTHyZ6abo7SDuuhn9VC5k5vZPR769FzJJhjwBI4XW/hcZ01g8qY0E97y9mw
         HVxcjhqfD+oXqv59BI/sboinh6nE3WQBICGCUuxhzSUgCtRrh8kW9GiO7mecW47ppdsz
         HiVY5e3MzdPpvES0jPPOUJ0QCNb+1H7648LNXE8iv/JbIJAOhaP6ACYRzcf2LL3b0v1I
         H73w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=RrjR0W5vMsT14UR+KBHZ8FBJZ9aoUO9RttZrE38Vpsk=;
        b=nFqkbm6h+z7C4DJOT5Ve0W07JnEdjwkuLxXtd/2CTqjO28+1DFrpPN3+Q9SfE1w+zp
         QRiv3Uvq5TYXmL6994K/gmR3gnZWBOnCuQLxMn+s93MXRf6oRHnYbOJstNWNwo/iweRF
         kWJv6XAy2NWFhPSW3LD8IYoM77lSf9yrWvoZM6N0zKw8XY5cpdeHDc1SX2vlGzBa5ZwJ
         xMf0Z5vO8bG7QabhK5/ChHsp7Rdybzg6Khvjrn7xIb5eVXou7WziuZnT0yo5zh3VXUeC
         PlHTWh1+nTdB47aTS89lGXkJQ4tA/aSlhcwY9HaQlnRDs5VNqJCnXx8H+2bG1AUawm6r
         V64Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.167.169 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RrjR0W5vMsT14UR+KBHZ8FBJZ9aoUO9RttZrE38Vpsk=;
        b=Pi9MFx/IvrdzqQgtMbtQ/a2LNm1cb7visi+9oA/VBwT4ArvXikyS0Bqe+3pm1Kdeac
         NZ09ZbgwM2gdzCCqM/KV1YvQjfZs9jxB6gxAoMUatVaeTaC0zIbk3WgDZvUE+mIHiFEZ
         WLH3Iepg7YI6gmJD5li0EPW0UxOuhTV0SZ0irZZzktaBXi4m9Bu6g0hbfztVllnix/YZ
         DQ+2ED5asQq2HOV1yGzxfGXbB2h9XQJ82rJ3qRQyneNEa8Ykm441qnh9M1q7I9YfY+uR
         JnEtfkC/Er1m/PXRH3Kg6RQUXYV2n61eAqg9MzkX3d6v9wMuBYPicwW58I/QNCYO4hVk
         tObA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RrjR0W5vMsT14UR+KBHZ8FBJZ9aoUO9RttZrE38Vpsk=;
        b=iR4N+Jbm/ZHVnoYPEEhELsqIAZro1uXbZYLkDjflrYww6mpXAS8DXo0psbUlKGn91F
         7kPBPRPXYBmyw3rT0uXF2mHQcEySfKRGHeFJmY+vJEcxIi5iR++NWtSoAs/Y0HOrz/MC
         WG4TIJPu/uqEMECCbhxl9Xm49VkZwB1OKGblzdw4w9zuT2S0Qq3VEYMhREMY42XWNjPE
         ytf1GHXBLVi0McKmnoLeqOKu0r/vnffcumThkXrTu0a+fbNogbxZ3WaSa+13RuePTgvS
         8CgBVLG6IWMEprvXZZYnovp9tUMOlxM6x8vFnayDk/7mpODa3DWTu1WMs1tQ/ojVBioU
         Wb/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ks+Q4RadPit1hJLKVfga/cHDWXNZVsmmFuw+wy/BvVw/6L9Lj
	jeZpfuIDrTx4JDtAM7TWFnQ=
X-Google-Smtp-Source: ABdhPJwMbTwDjNeyE5bZhz6VbNDvnjo5rMDvywY9Vg2ZlZamZ6vc/PbmC55df5XdGFsV6FJ+lmGr8A==
X-Received: by 2002:a1f:1a54:: with SMTP id a81mr17837750vka.17.1614103322444;
        Tue, 23 Feb 2021 10:02:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a5c5:: with SMTP id o188ls1044875vke.2.gmail; Tue, 23
 Feb 2021 10:02:01 -0800 (PST)
X-Received: by 2002:ac5:c35a:: with SMTP id l26mr5167239vkk.4.1614103321410;
        Tue, 23 Feb 2021 10:02:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614103321; cv=none;
        d=google.com; s=arc-20160816;
        b=BXLeT0cJW9SAV82/s0puNTDx59eac6BW5BXNPZB6Mb1+21PSMhK2kRb/BdDcGdUutO
         tDs17nuHVEnWh+pfKT2bqwf4IExvBaPcCTf3sX3JeTjJiERrv+GHKkGJ+IAvCudF0qp2
         NEE55LmV/8bEn/RtuIsEzA5l5e9zFFbFCKdUE+XoU2+J7/KDlQsaFYmhDUS7VFM0ATU0
         NbonlO5l/3poz1wEJ2Hb+KlAz0CWDeoERvPXY30OYbswH31KXI/LueurF8gpsoqAi6T2
         IwcoRqjMzEtPZpGsvZ9lh9iHr9NGZDjpxxawiilclB96kQb6flb54a3Vz+vliVKSpG72
         v/sA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=Hr05fO8KOjmWsbPm+ZFI7vyJ8Gmfr+uEbMgTqe1usGE=;
        b=zhR9Gsvh+FAupgDdAJt1COre9Z+NDy1VMKCWPBe1KeBYFMo5rzqimXMfHW02N9lmUl
         X6pOv0rmzHyVw5DzgeB16mcy+ZSLxTTb9NAg+fTbCaiC97Kpze5iQ9NEO+ul6kzVMGGi
         FhMZRj7Ol2x0nG1xoqoUgJNLdxAn7N7/e30wkA9v6zVIARzb9IDXerGWaxuYof4RL/2l
         QjpZn3lPjH2f09yYhAWZ0zBDIg0wLkOFK5L8BoaQnnCKuQ43YxpoRlYlpCsr0JM9J5ca
         tjOfrMKNeOd6eI9V4abnOL6IumavNAW9kp/FDr//+MPnjxh8HSlNEPwt0kffrAlqDM1G
         qjGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.167.169 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-oi1-f169.google.com (mail-oi1-f169.google.com. [209.85.167.169])
        by gmr-mx.google.com with ESMTPS id f124si739058vkc.3.2021.02.23.10.02.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 10:02:01 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.167.169 as permitted sender) client-ip=209.85.167.169;
Received: by mail-oi1-f169.google.com with SMTP id 18so18530940oiz.7
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 10:02:01 -0800 (PST)
X-Received: by 2002:aca:744:: with SMTP id 65mr19161636oih.153.1614103320874;
 Tue, 23 Feb 2021 10:02:00 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-3-elver@google.com>
In-Reply-To: <20210223143426.2412737-3-elver@google.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Tue, 23 Feb 2021 19:01:49 +0100
Message-ID: <CAMuHMdXVZ+UvNgoaNC-ZZoiuJ=DOsZs4oZzd8DubA7D+4iLCow@mail.gmail.com>
Subject: Re: [PATCH RFC 2/4] signal: Introduce TRAP_PERF si_code and si_perf
 to siginfo
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Dmitry Vyukov <dvyukov@google.com>, Jann Horn <jannh@google.com>, 
	Jens Axboe <axboe@kernel.dk>, mascasa@google.com, Peter Collingbourne <pcc@google.com>, irogers@google.com, 
	kasan-dev@googlegroups.com, Linux-Arch <linux-arch@vger.kernel.org>, 
	Linux FS Devel <linux-fsdevel@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.167.169
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

On Tue, Feb 23, 2021 at 3:52 PM Marco Elver <elver@google.com> wrote:
> Introduces the TRAP_PERF si_code, and associated siginfo_t field
> si_perf. These will be used by the perf event subsystem to send signals
> (if requested) to the task where an event occurred.
>
> Signed-off-by: Marco Elver <elver@google.com>

>  arch/m68k/kernel/signal.c          |  3 +++

Acked-by: Geert Uytterhoeven <geert@linux-m68k.org>

Gr{oetje,eeting}s,

                        Geert

-- 
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdXVZ%2BUvNgoaNC-ZZoiuJ%3DDOsZs4oZzd8DubA7D%2B4iLCow%40mail.gmail.com.
