Return-Path: <kasan-dev+bncBCMIZB7QWENRBXWK33XAKGQE32CTXDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id C5B1410689D
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 10:07:43 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id q2sf4212815qvo.23
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Nov 2019 01:07:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574413663; cv=pass;
        d=google.com; s=arc-20160816;
        b=yEfeReiWGsx+nCHDWFxmky+HDqY9CBPWn26DYVETZGC+OHaj0LTXCY3W8OECJNk/aM
         hUAakcTr0Ina+by+RgBfgzRkckUlscL73Eu7paxewZecVIZATt/3AkwsVgw1tSivyTMC
         6Qr5zb0IYi8Ylsp73Sid8Xyt6bwVG6k6pX8y4cwSdtw0NZeM4+X34M5Ri3URjNeiM5O2
         oN7ZnGU2kgQFMZ6UE3fVx2MZwc8ZtgxeHB42hrbXyZg4JaVSuXE/VTZAIcgnM8nnSOQJ
         WpTliFQUp5E06VVz5Oo79yFrCjF0a8GZ1/FWnTfU/fuQ8uf9cUJPuS08lxNogt3rZ48h
         NNpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wjP+wrkCv7WgaLCh6x10RYydvezt4LoDTZHFLgi8WBQ=;
        b=lubWhnXAb4lDMdrjC+t5TfXcDp80Fl0DzPrV58oqM8yDvWxOQoNs+RZKq887XgZeez
         wTp+yIT8QTKdiYQ/C9N2FT79v9JC4RwPKyVTzFeqOHsGT3lo60BHNLW7KTQsT3irlCow
         926hBntRmxLWEWuGiTjD/AG94vBsjiqBr7u/oLr5+rf6ts7snwnZl3TOi3it5FgnGEVu
         kFke51TCxmBxsxHAfWTgSqnKN+EkafVhM4sKHBvHrUBd1JTvFc9IlD9ttFrueQ1kaRRN
         OkYbubk80DB1/EDjV6KQZOfHX1wh/YxNxcO0WVfQS05iv1P11Y8EYPJv5x0lrDP7GnzY
         BB7w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t13lqmTw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wjP+wrkCv7WgaLCh6x10RYydvezt4LoDTZHFLgi8WBQ=;
        b=G+ecAXPgPdA8Dy4TA9lxVgz4EBRegx4UKbuDgvm6rrWOMqHtshTfaV1MWVJAqCd7xG
         cArEprpRlJ8IBoS94ElnW9r2EO3ux1tDAE1Fp/VbDzNf0sGIP9U2fBSMEX4vr0lzf9Zv
         ScJsS7G5B/+MeH5JvqBPWflTC1W+yKw7KMhZdESxzfqyrulpky3VhPNa1PAsoTwmNgGR
         IVlwNfbTvGoMiY36iuQJfJvI/NGJo7IE0PUmPuVuDEQULuM2nW11hZvlQDeoYx3/7apK
         TVb1D3jExWFCkH8h+IT4WuOhknCwy1xkgLLQW8Utj4PBf5+JfEItxgvqR03t72kVa9Dr
         W10w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wjP+wrkCv7WgaLCh6x10RYydvezt4LoDTZHFLgi8WBQ=;
        b=NAQcupsutaJta46yBvF7qvuWSQpizlVSQldqa4WrvBnjJ41QU6WoyJ1Tr0Y30gMZan
         IJDHHrWAs//qXXfQWY2EnenHlbFn5+gtCAd8hCGZ/HT9PjXyhuydIYVe7nv/u6Y465i1
         CGDmyBbnGtBSDKnMO3gQVQgXWeTjgtKwzO7w7KBl1e7jaGDBGuuK7or4jLSDBxbG1lVB
         bcsCGNo8pDx1ppNcNdMgoIBIs3LmK9MdE9QVLrAnZLU3XFZ5915FExJtCvgOzlfAFkjE
         jKxXtSK/RDc/5SVcxztcgHS4YWcJtQD77kT3nIo6MiUzEnAIs0gfParfwhmdOtlpLDNa
         BLqA==
X-Gm-Message-State: APjAAAXUqrD7FhjCXd3Rkc19EHqgAbHbWwA0WuD5+ymXj3NVDNzZjmGy
	bzZbap37vbN3VgnUBIgRljM=
X-Google-Smtp-Source: APXvYqxh+WpqpwZkRFud6Ylr2yeur6oecskUendUOSF+9HMsG9ljuqZcitvbZLi81A1hFjlEVnTclw==
X-Received: by 2002:ac8:28a1:: with SMTP id i30mr13806401qti.245.1574413662863;
        Fri, 22 Nov 2019 01:07:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:68d3:: with SMTP id d202ls1722132qkc.14.gmail; Fri, 22
 Nov 2019 01:07:42 -0800 (PST)
X-Received: by 2002:a37:4dd2:: with SMTP id a201mr12812527qkb.5.1574413662458;
        Fri, 22 Nov 2019 01:07:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574413662; cv=none;
        d=google.com; s=arc-20160816;
        b=s/Y6i6K2Z2rYWf8UmzzrAOlZnQ+og2l8ng1GI4DqwjMZ07f0NYzUcWU+TqueVevkM7
         jCUZjNBhE7tttv8OuVZKd4KDY/MkXIfePPKaSiVEWe5365kUrQlzHZ8U/SeRsa7KjCyd
         bWOJONSs3Awjw2gTvK/EBACGCLhOwOoz32LN6tGe1GxDfbFhxRf5NdUR+T2b5V9a/f6Z
         UtB1MWvcJDBYSuSV6hvbKERzd3vkdhNGxqSmgRFvXinjTf68mFPUnfuFmkcF809iNPGN
         MRxNcSqKS62Mkp8Z5jsPWN4PhW9KJ8IIhz+AXVswxFQ2MxoMjFCcNsZxueMt1ZeFbMLO
         M0WQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ljr/rHZhX2cKSZOMtdFMLeDFfDK4qscTIQX92Z+51jk=;
        b=E3IFtdY4rYzHiZEA893rXzlYEMkIbSB7Ez1tQOT+rXOsxAFissKgjE7zszydLNlBGK
         EVe+6O88MLzMQUe94dTGZk3gSz9JzyryRIlNOmrovA7NAy9qvfCMcL4Ye31JkKkBg3Z+
         sch4pWX31mSMSkpNOXM+EhEZI+VCZBwE+yFs4jcJn3sCZrNv5K6r8QawzObW70sN91ph
         ptSiyNdrjvnFJm5UBvQQMwJJ15Oy0e0gumSIC+07bgaDzg0dtWWkeVYdqZZETLHsy996
         2YQ2jlikbHCPCxobHRdjAx9pbETsPvlXudhBwXM/h0ZQKTjNkcl30Kh8r22Bs9cCbWWw
         zRuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t13lqmTw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id v189si290304qka.2.2019.11.22.01.07.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Nov 2019 01:07:42 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id d3so2553070qvs.11
        for <kasan-dev@googlegroups.com>; Fri, 22 Nov 2019 01:07:42 -0800 (PST)
X-Received: by 2002:a0c:b446:: with SMTP id e6mr12863287qvf.159.1574413661601;
 Fri, 22 Nov 2019 01:07:41 -0800 (PST)
MIME-Version: 1.0
References: <20191121181519.28637-1-keescook@chromium.org>
In-Reply-To: <20191121181519.28637-1-keescook@chromium.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Nov 2019 10:07:29 +0100
Message-ID: <CACT4Y+b3JZM=TSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] ubsan: Split out bounds checker
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Alexander Potapenko <glider@google.com>, 
	Linus Torvalds <torvalds@linux-foundation.org>, Dan Carpenter <dan.carpenter@oracle.com>, 
	"Gustavo A. R. Silva" <gustavo@embeddedor.com>, Arnd Bergmann <arnd@arndb.de>, 
	Ard Biesheuvel <ard.biesheuvel@linaro.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, kernel-hardening@lists.openwall.com, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=t13lqmTw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Thu, Nov 21, 2019 at 7:15 PM Kees Cook <keescook@chromium.org> wrote:
>
> v2:
>     - clarify Kconfig help text (aryabinin)
>     - add reviewed-by
>     - aim series at akpm, which seems to be where ubsan goes through?
> v1: https://lore.kernel.org/lkml/20191120010636.27368-1-keescook@chromium.org
>
> This splits out the bounds checker so it can be individually used. This
> is expected to be enabled in Android and hopefully for syzbot. Includes
> LKDTM tests for behavioral corner-cases (beyond just the bounds checker).
>
> -Kees

+syzkaller mailing list

This is great!

I wanted to enable UBSAN on syzbot for a long time. And it's
_probably_ not lots of work. But it was stuck on somebody actually
dedicating some time specifically for it.
Kees, or anybody else interested, could you provide relevant configs
that (1) useful for kernel, (2) we want 100% cleanliness, (3) don't
fire all the time even without fuzzing? Anything else required to
enable UBSAN? I don't see anything. syzbot uses gcc 8.something, which
I assume should be enough (but we can upgrade if necessary).



> Kees Cook (3):
>   ubsan: Add trap instrumentation option
>   ubsan: Split "bounds" checker from other options
>   lkdtm/bugs: Add arithmetic overflow and array bounds checks
>
>  drivers/misc/lkdtm/bugs.c  | 75 ++++++++++++++++++++++++++++++++++++++
>  drivers/misc/lkdtm/core.c  |  3 ++
>  drivers/misc/lkdtm/lkdtm.h |  3 ++
>  lib/Kconfig.ubsan          | 42 +++++++++++++++++++--
>  lib/Makefile               |  2 +
>  scripts/Makefile.ubsan     | 16 ++++++--
>  6 files changed, 134 insertions(+), 7 deletions(-)
>
> --
> 2.17.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb3JZM%3DTSvUPZRMiJEPNH69otidRCqq9gmKX53UHxYqLg%40mail.gmail.com.
