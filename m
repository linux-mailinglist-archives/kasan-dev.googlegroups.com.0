Return-Path: <kasan-dev+bncBCMIZB7QWENRBQXG77YAKGQENFZJT4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AEF413D38F
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 06:23:16 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id p8sf15206905ilp.22
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2020 21:23:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579152194; cv=pass;
        d=google.com; s=arc-20160816;
        b=GuxH1fxYByY6c971q3GKBr0ynUJMY0TALxCOgSqlaE58qpqP8XLkk1vh3Vgw5xOjr2
         NfAjOjHA2v9PXvna/JF7m6gX8eodZOV7aAwxrQwkVUZBk2xo1MSyv0DK/ShTrURcjPU+
         fXyC49k1S05+mpqPXWMXGJk8Qy4+6PIna2lZ8nKbSXRd0APCo2x8jfWlMNhamogRzKt2
         pKS+MJoD7uKKuxE0vm97qb7aetvDehFBKQNHHX/UKPYot2Y4XHEi/0526jAh2jm98lUW
         b0HqXyBfvgG0olg4/ilKaNEDa37alKobBShyolFukwKpc4k7cbCyPa4wOKb1USGJBZfb
         3XCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vjzKvN9cJsbl8HlLtGUmRX8lL48qH1tbVbBmKBYJ/cs=;
        b=GkNqMkC1ZcKXqZdNIq6BpM2d+QZBWbjv0Ey2gH94LlxPEt9YBja8rBn0j4/++pu02c
         ZWOhvujn5k6Slwf7IX7nYFoCCB/n8cqCDirG1ndyofF7EY0MujwxJf4oYaz++vqGV9eV
         2OMFA4zxoLXFrPIou1qO9SXzkCsbjDQmRE1AuLaWzrFAYnWNjhFp22oVK2IWm+LMU139
         NEX4RsGWnuCvxidS4RUq9eWfO/sg2tyfOAknK7Xux33Dsm2L2z5RrS93BEKKPx9WnqqI
         cc8A3iCVwC0g03n5mEkEC9tuQG3pjmasm5V/6zdUuL4gWkawIw3zzyUjJqUhH8Yv02ZT
         kbFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OZdQn+Tv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vjzKvN9cJsbl8HlLtGUmRX8lL48qH1tbVbBmKBYJ/cs=;
        b=WszgNvuRcsm/updiPZMNyjpDngxdxF7RO0STTDJBPiGNF6hOrsFFpKTh1ptrMJFy7E
         IgJv+qe9ue+PZAx240CPAPaqWVJtHx9vVKkUtrCTXxgpBhiSu2Vu85rtfHURUd5SGPu4
         LRtgRldj7ylRnYzy7SUcGAKmYW+nhQpulUXQhEr86vl9nTZ6gr7IY75CZU8UZD7Go5aJ
         9Fq07IsTY5I4Fp5Rrll0U41C10T3BcK/xsgFXjhqgtjTq/ewXIQO+ZM5xsSb6/bojt1o
         6PRL6eUU8VSrWtsrWaPWScRVaiIwCTAXkHgQ2L2avwdB6AWFvKFi6nDTj1b9ks1Rw40a
         3twg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vjzKvN9cJsbl8HlLtGUmRX8lL48qH1tbVbBmKBYJ/cs=;
        b=Q0Pstfr9KiLfJ7xnl+dqwedjn3yX5syQnVi7DtvcYHD9X6vmpPPFHvN49oq48WZNHd
         SQ8EC5iMDLq4wl7+08HiCVwOzppWXFQZwRN9pu7yJAUsLB4wV7ftaL0Qzo8QgFY1ql4t
         g3w/DezbHDw6/jnuVMIhIN/o1pOQg5Q4I8ZTyUaCMWcERA2pKkHGwIir/TNSI/JoA2cs
         zTYNcm47N4z8nV9bwbV+wkHK3tG6j66lYZjibZ12exb+BYKo7UHv9frFT5rU0oNZWacG
         7yhkDN9JLFGcHr7HdhNwFhdLbKYzHPp2n2/s+Mh+M7noyW87Whse2GP9MTsja+ndDGJ+
         968Q==
X-Gm-Message-State: APjAAAXfN3EBO4fGJlQDjY6kVeQP4uTL9UfELOcnkpQX60L9lhO9dsgm
	StE2oRKcKJjVqG9JgHpny94=
X-Google-Smtp-Source: APXvYqxRt0uOB9Kcs1iXCXNU3R0qYhV4Uo/cz9vb7BYZLm+5colILBzIBf96evmVpLuZvCQNmHjSKA==
X-Received: by 2002:a5e:df46:: with SMTP id g6mr24894192ioq.240.1579152194708;
        Wed, 15 Jan 2020 21:23:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:607:: with SMTP id x7ls3775875ilg.14.gmail; Wed, 15 Jan
 2020 21:23:14 -0800 (PST)
X-Received: by 2002:a92:981b:: with SMTP id l27mr2025952ili.118.1579152194374;
        Wed, 15 Jan 2020 21:23:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579152194; cv=none;
        d=google.com; s=arc-20160816;
        b=YnOy2+L258AmsYGkCEtf1Iu6J51Z96mmDRAQpPmLhXmho9qLiK5Q6Gqfa0LMz3bsIg
         B41TaKIwkJBlsqJ5kykZnIZ9iI8JHuszFa57LA/fQd6fuJSuWQJsFHsGYHAUP4uKArKl
         HsVFSHIFX2DNJnCV4lxl7ou8LbSZyZ7jONo8iYaIaD5NUMZ1KPKO15PtaCRX0NCot/gE
         NQEdNh5cJZo87fz2pP2lAMPbEEWHoe9E/2xa5PbmJjC/vRR2qwlbeH6lS/zp0CetelbV
         mFitf7vX834SLLQt3PdHd22FVcSN7Hd88ieP37mR8/eZz0TOlmJHiHnEBVYwGLZgeacK
         6nNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yYiCDbJIjI5Gc+HCG21eDD5I0VhMo0bA/4w6OlV0KM0=;
        b=F0RHp9nllZZXZTw+irPhHXeYE6Uq/0i8KZ+gqNnh8XhHx7H73c9XCgA49r7nFFROX2
         ex2/3uw3J+icbMRCu4wjtF9TC/NtQ8r6RNyU/3/D+gY9qJg9EePXpamDfT3/DJbd0Xkg
         1wD3KANJOEis4vq9iRr4mu/q6M4RnatSLiquiAmmRvYTuytp2cgVxDBZ9ISsVHBkNMIi
         3Zt2kO/vhaHKNWC5l/WXNk1l4R/Uj4mQJwVdS7bCCxwcxe8v0BmhW91v99Kf0Sc43Ik7
         yKGYbg04ANDUOXtyOA/lQqz1Ye6dWMY/VSHzBJJugIkKIpuHFm/pjbKDhI6ovW0H1afW
         kCTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OZdQn+Tv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id h13si893171ioe.5.2020.01.15.21.23.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Jan 2020 21:23:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id i13so17940268qtr.3
        for <kasan-dev@googlegroups.com>; Wed, 15 Jan 2020 21:23:14 -0800 (PST)
X-Received: by 2002:ac8:71d7:: with SMTP id i23mr784628qtp.50.1579152193440;
 Wed, 15 Jan 2020 21:23:13 -0800 (PST)
MIME-Version: 1.0
References: <20200116012321.26254-1-keescook@chromium.org> <20200116012321.26254-6-keescook@chromium.org>
In-Reply-To: <20200116012321.26254-6-keescook@chromium.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 06:23:01 +0100
Message-ID: <CACT4Y+batRaj_PaDnfzLjpLDOCChhpiayKeab-rNLx5LAj1sSQ@mail.gmail.com>
Subject: Re: [PATCH v3 5/6] kasan: Unset panic_on_warn before calling panic()
To: Kees Cook <keescook@chromium.org>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Alexander Potapenko <glider@google.com>, 
	Dan Carpenter <dan.carpenter@oracle.com>, "Gustavo A. R. Silva" <gustavo@embeddedor.com>, 
	Arnd Bergmann <arnd@arndb.de>, Ard Biesheuvel <ard.biesheuvel@linaro.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, kernel-hardening@lists.openwall.com, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OZdQn+Tv;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Thu, Jan 16, 2020 at 2:24 AM Kees Cook <keescook@chromium.org> wrote:
>
> As done in the full WARN() handler, panic_on_warn needs to be cleared
> before calling panic() to avoid recursive panics.
>
> Signed-off-by: Kees Cook <keescook@chromium.org>
> ---
>  mm/kasan/report.c | 10 +++++++++-
>  1 file changed, 9 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 621782100eaa..844554e78893 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -92,8 +92,16 @@ static void end_report(unsigned long *flags)
>         pr_err("==================================================================\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
>         spin_unlock_irqrestore(&report_lock, *flags);
> -       if (panic_on_warn)
> +       if (panic_on_warn) {
> +               /*
> +                * This thread may hit another WARN() in the panic path.
> +                * Resetting this prevents additional WARN() from panicking the
> +                * system on this thread.  Other threads are blocked by the
> +                * panic_mutex in panic().

I don't understand part about other threads.
Other threads are not necessary inside of panic(). And in fact since
we reset panic_on_warn, they will not get there even if they should.
If I am reading this correctly, once one thread prints a warning and
is going to panic, other threads may now print infinite amounts of
warning and proceed past them freely. Why is this the behavior we
want?

> +                */
> +               panic_on_warn = 0;
>                 panic("panic_on_warn set ...\n");
> +       }
>         kasan_enable_current();
>  }

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbatRaj_PaDnfzLjpLDOCChhpiayKeab-rNLx5LAj1sSQ%40mail.gmail.com.
