Return-Path: <kasan-dev+bncBDV37XP3XYDRBJPCVWKAMGQE6ELNY7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id BC0CA530E91
	for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 13:33:57 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id c62-20020a1c3541000000b0038ec265155fsf10450086wma.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 May 2022 04:33:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653305637; cv=pass;
        d=google.com; s=arc-20160816;
        b=FADuMRjSgMr7fQvtIF2DgpqTuAwpzjOffqogUSiVdZEcrINHf0kzJOahDUUZ6Hr8V7
         EJKzGCHQedMXeUlFy9Gk0Dh42JRfgGrIgPIiUWiAEA2NJcJphd7ii5hyH3xVTQ96QILn
         RyVq1GrEje3RTuYQQhC1ikEDjv0aMZ4VAZD7jsUki6YUQVBFVZjgvxmJjoKsAHDDpoKS
         z9LJ1v60wYBq8DMyItFYR4A0fp24/5X654DoQyPNwvRRFhXn6gYt2SWcdS4WGUxJuQJj
         IDtOBagPS8v3HrRpsd2jEDlpfiz63NWSo1+wrHXdz4CqlN2olV680ZmQ7FuV7ZX24XV+
         K5Kw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ExnGknOJdPFluk4s9kFyovZLxMyKnQKvxo0nuaBE+lk=;
        b=pfcEz2LWHgbOoId/n37Q+bh8V3zxYIaHgxtZwDeR5izpahwQQDao5u7gM0TemMlXqU
         L8D3ifjUhAvT9NeeTREaM47+BGyO0J9lH/i6p9HMWdv3OC0Ay3F19zG9uM1dSJ2xnOac
         4ekJhq6ILRyXFlnh9udK6d801yKrxFCUAwleeDfl4ux2Jb6S22bXZjvGVAnOTHSkpVyp
         gmXqq3BGIx7kpIt8+WncsxJ4Mfs2R1WuPZAbiVFq1SBKWM1QzDgQRWQD84sybpb8YQij
         +O5D6tqwB4LInJSv5Py6VjwIe1xWfjwAn4+1DfPNhP6+IlawSxZJGcip9//LySYVGlj1
         9TQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ExnGknOJdPFluk4s9kFyovZLxMyKnQKvxo0nuaBE+lk=;
        b=rLBQ3KdFetLBReKZglySIwkZpMts/JF8GSxPXFQJq5fiVbdDHIp1aihxIrGZyMOJ3h
         9WkW5h0wmUx0ZeD1ZnH/bEZkGRr2Ea95K/Uz+4ZzA4oB7ww7XzuYyMy2APthS6DS9kaG
         oHGcrl76N+SZbDKFN/IGv83XZTJtj7/YbSukJFZ9PUcJgTKeIVxHLPnP1GOLF9J611wc
         mDkJGVXDzFh2Nh+bT6HlipworxPOMjxGjZXrX67pTj2zVzR9+QLfWoNzMgQRH3ZUO5cQ
         CAL+72u8Jzt3z7/0HnvkbeNHMd4S3UV/VYPAV7GdowssFC9LV0KjeWu4O5LlOJLZasFi
         ++5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ExnGknOJdPFluk4s9kFyovZLxMyKnQKvxo0nuaBE+lk=;
        b=UnjgUKtXOGer3cB1g0rO5Jke1KngJ3s8cFwEC4fcOudzl7Oqp/DhJPkPprFQUkQLxl
         z0vl8fy7l2rzYxeQgiRLP73LEwMoNEL7SzzlujF7rdg1ZnjF+6JRCdjNypld7IDv8SGZ
         WM2v1FfI0jmssusoPiTCS6J6lBdQoay3DhO7ZcOkrnBCjtnHMfS73emaD0NqA3ruj7rO
         3LcBjPValgqC/P7Qvhs6XQmMmLq75TcfnQbFkyEDe6/yWpR9QOq9VjyUuWuaTtrfg5ro
         vX98cHg3YpLrGQd6ij0ema9tlmo1CQLYMSBsFMs8x9B08Rsr9QSVZ4+7JOjQ9w8N9Cx+
         Z/8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531rNDHswCwjtOchKjkqNG/vGWd5p4BFDm1VQKdkuYqgQ7ylRO6J
	a77pteBIRouk5E5s7qqbp9Y=
X-Google-Smtp-Source: ABdhPJxwAEgeWKaKtHlVh/HvuZQwu5DqgYKfRRXl2LWyZbKXWt9rW3xNNgUX0mvrv6deHWvWvR1qrw==
X-Received: by 2002:a05:600c:3b05:b0:397:54ce:896 with SMTP id m5-20020a05600c3b0500b0039754ce0896mr1477159wms.3.1653305637261;
        Mon, 23 May 2022 04:33:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1e0b:b0:20e:7a8a:8c81 with SMTP id
 bj11-20020a0560001e0b00b0020e7a8a8c81ls11325686wrb.1.gmail; Mon, 23 May 2022
 04:33:56 -0700 (PDT)
X-Received: by 2002:adf:9d83:0:b0:20d:129f:6544 with SMTP id p3-20020adf9d83000000b0020d129f6544mr18481689wre.568.1653305636009;
        Mon, 23 May 2022 04:33:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653305636; cv=none;
        d=google.com; s=arc-20160816;
        b=KhQqrTPnoMf4T7DZODuXOyp/4IVw2GnNVnCLCvRVI4ZQrrW+EBssFsBDiTDxaK6LQ3
         bF31971W8joOhDICMtNWumw5XXfICjfP2amwdQbUX5he0iE5Ss80/jHC551LtRWlAPFB
         egYfPQCivWVWLRxOv98FY75HX9Yutjwg6H7RD08RY2IuibkoPkW4Sv0RBu513TMRTnK0
         PPgnOY/KPpvSvHCWo2bFafJ6uY7xe5tN+0dXmX950ukzIPnhgm0Wg/r3UPWCCL24DrbQ
         1IGWoZ9rWyo1HLFg4EzIgeZXs02lpkkozCThFpS9SyJcJgQepjna4LDvCUGf8iGn5tpK
         FVrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=XNT5MdP6tzK2RfufBFU9iRlBFu2p3wIno2G6EVmT8Yw=;
        b=sO+kGy7Q2wj47G1lbwq2CXpDp+mogCq7t7vnJ/tK2TM3r2zY2GdR2cj5zyAS6fwxfg
         83jwX0tNoO94cHAQf/FUsC4n3s+2d/ELi1Bpqzkrkx4N2pfN6yJzF5uwtp//+k+nbW7o
         sDOQslQBoY5+hbr25ZQRHCOdvNbegpF6RHkd+wCAxJ9HCJ6YjsUND/r7I/3Cmruvrnhc
         WRbcldSmf6HpKq3Yn3f6oXJOd6V5zd/xTuLHKes3PPv4WHVktYwR0mow0mLpsp2t8FFr
         GTyO+UP4gU7f22fLn0zl2XYiNsAcfHQ8uUlO49LIvyuOxujrhS87BpX0haIkoQ1X1QIJ
         aRSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ba11-20020a0560001c0b00b0020e674a0d19si186126wrb.0.2022.05.23.04.33.55
        for <kasan-dev@googlegroups.com>;
        Mon, 23 May 2022 04:33:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2DA6311FB;
	Mon, 23 May 2022 04:33:55 -0700 (PDT)
Received: from FVFF77S0Q05N (unknown [10.57.9.63])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C661C3F73D;
	Mon, 23 May 2022 04:33:52 -0700 (PDT)
Date: Mon, 23 May 2022 12:33:48 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: andrey.konovalov@linux.dev
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 1/2] arm64: kasan: do not instrument stacktrace.c
Message-ID: <YotxHEQNRet/zXHW@FVFF77S0Q05N>
References: <697e015e22ea78b021c2546f390ad5d773f3af86.1653177005.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <697e015e22ea78b021c2546f390ad5d773f3af86.1653177005.git.andreyknvl@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Sun, May 22, 2022 at 01:50:58AM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Disable KASAN instrumentation of arch/arm64/kernel/stacktrace.c.
> 
> This speeds up Generic KASAN by 5-20%.
> 
> As a side-effect, KASAN is now unable to detect bugs in the stack trace
> collection code. This is taken as an acceptable downside.
> 
> Also replace READ_ONCE_NOCHECK() with READ_ONCE() in stacktrace.c.
> As the file is now not instrumented, there is no need to use the
> NOCHECK version of READ_ONCE().
> 
> Suggested-by: Mark Rutland <mark.rutland@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  arch/arm64/kernel/Makefile     | 3 +++
>  arch/arm64/kernel/stacktrace.c | 4 ++--
>  2 files changed, 5 insertions(+), 2 deletions(-)
> 
> diff --git a/arch/arm64/kernel/Makefile b/arch/arm64/kernel/Makefile
> index fa7981d0d917..da8cf6905c76 100644
> --- a/arch/arm64/kernel/Makefile
> +++ b/arch/arm64/kernel/Makefile
> @@ -14,6 +14,9 @@ CFLAGS_REMOVE_return_address.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_syscall.o	 = -fstack-protector -fstack-protector-strong
>  CFLAGS_syscall.o	+= -fno-stack-protector
>  
> +# Do not instrument to improve performance.
> +KASAN_SANITIZE_stacktrace.o := n

Can we make that a little more descriptive? e.g.

# When KASAN is enabled, a stacktrace is recorded for every alloc/free, which
# can significantly impact performance. Avoid instrumenting the stacktrace code
# to minimize this impact.
KASAN_SANITIZE_stacktrace.o := n

With that:

  Acked-by: Mark Rutland <mark.rutland@arm.com>

Mark.

> +
>  # It's not safe to invoke KCOV when portions of the kernel environment aren't
>  # available or are out-of-sync with HW state. Since `noinstr` doesn't always
>  # inhibit KCOV instrumentation, disable it for the entire compilation unit.
> diff --git a/arch/arm64/kernel/stacktrace.c b/arch/arm64/kernel/stacktrace.c
> index e4103e085681..33e96ae4b15f 100644
> --- a/arch/arm64/kernel/stacktrace.c
> +++ b/arch/arm64/kernel/stacktrace.c
> @@ -110,8 +110,8 @@ static int notrace unwind_frame(struct task_struct *tsk,
>  	 * Record this frame record's values and location. The prev_fp and
>  	 * prev_type are only meaningful to the next unwind_frame() invocation.
>  	 */
> -	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
> -	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));
> +	frame->fp = READ_ONCE(*(unsigned long *)(fp));
> +	frame->pc = READ_ONCE(*(unsigned long *)(fp + 8));
>  	frame->prev_fp = fp;
>  	frame->prev_type = info.type;
>  
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YotxHEQNRet/zXHW%40FVFF77S0Q05N.
