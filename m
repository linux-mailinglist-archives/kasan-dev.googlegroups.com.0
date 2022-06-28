Return-Path: <kasan-dev+bncBCMIZB7QWENRBTP65OKQMGQE7CMOTJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id A0CCC55D685
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:17:02 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id k3-20020a2ea283000000b0025bcd580d43sf719450lja.2
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:17:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656422222; cv=pass;
        d=google.com; s=arc-20160816;
        b=N7j8nJRdbYeq+lbLtlq6eF16XqQWndVFlz7KT0wnAW1a2OTimsx8EqFO792NTNB6j0
         fBujZYPYkbCLIykQ4FkKLrM4K0YDlvxuUByi7hwSLjeJJt6oQpkJfQ2quRkpoVsqTGxd
         QucA+WQQwwbFLOykqvhQRixvuZytVc4bTuPMPhHU0M3t1Z9G14eCgMaPbcS6Pgmj4L4a
         Qgwl7CIPw/9QT391is7e4PZ4PMg4tl53vmw8fXJxXDFk6rKGw9Tv44VZpMQ5aDvXS0qn
         +Gc5YTaqQ7rwHi4CHu57t5jWISQa/kquhcohMzJ5eVQpYaTq3vXr7Ri7Cm4H0MhMdNmA
         47Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+pbdSicHRVgOnt9V0Q+IcBAv7z6zT7/QUUN8zTu4xj8=;
        b=ib79+qeWuc5WrCBTwviEAh9tMa7e5ZwC0YmSUjBwnIRIU7NqVRKvue+k7+gc7I/tOk
         KC6L36tqWxWJ9TxuzUaH967m69adFJW9sd8dg6qCjNgbkzCpGIdN+L13wORLdlG52qMx
         F0L9Cb50KjJ/iL03SpP/34G4sS7mancVZNu0Nxc5tEXfxFo7zgF0b+hQsJ1/5w4fWs4n
         LzON2nrVwWJOUBT1zS7Cf86Evg3pPC0rttx0nidIDoqkyVzlfPwakD8CReTrCF89mkEd
         Y8iInzKlqz0cuZ2XydEcaQYvarsGirFd3FVRYV4eoedz9aazOJL8tT7j8RnWwJaFnHNI
         VIEg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AT2t+rTr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+pbdSicHRVgOnt9V0Q+IcBAv7z6zT7/QUUN8zTu4xj8=;
        b=Mi/yp7UFELnr5OD8lla8w3wdsqb3+bH7T0wZSxDXM/B6SHhWEp0GZY/6r24lt3rBqo
         BYLi8Fk1qpLN7KUtRL5aYIJUvwYCVkIwhPg3pMueyfP+37WxraxDdjkEilKEov+hX8gP
         5PNboOiGpOTFWy7rD9hml9WymkToIgiMqUzt4Hc1a1yYQPDzm3VE/Mt98MCAfSG6WCHG
         mfZCo/Go1R/nZd+G12BeMEPPJpTxAqMALTyLlPwaL9212XUMSo5Vjx7YKK2NqPs6yn+I
         bAzCquD7IrzOuLsjnQvCbKIJKLeZ1NFrNLroyckLgDbYqdZ1GKAoJzuug/hLHQF0JXBz
         F46Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+pbdSicHRVgOnt9V0Q+IcBAv7z6zT7/QUUN8zTu4xj8=;
        b=EzGKp5nP/T7QNFyn7ykQZVELzd/KEzkhn/5zdE8oIDCDtUMX8vXhC6PajuNT1NE/8a
         80rUoNxV+BF75WKS6ecGtvqziofAg6TZ4XbL0BnZfa84g11UMKCBkT4fCpESg+cuas2H
         ePcgSnIw8zdx7x3iQSsPHq5Gpqm03AAKJXzqwsfdTUCV8i0/6Ds+7uqlaq1cITOdWUoK
         F0gRGlFv8zp5BNU4Pmot/Gt5USqYE4wDg9m+qUSABvz6xMQFZ0X86prqfPvsqNFJLn6f
         K3XvBLchFFBksgpMSvFJyecbeSCxFBJwRKnNSt5OLK9e8mI79SwkprIaVa39IgnR9HdF
         SHHg==
X-Gm-Message-State: AJIora+w7xOiLtjgrpIT8DGd491KUmnP1sScmZQXAhoGTts6aMA9IWf8
	dZIrPLq1hOzvS7+auhdsa2U=
X-Google-Smtp-Source: AGRyM1uZYVzJbfGgUPvDaJfh5B2TGdkPTTQtTWxKXDNIaSNA/MpF3KORL+Biq8ZFsj6ilsBuu28q8w==
X-Received: by 2002:a05:6512:1055:b0:481:3378:b96a with SMTP id c21-20020a056512105500b004813378b96amr1549250lfb.426.1656422222113;
        Tue, 28 Jun 2022 06:17:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:99c6:0:b0:25a:89ff:c693 with SMTP id l6-20020a2e99c6000000b0025a89ffc693ls2818301ljj.9.gmail;
 Tue, 28 Jun 2022 06:17:01 -0700 (PDT)
X-Received: by 2002:a05:651c:4d1:b0:25b:b6ab:5b56 with SMTP id e17-20020a05651c04d100b0025bb6ab5b56mr7972663lji.84.1656422220991;
        Tue, 28 Jun 2022 06:17:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656422220; cv=none;
        d=google.com; s=arc-20160816;
        b=xuzbX8f/b4NgiTfg1BKQryTNfQIVCx7oGWQ5fPAoFwa/JUmRVRr0lLnLmTHp+MH+Rh
         MyCRi8mw66moRMmq1qerTLmsy2Q6mxpPKcDR7XFRFByVayNecbwUM9Q2j09MpUV4wdev
         RS/KF5ZbmkU6xPYKgy1NkBDFYXU+hXf2oJLJgFwxqzTh81hFT4ARoKj96PCRgduHEnPZ
         ahHwBX+WCCiIM8ZtLUFjZtUxb2cAGGvxIjVxCRLkcjAJsEDzy8GJRtgr0fVW6v5ZSA1i
         Ra26Knd/A52VGc8U3LNJYrLSyS+uHJLwDRcf8z0Z7KO4pxRrtTbIgasp1BLkgPFHopRX
         AqZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X57uwopXnuwAGxBJfo3nXt3MJLIDmWTaNVtJmoGBIrs=;
        b=efooNwTlIV+cPDBIHNNjDZtetEDtm+mH1jF1/p/jg97PcqTQT4O5GmoqOf25sJPn2p
         V+Lx1b1q/y7T8DPAE1vC9un6vGQbudVr5qcULqreen5wUSUGjZlBVDhn8HXsG/kd6JMx
         3iCXEuY2tgkRNRcKAuDaFzXlagmE7auj5tlHB9tO+v+Q7fwboIwlE0AAe1INxxMqMgUj
         l+JAq/0wB6mbh0eBT2oM/WR7nYGASAfwCnQuSBFqcUQPeUXmKFeW2PiFrJLDfW0mMdF/
         5qoVRw0hZ7PyMoTjXfsjkJZBcfMWyQbTq5CJoOcUUjCm2KTG8mopTQ1l8FPS1bgHQKQ2
         14Og==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=AT2t+rTr;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lf1-x12f.google.com (mail-lf1-x12f.google.com. [2a00:1450:4864:20::12f])
        by gmr-mx.google.com with ESMTPS id p15-20020a2eb98f000000b0025a8d717b7dsi641707ljp.5.2022.06.28.06.17.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:17:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f as permitted sender) client-ip=2a00:1450:4864:20::12f;
Received: by mail-lf1-x12f.google.com with SMTP id z13so22146653lfj.13
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 06:17:00 -0700 (PDT)
X-Received: by 2002:a05:6512:39ce:b0:481:31e4:1e06 with SMTP id
 k14-20020a05651239ce00b0048131e41e06mr1777836lfu.376.1656422220502; Tue, 28
 Jun 2022 06:17:00 -0700 (PDT)
MIME-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com> <20220628095833.2579903-7-elver@google.com>
In-Reply-To: <20220628095833.2579903-7-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jun 2022 15:16:49 +0200
Message-ID: <CACT4Y+bkQNci3gOyvBAkcfJjqE9h2kPJ2nKjrD7XjQ+sg1L4kg@mail.gmail.com>
Subject: Re: [PATCH v2 06/13] perf/hw_breakpoint: Make hw_breakpoint_weight() inlinable
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Frederic Weisbecker <frederic@kernel.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=AT2t+rTr;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::12f
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

On Tue, 28 Jun 2022 at 11:59, Marco Elver <elver@google.com> wrote:
>
> Due to being a __weak function, hw_breakpoint_weight() will cause the
> compiler to always emit a call to it. This generates unnecessarily bad
> code (register spills etc.) for no good reason; in fact it appears in
> profiles of `perf bench -r 100 breakpoint thread -b 4 -p 128 -t 512`:
>
>     ...
>     0.70%  [kernel]       [k] hw_breakpoint_weight
>     ...
>
> While a small percentage, no architecture defines its own
> hw_breakpoint_weight() nor are there users outside hw_breakpoint.c,
> which makes the fact it is currently __weak a poor choice.
>
> Change hw_breakpoint_weight()'s definition to follow a similar protocol
> to hw_breakpoint_slots(), such that if <asm/hw_breakpoint.h> defines
> hw_breakpoint_weight(), we'll use it instead.
>
> The result is that it is inlined and no longer shows up in profiles.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  include/linux/hw_breakpoint.h | 1 -
>  kernel/events/hw_breakpoint.c | 4 +++-
>  2 files changed, 3 insertions(+), 2 deletions(-)
>
> diff --git a/include/linux/hw_breakpoint.h b/include/linux/hw_breakpoint.h
> index 78dd7035d1e5..9fa3547acd87 100644
> --- a/include/linux/hw_breakpoint.h
> +++ b/include/linux/hw_breakpoint.h
> @@ -79,7 +79,6 @@ extern int dbg_reserve_bp_slot(struct perf_event *bp);
>  extern int dbg_release_bp_slot(struct perf_event *bp);
>  extern int reserve_bp_slot(struct perf_event *bp);
>  extern void release_bp_slot(struct perf_event *bp);
> -int hw_breakpoint_weight(struct perf_event *bp);
>  int arch_reserve_bp_slot(struct perf_event *bp);
>  void arch_release_bp_slot(struct perf_event *bp);
>  void arch_unregister_hw_breakpoint(struct perf_event *bp);
> diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
> index a089302ddf59..a124786e3ade 100644
> --- a/kernel/events/hw_breakpoint.c
> +++ b/kernel/events/hw_breakpoint.c
> @@ -124,10 +124,12 @@ static __init int init_breakpoint_slots(void)
>  }
>  #endif
>
> -__weak int hw_breakpoint_weight(struct perf_event *bp)
> +#ifndef hw_breakpoint_weight
> +static inline int hw_breakpoint_weight(struct perf_event *bp)
>  {
>         return 1;
>  }
> +#endif
>
>  static inline enum bp_type_idx find_slot_idx(u64 bp_type)
>  {
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbkQNci3gOyvBAkcfJjqE9h2kPJ2nKjrD7XjQ%2Bsg1L4kg%40mail.gmail.com.
