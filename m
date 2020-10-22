Return-Path: <kasan-dev+bncBCMIZB7QWENRB7N5Y36AKGQE4PC3LZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id B3498296160
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 17:02:22 +0200 (CEST)
Received: by mail-io1-xd39.google.com with SMTP id e21sf1475149iod.5
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 08:02:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603378941; cv=pass;
        d=google.com; s=arc-20160816;
        b=FOVVCRA0RXPcqemV+gYT0qkCa7nVKXEwnJBa5BJWKJTeH1h4FcA+2juk5y0PyKb/wj
         F9B4PTvMjubfS4Z7gvk69DDe91jovFjNQOKm1mKkf//MtGEBsSldtvHneSYxDYQ3o0++
         l+XVbzSCUdX0fVPfu/l5AzJTpWcEZTVnRybUzcqsf7UfDEelovO9ZBAa6rR24hQcDE/H
         52kXgqC03P3KB97VCH6wGxyxhJVadzss8GuhMFlVX1ZhPoMqKSelzZt/pnuiGWlgErDb
         veouOt2nsLH4cms37nqK/j2+rWr97a+hzK9LNWYyOWcsXeT/ZSCl1x8RyG5eVpFG29e5
         ZtTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1E2l2zzDOIQgRPxSaPZpsjlG3hHra3jgL/z3tUAO6CM=;
        b=m/hJexqhex7O1gu0eTsrMBezMr2NeZqC1RcI1NaTAh5hCBVLcj7FeESlHsH0xGrwPH
         4sQgk0qoVlyqORVmvrxYXt/R6KA7cB3KYK/KbZ5dp4lZf09mXk9wyy75RX7erKjFpuO4
         TFUneU7vplg81nVJZhWj3pUhfWQ9KLWTsTGdhwaicjAxKWtcCjsULalv5Sla6Bg2Negg
         fEKGQZoMt8BnRNqregemfVGtzYML7jafhR6innRIeJtIRx5j2sXvFWE2l7c1ZQRrrnOc
         YpYMG+6bRFjgP2P2tjDDnx5WTG7EzEfWvzlVIotn0LQCAH13n9gLhY+pIZ9jeKSbPr5T
         DAQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JzgkLntJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1E2l2zzDOIQgRPxSaPZpsjlG3hHra3jgL/z3tUAO6CM=;
        b=Gv08IR7tkWokh+S7WOB41GNBGlanfIbwzWoPSY14f4Wcblkskpk70PXIwUXf5eFOBM
         8kZMU68pl2eLxPD0ftJfGHoGk6m+9eC5BwjmbQJH/VdBfk5DkCx8aQ1eOLE3peEu/Xu4
         xfDvSEwKATqh70P8zI7w0kpWdTRdX1m7wTitIKses6T6z/Jw+8t9zvQ63JjnK+6TJwEh
         CSf9z/px0463a6QxFO90ESEEVie5FfOrbqFlsvXTbQ4/y1L4mlIqFyEdR33IlpoOtfKs
         CvsKxlLvM7rDDKH2hWI+ps4epsSgJah8HbjL6qqxyufKzC3IjD3Kg0enp9oA1+A/Ng2M
         8BBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1E2l2zzDOIQgRPxSaPZpsjlG3hHra3jgL/z3tUAO6CM=;
        b=cvfW2pzfZYZXBl4o+FL9jLRgPnnwzvZvtl5QZCZwtDwtH88h3VmzbKKaRbgQawt0Py
         nTJI5KE58GliE0biMeh9g/4t6Twx/TORZ5lhU7q9uhsnMeLEqCFbv9pR/3c8lmIsZhk2
         ACKcuhGXEvhy6J5V1nU4PoPflE4d6qVVhzsACCDhsworvxTgYB1GKELPlIIGfCvWn4si
         xgFbqZoB0abo+BudEOt1dbfLtVCRg9bYTo8+idx2v8U8XzcDtlys/r3oBDt6YlThOvjI
         +hT8qKf532cP4fRoDr+KHyYgoceAtJ7Q4L0YBFekR6dZLNGypuwfalbk3rTSu1COhvwV
         zR5w==
X-Gm-Message-State: AOAM533Gu8RZP/cA9k/fYjTQecTvQw9zGZTRovP0c4NVciBKYsecCwBc
	SMtT+HVLWDVIPB/xOjyx7V4=
X-Google-Smtp-Source: ABdhPJx28VBOOeKGt0Lq2+2x5AFEfOdYvp+R4LbDkbdZruCNcPkkcanAW5Wx/9yuybMyY0DoePkoRg==
X-Received: by 2002:a92:41cf:: with SMTP id o198mr2162298ila.262.1603378941267;
        Thu, 22 Oct 2020 08:02:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7e41:: with SMTP id k1ls262073ioq.8.gmail; Thu, 22 Oct
 2020 08:02:21 -0700 (PDT)
X-Received: by 2002:a5e:d719:: with SMTP id v25mr2217736iom.32.1603378940962;
        Thu, 22 Oct 2020 08:02:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603378940; cv=none;
        d=google.com; s=arc-20160816;
        b=qDFyUjfRgi+hikcKt4kUP0yPQpmPzhTnKdOxshJBIyuZLQjmhsOKPyXuRR89uv7WWm
         iiQUhLER9JYoAbV6tyRS2dJ5e+KVKJ1fZjrGqhSxlwEPiG5phNuGl/fezh7R7Y4MmL5e
         mpKmVy4Qy6z+w2p/MlczFdOyNH6gR/98feifjIWR6pEGg9R2vw4jSEyG0Ny0xbLSSKgZ
         N2QDphriXJ1wpvHVLMnM4CrIiuFWQJXoC1AnpAPj3QbLc3M6qPyfIbAMCEoJvn/6gxG3
         oQYYyZqL00O7KYunNMYqW8HM8UPhqgzXR82T0jZ48gUI46gUbh7fc7IVG0g/Ho/uZnvc
         4+mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8+m1UPja2DtoudA/ILdxkbDDyCOqxZ6QYeC54vUwf94=;
        b=TvqNdwTWjcg87OnXyrSf4y/lujg0Xc2NrhcHM2zgOuCqUnuVmOxP9THwE5nAr/4V/D
         diFPcKM+4Auzy+uDa3WiYdDYbvCFhew2MtV8aml22EHRC7DdumwdyG+hIZ2wZ7KyA6Y8
         Jy9jPUMd4ZJzFbtwDaYPuGQX+Cwxz7Ht2KBAp0cm1TA+4xLvbAVwYOPshDCjU/ta0Ddy
         JGa5lN1I8aREfHjVk2Dj/WL62jzJnzXsXDU+/1dXSfaiREDqoL0FdOJh3smyXyDn8Ci0
         fhEMSJMJQt3PQehA8AGL9dAEZUBnWIuP9ozp16+HJTCLlTvxW7L/1Qil5J+uJWgTStuB
         qldg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JzgkLntJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id k6si74230iow.4.2020.10.22.08.02.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 08:02:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id r7so1737759qkf.3
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 08:02:20 -0700 (PDT)
X-Received: by 2002:a37:9301:: with SMTP id v1mr2908065qkd.350.1603378940363;
 Thu, 22 Oct 2020 08:02:20 -0700 (PDT)
MIME-Version: 1.0
References: <20201022114553.2440135-1-elver@google.com> <20201022114553.2440135-2-elver@google.com>
In-Reply-To: <20201022114553.2440135-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 22 Oct 2020 17:02:09 +0200
Message-ID: <CACT4Y+aY=Z4D+FzMUL2f0gda-PP1t5-HNXBcc22KW7OTYuZh4w@mail.gmail.com>
Subject: Re: [PATCH v2 2/2] kcsan: Never set up watchpoints on NULL pointers
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JzgkLntJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
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

On Thu, Oct 22, 2020 at 1:45 PM Marco Elver <elver@google.com> wrote:
>
> Avoid setting up watchpoints on NULL pointers, as otherwise we would
> crash inside the KCSAN runtime (when checking for value changes) instead
> of the instrumented code.
>
> Because that may be confusing, skip any address less than PAGE_SIZE.
>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/kcsan/encoding.h | 6 +++++-
>  1 file changed, 5 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
> index f03562aaf2eb..64b3c0f2a685 100644
> --- a/kernel/kcsan/encoding.h
> +++ b/kernel/kcsan/encoding.h
> @@ -48,7 +48,11 @@
>
>  static inline bool check_encodable(unsigned long addr, size_t size)
>  {
> -       return size <= MAX_ENCODABLE_SIZE;
> +       /*
> +        * While we can encode addrs<PAGE_SIZE, avoid crashing with a NULL
> +        * pointer deref inside KCSAN.
> +        */
> +       return addr >= PAGE_SIZE && size <= MAX_ENCODABLE_SIZE;
>  }
>
>  static inline long
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaY%3DZ4D%2BFzMUL2f0gda-PP1t5-HNXBcc22KW7OTYuZh4w%40mail.gmail.com.
