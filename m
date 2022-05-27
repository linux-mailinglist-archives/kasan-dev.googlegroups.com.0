Return-Path: <kasan-dev+bncBCMIZB7QWENRBG6VYOKAMGQEDA2GUXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id AB71D536484
	for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 17:13:32 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id z14-20020a056512308e00b004786d7fde66sf2077509lfd.18
        for <lists+kasan-dev@lfdr.de>; Fri, 27 May 2022 08:13:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653664412; cv=pass;
        d=google.com; s=arc-20160816;
        b=hPHc8LnZC6oAbI8CL1W/ysAfY2gG5VEVot1wq47xIB4CwgMmp7bE6QUGZt4oVVawgG
         RIaUKy9UmkfVwk5f9e4jMpC8+qX9CXfA6IoxYGoBNxnfGxnL8Hv9Dw1qVf+YU75mkkua
         x16SGBZfYRvofVHOMqlH0H4b8Q8fyGx7aO4DYGIlPpRCwkUmVhKOd2LryM6t1MgnEQ+O
         iwj/6rZapwbxSSVGs5BBYcjx6r7fI7edq9w7ZaDRGOl6suIRu/oYzXBp/PWpC0bxY1zK
         b35lMpPP+NimuxFQwKMMQmOZfFR+21XHghq/wOes5XpsohlWcR+rWU96eKM/rnj6qNfX
         4OCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=w4zEmZiyXwviZHiyP5Td0gzan6lcvvUt2tiVd8lo0I4=;
        b=Ysve+tFrYe6dHk4Br7Jbsmj9QzoGZF/Dwia3swNkQ6WZwF4US1JAeL+oUtxgPMUxq5
         paYfNXV5KEno6kgBSc0Z8AV35WlLUA/aqK6cSyBayjhdgR9lec9QCEOAhPEEt036EYYr
         fPq3tD4q1rx58q1OLdjN3pUCHjVl4C5ab9Le6VaIp8Kwxsr4ng6wl6Kit1zJG2VmDmp/
         V20z+IFgJh/2YOOmbjH8yRBQnJlGU9lvxEBxQi8A/+6xPyMYbfVR9hFuHkfw5nfP469j
         6J9vbBXfGEcyJycLAHFoI3VDh3C0maiEBRt9AKa+jXGfpBWRfbBlTibySgpISeUSSGGW
         wBAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P5AegZqc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w4zEmZiyXwviZHiyP5Td0gzan6lcvvUt2tiVd8lo0I4=;
        b=tUXB+phMPt51K9GtS3Z2SKogaf6lcfwEzk7c9VGj5Bh1VPB3T+JfgPJxR0w8vUrdGa
         jtK27oDZP18m8JLKQFmtfUiT7U8OV44a+vppTZiBPATpyscIFgSi3oHQc+RDnrv0gk3q
         QnCKgegn4j4GYCJYznd0WLpSzxyf+OeLdaAZH28CqsxoEj/G0KKbgW8g/J0zr8khlqfc
         7D7zV4xNU9kgGFiZmfGu/ssQ87NUGP5jerx5YWS1sbgq2CXxm8cbBKCo2DDw+eAfru3O
         umIcqwgrd5O4h+IVJwHAkwzuz4FJgqjGrTwbV2yDn0Fyn0Nbhr5EVhoIvrMW0ANK8P/G
         jmVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w4zEmZiyXwviZHiyP5Td0gzan6lcvvUt2tiVd8lo0I4=;
        b=y67x7/izHnI6746GGLmI5jziEc59vADAhbRFIaSWkNDAX/Tzpbx3rEAgiqIWxhy4//
         r1II482jffgMNfonet9PQ7qwcH/XvuPewpfz75y+6+9NixxLxVyc7NnSdYYC+95w6L/F
         At/Pa2J15jW1PdI9PMRHMwVP4/OiVtDMSUdI4c9On++gZ/rs8ptzvAs0nymhS2uWQwFF
         LuM1w35jOtchMKZF2jHJ0KQbNu3DHvcAro5QNtmBUQ/j1L5gmSj1Uhjnks78I0vU1Ddx
         wKtDgJn1/x1VQYtgzApcAlVPyPkx4Zcb7GzuWfHyO1RQL4Co7uMUG0WhwW9NoYt5DwKP
         n9Bw==
X-Gm-Message-State: AOAM533o7HtkUjIvjHYYLK+LNu4X3QK/lh1mi53xY9hlXdlzXuP5Yg6d
	DFV0P7ogWBshFUPFYjsrP0U=
X-Google-Smtp-Source: ABdhPJzjkAdejGPeb8NjMgmRfHH5ZFsMwWgJA0irJ0DRQNd0rreJDPXgkXMiFDEhysJW49Kk/SvplA==
X-Received: by 2002:a05:6512:239f:b0:478:5c6c:ee0a with SMTP id c31-20020a056512239f00b004785c6cee0amr24434232lfv.664.1653664412024;
        Fri, 27 May 2022 08:13:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10cb:b0:478:7256:822a with SMTP id
 k11-20020a05651210cb00b004787256822als1450873lfg.3.gmail; Fri, 27 May 2022
 08:13:30 -0700 (PDT)
X-Received: by 2002:ac2:592a:0:b0:477:b81b:4d13 with SMTP id v10-20020ac2592a000000b00477b81b4d13mr30717466lfi.140.1653664410866;
        Fri, 27 May 2022 08:13:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653664410; cv=none;
        d=google.com; s=arc-20160816;
        b=JTH7/UN/quv4nOgPBbuuXJwxB41F56+TI1zAXDmk062R7cj4ZUvIPnsNIwoVOyVuIa
         mRn6ls93vjt+DFd3Z89ehaEcqTcekd2X6JP1dHfOFyu+ebV8hWns/PmH0KlYFi0ps0ki
         vXNKKrtr7v4+lAUrIAkxusap0vEN4tZjulDyiPkWqAvmgXKEBZ1LL7gUNGvxZ9jz5L7G
         img+9SWplMakz0RfFI4MTVcLnHdfjRHmMBLnxnkA/pb0MmZZONFDMRNSkC9P8+wbpdIJ
         toqxkuZxl+/BUBosgbe4xrC4Vv9Qc6GPt01+GhSsTKmP1dpVlw0wCfIsAymX6fH/S5b2
         EonA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=41SpoIfs7EY5Trq+an/hvTpst/Rhz6EiRSblcCMf3MM=;
        b=AXplhTGtKWdSDlKrg6jeQvP2fxIcWhzBZTTzqKh0Uj49AfXHK/IfJNH6YvpO+Ca9Ty
         Jnli1+KbFV03sxlI2mGerauV521eFgPQMXbhOxUklg5VNOPqrMikGvubkPzNhMYgYD7w
         ypAn/WBJffKGxijtw/MwfpMUdFox0ISeV/nd8P0v9UgL6ikC551mExPaOTHFdgRrT+J2
         ET3H9CzHJZCnK0w76IWuzF2L0YfEF3AY122RZNQG9B1sT8im4CGtNWcKdFN3nHx08jXJ
         ///4dc9DT9xt2UJL+K7cJHnHZf4wirOh+miiuspbzatyQxnHNasUW7xuDhaJujlJvAKs
         fiIQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=P5AegZqc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x235.google.com (mail-lj1-x235.google.com. [2a00:1450:4864:20::235])
        by gmr-mx.google.com with ESMTPS id k23-20020a05651c10b700b0024f0dcb32f8si245412ljn.5.2022.05.27.08.13.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 May 2022 08:13:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235 as permitted sender) client-ip=2a00:1450:4864:20::235;
Received: by mail-lj1-x235.google.com with SMTP id r3so5264909ljd.7
        for <kasan-dev@googlegroups.com>; Fri, 27 May 2022 08:13:30 -0700 (PDT)
X-Received: by 2002:a05:651c:a04:b0:253:f0b4:a406 with SMTP id
 k4-20020a05651c0a0400b00253f0b4a406mr12950332ljq.4.1653664410294; Fri, 27 May
 2022 08:13:30 -0700 (PDT)
MIME-Version: 1.0
References: <20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf@changeid>
In-Reply-To: <20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf@changeid>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 May 2022 17:13:18 +0200
Message-ID: <CACT4Y+bm++gFi8QYNk41g_ihZuvrMO5O2T_3E7r0h+_PRfShuQ@mail.gmail.com>
Subject: Re: [PATCH] rcu: tiny: record kvfree_call_rcu() call stack for KASAN
To: Johannes Berg <johannes@sipsolutions.net>
Cc: rcu@vger.kernel.org, kasan-dev@googlegroups.com, 
	Johannes Berg <johannes.berg@intel.com>, "Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=P5AegZqc;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::235
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

On Fri, 27 May 2022 at 17:07, Johannes Berg <johannes@sipsolutions.net> wrote:
>
> From: Johannes Berg <johannes.berg@intel.com>
>
> When running KASAN with Tiny RCU (e.g. under ARCH=um, where
> a working KASAN patch is now available), we don't get any
> information on the original kfree_rcu() (or similar) caller
> when a problem is reported, as Tiny RCU doesn't record this.
>
> Add the recording, which required pulling kvfree_call_rcu()
> out of line for the KASAN case since the recording function
> (kasan_record_aux_stack_noalloc) is neither exported, nor
> can we include kasan.h into rcutiny.h.
>
> without KASAN, the patch has no size impact (ARCH=um kernel):
>     text       data         bss         dec        hex    filename
>  6151515    4423154    33148520    43723189    29b29b5    linux
>  6151515    4423154    33148520    43723189    29b29b5    linux + patch
>
> with KASAN, the impact on my build was minimal:
>     text       data         bss         dec        hex    filename
> 13915539    7388050    33282304    54585893    340ea25    linux
> 13911266    7392114    33282304    54585684    340e954    linux + patch
>    -4273      +4064         +-0        -209
>
> Signed-off-by: Johannes Berg <johannes.berg@intel.com>

From KASAN perspective:

Acked-by: Dmitry Vyukov <dvyukov@google.com>

What tree should it go into? mm? rcu? +Paul

> ---
>  include/linux/rcutiny.h | 11 ++++++++++-
>  kernel/rcu/tiny.c       | 14 ++++++++++++++
>  2 files changed, 24 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/rcutiny.h b/include/linux/rcutiny.h
> index 5fed476f977f..d84e13f2c384 100644
> --- a/include/linux/rcutiny.h
> +++ b/include/linux/rcutiny.h
> @@ -38,7 +38,7 @@ static inline void synchronize_rcu_expedited(void)
>   */
>  extern void kvfree(const void *addr);
>
> -static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> +static inline void __kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
>  {
>         if (head) {
>                 call_rcu(head, func);
> @@ -51,6 +51,15 @@ static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
>         kvfree((void *) func);
>  }
>
> +#ifdef CONFIG_KASAN_GENERIC
> +void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func);
> +#else
> +static inline void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> +{
> +       __kvfree_call_rcu(head, func);
> +}
> +#endif
> +
>  void rcu_qs(void);
>
>  static inline void rcu_softirq_qs(void)
> diff --git a/kernel/rcu/tiny.c b/kernel/rcu/tiny.c
> index 340b3f8b090d..58ff3721d975 100644
> --- a/kernel/rcu/tiny.c
> +++ b/kernel/rcu/tiny.c
> @@ -217,6 +217,20 @@ bool poll_state_synchronize_rcu(unsigned long oldstate)
>  }
>  EXPORT_SYMBOL_GPL(poll_state_synchronize_rcu);
>
> +#ifdef CONFIG_KASAN_GENERIC
> +void kvfree_call_rcu(struct rcu_head *head, rcu_callback_t func)
> +{
> +       if (head) {
> +               void *ptr = (void *) head - (unsigned long) func;
> +
> +               kasan_record_aux_stack_noalloc(ptr);
> +       }
> +
> +       __kvfree_call_rcu(head, func);
> +}
> +EXPORT_SYMBOL_GPL(kvfree_call_rcu);
> +#endif
> +
>  void __init rcu_init(void)
>  {
>         open_softirq(RCU_SOFTIRQ, rcu_process_callbacks);
> --
> 2.36.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220527170743.04c21d235467.I1f79da0f90fb9b557ec34932136c656bc64b8fbf%40changeid.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bbm%2B%2BgFi8QYNk41g_ihZuvrMO5O2T_3E7r0h%2B_PRfShuQ%40mail.gmail.com.
