Return-Path: <kasan-dev+bncBCMIZB7QWENRBY5L2SAQMGQEUHBKSLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 97368322CBB
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 15:49:08 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id k11sf1888441pjg.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Feb 2021 06:49:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614091747; cv=pass;
        d=google.com; s=arc-20160816;
        b=G4OKaJGHy/sJ2IQmfom9RT9f1m1abtUxXL4GoIEF3ruSgLJ7PodhP5ICK8/zQjDHxq
         r8gNQFWZ6O7RmiNxzOuEY7Sq8Vc5dgrwifzSfojI+q2+bqX9v++lBXyzzLC4YztiWE//
         i2bPU5DVH+6N1L2alb9hbG/dOcVuCtonLcfTJpppmqNXRnHQTNcOiMJWuHwQqW+f+ugX
         K3iRb+RI3+4dgKGOZCEDnI+Xat39Xe5wp44Piy3qdtwQa0Z7t7848sNMG+PFAPiYg+3U
         /4fNFqLU1juDo5qmvedsXswoYTtBx6Oj77Spm68GJytZgrgontyl8MfDQVHLXb/Z33zx
         DWAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=cbML/+JZUtdjOedgfVvqeM+EsleX1gNJkV9lNgk0VL0=;
        b=n21mbl+nZVK1oeDc2B+tfUjgIZE2CxZuRHAezqp9bEwj9uq0jT8hvK476BkGk1feg2
         hkqorlfgBaOzxpJ8VltjckWUoTgNa3raWRYMoCPavYfuRAMGFCdRdqRSjAcNalkdxtWc
         K2QeoU4AzVJgmOd+z10aGLyx1OzPbpfRtuGJzAEhr4NhPXBvgr2ZSLMFGya6f/JLX5dI
         t+JEELGHL0ZlNtIwC2Hpjz/Qz67JRC4g7G05rhZMG73OVzo6swP61+H93nP549NwNp/I
         sv00jshuhIkd7HLYMMF5ckrrP5O6xJ5GhCawYRSUO4rezhrK/7G+BzXerCOoBzprwCqz
         69Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NiVKZu5i;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cbML/+JZUtdjOedgfVvqeM+EsleX1gNJkV9lNgk0VL0=;
        b=j8v1HOZ+CE/HjlBysffGm1WH67AdEvt5g4tl14HT7AH77EIGQlvgNi1j1hxpMv96sv
         Edd3stW7tb0RJugy3S3uG15kGFl1sju2UBdxmi9WFOCQZB1iR1qmD/irnDBHBPavDyM7
         +PVrltwihAiVVIXQ5QBIEiN/P6NRtDxZ2hSsHGr8fVnteVJdQWvxMAnaUz++4KGAh1Jz
         GCnVbswGOE2nJdUkNU9iNFfHyjfWhzo+TQw2d5GpKFvfEttKFyE2H97k6B+lwAcN2HIy
         fqYm/JPjpDeKAhZEnQ07uitL9rtwyb+y5ObvPIIUWGyCXEHYnz7VPXvQHF2+y+829oyZ
         Vluw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cbML/+JZUtdjOedgfVvqeM+EsleX1gNJkV9lNgk0VL0=;
        b=oULOWPdos5LHDXQCtkuYE/V6XwenQozMfaa0ZmurfN3T7Qzm6C4+8I+WyW8uWfRqgG
         YOQhfZaPPViSJo+rko0uO11/sxBB/DXwnZOob3d1duPNjgTJMTEwZbDZLktwxHVrLOGo
         v3u32j5+XZ/LejonlFU+rIUWwu01Bx6G53CNIT+JbR8a4N8Yu+8fQ1JH46y3HhC3LoPj
         XG5YZTDstHC/BpTYV/MZX6bF+OHiIDO8Bm3hK3CWEYqkU5uI1c+OoL1UFAkxnsZuGbX0
         bu7B7vnocVsRFo+d3tkWiDMzF3fO4+ffOfill8uxH85Bgs0829h5iAVk7ME0nbYch+tX
         WBVA==
X-Gm-Message-State: AOAM532vk1ttT7uR3QVn9jdzKWs/DKVP6zavv5KicbCQJ2L7vgZFK3ZY
	4aKyD/ev8aIaecBkNrhmbcQ=
X-Google-Smtp-Source: ABdhPJyFayqYThZHmIC86Ojt0X/+XzKDSo2VHzwZcQITVgXsrKso/AqKkA4l6jd+WmBfdqlFLJl3LQ==
X-Received: by 2002:a17:90a:5507:: with SMTP id b7mr21424080pji.174.1614091747177;
        Tue, 23 Feb 2021 06:49:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2311:: with SMTP id d17ls10212229plh.6.gmail; Tue,
 23 Feb 2021 06:49:06 -0800 (PST)
X-Received: by 2002:a17:90b:1284:: with SMTP id fw4mr22729163pjb.157.1614091746612;
        Tue, 23 Feb 2021 06:49:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614091746; cv=none;
        d=google.com; s=arc-20160816;
        b=woYJx8V91nNgLmJKQ1JWohtPx8WEEhTpSKkyjQcRp1tmGtHLooEn2e01sRClHMrBjU
         DaadfAlrG0Xa7F/QbS/f64zsHc5xN4cHtnEZXteB1KTX6ZTOVOg4XszyUfjHAO91dcwX
         BYVKLrMvTjPuzGaMdB4lWAVynV1AeCAX4FHG5APvtQt120//o1E/8wUDN7JdIN/1P1br
         ch4HbxsxBHl+8k1mw0nbuSSPbw/JrNZzIAuqc2Hi8IbGbSFH1xWiFoVVMwx1qFpZMQiL
         dgiXLeh4X7rI0304XSVBDeePu+4g865wGSi9hdL5mQ4F5iDwF2lSEsHPk9EHXi+kVs5F
         58FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5S1278VXBXOSLVzud0ikIuJDPMbbC2qcHtU1cXjsgPk=;
        b=gD3vQ1pQvKVCoHU+nJx6PVDqwPEWFiz08PzZqMsSEFvgXM++UUev0KS+k0U/pWQu1d
         hbE8yQPRxQBdikhEKEi2m7S08IJpK8Z+Z/EZ+EBgwLYGBP/kO7MzLHPsrNnjOCEflu+h
         U53fVhk3PzrQ2JAvNgKtq/sVC/NR2itLHJJFynv80RkXCOA8pw9dTinEsm2claIE8fSn
         FSAiPc2YzIeWgdNE88VfKQE2TM9wpG/Ew698XV/RXTTjy4iaUltQtLljkLWyTkkpAwie
         YFYP01p9nj6OaWoBt02NmCj2dOk4FGfMEBxJAsZ6zk7Oe4Zt2Ht8nc2qaXkE6k8ZipH3
         7Rsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NiVKZu5i;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id i23si145341pjl.3.2021.02.23.06.49.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Feb 2021 06:49:06 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id p12so7852645qvv.5
        for <kasan-dev@googlegroups.com>; Tue, 23 Feb 2021 06:49:06 -0800 (PST)
X-Received: by 2002:a0c:e20f:: with SMTP id q15mr22742422qvl.13.1614091745827;
 Tue, 23 Feb 2021 06:49:05 -0800 (PST)
MIME-Version: 1.0
References: <20210223143426.2412737-1-elver@google.com> <20210223143426.2412737-2-elver@google.com>
In-Reply-To: <20210223143426.2412737-2-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Feb 2021 15:48:54 +0100
Message-ID: <CACT4Y+YGrj3zc+KsxQ0=N5t3dPy58FwVuy=MY95RphOD4i4FHg@mail.gmail.com>
Subject: Re: [PATCH RFC 1/4] perf/core: Apply PERF_EVENT_IOC_MODIFY_ATTRIBUTES
 to children
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, 
	Arnaldo Carvalho de Melo <acme@kernel.org>, Ingo Molnar <mingo@redhat.com>, Jiri Olsa <jolsa@redhat.com>, 
	Mark Rutland <mark.rutland@arm.com>, Namhyung Kim <namhyung@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Alexander Potapenko <glider@google.com>, 
	Al Viro <viro@zeniv.linux.org.uk>, Arnd Bergmann <arnd@arndb.de>, 
	Christian Brauner <christian@brauner.io>, Jann Horn <jannh@google.com>, Jens Axboe <axboe@kernel.dk>, 
	Matt Morehouse <mascasa@google.com>, Peter Collingbourne <pcc@google.com>, Ian Rogers <irogers@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-arch <linux-arch@vger.kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-m68k@lists.linux-m68k.org, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NiVKZu5i;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f35
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

On Tue, Feb 23, 2021 at 3:34 PM Marco Elver <elver@google.com> wrote:
>
> As with other ioctls (such as PERF_EVENT_IOC_{ENABLE,DISABLE}), fix up
> handling of PERF_EVENT_IOC_MODIFY_ATTRIBUTES to also apply to children.
>
> Link: https://lkml.kernel.org/r/YBqVaY8aTMYtoUnX@hirez.programming.kicks-ass.net
> Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>


> ---
>  kernel/events/core.c | 22 +++++++++++++++++++++-
>  1 file changed, 21 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/events/core.c b/kernel/events/core.c
> index 129dee540a8b..37a8297be164 100644
> --- a/kernel/events/core.c
> +++ b/kernel/events/core.c
> @@ -3179,16 +3179,36 @@ static int perf_event_modify_breakpoint(struct perf_event *bp,
>  static int perf_event_modify_attr(struct perf_event *event,
>                                   struct perf_event_attr *attr)
>  {
> +       int (*func)(struct perf_event *, struct perf_event_attr *);
> +       struct perf_event *child;
> +       int err;
> +
>         if (event->attr.type != attr->type)
>                 return -EINVAL;
>
>         switch (event->attr.type) {
>         case PERF_TYPE_BREAKPOINT:
> -               return perf_event_modify_breakpoint(event, attr);
> +               func = perf_event_modify_breakpoint;
> +               break;
>         default:
>                 /* Place holder for future additions. */
>                 return -EOPNOTSUPP;
>         }
> +
> +       WARN_ON_ONCE(event->ctx->parent_ctx);
> +
> +       mutex_lock(&event->child_mutex);
> +       err = func(event, attr);
> +       if (err)
> +               goto out;
> +       list_for_each_entry(child, &event->child_list, child_list) {
> +               err = func(child, attr);
> +               if (err)
> +                       goto out;
> +       }
> +out:
> +       mutex_unlock(&event->child_mutex);
> +       return err;
>  }
>
>  static void ctx_sched_out(struct perf_event_context *ctx,
> --
> 2.30.0.617.g56c4b15f3c-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYGrj3zc%2BKsxQ0%3DN5t3dPy58FwVuy%3DMY95RphOD4i4FHg%40mail.gmail.com.
