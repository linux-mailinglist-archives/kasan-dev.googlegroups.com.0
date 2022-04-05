Return-Path: <kasan-dev+bncBDW2JDUY5AORB2WEWGJAMGQEKNC5XTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 19A914F3C61
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Apr 2022 17:38:20 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id o81-20020a257354000000b0063d95dd2c83sf7367274ybc.11
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Apr 2022 08:38:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649173099; cv=pass;
        d=google.com; s=arc-20160816;
        b=haMtvQnCKb0+rfsU1SurPCsP0ji57r8NYIuXl6f01vuqyqVMXrdAcS10jI+h2mwIFP
         sq6qYFMM+r6TbIYFBlP6hqcW+wWndSFI5IttBHGg9kfGX0HLuzIOtJTw1+rbIZ27xQWd
         Q3knMNwT8USWs6nLKQJ6fyPjmfk5+IBdTpqmKyNBtwtWyeZ6wFLaOEwGafozZsUdKSJk
         ml4iVXVDUrObvPXof8sUp3oUBYwk8OZjldW635osP91N/9ueqg6Rmv+R56ybxxiSZeLY
         5YcxaauCOsRuBoYF+i/dYiCRnDRULyOHhtJ+Asx8XC6kzC9K6IZTUReReX+rSlclYfez
         kjGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=bvCRB2YoprvNdTawbrv5ZnS8fWj88JL4Jt32PNJOtVQ=;
        b=BBu8rUVdWRryrYq6a/dgDfjwepT/eNQ0fAlRDCBYOQNWZLQfgwFW7TlXPRFyltB9gd
         CDzbHLENZ/MrMddSntUBx7pXJvd47iyhRgSQX08fiOWSBRkIkuy+rzmUtUuCztsiBTPy
         cj9Rq8NoS62u9THOUaD54dVLvZCsjGtm9WiA8Zqs9Gy5wXwbSBHrEIr+9vRSEgy5UHOK
         Sg67G3cBCJrVnaJ8/LC+HOTvEXNNOi2fHR/Gsbhbmtz7ftMR+JLrCois7jRlGgPoVndi
         IxTqKFAk3904472FxJT06ma/vcSsdsTAPPpXN1NS68CyO9MleZChRJel/hu16zRhKcwg
         bOxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ihYjRwCI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bvCRB2YoprvNdTawbrv5ZnS8fWj88JL4Jt32PNJOtVQ=;
        b=rK9hLcxfU4gJN0RFDnklui2rd5xgg/IdA3dyBR0zc/7OSdRYjdVNfdI2fk0lpxlRgR
         Tbqkw7mi9tiPm+92Xi22IhMB4IC5VYtSy12TNulj2o5lZdmiNeo+In0zNS8aR8fcij8S
         NYsqrCWPXxUjFI92D8E48WG8ekYaHU1iFYNjAhf8TGiy0UdTij0jJkxC2tEatR6qnFg3
         Ui/BfyP+iEfmVvHYJ3v0dh2Y78u/D/ok+1yy07mlMKLsi2rNoN2V/69xv8zZ1pr6Drpr
         X7E5VhEK4wpQsRvZmmztV2jlZdlqgkYFuf9QqEmGGulB6mjH/L9rBuKYoZdmsOJIX/3R
         PagQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bvCRB2YoprvNdTawbrv5ZnS8fWj88JL4Jt32PNJOtVQ=;
        b=ik+GhhpRvBmzWif6xeHD5bgEGKM/NdHo1fjswggdITxrSNvN/NzHildg0z7QqD+r0R
         JbPEv0Cpx1lyDwcSic5mE9eefU0FTDrgniWoLXIC+DcYlNnU13nWAQat5+ytsqHsE6P1
         APmEV3tQ5NNZCAT5lEawZg7KU70Wl8V2IMAVwa8/qB4d75NMpHoDEoRIqlE8r8G/8XhQ
         qm0xJcvtiqdsgV42dzs6UPg2ZX5JWwskRQyUFWrje1MZ+JWVVcR2ibseiDJe8mCX1JXh
         OEDSAVf3jQaMXKJJ8Q2iJ/zjipto3HVE+uH73I0B5go63bvmvFFvSQ7fREWefZ1aTvjT
         +wqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bvCRB2YoprvNdTawbrv5ZnS8fWj88JL4Jt32PNJOtVQ=;
        b=lQJscy/l2JrE/eLqhyAzeJ1yC/KJ9WvLTJ6J5PiEVqaI+bvb4+/1awyLKqekaIUZf4
         4E9PG68GooJTxoaKV9LkFWIzQY69kNcuk3/6aGR/kettOv1NNbZe6BgC0sdPIewg1OTY
         4Ti8oAS3yigbHa0MZf+TMJCn2nTyilaoBk12Yf1qBOwsTVnYL4VWzwfa9f//x75mh+7s
         ZVsY97sf+6iMMRBKKHvrGFRSKKr/pzDFtnkdC2X+r8xzKltQ1xCX1m1LhknJbHYCnSPw
         TESthMVe/pRVkIAel/jXs1vjiIM5qQKh0SPYAJ+Cd1Hk2CBOzxyIs3/xNUuKQ2Fsvx1+
         Qjpw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533LEgtXqgnmdeVDeAGw6UC3tUBKTSXUgwmIiRv5bXj05agErw3j
	9KCg7An60r3pW+wp3viQwJw=
X-Google-Smtp-Source: ABdhPJypkvONXO8EXvkZmyR1o5SHiyD4g4ZjvQg2VP61eWmZiVT7CzeWNqsVDP6GIseNtq/jmycQBg==
X-Received: by 2002:a05:6902:1143:b0:63b:17a0:d9d0 with SMTP id p3-20020a056902114300b0063b17a0d9d0mr3245000ybu.490.1649173098939;
        Tue, 05 Apr 2022 08:38:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2c02:0:b0:638:425:2eec with SMTP id s2-20020a252c02000000b0063804252eecls9170332ybs.2.gmail;
 Tue, 05 Apr 2022 08:38:18 -0700 (PDT)
X-Received: by 2002:a25:7310:0:b0:633:b888:5639 with SMTP id o16-20020a257310000000b00633b8885639mr3106283ybc.351.1649173098509;
        Tue, 05 Apr 2022 08:38:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649173098; cv=none;
        d=google.com; s=arc-20160816;
        b=PoRAB1a5YZQX7PUbEBE8ESAyKg2cH/jnIc0xctEv/17hfB4pKYdWxK1DX1Y2BxrQAR
         OR+k46UBB/FuNF+KjoQI6fjQLD8kpxdom32vfKneQljMtxqbKpyvjxEn8LJDRp/jTmyR
         NtYQdn2Ze+OMT4N8N/YB2g+DptAsly+zg7u04H86uHyMXU66Zy4/mTExU8FAFfAmQHRU
         DQ0PIeLoID+NHpg8UUQkCw16ZvyM/d3tPNje4NQJP53PTA95+mqEwkRYgZ54jUqHS1ds
         YD58FTj1xVzA+/eLrQTlUyoPr64IsePwNXnzOOO+La35Oek+779ipabwpH+AR9tAviyJ
         SW8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Oiy4ymydbM7WhtHftpHVioZDVdSgqELYIqmQkx6duOw=;
        b=N0iIAcvKX93j/izRV8m7bfseRPF06dMVUKH7jgB/ojR2RYzO5NlPJwIPM4TNuObG8j
         jsAoF632eDY5c9pOYELz7osLBRkyffL2f8aU+LupfxBZmCASyDEWtqRy0NYJRm15hZXN
         WeESETl6lt/nKgqJjn0OEmMKQpBoqcizauID+YREc49ciHWJcX8ffKY0sU33QnvSXLPp
         IMtNQbCXzEayVDFJp5ao8LWIFudys+2SpvN5LGgeQNrMjt3uAHvHpEuwcC3UmeA6JsLK
         jxvx4cnx5iVSmYAofr7YAvh2hdpxp/ACDIzbxdIWiXbFbw0BV63u861GZiALO7bPGbDN
         3n/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ihYjRwCI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id 207-20020a8109d8000000b002e616ec56b1si676094ywj.3.2022.04.05.08.38.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Apr 2022 08:38:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id b16so15638333ioz.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Apr 2022 08:38:18 -0700 (PDT)
X-Received: by 2002:a6b:116:0:b0:648:bd29:2f44 with SMTP id
 22-20020a6b0116000000b00648bd292f44mr2028950iob.56.1649173098285; Tue, 05 Apr
 2022 08:38:18 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <0bb72ea8fa88ef9ae3508c23d993952a0ae6f0f9.1648049113.git.andreyknvl@google.com>
 <YkV1ORaR97g45Fag@FVFF77S0Q05N>
In-Reply-To: <YkV1ORaR97g45Fag@FVFF77S0Q05N>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 5 Apr 2022 17:38:07 +0200
Message-ID: <CA+fCnZc0--X_bQDEr+3kgimFL3zGm-kBL-5Tx6KLYybUd3zEzA@mail.gmail.com>
Subject: Re: [PATCH v2 3/4] arm64: implement stack_trace_save_shadow
To: Mark Rutland <mark.rutland@arm.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ihYjRwCI;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Mar 31, 2022 at 11:32 AM Mark Rutland <mark.rutland@arm.com> wrote:
>
> This doesn't do any of the trampoline repatinting (e.g. for kretprobes or
> ftrace graph caller) that the regular unwinder does, so if either of those are
> in use this is going to produce bogus results.

Responded on the cover letter wrt this.

> > +noinline notrace int arch_stack_walk_shadow(unsigned long *store,
> > +                                         unsigned int size,
> > +                                         unsigned int skipnr)
> > +{
> > +     unsigned long *scs_top, *scs_base, *scs_next;
> > +     unsigned int len = 0, part;
> > +
> > +     preempt_disable();
>
> This doesn't look necessary; it's certinaly not needed for the regular unwinder.
>
> Critically, in the common case of unwinding just the task stack, we don't need
> to look at any of the per-cpu stacks, and so there's no need to disable
> preemption. See the stack nesting logic in the regular unwinder.

The common unwinder doesn't access per-cpu variables, so
preempt_disable() is not required.

Although, in this case, the per-cpu variable is read-only, so
preempt_disable() is probably also not required. Unless LOCKDEP or
some other tools complain about this.

> If we *do* need to unwind per-cpu stacks, we figure that out and verify our
> countext *at* the transition point.

I'm not sure I understand this statement. You mean we need to keep the
currently relevant SCS stack base and update it in interrupt handlers?
This will require modifying the entry code.

> > +
> > +     /* Get the SCS pointer. */
> > +     asm volatile("mov %0, x18" : "=&r" (scs_top));
>
> Does the compiler guarantee where this happens relative to any prologue
> manipulation of x18?
>
> This seems like something we should be using a compilar intrinsic for, or have
> a wrapper that passes this in if necessary.

This is a good point, I'll investigate this.

> > +
> > +     /* The top SCS slot is empty. */
> > +     scs_top -= 1;
> > +
> > +     /* Handle SDEI and hardirq frames. */
> > +     for (part = 0; part < ARRAY_SIZE(scs_parts); part++) {
> > +             scs_next = *this_cpu_ptr(scs_parts[part].saved);
> > +             if (scs_next) {
> > +                     scs_base = *this_cpu_ptr(scs_parts[part].base);
> > +                     if (walk_shadow_stack_part(scs_top, scs_base, store,
> > +                                                size, &skipnr, &len))
> > +                             goto out;
> > +                     scs_top = scs_next;
> > +             }
> > +     }
>
> We have a number of portential stack nesting orders (and may need to introduce
> more stacks in future), so I think we need to be more careful with this. The
> regular unwinder handles that dynamically.

I'll rewrite this part based on the other comments, so let's discuss it then.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZc0--X_bQDEr%2B3kgimFL3zGm-kBL-5Tx6KLYybUd3zEzA%40mail.gmail.com.
