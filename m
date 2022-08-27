Return-Path: <kasan-dev+bncBCT4XGV33UIBBS5NU2MAMGQEDUMKD5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id E542A5A343B
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Aug 2022 06:00:11 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id q5-20020a2e84c5000000b0025ec9ff93c8sf1208637ljh.15
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 21:00:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661572811; cv=pass;
        d=google.com; s=arc-20160816;
        b=Og5LMIquh28YIe+/8FDCOZEsVZV0DuQLA18FmFJEFJ3vDhmQvmLlm72Uh20LO+4oo/
         CCwHJqNiACtjQVR9LfjrOcLk1EGA0aaoqjtC490tikDd31dqC6vj26Sd8Zg8rCKDHFCp
         2fbsQ8QvL79VRxqS30GDI2FBqq9hySqx/kNrA6StQjf3atjdw9HgmQ67ijH3Xw0Y3obk
         BzHaGTAyU47GeunMngAO46tab5EmO+2OgFJ6TqCwSx0N2UWhW4ydMmBWh492qHHpS/OH
         BCy9fPaKGdNkqBALjhXbTWH/Fy0s3HrrfwxvRqLjhw8URhjlVnrOarLzLeh/Siz16h4U
         kIpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=fRD4f85gO808/1rt0UlMyu/Pc9MtXJgq84U7kIQ7Hf8=;
        b=hxx6p3CamO+qSbpqKw3loNZcR0oWVxmozArQXZaqbnYF5ApcRwOipa7V2Xs0959kSy
         R1gkTl5P/EQHccjYYr6PokCecJs2IgzizT3gJvneXmN6TL3FaeAS4PCOMWjxpg7P0iPP
         kCkYRe4+Alo/USKsI8+fsAg9MoihE5piw5XNJkRSx4ldMb9IygRLSrnuOpExdl82yhYq
         7GRNziyqCVgbmGCXXDOpMyqnenRPzZ08pSGG+nZROGDcYyG91TmNB9KKkcZ1l/MOvItW
         1oQCYQzjfgJsYqCKIIxrGGqUhs8PFd5zqXnFLshDCXUBX8vtDBtptZeOhvlubze/UibZ
         bj0Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=WH42edJ2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc;
        bh=fRD4f85gO808/1rt0UlMyu/Pc9MtXJgq84U7kIQ7Hf8=;
        b=gWIQl1nD5csgBOS9Lj+BJ/+2G93oeXqSoNjvBk5l+atH104jCe4nMEu0+Md7qCRARV
         BPJJFZdjd6ZYf1J7+VGvjBzCL2LY6Ar+9SrIK94OZLpcRLwGchZFkbnMV0cR6sZtlHjd
         RRXWg+SARFuop0MMqTJnfAUeBvmahO9myyGlsbwPsztALe0xDSYh5W2iMPyW5j21ufBA
         OKu8IPSEofZDSC7uC3qQSVdvW4+vNVj5YxEKDQlys6I1XRpDbUNxerzfzt/p+Fw4dDD2
         a6xcrzcgfgdCBz0xtyG5bNapSlm9NqZJ0mFZJ2K82oGp1gH2cX3yqAXb4wWPLQTr6Nwm
         nxHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc;
        bh=fRD4f85gO808/1rt0UlMyu/Pc9MtXJgq84U7kIQ7Hf8=;
        b=gSmbUZKmiB0d+dcSH2O2AJ2V9ltTn5qO0MbhjKQZM/EECKaqnCizau30ugdiOWl626
         nsVTIjZQKiLf6vMOea59g97d15bVmSS9GynV7+46TeUe6gXZY2fO6eaVGWktqHUGuDTf
         mojaCcA2jC8Pqt9gzOg0jaG0N+Rs2aK49NcR+mjf65Svxb+OAxDnNBNJQ4CYZDNXnXqp
         QUNjAVx1/m9Hj23TZcs5J+1Rzpz3/jqo2SrAu6z6P6KcIeVnNKQLwscallykZzs1E0n3
         6VrKowxvVqiHlbIjaxF6TjApOmscRKBau35RuWeO/Ss8vllz2zbLKe4wOLZMCFK6YxK7
         fggw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0aAuTJa6dBjLc0o/IyDTDhCS/j7HkZ2ARVA75WMz6znYjxWEYm
	6DCnewZGAiSzmduZj/I5q1k=
X-Google-Smtp-Source: AA6agR59QRC9shLlaWduLOanHkqzfl0WX5sflJM/RcBDmCCgRGzaA/1xvzBPLE5A25AffizZzh4eDg==
X-Received: by 2002:a2e:93c8:0:b0:261:e5a7:56ed with SMTP id p8-20020a2e93c8000000b00261e5a756edmr3117738ljh.483.1661572811368;
        Fri, 26 Aug 2022 21:00:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8193:0:b0:261:c2d5:4c1d with SMTP id e19-20020a2e8193000000b00261c2d54c1dls945107ljg.8.-pod-prod-gmail;
 Fri, 26 Aug 2022 21:00:09 -0700 (PDT)
X-Received: by 2002:a2e:95c7:0:b0:261:d8fa:c23c with SMTP id y7-20020a2e95c7000000b00261d8fac23cmr2843601ljh.306.1661572809605;
        Fri, 26 Aug 2022 21:00:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661572809; cv=none;
        d=google.com; s=arc-20160816;
        b=jKI7CjEoaEv3rljpKp2dRIkLHe80z7/SECO+wfHWSLbp3leI/lUOK8FDZFjmNEUI+O
         uv2te76i17INaoCczCwbS+IjDh5aA+3SAJAN19Jk57CCFU/Km91pvuR/H72WOeZnm5Kg
         G3Hv0lScp0L3kflqeOAUqoIOYg58wQK4mKC8D5s5yBBfPPMAjkQrzgoSb0pb2gWEtzMc
         MlXBuBfvEOnRF9ux5PXlUmpWkGS+M7W2a1HIBPIq+Z3Dxmrpm12tYzsq+B2QLtonwMeu
         gPKkum4X2BeEMb10h41LUAnlR2Ta0WRj7GSGHjrIpBX6qO6LAQZ1Dx9U2onruYACt0Cy
         ZqnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=/i85bfO59Yp3LlTJbN9mJVhZIA+EpU3oL5sT4GhjDfU=;
        b=qtd1tEiSPzpRmtZeDu60FW9R5+IVCXFY9ZPkVpdYN3zCh2EGR1aQn4Np7i3/8E+5xx
         jjEYMVa+OHcPfG2QTVEvJ6qokUuQJzJNrweingQ0tR7NGRm9PDi1PSfzMxHQpOgtJJaW
         jIfW2o0+IsLvZ6+3V7VYdxmFLOqyR/yE7LESBYn19Plehh0kZjQTid4RKgy+5SG9dDLM
         MKj/gtPmNfS6tJq0FvVeGob8CUwAlVLC/aYLv3w+KCRuXmLEdjx0P6Q7HOMhkqPiX4w7
         ibof9e0HBtK1GfJGE/jnjCfaNMybjG/F+8lEjfC38b/5Nqeh9V0vzgh6BjZm7IsA+L+b
         lglw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=WH42edJ2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id v19-20020a2ea453000000b00261c5a3061csi124720ljn.3.2022.08.26.21.00.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 26 Aug 2022 21:00:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id A21B0B833B4;
	Sat, 27 Aug 2022 04:00:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 35A2EC433C1;
	Sat, 27 Aug 2022 04:00:06 +0000 (UTC)
Date: Fri, 26 Aug 2022 21:00:05 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
 <ast@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski
 <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov
 <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner
 <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum
 <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-arch@vger.kernel.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH v5 11/44] kmsan: add KMSAN runtime core
Message-Id: <20220826210005.8e5f3bbef882c35d9c45102e@linux-foundation.org>
In-Reply-To: <20220826150807.723137-12-glider@google.com>
References: <20220826150807.723137-1-glider@google.com>
	<20220826150807.723137-12-glider@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=WH42edJ2;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 26 Aug 2022 17:07:34 +0200 Alexander Potapenko <glider@google.com> wrote:

>
> ...
>
> --- a/include/linux/sched.h
> +++ b/include/linux/sched.h
> @@ -14,6 +14,7 @@
>  #include <linux/pid.h>
>  #include <linux/sem.h>
>  #include <linux/shm.h>
> +#include <linux/kmsan.h>
>  #include <linux/mutex.h>
>  #include <linux/plist.h>
>  #include <linux/hrtimer.h>
> @@ -1355,6 +1356,10 @@ struct task_struct {
>  #endif
>  #endif
>  
> +#ifdef CONFIG_KMSAN
> +	struct kmsan_ctx		kmsan_ctx;
> +#endif
> +
>  #if IS_ENABLED(CONFIG_KUNIT)
>  	struct kunit			*kunit_test;
>  #endif

This change causes the arm allnoconfig build to fail.

In file included from <command-line>:
./include/linux/page-flags.h: In function '_compound_head':
./include/linux/page-flags.h:253:44: error: invalid use of undefined type 'const struct page'
  253 |         unsigned long head = READ_ONCE(page->compound_head);
      |                                            ^~
././include/linux/compiler_types.h:335:23: note: in definition of macro '__compiletime_assert'
  335 |                 if (!(condition))                                       \
      |                       ^~~~~~~~~

[10,000 lines snipped]

A simple `make init/do_mounts.o' sets it off.

It's Friday night and I got tired of trying to work out why :(

I don't think it's kmsan's fault - seems to be somewhere between
include/linux/topology.h and its use of
arch/arm/include/asm/topology.h.

Shudder.  arm defconfig is OK.  I think I'll pretend I didn't see this
and push it out anyway and see if someone else has the patience.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826210005.8e5f3bbef882c35d9c45102e%40linux-foundation.org.
