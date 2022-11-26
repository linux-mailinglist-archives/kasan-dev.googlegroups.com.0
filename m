Return-Path: <kasan-dev+bncBDW2JDUY5AORBZWKRGOAMGQEEWPFKNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5644D63981B
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 20:13:44 +0100 (CET)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-13ba8947e4csf3995842fac.6
        for <lists+kasan-dev@lfdr.de>; Sat, 26 Nov 2022 11:13:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669490023; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZRt5CV+4xFafgwIYhuAR/mPHpaKV9krNqdjneWAFnXnkRARpkmEiNoDHvax7vhOJl3
         aQ+x7YDFdgXmNUovAcuDRlZvXrvjasM2S+66gMr3MhoAJxiMpFB2GgOIbSUcCXKQmcMI
         0rEpATPUJ+3Se6EpNQh2F/hyOHoBnGSwtBplMQJ5Yhcav6yWtsDjSug5P5EzNSc1Tjgi
         PuuhA7+07VZGR1jTDGm/MegtnZQgUNrQvDZuuO4gbW15AiJEPzlO2qbOQtZXGObITEgm
         cIf8qia9OzPDw/nOCaJPeHbpsHI5ej0nP7qIxVZgwNFwd044sZbgV9LdOthbEwN8cFZH
         TJ/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=xmnmn5VGygGPJtjGhAemHbhplzGjN3pqm/1avobu+q8=;
        b=0PvzAaygS9q4b0DCHbuhW6LDlOT44fQ97DzniJSaOJWC1fZlXvgEYt6sVSHQkpLG2V
         lSV7SVmOMWnpC5quE8ZA1Mq3YIOwmuvxOSAfIE/0vNjIoi9Ty1iN0iEMQAAgsiCCRl+h
         PcODQdkdpyMxkTON3uvtAHceKtrASkEbGh8Rql1yvFmFV/e4iBgkDhdlJAQdbD/B9LGP
         nQksosOPveHAd2IoC58qsglL4MUCq8uutOqyFgzyz4lB2PlwtalUfb6jNgZX4QGhzVqh
         4DNP6Umx3zv4V+xAVeuQdcZauuQOAREI545f6FWgEyVUf5xSZ+C4/WMC0P6pUk0ZSeXU
         jT6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dGPoELH6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xmnmn5VGygGPJtjGhAemHbhplzGjN3pqm/1avobu+q8=;
        b=Mg8P/zBiRSL5tCVP0Dqu4YT0rdUQtF2HgBqaHsprc0l9UgUL6aDdcDnCFTQT1uV2WH
         ZYKoE/HFz6cd+ldvwnE6231uXJZ5K2NnxXptzdw7Y12wdNkZiMyW8YaZ4sZo8BbcJX++
         bnoVGueKin08OHma/XrU1bLJvzpPSZWpAl9glBaGXIAPctEUkJYBmHl77sQl5Ni04Bvw
         kb39bZWRJUuPXeLH75eCN/s025cT5ZdNP9zGyogbrZuw9w7I+Rmxl987Rg8J8/TzsSJN
         cOIvXr6S9XNf+I8ydbonQvLqTAkvJnxidIqEp/DlPRRl0I8vJCJQZfLJ/vufLBsot+vM
         MYrA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=xmnmn5VGygGPJtjGhAemHbhplzGjN3pqm/1avobu+q8=;
        b=Xgc/aD29DmVvBkL8RT+7bd0PyHaIjO4uT2Qjf/zbG8oRsgk4PFFH8fmCvblSLPeTbO
         UtovzbJeyLg2NoxTTR9MVWP5vgQJkc0qMoQnuPeL20U/0xyK56V+BUoSmPuX4ulzVMqA
         t3JqPC5wA7kwVwvwU19DoF0lfEhBIjcP0ZYTNppxJdA/rOFPHypK0iDPzLA6ZAwe1yfb
         m+DPkQz0xWX5AUzt43SB/q7wRCyELrCA2bC2cPsa1Xo9A2bxVYhsJ+2GPfz6BnjLmwm/
         qI+RrNtcnS94+rHkkEbhzfdG7D89XmE5RIHwvKXagWcY70KzD9vnYHqHGLFrvwiqgQ32
         W9Pw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xmnmn5VGygGPJtjGhAemHbhplzGjN3pqm/1avobu+q8=;
        b=UVItcUZgJgt8ZVFhI+trrndx+VcYRo1awuZ+CZcMhtHZBfYRWQsCoY4DWzEStcrOPU
         J7hJ96bmyAXBnrDlJ8uQsEXd3XrVQ+LwTAyJdx2sKM6fp5kuA8YcJDBRcRmDnHc4rs0D
         8789rtCI+VwR+e1yHPil6ySeoCAD57KcYckMrqpGUl7yMdBiYxcBDFT/M9Lh6WxzuMzh
         CjGOABTk3RS1kk+MHsIqaJnkDqMfoWdE3sgOmSCWklraTBx+8pJc6LEzHr2JmIXkGYUR
         JB0bCIB/TwJtuXXC5axSSC0kHQqfF/kyDbnyENubDYFZJGU7v7jiJLsOWPp9lIR5SOhY
         r9WQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pmth+4lf6hwQxav80u2bui5nI27EjjUsZND2fgIMi+/PDo3wiRq
	eWEEY4m9gOKkuwbRwvtl6g8=
X-Google-Smtp-Source: AA0mqf4Nc2DUFRqz4G66X5uTGf80vAYKd1OHRGmymxn+FAHN2rg/tXw0hn/7JGBHnvx/vLWuhfW3kg==
X-Received: by 2002:aca:d14:0:b0:359:eec7:7f98 with SMTP id 20-20020aca0d14000000b00359eec77f98mr20804262oin.248.1669490023063;
        Sat, 26 Nov 2022 11:13:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:93d5:b0:13d:173c:e583 with SMTP id
 c21-20020a05687093d500b0013d173ce583ls2470990oal.0.-pod-prod-gmail; Sat, 26
 Nov 2022 11:13:42 -0800 (PST)
X-Received: by 2002:a05:6870:6c02:b0:143:80af:e36a with SMTP id na2-20020a0568706c0200b0014380afe36amr3634218oab.254.1669490022704;
        Sat, 26 Nov 2022 11:13:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669490022; cv=none;
        d=google.com; s=arc-20160816;
        b=PpmnObOhbQtVFYJnmUc8OMzWugRnARumDC9AcpghSrDMWX43fiBsIOgx3ERNqWp6jp
         L+Gnw7PrMnMDdZROnfFGj8vi9/TmMZEngvi56y6tz5wLnz28p+ZpGPY2xPpZX1NMa3kX
         xkBpCI/7STskET0ebWRHl82fbI7h4UZRBVhrLJozIpxIg9u5FOwMLd3/jA7tXXmyqADO
         yKG80NgOq4tlkhXZ8S8/BDPcoA7NChymcrnPEaZILg5kHSQX8srz2bgM6TwBLh0xKs7y
         6QH6l0g/iQr6gW24WnCPX2zs01KzIQzef6qkjWMPPdeHoeC972xVib/gPLBmAjq6cLxP
         fYqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WPJu+jZjV0HF0T3O/nCnlgZiVdaWzUPqt5uvtlZaGzY=;
        b=mEAPle5jFAgQmdy6v4ovukoLB3VH+VRtl7J8dolufxWLvCACp8gjkTRq5CZWfY0Vkk
         AIcRtPZWRX3MqBc7TIvgePCZdutBzpnPD7doHaxrabLDR50cWKeg7oXHh58syOxk3DwQ
         bOvU+dZxsUCh9Q0REgm5US/J37qKliR6thsvmkW9e1KWQscLPnVfXCUy4AoqsmvG2Ec2
         aJ9pfl3n0Rii/gz35DzkEms755Joo7C1EKMjb48AXbamWpWP0pktudHQWe5PFzCtacqi
         +uyfFRcOQlWGH/tBWAQmGtQDUB45T8lBSoZEg2xhm92/LF5lRl+KbGZvx16L6S38+Iak
         Frww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=dGPoELH6;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 71-20020a9d064d000000b0066c2e89a82bsi459073otn.1.2022.11.26.11.13.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 26 Nov 2022 11:13:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id q12so2781851pfn.10
        for <kasan-dev@googlegroups.com>; Sat, 26 Nov 2022 11:13:42 -0800 (PST)
X-Received: by 2002:a63:f00e:0:b0:477:5e25:6d4c with SMTP id
 k14-20020a63f00e000000b004775e256d4cmr22089354pgh.159.1669490022359; Sat, 26
 Nov 2022 11:13:42 -0800 (PST)
MIME-Version: 1.0
References: <c124467c401e9d44dd35a36fdae1c48e4e505e9e.1666901317.git.andreyknvl@google.com>
 <Y13oij+hiJgQ9BXj@elver.google.com>
In-Reply-To: <Y13oij+hiJgQ9BXj@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 26 Nov 2022 20:13:31 +0100
Message-ID: <CA+fCnZficLHbDpqjn-wiQhg9dTTO8HjLSwAOLGuPgd8O511F4A@mail.gmail.com>
Subject: Re: [PATCH] kasan: allow sampling page_alloc allocations for HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=dGPoELH6;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42d
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

On Sun, Oct 30, 2022 at 3:59 AM Marco Elver <elver@google.com> wrote:
>
> > +- ``kasan.page_alloc.sample=<sampling frequency>`` makes KASAN tag only
>
> Frequency is number of samples per frame (unit time, or if used
> non-temporally like here, population size).
>
> [1] https://en.wikipedia.org/wiki/Systematic_sampling
>
> You're using it as an interval, so I'd just replace uses of frequency
> with "interval" appropriately here and elsewhere.

Done in v2.

> > +static inline bool kasan_sample_page_alloc(void)
> > +{
> > +     unsigned long *count = this_cpu_ptr(&kasan_page_alloc_count);
>
> this_cpu_inc_return()
>
> without it, you need to ensure preemption is disabled around here.
>
> > +
> > +     return (*count)++ % kasan_page_alloc_sample == 0;
>
> Doing '%' is a potentially costly operation if called in a fast-path.
>
> We can generate better code with (rename 'count' -> 'skip'):
>
>         long skip_next = this_cpu_dec_return(kasan_page_alloc_skip);
>
>         if (skip_next < 0) {
>                 this_cpu_write(kasan_page_alloc_skip, kasan_page_alloc_sample - 1);
>                 return true;
>         }
>
>         return false;

Done in v2.

Thank you, Marco!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZficLHbDpqjn-wiQhg9dTTO8HjLSwAOLGuPgd8O511F4A%40mail.gmail.com.
