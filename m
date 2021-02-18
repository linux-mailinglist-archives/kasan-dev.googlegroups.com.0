Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRUFXOAQMGQEIFFOXVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D37F731F018
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 20:40:55 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id q77sf524027ybq.0
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 11:40:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613677254; cv=pass;
        d=google.com; s=arc-20160816;
        b=cy4kSHIvLA4gpB7VPRmXkgw2CQWEQpeygakbUd1g+OvKbJrno4MR/DfA9ONXHrDVxV
         /cHS+2997ybVDj9+QQWhi9NA+LzURPH4hgI17PEXy5B7vtIkI2fhjFRIhZKl+Z5jJJgZ
         IoCI/xyG9KbG923PkEUlH+ER0wGddpFaEP+fwN2fhqoakVrWhG2ldb4eYTq0/naWH/WA
         Z0eABTNdsV4sw4mkiwIoexGD3XK9wo8iBroGtPkF5+54HET3WsQw9eK1J2T8wBEZKfyp
         u1vhY8Nut8Y3Ri3j3WDZTma5RlhBk2kAqPpZBW2nmWkb6spsIyQgfXsvyybI7F0/UheA
         1FJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VfgsBsjypVWvE9ao2+QN2oxSQj8k12xby+mLB3BvYOU=;
        b=sj33+VzkfkAV+tKeX9D/4sWhcPegMhpJ3R+WjRzNvG/J80o5tXqFvHtObItQswNMv0
         XMUTtXELWFjPpRLPZtH7f/3noRJsEycCwCqzHvBjBLYC2sZNpa+NYWytjjO0V4oRJYZ3
         NcAXxklnmDU45HAKfCuO8hJIltW7TQsVx6fORXcksdCQYldmhbt9zbc0VWg8StGewLlV
         eZfWmJWjhY4gQmhD4cY1LZRssuS+e8Mq755OvLipgMGW8HpWwtZPLXINXXmou13BFtPE
         tIKSK+t5hphFet5jy28V3UfkkzueNBst+FbWjEh1pvVi/VkTpxiEDBRCvU/ez7xY/olE
         wGIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W4TbLg8q;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VfgsBsjypVWvE9ao2+QN2oxSQj8k12xby+mLB3BvYOU=;
        b=ccWQDWlTTwjl4c2levj6xBhA5tCtx86St5UCzhLQrA12F+fXNyPOj9mvOAwHQ0o9Vv
         IWIkQ5lJ9mcPmCm2P4jYn6OtW0NTtvMF725cBYNy1iNnbCqHcO3Ks1T7eTXHhthcMjSZ
         cWrhqXuO/USMsjL9T1NPN1tzojV59aKYpGv5Hwf/0K76chcNvLX1O5rC7Xsh9b23aGLS
         i9Ocl9C9lzN0zKqQyzxVS1jGR699GD4lcAkV0VSWQ0Z3UtV2Srvlt/eaEw0/TnAfpAyy
         sN0VR5PrI3i8KS1DeUcD0zhXEp0hQ4nKXF4W9Qzv1HPJ/mIw+XqjjYMOVtjRJZOqT41f
         xmEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VfgsBsjypVWvE9ao2+QN2oxSQj8k12xby+mLB3BvYOU=;
        b=Sl7rkDDfyLMfC5n3aw75aKaJXl+bSbQAEs5yWoxCCrbwgvunx4ed78jXq6Z0WluCw6
         J0eW7fyryr1LTYBKby9uxecyocwZr124aey6Gle4jnjWH8V7IJRLKJs7mlAJEfiIpSD2
         DmOXlHuhiaRHUzPr+dzd3WTccOREQZ5XLvs6UzdmC0IeQgcNGNtP6oSQTcJ9yixRmN+V
         ICoZvf/ISGpY0Pg3Hmp38Ys1hnWfyOqNm3oxXhhAPOqArK1BYzx/I+CfmXi++xMFXEVf
         oXCDESbImacgf5r9Rb8vq3DKCDhIY7UN22+bCsruo4frzPF3Wk4egTshBwKIuXPrr/vL
         +6xw==
X-Gm-Message-State: AOAM532JHOIYWDv4q7xpMpEvcND72JeJY5jMvAg9uvArq7V+evB0dks0
	7Fgc+WtPRz/fXExJZ2eEp44=
X-Google-Smtp-Source: ABdhPJxPlwHKwKF3r8A5KuRAcHdEs6i2iP72ZI8cFsmitRx+NzXVZrGjc37TfJbPc6PdtA5YY/Q4XQ==
X-Received: by 2002:a25:d016:: with SMTP id h22mr9004648ybg.278.1613677254764;
        Thu, 18 Feb 2021 11:40:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:1482:: with SMTP id 124ls3409482ybu.7.gmail; Thu, 18 Feb
 2021 11:40:54 -0800 (PST)
X-Received: by 2002:a25:d54:: with SMTP id 81mr8575700ybn.401.1613677254257;
        Thu, 18 Feb 2021 11:40:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613677254; cv=none;
        d=google.com; s=arc-20160816;
        b=FM86oMeq0M3McZ9Fg9NuZUh3YvO/PegrK35af5P5ddd9pVqMbtS3N+YglEC2mwLryq
         DYV7zl8XOgssZ52XKLNvqunF+jS1Fzc6Z30bNqf538+Iu3X84RZiPu/04NgydXA6kJ9u
         kvRIR4AkJHKHlbDp7cGIs3nn4mIYUXI/1q068ymxX/fvVRD9Z3q57Woi5y1ZXqd1rztA
         KSUYcksDhqsd+7PSfwFdvkIWlsK44TSV5067AuzNzEw6oZk1dG6iZ+0f/dY6+lDad5Tb
         I2dJ5Vkz16Z1+oAw/XRw3+FFI31D5KaJXGPZNRSIg/cQWFnWP3INDActDv3VF9c714x6
         SJJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Wz58CA+xdym2cUyo64XiGmMsVDmP1Ip6ib85/PA+8zo=;
        b=LLWB2Jc5jGRkGzJoeg0uca+nxnsUJ6QgaTRq1PV2NEI5gzOjdcKPDZTed7m0QatiWB
         Dn7jk++W2QOv/48e+GbWLsx+6s4zK9VHqbbPNd3NrJueBmPheUFwC0i3x2vNftIkpFqW
         8aGw/ruRLk/YKX2Y09ra4Re7GL7QuYJxygdE/CkhLeyziP1Tm7Q15r81Is10Y8wxemvD
         5FtPpJbyKk9ZzzEEA/s/O9VafgDkYWkd/x8lXRXZpdUrJi4XCVFOiFe7RrhyR+97G/ZM
         tKLurj1tEPC3lF2TaocBymWQJOp+K97auyt5jdeIHRUoEAgxiu8C1YRCKTqyEktJ0POZ
         3cMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=W4TbLg8q;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id c10si487986ybf.1.2021.02.18.11.40.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Feb 2021 11:40:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id c19so1962170pjq.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 11:40:54 -0800 (PST)
X-Received: by 2002:a17:90a:64cc:: with SMTP id i12mr6170pjm.41.1613677253685;
 Thu, 18 Feb 2021 11:40:53 -0800 (PST)
MIME-Version: 1.0
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
In-Reply-To: <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Feb 2021 20:40:42 +0100
Message-ID: <CAAeHK+x2OwXXR-ci9Z+g=O6ZivM+LegxwkrpTqJLy2AZ9iW7-g@mail.gmail.com>
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: David Hildenbrand <david@redhat.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	George Kennedy <george.kennedy@oracle.com>, Konrad Rzeszutek Wilk <konrad@darnok.org>, 
	Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=W4TbLg8q;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::102f
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Feb 18, 2021 at 9:55 AM David Hildenbrand <david@redhat.com> wrote:
>
> On 17.02.21 21:56, Andrey Konovalov wrote:
> > During boot, all non-reserved memblock memory is exposed to the buddy
> > allocator. Poisoning all that memory with KASAN lengthens boot time,
> > especially on systems with large amount of RAM. This patch makes
> > page_alloc to not call kasan_free_pages() on all new memory.
> >
> > __free_pages_core() is used when exposing fresh memory during system
> > boot and when onlining memory during hotplug. This patch adds a new
> > FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok() through
> > free_pages_prepare() from __free_pages_core().
> >
> > This has little impact on KASAN memory tracking.
> >
> > Assuming that there are no references to newly exposed pages before they
> > are ever allocated, there won't be any intended (but buggy) accesses to
> > that memory that KASAN would normally detect.
> >
> > However, with this patch, KASAN stops detecting wild and large
> > out-of-bounds accesses that happen to land on a fresh memory page that
> > was never allocated. This is taken as an acceptable trade-off.
> >
> > All memory allocated normally when the boot is over keeps getting
> > poisoned as usual.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
>
> Not sure this is the right thing to do, see
>
> https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com
>
> Reversing the order in which memory gets allocated + used during boot
> (in a patch by me) might have revealed an invalid memory access during boot.
>
> I suspect that that issue would no longer get detected with your patch,
> as the invalid memory access would simply not get detected. Now, I
> cannot prove that :)

This looks like a good example.

Ok, what we can do is:

1. For KASAN_GENERIC: leave everything as is to be able to detect
these boot-time bugs.

2. For KASAN_SW_TAGS: remove boot-time poisoning via
kasan_free_pages(), but use the "invalid" tag as the default shadow
value. The end result should be the same: bad accesses will be
detected. For unallocated memory as it has the default "invalid" tag,
and for allocated memory as it's poisoned properly when
allocated/freed.

3. For KASAN_HW_TAGS: just remove boot-time poisoning via
kasan_free_pages(). As the memory tags have a random unspecified
value, we'll still have a 15/16 chance to detect a memory corruption.

This also makes sense from the performance perspective: KASAN_GENERIC
isn't meant to be running in production, so having a larger perf
impact is acceptable. The other two modes will be faster.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx2OwXXR-ci9Z%2Bg%3DO6ZivM%2BLegxwkrpTqJLy2AZ9iW7-g%40mail.gmail.com.
