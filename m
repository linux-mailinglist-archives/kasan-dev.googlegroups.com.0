Return-Path: <kasan-dev+bncBCMIZB7QWENRBHOJ436AKGQEQRDV7JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C176D29D136
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 18:04:30 +0100 (CET)
Received: by mail-il1-x13a.google.com with SMTP id r12sf4020015iln.3
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Oct 2020 10:04:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603904669; cv=pass;
        d=google.com; s=arc-20160816;
        b=PxCKXROeFkPwF1vqJ/jrgXDKAZvkFAUYLX6jAwoQF/+mV7ugtolXWcHqxYrozqfJRH
         d2r4OGbGQFwILROBAGjRT9GIoG/Bcdi7a3ddToMFYPKt2AAvRpw1BxQ3WFytqRjQsNiK
         Xvd8sVHAuiLh571jDp9hpuA74HuVCbZyxU+aSK2WWJgll59bUXnTPspeR/U3Pq5mAXTs
         srbceYtzgpInIJlQkNUYwRPC+kUABGXCGiJ9DpIFqGegFcQrCmHdeVd5VxbNtUM8WfKd
         /maJHrySDNDhanJL/pzNvVRs8qhzABl/nRObX07yFLQJ6YZh5gUO7Q1Gi/D6ReroGy0C
         Gupg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Lrj8aTF21DmRxwQXxCuSSBBMr/CmjfIrbaQ2F6RlaQE=;
        b=qdnysU7i0OVSQu0/THxfrFwMiv+s3attZx3lMp+MkeV8bLPWrLJYBaJAakIZT2fisw
         /FXqr+k+Tiqza7/yZDWEzhL/F53y8vdFW73SmIjhBlQ19jOGKiQ1vC+I6V/HPEIHcQGG
         c1G8dl5V+z9HEklPTy/KZfJQ9gygarvqIKypR7Rck9kT7Tgb+dgshb5sDTkfXxXlcygU
         L2IFw44J9lnffXwE8q3qUzkCwBojkL6DswxaWVY1Xpvj3puMPOUrjTDMTC8m/+DGx5Qh
         QOsH/aWw6tr7VNo6EmnlC91iHPMWx/KsBeVuF7I02JKzHKHu2XpslyugXjJSrTu871Ya
         Nx9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C3K8jt2E;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lrj8aTF21DmRxwQXxCuSSBBMr/CmjfIrbaQ2F6RlaQE=;
        b=Cyjs1c9WvGLPBU/uB7welIBEuqekczi2VJNKSiKbkF6hGFqxAAAUmed9lkcYzDZ7x7
         /5b+R73x2WpVbL3Cgbh/3FE9RMu8xnfMxZiCyy6hXvnzN/FNeFjYAOKEXG3TF28P2VZs
         JsY6klqZL5mwXg7EfdxybOSzirHMvoVg6mOqZJRpOAItWWInKnWqpKWXDh4EIC/x5ys0
         09NeZV14n3zSjqnH8/5KKjPnUGI4q1JQeOsjEu8ia5Ofc9OAIv0pX/BJPgzybVf2jRwP
         Iq+fukzNdLBBhCK0M5d9ZUEFgrba2B6VYbJsVUsyPiPjC9k2fr6lO96dAsaSwWSpCv3F
         syDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Lrj8aTF21DmRxwQXxCuSSBBMr/CmjfIrbaQ2F6RlaQE=;
        b=tcQa8+NY+euuJFdbyVVuXT5jGUDndYuyAWb+TYjt5aAPKwmVHMg4Bi77kh8+apCTx5
         w7Mc5wKoTOiK8wfn+YC8synPdXQJUVcNnxPCyUJQMhq/jhs3T510pq98lZcVux4QQ3Rs
         FLtbW4QndpWcbTkroNNgZZ50ZvwrNHzCfaWRYb6cr1F+GS7nRva5p85Z75EdruccADCb
         Fm+IsgTAq9ddow9D8IG8bE2dZgYICLrBUgMjur5ua7v78viTat3qOZs57zo4qqh/idjh
         4VHuM8W8scROV+y33eZx/DsDKQOnLJ2M4RavInfLkcpccSFSqR71NgFg1mugPPPa2kp8
         MZog==
X-Gm-Message-State: AOAM533Q/ssCU2GcbLUzMTnjIVfgIzVcrzmYQU7tR/qFiCqnfmaE8CXS
	xzq2Ju8muHgBiSPOYN65H9I=
X-Google-Smtp-Source: ABdhPJyqsJ+CYDuvwtsPOyDyE2XBNbcqHjaVey0GgCrsk2ifj1llJ66r5eExsdIW5Sl9dU7tX2QEyw==
X-Received: by 2002:a92:5f5b:: with SMTP id t88mr37357ilb.170.1603904669232;
        Wed, 28 Oct 2020 10:04:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7d02:: with SMTP id y2ls28637ilc.11.gmail; Wed, 28 Oct
 2020 10:04:28 -0700 (PDT)
X-Received: by 2002:a92:8906:: with SMTP id n6mr20248ild.13.1603904668873;
        Wed, 28 Oct 2020 10:04:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603904668; cv=none;
        d=google.com; s=arc-20160816;
        b=ZcB7/288h5oF95XWk+HLvGyPZq54aLTje0ZHT4bXDwjCerF51UX3lvG0edYC7C0cuI
         8vWOb31je1sN6AOQ3lSE9v+ryvk05E9fImLoSx63celOgq1LER93BZc0n13GW08iFt+x
         1RbcA3mQbfoUKBvYV0RceDGQUXl2TnXhVM333HF/odabFm+tpKyLZUaXEXT6vK0qmf7n
         YaFDkrKvCp6PUmOgPql+DqtDOLuzOc1Iu4lvBRuIqi/MxNub0ioPJvyk6Y9fF0bh3Cks
         G7C3TWwJQmBr/ATX7PeGSN1OnECUuWhlxxflTb3KMeS58dKTSl6kj7hc4V1nbB7dKHK2
         F/cQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AG7fb7d0C8MAPzIXBnKbPS8VY0VZhAzE0h3g8JJD9l8=;
        b=F9cRZX5QgaH6AB7TDyLZiPRdzQSoWBnD3jN0vu6/rWj+Vy87jZRZvrJ+2/709pxlnG
         yKzEsQ27bcOp3ZZVMHzmrmu46G1qjtDsVzWj5MV6v/91Y0fWLNElVj1tMmo+I/+cjfaK
         UG+nOs+CpVV+1zlzqrcb1jjxuN+12PNnFyhLSlWWy5b59lS4LKlgir20QdsVkttkWVe1
         MoAhDwXXmk0yDAbhz4KEu1Ejr/lTlRAR1Mr71lEztmcD+XckFaMqCgSvacvKGiXdAOoo
         4NQrrNLS/CeTj8ns7NwSseJELTjB9+HNprCl8GdmIhGHmwTgkUjilcOAjy5hzaeDyqJs
         9l3g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C3K8jt2E;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id o19si8039ilt.2.2020.10.28.10.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Oct 2020 10:04:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id i7so54107qti.6
        for <kasan-dev@googlegroups.com>; Wed, 28 Oct 2020 10:04:28 -0700 (PDT)
X-Received: by 2002:ac8:44ae:: with SMTP id a14mr8224570qto.67.1603904668207;
 Wed, 28 Oct 2020 10:04:28 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <6ed65cca58736301a1cacb539a6e672aecd7859d.1603372719.git.andreyknvl@google.com>
In-Reply-To: <6ed65cca58736301a1cacb539a6e672aecd7859d.1603372719.git.andreyknvl@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Oct 2020 18:04:16 +0100
Message-ID: <CACT4Y+YHvfccvAYgkO5TrB=uy_htvNi4qshfLOqvci3RGzfR1Q@mail.gmail.com>
Subject: Re: [PATCH RFC v2 21/21] kasan: clarify comment in __kasan_kfree_large
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C3K8jt2E;       spf=pass
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

On Thu, Oct 22, 2020 at 3:20 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Currently it says that the memory gets poisoned by page_alloc code.
> Clarify this by mentioning the specific callback that poisons the
> memory.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Link: https://linux-review.googlesource.com/id/I1334dffb69b87d7986fab88a1a039cc3ea764725

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 3cd56861eb11..54af79aa8d3f 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -445,5 +445,5 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>         if (ptr != page_address(virt_to_head_page(ptr)))
>                 kasan_report_invalid_free(ptr, ip);
> -       /* The object will be poisoned by page_alloc. */
> +       /* The object will be poisoned by kasan_free_pages(). */
>  }
> --
> 2.29.0.rc1.297.gfa9743e501-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYHvfccvAYgkO5TrB%3Duy_htvNi4qshfLOqvci3RGzfR1Q%40mail.gmail.com.
