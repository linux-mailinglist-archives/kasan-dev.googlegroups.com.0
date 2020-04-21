Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPFH7T2AKGQEOCWEH2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A4951B2B57
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 17:39:41 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id dc4sf14221136qvb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Apr 2020 08:39:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587483580; cv=pass;
        d=google.com; s=arc-20160816;
        b=fEdQs60Ky933AzHF6m9yVfjNUCcsCn96GyiyFjqaLA4SfUzZEAmq0GBhx9hXSW3KVi
         xuXqbRONr21NvySgKDbeuDiumQ7bRcc5elR9Llj3fVoH22FayibdHb5nq6WDlS1PQvOw
         LHtycfp25QSgKYoTpllSJIqv0ajMQcV/saZC8AG4sV8W/iRfR12YjIPsVeu1krmAMcAs
         62IWL4lJB51UThZdC4SRtCPQzZnEnCLXB82pvVkKOE5QsLtdUhWqpSeKBESfuCt60NBD
         lIRxbdF0wVlJg0JCm5PvMU2k99ULpiCU2kyKQDb/FluZLx4dusum2klv+81wfZUME7tu
         MLng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xlCOS4hS39Qmef74yOtAEuOIKUEQ4Gq8P9zC8v0HGVQ=;
        b=yB3PCTWY1DuA+KcgLmpXfl5GDpjfQP3E6zhgla5OjVOIS+oyfK43Q2ExzwAG/jGBH5
         8fEfD85JGdetsIfdY496tZiHkjFwNiCqMUw8GBNMWzPCbAvuvlleYdc1IR9YRVOk5tfV
         E3Hdm59BzL8dg5bwm9NwjAc0dBnrlQz/4FM8I3IBkpvqSa8qbsIScEwn2zeWTJKPcP7n
         nN/Ro3tEEFlpBCZM/O1j0hdYAll6EApY6Uj249wIYtG9R9zBEso23yGAElS2UWnl/WFq
         VHZ8WsclBrPyN9IsbPIrh7AF3j/WRNB0OeGl+zkfWU7P+STKJFq6OeyyPDLd+7P+XkVd
         mMvw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QGgo4tZ7;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xlCOS4hS39Qmef74yOtAEuOIKUEQ4Gq8P9zC8v0HGVQ=;
        b=rEqLImASsxxQxv+SftFX9x0rww1HQstrw1tZZU6PN3UC5I60GvK0jvrhalE1JKo3tW
         askjDy3fV5D0QuWKsWG7cnE9FKFD9YKfPqDX6GGnZ00SbUrKNd8lNELfEm0+ye5S19B5
         IAboND2e2MPNJ9R1mdlKcvV1dt0+RarefMayRNr9ZRKw6l1oupO34VtMkQEeKZX2aV5l
         aMKHFzSPPSJnEP1RbnxIH9pb7n8a59MU5ReZPfNCIrfhJbhxiXHxRfnEf1eOxBL7ChKk
         PYfHvy5T1bprGMCYLVy+qja3Y2kxt47X8I6CRL77dfHxvGhxtctJh16gXuGt1/ZEpupP
         8SlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xlCOS4hS39Qmef74yOtAEuOIKUEQ4Gq8P9zC8v0HGVQ=;
        b=stXp2cIxY5MC/cFze8xyhjfi8t4rGyE/KVuijOWanb76CU11ea3b+dMkS1oP7ARupn
         vV6ME7lzlAK4SXvQ/JVHXOSNV7v/4jZIluXkK6TYVoTj66mHZ9geTrttQ6UnD8/lDYiU
         zgMSVQDjvkgpo0btXNpEj7eCVwUAcPFuYXkhHtf9WhzTp+oQUrfzMk6Vacyb1RUXFJFr
         twS6W/reatCeNQHwhwDj0QYYx2K19AVwKZ8Tnj2bIAIAO37fY/AWDSdm/SRdZp/4X5G/
         xtcXhEkya94RrMZlFBLvHv9WiF/V+YykvpofqmaAmhkyf/Y5eWKiMYvyfN9uLQ+j5tC1
         A2BA==
X-Gm-Message-State: AGi0PuYQQ0/X3ckazqy8HBl/IxG1QrX1SesKUlBlCJQZkN8s/WFDikIA
	AXRul2tESbvMdHTUIIjatKg=
X-Google-Smtp-Source: APiQypJmBCBYorrJ/yXFEX1FYbq6cdE0xtERopb/aaEpWKuG4oQYDZeV4G1IokY6H1uqnnn468xYWA==
X-Received: by 2002:aed:3edd:: with SMTP id o29mr21907530qtf.149.1587483580632;
        Tue, 21 Apr 2020 08:39:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:2205:: with SMTP id m5ls6451311qkh.1.gmail; Tue, 21
 Apr 2020 08:39:40 -0700 (PDT)
X-Received: by 2002:a37:80c4:: with SMTP id b187mr21216736qkd.302.1587483580257;
        Tue, 21 Apr 2020 08:39:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587483580; cv=none;
        d=google.com; s=arc-20160816;
        b=SfjvtqXWjGn5a0tf2cokTs9O3TahSrUOrod/2njHPLXRqKzT3oZjhSTVHYRriw9svK
         1OURqNUaMBxq8b0kPNDi7/tRNFXnn/7YEzswEzeHN+V+tg4lYQx5+5YPLo33zCQyq/6x
         r18VzCCa8OehDKNswRG3g/esQv43PTVvyxsjXqlxyqeH0fqYSaAf8Exx8lLWG6LIiuPT
         HQXq33MEKEg8ZigJR1YZbti6Q+5AFhtlyqH4B6kJ8LJgPVGT9lcRyu0f00xFyvl6jxIP
         q2H1nbQ1WCGUAXdgzwxLFGWZjCo7qvfIHFKogkFSdZpjlV32JwGpErDo+zdmQb0izU/t
         PeqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2mmoGh7NbU2I6i6mTnfpxZZ+azD3XtCswEGTNXCLuyA=;
        b=n/Q3PsY8IpYF+kxFicQtO+lPbqL/ckzZpZzuvTUUvngA5xE5FSVO/ci55zwqX9jQkD
         qaUAliK0EFmqxvXfBlySX+Js6RvCkn2IVgL9DYpclivIHNnQoBSm+L0drCrM6Fsiy7ah
         u/uBatvP6llz64vrowMzX33977IYS7hCQjTe6I+RpZb74KSzHA/f/ATnfg7KQ6au1Y+Y
         IlX28ziJDl2JXFwkdM4e82svCgBV+SE0zKwWkFjt4HUwOi2H7aPqvz6R4Ewqv1r4gPru
         dnBGX8A5es82vCTu2p+uJUdUYskNcE9U7HupUIJbq4BIH29shFqm41J912BJufFmzOpl
         ekhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QGgo4tZ7;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id f3si183512qkh.5.2020.04.21.08.39.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Apr 2020 08:39:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id y6so984472pjc.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Apr 2020 08:39:40 -0700 (PDT)
X-Received: by 2002:a17:90a:8c93:: with SMTP id b19mr6142175pjo.90.1587483579220;
 Tue, 21 Apr 2020 08:39:39 -0700 (PDT)
MIME-Version: 1.0
References: <20200418031833.234942-1-davidgow@google.com> <20200418031833.234942-6-davidgow@google.com>
In-Reply-To: <20200418031833.234942-6-davidgow@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 Apr 2020 17:39:28 +0200
Message-ID: <CAAeHK+xBnxfmS7Q6oY94JRqzVtSzpUpWtsM3u+1S5kixJfZ+yw@mail.gmail.com>
Subject: Re: [PATCH v6 5/5] mm: kasan: Do not panic if both panic_on_warn and
 kasan_multishot set
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Vincent Guittot <vincent.guittot@linaro.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kunit-dev@googlegroups.com, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QGgo4tZ7;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
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

On Sat, Apr 18, 2020 at 5:19 AM 'David Gow' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> KASAN errors will currently trigger a panic when panic_on_warn is set.
> This renders kasan_multishot useless, as further KASAN errors won't be
> reported if the kernel has already paniced. By making kasan_multishot
> disable this behaviour for KASAN errors, we can still have the benefits
> of panic_on_warn for non-KASAN warnings, yet be able to use
> kasan_multishot.
>
> This is particularly important when running KASAN tests, which need to
> trigger multiple KASAN errors: previously these would panic the system
> if panic_on_warn was set, now they can run (and will panic the system
> should non-KASAN warnings show up).
>
> Signed-off-by: David Gow <davidgow@google.com>

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

> ---
>  mm/kasan/report.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 0c206bbf9cb3..79fe23bd4f60 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -94,7 +94,7 @@ static void end_report(unsigned long *flags)
>         pr_err("==================================================================\n");
>         add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
>         spin_unlock_irqrestore(&report_lock, *flags);
> -       if (panic_on_warn) {
> +       if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
>                 /*
>                  * This thread may hit another WARN() in the panic path.
>                  * Resetting this prevents additional WARN() from panicking the
> --
> 2.26.1.301.g55bc3eb7cb9-goog
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200418031833.234942-6-davidgow%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxBnxfmS7Q6oY94JRqzVtSzpUpWtsM3u%2B1S5kixJfZ%2Byw%40mail.gmail.com.
