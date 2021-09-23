Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVHXWKFAMGQEQT3G6BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id 660F4416488
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 19:39:33 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id ay30-20020a05620a179e00b00433294fbf97sf20928275qkb.3
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Sep 2021 10:39:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1632418772; cv=pass;
        d=google.com; s=arc-20160816;
        b=gA6c2lRRj4lhIqJeso8AuaaxThWPiTfceCEaYit90Cpk28z65kLb5yOg82EHTH+/0c
         Zq/ga9Xf/XDvP6TKziiqfPZdT6TYKZ+KeFnrxbXmsoKR3c1szh/YkX0Py0wdce1yOMku
         u2aqHJNwlHXJv4h2dF5e17IKQKXAdl2GuYeTHoRPjFe1ZS8Sz53HWelJdK86SUUR0oJ+
         h2iINfT4KeLByhPVSaEOxQ2UCl9RVuGEbr+Pk7REedyI9rFvcQ+027hdiINgNSr/HF2x
         8vA8t3WypLmhyCyje5qD0hLWfKNlB8C6ZfCrvs5UjcaU0z3rSOMyvjnNa2v3tHQQv+Do
         HZ1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=A4tYT1HTfltjgKXS28xU5redw0SQp+eRWGxhAF+Oc7E=;
        b=fwBDXyN6JCYIFyHKEOV1xD5V4az6erR7IpmcwOY4jniE25EJNBlS5XGT44VS/WtR+m
         IZAe85YKjribsxjUdMxZdB35C7B9v+nNnL7xee0dMGihaNlr0rLcicHaF5xe3B+hjgok
         Fo5cYyKtegGf5CGGTGHWg7SkVIULB8qakg3HKZvB6K+rFbjBDvmTWGQDgy04+qfDuiD+
         grbxY+AEx6KJvRSLshiMyOLwxbaLpK+cDD/FHztrls0HRm23qByavdzkmOD5A47NTvRu
         NHVle1B/y80Jp0xB/kRQXyeRUF23KkyVPXIDjhvDlOMOZ0asHQixxzLY67muDrIc/bay
         ACsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=H75LXkHa;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A4tYT1HTfltjgKXS28xU5redw0SQp+eRWGxhAF+Oc7E=;
        b=WFYSCAmiZvhVx5xxeglNgaOXNk7UUGQCKxqIcifbx49QEADfjmIj0nS/zTzwT2UZzo
         XYQObwVImLQs5zS68TKDN1weTzMBpqnEo0pd+LgusTQP5XERl+k3FygsX0jrT6rNZVO9
         3fA0ZFR3gTOb8NlBpS4bjrcvDpChKDsUjbA22bZ8BKdeQ1YyCGbLXkyiekziT+0870V9
         JsoMEOs+k4gGzGXkyshrsfjf6qoEZ6gVGSwyyfyqwsA9q/QbeR7tccapk3wUMPXGuFHu
         QRMsCqbynM9AAavtKlqmecWlCS3zDFOBEPo7QVfVrd9fFGNcXqAQLCiM8V6yWa1TmylB
         iXXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A4tYT1HTfltjgKXS28xU5redw0SQp+eRWGxhAF+Oc7E=;
        b=L9111fP6sE486oIoCHiQDYeKFzDPp8aVsU8sFSaJBlmc7+1aS+snWHgSuxssMcAJM3
         7KZix5rd2ndaIH40ewu4xmyNMAiGPu0zwTEgra8I6bjoAxW0IORrXqDYtTTJdrgoOP0A
         SgWyiWnkoQLuvPHsEHmWqtELEdUtE4H7VCkfFnflx2mRtawXIUtyYPJFPwjWhYNEd5qK
         /VpPeDzE+ZOfsuWqpGj2j/9FG+sZZ9CEqxAQJrVRyosJ01ujJYPiwXL4I0viq83SJ/lc
         7L8zPMa8RadRURvyCDEtwwYKEYg0KuLQgkdw+mHdKwxPXtzxTQU7KpMD26UkMldgJTcF
         CwtQ==
X-Gm-Message-State: AOAM5321sDL05VEQ/qwqf7HRFq8E8jBt+Ol2Qn9wlKLEEEnMl47n/nas
	KuIQQ7CBEES0p2LHEdnDsHc=
X-Google-Smtp-Source: ABdhPJxFz4E/P2nF5u8PDr/4dVsQ064LOvwg4E3woCfFMxbdkXVx5OilUD5wZvfHEgOm9QUB7ilD/w==
X-Received: by 2002:a37:409:: with SMTP id 9mr6015205qke.71.1632418772385;
        Thu, 23 Sep 2021 10:39:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:6c7:: with SMTP id 7ls3480231qky.4.gmail; Thu, 23
 Sep 2021 10:39:32 -0700 (PDT)
X-Received: by 2002:a37:6658:: with SMTP id a85mr6239923qkc.34.1632418771925;
        Thu, 23 Sep 2021 10:39:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1632418771; cv=none;
        d=google.com; s=arc-20160816;
        b=c+7EoEwC580A1O1PTnMd1cs/n27g1JhjIRbSmrmUdrse9Ci+radTnbzcgoQgRxiW61
         wEkiNBDtb0jWXybxvaXd98EgNVjxmABi9MNVabICSupXuq82qRV6hVJGRtwHe1Fe8rJR
         NF+zgI1C909io6ZcLSj6cfckKgNcYuPFnibtTtmG5RK3J8RF/5vYS+v7JbEshzWxEVKh
         6ACGRbPiEO/1LrqgVlrjtAVpnbRSw587kB2ad5+j1q+hXl5B1qhHJLA/L4EQxOlI5Vbg
         254IqL40wLam+lqp5MHdrqwpTKczzgFzQ5wZ6aIOcLiAFTP3bPf5c75cPQHdMWFJ3SeC
         3EIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8tzYzW9ssEz6BTq7KxGd6zNB6scfISySpG7l9Pl80cU=;
        b=MG4S63wYOPgz2aF2oJt+R0kzXZytekkZb6NcWg0jU5s4O5gZmyUDgtIIMt2J+7dYhD
         fpxbRjE+TX1omUmQNOmk/VYcLvSno+7n3IYqsfv/yNiAYoEVd3Hn7h/4wpErZJS6rWmB
         6qdFPxXSRVhQXwNe20Gu7L/udYyppjh773/vqf9gmHnHrEsXoQLiWY0WKvut3RTQpTf0
         a8atEz7cYoIDj5QMmfn3yyd9TDcPs/dMQ9jtJnNCqzj6CnXvmTt6sPzbzmU4kID3XolI
         J7EBFBPu5mhzQY5FldiYwhNfWr9iZxQ9v5JX8xNLP26rWHtP6YtU7bY3k/C/HkdolGGp
         4epQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=H75LXkHa;
       spf=pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=davidgow@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id a21si127653qtm.3.2021.09.23.10.39.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Sep 2021 10:39:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id q125so10134344qkd.12
        for <kasan-dev@googlegroups.com>; Thu, 23 Sep 2021 10:39:31 -0700 (PDT)
X-Received: by 2002:a37:a90d:: with SMTP id s13mr6209571qke.115.1632418771499;
 Thu, 23 Sep 2021 10:39:31 -0700 (PDT)
MIME-Version: 1.0
References: <20210922182541.1372400-1-elver@google.com>
In-Reply-To: <20210922182541.1372400-1-elver@google.com>
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 24 Sep 2021 01:39:19 +0800
Message-ID: <CABVgOSmKTAQpMzFp6vd+t=ojTPXOT+heME210cq2NA0sMML==w@mail.gmail.com>
Subject: Re: [PATCH] kfence: test: use kunit_skip() to skip tests
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Taras Madan <tarasmadan@google.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=H75LXkHa;       spf=pass
 (google.com: domain of davidgow@google.com designates 2607:f8b0:4864:20::72f
 as permitted sender) smtp.mailfrom=davidgow@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

On Thu, Sep 23, 2021 at 2:26 AM Marco Elver <elver@google.com> wrote:
>
> Use the new kunit_skip() to skip tests if requirements were not met. It
> makes it easier to see in KUnit's summary if there were skipped tests.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---

Thanks: I'm glad these features are proving useful. I've tested these
under qemu, and it works pretty well.

Certainly from the KUnit point of view, this is:
Reviewed-by: David Gow <davidgow@google.com>

(A couple of unrelated complaints about the kfence tests are that
TRACEPOINTS isn't selected by default, and that the manual
registering/unregistering of the tracepoints does break some of the
kunit tooling when several tests are built-in. That's something that
exists independently of this patch, though, and possibly requires some
KUnit changes to be fixed cleanly (kfence isn't the only thing to do
this). So not something to hold up this patch.)

Cheers,
-- David

>  mm/kfence/kfence_test.c | 14 ++++++++------
>  1 file changed, 8 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index f1690cf54199..695030c1fff8 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -32,6 +32,11 @@
>  #define arch_kfence_test_address(addr) (addr)
>  #endif
>
> +#define KFENCE_TEST_REQUIRES(test, cond) do {                  \
> +       if (!(cond))                                            \
> +               kunit_skip((test), "Test requires: " #cond);    \
> +} while (0)
> +
>  /* Report as observed from console. */
>  static struct {
>         spinlock_t lock;
> @@ -555,8 +560,7 @@ static void test_init_on_free(struct kunit *test)
>         };
>         int i;
>
> -       if (!IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON))
> -               return;
> +       KFENCE_TEST_REQUIRES(test, IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON));
>         /* Assume it hasn't been disabled on command line. */
>
>         setup_test_cache(test, size, 0, NULL);
> @@ -603,10 +607,8 @@ static void test_gfpzero(struct kunit *test)
>         char *buf1, *buf2;
>         int i;
>
> -       if (CONFIG_KFENCE_SAMPLE_INTERVAL > 100) {
> -               kunit_warn(test, "skipping ... would take too long\n");
> -               return;
> -       }
> +       /* Skip if we think it'd take too long. */
> +       KFENCE_TEST_REQUIRES(test, CONFIG_KFENCE_SAMPLE_INTERVAL <= 100);
>
>         setup_test_cache(test, size, 0, NULL);
>         buf1 = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
> --
> 2.33.0.464.g1972c5931b-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CABVgOSmKTAQpMzFp6vd%2Bt%3DojTPXOT%2BheME210cq2NA0sMML%3D%3Dw%40mail.gmail.com.
