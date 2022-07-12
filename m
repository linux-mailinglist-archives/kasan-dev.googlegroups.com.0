Return-Path: <kasan-dev+bncBC7OBJGL2MHBBFGCWWLAMGQEPOJXTOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E32B57191E
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 13:55:02 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id 79-20020a630252000000b004125da7d520sf3232614pgc.11
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jul 2022 04:55:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657626901; cv=pass;
        d=google.com; s=arc-20160816;
        b=QvtdGS+XTNlRxqSxrW4zuICumsslsT0NU12PEsCEOIysN5XI6I1DplmhoYKaaDS4Yq
         1CJV0EcZqPyJVzXiAuOhcSok+EWCEvh1QqKm9b0cDJ6caAxGAp3biDE2N/kIRQfbrtxc
         WgcES7KLaoS7VgkyUq3BENrs/9dRXz9sVz2CC1d8ICzbeQ/AgpZztmcNF5NusoeeDytA
         aatitOxVnDDwDo2uhrcED/dz157SB2UMKLAFuv8bADBO3sO8LzWU5ShjxpULmHu4eCvG
         cPVkpDApEffbUkyEbJRaoBqq0pEzqDT/R8PLGq8SMbIB44C8m19/12jx4AHqphTjlFsp
         f2JQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dSUUWfMG1jmaDmxVb32LWg2bF8PxEsLrUxr6wP8x2BM=;
        b=xrJ3BlJnoftpnDIoxhU0DtDNpNNHqUZcDmVE1+OZbLTtXAOv/s18x+DNjdjidlVhzJ
         1xQMYybZEwwhyaP826/y6i2NbQ++os+k7ZPFMEjzgOVL+DD+lmit7i5MYhbR2FPb+7w9
         BDbgjdw5tdBIsrZQLTFGJLWhDTsdNMWrJOenrJuDKRrUNIY2zR+SotRFFSiFetN96CVQ
         ujbj11PGT7INo8qNEK7mq+MXk9wQm3bKthHaJTMDrQ1fugVlzqcfA+b6FP2MQZlLEGom
         eO4bDq5Myprc51sNxA3GJRk1/F4hBXZcE994unih2y55RHLG6ZhGtj2tpIage0xqw5Ft
         R7ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mlIxG6kQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dSUUWfMG1jmaDmxVb32LWg2bF8PxEsLrUxr6wP8x2BM=;
        b=r4CRLiw3xT63lBUr/PliT+v+79PYcY9YfJenXXmR03ndGM5zlmQxudGVTrK9hlSvco
         IevGSoI9kvjRy0Mnlg1PfiWyTB87Jn0ns9XI13M0lttWExvSQz9l5my+LUne54Zdk00S
         7vnC1AE+jDsivLsMB5MCuJn8mtm3O94GXgGL7x+Xc9JM3N4g6XFRmY/yqp+0Xk/QOdjJ
         Ufq4r14EjxyS294XFlp0D3cF79WFRGddRX4sUr9y731CVQ3xLa5wMbFwMKyHy+ZifjRk
         kRxzPyAfhGAdoKoBR2Mvv6pi4RVCi5TxEWTPQ2KrnkUHXsJaKAcqyPDvinCD73U2afcG
         Y3Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dSUUWfMG1jmaDmxVb32LWg2bF8PxEsLrUxr6wP8x2BM=;
        b=KvInG/XL9klvikIHClsWnpvYFvfFrLNwZWssIkJ/cRX6ukWMjX1U61bnk1RkF/PX+V
         fna6iegMLr/YGTCxbaQpljD+SFxWeMBLYMcGXgM47cKpWCjou0Lvf0jzBmj2wupX2XJl
         ELoLpmdfJWhMZntMbbD6VHSRA8xBhLdcuxiqxUblgrQUt3Kz2RU16NnmR4y8KKWJpiar
         KG/6AbSixZyalwyeX2yF1iJq1kUgWP8dsWUDrXBk7ltEfFg60k3URxjTgL6NH06Jjq8V
         W29Q/QCEY1uwrVKl3pSXwWEPgu+MUakWTMuBGfSzHk7t6jvWnT1XLufSdhj/keMjlX+w
         6lDw==
X-Gm-Message-State: AJIora+5lIE6NKa/9q5+SwzB+VkXMMI5n3YYKTRM3n9Qw943iQZs5Rhd
	UVr1wtTLaJJixg4L90g8Czk=
X-Google-Smtp-Source: AGRyM1vLo9Yjiw3rkQWQywaAVG2DzMiEMSHTL91Qhs4kT07r4YM0/n9bRjB5g+2StvjhJOegINsYPA==
X-Received: by 2002:a17:90b:343:b0:1ef:b65d:f4d8 with SMTP id fh3-20020a17090b034300b001efb65df4d8mr3805411pjb.187.1657626900823;
        Tue, 12 Jul 2022 04:55:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:884:b0:525:23f4:c380 with SMTP id
 q4-20020a056a00088400b0052523f4c380ls1307972pfj.5.gmail; Tue, 12 Jul 2022
 04:55:00 -0700 (PDT)
X-Received: by 2002:a65:4907:0:b0:3fd:bc3e:fb0a with SMTP id p7-20020a654907000000b003fdbc3efb0amr19297292pgs.123.1657626900036;
        Tue, 12 Jul 2022 04:55:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657626900; cv=none;
        d=google.com; s=arc-20160816;
        b=kSp0rBcvOuSnR5yM4H0gSB3+zpV+dqhiHtykz8YzcWA2OVIeeQ4x5DcmFPyP3Q4SlU
         EgYc8CsLncgXnPHasrQ6aHFwMzIKOQ0xthAnOoxzuN95E1YbDbICR6ry3YU98UG8+UKk
         i5pOO5xUXrEmZjwEqQ1bmetXB2IfFMpEVcTX1zCpIfPnchKHaun+FONqRZPnvtBFvqYK
         o1q7gOPGiWo0QnJDw4STHoXCevY2UZjnrNnRo1Nzdb4ezbP0W0FyJJxUKGqhWi1shy6M
         HpiJCPpv8grYbZvpA8j84HIVAk7I+DulGIwbQ8TNeIVifCjd8+9F9uNjBykm28Nh78zF
         /5Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OUm36JXbn2cFfASaBApIenl9AkY8jJt+kU3h2jjV/Do=;
        b=dCPX2upti9PKksE4IJWZIQEvSS++uZ4udnpAnw6wVoBJtfofxwgOo5Ycfod8R0/Wl7
         7J/5Ra0kEV4Sx0s+YzmZ6evxyYviUf10jSOg60WgV4IPaqqMRILBRZt3wxYFCHNLlGv3
         lZzQzC65UWzZUx3rJwBs8xZv9bWL/SGQIJAsfXfUS+3kUKIuDg1+ClA95HrMvsjkfAhe
         t3L9AWVSpClOfdOFd6BcyU8JN2n0I/Jlfq63YCmjnD43cgkAo2lwI1sIPK0rE2I2ifD3
         6BmqmYIiqLrLXaTNvojdz9v0dPLCcC7ayck1qvcE11CHebCDPkY3TfcQg52gLm+Sbay6
         hJ/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mlIxG6kQ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id l19-20020a170902f69300b0016c28083b2bsi212021plg.6.2022.07.12.04.55.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jul 2022 04:55:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id 6so13514697ybc.8
        for <kasan-dev@googlegroups.com>; Tue, 12 Jul 2022 04:54:59 -0700 (PDT)
X-Received: by 2002:a25:2d59:0:b0:66e:32d3:7653 with SMTP id
 s25-20020a252d59000000b0066e32d37653mr21902834ybe.625.1657626899153; Tue, 12
 Jul 2022 04:54:59 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-13-glider@google.com>
In-Reply-To: <20220701142310.2188015-13-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jul 2022 13:54:23 +0200
Message-ID: <CANpmjNMjAzYtTOkc7m2j1qypjU6zYigKHwAcrHOJpRu0HCbKQA@mail.gmail.com>
Subject: Re: [PATCH v4 12/45] kmsan: disable instrumentation of unsupported
 common kernel code
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mlIxG6kQ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 1 Jul 2022 at 16:23, Alexander Potapenko <glider@google.com> wrote:
>
> EFI stub cannot be linked with KMSAN runtime, so we disable
> instrumentation for it.
>
> Instrumenting kcov, stackdepot or lockdep leads to infinite recursion
> caused by instrumentation hooks calling instrumented code again.
>
> This patch was previously part of "kmsan: disable KMSAN instrumentation
> for certain kernel parts", but was split away per Mark Rutland's
> request.

The "This patch..." paragraph feels out of place, and feels like it
should be part of a v4 changelog below ---.

> Signed-off-by: Alexander Potapenko <glider@google.com>

Otherwise,

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Link: https://linux-review.googlesource.com/id/I41ae706bd3474f074f6a870bfc3f0f90e9c720f7
> ---
>  drivers/firmware/efi/libstub/Makefile | 1 +
>  kernel/Makefile                       | 1 +
>  kernel/locking/Makefile               | 3 ++-
>  lib/Makefile                          | 1 +
>  4 files changed, 5 insertions(+), 1 deletion(-)
>
> diff --git a/drivers/firmware/efi/libstub/Makefile b/drivers/firmware/efi/libstub/Makefile
> index d0537573501e9..81432d0c904b1 100644
> --- a/drivers/firmware/efi/libstub/Makefile
> +++ b/drivers/firmware/efi/libstub/Makefile
> @@ -46,6 +46,7 @@ GCOV_PROFILE                  := n
>  # Sanitizer runtimes are unavailable and cannot be linked here.
>  KASAN_SANITIZE                 := n
>  KCSAN_SANITIZE                 := n
> +KMSAN_SANITIZE                 := n
>  UBSAN_SANITIZE                 := n
>  OBJECT_FILES_NON_STANDARD      := y
>
> diff --git a/kernel/Makefile b/kernel/Makefile
> index a7e1f49ab2b3b..e47f0526c987f 100644
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -38,6 +38,7 @@ KCOV_INSTRUMENT_kcov.o := n
>  KASAN_SANITIZE_kcov.o := n
>  KCSAN_SANITIZE_kcov.o := n
>  UBSAN_SANITIZE_kcov.o := n
> +KMSAN_SANITIZE_kcov.o := n
>  CFLAGS_kcov.o := $(call cc-option, -fno-conserve-stack) -fno-stack-protector
>
>  # Don't instrument error handlers
> diff --git a/kernel/locking/Makefile b/kernel/locking/Makefile
> index d51cabf28f382..ea925731fa40f 100644
> --- a/kernel/locking/Makefile
> +++ b/kernel/locking/Makefile
> @@ -5,8 +5,9 @@ KCOV_INSTRUMENT         := n
>
>  obj-y += mutex.o semaphore.o rwsem.o percpu-rwsem.o
>
> -# Avoid recursion lockdep -> KCSAN -> ... -> lockdep.
> +# Avoid recursion lockdep -> sanitizer -> ... -> lockdep.
>  KCSAN_SANITIZE_lockdep.o := n
> +KMSAN_SANITIZE_lockdep.o := n
>
>  ifdef CONFIG_FUNCTION_TRACER
>  CFLAGS_REMOVE_lockdep.o = $(CC_FLAGS_FTRACE)
> diff --git a/lib/Makefile b/lib/Makefile
> index f99bf61f8bbc6..5056769d00bb6 100644
> --- a/lib/Makefile
> +++ b/lib/Makefile
> @@ -272,6 +272,7 @@ obj-$(CONFIG_POLYNOMIAL) += polynomial.o
>  CFLAGS_stackdepot.o += -fno-builtin
>  obj-$(CONFIG_STACKDEPOT) += stackdepot.o
>  KASAN_SANITIZE_stackdepot.o := n
> +KMSAN_SANITIZE_stackdepot.o := n
>  KCOV_INSTRUMENT_stackdepot.o := n
>
>  obj-$(CONFIG_REF_TRACKER) += ref_tracker.o
> --
> 2.37.0.rc0.161.g10f37bed90-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMjAzYtTOkc7m2j1qypjU6zYigKHwAcrHOJpRu0HCbKQA%40mail.gmail.com.
