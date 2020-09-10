Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPXI5D5AKGQE2RQ3XAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 777112647C6
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 16:12:16 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id 82sf4502100pfz.20
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 07:12:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599747135; cv=pass;
        d=google.com; s=arc-20160816;
        b=VYqc3lXeeaVZ2Sal9wNDKHnuB+pp5+y5m5Ry3S+5U1qnD7jvF0ALfGsdov48X6dFBU
         VVWyI9m7dhY/vzDxgEmdECNVPW2XmVLx2KGyiiR0oFQgkh/9kk0XYpBxC08GvUNAoXkF
         KGdWT7OHWdeCYPE07sZH2p6Jn81IyaM7YCSAt1QRHVU99o3M/NqNJBkrYSrA44MWzN2f
         Se65RsAxMMMa16snkY60RJf63l9j8YhBk3TTtiSQhXPyOrMzkg6M9Prd5KNEaDlpD5Ff
         k3qSi1ZnDcflwk8Rc8rC/6I92I4J11q0WqSXrq7gWJcOzqZmwHSMnAwkltqhMEuh+9zz
         r4tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7LaZMOY4cZNOAfv5lUzyV5AiefQir+VmKc52YBoxGWI=;
        b=ItCLLDHee17Htm8OCw7zC+Z3i5hvUykLEZoQm5+MGOjm11MBA9US1LInY5YHA10o+Q
         BwCoSOYPe3WL8TfFLfuflTq+IGjNfWQ6RnIs4pffjoU+TuE1ZvgxAwYTQLNR1/kVL9Te
         cgGqV0h3nIJutUdRNgFALPKuslqG1JB1ZqqbetX5VJ1WTWghJFM24EynhzMJjbyGTFNk
         b3idc4XiqDyfohyXHDZyc1lACecsLcfjEYmRZi0EMA/4Ueg3OouuoeMVViN+dTPpUrI/
         eeLoC5M/RSLqiQn8A/CnJA890yTY6M1gycUTkeTsY4lQgCKaEKvNJT7soDm/euVMf4BY
         HOaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="c/e5qR7L";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7LaZMOY4cZNOAfv5lUzyV5AiefQir+VmKc52YBoxGWI=;
        b=ASpyYOaRt2d5HS61cUYsUXyw/orxX2TxETEsnWOsq8D7L82sRg15KoWnizPgjnucjb
         kSsOqL5JaYCYoYcoExNq0kYOYBUvBDkeMuQiMrq/PDuotmrj8TA2qmjo3qcWwvukZFE4
         XMEJymtWBS3uE9xmQWSxFd2LBRQ9qPUlZ6YtsWDyGsmh6dmQ31v76C3RM8HJUhHWGOBB
         SGqcsYkdwuQDd2HMvIn6a3ON8Pm3VRUUCIpyPWNrB9hQmyyXaao41RO2mLyJEZf1bVPr
         ZfOBRAgYCARWCqYWLSMrVk65eTmmhCH8HneA+BcxYJVdowX2nwmwV9bm+BO9wDaP6Gbh
         ySfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7LaZMOY4cZNOAfv5lUzyV5AiefQir+VmKc52YBoxGWI=;
        b=FE+jqdOTuGVCb1Ups1WC1/z8JoI7IHBs80f5ND+ktTYlKZlGYpby8Tfe17ppwy1oBR
         dDF10oBwhFeiwNDrit9jYzw728lbor+ByNtWIKHQRT4C682ybgE2XHrUeaQzsBZfuJ4M
         MnrT/Fc21zCeiW5wpQwSIVC9u05iEhZzy65GzBJPiBhv4PAlsQfCf0oK63E+Ypl42DCz
         aHEAfsMElgh/AvVMEZoyb3CqZj0k0EaM15TBbIp2yQbNuJa5O8Y0TiKuAsrE2qK/Q+sy
         tEs66a7A8tWxwMB2elP8SRooeEsN3rIIvv0T6HhfU/CtqJTomg7I43VNJmLlWvcQTKkw
         KSjw==
X-Gm-Message-State: AOAM5301ldxCh5/8n7b5VwNP7vA4M/0YoJ5zL01QkaloVP1ZMKVHw0Oh
	yarHo1vXOBydVniC6hRkSrA=
X-Google-Smtp-Source: ABdhPJya+QUxwDEv6L/KWzOXOgTF83aDvAWdKEVFwptbRFvD0FWdJkxLDEU7TqGDWAA/nIDhdU+mrw==
X-Received: by 2002:aa7:911a:0:b029:13e:d13d:a13d with SMTP id 26-20020aa7911a0000b029013ed13da13dmr5653523pfh.37.1599747135116;
        Thu, 10 Sep 2020 07:12:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4bca:: with SMTP id p10ls795636pgr.5.gmail; Thu, 10 Sep
 2020 07:12:14 -0700 (PDT)
X-Received: by 2002:a62:7616:: with SMTP id r22mr5733097pfc.48.1599747134406;
        Thu, 10 Sep 2020 07:12:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599747134; cv=none;
        d=google.com; s=arc-20160816;
        b=uV06k+37ZRYT3sJjn61GL6j9yWYMUhyTRRmzTk2AbkDX2KL2CvLJrrN9lwzlttCyf8
         5B8emO/OA1QOJn9+VCbWo+7EQUyNg/ciDYNhU1bRA5ky+PjQiTby5i0AcWdBCE+yJ4Oc
         WToxtn4IC0TapluLgfbRBaG9elQSGKQk3W2wzWs/smCX9VvUFlpOdtLvstd3VWnPYdHq
         YXBOD08pXUpcPxZFCu0kZaGJvcDk18cP7d222sVdVGa3DurRTKB07ueM5dnflmzT4/fe
         KvF7VQ1ggpZnwbNzVy6zD9YRRgcMSXt01y+frhzB9DLe5kYAXYfFsuZRs83v8QJghA8T
         pMTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kcGVZn8a+TssCx5V7/oWyKJ/qM6HLG6mmAZ+V9sySx8=;
        b=TGjT9vwk2UzpQm+QUkRurFnNJRKzt0Ut2Nk2bIF3tCWv3CDI+YvbE5wVIMSg6HRn1G
         eTFAJw0funNqSoCSIo2AKTyw5Z08JgzpZyGXh0wNEY/us3ni3kTCLXe1xFfGda0Jjq3d
         APHSEltscra+XA/HTGRxa3eSrX3giCl815gsQRQgbvo265nWELvjZ7ycvkstHN+m+j99
         3RadDY3auxyjhzF5Qv+UbPt8C9ZrlM1ydAlUD+tw43WPEMdOE+obmWvJfCRvullnMRuf
         bqog7UkhxUInDvQ4c4b5v5uNENmWKo2bMkXDZqunWlXx2IV/44HTQgJYybFIHJZPMgB8
         BRGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="c/e5qR7L";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id lx5si87549pjb.2.2020.09.10.07.12.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 07:12:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id 60so5458871otw.3
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 07:12:14 -0700 (PDT)
X-Received: by 2002:a9d:3da1:: with SMTP id l30mr4255115otc.233.1599747133357;
 Thu, 10 Sep 2020 07:12:13 -0700 (PDT)
MIME-Version: 1.0
References: <20200910134429.3525408-1-masahiroy@kernel.org> <20200910134429.3525408-2-masahiroy@kernel.org>
In-Reply-To: <20200910134429.3525408-2-masahiroy@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Sep 2020 16:12:01 +0200
Message-ID: <CANpmjNOcpNLe3T-Qf1gVkqxpLCPQ+yjJZ0wM79jCUrmet_QH0Q@mail.gmail.com>
Subject: Re: [PATCH 2/2] kbuild: move CFLAGS_{KASAN,UBSAN,KCSAN} exports to
 relevant Makefiles
To: Masahiro Yamada <masahiroy@kernel.org>
Cc: Linux Kbuild mailing list <linux-kbuild@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Michal Marek <michal.lkml@markovi.net>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="c/e5qR7L";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Thu, 10 Sep 2020 at 15:45, Masahiro Yamada <masahiroy@kernel.org> wrote:
>
> Move CFLAGS_KASAN*, CFLAGS_UBSAN, CFLAGS_KCSAN to Makefile.kasan,
> Makefile.ubsan, Makefile.kcsan, respectively.
>
> This commit also avoids the same -fsanitize=* flags being added to
> CFLAGS_UBSAN multiple times.
>
> Prior to this commit, the ubsan flags were appended by the '+='
> operator, without any initialization. Some build targets such as
> 'make bindeb-pkg' recurses to the top Makefile, and ended up with
> adding the same flags to CFLAGS_UBSAN twice.
>
> Clear CFLAGS_UBSAN with ':=' to make it a simply expanded variable.
> This is better than a recursively expanded variable, which evaluates
> $(call cc-option, ...) multiple times before Kbuild starts descending
> to subdirectories.
>
> Signed-off-by: Masahiro Yamada <masahiroy@kernel.org>
> ---
>
>  Makefile               | 1 -
>  scripts/Makefile.kasan | 2 ++
>  scripts/Makefile.kcsan | 2 +-
>  scripts/Makefile.ubsan | 3 +++
>  4 files changed, 6 insertions(+), 2 deletions(-)
>
> diff --git a/Makefile b/Makefile
> index ec2330ce0fc5..4b5a305e30d2 100644
> --- a/Makefile
> +++ b/Makefile
> @@ -517,7 +517,6 @@ export KBUILD_HOSTCXXFLAGS KBUILD_HOSTLDFLAGS KBUILD_HOSTLDLIBS LDFLAGS_MODULE
>
>  export KBUILD_CPPFLAGS NOSTDINC_FLAGS LINUXINCLUDE OBJCOPYFLAGS KBUILD_LDFLAGS
>  export KBUILD_CFLAGS CFLAGS_KERNEL CFLAGS_MODULE
> -export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE CFLAGS_UBSAN CFLAGS_KCSAN
>  export KBUILD_AFLAGS AFLAGS_KERNEL AFLAGS_MODULE
>  export KBUILD_AFLAGS_MODULE KBUILD_CFLAGS_MODULE KBUILD_LDFLAGS_MODULE
>  export KBUILD_AFLAGS_KERNEL KBUILD_CFLAGS_KERNEL
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 1532f1a41a8f..1e000cc2e7b4 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -47,3 +47,5 @@ CFLAGS_KASAN := -fsanitize=kernel-hwaddress \
>                 $(instrumentation_flags)
>
>  endif # CONFIG_KASAN_SW_TAGS
> +
> +export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
> diff --git a/scripts/Makefile.kcsan b/scripts/Makefile.kcsan
> index c50f27b3ac56..cec50d74e0d0 100644
> --- a/scripts/Makefile.kcsan
> +++ b/scripts/Makefile.kcsan
> @@ -9,7 +9,7 @@ endif
>
>  # Keep most options here optional, to allow enabling more compilers if absence
>  # of some options does not break KCSAN nor causes false positive reports.
> -CFLAGS_KCSAN := -fsanitize=thread \
> +export CFLAGS_KCSAN := -fsanitize=thread \
>         $(call cc-option,$(call cc-param,tsan-instrument-func-entry-exit=0) -fno-optimize-sibling-calls) \
>         $(call cc-option,$(call cc-param,tsan-instrument-read-before-write=1)) \
>         $(call cc-param,tsan-distinguish-volatile=1)

This doesn't apply to -next, which has some KCSAN changes for the next
merge window. Although it seems git-merge figures out the resolution
for the conflict automatically.

Other than that,

Acked-by: Marco Elver <elver@google.com>

Thank you!

> diff --git a/scripts/Makefile.ubsan b/scripts/Makefile.ubsan
> index 27348029b2b8..c661484ee01f 100644
> --- a/scripts/Makefile.ubsan
> +++ b/scripts/Makefile.ubsan
> @@ -1,4 +1,7 @@
>  # SPDX-License-Identifier: GPL-2.0
> +
> +export CFLAGS_UBSAN :=
> +
>  ifdef CONFIG_UBSAN_ALIGNMENT
>        CFLAGS_UBSAN += $(call cc-option, -fsanitize=alignment)
>  endif
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOcpNLe3T-Qf1gVkqxpLCPQ%2ByjJZ0wM79jCUrmet_QH0Q%40mail.gmail.com.
