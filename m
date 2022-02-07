Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBH5DQ2IAMGQE3ZZVQCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 979F54ACB67
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 22:39:43 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id v2-20020adfa1c2000000b001e31fe03e3csf1278563wrv.4
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 13:39:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644269983; cv=pass;
        d=google.com; s=arc-20160816;
        b=A5E683HHev8znNDjHJsFjERWM480gcqrLIMn5UoO15HYlYoSRK43EfN4gvsTqKSDiH
         UBjYfMQQV2uy1WSAmmVbdHBQiP4q1L2e46FGVzzz8dE4vdvReSVB3MH7W3NnFB4kf92o
         F5sm6uDMhMdPVoBxJMlkGemCiO071tW4KLZ48evamrbJZU0megZ7TwFGcFYZjNZFg0Vm
         pdNtoy1rl1vz1EYqKcfcYvX1KptQRJg8515mnRke9zURDaSnhdZadCfAw8J12hxUrGTN
         t2vEZv6fM/2eRuJkAC+SIXBehmGR8QTloPvwkCscHn0/+vl3hvsU/H203L8i9qhan5BA
         g3bA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1Lt3DSFbRmzgDYWu4WHihi5PZWuglZt5Ds6P70o7dM0=;
        b=HC81S2RI8iwcktHHeXgwDKzKVGRK8ky37QZHCS1VyPl7Ufs70nC3xvQ9nC7cFtRJ90
         Z+Pj7/gLkyrxMcRdnz8ydVBwWwYhaBFmPuPnCxx9M7AZ1+Ai419ToCO1nOckDel/YP22
         YJmVQ5TcYAcNomhIJko3orBR3jXbpI4rSgmiB518jYjt3zFgKHMKxlwLANPAAeCumNW2
         BjGiR/ds4MxcHGKEJ2NtD6OyOjiSzdfrAyixkc1l+I4cAJmshgx2sSWjMwdUK9WU2mSH
         RXpStowXIE7Hf2HtMpURBGAxc3LKEDWT3lfazdadOSLkzq8y6voFh2DX0StRLOUhYHt/
         BbFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Oq62eM9Q;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Lt3DSFbRmzgDYWu4WHihi5PZWuglZt5Ds6P70o7dM0=;
        b=fH5YqtRKe8Fa07l9YZFToe30rc8FXKfDMnta9t2g4XJ8/rHIts3CsMhEJEx5YaSELr
         sbxXbW6CbjJuWh/qlSYhNwFcfiDHjt8ap+EH/mxKhpu+1J1gCoE8uaTMERfFd6YYtvqV
         64vjKsDrCyiQ5TsUL/Rbv+QY+RK2ARI46D8MwYRoqloPRdMFAFQG4Rgh6dihlFE1XtDT
         3FEswxaYg7Kuocrgp0eD92+i68qfdchWmhjrCBDP3uCv57pY0M2qXyi9IrIE6PFK/Uy3
         FsO/HkVV3LC8absUHmyXJb+EbSHf+gyHv4V8QbeepuFyda6TO3NJ1g1evY7OLWR7I6xO
         cAdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Lt3DSFbRmzgDYWu4WHihi5PZWuglZt5Ds6P70o7dM0=;
        b=hf+hAH2geBYlzK2sd8wI9ZB3GoZwLI+0ozy7Jy1v9QVE3pudxPAabyNo4GtN3Euwck
         mYsAFNCqXbXILBt7h6V4YkwcdS22GsExtThGCo3y6yMUFJP0TvJPPOQmbRhOIZ5CKTY6
         EGXDHDIUiR4OQ0QfBt7J6c/aZ7L0YpouvLTBEkq2EZWCTz2JxMPMPcx/bsmphHCRLDW7
         EcmYk94lPL8ISFii5hqB6e5bdDa4VSblqnEumqRG5BCpCnhOADQaTNNGHsoqb7BI7DUL
         gprGmY/FLh9Lw1Wc/lzopmzf46MLmA7B90jCNwRMCi89ColE7WLtz03tAE1hooaZEN7O
         l/mg==
X-Gm-Message-State: AOAM531iTjfA7r7T0+oaTpsqL1Y8q8S8z5AkhvuBd0MwmRo6mWHQjYZ3
	4dDjxfPO62OWnOY5TrVIjWM=
X-Google-Smtp-Source: ABdhPJzPYQCNY1oUNNM7zlJgdGznQeJUPIM6vd3kA9IJEyIxk29uiroRbN41bFHSiA+7x8UrGhmqeg==
X-Received: by 2002:a5d:404f:: with SMTP id w15mr1106639wrp.404.1644269983398;
        Mon, 07 Feb 2022 13:39:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3c9f:: with SMTP id bg31ls223687wmb.1.canary-gmail;
 Mon, 07 Feb 2022 13:39:42 -0800 (PST)
X-Received: by 2002:a05:600c:1e8b:: with SMTP id be11mr679555wmb.96.1644269982586;
        Mon, 07 Feb 2022 13:39:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644269982; cv=none;
        d=google.com; s=arc-20160816;
        b=CC2kbqTXcoi39KxiFhmVdfzKqujVA5GXSw1DCeqHBKbprN9nvfy8CEjDy4/QoyrJOb
         Ww6RmDKAJvfqIKLhrbBQW6iHVZsXHem9X+KGzz9jAIgp3pxxZYSCaIEjOYxkt1ywfgC1
         nCuxtHoGNrQJ89v6jyMiVrwM4tr8cSQ+hm03luHeAVEn4cs9Y4+eRBv48SjReioi+tzn
         BByu5EZ75+4ZMGD2i2dpwlx6vQ04MzBjr8Mcxreh48v+xJkV1wwNHRlzhC8LZom698F7
         G/OVtDPnEj4cJHpCyecf8NfSZLkgtho/UjIpGHvAJnDqKEwJy5MbQIv47hk+e67B7Cv+
         wGtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JkUXjUfONMEakOKrSs8qeEQ8fO3Su2ebpIj8MlZJxVE=;
        b=xkGrHAsy+8iqQxBb34p9b6dM78xO5NdLG6kurp9klGE+NszxGdTfYNOiGZfKpNTMx5
         C/auVLV1MzM9AfY3EvD5cxzpu0GdPYuAFQ+J/GpLgFh5p3moIsdZRoldvAHCgDHux7vx
         rIQJ67w34ihIiP6PT3CQvqtyLwQ+xVJ/W2fuVubs/bOP5kCZ9HMM1d0sgJD7zfSScegL
         FGpAiJm7BBqrhr4O+g+Op77DS5LUpGoZeqiKyt4UaBQl4+ggyc+HQgHnLwJKZg7M4eJ9
         B2fC4zKvyKb4ONBSC9SN4S81Vq8K824ENbQdbIcGt86eRawSWevOUkrhh3XfL6D1miTt
         /Kxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Oq62eM9Q;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::536 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x536.google.com (mail-ed1-x536.google.com. [2a00:1450:4864:20::536])
        by gmr-mx.google.com with ESMTPS id e5si583193wrj.8.2022.02.07.13.39.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 13:39:42 -0800 (PST)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::536 as permitted sender) client-ip=2a00:1450:4864:20::536;
Received: by mail-ed1-x536.google.com with SMTP id da4so11080292edb.4
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 13:39:42 -0800 (PST)
X-Received: by 2002:a05:6402:34d3:: with SMTP id w19mr1422514edc.377.1644269982031;
 Mon, 07 Feb 2022 13:39:42 -0800 (PST)
MIME-Version: 1.0
References: <20220207211144.1948690-1-ribalda@chromium.org> <20220207211144.1948690-2-ribalda@chromium.org>
In-Reply-To: <20220207211144.1948690-2-ribalda@chromium.org>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 13:39:30 -0800
Message-ID: <CAGS_qxo5d5uTcHfG6qxtQjzCkkHfEOKMjgO75bk_WNb6JyYutA@mail.gmail.com>
Subject: Re: [PATCH v3 2/6] kunit: use NULL macros
To: Ricardo Ribalda <ribalda@chromium.org>
Cc: kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, Brendan Higgins <brendanhiggins@google.com>, 
	Mika Westerberg <mika.westerberg@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Oq62eM9Q;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::536
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Mon, Feb 7, 2022 at 1:11 PM Ricardo Ribalda <ribalda@chromium.org> wrote:
>
> Replace the NULL checks with the more specific and idiomatic NULL macros.
>
> Signed-off-by: Ricardo Ribalda <ribalda@chromium.org>

Reviewed-by: Daniel Latypov <dlatypov@google.com>

LGTM, thanks!
(This will still need Brendan's RB to go in)

> ---
>  lib/kunit/kunit-example-test.c | 2 ++
>  lib/kunit/kunit-test.c         | 2 +-
>  2 files changed, 3 insertions(+), 1 deletion(-)
>
> diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
> index 4bbf37c04eba..91b1df7f59ed 100644
> --- a/lib/kunit/kunit-example-test.c
> +++ b/lib/kunit/kunit-example-test.c
> @@ -91,6 +91,8 @@ static void example_all_expect_macros_test(struct kunit *test)
>         KUNIT_EXPECT_NOT_ERR_OR_NULL(test, test);
>         KUNIT_EXPECT_PTR_EQ(test, NULL, NULL);
>         KUNIT_EXPECT_PTR_NE(test, test, NULL);
> +       KUNIT_EXPECT_NULL(test, NULL);
> +       KUNIT_EXPECT_NOT_NULL(test, test);
>
>         /* String assertions */
>         KUNIT_EXPECT_STREQ(test, "hi", "hi");
> diff --git a/lib/kunit/kunit-test.c b/lib/kunit/kunit-test.c
> index 555601d17f79..8e2fe083a549 100644
> --- a/lib/kunit/kunit-test.c
> +++ b/lib/kunit/kunit-test.c
> @@ -435,7 +435,7 @@ static void kunit_log_test(struct kunit *test)
>         KUNIT_EXPECT_NOT_ERR_OR_NULL(test,
>                                      strstr(suite.log, "along with this."));
>  #else
> -       KUNIT_EXPECT_PTR_EQ(test, test->log, (char *)NULL);
> +       KUNIT_EXPECT_NULL(test, test->log);
>  #endif
>  }
>
> --
> 2.35.0.263.gb82422642f-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxo5d5uTcHfG6qxtQjzCkkHfEOKMjgO75bk_WNb6JyYutA%40mail.gmail.com.
