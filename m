Return-Path: <kasan-dev+bncBCA2BG6MWAHBBAE75HZQKGQE4L2P4BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id 8DFA71918D0
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 19:20:49 +0100 (CET)
Received: by mail-vk1-xa40.google.com with SMTP id r201sf4342503vkf.5
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Mar 2020 11:20:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585074048; cv=pass;
        d=google.com; s=arc-20160816;
        b=o+ZavtpjMtQCTWPfcZqKq8pLxdlxokIYcYXycnXePZVCoC4LYKX57XfbMyShARnERF
         oYwrfWG5UmvPjhktkLLjDm5xkFroROVQJey4csHmx7J2UMdL6AWZMdLriFP3q69/YkXV
         X9EW4oAZwV0IodM2+DrIE7SBN4FqyWIR8l5Ctx2gMxRIzB7Wr4v/9+8VjdoZ+ZFGapKg
         zffE+2AdOIvy9QRDbhFPw7l7nKMBfBv3vG6MHr/ZIbQ7pWmobt+jajPaNRaPR0Q+XGvC
         5IMy1QSEz1U1YEuM3lYqvSYO4WGUjJeEqg/GLQdqyVv1T0MhIrFps1c5GPzbaljKbk/x
         VJNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nar9iSFeI0YMVqE5dnJjF/g0kO1EBfs2gcswWHKFcbI=;
        b=Cp8E13ZnU+NKLuvD2hZo0UjQcG4YjPVQ0FilIQJnULw4f6wqwz7ty7f9UsmeAqfrH3
         Ihw74YLoQ+aXFRXHirdhwA5vNQ6fZcM57zUZ2Ug2bzu+eGmbJjt6TfY/AgAuNt8ss6Rd
         ovSSk9UIF6Icu4NbUEIbLUza9gUfI9YWPprASEFjgl9Gh0c5ApXG9x3C0W4wI68g7nFG
         9iIgq4xrSo4Gerk0hB8oHJd8+7STa2JwHrcGPNXG5dFrau1YMluNQ89UDVjQX8hpORI2
         xGQof0lvBPqScl9/Os6kuYGZbSWiJtmEIwfnw7bEE42JG2QGrLlD1kz7oTMa9W4Fdebq
         nbkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qb4Qiodo;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nar9iSFeI0YMVqE5dnJjF/g0kO1EBfs2gcswWHKFcbI=;
        b=A7xoBt9f45NjiXHDeceuB9ZbjeCeNUDOc7bl3j5MqsH3p+ByLE+6pyT8ePEAdPJFTT
         Zhfzd0IXSuJS514BlNEbdK88m67GQK8dmm9Uqj75kDEovgv3XfubJfDwqhSZes00i4qv
         zOZ/DPX/v+HtYunqAH0BEcpcSbRtOnDMCLOe4qWBXU++GanQUJIPPDE3xaQuF/EFjuPr
         TAozfPvqkb+ZSQs68Sxt1Zxp4J2OPMppG204V/Bs4j0e2qyZBvHmCZsq3L4wK+FUVzDF
         qwZ3PKIsBY/aF6owJRgUSlN7Ze6tXweipiQnQNrRccgIJOXVJn4kYEISzX5svFsS18v7
         Z8pA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nar9iSFeI0YMVqE5dnJjF/g0kO1EBfs2gcswWHKFcbI=;
        b=L+y24iXuPGGpONI8OOlnP4sT3Mla4775lBxrKuup7LasuWkPP8RHqJzd1rk4BcdSpj
         Yu1fuf9s8LLn+y0pxCmvJraj5yl9pN8pYXpVIsmj7iCqCydhFC/UVCMmIZbAdEjGqKe7
         LlPmdmALk95jbFee+vZ4JmCNPi4FktcfC0JiRZs49ZmYMEARam0Px5D5eVqR1OKN3pqe
         ZD7ZK0ajUEAbEsdqIlkYtv90wSNUpyUe3E+M3uhMkP211Yph+zGv1nctkxoFP1vZS+h+
         JyManU7I2k2jpK9Jg8t7BolwN+pGESCcc6HHyfdWUigte+ve8IpKxJbvFoyiLpedspOQ
         4A3A==
X-Gm-Message-State: ANhLgQ0sqcqMt86uEU/YR0BetdFzuQo3AunGDWP59cYLMPzlcCspxuLD
	EKnKPgyhKmVvIH/Og8OCRiE=
X-Google-Smtp-Source: ADFU+vvAkZCKK65ubDQ9yZezPAxkwwSastzHrEaXJ0AyaQgYNe2R6sV1/0zhuOovm10iTxIX8y2ybw==
X-Received: by 2002:a1f:5cc4:: with SMTP id q187mr14325072vkb.85.1585074048609;
        Tue, 24 Mar 2020 11:20:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:a989:: with SMTP id s131ls1001350vke.4.gmail; Tue, 24
 Mar 2020 11:20:48 -0700 (PDT)
X-Received: by 2002:a1f:a452:: with SMTP id n79mr19890903vke.36.1585074048251;
        Tue, 24 Mar 2020 11:20:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585074048; cv=none;
        d=google.com; s=arc-20160816;
        b=WFoiBT2ZJMYKt/2QH+G9okyqxUTdH1HxTFRK54upCoqRdBU92fu7t2iV2Jxfgt4Git
         vO6FWn13ozh1TqWL+6kskkZtepM8ONWkPLOb1ceP4hjaWGPNrQwNLl29eq1YQIXsffI3
         1ZGgLP6pkdFEkRyLUvlvLKV5JQsmLSV0siPmA5KUm9ZhJen9lKFDpTvm8XvtzRA6yEmm
         XFcsTqO44Y3p0+Y+Ne0s23nM36K5SdQdfSXGs0corbe1aeAeLeIPucIieZCnw43uEp0o
         6e3Jja25klThb4E4QvBfo9EPsQYUq5D+0rNkh/CCOPka/uYhDTCwD4Jb4w2trn1E0WiC
         YItg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G7TBBxwNpvZEgu2P5vS45mLuMGm5bXW06PLHgtTqssI=;
        b=NiGoFdqoE6wV4EuoCksmuNK+rkc8A9YsEWl4BLnBcksKDIlHyxKrGl4wyxhB6jRp7J
         Bidt+dfvHTjMUQkUaDv7jXr/Vsbf+GS4pyOivFSYW2A1NW4jZ0qKF8M5HRUs2x6L2FlI
         j9hoBgxwnS0A6CwGFH7DP3bTignVYvD+flJxISdLgLwEOgKh0Ij/wUmYEm2KsG6egSwR
         O1Aw1jbdL2dcu7o93vTlXfvXwfAGYwpKaQdgiCUylmAMqn8VBHepPxtbdnXzEi/qcjpr
         Vydtik3n2dHm/bP6a5UVQJGctKAWXNRnoqRyHubNbr2HEpD9Cblf/jRGCzsj187d6UsK
         x+RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qb4Qiodo;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id v5si596106vsl.0.2020.03.24.11.20.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Mar 2020 11:20:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id a23so7756684plm.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Mar 2020 11:20:48 -0700 (PDT)
X-Received: by 2002:a17:90a:30c3:: with SMTP id h61mr6876474pjb.18.1585074047136;
 Tue, 24 Mar 2020 11:20:47 -0700 (PDT)
MIME-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com> <20200319164227.87419-4-trishalfonso@google.com>
In-Reply-To: <20200319164227.87419-4-trishalfonso@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Mar 2020 11:20:36 -0700
Message-ID: <CAFd5g47jJ0f+NFDBXK5gTqbx4-UiyJ9xfZaRW1qzZ_6AcGKC+Q@mail.gmail.com>
Subject: Re: [RFC PATCH v2 3/3] KASAN: Port KASAN Tests to KUnit
To: Patricia Alfonso <trishalfonso@google.com>
Cc: David Gow <davidgow@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Qb4Qiodo;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Thu, Mar 19, 2020 at 9:42 AM Patricia Alfonso
<trishalfonso@google.com> wrote:
>
> Transfer all previous tests for KASAN to KUnit so they can be run
> more easily. Using kunit_tool, developers can run these tests with their
> other KUnit tests and see "pass" or "fail" with the appropriate KASAN
> report instead of needing to parse each KASAN report to test KASAN
> functionalities. All KASAN reports are still printed to dmesg.
>
> Stack tests do not work in UML so those tests are protected inside an
> "#if IS_ENABLED(CONFIG_KASAN_STACK)" so this only runs if stack
> instrumentation is enabled.
>
> copy_user_test cannot be run in KUnit so there is a separate test file
> for those tests, which can be run as before as a module.
>
> Signed-off-by: Patricia Alfonso <trishalfonso@google.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g47jJ0f%2BNFDBXK5gTqbx4-UiyJ9xfZaRW1qzZ_6AcGKC%2BQ%40mail.gmail.com.
