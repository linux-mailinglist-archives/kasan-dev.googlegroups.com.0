Return-Path: <kasan-dev+bncBC7OBJGL2MHBBINF534QKGQE7RIYD3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A24A2480B7
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 10:34:42 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id j13sf4546500uaq.3
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 01:34:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597739681; cv=pass;
        d=google.com; s=arc-20160816;
        b=iRcWF/m6EokHC6bswPlVBqzJnAAglJuWNCjLI9a7fDPm02UYy9niojpoMlEnmkiS8j
         SxKOBdInHRNY7YPs4DjBC5t6jmzZACVwox215OAFmChknkhX6sNn5mVfWLCLm4ef3C3a
         IRMpV3MFcvh64tVbECEbo1ddNaTUrDPATYVs8Sl+ex/OnxcmWpxqnjK7c1YaDPEqtkv5
         M/7tBS0rAM/UqQAUPHJ79vojs4dxaysMqOnySkxVafW6J+5a5IkBFqNgZYxmtCXKYFMF
         LKn6lKVb5PgnbY5GcLik8Wj32rhc++1PHJABplrdLiHScU2/uZdwmaIrcfHNb/ZkWIhm
         hLHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=C8eSHWZViSwiuVM+9o9vwCpTfAU0KUy82i7bIFe9tNo=;
        b=B3msna4d5PFD8fPe+GWkPbzvBOh8X7OoQzHp040VaubNe2uDvBSGvE8g4kmQdfbumI
         xYWxt3O4TdSI3C5xZznoS9t2swk2uklUoD9pSLtyBaDD0SpNl52iZVn91DyjZGZIhrCT
         r6znrFDVZJM/UBikC98s1mVaPWg2qFykj6DtbMX5iHMkLOMNsCfcf/fMTh687ZDrr7eN
         HdsnjUXWlz64+6+B1oY8d2G3ETpKMAkyXwUX2PiFC7phRbSBR6WfCDA/WfEh4Jd7cbJA
         B4/LqMeYDMr8vJsPDKAUI7xgq7zeKDSjO4uM49EoXb//2LKArlpnxEGASh99bPKQ2lGr
         wbdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V8m3BO+x;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C8eSHWZViSwiuVM+9o9vwCpTfAU0KUy82i7bIFe9tNo=;
        b=SQ2/+2v6OYSU1+8EUYma/NNKZyX4r2C8viIAk0l9q2SDf2PMaEfNrmooIq9N7ur79l
         HjLQCGngbXGqeE+LQCxSNJ2Svh1znlDgP0/qyhvXfvqou3yOBPKUzwPV8aOE/MQnowVt
         y+hLf1SETauNwpKHfHoYokEmRjMEWeL8npczGAbjB27P932FlZ6AA4yyskl23Mew6Cy1
         WUy8gap/G9n4hx0tdDCzmejU6NO6JrH/xhvqrzNVv5vn3C8EbyjPP76rXHcoNPpP4wCM
         vZh3IsQX5HG/ICJyKF710B5ricYRx4biuwrpmvfvW3EPxlYqUigPLfpHDXYHTUOzK7S5
         xGXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C8eSHWZViSwiuVM+9o9vwCpTfAU0KUy82i7bIFe9tNo=;
        b=Rk+qFxkMJodMbaPGfB5Ta8KfXgO5bCrboT+IWzKwLtZ8mfD+ir1f5X5doSWeV960+M
         vXZbkBoYsI/msC0cNSzfp3p83BHxEx99p4ihCqO0rHkq10n2AXOj5bYgQOckC0sE8rBX
         aDT1ecEiNNb1YyRmu2mgfgok0SWiCclTJiFXuiEbyHUW6kZgxTTY4rjom6AegXPW3QSj
         Yr/kZuYa70cyDv7G6A87ejkgO3LArf91pgeG+b+hYb7CfYGc2p1kfzXelLVtAcKrzcAF
         8CKU8WgHn3QdwRaalLGHD0+DQxxxWzJedeYzmAjx0OKm3z09lv2HSvdy140gBJiB5CAy
         7YPg==
X-Gm-Message-State: AOAM531mySy0W1LgaitqDtzPxw7tDNb+DhXxuA8FdDgHUDVj8Auo8h1l
	6vQOjYKKPGpjhmdUIoURatM=
X-Google-Smtp-Source: ABdhPJxUUnhaPNKeTfzT4KtnVprsFy0bn3jsUyy5yP8EIYHK104Qph7PBxWaIxPnR6JtRZWBr2fp2g==
X-Received: by 2002:a9f:3dc5:: with SMTP id e5mr9962414uaj.63.1597739681690;
        Tue, 18 Aug 2020 01:34:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:4d6c:: with SMTP id k44ls1303062uag.2.gmail; Tue, 18 Aug
 2020 01:34:41 -0700 (PDT)
X-Received: by 2002:ab0:2642:: with SMTP id q2mr9573456uao.16.1597739681311;
        Tue, 18 Aug 2020 01:34:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597739681; cv=none;
        d=google.com; s=arc-20160816;
        b=PcVQJd81Ks4Lwl4SWnRzRsdqFSPeZ32wM5y0aVZHqmsOfNPFENOOQKezPiHJnhTZ9Y
         yEhEaJs0rl10Eow7z+aJzaNhklHwi/LSZmPTuWU3mOtLxdHPSu7wlCpqUpTmGjiX7f3K
         mTmX/p/+OYsQ21dh5jc9mxAsvYtjODVXPlWU8Lm5A0lydn37yv52ypNZQt9p4KLzD4f8
         0meRbSxZ1kaTeNx4TPkPWOZCnpCYQVL8QGFUW0A5FZOLCNJYIlPb4Tp3G93jhurPyxMw
         9e66YpJ9I04o66OAr5w1eclaP7dxKuC9qpVssvvq9ZXBo0c7yf6rIVY0jhzrfIg49vYI
         TKyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VaNLfRHzjmAhC1MdbIpHRe1zX0H+Foac1RDS2VP3MjY=;
        b=ti/ZSekeSnWOcW5wENwqSHNUi/ALnNjdJ923773Iof059TaxlC9/IzLETkJlH6vu49
         i9dUFDw9pm/KQuFHXh0LjIVonpJ1Z2tBBgh9PZV0dn+N3nrWXIuu8LN+4P8WNukuxlS2
         6n/0a68ZjK0ZzM/tBo4kRnkoVjCRxghlGpcOiFFgs/0Vb91Gej+nNpFN2CGEQkKxOtaG
         5uxz7XuVpk7mw5SrkUf5B8W/9XDe2z7YI7NFaP/hf6h1jj0D/7Wude3ZBpwdQSUYtTqd
         KqMfHiFFLLsm29WhXbPgNCtecdt/pbqjC3ThkVoowUT3NZ6c4mqDySx5OtLpcl6gbIPQ
         VWUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=V8m3BO+x;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x242.google.com (mail-oi1-x242.google.com. [2607:f8b0:4864:20::242])
        by gmr-mx.google.com with ESMTPS id p197si1057789vkp.0.2020.08.18.01.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Aug 2020 01:34:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as permitted sender) client-ip=2607:f8b0:4864:20::242;
Received: by mail-oi1-x242.google.com with SMTP id n128so13420727oif.0
        for <kasan-dev@googlegroups.com>; Tue, 18 Aug 2020 01:34:41 -0700 (PDT)
X-Received: by 2002:aca:5145:: with SMTP id f66mr12152867oib.172.1597739680577;
 Tue, 18 Aug 2020 01:34:40 -0700 (PDT)
MIME-Version: 1.0
References: <20200813163859.1542009-1-elver@google.com>
In-Reply-To: <20200813163859.1542009-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Aug 2020 10:34:28 +0200
Message-ID: <CANpmjNOvS2FbvAk+j8N0uSuUJgbi=L2_zfK_koOKvJCuys7r7Q@mail.gmail.com>
Subject: Re: [PATCH] bitops, kcsan: Partially revert instrumentation for
 non-atomic bitops
To: Marco Elver <elver@google.com>, "Paul E. McKenney" <paulmck@kernel.org>
Cc: Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arch <linux-arch@vger.kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=V8m3BO+x;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::242 as
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

On Thu, 13 Aug 2020 at 18:39, Marco Elver <elver@google.com> wrote:
> Previous to the change to distinguish read-write accesses, when
> CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=y is set, KCSAN would consider
> the non-atomic bitops as atomic. We want to partially revert to this
> behaviour, but with one important distinction: report racing
> modifications, since lost bits due to non-atomicity are certainly
> possible.
>
> Given the operations here only modify a single bit, assuming
> non-atomicity of the writer is sufficient may be reasonable for certain
> usage (and follows the permissible nature of the "assume plain writes
> atomic" rule). In other words:
>
>         1. We want non-atomic read-modify-write races to be reported;
>            this is accomplished by kcsan_check_read(), where any
>            concurrent write (atomic or not) will generate a report.
>
>         2. We do not want to report races with marked readers, but -do-
>            want to report races with unmarked readers; this is
>            accomplished by the instrument_write() ("assume atomic
>            write" with Kconfig option set).
>
> With the above rules, when KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected,
> it is hoped that KCSAN's reporting behaviour is better aligned with
> current expected permissible usage for non-atomic bitops.
>
> Note that, a side-effect of not telling KCSAN that the accesses are
> read-writes, is that this information is not displayed in the access
> summary in the report. It is, however, visible in inline-expanded stack
> traces. For now, it does not make sense to introduce yet another special
> case to KCSAN's runtime, only to cater to the case here.
>
> Signed-off-by: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Paul E. McKenney <paulmck@kernel.org>
> Cc: Will Deacon <will@kernel.org>
> ---
> As discussed, partially reverting behaviour for non-atomic bitops when
> KCSAN_ASSUME_PLAIN_WRITES_ATOMIC is selected.
>
> I'd like to avoid more special cases in KCSAN's runtime to cater to
> cases like this, not only because it adds more complexity, but it
> invites more special cases to be added. If there are other such
> primitives, we likely have to do it on a case-by-case basis as well, and
> justify carefully for each such case. But currently, as far as I can
> tell, the bitops are truly special, simply because we do know each op
> just touches a single bit.
> ---
>  .../bitops/instrumented-non-atomic.h          | 30 +++++++++++++++++--
>  1 file changed, 27 insertions(+), 3 deletions(-)

Paul, if it looks good to you, feel free to pick it up.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOvS2FbvAk%2Bj8N0uSuUJgbi%3DL2_zfK_koOKvJCuys7r7Q%40mail.gmail.com.
