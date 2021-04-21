Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWG7QCCAMGQESIKFHMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id C5171366D68
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 15:59:53 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id s4-20020ac85cc40000b02901b59d9c0986sf10456574qta.19
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 06:59:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619013593; cv=pass;
        d=google.com; s=arc-20160816;
        b=ah4PQqXsmbxi3Nlq0Jd/U0Lia36qq7qh/Ic34seLnHZEs1Khv64zahhP2CFN9NIOZz
         3ZBA+IBzVRZzHaskce/hCAwYqXWKGL6r5f+YsxYhCG9zJuFMqIGftsp21R7sSiuIh91x
         gt9DS+dqkMlTODgkt0wXyP2hV68UYx0YwQRzjEqB5uFOHtAk1VNPJqFVYajIeBdQcipZ
         fsLeoXrDIdpVeI3S1A83jOqJwtGz0/GXaSbjcDwO2SOGWlg2hLwu3XMZVtjLT6gupnmT
         f0FWbUoMk+pzYR06E2p9UxE/BFDx6knWiaWN1PVW9i2oabjFu8wJQEShViNVc36D5zjk
         7ouQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VATGBIitco3iZjIWH2ciJYy4x+25R1PPOdwVdE+oRog=;
        b=ozC+TvVHpyPZBD4JaeaAZ96+g5mT/Ii2tAPxGzcU+PM1rdrs5xiCPxf4RxsdmZaloZ
         LfhFwVLSaVMjdDfdc/P0FstWth+f6OYOvasgezePFCS/RVaLd1ZO/OLdHem2NC6Rema7
         bheoCO+H2THgBob/8Wd0UyDW2+EiALScCl+G0U+cspithVttRk1Das87Ui5C42YCBsZ0
         aUYQZiHWEY82rG1xZAct7CufRbPaWFe4UF7hBVxCLVZCTLYDqUCGd7DcjrrStEmkaLvv
         r3xkn0fecetQHXLK1U7fYp0hvfLJok5ThgwM1iCxyifjlK8Kojw0Kb6P6Cw3Xsw1OvrO
         CV+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DSVCS4qh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VATGBIitco3iZjIWH2ciJYy4x+25R1PPOdwVdE+oRog=;
        b=pFZwTk5XqK+3US0hfHSlO6GVEmblQJFF9J7iKKgXOu26Cr8Xj832dUK8D+MuhyutL2
         S56jKdqjkfiI+V/zQ5TZyn2yw6w3l+HgyF3wfoeUVnLn1SkFNdX2JxivrHz/wp6uWIzW
         o5M5FWJZvG1wawiaGvy6n+8LwEMh8vuwkFUI182eTUZXJU+7rtrJGX/iyR3McfS/FKqt
         8Lw4UuWS/tojnYHfC6HlNriflOb8EBvSyIdDwtTQdRo2raJK1Nu+c+eWbzMEx434H2dK
         ieKGuXxaNySS4URRtTl+mChKYLkMHyVCtz1wWrv3zZ/xJQgxhpljRBM6C+dzTIR/9w59
         pwPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VATGBIitco3iZjIWH2ciJYy4x+25R1PPOdwVdE+oRog=;
        b=g+gCM/k/AvjstPHvcmVs7mSjYH7qFOPbK+pdUiu5Dw5gW0US4RcZhZOfnPXc6SMYvX
         lzbs0jujuWuv+OEX53DZPvuUGn7Js/cEVlnH6vGmCz0le3v+K70n4Fmqbw/l64XOT3Fp
         RjJYV9L9POgX0avz14k7Vvg1AODJ0KSENanTmdJkJGHV3+bYwPoFPwiChp1uy65wTYqS
         wWowjXgDpP2cOenHNj8CboMcdXKDpVdHFDbml79IKseid/aPRDPQQInMEyQIb1d/cCiA
         gW/jJqEtGUK1+JXgpODFwEOZ5oLoLR22fQPcZGf0JUhUpBVFU517uvVyKMN9jxd/nSnl
         cMdg==
X-Gm-Message-State: AOAM533JxdImMjIfJPWCFEjy4W5OSVWkfhorf2zFPg239HI/YcHz0i64
	MDXu+dPQPbuRr25cP/5N6B4=
X-Google-Smtp-Source: ABdhPJyxY8vpHNhn0mNPdMc+/sL6FC6gerbHKURTvAhaWbZ7MLfgISPtSYjC3Umc8myLjjIR04+/Ng==
X-Received: by 2002:ac8:6b49:: with SMTP id x9mr16059084qts.193.1619013592896;
        Wed, 21 Apr 2021 06:59:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5b89:: with SMTP id 9ls703734qvp.8.gmail; Wed, 21 Apr
 2021 06:59:52 -0700 (PDT)
X-Received: by 2002:ad4:4210:: with SMTP id k16mr32290906qvp.30.1619013592456;
        Wed, 21 Apr 2021 06:59:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619013592; cv=none;
        d=google.com; s=arc-20160816;
        b=urOOzP7vybLkOdLaTkGBeugap6J4xFPsJI+1kWF6l4HW2QR1o78fAOtqbJr5Vrh12B
         GXjVyAi+gLPQQZSJi70VVsqSGqa8QTDqV3i2wHmI6qZcilz4CW9Th5HzSFOy2kPRT0Mf
         yHqj0PlKR3lxgyhc7Nu4Hy0nkvo6BlI6B4Kq+BitRqEnEaAtAHmws0JUkdp7ZqWdTdvG
         cdbMBu46acra44qPOETLg0t8aATVJdgW4ATJ54DpNpld1c6x/aQdjBriL6BvhfuuMJH9
         C2r8dD5AfDFU/hSe9iaElOBnvc17xtD/G0kobiKGNw4shHs/HUBEAv8fAq+BuFV70Kj9
         AiJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ojaZEJIsv8ujX9Ndfl290AF0sng1kMHpf6JRlQJX1FA=;
        b=gEDv/R4HLG3hVbrsdDerVpLtegTGnbgovh01siRuWRRiUo6wkbuJwKe4ktmqFyZIA9
         yu4vxCze+iEEfJ2HGhdVVHgkn1PwyBZk5I/yxrwjGl33Wob72zJbv6ARLnhkx/xVjesW
         /LmQORttzBdQyGpMSEBtOJSRdoAsZzqQYk29IYuFOHDvrW8nFhP2kP2rsQK3hPD/8oDg
         5KMRTYd61iwTXphLwOocS07ePu5jDjsuS9QP3aE8A5xMi61BLCgGZyN/5+lFVHzPoiAt
         LGL+St5aepYFOs2EHu49ooxOSN+3uJEc8Pb+lByAFEOG0OMF68u2RiyiH3P3+BsqR6pq
         IcBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DSVCS4qh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id h83si247715qke.1.2021.04.21.06.59.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 06:59:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id e89-20020a9d01e20000b0290294134181aeso13219931ote.5
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 06:59:52 -0700 (PDT)
X-Received: by 2002:a9d:1ea9:: with SMTP id n38mr18788241otn.233.1619013591799;
 Wed, 21 Apr 2021 06:59:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210421135059.3371701-1-arnd@kernel.org>
In-Reply-To: <20210421135059.3371701-1-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 21 Apr 2021 15:59:40 +0200
Message-ID: <CANpmjNM81K-3GhDmzUVdY32kZ_5XOwrT-4zSUDeRHpCs30fa1g@mail.gmail.com>
Subject: Re: [PATCH] kcsan: fix printk format string
To: Arnd Bergmann <arnd@kernel.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, David Gow <davidgow@google.com>, 
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DSVCS4qh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
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

On Wed, 21 Apr 2021 at 15:51, Arnd Bergmann <arnd@kernel.org> wrote:
> From: Arnd Bergmann <arnd@arndb.de>
>
> Printing a 'long' variable using the '%d' format string is wrong
> and causes a warning from gcc:
>
> kernel/kcsan/kcsan_test.c: In function 'nthreads_gen_params':
> include/linux/kern_levels.h:5:25: error: format '%d' expects argument of type 'int', but argument 3 has type 'long int' [-Werror=format=]
>
> Use the appropriate format modifier.
>
> Fixes: f6a149140321 ("kcsan: Switch to KUNIT_CASE_PARAM for parameterized tests")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Marco Elver <elver@google.com>

Thank you!

Normally KCSAN patches go through -rcu, but perhaps in this instance
it should be picked up into -tip/locking/core directly, so it goes out
with "kcsan: Switch to KUNIT_CASE_PARAM for parameterized tests".
Paul, Ingo, do you have a preference?

Thanks,
-- Marco

> ---
>  kernel/kcsan/kcsan_test.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 9247009295b5..a29e9b1a30c8 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -981,7 +981,7 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
>                 const long min_required_cpus = 2 + min_unused_cpus;
>
>                 if (num_online_cpus() < min_required_cpus) {
> -                       pr_err_once("Too few online CPUs (%u < %d) for test\n",
> +                       pr_err_once("Too few online CPUs (%u < %ld) for test\n",
>                                     num_online_cpus(), min_required_cpus);
>                         nthreads = 0;
>                 } else if (nthreads >= num_online_cpus() - min_unused_cpus) {
> --
> 2.29.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM81K-3GhDmzUVdY32kZ_5XOwrT-4zSUDeRHpCs30fa1g%40mail.gmail.com.
