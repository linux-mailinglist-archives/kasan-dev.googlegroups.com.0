Return-Path: <kasan-dev+bncBCMIZB7QWENRBF6QSKFAMGQEX7NQAQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 90D2B40FA50
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 16:37:14 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id m4-20020a0566022e8400b005d5880ff784sf801699iow.13
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 07:37:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631889433; cv=pass;
        d=google.com; s=arc-20160816;
        b=kDI6NuKoEMs8LL26n56oZ08cZikZfBu6H/GerSo+IJR0qmI/3jqtZnNNknoDTgpYXF
         7l/6jI18noHG0SEwzYnKr1xJjiStVh2K0SMXH/ox1A3ztAZYSqEFpg+CDleGL5liGgRS
         HUT6ELFdlFlnlkc04mlj3U+cID5Iwiwd4DYGCNChDqKfY3y9H99B6ZzqRLSnkuz8f86s
         SSf66t2PgIaSLojIpDMbEUMFHhPlW7FGViSjEEF+UK2NZdP2XhTgo3RGtlGCTJL8vkjd
         gWF6reQz2y4XRl0tyW6Z9rUg0qSlFPQ3vjbZVHhH5g/j/7Grvp6JaWsMCnS3q0hgLY0Q
         xjpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=khcYm7G73b/crjBq3y6oCYH2JlvHhlX2x6HOaSKORDc=;
        b=GMzru6QMslYp64No8J5OjwGcQp1E+fKSVycLY5cWrz31ZjsBuHM5I6KvtTFv1T1Dd6
         dJH9QYNK9bJSUg0b30Ju+0UuJjuJMKdO2qZTz16Q2/t9yAVO043HRMcXWEY86MGOP3E0
         8WBlh4xWjRjlAvjzFVWhcQzBtXmJEdEM1KhIYVjs+7vu090fi1sKPB5rGBU2Jd/OiRwa
         OKeISRBjTzc674HDfOanEABMucfjD8+HpEgUeI9RBcmJpgIK8RjDEj0SK3NL8eDAi2Un
         O9ldFVY7Wbz3Lgj4rshdryr+TZtzOLhm4iK5aFmSIxI0KRxADleJbbdHcM0ulhxH5xaV
         UgmQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DYn3EwXJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=khcYm7G73b/crjBq3y6oCYH2JlvHhlX2x6HOaSKORDc=;
        b=dV2ammDEU2J5r9SkT6ADls3FFZptAiIHC3MAiLY3BuXaBKYGhawlw4TsOZPrCxhT3A
         tauk7Gs9dkWp7BNeTwM/8bVJW2Gv74V6AmYrrcq4IpbnUEzcwgL6CSKqrT0yoib3RhCE
         JuhsEaZiGcrGfSZuOo7Try47SAjo4TUYbunhfH0wCI5aZx11ejXA6RPK6h+qJl63hk61
         9q18hkLD2C4yQHIsyw4Fd8T/bCUrb0/V1Szc56PbqxMKW9W40nRNjdj7qc1H9PjlyeuS
         UBt5EIIERIoFyLLhhLlEdhhuqNIKGT9RlZCTQYlYB8nb+C1Q5Ybtgb8BphQC5goQx0NF
         JP+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=khcYm7G73b/crjBq3y6oCYH2JlvHhlX2x6HOaSKORDc=;
        b=leGUoenbwqKdIKjYliJ/ZgXKjW32oEbqMeM4S7DkGH48z3YaZFkKAtci3an/4A+s4w
         q9uOC0NGDBtWYWdAnO2fqEpkoSHTeMCbfDrODCBbNfNjs1LBPURVulp3/oRaYp60ipoM
         dq0Y3Zni7N4802ztWtSbeq2hNkz6GXkWjaYlZ4lNbqLIdbPiVoWt54VpdUi5MKzP5kJ7
         RvzUFsk98lKbfZ4AmnXELef6Es2T+ys8Qb17NoctYEdSTq1FqzEFDJ8u5H5+VkjPOqao
         +Aazj1ecZVFJq4GLJRDDwX2nNS8MdJ+2l2ltvxWS24SPJvqBei2YdAsV4kGswiA4ZB2b
         IpMw==
X-Gm-Message-State: AOAM530UNKmkF0KgfGd843mUytLYtd8N/PA5AEWl+brwacfjiE6gzXiV
	9nag3L+9VpsnlYmfnG+sUXo=
X-Google-Smtp-Source: ABdhPJx3ebWRW6xoM3ZIivBkIXdwAemZzYZt+r3BY8UR2iaAUcnSutqoL2g+6HmqnIO5pcPQMnOLJA==
X-Received: by 2002:a02:998a:: with SMTP id a10mr7807063jal.23.1631889432012;
        Fri, 17 Sep 2021 07:37:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:10cf:: with SMTP id s15ls1609039ilj.3.gmail; Fri,
 17 Sep 2021 07:37:11 -0700 (PDT)
X-Received: by 2002:a05:6e02:178d:: with SMTP id y13mr8383480ilu.266.1631889431653;
        Fri, 17 Sep 2021 07:37:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631889431; cv=none;
        d=google.com; s=arc-20160816;
        b=AGU2c68U+HshL7ajxMeWtDwiJ9HbFQfH6bshFg2EW5/FRaOgonW5p+zr1lTgJlljXX
         H/jeTzd3jVJzmkMsU+BNECMSrMO5pb5gHYi7s9lDmgDPpvNoC5dP53vDxZa8AhkcRKsW
         vqQ2NwQixT+R8hORseWezAK8GYVIVY8GvN+MmU48cnfXPaLoDfwzwRDIY4aPgfmpagSA
         CwBkOlNXGjeUGy1s3A4llUev4Qr1JqHPaRW9V47lU1OWbtXk94MH/qe0rfJYwaR10vxH
         HthCLelSG+6s+a3sTDD43fA3WhlxLlUIWpMqcRlRIbsUHfxOkn8DgZo119pOetGtmE+g
         g6RA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CHasoNbCFWsiX9dMsKrnxNkdea5daLbcgcWNoEUJAKg=;
        b=YBANL8OQYufjjSpz44rW87ENH0XPj8uybyvZI1C1sqWdvfojzH1cRIKAIF6yelRVOA
         jnRyr1OJm2DQXA+sLOxnDFnmZTs2yCMX1C/RZjlmjtX8v3RLG6OBTgZy0ghO0s6WZjV9
         VwOMdlA0f4TlhMy1j9FmLAuBZ2HhJDuPObWpTZ81d5F3kHZIqBJsakx4lmddG6/DFXa1
         SShz22tamr3Jmx/mUMnArlm49Zl5JQd++WoN2+XpfjFPxKR5ChhRtBPu5Gk+R6sHlrRR
         BALeq8iv+Y77nqrgLcvuJ1i3HS4xwgkpPMO7TX4Bn13GRTufVwkfEnYU/GKdnvUniAbK
         ltYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DYn3EwXJ;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc34.google.com (mail-oo1-xc34.google.com. [2607:f8b0:4864:20::c34])
        by gmr-mx.google.com with ESMTPS id z4si542471ioj.4.2021.09.17.07.37.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 07:37:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c34 as permitted sender) client-ip=2607:f8b0:4864:20::c34;
Received: by mail-oo1-xc34.google.com with SMTP id y3-20020a4ab403000000b00290e2a52c71so3275247oon.2
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 07:37:11 -0700 (PDT)
X-Received: by 2002:a4a:e3cf:: with SMTP id m15mr9150899oov.21.1631889431067;
 Fri, 17 Sep 2021 07:37:11 -0700 (PDT)
MIME-Version: 1.0
References: <20210830172627.267989-1-bigeasy@linutronix.de> <20210830172627.267989-3-bigeasy@linutronix.de>
In-Reply-To: <20210830172627.267989-3-bigeasy@linutronix.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Sep 2021 16:37:00 +0200
Message-ID: <CACT4Y+YsrcejyF-VZ5OGtk-diwHtVEJU0Yhipfomur5HTCc=Zg@mail.gmail.com>
Subject: Re: [PATCH 2/5] Documentation/kcov: Define `ip' in the example.
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@gmail.com>, Thomas Gleixner <tglx@linutronix.de>, 
	Steven Rostedt <rostedt@goodmis.org>, Marco Elver <elver@google.com>, 
	Clark Williams <williams@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DYn3EwXJ;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::c34
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

On Mon, 30 Aug 2021 at 19:26, Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> The example code uses the variable `ip' but never declares it.
>
> Declare `ip' as a 64bit variable which is the same type as the array
> from which it loads its value.
>
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  Documentation/dev-tools/kcov.rst | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index 347f3b6de8d40..d83c9ab494275 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -178,6 +178,8 @@ Comparison operands collection
>         /* Read number of comparisons collected. */
>         n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
>         for (i = 0; i < n; i++) {
> +               uint64_t ip;
> +
>                 type = cover[i * KCOV_WORDS_PER_CMP + 1];
>                 /* arg1 and arg2 - operands of the comparison. */
>                 arg1 = cover[i * KCOV_WORDS_PER_CMP + 2];
> --
> 2.33.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYsrcejyF-VZ5OGtk-diwHtVEJU0Yhipfomur5HTCc%3DZg%40mail.gmail.com.
