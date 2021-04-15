Return-Path: <kasan-dev+bncBDV37XP3XYDRBYGP4CBQMGQEWSLVMJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23e.google.com (mail-oi1-x23e.google.com [IPv6:2607:f8b0:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D1E4636087E
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Apr 2021 13:47:45 +0200 (CEST)
Received: by mail-oi1-x23e.google.com with SMTP id i19-20020a0568080313b029015a3ff29eb0sf4428620oie.20
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Apr 2021 04:47:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618487264; cv=pass;
        d=google.com; s=arc-20160816;
        b=d2z6lSrvhyA9rVqAAUWm6r+XBn2XZjRZZaUmVTAyBne5do0iisG50aHRJroMIpPtzJ
         E1rs9UAEWKt8ekz3tg1UeeWsFvdP+S88Wq2jAJ5d4Grd8FMIUZ0EnEjAMdL/ZQ1HeZ+O
         D+3vAv4t0MzD02AIgVZb1DpAn9TdhHj2cDCYJKSZFGEguELkoYsoGw1xIX2HpPj3XPJd
         PVZYwq+DJk9LBz0qzG94PBpDlZMMD0BMpCwekiB20PzLp1E0BgypSIxReSrbwIPxyhV7
         bfpjVL3CpvOCTwZCz+j8c7dStpDsl34EW9mc1CGBDxGJ2eFQ004lVKrDQrL4NjyqL2Bj
         LjSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=3i/NcqhEmTnKiTetWpBo1tUV8QajT0o05JNpH/+Z4lw=;
        b=Bs2I1NiLmQ0lYsjJXPe27eAi8gXl5kCAhXdV2aRX9hmbRP/pEp+PZQ3h4iT+4cxgZL
         K+clIsWQ5kLCpR3FKK7XveYkr9OM/VP9v+q0jyu7zVvGvZ1eGtVexwsR28gex91bNmbc
         VP91foX99s6KivhTY6Lfctkt36K+dHNydvgMumiFbDFqb+F/WCGoNhTmHJ1dBT728O6Z
         +RS3jz0RSA73wOX20zBPOSMxIoIPO+UNiqxqa0nAojJMVqMKLUrE2Pbj/4FmPMvBr1Dv
         QNvNF3p42LlhxGv4PGKasODp2dYeAs9oh0CY39ZkhNms4S2ZHWNADJAwXgM/DiixP5B9
         Uk4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3i/NcqhEmTnKiTetWpBo1tUV8QajT0o05JNpH/+Z4lw=;
        b=fHc2wJTKbLvSz/6xfBjFd9l1LJWrkLSbcwWtxhKvkPCVdNQE8p6yNzmFvi7FYwYLbj
         XaneoqsFa06QOK0ECDVOKmRltKiALEUqMVdNBMUz0h6VUZRlf70gkKfvk+17CbrrmQq9
         kOXIGE41nAa6ORiRi3IO6NoPZOxg53JZX49panA/+hwcJo+I1mVghtdtzOdTwLdGVv4j
         ElnGVwf7u13m5kOsKSGLNaQJPKkjiFVJ4La4MEFC2SiDlkgbcn3X+ZCmSmtQCAQ4WQrt
         OyQn4WcZzpsEKmxjlmeqHvCkcxewi6RdHf6TIesvyqa6j0t/l78y1kGgWP+X02/Eq9gd
         P1Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3i/NcqhEmTnKiTetWpBo1tUV8QajT0o05JNpH/+Z4lw=;
        b=aQtqpmFZRGnct6N0AJFfazNp+DMGcXMZNYKLVxmQOR8lUuxWwoyMVxFSFnWojQcQ9U
         93lCwJ5FQH8huk/5ucqoIZkArbbbXbQTkfmWHFJc1sM6k/k4YivokNckIHJOxs8d/Pur
         vO+6xt09VKHPA6VxO//Y5gHfgkV8QNlN8KJvIrao5LcElcjp/WFthwzkct5rEh7HdbLK
         VX9X5B6lLUWIfbhD8vjw8kyN1WzGGdFFje260BOfUpYxH3gEhoId6bEO2Ru27WNrQznf
         RfaJDLJbbqtb5Ydb3MxzStlSq8Nx351gHHfWg73BhlEUxwR1iBKNazwFGvIFureCHmRk
         xmWQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531+6VfrClp9Zljk4xeRbJ8QcNGpPbgzDmc/gEhNtPUpIs8O4NOs
	cK4U29esNNErljn6dBBT+AI=
X-Google-Smtp-Source: ABdhPJygIR29uq5B+BzUw03UBaldoTqSypRWawL4/1gQYujhws6tqigbT0xp47DnTUxh9/mEojb77w==
X-Received: by 2002:a05:6830:2105:: with SMTP id i5mr2356256otc.215.1618487264311;
        Thu, 15 Apr 2021 04:47:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:7541:: with SMTP id q62ls1264844oic.0.gmail; Thu, 15 Apr
 2021 04:47:44 -0700 (PDT)
X-Received: by 2002:aca:5846:: with SMTP id m67mr2368842oib.46.1618487263964;
        Thu, 15 Apr 2021 04:47:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618487263; cv=none;
        d=google.com; s=arc-20160816;
        b=v1JahoZvG5p9rXxauHWEtR0HE/+bcX8yztuhd0XxT9kfwU3luBzWkcLTDZLBqaulpF
         It08sLnhvcNg5Wz9/hTl2Gef36sHoCugtaARqLsuP01sWT7/Jsy5g4r90strdZIEkBL/
         7H9SvIjDZcbLn9u0Xs7J+2mGZnElEZuMonkxMLKh1ilDLxuoxq1jcS+cXfmmXkgihwBl
         kpTyZ0ibsVx7MDhEEtcIVYpLnrTudwTpk15CxpX+QI5deLJUvgXGkaPJh45rSRLPCYeB
         TFDZLSFpENrHogHunKQk66HDd3XsSwXLR4eo8wyIwEUfJwtd5eghD/dZwYJpn5NEsPmc
         eEtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=sNUw7tMxM0uC1Vm5pDT28WAi8B0bUKPzKnONdJVkpdc=;
        b=ELyUEkPtvGOcypUy+AOimS1raNAAd29ZN+xAHppIykebcueqTEOl98oJXBjXNodtPz
         kaO6iORbeeDyiWovsPSu2a7UvfWqrpxq+plC9gIi1EpSKr/TnpgWzuZy1KI1vpgb4qgn
         5T1+zMIC0Qkc07hp10HDDF+o7Xhk+6KCgMqpcMCIw//Rb71zlrP4QqjTdqmK3F6U0Ukg
         g8n/8deHwxMl/5GyeNxDIirjSzuF0qv7qFg19WJjZmR9KDHX1fiwonKM+J5/rHzIYvvs
         7Z02pFE5tsqaB1fd9XX/EnY19GngZe9ge3FSRoJ2SjmIK4ZSfrYJskyzDxlalWL+qc9e
         u9RA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id w4si149322oiv.4.2021.04.15.04.47.43
        for <kasan-dev@googlegroups.com>;
        Thu, 15 Apr 2021 04:47:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7FA3C106F;
	Thu, 15 Apr 2021 04:47:43 -0700 (PDT)
Received: from E107129.arm.com (E107129.Arm.com [10.50.68.201])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8A6473F73B;
	Thu, 15 Apr 2021 04:47:40 -0700 (PDT)
Date: Thu, 15 Apr 2021 12:47:31 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, will@kernel.org, dvyukov@google.com,
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/9] kcsan: Add support for reporting observed value
 changes
Message-ID: <20210415114731.GA73625@E107129.arm.com>
References: <20210414112825.3008667-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Wed, Apr 14, 2021 at 01:28:16PM +0200, Marco Elver wrote:
> This series adds support for showing observed value changes in reports.
> Several clean up and refactors of KCSAN reporting code are done as a
> pre-requisite.

> This series was originally prepared courtesy of Mark Rutland in
> September 2020.

For anyone looking for the original, it was never posted to a list, but
is sat on my kcsan/rework branch on kernel.org:

https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=kcsan/rework

> Because KCSAN had a few minor changes since the original
> draft of the series, it required a rebase and re-test. To not be
> forgotten and get these changes in sooner than later, Mark kindly agreed
> to me adopting the series and doing the rebase, a few minor tweaks, and
> finally re-test.

Thanks for picking this up!

All your changes look good to me (along with the documentation patch),
so FWIW:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Thanks,
Mark.

> 
> Marco Elver (1):
>   kcsan: Document "value changed" line
> 
> Mark Rutland (8):
>   kcsan: Simplify value change detection
>   kcsan: Distinguish kcsan_report() calls
>   kcsan: Refactor passing watchpoint/other_info
>   kcsan: Fold panic() call into print_report()
>   kcsan: Refactor access_info initialization
>   kcsan: Remove reporting indirection
>   kcsan: Remove kcsan_report_type
>   kcsan: Report observed value changes
> 
>  Documentation/dev-tools/kcsan.rst |  88 +++++++---------
>  kernel/kcsan/core.c               |  53 ++++------
>  kernel/kcsan/kcsan.h              |  39 ++++---
>  kernel/kcsan/report.c             | 169 ++++++++++++++++--------------
>  4 files changed, 162 insertions(+), 187 deletions(-)
> 
> -- 
> 2.31.1.295.g9ea45b61b8-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210415114731.GA73625%40E107129.arm.com.
