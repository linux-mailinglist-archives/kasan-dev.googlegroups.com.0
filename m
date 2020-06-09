Return-Path: <kasan-dev+bncBCA2BG6MWAHBBUGH773AKGQE4MPPLPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 79A241F471E
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 21:32:33 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id d20sf4885946iom.16
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 12:32:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591731152; cv=pass;
        d=google.com; s=arc-20160816;
        b=bz4lJg2UszChTai4pjd4PyCJoU62iQCwVNOb4NQQiYoMNNz0jaTATBu1rX2YWc5dtP
         +8bZC5B0TTbR/a97zc0sn7r1oW0SwXOCZzF+CwJOdN53wV9ra2S0Zz0eyiVQ7YIOBgpr
         1E66XsWqq1qt1bDp49HTddmgnzP76uGnoFBN81Hm/zce749j1XuixestljbWn3u2tjaK
         uYCfQn5/s8M3i1cuYYOwl5bhZ61f40p85cGy3pkMfUff0g3tPJcQdkz2yVFAPPwUbf0f
         DLHnO8qXKj8V5l2BdocCxrTua6nIIbOsdSR3sg0BAblYtNS2PiePaIikBRpDWPxqi9ky
         nU9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Jmy2Mnk4ok1RJOPMlcVF9jpT5CRLSJVTgPIua6CtggM=;
        b=m8CWDFrYib6X2TGGG8DgCQRLXtYr6PDTTflrB2NkwKsi3amCmotkQhUPmCAKsLSmf8
         Kw44+06Q4TA9BzbpZ0y47SIMxI89FG93EXx3Kwk0HapU2i31Uk3BQkItZ7+xuYMkh9wI
         YxErn/UqUmSk4YmvtT9NEazyn8Z+DGNET6kDuHLDl05dRL2qOtn/rzPThAAgN5p8Q6ni
         tvrHa0aAmEEsbLYPb/DrbX7v5iZlz3vKZPSHnT3i+6LK4MdfnT6xIWR22RCE51DJ09RK
         LglNDmfm3JjfjYX70BRPHq8ziTCGDVj4trc7pNwSCVPDc6JbBB0H1Boevhoj3wOm1YhX
         vgaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OJfv/PGG";
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jmy2Mnk4ok1RJOPMlcVF9jpT5CRLSJVTgPIua6CtggM=;
        b=Uii8V1DBe2S1qFwN/t2v2mvc5DcL2BbuiD8bJLG9V8AKV67ZLX/XMN/0rL4Bk/OqxU
         sdh919MUlT1A5L29mzJxhJKYqP8Dg/AgQWaYos8gasy2XabcyAJXJXT59bfS5aQoKRlV
         KIC3wZ5ADGgzfNqGLYle3lRimGuVhPAJZPfT8CVBxwSc59d03YzwQj/ipVaisAWlKfOK
         +d6Ry+VWnVkLuLhGiLUf6XdjJU2ciwdmwRoLsaX5jbRxeJ7A9vBSx8zv6Pv65qvQ1zVO
         IJaByCJ1kI6Vw/iqSbsxAM4Yzt0m577q5cv+Dff5lrve9OdP9Kk9kzF7oD99fXCwvEGb
         O2zA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Jmy2Mnk4ok1RJOPMlcVF9jpT5CRLSJVTgPIua6CtggM=;
        b=mgD5Jhub/taS8AhJIMcNo3S7rmcL2Rz2MKO5zWhy3DccS4F1ELxFEgDHgSjq0fghGa
         LcqKO0EhTwGex1yZxXoOvdU98B4M+V5HFzPbvCYCnJLxKOy2/jmi4ad5b6KjwLy/U0YV
         MA51BmMvXYr9FjQiAAx/JZxoRk56/LcHT2ek1rTVPLPCGNX0tC7uSRT5fKWhiIkjvsEz
         nuaw7TxkBaiRyxEc+8OFEmMRVl81kiYu98aWuQfXFl5+BzvpvQzIzmShHiR89x7w954W
         SLfLdi3p4I7ZnIc/6GDfE3RxzNVU0PyAeaaspUYfustnagOIKhdUNAAYlBJy47Iy8irC
         w0Bw==
X-Gm-Message-State: AOAM5329kNGsU/+ltKTlCxYRHkmg1dIJ2brMGSxQWzCUaR3DZJis0Krb
	lG8HwfquVvBBpJClOq7XGQ8=
X-Google-Smtp-Source: ABdhPJwM43ZIiXCpCEb5BJAgujhMlkdod54v3GWyxWJcs9MPTX83A3oazL5rVYtvLrJCLxmWcBJEUQ==
X-Received: by 2002:a05:6602:2e96:: with SMTP id m22mr28842528iow.165.1591731152403;
        Tue, 09 Jun 2020 12:32:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c205:: with SMTP id j5ls5712590ilo.11.gmail; Tue, 09 Jun
 2020 12:32:32 -0700 (PDT)
X-Received: by 2002:a92:9f4b:: with SMTP id u72mr28512376ili.273.1591731152105;
        Tue, 09 Jun 2020 12:32:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591731152; cv=none;
        d=google.com; s=arc-20160816;
        b=oA/hbC89jp8z7R0yo5ux8mp6Q7MZX/XivA9gHU3do36oP/OrOixBGrvDoGKtd6uiQ5
         Yb5pOIMhqrxm49aeaOnoo5SoxJO+njvt6JAYVPZyhjlN2n0+L6Dayo+eIPk2tDcokIF0
         2SCBUYYXDprbHuYumijqFHBCzEyuz1w85sg2Qx9SQH1paRiErCZeAaNvVybjUe8Tjbzg
         YFzbxPa/ITHoxqXfP27+05Roz7UXasUJQVFFHtMeco/32yIBmM+DQ8wj6otUGnrigZVj
         FOwW+95hafzldDmm/MCJS75DwhMLUL6H3crL8iUyay4jmJUEPMuWk0V2jrEx8W+YxneR
         Tlvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3rS0PjS0rxiYFFA6NkJOsLiVgpILALWXqX0+c6m8rUY=;
        b=X4/MRjt4aUTunw9PnaphObnL/DJd9yJ1H8O8xHTL4NDJozfT8rtKpAt8aBY9Z5kZm5
         QXnRd3+SbjvlAAt2OtiIxzl0XPfMtWdl49RjZJMtCA6vax/VBwb2j01sVQ/+aLZQnS7T
         WSsY4OflWIoq3muPXYcb3ZGZAP+BfajMrf0BdrHrZqDLLncZfBlDXJGNTGDPpfYYYXTf
         cGQDtIuVqiVpwOVxrUlylGrH/JVA5jrVzapP/ApGIS4OeRH5whF3//+NWR72e5CASUw7
         97HqOAAFm6aliWGgZ1QwoV+SfqJSRdj9qLPTDoU/TFbDXWkn/zSOcDBQgsb+vaTz9BbR
         PEqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="OJfv/PGG";
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id g12si595970iow.3.2020.06.09.12.32.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jun 2020 12:32:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id i12so1822345pju.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Jun 2020 12:32:32 -0700 (PDT)
X-Received: by 2002:a17:90a:df82:: with SMTP id p2mr6575703pjv.217.1591731151274;
 Tue, 09 Jun 2020 12:32:31 -0700 (PDT)
MIME-Version: 1.0
References: <20200606040349.246780-1-davidgow@google.com> <20200606040349.246780-6-davidgow@google.com>
In-Reply-To: <20200606040349.246780-6-davidgow@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Jun 2020 12:32:20 -0700
Message-ID: <CAFd5g44KHLV3EV+At3tsnbcagbW5Yc-fRXoTBae8no=peCJsmQ@mail.gmail.com>
Subject: Re: [PATCH v8 5/5] mm: kasan: Do not panic if both panic_on_warn and
 kasan_multishot set
To: David Gow <davidgow@google.com>
Cc: Patricia Alfonso <trishalfonso@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, andreyknvl@google.com, 
	shuah <shuah@kernel.org>, Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KUnit Development <kunit-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="OJfv/PGG";       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
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

On Fri, Jun 5, 2020 at 9:04 PM 'David Gow' via KUnit Development
<kunit-dev@googlegroups.com> wrote:
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
> Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44KHLV3EV%2BAt3tsnbcagbW5Yc-fRXoTBae8no%3DpeCJsmQ%40mail.gmail.com.
