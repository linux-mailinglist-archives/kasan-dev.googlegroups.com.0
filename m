Return-Path: <kasan-dev+bncBCT4XGV33UIBB6EWUX7AKGQEDSPHNSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5EC9E2CDFBB
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Dec 2020 21:32:58 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id 4sf1848156pla.6
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Dec 2020 12:32:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607027577; cv=pass;
        d=google.com; s=arc-20160816;
        b=nAsoJyQOvsM0L/cC+Z9PUDJdT67IS1802f5ULfiWZ0deS5Z6Jq6pFUoGp0X1sWRJRF
         HKW3lNo/ZoxEnbJGWpyOFfLLj9R8l+CSkPYZ3IRd4SNKEKmG6+5ZGtIDMMavylc7hIVV
         vGOvFfNuatCcUwg6RV/9kFAQoNXDXmlqtHgQoAn0D2dS/ui1dvCbd1eWkV5qtJoIgsgu
         HOOnKCaePu/10jWv9BPJZufxjSeX7WYXTFTat4V/KvNQs0jRFufEk7qrmUZhFuLNsHtd
         T6SrKtBogd5NzSGdU/XP6fl0joxOdWX4BrzBhbDafn8BjQbQIWXncPCxsjUxL/ybvxhN
         Sp5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=FnrF+c5twVGOPOywDk8SNB9/YnvBh1SU2GzpaLEHYhE=;
        b=AXCH95cn7uzmIElW4O00zKnFoJr/8kBoCe/79/bmwP1Xmlznixtf3mOOzHLSR3Fcac
         insCyTz/iOE28XkzChBaqGZEG/+c/rTFKpfLd6shz7rkaRXJDTNaidzVfmIt3n/+V+Lj
         qZ7g1kmDMf4j8xek1KiRQgFRZFC0mXV7sREM71x66QFNQpykl380LuywnG7d1Ho8JVnj
         c8LlgPBp3STDOMQwd1NCWDpBOKvooprh9B2NPR9K9fPddAZs7Y4PfdLFsnLr9zkSpl5c
         EJpC9+roda85v2/PAZ5TXnz5QJV4kKtkQCAIhW88dnlITJei7SHtpIqpjrvLRNM3NjDx
         hkcg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ZoueEGZD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FnrF+c5twVGOPOywDk8SNB9/YnvBh1SU2GzpaLEHYhE=;
        b=hkNeoydEJNl9+o23+HzMAkvlJ91UpkDNok8E6SWrUsAqd50l0Z3Xti1SNIh276n2TX
         4RfVPNCCWkBACCu65kQM1zE/fS2PflwnbIt1FgL0ekzGSVmZle6CF6v0zhCyAYkGHK4E
         pXf4GoeY5IspvzLYsnCcdo523HcD3N7vIjUXUxoi9lBYmahusSGgGrcg7ZGAZQN0IYbP
         rBe2iGWvneHcZ+u9E5x9KYzQ0n18TF91g//SAOlVCZtcmmPHPPOOeHACgoziDL34+0f1
         6i/Cw4mD0xtKEfgYW5Nv6RyuChUpBWjLCWvISjQ7ofmUck2USlAvTlKAALuDJ8ROiqis
         m5QA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FnrF+c5twVGOPOywDk8SNB9/YnvBh1SU2GzpaLEHYhE=;
        b=gqFMhSU88bq7/i32rGwywOArGiCT89tEMZTUTAakhtIFB881JoXyZAf/x47juLTSDe
         NzKdZBjznLdrL0WEfTtNxbTAqWnVGHDcEcwrtXoaD61rJ3FmaaDUk0tg0EH+BVUbPd1+
         ZmalBOdPCYcRYlIObEq1ozQhLAzedr20eZUtCTj0SRzSQE9V9XD8ihyigsgBHXLda7AT
         bTKwjdQFRrxXgy9gEnGHfnBQ9f5ixWpdOaKLNy8ky/5IrrVw840RPoIwKi+3rXcV1xvh
         MD7xKyggf4RbjYDeIu75Df+l36fuTjE7nJpvDquNpEACpKHPsygxUurYwj0DGtiWX6i2
         /3mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Jy3b0DRP0TVDlaUftXi6zvgoOTh2cCdM7iAVvXLIZ+cT3R0ec
	12pTVw+7iXQB89TI3vUztts=
X-Google-Smtp-Source: ABdhPJzBM3MBPkV1VcSIHB/gmhEqrt3MBLmTg8QAXf5qwLp6ZrDWJ2bGr79e/oYJZS2PvJz0C/xC7A==
X-Received: by 2002:a17:90b:3011:: with SMTP id hg17mr841710pjb.22.1607027576858;
        Thu, 03 Dec 2020 12:32:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a47:: with SMTP id x7ls3164033plv.1.gmail; Thu, 03
 Dec 2020 12:32:56 -0800 (PST)
X-Received: by 2002:a17:902:8c82:b029:da:c46c:aa44 with SMTP id t2-20020a1709028c82b02900dac46caa44mr893696plo.26.1607027576229;
        Thu, 03 Dec 2020 12:32:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607027576; cv=none;
        d=google.com; s=arc-20160816;
        b=u+2v/aWKXftHQfw7RmJDDpIETHPP+S1Vc4TFgiyNVhS/F9/v2FRqhZ0LN7jPAWToog
         FrsOrThd8G1/XOvcFmh+qfBdj/+ynj+Hh2u3HHD+wVraz0806UJ92UsESFf+oTtZLRcH
         24fjIu0dgQXzHVXK4nipce4Hpv57qvahwIXNZRllR5LzuNU6hoy41lQmRzJfBj0//Myw
         19XDpWicuUrkDd0eN9hZ+vXtK0ln1WM3Rj2f29GAPwOY/4HWtwD8X4guAhC1H4kq0X6L
         kKaiBDESTBT+o2bhuDaE+1uJXl+ist5ggI1MG/FoBerJZfNoJDunHVyPPkwVb/AvoxPn
         lI8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:dkim-signature:date;
        bh=26slEW2Tmsk3pbPNxp6XsiGy2XpUerGQii29Q5ICvNI=;
        b=WchhAXspWsoOoLB1Fj9/TquXIqLtXTVvH72kI9JsSH5GbYjEPBvC0mBsFXjJBSQDLr
         v+QKm5CsOUvOczxWb3kMynqabdDjkbKq/XO7pb1e7+tnONTgdLHWmrIXYlsQwC1amdcB
         K+HF55eaoyYKWKTyNdKwoLSvUpJuOA+sHlbz1n3oq0/6Ii622JhBp3//HvoS9ll1mmGb
         kv0r/72bmV7WI+FZxhpRGXhediZyhAjzPgdZGsk3lwu+O4P9swlrLyM9vdVtSvYI4Bry
         m5aYi3mb8/yHAYHBWarayHL45t5wgnfaBvIlJ4jp1hlNDXzCaEKWPZ6UooZ/PRLVovmk
         Zh2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=ZoueEGZD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id z10si203737plk.0.2020.12.03.12.32.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 03 Dec 2020 12:32:56 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Date: Thu, 3 Dec 2020 12:32:53 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>, Catalin Marinas
 <catalin.marinas@arm.com>, vjitta@codeaurora.org, Minchan Kim
 <minchan@kernel.org>, Alexander Potapenko <glider@google.com>, Dan Williams
 <dan.j.williams@intel.com>, Mark Brown <broonie@kernel.org>, Masami
 Hiramatsu <mhiramat@kernel.org>, LKML <linux-kernel@vger.kernel.org>,
 ylal@codeaurora.org, vinmenon@codeaurora.org, kasan-dev
 <kasan-dev@googlegroups.com>, Stephen Rothwell <sfr@canb.auug.org.au>,
 Linux-Next Mailing List <linux-next@vger.kernel.org>, Qian Cai
 <qcai@redhat.com>, Stephen Rothwell <sfr@canb.auug.org.au>
Subject: Re: [PATCH v2] lib: stackdepot: Add support to configure
 STACK_HASH_SIZE
Message-Id: <20201203123253.c00767545ad35c09dabd44ef@linux-foundation.org>
In-Reply-To: <55b7ba6e-6282-2cf6-c42c-272bdd23a607@arm.com>
References: <1606365835-3242-1-git-send-email-vjitta@codeaurora.org>
	<7733019eb8c506eee8d29e380aae683a8972fd19.camel@redhat.com>
	<CAAeHK+w_avr_X2OJ5dm6p6nXQZMvcaAiLCQaF+EWna+7nQxVhg@mail.gmail.com>
	<ff00097b-e547-185d-2a1a-ce0194629659@arm.com>
	<55b7ba6e-6282-2cf6-c42c-272bdd23a607@arm.com>
X-Mailer: Sylpheed 3.5.1 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=ZoueEGZD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 3 Dec 2020 17:26:59 +0000 Vincenzo Frascino <vincenzo.frascino@arm.com> wrote:

> 
> 
> On 12/3/20 4:34 PM, Vincenzo Frascino wrote:
> > Hi Andrey,
> > 
> > On 12/3/20 4:15 PM, Andrey Konovalov wrote:
> >> On Thu, Dec 3, 2020 at 5:04 PM Qian Cai <qcai@redhat.com> wrote:
> >>>
> >>> On Thu, 2020-11-26 at 10:13 +0530, vjitta@codeaurora.org wrote:
> >>>> From: Yogesh Lal <ylal@codeaurora.org>
> >>>>
> >>>> Add a kernel parameter stack_hash_order to configure STACK_HASH_SIZE.
> >>>>
> >>>> Aim is to have configurable value for STACK_HASH_SIZE, so that one
> >>>> can configure it depending on usecase there by reducing the static
> >>>> memory overhead.
> >>>>
> >>>> One example is of Page Owner, default value of STACK_HASH_SIZE lead
> >>>> stack depot to consume 8MB of static memory. Making it configurable
> >>>> and use lower value helps to enable features like CONFIG_PAGE_OWNER
> >>>> without any significant overhead.
> >>>>
> >>>> Suggested-by: Minchan Kim <minchan@kernel.org>
> >>>> Signed-off-by: Yogesh Lal <ylal@codeaurora.org>
> >>>> Signed-off-by: Vijayanand Jitta <vjitta@codeaurora.org>
> >>>
> >>> Reverting this commit on today's linux-next fixed boot crash with KASAN.
> >>>
> >>> .config:
> >>> https://cailca.coding.net/public/linux/mm/git/files/master/x86.config
> >>> https://cailca.coding.net/public/linux/mm/git/files/master/arm64.config
> >>
> >> Vincenzo, Catalin, looks like this is the cause of the crash you
> >> observed. Reverting this commit from next-20201203 fixes KASAN for me.
> >>
> >> Thanks for the report Qian!
> >>
> > 
> > Thank you for this. I will try and let you know as well.
> > 
> 
> Reverting the patch above works for me as well, and the problem seems to be the
> order on which the initcalls are invoked. In fact stackdepot should be
> initialized before kasan from what I can see.

Thanks, all.  I'll drop
lib-stackdepot-add-support-to-configure-stack_hash_size.patch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201203123253.c00767545ad35c09dabd44ef%40linux-foundation.org.
