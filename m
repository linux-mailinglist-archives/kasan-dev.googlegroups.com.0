Return-Path: <kasan-dev+bncBDV37XP3XYDRBO7MQKDAMGQE6UDFRJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EC9803A1497
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Jun 2021 14:38:20 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id v28-20020a25fc1c0000b0290547fac9371fsf8715553ybd.14
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Jun 2021 05:38:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623242300; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZcGLaNSaScYtG/GfB14yxIzKUzp56wPhOm/VuVnvGGAskf2GPr7VzpzGjmwEac2XzR
         VAwRBxQ6mp/p05xEPcc2oU55YOZTRvv4dFtbUl+x3moQ4gOfbwHUJ/CFOOeaARcb2gs9
         kF3zPRbdwIvwgz8PQU4/JCvF1FmRooluvrhYx1X+qDIFkAEHfahBiMiZJuXfUHGwIZpF
         ZfdwItDb9HnOglamNjI5lmsUoly82Lcm8BnBn34N4jwseqb6gYrwW1Y5tKd7xTJlBuep
         /yELGMLA9eWbHmZJVqIihzxTTPmFkKpx03l9dxcxj9zfEqGA9bgfxLV1lmOJh/AlOsPW
         j2BQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xLWbXYssZwa8EmbwgNj+Qa47WbgWexyf7krTjWOaIYw=;
        b=v516HG2vZLuHt885eTQY6x19oIv6Uqq+h/tCEKHDwUahIJNbnQlwTW2+gjjubXxuVQ
         Oh65bLBdhQtQKhes3Mgh3Cv3DxqocD5ltmHSvdkn2Y/ZsDlbyTN6zl5iOKupLUfeo+te
         8WbUJBOzvmXPvLngyme1vyV6GD4uXgS7+D3Vk7VCnAI7nW9adh0cBqeHZ8ubknBntbWL
         HGdcHqZFSslJJJD3Uj/PLdRztIgQh4pHdROabOdX11Z9eO1xNVlylBYQGAXaSVjvDIT/
         uHrSM3ycFjO5fT0/jYKLsZZJKxSQoDst1Bru7JxHIXX29wtEl3U62UpMoEpBgvNPj8Jz
         qM2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xLWbXYssZwa8EmbwgNj+Qa47WbgWexyf7krTjWOaIYw=;
        b=stj+jYOOFimsAYF5KdW75uHRG1Uz+ol3Y39FZ1I4e0wnt1XupC9DuyKpal04Ypl5U8
         UjO2DJYnToHJed2toux8aZ/S33o9Cq6XzQzYzqtnQBUlc9NeY1skaPFopQS0b9YFqpMI
         Erj3OowBWZE0Fp4tLTYGAx7b4i79tMb0VoRjF20dtkXIE+/0BARajD1T+9G+uk+1zqhj
         GqkGHZqhe2xMiXL3iXB5A55G7SxIOFAZVYeNu65gOjVwOhONLb8kG9sjzi76iKgUNqGN
         EpaWf6dIfQCUDY8Lwy3POx1wQ7URzCkjuOfh4apCIWTAYwApIXeEhSNlPOVEaZbak6xO
         Wt7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xLWbXYssZwa8EmbwgNj+Qa47WbgWexyf7krTjWOaIYw=;
        b=gr5BtkECARBINOl4gGGVbphBkf6og4LzTE4hOAQ35XBndNWVpOT1pQcGM4Wh60Z2mA
         DJ3pm+tU47vQBlKNUUqEM5OPaUU8BKw9VxzvGZ/Cd2qpRXQPyD5nrelJ5Y9P5RiXosLF
         ch+JX5oz2u0uw7eHSuVwBILH2yR7Z/ftymlAvnFXp3S99zCTW+st9rxZBsMUbBFtANXn
         e+rr2SDzo0LOG+lq3eBPY16YVFhHAUv3PEkdyCP2Htz9oPlFMCxCOj5OzaV6XIMCLpck
         /ych0p736uTZSSgbO+ws74QMLRMZjV9J9w3rNoZ3zWmstL0cxi4jgbNnaYdt42LjoTAM
         E9NA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Kf/1V8m7R+ubj+0rrQPpKQV5zjTzxhZfJopnV4RmDHexVCJqL
	dZlQkehM5uj1q6Rbt8Y55n8=
X-Google-Smtp-Source: ABdhPJxDf4DX+rgdAQjUTBOb0hzbet+tgp08EoU4IX9QaWOz92T7rwF0uL4o9grKBtr3lIwi1DfP9A==
X-Received: by 2002:a25:4d4:: with SMTP id 203mr36304166ybe.367.1623242299833;
        Wed, 09 Jun 2021 05:38:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:38d6:: with SMTP id f205ls1438917yba.1.gmail; Wed, 09
 Jun 2021 05:38:19 -0700 (PDT)
X-Received: by 2002:a25:6005:: with SMTP id u5mr38149382ybb.56.1623242299338;
        Wed, 09 Jun 2021 05:38:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623242299; cv=none;
        d=google.com; s=arc-20160816;
        b=mfPM8IcDfr6yNeFxfOYH4mHTz5vqp2WzJq+rmA/MkB+4RIquKFBt8KufLrmN+DVu5y
         IIasNuT0miFRcXus3+e7sMVcIZVWBvHOT48LaRIgfDoRkDM8BIqJqOoRhvamWaqvF4h5
         +c71O1khrIKzhG6p13+nhud8ga6F1yYV52nadzHCkwJYHODeiRhQeMdTuf4+SvqISKbW
         n8RDoZ8hdLme5WSQN+bX07g90f+RRgbrAb41psi4pkdV+A8Aj4Sl7v0kZj6MXhcjH2m1
         6zY6/+uqpcqKZ57wHsOmWtGp75KLu9wLtkkhgrp3mOJm2d0GwK1M8K84aCOE3dRkMS+C
         +MYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=XESQj4hkMo22raHCOnPLNWU6wBeF3xWpMBQ+aWl/wQE=;
        b=iG3mWHxv2bf0XBkbL51+cf/XZqOY36RhLdFEDXvwbhyVQ3K4eNVVu9WWgQnepUsvOh
         yXiSRUjuqZ2F680pSMzvdjk7MtXsgSopunDTVKh+4bYauFq53x5EkUhg4jfV6w35h8Uc
         uyNS2gg2tOPQwmsPHrQWdgxrhLFayck5gwbNtiFKcdPP7TaWA+njpyLvN5dbi5MYmhDZ
         yBthhVimyz6pdDECa3+sBX4/Eihctt2Rv/oOFTph/CUrpeifjEI4L0dZ5/Zx7+/r96kI
         HZusg+pa5v3rzcE6Efyd2gzGQY43+wXCq6CQc65aQyh74bcHG6blX/jyVLJnxA9OOoWe
         RB+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id g10si2609486ybc.2.2021.06.09.05.38.19
        for <kasan-dev@googlegroups.com>;
        Wed, 09 Jun 2021 05:38:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id D4253D6E;
	Wed,  9 Jun 2021 05:38:18 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.7.102])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 733653F73D;
	Wed,  9 Jun 2021 05:38:17 -0700 (PDT)
Date: Wed, 9 Jun 2021 13:38:10 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: paulmck@kernel.org, boqun.feng@gmail.com, will@kernel.org,
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 0/7] kcsan: Introduce CONFIG_KCSAN_PERMISSIVE
Message-ID: <20210609123810.GA37375@C02TD0UTHF1T.local>
References: <20210607125653.1388091-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210607125653.1388091-1-elver@google.com>
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

Hi Marco,

On Mon, Jun 07, 2021 at 02:56:46PM +0200, Marco Elver wrote:
> While investigating a number of data races, we've encountered data-racy
> accesses on flags variables to be very common. The typical pattern is a
> reader masking all but one bit, and the writer setting/clearing only 1
> bit (current->flags being a frequently encountered case; mm/sl[au]b.c
> disables KCSAN for this reason currently).

As a heads up, I just sent out the series I promised for
thread_info::flags, at:

  https://lore.kernel.org/lkml/20210609122001.18277-1-mark.rutland@arm.com/T/#t

... which I think is complementary to this (IIUC it should help with the
multi-bit cases you mention below), and may help to make the checks more
stringent in future.

FWIW, for this series:

Acked-by: Mark Rutland <mark.rutland@arm.com>

Thanks,
Mark.

> Since these types of "trivial" data races are common (assuming they're
> intentional and hard to miscompile!), having the option to filter them
> (like we currently do for other types of data races) will avoid forcing
> everyone to mark them, and deliberately left to preference at this time.
> 
> The primary motivation is to move closer towards more easily filtering
> interesting data races (like [1], [2], [3]) on CI systems (e.g. syzbot),
> without the churn to mark all such "trivial" data races.
> [1] https://lkml.kernel.org/r/20210527092547.2656514-1-elver@google.com
> [2] https://lkml.kernel.org/r/20210527104711.2671610-1-elver@google.com
> [3] https://lkml.kernel.org/r/20210209112701.3341724-1-elver@google.com
> 
> Notably, the need for further built-in filtering has become clearer as
> we notice some other CI systems (without active moderation) trying to
> employ KCSAN, but usually have to turn it down quickly because their
> reports are quickly met with negative feedback:
> https://lkml.kernel.org/r/YHSPfiJ/h/f3ky5n@elver.google.com
> 
> The rules are implemented and guarded by a new option
> CONFIG_KCSAN_PERMISSIVE. With it, we will ignore data races with only
> 1-bit value changes. Please see more details in in patch 7/7.
> 
> The rest of the patches are cleanups and improving configuration.
> 
> I ran some experiments to see what data races we're left with. With
> CONFIG_KCSAN_PERMISSIVE=y paired with syzbot's current KCSAN config
> (minimal kernel, most permissive KCSAN options), we're "just" about ~100
> reports away to a pretty silent KCSAN kernel:
> 
>   https://github.com/google/ktsan/tree/kcsan-permissive-with-dataraces
>   [ !!Disclaimer!! None of the commits are usable patches nor guaranteed
>     to be correct -- they merely resolve a data race so it wouldn't be
>     shown again and then moved on. Expect that simply marking is not
>     enough for some! ]
> 
> Most of the data races look interesting enough, and only few already had
> a comment nearby explaining what's happening.
> 
> All data races on current->flags, and most other flags are absent
> (unlike before). Those that were reported all had value changes with >1
> bit. A limitation is that few data races are still reported where the
> reader is only interested in 1 bit but the writer changed more than 1
> bit. A complete approach would require compiler changes in addition to
> the changes in this series -- but since that would further reduce the
> data races reported, the simpler and conservative approach is to stick
> to the value-change based rules for now.
> 
> Marco Elver (7):
>   kcsan: Improve some Kconfig comments
>   kcsan: Remove CONFIG_KCSAN_DEBUG
>   kcsan: Introduce CONFIG_KCSAN_STRICT
>   kcsan: Reduce get_ctx() uses in kcsan_found_watchpoint()
>   kcsan: Rework atomic.h into permissive.h
>   kcsan: Print if strict or non-strict during init
>   kcsan: permissive: Ignore data-racy 1-bit value changes
> 
>  Documentation/dev-tools/kcsan.rst | 12 ++++
>  kernel/kcsan/atomic.h             | 23 --------
>  kernel/kcsan/core.c               | 77 ++++++++++++++++---------
>  kernel/kcsan/kcsan_test.c         | 32 +++++++++++
>  kernel/kcsan/permissive.h         | 94 +++++++++++++++++++++++++++++++
>  lib/Kconfig.kcsan                 | 39 +++++++++----
>  6 files changed, 215 insertions(+), 62 deletions(-)
>  delete mode 100644 kernel/kcsan/atomic.h
>  create mode 100644 kernel/kcsan/permissive.h
> 
> -- 
> 2.32.0.rc1.229.g3e70b5a671-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210609123810.GA37375%40C02TD0UTHF1T.local.
