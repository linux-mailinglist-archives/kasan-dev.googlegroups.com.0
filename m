Return-Path: <kasan-dev+bncBDV37XP3XYDRBZPHUH4AKGQEVFGXY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id B999321B74D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 15:57:58 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id 14sf3635078ioz.17
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 06:57:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594389477; cv=pass;
        d=google.com; s=arc-20160816;
        b=UT1Lt15xJDe30kBh5mGKrnWBgWx1vPPBm9jAO1KAPwv7iMTIKQg/WpAk3BPtVpivBs
         WXVvcHLDIGhTRoAZZ5RP81eJUGpKkWLmyl1UCWjeSIRI0KX3oVDKXGD/Ir3xo+xPrAsG
         3hteQkhSnbpTx5qSxMzFJcJBg4xyl5TQgKkdT9HWJ2tUA+W4V1LCGA1nGBSWKB5Tio33
         0qXUAligDZZnNy5YRz38RimRoXEqMIU9xx8i6dukhtaU3BsOR1bE94WZ7PmhnbQYcxdT
         QG7Nr1Luhyt1RngqJpGzvv2cuSsv3+zKgNx+U4fQij0/+Wu8IyWCpsb/+/9eMRJ087qk
         6ogQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=GoUejqotcjyUgH9590k/P+0t9DhFUeN+d68UZq2Xg8M=;
        b=DsvK5yx41pU8qnc+XO9yR+8MTmPOZ4L8kecnpgdoDY3b4rptaP/6mxTjzsbSypvNsz
         otAVB8E3NeSm63uIWqonv8CfixX0wOW/D6da2iE4w/cSf3LjMOocAFZHyIO7hnGOVbQj
         9vOsTYYDsCe6jkJejeAKvYlM2jWqWijWo4kk4RuVOLQ8Krvs7cS8ShINM/cl+3IuI8rY
         FXGx/LLXPjfgkwcptnlKy8CjRWLmZMwflwjmgV4Hb/b5Q/iota3dtfqP90UFXXsKnTEE
         yTdPb7kkptk5vOVrYalTJFOQESAwgBkAQrrfPM2AqwV5OD9TrWmIXPzwaDee7i/BLuF/
         xRrw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GoUejqotcjyUgH9590k/P+0t9DhFUeN+d68UZq2Xg8M=;
        b=sg2xQ20nxCRmu9phhaBl11ymAaGZzZFmpN7nlI8OPxyXePh0qELHX5QEyLJef4W7Om
         j+TG4olcBxpfHJIS2xcwf/xfcnso1XcZCXagVkvDHol9tIC5l0UErQHfCIU/qj58ROX/
         ehoZ1DtT3TvtD4ELo5jO8P3Yh+n0ERqMaIwI9n5aySBD2f9aoMYq+JHgsYA5jPvc+7KT
         Y2ST+sxAaNaFHCCBDvjw1ZGVO10whKFCXKpag/9DeUuKI2bD8utygBpsv0fhNRPgIAII
         oFu8MCkVsSQRExef0SRweUhD7Qsw7uRdCUBk97F6mgxUYwqx7i5YpBuZ4F20T0N/EZxj
         1NoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GoUejqotcjyUgH9590k/P+0t9DhFUeN+d68UZq2Xg8M=;
        b=cfhfKrXtVBvFDjx+GxXMGGvfMWR10V4XquP95K7dj9YEVHQPjGdFe9hg3nuTJi691b
         bJwDV7oqqt9moG3Xf5fqpZkX7RFQ6hfeZEAqdNtdrDX+xwKiuHI+7XGCela9iLMyF0J6
         d01TYHSlVhRgyt5f22I6B/vGgqtGBBmvLCrjN9eS4EGcT8MoqvQFG3q2hEUsnersclfM
         +AiPD0Yo3MNUL64SHlc5AzQ0PPi7HfJS09qHn+6AG1baZHC15GdyBQC7f5anwytfyUhG
         XDmes1kEbdQmStiezlQAXPsGqRni5suxltvC1/ZBRFOkkjMce0vowQgt7XHajX874ldH
         MRiw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531JzezACNcwUfTt0rXBcJGpQJ9iOkqTusEqF8M+kVtJeZI5mWDn
	/BFEK3ya+0VK/WvZd21mv34=
X-Google-Smtp-Source: ABdhPJzi2wVXzYAFg8MCBXErsSIjsTxncHtYETImuEAjxDyE7n46m9UJxCMANyjc7+9pqoRlFPeSsw==
X-Received: by 2002:a92:9f96:: with SMTP id z22mr49830934ilk.266.1594389477364;
        Fri, 10 Jul 2020 06:57:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1082:: with SMTP id r2ls2360283ilj.8.gmail; Fri, 10
 Jul 2020 06:57:56 -0700 (PDT)
X-Received: by 2002:a05:6e02:cd3:: with SMTP id c19mr53023832ilj.16.1594389476940;
        Fri, 10 Jul 2020 06:57:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594389476; cv=none;
        d=google.com; s=arc-20160816;
        b=FEOADfhvH1WsaCZz+/TokL/vuIQacCVACsRD0UXOd48iz1iEouJobdjcz4l2+EZU3v
         EZQFhv5eqde6WFW9dJjdg0rousEI/4/hI9n2vDgP5KrXSPfaeA354B/KcBzDcb4kHCMy
         JHZTzlpNULpzdCzUjk9zWyD8wHJvIRi3mjvhXGqT2qbn78fs13oyPenlAKFZMWlGPwoJ
         /rBW+ITh9/jXQPOe58IhmNBb83PT5nFcr4VSQAxX9Z1vIFYyqf8FJZaXxhyuDNk4E+T3
         CaOUTRhRf9i/maduC5SHtdE7FXqBa1tEK5KjMSlT5bPyvgg4hCD1nw5Fetv8eJ87ncA5
         J5zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=hTkqq23qrVEEpLfEWgPmtfyAVF+d7Tb51Txj9jE5iLQ=;
        b=aWclNSMgv+0rW0IxLAksBvMb9Ug9862A0yaKFG/D8bhMQqHQAhT9hBGFegpDPsJvh7
         C0foUc09d352881IPNtBL//GnrpJ9nBkinfsc6vmZlqXkOjRNWZsnwcis6116/7CwY1e
         oST1D6rwLd4HsJG8yK/o2rx8qqktgw9shzAyXyULOnl885RW8Rs90NWdfiZ+9DqDSOZ2
         6xkwf3hn8jXMgeSZAg7LIVDZmqjRVo4dpyjnVE9GPyS49WutvNZ6oB8ikjs8EgJ8M7LJ
         fKEoDGVpXLpwx+Ij10RD8120vXG36r2TC/j2t0H3XZLwadIgot0nNZkKMfOkVPAHSkYG
         iuRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id p1si424974ioh.3.2020.07.10.06.57.56
        for <kasan-dev@googlegroups.com>;
        Fri, 10 Jul 2020 06:57:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 61B831FB;
	Fri, 10 Jul 2020 06:57:56 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.15.46])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 28CD23F819;
	Fri, 10 Jul 2020 06:57:54 -0700 (PDT)
Date: Fri, 10 Jul 2020 14:57:47 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20200710135747.GA29727@C02TD0UTHF1T.local>
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org>
 <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com
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

On Fri, Jul 10, 2020 at 03:41:03PM +0200, Marco Elver wrote:
> [+Cc mailing list and other folks]
> 
> Hi Sachin,

Hi all,

> On Fri, 10 Jul 2020 at 15:09, <sgrover@codeaurora.org> wrote:
> > Are these all the KCSAN changes:
> >
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/log/kernel/kcsan
> >
> > And the same are applicable for arm64?
> 
> No, those aren't all KCSAN changes, those are only the core changes.
> There are other changes, but unless they were in arch/, they will
> apply to arm64 of course.
> 
> The the full list of changes up to the point KCSAN was merged can be
> obtained with
> 
>   git log locking-urgent-2020-06-11..locking-kcsan-2020-06-11
> 
> where both tags are on -tip
> [https://git.kernel.org/pub/scm/linux/kernel/git/tip/tip.git]. Note,
> in case you're trying to backport this to an older kernel, I don't
> recommend it because of all the ONCE changes that happened before the
> merge. If you want to try and backport, we could dig out an older
> pre-ONCE-rework version. Another reason I wouldn't recommend a
> backport for now is because of all the unaddressed data races, and
> KCSAN generally just throwing all kinds of (potentially already fixed
> in mainline) reports at you.
> 
> On mainline, you could try to just cherry-pick Mark's patch from a few
> months ago to enable one of the earlier KCSAN versions on arm64:
> https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/commit/?h=arm64/kcsan&id=ae1d089527027ce710e464105a73eb0db27d7875

As a heads-up, since KCSAN now requires clang 11, I was waiting for the
release before sending the arm64 patch. I'd wanted to stress the result
locally with my arm64 Syzkaller instsance etc before sending it out, and
didn't fancy doing that from a locally-built clang on an arbitrary
commit.

If you think there'sa a sufficiently stable clang commit to test from,
I'm happy to give that a go.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200710135747.GA29727%40C02TD0UTHF1T.local.
