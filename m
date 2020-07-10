Return-Path: <kasan-dev+bncBDV37XP3XYDRBBWWUL4AKGQEPSVNPMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AC5921BCA0
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 19:53:11 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id 13sf4971151qkk.10
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Jul 2020 10:53:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1594403590; cv=pass;
        d=google.com; s=arc-20160816;
        b=Aww+1TT57hUiZlkMO05SpRoSpyY0eafTZA7RY5WudFgfOT4hMhRP4RtlJhZjrqfhL8
         HNzf0JH/D1fIJTSU2ZWK0bya325+35F0I3ZKjFbJFRBwUJbXDi3dm3NlF7mmfKiNKA71
         TfzABb+MFOo6CHXabvKibpCbCJx/KWVubn5SI43OBFLpCeNFx7tTFnfJXoZOP6spy9Xd
         FxKe3E1WzuhkdOBUSDIH/Aj8u55lSBd3GbeSFU0whkiDHuNF8jY5qLzNt+w2JTQbKbut
         4hAwgwqUyT9qLIF0x9NRrWPz3/Zmpyf7PPAkUvnvfNj9ksLDkzIHcwc9rmQhMV0mVOT5
         n9cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=aP8iEHAzUZ7mC3xO4WhG9rJKIerKXMoXU/tM9q5UppI=;
        b=i+K6BIL6RXzZdCDMHid2KJ+bskMrTeAoKGe3VMjO21TWqnsotD2dgNDT6wJT6879Y1
         6SPe8VKd0gAO4puziVVjYx1kd2tCgeFIvUNG8SLfO/e7n14fFBjk8+gMEyl0cl1KOswS
         wR0GAEB90fvp8GN7OK91N3Ea9RjseIHRb+fXfqjy7wtC89CdGkMTLF4TSkVgUv2qBiuS
         LCziA9dPk341ru90r0GIJm6BcKz66/A0ZvKJLw/xaKnDGnlsCw1/iZ06bVLYnVUm7J4T
         cXSp06ni8hOAKRnrb5RFJ1QlM4b5MXVkCMkb/k9vJvuk0WFZYy5d6Uwz5Lk1vKVUVf+Z
         ySWA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aP8iEHAzUZ7mC3xO4WhG9rJKIerKXMoXU/tM9q5UppI=;
        b=FR/y98aakgmVcGJJfePY/2jNbMO51jfd9K63Y2HLXkT7vq3FlqKTspjvcWIVdKav8c
         mKiva7cvwEF3Cu9hz1iQ9+XtoyQeSkZo+WhAi4qVyFvM3oRasIIoIZF7qE7pu3vM91Np
         cIhHYsVl5wSYTuCXdgWg89Um3D2BGZxUoojLaAiye9qv5ZJYzM7kO24DfoZjk5n2TvcX
         7WUlnM3jfmVYv16g2R2Lre9IpZFHM7X4Ze6WLD8dMJRzh2hzHHzxVqKfhlqkl/5Iygv5
         pZ/KfdbXO0jm/SGDRs6XqFSz/arkaGo1wialVRRjzr+KdFLkhQidPUbtEaBhwp1rfzZY
         VIOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aP8iEHAzUZ7mC3xO4WhG9rJKIerKXMoXU/tM9q5UppI=;
        b=bh0NkGTjHre7Z+QfCXLXATDTNNy25AXyXJqM4TW7jYCpMp0HiGOrLFz6vkzFRiuaW3
         kxSpYgkHLHTU6JwJNTbcUV/t35YrIWpq7hHYyT3zY3y31VxDMulKuOO/WDTqGm5ACx6U
         Mr0J8r9Y0M7E/rhlHv9BTkSSZfy6yC6JToWxIZuBF4nUS7FeLBFIF+/5DwDlHbqEXoA1
         qOIpeQrUrcXJRFDLxAdkhgrRzn/QOsEtBJtnxCQta/paUXGEwQ9pqjVPZm+fJyLreP/w
         C2qFHZBJN2vyqW1YsyV9m+moctHXI9+tXIrCGZlU13PFWDDb/kEtCGL9sevNyU1sLkKL
         RgCw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531dIrPld4Hh56TH5ZCVDuydP9zJAn+zwltPbdqHQ+ncZ6VFJvA5
	J6kMgS4BYIBSXWNp74IG+/M=
X-Google-Smtp-Source: ABdhPJwh3ltzBV0U52VhmP9Iym3UiX3BPE+tGLm856iH28Y8GLKbROeTlvVfVIzHtA7FQrudN4aftw==
X-Received: by 2002:a05:620a:a1b:: with SMTP id i27mr69827973qka.429.1594403590516;
        Fri, 10 Jul 2020 10:53:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:522:: with SMTP id x2ls2328033qvw.3.gmail; Fri, 10
 Jul 2020 10:53:10 -0700 (PDT)
X-Received: by 2002:a0c:fcca:: with SMTP id i10mr66187167qvq.150.1594403590078;
        Fri, 10 Jul 2020 10:53:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1594403590; cv=none;
        d=google.com; s=arc-20160816;
        b=eiDSjGuPtapGFmp+uxenQJuZhwL5SCyp/CpvPrDMpafUdS3Fry1Rz0y9VA3MeONly8
         1i2hsS2PtaJgqwmo3Lmjx9JA/ujRbpax+hfBTPqhUT/zkth2zXopigMvy/iMhw1x/zMD
         ZXASlu3jsTwwt6mmjPaMLz31BxywKpUUrJF3IkSj/GUCnHRCCNEXLfOblDeKrgmU+KN9
         W3LusKPlDtq/m+JzYuhMzFSmGeCO3F9qbRpUogy5E6kifyGG520KsysMvSL/SQp1iZQs
         fN5BpsmOu1sHB7gHlnssAqtIJrXEL6UPy5Ml8tkkVVhWeSZvdOlNrPgPT7s0Dot42B5x
         pnGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=s/07MiHHwC8EdazGqOe62CkL9n5fpMe4wPqojzi1F4U=;
        b=lMQeNqulM7ccCWWwQWp4GlItBJtLsYo28+aQ11kkdFU+8pageqnBbmlKcw7HKtgeFP
         1mzULcLYgM+oje0EZwOA3ksBNeJmX27PCmSYhMlbS70MpmewxKwR4xpPGjdcgNwqxVTK
         Z9hACBgkpViidm+ELe4DzDvl2mNjdb9axXqk32RPOL5bbsuNsoy96HNyFusQ1/uE0Y3i
         lZLS57hb7XhxwJ5VhTANJSPx2V6uaozJo2yUX5CX7dJtwFsVv9dDwX5hsdnQnVGvQshO
         DdgCbwITLfAnhXP/wga9Iq8LKjCAJE6OiWhcvjPqr/723EAWeXmXhmBHklHa2mh896HI
         ktAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t55si335710qtb.5.2020.07.10.10.53.10
        for <kasan-dev@googlegroups.com>;
        Fri, 10 Jul 2020 10:53:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 84F8131B;
	Fri, 10 Jul 2020 10:53:09 -0700 (PDT)
Received: from C02TD0UTHF1T.local (unknown [10.57.15.46])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 166743FA00;
	Fri, 10 Jul 2020 10:53:07 -0700 (PDT)
Date: Fri, 10 Jul 2020 18:53:00 +0100
From: Mark Rutland <mark.rutland@arm.com>
To: Marco Elver <elver@google.com>
Cc: sgrover@codeaurora.org, Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KCSAN Support on ARM64 Kernel
Message-ID: <20200710175300.GA31697@C02TD0UTHF1T.local>
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com>
 <002801d58271$f5d01db0$e1705910$@codeaurora.org>
 <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
 <CANpmjNM9RhZ_V7vPBLp146m_JRqajeHgRT3h3gSBz3OH4Ya_Yg@mail.gmail.com>
 <000801d656bb$64aada40$2e008ec0$@codeaurora.org>
 <CANpmjNMEtocM7f1UG6OFTmAudcFJaa22WTc7aM=YGYn6SMY6HQ@mail.gmail.com>
 <20200710135747.GA29727@C02TD0UTHF1T.local>
 <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNNPL65y23Qz3pHHqqdQrkK6CqTDSsD+zO_3C0P0xjYXYw@mail.gmail.com>
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

On Fri, Jul 10, 2020 at 05:12:02PM +0200, Marco Elver wrote:
> On Fri, 10 Jul 2020 at 15:57, Mark Rutland <mark.rutland@arm.com> wrote:
> > As a heads-up, since KCSAN now requires clang 11, I was waiting for the
> > release before sending the arm64 patch. I'd wanted to stress the result
> > locally with my arm64 Syzkaller instsance etc before sending it out, and
> > didn't fancy doing that from a locally-built clang on an arbitrary
> > commit.
> >
> > If you think there'sa a sufficiently stable clang commit to test from,
> > I'm happy to give that a go.
> 
> Thanks, Mark. LLVM/Clang is usually quite stable even the pre-release
> (famous last words ;-)). We've been using LLVM commit
> ca2dcbd030eadbf0aa9b660efe864ff08af6e18b
> (https://github.com/llvm/llvm-project/commit/ca2dcbd030eadbf0aa9b660efe864ff08af6e18b).

I built that locally, and rebased my arm64 enablement patches, but it
looks like there's a dodgy interaction with BTI, as the majority of
files produce a build-time warning:

|   CC      arch/arm64/kernel/psci.o
| warning: some functions compiled with BTI and some compiled without BTI
| warning: not setting BTI in feature flags

Regardless of whether the kernel has BTI and BTI_KERNEL selected it
doesn't produce any console output, but that may be something I need to
fix up and I haven't tried to debug it yet.

For now I've pushed out my rebased (and currently broken) patch to my
arm64/kcsan-new branch:

git://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git arm64/kcsan-new

... with a note as to the brokenness.

Thanks,
Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200710175300.GA31697%40C02TD0UTHF1T.local.
