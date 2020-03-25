Return-Path: <kasan-dev+bncBCMIZB7QWENRB2ED5TZQKGQEAWIHQXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id E625C19217E
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 08:02:01 +0100 (CET)
Received: by mail-oi1-x237.google.com with SMTP id s126sf1094463oih.6
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 00:02:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585119720; cv=pass;
        d=google.com; s=arc-20160816;
        b=DKphTjsBdj8eVQM3+nCPinVBDSPQqKbPB33N1Ue/8+kjW0cYdWtVkU9aHj5ZQl7obb
         fDIBG/ijtRygePtWrpaRU7C0aSUW+XGS/NFA9q22hGXufkVQtWsJRylbi4rr0cV5h8ea
         ON6ZvezXji+r3rX9+hMnUiZbimeR7wmmyhIYUA8UCEwHGey0Nw6KT23p49g6xwdeozGQ
         Gynk0mxfigWQ6ZwT5WxRJnQpWJkU1+Z6h4HBqLWb8YRstUqSIrV/wHkwyIUt6cwCjike
         6MYg0yRSKRIyZ3bNgdVbYXsYKMvOP+HrYdmEehF4TPl8fzMwntbAHx7lnQpb135pslFU
         5+1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=T0h0yEtarYsu8fCKWvi8NzhiWDDkui5f5uOOS3Nivp0=;
        b=jVDvUOvvrAa2mKCdenYOLgDO3dlq2RSGXiQcnJFClhZvpmJN8Ju3Fl+p7CyNeoXFFJ
         xkzLHmnFWCLsXOOuIA/krcPwBNh5Mi/uiBqmCQi8Kth/RCul3MSgAWukw0i2WfGuC0/R
         l0ANIwujMbcS8gql+GP3L0H9P/4fUlwTW7BOWhrI5WXJCFTRwz6yR/bkYfedLp5FQKfd
         XXYuFlKll5mxSkNrOhokCSWsIUAA/ENrqEQbWDBnrG3nSDOHvlFxW6884rFVi3kZzfxC
         oMXRTAO1nPSoUMUX2LO217p7LfCqlFg9zLULXJ1GTxscj5nHm7rXQiumSbCd96w/r4BF
         VGOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JmooXooB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=T0h0yEtarYsu8fCKWvi8NzhiWDDkui5f5uOOS3Nivp0=;
        b=NxiP6Z1LIZir8sg0SXfGe/sx/1soW8mY1GZ7kRS+LidoygTc/fUxOkL7gpi/xsNE7R
         KTgFShGO6EfRMxUMPl8CgsgJ27JVEFFSP2mVz4xR/pUiK3rgFIA75JwtkNDh5qc0DQhd
         Givcp95PjwBj9ChQtGZegNS3qw/ty4ONQo1QmsD5LQ5ZfcDK1UZPvkV1bMHc1MsXa1BQ
         xwhbSrtsZgktuGSQiEVNrpikona/r6ZA+BMpzc/E1k1/79Z4iUvUFe5k5oBkBxqoBnBE
         ONICSkKVCLi7ToBuniMKs+oF0N28B5M3A9TQ0WEBk1cPXjFVH/FwaOOtVhA3MsgHAqLd
         3gKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=T0h0yEtarYsu8fCKWvi8NzhiWDDkui5f5uOOS3Nivp0=;
        b=KmZyfAHJcU5QtsOvrUwr8cNS/gqPfjhOu1XGuGeUCwW47XDOSbuGAo4P//t3NssILi
         bBdifZEzR6+DTnkwyzp+WWgNR5IEag8lJx2czp2ZxflKdGtrrR7B6ylRTCdtnC8iAT6H
         9B7jY1pGm87mPIP8ZDtyTsEWIGvL/WE4kgjEdmZtiBY4O+RzUhfnb/GzhNehGJiQQIDk
         MJHfzlbD+Cy9gKtYnNcE24cBJV2Vii1XJc04e79a5gRjLnQUAXGV4Smv1adpdAbaLhsn
         8cEB7uKqtxnOIUP51iW/JaOW29HpSsF+TcMhRb9j2oPIQXEuOlInngt6WX2LSXkHFhqC
         SoHg==
X-Gm-Message-State: ANhLgQ2vHXn5/2Yh8cLNYYjsaZmjT1zl9Tqjl5DZOWtpFLTwl/D/Se7s
	nKqetI5jcgkpRs2AF2Squrg=
X-Google-Smtp-Source: ADFU+vuUGtDE2f5z51hWHibGYcA64UGf2ydbuFY49RHnyPqA9zqghWohJu0NnEkJ+UBsQ8GYFObksw==
X-Received: by 2002:aca:4cd8:: with SMTP id z207mr1406783oia.155.1585119720743;
        Wed, 25 Mar 2020 00:02:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6082:: with SMTP id m2ls307368otj.8.gmail; Wed, 25 Mar
 2020 00:02:00 -0700 (PDT)
X-Received: by 2002:a9d:6744:: with SMTP id w4mr1464432otm.220.1585119720370;
        Wed, 25 Mar 2020 00:02:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585119720; cv=none;
        d=google.com; s=arc-20160816;
        b=d1OjFIiYn6ArIxagjYdvHuenkNTotw1ZDHKRwGg/Gc7YFVrslXk8sUOInrHxTd7Wzb
         AFDAmytgz1uw5Cq2MQUPwxphcav7isL+18qyy06IH+pq0hqbjPgn9sE9+qM+V8C0m2V+
         WlcNVeKYL8I37BV5FJ6Q/DcoeGXH4cA/RScBRTkC8jEQeANbMBpwEZQfY0ifnswqcx3F
         ebMqEH0gGNarfG9hhdsjYxV+ZCBD1AXBOEWKe0WAlAZtg81aO4d9l6EyJ3t3dZM5drrW
         Mlfgg7n3HhcYo+pD1igZOoEJBk5Hn4EV0ZMQZsKOYcmA00yVwocoVk85VLuC61pPpZdS
         nTOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=o1bzOxpIYCfc405aT2K97rWEpKgnVHKtv3CEiQWv3o8=;
        b=O+Q4MjOUQ2glKT+6ciOz6qQPtZs/Lal/TxuvMf0NV4zJyIL6hOIV0XPcO0N1skyEq7
         QUw98d7uAXay3JZcuFjIOANi28eEQa5Cy9vX7DDUyR2Co4UWaoKGxuGN7DGNOzrFIXof
         xULd+9zVIRMdy135m3oKGhbwpg4tNKd9BrUn4rgzCCjgo738e7219RU+z5bOEBWx4ZvA
         N7vBPs6MxBeG8BDcuukhSviVRSJYayveXtkOnNANMwB93NYlSswz2DEjuFbg7/52pB8l
         Y4RiMMDCEonuaoE5smizYge+E07YXypBPyEHkHSkHHgxtAbZQyjdf6+2CgMimen0SDW5
         ms6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JmooXooB;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x843.google.com (mail-qt1-x843.google.com. [2607:f8b0:4864:20::843])
        by gmr-mx.google.com with ESMTPS id m19si536510otn.4.2020.03.25.00.02.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Mar 2020 00:02:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843 as permitted sender) client-ip=2607:f8b0:4864:20::843;
Received: by mail-qt1-x843.google.com with SMTP id t17so1324218qtn.12
        for <kasan-dev@googlegroups.com>; Wed, 25 Mar 2020 00:02:00 -0700 (PDT)
X-Received: by 2002:aed:2591:: with SMTP id x17mr1588738qtc.380.1585119719764;
 Wed, 25 Mar 2020 00:01:59 -0700 (PDT)
MIME-Version: 1.0
References: <5612aad0-2579-4965-8d8f-b3073ee52b56@googlegroups.com>
In-Reply-To: <5612aad0-2579-4965-8d8f-b3073ee52b56@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Mar 2020 08:01:48 +0100
Message-ID: <CACT4Y+ZoGe8gW5trnGaxNBVV0JHxioKQQvh+qjZfnn95ysu0_w@mail.gmail.com>
Subject: Re: KASAN patch
To: cyb3rphr34k <mfghani0@gmail.com>
Cc: syzkaller <syzkaller@googlegroups.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JmooXooB;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::843
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

On Wed, Mar 25, 2020 at 4:40 AM cyb3rphr34k <mfghani0@gmail.com> wrote:
>
> Hi,
> It's probably not the right forum to ask this question.

+kasan-dev@googlegroups.com is the right mailing list for KASAN questions.

> But syzkaller requires kernels to be patched with KASAN to get the crashe=
s right.

Hi,

This is totally false.
syzkaller is fuzzer, it produces a stress load and provokes bugs. Now
if the kernel will be able to self-diagnose these bugs or not, and in
what form is a different question. Without KASAN it may miss some, it
may diagnose some poorly. But it's true for every additional debugging
check. One doesn't enable LOCKDEP, they miss deadlocks or get poor
diagnostics.

FreeBSD -- no KASAN:
https://syzkaller.appspot.com/freebsd

OpenBSD -- no KASAN:
https://syzkaller.appspot.com/openbsd

AkarOS -- no KASAN:
https://syzkaller.appspot.com/akaros

Fuchsia -- no KASAN.

Linux KMSAN instance -- no KASAN:
https://syzkaller.appspot.com/upstream?manager=3Dci-upstream-kmsan-gce

Linux KCSAN instance -- no KASAN:
https://syzkaller.appspot.com/upstream?manager=3Dci2-upstream-kcsan-gce

We test some Linux kernels without any sanitizers whatsoever.


>  hence, to test older kernels, we'd require to patch them with KASAN. I'm=
 confused that KASAN is just an address sanitizer so why do we need source =
code patches to the kernel e.g for asan, we just need the compiler instrume=
ntation and we don't need to change the source of any program. So, how it i=
t different when it comes to a kernel? why do we need kernel level patches =
for KASAN and not just some latest compiler?

We need kernel patches because asan runtime for the kernel version
lives in the kernel itself rather than in the compiler.
It lives with the kernel because it depends a lot, touches, hooks into
and needs to be evolved with the kernel source code. THis is not true
for user-space asan, it does not depend on one's particular program.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BZoGe8gW5trnGaxNBVV0JHxioKQQvh%2BqjZfnn95ysu0_w%40mail.gm=
ail.com.
