Return-Path: <kasan-dev+bncBCCMH5WKTMGRBC4H7CAQMGQEEOMPOQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 56F0A3297CD
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Mar 2021 10:21:16 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id x6sf4775030ioj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Mar 2021 01:21:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614676875; cv=pass;
        d=google.com; s=arc-20160816;
        b=DcH+su1kDviPdCWy2II84qgTD6xsZ6GO20SVhaj5KSfb39Qgp12o2xkBFXBG6g12Yv
         ZVTsETwONUX8XTeYmbBVQKhS29OEYtyDphP+9+ugeLHXOWQQgZi+W2n1HCue0hREEt0a
         c2w9sIer2UDg3FdjB6D9OBo9Vp6JKz1IC/aL9ApPkUAP9vkShdlGpJG3Th0shtBTRI7v
         dnZ/xrzZ+YyswytC+LB5DmkxRCDORwfXgJ3mqARP6z+PymBdR06/ETafEKDKiv4oPBT0
         D6cf0YmJW7OR7cjAHwbZqx0RsNXoaheLHoCep+WMsyDv9Mpl0C6K0qMLXZhzwilUvQ2W
         Zg7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3XiL5FewrhteQsQdVZ4dFhJ6j80HprJGmLa9tp46FqU=;
        b=IXDvqzmafOOG6iY/TvtoiJHdGdclliVGPAOTMTft3xjumjKG4NR/AGpaGAoCtLRdrK
         3p8Y7HUfl+fOaSD9JkMg/OMric1Gv0TL4jjDdWLbYgrMUE8X+rvdwBJO9yrSUGT/dv8h
         EBxsVIe7V5OqrdBoXgScRRDigca2ql3zydottRRBQtRmKWJMlVI6/KoxDUsPWCP3vcI7
         rONa3v8tYPY28Qt5T4iDC9uy2/9eqHUL3Lm5DMuTwHJWb/BqCKt832gSNMzReLL7g60D
         kPHCqV/6ZpF0iTlJ+QYQ6G8rhUu119y203vDIetBxZp9XQQrEn7XvQGzrksnBA2pGkMd
         3cvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gdg7LlV9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3XiL5FewrhteQsQdVZ4dFhJ6j80HprJGmLa9tp46FqU=;
        b=AlqNb9Hjoo21QiFHVGEiT7Qrn0H9iyickRzUkcgA/ZYByfXn4dikKZdQkIzfpqrFQr
         o9bcSoTaT9S929TnSj/Mb8MoCV+bUZjpJ9HolAHDPqZ4wNujLOrIwMIf/05jPWOpG+cS
         ebPsr4xGYQpYnfX4vDAn9oKt0EWqZ+YxzecPrcxGKV9TpDvsNH+KCiBZxXrKCCY0PeR8
         15/2DE1JhLsQ5cjyKECn2jdSdHH2qOs9Zxyvd+A9Cnvhi4Lj5GRmLgBZJD411h0Ke7AX
         xEVEEyMSQIRahSHQXV5Trp9EX9V+GdLRl34kOraUoAhPig0KdRZMHQt9DI4nh3kFJmwx
         Ud1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3XiL5FewrhteQsQdVZ4dFhJ6j80HprJGmLa9tp46FqU=;
        b=Oc2FTSfYeDq6TFfY4Fv9QwUYiK4Wt/7iCzyqqEzXIO8TSKSVA3GtnyGdVWs7aWJrkb
         e5qzC5m3TuKdP8070/c+fGZuJz4m9v6yiPOgw/1OLK6ZcWP77qUHsvH9Nu5Hx2JlJMCM
         iAZ/bTbmYrabjKmp9yLv6g/Z8Dgq+36iycYWmWmiG1+qPyWu0XsQTngZubl3K3ZVCaij
         kB8VoOuHYLPaHRrIZ0IyajBTRNjKdq5I2457PXE+Si+JpiDHtvmRdzKDJzwDfZACADCz
         A98ax6c4skKO4eTt4epNk0CFO4zfvv7mnWV1/0Igs0kABGb1gqn6r4bU3mJegOjWNBUJ
         J+5w==
X-Gm-Message-State: AOAM531DvIEOjL0pft2wG7dG9VbIYrDh8A9kNqMt5WWFTDRweggurolw
	LAd8YVm4s/VPNeoCF/4NmI8=
X-Google-Smtp-Source: ABdhPJyAOgVLOdQUhSlPJ3dOCmFhcGckcqCTL5NPsz2OXmXxJlkAsgctmD4ZRnsgixy7UszU72MTtg==
X-Received: by 2002:a5d:9252:: with SMTP id e18mr17940117iol.146.1614676875417;
        Tue, 02 Mar 2021 01:21:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:170a:: with SMTP id u10ls4688887ill.9.gmail; Tue,
 02 Mar 2021 01:21:15 -0800 (PST)
X-Received: by 2002:a05:6e02:f06:: with SMTP id x6mr15628707ilj.287.1614676875141;
        Tue, 02 Mar 2021 01:21:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614676875; cv=none;
        d=google.com; s=arc-20160816;
        b=Fuj3n9VV9kaBNeKouFk/5aUIHO2avJHylIQNVyA9cUJo7vEvKWdp7RdSJpGriu3wmx
         BZS25711Oog0q3pWbXS8o4ic+D45HiznWGxiX1SlaNPWiLJpvOMRXhxaXLQf8+Hgcc4I
         h3sKKh9v7MBSW9yozxYwoCWfVztHroIhPKO9mJvagDEGnyVuYL9K+W9egFzVRYIt4wp0
         J3lF8PdTUkLChOofjxg7/Sk9Iu14FFwETcZFuGaxtNDo1s9qXDnmsuILhIpHihFpKrmu
         YphfavOQIPuvrcjKVV4duQKhdo+88FiCKvfhtZYEpyYeATd8kbEb6bzsZThdd6cFJoxj
         S9xQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vwRL+zg0sY1QI/aDS9tQBo/9/k6q6jsJr21NnguWVBI=;
        b=ZuU/CWpy13w3ZB82QRMZLndXZIeMXNllnc5KKR0P3oN4f+E7C0F9OYIu4D4Jn4lMZ9
         wpj2ok9lHZmEFHgN1gmkWJDYaCjxq6cOtnLacfO4dqXZ1/5mnFIbD7LIkskG4XyhyIaq
         Yopb2xi8R2V66IA9DbLqrZMsL7NIbKu85hoayi37ZcWGOBwHU8YGVhFqB8fdsVA5J+bu
         kFHd4+fyp26irvZYyzPR3cdnLtt1ejQj92dACWvsdEJglg0mNJQOqVkFBnAXAALMJ2eW
         tjAVN0zmH5ac0zjP8+1HKDHIK5ei+T0LEm3w2jM05Gkgl5hCSF1LUySdW00JjbGGlIEy
         A7qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Gdg7LlV9;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf36.google.com (mail-qv1-xf36.google.com. [2607:f8b0:4864:20::f36])
        by gmr-mx.google.com with ESMTPS id o7si851336ilu.0.2021.03.02.01.21.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Mar 2021 01:21:15 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as permitted sender) client-ip=2607:f8b0:4864:20::f36;
Received: by mail-qv1-xf36.google.com with SMTP id n4so7245753qvl.4
        for <kasan-dev@googlegroups.com>; Tue, 02 Mar 2021 01:21:15 -0800 (PST)
X-Received: by 2002:a0c:9a04:: with SMTP id p4mr2656029qvd.38.1614676874297;
 Tue, 02 Mar 2021 01:21:14 -0800 (PST)
MIME-Version: 1.0
References: <51c397a23631d8bb2e2a6515c63440d88bf74afd.1614674144.git.christophe.leroy@csgroup.eu>
 <CANpmjNPOJfL_qsSZYRbwMUrxnXxtF5L3k9hursZZ7k9H1jLEuA@mail.gmail.com> <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
In-Reply-To: <b9dc8d35-a3b0-261a-b1a4-5f4d33406095@csgroup.eu>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 2 Mar 2021 10:21:02 +0100
Message-ID: <CAG_fn=WFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw@mail.gmail.com>
Subject: Re: [RFC PATCH v1] powerpc: Enable KFENCE for PPC32
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Marco Elver <elver@google.com>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, 
	Dmitry Vyukov <dvyukov@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Gdg7LlV9;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f36 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> [   14.998426] BUG: KFENCE: invalid read in finish_task_switch.isra.0+0x54/0x23c
> [   14.998426]
> [   15.007061] Invalid read at 0x(ptrval):
> [   15.010906]  finish_task_switch.isra.0+0x54/0x23c
> [   15.015633]  kunit_try_run_case+0x5c/0xd0
> [   15.019682]  kunit_generic_run_threadfn_adapter+0x24/0x30
> [   15.025099]  kthread+0x15c/0x174
> [   15.028359]  ret_from_kernel_thread+0x14/0x1c
> [   15.032747]
> [   15.034251] CPU: 0 PID: 111 Comm: kunit_try_catch Tainted: G    B
> 5.12.0-rc1-s3k-dev-01534-g4f14ae75edf0-dirty #4674
> [   15.045811] ==================================================================
> [   15.053324]     # test_invalid_access: EXPECTATION FAILED at mm/kfence/kfence_test.c:636
> [   15.053324]     Expected report_matches(&expect) to be true, but is false
> [   15.068359]     not ok 21 - test_invalid_access

The test expects the function name to be test_invalid_access, i. e.
the first line should be "BUG: KFENCE: invalid read in
test_invalid_access".
The error reporting function unwinds the stack, skips a couple of
"uninteresting" frames
(https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#L43)
and uses the first "interesting" one frame to print the report header
(https://elixir.bootlin.com/linux/v5.12-rc1/source/mm/kfence/report.c#L226).

It's strange that test_invalid_access is missing altogether from the
stack trace - is that expected?
Can you try printing the whole stacktrace without skipping any frames
to see if that function is there?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWFffkVzqC9b6pyNuweFhFswZfa8RRio2nL9-Wq10nBbw%40mail.gmail.com.
