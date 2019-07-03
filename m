Return-Path: <kasan-dev+bncBCMIZB7QWENRBDHU6DUAKGQESTSJYMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id B5D725DDB6
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Jul 2019 07:15:58 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id j22sf753593pfe.11
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jul 2019 22:15:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562130957; cv=pass;
        d=google.com; s=arc-20160816;
        b=S8hncVqANqGULF9drfibCb8Aqa7dR10xkYDXWve+lwh7OEISn7DVS9SFax9lAlOWQ4
         MomA1uf8Yz1zzlXbxs8rvKfu3p1nE5ejo0vuQmF7jeevUP6PH9WRP652r/mHy5Q0K617
         cF9ppZXe0s0t/L/Q2Ud1RAVziF1dEMNJDBcPGcJzbQlHCdUyTFc6TuImS5mrfEwso0SP
         HTWTsMNCfPcoLq/KIDlUe+ldQu934IHicF2q+AUAAOlkVNhRKDOyeplKOJZGYJVNYkhF
         V0P9LdUBEu2nixTFLwGYv2lgqMkYmdbI0lehJ6pMb7nTeVVYBa+RqmXXBRbE+R0Ni90r
         Mcdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7OFSQzD/vTuun+G9e1k/NES5kYRMklOCvJ9NaH8yPUw=;
        b=MGJtdYC3foQDKLg5UKZZ78FPSNfg+IueNv16IHawfOpzRE/SXGa0/C88tWrvUWOjXr
         KszdWvbZpFOPk/fvSg8jMtlfdyv21IpZ4AU5Lk+qcdo0GCBxt63CQU4HAFqre8tTq+yt
         Xat8X+fx20HZGHm4pA8OsWkQFMqiHMPg1kpD9ks11vq6rJBUXp2QNorO6eDdgZLJpTkb
         Z9VCK5rjXE9TgRohiWGLUMAf1qMd1j1Hh4BzbRcOU5VOLLbTm18UeX8L9Cg513AvwAoO
         O4mHjhQCpkEnvBg5mQnY22G7rqCwlSvKiOGWLCYXqf8dO1Zb1dfuai8WuuMvFJ55ceB4
         vwdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WI4di9jf;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7OFSQzD/vTuun+G9e1k/NES5kYRMklOCvJ9NaH8yPUw=;
        b=EVti58QTdlbyBM8Xrrjvkzu8kNdSiaPs3spgvultwIBMhD6v2HKDz+ZZL/gRZRdme5
         uP9wevSJM3pHW24zVAVYaxZ/JZHSbm1D7ov0ukdnUj8VwC4xo/KLsLL7L/983ac5V0hu
         s1AHL3xOgsV3E63J0WE09z28g8POMtX++joTQ1AYvCJu9cS0dW3kq8v0wAeqrJgCAfgU
         dyZ+5D7iYHAfDTpV34/wK0aTzxRwmM7qFQJ2OdttjBisSzTHAjwoGmdvGUyhmtNfGQD3
         nVWEUZDJ+EecQfHNc3UcmJCG/O0wow7QRjaac858NYdgLw50SoW5ZW2jdX/4KW0NUWv5
         kOvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7OFSQzD/vTuun+G9e1k/NES5kYRMklOCvJ9NaH8yPUw=;
        b=h8BgcGvWyLGbnsMlZxhf7lw/eJ0VvfRpHkzWvg3aHvMc4nNyNw0taN1aS29thlX/wJ
         qsXeHcIQbNBtex1+OVWKLN/xQPe9g7tDGigX+deW4DSjt09bxK7/DrwKiwCc3MylmfZi
         RMYsYok7mHQLQW9ALcVXeOu6i0xZRbomf3h1K5e+BSRv063/7JtUxeBeUJF8Gu4cyRuy
         JZwDqycA9ORIia7VkJU53x/bhjvM1darIPWB/OHoJ04Ei4NADfuUYbMfBcKb6d7vU08Y
         tYu87X8POqQdjC9yqzNGZ8coU51a0WeC/adMrVwNdXUJhkNs3dPpl8m8MyY4TS52OnvO
         mfYA==
X-Gm-Message-State: APjAAAWelJdY7EDh5AV7u+UsST4prcCbPlsDOJzpOPzRYO4lwCyBCX6A
	sbW3u0WoPerya3ooTYSsaC4=
X-Google-Smtp-Source: APXvYqyE9XjYV+qqrL/9FfJ0eLObtpdMIuTJ51bmX2COjKhIM5FUOjusMSWuZz4XCdhKSesqRUaceg==
X-Received: by 2002:a63:1046:: with SMTP id 6mr15935530pgq.111.1562130957051;
        Tue, 02 Jul 2019 22:15:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ed0b:: with SMTP id u11ls204948pfh.15.gmail; Tue, 02 Jul
 2019 22:15:56 -0700 (PDT)
X-Received: by 2002:a63:d950:: with SMTP id e16mr36477210pgj.271.1562130956633;
        Tue, 02 Jul 2019 22:15:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562130956; cv=none;
        d=google.com; s=arc-20160816;
        b=GEAUuPbCG5NpQTdg/I6q3TmJ7itvK33E8OSN/ca8l1xYtinRh3bK2OQjYptllY0ZfU
         60JcLxK8po8IClJr7gtUZQP8kY1J2PCk1sd3V+WkgGbX8410VZfqW8T65IqV5CuW2YrI
         Ygrvc1ToPb5p+da+eEpje/iLRsLvRQhCubyyCerqyKxAlxJX7YYkp6lsj0ChbPTBWNm2
         vhLC7AKLBZmcXbeeEMriRfaguyCaNqLMNRtrVSXD5EVXqfLkUfyEK0CRz7D6KwEvscVB
         6nYBLE02OgT5MPtn3wC7DCXLfuOdQCgiYadjMnEJ9LdOnkOBhDQs5CoxmvxkN5kkdPdJ
         wuLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tFISfk1oJzZqboAPko4ozIYdd3T93WBp7TYM+XUynm8=;
        b=skongtKi9VSXzESyoyBofiYMS0EmSWwuCqMI9oMxqjJ76iSX1+xjNL/UUY57jjVkXc
         GW3fCijlApTyMg2jlhXHlL4fxgIrxx7BWni2gnkSsWDpIU8I4WrcKm1okEZ91r7usu8v
         Vkeh58xkUoXzBYaU1gZCE5xqnoUerJxVnNTB7FpKgg49Y97L652njPPcN16LROeasE2D
         gRlOtiCljW5d//VOQG29R7sXL7vMmT8TImEMd/TCaKi979gXO0JliT97GTpRTSUi2BIU
         kahIVvZsF7iBZGs5I93I1oCtmoMmebBO4Z4TJ3JfTqpeBioVGSIAZUk5HoG/ak/Qvxbb
         clJQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WI4di9jf;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd44.google.com (mail-io1-xd44.google.com. [2607:f8b0:4864:20::d44])
        by gmr-mx.google.com with ESMTPS id cm10si105523plb.0.2019.07.02.22.15.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Jul 2019 22:15:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44 as permitted sender) client-ip=2607:f8b0:4864:20::d44;
Received: by mail-io1-xd44.google.com with SMTP id w25so1774581ioc.8
        for <kasan-dev@googlegroups.com>; Tue, 02 Jul 2019 22:15:56 -0700 (PDT)
X-Received: by 2002:a6b:b556:: with SMTP id e83mr27329054iof.94.1562130955680;
 Tue, 02 Jul 2019 22:15:55 -0700 (PDT)
MIME-Version: 1.0
References: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
In-Reply-To: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Jul 2019 07:15:44 +0200
Message-ID: <CACT4Y+bNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga=BnkscQ@mail.gmail.com>
Subject: Re: KTSAN and Linux semaphores
To: Anatol Pomozov <anatol.pomozov@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WI4di9jf;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d44
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

On Wed, Jul 3, 2019 at 7:01 AM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
>
> Hi
>
> I am working on getting KernelThreadSanitizer into better shape.
> Trying to make it more stable and to report racy accesses a bit more
> accurately.
>
> The issue with Linux kernel is that it has a plenty of synchronization
> primitives. And KTSAN needs to take care of them.
>
> One such interesting primitive is semaphore
> (kernel/locking/semaphore.c). I am not sure what is the use-case for
> semaphores and why other primitives do not work instead. I checked
> some examples (e.g. console case -
> console_trylock/down_console_sem/up_console_sem) and it looks like a
> typical mutex to me.
>
> So I tried to add KTSAN interceptors to semaphore implementation and
> found that down() and up() for semaphores can be called by different
> threads. It confuses KTSAN that expects mutex ownership.
>
> So now I wonder what would be the best way for KTSAN to handle semaphores.

Yes, that is the official meaning of a semaphore -- it can be "locked"
and "unlocked" in different threads, it does not have a notion of
ownership and critical sections, only the counter. The counter for a
non-binary semaphore can also go above 1, i.e. can be "locked" several
times.

For such primitive I think we should just add release annotation in up
and acquire in down.
But how did it work before? Did we already have these annotations? Or
it's a new primitive? Or it is used rarely enough that we never
noticed? Or maybe it is already indirectly annotated via the
implementation primitives (e.g. atomics)?

We now need tighter synchronization on KTSAN as +Marco will start
actively working on KTSAN soon too. Need to avoid duplicated work and
stepping on each other. I think we planned the following as first
steps: rebasing to HEAD, rebasing fixes for benign races, fixing any
new benign races during boot/ssh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga%3DBnkscQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
