Return-Path: <kasan-dev+bncBC7OBJGL2MHBBUEIYXTQKGQEDWWRTGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-it1-x139.google.com (mail-it1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 5600331100
	for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 17:12:17 +0200 (CEST)
Received: by mail-it1-x139.google.com with SMTP id m20sf8430824itn.3
        for <lists+kasan-dev@lfdr.de>; Fri, 31 May 2019 08:12:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559315536; cv=pass;
        d=google.com; s=arc-20160816;
        b=Mnt5XEw3Qeit0G5aC+/qXWYU4zYYAGbcCxuFzY+XS+vQ35xle3fIwd8/Ow5H3T+kpN
         lpmQUtxCMKnthfNP5pd0XpPpvtXkufFuRfm3Z61CTUWxvwIA+NgSQDyaRvtyiAvftx4b
         o7Vzdi/9mP51mLXaKgZZnAmBRPJIB4S3mEpAaCm56Z+03dp5zgRmdpXyGyixHrxk8jzl
         QuTFIS/vgkcyWtwTPlh6fdHCZAgLvedi4bxWbCKpnzsRgk6Et8ephw5EL/xwhP06JW8c
         cBeqYa1WSgRbL+Yt5zk6CBb8+F2+dGYx2DfqFs2adFKXSF99Hicxy6vcR/URkHAMS/pL
         zW5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=M4/pi8zFpPFzjIbOygG3pDl1SD9/F/GTYAn/DhZ1HnI=;
        b=gzIsPQ7qG62os8fj3x3ROKS++7DJ+0XV8PcxO9Xv3L8jjQ1QtiI+iMPK/glvbYydTs
         XkoqWHbXyAsu9BwPWgLzuSEYGIeZL+uyRy+GqMYQZQ5NRMDh+dPCyEJD4AJ/mtKR8agz
         u+EGlLLh+nZfhOiCFR3Mq8R6b8BAar4UwiZ20qN5S4g92KQaofWbm596MLCx4DK/JpuH
         dh/XWWPG5N3ye3Yy5MlMQEKWFu8i/sKexeU7tpz5qoVZFg9nGqj32a7kfcKVKwPu+hoQ
         ewFtqDodnpwYBbS6+DMqxIdWKxu1lXAyc+msfzzL6AtPXdMBXLZFo/ZZYbb1b4d7RQ8x
         Cj/A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nXGiYMKO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M4/pi8zFpPFzjIbOygG3pDl1SD9/F/GTYAn/DhZ1HnI=;
        b=BVIpLl6TkA2lK66g6pvEkI0Lnjt+6qNkPpd4DYdy58xOz9LsAHWI+k3AwoxWzzF7Sd
         T0BO2pX5RmOYk8c3mz3I2BC3xhLqMwZm/a4p7ggXapBBv5TTjAV8nICPmJh+0u23tlxH
         yXMrvcDhmsR1lRMsISOTUk00uY3SqCQLtXN7alRX+rEw8eSa6ELB7RT4fx6r0BGv77Vn
         z2raCtt4E1VyGz8uWMUVwc7V5hytw1V28PwW/LfyKP0FciGxi9/3FF/hlY5+awOm3zcF
         3LgcwxYzhHt44rtnrrsYiIuHRiuUKfvHxHpu+A3NyodkiEUX0RcAble7sarUG+0dcikd
         QYNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M4/pi8zFpPFzjIbOygG3pDl1SD9/F/GTYAn/DhZ1HnI=;
        b=oTmzM808OFHsjz/KfeyfU8xbzikh7SumW9/RSMCLFzxZc1r8gl4UaY3UhpD+LCwxmp
         iwLh44RoSn5I42JTuJIG0QsxcnLpVS+Zi+lCqhtPhSu6VjF47mEzF83tRJMtuv9vaPXE
         xiCquHNP63B1FpDN+cs2yh0n072qmhDI14YomO4BtcaSPtmvn+nTliw1plxlY9UVawEl
         JNHBF7rJATKkwsWWB1ImLDyTLuJ+VynHRsXBJJTpu6nsDlpynGy6EDHHFPwN0ThiNLDq
         VKPl5LFVL/DhFFOrr+ZbtBtSj4QuKFdBnjJX60B+LQdCnJ/QabICuLjwgwmEplUfRPIi
         r6+g==
X-Gm-Message-State: APjAAAVEpVi0hom9w7hI7y8lPxyZwdzkJ+CnOSceMdBhNIQ2+j8hYJos
	ucXHstR83cRYWKG2nJy0GLE=
X-Google-Smtp-Source: APXvYqzcEdbz3Q1cWtgg7vERZV8dCz3nmxkdS7R7S40L/fNy4iTC7f6psP9MUJrhFHjQkVf4JtJIkQ==
X-Received: by 2002:a5e:8412:: with SMTP id h18mr1573267ioj.268.1559315536124;
        Fri, 31 May 2019 08:12:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a24:914:: with SMTP id 20ls2911607itm.3.gmail; Fri, 31 May
 2019 08:12:15 -0700 (PDT)
X-Received: by 2002:a24:160e:: with SMTP id a14mr8254009ita.119.1559315535761;
        Fri, 31 May 2019 08:12:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559315535; cv=none;
        d=google.com; s=arc-20160816;
        b=bGmvEoafn3sI6+5fQywwA7BZeMKue1/iqW5CdPxeirT2P68rrcslXAhOLHtCq8XsTK
         yxgzfDid8ZUPYmjSCHnGXGq1b2PsaMI0Rbf/Pi9GMqSZ3zaWKARPN1BcTfDDyfl469Vx
         teNmj2DhpnrtoU7cU5AdyGMLqebE3orR4kAd5gA010mbhi5lB9TIUZ+B4/MlQkYpOE3m
         82YI10xIDWOKRY+E4AXmfm/pkiiI03Gh5fqPOeDI47BCgDbxt5bE+C6mG7GIJy3gtpJY
         TJgRFeOFB5a4Sy8d74eUzwZSYp8OB6qGPNR0Gph+xi1kTrf6KjS/EqrimTRby1DoccDn
         H0qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3Qecf3R/ylaKOMr7DmXC4K+hYJVpsjs/jTI03UY5jdQ=;
        b=Ancl6jjQDNFvqebrvYXdsJTUvbyc2QyRe1zRjepn33c5SQlDFw3YH8gvgyemKPDxwa
         gZFNCxQWyyLXhLiz01RDfgJ3+lSKZ9ZmG8ganWtt6fgWto24uJU/L+lO/SMte/kjSJ4f
         8kD4YZVo9l3/kUUUdpx5A3XWgJF72qSj1ONxY7vZTdJJm433Q+sgcHC6Q1+iPPsGaN5X
         /mQA/G21RhkbFZhsKS9wsNNNnZsdKqcOgLhly4HzwGEybOzi0c0ZlcRrLzl+w7TZ9Hd3
         XOMATKLDHTQwdmlmIohiInzHQ8nIr+vdvzuJqgYL060E/E648EO4AXaWEbSh/G272r3W
         ePmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nXGiYMKO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22c.google.com (mail-oi1-x22c.google.com. [2607:f8b0:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id y3si400841ioy.2.2019.05.31.08.12.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 31 May 2019 08:12:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as permitted sender) client-ip=2607:f8b0:4864:20::22c;
Received: by mail-oi1-x22c.google.com with SMTP id u64so7992529oib.1
        for <kasan-dev@googlegroups.com>; Fri, 31 May 2019 08:12:15 -0700 (PDT)
X-Received: by 2002:aca:e044:: with SMTP id x65mr6446367oig.70.1559315535037;
 Fri, 31 May 2019 08:12:15 -0700 (PDT)
MIME-Version: 1.0
References: <20190529141500.193390-1-elver@google.com>
In-Reply-To: <20190529141500.193390-1-elver@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 31 May 2019 17:12:03 +0200
Message-ID: <CANpmjNNH2e5YpxKymXE0sTgcrrW0z0EP+dEsPJOfTQJ19yS_Yg@mail.gmail.com>
Subject: Re: [PATCH v2 0/3] Bitops instrumentation for KASAN
To: Peter Zijlstra <peterz@infradead.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Mark Rutland <mark.rutland@arm.com>
Cc: Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nXGiYMKO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Addressed comments, and sent v3:
http://lkml.kernel.org/r/20190531150828.157832-1-elver@google.com

Many thanks!

-- Marco

On Wed, 29 May 2019 at 16:23, Marco Elver <elver@google.com> wrote:
>
> The previous version of this patch series and discussion can be found
> here:  https://lkml.org/lkml/2019/5/28/769
>
> The most significant change is the change of the instrumented access
> size to cover the entire word of a bit.
>
> Marco Elver (3):
>   lib/test_kasan: Add bitops tests
>   x86: Move CPU feature test out of uaccess region
>   asm-generic, x86: Add bitops instrumentation for KASAN
>
>  Documentation/core-api/kernel-api.rst     |   2 +-
>  arch/x86/ia32/ia32_signal.c               |   9 +-
>  arch/x86/include/asm/bitops.h             | 210 ++++----------
>  include/asm-generic/bitops-instrumented.h | 317 ++++++++++++++++++++++
>  lib/test_kasan.c                          |  75 ++++-
>  5 files changed, 450 insertions(+), 163 deletions(-)
>  create mode 100644 include/asm-generic/bitops-instrumented.h
>
> --
> 2.22.0.rc1.257.g3120a18244-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNH2e5YpxKymXE0sTgcrrW0z0EP%2BdEsPJOfTQJ19yS_Yg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
