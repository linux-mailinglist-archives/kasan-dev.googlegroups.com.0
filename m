Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV6WVKGQMGQERR43KZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 484694680C6
	for <lists+kasan-dev@lfdr.de>; Sat,  4 Dec 2021 00:42:16 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id i10-20020a056e02152a00b00293be3da5c0sf3177861ilu.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Dec 2021 15:42:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638574935; cv=pass;
        d=google.com; s=arc-20160816;
        b=jA1MtG5awNTKNFSHGEVIUMcZ30Bvdd3lEKXp75M8L1k5XU+zJJlw2UTKuIwFYkPLxC
         cP8lyGBzGRuCY1gINiwXKzCv14rPCN7wYxIMpiUvelX0UOILwVxxHmteURe7nOFsjrnx
         +eb+I82Eg43asCtIVBh9viT0OxYrWPdrKUjQKRgiEERtjhqi2nP+DDf807okT4T3E0RX
         OE0tEPy3fvLqsfd/Oa95LxQVwTvshMy8uXhVhBqOBde1Kw2dvTAHc9kVnrnD1EtQdmX0
         YZ/UlHFEd3lqARk5DvC/2ZUFIAK24AqGm9qjZ3swV/ltwhmV38aZa6Crbj/szPv9EWXL
         iHag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=67lphaQMkdCHFv8aON1GHCEvBWzbfULSUFN/MigvYeA=;
        b=iaRxG1og6tX2/8OljTAfOCUukpz+RK+0pZtbMRxdACXhIATIocKyQ5zs4MDiMDHxbk
         LjAM89GSOGrgOdu67oMyzQauApzfCpftGpQ3DO81n6+tm/X8tg3tgHMQ6xnCeV46JfUY
         WMsiEhE2yRlhS3htLLAxKv77STwhjdjJkNIJsj12mr0qfd4aPI0uYoEd5plFPTraDuz+
         0qtw2ZYe3AHSHSbFxQTwvt8ite29HwN4QYcR8yYHtiS4THX+nYU3C2+UbwO+dcK1fGv2
         yMNlujin02G8B/J1g5V5hIpfvBxHbW+7zVPD5XZwntl9x8Dwr//v6aYgEqvehpXXTPlU
         4lag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="AJ/TTnwy";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=67lphaQMkdCHFv8aON1GHCEvBWzbfULSUFN/MigvYeA=;
        b=sy5ZNIpoaFg3Xfe53x2ozDHC19hdL650mSy0ns7ETm/HT1Onbjc7RcKDgrO4AW0cgP
         ahR34ZGF7pRDNsQ413krunRlYRPDH3vCnZqpDGoAQ8Mc+zEweevlNKjmQ645EgV1YdvK
         22sVQxppCkxFVy4A1OTGvV6ZrPBeGTp5DMZgSppqFeJXMxcaicrTec6MEYYIcV+vuT+X
         FvXShv+MK7E6VlmPBORfBeClOcQIR1coNgw3VnF9IQKrfLNQQmH2BN9Ndu1otJnNszkL
         JIC+e4kUmUuYOF/bWCzwI0F3l+zxdLAoWOaDCktlD9ZHD44q0RF+LtQMPxg0jF1NsbM4
         siXw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=67lphaQMkdCHFv8aON1GHCEvBWzbfULSUFN/MigvYeA=;
        b=afgdTjvpIz6/YCtG6Jdff1+cSPcEcLHHxpxKLirhsO4C8QQL4Be6Mv48GyvCe5adsQ
         pZS2P4jm/UyXNAmLOv1D2Dcm61JWA8d2kbcR6kY5npjJ3Qn8FnKrwMVbrhwiqnD7e0ac
         JfSwa4ubueyfYZ6ArU6cIKGxp/RsI5BJPG7xjx33gt8p0Sg3Kylm9sBvAv3HLa2UM5dD
         mjjzzfiKkuo2KqtAT+qU7EthN5FkSETEYq03HM4dOf/sc3YhTk5xgE6La2M0zs4pMqIB
         yqqzV/WslB+qP+Xl3GSxlpTrDmFYm/g2omEjhfG3xgZKhF4UGpBZIGCqxKsxL7iLbTro
         V3TQ==
X-Gm-Message-State: AOAM532HHMg0+88oZ0Y7AL19axoz/s3ZnT3XKPk4S8372zCliV+ijvjp
	NRq3smMWBH4emLcDjvtc4mc=
X-Google-Smtp-Source: ABdhPJzLKEG90GEfHk9n6xA+NS75UHuhXiNkdpPq6aroRbubYLEOWMWA5Y0OQB5N+Z9n8eVKoaq+wA==
X-Received: by 2002:a05:6e02:1c87:: with SMTP id w7mr21982444ill.239.1638574935120;
        Fri, 03 Dec 2021 15:42:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:c554:: with SMTP id g20ls1254987jaj.4.gmail; Fri, 03 Dec
 2021 15:42:14 -0800 (PST)
X-Received: by 2002:a05:6638:16d6:: with SMTP id g22mr27546714jat.140.1638574934659;
        Fri, 03 Dec 2021 15:42:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638574934; cv=none;
        d=google.com; s=arc-20160816;
        b=YlMv8hLLnwWMsGawCJfZq8Z277pN9IV8Uxnkza7ic6IrqCYpcZFKUgmotTwTcWrZS4
         5RuUUsdb6elW5ghkuouKZ4ipTyX4TJjDkhYwDDuqGyTiI+Vg2yaqrvPkJU1Uu6Ewm7Au
         YO5tJnaRdTd47S6RkRrwyQyh/wO/kXzFGkZFGEWec/QI9OnivIG6qNAPScqUgfL9GAMb
         5spvx6nI56zibebRpXhIc7O11LwTM0Jv2xLnxX4PFEcA/4Tk9bJVbELCVAxScxh77PDo
         oNAM2DM5Nx8pLQTbsMfMACMtll93e7QP80QCHJDhYEvvK35DWpP6Phut3LWxlU5M/k+O
         2HEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4JwQlDJ0eW7f9hYvr2thOhENg/qO/ZaZzGs6+sDFshM=;
        b=Kl0TWECgoJg0fRnyt8F5/XFH0Ibeg9q3/DunWtq2n9wGleQUU1nefO9/50FF4Oi1DT
         Lgxj9jR+7GSeosCXAQtPe94FaDMkB7WbPN1QAvDzNdfcx7wjtu2eMjFt91oHZQyZLeGl
         iF9Nitopxs6EoanRXdPwTuEVjU3dWWw5lfbaycH8O2nzgCTM+eSEvIE6RVhLJyBujOAB
         K+qhjN9fALpXLg9uQldz20c8l3KRAVsQ0DdJ/y1Uv04F9iQdTz1ezVjq9+9iw8F/l7R4
         s1JTbM6LpuSq0SZEr7u7X2amL8BRY2KbUWss0tEFWKRA7wtn4+oDhyO3jCgrg36NJmko
         7/jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="AJ/TTnwy";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id l7si734481ilh.5.2021.12.03.15.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 03 Dec 2021 15:42:14 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id 35-20020a9d08a6000000b00579cd5e605eso5504132otf.0
        for <kasan-dev@googlegroups.com>; Fri, 03 Dec 2021 15:42:14 -0800 (PST)
X-Received: by 2002:a9d:7548:: with SMTP id b8mr18387018otl.92.1638574934196;
 Fri, 03 Dec 2021 15:42:14 -0800 (PST)
MIME-Version: 1.0
References: <20211130114433.2580590-1-elver@google.com> <20211130114433.2580590-5-elver@google.com>
 <YanbzWyhR0LwdinE@elver.google.com> <20211203165020.GR641268@paulmck-ThinkPad-P17-Gen-1>
 <20211203210856.GA712591@paulmck-ThinkPad-P17-Gen-1>
In-Reply-To: <20211203210856.GA712591@paulmck-ThinkPad-P17-Gen-1>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 4 Dec 2021 00:42:02 +0100
Message-ID: <CANpmjNM0X1iAgz4vHTH4FSzdWdr1PiQQnoyFt-zoT2_VonFvVA@mail.gmail.com>
Subject: Re: [PATCH v3 04/25] kcsan: Add core support for a subset of weak
 memory modeling
To: paulmck@kernel.org
Cc: Alexander Potapenko <glider@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Borislav Petkov <bp@alien8.de>, Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="AJ/TTnwy";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::331 as
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

On Fri, 3 Dec 2021 at 22:09, Paul E. McKenney <paulmck@kernel.org> wrote:
[...]
> A few quick tests located the following:
>
> [    0.635383] INFO: trying to register non-static key.
> [    0.635804] The code is fine but needs lockdep annotation, or maybe
> [    0.636194] you didn't initialize this object before use?
> [    0.636194] turning off the locking correctness validator.
> [    0.636194] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.16.0-rc1+ #3208
[...]
> When running without the new patch series, this splat does not appear.
>
> Do I need a toolchain upgrade?  I see the Clang 14.0 in the cover letter,
> but that seems to apply only to non-x86 architectures.
>
> $ clang-11 -v
> Ubuntu clang version 11.1.0-++20210805102428+1fdec59bffc1-1~exp1~20210805203044.169

Good catch! That would be lockdep telling me off for putting test
locks on the stack. :-/

I thought I had tested this with lockdep, but it seems the set of
semi-automated tests I run didn't (yet) generate a config with
KCSAN_WEAK_MEMORY + LOCKDEP.

This should be fixed by:
https://lkml.kernel.org/r/20211203233817.2815340-1-elver@google.com

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM0X1iAgz4vHTH4FSzdWdr1PiQQnoyFt-zoT2_VonFvVA%40mail.gmail.com.
