Return-Path: <kasan-dev+bncBCMIZB7QWENRBGMURTYQKGQEMZDEJYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 97E871417B8
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 14:37:30 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id j16sf4604910uak.16
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 05:37:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579354649; cv=pass;
        d=google.com; s=arc-20160816;
        b=pilmh25/Mrlm5TJG9G9CJDSLyWPKW5atW+z0ZmYFO1K3b3S3A5YtjfTWdgOiE0so1f
         Mi3J4Ah2jqxy4C9hN9AfzM7BtHZyKclloh+wscXsVvcxpfUgds6h3iOZ0E5e6j9+m0S/
         jMcJMkYcpXikd7DvpKHMfE/WyzV6MCDA0A4i3UD+HpuuydinaE5kVJxd7HpFnFruHVTh
         /FsHZM2YGtiKIZ57F60hK1DWGdjk1SXvgEngbQeMl95jQJP8KyMPLt1bSgEbJwfkkQES
         m1jH75Rr/dqLnVD6ZDkxGItwxVIo0kJqAve0Dp65tt8JV+rE6s82XoaYwd4zltei35PY
         DjJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=blmMSTixmK4gZkQWjSofniufxBgXV1DwKSGPMyTvkKo=;
        b=Sh09Z37bcg+nAaah5hAwrPgOyuR6AundBuwzwcYWE5hMv/W+jUNRt5VxLSAxuKJrAB
         qDWDRuXv+Zqms/v0YpvmGISuNXtHYh+LHhlELDVoevd7TmJz9KmRBrOTAtjhCG2WUmVL
         gw8Pn7cqv3TWdATjAz5rB6+RjmzGXpBLC9k3utxjqqjFb35HpM+1ahVfaADjBc6hbX30
         3pjuowdXq25tiHP4GphUFL8x/YSj/Bgk2dHhguIpwCCVMsiPVDaCFVHcURERRxliusBh
         CyF5MBTmslQ70FtWjB8+LX7KSHdwJTHVTb37gyF5PDTBxjjyma25xDJztWPxuZExCYAh
         pJzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EY3A6DSL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blmMSTixmK4gZkQWjSofniufxBgXV1DwKSGPMyTvkKo=;
        b=JtqZf6y6FQDGVzijMxvEXiYNqdBMNPYMDw+HHfnQ7CPjRyJvY3U+McELsxwzQSBFBz
         AKgeqoS9WKLwMHmYHSf9kXe9sZr2x3I3tYZZy/ngDRq+6NPD9TI+Z2kVp0tX7ei7hFgD
         f/yhS15qAyV90d4AfPE3S4KqVf8/ZXLhjiqnaj8NU7sxBziM7t9LtHmsSEdP2/yPSaoR
         2jS4VyPhLpfIfKC8358N8P+WfYt0oA2O14GUNv0MRKt7OsU3qx/Bk/iPyutnSzbiWT9J
         uMGgfMUhr3Y2L1iPkzCnxNTv+FALZt3HouVDhPMtqr2lKgyEacRHje/B7WOaFUgJEq9I
         5EyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=blmMSTixmK4gZkQWjSofniufxBgXV1DwKSGPMyTvkKo=;
        b=OQZSmaKVeD1F4qb8h3rR+ObyTev4Ss11FJyDfYF8jPMLWeuIpcswWwLFcPUjyZpKcf
         lQCiJJFNjquojsnAso+bDWL+9qnoHLOHsd0gVZyL5iTv5CH73hEyxRzoZgsi5yoN0Mvz
         i0O6MUE9Fe2Aihltu97nL2fk51dY1gnPS6Rca7rkOGV63zWdDiEq4F5uSkUg+K2e7fQd
         9OvHSfp9UyKT+CfBDvpKGJx33pZ+/Be5k5MOt0lVylCrwXAvoStwk/RcteuVlFou9uTh
         MNdg/lJrf5j92B5K1QUrFQGAA3hgxPFrdG1rSd8Ik78gSb6NvdTVqZYdFuAzqteNLKTy
         b+NA==
X-Gm-Message-State: APjAAAXl4E20c6mrGOeLJWdM8vfqxyav6r1TOsiWT925ywLl9mJ2jaeW
	h9dONR6b6YDf5sGZW8F89+U=
X-Google-Smtp-Source: APXvYqxg8fmNJIhr8xEpObpv79f6rnhqc8GqD0BSPnoNan4kcPMkfvb1/P/KqxDUvT/0GRRamKVNZQ==
X-Received: by 2002:a67:b64a:: with SMTP id e10mr7004842vsm.42.1579354649563;
        Sat, 18 Jan 2020 05:37:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2aa:: with SMTP id 39ls1618999uah.15.gmail; Sat, 18 Jan
 2020 05:37:29 -0800 (PST)
X-Received: by 2002:ab0:70b6:: with SMTP id q22mr24313362ual.78.1579354649188;
        Sat, 18 Jan 2020 05:37:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579354649; cv=none;
        d=google.com; s=arc-20160816;
        b=VW3DbBnm3CZ4RCayhnz01Wlb7z28ZJvZE0o7BLDJJmxSSHbCNyf5KvRf1w1PE4ptU0
         DmNljtouQUEDOV4c5z/bmx5PH3gmwvBsPm7V/w/8Qh7E9GIRB6NqUdDTsM6bxOR1yadX
         KblQFnuWKkA5UpquzKt+tgo+XhTqZGPiQ7PMC5svNU2LXgRVhwi6wyoYC51cPsFUSxoQ
         xUIEMDAotv/JZRG0ubp31QLQy6Wg7Gc6aBHt4/LLJ2FyGVPQddKxVXHm0qZ5f5TaXFF+
         p4bkr0RHqYR8yaRdL+cfBZM9G3glStItELo/kcNPXpotGJ2W21T3CnuXBWF2GQ0W79FG
         8sTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VF7Ybre9nicDdkbJ8YLCx9ZGXACXxQfpsesRhP5xc4k=;
        b=YCz4h4FBW2cgnBr4+xXzWDNpZk4xLZsgA0d4JRs2yozM2yHYraXxkrFjBgPxP287iD
         nT0qQDpw+Fup2curm6UrqSBRXknEEsVVtBy2KPz+sdQPSFfdy49bgpwNo0ZzXYfHT+V8
         FSdsQ8ALgvQTAI3JKiqFZmqMLcXKBrRPdVvyoIvNSgTbDceZX18jHqQsaYw6xebkdefn
         1zYjOn9zSrOZbbUslP6Hal4Z0KEHeoy7Q/1UYic9qSykrcZYwDMbJAp4QznzqZEjE9oa
         nYMKAnO3C2Hwe/LsqHPYBMIBUIK9s7oZRigjRs9hdPNNXXZrtDChdbFONjS49Ahs14fq
         R5Gw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=EY3A6DSL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id h7si1183636vsm.1.2020.01.18.05.37.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Jan 2020 05:37:29 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id x1so12013395qvr.8
        for <kasan-dev@googlegroups.com>; Sat, 18 Jan 2020 05:37:29 -0800 (PST)
X-Received: by 2002:a05:6214:1103:: with SMTP id e3mr12426686qvs.159.1579354648459;
 Sat, 18 Jan 2020 05:37:28 -0800 (PST)
MIME-Version: 1.0
References: <CAKv+Gu8WBSsG2e8bVpARcwNBrGtMLzUA+bbikHymrZsNQE6wvw@mail.gmail.com>
 <934E6F23-96FE-4C59-9387-9ABA2959DBBB@lca.pw> <CAKv+Gu9PfAHP4_Xaj3_PHFGQCsZRk2oXGbh8oTt22y3aCJBFTg@mail.gmail.com>
In-Reply-To: <CAKv+Gu9PfAHP4_Xaj3_PHFGQCsZRk2oXGbh8oTt22y3aCJBFTg@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 18 Jan 2020 14:37:17 +0100
Message-ID: <CACT4Y+bKhgRdCM1v8wTht=pEcX6u-J_Rq6=zA5yfMuBUcj169w@mail.gmail.com>
Subject: Re: [PATCH -next] x86/efi_64: fix a user-memory-access in runtime
To: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Cc: Qian Cai <cai@lca.pw>, Ard Biesheuvel <ardb@kernel.org>, Ingo Molnar <mingo@redhat.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-efi <linux-efi@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=EY3A6DSL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Sat, Jan 18, 2020 at 2:35 PM Ard Biesheuvel
<ard.biesheuvel@linaro.org> wrote:
> > > On Jan 18, 2020, at 3:00 AM, Ard Biesheuvel <ard.biesheuvel@linaro.org> wrote:
> > >
> > > Can't we just use READ_ONCE_NOCHECK() instead?
> >
> > My understanding is that KASAN actually want to make sure there is a no dereference of user memory because it has security implications. Does that make no sense here?
>
> Not really. This code runs extremely early in the boot, with a
> temporary 1:1 memory mapping installed so that the EFI firmware can
> transition into virtually remapped mode.
>
> Furthermore, the same issue exists for mixed mode, so we'll need to
> fix that as well. I'll spin a patch and credit you as the reporter.

If this code runs extremely early and uses even completely different
mapping, it may make sense to disable KASAN instrumentation of this
file in Makefile.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbKhgRdCM1v8wTht%3DpEcX6u-J_Rq6%3DzA5yfMuBUcj169w%40mail.gmail.com.
