Return-Path: <kasan-dev+bncBDEKVJM7XAHRBBOYWGCAMGQEINYJWQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 39C07370252
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 22:43:50 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id r12-20020adfc10c0000b029010d83323601sf3906785wre.22
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Apr 2021 13:43:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619815430; cv=pass;
        d=google.com; s=arc-20160816;
        b=n82GRuqHfsNt1xp4uPxizwJewX88nkn3k8H/crxDcZ+z95CB9ORC8GFUybFbsksS3/
         AkxBTDxQPkaFwumRa/pAjBNvsoAw6MSOd4uAhAFYqqoRqA4eWjqQp73H3j/cazXhuVO+
         e4AJhmEeSJUVlX4mlJUXAch3pwF6yq5QbnWE24wGkAMLu2fEw/3n7jyVTPjINrq0kMpx
         vgKsdAUC/U4vJ6g7NLneta0o66bG4n83OACFt40L7wBaaiG9oxnolZHfwvhU4zc1wAfM
         tFSvH6TUSsUdKbjV6qikWsNKoYn6uLVkIshEwp2otLfFgtTM5/1tziGYsJ2uMzMpaso+
         t4EA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=SNtKDCYXeJ1eh952d9WLEYMl5aKuX8eWGxwYny8qqHw=;
        b=WzidNGITFDDTuOjqyxG8HZqVPSgREBVKrLyg0OAu7dDE1eUD6jzXkvKK4k+Z0BvKXI
         S/wT58Y/+KdgIrpRw9Eup3WolsjG+PinvaDtETBFFS3ifmUcZBDoA2U0fcI8TP6+7HAu
         fNbQ+634H3GaA5giFXpd9ZnpVnz89klsGaZvoKOSZEeaA2HURua3hdFySPPnUGUKZcKp
         AGPLf6UngExfFlmVIe3GBKE+IRgaTFEla6G9br9xdX9MZpuVUPk3GZe4v8HMkuv8D9JV
         xWlwILdNAub329gtldk5h2momr7acvtBxAqVE38WqmdXkDOtZ4LvtLRQ80f4h1NTZKPe
         /WLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SNtKDCYXeJ1eh952d9WLEYMl5aKuX8eWGxwYny8qqHw=;
        b=JLZoCsXkhhifDYkvQraQ4ljHUpqDDmxPAk54r790lhnSnb3NEmizOORSE6Aa7yfQ+6
         lFcv1GvWe6dU5zlhywZCTyJ8AnU0O4KwGyrGN29XPESLNNXIOmHIxI11/2sMHauYBgKa
         FZILZdOtDPsCCqqZVZxwM3AdJ+1/A2xlKzt0dEma6EC5PY5GdkdZ34bXbVjiyWdmUNco
         K36mRTHN/3SuLzpJmArIHi0ICIdSR5nvlFcXaMAKHOFHoICNIXeyh6vaNgQsg9FOogyP
         D+yaHDx0FNeMnyG6qLOiWAeB1cNx+WfO0pQFMGLTw6/yoshO3aQeoitcg0qrRyQk5Ljw
         tLzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SNtKDCYXeJ1eh952d9WLEYMl5aKuX8eWGxwYny8qqHw=;
        b=jW3te0U0EESYQj5k7y/g+cPXgQ0bfaDA7ItFZ9etUsq7jpRswH53lSAAzXsFyKRAXy
         8CNPb5Z24P569Q4ojEWOPcDsGsM5YBYodKK2mmm1jlQ2grvs1HhjNdLAHdeq1V8TM24k
         0NCRLOQwA3DmwdauqOCuUs9SyOB6rrXCdK9gEjPr5GacmlcOI9BL0b1/Tf/QW+eNXoPM
         LOP+ljjrntgFELAdE2DLS85l1AVX0Y3t7D5f4FTJ/EgwIgYFNiWd27QCgkW1TgwjZFhC
         kCUsjwKa7v/1T7+mM4rzDibwUpvg2lio2KRHkXT3vxHCp1FEIWbk06BAMBdyYjiSNT6q
         JaWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Mp3ByG+2z61cUPFMuUFTorp19ID7c+q467QfTG+uJpH2JOTIT
	M4arQDPGhJj3HflJw8RQuHw=
X-Google-Smtp-Source: ABdhPJx1C5NNJ4m/YJoL26Lu1VRcVTxZTPhhxAejUtKdBgCKCdosTd+ZNZrZW2pTzU6ArBmy8dOIPw==
X-Received: by 2002:a5d:64c6:: with SMTP id f6mr9458943wri.18.1619815430047;
        Fri, 30 Apr 2021 13:43:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1287:: with SMTP id f7ls6256072wrx.3.gmail; Fri, 30
 Apr 2021 13:43:49 -0700 (PDT)
X-Received: by 2002:adf:f192:: with SMTP id h18mr9223965wro.270.1619815429252;
        Fri, 30 Apr 2021 13:43:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619815429; cv=none;
        d=google.com; s=arc-20160816;
        b=SsdIMSdhubfqsvSaaQUdGQQUY3wdZ+p32BSBOdSFRYM4Ovk9xTxkKB3BAQxGt8ysxV
         Pv7qU3KpTLq6uaZfhL4nuxA1fbaJvcD02IB2cNhGs5lpvpOY2l2fVNwdqRHzl9Aa0Z9+
         Fh+Fo1Ia4xU6Yw8KlzX8JWPKHq2UxSLqfm37aaJu4TCdD3BB7mQRcfdDIaLs2QeOI3EG
         kJGZ61CqK4t/p64gjXQzzEqHfswrddFKI6oIzAOxoa1243NcsHVJhIZXiqFollPH/Rc+
         fv8Jd5S9FsOgVq+rjngrdTPHvQqqN5DoM81JHJaOT6/DQLF0l3Rrbd3P9wHgT4jPqCQo
         8bsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=3xuvPUiFW70v8A7b4QJlGXXjjayYCI/7YbDiNjBENrA=;
        b=v2/TktWg/t7gcv32RwPMDpoEDuQRMiiUCs5wFfcQ6pRNG5dGffJjmKPX1eRLfDL+Oc
         J1aNLf/TNZgCdaSbSM6+hIOvjM1hFQRpdASVJulKvBXHRKN8srANxucji8M5jWIMs9pT
         aLJVP7tCxGeundCLFHWp5IIs1oEoh46r/wHfcu3kHyJR/StK4TdGh6qr/u6wVCv60fds
         0xhWsDnLMOxfhacaorewyVhDbvedRQSrqFiUzYJT8SAEx+YMf255qqyfbVuyDG31ujWp
         6Wr0fiI6lFkor8z/FrNYJ0xLwByZVfyidDh4fMHZBZJOPcBfcp7LDkO5pmXl9zz1+s7d
         TAEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.131])
        by gmr-mx.google.com with ESMTPS id 7si403390wmg.0.2021.04.30.13.43.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 30 Apr 2021 13:43:49 -0700 (PDT)
Received-SPF: neutral (google.com: 212.227.126.131 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.131;
Received: from mail-wr1-f49.google.com ([209.85.221.49]) by
 mrelayeu.kundenserver.de (mreue010 [213.165.67.97]) with ESMTPSA (Nemesis) id
 1MfYc4-1l5jDQ3IxU-00g4G0 for <kasan-dev@googlegroups.com>; Fri, 30 Apr 2021
 22:43:48 +0200
Received: by mail-wr1-f49.google.com with SMTP id d11so14109954wrw.8
        for <kasan-dev@googlegroups.com>; Fri, 30 Apr 2021 13:43:48 -0700 (PDT)
X-Received: by 2002:a05:6000:1843:: with SMTP id c3mr9808647wri.361.1619815428535;
 Fri, 30 Apr 2021 13:43:48 -0700 (PDT)
MIME-Version: 1.0
References: <YIpkvGrBFGlB5vNj@elver.google.com> <m11rat9f85.fsf@fess.ebiederm.org>
 <CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com> <m15z031z0a.fsf@fess.ebiederm.org>
In-Reply-To: <m15z031z0a.fsf@fess.ebiederm.org>
From: Arnd Bergmann <arnd@arndb.de>
Date: Fri, 30 Apr 2021 22:43:09 +0200
X-Gmail-Original-Message-ID: <CAK8P3a3mb6X4+4Q1WBQp22O2Bvc3w-Q=L25jh+WPvp2kJFwHiQ@mail.gmail.com>
Message-ID: <CAK8P3a3mb6X4+4Q1WBQp22O2Bvc3w-Q=L25jh+WPvp2kJFwHiQ@mail.gmail.com>
Subject: Re: siginfo_t ABI break on sparc64 from si_addr_lsb move 3y ago
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: Marco Elver <elver@google.com>, Florian Weimer <fweimer@redhat.com>, 
	"David S. Miller" <davem@davemloft.net>, Peter Zijlstra <peterz@infradead.org>, 
	Ingo Molnar <mingo@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Peter Collingbourne <pcc@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, sparclinux <sparclinux@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux API <linux-api@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:hs2bwK2OIlgw16opJZJJ3sQhOtbYJDs67nJSudhnjdtt71d7UGa
 yrCM3AjmEi0Pm926zYkZnAPykYLFgytWJOlkIU5TZyR326kzLqYpiRWjAw7VQOaflqnzBYR
 RidX8OdXzuQ2rCMvQrF3mhWPGB3U6wLaQmqYlSSrWsjES1xWB8Gmwb7EOg3pxdEE7Mz/iLH
 ZN6Q0B0K/lWg6LukTZkOw==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:n+Tf0U+188c=:QRkvwSx3todJ70A5yt4d3Q
 RsY2w9kwJHv5ewohdfnCV0f7vRL32agvC2yfGovWIV7iPItepLXGgESlHH2ykHwu29Hvg65T+
 VyDBdMPjvAu40d7Zy0HX0FVenG4gwOqULMb+3QBIkzlNlvu9ijAALDu0W2wo1rOCkDP5DMqTz
 awnmeJjBQRkcXCHJuthyT4fcFlFRga0zqUK9FBz7HXr9RO4ThGJuaTLwfwOYtPY3nHdmKF/55
 00E01r3o4gBUbQkWDtJTOiCF7pC9AlZgvuoA8uMVBYMN7JvwROpTn0uJEdtyXaq54m509wOl3
 TlPIfcXkayTmxRitvqi5igw1t/jTWo8xLe0itSTPR/vnsXxNSLWywmH7jDKflFIxYkwkLYggm
 xiT5zbCghAc2cvtBGBcGsv7PjdfWJ2rLpfX1SkgifAwM9JyCLSp9bAgI9eKWTO3ElRob60v3R
 Zas2myy4m10QFNH7ugI6jxy9IhJ6o+JRF/aGAee38D9bLVphe1TM1t2ZjTyxp6oF9tmTCL4xU
 FP5KwwUvzaK1YkHxYnxSoc=
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.131 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Fri, Apr 30, 2021 at 7:08 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> The code is only safe if the analysis that says we can move si_trapno
> and perhaps the ia64 fields into the union is correct.  It looks like
> ia64 much more actively uses it's signal extension fields including for
> SIGTRAP, so I am not at all certain the generic definition of
> perf_sigtrap is safe on ia64.
>
> > I suppose in theory sparc64 or alpha might start using the other
> > fields in the future, and an application might be compiled against
> > mismatched headers, but that is unlikely and is already broken
> > with the current headers.
>
> If we localize the use of si_trapno to just a few special cases on alpha
> and sparc I think we don't even need to worry about breaking userspace
> on any architecture.  It will complicate siginfo_layout, but it is a
> complication that reflects reality.

Ok.

> I don't have a clue how any of this affects ia64.  Does perf work on
> ia64?  Does perf work on sparc, and alpha?
>
> If perf works on ia64 we need to take a hard look at what is going on
> there as well.

ia64 never had perf support. It had oprofile until very recently, and it
had a custom thing before that. My feeling is that it's increasingly
unlikely to ever gain perf support in the future, given that oprofile
(in user space) has required kernel perf support (in kernel) for a
long time and nobody cared about that being broken either.

sparc64 has perf support for Sun UltraSPARC 3/3+/3i/4+/T1/T2/T3
and Oracle SPARC T4/T5/M7 but lacks support for most CPUs from
Oracle, Fujitsu and the rest, in particular anything from the last
ten years.
Alpha has perf support for EV67, EV68, EV7, EV79, and EV69, i.e.
anything from 1996 to the end in 2004.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a3mb6X4%2B4Q1WBQp22O2Bvc3w-Q%3DL25jh%2BWPvp2kJFwHiQ%40mail.gmail.com.
