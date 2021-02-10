Return-Path: <kasan-dev+bncBCMIZB7QWENRB6VPR2AQMGQE4KFNG3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 674D53160DB
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 09:23:23 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id 137sf1172003pfw.4
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Feb 2021 00:23:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612945402; cv=pass;
        d=google.com; s=arc-20160816;
        b=mrFlxo/aRXGSb0DM4iyOAvooJJsst2qBNWP6T0SfjH9iU2fZDQhQ9sDi4x3Z6ynOmd
         aP0CtyTWTgYh7YCl0ZYUZ7F6YPOf5aPfAFwy10WQ235By08lvFIhTmte61jNqsrA+4sw
         qa3/i3jkJqbHba/BHUxTsEkWfSVgAlOzBj6++n2MUSy2GOt6MFyf3s9dAxPnLVtJlSER
         7Eqns1MK6r93VFnazqE+aa5D4PujzAwI8cQ+hOo6Q21ny0qAvADOc1kwQ9P7aCSegh3h
         CPL7/AY6KRqgmFOoGcF7HR7l8VJ5lOwzj/hK6sTlpyA5KjNCGdv3lckrrKEKy1xsEqnx
         O8gA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Ed39SbRqxx3IW13pdK975DFRFkuCjJ/GnPROXujB1hE=;
        b=gvKjdTa1P1ncGjaTrmJx5/WRXPmZzEGq+csKgUBm1QRyrqhfMQw6q2rijrKj6/xzKs
         dKuKaHr1DQZbcpaJxcgw/ZSc9f+aZ0QQFSbvfEfpn55PK/89ru0SCrHOJQz4yBSIg6ga
         CHd4xa9Po+rcF57PIy5idPsgEyZbmebM+wJptI15s7I8tNDYyU8Z4LLxfRxu4LR1Vwyo
         5+9bgm/MCvL0McVA8XqyDUV2DapkhwmEmCMgrXR5BUV9dRasOVoHjZYQn/wvbYyPrUw4
         L2sPA9mhw5MDyFXhKQ+8ywQn6+6mAg+jtljqXKAcMsX6aCd8IN66oOOxUZHpEETivlSl
         Iojg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A6sqOtRI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Ed39SbRqxx3IW13pdK975DFRFkuCjJ/GnPROXujB1hE=;
        b=Xok0DSiV+3TmowW23uE+bzu5XAUYMF5NkFdmXh2DxB8Pf8a2/ytq+x7C5YstQkVIYi
         iVm1HezojZK7WqEBikq2d+wnM/579/8dYvXv55J+ZkzL4XMMiCKH+w3+90/CENO70Rvl
         R9Fav9mM8yG6NeqOSN5zWwaZ97D8uJIIChJxsHysu2jMqX29yYeLKPSEng4DHbltkNVA
         S6bE88de91lcGPTNCsZ5dPcB4bP9lasdjEfem9avGiSigBvhTovaBGHBii/JxZtIMyzq
         rJRxWl9JAzIrykyuyd6OEQXLeBqqrwHKxQ2jB4Wj4KOp+3mGo+OP05q6wqqQA8lDI0xM
         s6PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Ed39SbRqxx3IW13pdK975DFRFkuCjJ/GnPROXujB1hE=;
        b=g/vPts6YR5IoJX10XwYpd27xPpp95OBPICd6lnuqvUA7VcHyCg7SxwQJzFhoO1dB+d
         crjwqPo4g1dqD2ycJQexP87kAgxFyKZA+wy0fcwOQ3FRHuPrH3Xz2+IYbzPn+T349kZj
         mrqsnKmMIuPsRMC9ST/ZA+59DleAafQ0ezRMgHqPzMFFYIpzyKuY5vTj+go89S4eEyo1
         tiv6EUCBJWFvy+r7Y4ILBeAFuKDa4GTU1a7YiADCHCtWhdWNvADhkpt4C5GcU7CO63Mc
         t0qIb65hrjvUE5dBYRRcfZNCRQn9u/dUt0Zj2APP5X0d8UIooyXKcqsP13otKECl/mQv
         L0xQ==
X-Gm-Message-State: AOAM531R0mvKFncAcEFgPsVStrRrEgN0sqhhh5N6rTQhsD4pbBgCZz72
	JTbZ8ZfnMFSzmTCzf4Nemp8=
X-Google-Smtp-Source: ABdhPJwg5RrZN5p9EIaUce38JaxwuN7Phz5KVU2Ashmt4oiKZMoZbUDvs+yFECZu0C69jhiN5j/i8A==
X-Received: by 2002:a63:d24e:: with SMTP id t14mr2073063pgi.348.1612945402154;
        Wed, 10 Feb 2021 00:23:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8607:: with SMTP id f7ls12399plo.9.gmail; Wed, 10
 Feb 2021 00:23:20 -0800 (PST)
X-Received: by 2002:a17:90a:e17:: with SMTP id v23mr2065130pje.193.1612945400074;
        Wed, 10 Feb 2021 00:23:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612945400; cv=none;
        d=google.com; s=arc-20160816;
        b=japxFT1ce2Hx32x7d4I+/bDw4v8C3GGL+V9EZBFqybxSXb7+2YyRBbpuIIvyddJ8R/
         wG+42LbLkMYziTpdOyojAsExltm92uWOnWFcSSNeHYEm/8DREyMwHCuE2Ye/ctVXs3EM
         8mmhJ7hl/MvJiqspakKz3rcUXK63BLlR2pr99V0ffdD7GtovJdGu0ZzhpbYZaERPDe3L
         boRd7rA4WfG9SZ1e8MmJgRS4dUFiwmJzQ0Ze+vxxMgJBx5HISiEmvotd4FzK3kwP4RJ1
         Nz0ru5jZ9C3N65uOWq6yimy5TbBv2l2QzK0SdC2zx1OeNwcf4GlDmuwQMalLpF0WmTc/
         Z0Rg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Ho+2bvrrsoPdhS9pYL4rE6YiGpBVQqSVcakkTYOvlKs=;
        b=TTfnTEcV00ag4AJ+DZp6HBufRiygAKh+BHbSR9oksz0SUx2vBwAgYnBb284ygFTm4B
         l7JFovCY0SzEpyNbPiTtWlsD9aFej9qo0JD0CIT9DK52TBsjtJXijkLWS89CbXs1ubPz
         aqDXM0soa/pwLgBDNBpQ5f6OBgm0V5oKMi+Tcg3RRGPlAGPpx7eTX5iTjuAFdPrP+O0d
         pLwy20muM+F8nye131rVTaeZYHyayaIOW8pHucrppu1bcl2N4XMSh7JPvG0V70rfGNO+
         7LsKo98i0J4uRxq7lvhegs7ffRPwx9rU9wkduTtowEho51M3jXv9R/SIRT6NOirvCAPI
         q+Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A6sqOtRI;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72c.google.com (mail-qk1-x72c.google.com. [2607:f8b0:4864:20::72c])
        by gmr-mx.google.com with ESMTPS id f24si325719pju.1.2021.02.10.00.23.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 Feb 2021 00:23:20 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c as permitted sender) client-ip=2607:f8b0:4864:20::72c;
Received: by mail-qk1-x72c.google.com with SMTP id d85so903018qkg.5
        for <kasan-dev@googlegroups.com>; Wed, 10 Feb 2021 00:23:20 -0800 (PST)
X-Received: by 2002:a05:620a:410f:: with SMTP id j15mr2346020qko.424.1612945399018;
 Wed, 10 Feb 2021 00:23:19 -0800 (PST)
MIME-Version: 1.0
References: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
In-Reply-To: <CACV+nar9Apf15oXvwqsyd5OEX3PQ6OTxbhgG+0JRP0+iUvh_KQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 10 Feb 2021 09:23:08 +0100
Message-ID: <CACT4Y+Yo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g@mail.gmail.com>
Subject: Re: reproduce data race
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A6sqOtRI;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72c
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

On Wed, Feb 10, 2021 at 6:20 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
>
> Hi, my name is Jin Huang, a graduate student at TAMU.
>
> After running syzkaller to fuzz the Linux Kernel through some syscalls I =
set up, I got some KCSAN data race report, and I tried to reproduce the dat=
a race myself.
>
> First I tried ./syz-repro -config my.cfg crashlog
> It was running for about half a hour, and reported some KCSAN data race, =
and stopped. And these data race are also different from the one I got runn=
ing syzkaller.
>
> Then I tried tools/syz-execprog on the crashlog on vm.
> And it is still running, and report some data race as well.
>
> I think there should be some way for me to get the corresponding input fo=
r the syscalls fuzzing I set up, so that I can reproduce the data race repo=
rted, or as the document suggests, I could just get the source code through=
 the syzkaller tools to reproduce the data race?

+syzkaller mailing list

Hi Jin,

syz-mananger extract reproducers for bugs automatically. You don't
need to do anything at all.
But note it does not always work and, yes, it may extract a reproducer
for a different bug. That's due to non-determinism everywhere,
concurrency, accumulated state, too many bugs in the kernel and for
KCSAN additionally
samping nature.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BYo-HtoNrA8PL3qWYoUitt-WHgZmJ7wqh9zn01t53JL9g%40mail.gmai=
l.com.
