Return-Path: <kasan-dev+bncBC7OBJGL2MHBBH677OFAMGQE3HXBY3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FEA1425394
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 15:01:21 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 7-20020aca2807000000b00276b595573dsf3423258oix.6
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 06:01:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633611680; cv=pass;
        d=google.com; s=arc-20160816;
        b=quZ7Etn2XSIwX1yIa1ShL/213q8G3Hon4wfJ2LEJoW3q7lebbiBZ7+6HEFJPOwqK50
         t6CgsA0zvyndy3Mpl+zxzOK9hTH4X701cO+aaOErLCCvT3nY69MOLkA/n49E4s469AVz
         GENCw20dUlJHxwTc2mjs09A6InFUsB2bksHmpKnPRzJ8ovy4QOw9tEdL+lVlb3iBGbvy
         d3dtz8VVlkXn7FjInY6FeizPV3qqWuArF1nVAK5TwPZ5Bhcoi7NDdbozp3xx+tNVmi3Z
         3Zt7+diFhnz5vfVd5EY0JUmsbx+ghMSmxeo2HSM+FtrIaIt4wgxmDOoWl84YF5uYHhlW
         F6jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:mime-version:dkim-signature;
        bh=ba3Q8+htAenZmmmMC6FAUQvDsj5ALlL6/Wq28Zm1OwQ=;
        b=ywR63+uTVpPui2kcSDoa+gEAGda1k9ACx+SLRdZjRJ5rbLg26dvv2P/NjktBpLcf1d
         RlJbHjzgPi3K58IkXCMC5hw+MwZZLvnVpo6B+Zt9GXa8Ls6z2aMs5qOB1TquyOLT4fi0
         VFXMXQGpFPskD/UPiwSvGAaipn36Hl2MTrsHbpjrecqGV3jaSIUUbHeWVSwFHdFoW7hJ
         4R+L5UMb7l16oqL3DP/uzkOKR/M/JDQkpU+4Bb0dHGoLPjWcIPsRgVfWkOs6J/4AQLyi
         db5c7FY1budB0BncMj7M2t6FvhoJbS7U2Ptx0TW9K0fp4y714FDRcSuK5LuTsMLpvZpu
         1YBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DEhqmx3g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:from:date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=ba3Q8+htAenZmmmMC6FAUQvDsj5ALlL6/Wq28Zm1OwQ=;
        b=B7/gUkA0+ZDWlP+GoKEBTfqIW+/Y3nRTaci8tWswzSixFgVYitGsEVcsTBsKn1o4ym
         K+FMqr9AQdiJCPQXUp3hLnJ7lZv6Rrg4qAQcMmnepdBKyYn9/RFjbSsk7wOy30GMdsn5
         L3XqeeKL0ffwx9uMXn1Ln4zC5G53wSosE1jV5XhXf59ZNOOacpSmXnj2scYNxUjUxDMP
         DY57Mty6fq+DLGhnOgATLMytP/e0JSiIWX4msGxmEb5M/5sdTuMftz90L0CYWy7rVBw1
         oVC/Lf7Uo63JK+3CQ36QpeG10Hp3JsiqxEQHLlDaSai/QzAGy9YTZH26tapD3bJVmvyh
         0gWQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ba3Q8+htAenZmmmMC6FAUQvDsj5ALlL6/Wq28Zm1OwQ=;
        b=X08ChCDQZ9rWoyQhNBo+WS4521Nwkny4tr23RoyRKv36A9MczbGm3/nQYhXKVrfS3N
         zODWAeDl9oyWA+FjLS1Ospu0dSSk36XZ7dNzjgNufEeP6Ywj+iX8iyPYChbqX7a/Zj+8
         7ENzpu9xP8bCj3LXYnZo+5rHdATDVYC/aU0jce/aLANJSfG56YeGqXUIgUvM5XIqSbtg
         9u5oaADzWRDfdvwHZYyDoLxoVugeflYlHwlYzWPB/JJIiOReVZM/tcj28qfhg8FCGDyd
         hv1GFTJ246yN3ZrNAm1NqU/fuTX9D+uhuGdPp4WxAMwbDt9rpA6kjtbaZee1A31L9Jmh
         717Q==
X-Gm-Message-State: AOAM533Aoj0idZ1ApkP3cUiSmteYiWmexwt2SkqJ8wcgJUnbymtrt7P4
	QEFr8SdtuMiSIYDm3uLM6S8=
X-Google-Smtp-Source: ABdhPJyP2sOXZbSh89a4heC6AwQPqyn9z8qJeuV3dy4lqrRiO0DDcdsGmaa+4hfN5j/VDu2qZ5CRWQ==
X-Received: by 2002:a9d:357:: with SMTP id 81mr3293718otv.381.1633611680008;
        Thu, 07 Oct 2021 06:01:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:31bb:: with SMTP id q27ls969912ots.11.gmail; Thu,
 07 Oct 2021 06:01:19 -0700 (PDT)
X-Received: by 2002:a05:6830:13c5:: with SMTP id e5mr3305560otq.374.1633611679557;
        Thu, 07 Oct 2021 06:01:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633611679; cv=none;
        d=google.com; s=arc-20160816;
        b=x9MmKFCpIDP59//VtWpzqQRFvkos9zN2alhqx5lMBVB4r33ldIZVQ/BGXhVyu/+70v
         VRSM6fEyLc1LpTFm3tkVZLB/68bkh9H1ThTkHZrCY0Pag41E9x3WtGQVWvNeBf5tXNSx
         zHU1KAsdgzfeP9+iFkYKjZClHgEOIUHxkSnEfCWRFLOkg9SmlZ6+l0XQUuEeQvn62kU4
         X4lqTnnj/URcbc6mwSNtgw4pDuw3Qxy4nOsGmuvcPwGqbrXxYT87B6ho7XlztA5/OeIP
         1qcU7BAzp1+Wv/WRXJxcJo5CqgyG9coOHBTVmQMuOEn9Y45Ln0MHNW1EVJqyfyShPfz2
         fTyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=E8AZM2qnbjrMYx8fqpEYqISaPhSicQU67TSBNbHEWho=;
        b=WM+xCK/8SJJKNcMbuClkNvjPXZCO4ygHSgL9+tAJxDEWFG3iUM1Cvq5Vmou0eH2j5T
         CHLcOpu9aR4ixit2wdQG5SnrZJonjWfcWdicXM1rlEr/IqkEgAzAFAy34IvMLAGBHtwh
         t6WteaeiK40KRf9H3WzgVOT8rupekWXRrhBtUp1K9HIVkCmeuRE8t5sh9C0Ha1q21YTH
         B7d29qwaiTu5AnGxfeEXYdbKD5httpoc+g5fBlhNYH7jL0od3WT7L5u/ZwQ14Ur9WuVS
         sm6dnghdXqTUughvwXmb0qdv1lRdipP3+Iv6ed7phRpsnqoteMz3FDpa0a8CD0aDmVx2
         ZaJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=DEhqmx3g;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id bd5si3078325oib.2.2021.10.07.06.01.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 06:01:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id l7-20020a0568302b0700b0054e40740571so1668198otv.0
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 06:01:19 -0700 (PDT)
X-Received: by 2002:a9d:6f04:: with SMTP id n4mr3442262otq.157.1633611679102;
 Thu, 07 Oct 2021 06:01:19 -0700 (PDT)
MIME-Version: 1.0
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Oct 2021 15:01:07 +0200
Message-ID: <CANpmjNMijbiMqd6w37_Lrh7bV=aRm45f9j5R=A0CcRnd5nU-Ww@mail.gmail.com>
Subject: Can the Kernel Concurrency Sanitizer Own Rust Code?
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Boqun Feng <boqun.feng@gmail.com>, 
	rust-for-linux@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=DEhqmx3g;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

Hi Paul,

Thanks for writing up https://paulmck.livejournal.com/64970.html --
these were also my thoughts. Similarly for KASAN.

Sanitizer integration will also, over time, provide quantitative data
on the rate of bugs in C code, unsafe-Rust, and of course safe-Rust
code as well as any number of interactions between them once the
fuzzers are let loose on Rust code.

Re integrating KCSAN with Rust, this should be doable since rustc does
support ThreadSanitizer instrumentation:
https://rustc-dev-guide.rust-lang.org/sanitizers.html

Just need to pass all the rest of the -mllvm options to rustc as well,
and ensure it's not attempting to link against compiler-rt. I haven't
tried, so wouldn't know how it currently behaves.

Also of importance will be the __tsan_atomic*() instrumentation, which
KCSAN already provides: my guess is that whatever subset of the LKMM
Rust initially provides (looking at the current version it certainly
is the case), the backend will lower them to LLVM atomic intrinsics
[1], which ThreadSanitizer instrumentation turns into __tsan_atomic*()
calls.
[1] https://llvm.org/docs/Atomics.html

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMijbiMqd6w37_Lrh7bV%3DaRm45f9j5R%3DA0CcRnd5nU-Ww%40mail.gmail.com.
