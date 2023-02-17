Return-Path: <kasan-dev+bncBCCMH5WKTMGRBSMJXWPQMGQERKFZQHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id C92F569A7E3
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 10:11:41 +0100 (CET)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1718a51a8a8sf37029fac.16
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 01:11:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676625098; cv=pass;
        d=google.com; s=arc-20160816;
        b=MKe0c3x9lPuFrUHeXH8csrrALOGEzdh/0nvS8YQH3NCgzNc+ce9zQ4jWpm/iSjwbMt
         5jCHXk3hIydkNe8p+HiMSq1ddmcK4Wo8EJ+jXVwJ1gsNDvulZaVAoS5EQcujrHsi2AsH
         XDgrAEXAm6erixMBQYBmEB4Tn9GjlqyVcTitAjqoj2OwldQVRv/nZwxAF8FyEVua8OQz
         a2Ij3V0Q9vwHQf2/NsgMtgakvjxD29GvqG0mqVKK4od+GJCvqQ/OWkpqZR0EN55JHCHR
         dyCaxCyt5v8VJJlYXjggwY6vdMzCk5A3hfXKWPlesWURqBmFKgYliVI22ao4HUju9HJF
         UWeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qmrFHZZncyTxFnSGwN4uzgBbUDaAurpk+Wx1AYZ+Qpk=;
        b=o7Tx76NcjhgVg5bdJCofcyZliwPJEqkGLHWXlf36ttAWOdyZk2iFUTAOJaJNC3ylwt
         7ISkW4+36MDqABIFXQ1FGsbozHumQcgnwOPOHKthjTV1Vy1nHJie558+TG/U5vnVbH+Q
         7UDmvV2YoKrxVldaSCJNw4iy/EM/y7+Er1v57cnlcNTLnDgc0TqdsgdT3vbA3OnyBeXX
         VKELMfGJqeLrrfVfxuFQvvAajf2bKwt6zcVUV6dwJ58CcUR/epsI00eRrwzaziKjlSSv
         iXZfBNHfkEU5+zxZNXgfwN+xf1yrNH98hVm/uyDTC39lHHVYQVOApkPm5WoV9J9qDmPx
         ptVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E1ro5b2E;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qmrFHZZncyTxFnSGwN4uzgBbUDaAurpk+Wx1AYZ+Qpk=;
        b=H3cv1Kd/ZYgsAV3ap+o6tOWKDGL2DGB0Gm0AVpQmJsYyoeHLkduE/u5dLz0bukJZWh
         4i6aQWmK62UfciAy/SdGu1jZ6+JmQWUlHcsULIuQqzWv0Lkc3mnKxIa6BN9/1c8+5nej
         kDTbA6tJTLlYALcY0YByc4IDEnmqkVun0RyuPNB+BpKt+qY8SU1xzstSEToUvGxrwvK1
         roKk6qI+YBqle9GetYP+MpEMLxzYObXV1h7ZikrRylyDwtMV34E7OjueAu1D8u9QZNdU
         zAS8/IA2NdfdqBUd6FG4I84u5vBh7GvNBlDY5FThkyeZSH1+SSTJZA6K0MDisH6nD3DY
         e/Aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qmrFHZZncyTxFnSGwN4uzgBbUDaAurpk+Wx1AYZ+Qpk=;
        b=m5rKcAbQJwqcNrinSj1iWH/icIFDNDJvaB4lySycQzCCEgr9KaNvm6G/bLtSBUXXMB
         uMVmYG2ylhCmo2PZJ5qPnDYnlEptGUCHPO2AXWMNuXn0AssQkxZ7HUsWfoXyuGPHN2mX
         C2uaQRNgD9V6b8wd24emZxrRkahCv13v7pQKFi7/fqzkqginAYLOUPrdQNoz7K45ukcm
         76xp2LA7+opdE2+s4XCSxO7BqFYTUbKMAXIrmWUEXvEqLVCRJ6dEUNh40ocH2bzal90j
         FMkCUFo7cPzThjOZgacXrTviiKRbPfZyTzwK4VSlYtdKxeSO18PyZbxXtQ4dn28eUJrr
         asoQ==
X-Gm-Message-State: AO0yUKVDCh6EK8XwtNM4QLiHFRpKikAvY3+rpG7yxdIf+YBY+1XoUIwl
	zHW9dJ8Qs+Iu7DOy30yK9k0=
X-Google-Smtp-Source: AK7set9oKqnc0/PIV6/c/1aqjHIy7xUUzhYF75u+zPn/QLXyvRRbA5QkUDBbgwLUpStZfYEvh9dmAg==
X-Received: by 2002:a05:6830:3376:b0:690:e6d9:4842 with SMTP id l54-20020a056830337600b00690e6d94842mr142815ott.0.1676625098014;
        Fri, 17 Feb 2023 01:11:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2802:0:b0:36b:9295:8fcc with SMTP id 2-20020aca2802000000b0036b92958fccls209564oix.9.-pod-prod-gmail;
 Fri, 17 Feb 2023 01:11:37 -0800 (PST)
X-Received: by 2002:a05:6808:4382:b0:37f:a5bb:69d3 with SMTP id dz2-20020a056808438200b0037fa5bb69d3mr1383458oib.31.1676625097549;
        Fri, 17 Feb 2023 01:11:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676625097; cv=none;
        d=google.com; s=arc-20160816;
        b=T2BvdSIztsPAVByyOI5LhwqFH2O56rqcs9VISxeBniyBbhOoqbjChQji9Dmo12BkLl
         hchSUCXymmXmQqR+ekIlfpQu5gmxXsCU6OrKUP4Ise/kajEhygLX6jrLIMhzBScG/qBk
         07rqo8E8qp2pJrZIivcDD7u7bOv2vSnx/o9fcZVhV0onnjBk0UaL1qmY4HQcQ4WE6Hay
         3xKtCB7DhUBlNlT0zrnbSJ3MU/J6nbaeS5mpUSIMIB+qdmNx2c5/Y/b6ivQSbWKqrpDr
         K/6csRB5hxzuA2eKEA2GOwMlsUcaRJOx5mEWU5ybV7V9cVvHvydLHsTaAL8nKkav+5C8
         mQMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+Wm0umPVZ0DPbMR0SC6Fc8s0kVXs3TVj3JMgvwdynUc=;
        b=oO2WULH9QOQVew+B8oN0r/++JdlNPoKemeXd82vJRIj1s0+oJ5q+kTYSK1a8wsPofW
         sSShC06hAGMT87juD+AFZ9c2prS9bCVavW+66ZoiT3333JI5jlbA5wIqQ6R/0ILguWLd
         /PErOJpPB89H30DAr+1PAkrlQk8BjQDMRIVpRwevYX3tSdGOV+exd5A1NLyQ/3xbzAq6
         zxHR3DswIRA6gMv2uI4gWqq6XwJhUvqvtTdnOtbcMvts3MVHbGs05Q+hv8sfWFzG6VrT
         /5P/N8p8reKXA2+JZd6uDet4qRqGoAaDdGDRx9Qo472GgpYJoAQN0j80aomRc/zoz3r5
         hbow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=E1ro5b2E;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id bq19-20020a056830389300b0066e950b0580si442903otb.4.2023.02.17.01.11.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 01:11:37 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id x3so272128iov.5
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 01:11:37 -0800 (PST)
X-Received: by 2002:a5d:9859:0:b0:6de:383e:4146 with SMTP id
 p25-20020a5d9859000000b006de383e4146mr2600092ios.48.1676625097139; Fri, 17
 Feb 2023 01:11:37 -0800 (PST)
MIME-Version: 1.0
References: <20230216234522.3757369-1-elver@google.com> <20230216234522.3757369-3-elver@google.com>
In-Reply-To: <20230216234522.3757369-3-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 17 Feb 2023 10:11:00 +0100
Message-ID: <CAG_fn=XPn-gp+FVZi3nERgMq5HzZ6K4Z21sqZ0+BwrAbfCpa2Q@mail.gmail.com>
Subject: Re: [PATCH -tip v4 3/3] kasan: test: Fix test for new meminstrinsic instrumentation
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>, 
	Jakub Jelinek <jakub@redhat.com>, linux-toolchains@vger.kernel.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-kbuild@vger.kernel.org, 
	Linux Kernel Functional Testing <lkft@linaro.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=E1ro5b2E;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d30 as
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

On Fri, Feb 17, 2023 at 12:45=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> The tests for memset/memmove have been failing since they haven't been
> instrumented in 69d4c0d32186.
>
> Fix the test to recognize when memintrinsics aren't instrumented, and
> skip test cases accordingly. We also need to conditionally pass
> -fno-builtin to the test, otherwise the instrumentation pass won't
> recognize memintrinsics and end up not instrumenting them either.
>
> Fixes: 69d4c0d32186 ("entry, kasan, x86: Disallow overriding mem*() funct=
ions")
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
> Signed-off-by: Marco Elver <elver@google.com>
Tested-by: Alexander Potapenko <glider@google.com>

Now the tests pass with Clang-17 and are correctly skipped with GCC-12.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXPn-gp%2BFVZi3nERgMq5HzZ6K4Z21sqZ0%2BBwrAbfCpa2Q%40mail.=
gmail.com.
