Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFV3SL5QKGQE7OQ5IHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id E424926FBC0
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 13:44:23 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id f12sf3196404plj.10
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 04:44:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600429462; cv=pass;
        d=google.com; s=arc-20160816;
        b=lyr7VONlpMeS9xy8DMFdKHn2C1EZ/wfSTk6moiG1VOpk/E5t6PxXqBFU6dEaV1WNFQ
         9qMAy5qDL22Kbr5g2N6CIOe9jmIaI3h/edKlrIhnhopErrwfoUCq5LFf4L6On5BNNmgj
         7DgQtCdEvs5iLl1Nfm5c9tSIgL0d42rrgnUkXIRzF0R0Jk3Vq2JNye9JKDwR76OOZaGP
         Hf5XQa494WcUlErQO3RnkAZ9G1a71ltr2qfgAuzrJ356xuHJ4p6k35isqMDTdPIzDdGt
         w0Hh+O3/qpXxT3QrnnRBQImUaBas6bpx65YesJpFMmYg/mc2DItFY+N09FtimkczBPi2
         +CMA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AMCWyqTHr2/KjnFvtGbPg0hIMAFI5DKEVDvInx02HYE=;
        b=PxMIKn5LrlwhCaYgFLx75T0A0XA99VwdfHTbCkoL3Tpin0ffxRQ+4XgRNVghOsPVXd
         1TSrMtlWe+Ezsu++GrmPfdRmfq0TooeXqgB5TmuzUgl+ui1huuir9ut5txBWZsxLBI0P
         +8X7QLpRLGwUOeP7H8X4UDKfcgFYjjRRJRT0cgixBj5xZnJp1Tjb/AxM+mupqAJExZiA
         Qrhiyxq95iq+/seyPOqM7hJolq/MQBHypOBnizT0J5E2dLIR+luBHknkXTqB1GlVlSlT
         x841U+Z4XAca4pMTfY0FKgM5cAwsUAj1LFggTKeCVkih8g+71cSmHtD7yG18V5S25zxe
         m6jQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TpjzFHO4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AMCWyqTHr2/KjnFvtGbPg0hIMAFI5DKEVDvInx02HYE=;
        b=FUjxtlPAE91tg53zsXVdCyoSkQY6YVihxIQMpfeCX2Ml02ZoCCFXZX/B+1lLGORX8f
         /JcCeyKFHd83wgKTWrS2F7yNag/GysCK6CRUOQ9immxFpuzCyBdwNG6NZ9CYbP3tUCOz
         lbf5p9IIWlcMBIlp/RGVjkIM+w5m6/c9+X0s/zrcqMNTCdwvkX8foIMntg4ZXqkRrvPt
         SilMsJPt62ks32YH4HA097kJGGDqOhQd/W8zBlN6OdUlLmhMqVdX6r7dyktvzrFjT1fP
         Ml01RK+kM2512FA5vmxsoEaOofsx4uLREkl8X0f5fV5g79CFAKqtdHyJuV+0lGY0YTup
         /9Sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AMCWyqTHr2/KjnFvtGbPg0hIMAFI5DKEVDvInx02HYE=;
        b=Y/sW3eK2qrnLU9o+kBcPMehywjWlAKKGyXuBw4JumbknaabZuuVx8J7Wtu1qSw6CWt
         2OYrRimWTF9FrTyfmIvX1wNoko85gb9Mhgqr+sKbXt4IFdPPpu8HtbH+L6Eo8PjDXR4n
         FHNvWrjUD6IQL35L/0LHFsvQEDedPrp3rpUGTAe7We2+1BGbB5iXPBS6/ZhErnFLyZxE
         z0BBG+TVWONmXqa59aPdObAu0QxMWGzen9koixE5mTi+mperrV9SBQ4kR5Xu972jxJxx
         w3G82lTnCBX9ZD+xUUh5+ZVfJfLqqAbWLa9vlL8zenwzxGhkl1Zqk7KjSVxTnVzEAXD8
         +pNw==
X-Gm-Message-State: AOAM53260mVDHlhJVN8JE+O4e8cJeVrLf1c9tFIADmovhKSCB4rIdwiJ
	Bh9l70hEDn7bpXB5eOqxWDU=
X-Google-Smtp-Source: ABdhPJyb42QCM4F4+6y4P8uP1WhmZMnd+p+aydgRXGThx3g6+avSuIm+gcNIvbCjJMEwcJRtwnV3pw==
X-Received: by 2002:a05:6a00:808:b029:13e:d13d:a05d with SMTP id m8-20020a056a000808b029013ed13da05dmr30610401pfk.35.1600429462637;
        Fri, 18 Sep 2020 04:44:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7612:: with SMTP id k18ls2634487pll.8.gmail; Fri, 18
 Sep 2020 04:44:22 -0700 (PDT)
X-Received: by 2002:a17:902:7d95:b029:d1:c91f:5675 with SMTP id a21-20020a1709027d95b02900d1c91f5675mr23052351plm.34.1600429462030;
        Fri, 18 Sep 2020 04:44:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600429462; cv=none;
        d=google.com; s=arc-20160816;
        b=oMLbxbPYWiOCaK+GZu5CcwKAry6dlCm6hLPMqlR2ShP+cNdjtP5urOLMc+WEssB17o
         vsGppy8Vk/NwD+ORsLwx6bXjNQiKz8EWRQtxzG8iHj2AzusnWe+0h0dlWKPot0MS0awb
         vkSuRuf/Jy13/X6IdkcsdhtpWqxB07kpl0hm8ZzxumK9TY5jV/4x2zKktUDda9REdJaV
         qwFTaoAp0HkEgM9efVkIvZ3UCjpIkRQSGkK086wjdfy5oFW8EylXUTL8O84/ufvQHPe5
         f6hXTpZYy1QTGnY+HaNtgfuQjKFYCsDENNDHZREG7CWYq+kb2EUOCqWHDPLcCSnzzBpR
         nPNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qnYIT2Fro5rrEPZwxE6ivwPIktYrQuk+TOWeG9l01y0=;
        b=qRKPbuvB6io72mj6w7MrtxU5WRze7pj2oGEeIlM3UtG1P0urZbXKfrEE2KCCMOWVRs
         4yK3Zkzuh1VnbvH/fwgkZLugx96fnQgR8sVBz//AkRDBYEOQKparMbLacZHVUmUtFjzn
         KlPPuwC9G+BABdfhDo8t5QgG/lZmUgb3SIEL7DP6QXGgnPcL7GKrMUOQgOtVvUdl0Vzp
         4rs32agasjhED/llHGMa/rv6+GqRuu5NTOvhuSOB3/vFOpf8mqh8YSnCZi6e6eF1nSls
         U+G1Tbe9L8gaLKa3Cn8uRGhWQXkQgK7rwUv6+3bBM1QI5ynMzvMNsGTFTEhuYf2SaUvR
         To1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TpjzFHO4;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id q125si249486pfc.2.2020.09.18.04.44.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 04:44:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id fa1so3040958pjb.0
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 04:44:22 -0700 (PDT)
X-Received: by 2002:a17:90a:cc0e:: with SMTP id b14mr12117134pju.166.1600429461570;
 Fri, 18 Sep 2020 04:44:21 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600328701.git.mchehab+huawei@kernel.org> <53f6987c1a4b032ff636a95e3fce53ff8bfef630.1600328701.git.mchehab+huawei@kernel.org>
In-Reply-To: <53f6987c1a4b032ff636a95e3fce53ff8bfef630.1600328701.git.mchehab+huawei@kernel.org>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 13:44:10 +0200
Message-ID: <CAAeHK+x-pDCWZX+vwiib6VH8mLJDD+Fbe6xeBA-_7OCcuLg_Ug@mail.gmail.com>
Subject: Re: [PATCH 1/3] docs: kasan.rst: add two missing blank lines
To: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
Cc: Linux Doc Mailing List <linux-doc@vger.kernel.org>, Jonathan Corbet <corbet@lwn.net>, 
	Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TpjzFHO4;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1044
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Thu, Sep 17, 2020 at 10:04 AM Mauro Carvalho Chehab
<mchehab+huawei@kernel.org> wrote:
>
> literal blocks should start and end with a blank line,
> as otherwise the parser complains and may do the wrong
> thing, as warned by Sphinx:
>
>         Documentation/dev-tools/kasan.rst:298: WARNING: Literal block ends without a blank line; unexpected unindent.
>         Documentation/dev-tools/kasan.rst:303: WARNING: Literal block ends without a blank line; unexpected unindent.
>
> Signed-off-by: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
> ---
>  Documentation/dev-tools/kasan.rst | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index c09c9ca2ff1c..2b68addaadcd 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -295,11 +295,13 @@ print the number of the test and the status of the test:
>  pass::
>
>          ok 28 - kmalloc_double_kzfree
> +
>  or, if kmalloc failed::
>
>          # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
>          Expected ptr is not null, but is
>          not ok 4 - kmalloc_large_oob_right
> +
>  or, if a KASAN report was expected, but not found::
>
>          # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629

Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx-pDCWZX%2Bvwiib6VH8mLJDD%2BFbe6xeBA-_7OCcuLg_Ug%40mail.gmail.com.
