Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBP4S5SXQMGQELTD2DLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 762FD88152F
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 17:05:21 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-5158587c40asf6048e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 09:05:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710950721; cv=pass;
        d=google.com; s=arc-20160816;
        b=EoCj5gcNm+XpBgJiTX9KnhAFNupo+WrIAgDaA+s5wAnOGh3SsDFxURGoFhKiL7+s5k
         XjNLPPkq0FX392FfxaCxhe7cajFcD7JBgeHI4qQ1FBF2SDz5lRqvDd9xSa0st8PuIZxg
         KQCM0XEP8qlPhGowmzk9BRVICR3Hmp9x5l06iG7sUHxeQ++EyaOhLZmRisb5phq8R/7c
         sa/ypTLsjXJQ2xECMHessDgjiccwBtRlUxw2ynESHqoIhRyx91DvYTYj6gVBwz/3NHpQ
         SYwko3PZOZjFJlu/9wYhl92cnhx/mTFstHghHZx0jK/HujriS+fzLPnwUJH5Lsf0T+qd
         MTHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=+p9aCnrxLnO2m5dPbJhjTCdT8tvbA0YYwlILQcFNn1A=;
        fh=fYZhGLOFq867RRHsowNKQfGwuLniz8g03TdtEJ9ibs0=;
        b=V08oncgoIIrYU1W87m+Imi5RYSQSMUEfx83LnSz7HjdY3YzYefpznnHlCzRWAWWu9t
         zyU1e5Aoz/yeTjLZ7G6xOXed2+KlVdrSm5ZOlv7ISHSVo1XtxJpRGKmd9c4fiZUXdQV8
         HWVI2/HxTgwGbsfmKUnratPa4JOuv2EnRLqTGS2TmFmnjpLSz0Lz8bRJ1hdIw+1VJj1s
         8TpT+wrvyz0JGVBjyXKDGuMU42DJTV+/I9cVpSQn6YuSsBPjOuHglKxznDELvo3rDNjC
         GgZ5/1l+olfQyOLs3OpErv6oJTmLldWGvHxc/U7ORDOmcxwBptxL4cpuMx+WvazwlXyM
         0n8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=QWakOTWs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710950721; x=1711555521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+p9aCnrxLnO2m5dPbJhjTCdT8tvbA0YYwlILQcFNn1A=;
        b=JqKRp7rcKWdyZHy6c+9CXSwlRAtrkxgSMBcN/vRZ+0IjolBhgAO5IbZaE4JOfQ+wq3
         zx9i+9BioCY1oXOrZx5mGdCjtNnccooZhNxGGAfAKT9bHwULnpA8ADb3/llWxohtBztw
         CpkJPqUVO2Fi60PElRTn3JBDtDjuzqpcnnc9snHN90zvDoNnjf8wVR4k2Z0cLwvSdRUH
         BLlrD6E5vcvVBqCPb4ymQ7sbRMo8Vl1vsc5cwqtAlq6JVAqKV4tMBoRWYhwskeF4RoIU
         NHFPzZOaypH/hCIN8R5SX/MM8jCbentnoYugmnoSJyaMoJyUDw+X1FL3uwrY9lwtkE5S
         QwyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710950721; x=1711555521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+p9aCnrxLnO2m5dPbJhjTCdT8tvbA0YYwlILQcFNn1A=;
        b=OmMA+UYC67zi+S3WkqZM2H7HZ8RnXNPbCZ9jrPWyZMb/nbw3XpMDAPkkZ7Ux40janb
         ha6iUq+SzTl/AKY2Cg2uMpv4759c+QOucwrWbpNvr+1/xR4oj+Fudx+yauFd8wUmLYde
         zO6OOVDK/Hw8J+XMlk+KXlG9jjhs5Z/kBSQPssWV3t4od3fh0acYDdhVfpaNg7YoO7LN
         HJc/feWYTInVviEM239xnCMlnTiL1w7qfxmaMRmlL2dBLeAxDKY/dL8jgxSXzeezPsjp
         dphfn/8swKSXshfBu4B7NwFICGc5vof/cn3Iv1wbOclFI4XYnAioKjL75XoyAypJw8DW
         Qjhw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWxXGZQOk7cOCmyrLcHMn09tdh9il6QD3OXRN5pQxKBmqLPoXnVE9qS0Y9LOrKls5dEeYUxDG5J3t1pmS4k6tYAlApmjUmnWg==
X-Gm-Message-State: AOJu0YzDCurahLZX3+LOOT/QcdjftiUelruEiYz8vN3A9TUzCqm9uu5o
	dtegGmxU5XrkoNdtX8XoWA/FUeTgkocXxDt4R/6ehJWLcRPKIqxo
X-Google-Smtp-Source: AGHT+IEwui4ZcjWLvzNT3MMN3LHM6qj3TbCnn4sZF16hQOsoJ0N6c9Eyhl1hMBsfN5RbxvjxC0BYuw==
X-Received: by 2002:a05:6512:3118:b0:513:30fd:2991 with SMTP id n24-20020a056512311800b0051330fd2991mr4043135lfb.0.1710950719936;
        Wed, 20 Mar 2024 09:05:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:2105:b0:513:5f27:9a68 with SMTP id
 q5-20020a056512210500b005135f279a68ls108383lfr.2.-pod-prod-09-eu; Wed, 20 Mar
 2024 09:05:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgt9wQincnymfG+M4lMgNZQ8YrIMmEyWxdPhfA9dcOoXJpi0Y0UZvbRPZaV0YCmEjOPcCY6v+fZAl1pCPUq9SXXX+ipn46OjJJwQ==
X-Received: by 2002:a05:6512:526:b0:513:c1ff:7957 with SMTP id o6-20020a056512052600b00513c1ff7957mr4475175lfc.52.1710950717349;
        Wed, 20 Mar 2024 09:05:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710950717; cv=none;
        d=google.com; s=arc-20160816;
        b=0+jbffwFRiB3ujOkFOb9KVmtMe8OszaG1W8Hm+9mLn7kXT+bfTrJEDItT9ddPnYQD5
         sQ/l40NcP1kY2AkydJKm0F/SayjCJ9nzwoELp776zL6Rad629j0cRzgVG7heCuYwwVkH
         KFm/dR0Pln3VudahEGm3KpbQ+GNCLDIX1xlt9vcaGXTI9+ZRAzZTYsnm2EQbGcyxUJtW
         csUZxVnthAdlYz4I0ITklYB6tkdS1jwZG1irPY3FALv+o9GOytskbQ8dvnWSzcDNAt/s
         bgY7VnA32rKAnnYVUhYUuqCJel2uVSNr91zIJ16yfpu2H0NWrYmgvD37Wl5dQh6W1Gho
         0RGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=flOLAPt+j2N3owHC8tz8TWGzLUzASU0n79EdF+rziHs=;
        fh=zmW08VbA2TiJne6klJntENA/WDrglFf46JltjxmAh9E=;
        b=stkSUuHYlzECLri5HnSQa4nUa3mjyMez6B9Z83IzIweIF0C2sOKulkCXMiLU12J/01
         uAhyce7kZWy6wrkG4JmtA8CJIguYMua4Lkrjouol0athgVI+NuCGa5XaZ4NqFXwd94wI
         XyDLu2fBfFnKfd3m7Ur1gHr5iW7qt2EfPEOoKOkLyZdpvh6hE83K02ohmAUTY8hlvSym
         /AD3cB0MokH+XvnucjSZwpspe2iTr6sRvgTTdo9ZQEKC9xPrpBy7URuT7Sd2zduRjSGt
         vZ9Ch23e6QiKa2FgtQ8KIooSzlesYhUNRpvlis8YijzduDrAXwlRd+SEVkpInp8CLx4a
         XnSw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=QWakOTWs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id hp16-20020a1709073e1000b00a45a3691f9dsi844263ejc.1.2024.03.20.09.05.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 09:05:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id a640c23a62f3a-a4702457ccbso38651566b.3
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 09:05:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUqtP/zhcT9FvLwGE43ri0TZd6MZ2TJFB/r/belEPluys7qV0Uracs0nRkM6g7RQSllUlcE7GD5PF0FPEfpy3F/VGecDkXIYUiDqw==
X-Received: by 2002:a17:906:7fd0:b0:a46:e8c1:11ac with SMTP id r16-20020a1709067fd000b00a46e8c111acmr2839978ejs.18.1710950716757;
        Wed, 20 Mar 2024 09:05:16 -0700 (PDT)
Received: from mail-ej1-f49.google.com (mail-ej1-f49.google.com. [209.85.218.49])
        by smtp.gmail.com with ESMTPSA id y24-20020a170906471800b00a46be85684bsm3700908ejq.223.2024.03.20.09.05.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 09:05:16 -0700 (PDT)
Received: by mail-ej1-f49.google.com with SMTP id a640c23a62f3a-a466a27d30aso905325266b.1
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 09:05:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWNlp1LFpnopWYNCVvTZX2+mFoFm5xSDlyhEWJA1mtJaGskAm9/ltIi1ehdOSWnEUCRgELKCtsW9ieEoFzwCXZcM7Xw073/w8sJBQ==
X-Received: by 2002:a17:906:c14d:b0:a46:edfb:ff68 with SMTP id
 dp13-20020a170906c14d00b00a46edfbff68mr2554701ejc.5.1710950715478; Wed, 20
 Mar 2024 09:05:15 -0700 (PDT)
MIME-Version: 1.0
References: <20240320101851.2589698-1-glider@google.com>
In-Reply-To: <20240320101851.2589698-1-glider@google.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Wed, 20 Mar 2024 09:04:59 -0700
X-Gmail-Original-Message-ID: <CAHk-=whepBP2i6KrkSMdV98vs2PSpRcWS+zg0e8cNZKq0WUDnw@mail.gmail.com>
Message-ID: <CAHk-=whepBP2i6KrkSMdV98vs2PSpRcWS+zg0e8cNZKq0WUDnw@mail.gmail.com>
Subject: Re: [PATCH v2 1/3] mm: kmsan: implement kmsan_memmove()
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=QWakOTWs;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Wed, 20 Mar 2024 at 03:18, Alexander Potapenko <glider@google.com> wrote:
>
> Provide a hook that can be used by custom memcpy implementations to tell
> KMSAN that the metadata needs to be copied. Without that, false positive
> reports are possible in the cases where KMSAN fails to intercept memory
> initialization.

Thanks, the series looks fine to me now with the updated 3/3.

I assume it will go through Andrew's -mm tree?

               Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhepBP2i6KrkSMdV98vs2PSpRcWS%2Bzg0e8cNZKq0WUDnw%40mail.gmail.com.
