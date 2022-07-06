Return-Path: <kasan-dev+bncBCA2BG6MWAHBBI6NS6LAMGQESRAR5YQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 293285692D1
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jul 2022 21:46:44 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id t20-20020a1c7714000000b003a032360873sf10791742wmi.0
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jul 2022 12:46:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657136803; cv=pass;
        d=google.com; s=arc-20160816;
        b=n2WqqJygDkloR2Z4PfO5jfbnVM9CdeR4qaYbA1Ujv7AQ9donMTh3v3JBqgAMSD/o63
         JJCAclw+YHwu6oM9RTFZuagfb5DR7iIJnbP9XbP4vN1vKyoLxx7ueR+jG0ucLSwIaf+r
         ozbmjziYwdmj1t+HwPweSMvVEQi802hcjBw9owAoQqb2WhE7KsQg5Dy96z/76SsDWcvU
         ivN9Ux9oodi3Tz0K0BDysAkeJjLkv/Ynr6iXDA/2QJZ49dFTO9Lw7yeXdDNEG7XjQPLx
         NIjLUp7p24WzjZBTJ99FO5zNbQ0t4gqfHDjxdXNPTJLKZrBIawACEN2M8v06U5NLd5SF
         98dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=U8oqqOLAQ4thUSCbyInU7WAtLp6VOOwpUEprX7xMsAo=;
        b=iG0jaoo5pZGT1rOzs87Skyyug/7XEAyT9AQYCwvTp2+KVrkTfxFv96vGP0Bt5Fs3jX
         wxWfqHn9sOK3H/NG/669fxgtVr3DPWheNtRZkr775YQ30QOWqlrDNAFg8Q8/2ZxwR8C7
         /oplpio17di5yOkahkjnfWDgUrGCularYHfZONI2kvshDK+/RNtdJmBxca+LpdagZEDE
         utjM6bPgPhWPiSekP7Y7LKieAOR/Npk5DYetZMmfFEVRqcV6/syXI/tgXTYpdC+VuwwJ
         ye0j9S/8KWKvKoSh6v9mypQVS+J6xh+hscoNF1tjQu12+aGmtTvgO9eLMuUSSV9PGRHl
         atFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QPubt1Ja;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U8oqqOLAQ4thUSCbyInU7WAtLp6VOOwpUEprX7xMsAo=;
        b=gbT8oeqFCYgckiS8mdFcJj6T6ssj982BmPAXd1J/AaFZxWL7CoWoDU8SWJFsroV6co
         LSBh1su89YuwllVZB9Khrg9rjj7nZ6MXWfMbO61Ck4rs2vyL8+i6zbMvoP8EToqi5Ejo
         saZhC7MphshgM0du1B4bSue27jWTube/IssPI4zj36dwP+Y5n3PuMuVgnk7o1E6tkuRX
         PcoznbY47sFpvaFYJrzdZNFA60996cYWdU9pooE1paqO8hqwlldECy2uervu6c4oQQF/
         fCBmmEhXfIT+2KBgNU3F2BDBRlImF35LEA2WR/Z9rCNpcUa9uDkXYSj99At1AFpGwVQm
         sm8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U8oqqOLAQ4thUSCbyInU7WAtLp6VOOwpUEprX7xMsAo=;
        b=ZGt+brjQMOAfZ3/bzSfBLSAmSGfJYrns91jJQaRT7fBB5C1m2jJfaV9Wszg9SpW1V2
         Kmzft+g/QRQ6S1ZUg1W2omMEBZ/qyPPgGCUCjrBbUzyEseKUvLP1pnI1K6Ptlg2X39xD
         2tNaIqqWcYH9EHFjvGwDBpbgo6h4ylcGV/lBKs96SN3GNy1mV7xvkZ/uTaQzR/QJyfAE
         mPp2TC5lj0CglcKW3m9PaBNHlk4T5XlavnmgBnwHQXXtcVMu8j11GkzMPepxKnZovi2a
         n1dpJOhZ5vD9T8GrhoIi2HGmIaAnoXZEYreWHZqNYYaEzudhgP2kXGlFVeIrn7Ncg7dF
         YNoA==
X-Gm-Message-State: AJIora+XJmWQ0dWElesmFPBGN7FTTILIQsHmouNbQM6SBdRsUYgYCU1T
	L9+TEYCF2JFDQrbmue00pHI=
X-Google-Smtp-Source: AGRyM1spWbTPOgZf25Wa9fapxpYRnj6y1dEVEzs3T7xd/SyI+xxjRFe2/NhoV2IE6yZsiObJwnHb/Q==
X-Received: by 2002:a5d:5268:0:b0:21d:6c45:fe6 with SMTP id l8-20020a5d5268000000b0021d6c450fe6mr16172355wrc.380.1657136803656;
        Wed, 06 Jul 2022 12:46:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:184a:b0:21d:2802:2675 with SMTP id
 c10-20020a056000184a00b0021d28022675ls7299593wri.1.gmail; Wed, 06 Jul 2022
 12:46:42 -0700 (PDT)
X-Received: by 2002:a05:6402:26cc:b0:435:80e5:3d78 with SMTP id x12-20020a05640226cc00b0043580e53d78mr57831151edd.227.1657136689998;
        Wed, 06 Jul 2022 12:44:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657136689; cv=none;
        d=google.com; s=arc-20160816;
        b=Z42Fd4e4uBOT1A6uW7ZLtbsQVPRxkK6vKqWHFlWeUqXJQUgxf0PUL0fnTeLCsnl2tC
         T5TxU9ji8foXZTW5u9dx7SbJdgBUmhRrJeQHSTnhHX6G634EmWsxHRrO3ntiHiCexFxb
         i4pxknn7DNjQDN68R28Dw+74qVJxZPReS8emnzL2JP6jL+5vTXQ75gtR9hPTNb4WSp6b
         oqoe8OZZVaSgyHppfCyCSTNBVN3RoddEqVo8vRjLEXGMrjFhFvLqNyt7Ufb6xSyvRy3n
         8lCoQonW+dMINwW+PGB4+o0bhnOTtxUFPVP7JkfqsVPqKICMkHl9jo7O1KKIPFEi/z2i
         Xn8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VKmMBf94dqxoTjWi2eeMymoq1+LEzz8Mcbmk6X430xs=;
        b=K0wMOKpT3x5Ohiqi3OYwM31Lt0uq3a5BM3j57M8wzX5U7GkyYh3qx4zF/izFHi1Fsw
         veFMZ5EGlYCrteWeQF17VZWMpCoUsoWO2Qr2YZaeSz4WhFFbBphIuNEVpKQYmfJHxGOK
         OWHpXppi1qRnLOlXCrsMT1TWQ5SzUU5BHwg4I99CPsDQx2r8frEpR7m1GEKaqftOGCIL
         NvYgCvW4gwGasCDgzGnw99TCFiQruJP9rX2PlwpipO0+Uojyoi+ZPm5NSLQhdRdCkzLo
         yS8GsYIE1Sy6UquUKgZApXdBqllMBnCkac50VAcJSjv8GLKFOlbT32XkKkY2cpdkkl6p
         Hw3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=QPubt1Ja;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id a22-20020a170906245600b0072695cb14f9si1147516ejb.0.2022.07.06.12.44.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Jul 2022 12:44:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id k30so12436248edk.8
        for <kasan-dev@googlegroups.com>; Wed, 06 Jul 2022 12:44:49 -0700 (PDT)
X-Received: by 2002:a05:6402:43c4:b0:43a:6309:6c9b with SMTP id
 p4-20020a05640243c400b0043a63096c9bmr22725476edc.91.1657136689614; Wed, 06
 Jul 2022 12:44:49 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com>
In-Reply-To: <20220518073232.526443-1-davidgow@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Jul 2022 15:44:38 -0400
Message-ID: <CAFd5g44i2rQf8KVPc00bZzMx5zPtjoxesqyTd1aawVc10-0kyw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
To: David Gow <davidgow@google.com>
Cc: Daniel Latypov <dlatypov@google.com>, Marco Elver <elver@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=QPubt1Ja;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Brendan Higgins <brendanhiggins@google.com>
Reply-To: Brendan Higgins <brendanhiggins@google.com>
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

On Wed, May 18, 2022 at 3:32 AM 'David Gow' via KUnit Development
<kunit-dev@googlegroups.com> wrote:
>
> Add a new QEMU config for kunit_tool, x86_64-smp, which provides an
> 8-cpu SMP setup. No other kunit_tool configurations provide an SMP
> setup, so this is the best bet for testing things like KCSAN, which
> require a multicore/multi-cpu system.
>
> The choice of 8 CPUs is pretty arbitrary: it's enough to get tests like
> KCSAN to run with a nontrivial number of worker threads, while still
> working relatively quickly on older machines.
>
> Signed-off-by: David Gow <davidgow@google.com>

I know there is some discussion on this patch, but I think this patch
is good as implemented; we could always delete this config if we
change our policies later.

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g44i2rQf8KVPc00bZzMx5zPtjoxesqyTd1aawVc10-0kyw%40mail.gmail.com.
