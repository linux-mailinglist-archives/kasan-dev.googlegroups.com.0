Return-Path: <kasan-dev+bncBCSL7B6LWYHBBF552PCAMGQEZIMSIBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F5CEB1DC55
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Aug 2025 19:12:57 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3b7865dc367sf631771f8f.2
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Aug 2025 10:12:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754586777; cv=pass;
        d=google.com; s=arc-20240605;
        b=fOTLalCSZOu/XoOzuzCBJvVOMO8Rxfv5uUh61caQKU1IcxIgjSL0GjXv8UE1oYB6vX
         nmETrXpSV65BjcOfBqb4RufIPUMgFTVmyeV1TFIvgaJXJmi/UfpD34Exz9n8can+2DHJ
         qELGi8GLmta/ffuD6C0A5oEwt8U8IQq7QGcSoV79baIZKEPU4FEphDw4JzEKiFlDFHUn
         wPOFgazH6a3C5tRGeJ3k5ei46Plzss/38j8yi0BIlIohwlVZ0Qpdv/UgQuTd1PoE2VoW
         CfjTYNbThpVn/nqSx4Lny2lfNL+wCyyQ20Q8BXLbOX1ZS6QAQ+5k5ZDVcJN2iOUE58qJ
         yoIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=XiabADqMdcCxlHcI81vLw4YAspKgqliwvAoYdj3oBqE=;
        fh=2uJE/KJ+izx9gbloATRVxGLG1IzchP/HZPZ1o1L7XcY=;
        b=T/mK1Rs526bQQ8XTfkJOaVKwOkdsd80FNpacYkKRnFI4W+TwT1vlRZ4uMDr94fX68L
         LK+NipfLU6RV2MAMKeZa9x60woC8tOemvcz0HPMD9cTq6nZ9TYnMOfUM8eSvOCIDtMTd
         uukTUk6Ct7pcVzHFYCkiO7e/tnx2VzyvGuV6lMgMXWQ0+k7tbKiiWIqnaz2pcbmgjlyZ
         ThkgfE7Ib+XuJkmKk/rhwBYzE3wJ4o0+kVx+j3W2gJImfF9NBk9dprbdr6t+NVugmGwx
         7DUiiNl2KfFCAQlWq+RGhmr+FlNDTzi0FE7F331opB1BMrkOYvnY33/vf2KfMsN5tk5x
         a8/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UkeutBOr;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754586777; x=1755191577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=XiabADqMdcCxlHcI81vLw4YAspKgqliwvAoYdj3oBqE=;
        b=fEpo7FiFbsB1lgRcVDc8BKblwmktAIFoUEyaiXprCTgKJ3cITJNnEvI/uAutzacUi5
         p9pZg8a+Kmq4oiSv1ml19Ti9b5yXND8bEoIPH44lqt+/d6p0FBCdSPg8v7VLR1StA+07
         MIvZI5qQSCl4ByY+T93IZmUpc2kM/AyNK18lRxmcmfiB3Fy19njgNsNDmd+fNn4mE0ca
         tu9bshCxXJKZnz1MpYUHY49LP6rm29SWmBRLQyuEREa9wS+oqcX8uqEMJsmoCZzv3nDa
         Tujd2Op7zloQ2OrGjMoENwJqEKrBHba/ZpsIZUFd/Dpy4Sp2Hv2JtM6pEjhuG/XSLiyv
         6big==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754586777; x=1755191577; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XiabADqMdcCxlHcI81vLw4YAspKgqliwvAoYdj3oBqE=;
        b=SApnNqi4yY0griAtzfyBrYRftEJDHICj/hmoQedbylQYyr8yM2/VlF9ZvF396QfXCY
         Sy/4PJrRviNNTxyPc7Y1mPWNhFPdVhs9VHkwHuJZe/5OqfzjB3+/ZvkrKTHRYil0pxrM
         EmngQN17u3JJlWa+3uxvaeiKbacf7hSNSx/PG8Wu7nveSD1XQP05972ptgrxbs+QpMXv
         heAk5+Gr9b5jhW60cyeqtGGUtL549xV6bNjaBYd+gkxzFl38Ilboo2P8JXShcicJshkF
         6AiZAdk/vfCiYOWjuEuN+m7USMSKTaR7wL9u+hZPN6txI7+M1FOhpM9lK46fQTzw2fGh
         uyHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754586777; x=1755191577;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XiabADqMdcCxlHcI81vLw4YAspKgqliwvAoYdj3oBqE=;
        b=KnGeM2qN9Vxe6OrMieOTLr7j274ToGNzYxg8uEDqBk4g+r3yUgXnD50xuLApSFUmlK
         83TUYdhbeQIz8jR9ZDEtY6H9Ccp5RgLuecSef6Au0kNfBNWtZSTKacnKsWCxeA67QOS5
         FvVAMXLufLzSQ5myChPumTeQxWY9UuG9HMPxQrcn/7Ld0bLZ/voXEs11ISCoy6oBsoH/
         /8EMKKapKtaEjCgdP3zBv9uvctGP+f6cyx7p5blygD6Vgf8RtVJpgXZyzcUQ9QhEca+4
         c0rJhZwUv6Nfta0HbStn+7RawcU8Rorss05CI/rgS9ms0y6FfPbp0kK9fSBM3p2CAfta
         qjzw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV4s+RhPRuI+0eFcxN+iNudBoCuKydCGSd64XjU18Z8nJIP4BFZliYkp4Js9KcVW4lEhO1+VA==@lfdr.de
X-Gm-Message-State: AOJu0YyqkXzv2va6a3wFelPDVZf0BL6SI/KbVHkgHnYaHnKh/U96kpC3
	McvKrzTyS93X/fmNtCpBamUNTwmlwJeSfPRbpRQUwXglY5XwpO8iGkQm
X-Google-Smtp-Source: AGHT+IGe5FuSxgM6ERx3gFgl5BvXr7nVX86+CPntnCjeJvhCvIvAnEe98sJYAeLiEOaLlGI/YeHWxQ==
X-Received: by 2002:a05:6000:40c9:b0:3a5:2f23:3789 with SMTP id ffacd0b85a97d-3b900b4cb27mr29722f8f.15.1754586776523;
        Thu, 07 Aug 2025 10:12:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfz8mBnqvI4AaRqANGjkXH/w8DcfLolIqdyoRu86KzhMg==
Received: by 2002:a05:6000:26d3:b0:3a4:c906:f8eb with SMTP id
 ffacd0b85a97d-3b8f9498fe6ls632045f8f.1.-pod-prod-05-eu; Thu, 07 Aug 2025
 10:12:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuMntVydl8wok/mA2EEjPoW592V6DLLSOzEhfvA6rTnPneff34Wwl8d06kQP+YvDrDbjtmh096EQs=@googlegroups.com
X-Received: by 2002:a05:6000:26c8:b0:3a5:8d08:6239 with SMTP id ffacd0b85a97d-3b900b4d3d3mr20378f8f.21.1754586773270;
        Thu, 07 Aug 2025 10:12:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754586773; cv=none;
        d=google.com; s=arc-20240605;
        b=CH16RyEonntJPsaqtojiwkl1ZFT8/AFplO+0WCReoybqGjrdCNvBePQYRXWMY41Cv+
         camR0D4FKllrCHcuZfmTp8UTYJaCv5LoiKIewEzYBPyNWJM1nIEYYpb513kjxGkSrx5t
         xHC717FybhjeKnFeFolkHtzB7gYB9XsrbHdFXaJYKDGQ9GNlogB1RsrxmSmFQ+Hkeg4z
         4S8d2O07+tMoRNcTy5j/1UEAl+QNbU/Tf1hsVaouiR5V5J2ZFeEKGz1ZDY+Up7u4QaYZ
         JqeiqsQut7oMrfqURHXlMjzWAA3QwWjUlJIziv0zzwJu6wPENTYvrKQz1V5wF7LyhDL8
         SgOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=yEUJrNTVfNIvacBySzD/xtaOi3Go1shw4gqk3/yKQ60=;
        fh=4atZ4F/HXsWpbGrk+hetL6RqYdMc0xYWkk0+Bn1ZrVs=;
        b=izy4t0KkREBhNMQ5gQVQJr2BxNArtDxL7r6QeCQE8wDEocnJMQCI/KUbxoNqMb7cfI
         nq2GF3wmkcZ1LX1iFHz9cNW1Oyt9flKtTAvZ3mXKFwRhwq8bZPBesA4wLSo6AbpTn1l9
         U8h5Q/N/hlFh+tpHFLiXksRP+kxchzF8r5nCmJyFacAZ27WSlR9l6hIkekeqPPTVy5tV
         z69+oRl1XlObSLTfUbG/hg4BhvLiFTMD9JsE8wYQSu7jt05vF7ERMZQrzm1ISXOwNdD1
         Hi/8xFxIpIR+zvWrETmBqANSuct/UDThu8UYKdg3E5T/62rO20GeHiTlYvkYKfKNqafA
         F3TQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UkeutBOr;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x131.google.com (mail-lf1-x131.google.com. [2a00:1450:4864:20::131])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79c46a1f6si430523f8f.5.2025.08.07.10.12.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 10:12:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::131 as permitted sender) client-ip=2a00:1450:4864:20::131;
Received: by mail-lf1-x131.google.com with SMTP id 2adb3069b0e04-55b98acb9faso99403e87.3
        for <kasan-dev@googlegroups.com>; Thu, 07 Aug 2025 10:12:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVlMOsU0FgblPtQINuyNx039im/nmw2eA6vdNNHHj0LC22YzKwPTTy6x2auuct1ftw8zjPexYvED28=@googlegroups.com
X-Gm-Gg: ASbGncvJsdYtuAMBDjz/Pb5kaomWeQHwSBiiFVbVP3xnTeTZC4u9oGI6ocVwpYW0U5+
	+ITUCb14NNi6yZIm15LEky9+b9LvmFLI61+t1r/embHVqyI1zsz74HS5A5kOa4RZ3e3N085HppP
	e+kalQRH2ds6LNrZ7pyHacPm5ahmw89j+hue7lYkYNaVGHELEHN2l1ZNvk/UxyJ3QlB3PJPQk43
	gpW3aoR58XbNQIYjNLE7PARLTafyGFGMUsKYld3pT9Md6r1OXXNtOeYzkP01yj04sCq4qQ77zZ4
	9RgOj7NBggTl7H5TldsZ9INEzq7K8QlUkZ8UAj5DhvuIvjT+oaR3pRNa4L+Ys9G0GF1tx2Gfiox
	yrd1R8x/Kpf9FSWWnl51iDaXn02EW
X-Received: by 2002:a05:6512:3d8b:b0:556:2e02:6957 with SMTP id 2adb3069b0e04-55caf35f712mr1032543e87.9.1754586772390;
        Thu, 07 Aug 2025 10:12:52 -0700 (PDT)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b88cae595sm2715631e87.155.2025.08.07.10.12.51
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Aug 2025 10:12:51 -0700 (PDT)
Message-ID: <c540359d-b609-425f-a921-c7dad3213811@gmail.com>
Date: Thu, 7 Aug 2025 19:12:02 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 0/4] mm/kasan: make kasan=on|off work for all three modes
To: Marco Elver <elver@google.com>, Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, glider@google.com, andreyknvl@gmail.com,
 dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 kexec@lists.infradead.org
References: <20250805062333.121553-1-bhe@redhat.com>
 <CANpmjNP-29cuk+MY0w9rvLNizO02yY_ZxP+T0cmCZBi+b5tDTQ@mail.gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <CANpmjNP-29cuk+MY0w9rvLNizO02yY_ZxP+T0cmCZBi+b5tDTQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UkeutBOr;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::131
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 8/6/25 9:16 AM, Marco Elver wrote:
> On Tue, 5 Aug 2025 at 08:23, 'Baoquan He' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
>>
>> Currently only hw_tags mode of kasan can be enabled or disabled with
>> kernel parameter kasan=on|off for built kernel. For kasan generic and
>> sw_tags mode, there's no way to disable them once kernel is built.
>> This is not convenient sometime, e.g in system kdump is configured.
>> When the 1st kernel has KASAN enabled and crash triggered to switch to
>> kdump kernel, the generic or sw_tags mode will cost much extra memory
>> for kasan shadow while in fact it's meaningless to have kasan in kdump
>> kernel.
> 
> Are you using KASAN generic or SW-tags is production?
> If in a test environment, is the overhead of the kdump kernel really
> unacceptable?
> 

kdump kernel operates with limited amount of memory, whatever was provided 
in 'crashkernel=' for the primary kernel. So it's quite easily can ran out of memory.

By default kdump uses same as currently running kernel, but it can be configured
to use a different one.

At least in fedora it's in /etc/sysconfig/kdump:

$ cat /etc/sysconfig/kdump
# Kernel Version string for the -kdump kernel, such as 2.6.13-1544.FC5kdump
# If no version is specified, then the init script will try to find a
# kdump kernel with the same version number as the running kernel.
KDUMP_KERNELVER=""


>> So this patchset moves the kasan=on|off out of hw_tags scope and into
>> common code to make it visible in generic and sw_tags mode too. Then we
>> can add kasan=off in kdump kernel to reduce the unneeded meomry cost for
>> kasan.
>>
>> Test:
>> =====
>> I only took test on x86_64 for generic mode, and on arm64 for
>> generic, sw_tags and hw_tags mode. All of them works well.
> 
> Does it also work for CONFIG_KASAN_INLINE?
> 

I think it should. Because we don't initialize init_task.kasan_depth we always
bail out in kasan_report().



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c540359d-b609-425f-a921-c7dad3213811%40gmail.com.
