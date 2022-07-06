Return-Path: <kasan-dev+bncBCA2BG6MWAHBBM6QS6LAMGQEDUGVWSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BC645692E0
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jul 2022 21:53:24 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf5396738lfa.10
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jul 2022 12:53:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657137204; cv=pass;
        d=google.com; s=arc-20160816;
        b=u0S1DDaW6Dkh33/A2R/Ava3A9HOBD3kVLwPQRDOFiAJQxJibx1mpn06+On24lCz6Nn
         gzZhmdiW8XwcQwKydMJZI4GvieqJwvkIGnHM4pbNs8NlwlvwF7yYJZ1xoh0vE4uqnkhk
         UGicuIG/sHaOhr34Zc2jZl0RQe0r1381L8Ury2iRcOXhEm55FjO08lABhlQNgE66y940
         jRHq387626DHCh8yIyrUNbwkAs3wnZi6Hgt8V2z7i8yNvV44ObYyGxrIceL3rGjYNBfh
         P/yprqpD44lzlF9nQocFLCL33NWdP8Nwqq+BDU9wSePESIYkOifCYTmytMKyTIz2m7s3
         ykLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KjLP4QiT+jw6WqWG1ttKFIEMq+l2eGaA/mSB605bFa0=;
        b=uvRcYyuMbKAA2uzopY738urJltWJLL4wH0hdTU07glfpgSduz9qmxy2u022bheziyC
         TkG4YrStFoKyh6H83lnGka7Zs8HJ8NJpzbD3SYQdqSCXWg5QIKMNIpMo3S3dg1A0miUT
         xNjwdnhQbluEzlyWYzBme14X9x1Z3SokHlkoj4OapsF42eS+PXWjt5108LInvz3llaMO
         jgPdWRfexC+ogDOchjTc1LE5tRtum/wZ/2Zff82OdAw5ZGEO9qc1HO3DBUlrHso5Ppob
         Tnr+E41myMf6I7vY6Re33a/X8/pmkWWSEz41/B1MmgvM0Fh3Efa/tV8/4ehGNbxPr7qm
         t96Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nGUFuIUn;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KjLP4QiT+jw6WqWG1ttKFIEMq+l2eGaA/mSB605bFa0=;
        b=SlBsB/UxOchqGPRHyCsGKqporS63uk3XBmd1yPAXjlbwwpSOXRpPxQa7uXlrEsWO1B
         hAwUErimpsKM/uFmjuDJUKSQXMl+kYpHAEwP3a89jL/dprLpRddGYRhESWCEYyk8ikf0
         FNXseKoUnPA4Qgmu8dG1qYMNH8qssmrKW+UDRqm1xPTusWgERXtGZq1YCrCibHkrNgXo
         7vuW0599KIh8J7RIiDTGubNVtl/m20vEjtwZknIoRrKo0zHBh6F124AfeowlpF/VmugJ
         G71w7ro6vMSgGpqayah8k8Zjw3/N1W257csDPtFWfN2wgryq1XQfhCHwD2/gaXM0/asr
         Pjtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KjLP4QiT+jw6WqWG1ttKFIEMq+l2eGaA/mSB605bFa0=;
        b=httOVYtT5kLW7smb+cxVvksvuCTQi25TsAmRrO5aAvUGDdX6WWo56jSo+RVed8BLhg
         ditfBEMJw0Z/Q5tQQaagTjpcQqAj4Zag61UzqIeWJ/EXPnrjxDeJgdb1MEoEju4IlYXP
         xKlD6JK94x5QXyB7nL9Zp/BHBQC0wekHYrVOT1VTqktE8UeKYpwz3a8zB3zx+uYlCD1r
         lRbcwK3juuo6SYJhPhlGOvgIYUsPmlhfSyBvvpCLbNjnYx9QC7GIvAwSD5c0p+u+6zqU
         BjGZZy0YXKdZDGrPtd2lfI4b+jkSq8uoCz0g8KDtbAOVxey7TUT08blkGQg07/xP3dOb
         yPEg==
X-Gm-Message-State: AJIora9IlpN+Os9BN8SVzh4O32j+jXlIlznfvbU2IFrYV4Es2b53yWug
	INJTED2iChgebGCUW3M2Gyg=
X-Google-Smtp-Source: AGRyM1vcR+GGtN0x5wSeL7Ae69m+findLCMDJEG3y0eRDrdTFXOZcu6YAhiPv78p/VoZR+nR3uqXJw==
X-Received: by 2002:a2e:9941:0:b0:247:dce8:b0ec with SMTP id r1-20020a2e9941000000b00247dce8b0ecmr24926728ljj.404.1657137203763;
        Wed, 06 Jul 2022 12:53:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9c88:0:b0:25d:3a42:174a with SMTP id x8-20020a2e9c88000000b0025d3a42174als904352lji.5.gmail;
 Wed, 06 Jul 2022 12:53:22 -0700 (PDT)
X-Received: by 2002:a2e:bf27:0:b0:246:7ed6:33b0 with SMTP id c39-20020a2ebf27000000b002467ed633b0mr25496311ljr.167.1657137202614;
        Wed, 06 Jul 2022 12:53:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657137202; cv=none;
        d=google.com; s=arc-20160816;
        b=SrBUOgxKljjxxFHbYcEVXExykPjy8oHJqP5kBTanTWd0jNhkIXkUMb0dgXilKrrNrc
         KKd4Q6zd1QP3N0IjJ87CIx9iaJRZv5tPWado20iH5kIqBlgQf50+42WhAoFdhKA+o/gU
         G+rSHfXE58pR1Ph3vk3DrIaFryJoG9BFJRXq79CwQOqdhWDTD3nqLnmi0TKuPT7Q2f++
         a4ZOAiEdm1kSsf95LfyNO3KakkAsX8nhVUrj+dxcTfmQh65d11u12UNIHKS5DF4khMfk
         M7vtv+BJZDjB7Q1VV/KzezTxLRkmDdSip7t8TaCB1gzBNjK1FXs70PfISwwSwZ/XnLyk
         GdSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=d00ziUFyPDQ6I0nNLFmAgrCX7fUelcKHDlXhvLnYQpo=;
        b=PTV2+h/9+lDRtQGRdSSuhTkaTvNVl5JnounYXjf4ua3pzEopOLJhbIYgUwm5X61kTl
         arPMZG+Bc/iX6qvTGXfudZzTXsBhc8mHJCikhZSRLGOo2B1eph7xj1bRbmPEH372+EwL
         VG6Ww0yNTnxvR2gkepLYXXJICSQYz8AGogouyzhz/GB0mhX/2eSJV3ubIk9seqK4Oi4K
         lny86cHf+BLSA/f+2UaqZ5ZTD9WC1dhJ+l+41xLyu3LbnKYYmGSdmHsQGPirJiziJ93P
         bKEgslspzLIRwhQubQcnqhi3MfQA2EkXMjupRf/sFXdqvWTSwTi+QwBDKKv7NIFjhOtl
         r6IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=nGUFuIUn;
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x636.google.com (mail-ej1-x636.google.com. [2a00:1450:4864:20::636])
        by gmr-mx.google.com with ESMTPS id m7-20020a2e9107000000b0025594e68748si1578822ljg.4.2022.07.06.12.53.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Jul 2022 12:53:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::636 as permitted sender) client-ip=2a00:1450:4864:20::636;
Received: by mail-ej1-x636.google.com with SMTP id h23so28819014ejj.12
        for <kasan-dev@googlegroups.com>; Wed, 06 Jul 2022 12:53:22 -0700 (PDT)
X-Received: by 2002:a17:906:cc96:b0:728:baf0:ba03 with SMTP id
 oq22-20020a170906cc9600b00728baf0ba03mr40145424ejb.52.1657137202253; Wed, 06
 Jul 2022 12:53:22 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <20220518073232.526443-2-davidgow@google.com>
In-Reply-To: <20220518073232.526443-2-davidgow@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Jul 2022 15:53:11 -0400
Message-ID: <CAFd5g47Jm78WxSo_A4syoUZApMHvRdXb2yNvdeu2BUDRpS75KQ@mail.gmail.com>
Subject: Re: [PATCH 2/2] kcsan: test: Add a .kunitconfig to run KCSAN tests
To: David Gow <davidgow@google.com>
Cc: Daniel Latypov <dlatypov@google.com>, Marco Elver <elver@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=nGUFuIUn;       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::636 as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
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

On Wed, May 18, 2022 at 3:32 AM David Gow <davidgow@google.com> wrote:
>
> Add a .kunitconfig file, which provides a default, working config for
> running the KCSAN tests. Note that it needs to run on an SMP machine, so
> to run under kunit_tool, the x86_64-smp qemu-based setup should be used:
> ./tools/testing/kunit/kunit.py run --arch=x86_64-smp --kunitconfig=kernel/kcsan
>
> Signed-off-by: David Gow <davidgow@google.com>

Ack, but I think Marco settled on removing CONFIG_KCSAN_STRICT=y and
CONFIG_KCSAN_WEAK_MEMORY=y.

Acked-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g47Jm78WxSo_A4syoUZApMHvRdXb2yNvdeu2BUDRpS75KQ%40mail.gmail.com.
