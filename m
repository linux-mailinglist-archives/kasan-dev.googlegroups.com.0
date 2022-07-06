Return-Path: <kasan-dev+bncBCA2BG6MWAHBBE6ZS6LAMGQEFJSKPGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 57AFF56931A
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Jul 2022 22:12:04 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id o28-20020a05600c511c00b003a04f97f27asf8526018wms.9
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Jul 2022 13:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657138324; cv=pass;
        d=google.com; s=arc-20160816;
        b=DRdIgrwCgkdAcrKxrW5ALCyvGFNqj1rKOoY1y+VqrNbekF1i1d60i/eKukcXcbPO/7
         sLYxRih3FL9MP8z14I4mSdwidkk46mX67c+Btme9kgPX3snAj7ykV9hNtfsbXnrd1TgM
         ZelOKEG2kXwqwTuQAko+rh4qxE3A1jt6qAdU2kNu7DqF57k5q6uDznN6MQmpg+u1jvS5
         ojR669hYaV9hLFgg/em/4Kx7ckMcJhZNs1Cl3P7+fdsj7NKQ+wRgOKbj/k2BGlZw4yDu
         KoXNeAMIwZJJkfRV6LXZx3jTHtL2X4TUA/WtzH+7COQI8jYXZbraD/AamCCZf+uPIe/Y
         licw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=DNmMBNZTW1/u4qUEVJFlU8bnvMeMuPTwcixb2b6qgAY=;
        b=KC42CNlDc+N0K7Ni7ShhRs9RjD20oL98oU5cwBPdJuZ6n+cXQljjbapfGj4N3KsDQB
         uSNLX3sHEQIGd/VE+jwX1fDFBPraU/8thUSTcqP+KE80eQWXxcQUznSN9v+DRt6M4VTM
         jgyGTXf/a5r4F3rdZNrRhyNyplXedNpKq1U7WYfMI1H7pA79M7Rr+Ku3DDSY6W3FwzIQ
         Er508MViJC6Y3a2orUNCDRVXIVALBoRXrHJTXmkEU5+hkJdibjcuRrAAY2X5rhTQmyL3
         FcFqdOySt2A01gnGd789oKLeum14bzINleucsMNVNCs6xaxVmrcHhRGbPW/b/9aAar1E
         JaMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="F9A/ikOa";
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNmMBNZTW1/u4qUEVJFlU8bnvMeMuPTwcixb2b6qgAY=;
        b=RjddKoaDPCQXiq7CDpvu90gvbKfEphmrL9kM5QAmM29WCu01sDvX8lxtE4mFNiZyi7
         RUiUrRv7NFEPNGcCUpJZUJXy3+P8skO2rp7Thz+C+p7ZqGfXAX2ET+oW3zodBvc9GlF9
         gJAclpv/s7mUtKEzB1vy29jzFV76sKHjTZABXnDdf5sQFu29ZXjQpAB2ocJ5lEt435hW
         ePnrBlPla9RYpbqwTG82hTKVlYEvZzHow/5NK0dnzIBgpy4Zeri+MRCaIGEQnX5Y3tsV
         vnJGo/YVQPCkliFJAuvclGfieDhWhSdzi30Ya1wFWbr2l1/hLwpZxcu8OGY/8EfZRAtD
         j/dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DNmMBNZTW1/u4qUEVJFlU8bnvMeMuPTwcixb2b6qgAY=;
        b=TR++efMt7fmxulaQPGFux+yIm5wuVY4okXcMjDAQ7rCm3NjiUyWhOlUr4S5OeCG9Ve
         lqN0mixQrasapYaFp2/SsF/ZIzioXYgaQtqrjeHJKzYxeLzyGHvValPQsnuMII43z9i2
         CuLj6OoDMgx3bKvQ58bjvsdLKqpIpELAQbWmaQI3NtiSwCveWIJYR2HnqHvwcDZyMGfU
         4td/A7kWUYw1IxAW6BAq3qEQDnvKYEDphzVksP2xvX3RMcIlMgBkAAaGpAOUT4hj+bpX
         cJJ34DlKcbq2uQpJ0g+PAArgK41AIAi4fTb+ebDuQxAU5CGnpR/xZSo1Jnz6AFec99O+
         89Qg==
X-Gm-Message-State: AJIora++2+aROPYONpnJjugxvV8gfGyq3vRiJCmKjn1fW1a4/sCfJ4I0
	L0PKC22yyrKJKN/mBkVXEGs=
X-Google-Smtp-Source: AGRyM1vkiRuC8zvTxe2puTmwwhnnVclwuCGWGdDX9TFgq/spL3D/DTfEEfE9Mh/6uRvFi7dAOGfOuw==
X-Received: by 2002:a05:6000:15c1:b0:21b:ad5d:64dd with SMTP id y1-20020a05600015c100b0021bad5d64ddmr39273118wry.642.1657138323959;
        Wed, 06 Jul 2022 13:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34c6:b0:3a0:4f27:977f with SMTP id
 d6-20020a05600c34c600b003a04f27977fls10591574wmq.2.gmail; Wed, 06 Jul 2022
 13:12:03 -0700 (PDT)
X-Received: by 2002:a7b:c3cc:0:b0:3a0:5038:da1d with SMTP id t12-20020a7bc3cc000000b003a05038da1dmr367065wmj.134.1657138323143;
        Wed, 06 Jul 2022 13:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657138323; cv=none;
        d=google.com; s=arc-20160816;
        b=zC3cthXsTZQ2NfFAz3oHFlebBK6pC6760+YtjRf7TIrkXAe1PlO1lTkL7YCLE65iqx
         qowv1TU4+lHWZ2i+nO7GZaD3M6pSA+h5cu9SqzeDpS93GZPfuCE41xrqQxTPjeMeEf0n
         OmI3J0zg8DF5+0aeHQFcaxN57EXVaKaG/r5Hpv5EUVYYZo9UmLvkPqLlS1f/v4iOUcCK
         IVf4iC3119V9TjyXQedjos3gW62ynEsEuJDA9yWumHFAfu968ctqiVvFBUSFmG3PhJsg
         J1/aiej6pd1HJdNu9C0e4ZrwZlQEv2Cz7g6N7GuMc4I6FlEs/cKGleN+4uat8kgwta7t
         rQPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=HVOyRJFl3auzy5uUE3eiIM7wPcPXSqEg2Dt9oNXrcRA=;
        b=u+raVAdjeonv8V9gB2zC8SpPMxJ9bez9UBdR/vZ/tzvFSOPgMObQa+p3zmWpeykzh/
         OOjD8IPiKrbrOdtW6Ils8PxrahnUpHAVE8fVbBjNA3si//4LjRp3nQQlzWoCW//bqhbO
         XcrBXRs5CVn1dY240w3vLSav4enDYDcvvn0E3rIWEOH5ntyxc6Vq8I5bLXi6BPEJ5izc
         F8w3Nc1iWkgaGHVZfhyfiTHRACHf9XrDvzhI1fmhLNMYcTNjYBNFB+RZjo+txMsN9oR3
         dQ8nO76I3HeyLYsBJbr9C0fVPAsNU/jFXV9TpCtUDz6IqhsgLjOhflVdvJw2dw23pgUh
         asFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="F9A/ikOa";
       spf=pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id l10-20020a1ced0a000000b003a2ca59af2dsi8798wmh.1.2022.07.06.13.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Jul 2022 13:12:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of brendanhiggins@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id r6so9216148edd.7
        for <kasan-dev@googlegroups.com>; Wed, 06 Jul 2022 13:12:03 -0700 (PDT)
X-Received: by 2002:a05:6402:4488:b0:43a:7b6e:4b04 with SMTP id
 er8-20020a056402448800b0043a7b6e4b04mr13073971edb.202.1657138322816; Wed, 06
 Jul 2022 13:12:02 -0700 (PDT)
MIME-Version: 1.0
References: <20220518170124.2849497-1-dlatypov@google.com> <20220518170124.2849497-4-dlatypov@google.com>
In-Reply-To: <20220518170124.2849497-4-dlatypov@google.com>
From: "'Brendan Higgins' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Jul 2022 16:11:51 -0400
Message-ID: <CAFd5g47LpZDVe7L1-B3Pz-pDmPkyojNFiugHEEAzWD_W5eOrHQ@mail.gmail.com>
Subject: Re: [PATCH 3/3] kunit: tool: introduce --qemu_args
To: Daniel Latypov <dlatypov@google.com>
Cc: davidgow@google.com, elver@google.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, skhan@linuxfoundation.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: brendanhiggins@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="F9A/ikOa";       spf=pass
 (google.com: domain of brendanhiggins@google.com designates
 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=brendanhiggins@google.com;
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

On Wed, May 18, 2022 at 1:01 PM Daniel Latypov <dlatypov@google.com> wrote:
>
> Example usage:
> $ ./tools/testing/kunit/kunit.py run --arch=x86_64 \
>   --kconfig_add=CONFIG_SMP=y --qemu_args='-smp 8'
>
> Looking in the test.log, one can see
> > smp: Bringing up secondary CPUs ...
> > .... node  #0, CPUs:      #1 #2 #3 #4 #5 #6 #7
> > smp: Brought up 1 node, 8 CPUs
>
> This flag would allow people to make tweaks like this without having to
> create custom qemu_config files.
>
> For consistency with --kernel_args, we allow users to repeat this
> argument, e.g. you can tack on a --qemu_args='-m 2048', or you could
> just append it to the first string ('-smp 8 -m 2048').
>
> Signed-off-by: Daniel Latypov <dlatypov@google.com>

Reviewed-by: Brendan Higgins <brendanhiggins@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAFd5g47LpZDVe7L1-B3Pz-pDmPkyojNFiugHEEAzWD_W5eOrHQ%40mail.gmail.com.
