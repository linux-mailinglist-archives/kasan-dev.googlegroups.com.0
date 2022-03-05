Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSG6RSIQMGQEOOLZAVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 22D094CE3FC
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Mar 2022 10:37:14 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id a142-20020a4a4c94000000b0031a9acddae9sf7536494oob.5
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Mar 2022 01:37:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646473032; cv=pass;
        d=google.com; s=arc-20160816;
        b=OuTCuu0+M7eIGihKF+QueNtYIQ4VkhcjOAN0yQOJ4benw3SXw92mAfRmo+n4V1BEXS
         0WWmbiOMZ5K+0V8N59Rs7/jwZdA1yNY2t+J9KdzQP1Xo80CHu+143bmu0yHu/Z8B7KIl
         EntdVHPH0a5RmsGBShJ93X6xabVBcNRxZEKOsHLJwhUfaClBozkRnn1apOAL5fHqibAL
         IZ6u+gPpKQXHsJaCc46y18hClD43Re/Rzy02/6doWPWTSQ6eIH5WpoYa19Dkt6pYBC5k
         kymnPy/Mo7KPvsk16ZN4giOMmvjyvTa97kIPSJrQ0GgCp+VVZe14XHpHxRfCpZgz/KJ4
         S2Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BQl6VoE5V5H1q/0eylP2Fm4qW/1aCpXfyXPliptya6s=;
        b=GYmpkTsdBaS4gKT7BNK4o/YEjgeBN8b8eyyFun9o3vhdtRRQln6OML1vsDWBMcJd7Q
         06Bph/ft662jfHVHr4JepoZvurzmn/TO/Vpuvxdrz8EAyBRAd9n8ste36xCFJcAuPdYh
         pRZbyYqMHjwD80jfIuRCFrTrkN5B2XdF64f58HKhcXZrf76BIV9zIve244tvvc8XaQAt
         Py9nQGncN7wKTP25Mpc12zFWYIiixdsCOX0zCY2c2oBDmixQCjulkAZIvjvdd1w7OyaB
         BOGpvWiSbAoasMci1aAS9vQ74eIcz801YYAqRz9dxF6LaBjZGVBRDjvztxYvAKsQEt7Y
         1Xig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lHnnCFcH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BQl6VoE5V5H1q/0eylP2Fm4qW/1aCpXfyXPliptya6s=;
        b=kUtJ7XPHoX2Du6zyN+uTNEPevpYXlD/llZfhNeK3iySV8tAp6LJyBq1hOhd8OqMRS3
         t7gWx7TsvwexdN7y8ylKFowBFX6BodrdE0GL4T+Z3RiBy1Zqoj4GhSYzrSZ08wSVItiR
         A4eCzmnP93WEQCmXvPkOwWXOnlUissLhXXTaJFyYLaWfqMEvG034KAyYVDR6a8O7DiYm
         T0jQL7XRXf97D/0ALUV/OukT/DUygTRVcri3ziJjX6zw7YVg8oStUnqidC7K8kfw75/7
         RXj9Y5M5aJZKqzFSSZqCXLCjQs/RyfngW0yG00sHYupmKauh6oCyyN6G6fxJ0otI1egH
         fRHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BQl6VoE5V5H1q/0eylP2Fm4qW/1aCpXfyXPliptya6s=;
        b=Z3Ht3fQTXOOdu3jkBTXCT7ZUv/kpJEIxgo6fgyNiSlY9lZTCfs6xXMJsmzoP/T0CXz
         VxcuBz+VsjwlqCh0OwI0jpqGxRDxTA0c/44vTFXuf/oj3JNvq/4REaN+O2+l9+dGT5oR
         AQyxV9wkNEjfqnfwvU6fiibfvu/SYMwQ6aCQUpSGvi4Zlo9H2Z5mHDShOk5KhK2IaCMP
         +4FVNku1f6StDZo9cbvUTFbOhxCV7q9SlM7bHPeMDV1raxgMfHXwNkH9DXhnQgUNALAG
         B2tD6k1ErIQvkXctaWq5RHkJ7g6aUAKZbBKjM/qtz1D1yOrS0i4vqWPJi/UzaZ1eG+8V
         syKA==
X-Gm-Message-State: AOAM532OCmOBdpMRnlQ3+gsvLSuTCki31eT2By5uY308yizXxBLKXipt
	A4B0Dwn8NXY354V+yBDBulE=
X-Google-Smtp-Source: ABdhPJzNScBDbxoW2ViZAGTWffUwP81hsXkH3CgtjA4CMkxi5p2SewrTAAJjyT4AwpMORg1ZuETUNA==
X-Received: by 2002:a05:6808:bd6:b0:2d9:a01a:48b3 with SMTP id o22-20020a0568080bd600b002d9a01a48b3mr1946403oik.254.1646473032775;
        Sat, 05 Mar 2022 01:37:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:61d4:b0:d3:d118:cc2a with SMTP id
 b20-20020a05687061d400b000d3d118cc2als2588498oah.1.gmail; Sat, 05 Mar 2022
 01:37:12 -0800 (PST)
X-Received: by 2002:a05:6870:7091:b0:da:b3f:2b33 with SMTP id v17-20020a056870709100b000da0b3f2b33mr1540563oae.210.1646473032438;
        Sat, 05 Mar 2022 01:37:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646473032; cv=none;
        d=google.com; s=arc-20160816;
        b=wbqz+QYDm0Kpdp7fIG4ohoLCehMPTkvd+0gR/mZonHhmP9RsV4DNIFl2IqeJi+LykG
         E4ZHuODW3rOASF/YvmIRRZJlv+lsjGWvqcDTPn/3cq3ooUOI3Rzjv7J9p/9gbUN7k1Wl
         oNFYl7kL6kGzscHYN2KIa7stFD/MFiGgDPYLTXF1o7iF+WscT2FZLSqrLoQ5OzkJwxXO
         XFKELvZ80JHOYt9lPdciqWgGYxDvihkm9lW8fTzm2DgbJcNKN3pXqCiLO4DlZ8xOYZNb
         oENUDLEZAKFHsIy2hX1x90bjbDIgdTqEMKSkhv5O52rVm0uwmFNUgUnTfiZA/fK/15c9
         xIIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=o8YRPKtxEMPdU6+Q3B6e4fqO0sPdCeK3qQDcbu/LSDI=;
        b=WFzSn0FyJCFb5rJeeTl65ioGUjbEaJqPfjBzFpuo9s7ZJmW+SO6jMv6KMGycb7ybLk
         yKN8jY9PwhQI0enXgJ01D7LDVJ8WjNlF5UitGdYivu6AGO8gqiUChWzSaOularcb7Ln1
         6XvvLYv9gcixaumC4levq4kNbjsWeT7vVsxTWBtc67mORgx1jrhz4rd2OaVdIiRgGsln
         CoRBC0Z4mLTnJpWjRl100hAo6ZDao+CLYoHtxysrK3XAZdp7XJ7OQ1UydINhKombkmIp
         JHEaFgQ96w5YclE8WF1Tg6fsUkYCZOs4pZhXUb/wZg7MiRbKTG9iPA34zShvixyaRnYo
         ATLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lHnnCFcH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id c6-20020a056808138600b002d560aa6678si1036740oiw.0.2022.03.05.01.37.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Mar 2022 01:37:12 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id e186so21584102ybc.7
        for <kasan-dev@googlegroups.com>; Sat, 05 Mar 2022 01:37:12 -0800 (PST)
X-Received: by 2002:a25:6994:0:b0:629:1e05:b110 with SMTP id
 e142-20020a256994000000b006291e05b110mr497927ybc.425.1646473031701; Sat, 05
 Mar 2022 01:37:11 -0800 (PST)
MIME-Version: 1.0
References: <20220303031505.28495-1-dtcccc@linux.alibaba.com>
 <20220303031505.28495-2-dtcccc@linux.alibaba.com> <CANpmjNOOkg=OUmgwdcRus2gdPXT41Y7GkFrgzuBv+o8KHKXyEA@mail.gmail.com>
 <ea8d18d3-b3bf-dd21-2d79-a54fe4cf5bc4@linux.alibaba.com> <a293da49-b62e-8ad1-5dde-9dcbdbcf475e@linux.alibaba.com>
In-Reply-To: <a293da49-b62e-8ad1-5dde-9dcbdbcf475e@linux.alibaba.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 5 Mar 2022 10:36:35 +0100
Message-ID: <CANpmjNOZSuJTMQRW9LbsKTcak2Qyx_VdTp7Fu99MK1GxPmwO=w@mail.gmail.com>
Subject: Re: [RFC PATCH 1/2] kfence: Allow re-enabling KFENCE after system startup
To: Tianchen Ding <dtcccc@linux.alibaba.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lHnnCFcH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
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

On Sat, 5 Mar 2022 at 07:06, Tianchen Ding <dtcccc@linux.alibaba.com> wrote:
[...]
> Hmm...
> I found KFENCE_WARN_ON() may be called when sample_interval==0. (e.g.,
> kfence_guarded_free())
> So it's better to add a bool.

Yes, that's probably safer and easier.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOZSuJTMQRW9LbsKTcak2Qyx_VdTp7Fu99MK1GxPmwO%3Dw%40mail.gmail.com.
