Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXUKUGIQMGQEAOXDQWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4BE64D28C6
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Mar 2022 07:12:47 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id m16-20020a056808025000b002d9ddfbc38fsf1190772oie.10
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Mar 2022 22:12:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646806366; cv=pass;
        d=google.com; s=arc-20160816;
        b=gNVuriGA7lTJXrXNm7pEIFHXbecgQzVhNK4P6TY+0bkptrKMfE0MPEH3To2BnO8emK
         kTODSzv0Gl3DnlSqE1V8Vbz/CFfW34yAghF9ykO/2kcyFL4lUCr19DNuRVfpqnn5FdW+
         XC15Spizt6sJl3px/4yI/BNRNaz2K4Ptub/tDeC4lfkYgThHZf0tqb9EtO/iPEZYrK5S
         TmqGewIjtzaYpfs6d6EOidRrdjD5Yf8YRH6exrVYh3v/4up/KQFmZ8EiyytmpG85GJEF
         AppDxbaZXZYYo14Z4PXKkgptX9hJgbMokcCxE8JNiqdI3i6sfnMdzedzKw+7cstwWjMG
         aFIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=D4nMxqz/zWBTHIBEs5n/SHuu5+W3yTuYAL2xrt9C6gE=;
        b=tXED5Jj4RmRRqBtiit0UrtvbgQCQnmcPMCZSd0Rm4FlTB5RHuK05MarAS3Aih0ea4x
         PoV2+kTMPXAZd2+TovSFmCPsp67fB6EgNiWCIgBw4DI3s2Ckp3lxYwNgUVyEk78SccFb
         6ApWhOD0zu86jWLvCF+U5OtDhc/lnD9IgzYMI0aaprYU05uCbOh3h95gdK692zbJwmw3
         60XqZZQ7FqQ769yOKj7yrLI9pJdEefeSGukdwQA8ehNEpjr4ssDNwcvK8F667efvEpQz
         B35o7mInSaDjU9IrwaMLZ55Jhmx659T0dLQ6U8RTZhzpwMeXI3cwNXN4yxAqp3HR33Ds
         RykQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aPuBcekG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4nMxqz/zWBTHIBEs5n/SHuu5+W3yTuYAL2xrt9C6gE=;
        b=TxA04gv9/EUBsW9Ng/UOGEzmvH4xjIarYPaEPAe9v2LMEIADG8L7X9EtLsxmCSGyE5
         bpJNgPE5uPrIMVG7el8KeA6Q0WvbrHdfV8gy/vWMFxCeqe3YdrdD2vIkitxeFFXVPNr9
         ifd920hRiyhCQGrm2lxz0aiYA2ZCly2KH+F2dswBJuzeGgphbVfReZn173vFGORuA4Bd
         YduCNkmx0mO0zjOtA97S7f/DqFO4Ko8QgucKmqkao60+HFmRpNzkFPAo7D9DCAisDbSE
         w00WFGsNdj0yZI3LFlHwe+H4zEhmW3N2j0o3bR/3T62zJz/LSaJ5xacAHVtHGzyLDnzy
         DfmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=D4nMxqz/zWBTHIBEs5n/SHuu5+W3yTuYAL2xrt9C6gE=;
        b=2UbjM3AjY2z3J4qpVnaYK1YcodwBC7f6u816YMS4FqRHpDDczs5mngiwW3NrU8NyX2
         bTWNk/ybW93gwr2sLwG+uFKIDN4wb0v6ug+Yw3Ec88vfYFZirEYqIShHx51U9s3R0PBq
         zIu3bY+/g2oQ07uI27GaR9/LLWk4QPOkA0wgHMxyK7A4V+d5okuTK0M48wRC2FU8qQyC
         13/8SltlzbSV5nLCJXLJFzTMFTtFgYDQjVriKA3AuUrJs7R1ORs1NKvDra1wV8LPzVKS
         HAJ7YV1WLKDthreXoMTjmJIBFIz1OxIjPZhRRts95qOsFMVpkUeU5rdzZa7ZCb8WVZzV
         gGpA==
X-Gm-Message-State: AOAM532MpvHsfqYUz5KrIAapwdGneI1A46BmfZk4/epOvd/lU/AGwOLs
	v1j9+d7X++urt9b900mn5+w=
X-Google-Smtp-Source: ABdhPJz61kCnYv/yUQoxZZKrfUxDwAIVKQm17D3BxyLOtQxTj89qhyLX/EPbjUE5mMDDfhvytzijBg==
X-Received: by 2002:a05:6870:b01b:b0:da:201b:8f7f with SMTP id y27-20020a056870b01b00b000da201b8f7fmr4258913oae.159.1646806366298;
        Tue, 08 Mar 2022 22:12:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:530a:b0:da:8e21:29ef with SMTP id
 j10-20020a056870530a00b000da8e2129efls426740oan.6.gmail; Tue, 08 Mar 2022
 22:12:46 -0800 (PST)
X-Received: by 2002:a05:6870:95a0:b0:da:b3f:2b18 with SMTP id k32-20020a05687095a000b000da0b3f2b18mr4637200oao.183.1646806365976;
        Tue, 08 Mar 2022 22:12:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646806365; cv=none;
        d=google.com; s=arc-20160816;
        b=r+TUc7eEgL+14319ThglyWk1n66bSDbFLfk68FSBAGdUX4RaMiwVojaiaadxfs3JZr
         GezPSeaHCr6Xk0zfzhokn+GU5yR2jS6/1jz0PwNTDscYJkuFYSpGEF42N79rtqXqdqXC
         CgT86N5TmnEv0pSMkM4MtTh/oC72gnlA20UiE52GBkgbMYhiOiIyVGTXLiy5DhC9TZZA
         O1UdUffp9Ju8T1irhO+Bd4qEtc+OkS+WpSKmwLvLyynFdZXYTCOuGq9VC1hNCgM51FuT
         8wlxVBdlnePhbgGE+WGfS5xlNHZw2fMzpp95rdnZgQc2VXJ9yxy+ol8bsv5DPmV1Tvy2
         GVhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=//61snb4FzOH8xBVPrGQSTEOIUqrxrg6uRM2aNBozZM=;
        b=rhE28JfKEe2xrD60nYtWcvNR3kHBYG1UZUanlomlsSp7/fRhSw0V+uF9SK/sy2mhJO
         BjUZoZh1Z3dlG4Rf9AAyAGD5AJYU2yo49wLRHC2SQV1EqgWOV2vBJtY9ro8agBfK45xA
         ZsN9+vF8SHxA0Q0FVwHWz+01jhQx4Lgo3Zh4pOTPOIjwioX+iSo6XJQqhf4MD/7H1Exi
         fIx6SsgIo3O7ugme2ddETZYvPwjMbtwW6FXGnHQPYviSl2DnrmXgQOFTX3IQF1EblSlK
         uLPpg+W7G/4Lnhj+KXpc2pmO3vP0t7aSfAF6aJGDvkmYGNA372eaZKmAgylqpxnIBzYk
         rLog==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=aPuBcekG;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2e.google.com (mail-yb1-xb2e.google.com. [2607:f8b0:4864:20::b2e])
        by gmr-mx.google.com with ESMTPS id e184-20020acab5c1000000b002cf48b6b783si88017oif.1.2022.03.08.22.12.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Mar 2022 22:12:45 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as permitted sender) client-ip=2607:f8b0:4864:20::b2e;
Received: by mail-yb1-xb2e.google.com with SMTP id v130so2181678ybe.13
        for <kasan-dev@googlegroups.com>; Tue, 08 Mar 2022 22:12:45 -0800 (PST)
X-Received: by 2002:a05:6902:203:b0:628:7b6f:2845 with SMTP id
 j3-20020a056902020300b006287b6f2845mr15356927ybs.533.1646806365542; Tue, 08
 Mar 2022 22:12:45 -0800 (PST)
MIME-Version: 1.0
References: <20220309014705.1265861-1-liupeng256@huawei.com>
In-Reply-To: <20220309014705.1265861-1-liupeng256@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 9 Mar 2022 07:12:08 +0100
Message-ID: <CANpmjNMfkUSUEihTc2u_v6fOhHiyNOAOs2QROjCMEROMTbaxLQ@mail.gmail.com>
Subject: Re: [PATCH 0/3] kunit: fix a UAF bug and do some optimization
To: Peng Liu <liupeng256@huawei.com>
Cc: brendanhiggins@google.com, glider@google.com, dvyukov@google.com, 
	akpm@linux-foundation.org, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, wangkefeng.wang@huawei.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=aPuBcekG;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2e as
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

On Wed, 9 Mar 2022 at 02:29, 'Peng Liu' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> This series is to fix UAF when running kfence test case test_gfpzero,
> which is time costly. This UAF bug can be easily triggered by setting
> CONFIG_KFENCE_DYNAMIC_OBJECTS = 65535. Furthermore, some optimization
> for kunit tests has been done.

Yeah, I've observed this problem before, so thanks for fixing.

It's CONFIG_KFENCE_NUM_OBJECTS (not "DYNAMIC") - please fix in all patches.


> Peng Liu (3):
>   kunit: fix UAF when run kfence test case test_gfpzero
>   kunit: make kunit_test_timeout compatible with comment
>   kfence: test: try to avoid test_gfpzero trigger rcu_stall
>
>  lib/kunit/try-catch.c   | 3 ++-
>  mm/kfence/kfence_test.c | 3 ++-
>  2 files changed, 4 insertions(+), 2 deletions(-)
>
> --
> 2.18.0.huawei.25
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220309014705.1265861-1-liupeng256%40huawei.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMfkUSUEihTc2u_v6fOhHiyNOAOs2QROjCMEROMTbaxLQ%40mail.gmail.com.
