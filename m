Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHFQTCEQMGQEMJVUMUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D7703F72C3
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 12:14:53 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id e6-20020ac84e46000000b0029baad9aaa0sf11978196qtw.11
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Aug 2021 03:14:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1629886492; cv=pass;
        d=google.com; s=arc-20160816;
        b=p87adx/GeOvfx/fEt4SyoEoKZE5kvvm49rlbIerIDTmhnAGM7nmOGVsDCs23L7iGhq
         XC5xX+FyzVY59a75D1wXIfjVKeCdRNHfyp49Qdpk4zPKK1BSbAuIIsjokIyuwzvxgwp+
         m68LdzVQjv1Kx+GAgf8C6ZjrAPChwcOqeVQk6xVM5IL6/vbhufqxEN5AMT7v1JA4aVlf
         Tc70h15tWHxckehPfV0G7bKnjcvvywJipk646cDhuzozmaRfC8bqI7zCB3HQwD3y3O8R
         GGX59NilUGPUmneZuR6aAdZk+bqeRkUdU4GUek6wfJwiUbvGNiT0sQWa/xbYXTCndldU
         R9Nw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hYERCQs+hUv6jjulGcs2+34gfy/SLCygn29Fzzegjd8=;
        b=glaO8MePi6sKL6OBLDx/CR8901u/V3uVeGarbfyNgSqtaXSWSZjDr7hkZgjew7Sau3
         ctB0QVGvRxnUSY1/JujHBsKPDShaPixDcdFvQy77viMJ351VhZJsn6BqMKYC+n7jEV2C
         2oSjDsqLaSMorYFN+JCvPexQ6UBYB8nRAVbBEIWTjNLriQKUGuC3aS9GfdAfVSBwheka
         GzmhP8dDsVqUHm+SwOslaJmtiyDUK+S9/nEvrtqHkmjGZsjuDTdHTdFK0ul6QuZz4Afb
         YhUPndc4E3clu9ZKcpAKRbgj/9J4b1zugUgabBJmP5roofdHkx8ddhC00VgNkIoRcRwo
         w12A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UfV7KZLI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hYERCQs+hUv6jjulGcs2+34gfy/SLCygn29Fzzegjd8=;
        b=mVm2cJM5Q5Ofg1/hwh6m8OAN6UQWBg33nJvMPz+GacdXG3vf1IpkX+l0lGqa1jEDLW
         KvD9ru7AcfPb0ANCMn033REps/6Kao9PT4j/O5rdIAU7HF2VmtYr9iNqOw8RSR0FSYST
         uVFOtZy+vWcqayFBOZJFjUVO2M157JF0cfsV26unrLdcwH4IW6FzlWeKBykQre2CWvNP
         D6kDZ0DAlIg/NnHAHOjAtbDl/IDFikCZcEByOUPvsO5+ZVcXqkPazoBTKVUiGGAw7Jec
         9TMBk4UqsBG6xOUYn9IJKIlu8TT3Q/hkHXRbQ8lD8skUbmx0SmgO9M6reDP00xTbjrV2
         aAmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hYERCQs+hUv6jjulGcs2+34gfy/SLCygn29Fzzegjd8=;
        b=dgkskMVdBrkMH/vXDr0P4edSXCA2LU1UQdeULGMDnuQJ4Ei+fd1pV50P2hcNIhP9Eo
         P8DIWltLB79RMaqPJvylxKC+NtyQ0jlhRez2NvFc8y2DINxiSHNqKsSppRhhFzz71USg
         C0B9pgCHHlneSXQs6K1qhnWiBVuOCXN80nrdm7DMnAICGwpFjit9drYwQdEfWX53zMga
         nlOxSJZ1hMK/bL3vAOAP4jjDh/5BMYcJHeFsXEEh7vAp23HVZy/bc4i/tCK3O62GI6Es
         bDnLkO/3z5+0/0PdBsh05BTSjuaO3nkw6WNEJMxV/KG9y39Ybzk6RT6ZBRUhHijqx7hq
         D0HA==
X-Gm-Message-State: AOAM531VPVPv1R72UuUZhCIIBJDcMI8HutuOrpVmvF91VIJzE9KeC2Jr
	bDfcFDQHiapte+0o5mGJ9QM=
X-Google-Smtp-Source: ABdhPJzsSllSqYhOAHuuTRASlzu2zBe215ipClSB5mkSB1dwI8Cllu5brSXE4HrAkJu4ht4Yfyj5cA==
X-Received: by 2002:a37:6303:: with SMTP id x3mr31082004qkb.214.1629886492574;
        Wed, 25 Aug 2021 03:14:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:5f81:: with SMTP id t123ls901137qkb.6.gmail; Wed, 25 Aug
 2021 03:14:52 -0700 (PDT)
X-Received: by 2002:a37:9e55:: with SMTP id h82mr31139578qke.42.1629886492107;
        Wed, 25 Aug 2021 03:14:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1629886492; cv=none;
        d=google.com; s=arc-20160816;
        b=iUcxA7jpUQgNs0TAU0rri4daFq1qLQYVOxxchSe/p90mr5cVsBKqVaTvQxgu3yB0iX
         jj8hCBZHyXFy1xP8BwohNCu7ALHuQdOAzj9/3ZLNz/xdV6lcYVOR9hVrE7q86TIJ51Np
         V1oLc4/zv0uUVtOKIvvrGUVcEXuM2oPohXCD0tLFKlNDbOfC3mdsHGDomxd5gatJPrQl
         lAEm5AXnXIStAUpzXbMPO49BBhAhYyyyophgC9PoiYTmY04KOMfboRZZmRvzRd5StLxJ
         ZWUmLEVQlhbTA3cWZXg2zOBkjGlLO4jNgNUxGhnfxXpS8qsC5TWe3kY2S7lfjHH/PkQE
         cbjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ex9BVVFADdOQoNAST2PICmKZlAuG8UXgh5xdQmKSPzE=;
        b=OGILlrqXUUjTQTsJLA6MlcmH95jsHxKFe3lqEcVxI8mQFnQYoIK4oFb3eFHdd72mOC
         6ce6fviImlPzEVb0gYLDgULBBTW2eorEc4hp7RTKu6iTRu8IZrwvGbX0rqBcEZQl4WD1
         e13UglM9G5jSyoB/dAKqFQj1PMfjJV0QhZljK2KIfWQCReDTprNCpe8Vslvb4bEL2hju
         DZgTlDZ4Fwt0luykFrCzaF0oYJ+Lup66Wo255pg+tKtptiOZ9yWFg8QItuvUR5LiZU2X
         PioLe/59cnxVaUfJilq2z9x4p8jzMwnFB0kvCGhrErcIh8poq8Ny+MXIwi6PGj5nEvCK
         7Rsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UfV7KZLI;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id n78si1159701qkn.1.2021.08.25.03.14.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Aug 2021 03:14:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id o16-20020a9d2210000000b0051b1e56c98fso39335049ota.8
        for <kasan-dev@googlegroups.com>; Wed, 25 Aug 2021 03:14:52 -0700 (PDT)
X-Received: by 2002:aca:4589:: with SMTP id s131mr6177609oia.121.1629886491492;
 Wed, 25 Aug 2021 03:14:51 -0700 (PDT)
MIME-Version: 1.0
References: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
In-Reply-To: <20210825092116.149975-1-wangkefeng.wang@huawei.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 25 Aug 2021 12:14:40 +0200
Message-ID: <CANpmjNMnU5P9xsDhgeBKQR7Tg-3cHPkMNx7906yYwEAj85sNWg@mail.gmail.com>
Subject: Re: [PATCH 0/4] ARM: Support KFENCE feature
To: Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Russell King <linux@armlinux.org.uk>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UfV7KZLI;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Wed, 25 Aug 2021 at 11:17, Kefeng Wang <wangkefeng.wang@huawei.com> wrote:
> The patch 1~3 is to support KFENCE feature on ARM.
>
> NOTE:
> The context of patch2/3 changes in arch/arm/mm/fault.c is based on link[1],
> which make some refactor and cleanup about page fault.
>
> kfence_test is not useful when kfence is not enabled, skip kfence test
> when kfence not enabled in patch4.
>
> I tested the kfence_test on ARM QEMU with or without ARM_LPAE and all passed.

Thank you for enabling KFENCE on ARM -- I'll leave arch-code review to
an ARM maintainer.

However, as said on the patch, please drop the change to the
kfence_test and associated changes. This is working as intended; while
you claim that it takes a long time to run when disabled, when running
manually you just should not run it when disabled. There are CI
systems that rely on the KUnit test output and the fact that the
various test cases say "not ok" etc. Changing that would mean such CI
systems would no longer fail if KFENCE was accidentally disabled (once
KFENCE is enabled on various CI, which we'd like to do at some point).
There are ways to fail the test faster, but they all complicate the
test for no good reason. (And the addition of a new exported function
that is essentially useless.)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMnU5P9xsDhgeBKQR7Tg-3cHPkMNx7906yYwEAj85sNWg%40mail.gmail.com.
