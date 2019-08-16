Return-Path: <kasan-dev+bncBDZYPUPHYEJBBKGJ3TVAKGQEWJQ474I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3a.google.com (mail-vs1-xe3a.google.com [IPv6:2607:f8b0:4864:20::e3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 87DAD90A72
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 23:48:25 +0200 (CEST)
Received: by mail-vs1-xe3a.google.com with SMTP id d15sf1944758vsq.5
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 14:48:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565992104; cv=pass;
        d=google.com; s=arc-20160816;
        b=vT6fnapVAFNo2miCDYkWQwBgo/bfPvgKCw1XCsEYtwe8klsAjpYC/Iy2rFj7AT6glp
         y8YJBhJXIdTUAXyHSOEt27cEHgWVaXu8ANkjTCSAH3jITNl/mjlcpbwQ/GaFy1Nabr83
         KnCMNymEgbuQcUeK/YqoqXgYWoyda0XE9oeW/hNo1XyUR2mT/YbKhKuX5pdL2rtBV+Sr
         sYZk2bXiIJ4f1emDT7Ya6GMBhldnuQZfMctTQftXSkvqDj0MtNpgGGyPwkuRCGL0EqL1
         Sf68/z6jfYGN+guoVKpFnssj1oVuNCN1yp3T145CF4XSjaN0f/NOU0mS7Qjl/FwUdanm
         +jdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=h9fCVwaTZilKPzCkW5mwDPF5DECCGocMkiWLX/J53os=;
        b=epbaR8bgpgpzKRpM7XTiIwwyt1Mw8dTYqSASMT3DDU7NtlP6+eII2B7u5EW6nBm95q
         iaMybTdTE7ppIyV1o0cWW/5lTAP2F+SDct+yqhQMM90IfBS7E7cAyZHxsQv5p/Cy93Cq
         D7Us1Oguma1HBz2Yi/+dzGCcGvOkPiXuSkQ8q4s1rphh7J7zWpu4yeyrvVjcR5wv6vJc
         +MIKvmL/8wx2uMPigcenwfOTLtUgzyrFeSENn6klMqensDyRmHTYoVZpJRlMakf+eIMd
         grGBbkeztqcbVjyV0dpVICg1mXAJo+KbBaMHXtsT0kAAnURMntrjIVsWLFqTWgsm91ge
         tjyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel-com.20150623.gappssmtp.com header.s=20150623 header.b=mrS+amgv;
       spf=pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h9fCVwaTZilKPzCkW5mwDPF5DECCGocMkiWLX/J53os=;
        b=bLknZq09sEmYiZbhfPHjMForlNX/i0lBpzNT4BNYuehkweuBWXzOTMLn6OUCfZoUqN
         SINBYMZ+HJnVn/uf3NVGbj7GOYuMxX/aX15ejXcUWBljI8aajCChwfNwhxicAbXHQcYV
         T+n+uCeloJBBFBlJ5T8RiIoedkBiOfsPNyjdWGh+5+RgIDYiKcYbvwkILpMPSPHwHZAt
         cW0l2PZlHrnOwH4isv9ASB5RILuQPzKg2hW01iJg/i5L2eDStxUGlc76E67GKZ/DC0oK
         SZSdbwTsoBSh/lcDHWmju6CfkCFVXn8daQ+i71lsZmyZER4UpQkt0yT9w+GQppwqvl9H
         2AFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h9fCVwaTZilKPzCkW5mwDPF5DECCGocMkiWLX/J53os=;
        b=bP+FRFWH0vn0Hn6GikFW+LR8AddYSUmRwyrSbaJ5cU3cGmvQIynuzT2sP/cOhNDEvL
         2mDc2H3qL3zdOG0jp6yAM5By+HiN8LsMc/mvYzkH9rWUoYtZDK+B77W6fOChGQ7UldJ7
         ZLKR8RfCk8aALig4xRqeksW8liSINKX2JXzvgm5k9IYDDvBuXNtu4IXv7zr7ebcGW63q
         kcxbKRGrK/pUkJvowMwUgphCWKe5gXEvr0sz69GvM19RYg12dsSM1/J9NCMt3DEkEMPN
         /P/t9MxgnvUeILEFLgMd2GoT6otUSSJDV0/siDfY4yKyauOr5xsN+jnyn1/d7Y9rUuc+
         3WEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXbrIMRMDEfL1Gwl6c+NhsiWAukl/Xp4ovC14DNDHJlOsYv6X2n
	r+JnBNZyZ/AjReyoZLzseaQ=
X-Google-Smtp-Source: APXvYqxPesqClmr2DuXDeea3Hf0U7IvMw0hxwExoKM9PrC3/d9zVhpMwtId+WDC4oyYQG3dIIz0hrg==
X-Received: by 2002:a67:79d4:: with SMTP id u203mr7430377vsc.85.1565992104591;
        Fri, 16 Aug 2019 14:48:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:6913:: with SMTP id e19ls1181834vsc.16.gmail; Fri, 16
 Aug 2019 14:48:24 -0700 (PDT)
X-Received: by 2002:a67:ff93:: with SMTP id v19mr7515163vsq.109.1565992104283;
        Fri, 16 Aug 2019 14:48:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565992104; cv=none;
        d=google.com; s=arc-20160816;
        b=evPFdjtYblYPr8GIPfNKW3ryxc7M1VY1EXr4Rt53fshxS3ESadf06tAjtBFtTm6//A
         j2RLnDewce5utXf7iqrjro0o11rikCyOaYi3nOmOTDaABN4VFwhEx5w65XVv5WRIozjO
         EZ/UItJNWvDgP5vPAi2mz6MD13GcQkqgrLxHUAoO8qMZ/kfheQ0H5SaNnwh8bpCVMadn
         sBR1/HibXKGYDXmFAiob5bPRusQempFOQ4g/AtoSI8SvRfWbY491XJMIkeqBbISK0uR+
         0rY3u7fC0mWgH1IMrE3y5n49M/f/Ubxamhb/z52wfGxEmZV/KDU5Sy7v7s87rEoOILJJ
         G3lQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LyElFB/DQKr6Gizru8u06ztJ06NwMdbnhXlNaM4nxfY=;
        b=FkCOcFQ/bT6mlPGGOb8VeaeY4T8rf3PcngWnhM9JOZPHugD5fU2R2PZ69Xf4g6vDqh
         55T08C1jS0IKjwKxK7SkpHT5lCp+TYnoIVydBRiERVobPzzNkfTDmq7xkxLCchSoWWIO
         hQkdTPlAz4TBRVb4SGX6/z5kdbr7WnV3VJqBlOkWx8yswPfOU4NfLvLrw8y/PMtidAeQ
         Ld+y90fEbxcxSb0HkVS6U2D09b6BjFPKQlf8vO5f4UXnGCU/b44w56smIs5XZiKXt4Lf
         ET8W3gkTh/t3pmTCV9nYKNncI5dUGO9WFfOBEJ+RLJGWx+UmxQEGcPSK9xfURZzgWAOo
         hv7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel-com.20150623.gappssmtp.com header.s=20150623 header.b=mrS+amgv;
       spf=pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mail-ot1-x331.google.com (mail-ot1-x331.google.com. [2607:f8b0:4864:20::331])
        by gmr-mx.google.com with ESMTPS id z67si506219vsb.1.2019.08.16.14.48.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Aug 2019 14:48:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::331 as permitted sender) client-ip=2607:f8b0:4864:20::331;
Received: by mail-ot1-x331.google.com with SMTP id c34so10925126otb.7
        for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2019 14:48:24 -0700 (PDT)
X-Received: by 2002:a05:6830:1e05:: with SMTP id s5mr8439514otr.247.1565992103975;
 Fri, 16 Aug 2019 14:48:23 -0700 (PDT)
MIME-Version: 1.0
References: <1565991345.8572.28.camel@lca.pw>
In-Reply-To: <1565991345.8572.28.camel@lca.pw>
From: Dan Williams <dan.j.williams@intel.com>
Date: Fri, 16 Aug 2019 14:48:11 -0700
Message-ID: <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
To: Qian Cai <cai@lca.pw>
Cc: Linux MM <linux-mm@kvack.org>, linux-nvdimm <linux-nvdimm@lists.01.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dan.j.williams@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel-com.20150623.gappssmtp.com header.s=20150623
 header.b=mrS+amgv;       spf=pass (google.com: domain of dan.j.williams@intel.com
 designates 2607:f8b0:4864:20::331 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Aug 16, 2019 at 2:36 PM Qian Cai <cai@lca.pw> wrote:
>
> Every so often recently, booting Intel CPU server on linux-next triggers this
> warning. Trying to figure out if  the commit 7cc7867fb061
> ("mm/devm_memremap_pages: enable sub-section remap") is the culprit here.
>
> # ./scripts/faddr2line vmlinux devm_memremap_pages+0x894/0xc70
> devm_memremap_pages+0x894/0xc70:
> devm_memremap_pages at mm/memremap.c:307

Previously the forced section alignment in devm_memremap_pages() would
cause the implementation to never violate the KASAN_SHADOW_SCALE_SIZE
(12K on x86) constraint.

Can you provide a dump of /proc/iomem? I'm curious what resource is
triggering such a small alignment granularity.

Is it truly only linux-next or does latest mainline have this issue as well?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA%40mail.gmail.com.
