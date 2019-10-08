Return-Path: <kasan-dev+bncBCMIZB7QWENRB6HZ6HWAKGQEW4OQBWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4135FCF95E
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 14:11:38 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id x13sf32255728ioa.18
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Oct 2019 05:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570536697; cv=pass;
        d=google.com; s=arc-20160816;
        b=RVf5FDIK+jK9JywQBhj2JhRMJygxFhbLL6U9XYpkrEmrFjB7rbcyo/VSXGl1Qe5Z+1
         B9XWFJ70xCahSSE5doh2jEzxAfLDdT8YNYuCioDiBx6CTc5v0wmkQB53jYvmJEaL1K0W
         U2JUtqSe5DgZWBCKL6QEBP0GzucbaEi6BGjZv2UIAT4nt/flKIc52GpqcsWzFFzUT9Ra
         kRQInmfgQEs006UBZohjq7LLaCstCkVTxsmMhFMgs5ZsCInbfFst7UpGlKu+khnGKN5M
         bZr+3wrPiEqEsJo0MOC+7wJyLu5dsIv4CtsFXbTKHva/A5cVOAG5uq3rI0i0oohLgfq2
         B17g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dUIhxGf8CiyzUbK/wK5UYhX4DmUXHAC5trYdBgosBJg=;
        b=pDSh4KalMNPlArglx8aEShnoPKS49qBdigfxmpGI7i77Zyegjvgd61X5GUHac+k1oJ
         9JkECwSoSw8uodIAvnpXd3oeq9lb71/CjuMYgywDTQen/mPuzlsOL+1HZIB1Ihp8JaF3
         5Ecc7ESpd+XiAz2e9Tm6BN1OuvRKDa8035XMoWcgRz4efB0TqYDQCGfIWsXM1OFjojEc
         7grTtquPO90jumzbeIrQ8by38elr7iwxGhFvXPncXl9DYCf6RlxHv1WbyLwkzKzslVSJ
         sEw1sknvABezZRtG08Rmwr4I6teExiaJYIFS0pvqF0tF5D/WBMs7N4Ng0WJpYoB6FfDL
         5irw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eh8pCLow;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dUIhxGf8CiyzUbK/wK5UYhX4DmUXHAC5trYdBgosBJg=;
        b=gfU5WycSgRw4ZczfMStXbW3bphyDOz2+KL5Rom7sxKk96v52lBnbHgSQNXGqPvmkw5
         TBEa/BRWRWRDNGZgxOI2jtgRaX98F4IUG9Ap0siFE1/j3wSgBwdN2+28sIH6938QSfVU
         q0ek01lOhJLHm9MZKhBz1pCNMX1rUlJAKOX+f5JwdAsqOqwiaO0hAVFLxyFg6ap+QU8N
         Ywq6OMnH0pyhTxChGIAX4zYnJ5FyE1lYjw3OJGKq61iN+s7rUdoL+1UGYTEwKU9zn6tI
         tkId0D/e0WgQkpVufx27dmx9t7L168hcfYcDFtGBWBP9BDxPutm2LB2arPW/x//6GvHJ
         2Cmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dUIhxGf8CiyzUbK/wK5UYhX4DmUXHAC5trYdBgosBJg=;
        b=d9h3gVHfeWacG2/DbEfOs6Z6rvQu0pr2wQFWGqougpnkwWaXZHQqvv69djh1RkyqoN
         DnWcO9DQdwMscoZympJecmyRJ/6AxDWIllZmAqdMJKW7FhK2ZX7/17pWZRP0N9hRNV+6
         +FSyqcsfD/Ka+Mto4aLVk2Xsth8aK/mIN+TnXR0t6Cnox3rySD/AFJzZk/fr72uIII2O
         /0bCQG/TXF5IgfMurOYZWw01czGIxf0qID3+Hg3yIXy3mCWjbRFua0ejJQf2RLYlgyIY
         9wx2lltJj5eMmTp89qDkmDaC0E4FosE3Ac8GdRW4YO2DLW2HWmNiRfOhYx8q/4+gTzX9
         DI+w==
X-Gm-Message-State: APjAAAVAorydGwT5UFIAwKTwHr2CWQPYZrviNaWf43Tfw0NtuQV+HWe4
	Nxz8vexGJB/58MzE554Zyac=
X-Google-Smtp-Source: APXvYqzJ46dY2JV+SKvY6AheUFEgDqLfEpucnOeGZR/vawaixri/034iQYtkBKMSyxDm/ugr0+lCNw==
X-Received: by 2002:a6b:1882:: with SMTP id 124mr28094416ioy.116.1570536697011;
        Tue, 08 Oct 2019 05:11:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:348:: with SMTP id x8ls302692jap.9.gmail; Tue, 08
 Oct 2019 05:11:36 -0700 (PDT)
X-Received: by 2002:a02:a598:: with SMTP id b24mr32213572jam.53.1570536696223;
        Tue, 08 Oct 2019 05:11:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570536696; cv=none;
        d=google.com; s=arc-20160816;
        b=ExB1KP41ArmQth6O/WSnVLsjuyZB2U1+rqhk5WCi+FKq30Lmw+q2Vf3wbfohNydQQA
         29TtPiwyU2wupHta6uiCKtYFAPiZya/Ymk29miDOx28FTZ4nG0xD1jzikaui4FBJlKVU
         8sSLgjuHTf4KXPnYYEzPzJg33kDLhqMvGfoybFbCG8h3reiq8R0LX5MAKaslVzzrk7bt
         as486buLYJgOoO8Kqfg+Lb+yhjvEa44hKdUAiQG30OW5z7HlU5ElKQDdBA4PFRxU2lZK
         BFrlqCRYE5IFlHZbt7maOfu4XL1cvjXymyG8zpG9G6Mv+cdoFheBLp8q7K6P4py9B6rD
         3NIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GMN6AE/Wckiy15zsiQVxc8Ha0nqrOTJmAoLEeM+N80A=;
        b=mTZ1X3MBUnyl2/hIP4vl3S7B4UO5wYPJUE1REcHJJgFhOFj/MpmuVoJXCPECcDJzZV
         1X7l619HFPbqtf5x2MwpUBuPP3TX1/OQK5iapUwfNtZHCbKAd+HXicpej7rQY/svg2U9
         697VgoBZHsEpf6bUDuoCpmh5oWUy0BHJcapfLzsWKSY7ruOrFr3h+/m4DlV7x+v4uPhb
         HVszIWALFUr6y3CfV3BqdkGIg+ZAmcoMvnvkAxcebxGduVzueXG0l4W3rDljc5Zw97NU
         NOIBix3HF3OkjBsK3pm+vBLT6RU7ei56xccoJsJGnigPmhWgP8Tn3hSwcpIQZY67MV6b
         H1sg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=eh8pCLow;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id i8si984581ilq.4.2019.10.08.05.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Oct 2019 05:11:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id w2so16454580qkf.2
        for <kasan-dev@googlegroups.com>; Tue, 08 Oct 2019 05:11:36 -0700 (PDT)
X-Received: by 2002:a37:d84:: with SMTP id 126mr26540903qkn.407.1570536695225;
 Tue, 08 Oct 2019 05:11:35 -0700 (PDT)
MIME-Version: 1.0
References: <1570532528.4686.102.camel@mtksdccf07> <D2B6D82F-AE5F-4A45-AC0C-BE5DA601FDC3@lca.pw>
In-Reply-To: <D2B6D82F-AE5F-4A45-AC0C-BE5DA601FDC3@lca.pw>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Oct 2019 14:11:23 +0200
Message-ID: <CACT4Y+Zbx-2yR-mN5GioaKUgGH1TpTE2D-OgLbR2Dy09ezyGGQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: fix the missing underflow in memmove and memcpy
 with CONFIG_KASAN_GENERIC=y
To: Qian Cai <cai@lca.pw>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-mediatek@lists.infradead.org, wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=eh8pCLow;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Oct 8, 2019 at 1:42 PM Qian Cai <cai@lca.pw> wrote:
> > On Oct 8, 2019, at 7:02 AM, Walter Wu <walter-zh.wu@mediatek.com> wrote:
> > I don't know very well in UBSAN, but I try to build ubsan kernel and
> > test a negative number in memset and kmalloc_memmove_invalid_size(), it
> > look like no check.
>
> It sounds like more important to figure out why the UBSAN is not working in this case rather than duplicating functionality elsewhere.

Detecting out-of-bounds accesses is the direct KASAN responsibility.
Even more direct than for KUBSAN. We are not even adding
functionality, it's just a plain bug in KASAN code, it tricks itself
into thinking that access size is 0.
Maybe it's already detected by KUBSAN too?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZbx-2yR-mN5GioaKUgGH1TpTE2D-OgLbR2Dy09ezyGGQ%40mail.gmail.com.
