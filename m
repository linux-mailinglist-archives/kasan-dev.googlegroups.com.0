Return-Path: <kasan-dev+bncBD2OFJ5QSEDRBSOOSSKAMGQEAL57FWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id D795C52BFDF
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 19:05:13 +0200 (CEST)
Received: by mail-lj1-x23c.google.com with SMTP id e22-20020a2e9e16000000b00253cd8911easf428783ljk.13
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 10:05:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652893513; cv=pass;
        d=google.com; s=arc-20160816;
        b=oy6+6uLtY2FNKjq+6qF9nMXf+jw4EV3UHG10T9oi0bAJAmz2dpXKMtXAR8rr9GgOiy
         reyOEQLJf7Xmb6OYfQNXCEL+MxU9DAGw8YGxciSMsml9ZWJi7w/0GPsVGkarf5+ZQJeO
         W2YSQBheTv7Fnu2hSH1WChHLf3+KCnjmP4XTN3Kd1ykjll/GUpga98Gg2HgTUq3d74Yr
         WHfAEnpgu8Ytnl2rOis5PR8ueZH5NLIon6wzE0xuWxzIcO0dB782yuZnsunRSXBEV1eD
         SYF2/GRslvKmDmLeAl/fyOhrShdfLGOzjCR8rSivwypM7xhG0s73MhdNL7NsIHljY+3X
         P2ow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KfWRVSuT95tnRqZTgWaG4u7dCw//ESsE9dhHhWtA1so=;
        b=00F8wBL3xyYV5t2aLAkW0X5ldOJo+8Rq6kMckuvt5vhZgSc/grC7HDoMhLZrMBWfNa
         KOrppOpT/QmwlMyEuOy54w1gN/3+0hCv3YQMrvnfjYNiT8aQpdfm/nasKh7j9ij6ydYn
         KMG9uAcChYMohBtZCSrmbDNYwRe8+c/2khqT+qLwK6ebHnj47X3lnAG/csdeE7/I3l6U
         jJnWT8WbiqSiUfTWLNZvTX20HfHhbGGW7ZiR9LmT/iQaub9To6QvmYZZV+Jpvss9Fa10
         PSDkPjEHqfbxcl6nJCO4woiDhM83Tj5R7jJWkRgg/h9+oF+8IWEdJFGbn+50La9u1da8
         u+8g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NOHuR58P;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KfWRVSuT95tnRqZTgWaG4u7dCw//ESsE9dhHhWtA1so=;
        b=jMtXtCc6LdfX6Vxyp81Ht1tQDO4yhvpGcNLWwETvBGg5VleIgL5N5mkn+KIhVmMvUi
         QqqZ7AbDz25+RDcOPK96Q4P6dLKW9jyKqxEtgc3zCkqfUnNUY98ahqkC7maHgdyIfRKt
         +0iBFrB3++t6rX7Lzu5zXnRO5utDPLy5RHEm8fp125RdIcXFyM+CBm01//HetFumCAXv
         ddxSuRQEcPg/5gqr//MHeXrZRZBAlEn33e9d2qnJJMhdsEQDhzIfbBgJeGeqvuFlVI0J
         I8iFgZBYZ36ENULXnZDMcU3375q0UmVKPdw2GH980tGuSszHIAIWNhvI+NMgasUa0ofo
         ymbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KfWRVSuT95tnRqZTgWaG4u7dCw//ESsE9dhHhWtA1so=;
        b=GnEeE+SGqiB6bcVX3EZYwvjKPk7caPxkddpfSjh1QDn7V3F2+l4v0shiJNIJhh3NUl
         K2OkKQkeBeBtmtG8Dq7mI1srYcgr8udUmsVVqpeza2CZm79+tNw5DWz16IiBoqAAvtSo
         OapeROpv+uMlMwShKGqIOGGXviscAXq3DyjYM0qJ5+/pQ8PStJOBC+1ePT4Gl2XnnYGT
         wUhre/jn0FPe0F3rY1+XsoUK2T3flWNRcWMRoPL/DM2m9HxhR/cAkpNVONikCEpm8R5W
         nW1pAH1+Ecx0OzV9g4rH8nARoaOjPcWUA5sJVEA6hcb80lGr8xCBNVOJdz3riJPy/cc8
         wVfw==
X-Gm-Message-State: AOAM531UUQjJtO6pvjBJuI4sMZweNGRiZtO3+TQh9uh/IMPoTj3kX6DZ
	T4ERjLZx9/HhmNPEES36f4Y=
X-Google-Smtp-Source: ABdhPJw6ZWpkKMSoXdp5HhbdK1N/S7gDyFVmK5swjes2sS0alcWZ62tx081fsGC8/e5/hnIk7GYm2w==
X-Received: by 2002:a2e:b0ef:0:b0:24f:ddc:cfd1 with SMTP id h15-20020a2eb0ef000000b0024f0ddccfd1mr173473ljl.519.1652893513319;
        Wed, 18 May 2022 10:05:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls310568lfu.0.gmail; Wed, 18 May 2022
 10:05:12 -0700 (PDT)
X-Received: by 2002:a05:6512:150a:b0:474:bb9:5174 with SMTP id bq10-20020a056512150a00b004740bb95174mr291896lfb.207.1652893512154;
        Wed, 18 May 2022 10:05:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652893512; cv=none;
        d=google.com; s=arc-20160816;
        b=YciR5gxdvMSiaSsML4Du66cQmd3AVE4UDwFmpDw4sgHLIQd8H2NL6N7r0pQ6qkba5n
         5gohKtVkfJuwtaHlxYqOP9NBO68i4mCAm42mwZ73om6PmxGhC9HkV4nbflzGVMpi2Fjn
         Lp3sc5qvvDZRumoyM0Xmjo/ZvFQcm8A716EbQXaBb6Dtu6T+cc3cws2VL8bY7enyHvQz
         vA4Ft+4XFaEKlbLou2pPNzDQ5a4qDchDikd9XkUuvZwFjNpS1fpMoy9ut5uIi7gvC2BH
         AqCRxhik7pTM1aMts9wUV+N9RLPEs0ncF1pDuC9DBHBtajYvE+8aIULbUK2m0PX0aVzN
         FS/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yGAntEp7VsrLOr9oJK5iuS5kORmPqq6P0c1ahFe/D8o=;
        b=s64SUxAANSeT1QGl/uriLkr9I14v4RZtp2Q4fW+f0EaUsx+qtx+Iy6XHbQQTPLFRKv
         wqa2ofDO/VhLTWGdpmo/9sQpmduFyKn2abVNDxRCMeCXhX1eK4mAu7C5q1xWAD8J/dIb
         WDeTNdBPsLCX7+fKSXSS/xOgTQA91wzQGBZoFS5OM5rpukADnzU6H2gt4Zr3J8TbVQKy
         kE9qdGJVsjwx009G/rysdu8GeaaG4rU1vOMn6hMBa9n30tYhFgB65FwWttzpwqZDj7f1
         Klj5bjCs8jVH2Vpgw+nFZ8aU8RWtAVwK5VSTaKzLRYD4XxRmf94BI4969EuaqsTHKXwW
         HoUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=NOHuR58P;
       spf=pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=dlatypov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id f23-20020a05651c161700b00250a0b5e050si118928ljq.4.2022.05.18.10.05.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 10:05:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id h11so2673635eda.8
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 10:05:12 -0700 (PDT)
X-Received: by 2002:a05:6402:3787:b0:42a:ea83:ad25 with SMTP id
 et7-20020a056402378700b0042aea83ad25mr754096edb.233.1652893511663; Wed, 18
 May 2022 10:05:11 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA@mail.gmail.com>
 <CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA@mail.gmail.com> <CAGS_qxr4vTSEtcGGFyoZibga2Q_Avp9pFD78GOA3W9o6F9RVRQ@mail.gmail.com>
In-Reply-To: <CAGS_qxr4vTSEtcGGFyoZibga2Q_Avp9pFD78GOA3W9o6F9RVRQ@mail.gmail.com>
From: "'Daniel Latypov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 May 2022 10:05:00 -0700
Message-ID: <CAGS_qxqb+pKeKBVxzFFTss5QLSWo6nVAajwQTMB2fWbMnMHvgg@mail.gmail.com>
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
To: Marco Elver <elver@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dlatypov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=NOHuR58P;       spf=pass
 (google.com: domain of dlatypov@google.com designates 2a00:1450:4864:20::531
 as permitted sender) smtp.mailfrom=dlatypov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Daniel Latypov <dlatypov@google.com>
Reply-To: Daniel Latypov <dlatypov@google.com>
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

On Wed, May 18, 2022 at 8:39 AM Daniel Latypov <dlatypov@google.com> wrote:
> > Either way works. But I wouldn't mind a sane default though, where
> > that default can be overridden with custom number of CPUs.
> >
>
> Ack.
> Let me clean up what I have for --qemu_args and send it out for discussion.

Sent out as https://lore.kernel.org/linux-kselftest/20220518170124.2849497-1-dlatypov@google.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAGS_qxqb%2BpKeKBVxzFFTss5QLSWo6nVAajwQTMB2fWbMnMHvgg%40mail.gmail.com.
