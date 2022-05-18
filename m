Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4NESSKAMGQEVEQ26MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1139.google.com (mail-yw1-x1139.google.com [IPv6:2607:f8b0:4864:20::1139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CB5252BEC5
	for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 17:36:19 +0200 (CEST)
Received: by mail-yw1-x1139.google.com with SMTP id 00721157ae682-2fedd52e3c7sf22361767b3.15
        for <lists+kasan-dev@lfdr.de>; Wed, 18 May 2022 08:36:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652888177; cv=pass;
        d=google.com; s=arc-20160816;
        b=LOnh4LDo/jxnnkO5heae7RK8Ju+eMKBFNMbPX3AgiCzdMX7vhnzu9mgK6vUFGAWSqt
         h6cGjPN/lRk3VOMvcSlhDRHdRq/0Hkbl/fcU2e8reck5ijzbLdIGvMiZv4hRoCWd4LXv
         WmLX5T32VO0IqvRJuCbRpRDwDyuufyO2Cr5A7AQEHm4APu0WyAHQ0vaV1/VX1QvYM/Xn
         gqHWQ2k8kjGWwyHuD5lFb3ePbv/xJVwCaDtFAh+yxIOjCVtRL8I9rOXgwVwuHpv1XFey
         gRUCkWk3G2PWJe13PoCMnFnaeo2g2hJXmjEIRyrIKBUPliXUMpLhtkP+JmryO2kverwP
         VRcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=1Pk0xb8ttXSd/YTmS2YuGxBQd+2Y/cuS16CAffFjAf8=;
        b=MrOZivTCeaOvtp3ytkATSJi87ZfHMVlRcUsRyNrYWk9ToGuMrUUwbI21L2ECIDMaqT
         g7F+m+u/iPrAOBX4db1t4DM+Vp6pKusDRehUjUeBlbwO0npOjGQLjhnL86zqhU1Z6RGD
         Zu3HU2vpcJKOJwAS4cf+GauoA+9lmsgCiNeSwFV4KOHweSJTKkAimeeTfRvsO+slJJsc
         af505eJKOcRtAvJKJzfleDEqVmy/A7HYODJgrPKKpqkWernRtnf2rPnLxvmZFgksNtI0
         iaTFf6KlbjjItZenJzN9yTH/xPi5h/xlFi1DnwdRnrGk+8hMKGC+PM9ExeMO9rC92zUX
         IU9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Dl7ZXvqH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Pk0xb8ttXSd/YTmS2YuGxBQd+2Y/cuS16CAffFjAf8=;
        b=iIBH9tN57ipEjfMuK9b1mLXl62FfmE/Rt5oMxF7Ue23M9bnqRbb4dD8zTgUmotZZ5+
         n5Syp0X4EFxNZk/61Fwo/L65KBPEV4ScFxVa39WJGW2442UuosQ8piu4LttsFcz1+ppZ
         cIAih/K+J4OJPmpCPa312PSJ1/QIRXx3db1hwbE0XmbxEgNC4esz9uib8EUhLdno+yJz
         qElSCOYoF544548jrX1jMadyp4j+6acc8YpZSXB3Mpj9ewAfMeoPP7lnFLrxg4r5rOS9
         fPjv8WjzFyFI1klkjsTGkO4l7rJwcdFXrs9+cxotidaQ5dmpqZg+anZEyoLgvBgFBYRV
         PUhQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Pk0xb8ttXSd/YTmS2YuGxBQd+2Y/cuS16CAffFjAf8=;
        b=xBfzDPUjxxnuPEyUBk1eqGLftvMuMumsChy+dut0HQ3aPa+pkzjRtH8JMLc7k6tZya
         H5QMuDfpyg1eEC/fppEMQvm4atyyG3GLMAJqty55ZALWp53unGCszm2d4E17nxXbIIb1
         muHSJ27DaOmysUYroNER1Rqo+9JQSCL0Suwc4VHvzbueGF+Fmwev4YkliBM3MFZO79V3
         u/rej1iLdVi3yOzqMpEQ/XV6K53oxGtvhLQ4kyLjtK3UBnSwmAWkjMUQ314rH5K3WDK1
         4dtINFMHMlatgbStvGeP4/nDh91zYvSorO0pMwtZ4Pz/6BZ3OOTezhZ7ERePmGGXvcaO
         jpEg==
X-Gm-Message-State: AOAM531G71JVLckCWQX9TPi+3lFdh8F0LO1OEaphOeGGsouGgrf4S1oG
	WTSXbsXB6LhvyUV98BcuRGg=
X-Google-Smtp-Source: ABdhPJxcVyqW5xtUOMeCrsMSlGHNo7yCHm3leQ54bPkJZD1dWOtyvh8PTWGrQkXEGO2iqoF5iFFDLw==
X-Received: by 2002:a25:5f12:0:b0:64d:bff8:2af9 with SMTP id t18-20020a255f12000000b0064dbff82af9mr187081ybb.91.1652888177710;
        Wed, 18 May 2022 08:36:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1502:b0:64b:6f39:ede with SMTP id
 q2-20020a056902150200b0064b6f390edels111363ybu.7.gmail; Wed, 18 May 2022
 08:36:17 -0700 (PDT)
X-Received: by 2002:a25:cc4c:0:b0:64c:b766:5a0b with SMTP id l73-20020a25cc4c000000b0064cb7665a0bmr158828ybf.495.1652888177138;
        Wed, 18 May 2022 08:36:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652888177; cv=none;
        d=google.com; s=arc-20160816;
        b=wVUKSnWj5yeKI5Kj441n3G9eu5pz5Nc6s01uD1K3VUWxqLzzdXrTV3b3JkpKVSCYPD
         i/7Pkxy7npuKayJYATZDuNNe80q6pWebE7Pg2HNz2mRKZABJ6ZlfpvISAVxly543hJtI
         w158D22IcpzvwfusF2imD1eivf6TFTfqUl8c6Nw7i3JDQOlNi3slFcRTd8F3YIoHM/ab
         O3rofMBMocr+A7CtWaezawhkVYEPwb+od8xc7rSTmX7WXF623cT7Bb7FDOW3ROD4OXzn
         aEx4MBzoBItya78ZMz2tkBzHBtlkeUJnvL4AX63jlOKJhfwpTQ9PwKJRqPTpb7VKZuS0
         iEIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kF21wFqfnoIq6E9PfI/et5u3jsgWYenFv/GCYPgvGFo=;
        b=Y+DRIhDmGXc/wHSp4MRP31m9YjhqSQduCvulqc7fkpqGG9mRxCXlTLx7GSa3zdp+T5
         vnDmHuC0eLg+JE0fg0BsqyyZvVuhO+PjamJ0v9B69Kl7n8gvLkQgTjNaDY/O1r+wmhKE
         iwbaqC5nRYQcvOCIr3z8NxW4AOqtdPLKDX8O1uk44lzmoBxHMZgCvooO3tvr4UWiUxj7
         F2J4jAVkhORF0tlWUuZV2OzxqENZlyU1j+BgXm7I5symzMfR9jLD/L0/p9xxzMleEIcz
         Fly5sCJsol4VUhIOmvt8PDmJpJbvtUGgwK6rdecyA1i7jSb1pAZtP3sGZp+2NEDjgkCW
         14wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Dl7ZXvqH;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id bh28-20020a05690c039c00b002f8fd405eb6si129452ywb.1.2022.05.18.08.36.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 May 2022 08:36:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id i11so4297026ybq.9
        for <kasan-dev@googlegroups.com>; Wed, 18 May 2022 08:36:17 -0700 (PDT)
X-Received: by 2002:a25:2d4b:0:b0:64d:a722:b4ae with SMTP id
 s11-20020a252d4b000000b0064da722b4aemr180011ybe.87.1652888176675; Wed, 18 May
 2022 08:36:16 -0700 (PDT)
MIME-Version: 1.0
References: <20220518073232.526443-1-davidgow@google.com> <CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA@mail.gmail.com>
In-Reply-To: <CAGS_qxrOUYC5iycS436Rb-gEoEnYDa2OJLkQhEVXcDN0BEJ4YA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 May 2022 17:35:40 +0200
Message-ID: <CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kunit: tool: Add x86_64-smp architecture for SMP testing
To: Daniel Latypov <dlatypov@google.com>
Cc: David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>, 
	Shuah Khan <skhan@linuxfoundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Dl7ZXvqH;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b35 as
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

On Wed, 18 May 2022 at 17:31, Daniel Latypov <dlatypov@google.com> wrote:
>
> On Wed, May 18, 2022 at 12:32 AM 'David Gow' via KUnit Development
> <kunit-dev@googlegroups.com> wrote:
> >
> > Add a new QEMU config for kunit_tool, x86_64-smp, which provides an
> > 8-cpu SMP setup. No other kunit_tool configurations provide an SMP
> > setup, so this is the best bet for testing things like KCSAN, which
> > require a multicore/multi-cpu system.
> >
> > The choice of 8 CPUs is pretty arbitrary: it's enough to get tests like
> > KCSAN to run with a nontrivial number of worker threads, while still
> > working relatively quickly on older machines.
> >
>
> Since it's arbitrary, I somewhat prefer the idea of leaving up
> entirely to the caller
> i.e.
> $ kunit.py run --kconfig_add=CONFIG_SMP=y --qemu_args '-smp 8'
>
> We could add CONFIG_SMP=y to the default qemu_configs/*.py and do
> $ kunit.py run --qemu_args '-smp 8'
> but I'd prefer the first, even if it is more verbose.
>
> Marco, does this seem reasonable from your perspective?

Either way works. But I wouldn't mind a sane default though, where
that default can be overridden with custom number of CPUs.

> I think that a new --qemu_args would be generically useful for adhoc
> use and light enough that people won't need to add qemu_configs much.
> E.g. I can see people wanting multiple NUMA nodes, a specific -cpu, and so on.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPSm8eZX7nAJyMts-4XdYB2ChXK17HApUpoHN-SOo7fRA%40mail.gmail.com.
