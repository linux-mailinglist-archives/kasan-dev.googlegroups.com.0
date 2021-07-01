Return-Path: <kasan-dev+bncBCRKNY4WZECBB7666SDAMGQEIWTEMAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E1F53B8C74
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Jul 2021 04:59:12 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id d11-20020a0cf6cb0000b029028486d617fasf2835049qvo.19
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jun 2021 19:59:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625108351; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wr9yBSSpzsivt4Qe175s5bgXgkelGbnxrpfJpBJMpQ3kjCImU8gDPvvs5+P+4iSHFI
         HmA1mdEuxrD1VHXLtPx7m9fj3iJkqPmGQqpfFoAJufJzCItjCazYJFAqsdkK/RS8cgaM
         huJ/aDV+tBvdI43Hb3Pzete+7GWTUxIbqewGrJbVXyqZMW1tKGzXpgn3nEDI9q73nHNs
         /XAytkjRoKj5hz83AtIOOrnR4O/nLZC5QSbfkVFvkvLeUbKeQLhs5So9eKIkTveJVxTM
         BtJL0VdyBqv9iUW3zrckmNfy+2p8TAHIr6FwBqfcTqHrb+DE+P/DM89mar5kXmpByeqT
         Z/ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=UzSj3CgbOhgOBWp7C9e/x/tobPFrhAzAJpt7O8VC1YM=;
        b=mE3DPf3lOOgvyJtTeV9wl2zDeOEbKUuB8NEwi1L78k3D4wr8ENB5FbtJIV5YIGgK6G
         Wg3reYJwePSTD+yhjmGBJmBd26/jzrjaVgtQnL+agKKX7op9Dw/ZrPGcPyuQrpMk9bpU
         bhV5xtE7aU/WplO3oQZJRQR2aPk2YQ+w6U/7Rkm/HGCn+Sklc7rDGg68u+0KorDJt0RY
         ZlLohpRCwMmUGMaVbgoVckY0jo4G4tDG++6wFw3R1xx79H2VTnL3BIfGd5e00cbI2F3K
         POR4uk80MkyNw+lw7Y3jQrkiZtAq0rEvBocVSvMH1lekVmj323AbzhsEL907jNjqPdgM
         aJ6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=JipM+EK8;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UzSj3CgbOhgOBWp7C9e/x/tobPFrhAzAJpt7O8VC1YM=;
        b=L5cvrn80pIZ6JLl8xyrH1lyXsqzQwOAz8U7BrvRkY7gKansV81VIt/8TcZSpOAEWAr
         sNng6SndsoUyBkV+ONxVglAMCRP8yRUxT+MWxyHDPglWp7OTstiyuxjYYkkXqlxo+UkS
         BynZOydPOuedwcoMdypLoc3zO8J9PDhjRLu4aRRnUFx8dnMlYP/Y5SQYXsWqT0h3Uyod
         E0JOk8t+wuUZlhNDCBqERzxfsOXwsMUk4OwuSFgO598cQN1qRw2Fh8Tq4vr/fF/gqcMv
         OcnEGrh+K0ygdyUthC+aOX2K7So8tDw/J5BuDtcKvZaSfu0PR2Y6b+Wl1csSP9tPALbj
         Gz4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UzSj3CgbOhgOBWp7C9e/x/tobPFrhAzAJpt7O8VC1YM=;
        b=SPKc9v3F6hLg/XIHp7PcF+9hU/6nAfmcfzCYu268OBTV0oZFeygTCpXxiHPTqT9oiH
         Z3n4RkONlfvKV1QMXwH2N4s0AafHWUaoy027TGcpCJ7bhsatCTh/xbq3/YKYruWfs2de
         d/HDR0n/NU2tC4oF6QpIVcC7NJBEuJzRsCwCfQsyyTs5W4M44HwN7J2exJjxrBSgruuJ
         9jmk8MZbMqbMUFT8JDJFOm//J8fCVCZFEj+PPsTZkp2Hu9eAdgl14vxKZLbbp2QTshxq
         /PW5dw8K+FGqD26n6lcZ/FKWAMT/xq/62fKA7Nk6FkQC2VL19kIUZggHNoHH2njsPCnd
         Qy0A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530N+SXJ8Ym6oTo0wyDyhMGh+y9skF1UkQZDwXANtyfdST60lI6T
	GxLWxl87X3AAeHVK40ldnoU=
X-Google-Smtp-Source: ABdhPJzh/kUwNHKXva26RdVtmeM4sQkXMZWYUaj2aRL3qukomuulKPgmwHw1ZtKLLRXiGjXKL9urGQ==
X-Received: by 2002:a05:620a:805:: with SMTP id s5mr29575864qks.326.1625108351113;
        Wed, 30 Jun 2021 19:59:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7fcc:: with SMTP id b12ls747381qtk.6.gmail; Wed, 30 Jun
 2021 19:59:10 -0700 (PDT)
X-Received: by 2002:ac8:5045:: with SMTP id h5mr34267084qtm.178.1625108350680;
        Wed, 30 Jun 2021 19:59:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625108350; cv=none;
        d=google.com; s=arc-20160816;
        b=Lvc0z452Tv0mY9A3URHEMohyUgBlOsq+R55DcctJGzvQrIy9aJPwVQAn44aQb6OcfD
         AAhlEK6Uasun8i03tlu8HiD3TKlmjiPdyvJ/sZ6NzydR+MLl0QqQipw3MiCcrRPbPZnV
         5tox7/PgB69e4SjTKk0RWUvyFZOMYAEknd9Juwv+jc47gdJL/EDJibDPC4PSgxdx2R1L
         v51MvNgRBhEonmvZ5G6StfF+sZIeWGRhZhuzmFTmV+Ll0WGq3MaeJprJM7h0Vxk6G66h
         BRnXNvX4ucUQcRSdUp1MEfeCh4dOzt9aOs/O1DCKrSBLsWzumsqFLFnmPWINanqnVaDd
         l9Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=HD7nLLZFahFZKeQRkjIKTsUXoINqr80+ydWGPG7amAY=;
        b=Lp2p/2p1L7V4N7eUGa7xudFAoOWfadMbxfR8Vqw+MyupngGbTrgRrevM38F5mZQypj
         Sa3x94zx29xZnsNcBL7IZ3NLneY3Vie6rmRhOKRb3hnuzHVD0NOEoLKerMgrR78Z/UTR
         zueKASQQidNbBXOCKy7IVdUGVlpyzrD8ZtJ7VmXyBUZmPv/sMsX4brvimx6sL35WevG7
         vRJH7hBs8hBuK3ENyt4d2Ag0G4tWxvn20qvWN6XRvQyQck6rEVLCEaUN41gON2Q2qy1X
         Q5zl0ogPRFFC0PJe84Ar9wm6a/Zc19DSij9eGfB3RgIJOAb6szQtH1lR0Nu0xxQN47Zs
         U/2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=JipM+EK8;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id i6si2570644qko.5.2021.06.30.19.59.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jun 2021 19:59:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id x16so4582599pfa.13
        for <kasan-dev@googlegroups.com>; Wed, 30 Jun 2021 19:59:10 -0700 (PDT)
X-Received: by 2002:a63:4c5e:: with SMTP id m30mr37239105pgl.153.1625108350026;
        Wed, 30 Jun 2021 19:59:10 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id k8sm14831808pfa.142.2021.06.30.19.59.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jun 2021 19:59:09 -0700 (PDT)
Date: Wed, 30 Jun 2021 19:59:09 -0700 (PDT)
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear mapping
In-Reply-To: <87czskonsn.fsf@igel.home>
CC: linux@roeck-us.net, alex@ghiti.fr, corbet@lwn.net,
  Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com,
  glider@google.com, dvyukov@google.com, linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
  linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: schwab@linux-m68k.org
Message-ID: <mhng-99340121-50f8-49ca-ae6e-0f737fc4d736@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=JipM+EK8;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Thu, 17 Jun 2021 02:14:48 PDT (-0700), schwab@linux-m68k.org wrote:
> On Jun 16 2021, Palmer Dabbelt wrote:
>
>> This seems a long way off from defconfig.  It's entirly possible I'm
>> missing something, but at least CONFIG_SOC_VIRT is jumping out as
>> something that's disabled in the SUSE config but enabled upstream.
>
> None of the SOC configs are really needed, they are just convenience.
> They can even be harmful, if they force a config to y if m is actually
> wanted.  Which is what happens with SOC_VIRT, which forces
> RTC_DRV_GOLDFISH to y.

Ya, in retrospect the SOC configs were really just a bad idea.  I think 
we've talked about removing them before as they break stuff, I just 
haven't gotten around to doing it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-99340121-50f8-49ca-ae6e-0f737fc4d736%40palmerdabbelt-glaptop.
