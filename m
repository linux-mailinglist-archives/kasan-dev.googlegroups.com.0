Return-Path: <kasan-dev+bncBCMIZB7QWENRBWNF374AKGQECHH6JLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id CF14322900C
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jul 2020 07:47:06 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id a189sf496340oob.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 22:47:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595396825; cv=pass;
        d=google.com; s=arc-20160816;
        b=UjW9hwCjSFhhJfEGPmXV0bKyZnb48DgIq7CZtk4PXT1oymZIYEYn+fEnYzV64RJqG8
         tTkbVzDxyYmcXvWUPnD1m+CJWxwXQgp+v//5NWwwBHwS14HkH9lxA9KkRn9eTuYOdSPG
         N4eYdEGZ8hKhWpHOQxN/mkC35Jeud/n7Hm3o+eB2K8FnbhPd9eiZUx2ohRx7h4hPyb9g
         gKqowU8NN+1CDcyCiuTR3a3HdcSt2iMSTMwK1aoS9tmmv7hf8DVkvGrNSViIkLbay7XC
         wkyOH91+RQlbD88hEy2UB/nOeaoD7zWeCNCeoeWClg7F6iRerebFr3VwWpNgBuf+UKWD
         1yhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r0w/kNDi52F5lgLrqvZiOGJb4m1NZ41b9e7TajIUTmc=;
        b=GhV8jzo9PyAsoHrauUZ8+4w/9vQIKBGcwP4/wGtBbYRw9OKbpIDNmjdLAjxsQV0Ney
         eugolZsi8iuY3F8V8OSrwlF4hHGQf6YC4oDswskZ+tWt0uXVMak9DhvQXkb03lHqJ8jd
         mdwl0e5w8kbbV08xHZaEJrrOPy/mCJSwO7CdsT9hf9eG3xipkwmMsYBiTvjdYVN8CusP
         H65PLJ2pK8dSU+eePakknGlkVKcqhqZ3wHaOW2OPXq8hbv5Gt7uEk+6aA7rvdxuzvbAX
         26/xv2MVxhuMQBtuiZFC/xVEfvNdfMomM3i8HJYFixlNchovC1ovhXgtf4L/HyaafDl3
         BoaA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qm6Vy7Ay;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r0w/kNDi52F5lgLrqvZiOGJb4m1NZ41b9e7TajIUTmc=;
        b=ik0dfw3bKHYUDAjmsjqfeyGevkuiMI2ywc9PTzZWGSto7xpZohvoG6g45ZF/cnUAS4
         XEIYk8Al8IOCTmrosliU2ND+aRGKReLJ6tHdFldutk5lo5KGMiDHZsOrzqqXCzNhSbBX
         zCP6f/u/2kHo1397/hN0uKMIHZ+CTMAlKi2n6vayI7AXdRYK3QVSXTf+x/aFFmIetk6U
         /xbZ9NnipT1LxiV3p7cEGTvia2osjX1PI8MmJTPMBWk1KxPdr8sAhFEaVpv8yGSbHRwx
         R3quKwDtx3IY1PkrQ2tNkM9sKLl7YX405HJuUc8srFKlMrwlQK/F67+r/tCgGfMYXhDt
         bHtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r0w/kNDi52F5lgLrqvZiOGJb4m1NZ41b9e7TajIUTmc=;
        b=mywqgGsMytaB8JtdvY0pp898kdI3EcizLpgd5QpmCTAkjwkR3B17UbBrSWKq3HCjMU
         oz0ieSZ3yj7VKGDIcp3MFIKmS+H5aQaioOHkQgBSPnjh+CQUrlwwYjKxLLuxYZAxpuY4
         ejqn72r326fe47fYhqyZHCjPloBVPjSiCMWemNg5BKUpqjgLjAiqtj/RjsQXQKt67R54
         c0ANIP9KlBRDuDUMQ7vMhXQe9NxyXQDRhf4mkvOk9R8vs8QUa1YX/FHgCmPeq+F4KdFt
         bWClPZo5kpKpuQ1IgPHAPeZjpmDtCWI8wS9+wkJPs3vKNUL/dSk7y824mQCdgkFsGdhr
         7YlA==
X-Gm-Message-State: AOAM531sX0SColkd3DvFzpAnUm1NbITBwFloBG6OcDCBLXsQK3CHnVC+
	zRkxTZW7K49jUjYaJ57/iVQ=
X-Google-Smtp-Source: ABdhPJz9WPZjEf3d1udSAM38JABmPImpIY3gXmqNVbhovMX/oihAvtFTa5t/LfTmKCa9Xv4QS3r1YA==
X-Received: by 2002:a05:6830:22d9:: with SMTP id q25mr7475739otc.302.1595396825403;
        Tue, 21 Jul 2020 22:47:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:8cd:: with SMTP id 196ls191892oii.4.gmail; Tue, 21 Jul
 2020 22:47:05 -0700 (PDT)
X-Received: by 2002:aca:de42:: with SMTP id v63mr5965645oig.21.1595396825138;
        Tue, 21 Jul 2020 22:47:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595396825; cv=none;
        d=google.com; s=arc-20160816;
        b=LGP3eOnjScBL100lV/cQvdqXINmAkLZ0MG/lCCmAqB4xvWoiFEwQKr6rhPGrwZc4yN
         +feoq5PI8s6AhVkinumh+2Pqq+fceT2X2HLw+nCSe0FEx8ugeYbpnjQWl+z057HrRFU0
         P1MYk0zHD+8hQVwlFvJRdrO8nAJ3g58pWDkTaMS4QazmhRhVvaac7ZLEXbPwgwXVs9ti
         7P8dBJbTCplueAltjWMcqfoxaxMRhVW9Fk6s3pt+bK790843DmOerqHozzvv2wAAxy/b
         GA8jMoakmrzpy8VNUXmSzP1AcBLGMj0WB5JC1ZL2kltnoUapJsetdndmULLpm8A3Uvcw
         d4eQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vlXROEHgzJZ1vBjV4CoHiN+1cF5EdfW83RiegXm1ITM=;
        b=jQ5LW2zjXJmx6FrNSjc0nz9LG+9RhIlqrjix82ChaN9kb9XSaZx7ehPGLc4zAiPOtb
         S0Yke5qmo5LSFPH5xgqb+ETm+h3e807g4Zvt62XfOJpfDaWYvkEkH3lDdCgOu1ZD9803
         Sy4vMFxgs95ZxyLJHRp6oEYcL5L4N2BjAcRftC3v7HMVSa+m8Euee89hZD9LsP2k3roh
         6IJWsNGSMCLRq/rQyqgM6dzIr8tdgOJOuusfYz/8r5GbUN5CnM2V96Nk4iSReY0E1tlA
         23o08XVuVgbENypKD0bQyhihBgpQC6ehXVzxyS2oaY4IswQ3cpRcgt/Lzzv37TLXDLmt
         zZRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Qm6Vy7Ay;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id m21si1655082oih.4.2020.07.21.22.47.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 22:47:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id h7so908519qkk.7
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 22:47:05 -0700 (PDT)
X-Received: by 2002:a05:620a:152d:: with SMTP id n13mr5173019qkk.43.1595396824384;
 Tue, 21 Jul 2020 22:47:04 -0700 (PDT)
MIME-Version: 1.0
References: <202007211404.0DD27D0C@keescook>
In-Reply-To: <202007211404.0DD27D0C@keescook>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Jul 2020 07:46:52 +0200
Message-ID: <CACT4Y+bpDUa6bzP1P6apPDOFM5h+PkMfoauBnxe7uByJovZRdA@mail.gmail.com>
Subject: Re: alloc/free tracking without "heavy" instrumentation?
To: Kees Cook <keescook@chromium.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Qm6Vy7Ay;       spf=pass
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

On Tue, Jul 21, 2020 at 11:11 PM Kees Cook <keescook@chromium.org> wrote:
>
> Hi,
>
> Is there a way to enable KASAN's slab alloc/free tracking (or something
> similar) without turning on all the "slow" instrumentation?
>
> Specifically, I have a corruption that is due to a race, but using KASAN
> to see it doesn't work because the race stops happening. However, I have
> another much cheaper and specific way to determine when the corruption
> happens and I'd like to see what thread called kfree() on an address. I
> didn't find any other existing tools that would track that kind of thing
> besides KASAN...

Hi Kees,

Such mode does not exist, but if you are interested in a one-off thing
that it should not be hard to do.
You can disable the heavy instrumentation by finding the Makefile that
adds -fsanitize=kernel-address flag and removing the flag.
Then you can eliminate most of the remaining overhead by commenting
out bodies of kasan_poison_shadow, kasan_unpoison_shadow,
memory_is_poisoned*, check_memory_region* function in mm/kasan/*.c.
That will remain is mostly what you need: heap object metainfo and
quarantine. Call print_address_description when you need the info.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbpDUa6bzP1P6apPDOFM5h%2BPkMfoauBnxe7uByJovZRdA%40mail.gmail.com.
