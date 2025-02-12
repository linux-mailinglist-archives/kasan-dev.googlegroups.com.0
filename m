Return-Path: <kasan-dev+bncBCSL7B6LWYHBBQWAWO6QMGQE2PSUNIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id EFB03A32DF5
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 18:54:11 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-308e4f61cbasf64621fa.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 09:54:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739382851; cv=pass;
        d=google.com; s=arc-20240605;
        b=lB39+uj91NINGkNp+A3OYXQrO0yYibMnTa2oLgvFqYWHeGI/aBzJmTIjFxIfi1B4QZ
         xakazZYiySiwSxSSICBMkvk7XbMT1JcqBk3OrijBd8ZQLZzr86U/2ILP1yznscfAtCAi
         n0ANAkTOzs3/9R/yANwAwoxFliONzn5FBI967vVh6s5HZRcVU4hQD+ch8vaULi4B3J0O
         GDZpKzoFkJMwGy+FYKvWTkuqnwUCloHjlIeF2Bdo+9oTVTj2TWGcxLFsk8vXjvhfBtjS
         qQQQ3Fm7UhEw3Lv153qET/D4ZSS5nr6uS56AZItqLrGDYeasi/g6j9KljirxS065vJ7F
         Nklw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=PMK9fc7qToYKLVr8imzGe7YIgW+SJnVtJxb1TSKXctw=;
        fh=KWz6l7oOfW9nkOUDzNHPlAUIutzeEImhhsuBQVkrstw=;
        b=CWVj0Szm6umxV9ISyvCIAJ0lN8MifazyDCMyttD5o6EwuLPMJuezlobH5YwtZMxK4Y
         Wc+k24T+qGy+l7Wt2M9+kJiWuC2WK1qdA/Kbulifdtq4Usr+RPE28P2GJ8ciUnY6Et8M
         nOTHEyxkkRBvyER0eg1eKvGTp8RgnRrqFlup1K8SfDtQd4deL0sluAUm+byGj+iWvLz8
         3xLMb3tjpuG839StZtAOP04dSzH1NgKEtpdl3Pr4ehuV2vzbPWKb6OsOIONet5YDLySz
         U/jQSvK6PadOzCsBtR+S2bQzTmO9tpjK7MV4CDWLFGYh4Z2nQD7rgBcouID62GPOC2+J
         2iVg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=arAqVqyr;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739382851; x=1739987651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=PMK9fc7qToYKLVr8imzGe7YIgW+SJnVtJxb1TSKXctw=;
        b=TPLjagzeWQnLbK3KIw6FUvyn5Zmi6JKalCuwL/tKqmaIWjIi39HO24rrBhgCKhtdqK
         y20Gkv/F0dh3ji4MOkZ9nIVahlk0ZqhHQmo4P4ycWwAMtv05cBIjA4Jf/gcyidZCR/uz
         lkX2VPY/26xU4bgW793hF2Nh9p0876nggGZNt3WM/TkJdXYWHGfAEuSIO3BYwdEMCZNE
         V2odV4R67RH97vaX0H6ztFrs8sxceceFtH8UDzPFqLzFPcM7VEGuuvM03St+LXzh6FpP
         47LCkE/q0qWgmFASBdeyr0Fj1QP2o/cJfZ/HqbyzjLIi4ski3ObTRCrhPq0R6XA+3ESi
         giaA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1739382851; x=1739987651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PMK9fc7qToYKLVr8imzGe7YIgW+SJnVtJxb1TSKXctw=;
        b=Po/CXpEJ4pz1cKgNUPqx5/3UTGU1L8UlGbUIYEir0LZR8BQq36bwIUHWpboakUG2Tt
         xs82cWODBLe7Q0fYfNL9FCujAUwxKqzBdQsYw+OenUilHwS0xexaQgxLFIk3LqAxkjqH
         572B1/oU2egul6o9b3eN2NDGiOQwTwEVBJw1/3gGtCt7JvTH0YMaZkvJsL2pNGtbn6Uv
         9/2FfwLoZxWE8lELHidnJoaHkPHwfPdYhEjTknEh8Tw24v6f11e1TGPc33BAxDKPz4OA
         6r/LPKMtkOgS1/Zg35rv0Ox7lgvrfttdCzD1RRZbdA8jrKkkC2W3cUU/NBKJeIWO1ijl
         sl2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739382851; x=1739987651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PMK9fc7qToYKLVr8imzGe7YIgW+SJnVtJxb1TSKXctw=;
        b=hv06osKq/8xHclj90RK5qu2HssD9SkwsfQrV66tvxVCXnqLExH3VkGkhZuERAEHoSI
         +hoTREVHXY0goMEJaqJt/Oj1UbGcYa70IXvd1YQMBaXWYmFxG7ZNzjt6EqNA1HSzZhoq
         vS/SeDhiAvxL2m2DNfmS3xrJR6YXKsymEx2PfaS1JzxKYRJbw+IvVZXXGN5rRNUqE6mC
         i9T9JoYwDyVY4ZEUMZjuPXk5/TdX440Pltp35lc2LaenTSFQrTcycLICoEB+fPzjA101
         xyKHRyRQV2TdbCXzBIQWbiNrtkgt2vD8L97p0l6H3X57gBGxaS6Z2rsV9tc1W1BuDMoV
         CzaQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXm2KGzMAKxN8++NyLEgmLdq+m6NV4aeoUsaW3mC9hVPSnACtjccJhBdicbFG/QMGJuQ6evvA==@lfdr.de
X-Gm-Message-State: AOJu0YwVKWzy3TtsokqrNc3LqLSFbLCD0bZZd1gCmdz9ljoo9ayCxxqg
	hPaLjcG9+UaX6Fyr9wfL2zq2EQTYuwFstoOy4Q7Egm/BxLDC76rn
X-Google-Smtp-Source: AGHT+IG7vzGTovEEj2NuXC1sOVKdzRDQu0t8sPYw0s1GsDe+rAPGStq+POtUCymGIUWrTi4nQmq2aw==
X-Received: by 2002:a2e:a78a:0:b0:308:860e:d4d3 with SMTP id 38308e7fff4ca-309050113cemr11522101fa.22.1739382850587;
        Wed, 12 Feb 2025 09:54:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEZni6jADE4av29OXlCZ7bg82+l8pWYBxkjYCkZuT3bcw==
Received: by 2002:a2e:be0f:0:b0:308:e803:1177 with SMTP id 38308e7fff4ca-3090e175021ls179881fa.2.-pod-prod-01-eu;
 Wed, 12 Feb 2025 09:54:08 -0800 (PST)
X-Received: by 2002:a2e:be0d:0:b0:308:f75f:459 with SMTP id 38308e7fff4ca-30905091606mr12498141fa.26.1739382847740;
        Wed, 12 Feb 2025 09:54:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739382847; cv=none;
        d=google.com; s=arc-20240605;
        b=CzcsBHsKje0jEd6ZfZ+ttd8xHwhfWTeS6zpZ6mxk/ySYqOxpFJ2hgU83S1Nrg0j3WY
         NWUDA8VD4G6VNROx4QclyJ6WpmkGxrMMx5YDGyhXGWIlGo8SWLf/YmaWDUXhKM4VZZF0
         w1/+BLSk6zcEZTY9SiVf1ULmxgUNdneBfnXHy24AV3k/upSonI7lIn1c85p8CPoftAL5
         YeJqXJ5TJf/GdSYByOcn3LAS/VuJ+RMq3AomgxvOMuBPzuoOfVUPtcEd1drwNc+sdVoO
         LzrHot94CGydQ+BsaK9ZD1P6ZTOHIbGkzSIX6a7hxMKtRBSvfA0RpHCkYNHoy4I3FF9o
         fq6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=uuI5Z03zLDZiJXA9fnZE8eRXvdvS2QYxe0ggSv4hyho=;
        fh=6AwNN/H+Cd4LXfgYiqnRmUbJ35ovEaigqdKY2qBjBEs=;
        b=N/i36pw9tpgzGWY2uea2OcxRvfxPxl2+TlXzXwrV1COarOInS+6HXnL+awP/gaK6eP
         cfjRXfQeNqaQi/f6snUxHEBMq2AxtbGvmnzFd5q5myZDr6rKEFqc4mPVqcmedq0Pr7Tr
         XSFVt20+19l2WzeQeJCyiaSHLlB/WF96TAvoQ8Qqdg1vElpci/clPbC2zZhDe3vv8Wx+
         gSB5GvS5b/DpMrqPPy+bFPbpY1ftN1B1Hf5Utg7R2Q0W07Zfrg4meVpsITfbgtFkwKMZ
         LT6Dly6hAOZoUVv7UEoYYCgxs75D2FyH/OIgoj/WtempbE5oK+UfsLIMdboRlignPZEc
         tmqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=arAqVqyr;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-308f18b5885si1405901fa.4.2025.02.12.09.54.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 09:54:07 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-5451ccd7f2dso40680e87.3
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 09:54:07 -0800 (PST)
X-Gm-Gg: ASbGncvtDkDL9XMusMH34tL82d9LcTaiYtabbQ5xPcFwDqAd0gTz5rDceS6Iof8vaG4
	muucn4eeuBrUlToVL+gu+4LLplXpl7d5VxGSTs6UxCR2ZjQwoBaPgIc8WVq7HyW4+imybiKq+90
	seLXyyWgohigwGMKLs8LRXalfUT/GBy6rb+A4NnP1kRIdnoL6yp/z+pwqcZ2auKFhqFTEuZREoC
	lSGla6nq951/7OUWM4MQCzsCwHuTamLz+z03uAWUlPr/RcrB8rfout4joyMhkjbHnIrlREOPypA
	BWTZOUHywDxvvvB8c2wxiw==
X-Received: by 2002:a05:6512:124e:b0:545:8a1:536d with SMTP id 2adb3069b0e04-545180ddfadmr473410e87.2.1739382847092;
        Wed, 12 Feb 2025 09:54:07 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-54410555a60sm1976613e87.87.2025.02.12.09.54.06
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 09:54:06 -0800 (PST)
Message-ID: <d0d2c78d-9ea6-43c6-8413-97d21ff77bdd@gmail.com>
Date: Wed, 12 Feb 2025 18:54:02 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2] kasan: Don't call find_vm_area() in RT kernel
To: Waiman Long <longman@redhat.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
 Clark Williams <clrkwllms@kernel.org>, Steven Rostedt <rostedt@goodmis.org>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev,
 Nico Pache <npache@redhat.com>
References: <20250212162151.1599059-1-longman@redhat.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250212162151.1599059-1-longman@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=arAqVqyr;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 2/12/25 5:21 PM, Waiman Long wrote:
> The following bug report appeared with a test run in a RT debug kernel.
> 
> [ 3359.353842] BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48
> [ 3359.353848] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 140605, name: kunit_try_catch
> [ 3359.353853] preempt_count: 1, expected: 0
>   :
> [ 3359.353933] Call trace:
>   :
> [ 3359.353955]  rt_spin_lock+0x70/0x140
> [ 3359.353959]  find_vmap_area+0x84/0x168
> [ 3359.353963]  find_vm_area+0x1c/0x50
> [ 3359.353966]  print_address_description.constprop.0+0x2a0/0x320
> [ 3359.353972]  print_report+0x108/0x1f8
> [ 3359.353976]  kasan_report+0x90/0xc8
> [ 3359.353980]  __asan_load1+0x60/0x70
> 
> Commit e30a0361b851 ("kasan: make report_lock a raw spinlock")
> changes report_lock to a raw_spinlock_t to avoid a similar RT problem.
> The print_address_description() function is called with report_lock
> acquired and interrupt disabled.  However, the find_vm_area() function
> still needs to acquire a spinlock_t which becomes a sleeping lock in
> the RT kernel. IOW, we can't call find_vm_area() in a RT kernel and
> changing report_lock to a raw_spinlock_t is not enough to completely
> solve this RT kernel problem.
> 
> Fix this bug report by skipping the find_vm_area() call in this case
> and just print out the address as is.
> 
> For !RT kernel, follow the example set in commit 0cce06ba859a
> ("debugobjects,locking: Annotate debug_object_fill_pool() wait type
> violation") and use DEFINE_WAIT_OVERRIDE_MAP() to avoid a spinlock_t
> inside raw_spinlock_t warning.
> 
> Fixes: e30a0361b851 ("kasan: make report_lock a raw spinlock")
> Signed-off-by: Waiman Long <longman@redhat.com>
> ---
>  mm/kasan/report.c | 47 ++++++++++++++++++++++++++++++++++-------------
>  1 file changed, 34 insertions(+), 13 deletions(-)
> 
>  [v2] Encapsulate the change into a new
>       kasan_print_vmalloc_info_ret_page() helper
> 

Not exactly what I had i mind, but this way is fine too.

Acked-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d0d2c78d-9ea6-43c6-8413-97d21ff77bdd%40gmail.com.
