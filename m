Return-Path: <kasan-dev+bncBDW2JDUY5AORBKM7TPBQMGQELZMQYRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C690FAF806C
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Jul 2025 20:44:58 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-32e0bb64d99sf2090861fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 03 Jul 2025 11:44:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751568298; cv=pass;
        d=google.com; s=arc-20240605;
        b=f6gFM63o/yluvcihyjG6iSqfQSE+wJrpU6LqPTF/4A179dlt+ZfJkhGt+hwe0jVsVk
         31fq8rEhH+a8EWhJqjQgN+lgbZRw92O7uowtLkxXQkv3dacIfaDil6MWYnhSUO7gmlI1
         RTY18ehbHfhnGZslWDrppmQL+eRx5e2Oh0Bl6NR8GxIekvqwF7AYfOI4MLqs9sblQ4Wh
         KB9qYAAfawlTC+KEeOOARaLRScak8TiXJxVC8cyDJxtNSXtxkernjYnk1Mo5SwSsPGR2
         ot+rbEJOJELwBf7HK1CXzUIv7VQXemmtzaZM+KO07O5TaAcIw5m4pQsVPSvWidv3FAGF
         A4fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=UAHvFh2/m1JeEqY7pXFItCvRAoHbNof14QUQvMVLdB0=;
        fh=j4D84i/3bL5oyi09NhKsOt1I4/ot32Xg7K7hxEVfbno=;
        b=bu/BG6QvdRaeHZh/6Ys2gV3eZZeBVox7vvjB/WczWMcpIrA0vLXjbMzp9K0LpZZWG+
         CJnoX1xYGsz8srP+3K24Na21F1+ALgoaqxT0ETKk9+6L9yCecz6cB6B5Rt0OWHc4T8VX
         k0f4Qmn8kt1Zsp3F/DCjdj1X8qgh0JwzZBcrBjHWZELhxvjU7yOnXzAiLsVLmjJWFGXQ
         XlbkvQsi5NuuKlac3Xi1cNQZZdLk8muuUFzHzE3h/0QoHwIRw+bKd3/OMKLDKyzfD7af
         RDPJJnwga1sGkoTJBUb/hNh8cclQ7w7nLMS3qQriDAQTXFVHeT131AZf4Y0N/k5vplTX
         VMJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U2poOcLQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751568298; x=1752173098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UAHvFh2/m1JeEqY7pXFItCvRAoHbNof14QUQvMVLdB0=;
        b=Q6UFc7+jbceoxueK9w1kLPfdH/KXYf40qldH/I4ZHR+U4/A5yE6WjsKn2JuAT6Hr8B
         fn5iSR1xt/Fd+UgnyhcWoH5xnUyObdcf7cdly2xbsuzEs4hB4n0b7rgdMxVY1r9Yvjaw
         rhXC55e+Z9e/0vMRfGBbatuUrtiYaYtM/2fDxZcvW5aXA9flzmgpgb459771aIZIZfNT
         Y+G9NbTvGAXwzCTgzGpDIRGNzA8LQYbMsVyYB7+5FtHDfXbvapBmVczn9KlqpIA+4naJ
         Nq2ztix+iJPMZZ0Fd+OU7zietngxo3c0jq4U8quxx9cNZOpsjorrO+kxba9T4OP9UdPc
         6rCg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1751568298; x=1752173098; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=UAHvFh2/m1JeEqY7pXFItCvRAoHbNof14QUQvMVLdB0=;
        b=gly3L6l/WcmInV+HYNJzpzOST3sHOozlYGka6v8EXvW3uF4KcZCXTMzTJ9J74mCd+U
         NjrXjBG/MhXRTHiY37aw6b5ANYOUkpc/YJ6mrtebIJ2kiQIAdlwRxNm0+yz7/zuPRY46
         hh+KS+aEmoVFwNzZRb6bQ2vpTLDFYFjlj7AeGE/D9WvISEoKGi1a1nRkRZdX+3fWo4xo
         3Rl1qXmfCevucUQDiTvwCJ7tMXyDQa8ANdgH68eox8O8SSJ28nMShXtuduEzgbFb80x1
         bGQz3mUwr7ASO7X3TVHN30M5EEC6s+7gEocERsvQKXwY3fg4GcPT6qYaUQsKphh4+mFN
         TDKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751568298; x=1752173098;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=UAHvFh2/m1JeEqY7pXFItCvRAoHbNof14QUQvMVLdB0=;
        b=dyfUzbOTzXBbUUpvjpAVCDevG8hDodRhCKJu6A5mYMHZffTEwd6Pom2+EdyqGt3lN6
         TY5EsnNgWtLO1//RNEuPxACUyrM4iQsH//uCkQKagawHhjXCCddIPMAVzzZv6OD9Quw1
         y/RKfpQKSE14HiGgTuxBX0Zvo4V33JaJxeeWy704J9tmbtj6ewCEiYCQlHR1xOyN6FwA
         nZSVTRiv5sg1spc8COlg9hSZlEt1nlafnNwmhq1tgpZ0ULaybmLKNWgNLmH28Ghw9bgI
         PFlQ8JcVyUikpg3q/xRrtbw1h/lH5KwcoGccgq6ecBtQZ9SjlLtKb/2ByZ4YNSFU8I1B
         /sgw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWr2sTJyajivLSej8fms7+Aejx01Ev8S1zjtYv2jxJvTYadFX4EqbSBdIv0OtiSr3TK6YLMcw==@lfdr.de
X-Gm-Message-State: AOJu0YytV47etkRzkdxkh/ufkNbqdniqzko4MlAI+/H+Q+t0LRZRnwdD
	UOYEUk2jUm5P5Q+We4TG8lzSES6X4VEjPemC2JIlZ7dUUHQXXdhm7fJT
X-Google-Smtp-Source: AGHT+IFkrzvzwPgRCqbjJomc89FH+6uNeb1qNut+jaQ8zIujQ9IVW6mw+9tkJ2cPn4K6cuCe/0vSzg==
X-Received: by 2002:a05:651c:41ce:b0:32b:522e:e073 with SMTP id 38308e7fff4ca-32e0d05548dmr20970081fa.25.1751568297725;
        Thu, 03 Jul 2025 11:44:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeTcN13oDBxmtBwdegMW8o8Vvc5TLQ/tx5pyfB6Qo+uZg==
Received: by 2002:a05:651c:30c9:b0:32a:646b:ac65 with SMTP id
 38308e7fff4ca-32e1acdd534ls2353931fa.0.-pod-prod-05-eu; Thu, 03 Jul 2025
 11:44:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHzlREBhkhHZMj14uTUXGh56UVWZ+367O5/KEQjSl16wuoM7KqzUjCD5aMr7UfovzIUzE8pp5le70=@googlegroups.com
X-Received: by 2002:a2e:8a99:0:b0:32b:59d1:7ef3 with SMTP id 38308e7fff4ca-32e0d0c443emr11054021fa.35.1751568294596;
        Thu, 03 Jul 2025 11:44:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751568294; cv=none;
        d=google.com; s=arc-20240605;
        b=ZWf+WwkMv9PPUgjVFznZmfPv1oR8ZtBZnCUNiAAD6VYky3000ygwaohMEhqujBQFK9
         2CtjFH1CaGPHnMsAEAfzUHj82HhhCTo7s+dhm75B85r9/YaGFTNqi6dRSpSRUqUknvj3
         0NTaz2O6Qa8SJb0B2XDxa0WOw53BsnWfCW6Y5I3lhz7ku+ErI0XrSy1EBT9Pzvk4Rrw0
         o1EW23lc5/wWFHsj0Rc50cm+bPNV4wZI4FWy9s9Lv2b8/Uxovp6+DhtXWmYvVwNsjFWq
         h+9+hVD5RnT/e1XKs9EvvkVJXp9IpCcJ1d8tyzei0VuzwqcR47sYrLAOel/eYJ/gMVmZ
         Sd6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nhkOyWvT8G/VMXyw/UKeBC01BSrCEvw5VmaWeJzf0yQ=;
        fh=KU3SdjVvR3CFFEEOt9REjR6Rhgd9sAwkNbsLwOWOCzY=;
        b=YlIa8c2CewspT9sDJaX58vKQW2M4bAVlTKfU15Ee7tTHn5LpoLJppGbsys9Ua7qemu
         +ImH4+RrTKO870k5fKRBNnzZVipCQKT3+dN7q/d734GjMJcUGC60KjP9tpJ2b8jVXFQD
         1PVj5mjDlJmPzQGHfAoIzMz/sgRB93SZYiWzzetvr3BwncH+U42vt1ldKToaN9TCEVZB
         50V7T7P4WXULm+2OZne5lTrOHKrS++spnc8SCt2JBQXZ9E2lbl44GMBrSbpqEeDS6bdF
         O7jEvsr6V0tctE80B7KZZ8GKKwsKg6IjetGinzxOz0yAaeEH9w0mI3tHlMNrRO9gOLe5
         VnFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=U2poOcLQ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-32e1ae410e3si97681fa.0.2025.07.03.11.44.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 03 Jul 2025 11:44:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3a52874d593so103401f8f.0
        for <kasan-dev@googlegroups.com>; Thu, 03 Jul 2025 11:44:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWPjTEHb4XX+Y0N+2g1v2+S0iL2uxetSJFCWquT6yGSt5jZxgacJZk8Q3zS4Vk3bTSWECTT8ngGlqE=@googlegroups.com
X-Gm-Gg: ASbGnctDMF9xIeBhSc/iQNpVyHooSoByXaypyCmoAmaiZ0FUT5g1BpsadfI55dx2a3U
	BKcBDJzBunTkkiCSXUsKFt93rOlH65fvJipw3erekK/j7mWTMmD3d89uHpYWu5awi26t6L1FQz8
	naXtESti5duSOqEMyDbx0QzvQnUvfwcW3kAMNhuQitAP3tG7R/tc9j2qsp
X-Received: by 2002:adf:9b96:0:b0:3a6:d191:a835 with SMTP id
 ffacd0b85a97d-3b32de6aa89mr3137295f8f.41.1751568293470; Thu, 03 Jul 2025
 11:44:53 -0700 (PDT)
MIME-Version: 1.0
References: <20250703181018.580833-1-yeoreum.yun@arm.com>
In-Reply-To: <20250703181018.580833-1-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 3 Jul 2025 20:44:42 +0200
X-Gm-Features: Ac12FXxK_uNd7MYB8JUTDzt5QKdGlekxuViZupditnH5BtfReGGJsAY_cAZre7c
Message-ID: <CA+fCnZeL4KQJYg=yozG7Tr9JA=d+pMFHag_dkPUT=06khjz4xA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: remove kasan_find_vm_area() to prevent possible deadlock
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, bigeasy@linutronix.de, clrkwllms@kernel.org, 
	rostedt@goodmis.org, byungchul@sk.com, max.byungchul.park@gmail.com, 
	ysk@kzalloc.com, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=U2poOcLQ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Jul 3, 2025 at 8:10=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> wr=
ote:
>
> find_vm_area() couldn't be called in atomic_context.
> If find_vm_area() is called to reports vm area information,
> kasan can trigger deadlock like:
>
> CPU0                                CPU1
> vmalloc();
>  alloc_vmap_area();
>   spin_lock(&vn->busy.lock)
>                                     spin_lock_bh(&some_lock);
>    <interrupt occurs>
>    <in softirq>
>    spin_lock(&some_lock);
>                                     <access invalid address>
>                                     kasan_report();
>                                      print_report();
>                                       print_address_description();
>                                        kasan_find_vm_area();
>                                         find_vm_area();
>                                          spin_lock(&vn->busy.lock) // dea=
dlock!
>
> To prevent possible deadlock while kasan reports, remove kasan_find_vm_ar=
ea().

Can we keep it for when we are in_task()?

>
> Fixes: c056a364e954 ("kasan: print virtual mapping info in reports")
> Reported-by: Yunseong Kim <ysk@kzalloc.com>
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---
>
> Patch History
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> From v1 to v2:
>   - remove kasan_find_vm_area()
>   - v1: https://lore.kernel.org/all/20250701203545.216719-1-yeoreum.yun@a=
rm.com/
>
> NOTE
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> Below report is from Yunseong Kim using DEPT:
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
> DEPT: Circular dependency has been detected.
> 6.15.0-rc6-00043-ga83a69ec7f9f #5 Not tainted
> ---------------------------------------------------
> summary
> ---------------------------------------------------
> *** DEADLOCK ***
>
> context A
>    [S] lock(report_lock:0)
>    [W] lock(&vn->busy.lock:0)
>    [E] unlock(report_lock:0)
>
> context B
>    [S] lock(&tb->tb6_lock:0)
>    [W] lock(report_lock:0)
>    [E] unlock(&tb->tb6_lock:0)
>
> context C
>    [S] write_lock(&ndev->lock:0)
>    [W] lock(&tb->tb6_lock:0)
>    [E] write_unlock(&ndev->lock:0)
>
> context D
>    [S] lock(&vn->busy.lock:0)
>    [W] write_lock(&ndev->lock:0)
>    [E] unlock(&vn->busy.lock:0)
>
> [S]: start of the event context
> [W]: the wait blocked
> [E]: the event not reachable
> ---------------------------------------------------
> context A's detail
> ---------------------------------------------------
> context A
>    [S] lock(report_lock:0)
>    [W] lock(&vn->busy.lock:0)
>    [E] unlock(report_lock:0)
>
> [S] lock(report_lock:0):
> [<ffff800080bd2600>] start_report mm/kasan/report.c:215 [inline]
> [<ffff800080bd2600>] kasan_report+0x74/0x1d4 mm/kasan/report.c:623
> stacktrace:
>       __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inlin=
e]
>       _raw_spin_lock_irqsave+0x88/0xd8 kernel/locking/spinlock.c:162
>       start_report mm/kasan/report.c:215 [inline]
>       kasan_report+0x74/0x1d4 mm/kasan/report.c:623
>       __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
>       fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
>       fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
>       fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
>       fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
>       fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
>       __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
>       fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
>       rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
>       rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
>       addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
>       addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
>       notifier_call_chain+0x94/0x50c kernel/notifier.c:85
>       raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
>       call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
>
> [W] lock(&vn->busy.lock:0):
> [<ffff800080ae57a0>] spin_lock include/linux/spinlock.h:351 [inline]
> [<ffff800080ae57a0>] find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
> stacktrace:
>       spin_lock include/linux/spinlock.h:351 [inline]
>       find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
>       find_vm_area+0x20/0x68 mm/vmalloc.c:3208
>       kasan_find_vm_area mm/kasan/report.c:398 [inline]
>       print_address_description mm/kasan/report.c:432 [inline]
>       print_report+0x3d8/0x54c mm/kasan/report.c:521
>       kasan_report+0xb8/0x1d4 mm/kasan/report.c:634
>       __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
>       fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
>       fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
>       fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
>       fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
>       fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
>       __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
>       fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
>       rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
>       rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
>       addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
>       addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
>       notifier_call_chain+0x94/0x50c kernel/notifier.c:85
>
> [E] unlock(report_lock:0):
> (N/A)
> ---------------------------------------------------
> context B's detail
> ---------------------------------------------------
> context B
>    [S] lock(&tb->tb6_lock:0)
>    [W] lock(report_lock:0)
>    [E] unlock(&tb->tb6_lock:0)
>
> [S] lock(&tb->tb6_lock:0):
> [<ffff80008a172d10>] spin_lock_bh include/linux/spinlock.h:356 [inline]
> [<ffff80008a172d10>] __fib6_clean_all+0xe8/0x2b8 net/ipv6/ip6_fib.c:2267
> stacktrace:
>       __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
>       _raw_spin_lock_bh+0x80/0xd0 kernel/locking/spinlock.c:178
>       spin_lock_bh include/linux/spinlock.h:356 [inline]
>       __fib6_clean_all+0xe8/0x2b8 net/ipv6/ip6_fib.c:2267
>       fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
>       rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
>       rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
>       addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
>       addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
>       notifier_call_chain+0x94/0x50c kernel/notifier.c:85
>       raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
>       call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
>       call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
>       call_netdevice_notifiers net/core/dev.c:2228 [inline]
>       dev_close_many+0x290/0x4b8 net/core/dev.c:1731
>       unregister_netdevice_many_notify+0x574/0x1fa0 net/core/dev.c:11940
>       unregister_netdevice_many net/core/dev.c:12034 [inline]
>       unregister_netdevice_queue+0x2b8/0x390 net/core/dev.c:11877
>       unregister_netdevice include/linux/netdevice.h:3374 [inline]
>       __tun_detach+0xec4/0x1180 drivers/net/tun.c:620
>       tun_detach drivers/net/tun.c:636 [inline]
>       tun_chr_close+0xa4/0x248 drivers/net/tun.c:3390
>       __fput+0x374/0xa30 fs/file_table.c:465
>       ____fput+0x20/0x3c fs/file_table.c:493
>
> [W] lock(report_lock:0):
> [<ffff800080bd2600>] start_report mm/kasan/report.c:215 [inline]
> [<ffff800080bd2600>] kasan_report+0x74/0x1d4 mm/kasan/report.c:623
> stacktrace:
>       __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inlin=
e]
>       _raw_spin_lock_irqsave+0x6c/0xd8 kernel/locking/spinlock.c:162
>       start_report mm/kasan/report.c:215 [inline]
>       kasan_report+0x74/0x1d4 mm/kasan/report.c:623
>       __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
>       fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
>       fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
>       fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
>       fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
>       fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
>       __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
>       fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
>       rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
>       rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
>       addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
>       addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
>       notifier_call_chain+0x94/0x50c kernel/notifier.c:85
>       raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
>       call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
>
> [E] unlock(&tb->tb6_lock:0):
> (N/A)
> ---------------------------------------------------
> context C's detail
> ---------------------------------------------------
> context C
>    [S] write_lock(&ndev->lock:0)
>    [W] lock(&tb->tb6_lock:0)
>    [E] write_unlock(&ndev->lock:0)
>
> [S] write_lock(&ndev->lock:0):
> [<ffff80008a133bd8>] addrconf_permanent_addr net/ipv6/addrconf.c:3622 [in=
line]
> [<ffff80008a133bd8>] addrconf_notify+0xab4/0x1688 net/ipv6/addrconf.c:369=
8
> stacktrace:
>       __raw_write_lock_bh include/linux/rwlock_api_smp.h:202 [inline]
>       _raw_write_lock_bh+0x88/0xd4 kernel/locking/spinlock.c:334
>       addrconf_permanent_addr net/ipv6/addrconf.c:3622 [inline]
>       addrconf_notify+0xab4/0x1688 net/ipv6/addrconf.c:3698
>       notifier_call_chain+0x94/0x50c kernel/notifier.c:85
>       raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
>       call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
>       call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
>       call_netdevice_notifiers net/core/dev.c:2228 [inline]
>       __dev_notify_flags+0x114/0x294 net/core/dev.c:9393
>       netif_change_flags+0x108/0x160 net/core/dev.c:9422
>       do_setlink.isra.0+0x960/0x3464 net/core/rtnetlink.c:3152
>       rtnl_changelink net/core/rtnetlink.c:3769 [inline]
>       __rtnl_newlink net/core/rtnetlink.c:3928 [inline]
>       rtnl_newlink+0x1080/0x1a1c net/core/rtnetlink.c:4065
>       rtnetlink_rcv_msg+0x82c/0xc30 net/core/rtnetlink.c:6955
>       netlink_rcv_skb+0x218/0x400 net/netlink/af_netlink.c:2534
>       rtnetlink_rcv+0x28/0x38 net/core/rtnetlink.c:6982
>       netlink_unicast_kernel net/netlink/af_netlink.c:1313 [inline]
>       netlink_unicast+0x50c/0x778 net/netlink/af_netlink.c:1339
>       netlink_sendmsg+0x794/0xc28 net/netlink/af_netlink.c:1883
>       sock_sendmsg_nosec net/socket.c:712 [inline]
>       __sock_sendmsg+0xe0/0x1a0 net/socket.c:727
>       __sys_sendto+0x238/0x2fc net/socket.c:2180
>
> [W] lock(&tb->tb6_lock:0):
> [<ffff80008a1643fc>] spin_lock_bh include/linux/spinlock.h:356 [inline]
> [<ffff80008a1643fc>] __ip6_ins_rt net/ipv6/route.c:1350 [inline]
> [<ffff80008a1643fc>] ip6_route_add+0x7c/0x220 net/ipv6/route.c:3900
> stacktrace:
>       __raw_spin_lock_bh include/linux/spinlock_api_smp.h:126 [inline]
>       _raw_spin_lock_bh+0x5c/0xd0 kernel/locking/spinlock.c:178
>       spin_lock_bh include/linux/spinlock.h:356 [inline]
>       __ip6_ins_rt net/ipv6/route.c:1350 [inline]
>       ip6_route_add+0x7c/0x220 net/ipv6/route.c:3900
>       addrconf_prefix_route+0x28c/0x494 net/ipv6/addrconf.c:2487
>       fixup_permanent_addr net/ipv6/addrconf.c:3602 [inline]
>       addrconf_permanent_addr net/ipv6/addrconf.c:3626 [inline]
>       addrconf_notify+0xfd0/0x1688 net/ipv6/addrconf.c:3698
>       notifier_call_chain+0x94/0x50c kernel/notifier.c:85
>       raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
>       call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
>       call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
>       call_netdevice_notifiers net/core/dev.c:2228 [inline]
>       __dev_notify_flags+0x114/0x294 net/core/dev.c:9393
>       netif_change_flags+0x108/0x160 net/core/dev.c:9422
>       do_setlink.isra.0+0x960/0x3464 net/core/rtnetlink.c:3152
>       rtnl_changelink net/core/rtnetlink.c:3769 [inline]
>       __rtnl_newlink net/core/rtnetlink.c:3928 [inline]
>       rtnl_newlink+0x1080/0x1a1c net/core/rtnetlink.c:4065
>       rtnetlink_rcv_msg+0x82c/0xc30 net/core/rtnetlink.c:6955
>       netlink_rcv_skb+0x218/0x400 net/netlink/af_netlink.c:2534
>       rtnetlink_rcv+0x28/0x38 net/core/rtnetlink.c:6982
>       netlink_unicast_kernel net/netlink/af_netlink.c:1313 [inline]
>       netlink_unicast+0x50c/0x778 net/netlink/af_netlink.c:1339
>       netlink_sendmsg+0x794/0xc28 net/netlink/af_netlink.c:1883
>
> [E] write_unlock(&ndev->lock:0):
> (N/A)
> ---------------------------------------------------
> context D's detail
> ---------------------------------------------------
> context D
>    [S] lock(&vn->busy.lock:0)
>    [W] write_lock(&ndev->lock:0)
>    [E] unlock(&vn->busy.lock:0)
>
> [S] lock(&vn->busy.lock:0):
> [<ffff800080adcf80>] spin_lock include/linux/spinlock.h:351 [inline]
> [<ffff800080adcf80>] alloc_vmap_area+0x800/0x26d0 mm/vmalloc.c:2027
> stacktrace:
>       __raw_spin_lock include/linux/spinlock_api_smp.h:133 [inline]
>       _raw_spin_lock+0x78/0xc0 kernel/locking/spinlock.c:154
>       spin_lock include/linux/spinlock.h:351 [inline]
>       alloc_vmap_area+0x800/0x26d0 mm/vmalloc.c:2027
>       __get_vm_area_node+0x1c8/0x360 mm/vmalloc.c:3138
>       __vmalloc_node_range_noprof+0x168/0x10d4 mm/vmalloc.c:3805
>       __vmalloc_node_noprof+0x130/0x178 mm/vmalloc.c:3908
>       vzalloc_noprof+0x3c/0x54 mm/vmalloc.c:3981
>       alloc_counters net/ipv6/netfilter/ip6_tables.c:815 [inline]
>       copy_entries_to_user net/ipv6/netfilter/ip6_tables.c:837 [inline]
>       get_entries net/ipv6/netfilter/ip6_tables.c:1039 [inline]
>       do_ip6t_get_ctl+0x520/0xad0 net/ipv6/netfilter/ip6_tables.c:1677
>       nf_getsockopt+0x8c/0x10c net/netfilter/nf_sockopt.c:116
>       ipv6_getsockopt+0x24c/0x460 net/ipv6/ipv6_sockglue.c:1493
>       tcp_getsockopt+0x98/0x120 net/ipv4/tcp.c:4727
>       sock_common_getsockopt+0x9c/0xcc net/core/sock.c:3867
>       do_sock_getsockopt+0x308/0x57c net/socket.c:2357
>       __sys_getsockopt+0xec/0x188 net/socket.c:2386
>       __do_sys_getsockopt net/socket.c:2393 [inline]
>       __se_sys_getsockopt net/socket.c:2390 [inline]
>       __arm64_sys_getsockopt+0xa8/0x110 net/socket.c:2390
>       __invoke_syscall arch/arm64/kernel/syscall.c:36 [inline]
>       invoke_syscall+0x88/0x2e0 arch/arm64/kernel/syscall.c:50
>       el0_svc_common.constprop.0+0xe8/0x2e0 arch/arm64/kernel/syscall.c:1=
39
>
> [W] write_lock(&ndev->lock:0):
> [<ffff80008a127f20>] addrconf_rs_timer+0xa0/0x730 net/ipv6/addrconf.c:402=
5
> stacktrace:
>       __raw_write_lock include/linux/rwlock_api_smp.h:209 [inline]
>       _raw_write_lock+0x5c/0xd0 kernel/locking/spinlock.c:300
>       addrconf_rs_timer+0xa0/0x730 net/ipv6/addrconf.c:4025
>       call_timer_fn+0x204/0x964 kernel/time/timer.c:1789
>       expire_timers kernel/time/timer.c:1840 [inline]
>       __run_timers+0x830/0xb00 kernel/time/timer.c:2414
>       __run_timer_base kernel/time/timer.c:2426 [inline]
>       __run_timer_base kernel/time/timer.c:2418 [inline]
>       run_timer_base+0x124/0x198 kernel/time/timer.c:2435
>       run_timer_softirq+0x20/0x58 kernel/time/timer.c:2445
>       handle_softirqs+0x30c/0xdc0 kernel/softirq.c:579
>       __do_softirq+0x14/0x20 kernel/softirq.c:613
>       ____do_softirq+0x14/0x20 arch/arm64/kernel/irq.c:81
>       call_on_irq_stack+0x24/0x30 arch/arm64/kernel/entry.S:891
>       do_softirq_own_stack+0x20/0x40 arch/arm64/kernel/irq.c:86
>       invoke_softirq kernel/softirq.c:460 [inline]
>       __irq_exit_rcu+0x400/0x560 kernel/softirq.c:680
>       irq_exit_rcu+0x14/0x80 kernel/softirq.c:696
>       __el1_irq arch/arm64/kernel/entry-common.c:561 [inline]
>       el1_interrupt+0x38/0x54 arch/arm64/kernel/entry-common.c:575
>       el1h_64_irq_handler+0x18/0x24 arch/arm64/kernel/entry-common.c:580
>       el1h_64_irq+0x6c/0x70 arch/arm64/kernel/entry.S:596
>
> [E] unlock(&vn->busy.lock:0):
> (N/A)
> ---------------------------------------------------
> information that might be helpful
> ---------------------------------------------------
> CPU: 1 UID: 0 PID: 19536 Comm: syz.4.2592 Not tainted 6.15.0-rc6-00043-ga=
83a69ec7f9f #5 PREEMPT
> Hardware name: QEMU KVM Virtual Machine, BIOS 2025.02-8 05/13/2025
> Call trace:
>  dump_backtrace arch/arm64/kernel/stacktrace.c:449 [inline] (C)
>  show_stack+0x34/0x80 arch/arm64/kernel/stacktrace.c:466 (C)
>  __dump_stack lib/dump_stack.c:94 [inline]
>  dump_stack_lvl+0x104/0x180 lib/dump_stack.c:120
>  dump_stack+0x20/0x2c lib/dump_stack.c:129
>  print_circle kernel/dependency/dept.c:928 [inline]
>  cb_check_dl kernel/dependency/dept.c:1362 [inline]
>  cb_check_dl+0x1080/0x10ec kernel/dependency/dept.c:1356
>  bfs+0x4d8/0x630 kernel/dependency/dept.c:980
>  check_dl_bfs kernel/dependency/dept.c:1381 [inline]
>  add_dep+0x1cc/0x364 kernel/dependency/dept.c:1710
>  add_wait kernel/dependency/dept.c:1829 [inline]
>  __dept_wait+0x60c/0x16e0 kernel/dependency/dept.c:2585
>  dept_wait kernel/dependency/dept.c:2666 [inline]
>  dept_wait+0x168/0x1a8 kernel/dependency/dept.c:2640
>  __raw_spin_lock include/linux/spinlock_api_smp.h:133 [inline]
>  _raw_spin_lock+0x54/0xc0 kernel/locking/spinlock.c:154
>  spin_lock include/linux/spinlock.h:351 [inline]
>  find_vmap_area+0xa0/0x228 mm/vmalloc.c:2418
>  find_vm_area+0x20/0x68 mm/vmalloc.c:3208
>  kasan_find_vm_area mm/kasan/report.c:398 [inline]
>  print_address_description mm/kasan/report.c:432 [inline]
>  print_report+0x3d8/0x54c mm/kasan/report.c:521
>  kasan_report+0xb8/0x1d4 mm/kasan/report.c:634
>  __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380
>  fib6_ifdown+0x67c/0x6bc net/ipv6/route.c:4910
>  fib6_clean_node+0x23c/0x4e0 net/ipv6/ip6_fib.c:2199
>  fib6_walk_continue+0x38c/0x774 net/ipv6/ip6_fib.c:2124
>  fib6_walk+0x158/0x31c net/ipv6/ip6_fib.c:2172
>  fib6_clean_tree+0xe0/0x128 net/ipv6/ip6_fib.c:2252
>  __fib6_clean_all+0x104/0x2b8 net/ipv6/ip6_fib.c:2268
>  fib6_clean_all+0x3c/0x50 net/ipv6/ip6_fib.c:2279
>  rt6_sync_down_dev net/ipv6/route.c:4951 [inline]
>  rt6_disable_ip+0x270/0x840 net/ipv6/route.c:4956
>  addrconf_ifdown.isra.0+0x104/0x175c net/ipv6/addrconf.c:3857
>  addrconf_notify+0x3a0/0x1688 net/ipv6/addrconf.c:3780
>  notifier_call_chain+0x94/0x50c kernel/notifier.c:85
>  raw_notifier_call_chain+0x3c/0x50 kernel/notifier.c:453
>  call_netdevice_notifiers_info+0xb8/0x150 net/core/dev.c:2176
>  call_netdevice_notifiers_extack net/core/dev.c:2214 [inline]
>  call_netdevice_notifiers net/core/dev.c:2228 [inline]
>  dev_close_many+0x290/0x4b8 net/core/dev.c:1731
>  unregister_netdevice_many_notify+0x574/0x1fa0 net/core/dev.c:11940
>  unregister_netdevice_many net/core/dev.c:12034 [inline]
>  unregister_netdevice_queue+0x2b8/0x390 net/core/dev.c:11877
>  unregister_netdevice include/linux/netdevice.h:3374 [inline]
>  __tun_detach+0xec4/0x1180 drivers/net/tun.c:620
>  tun_detach drivers/net/tun.c:636 [inline]
>  tun_chr_close+0xa4/0x248 drivers/net/tun.c:3390
>  __fput+0x374/0xa30 fs/file_table.c:465
>  ____fput+0x20/0x3c fs/file_table.c:493
>  task_work_run+0x154/0x278 kernel/task_work.c:227
>  exit_task_work include/linux/task_work.h:40 [inline]
>  do_exit+0x950/0x23a8 kernel/exit.c:953
>  do_group_exit+0xc0/0x248 kernel/exit.c:1103
>  get_signal+0x1f98/0x20cc kernel/signal.c:3034
>  do_signal+0x200/0x880 arch/arm64/kernel/signal.c:1658
>  do_notify_resume+0x1a0/0x26c arch/arm64/kernel/entry-common.c:148
>  exit_to_user_mode_prepare arch/arm64/kernel/entry-common.c:169 [inline]
>  exit_to_user_mode arch/arm64/kernel/entry-common.c:178 [inline]
>  el0_svc+0xf8/0x188 arch/arm64/kernel/entry-common.c:745
>  el0t_64_sync_handler+0x10c/0x140 arch/arm64/kernel/entry-common.c:762
>  el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:600
>
> ---
>  mm/kasan/report.c | 45 ++-------------------------------------------
>  1 file changed, 2 insertions(+), 43 deletions(-)
>
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 8357e1a33699..b0877035491f 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -370,36 +370,6 @@ static inline bool init_task_stack_addr(const void *=
addr)
>                         sizeof(init_thread_union.stack));
>  }
>
> -/*
> - * This function is invoked with report_lock (a raw_spinlock) held. A
> - * PREEMPT_RT kernel cannot call find_vm_area() as it will acquire a sle=
eping
> - * rt_spinlock.
> - *
> - * For !RT kernel, the PROVE_RAW_LOCK_NESTING config option will print a
> - * lockdep warning for this raw_spinlock -> spinlock dependency. This co=
nfig
> - * option is enabled by default to ensure better test coverage to expose=
 this
> - * kind of RT kernel problem. This lockdep splat, however, can be suppre=
ssed
> - * by using DEFINE_WAIT_OVERRIDE_MAP() if it serves a useful purpose and=
 the
> - * invalid PREEMPT_RT case has been taken care of.
> - */
> -static inline struct vm_struct *kasan_find_vm_area(void *addr)
> -{
> -       static DEFINE_WAIT_OVERRIDE_MAP(vmalloc_map, LD_WAIT_SLEEP);
> -       struct vm_struct *va;
> -
> -       if (IS_ENABLED(CONFIG_PREEMPT_RT))
> -               return NULL;
> -
> -       /*
> -        * Suppress lockdep warning and fetch vmalloc area of the
> -        * offending address.
> -        */
> -       lock_map_acquire_try(&vmalloc_map);
> -       va =3D find_vm_area(addr);
> -       lock_map_release(&vmalloc_map);
> -       return va;
> -}
> -
>  static void print_address_description(void *addr, u8 tag,
>                                       struct kasan_report_info *info)
>  {
> @@ -429,19 +399,8 @@ static void print_address_description(void *addr, u8=
 tag,
>         }
>
>         if (is_vmalloc_addr(addr)) {
> -               struct vm_struct *va =3D kasan_find_vm_area(addr);
> -
> -               if (va) {
> -                       pr_err("The buggy address belongs to the virtual =
mapping at\n"
> -                              " [%px, %px) created by:\n"
> -                              " %pS\n",
> -                              va->addr, va->addr + va->size, va->caller)=
;
> -                       pr_err("\n");
> -
> -                       page =3D vmalloc_to_page(addr);
> -               } else {
> -                       pr_err("The buggy address %px belongs to a vmallo=
c virtual mapping\n", addr);
> -               }
> +               pr_err("The buggy address %px belongs to a vmalloc virtua=
l mapping\n", addr);
> +               page =3D vmalloc_to_page(addr);
>         }
>
>         if (page) {
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeL4KQJYg%3DyozG7Tr9JA%3Dd%2BpMFHag_dkPUT%3D06khjz4xA%40mail.gmail.c=
om.
