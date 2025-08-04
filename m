Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7MYYHCAMGQEWMPMMGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AAB0B19B36
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Aug 2025 08:00:32 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3e3e69b2951sf36816675ab.0
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Aug 2025 23:00:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754287231; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZKw8vsk/jZW/jphRSQ1+qKJSQCIKU5/EamLEg83sWRFxDnQWuHQP1gmZUPPAY8szXn
         BFJxmqzlznNukN8EmRDmDcJaiaag+PWslPEHrflodRdQUCbLfb7HdpCWhQL8e0zQg7xM
         UdQY3R+5xVZmfY00yFZmLEm/3fk5r/64mdtxAUG76XeqV/GbGN0BhNGS3gxXsLpFZR1+
         52b4EsJm+GW3wkho15D0bE6CfydtuBAbVKEmnvJQEOSZti3X1+GL7mp3w6lfRp0CDP+W
         cuZMWRBe+EZu6jcYGQeAcP2UjYituEbXow/EGFgFD7cAfKDYAkTINvW+FxRUXz3ds0g2
         az2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YtsiByp16RKGRgfA3/0pZpnuhdlMlLTR7T19I5g7sy0=;
        fh=dsxOXzMidNyjHo6yF/I999/W3j5JoVpVbgwVp7c8Gzg=;
        b=hrDGyOF2cpSk8qFIdg4jUTTbq8opTpogRXGNHVFUzgQDCe+mRW/kCVXy1jBJ1giIuS
         cjWzVleuHD2hMoA/Uwi8KdPO9J0ORvJHmVJe334nzYvtB7+kHioVKa3vaRytJ+IdXG63
         Rs7JDvRNM7WaoNXNKQDmlq6em4qYxlOhaz1RqdlKVu7rQhyDzAs1IYI0zfXTLyg4NFJZ
         t3lbjOZoZ+diwp/+xHUA5ycH9xD3WY8h/OOLqVtr+DmtiwWGD2Adt/Y6cncnTu2aE2Ac
         Qh91zABlI5Qj4mhGB0LvtcBLpekzlimtWlF7IaLP/5Npa5AaG0Qq95B2NbD1DhZ1xeS+
         6ZMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4cBZUw2k;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754287231; x=1754892031; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YtsiByp16RKGRgfA3/0pZpnuhdlMlLTR7T19I5g7sy0=;
        b=CygIJXRLI9wXMUtoehGNWeBN+Xi+UgnN22eKxXvzpyOPNuSsYnFDPK6UhrjUMuE1O2
         1U7bsmY9rkA8d4StJ0PRseiydtPoUjLChJaFGFueeyOQChvrfehMaSeQ3fGp3SFkz9VZ
         eSxLjWLrMGleUjqJLnZK3N4ZhObfjEbRHekXnUkBSROgsNtMGzy/1HlfbPUBk8Z4cFiG
         jY6E7s6o6+6ueGg1EerbI2TMzrgGj/MN/rIk9Q5+dDtgDYYaa9RJ7mSo25KNQV8ykzza
         x0HW3huL5rkBmJdjGuQfWQuIPJQMLRgayW254+Rmf+uZDir3UreuDoVw/xbsxwWtmHOD
         r5Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754287231; x=1754892031;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YtsiByp16RKGRgfA3/0pZpnuhdlMlLTR7T19I5g7sy0=;
        b=nVbhVEff4mg8sOipkBFiaeYeygdALT3PkuDz3CFdslFXoopyI54q9hfAhwHxH/PMgI
         vWnSwo5hMWaYV0a+g9Hq6K7lBew0JXuIkYMcXdmah2BBd/4ZCOeDJ4WQv/7LbRUdon1o
         On1R3xoj69igeF00Q0v5uFIDvxf09SiBSNXSESmg0Hke1zswizfOn599dv5E40RYZu1S
         JReW/yVDegL/hqVb4Ov/HF8Eo993r94AI/VpJ9h1mngm+RoryJNZHidFd2LhZoaKuoTa
         akShC4X7TpU7KIYg1KvTWCvkANLyw3ySNWP2JKkb1gAE7hdSizlml4rtzxUYJGJjF7pi
         KPcw==
X-Forwarded-Encrypted: i=2; AJvYcCVDu9dw2TOToWlp7g9kwuitWcTCcaUlBUmgyP/yOoxLry7fRV9v1hOZgGGBan/+yKUwD8iFFA==@lfdr.de
X-Gm-Message-State: AOJu0Yy7CVsZNdw9tK9d5M2PANe38btJJs3fzuOGCnC0rv3DRxUt/4I4
	/osYlvD0IY3AGLVP0Zp/QZtKToAVH7e1BgYU6XhCFmUAbVx9VM8lhPZ7
X-Google-Smtp-Source: AGHT+IFIIIDQ/jt2t6QPN6SEe9cyAlpoKC+N2ntkru380FRyEo0q8Rj8DZINEeEKp6DfgmISmh9Z+A==
X-Received: by 2002:a05:6e02:3801:b0:3e3:ed80:843f with SMTP id e9e14a558f8ab-3e415e40b58mr151155085ab.9.1754287229369;
        Sun, 03 Aug 2025 23:00:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcaeMZKrDW9+vwIydSacj/qL9ehUvuc4Ivmi24vpnENBw==
Received: by 2002:a05:6e02:250f:b0:3e2:b5c4:3547 with SMTP id
 e9e14a558f8ab-3e3f67a4ad1ls24550905ab.2.-pod-prod-00-us-canary; Sun, 03 Aug
 2025 23:00:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV+XKsvtnELzimwzILJdHm+J579uOasl4BUkwSVc1W4uk3cp5TPn0gcSxLiqH9BM9GAs6Tzbc+sPCU=@googlegroups.com
X-Received: by 2002:a05:6602:150c:b0:881:8a24:5598 with SMTP id ca18e2360f4ac-8818a24688fmr80013739f.1.1754287227427;
        Sun, 03 Aug 2025 23:00:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754287227; cv=none;
        d=google.com; s=arc-20240605;
        b=BG7ZpWultTyC5bdIjcUgXO0ZV7/8XZ0DHkurxLHpUXJCBN4Av/4PwcSGQuvMgTyLYF
         bEyGTzBwaOkMaoAKiavg9t5exXuqta5+glVgL26e9PfbPGcDpIvx+Cq0eFzNXE+muYbS
         wMc6FkO8XWiCOadgUv5zNqCiZAqRFkNjP9m1Zv4FCSKDWTewsgSfIcrGhUJLTTayPcIm
         cxDv+6PWhsNPTtrS6tlXoSAMO/Rd7cce/qP1Bv76CipCWfoNRFaKe8i3vq0sCZhKueDr
         yrQCQyDTy9sYWppU2fJozUNjuP+ahuwyRNqpgLJfWGOIQIH+LA4vfisE9fxVf/sLtR7R
         aS5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=GW9ee20vQhs+179oAZihQfxJ7e5GO7cvFv5OZiXPnJ8=;
        fh=r/VrD3VJTIF3jPcHLUCiQK2z2ZKt6DXvG1XC+AuoNHI=;
        b=esHOjydjpztGdESxAZQ6Rp8ZOt8bQTi6VB9kDEGxFyrsM1FAhPy7CoM+0Y0ubgTvtu
         OGiNnuWNBV6AHO+Lek/w3qZxEg6v9sAptvQ++uHgRjzpAjT40P4ENJtaxkH8wiZIuo/L
         ixQIx+UeWI3RFy5MNU2ICN7If3ieRDLbPIxBI7mEnlw8jngHD43F26y7m3qAq1tVxniT
         82qFTyOqjHTT32wtWksnq3yhEHslVmkoQfsck/3YIqEYNuPLxl/5uRZK9Vpzn0sAGnM+
         ZD8f9DzLGMigtZV/75a4sR0FbGrblwyGb20OmuFUpSgswKaZiyCm/QDazZsxILC4o0Gy
         3glg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4cBZUw2k;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-8814df9352bsi42701539f.3.2025.08.03.23.00.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Aug 2025 23:00:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id d9443c01a7336-2403c13cac3so38019405ad.0
        for <kasan-dev@googlegroups.com>; Sun, 03 Aug 2025 23:00:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWhDcxv74pAbJ7OGU07j5DS7cukK/RWngcfUaft1BZSiLTMBCYOwV6K93m8fc7Ktb5eoEmQopQzGNQ=@googlegroups.com
X-Gm-Gg: ASbGncteYJ5muBBWk5mRufgf/zrgnP0OcRJY/hVxKpijQqCM6CDbFLo3V7My9523544
	/bGJ5HOaXYMisR3w2Nz6Uu67W5uEGjY+WYIl4pemqBjFtjDhuIw2wXz27m61EJseqzho26jghyY
	uA1EG44OCdGbpg03SpKLliOi9zIM7wlLKWItuIwM3XelJLXqChZ/bsBSFQ23EburCwkPfip+uWb
	9Yf50MjjqwGHvAS+k8xzs5I0e5hY9DnuGG7zh4=
X-Received: by 2002:a17:902:8601:b0:23f:ed0f:8dd4 with SMTP id
 d9443c01a7336-24200d7d3a1mr165647385ad.23.1754287226255; Sun, 03 Aug 2025
 23:00:26 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPWzJZrAFT3-013GJhksK0jkB6n0HmF+h0hdoQUwGuxfA@mail.gmail.com>
 <20250803180558.2967962-1-soham.bagchi@utah.edu>
In-Reply-To: <20250803180558.2967962-1-soham.bagchi@utah.edu>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 4 Aug 2025 08:00:00 +0200
X-Gm-Features: Ac12FXzqJppzOFmhwA4bjarsTDBlyoRY0yvvampHjfyILSAANQCwWK9R6F2pkOY
Message-ID: <CANpmjNNvsJ_u7ky+d1tiXtwc-T3z6VB4SiMqpo6aKWBBFO3ERA@mail.gmail.com>
Subject: Re: [PATCH v2] kcov: load acquire coverage count in user-space code
To: Soham Bagchi <soham.bagchi@utah.edu>
Cc: akpm@linux-foundation.org, andreyknvl@gmail.com, arnd@arndb.de, 
	corbet@lwn.net, dvyukov@google.com, glider@google.com, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, sohambagchi@outlook.com, tglx@linutronix.de, 
	workflows@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4cBZUw2k;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Sun, 3 Aug 2025 at 20:06, Soham Bagchi <soham.bagchi@utah.edu> wrote:
>
> Updating the KCOV documentation to use a load-acquire
> operation for the first element of the shared memory
> buffer between kernel-space and user-space.
>
> The load-acquire pairs with the write memory barrier
> used in kcov_move_area()
>
> Signed-off-by: Soham Bagchi <soham.bagchi@utah.edu>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>
> Changes in v2:

Btw, it is customary to send out the whole patch series on a version
bump, even if only one of the patches changed.
https://www.kernel.org/doc/html/latest/process/submitting-patches.html#explicit-in-reply-to-headers

> - note for load-acquire shifted to block comment
>   in code rather than in the preceding paragraphs
> ---
>  Documentation/dev-tools/kcov.rst | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/Documentation/dev-tools/kcov.rst b/Documentation/dev-tools/kcov.rst
> index 6611434e2dd..40a4b500073 100644
> --- a/Documentation/dev-tools/kcov.rst
> +++ b/Documentation/dev-tools/kcov.rst
> @@ -361,7 +361,12 @@ local tasks spawned by the process and the global task that handles USB bus #1:
>          */
>         sleep(2);
>
> -       n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
> +        /*
> +         * The load to the coverage count should be an acquire to pair with
> +         * pair with the corresponding write memory barrier (smp_wmb()) on
> +         * the kernel-side in kcov_move_area().
> +         */
> +       n = __atomic_load_n(&cover[0], __ATOMIC_ACQUIRE);
>         for (i = 0; i < n; i++)
>                 printf("0x%lx\n", cover[i + 1]);
>         if (ioctl(fd, KCOV_DISABLE, 0))
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNvsJ_u7ky%2Bd1tiXtwc-T3z6VB4SiMqpo6aKWBBFO3ERA%40mail.gmail.com.
