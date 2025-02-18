Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLGX2G6QMGQE6QUBQCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 27AFAA39A30
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 12:14:54 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-3d2a63dc62asf6476735ab.2
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 03:14:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739877293; cv=pass;
        d=google.com; s=arc-20240605;
        b=E6G+7j1qQuzSAJwcOaZcNLIRN7S6ZLyrkmGIZjqRUVDiN6hOukaXufh+tIiUUq41XD
         KyMA46+dOV80aP0GmVa5bArrai8GC8IR8hGywhYyH+O+VP7w0of48WkNv9tPnrhQGY25
         i25SsK/XqjGMPqDHeYckGxJpF2aX/O97YB/g7Xc6F1kJ6ytpkfpArwd+Mqu7lcWrnGjs
         Vk9AxqkA1FI+KcCMtvRq/C7Vg7S0wzFfwM0NLYu9iVgf1k8tvjTXmsTrtGYA5dYiVCwL
         vhsQ6HX30PhtrsCyIMyuwBB8UR3TyYphPyGpVoLxZ3kgbMFyx8mqMve2uXreFu62Y94L
         dZ7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FhPkE6Gy4aixd7M58St5ChK/7OP+RaOhX7tTYyD7/WM=;
        fh=GkwMKJaThzJjmgi6auDKao1GKSr+NO7bqjB3DwuYh7E=;
        b=Me9+RXrNH2GebwICTH1UqAyj0VaSPGM7rv177eYphnucW3nfGClnF2UmiRHjGEogUK
         5WYoTsG1gNJ0N6MC/f+FlpkKRwjFxNxwV7SKIRpR0iNQS6mBIfO7frgbsWCeHq4ulyHz
         x7CgGCx1h4upqk6QiUQrXeV2IipzI54SbLYjnwyBeAhVS9W7pdj06zq0SJZOHGL4JSmx
         Qwuxl/Vy3AxJbJhPf2tDU09Bs8jtzcXxJQD5zHwf3CEc4QN9pF3L81raKeAPuWBzyKJj
         V3sKHf9Q5vhLe6/6i5MjL3wXsH2QiQJgerGB4Qlpzhl9zdNKUv1NOFo5qCt5wnXkig6T
         QvXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dRR4nW4A;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739877293; x=1740482093; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FhPkE6Gy4aixd7M58St5ChK/7OP+RaOhX7tTYyD7/WM=;
        b=Qum/j1+JvW1ovYJ/Fywd1IBjAy8i7YyktOBbwaUXcB78VheD3iy/dEztnuAg62nAdC
         2KkWRtwk2b+wSiLOi9rp+L0dIawZvgvzTixZj1cDYkeMvAcpjzCH/LsfTGFF/j6qYbdg
         683voUZAgfL3MTqOXPByEh1ATg5PRdgj5upgIc7CDe9NPcXm0WeazloajZkw1OzHVxkZ
         ujMDO09Vm5J1n5f46lMAUqLmg8/hrr19AWtIF3NqDnm7q2sW+S+/2WYbpVKpM7VYOK9e
         9iKwCQaeNdqT0LHfnyIJMki6Y+2dbS1K9oa4dTxGbYsiCkt8dW79ShkeYEzmm4biVbyR
         mAaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739877293; x=1740482093;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FhPkE6Gy4aixd7M58St5ChK/7OP+RaOhX7tTYyD7/WM=;
        b=NojqOCA35mYqtfrTjKGnKO8KhOwgiwOAjexRTBckeZ9cKRggZNRyLjOzs5ZtTChoCN
         4XEL+7eUVVazMK1HNDh2FrPl7Ui6IRf7p6oMGQ/rvE3hgVaKqwi5jHv2rhS/oMUEgZXH
         j5kxMED7AwRs/jo5wASWD6dR0GFjMbcvOrW/S4iX+BMhgtqcABhVRIcs8D5XJJRr7gYN
         J8JB9eeJW2GDcJKSRpTZke/yHneljj5PCGGqR7ASJqXad5u+3f+6atpeln42GszzqDln
         QgU1V1UMFWkfb+mzcEsI3Rq4rimPt/N0mA6cN6bup0qC+drgTgH7+vGo82tw4RpY94W6
         jfTA==
X-Forwarded-Encrypted: i=2; AJvYcCVhMG1LFu/ytRqc1htpx/gg9VnqKEmpe59V/JARsQmpHgP6SIZ+SbdzRjkvJJgDUuaUYFrgxw==@lfdr.de
X-Gm-Message-State: AOJu0YxPTpUArsUgN+FQkz468o+WEukiZpUaRA186fambVK45LoOO82q
	kvrxt1Ur/QYl/WyV54S3RLEUCmI30cyt72bd3t8AtusZQmzCV3T+
X-Google-Smtp-Source: AGHT+IEOkEEUdZHAuuCt9evBkPiEvuw+wPUFT3112Xd8YOeqYzXpRL5NzWXrVbyIJNqzV/5GD8emuw==
X-Received: by 2002:a92:c269:0:b0:3cf:fe1f:f5c5 with SMTP id e9e14a558f8ab-3d28078e07amr116207015ab.9.1739877292745;
        Tue, 18 Feb 2025 03:14:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHMrdpLT70sYYn4272am2TVX/7R95b0FmLz/hKfSe0ETQ==
Received: by 2002:a05:6e02:1342:b0:3d0:45cd:cd1a with SMTP id
 e9e14a558f8ab-3d18c39bd63ls17567975ab.2.-pod-prod-06-us; Tue, 18 Feb 2025
 03:14:52 -0800 (PST)
X-Received: by 2002:a05:6e02:1a03:b0:3cf:bbb4:f1e with SMTP id e9e14a558f8ab-3d28079040bmr115695665ab.7.1739877292054;
        Tue, 18 Feb 2025 03:14:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739877292; cv=none;
        d=google.com; s=arc-20240605;
        b=VcartzBZQpoo9nCP4zhkUqddhSW4ZFYriDurvQwcAE6W8i3U9+mPjfm0Hi80Aey587
         F+3KpGqJhmtFtOrfF703G4YyHljVYTipyXJQabq7IOYIjcb7xmB9uP/YCt5wgc8RHHtu
         tM0BWgu4KMbZY6KV+sAEZwdh2fgYeDOLA9LHFGHGLS/iuP3oJTzzZAbBbjVMfRgmnQDL
         ZGHJdnxuJzyjT7H1URd9ddabJ3HbWxDxFoJN12UkjwDHBRPJCNnFAXkUYQbnRLCmMmD/
         VAoCVhXC1xrARow2Sj2mqzpKjVHsYeQ6i/juhd2TtP1X5PWnLlftzGUMqaOlDiVQPxgs
         LCvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=e4ePEsIFIVWnVVp7x965KwnUxkPN33NpLp6ekCRE8KY=;
        fh=WQhmsbu9d8Vh6m1/TBbDvawu3yU1aBOJXxCBfVu+uFo=;
        b=Y0xXZ2cG0FoitgQnOZqNmaKBsU1oFMHXouJe5vplOGp/s89p7DD54djudkjnWPqzsE
         pAy/BpfU0a6PhNqS74XnUj1gsj2eAaiLiQR7qLUIHjE5TXxvfE0ENsvVTq2AnuV8aZFY
         km4gjncjAJooNG5O0ePMZAtklON7kiwBFCvwMOPN1NliwZ9O6W+CWRkD/qB+EP+fqRdJ
         ENDbV5ruzmtlyXKPoTOuHOcw7Es9vEtVuVz2pZKdXSSa53IlI9k3IOAGVgFD5XM26l/3
         6WUNMhKCVtev027/Saq7FJqMIvdCwEfgBhVJEb6Mbj89TXoy6zQahx77a6hu9yxdbmEZ
         gvCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=dRR4nW4A;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4eea5e1da42si124404173.3.2025.02.18.03.14.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Feb 2025 03:14:52 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-6dd01781b56so65026706d6.0
        for <kasan-dev@googlegroups.com>; Tue, 18 Feb 2025 03:14:52 -0800 (PST)
X-Gm-Gg: ASbGncs9CFWMF4HSl/O7MJKoORrW1Nq1TKM4iaQ6KiIr0lA8v8VioAmpPVf4H0LZeQJ
	qsCWIWdvR12W4YNjJqilor4nm4VMVcPC7PnL0qt/pL9LMS8uZHMLCxxWBdX8Sc7GZWmZ1EZciRb
	FohA/z94a6Q7h2eKYI2Xie4Bxfrq8=
X-Received: by 2002:a05:6214:29cb:b0:6df:9771:978e with SMTP id
 6a1803df08f44-6e66cd063b0mr215315016d6.34.1739877291222; Tue, 18 Feb 2025
 03:14:51 -0800 (PST)
MIME-Version: 1.0
References: <202502150634.qjxwSeJR-lkp@intel.com> <20250218091411.MMS3wBN9@linutronix.de>
In-Reply-To: <20250218091411.MMS3wBN9@linutronix.de>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Feb 2025 12:14:14 +0100
X-Gm-Features: AWEUYZkW-ELgmmWvEUCGBMqnFptxrYx8irjbyp0U6Ob-IrK0R7M-ystRnmQpahU
Message-ID: <CAG_fn=WzE5d4W1YheYN3SPYmVR5=r74zhV-Zhao5xu-Fqi461g@mail.gmail.com>
Subject: Re: [PATCH] dma: kmsan: Export kmsan_handle_dma() for modules.
To: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kernel test robot <lkp@intel.com>, 
	Peter Zijlstra <peterz@infradead.org>, llvm@lists.linux.dev, oe-kbuild-all@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=dRR4nW4A;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Feb 18, 2025 at 10:14=E2=80=AFAM Sebastian Andrzej Siewior
<bigeasy@linutronix.de> wrote:
>
> kmsan_handle_dma() is used by virtio_ring() which can be built as a
> module. kmsan_handle_dma() needs to be exported otherwise building the
> virtio_ring fails.
>
> Export kmsan_handle_dma for modules.
>
> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202502150634.qjxwSeJR-lkp@i=
ntel.com/
> Fixes: 7ade4f10779cb ("dma: kmsan: unpoison DMA mappings")
> Signed-off-by: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWzE5d4W1YheYN3SPYmVR5%3Dr74zhV-Zhao5xu-Fqi461g%40mail.gmail.com.
