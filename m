Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBOOGWO3AMGQE4QZLJPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EA1A395FA85
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 22:19:06 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-428040f49f9sf44118645e9.0
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Aug 2024 13:19:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1724703546; cv=pass;
        d=google.com; s=arc-20160816;
        b=DX4IvXuWaB1xjxEu94v/pgZfxgBnsiaE0lPRjYUuVRVduTr5j8JVlcb0TXiJ6JZh6b
         AXL1G7t8JMKcAgcakJAYDIe007r6baW5SYiHauEWZVxCw2D2kL6RdD9Ikw+6RtTh7Hi9
         tcAGNQ7A7w4zFYiWO9lV4OpYaCg5zxQMkqnei8upit5BIAEvm1uS8Bf8binZGS4lIpe2
         0+1fyqLkSZT2m/PXeAjLhVOwOA1dc2PjTGFoparoTEIpugoT2fvBE2pt/nh08VZj82Nx
         KuHp/wmEIiZknVowE2tGsXcX3YaShaiPZ9eMx0W9L+LLe5xiMHO1iUtPrrvhwSzFBfxU
         nqpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FlIcQfT1Nl6k/jXdxGKH8sxMcVqssMIF3+tWlHq4MnY=;
        fh=3o/PjEXSViziz/pP5ZAqWrZtaaUmOff2aYQqjLTb1II=;
        b=XkMMzu69Mb4DJ6yLy0dCVv/HovE2Llw0xHSLTXxY8YH26GRJu0r+5Uyn/Jqrze5CDz
         iiC/nPTtozG+/ZTl7APsfq5eA8qizor5hiJRN8bVxbnhF3u67+OG2HxtECa65IwE3Bc4
         QQg9wGYZhzS6sJnWMkGJvHK2qEB6hsaKUuaKcUaLR6kLVnUoFcwsMi3hmnNgHIYDEGzL
         pLAAXxmYHn2ntL29cwUOVjP4hCyaIn7oe8DNIpiRv2gkOO5JDGrWo+lr0omNKbe0kXAI
         z/powAzxz+s7fF0+262h0Jr4ZbZqazRpZW34SUfvUFJwac8KJGrCRYpx+tLz/BlwO/8K
         rkgQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4K1XPzqY;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1724703546; x=1725308346; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=FlIcQfT1Nl6k/jXdxGKH8sxMcVqssMIF3+tWlHq4MnY=;
        b=g5lXPbMdJAEOZMLrX6bgVt0Gs/jCmiFygXAoQSLuLxSR+H9E7edwmlSsMXacvjcAUR
         s/GIAFmd8NMzBjGbnhBDoj862ahQljONI5Ya+dlw4xlueaSiyZekUtAvlV1xVGox5zlo
         MzExDt6iynXEOV6HNOGzwHOYG10DsIDfUJAUPt7eYpktNsYGFxFXIwRuaV5LiXpGM/ZX
         nQpK/sM827iy8Pgq4MlrAcFxWPoylkZCD2J3Gq5BWqMwUHx55JDVrdJLVdnnN9Na5bzG
         uPcGlrGn6NqCV4ur48N9dDoTVj9BGOBDWXM2lzGxCCAg1mHuQ+Joj7vpbJ4TtQQiXtJp
         41Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1724703546; x=1725308346;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=FlIcQfT1Nl6k/jXdxGKH8sxMcVqssMIF3+tWlHq4MnY=;
        b=nmQyA0a8FOrMZSv1BH0P9NcpdzZ9CDI38kmlKsdKkzB8hrmENzkNaksheH6cLY0WB3
         NjWacVUQ8w1UrdQGoaeWdWyPXRkXqNcC9WHtntX+k8fGB/PoZhzukv/SpD1Vy807fikP
         6wbsoF8ZWqyT6oXnxZ8hTETMoKjJV/G2PQgRrfAjqEZXFe55bSegDjv1U6lP/sq4InG+
         xZbJ+EI87hIACeYprwBBdxv9wlmH4Hrq2+Ejyuf/fNfy1VVqMKQk3hfr8zZaD8h3zEu3
         IEo/YBybbfCjg6fBC6A9U1EwdRoec+b4+YtaDUOxiJ4p5QzLt/Xmj8KICm8R5GVY5b3U
         2tBw==
X-Forwarded-Encrypted: i=2; AJvYcCVaoYV8reWwCa0dNOVriHJKMnjEzYVsLdcccUqeJ7WyKxNbcosogY8a3UYlMii//YXwWnQrkg==@lfdr.de
X-Gm-Message-State: AOJu0YwW92GFis9gLGC979nBdGqHjO6T++wJ4GzzkmiEGa2WmdLZoiUY
	1J8klLXRyXJNnUd9btsViuhfyqckwuQX+vzFEnahv1cGv/CcP1MU
X-Google-Smtp-Source: AGHT+IFTn4AgGe2vM6q4IGmOTJRbG3UzUSgIPG13G3srSrZWechkLFWU5mCdStpOF6C6m4MjK5vw+Q==
X-Received: by 2002:a05:6000:1841:b0:368:664a:d4f9 with SMTP id ffacd0b85a97d-3748c7d4d19mr628405f8f.28.1724703545785;
        Mon, 26 Aug 2024 13:19:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4fcb:b0:428:1007:62f6 with SMTP id
 5b1f17b1804b1-42ac3df7ee6ls18312285e9.2.-pod-prod-08-eu; Mon, 26 Aug 2024
 13:19:03 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWgEtJn+/71AgR/c+9TTZU1mTClP/c5VQN2YwaMyzI/pQbwgDf1nFkk5DWSS4GABmfSki4YsvqQD6Y=@googlegroups.com
X-Received: by 2002:a05:600c:458b:b0:426:60b8:d8ba with SMTP id 5b1f17b1804b1-42b9ae3b70fmr3699865e9.28.1724703543588;
        Mon, 26 Aug 2024 13:19:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1724703543; cv=none;
        d=google.com; s=arc-20240605;
        b=IHGijpDHWkTsu7nnARC6y/cZi2OuXAjt4OGHh2drkcLClpxO3bXLQ04BFsQqc1Oaf/
         MP+KuQpx4P2OC0BCploz4BxjrtHYFSazsegkQ0Yc2rlpJn69bcJCDDtsP98AiIjC2N9+
         /U6BUW+jDz+Wx7saXvxuPnjOfo7dIMZ9DVQ0bgaA2jtyzueJXOnW83Ncj2Ff4Mu63Uxp
         czYTMX67KuA0N359sEOlKUDerEH8zUTGDSAQaTM+IA70GPQ/sSaJk0AQG/rRW+3j8fny
         DQ2fe1GII9mwxi8+tzdTQMNAFgX1bNES3kNatYKnwWxijewPEyXcJtH/DZUQlns3sRQl
         T1+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fH/f0aeeE0GvpHSIy7huShE6UD/+U+Xn9Ls2T2sTWWU=;
        fh=Tmr1zlmYjupEfncdXkEHNEQfSbTMyEoEtKT8tNLGuhc=;
        b=G1xrETXItKl9dN8uEk4rbHW29pADF2wEKfGzy5NUjl7cvHFfmqc8ojWJpB2rCxMiWa
         ISeTg/7R+WhNKgvh7Kmrl1NDZEiy8sYh2YAcdJEI73qhG2Qy7W/nXv8JjVkW1F1v/8Da
         Tz6GDPA+mjy6npTs8Xgu/8lHekWYjN2Lrp2RPyigwB7QiY4J9iHrx2h98Has9ztdvr+I
         WHmm9D4YaGkqpEIH9eC7/lFnfmGc6wErSTykqQGMfQsJ4y+An0fAhBK4Dgas8moukSV7
         rHlZIjaaBlW6h7IKcqpnpt0gEucOaBhtWzHc84ZkOWVywoiZB1va4dmWr2Fu0UkOPlgJ
         IeVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=4K1XPzqY;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-42abeba160esi3230005e9.0.2024.08.26.13.19.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Aug 2024 13:19:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-5bebb241fddso1161a12.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Aug 2024 13:19:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVKjOv6mlfONHbO4OujpQi9y1INPmpOvmuggTGclbnvccrxzN+OnWr0aAUrX+O7khVm3IPH9WKSFh8=@googlegroups.com
X-Received: by 2002:a05:6402:510f:b0:58b:15e4:d786 with SMTP id
 4fb4d7f45d1cf-5c0c0b167d8mr602a12.5.1724703541888; Mon, 26 Aug 2024 13:19:01
 -0700 (PDT)
MIME-Version: 1.0
References: <202408251741.4ce3b34e-oliver.sang@intel.com>
In-Reply-To: <202408251741.4ce3b34e-oliver.sang@intel.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Aug 2024 22:18:23 +0200
Message-ID: <CAG48ez1o2GvYuMxox5HngG57CFcZYVJ02PxF_20ELN7e29epCA@mail.gmail.com>
Subject: Re: [linux-next:master] [slub] 3a34e8ea62: BUG:KASAN:slab-use-after-free_in_kmem_cache_rcu_uaf
To: kernel test robot <oliver.sang@intel.com>
Cc: oe-lkp@lists.linux.dev, lkp@intel.com, 
	Linux Memory Management List <linux-mm@kvack.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=4K1XPzqY;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

Hi!

On Sun, Aug 25, 2024 at 11:45=E2=80=AFAM kernel test robot
<oliver.sang@intel.com> wrote:
> Hello,
>
> kernel test robot noticed "BUG:KASAN:slab-use-after-free_in_kmem_cache_rc=
u_uaf" on:
>
> commit: 3a34e8ea62cdeba64a66fa4489059c59ba4ec285 ("slub: Introduce CONFIG=
_SLUB_RCU_DEBUG")
> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git master
>
> [test failed on linux-next/master c79c85875f1af04040fe4492ed94ce37ad729c4=
d]
>
> in testcase: kunit
> version:
> with following parameters:
>
>         group: group-00
>
>
>
> compiler: gcc-12
> test machine: 36 threads 1 sockets Intel(R) Core(TM) i9-10980XE CPU @ 3.0=
0GHz (Cascade Lake) with 128G memory
>
> (please refer to attached dmesg/kmsg for entire log/backtrace)
>
>
>
> If you fix the issue in a separate patch/commit (i.e. not just a new vers=
ion of
> the same patch/commit), kindly add following tags
> | Reported-by: kernel test robot <oliver.sang@intel.com>
> | Closes: https://lore.kernel.org/oe-lkp/202408251741.4ce3b34e-oliver.san=
g@intel.com
>
>
> The kernel config and materials to reproduce are available at:
> https://download.01.org/0day-ci/archive/20240825/202408251741.4ce3b34e-ol=
iver.sang@intel.com

Oh, this is a weird one...

Do you happen to have either the vmlinux ELF file that this issue
happened with, or a version of the bug report that's been run through
scripts/decode_stacktrace.sh, so that we can tell whether the reported
slab-use-after-free is on line 1029 (which would mean that either ASAN
is not tracking the state of the object correctly or the object is
freed earlier than it should) or line 1039 (which would mean the
KUNIT_EXPECT_KASAN_FAIL() is not working at it should)?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez1o2GvYuMxox5HngG57CFcZYVJ02PxF_20ELN7e29epCA%40mail.gmail.=
com.
