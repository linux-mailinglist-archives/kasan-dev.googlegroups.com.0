Return-Path: <kasan-dev+bncBDW2JDUY5AORB2OZ4C6AMGQEULNC3CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D36BA202CE
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2025 02:03:39 +0100 (CET)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-43582d49dacsf34753025e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jan 2025 17:03:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738026218; cv=pass;
        d=google.com; s=arc-20240605;
        b=PypOHypqwE66dXGwH6J1WHmNUW25Bqu55GRBtPUKgFarwX87J+jF+bKLtKsBrflzsZ
         XSUyFvdHBPGBTgYXJ3hqnjlHHhG28D4GaipnuYVhfxcuvMVaEIaJ+7OKvyIT10Do4BP7
         w/Vd7udCCkpHRIH2K3ri2/LzNOxbIQNk+DfiZjM9lY5EsfDE9z3oKMqGw22kW+j8ff1S
         Fdftfps89eq4ouKX8Rte5MD5D33gMVx5exYTVfP/vTqvEYywq7oz2NNAcagENtkx2pw4
         H0lu2cJxG0dzD46RwIZV7O3lKppED/oiP/8faiClfBC7p7YqnvVVuWrIU8AaZ70w5RMK
         BtGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=BMOXhRhXP28TvcEpPkF/9ESxMRGGyGsh/MLPXGY3pMc=;
        fh=8tAd5OpnuyXcorc4SCk+HGImmGWHQFuLLU2n4+ShIDE=;
        b=ZUMnA5mRP+LH2B8K0sCfAA7Ec9lhzTNa+ClCxFXFLSc+r8D+hMoq6qhTRf9OEYd3HS
         nuS3cdwQFMAmubYdsuJgInvPcAMYHR5toRmx/eZIRWwCLnwjHpyTQqxG1cPousB8aG0T
         X66nrtkVKH6qdTZCjgFWwCA83FaJTKV7TN/OrwXK4ph9yqsJC4G05yRMovtnGmrPt9fU
         dxzV/qRlCMupcmTnvYNRYmu3yFvQqn7rmclfVedF7+eDjTlMp6jXOUoGcDaS3xYbSg+R
         Aae0sdgi/rvuF6nB8ZFPkJXfHOMKvpoqK1bom8q7uGXbu62ey0sm5yLWh6jusK1dFEVf
         oDww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Pb7VZjaH;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738026218; x=1738631018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BMOXhRhXP28TvcEpPkF/9ESxMRGGyGsh/MLPXGY3pMc=;
        b=Tnr7DSadu2cj7AsWGac7GgERVXLYmjVK3WiM01B/l39wvZBJlu7UD/c0HiykLaOdMs
         aSENk2v1OtBrwxE0Pgi2UpUW0TVMh9vA5Q33uNES+1NLlj0HmFxOK4mI1XEK98BUCzCm
         MIak8DJUK0SbZVvUvj76ydhPMzrUhhJ/bHN+PpBbDbfRcReEkv6GTxpGwZhinxIfESFK
         hOMcqEUsVeDaMeZy2GIwxYLtrQwlpPQ70PRujuBLxpgkY8TV9hRkWo4Xfw0BJJQ7YFAJ
         Dn9hB0vSOrJsoK9Xnu2x3iuY893HS5yCOWMTKI+QFWgzag3MLTqhS0FRV/tq11mpNdH1
         ir/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738026218; x=1738631018; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BMOXhRhXP28TvcEpPkF/9ESxMRGGyGsh/MLPXGY3pMc=;
        b=Ru777UCiOBZI0KQLezdIhQgej1SbRltRoSMY51/z5WLi6lhLHjxHVXceVXUlgWwyLL
         Ts8aX9od9di3nkw8FgNleXzXNrLe90nLRa82TY+hyuE1o2RF2msCJ1qleTxMxHqIfqO2
         yelwnKzc2aneENFlM5DG0RKjrJLDSTMpN0ntGDWPyGD1I/jiwbGTkmLGsNMIhMTw6Fvj
         YCr9beW2JJ+6DfHHRgVRDWqMmfHrXFrlC4cfSTXBR+1URQy09TBceWo8pHgVIwBEzKfp
         9qTY/E2Qq7DReCbINQNbeypoJhFXsGGoHALL6PpOQ7Ad+Co/QZoCzJBajO+BAKSu/k1I
         P4iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738026218; x=1738631018;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BMOXhRhXP28TvcEpPkF/9ESxMRGGyGsh/MLPXGY3pMc=;
        b=IOQrAR4+h/bDlV56y/jXEea8d1RKyCHF+QgNKuIu6HbBeOBwVr5nwPn0V1KyVUJAbJ
         hagErB2FBghgir4svuQVWct8fnhitfee5pTjX4aS/KtbLLNTIVIT5YcvQjb+qyDYG/6L
         UqVrOCKvvMT4R/CpPNPTQaNFv8w6v9oGhD2PmadkJSJaJzdMehR2APXmvVnx1S3DlE43
         vLYLgsGOC3zHKFOyn3ZcJk6xDEGcMYCNK6xuXAb/b3ShS4SUjot54B6quX8GXWJ41MtI
         uWrN9UzfGBFqpUGkJpW+cc8s24/IeIMRT7O04NIrAsm61NqFlVS9S8028Wtj2F6jXLzS
         Wnbw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU5kNv8GYXbXyKBccuxmUTs7ENDs+6bC3or5y0nUy6/nfc2DtUTe8zQEcqeIbQ8SEtSW642ow==@lfdr.de
X-Gm-Message-State: AOJu0YwrhK2KIuLxk89dLsBBs1Xufwa75J5D3fbicQuf1Nzmocjuv0b0
	LBzYaAocUN+BWGVmFNWqukGo6TkaNANiz9ZQWsgqCovCOWMLvJ67
X-Google-Smtp-Source: AGHT+IHxLD1XF7F0dqbhJv+lzwz/YB3cRZ2zBNooy3LDbS0nYG4O00BJkTxJRbPt/sHCygOS3HC+6w==
X-Received: by 2002:a05:600c:6c06:b0:436:e8b4:36e7 with SMTP id 5b1f17b1804b1-438913cb191mr367354665e9.8.1738026217641;
        Mon, 27 Jan 2025 17:03:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3511:b0:436:8a89:bfe6 with SMTP id
 5b1f17b1804b1-438b875f73bls4952905e9.1.-pod-prod-09-eu; Mon, 27 Jan 2025
 17:03:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU4n5K5baiY1voTwW9jLqVn4N7abFpuF+POc5G22SsT4ujuQpDcw3Jqe/boRJJSy+/jB+Mlde644wo=@googlegroups.com
X-Received: by 2002:adf:ef04:0:b0:385:f23a:2fe1 with SMTP id ffacd0b85a97d-38bf566f7c9mr27110288f8f.26.1738026215423;
        Mon, 27 Jan 2025 17:03:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738026215; cv=none;
        d=google.com; s=arc-20240605;
        b=CCMA/o3QWTJaY3plLEMSEEbHPJXUGWL+bC5OXnQYzIZ2a1UaCtyfSJ6kgV4B3IodCB
         zygmJEQ++7b5qYduibl3V6G098ZK4niQKIjMbLQXCo9mUvuZXBgGHR3KhbmoZYBHPAa9
         aTtV3pOS/F0Vtuhh+dEbzrOBjJiobmG809EhKNiQgzkIY6lO587WXfnlKhwcNxvZ6UAX
         gxT8Ztsmr9cJBSB8X8WS9ELN8EsiJlzVvxTEZDCbsrmV8XRxGgSF3EUBZpPl9xscCAsi
         f95ZDMRZ8OJ/qc3B8s3LoSvFBF4oYoK258cdIsnrEG8zdSh6LbWk+ZXEI2sc1xewEO/a
         xPig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rhmkjsOBo2Z/j8AVygLCN1cexQOSzzXPKI5vQhYu1KU=;
        fh=N8NGCNYSnxhikpdOzBzwV14H3C4JBltT2093+EcFS1U=;
        b=FOf3nMd/DnjWAYLz5Bn29axHkunatxYALr1U4Q6y7cj6l2akj7RWvSyNIdvfNDdtEN
         /lb+TAIxpujwlFsjdFVc/+O8Imq3cczKgWx0qJbpX5LcKwcF6cSs0zgCqTdceKJBwhZq
         Oj8x//YuTy8J1wIBg0QiJzRXXAjSulWdCKreTaskencDvcMd3YM+PoJcETo/wLqIPCQr
         QjtykUOsXY4cUdeQXQSvMekC5bQf6xJQmo3OKDorCe09ejuMqBMGv4vvLUxB1fFcAVWF
         ewswDd/wP1VS6jMnIj2AxmZ0WXj4I8R/DoOrPC2HWpRrI1zy9/5svsiBISd7Da4nJ3E3
         LHsA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Pb7VZjaH;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-38c2a1790e2si118358f8f.2.2025.01.27.17.03.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 27 Jan 2025 17:03:35 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-4361f664af5so58254095e9.1
        for <kasan-dev@googlegroups.com>; Mon, 27 Jan 2025 17:03:35 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUhg6ky0WcLVGIBcUEcHXg00icsu3B//0ynRGtpyVQTA3GzszKxMJK/JGe9ufCjkLMKqVtgefwipVI=@googlegroups.com
X-Gm-Gg: ASbGncvGyTZOReL66sKGc1zYFg8d7BSOlSWHdoZUz5xunedJ3TvYFuFLga6Zmm3U7Bf
	Oirzpx/r6HEYmDBrD7s3gha8JpWT1hzHKSAB6SXV5jEDcN+6VrYk6ym7MQJGbQRUM
X-Received: by 2002:a5d:59a3:0:b0:38c:2745:2dd8 with SMTP id
 ffacd0b85a97d-38c27452f9amr14952851f8f.37.1738026214807; Mon, 27 Jan 2025
 17:03:34 -0800 (PST)
MIME-Version: 1.0
References: <20250122160645.28926-1-ryabinin.a.a@gmail.com> <20250127150357.13565-1-ryabinin.a.a@gmail.com>
In-Reply-To: <20250127150357.13565-1-ryabinin.a.a@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 28 Jan 2025 02:03:24 +0100
X-Gm-Features: AWEUYZmeJLtK41LtsCBto-t2LF1U1pFl4f5DNAiSNd3CvJ2BmMeJGFRaWxwbPLE
Message-ID: <CA+fCnZck1nvDZaq9JwOMG6pBR+Uy3gHRAOM67UvDxxLzqChsug@mail.gmail.com>
Subject: Re: [PATCH v2] kasan, mempool: don't store free stacktrace in
 io_alloc_cache objects.
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	io-uring@vger.kernel.org, linux-mm@kvack.org, netdev@vger.kernel.org, 
	linux-kernel@vger.kernel.org, juntong.deng@outlook.com, lizetao1@huawei.com, 
	stable@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Jens Axboe <axboe@kernel.dk>, Pavel Begunkov <asml.silence@gmail.com>, 
	"David S. Miller" <davem@davemloft.net>, Eric Dumazet <edumazet@google.com>, 
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, Simon Horman <horms@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Pb7VZjaH;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::332
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

On Mon, Jan 27, 2025 at 4:05=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
.com> wrote:
>
> Running the testcase liburing/accept-reust.t with CONFIG_KASAN=3Dy and
> CONFIG_KASAN_EXTRA_INFO=3Dy leads to the following crash:
>
>     Unable to handle kernel paging request at virtual address 00000c64550=
08008
>     ...
>     pc : __kasan_mempool_unpoison_object+0x38/0x170
>     lr : io_netmsg_cache_free+0x8c/0x180
>     ...
>     Call trace:
>      __kasan_mempool_unpoison_object+0x38/0x170 (P)
>      io_netmsg_cache_free+0x8c/0x180
>      io_ring_exit_work+0xd4c/0x13a0
>      process_one_work+0x52c/0x1000
>      worker_thread+0x830/0xdc0
>      kthread+0x2bc/0x348
>      ret_from_fork+0x10/0x20
>
> Since the commit b556a462eb8d ("kasan: save free stack traces for slab me=
mpools")
> kasan_mempool_poison_object() stores some info inside an object.
> It was expected that the object must be reinitialized after
> kasan_mempool_unpoison_object() call, and this is what happens in the
> most of use cases.
>
> However io_uring code expects that io_alloc_cache_put/get doesn't modify
> the object, so kasan_mempool_poison_object() end up corrupting it leading
> to crash later.
>
> Add @notrack argument to kasan_mempool_poison_object() call to tell
> KASAN to avoid storing info in objects for io_uring use case.
>
> Reported-by: lizetao <lizetao1@huawei.com>
> Closes: https://lkml.kernel.org/r/ec2a6ca08c614c10853fbb1270296ac4@huawei=
.com
> Fixes: b556a462eb8d ("kasan: save free stack traces for slab mempools")
> Cc: stable@vger.kernel.org
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Jens Axboe <axboe@kernel.dk>
> Cc: Pavel Begunkov <asml.silence@gmail.com>
> Cc: "David S. Miller" <davem@davemloft.net>
> Cc: Eric Dumazet <edumazet@google.com>
> Cc: Jakub Kicinski <kuba@kernel.org>
> Cc: Paolo Abeni <pabeni@redhat.com>
> Cc: Simon Horman <horms@kernel.org>
> Signed-off-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> ---
>  - Changes since v1:
>     s/true/false @notrack in __kasan_slab_free() per @andreyknvl
>
>  include/linux/kasan.h  | 13 +++++++------
>  io_uring/alloc_cache.h |  2 +-
>  io_uring/net.c         |  2 +-
>  io_uring/rw.c          |  2 +-
>  mm/kasan/common.c      | 11 ++++++-----
>  mm/mempool.c           |  2 +-
>  net/core/skbuff.c      |  2 +-
>  7 files changed, 18 insertions(+), 16 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 890011071f2b..4d0bf4af399d 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -328,18 +328,19 @@ static __always_inline void kasan_mempool_unpoison_=
pages(struct page *page,
>                 __kasan_mempool_unpoison_pages(page, order, _RET_IP_);
>  }
>
> -bool __kasan_mempool_poison_object(void *ptr, unsigned long ip);
> +bool __kasan_mempool_poison_object(void *ptr, bool notrack, unsigned lon=
g ip);
>  /**
>   * kasan_mempool_poison_object - Check and poison a mempool slab allocat=
ion.
>   * @ptr: Pointer to the slab allocation.
> + * @notrack: Don't record stack trace of this call in the object.
>   *
>   * This function is intended for kernel subsystems that cache slab alloc=
ations
>   * to reuse them instead of freeing them back to the slab allocator (e.g=
.
>   * mempool).
>   *
>   * This function poisons a slab allocation and saves a free stack trace =
for it
> - * without initializing the allocation's memory and without putting it i=
nto the
> - * quarantine (for the Generic mode).
> + * (if @notrack =3D=3D false) without initializing the allocation's memo=
ry and
> + * without putting it into the quarantine (for the Generic mode).
>   *
>   * This function also performs checks to detect double-free and invalid-=
free
>   * bugs and reports them. The caller can use the return value of this fu=
nction
> @@ -354,10 +355,10 @@ bool __kasan_mempool_poison_object(void *ptr, unsig=
ned long ip);
>   *
>   * Return: true if the allocation can be safely reused; false otherwise.
>   */
> -static __always_inline bool kasan_mempool_poison_object(void *ptr)
> +static __always_inline bool kasan_mempool_poison_object(void *ptr, bool =
notrack)
>  {
>         if (kasan_enabled())
> -               return __kasan_mempool_poison_object(ptr, _RET_IP_);
> +               return __kasan_mempool_poison_object(ptr, notrack, _RET_I=
P_);
>         return true;
>  }
>
> @@ -456,7 +457,7 @@ static inline bool kasan_mempool_poison_pages(struct =
page *page, unsigned int or
>         return true;
>  }
>  static inline void kasan_mempool_unpoison_pages(struct page *page, unsig=
ned int order) {}
> -static inline bool kasan_mempool_poison_object(void *ptr)
> +static inline bool kasan_mempool_poison_object(void *ptr, bool notrack)
>  {
>         return true;
>  }
> diff --git a/io_uring/alloc_cache.h b/io_uring/alloc_cache.h
> index a3a8cfec32ce..dd508dddea33 100644
> --- a/io_uring/alloc_cache.h
> +++ b/io_uring/alloc_cache.h
> @@ -10,7 +10,7 @@ static inline bool io_alloc_cache_put(struct io_alloc_c=
ache *cache,
>                                       void *entry)
>  {
>         if (cache->nr_cached < cache->max_cached) {
> -               if (!kasan_mempool_poison_object(entry))
> +               if (!kasan_mempool_poison_object(entry, true))
>                         return false;
>                 cache->entries[cache->nr_cached++] =3D entry;
>                 return true;
> diff --git a/io_uring/net.c b/io_uring/net.c
> index 85f55fbc25c9..a954e37c7fd3 100644
> --- a/io_uring/net.c
> +++ b/io_uring/net.c
> @@ -149,7 +149,7 @@ static void io_netmsg_recycle(struct io_kiocb *req, u=
nsigned int issue_flags)
>         iov =3D hdr->free_iov;
>         if (io_alloc_cache_put(&req->ctx->netmsg_cache, hdr)) {
>                 if (iov)
> -                       kasan_mempool_poison_object(iov);
> +                       kasan_mempool_poison_object(iov, true);
>                 req->async_data =3D NULL;
>                 req->flags &=3D ~REQ_F_ASYNC_DATA;
>         }
> diff --git a/io_uring/rw.c b/io_uring/rw.c
> index a9a2733be842..cba475003ba7 100644
> --- a/io_uring/rw.c
> +++ b/io_uring/rw.c
> @@ -167,7 +167,7 @@ static void io_rw_recycle(struct io_kiocb *req, unsig=
ned int issue_flags)
>         iov =3D rw->free_iovec;
>         if (io_alloc_cache_put(&req->ctx->rw_cache, rw)) {
>                 if (iov)
> -                       kasan_mempool_poison_object(iov);
> +                       kasan_mempool_poison_object(iov, true);
>                 req->async_data =3D NULL;
>                 req->flags &=3D ~REQ_F_ASYNC_DATA;
>         }
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index ed4873e18c75..f08752dcd50b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -230,7 +230,8 @@ static bool check_slab_allocation(struct kmem_cache *=
cache, void *object,
>  }
>
>  static inline void poison_slab_object(struct kmem_cache *cache, void *ob=
ject,
> -                                     bool init, bool still_accessible)
> +                                     bool init, bool still_accessible,
> +                                     bool notrack)
>  {
>         void *tagged_object =3D object;
>
> @@ -243,7 +244,7 @@ static inline void poison_slab_object(struct kmem_cac=
he *cache, void *object,
>         kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_S=
IZE),
>                         KASAN_SLAB_FREE, init);
>
> -       if (kasan_stack_collection_enabled())
> +       if (kasan_stack_collection_enabled() && !notrack)
>                 kasan_save_free_info(cache, tagged_object);
>  }
>
> @@ -261,7 +262,7 @@ bool __kasan_slab_free(struct kmem_cache *cache, void=
 *object, bool init,
>         if (!kasan_arch_is_ready() || is_kfence_address(object))
>                 return false;
>
> -       poison_slab_object(cache, object, init, still_accessible);
> +       poison_slab_object(cache, object, init, still_accessible, false);
>
>         /*
>          * If the object is put into quarantine, do not let slab put the =
object
> @@ -495,7 +496,7 @@ void __kasan_mempool_unpoison_pages(struct page *page=
, unsigned int order,
>         __kasan_unpoison_pages(page, order, false);
>  }
>
> -bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
> +bool __kasan_mempool_poison_object(void *ptr, bool notrack, unsigned lon=
g ip)
>  {
>         struct folio *folio =3D virt_to_folio(ptr);
>         struct slab *slab;
> @@ -519,7 +520,7 @@ bool __kasan_mempool_poison_object(void *ptr, unsigne=
d long ip)
>         if (check_slab_allocation(slab->slab_cache, ptr, ip))
>                 return false;
>
> -       poison_slab_object(slab->slab_cache, ptr, false, false);
> +       poison_slab_object(slab->slab_cache, ptr, false, false, notrack);
>         return true;
>  }
>
> diff --git a/mm/mempool.c b/mm/mempool.c
> index 3223337135d0..283df5d2b995 100644
> --- a/mm/mempool.c
> +++ b/mm/mempool.c
> @@ -115,7 +115,7 @@ static inline void poison_element(mempool_t *pool, vo=
id *element)
>  static __always_inline bool kasan_poison_element(mempool_t *pool, void *=
element)
>  {
>         if (pool->alloc =3D=3D mempool_alloc_slab || pool->alloc =3D=3D m=
empool_kmalloc)
> -               return kasan_mempool_poison_object(element);
> +               return kasan_mempool_poison_object(element, false);
>         else if (pool->alloc =3D=3D mempool_alloc_pages)
>                 return kasan_mempool_poison_pages(element,
>                                                 (unsigned long)pool->pool=
_data);
> diff --git a/net/core/skbuff.c b/net/core/skbuff.c
> index a441613a1e6c..c9f58a698bb7 100644
> --- a/net/core/skbuff.c
> +++ b/net/core/skbuff.c
> @@ -1457,7 +1457,7 @@ static void napi_skb_cache_put(struct sk_buff *skb)
>         struct napi_alloc_cache *nc =3D this_cpu_ptr(&napi_alloc_cache);
>         u32 i;
>
> -       if (!kasan_mempool_poison_object(skb))
> +       if (!kasan_mempool_poison_object(skb, false))
>                 return;
>
>         local_lock_nested_bh(&napi_alloc_cache.bh_lock);
> --
> 2.45.3
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZck1nvDZaq9JwOMG6pBR%2BUy3gHRAOM67UvDxxLzqChsug%40mail.gmail.com.
