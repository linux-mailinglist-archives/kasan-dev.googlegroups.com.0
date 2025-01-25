Return-Path: <kasan-dev+bncBDW2JDUY5AORBVGU2C6AMGQEQMQXV6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id ABEC9A1BF82
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Jan 2025 01:03:34 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-43623bf2a83sf21254995e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 16:03:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737763414; cv=pass;
        d=google.com; s=arc-20240605;
        b=W8qs8i+G7tjpL6/gyYD89iohsNaYeVpilZQS8hDcjWzSlnmkh2PpiDB1lwLTQOG1iF
         1ngqBzx0FT+9139LLnyFVZQQ8JzIy+L24mzhKjv2xZ1RRkzLUqiwnxzu0cDGoF6ZEhIb
         OKeED7wjhATcMdh6pwACv+cGEkyWvohoRz/yDVXLIMDqsb7tCaCQwo7zKK9QJogVm+y2
         mGZ/IOawdK/tIwx2aPxXrhaYWhtgS+cCTOM3/p0/zXLt6SmdP7KBTQpGqnCKis9K9BJ6
         ZFa3bxRFxqqxmsZA680/wIze983V+goTbupSNsq489LaYVtOa/DDl3t3+T7+nvj+qJPH
         LmCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=gbv0I1b72PZv+rou/07gyHhjnEOvSDz9KHv7cxaFLq4=;
        fh=w96hz/L0YUp0PM1SwBexf3khqawUTnHovF3O/joAegs=;
        b=lDCblxB8SLuDsmMQEWw1gI8ed0GttyGUO+JAQqHOleLuTRpS+f1IbIdEmP1a7RlQe0
         KO3CF0TEyxAUwL5JSMawyLFuG+vscuAIeUtPHgOvYp2y2jN/UEZDIAnOJv3+wU90RX4R
         jANgvOrEhAvFs57uAur805Fqh2iupPi6r+Qk0qTaqlGCilFxFDL8INSGt5WAkWC5jc6/
         vJE7Y/4fKDlZoSZVaDdiO4AfVpDkU9UZPvw+Wj7YAHFtxxTDOo/S1m2qj3+XBzffe+T/
         g08BckU9WsKc3chjoWZqWGfwXHQapvIvwbJvTQ+czFRd4F47N0S6itzIBdtyb323ItCS
         4oUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WLazIPzd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737763414; x=1738368214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=gbv0I1b72PZv+rou/07gyHhjnEOvSDz9KHv7cxaFLq4=;
        b=R8eF6T9meCSFIS+PuCL5wfd7ZwrvIA8peVN53Kop+s4Xys1GdnFKG+0DX6+ajdjnen
         +a7SHIPBFpHvmNUuffFS73SBC8+9U7p3MrGV+qvfEOz65i8fruPLbTqy5vOrQtvMdLiX
         7tqsI4/jXNTaBl+JD8yOwM6K1XCgDK0OzCmyARxI/EN+2b+fJYk7lrJvJ29NMkAHwpIU
         A8QAUVc/998hQ2f7pKBQmg9X9fvQInGQPenGHfn/Hf7f5wBR6HtrHp9JwtGn5RrYWlkJ
         x7i6eHGOpRC+ib6guFDXQkH9CH46yMf6xr/TeO1/4dhVCqGclccQlO7EBLU3Tu/+A+W0
         lzqg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1737763414; x=1738368214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gbv0I1b72PZv+rou/07gyHhjnEOvSDz9KHv7cxaFLq4=;
        b=HntV4tGJZsnbpw/zXD7rLu24Dn0+vBc6R3Fpqt1GFJQH5MRGQW8zBfDDaKTJFFM1aW
         XbrhkP0dYxwIkFvJz2/5Vh0tfyYmXCzRPR4r+E2UWANy/rEnPN2eZIn8gKO1v70kgljq
         TDuxxQXU2ALYjBAtKWAA5AWtPAKQ2XUM2rfK2lDvb0wW1f0BS/qeNa5LC922WiFXG44+
         3rJsszYWPETy6MpK6SQwYBXxRDwHo6OSOQoCGV0akTPT7bvRWzuSZoASWubikUzBerz4
         QNFJmlk55RqPPaWk6bURRpluY76mcw1n8aVC93G5rLlP326/Geyhke8OGhjTBZfB73H2
         nUBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737763414; x=1738368214;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=gbv0I1b72PZv+rou/07gyHhjnEOvSDz9KHv7cxaFLq4=;
        b=HZPZnzMyXckf6B3HnfLrD1Q4b0MA29X8U94ZKijESNoGqfhaGwS9iQEIjdTYLlaqkM
         9LAWsRC4WFD1sNp9UAvXpyuRamvLlfZ3tHR6GyTyPfkL7H+ucAQ8Qp8gOuPmOCDXYUbB
         B61FPvhhuv0EaEmQ6lAN08XJ/LY0ZMuNnHyqGKHtVaQuibJgCd/lInK2WJD8kig4jF1x
         mF+d6vgmsNftKEYuOzhM0pbFRK53Dn4E7/KIOn4ye28yf3GkG3U8PuEG/aToiVNHEPI9
         3APjzmoVWesiICaO3KgqmQnarc2dm1fzArHWw+xuAVCC0eTaEcj5DFWkC/ka73Ek/nmt
         YZow==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbQzM4re28Wn0T0Jy1U/Ayiqn9tuM0ATERNCInZq7VYv01IeetlMEbqsBVQEWKe5TyjEs1eg==@lfdr.de
X-Gm-Message-State: AOJu0YyYRr6LCF7YsyLATF2IBxSJbYEBEGSBZUrjKmUEAGJtznZ/6HBL
	PAT6uox4WAiggD5GyDSiS10kxNZJ5CZQE2ruYi/t8lMOU6lWFtq9
X-Google-Smtp-Source: AGHT+IHB8d8u6A2IDl45lwyoO94k2QTjyiu+GNJxcuJyWAL32dvE+XOMc3uHDWD5p/fXqTGr2d9G7A==
X-Received: by 2002:a05:600c:1c84:b0:434:a94f:f8a9 with SMTP id 5b1f17b1804b1-4389144fa26mr274141615e9.28.1737763412659;
        Fri, 24 Jan 2025 16:03:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:22c9:b0:436:5165:f202 with SMTP id
 5b1f17b1804b1-438b87b081dls8854685e9.1.-pod-prod-02-eu; Fri, 24 Jan 2025
 16:03:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbMEuZWdasJbvPNWC0ngdmjB9zh20/lGE2Cmy9qSvLrywrwJI3cahSfZs4cd8IkKh4rB5SZI2L+IY=@googlegroups.com
X-Received: by 2002:a05:600c:6a94:b0:434:f753:600f with SMTP id 5b1f17b1804b1-438914376b1mr279748745e9.19.1737763410334;
        Fri, 24 Jan 2025 16:03:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737763410; cv=none;
        d=google.com; s=arc-20240605;
        b=OgqSrA1yXwlzeLzMHCd7YVut5rh4SEXCt2MB+9TdmWZrnMdOGNaCZEsLaLFxoE8nqy
         F+AVKStbSoKVDaU//5kY+Rvo5jnzSOPyHOzFsnI0tu1tXodX9nCh1RLluw9bRxIO1o7b
         4fjwGfivDOdcumq7mVYKdKS1PyCvImggwJf6UyGpwBb1zj+aHv7swJSLkFYU4ENCYdQr
         61DqtR6cmB69qD3H/kbRJi4LezlUU+dnAxH1nFfbOM04iRK3yVUOjykr1x+sCSHRAB1J
         5XF/rEaI+p3U/fET52uESw1YNDNYDGrF3RQyasPSPeujjMVms6RWlt4fjfIsdfpZaNG4
         xkmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LvkUz6rrh40BWkmgbM3RB98m2jGyTmY3Ec69ZV7r1sE=;
        fh=RRtauvCML565xLtbNKhk1yxBJFEhSOpHRjgz+zTHEf4=;
        b=Puiwdv9YQaJrJZsKeRx5xrv6ZqJBVcCBPhVuKPRfwVK88IyHr4J7h6CTod4QJt9Ipi
         YZl/1/7LWy1fb3ogVD+bsAD8om1AwUjghy3sWET19fYF+p/nBCVC1WNmdaVcqvDMDvfo
         VwkvT6q25i1X9AspjH/WmVH6Eq0/WAqmNEhnI2h3Od2Md5vBkdV58uVZe60958vANv3F
         55Q//U9Tv/dxQQhB5QMhTbCzQb1TVEImw2Za2bUENqBEGadpvVrcBubBk9af9Syis/hQ
         o+6NUvzb8zburhFDQuOkadf0nXdGwiqZ3SL8Yl9G9g0GGETVttknie6oRCKB4AKqOvZ/
         /aNg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WLazIPzd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-438b1cc75c2si3134535e9.1.2025.01.24.16.03.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jan 2025 16:03:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-385e27c75f4so2340197f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 24 Jan 2025 16:03:30 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUxn7kJyPk4/VITMD4z35VFPJZCrRD9m+11OuvwWltq6DwPNa/3/wY/r0dSIzZJAiF3CZzXSnGrP7Y=@googlegroups.com
X-Gm-Gg: ASbGncvnW+4L/PQ1fUx5KcwfeMi1PiPr7AFzvnOgiBr0QB4HgMsMFMxngkPWN6D2xHn
	Bq4pKgGyLLPigr/WA+ZHNI4xYJnrAHXIKC9I1/RBOJ1B71J5Idp5Hxe2GkR6lTKHpuIJLS/ujR4
	k=
X-Received: by 2002:a5d:64eb:0:b0:385:df4e:3645 with SMTP id
 ffacd0b85a97d-38bf59ecb69mr32501744f8f.50.1737763409484; Fri, 24 Jan 2025
 16:03:29 -0800 (PST)
MIME-Version: 1.0
References: <CAPAsAGwzBeGXbVtWtZKhbUDbD4b4PtgAS9MJYU2kkiNHgyKpfQ@mail.gmail.com>
 <20250122160645.28926-1-ryabinin.a.a@gmail.com>
In-Reply-To: <20250122160645.28926-1-ryabinin.a.a@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 25 Jan 2025 01:03:18 +0100
X-Gm-Features: AWEUYZldK5UH-Z3qoetD2eelx-La3CJnQOnijzUbA8Se3XdD6uoFtorpaKUcIs0
Message-ID: <CA+fCnZdU2GdAw4eUk9b3Ox8_nLXv-s4isxdoTXePU2J6x5pcGw@mail.gmail.com>
Subject: Re: [PATCH] kasan, mempool: don't store free stacktrace in
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
 header.i=@gmail.com header.s=20230601 header.b=WLazIPzd;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::433
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

On Wed, Jan 22, 2025 at 5:07=E2=80=AFPM Andrey Ryabinin <ryabinin.a.a@gmail=
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
> index ed4873e18c75..e7b54aa9494e 100644
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
> +       poison_slab_object(cache, object, init, still_accessible, true);

Should notrack be false here?

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

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdU2GdAw4eUk9b3Ox8_nLXv-s4isxdoTXePU2J6x5pcGw%40mail.gmail.com.
