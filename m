Return-Path: <kasan-dev+bncBCVJFSG3KIILLLUHSUDBUBERRIURS@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id DC8B25449D8
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:19:18 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id h189-20020a1c21c6000000b0039c65f0e4ccsf1433922wmh.2
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:19:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654773558; cv=pass;
        d=google.com; s=arc-20160816;
        b=I/zkHPH/9rad5uWs2qFemZk7Sp0GZGYvVIVs93pfSAzP9Us0bytH3B+LBxRG+h85VN
         dpOSnFJZ2pjkzvveBe+mKNOWQl60sI5+HNtFYvxgLAo9StiRHhpW2AVsmUto7YNJJfbT
         raCe0Z+PBIRiXEFY8gS4zXW6Ne0qYmAyPBYv8eAoXhDslyf8lY4kjnd0L6QKN+gqG/vP
         UBdZMra1MlCrTFIZQ8inBFcfX281qFOUGUXzEeQPZzOVzkD18ARw3vxOd1oyF33nFb0b
         yGD4qEvmO8tpKGpLJqKPJkHXXf9M6HKgHkRbAfQ/2Xjn9mW0AkVWF11VqzLuKzbaX0X5
         Tiwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=FpfYsVfpgB86LqhnMfEIMubMw/W+JKABSgtT5G3zB5Y=;
        b=c+nzEXW7xKnpw3HvvgNzpDDRpf6FNPAS66Yua/Nvl4TabMouzr91L/mGlh5AN1Y5Td
         dd21vgOgSlhCI3jHzX3qSkSCihbndItK/hqe5kkd04ZNeONjmENyumeTgNxvY+N8Dawz
         8rjba3XW89Xd6LQkYsZ8J/GD0aSPmUSZbfY8ZbqbdNQyATPgXO/ORxs2Yx2JSGH/OlXE
         arrMN2YdGqhhuxOT/L7fHIMxje6my+ZUyBSvCiIlgjWh/cfOBii7jmJt/7TvM+T9uHF1
         i4W2AFcCIFduVFQR5CDWNluv5Ld/qPPMvhlTbwoUH193BS9spmZHHfZESHh5v4zzwqCx
         iQ7Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=JnUH5R2k;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=N8p5zbYz;
       spf=pass (google.com: domain of john.ogness@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=john.ogness@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FpfYsVfpgB86LqhnMfEIMubMw/W+JKABSgtT5G3zB5Y=;
        b=VdUWMoqXAm9RQYsz43WFp4jBflV6fRZZzi9oQGQqXgJX7iHNiWIEe4AwF15JDIcUV2
         /kMy6Rx/TACuxGBIZBRU/N4ir7NrbKv+yKtR1flV9dUhNKKTFgXDX3akgmVUvls0tS8K
         uV7QDSSBoE08IiEy3ZruUeD0qk7gHPOt9cPrIvYrDX9MRwRJVPsmYz5BCzdu57qnH1Ia
         KZBmOcXl4/aZm6UGYVm+ky2Tw/7Etkz0a7GPzhlXOXBFQnevItg7/kyv9Ftt+C+jl32k
         6VsXWENbK14gsA7//x+u/H6lH3S9Tui4zRVZ5fkk4R4wFOA1fOmf0yoTqOzBt8uDfyGO
         ek2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FpfYsVfpgB86LqhnMfEIMubMw/W+JKABSgtT5G3zB5Y=;
        b=e54LDVdDR6wyOjyZYIoJcbN+WzmDlhPwgrewHi4RDNUYBHJneY350saKzHwHZovmtc
         Z9selM4qy8DxbXYIQxErWJyTvn/yCtljUB6vCCOdRyHVF5fgR2ON98QF+UB7UIarBbpF
         m/mRhbiZLFEDCpOxhm7AyMk7Y583+Q7xGGH2cOq9WA3oHTuY2LiGXGF2/mSkvVAG36MC
         lW9rz2+eBddelrcY1flwkxWDgQUYldhlM9RHj7VJCL8oD/jdlscusjcH01miV/HHCQW0
         p3q9bu6wmnVcEk2RNmfFVAC20ESMWPUud0Cu/T6Bv1gEcqKZXf3XXX5gtc2BUhomjDm7
         yDdw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5310QU4KElUVUFywIfZGlRjkeWprE4BaDJumy1DbbvbBgttL6jWr
	Zrfu5tP2c3WVCl0+NZTHLH4=
X-Google-Smtp-Source: ABdhPJx3toqSGCngbgjxNeg3VrH8ONepZ/i07EHvXQhlsonG9rjoagcxpCMu5l0WDMUViQnRc3OrpQ==
X-Received: by 2002:a05:600c:49a2:b0:39c:5d0d:2e29 with SMTP id h34-20020a05600c49a200b0039c5d0d2e29mr2683332wmp.95.1654773558134;
        Thu, 09 Jun 2022 04:19:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3d8c:b0:39c:5b80:3b5c with SMTP id
 bi12-20020a05600c3d8c00b0039c5b803b5cls722057wmb.2.gmail; Thu, 09 Jun 2022
 04:19:16 -0700 (PDT)
X-Received: by 2002:a05:600c:4e90:b0:39c:5873:42a0 with SMTP id f16-20020a05600c4e9000b0039c587342a0mr2907735wmq.176.1654773556938;
        Thu, 09 Jun 2022 04:19:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654773556; cv=none;
        d=google.com; s=arc-20160816;
        b=ARHM8/UhyrFpuok2V2NQn1hwb1A7AK3Jqyl4kxjwWx+vcse66nq9CSSd3myZIxplKa
         pkbPPwbeSDkxMnH3lnGqoCZU5iquzwH2qBv3Yn1GHJgNraca/M6r2DAx+0yCl4oS9egD
         nBVIcjQ+nmRAbYMQGJV8igly07/fEXAReBo2sliKbb1bCKEfk7HyYCSK9nd36W3vHiHR
         g1LwItQfiIcu312c4KsOhlrgy1UTkuBt+bHf8ByLX/isqMVpMxNVZh3oqwi27+QSXOV+
         qD/idoMjLymU2Q60gtXq5hubdO34CrHhIjRy05mO/u/VqkGJsMjAo8a8AKsqz/wfqtFE
         04YQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=1WfcyJ5/Z+Ptknrmt9EKb2lYt88mTxvWrPcDw1CBGnQ=;
        b=y6DHBVTK9E33AQD6rdjxCjfQny29CcBPDlSLU/Il+B7OTaaHKSGMrvuk7Fe+ixutbB
         XM+T59eVM/+mnXJmUrbBxNtfttDYGFaCABQf1AKdCvcEOg7A+JhSEndnuW2xGACRFBz9
         /e/ZsTrU4CX6UnmzTKrzWcunXE/Fu7SfgApBWIHkyMXPAgxK9S4iCKoTLx3DKyHN7Dlz
         Ytt2gGhWfi4kaXKtNTxtaS21A1xkEZ0OGwV5/nhdAkfp0uDZWAgQ/oxlM5L1yNmyLvwd
         AUfh740rWqSmEE3ak50tMCWZO06pgUIHuVsyvoC+Ybl2DUR/xs2dKvmVm2n9pBdaJg7I
         69Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=JnUH5R2k;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=N8p5zbYz;
       spf=pass (google.com: domain of john.ogness@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=john.ogness@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id co19-20020a0560000a1300b002185f697309si160228wrb.5.2022.06.09.04.19.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Jun 2022 04:19:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of john.ogness@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
From: John Ogness <john.ogness@linutronix.de>
To: Geert Uytterhoeven <geert@linux-m68k.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Petr Mladek <pmladek@suse.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"open list:ARM/Amlogic Meson..." <linux-amlogic@lists.infradead.org>,
        "Theodore Ts'o" <tytso@mit.edu>,
        "Jason A. Donenfeld" <Jason@zx2c4.com>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>,
        kasan-dev@googlegroups.com
Subject: Re: [PATCH printk v5 1/1] printk: extend console_lock for
 per-console locking
In-Reply-To: <CAMuHMdVmoj3Tqz65VmSuVL2no4+bGC=qdB8LWoB=vyASf9vS+g@mail.gmail.com>
References: <20220421212250.565456-1-john.ogness@linutronix.de>
 <20220421212250.565456-15-john.ogness@linutronix.de>
 <878rrs6ft7.fsf@jogness.linutronix.de> <Ymfgis0EAw0Oxoa5@alley>
 <Ymfwk+X0CHq6ex3s@alley>
 <CGME20220427070833eucas1p27a32ce7c41c0da26f05bd52155f0031c@eucas1p2.samsung.com>
 <2a82eae7-a256-f70c-fd82-4e510750906e@samsung.com>
 <Ymjy3rHRenba7r7R@alley>
 <b6c1a8ac-c691-a84d-d3a1-f99984d32f06@samsung.com>
 <87fslyv6y3.fsf@jogness.linutronix.de>
 <51dfc4a0-f6cf-092f-109f-a04eeb240655@samsung.com>
 <87k0b6blz2.fsf@jogness.linutronix.de>
 <32bba8f8-dec7-78aa-f2e5-f62928412eda@samsung.com>
 <87y1zkkrjy.fsf@jogness.linutronix.de>
 <CAMuHMdVmoj3Tqz65VmSuVL2no4+bGC=qdB8LWoB=vyASf9vS+g@mail.gmail.com>
Date: Thu, 09 Jun 2022 13:25:15 +0206
Message-ID: <87fske3wzw.fsf@jogness.linutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: john.ogness@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=JnUH5R2k;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=N8p5zbYz;
       spf=pass (google.com: domain of john.ogness@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=john.ogness@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

(Added RANDOM NUMBER DRIVER and KFENCE people.)

Hi Geert,

On 2022-06-08, Geert Uytterhoeven <geert@linux-m68k.org> wrote:
>     =============================
>     [ BUG: Invalid wait context ]
>     5.19.0-rc1-ebisu-00802-g06a0dd60d6e4 #431 Not tainted
>     -----------------------------
>     swapper/0/1 is trying to lock:
>     ffffffc00910bac8 (base_crng.lock){....}-{3:3}, at:
> crng_make_state+0x148/0x1e4
>     other info that might help us debug this:
>     context-{5:5}
>     2 locks held by swapper/0/1:
>      #0: ffffffc008f8ae00 (console_lock){+.+.}-{0:0}, at:
> printk_activate_kthreads+0x10/0x54
>      #1: ffffffc009da4a28 (&meta->lock){....}-{2:2}, at:
> __kfence_alloc+0x378/0x5c4
>     stack backtrace:
>     CPU: 0 PID: 1 Comm: swapper/0 Not tainted
> 5.19.0-rc1-ebisu-00802-g06a0dd60d6e4 #431
>     Hardware name: Renesas Ebisu-4D board based on r8a77990 (DT)
>     Call trace:
>      dump_backtrace.part.0+0x98/0xc0
>      show_stack+0x14/0x28
>      dump_stack_lvl+0xac/0xec
>      dump_stack+0x14/0x2c
>      __lock_acquire+0x388/0x10a0
>      lock_acquire+0x190/0x2c0
>      _raw_spin_lock_irqsave+0x6c/0x94
>      crng_make_state+0x148/0x1e4
>      _get_random_bytes.part.0+0x4c/0xe8
>      get_random_u32+0x4c/0x140
>      __kfence_alloc+0x460/0x5c4
>      kmem_cache_alloc_trace+0x194/0x1dc
>      __kthread_create_on_node+0x5c/0x1a8
>      kthread_create_on_node+0x58/0x7c
>      printk_start_kthread.part.0+0x34/0xa8
>      printk_activate_kthreads+0x4c/0x54
>      do_one_initcall+0xec/0x278
>      kernel_init_freeable+0x11c/0x214
>      kernel_init+0x24/0x124
>      ret_from_fork+0x10/0x20

I am guessing you have CONFIG_PROVE_RAW_LOCK_NESTING enabled?

We are seeing a spinlock (base_crng.lock) taken while holding a
raw_spinlock (meta->lock).

kfence_guarded_alloc()
  raw_spin_trylock_irqsave(&meta->lock, flags)
    prandom_u32_max()
      prandom_u32()
        get_random_u32()
          get_random_bytes()
            _get_random_bytes()
              crng_make_state()
                spin_lock_irqsave(&base_crng.lock, flags);

I expect it is allowed to create kthreads via kthread_run() in
early_initcalls.

John Ogness

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87fske3wzw.fsf%40jogness.linutronix.de.
