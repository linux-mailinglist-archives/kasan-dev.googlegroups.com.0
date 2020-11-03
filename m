Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBEVOQ76QKGQER7TYR7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 79EB82A59E5
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Nov 2020 23:17:55 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id v22sf458002ljd.12
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Nov 2020 14:17:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604441875; cv=pass;
        d=google.com; s=arc-20160816;
        b=AR7VeaPE7dbq20HnpMuXlDFi3l6Euu9W21kkzMyo+OPGZ9lDiOoLzEI+FUO+97gjtY
         3WV27lLHNJFL/qeApJQFFoRR+yoZKMbNQC5UrSBBVBzNJHQz5Ij397O8mOxW13G3f43t
         MR3QCl+pM658x6znQQkPgHGPXwJeY4kQA88kGzCUqVnWcxwnv0dw5iqkdcXwRj7WPkNR
         cbn04eOrSzjyw/Tz/izyBHuRRyRx4XZZfwzdMqYxsat/zgrrc0yYtf2GYO05UNQjYmna
         qlBLPoDJ7lyr4R7H8NelKS6xI5cHKF/Z1pkdEIn8B0UjqctbtOqa3DVCq+4kchNfeaSb
         AmQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=quynuFvckwNqcQ6rXe7kF2xWQny5JXU1Dpm8ZEk/ilQ=;
        b=L9rFESa7RCcX9wocDGtvUq0k6skphydsryHryKWlIgVwE4WQ708fEls3+HoHLUMWU8
         bX+f6LrRHpWyLToQHox2zm/Ruy2A5kQ2IJOdSsn+PisCeG/F2E3agUES9X/lZTGkiu+2
         XyX2BbD0HigHmgqhqqtLA1rPVwfObLtX9+ONE8IzWq+V/2wZMMXtWq+OQ7yS02JCp9zR
         W7juuTJOuignC/MI7+gD82YIzsx2orC8+KifUFkDBieKvPL5UIopmBWViqumzSVSQPmx
         1sPIjK/gmmKL5PvC+XtarFqA9DjQL99V15KfFT+6fhWhHcIU6mCEl3KgbFvXOY1Ql9t2
         K2uw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Syi5K4Qt;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=quynuFvckwNqcQ6rXe7kF2xWQny5JXU1Dpm8ZEk/ilQ=;
        b=TdYkEDR1UJZ0GeguDLnbC/EPmu1qwnqDUp2OZRoAQNBQK4hUeQRM8VAqw5PYOxCyof
         y5j6b8d5A6hF7C7hIqXyaBJQx+YbYvm7dz967g+vbTckfAmfUYZJvFIgxgfWd2GBb3df
         MYWeDrbqDWwBFL9t5/AjIpL1tOZpZ3Zi0mSHK1+S+enH5KpYXZ+EpGgZ0+t9reY89dUy
         7XgepTEs3+m6Vr5eHWTd1Q2XjbP3BEWKztPChrCSpyR9NKQnVGCdgl2hHFY2rC79TDMu
         vmE2rU4bWsrqZiqswY4MG/W3GsULjz2RtvI++FcOxOCLpLBsPcCCK7xnSMcoOy1NH6Yk
         7xLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=quynuFvckwNqcQ6rXe7kF2xWQny5JXU1Dpm8ZEk/ilQ=;
        b=P9W5eOYWZbojf88GjjPwrLCA75dtV9ZqlO5HLDIIhRGPA6htv2AKP/tM2qlfbvTwsF
         goJGSf5Mamo4/FCdtk4ClTBLf+RhatYB1Qf5vroRi8a5Wzhg07QhWM0zXyz4CYziFtUX
         b1sSofULZiyZyNxGTgz0RkHP+fvLFqDm9nUcYjlzQpqOP+hnjgBS2PJqAWI5VX4mZ+jt
         zPc7+V/bZm229R9nuzZugo6mI/oFDWZQ7jdnCGipU3VGfxB4kdJpcotnUgmOrFgRtSkn
         27vqBmWMriAoZ2YGdIintE6llFfy6+XVracz2XKQBEgUR8IlWVe4wdSlmvKbR/V9V8dv
         Uztg==
X-Gm-Message-State: AOAM533HS21UMQzPdYUJufEbVm52bxNtbW7fDLyGHpuzSNarX85HqEde
	VK3gh9bOgRYoSyU8eAqNyx0=
X-Google-Smtp-Source: ABdhPJxbxBK6aLzIYJXysUqgzN4HUoQxVOAn4FykfiGg+irS0wzruHd8KxXHdFd7MRurgjpddxD9Kg==
X-Received: by 2002:a19:4815:: with SMTP id v21mr9288492lfa.603.1604441875053;
        Tue, 03 Nov 2020 14:17:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3fd1:: with SMTP id m200ls2128031lfa.2.gmail; Tue, 03
 Nov 2020 14:17:54 -0800 (PST)
X-Received: by 2002:ac2:57cf:: with SMTP id k15mr7679081lfo.501.1604441874177;
        Tue, 03 Nov 2020 14:17:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604441874; cv=none;
        d=google.com; s=arc-20160816;
        b=B+3vOdagKFSKJxXnb9OJcBGabJweO4oKQmm6Gs0jFna6m0+/REainCOM1W36mIFdaL
         c6Fd9e4HqqfbyQJvVMFXtmkww3T36u6Jp/BDJQgQR84XVmJMs4ejKqRCKDc4GJRkO/we
         SpLzDMN9IZQodGLYMWndCE0VHTpdiqsBvRIk/YMqwovijKLvn4pPLEKyYuLweiQjLScV
         qp13dERkb7WZ8aRIqrauAVnKFjIEkQJpi7g4Qa2ihS5wwbAWyufLuZkQhEoeux4kw/vQ
         tz1uD8ZxnQmuC+VjC0x7WUS5uBg0apUwHVyf39oCppMr6uZuTa0gYowp1H0MK2gA5Ybu
         MMwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YdCtwbqMAyOyGH0CTbWZbzS3jok6JKd1ti4BRTFY2CQ=;
        b=bqy03hRR2ge/srcJndw6Dl9PQkzyFXRYj/Wc4YWVJVGIN2MTCvCakbN8Lwz6Wdx5VI
         Nc+sWxsxQjnRWJNdns1wQq4EvGTiEhdmAy4fJiL/FLahpte7aO5s3Mh4MUJBUPV0NVXz
         hDn3SECz670lmOg+JkSyMawVp7c7/OaQVkwfxInYbFNjLoEcqSbVqI1bFzuCVYTP/F+T
         Cs0cqVcc6cTm8zgZV2FieGbGSmVik8Cgtb6530g2HKzvjhSPaSzXYOi3WZ0tt7vUih4Y
         GUhax2tI5AsqH6x8UmgNtB+AGUk21iDKQ0nIesMzYaq28qAdGxJ5ywimX15difqpbK2c
         9tCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Syi5K4Qt;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id x20si2871lfq.12.2020.11.03.14.17.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Nov 2020 14:17:54 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id 2so20745547ljj.13
        for <kasan-dev@googlegroups.com>; Tue, 03 Nov 2020 14:17:54 -0800 (PST)
X-Received: by 2002:a2e:8816:: with SMTP id x22mr8822321ljh.377.1604441873724;
 Tue, 03 Nov 2020 14:17:53 -0800 (PST)
MIME-Version: 1.0
References: <20201103175841.3495947-1-elver@google.com> <20201103175841.3495947-4-elver@google.com>
In-Reply-To: <20201103175841.3495947-4-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Nov 2020 23:17:26 +0100
Message-ID: <CAG48ez34gt7_itkCHiz6z__oepD89=sYWu11=3aq8ASV8ph5pQ@mail.gmail.com>
Subject: Re: [PATCH v7 3/9] arm64, kfence: enable KFENCE for ARM64
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	=?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Syi5K4Qt;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::244 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Nov 3, 2020 at 6:59 PM Marco Elver <elver@google.com> wrote:
> Add architecture specific implementation details for KFENCE and enable
> KFENCE for the arm64 architecture. In particular, this implements the
> required interface in <asm/kfence.h>.
>
> KFENCE requires that attributes for pages from its memory pool can
> individually be set. Therefore, force the entire linear map to be mapped
> at page granularity. Doing so may result in extra memory allocated for
> page tables in case rodata=full is not set; however, currently
> CONFIG_RODATA_FULL_DEFAULT_ENABLED=y is the default, and the common case
> is therefore not affected by this change.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>

Reviewed-by: Jann Horn <jannh@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez34gt7_itkCHiz6z__oepD89%3DsYWu11%3D3aq8ASV8ph5pQ%40mail.gmail.com.
