Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPHP574QKGQE3ZBIJ5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id E0001248A53
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 17:46:05 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id r17sf3782046uah.5
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 08:46:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597765564; cv=pass;
        d=google.com; s=arc-20160816;
        b=lTjzDdtHr19nj7qBlaIEkLYzniI8++9QHvMTZDfxxM9wAAW/AXSB6liZJ+7oD7h5ZP
         U8bXVSuBKKazVB8/JZciVZ+sMDM1lMC0tuCcciK9pQ4QpvO5Cxb8AMwfQ8LPR5ILRn3d
         izBgbKjINrHq6srt5s2HiWQA/d64S1JbHhKZj6+ZsiVcx870ambLEJCU9jC3SlQZFNGi
         nUF+69Vq3ef/LerFgQ6HoLP9haVIrnc4MXvTnuG5tt+xGTtmHA3DIsHx+J5+O/nu2m7S
         iKWsVflF6GC85hAPLEw+FmmNfESI8Z9XGaGmZWV4LXdFGzK5+si+A+zHn0ahAejhvR4n
         Q96Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=17YEaqEUVPN21hMZXan4TYLmTpTnNya0SKkuCNziIe4=;
        b=qYH6pewxRY1/MkMQXvBhbWBwEXjwGtD5ohSzXTCyu4pOpiDr/e2Zo8sApWCYnwGeZw
         83s8rFPhzT0V6ptwuPIZY5CfCXFfhT7Gq3tlihAST5+ypg7cnvRjDhKjveM0nwb65aWI
         sYcJb0FAJohQZHNCh/H791XMXIb94M2ILaEQC9kFcn8Q8y3d6xnSKdloLHoto9hVmgG4
         Xw3Oty8Td7eBxBBn/FSKtt/hyah5AnZDpiIUje2q+asLPPXYG6NYSFaCX15r17nJ+qtg
         TrTBLoz99+VjgT+yEpD+pqZaAT48hWwMYneiDFkivSjVC5m5rxLd8xDUG/dGBgtM6Wpm
         Lllw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ee8Rbkby;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=17YEaqEUVPN21hMZXan4TYLmTpTnNya0SKkuCNziIe4=;
        b=IP0UaPOB5ZPqtEJaChnY1XcGrosrym79//bb1iNyV0R1UE14ve0ttT34vbFqozHOXV
         AtH0zsRi0JyPoUP1S8z8BC+5nQrX7HnqOus5osOSVvgu1JqDODlQG7o8Z/V3tPnGiQOk
         npQi2hWNQyYqTArgW/5taFG+cScsjvSVdL52ESzg0Yn7poMsM3tC1hyxeJvERunSFa0e
         /XjbD56kgB6lCb51L/YeWEzhVOQGTY9KC6/C0xxlLTf/FDXOazDpi6Bbe+vqlht994QT
         +sLL6vrWL+h+TzE0DaRGQH+S3uqLUnRb5b71W9lfYMKFteBulQMalWJ2Mtw7hJaC0YtT
         ObLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=17YEaqEUVPN21hMZXan4TYLmTpTnNya0SKkuCNziIe4=;
        b=Pxemn8+ptdxHPnDiz4uYb5zUKOZnCwsx3z9dbf++WZ3/ejmPXtcjyOV7pwm79TwEci
         n725YWDvBjHglrLARulL34Gc6Xziaor1lCGkswh2DZqYH03qdbiYOGsHZBs6XNCrPSHG
         /H1QR1oGwZAOm5fgqvtvFOqgkAnz3ardhatLsaYzzrs2ErzYeLxJoCzrqUfgnzLdv8wh
         FsOD7r9CsD8bsopkk6dSOF6Sm1Hez29mVJ0pbprjYik5SKxxEuHB/IxOkwW9T4Jfttrc
         mfmkhPE0UwXvsDC5e5/oiXIQZw+WJlEcxdkR42i60x2p5gIQt6F/3CV3WRtwxqf0Pvam
         iKSA==
X-Gm-Message-State: AOAM532HhHaCrJtf+SxqJVqZapp00NaYX3n3k/OmCzUXj1Ip7RMyILAu
	poGuIKOFlnX0hggtHuW0FzA=
X-Google-Smtp-Source: ABdhPJzpkvFciALbHl6Lk/8muuQ9epnMc/psPPbJ/rXSGSJZ0qKLd+4FECjJiMUWgEfKMgSBeDioxg==
X-Received: by 2002:a67:fe16:: with SMTP id l22mr11466625vsr.67.1597765564784;
        Tue, 18 Aug 2020 08:46:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3cc:: with SMTP id n12ls2400383vsq.8.gmail; Tue, 18
 Aug 2020 08:46:04 -0700 (PDT)
X-Received: by 2002:a67:f302:: with SMTP id p2mr11698359vsf.0.1597765564330;
        Tue, 18 Aug 2020 08:46:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597765564; cv=none;
        d=google.com; s=arc-20160816;
        b=MrYp8q4g+/MhEfurSN+9VNoo4BkvAFgQxYvUlr40mSRfDABQW0aHzYJkexM4pBkA0n
         vrBpX+Fqtocqokd9kxI7Sq99StSfn4dnnXI28s4iFBunh1mIyimOmJi7owGZue7zKc4E
         8MF0q30xuL72AQ7BgCL6m8EJ3f6712TOjtydEX6HYk/UkPLIZtq/0kplrE5VkUuE7Bl0
         eTBcAZTZ0vF0QsTpyP583c1jCwwjWAH3fzxDenlvzz03dv1y4BlnhxmOIy9Yqiwha5ce
         cbGowwBcNizRH6zwafpScDCJsNmRT3qgIZmJ9cvk+XhDQ1LecEAxDIJD+5NGZ50EdPx1
         Hk2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LaWl8Zpiv/jFVXO3m0WashM5ldm/W64kfnal4k5ac3s=;
        b=p6kv7NQo7EzhLmdf0zjmiRdOXiCSF1mx9s/D7d18erXFm9OEBLDYJX8Do1lZ/O0gMk
         nz/s+q4dn8DxPHHuixpmaZ7l9y6DOuf0F9TltDHny1UDBAoEpgMQhgq9I/To0jaCqOZ9
         qRZWZmCIf7IvB6EnKgv6hOV8dpb/ug05a1G5SQEp6qsVUqZWTidSLP/J0K9/CoLH11KL
         u1+nEXESMPn/bLQoLn+o8ou8SJiHd+XRFSUYVnPfSCOX9GQNC9435LNiFgBd+VJnfOHg
         ROemDHIozlaf9LGCbmA5QlG4CaZ9bb/hgGV7Bw4HXk5JHnW5uenOimM7rY4eys9Q3Zzt
         si4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ee8Rbkby;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id q1si1537095ual.0.2020.08.18.08.46.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Aug 2020 08:46:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id 128so9935747pgd.5
        for <kasan-dev@googlegroups.com>; Tue, 18 Aug 2020 08:46:04 -0700 (PDT)
X-Received: by 2002:a65:680b:: with SMTP id l11mr7436248pgt.440.1597765563163;
 Tue, 18 Aug 2020 08:46:03 -0700 (PDT)
MIME-Version: 1.0
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com> <202008150939.A994680@keescook>
 <82edcbac-a856-cf9e-b86d-69a4315ea8e4@linux.com>
In-Reply-To: <82edcbac-a856-cf9e-b86d-69a4315ea8e4@linux.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Aug 2020 17:45:50 +0200
Message-ID: <CAAeHK+z9FPc9dqHwLA7sXTdpjt-iQweaQGQjq8L=eTYe2WdJ+g@mail.gmail.com>
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
To: Alexander Popov <alex.popov@linux.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>, 
	Will Deacon <will@kernel.org>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Masahiro Yamada <masahiroy@kernel.org>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Peter Zijlstra <peterz@infradead.org>, Krzysztof Kozlowski <krzk@kernel.org>, 
	Patrick Bellasi <patrick.bellasi@arm.com>, David Howells <dhowells@redhat.com>, 
	Eric Biederman <ebiederm@xmission.com>, Johannes Weiner <hannes@cmpxchg.org>, 
	Laura Abbott <labbott@redhat.com>, Arnd Bergmann <arnd@arndb.de>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kernel-hardening@lists.openwall.com, 
	LKML <linux-kernel@vger.kernel.org>, notify@kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ee8Rbkby;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::544
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Mon, Aug 17, 2020 at 7:32 PM Alexander Popov <alex.popov@linux.com> wrote:
>
> On 15.08.2020 19:52, Kees Cook wrote:
> > On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
> >> Heap spraying is an exploitation technique that aims to put controlled
> >> bytes at a predetermined memory location on the heap. Heap spraying for
> >> exploiting use-after-free in the Linux kernel relies on the fact that on
> >> kmalloc(), the slab allocator returns the address of the memory that was
> >> recently freed. Allocating a kernel object with the same size and
> >> controlled contents allows overwriting the vulnerable freed object.
> >>
> >> Let's extract slab freelist quarantine from KASAN functionality and
> >> call it CONFIG_SLAB_QUARANTINE. This feature breaks widespread heap
> >> spraying technique used for exploiting use-after-free vulnerabilities
> >> in the kernel code.
> >>
> >> If this feature is enabled, freed allocations are stored in the quarantine
> >> and can't be instantly reallocated and overwritten by the exploit
> >> performing heap spraying.
> >
> > It may be worth clarifying that this is specifically only direct UAF and
> > doesn't help with spray-and-overflow-into-a-neighboring-object attacks
> > (i.e. both tend to use sprays, but the former doesn't depend on a write
> > overflow).
>
> Andrey Konovalov wrote:
> > If quarantine is to be used without the rest of KASAN, I'd prefer for
> > it to be separated from KASAN completely: move to e.g. mm/quarantine.c
> > and don't mention KASAN in function/config names.
>
> Hmm, making quarantine completely separate from KASAN would bring troubles.
>
> Currently, in many special places the allocator calls KASAN handlers:
>   kasan_cache_create()
>   kasan_slab_free()
>   kasan_kmalloc_large()
>   kasan_krealloc()
>   kasan_slab_alloc()
>   kasan_kmalloc()
>   kasan_cache_shrink()
>   kasan_cache_shutdown()
>   and some others.
> These functions do a lot of interesting things and also work with the quarantine
> using these helpers:
>   quarantine_put()
>   quarantine_reduce()
>   quarantine_remove_cache()
>
> Making quarantine completely separate from KASAN would require to move some
> internal logic of these KASAN handlers to allocator code.

It doesn't look like there's quite a lot of KASAN-specific logic there.

All those quarantine_*() calls are either at the beginning or at the
end of some kasan annotations, so it should be quite easy to move
those out. E.g. quarantine_reduce() can be moved together with the
gfpflags_allow_blocking(flags) check and put before kasan_kmalloc()
calls (or maybe also into some other places?), quarantine_put() can be
put after kasan_slab_free(), etc.

> In this patch I used another approach, that doesn't require changing the API
> between allocators and KASAN. I added linux/mm/kasan/slab_quarantine.c with slim
> KASAN handlers that implement the minimal functionality needed for quarantine.
>
> Do you think that it's a bad solution?

This solution doesn't look clean. Here you provide a second KASAN
runtime implementation, parallel to the original one, which only does
quarantine. It seems much cleaner to put quarantine logic into a
separate module, which can be either used independently, or together
with KASAN built on top of it.

Maybe other KASAN contributors have an opinion on this?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz9FPc9dqHwLA7sXTdpjt-iQweaQGQjq8L%3DeTYe2WdJ%2Bg%40mail.gmail.com.
