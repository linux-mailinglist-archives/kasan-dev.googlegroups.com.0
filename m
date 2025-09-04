Return-Path: <kasan-dev+bncBDW2JDUY5AORBLGS43CQMGQELL7MBEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id E2566B43FC7
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Sep 2025 16:58:53 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-45b80aecb97sf10063385e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 07:58:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756997933; cv=pass;
        d=google.com; s=arc-20240605;
        b=G9Nw2IdQYYTAHw6VNRUFGVgbGB7Ubex940eb5DNK8L/OxjOqY5/WoYC16YBZn94BFs
         ZqiMPvXgjPIx5ZZPjl83tcDuuS75Rb/9lOaDdcmuI/A8qiNXaqlksHb9QLOWRALh7SnS
         y6mg2QTPUAwv42B4HJyr7dSTWKTduQdIhIByHSsfE12+4bYMe67uOmffTCB6/lj74TeY
         YrwB/GUIhiFFLmnZfxbMTphYnHOj4E4AETqZ2NVBd5GYwWHhPtEmjJ9XibpO1fnQmHo8
         GD4VbxnFapoBusKSS3mgbMICtah45GwXHROtvpLnq5mo79ly3KhlkxAxoxmUrbn2WXv1
         kFIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wjZklY3nkYOyB+hMsy01wMXx4NECBfd4ZIFvmw9XynU=;
        fh=KcmQ12cyElopKOirilHLkN8UYo/GRsVaI+nXmEc9xRc=;
        b=efHIHscoNhrbCWhWVt4tGFVS4wTF9N5xyIVOMEh25R3IqhOH2RpvgoOnYUguBuudc+
         awF9ZOxEJU5aF+ZNjJKguqI1RoBzsspIMegjVYTXbKvl1Ajz+mu7i3OGkKYB2iB1nf6v
         tHvZ3WjEtefYcW3oILTNX1FzjK3ykKfJfqfSPGrSQXYgMgJuYWtxoscr3Ovky3lCps+C
         ESS7je4jon99Sh8zKr0Q7ExIhh4OH0QQnZAq6F5rY03eo+fcL75W0X2DcErdPjjkl0dh
         1IEsLPIIf3/suCimxjWnIsu/FduMvM+AgO8QuZXSvEe5vfv12wWW/ml+2LB8b3DOKUSb
         ZRhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Xe8Q38AO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756997933; x=1757602733; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wjZklY3nkYOyB+hMsy01wMXx4NECBfd4ZIFvmw9XynU=;
        b=I1WKcktegzqlepXe8aS919pHl7UvoQxXXHcUlfoMtpm2tNb4b4kK9pR3tMLJUTtxDX
         kW7ynZB9Pzjla2IpHh+sOqZvgt6aKtqng8NAkMb3iD6m4ysoczG72p3jziIiIG0iO2lY
         8gzEBGSx40CBvSiUNgu6u3luXmtZj2p3IdXJsdzJKECk99Cj9FIekskdHsabkRoyrS/r
         h7B+ZJqCvD+QQiAnARNwOzRo1Lw9/57Nqj5dnnG699VqqFd3OF08+w+Mj64U6R2ObS6u
         rcbqTKKiumyWHYR0RpMzL70ZwfphjFNPxBTm/FK1ZUQNj1A43ZCjGdqKlFuEvkVKwJMi
         mwjg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756997933; x=1757602733; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wjZklY3nkYOyB+hMsy01wMXx4NECBfd4ZIFvmw9XynU=;
        b=Ucv1DW/ATc+hNtIzz3OiNqWlKYOWDWLuxrNQ0oiRq+iWr1gzkTEQQk9T7zyd8aIrrr
         zJSq2Xj8yB7da5/4TojyJIb1N/A1esM5jPW4+/dvK311KPLc+Jr1rAznIwyqVFcN/LcW
         dBSJByNptDS0f0tGjCSNrfIo9OQB+HxZtQejxGnE4EvUy0HWzOV1+GsR1nKB1/hBO+7+
         OW6F4GjZO4TOP/MD9XlhC74/lMJ+u93QFeUHlpKtK2slJjrm6lqjIZFYYCL+5NlUbwmA
         dBl/HF4qIvQk0yY+GcAlV/1FMtkSe43lEwZfdrDto2oLekn5zkf737JdS5Osk7a58HvH
         N7+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756997933; x=1757602733;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wjZklY3nkYOyB+hMsy01wMXx4NECBfd4ZIFvmw9XynU=;
        b=Ukai36CaOTky3ILOzibDcjzvCI+dByVck4WP+zpBsEhsLN7mdjMp5Dx4Ww59auXUzz
         inCKx+7Cq2WB4QbGOxmzagU99p9QUFvjCsVoPW23s4D3bZjqVXynWOCG0W266CyKThnA
         UpPY5MYTRtzZRpgM39FLpMDeGUj7CZld+cM2iF8Wfyi84DXXvtCHKCAJEg1mWJ7/PFun
         8cW/lbMkkbUQ3bmDNg5TDiH2/6fGcg+yy+ZAEASCMbzPDJ73kvwGx5j7bYt907FHdnLF
         TO0F5cwokB9pW+l/POqy2VqDpFGQx0nt2EDcs4Fg6lBSxS5Qbbw/GTh8mqhmqtocKTgK
         ZaTw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXO0oiWO6GTIxhDUmYWMYYzOArviokxE2N8mmuIPPjQHUskkFvH8sYLYzRxcNMD8gxwER0xog==@lfdr.de
X-Gm-Message-State: AOJu0Yw7XHvHGLNKYNCE3Ua3AONvTRhgH6efHrrIvglh0z3Z2UPh6xcU
	MUpORRsFxN4Ac+Dnvl8Alf5/HOoMuUOa4KOm8eIJiK9hhj9392S9Lb7X
X-Google-Smtp-Source: AGHT+IHnPkt4NckT5v2jeq/jTtD6M6mtJhATKVsjtQQliTIBTnzxBCe6yGTQeRSx6+x2WLJJXgkm9w==
X-Received: by 2002:a05:600c:190f:b0:45b:8939:8b03 with SMTP id 5b1f17b1804b1-45b89398d27mr130148745e9.27.1756997932843;
        Thu, 04 Sep 2025 07:58:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcrPILi8SNOcF6rI/ddDg77UK2aBBMqtatbsdP+xwuRzg==
Received: by 2002:a05:600c:5249:b0:459:d3be:4f4b with SMTP id
 5b1f17b1804b1-45b78cea2f2ls44759175e9.2.-pod-prod-09-eu; Thu, 04 Sep 2025
 07:58:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUkBvmsnBjqI8tjQQMgi4F265IV6+gcPm9wKWxARAddVIoFazPvfBRXxbMPn/ViwmxSKu+3onh0A5I=@googlegroups.com
X-Received: by 2002:a05:600c:154b:b0:45b:9961:9c0c with SMTP id 5b1f17b1804b1-45b99619d89mr89539195e9.33.1756997930268;
        Thu, 04 Sep 2025 07:58:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756997930; cv=none;
        d=google.com; s=arc-20240605;
        b=k2COGxAwCXlJL7D/l95H63LQBhkkiOtnmnHKx1IKVzunn4Xn4Qc8hcY+gtudio2aNM
         eKg03lTKwj2DRmlg/+F0n950rXkwMFhIcM0jVF9LMOiLwyu6Q4VvT2i6RMvgiqtC739S
         2KIalDViiuQikmvWU13SZi8hz1GLPc5rhzy+Vm7PfDgL186Sf1W+hHDGaR1A8/IBLeb/
         slfeIa7n5mLGtfJaDtB7chnnhiwl0q9ZkIxpJXrLhgUnYOraVvTmVq26OC2PTB0mRCbi
         LYorRKHwrTO/TmgcIxymoUxpOHowzod2/ZHV1/WU61Asue6HFuXQXEGfeNXxbv3eqFru
         nSYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jjoOxNGipBZMZSrHgnJO7zIqbW8l/mlQVhOAOi/XHNk=;
        fh=wXxL0dKuIKKk0AZlyOIUh5dLMl9bRNDGTvNrA6pVIyg=;
        b=PFjylDMedw1ZlCLYzM8/0R1dbbtCvggnzVqPIuTHW54PtKq4IfCPiQ/fzFY1C479R6
         dkMO3mzZDRh/FEjnZ8xW8MkWxjypg8B/s2MYP3rCK64BSdF+s9vyvwYqEGIQmpmOrJwk
         i8LOJXrbVpST/o2+Va9RMXfSVKoLVAgUE+SptCoiBr12QCO1WmjYTQ+Fz/BSUt/V/v1r
         wNHWikZg5NsTNJrFSpkJ3S6OveiZcwff2Hmf6PapNodTotkHAxxNjgYwyXRD4/I16m0m
         9QQSLoPTxu7ouYZb3dA61x1arPD70FCUh3cFgm3y6D/sj0q9/a6xnTm4IhU677xYdIbe
         lAFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Xe8Q38AO;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dd05960a7si447005e9.1.2025.09.04.07.58.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Sep 2025 07:58:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3d1bf79d758so917816f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Sep 2025 07:58:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXoPbwT0oKfFhg95Ie+UZqNwtLzwg/a6x3VCwgl/2h21Bt7CwpqMnFq/p7X6hwdmHvcic1BQ7TzfJs=@googlegroups.com
X-Gm-Gg: ASbGncuLtiCL+b1hB0oxKDFiPu2VxH4hrIoSQpYOe7jCJfX8tGl+bskDUFreqNCgJlx
	7BtyNm7Ae8KEBrK9F8DEjFiuyAqRL9IHvcvhEcX+tf1lyRsFV9xKohXejR9RWYFggz0cER/NFIL
	1X5s9uxPA1Ve33VLG21xdYKZPFdVvRWDfwEGIqf+x38y4uxNi3Hsamo124KwmFRQauFMSBfCTxe
	lOrh38=
X-Received: by 2002:a05:6000:430c:b0:3e0:4d29:80be with SMTP id
 ffacd0b85a97d-3e04d29815cmr2637642f8f.49.1756997929274; Thu, 04 Sep 2025
 07:58:49 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com> <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
In-Reply-To: <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Sep 2025 16:58:38 +0200
X-Gm-Features: Ac12FXyGDcz59ifSydw05MuQg_P1V6YF0m9gsQ5VWAu0_B8ZIjHvT6en0L_OHZQ
Message-ID: <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Baoquan He <bhe@redhat.com>, snovitoll@gmail.com
Cc: glider@google.com, dvyukov@google.com, elver@google.com, 
	linux-mm@kvack.org, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Xe8Q38AO;       spf=pass
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

On Thu, Sep 4, 2025 at 10:11=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> > If so, would it help if we make the kasan.vmalloc command-line
> > parameter work with the non-HW_TAGS modes (and make it do the same
> > thing as disabling CONFIG_KASAN_VMALLOC)?
> >
> > What I don't like about introducing kasan=3Doff for non-HW_TAGS modes i=
s
> > that this parameter does not actually disable KASAN. It just
> > suppresses KASAN code for mapping proper shadow memory. But the
> > compiler-added instrumentation is still executing (and I suspect this
> > might break the inline instrumentation mode).
>
> I may not follow your saying it doesn't disable KASAN. In this patchset,
> not only do I disable the code for mapping shadow memory, but also I
> skip any KASAN checking. Please see change of check_region_inline() in
> mm/kasan/generic.c and kasan_check_range() in mm/kasan/sw_tags.c. It
> will skip any KASAN checking when accessing memory.
>
> Yeah, the compiler added instrumentation will be called, but the if
> (!kasan_enabled()) checking will decide if going further into KASAN code
> or just return directly.

This all is true for the outline instrumentation mode.

However, with the inline instrumentation, check_region_inline() is not
called (in many cases, at least) and instead the compiler embeds the
instructions to calculate the shadow memory address and check its
value directly (this is why we have CONFIG_KASAN_SHADOW_OFFSET, whose
value has to be known at compile time).

> I tried inline mode on x86_64 and arm64, it
> works well when one reviewer said inline mode could cost much more
> memory, I don't see any breakage w or w/o kasan=3Doff when this patchset
> applied..

This is interesting. I guess what happens is that we still have the
early shadow memory mapped so the shadow memory accesses inserted by
the inline instrumentation do not crash.

But have you tried running kasan=3Doff + CONFIG_KASAN_STACK=3Dy +
CONFIG_VMAP_STACK=3Dy (+ CONFIG_KASAN_VMALLOC=3Dy)? I would expect this
should causes crashes, as the early shadow is mapped as read-only and
the inline stack instrumentation will try writing into it (or do the
writes into the early shadow somehow get ignored?..).

> > Perhaps, we could instead add a new kasan.shadow=3Don/off parameter to
> > make it more explicit that KASAN is not off, it's just that it stops
> > mapping shadow memory.
>
> Hmm, as I explained at above, kasan=3Doff will stop mapping shadow memory=
,
> and also stop executing KASAN code to poison/unpoison memory and check th=
e
> shadow. It may be inappropriate to say it only stops mapping shadow.

That's true, but we can only achieve this for the outline instrumentation m=
ode.

With the inline instrumentation mode, the (early) shadow memory would
still get accessed all the time even with kasan=3Doff. Which can be
considered inappropriate, as you pointed out (though this is what
happens for vmalloc allocations when CONFIG_KASAN_VMALLOC is disabled
and it does seem to work; but the inline stack instrumentation might
be a problem).

We could limit kasan=3Doff to only the outline instrumentation mode, but
I guess that defeats the purpose.

I'm not completely opposed to making kasan=3Doff work with all KASAN
modes (assuming it works with the inline instrumentation), but then we
will need to thoroughly document the behavior it creates.

And let's also wait for an opinion from the other KASAN maintainers on this=
.

> > Dmitry, Alexander, Marco, do you have any opinion on kasan=3Doff for
> > non-HW_TAGS modes?
> >
> > On a side note, this series will need to be rebased onto Sabyrzhan's
> > patches [1] - those are close to being ready. But perhaps let's wait
> > for v7 first.
>
> I replied to Sabyrzhan's patchset, on top of this patchset, it's much
> easier and cleaner to remove kasan_arch_is_ready(). We don't need
> introduce CONFIG_ARCH_DEFER_KASAN. Please see below patchset which is
> based on this patchset introducing 'kasan=3Doff|on' to genric|sw_tags
> mode.

Based on a brief look, both patch series seem to be doing similar
things (except yours also allows using kasan=3Doff for all modes).

But I like the Sabyrzhan's approach of hiding the explicit
static_branch_enable() calls under CONFIG_ARCH_DEFER_KASAN for the
architectures where they are actually required.

So I propose we moved forward with the Sabyrzhan's series and then
apply additional patches for supporting kasan=3Doff on top (but again,
assuming they work with the inline instrumentation).

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw%2B3xAjOVxjoh6w%40mail.gmail.com.
