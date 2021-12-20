Return-Path: <kasan-dev+bncBDW2JDUY5AORBHH4QOHAMGQERFJIWSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CB4847B5BE
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:05:17 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 13-20020a0562140d0d00b00411590233e8sf1186631qvh.15
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:05:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037916; cv=pass;
        d=google.com; s=arc-20160816;
        b=IoQANc3IFVkVSNKFGDaFM3kuECp5H2XdZD8j2EWYEjoV7+ZN7tGgi7kl622pY924Av
         Gxs/rPkFETEkb3CWv0JmU6sbWVzdAgqOr7xp4IKNGCXKDgqFiJIqFEYjIWAp1GALFVdp
         cEDAI1hneELdAYPJ/s5T2UaS+6miX6tmvJJb7UrXBNhBjXo/NFZWsNTdb5pgtx8tnIt4
         0neV0HVPKgj5ocYJYzW5/utwj8ljEXgOhaEGAHC+rstMSDU05qHCrDyXuHQjz30VgpZe
         QFaREW/RuPK2bNr80gKBli4jRcZuMB03iqeO1jzhhd9rzT7290LvPvj96UGJcgVMwL5D
         xwtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=XijEmVW3TzMcDvMwdrJFBGftkE6YTOyx23bgnbDBHmQ=;
        b=OZgVbwEErOtqMnQ/yt+pLoX0Jt40bmg88rdd2eLDgDKStYS+ws2MwD7o9DVTlavtcD
         Jge12cenW8UVV/sr20YoeODrGSKZRglYr5e9T51lB/QwjCCpanK0TQYmQ6m+2UKVHgdD
         fmjossu9jF2V538P6hcZKZZ3uRh2kmMjg86m1ojONGtut1wixhoMqBok9jzWmMDfkeh2
         02Q041zMQa1SnDqjRKMiPiBxg4OT8pl9sX0Oq4CRDSkQTwEhilrWKICV6tckIkguVKIv
         pe9mhDxUSzJKSzQKtXB3iNoIJDYiLIbJMazgpaFKIx2rW9c5SiR5JG0eCpTWIEH/GG4l
         wKgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Zab6bdqg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XijEmVW3TzMcDvMwdrJFBGftkE6YTOyx23bgnbDBHmQ=;
        b=Uqm1yqtUn6i3EA+8DUMRiLDPx0FULZ/i14NcRbedJh8dcK7hxJLh7tcQU8vAOuCIQq
         LKARO7dVDIQvo6XCz5fCG5QXnbONOjImQRHx/qFrxDtNGtWINsucjp2R0WgSFxVlGAtl
         u0+5Wddo809R6aoO4EMmpcSLKHWEcBM/5uvWstoqwuNUFg/JwIXnzkMgJjmefX6fBdDa
         rWUVOitmC8/HSNESkT81IDdJUBo1jA+ibwRe31JcCFKC7Vnm2c73K5T4lfEiBFBjn7zT
         YiWLUbgjWTqopAscbSZndqGp3ltgbU5abkT6GpVVP0sQ/gEfA5/ugwQKbS6mAN9agOhM
         /dlw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XijEmVW3TzMcDvMwdrJFBGftkE6YTOyx23bgnbDBHmQ=;
        b=Qc2kgON159dLt0tXbbPvxsiXDZdJXC5Oa/7VyOWGC/ABLX/k6WDj21vFCYm4oKicnB
         ZC6+Eg1+SvUweWwsuGFXWpiMDrwG9IITHE9d6ihob1d7+wsVB0+mZ3z5UO89eoxvRl4u
         cYLfJXcQ+oI8xtQqGFYr+cZmvYGa1r503FanbIPG0+iP6oGfcoBI4Cy9XSuT501g+ZzE
         blQ93hDAemuK9i+RnLfTkg0mWsCUTrGjHxencKHANgT61Uqv9CThIhjVXBZsGjaGO4hh
         bHE+5C5jMuh5covQ/83MbV7gUL7cKBx5alj46Z3bIunX1vmdvKsBwOk/7ERjjMy6oR+d
         QFXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XijEmVW3TzMcDvMwdrJFBGftkE6YTOyx23bgnbDBHmQ=;
        b=gt27k5z7KK67vVe62t8sMKE+4rx9ocAVO60NfW27BmFzrgX9HHxnZWvJposTskZTN7
         2eMBIJErwamXr16RFRJ97/6YKO5nknAqmuiXfBU6r8QrZs211IhupSiC8p8jA35PtWK4
         4AarG6WyXnIqgRrfudkTGo2Nmx8IA5PAkIra33mny8nFPGOqP0lmW//UAVJ7jBaOKAqg
         RTTtskJifgVi3AtlGnVogjo02+EBsr3VZibjROWlUIvdNbbRXRl5n4xN+2r53l2Gsqjz
         scujhGYT2ha23FoyODlJfRDXZlRxZCHFXElFEVdD0r/SBgLzpqdgbYE/pe+syo14lOz4
         dPGg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Pj4gJupHvFamBTJvCkeaH4oV/K9in8H2d4EkXTmMoYNSLOFyo
	tXxXrbSaW7ndqrld5ta9/ns=
X-Google-Smtp-Source: ABdhPJyBhyOa9g56zMVplAFDW3/0f+Hqvy31IZaZF4sZXnO4BE9m9B9MLejELk0oZjkHosqV2PwbKg==
X-Received: by 2002:ad4:5962:: with SMTP id eq2mr14643975qvb.105.1640037916215;
        Mon, 20 Dec 2021 14:05:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:318e:: with SMTP id bi14ls8844645qkb.9.gmail; Mon,
 20 Dec 2021 14:05:15 -0800 (PST)
X-Received: by 2002:a05:620a:6d3:: with SMTP id 19mr141985qky.781.1640037915800;
        Mon, 20 Dec 2021 14:05:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037915; cv=none;
        d=google.com; s=arc-20160816;
        b=cA2xs6oQk3Ngze8+02cyXZKgF1IKE71YRX4i7X9r5TOH934OJzFLEk4oRd9LvMKZub
         fHTtUG2y2KTgdc1l8YDd2fVYmR1GwI66zTgDsORdRZvpCA0CM/REVI9CQfu/rH3nDMkx
         IIEeOeMCJz4HVExQQxf6vsw9VTGMMEUxyC38OHDp14NE5uuKg01ru4vFZV0xSA3lC5Q9
         KXYowsHsi9To6mCjrUDOZu6bLylUGiTIkEhGVHtpjYG58WkyTJiae66z6BcmCdjFQlQH
         8kUA0G1JIm1x2WUMgd6cNlVva+NN7jrSu330G1ULmIa8uf/zV3/eTQV/w0mYscCjxK7K
         ugqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5Hk8y3FD8xJfm6RryiwKYMpYBDu8nYDhrS0Z2nhR5mA=;
        b=R9yD9G68Db1jOXzK4Gnmjoykr7ye9IHPgqN5m9PE5Pu2kTD3M70Hsi5wiQwUaNNQry
         ObAIwoGs964a1cWyPx7clDcY9+pwLczXN6TSeF5V+l8OzZqk3hxQ7ZNLIAmzVyTPbsC5
         RHWOnUvT2eh2n1Fh3q1r3fo47tIRHt1gRVjDQZ7dPwM0CyNj7mv3p6SdCVJ8H4hke9eI
         cS7c9C8Ujd6zrDB5UA1nahgmgKhmzhdPgsrG9vCVO7gAoYDv4Vpf5wAThUDYxA6M8vlD
         PvCQymcqp8iLXopmBd97ahv7RsrN/WnRCq7UY1Lu8w0nl723zkHJLz3mfShnl+W7APuT
         yiyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Zab6bdqg;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id f38si2282918qtb.3.2021.12.20.14.05.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 14:05:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id w1so8691608ilh.9
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 14:05:15 -0800 (PST)
X-Received: by 2002:a05:6e02:178f:: with SMTP id y15mr19677ilu.235.1640037915336;
 Mon, 20 Dec 2021 14:05:15 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <85ecef50788a3915a9a8fb52e97207901f27b057.1640036051.git.andreyknvl@google.com>
In-Reply-To: <85ecef50788a3915a9a8fb52e97207901f27b057.1640036051.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 20 Dec 2021 23:05:04 +0100
Message-ID: <CA+fCnZdzzu=Fk_pyxCU3jCHkb0GW-nDA0E7svVfEeYVtRHSmsQ@mail.gmail.com>
Subject: Re: [PATCH mm v4 32/39] kasan, arm64: don't tag executable vmalloc allocations
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, andrey.konovalov@linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Zab6bdqg;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::132
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Dec 20, 2021 at 11:02 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Besides asking vmalloc memory to be executable via the prot argument
> of __vmalloc_node_range() (see the previous patch), the kernel can skip
> that bit and instead mark memory as executable via set_memory_x().
>
> Once tag-based KASAN modes start tagging vmalloc allocations, executing
> code from such allocations will lead to the PC register getting a tag,
> which is not tolerated by the kernel.
>
> Generic kernel code typically allocates memory via module_alloc() if
> it intends to mark memory as executable. (On arm64 module_alloc()
> uses __vmalloc_node_range() without setting the executable bit).
>
> Thus, reset pointer tags of pointers returned from module_alloc().
>
> However, on arm64 there's an exception: the eBPF subsystem. Instead of
> using module_alloc(), it uses vmalloc() (via bpf_jit_alloc_exec())
> to allocate its JIT region.
>
> Thus, reset pointer tags of pointers returned from bpf_jit_alloc_exec().
>
> Resetting tags for these pointers results in untagged pointers being
> passed to set_memory_x(). This causes conflicts in arithmetic checks
> in change_memory_common(), as vm_struct->addr pointer returned by
> find_vm_area() is tagged.
>
> Reset pointer tag of find_vm_area(addr)->addr in change_memory_common().
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
>
> ---
>
> Changes v3->v4:
> - Reset pointer tag in change_memory_common().
>
> Changes v2->v3:
> - Add this patch.
> ---
>  arch/arm64/kernel/module.c    | 3 ++-
>  arch/arm64/mm/pageattr.c      | 2 +-
>  arch/arm64/net/bpf_jit_comp.c | 3 ++-
>  3 files changed, 5 insertions(+), 3 deletions(-)
>
> diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
> index d3a1fa818348..f2d4bb14bfab 100644
> --- a/arch/arm64/kernel/module.c
> +++ b/arch/arm64/kernel/module.c
> @@ -63,7 +63,8 @@ void *module_alloc(unsigned long size)
>                 return NULL;
>         }
>
> -       return p;
> +       /* Memory is intended to be executable, reset the pointer tag. */
> +       return kasan_reset_tag(p);
>  }
>
>  enum aarch64_reloc_op {
> diff --git a/arch/arm64/mm/pageattr.c b/arch/arm64/mm/pageattr.c
> index a3bacd79507a..64e985eaa52d 100644
> --- a/arch/arm64/mm/pageattr.c
> +++ b/arch/arm64/mm/pageattr.c
> @@ -85,7 +85,7 @@ static int change_memory_common(unsigned long addr, int numpages,
>          */
>         area = find_vm_area((void *)addr);
>         if (!area ||
> -           end > (unsigned long)area->addr + area->size ||
> +           end > (unsigned long)kasan_reset_tag(area->addr) + area->size ||
>             !(area->flags & VM_ALLOC))
>                 return -EINVAL;
>
> diff --git a/arch/arm64/net/bpf_jit_comp.c b/arch/arm64/net/bpf_jit_comp.c
> index 07aad85848fa..381a67922c2d 100644
> --- a/arch/arm64/net/bpf_jit_comp.c
> +++ b/arch/arm64/net/bpf_jit_comp.c
> @@ -1147,7 +1147,8 @@ u64 bpf_jit_alloc_exec_limit(void)
>
>  void *bpf_jit_alloc_exec(unsigned long size)
>  {
> -       return vmalloc(size);
> +       /* Memory is intended to be executable, reset the pointer tag. */
> +       return kasan_reset_tag(vmalloc(size));
>  }
>
>  void bpf_jit_free_exec(void *addr)
> --
> 2.25.1

Hi Catalin,

I had to change this patch to fix an issue I discovered during
testing. Could you PTAL once again?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdzzu%3DFk_pyxCU3jCHkb0GW-nDA0E7svVfEeYVtRHSmsQ%40mail.gmail.com.
