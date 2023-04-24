Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPXCTCRAMGQE62WMFUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 9FB0E6EC738
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 09:35:28 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-63d30b08700sf21917375b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Apr 2023 00:35:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682321727; cv=pass;
        d=google.com; s=arc-20160816;
        b=gSaUDMwEHakOXHCnITGnll3o/obKibk+EEDpG+oshU5gP5OPW+MBbeeo35Z1QNQbIB
         dUbJ62fr/G2U8y6AI1Xdc2xFfVRja1AYzctO++fSpswpGRFIGYBs/65aiq74v7AOpegT
         U8rsukU0UVYg7dJV5ezay2bwQ8pfr2T59s6LcU19v6eCS+K8G8KNxtIq42KpoHMEz6dO
         3kpjlTKbTJjOhQ6NMSzhFtXQh478QcbgoxXpel7ShnFtnQE3S1h9nenjUiMsJfmLTaq9
         KRTUc+uhoaSOQ2VUzHfHL+9sYC4SzF8RD5UkznJ2G0kvGuPxrlRJq+9FZXp+YUql+ZUB
         PT2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LF8414YdtiIjLZYmgnTFcXQ6TfWYDZm96/RaI5VH0hk=;
        b=p8H5r7n99bq8E3Dvwst7HVy/KZItElibjSVN/nfQgXFLdp32tlJoZouFY5WCPKsB3B
         d41rEFLcLD28gNkvsMfoG/yLiyi7FMfvgqQbwGWhoYxwFywnFjclDDcejZ3j78XrwCSW
         2xkrVWP6SjqjJmHxuA8eXTJQef8Zok2K1JtSKg/pFABV2FssKKPYqbzIYKfr7BAzaUZ8
         vVvw01zlaPpBvkrBLT4uTUkfxAMKnCkgRiUYkexmY0bKEb8nmbJKEpT2cttncuGjtctA
         C8nIahnkhovwpjDL4d7AdL8iNdeukcI/k+VxBazIvwcuyLQaJDMYXWHSafmayKWdvovr
         XRxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=JEWfFzk1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682321727; x=1684913727;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LF8414YdtiIjLZYmgnTFcXQ6TfWYDZm96/RaI5VH0hk=;
        b=Rdn5EFYxqFmUd/d8PomlHEQ7l/iaPUgptw6ZWhhM5Puf95tVPlWMpklmbSk4xVavgf
         1m3DTvmhdJ5xxJiMvpTsTX2Bbl8tuFU8Cn0iYqTeqd/IGhnHnlScGU+rFDc04r3FKjF+
         4+jUWvpIKShajuCPljEhWcpXq9cvtKDuwP3h6vZYCHJdqDCDI+vfIl2odLfkl/yGiUnG
         R4YlpxVq1nJlsM3OkzAg9OjO4mwOPPjN2IY9Pg4pg1hQPIP24pGynBb/rdYkXTXikVml
         LlJTADKNWLQewALuNXnU+9EJFhtTLmJRCs3VAa5OD8+97Iinm6dsLP9cA1fp6coQTPwp
         2r1A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682321727; x=1684913727;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LF8414YdtiIjLZYmgnTFcXQ6TfWYDZm96/RaI5VH0hk=;
        b=W9xXQQJmhLaaaR7K51nl77EJa8tEW5+Qdlx4VHesbyQDYFwwv/C1rKYsL7RjfNRBZJ
         uSWqymJ+14+g+2t4UocuUuCXvnAS5OJjySptl/1fYo2DnfkN+FIEzvs+iMaENRyqznMM
         oxOH3kRQY0oegqJSYuScs5qMKvB4tas05Bih+UeOECIpgN2IR7sJf0C4JVPWUkk+CEPx
         2/TkXZSW7NRcjlzEjuXu1fixBsi6No6U7u6wBPIUyowVfybTwV/70bqCuIoTaDFjZVSV
         aEG6RgIhA9JKDzkDFnO/S4GjNMTFbCzHt9koOk12H+FIIz2UnriL5dbsMLOLsE7bW0gc
         eaow==
X-Gm-Message-State: AAQBX9crh9/6nYpfJUpYqp1MjWdElLJBIQf2lJUbyVmdyFEAG2VwJvsu
	KqFFgJUZhQwbKlmmbIIV0Mo=
X-Google-Smtp-Source: AKy350aYXAbuGjujZR2a+DOUnbX07eM3eNlkp1NIT94caKo5fX5ci5Pp4+eNDVdlOLzKt5cGKGIXyg==
X-Received: by 2002:a17:90a:404e:b0:247:1e13:90e6 with SMTP id k14-20020a17090a404e00b002471e1390e6mr2721544pjg.2.1682321727081;
        Mon, 24 Apr 2023 00:35:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2452:b0:194:d87a:ffa6 with SMTP id
 l18-20020a170903245200b00194d87affa6ls9903302pls.1.-pod-prod-gmail; Mon, 24
 Apr 2023 00:35:26 -0700 (PDT)
X-Received: by 2002:a05:6a21:3703:b0:ee:f5a4:c071 with SMTP id yl3-20020a056a21370300b000eef5a4c071mr10632491pzb.62.1682321726114;
        Mon, 24 Apr 2023 00:35:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682321726; cv=none;
        d=google.com; s=arc-20160816;
        b=b6fhHXX9MM31Uk/ubD7lEv39xho1MvqKaQIhjfiu8213lW7/aiPvDzEJWO3ji9xOeg
         uPUMHpeKWOIueQXsMrSI7bXkDmKKUnKuC9BdotfMS73uoCpdQilfridGG8yGR4kHaBfs
         Vh168A9fEa17H6u9g1TMZvNukIWBF+H5kOBSKUUxgzA+B41Ligt1vEUVuUOlPaFY9XhR
         eT/mvVN5dCfTqXLJAOlReV4tD5O/YPkluCXenSj3C7+ylek48l+71osxsw6w3f1BOdIQ
         kd6G8IxLD+xGcCPbr2qRJacbcTo5tbYRNCzly92r4nZ8EGDH4jaHe4XDu315AUlfkZTm
         Clew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2AjY/M9s0fw9ZiqI24bzonjYGKgwu6chZlbVLBE6b7Q=;
        b=Lny8FR/eBPbxxC3JVpwTKS0RzCzNDGtMCvYREotKFWnUP23Iryq3ESAGfPpm24vIFi
         2odrWVPV4wcYHEIck/TLFsKmTTjbVSZL7Mni3Q23bn6xWeZ4iHrywFXdBjuggcF5CrrB
         Yf4MeKoGZ4Qm4/O8PwXQ1Xtj5ihWEfh4X9FMALsn9pQx+R4F01+Ze/J6ddW6S+pPKpcG
         Fa6v/HqD8zePLvRSeN03Pr8af4eTHNf/5xSeRUIJiI2ej2YbkA8btHkJWcUK7nhyPUUu
         lyCdvLP8h/oz1luz2tzM0ElfJ78bdiBp5tk+m3vFLrLD944M06lRzwG7kIONrajbJ1+G
         RhwQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=JEWfFzk1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa32.google.com (mail-vk1-xa32.google.com. [2607:f8b0:4864:20::a32])
        by gmr-mx.google.com with ESMTPS id bg9-20020a056a02010900b005285b1a77d6si18256pgb.0.2023.04.24.00.35.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Apr 2023 00:35:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as permitted sender) client-ip=2607:f8b0:4864:20::a32;
Received: by mail-vk1-xa32.google.com with SMTP id 71dfb90a1353d-44054215485so2575927e0c.3
        for <kasan-dev@googlegroups.com>; Mon, 24 Apr 2023 00:35:26 -0700 (PDT)
X-Received: by 2002:a1f:ca04:0:b0:43b:3fda:1fba with SMTP id
 a4-20020a1fca04000000b0043b3fda1fbamr3384424vkg.6.1682321724564; Mon, 24 Apr
 2023 00:35:24 -0700 (PDT)
MIME-Version: 1.0
References: <20230421205754.106794-1-arnd@kernel.org>
In-Reply-To: <20230421205754.106794-1-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Apr 2023 09:34:48 +0200
Message-ID: <CANpmjNPZtoLzW42i651iYtdRsjKgwkkjNmkoFN69zQ3TXh10Lg@mail.gmail.com>
Subject: Re: [PATCH] [v2] kasan: use internal prototypes matching gcc-13 builtins
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Arnd Bergmann <arnd@arndb.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Kees Cook <keescook@chromium.org>, Ard Biesheuvel <ardb@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=JEWfFzk1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a32 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, 21 Apr 2023 at 22:58, Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> gcc-13 warns about function definitions for builtin interfaces
> that have a different prototype, e.g.:
>
> In file included from kasan_test.c:31:
> kasan.h:574:6: error: conflicting types for built-in function '__asan_register_globals'; expected 'void(void *, long int)' [-Werror=builtin-declaration-mismatch]
>   574 | void __asan_register_globals(struct kasan_global *globals, size_t size);
> kasan.h:577:6: error: conflicting types for built-in function '__asan_alloca_poison'; expected 'void(void *, long int)' [-Werror=builtin-declaration-mismatch]
>   577 | void __asan_alloca_poison(unsigned long addr, size_t size);
> kasan.h:580:6: error: conflicting types for built-in function '__asan_load1'; expected 'void(void *)' [-Werror=builtin-declaration-mismatch]
>   580 | void __asan_load1(unsigned long addr);
> kasan.h:581:6: error: conflicting types for built-in function '__asan_store1'; expected 'void(void *)' [-Werror=builtin-declaration-mismatch]
>   581 | void __asan_store1(unsigned long addr);
> kasan.h:643:6: error: conflicting types for built-in function '__hwasan_tag_memory'; expected 'void(void *, unsigned char,  long int)' [-Werror=builtin-declaration-mismatch]
>   643 | void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
>
> The two problems are:
>
>  - Addresses are passes as 'unsigned long' in the kernel, but gcc-13
>    expects a 'void *'.
>
>  - sizes meant to use a signed ssize_t rather than size_t.
>
> Change all the prototypes to match these.  Using 'void *' consistently
> for addresses gets rid of a couple of type casts, so push that down to
> the leaf functions where possible.
>
> This now passes all randconfig builds on arm, arm64 and x86, but I have
> not tested it on the other architectures that support kasan, since they
> tend to fail randconfig builds in other ways. This might fail if any
> of the 32-bit architectures expect a 'long' instead of 'int' for the
> size argument.
>
> The __asan_allocas_unpoison() function prototype is somewhat weird,
> since it uses a pointer for 'stack_top' and an size_t for 'stack_bottom'.
> This looks like it is meant to be 'addr' and 'size' like the others,
> but the implementation clearly treats them as 'top' and 'bottom'.
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Reviewed-by: Marco Elver <elver@google.com>

Looks better.

> ---
> v2: Remove custom size type that turned out to be unnecessary after all
> ---
>  arch/arm64/kernel/traps.c |   2 +-
>  arch/arm64/mm/fault.c     |   2 +-
>  include/linux/kasan.h     |   2 +-
>  mm/kasan/common.c         |   2 +-
>  mm/kasan/generic.c        |  72 ++++++++---------
>  mm/kasan/kasan.h          | 160 +++++++++++++++++++-------------------
>  mm/kasan/report.c         |  17 ++--
>  mm/kasan/report_generic.c |  12 +--
>  mm/kasan/report_hw_tags.c |   2 +-
>  mm/kasan/report_sw_tags.c |   2 +-
>  mm/kasan/shadow.c         |  36 ++++-----
>  mm/kasan/sw_tags.c        |  20 ++---
>  12 files changed, 164 insertions(+), 165 deletions(-)
>
> diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
> index 35a95b78b14f..3f5a21e5968e 100644
> --- a/arch/arm64/kernel/traps.c
> +++ b/arch/arm64/kernel/traps.c
> @@ -1044,7 +1044,7 @@ static int kasan_handler(struct pt_regs *regs, unsigned long esr)
>         bool recover = esr & KASAN_ESR_RECOVER;
>         bool write = esr & KASAN_ESR_WRITE;
>         size_t size = KASAN_ESR_SIZE(esr);
> -       u64 addr = regs->regs[0];
> +       void *addr = (void *)regs->regs[0];
>         u64 pc = regs->pc;
>
>         kasan_report(addr, size, write, pc);
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index f4418382be98..940391ec5e1e 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -317,7 +317,7 @@ static void report_tag_fault(unsigned long addr, unsigned long esr,
>          * find out access size.
>          */
>         bool is_write = !!(esr & ESR_ELx_WNR);
> -       kasan_report(addr, 0, is_write, regs->pc);
> +       kasan_report((void *)addr, 0, is_write, regs->pc);
>  }
>  #else
>  /* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index f7ef70661ce2..819b6bc8ac08 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -343,7 +343,7 @@ static inline void *kasan_reset_tag(const void *addr)
>   * @is_write: whether the bad access is a write or a read
>   * @ip: instruction pointer for the accessibility check or the bad access itself
>   */
> -bool kasan_report(unsigned long addr, size_t size,
> +bool kasan_report(const void *addr, size_t size,
>                 bool is_write, unsigned long ip);
>
>  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index b376a5d055e5..256930da578a 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -445,7 +445,7 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
>  bool __kasan_check_byte(const void *address, unsigned long ip)
>  {
>         if (!kasan_byte_accessible(address)) {
> -               kasan_report((unsigned long)address, 1, false, ip);
> +               kasan_report(address, 1, false, ip);
>                 return false;
>         }
>         return true;
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index e5eef670735e..224d161a5a22 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -40,39 +40,39 @@
>   * depending on memory access size X.
>   */
>
> -static __always_inline bool memory_is_poisoned_1(unsigned long addr)
> +static __always_inline bool memory_is_poisoned_1(const void *addr)
>  {
> -       s8 shadow_value = *(s8 *)kasan_mem_to_shadow((void *)addr);
> +       s8 shadow_value = *(s8 *)kasan_mem_to_shadow(addr);
>
>         if (unlikely(shadow_value)) {
> -               s8 last_accessible_byte = addr & KASAN_GRANULE_MASK;
> +               s8 last_accessible_byte = (unsigned long)addr & KASAN_GRANULE_MASK;
>                 return unlikely(last_accessible_byte >= shadow_value);
>         }
>
>         return false;
>  }
>
> -static __always_inline bool memory_is_poisoned_2_4_8(unsigned long addr,
> +static __always_inline bool memory_is_poisoned_2_4_8(const void *addr,
>                                                 unsigned long size)
>  {
> -       u8 *shadow_addr = (u8 *)kasan_mem_to_shadow((void *)addr);
> +       u8 *shadow_addr = (u8 *)kasan_mem_to_shadow(addr);
>
>         /*
>          * Access crosses 8(shadow size)-byte boundary. Such access maps
>          * into 2 shadow bytes, so we need to check them both.
>          */
> -       if (unlikely(((addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
> +       if (unlikely((((unsigned long)addr + size - 1) & KASAN_GRANULE_MASK) < size - 1))
>                 return *shadow_addr || memory_is_poisoned_1(addr + size - 1);
>
>         return memory_is_poisoned_1(addr + size - 1);
>  }
>
> -static __always_inline bool memory_is_poisoned_16(unsigned long addr)
> +static __always_inline bool memory_is_poisoned_16(const void *addr)
>  {
> -       u16 *shadow_addr = (u16 *)kasan_mem_to_shadow((void *)addr);
> +       u16 *shadow_addr = (u16 *)kasan_mem_to_shadow(addr);
>
>         /* Unaligned 16-bytes access maps into 3 shadow bytes. */
> -       if (unlikely(!IS_ALIGNED(addr, KASAN_GRANULE_SIZE)))
> +       if (unlikely(!IS_ALIGNED((unsigned long)addr, KASAN_GRANULE_SIZE)))
>                 return *shadow_addr || memory_is_poisoned_1(addr + 15);
>
>         return *shadow_addr;
> @@ -120,26 +120,25 @@ static __always_inline unsigned long memory_is_nonzero(const void *start,
>         return bytes_is_nonzero(start, (end - start) % 8);
>  }
>
> -static __always_inline bool memory_is_poisoned_n(unsigned long addr,
> -                                               size_t size)
> +static __always_inline bool memory_is_poisoned_n(const void *addr, size_t size)
>  {
>         unsigned long ret;
>
> -       ret = memory_is_nonzero(kasan_mem_to_shadow((void *)addr),
> -                       kasan_mem_to_shadow((void *)addr + size - 1) + 1);
> +       ret = memory_is_nonzero(kasan_mem_to_shadow(addr),
> +                       kasan_mem_to_shadow(addr + size - 1) + 1);
>
>         if (unlikely(ret)) {
> -               unsigned long last_byte = addr + size - 1;
> -               s8 *last_shadow = (s8 *)kasan_mem_to_shadow((void *)last_byte);
> +               const void *last_byte = addr + size - 1;
> +               s8 *last_shadow = (s8 *)kasan_mem_to_shadow(last_byte);
>
>                 if (unlikely(ret != (unsigned long)last_shadow ||
> -                       ((long)(last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
> +                       (((long)last_byte & KASAN_GRANULE_MASK) >= *last_shadow)))
>                         return true;
>         }
>         return false;
>  }
>
> -static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
> +static __always_inline bool memory_is_poisoned(const void *addr, size_t size)
>  {
>         if (__builtin_constant_p(size)) {
>                 switch (size) {
> @@ -159,7 +158,7 @@ static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
>         return memory_is_poisoned_n(addr, size);
>  }
>
> -static __always_inline bool check_region_inline(unsigned long addr,
> +static __always_inline bool check_region_inline(const void *addr,
>                                                 size_t size, bool write,
>                                                 unsigned long ret_ip)
>  {
> @@ -172,7 +171,7 @@ static __always_inline bool check_region_inline(unsigned long addr,
>         if (unlikely(addr + size < addr))
>                 return !kasan_report(addr, size, write, ret_ip);
>
> -       if (unlikely(!addr_has_metadata((void *)addr)))
> +       if (unlikely(!addr_has_metadata(addr)))
>                 return !kasan_report(addr, size, write, ret_ip);
>
>         if (likely(!memory_is_poisoned(addr, size)))
> @@ -181,7 +180,7 @@ static __always_inline bool check_region_inline(unsigned long addr,
>         return !kasan_report(addr, size, write, ret_ip);
>  }
>
> -bool kasan_check_range(unsigned long addr, size_t size, bool write,
> +bool kasan_check_range(const void *addr, size_t size, bool write,
>                                         unsigned long ret_ip)
>  {
>         return check_region_inline(addr, size, write, ret_ip);
> @@ -221,36 +220,37 @@ static void register_global(struct kasan_global *global)
>                      KASAN_GLOBAL_REDZONE, false);
>  }
>
> -void __asan_register_globals(struct kasan_global *globals, size_t size)
> +void __asan_register_globals(void *ptr, ssize_t size)
>  {
>         int i;
> +       struct kasan_global *globals = ptr;
>
>         for (i = 0; i < size; i++)
>                 register_global(&globals[i]);
>  }
>  EXPORT_SYMBOL(__asan_register_globals);
>
> -void __asan_unregister_globals(struct kasan_global *globals, size_t size)
> +void __asan_unregister_globals(void *ptr, ssize_t size)
>  {
>  }
>  EXPORT_SYMBOL(__asan_unregister_globals);
>
>  #define DEFINE_ASAN_LOAD_STORE(size)                                   \
> -       void __asan_load##size(unsigned long addr)                      \
> +       void __asan_load##size(void *addr)                              \
>         {                                                               \
>                 check_region_inline(addr, size, false, _RET_IP_);       \
>         }                                                               \
>         EXPORT_SYMBOL(__asan_load##size);                               \
>         __alias(__asan_load##size)                                      \
> -       void __asan_load##size##_noabort(unsigned long);                \
> +       void __asan_load##size##_noabort(void *);                       \
>         EXPORT_SYMBOL(__asan_load##size##_noabort);                     \
> -       void __asan_store##size(unsigned long addr)                     \
> +       void __asan_store##size(void *addr)                             \
>         {                                                               \
>                 check_region_inline(addr, size, true, _RET_IP_);        \
>         }                                                               \
>         EXPORT_SYMBOL(__asan_store##size);                              \
>         __alias(__asan_store##size)                                     \
> -       void __asan_store##size##_noabort(unsigned long);               \
> +       void __asan_store##size##_noabort(void *);                      \
>         EXPORT_SYMBOL(__asan_store##size##_noabort)
>
>  DEFINE_ASAN_LOAD_STORE(1);
> @@ -259,24 +259,24 @@ DEFINE_ASAN_LOAD_STORE(4);
>  DEFINE_ASAN_LOAD_STORE(8);
>  DEFINE_ASAN_LOAD_STORE(16);
>
> -void __asan_loadN(unsigned long addr, size_t size)
> +void __asan_loadN(void *addr, ssize_t size)
>  {
>         kasan_check_range(addr, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__asan_loadN);
>
>  __alias(__asan_loadN)
> -void __asan_loadN_noabort(unsigned long, size_t);
> +void __asan_loadN_noabort(void *, ssize_t);
>  EXPORT_SYMBOL(__asan_loadN_noabort);
>
> -void __asan_storeN(unsigned long addr, size_t size)
> +void __asan_storeN(void *addr, ssize_t size)
>  {
>         kasan_check_range(addr, size, true, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__asan_storeN);
>
>  __alias(__asan_storeN)
> -void __asan_storeN_noabort(unsigned long, size_t);
> +void __asan_storeN_noabort(void *, ssize_t);
>  EXPORT_SYMBOL(__asan_storeN_noabort);
>
>  /* to shut up compiler complaints */
> @@ -284,7 +284,7 @@ void __asan_handle_no_return(void) {}
>  EXPORT_SYMBOL(__asan_handle_no_return);
>
>  /* Emitted by compiler to poison alloca()ed objects. */
> -void __asan_alloca_poison(unsigned long addr, size_t size)
> +void __asan_alloca_poison(void *addr, ssize_t size)
>  {
>         size_t rounded_up_size = round_up(size, KASAN_GRANULE_SIZE);
>         size_t padding_size = round_up(size, KASAN_ALLOCA_REDZONE_SIZE) -
> @@ -295,7 +295,7 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
>                         KASAN_ALLOCA_REDZONE_SIZE);
>         const void *right_redzone = (const void *)(addr + rounded_up_size);
>
> -       WARN_ON(!IS_ALIGNED(addr, KASAN_ALLOCA_REDZONE_SIZE));
> +       WARN_ON(!IS_ALIGNED((unsigned long)addr, KASAN_ALLOCA_REDZONE_SIZE));
>
>         kasan_unpoison((const void *)(addr + rounded_down_size),
>                         size - rounded_down_size, false);
> @@ -307,18 +307,18 @@ void __asan_alloca_poison(unsigned long addr, size_t size)
>  EXPORT_SYMBOL(__asan_alloca_poison);
>
>  /* Emitted by compiler to unpoison alloca()ed areas when the stack unwinds. */
> -void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom)
> +void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom)
>  {
> -       if (unlikely(!stack_top || stack_top > stack_bottom))
> +       if (unlikely(!stack_top || stack_top > (void *)stack_bottom))
>                 return;
>
> -       kasan_unpoison(stack_top, stack_bottom - stack_top, false);
> +       kasan_unpoison(stack_top, (void *)stack_bottom - stack_top, false);
>  }
>  EXPORT_SYMBOL(__asan_allocas_unpoison);
>
>  /* Emitted by the compiler to [un]poison local variables. */
>  #define DEFINE_ASAN_SET_SHADOW(byte) \
> -       void __asan_set_shadow_##byte(const void *addr, size_t size)    \
> +       void __asan_set_shadow_##byte(const void *addr, ssize_t size)   \
>         {                                                               \
>                 __memset((void *)addr, 0x##byte, size);                 \
>         }                                                               \
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index cd846ca34f44..b799f11e45dc 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -198,13 +198,13 @@ enum kasan_report_type {
>  struct kasan_report_info {
>         /* Filled in by kasan_report_*(). */
>         enum kasan_report_type type;
> -       void *access_addr;
> +       const void *access_addr;
>         size_t access_size;
>         bool is_write;
>         unsigned long ip;
>
>         /* Filled in by the common reporting code. */
> -       void *first_bad_addr;
> +       const void *first_bad_addr;
>         struct kmem_cache *cache;
>         void *object;
>         size_t alloc_size;
> @@ -311,7 +311,7 @@ static __always_inline bool addr_has_metadata(const void *addr)
>   * @ret_ip: return address
>   * @return: true if access was valid, false if invalid
>   */
> -bool kasan_check_range(unsigned long addr, size_t size, bool write,
> +bool kasan_check_range(const void *addr, size_t size, bool write,
>                                 unsigned long ret_ip);
>
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> @@ -323,7 +323,7 @@ static __always_inline bool addr_has_metadata(const void *addr)
>
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> -void *kasan_find_first_bad_addr(void *addr, size_t size);
> +const void *kasan_find_first_bad_addr(const void *addr, size_t size);
>  size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache);
>  void kasan_complete_mode_report_info(struct kasan_report_info *info);
>  void kasan_metadata_fetch_row(char *buffer, void *row);
> @@ -346,7 +346,7 @@ void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object);
>  static inline void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object) { }
>  #endif
>
> -bool kasan_report(unsigned long addr, size_t size,
> +bool kasan_report(const void *addr, size_t size,
>                 bool is_write, unsigned long ip);
>  void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
>
> @@ -571,82 +571,82 @@ void kasan_restore_multi_shot(bool enabled);
>   */
>
>  asmlinkage void kasan_unpoison_task_stack_below(const void *watermark);
> -void __asan_register_globals(struct kasan_global *globals, size_t size);
> -void __asan_unregister_globals(struct kasan_global *globals, size_t size);
> +void __asan_register_globals(void *globals, ssize_t size);
> +void __asan_unregister_globals(void *globals, ssize_t size);
>  void __asan_handle_no_return(void);
> -void __asan_alloca_poison(unsigned long addr, size_t size);
> -void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom);
> -
> -void __asan_load1(unsigned long addr);
> -void __asan_store1(unsigned long addr);
> -void __asan_load2(unsigned long addr);
> -void __asan_store2(unsigned long addr);
> -void __asan_load4(unsigned long addr);
> -void __asan_store4(unsigned long addr);
> -void __asan_load8(unsigned long addr);
> -void __asan_store8(unsigned long addr);
> -void __asan_load16(unsigned long addr);
> -void __asan_store16(unsigned long addr);
> -void __asan_loadN(unsigned long addr, size_t size);
> -void __asan_storeN(unsigned long addr, size_t size);
> -
> -void __asan_load1_noabort(unsigned long addr);
> -void __asan_store1_noabort(unsigned long addr);
> -void __asan_load2_noabort(unsigned long addr);
> -void __asan_store2_noabort(unsigned long addr);
> -void __asan_load4_noabort(unsigned long addr);
> -void __asan_store4_noabort(unsigned long addr);
> -void __asan_load8_noabort(unsigned long addr);
> -void __asan_store8_noabort(unsigned long addr);
> -void __asan_load16_noabort(unsigned long addr);
> -void __asan_store16_noabort(unsigned long addr);
> -void __asan_loadN_noabort(unsigned long addr, size_t size);
> -void __asan_storeN_noabort(unsigned long addr, size_t size);
> -
> -void __asan_report_load1_noabort(unsigned long addr);
> -void __asan_report_store1_noabort(unsigned long addr);
> -void __asan_report_load2_noabort(unsigned long addr);
> -void __asan_report_store2_noabort(unsigned long addr);
> -void __asan_report_load4_noabort(unsigned long addr);
> -void __asan_report_store4_noabort(unsigned long addr);
> -void __asan_report_load8_noabort(unsigned long addr);
> -void __asan_report_store8_noabort(unsigned long addr);
> -void __asan_report_load16_noabort(unsigned long addr);
> -void __asan_report_store16_noabort(unsigned long addr);
> -void __asan_report_load_n_noabort(unsigned long addr, size_t size);
> -void __asan_report_store_n_noabort(unsigned long addr, size_t size);
> -
> -void __asan_set_shadow_00(const void *addr, size_t size);
> -void __asan_set_shadow_f1(const void *addr, size_t size);
> -void __asan_set_shadow_f2(const void *addr, size_t size);
> -void __asan_set_shadow_f3(const void *addr, size_t size);
> -void __asan_set_shadow_f5(const void *addr, size_t size);
> -void __asan_set_shadow_f8(const void *addr, size_t size);
> -
> -void *__asan_memset(void *addr, int c, size_t len);
> -void *__asan_memmove(void *dest, const void *src, size_t len);
> -void *__asan_memcpy(void *dest, const void *src, size_t len);
> -
> -void __hwasan_load1_noabort(unsigned long addr);
> -void __hwasan_store1_noabort(unsigned long addr);
> -void __hwasan_load2_noabort(unsigned long addr);
> -void __hwasan_store2_noabort(unsigned long addr);
> -void __hwasan_load4_noabort(unsigned long addr);
> -void __hwasan_store4_noabort(unsigned long addr);
> -void __hwasan_load8_noabort(unsigned long addr);
> -void __hwasan_store8_noabort(unsigned long addr);
> -void __hwasan_load16_noabort(unsigned long addr);
> -void __hwasan_store16_noabort(unsigned long addr);
> -void __hwasan_loadN_noabort(unsigned long addr, size_t size);
> -void __hwasan_storeN_noabort(unsigned long addr, size_t size);
> -
> -void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
> -
> -void *__hwasan_memset(void *addr, int c, size_t len);
> -void *__hwasan_memmove(void *dest, const void *src, size_t len);
> -void *__hwasan_memcpy(void *dest, const void *src, size_t len);
> -
> -void kasan_tag_mismatch(unsigned long addr, unsigned long access_info,
> +void __asan_alloca_poison(void *, ssize_t size);
> +void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom);
> +
> +void __asan_load1(void *);
> +void __asan_store1(void *);
> +void __asan_load2(void *);
> +void __asan_store2(void *);
> +void __asan_load4(void *);
> +void __asan_store4(void *);
> +void __asan_load8(void *);
> +void __asan_store8(void *);
> +void __asan_load16(void *);
> +void __asan_store16(void *);
> +void __asan_loadN(void *, ssize_t size);
> +void __asan_storeN(void *, ssize_t size);
> +
> +void __asan_load1_noabort(void *);
> +void __asan_store1_noabort(void *);
> +void __asan_load2_noabort(void *);
> +void __asan_store2_noabort(void *);
> +void __asan_load4_noabort(void *);
> +void __asan_store4_noabort(void *);
> +void __asan_load8_noabort(void *);
> +void __asan_store8_noabort(void *);
> +void __asan_load16_noabort(void *);
> +void __asan_store16_noabort(void *);
> +void __asan_loadN_noabort(void *, ssize_t size);
> +void __asan_storeN_noabort(void *, ssize_t size);
> +
> +void __asan_report_load1_noabort(void *);
> +void __asan_report_store1_noabort(void *);
> +void __asan_report_load2_noabort(void *);
> +void __asan_report_store2_noabort(void *);
> +void __asan_report_load4_noabort(void *);
> +void __asan_report_store4_noabort(void *);
> +void __asan_report_load8_noabort(void *);
> +void __asan_report_store8_noabort(void *);
> +void __asan_report_load16_noabort(void *);
> +void __asan_report_store16_noabort(void *);
> +void __asan_report_load_n_noabort(void *, ssize_t size);
> +void __asan_report_store_n_noabort(void *, ssize_t size);
> +
> +void __asan_set_shadow_00(const void *addr, ssize_t size);
> +void __asan_set_shadow_f1(const void *addr, ssize_t size);
> +void __asan_set_shadow_f2(const void *addr, ssize_t size);
> +void __asan_set_shadow_f3(const void *addr, ssize_t size);
> +void __asan_set_shadow_f5(const void *addr, ssize_t size);
> +void __asan_set_shadow_f8(const void *addr, ssize_t size);
> +
> +void *__asan_memset(void *addr, int c, ssize_t len);
> +void *__asan_memmove(void *dest, const void *src, ssize_t len);
> +void *__asan_memcpy(void *dest, const void *src, ssize_t len);
> +
> +void __hwasan_load1_noabort(void *);
> +void __hwasan_store1_noabort(void *);
> +void __hwasan_load2_noabort(void *);
> +void __hwasan_store2_noabort(void *);
> +void __hwasan_load4_noabort(void *);
> +void __hwasan_store4_noabort(void *);
> +void __hwasan_load8_noabort(void *);
> +void __hwasan_store8_noabort(void *);
> +void __hwasan_load16_noabort(void *);
> +void __hwasan_store16_noabort(void *);
> +void __hwasan_loadN_noabort(void *, ssize_t size);
> +void __hwasan_storeN_noabort(void *, ssize_t size);
> +
> +void __hwasan_tag_memory(void *, u8 tag, ssize_t size);
> +
> +void *__hwasan_memset(void *addr, int c, ssize_t len);
> +void *__hwasan_memmove(void *dest, const void *src, ssize_t len);
> +void *__hwasan_memcpy(void *dest, const void *src, ssize_t len);
> +
> +void kasan_tag_mismatch(void *addr, unsigned long access_info,
>                         unsigned long ret_ip);
>
>  #endif /* __MM_KASAN_KASAN_H */
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index 892a9dc9d4d3..84d9f3b37014 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -211,7 +211,7 @@ static void start_report(unsigned long *flags, bool sync)
>         pr_err("==================================================================\n");
>  }
>
> -static void end_report(unsigned long *flags, void *addr)
> +static void end_report(unsigned long *flags, const void *addr)
>  {
>         if (addr)
>                 trace_error_report_end(ERROR_DETECTOR_KASAN,
> @@ -450,8 +450,8 @@ static void print_memory_metadata(const void *addr)
>
>  static void print_report(struct kasan_report_info *info)
>  {
> -       void *addr = kasan_reset_tag(info->access_addr);
> -       u8 tag = get_tag(info->access_addr);
> +       void *addr = kasan_reset_tag((void *)info->access_addr);
> +       u8 tag = get_tag((void *)info->access_addr);
>
>         print_error_description(info);
>         if (addr_has_metadata(addr))
> @@ -468,12 +468,12 @@ static void print_report(struct kasan_report_info *info)
>
>  static void complete_report_info(struct kasan_report_info *info)
>  {
> -       void *addr = kasan_reset_tag(info->access_addr);
> +       void *addr = kasan_reset_tag((void *)info->access_addr);
>         struct slab *slab;
>
>         if (info->type == KASAN_REPORT_ACCESS)
>                 info->first_bad_addr = kasan_find_first_bad_addr(
> -                                       info->access_addr, info->access_size);
> +                                       (void *)info->access_addr, info->access_size);
>         else
>                 info->first_bad_addr = addr;
>
> @@ -544,11 +544,10 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
>   * user_access_save/restore(): kasan_report_invalid_free() cannot be called
>   * from a UACCESS region, and kasan_report_async() is not used on x86.
>   */
> -bool kasan_report(unsigned long addr, size_t size, bool is_write,
> +bool kasan_report(const void *addr, size_t size, bool is_write,
>                         unsigned long ip)
>  {
>         bool ret = true;
> -       void *ptr = (void *)addr;
>         unsigned long ua_flags = user_access_save();
>         unsigned long irq_flags;
>         struct kasan_report_info info;
> @@ -562,7 +561,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>
>         memset(&info, 0, sizeof(info));
>         info.type = KASAN_REPORT_ACCESS;
> -       info.access_addr = ptr;
> +       info.access_addr = addr;
>         info.access_size = size;
>         info.is_write = is_write;
>         info.ip = ip;
> @@ -571,7 +570,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
>
>         print_report(&info);
>
> -       end_report(&irq_flags, ptr);
> +       end_report(&irq_flags, (void *)addr);
>
>  out:
>         user_access_restore(ua_flags);
> diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
> index 87d39bc0a673..51a1e8a8877f 100644
> --- a/mm/kasan/report_generic.c
> +++ b/mm/kasan/report_generic.c
> @@ -30,9 +30,9 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -void *kasan_find_first_bad_addr(void *addr, size_t size)
> +const void *kasan_find_first_bad_addr(const void *addr, size_t size)
>  {
> -       void *p = addr;
> +       const void *p = addr;
>
>         if (!addr_has_metadata(p))
>                 return p;
> @@ -362,14 +362,14 @@ void kasan_print_address_stack_frame(const void *addr)
>  #endif /* CONFIG_KASAN_STACK */
>
>  #define DEFINE_ASAN_REPORT_LOAD(size)                     \
> -void __asan_report_load##size##_noabort(unsigned long addr) \
> +void __asan_report_load##size##_noabort(void *addr) \
>  {                                                         \
>         kasan_report(addr, size, false, _RET_IP_);        \
>  }                                                         \
>  EXPORT_SYMBOL(__asan_report_load##size##_noabort)
>
>  #define DEFINE_ASAN_REPORT_STORE(size)                     \
> -void __asan_report_store##size##_noabort(unsigned long addr) \
> +void __asan_report_store##size##_noabort(void *addr) \
>  {                                                          \
>         kasan_report(addr, size, true, _RET_IP_);          \
>  }                                                          \
> @@ -386,13 +386,13 @@ DEFINE_ASAN_REPORT_STORE(4);
>  DEFINE_ASAN_REPORT_STORE(8);
>  DEFINE_ASAN_REPORT_STORE(16);
>
> -void __asan_report_load_n_noabort(unsigned long addr, size_t size)
> +void __asan_report_load_n_noabort(void *addr, ssize_t size)
>  {
>         kasan_report(addr, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__asan_report_load_n_noabort);
>
> -void __asan_report_store_n_noabort(unsigned long addr, size_t size)
> +void __asan_report_store_n_noabort(void *addr, ssize_t size)
>  {
>         kasan_report(addr, size, true, _RET_IP_);
>  }
> diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
> index 32e80f78de7d..065e1b2fc484 100644
> --- a/mm/kasan/report_hw_tags.c
> +++ b/mm/kasan/report_hw_tags.c
> @@ -15,7 +15,7 @@
>
>  #include "kasan.h"
>
> -void *kasan_find_first_bad_addr(void *addr, size_t size)
> +const void *kasan_find_first_bad_addr(const void *addr, size_t size)
>  {
>         /*
>          * Hardware Tag-Based KASAN only calls this function for normal memory
> diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
> index 8b1f5a73ee6d..689e94f9fe3c 100644
> --- a/mm/kasan/report_sw_tags.c
> +++ b/mm/kasan/report_sw_tags.c
> @@ -30,7 +30,7 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -void *kasan_find_first_bad_addr(void *addr, size_t size)
> +const void *kasan_find_first_bad_addr(const void *addr, size_t size)
>  {
>         u8 tag = get_tag(addr);
>         void *p = kasan_reset_tag(addr);
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index c8b86f3273b5..3e62728ae25d 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -28,13 +28,13 @@
>
>  bool __kasan_check_read(const volatile void *p, unsigned int size)
>  {
> -       return kasan_check_range((unsigned long)p, size, false, _RET_IP_);
> +       return kasan_check_range((void *)p, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__kasan_check_read);
>
>  bool __kasan_check_write(const volatile void *p, unsigned int size)
>  {
> -       return kasan_check_range((unsigned long)p, size, true, _RET_IP_);
> +       return kasan_check_range((void *)p, size, true, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__kasan_check_write);
>
> @@ -50,7 +50,7 @@ EXPORT_SYMBOL(__kasan_check_write);
>  #undef memset
>  void *memset(void *addr, int c, size_t len)
>  {
> -       if (!kasan_check_range((unsigned long)addr, len, true, _RET_IP_))
> +       if (!kasan_check_range(addr, len, true, _RET_IP_))
>                 return NULL;
>
>         return __memset(addr, c, len);
> @@ -60,8 +60,8 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -       if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
> -           !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
> +       if (!kasan_check_range(src, len, false, _RET_IP_) ||
> +           !kasan_check_range(dest, len, true, _RET_IP_))
>                 return NULL;
>
>         return __memmove(dest, src, len);
> @@ -71,17 +71,17 @@ void *memmove(void *dest, const void *src, size_t len)
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
>  {
> -       if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
> -           !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
> +       if (!kasan_check_range(src, len, false, _RET_IP_) ||
> +           !kasan_check_range(dest, len, true, _RET_IP_))
>                 return NULL;
>
>         return __memcpy(dest, src, len);
>  }
>  #endif
>
> -void *__asan_memset(void *addr, int c, size_t len)
> +void *__asan_memset(void *addr, int c, ssize_t len)
>  {
> -       if (!kasan_check_range((unsigned long)addr, len, true, _RET_IP_))
> +       if (!kasan_check_range(addr, len, true, _RET_IP_))
>                 return NULL;
>
>         return __memset(addr, c, len);
> @@ -89,10 +89,10 @@ void *__asan_memset(void *addr, int c, size_t len)
>  EXPORT_SYMBOL(__asan_memset);
>
>  #ifdef __HAVE_ARCH_MEMMOVE
> -void *__asan_memmove(void *dest, const void *src, size_t len)
> +void *__asan_memmove(void *dest, const void *src, ssize_t len)
>  {
> -       if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
> -           !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
> +       if (!kasan_check_range(src, len, false, _RET_IP_) ||
> +           !kasan_check_range(dest, len, true, _RET_IP_))
>                 return NULL;
>
>         return __memmove(dest, src, len);
> @@ -100,10 +100,10 @@ void *__asan_memmove(void *dest, const void *src, size_t len)
>  EXPORT_SYMBOL(__asan_memmove);
>  #endif
>
> -void *__asan_memcpy(void *dest, const void *src, size_t len)
> +void *__asan_memcpy(void *dest, const void *src, ssize_t len)
>  {
> -       if (!kasan_check_range((unsigned long)src, len, false, _RET_IP_) ||
> -           !kasan_check_range((unsigned long)dest, len, true, _RET_IP_))
> +       if (!kasan_check_range(src, len, false, _RET_IP_) ||
> +           !kasan_check_range(dest, len, true, _RET_IP_))
>                 return NULL;
>
>         return __memcpy(dest, src, len);
> @@ -111,13 +111,13 @@ void *__asan_memcpy(void *dest, const void *src, size_t len)
>  EXPORT_SYMBOL(__asan_memcpy);
>
>  #ifdef CONFIG_KASAN_SW_TAGS
> -void *__hwasan_memset(void *addr, int c, size_t len) __alias(__asan_memset);
> +void *__hwasan_memset(void *addr, int c, ssize_t len) __alias(__asan_memset);
>  EXPORT_SYMBOL(__hwasan_memset);
>  #ifdef __HAVE_ARCH_MEMMOVE
> -void *__hwasan_memmove(void *dest, const void *src, size_t len) __alias(__asan_memmove);
> +void *__hwasan_memmove(void *dest, const void *src, ssize_t len) __alias(__asan_memmove);
>  EXPORT_SYMBOL(__hwasan_memmove);
>  #endif
> -void *__hwasan_memcpy(void *dest, const void *src, size_t len) __alias(__asan_memcpy);
> +void *__hwasan_memcpy(void *dest, const void *src, ssize_t len) __alias(__asan_memcpy);
>  EXPORT_SYMBOL(__hwasan_memcpy);
>  #endif
>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 30da65fa02a1..220b5d4c6876 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -70,8 +70,8 @@ u8 kasan_random_tag(void)
>         return (u8)(state % (KASAN_TAG_MAX + 1));
>  }
>
> -bool kasan_check_range(unsigned long addr, size_t size, bool write,
> -                               unsigned long ret_ip)
> +bool kasan_check_range(const void *addr, size_t size, bool write,
> +                       unsigned long ret_ip)
>  {
>         u8 tag;
>         u8 *shadow_first, *shadow_last, *shadow;
> @@ -133,12 +133,12 @@ bool kasan_byte_accessible(const void *addr)
>  }
>
>  #define DEFINE_HWASAN_LOAD_STORE(size)                                 \
> -       void __hwasan_load##size##_noabort(unsigned long addr)          \
> +       void __hwasan_load##size##_noabort(void *addr)                  \
>         {                                                               \
> -               kasan_check_range(addr, size, false, _RET_IP_); \
> +               kasan_check_range(addr, size, false, _RET_IP_);         \
>         }                                                               \
>         EXPORT_SYMBOL(__hwasan_load##size##_noabort);                   \
> -       void __hwasan_store##size##_noabort(unsigned long addr)         \
> +       void __hwasan_store##size##_noabort(void *addr)                 \
>         {                                                               \
>                 kasan_check_range(addr, size, true, _RET_IP_);          \
>         }                                                               \
> @@ -150,25 +150,25 @@ DEFINE_HWASAN_LOAD_STORE(4);
>  DEFINE_HWASAN_LOAD_STORE(8);
>  DEFINE_HWASAN_LOAD_STORE(16);
>
> -void __hwasan_loadN_noabort(unsigned long addr, unsigned long size)
> +void __hwasan_loadN_noabort(void *addr, ssize_t size)
>  {
>         kasan_check_range(addr, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__hwasan_loadN_noabort);
>
> -void __hwasan_storeN_noabort(unsigned long addr, unsigned long size)
> +void __hwasan_storeN_noabort(void *addr, ssize_t size)
>  {
>         kasan_check_range(addr, size, true, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__hwasan_storeN_noabort);
>
> -void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
> +void __hwasan_tag_memory(void *addr, u8 tag, ssize_t size)
>  {
> -       kasan_poison((void *)addr, size, tag, false);
> +       kasan_poison(addr, size, tag, false);
>  }
>  EXPORT_SYMBOL(__hwasan_tag_memory);
>
> -void kasan_tag_mismatch(unsigned long addr, unsigned long access_info,
> +void kasan_tag_mismatch(void *addr, unsigned long access_info,
>                         unsigned long ret_ip)
>  {
>         kasan_report(addr, 1 << (access_info & 0xf), access_info & 0x10,
> --
> 2.39.2
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230421205754.106794-1-arnd%40kernel.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPZtoLzW42i651iYtdRsjKgwkkjNmkoFN69zQ3TXh10Lg%40mail.gmail.com.
