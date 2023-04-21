Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZNKRGRAMGQEVQMQFOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 28DE56EA6CC
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 11:20:39 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id a1e0cc1a2514c-772b9a58252sf498179241.0
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Apr 2023 02:20:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1682068838; cv=pass;
        d=google.com; s=arc-20160816;
        b=qqyLLz02KJcVlt9IBEc2nFmnJv9mH+JeCQsxmEKWd3gMYvDsFpyZFLWd6r7ywHdxi6
         rPsAojg2JWsVJzNMyfogXQ90b33djPi5i1R7Q0BBfYRLBx35742UN+MwGndkzRDpILc6
         axnhoIbnDxmuA43sCCN8BNlyCCkZmNoWhuq9zv6Z2WjJx3raw3RhTNid89mNnUC7qwKH
         SY1BGsnSIVRCqnq7yWtRqOITYxDIkOTSThdwsbUj1Xkaht0SjM4m9UGVf/x9PUwusenm
         RO1GH/dv1QuXKM5WPXocgfraN9+Cqt42Q2JAR6qTB5zjg86N/zifSML/QrsipFFec0hC
         GSeQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=BKbtQnB1TjJcKtKNhfJz43RTAKXrBNMXOCo5A3PD7Qo=;
        b=xwHplaTmGUVIMxejxWpK9eqkajDki0XZZZr+u+KLeIw9xtNZ1rn7/yiNbfr1V94GCL
         w3qs5Gd2JuZPvV5alqZNpcFt73Db1gbnt2Yovt9GD6zOkDbVlTUNIighhO2PHc6xoGrX
         6Ymsa393CbSW88FKEWYsPVlT9U1w1KGIwHOJu09swkuPHxgU6bDW1qt39qwJ1Cc/azGO
         xjphRBmSKlrmOl77jbGlspPeyTxFNR0R77Dmo03yPjKaRR1Hi4Yt8SFBqr8v6yLXL7P7
         kgzC1FbgG0QoKF9ntNFZPs36KayKHweehP2c0wVkDvZolVkECZkt0hcinaK9ZbCFZb7g
         1v5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Y89RPHik;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1682068838; x=1684660838;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BKbtQnB1TjJcKtKNhfJz43RTAKXrBNMXOCo5A3PD7Qo=;
        b=aCRWJPRLSpjA8O+SfuQG/xUVjwFkUwWBBaM3T5TU9zz3QKQVSgdGTVOC+O6be1Rzkw
         qTw0oy5032quq2lEL/r2OIJrlBKz0sfoX2jY2UAB/XbHo7dI8f5ovRQdvVxxJfyMgw0c
         jkpmXztpMEmpFj7o7ZvwyWm+XHjAwBC+np5CmMRUYMaxaC048Rv3NTrRQ99Wg486FGL4
         kCKCLVD9Vxf2WsJjru+eiLjZG4j1szZwOKzTcQFkvEc3E19dvn+KKlAfvMyWYpMumqk+
         rqjq3AUrlQepKb5CeTns3yPBoT4VmRgXsk4/CTwYaiYBcVpq//410Y8AHh1UndFxRN0n
         7OjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1682068838; x=1684660838;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BKbtQnB1TjJcKtKNhfJz43RTAKXrBNMXOCo5A3PD7Qo=;
        b=gbFoKGHZpGwK3/9gqLqEfP2+hAz1VocMBihfSMwrtmxZz/s3YeK1u1U+PiyGDgP8SP
         SX9Ekqv8enKwUfsrlW7OoplVk83zN4HwGMxFeUBmp1l2yyOEHq3rT7XpYi1Sb8rod9Nw
         8PjojFnbZ5zZz4IByhh+xSGRZEe56biMRhuG9ksOSQ8mQoY2Z7I4BSXc/7Fd0aump696
         vx7md7JQdo/zi96vb3GktLfSG1dOrjBDsdcVQlPePOjon7av6LmjNuFJRiNz3BfHDkF6
         4lChuBu2mubm8tCSTCFVW3+YM0/is9d1F6fYVc9eBxbb00suTeT8H/SPhh2c3Vuoe5eu
         xZ/g==
X-Gm-Message-State: AAQBX9fjsJKOmMQosMSMDyQupb/bnYbUuXtdygkxsn6U4P37hW1TEFKJ
	TpgVnrZ/SHjcZPN1n1lC8iU=
X-Google-Smtp-Source: AKy350YO51Kp5nsC/LL3vAS1F2Mu70daquVyct1EEWnYIZypkyGjVEiwYZ/lTwlnE48BiKCp7Tlkrg==
X-Received: by 2002:a9f:305e:0:b0:771:f5ee:f4e with SMTP id i30-20020a9f305e000000b00771f5ee0f4emr2521046uab.1.1682068837704;
        Fri, 21 Apr 2023 02:20:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:20d8:0:b0:432:3540:65c1 with SMTP id g207-20020a1f20d8000000b00432354065c1ls496498vkg.3.-pod-prod-gmail;
 Fri, 21 Apr 2023 02:20:36 -0700 (PDT)
X-Received: by 2002:a1f:5f09:0:b0:43f:bd1a:50f4 with SMTP id t9-20020a1f5f09000000b0043fbd1a50f4mr516392vkb.7.1682068836827;
        Fri, 21 Apr 2023 02:20:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1682068836; cv=none;
        d=google.com; s=arc-20160816;
        b=rVZj9nuImUTxPYrLDAdVeokaWXtIuvcru18kkV/lLxbJAfYobYH2ah+BJA+kPV4Opf
         gAZaOu94X6vlbuUvWSCj6AuitREk5IRKNRKR/rf1dD6Aej48rz+9mXHpVdSBv3oyXZF7
         raNQP/PYpDh+5CKhuKDxeZ92zUK8WC5cmVVyI8A5lP7th5WLhKNeWfb+/uLuW4Vdphdg
         IHPg0jedyR0S+zfOkOOGDYLVxg7w7bp4GErvs6RvFgiQPzHfke400/YCnk8nUhNX8hzU
         D8NRtC28U0Lv2UCbyJDziuKl8wG6t5vUZO8b/O/XnVv7xVLV9yc0kSbC68ytYg+uegVQ
         ZgKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mfAz7BwEb0UdyABaDwDZ9FoWZJHZV+6NVF2UDA8vAjI=;
        b=geprg4aUXMXRiUoHayGM/kA7hIG+wZDk6i6XZq2lZGNh7ZN9zQSRKFkRKHh6HG2XsB
         EUtrzdJjLAlHuTNgWiVy7OmwEIGFbwri4WaHTx3S/NKs71JhTmohMUAhlootlP93bSqG
         PcuoNoSN9UoOaDGupBE+XQK1/KBOp7ZwGYutE5SxHAP4wdFInS6hfsFv9UBouqDHwwAy
         WWQaiyBpt0JG+Qxf/+D3hvMwZP9zfG88ejj/K34ovGr+Ew2ZaxZ2GCSW9QgAz6r2h1hA
         ZMnKrkgwOl/c0mUZbcb0B1jddL2WVfIZ7yyM64a619oAPOMvQ2gbAQAQrDpzauvvS56K
         1Jtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=Y89RPHik;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd32.google.com (mail-io1-xd32.google.com. [2607:f8b0:4864:20::d32])
        by gmr-mx.google.com with ESMTPS id z28-20020a056122149c00b004409ac628a3si192521vkp.5.2023.04.21.02.20.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Apr 2023 02:20:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as permitted sender) client-ip=2607:f8b0:4864:20::d32;
Received: by mail-io1-xd32.google.com with SMTP id ca18e2360f4ac-7637c5ed865so172550339f.3
        for <kasan-dev@googlegroups.com>; Fri, 21 Apr 2023 02:20:36 -0700 (PDT)
X-Received: by 2002:a5d:94d3:0:b0:760:ec3c:33ed with SMTP id
 y19-20020a5d94d3000000b00760ec3c33edmr1754809ior.5.1682068835857; Fri, 21 Apr
 2023 02:20:35 -0700 (PDT)
MIME-Version: 1.0
References: <20230421082026.2115712-1-arnd@kernel.org>
In-Reply-To: <20230421082026.2115712-1-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Apr 2023 11:19:58 +0200
Message-ID: <CANpmjNMRQiPPqifLbzob6OjOX9O+bWhGrQunZY+TY6gj9HwGug@mail.gmail.com>
Subject: Re: [PATCH] kasan: use internal prototypes matching gcc-13 builtins
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Arnd Bergmann <arnd@arndb.de>, Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Mark Rutland <mark.rutland@arm.com>, Kees Cook <keescook@chromium.org>, 
	Ard Biesheuvel <ardb@kernel.org>, Marc Zyngier <maz@kernel.org>, 
	"Matthew Wilcox (Oracle)" <willy@infradead.org>, Vlastimil Babka <vbabka@suse.cz>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, linux-arm-kernel@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=Y89RPHik;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::d32 as
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

On Fri, 21 Apr 2023 at 10:20, Arnd Bergmann <arnd@kernel.org> wrote:
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
>  - sizes are expected to be the built-in ssize_t type, not the one that
>    is provided by the kernel. On 32-bit architectures, this is usually
>    a signed 'int' rather than 'unsigned long.
>
> Change all the prototypes to match these, using a custom 'kasan_size_t'
> that is defined the way that gcc expects it regardless of the kernel's
> size_t/ssize_t. Using 'void *' consistently for addresses gets rid of
> a couple of type casts, so push that down to the leaf functions where
> possible.
>
> This now passes all randconfig builds on arm, arm64 and x86, but I have
> not tested it on the other architectures that support kasan, since they
> tend to fail randconfig builds in other ways. This might fail if any
> of the 32-bit architectures expect a 'long' instead of 'int' for the size
> argument.
>
> The __asan_allocas_unpoison() function prototype is somewhat weird,
> since it uses a pointer for 'stack_top' and an size_t for 'stack_bottom'.
> This looks like it is meant to be 'addr' and 'size' like the others,
> but the implementation clearly treats them as 'top' and 'bottom'.
>
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

Does it work with Clang?

I don't mind either way, but the custom kasan_size_t change seems to
just be needed to workaround the subtle inconsistency in type
definition, but in reality there should never be a problem. I'd rather
the KASAN code just uses normal kernel types and we just make the
compiler be quiet about it.

To do that, another option is -Wno-builtin-declaration-mismatch for
mm/kasan/ which just shuts up the compiler, and allows us to keep the
code as-is. Does it have any downsides?

> ---
>  arch/arm64/kernel/traps.c |   2 +-
>  arch/arm64/mm/fault.c     |   2 +-
>  include/linux/kasan.h     |   2 +-
>  mm/kasan/common.c         |   2 +-
>  mm/kasan/generic.c        |  72 ++++++++---------
>  mm/kasan/kasan.h          | 166 ++++++++++++++++++++------------------
>  mm/kasan/report.c         |  17 ++--
>  mm/kasan/report_generic.c |  12 +--
>  mm/kasan/report_hw_tags.c |   2 +-
>  mm/kasan/report_sw_tags.c |   2 +-
>  mm/kasan/shadow.c         |  36 ++++-----
>  mm/kasan/sw_tags.c        |  20 ++---
>  12 files changed, 170 insertions(+), 165 deletions(-)
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
> index e5eef670735e..c0cab050fbf7 100644
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
> +void __asan_register_globals(void *ptr, kasan_size_t size)
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
> +void __asan_unregister_globals(void *ptr, kasan_size_t size)
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
> +void __asan_loadN(void *addr, kasan_size_t size)
>  {
>         kasan_check_range(addr, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__asan_loadN);
>
>  __alias(__asan_loadN)
> -void __asan_loadN_noabort(unsigned long, size_t);
> +void __asan_loadN_noabort(void *, kasan_size_t);
>  EXPORT_SYMBOL(__asan_loadN_noabort);
>
> -void __asan_storeN(unsigned long addr, size_t size)
> +void __asan_storeN(void *addr, kasan_size_t size)
>  {
>         kasan_check_range(addr, size, true, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__asan_storeN);
>
>  __alias(__asan_storeN)
> -void __asan_storeN_noabort(unsigned long, size_t);
> +void __asan_storeN_noabort(void *, kasan_size_t);
>  EXPORT_SYMBOL(__asan_storeN_noabort);
>
>  /* to shut up compiler complaints */
> @@ -284,7 +284,7 @@ void __asan_handle_no_return(void) {}
>  EXPORT_SYMBOL(__asan_handle_no_return);
>
>  /* Emitted by compiler to poison alloca()ed objects. */
> -void __asan_alloca_poison(unsigned long addr, size_t size)
> +void __asan_alloca_poison(void *addr, kasan_size_t size)
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
> +void __asan_allocas_unpoison(void *stack_top, kasan_size_t stack_bottom)
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
> +       void __asan_set_shadow_##byte(const void *addr, kasan_size_t size)      \
>         {                                                               \
>                 __memset((void *)addr, 0x##byte, size);                 \
>         }                                                               \
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index cd846ca34f44..cce8fd1b33fb 100644
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
> @@ -289,6 +289,12 @@ struct kasan_stack_ring {
>
>  #endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
> +#ifdef CONFIG_64BIT
> +typedef ssize_t kasan_size_t;
> +#else
> +typedef int kasan_size_t;
> +#endif
> +
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
> @@ -311,7 +317,7 @@ static __always_inline bool addr_has_metadata(const void *addr)
>   * @ret_ip: return address
>   * @return: true if access was valid, false if invalid
>   */
> -bool kasan_check_range(unsigned long addr, size_t size, bool write,
> +bool kasan_check_range(const void *addr, size_t size, bool write,
>                                 unsigned long ret_ip);
>
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> @@ -323,7 +329,7 @@ static __always_inline bool addr_has_metadata(const void *addr)
>
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> -void *kasan_find_first_bad_addr(void *addr, size_t size);
> +const void *kasan_find_first_bad_addr(const void *addr, size_t size);
>  size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache);
>  void kasan_complete_mode_report_info(struct kasan_report_info *info);
>  void kasan_metadata_fetch_row(char *buffer, void *row);
> @@ -346,7 +352,7 @@ void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object);
>  static inline void kasan_print_aux_stacks(struct kmem_cache *cache, const void *object) { }
>  #endif
>
> -bool kasan_report(unsigned long addr, size_t size,
> +bool kasan_report(const void *addr, size_t size,
>                 bool is_write, unsigned long ip);
>  void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
>
> @@ -571,82 +577,82 @@ void kasan_restore_multi_shot(bool enabled);
>   */
>
>  asmlinkage void kasan_unpoison_task_stack_below(const void *watermark);
> -void __asan_register_globals(struct kasan_global *globals, size_t size);
> -void __asan_unregister_globals(struct kasan_global *globals, size_t size);
> +void __asan_register_globals(void *globals, kasan_size_t size);
> +void __asan_unregister_globals(void *globals, kasan_size_t size);
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
> +void __asan_alloca_poison(void *, kasan_size_t size);
> +void __asan_allocas_unpoison(void *stack_top, kasan_size_t stack_bottom);
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
> +void __asan_loadN(void *, kasan_size_t size);
> +void __asan_storeN(void *, kasan_size_t size);
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
> +void __asan_loadN_noabort(void *, kasan_size_t size);
> +void __asan_storeN_noabort(void *, kasan_size_t size);
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
> +void __asan_report_load_n_noabort(void *, kasan_size_t size);
> +void __asan_report_store_n_noabort(void *, kasan_size_t size);
> +
> +void __asan_set_shadow_00(const void *addr, kasan_size_t size);
> +void __asan_set_shadow_f1(const void *addr, kasan_size_t size);
> +void __asan_set_shadow_f2(const void *addr, kasan_size_t size);
> +void __asan_set_shadow_f3(const void *addr, kasan_size_t size);
> +void __asan_set_shadow_f5(const void *addr, kasan_size_t size);
> +void __asan_set_shadow_f8(const void *addr, kasan_size_t size);
> +
> +void *__asan_memset(void *addr, int c, kasan_size_t len);
> +void *__asan_memmove(void *dest, const void *src, kasan_size_t len);
> +void *__asan_memcpy(void *dest, const void *src, kasan_size_t len);
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
> +void __hwasan_loadN_noabort(void *, kasan_size_t size);
> +void __hwasan_storeN_noabort(void *, kasan_size_t size);
> +
> +void __hwasan_tag_memory(void *, u8 tag, kasan_size_t size);
> +
> +void *__hwasan_memset(void *addr, int c, kasan_size_t len);
> +void *__hwasan_memmove(void *dest, const void *src, kasan_size_t len);
> +void *__hwasan_memcpy(void *dest, const void *src, kasan_size_t len);
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
> index 87d39bc0a673..080c73acbfcc 100644
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
> +void __asan_report_load_n_noabort(void *addr, kasan_size_t size)
>  {
>         kasan_report(addr, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__asan_report_load_n_noabort);
>
> -void __asan_report_store_n_noabort(unsigned long addr, size_t size)
> +void __asan_report_store_n_noabort(void *addr, kasan_size_t size)
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
> index c8b86f3273b5..dccef3e9ad2d 100644
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
> +void *__asan_memset(void *addr, int c, kasan_size_t len)
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
> +void *__asan_memmove(void *dest, const void *src, kasan_size_t len)
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
> +void *__asan_memcpy(void *dest, const void *src, kasan_size_t len)
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
> +void *__hwasan_memset(void *addr, int c, kasan_size_t len) __alias(__asan_memset);
>  EXPORT_SYMBOL(__hwasan_memset);
>  #ifdef __HAVE_ARCH_MEMMOVE
> -void *__hwasan_memmove(void *dest, const void *src, size_t len) __alias(__asan_memmove);
> +void *__hwasan_memmove(void *dest, const void *src, kasan_size_t len) __alias(__asan_memmove);
>  EXPORT_SYMBOL(__hwasan_memmove);
>  #endif
> -void *__hwasan_memcpy(void *dest, const void *src, size_t len) __alias(__asan_memcpy);
> +void *__hwasan_memcpy(void *dest, const void *src, kasan_size_t len) __alias(__asan_memcpy);
>  EXPORT_SYMBOL(__hwasan_memcpy);
>  #endif
>
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 30da65fa02a1..ae8d26beb3a4 100644
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
> +void __hwasan_loadN_noabort(void *addr, kasan_size_t size)
>  {
>         kasan_check_range(addr, size, false, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__hwasan_loadN_noabort);
>
> -void __hwasan_storeN_noabort(unsigned long addr, unsigned long size)
> +void __hwasan_storeN_noabort(void *addr, kasan_size_t size)
>  {
>         kasan_check_range(addr, size, true, _RET_IP_);
>  }
>  EXPORT_SYMBOL(__hwasan_storeN_noabort);
>
> -void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size)
> +void __hwasan_tag_memory(void *addr, u8 tag, kasan_size_t size)
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

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMRQiPPqifLbzob6OjOX9O%2BbWhGrQunZY%2BTY6gj9HwGug%40mail.gmail.com.
