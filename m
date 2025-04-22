Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCPXTTAAMGQEH3DEZKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AD76A95E9F
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Apr 2025 08:47:39 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6ecfbdaaee3sf86217776d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Apr 2025 23:47:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745304458; cv=pass;
        d=google.com; s=arc-20240605;
        b=HjvLKxAFTIwyjjDYxVCwDsRVdFEInc5//YpDmILTo1L8yhtjunSSze2PRVHk2RvPQT
         4MdkGT8Z3OW1RPWDN2dSWY6dAzRpjupGLBM15VhsBI0+NonfQQ51qXAp/Dypmjff3dpO
         aCFxoCdyHJWTJmQz3B7x1L49bs42SrNkQMa+Vznz9gNqecj/WePe81C3bF9/5wttR5wn
         wsFkx757jmdcXalB+CnNuqJZcSpKY0DIgS1yjoySDInW4hQCNtI0IGuSUy5vRbRumUSk
         ynEfsFnd3dSdn3YDl4Nk0qnVz0Qo9LSWd5ktQnxhdQkoHaESojAzojOKjB/YqQnthaEe
         kJOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hE8d2MCo5YwPeQeftUWzbvqdo+rJK2uG17hSV/+Wwts=;
        fh=c3nVghg0Ns38Bs1H5xN6IqrKJ9pwn20h82dolXbm7kk=;
        b=Bfz2wKHlXpHLM8DTdnK1b971h2buT5i/O0FMNbQKqXSWZ29g82avSowlA0VhdzUKLT
         0M378LrgU1dM3bo2qlvPSmw5EP3cRN1XbE4dyFgGvUtYmx4BjZiB7RsF3U+pPLOb6nVJ
         qh2qtV6hR4HHJ+/ri2WNArhwGf00zuMATTxayNoI8OsCTSHe0QOZ9jqtvUXqsQeibBqA
         gas2ylklwUWVyhGEUuJtYzyN8Tm/kqbdJCeYDQOvZGarKu4nWXnfgvo14Qp2TQJsPbqg
         otnOcOGOxUsGcFwSFlouUsszKm3hdzCdqmue24JrtGgE23KNxCI3hkQezpHijeu9Lefn
         ej/w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pZtJUp9C;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745304458; x=1745909258; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hE8d2MCo5YwPeQeftUWzbvqdo+rJK2uG17hSV/+Wwts=;
        b=PglcD+er/+Q4lX6vqsr3E7KmyK4ZzhE2lIpvbxK90furHLyVW+iIBVO3yWJClTMOIm
         PjTpvEt5WdtmhsYukDAvUpas2Hl2D6U1jg99Vv1uZ3+PL3l8tsteOYDMkPNIy+wF9cPI
         lQR6gwGaGWFpxGAYFzqyy9iZcZ+UTV4yWlhRjKc1fivATHO4ewYkhApdgxNRq1R+csxJ
         siQxvSDJ33j7YmFGmM739Th5aNWDmTTOyzoeg+G9IwTtwJ7Xub6xjzvqsTggpLQx2eg0
         vGkFz+HIoHC5QYz6CGL6bDsgNx0GizWBek3fa9QOt38VD3gvShOn2MsdfXnD6xDV2IkD
         MsCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745304458; x=1745909258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=hE8d2MCo5YwPeQeftUWzbvqdo+rJK2uG17hSV/+Wwts=;
        b=arkEaWQ0xIiDkD9j7pst45RDZQDqGQW/Coza4T0A11APM8T9r+XvrvXdC+DmykGhFe
         rfMBtmszWrkB7zyekE8frAQ3afgn/ULvPs1KQIBdkv43JWZv7dC6QL+g3CtQDw+IsUof
         FOdYdt2Jh0tq2fhjw/meyE5qKiAe0UA+gJwaheE+RIs/F/Ay1kL8/glTL5ZhjqSfAkZk
         n0udzb5mUoOdpMXaECKcMiHSJ/y+4oi1yOPcdIdZkIimuF8ZPoAADh2PvDCjIMiWHAmF
         +CXngZpfjVSrXBtS8Eqe7TFCyYf6+zOz5uduawjZHaL7+bSfRl1Jrb/D7+act0Fpi8Fk
         k3ew==
X-Forwarded-Encrypted: i=2; AJvYcCUYZ67Ui78j1YkVzbe01ZIor3JtzW2VBpyHrBz4LDl1WPnAtttoyhkUEMGHjiqAmAUGdCXK6w==@lfdr.de
X-Gm-Message-State: AOJu0YyxeoAnGd4vvJ7cMzYwG2PNlD6DvzgrUfWaev9RZgE5QLGfDIpI
	6XoOtlD8Dv+tTszXVdnnFaIDZw7d+qPHv6ovvv9KhJtJ/nTehaDg
X-Google-Smtp-Source: AGHT+IGDxWHC8ihNx65NZXu8uPR1aI1I79qZiDZLb+nqeOYxp/9DvQU6W3KPbqGcc+LLtWKZUpblag==
X-Received: by 2002:ad4:5965:0:b0:6eb:2fd4:30a7 with SMTP id 6a1803df08f44-6f2c4656682mr255466776d6.33.1745304457792;
        Mon, 21 Apr 2025 23:47:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAL2Xqym9aNsGfVwkiiEoopqaZokhLfcg6EfIDRfexetVg==
Received: by 2002:ad4:4f31:0:b0:6e8:f267:6759 with SMTP id 6a1803df08f44-6f2b99a6e91ls14116216d6.0.-pod-prod-02-us;
 Mon, 21 Apr 2025 23:47:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWcpF1coLsEvjghxwqTQjOnsqwor1kgvL+ZJimqjELZP0V3vM32QDyBzLR8RzPp8GJD9HB/RAoeqT8=@googlegroups.com
X-Received: by 2002:a05:6122:885:b0:523:7c70:bc9c with SMTP id 71dfb90a1353d-5292541d3demr10268252e0c.5.1745304456635;
        Mon, 21 Apr 2025 23:47:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745304456; cv=none;
        d=google.com; s=arc-20240605;
        b=bhxuIzy8fkOXsBca3oGczi9wVn5W/S+Nm2La9aoSui1Pju/UGKVxonAr7/ETmZNQJB
         f6OMbVn7eE43UdhEyuez+fKdxXCARoMmcKNtKhgYS1jgnGZ0ocV+1Eq669e9NcD16Vgb
         FtjJAUmQncUv7t1VrQ8HhD3fhumvLYoaDNDTnqeyRI5w4B/xpQZ77Cno/IhzUbN6FtbC
         /vLx32pVHwrWqs9x3TbDHZdN36VQxkt/7TRJJ7UyA4+mA+x7EY3Y8d7NV7OWwep4XtXQ
         3UZOY0E+1+R+dd1coIdyIUPlCWhA+yz0FV/kC2yMJ4QV5SR5p84DCK3V5IFsz23MZs+2
         3yaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KKAS6wIFBYTNQk2AG4y+zlvav2QzKZsBSU++J/GtuPI=;
        fh=pVCWHu886KFcQ0IwuymxQI/53HQM2MF8DQClH3xTK7I=;
        b=NdCfkjGsKVDq8T9YRdPgs8I+rs+laYXbEmXTVp7Ld9uxDtJsKnrgzXrDVDY0A4whTD
         iJZriYvdY8SUWJcklBmi+r3izmUSYTGrnU4ZwBIeJI5k2+Wyee2CoabGUAojrpI/gMWl
         rjaJ8+ZfbYcUqdXW/uoo5iLNoVMVLAjk6Ed9dbaA1gJyTRLoNspjnscYw3y89CgMkYa3
         znBrt/KGmCk38MoISK3zZ+H3Q8XuwBA7sy4OJCTEKnYfJbEY6KPDeAUCatzosO0LAvyX
         y0m9NuyM65tu67t4z5QYrc+sV9+4MPxy1frhfDq03/DDaqdNzvgxY6LDDILkR3KLqGPB
         719A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pZtJUp9C;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-52922bf16c5si413657e0c.1.2025.04.21.23.47.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Apr 2025 23:47:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-af9a6b3da82so3066362a12.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Apr 2025 23:47:36 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWMlw3m8ypa7Dt8ib5Yb5eeqGcYAvGC9ndwmAKHRiVVuoRmlUZ5mJJULhsmU1yiNBrcGSpTjQLGj2g=@googlegroups.com
X-Gm-Gg: ASbGncufjemVfH8oOAFQVLdf7a3BUd+NXso+uK179wg59ybcbJM4OC+EUrYctPkmxGn
	dlq26c8Ge1SdZ0gdleZHTegPxC0QHq3OmVyOIoWXmK8k5sbU8yexsw9awHxkNgSjNDt6on/MJvj
	xpIg3UqSkbHzl4zaoF0pkf+dQDMjyuyjqm3pWjimXQRb3ALjNI//i1sENV4e74JwE=
X-Received: by 2002:a17:90b:3c90:b0:2ff:58e1:2bc9 with SMTP id
 98e67ed59e1d1-3087bbb08c0mr19968579a91.25.1745304455382; Mon, 21 Apr 2025
 23:47:35 -0700 (PDT)
MIME-Version: 1.0
References: <20250416085446.480069-1-glider@google.com> <20250416085446.480069-8-glider@google.com>
In-Reply-To: <20250416085446.480069-8-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 22 Apr 2025 08:46:59 +0200
X-Gm-Features: ATxdqUGqkiU8trjykBZPrhmswWXTH5ZyG4HAu5DV93iL9sw00B1XdAfKjEaLIO4
Message-ID: <CANpmjNOZyFeX2OfPsZkB3DfcFrdSWO9m+yGwB_rN3Mc+JySqnQ@mail.gmail.com>
Subject: Re: [PATCH 7/7] mm/kasan: define __asan_before_dynamic_init, __asan_after_dynamic_init
To: Alexander Potapenko <glider@google.com>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pZtJUp9C;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Wed, 16 Apr 2025 at 10:55, Alexander Potapenko <glider@google.com> wrote:
>
> Calls to __asan_before_dynamic_init() and __asan_after_dynamic_init()
> are inserted by Clang when building with coverage guards.
> These functions can be used to detect initialization order fiasco bugs
> in the userspace, but it is fine for them to be no-ops in the kernel.
>
> Signed-off-by: Alexander Potapenko <glider@google.com>

This patch should be before the one adding coverage guard
instrumentation, otherwise KASAN builds will be broken intermittently,
which would break bisection.

> ---
>  mm/kasan/generic.c | 18 ++++++++++++++++++
>  mm/kasan/kasan.h   |  2 ++
>  2 files changed, 20 insertions(+)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index d54e89f8c3e76..91067bb63666e 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -238,6 +238,24 @@ void __asan_unregister_globals(void *ptr, ssize_t size)
>  }
>  EXPORT_SYMBOL(__asan_unregister_globals);
>
> +#if defined(CONFIG_KCOV_ENABLE_GUARDS)
> +/*
> + * __asan_before_dynamic_init() and __asan_after_dynamic_init() are inserted
> + * when the user requests building with coverage guards. In the userspace, these
> + * two functions can be used to detect initialization order fiasco bugs, but in
> + * the kernel they can be no-ops.
> + */
> +void __asan_before_dynamic_init(const char *module_name)
> +{
> +}
> +EXPORT_SYMBOL(__asan_before_dynamic_init);
> +
> +void __asan_after_dynamic_init(void)
> +{
> +}
> +EXPORT_SYMBOL(__asan_after_dynamic_init);
> +#endif
> +
>  #define DEFINE_ASAN_LOAD_STORE(size)                                   \
>         void __asan_load##size(void *addr)                              \
>         {                                                               \
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e649..c817c46b4fcd2 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -582,6 +582,8 @@ void kasan_restore_multi_shot(bool enabled);
>
>  void __asan_register_globals(void *globals, ssize_t size);
>  void __asan_unregister_globals(void *globals, ssize_t size);
> +void __asan_before_dynamic_init(const char *module_name);
> +void __asan_after_dynamic_init(void);
>  void __asan_handle_no_return(void);
>  void __asan_alloca_poison(void *, ssize_t size);
>  void __asan_allocas_unpoison(void *stack_top, ssize_t stack_bottom);
> --
> 2.49.0.604.gff1f9ca942-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOZyFeX2OfPsZkB3DfcFrdSWO9m%2ByGwB_rN3Mc%2BJySqnQ%40mail.gmail.com.
