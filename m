Return-Path: <kasan-dev+bncBDW2JDUY5AORB7NMS6UAMGQEI2NU5NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id B3E2B7A3163
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 18:23:27 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-57354d4d075sf4444291eaf.3
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Sep 2023 09:23:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694881406; cv=pass;
        d=google.com; s=arc-20160816;
        b=CRtztKj083FZodmC1VcLtC9DQ7Vna6wEN0o1xmpdiemEI88vXSZ8JWXpf4w+SLK9ho
         opCLmWRXQn3CEGHGrLx8gt0UikEmz/prz+v9gIRHj2ybRVn7xHWx5HhPvHLkQAg0ocMa
         v4mv30T8ZYhilL9IIW20JErK2esPo20fTXUb26zGK6dif49rdJ/MvoHc4TqHmVjDt0kk
         3FqzF0RNbNLAnrGb+6hO7Zj2gdc8+HDhTa4AW8IehUVUKj/7AaWOJrPfLviGiTa6k6pX
         E8YCM+/I6CZerk8o5jDuhGXP4xHFJ5bFPbQjLqxvivCHt/AULXUmZQ3OsHbJsIUmlCCN
         KaRg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=qrsJNnMnM7yA/y2TPPXPLsdwt6+TLVgCV+u6w/3VL7E=;
        fh=+LUWCkJ0UIuituxBjcWE1BxZzH3KJlzA7rryUt8YPUI=;
        b=vEGxMOrZyHk6Nex/dL9vtioN+Yt6zY0raNNaYMLcsnQAxGQtZHtv7xVldrnXbwD7YA
         xUEXgOmmZxTmPszQN2EoSq9MD0h2RD18oa7XMxYuHoq+Sydc+MzigHD04zRB8DAOuZNK
         y/w0TqcCYw2vRpbNzXscEleaW7uV4XYK4SUXMjTZBLWh/NDtqUgs+DnA1PGjPIx9OVZs
         xAfGezjapOoGxzwC7rd4S0f15Ur9jqbmyZNTIkshVZebYqDqR4pWcF8XBCclhtxBndkf
         uGHojzwBpCbPbW4alePWYwmSL2+dOS8vZVDMj2W66WWU08DC/HjsdARmVRP+N4rZ8TEO
         AUvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LVXQjAwk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694881406; x=1695486206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qrsJNnMnM7yA/y2TPPXPLsdwt6+TLVgCV+u6w/3VL7E=;
        b=lrkAeetyA8I7Yn8XofGoHp4mLwacwlBErIsVFrNxibHCV728u40AcVYpMr+qAS1hT1
         JYCqdbJZj05C9qSF+z0jFMHKp/IcfEHQSGorHc7lqJ9WZqQjiYQo0vlEfMcHOss2+YR7
         NFYPqcA28nzCrfmtydy6XV8N7QZ1u08MsTrt3mepEcuIOB8a6TQeho0aa3qFlgOXaj3Q
         JTm/pt7Fn2F/ffVyDfsFj4GFXcEsCKKKbQoUat0uacgLfHrOYPqY7c1E7i4lrDqwpgqS
         um4kuuAM8uHjlSLRfk3NYPTOQx72EQN8mwIaJunETqB1qLXJIxyy16CS9TAGyhZaa9Xt
         XQrg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1694881406; x=1695486206; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=qrsJNnMnM7yA/y2TPPXPLsdwt6+TLVgCV+u6w/3VL7E=;
        b=hrvBMjPA1I/TOd+foxc3yOtpG4z4q22ykfvRyVVb+NZUpTpAPzx9iacV+qdvHak0Od
         h4iy+6fDPvSxLtbsWKcEfoVkYp2CmKPxV6SdtmOyiYXrNdVwAfbPBxTKVXWaKDwxeGgH
         RyatbdCLXrWKmjTmYZLBWDfj+dhIcrUTh7BdTHlrUGmQRAfNu69o38cJbDqaG6RZ3YCK
         gVowX+ygwdrZHFyMaPVI6yQCX53ImVNjLfMJf4GDPXYauo1vFjCSxmHbHgnpSbuOJynw
         Kd6lm/H4LYyYw+PJ7oR0EZO2kbCbAmDGNcXuIwBaoISYGfamMZx3mn5eDDm6FgUVjo00
         Hm8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694881406; x=1695486206;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qrsJNnMnM7yA/y2TPPXPLsdwt6+TLVgCV+u6w/3VL7E=;
        b=CCdKJdvx0vPmUlx47NOITb9o91nB2HYv1SlMDGuLt1VAfU51wbnuUP/MMwRIEe408g
         e47A3GKtcCu+PkD1rnOAF6F0+OQjv+E+TS7o18eabc6M1L8cA02rROrUAPevzNnwlu02
         oWXuReqXPyoBx2iKV4BtSTcYAIZUlLSE1X0FA82wFr7t5VqfSip4fQpFqzb9wBKD3xXY
         5dmW9v2laUcOyYJ1J5JahvZzt8xz0Hs5pcS4xwLr4mQmuABJJG3IwR05wT7/ileKksGj
         exR7iw24yQwrUaZPbpQEjJC2GG4jXFWlEUrbWvg554XusO6NMqaFoUWRNmhuS+5qLoCu
         eAFg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyiaGdKn0bQURp2CBEQIklIMJLK46L95v0clXphloCO4kLh2iBg
	Fv1R15dS4IRWiKJXLvCZeqs=
X-Google-Smtp-Source: AGHT+IGXsbeyrRMSz5XSJ7k6XQKoLJWin30baTupw1eILte5daxYGVyJvzaJ0x35hh0EdP7qSXD/Jw==
X-Received: by 2002:a05:6870:468a:b0:1d6:1668:db8a with SMTP id a10-20020a056870468a00b001d61668db8amr5878631oap.39.1694881405880;
        Sat, 16 Sep 2023 09:23:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:462a:b0:1bb:aa88:7406 with SMTP id
 z42-20020a056870462a00b001bbaa887406ls2146751oao.1.-pod-prod-01-us; Sat, 16
 Sep 2023 09:23:25 -0700 (PDT)
X-Received: by 2002:a05:6870:a11e:b0:1c0:d0e8:8fda with SMTP id m30-20020a056870a11e00b001c0d0e88fdamr5924583oae.16.1694881405299;
        Sat, 16 Sep 2023 09:23:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694881405; cv=none;
        d=google.com; s=arc-20160816;
        b=rX5qCrbulUf8H1QR2CGE06KBpO29K8jgAt6pEatjurVi36Z2Acj1qhp/+zt2Wo0ROE
         QzxtmRYmZYUYdonuNwtKoPJ/7BeIcFfPUcdGCqTd0zBbKU8qeihao/cxF8xzDPETbg0X
         PRE+w4NW5DYL2TvXakbROIZ7YAuJ8/MNOgTdVBFfuhfDqf4H5yLQvpfZMLOGHI3LknfY
         mkRBh09MZbzCXliQ1YPmIA88mo30zGki/qzC5BrEkw0Q79pMoTymlHldpzzYH4VPMDNx
         Yms4UmD+BOiTA5uJoUb9U2cEjSjGzJYH9HBqNagsAmQxMm9d3cyi2DP1pE/QnKg/FcIL
         ZWug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Vnbqp2QICXtxCRvhqirbkk4LQUQEjriYEsYOyafJQnA=;
        fh=+LUWCkJ0UIuituxBjcWE1BxZzH3KJlzA7rryUt8YPUI=;
        b=jjGyJO4Cr098YnzJPLqyvt9PiISPBfEGV7qxRuG5PgVDOoUXYtgrQzHyVTIk+TzPs8
         tRes+32m9cHEP1HF2AUaktmw168AdqzeH0j3QvljGgQeZPG7eEgvdKofOOpMK6OsTYWg
         L8LG4kQcWJ1M+sB1lYEnnENfMig0i0c8yHX10cuzlk32J53VZD72Jonq+UCuoyEQ1040
         2nXFdShPC91uSN/FmD3ntzvHDsPQlEF7o/udM8n74rmbDFBI07JRisgNjHpUzSKsoTMN
         sVK1a3AEE5SKRvQVMImlJuUHUUvYGb32GArdAqUu0L+d5Quia+RiD+cBl2poaEDilNnr
         YHRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=LVXQjAwk;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x429.google.com (mail-pf1-x429.google.com. [2607:f8b0:4864:20::429])
        by gmr-mx.google.com with ESMTPS id nx9-20020a056870be8900b001bbee2f288dsi980261oab.0.2023.09.16.09.23.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 16 Sep 2023 09:23:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::429 as permitted sender) client-ip=2607:f8b0:4864:20::429;
Received: by mail-pf1-x429.google.com with SMTP id d2e1a72fcca58-68fbd31d9deso2969183b3a.3
        for <kasan-dev@googlegroups.com>; Sat, 16 Sep 2023 09:23:25 -0700 (PDT)
X-Received: by 2002:a05:6a20:e11a:b0:14c:76bd:10c1 with SMTP id
 kr26-20020a056a20e11a00b0014c76bd10c1mr5776753pzb.21.1694881404475; Sat, 16
 Sep 2023 09:23:24 -0700 (PDT)
MIME-Version: 1.0
References: <20230912031750.3319584-1-chenhuacai@loongson.cn>
In-Reply-To: <20230912031750.3319584-1-chenhuacai@loongson.cn>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 16 Sep 2023 18:23:13 +0200
Message-ID: <CA+fCnZcSZi5nPPnbC3Ce7qChUFMwwSkP13fGSG4VXpDqOUimOg@mail.gmail.com>
Subject: Re: [PATCH V2] kasan: Cleanup the __HAVE_ARCH_SHADOW_MAP usage
To: Huacai Chen <chenhuacai@loongson.cn>
Cc: Huacai Chen <chenhuacai@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, loongarch@lists.linux.dev, 
	Xuerui Wang <kernel@xen0n.name>, Jiaxun Yang <jiaxun.yang@flygoat.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	loongson-kernel@lists.loongnix.cn, 
	Linus Torvalds <torvalds@linux-foundation.org>, WANG Xuerui <git@xen0n.name>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=LVXQjAwk;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::429
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

On Tue, Sep 12, 2023 at 5:18=E2=80=AFAM Huacai Chen <chenhuacai@loongson.cn=
> wrote:
>
> As Linus suggested, __HAVE_ARCH_XYZ is "stupid" and "having historical
> uses of it doesn't make it good". So migrate __HAVE_ARCH_SHADOW_MAP to
> separate macros named after the respective functions.
>
> Suggested-by: Linus Torvalds <torvalds@linux-foundation.org>
> Reviewed-by: WANG Xuerui <git@xen0n.name>
> Signed-off-by: Huacai Chen <chenhuacai@loongson.cn>
> ---
> V2: Update commit messages.
>
>  arch/loongarch/include/asm/kasan.h | 10 ++++++++--
>  include/linux/kasan.h              |  2 +-
>  mm/kasan/kasan.h                   |  8 +++-----
>  3 files changed, 12 insertions(+), 8 deletions(-)
>
> diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/=
asm/kasan.h
> index deeff8158f45..a12ecab37da7 100644
> --- a/arch/loongarch/include/asm/kasan.h
> +++ b/arch/loongarch/include/asm/kasan.h
> @@ -10,8 +10,6 @@
>  #include <asm/io.h>
>  #include <asm/pgtable.h>
>
> -#define __HAVE_ARCH_SHADOW_MAP
> -
>  #define KASAN_SHADOW_SCALE_SHIFT 3
>  #define KASAN_SHADOW_OFFSET    _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
>
> @@ -68,6 +66,7 @@ static __always_inline bool kasan_arch_is_ready(void)
>         return !kasan_early_stage;
>  }
>
> +#define kasan_mem_to_shadow kasan_mem_to_shadow
>  static inline void *kasan_mem_to_shadow(const void *addr)
>  {
>         if (!kasan_arch_is_ready()) {
> @@ -97,6 +96,7 @@ static inline void *kasan_mem_to_shadow(const void *add=
r)
>         }
>  }
>
> +#define kasan_shadow_to_mem kasan_shadow_to_mem
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  {
>         unsigned long addr =3D (unsigned long)shadow_addr;
> @@ -119,6 +119,12 @@ static inline const void *kasan_shadow_to_mem(const =
void *shadow_addr)
>         }
>  }
>
> +#define addr_has_metadata addr_has_metadata
> +static __always_inline bool addr_has_metadata(const void *addr)
> +{
> +       return (kasan_mem_to_shadow((void *)addr) !=3D NULL);
> +}
> +
>  void kasan_init(void);
>  asmlinkage void kasan_early_init(void);
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 3df5499f7936..842623d708c2 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -54,7 +54,7 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>  int kasan_populate_early_shadow(const void *shadow_start,
>                                 const void *shadow_end);
>
> -#ifndef __HAVE_ARCH_SHADOW_MAP
> +#ifndef kasan_mem_to_shadow
>  static inline void *kasan_mem_to_shadow(const void *addr)
>  {
>         return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index f70e3d7a602e..d37831b8511c 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -291,7 +291,7 @@ struct kasan_stack_ring {
>
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
> -#ifndef __HAVE_ARCH_SHADOW_MAP
> +#ifndef kasan_shadow_to_mem
>  static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
>  {
>         return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET=
)
> @@ -299,15 +299,13 @@ static inline const void *kasan_shadow_to_mem(const=
 void *shadow_addr)
>  }
>  #endif
>
> +#ifndef addr_has_metadata
>  static __always_inline bool addr_has_metadata(const void *addr)
>  {
> -#ifdef __HAVE_ARCH_SHADOW_MAP
> -       return (kasan_mem_to_shadow((void *)addr) !=3D NULL);
> -#else
>         return (kasan_reset_tag(addr) >=3D
>                 kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
> -#endif
>  }
> +#endif
>
>  /**
>   * kasan_check_range - Check memory region, and report if invalid access=
.
> --
> 2.39.3
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcSZi5nPPnbC3Ce7qChUFMwwSkP13fGSG4VXpDqOUimOg%40mail.gmai=
l.com.
