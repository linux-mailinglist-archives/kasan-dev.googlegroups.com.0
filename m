Return-Path: <kasan-dev+bncBDW2JDUY5AORBO7SY3EQMGQEC5FSRMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 530CBCA48DC
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 17:39:24 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4775f51ce36sf9215215e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 08:39:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764866364; cv=pass;
        d=google.com; s=arc-20240605;
        b=PeNp5DiuYmodzfJNvGKevBorSswcnz/QrBulnzP1FNJKiS7mpfOjaB5Opg7gsx4o9i
         0DH2Uz6gzyAnUJgj41WEm15qHsKARj6s2tFNessYZyKseAzVCc+qYKrHDynymBMLe5HM
         uVUPWMzasihBGAM6bpWhiex5nvALLPidiq8+nQJbMEsPHR+K5No3BIpIAJSv7Tv7r7Dl
         wDwJCvMaDOPCi//Gjw5AVvPs72wAM94T09YQnD0WHC0kTHv+V8IroXgZLSDzNcdeH6si
         cBxKL9MUX4iVWpw1P7tSYbqG2+Ehtga+VZ4R9vMO9aTmPrcrSOc/LkErCLr6gmV/dISb
         He7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=N2wHYZbc4aNsf7LYHoIeKqgtQ+umU9s9X4TPSN3inck=;
        fh=nsc9jflg//+PODBKhFSQYum2otvS8xUFOpi6E6HDThw=;
        b=KzcuX8kJuEVHtYoDDKFqwxvUtstBkpkfeprltFiJCWt3KQC/K+HS2THC795ETXxbXL
         /8k0ujaFq6Hm9CNOjEt8In7hWLR54sGMWsh7vt9f4ST6/pmwPOelbIo6E/sZeoNPEOlM
         3Ej1iQaD0ZCAASyXddcqKa+MTDNHw9M2XIhBKxP4IDUT3NIu6i2oQnMct94JxVuBtXlW
         84UFiFsNreGVg7YHPQL5r4vTH4Ewmc0g2GKYOgruAUGelAcheRRmiSVgIdN9Odjj84a3
         F0KcLygZ0JbDT9aqzb4w+Jlx3NuhWChm73ocwB/BTp6Hatlc0073/LNWfsdbPX4+uje2
         sRzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nB+OCi32;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764866364; x=1765471164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=N2wHYZbc4aNsf7LYHoIeKqgtQ+umU9s9X4TPSN3inck=;
        b=EU1I+tyHvp32uO/AVSAMdSdZLKLmDEdAoRodemx1v4T/n8A8F9xqj3zwWz25bH34xY
         S7q6kq1ZxKKZDwcloqduyI0Z/EIaLYY0jt8zP+0566yKqhWTVN4nXguxaprJ006CtC3b
         y3Ud+wto4IUgfcYH/+aBFedgCkcCzc8wV4zNBX8ldLHPEy8q0FmK2g67mffzZVZMOZau
         Np103O3kj387fl/p+pXw37alBHrGET1LkWoahP8SWknALpT2/RoM8E7lnPiwUxBksyG6
         zAVxyAJrK30kUY1/zYmhprO48E9bMG6T4o0FTcRFf6Mk6Ba55CSWs3Gm2YWVgWAICay2
         RnIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1764866364; x=1765471164; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N2wHYZbc4aNsf7LYHoIeKqgtQ+umU9s9X4TPSN3inck=;
        b=TZjH1oBY5rrOzYvxIDeYjb8kHnwgE5qpHvmwp+A1gOwXJ/ykQ/WR/I4h+CpDiDgmud
         8e2NKb1A5RzGRJAHXhO09/VgiPq6H+gKa2+zgEO5H/oPQ8i7AYM+jB4irWVV7GyTvK71
         LfgdGGMvQJb/+0FaYDazHIY9ZwTWQjqef7fMZBFyxfv/1OPD/jZzJ5CbidpnolaI/9ll
         hC6tLzHIfB7s7wdXATTp1O1klc+P2Uf2JZ8INGgS/Klg4onkO5iPPHUjKf7ipktvkTI+
         45fTsZRR+yFareOg5pFklzj5+7ZHEdCDWwuRvQLaNr1c/pozNgcKDMw/iOhwcUsal++q
         OjYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764866364; x=1765471164;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=N2wHYZbc4aNsf7LYHoIeKqgtQ+umU9s9X4TPSN3inck=;
        b=Hoo32RAC/Kh0N1X0nXFXC+CGaRqWfsFsCw4PCkpAZBJSG39Uqrg8QdQjTwtQafBkyX
         hvd27izWbkWCY68us5uwF9Y0CAnY7LBNo2tAArYjoc++CBBzPEUaG8VWg+W834AIgaN1
         cK9T0eFNlLuwqgp6drG9pxieyhVAFgwXpLUmuvfwnO4lK2EXvcDnF6JxlWGvvld4kxgq
         KEOqLs5x7t31t7ri6torGGLRcZaM8xFeAEBkUd1bB5crHngxqto41Ws5zhYq0Vi8y4gv
         TfHq1AypIJluDQSpzVvgZ7vQuF4hm3Cyyp8kIG/4fb9eo5NsPq2/bNpvq0Ulok1G5mUG
         GRlg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVOpU31PBZXBkbc59EN0tESdl6Cf7v3P6S/GmbpeKTR0BjG8U7hS886jWGM/WK3XKR9Wxc0VA==@lfdr.de
X-Gm-Message-State: AOJu0Yyf5WVgGjrm8kaFWo1KckkqvYSPDJbpHPh5ilNrVEsZv6Ttc3eV
	IS+eZUp6JMKnL8zl4xuw50XKe6IIB1IlIwKBVfAUkGGZNPtGmPFzwdG2
X-Google-Smtp-Source: AGHT+IFoob7OSsmD+5eNqkb9kt/pJsst5HH/XEY3g77nIFjTkRtOYzaJZohFmVRKds45xxtQfADY8Q==
X-Received: by 2002:a05:600c:198f:b0:46e:1abc:1811 with SMTP id 5b1f17b1804b1-4792af3e17dmr68218645e9.27.1764866363841;
        Thu, 04 Dec 2025 08:39:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aD50eIrtVW1Q+OfCjh2hBjB6vfIUPcMrn8EaIkGgSoqQ=="
Received: by 2002:a05:600c:c48e:b0:477:980b:bae9 with SMTP id
 5b1f17b1804b1-4792fb6232bls5335335e9.0.-pod-prod-05-eu; Thu, 04 Dec 2025
 08:39:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUA1qfb7fXbJqImBtRwh8JR7lurwWZxSnuzq9pgX1V86JQZzTpxF6e3hyzlSWlZGN428FpC0tthSmE=@googlegroups.com
X-Received: by 2002:a05:600c:4f0b:b0:477:63b5:6f39 with SMTP id 5b1f17b1804b1-4792af3267amr74806245e9.19.1764866361366;
        Thu, 04 Dec 2025 08:39:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764866361; cv=none;
        d=google.com; s=arc-20240605;
        b=eBTw//HkFxfbtetlqjYMvSIk4WLCBoSGsWOw7B3+TaP6ZOOhNCBPS1/1DJKbH2Lzd9
         X28yqGrgNbiMJN9dfr72R7IqAxROU19J5d2ysMaJxth+MZoyXDvbpI5ffK1jGxV3eaWJ
         JWc8Q+fLKS70Dy9/bBKaS9s451Zm1iq7ASZFICjZzn5R7D+FXniJEUh4eM+LRnzGyA+H
         L4nDe3lNXkA96Y/IvMxkCts+zcJUYdSyLKbdNS0XKP/dZh12Q5XJ9FgH7mdzV+DoDW/N
         JB85pgLBySwsTwihmFIH9AhklvL1caf+i4c6I1TaGW/M5slwIs9eLljo0uKVghtCHIDK
         Jy6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=hCk7JgdAPLLkYhpcS4mPpcBCsA+/FaiQTCAUq224jgk=;
        fh=XRCRngKty6wAMJaCDsD1FdB2Fi14v8xub+BAiWt6cOU=;
        b=BeuyBHoCj9JVrKxQVZCYr8MTPVzvPZVFFMw7bC0wYVt1FP1AMTTiD8uIZbXycJqv2i
         3DbpQdEmYm+8PhlveVPSPG85AEj2g9sQtLA9TJfaiOCx5lOevNkCEcE6fNVwfunLIbnA
         5rpdvHcCa85LJzmYouglMrsYM085S7cDTpE1UDSBweB+PUkPIJm0jAlreOERfmL/y0Wy
         5Eq34NnTxyeShJyxOv2/0oGEnFEYacaslvMmXUyKE6zjkbR67tA2TedeeXLzVkWGtYaW
         /2ywBrZQMybwyN+m2Nv12JNx0Pd05KhTtXBsWiRLdqX/1oUIWfIISIE00O4u84huMvVS
         8JTQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=nB+OCi32;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4792afab915si820915e9.0.2025.12.04.08.39.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Dec 2025 08:39:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-42e2e2eccd2so829403f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Dec 2025 08:39:21 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUiC6od2rL9Xt3LDnXWgxz9Q4znUlQR0pSSlnVm/jQKmxXtrZIT1lFAF3bfdyk5mo9NxiA7IuW/pPM=@googlegroups.com
X-Gm-Gg: ASbGncs+8gv8IjzWeYcF6S+15hlSSDjkSGVwLGwr3UmNS+/ta+KNfIMPEIdcCf2KT8w
	/rncqdNxMysBKneipEE0J9c2zhBVLyH1qvCDQ1yn1QJbajpGi+9io4XLzJ23LksgHqjeUPtus/z
	XUsl+W6f9qTBJlPVZOgqq+n/e4kSnC/8rHI/LPuyGj9adcb9X6zl9LYkAggFurXmQZBoeEzPhVc
	luRtZ5exbNai795rnWA6vzjUIb507XLUv3+x9FHWjOV2s9l1Ye43xJ5htOrCLHC25ag0JDTl4TA
	J93QbXZPNkjPXCgwWFyCBZdTvaNIO9UEsgv0kYM=
X-Received: by 2002:a05:6000:2c0c:b0:429:d186:8c49 with SMTP id
 ffacd0b85a97d-42f731bcd25mr6805868f8f.56.1764866360830; Thu, 04 Dec 2025
 08:39:20 -0800 (PST)
MIME-Version: 1.0
References: <20251128033320.1349620-1-bhe@redhat.com> <20251128033320.1349620-3-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-3-bhe@redhat.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 4 Dec 2025 17:39:10 +0100
X-Gm-Features: AWmQ_blUh_06nghjvNtkMSFLLH4KmVbjTWIqXM8ANs1LK16keDIndnTKt6SV0Qo
Message-ID: <CA+fCnZeHZ4+8GOn0untumM0TE9TeSHqja9kAsbEb-+jbEFNQQQ@mail.gmail.com>
Subject: Re: [PATCH v4 02/12] mm/kasan: move kasan= code to common place
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, elver@google.com, sj@kernel.org, 
	lorenzo.stoakes@oracle.com, snovitoll@gmail.com, christophe.leroy@csgroup.eu
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=nB+OCi32;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
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

On Fri, Nov 28, 2025 at 4:33=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> This allows generic and sw_tags to be set in kernel cmdline too.
>
> When at it, rename 'kasan_arg' to 'kasan_arg_disabled' as a bool
> variable. And expose 'kasan_flag_enabled' to kasan common place
> too.

This asks to be two separate patches.

>
> This is prepared for later adding kernel parameter kasan=3Don|off for
> all three kasan modes.
>
> Signed-off-by: Baoquan He <bhe@redhat.com>
> ---
>  include/linux/kasan-enabled.h |  4 +++-
>  mm/kasan/common.c             | 20 ++++++++++++++++++--
>  mm/kasan/hw_tags.c            | 28 ++--------------------------
>  3 files changed, 23 insertions(+), 29 deletions(-)
>
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.=
h
> index 9eca967d8526..b05ec6329fbe 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -4,13 +4,15 @@
>
>  #include <linux/static_key.h>
>
> -#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)

These changes of moving/removing CONFIG_ARCH_DEFER_KASAN also seem to
belong to a separate patch (or should be combined with patch 12?); the
commit message does not even mention them.

> +extern bool kasan_arg_disabled;
> +
>  /*
>   * Global runtime flag for KASAN modes that need runtime control.
>   * Used by ARCH_DEFER_KASAN architectures and HW_TAGS mode.
>   */
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);

So kasan_flag_enabled is now always exposed here...

>
> +#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)

but the functions that use it are not. Why?


>  /*
>   * Runtime control for shadow memory initialization or HW_TAGS mode.
>   * Uses static key for architectures that need deferred KASAN or HW_TAGS=
.
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 1d27f1bd260b..ac14956986ee 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -32,14 +32,30 @@
>  #include "kasan.h"
>  #include "../slab.h"
>
> -#if defined(CONFIG_ARCH_DEFER_KASAN) || defined(CONFIG_KASAN_HW_TAGS)
>  /*
>   * Definition of the unified static key declared in kasan-enabled.h.
>   * This provides consistent runtime enable/disable across KASAN modes.
>   */
>  DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
>  EXPORT_SYMBOL_GPL(kasan_flag_enabled);
> -#endif
> +
> +bool kasan_arg_disabled __ro_after_init;
> +/* kasan=3Doff/on */
> +static int __init early_kasan_flag(char *arg)
> +{
> +       if (!arg)
> +               return -EINVAL;
> +
> +       if (!strcmp(arg, "off"))
> +               kasan_arg_disabled =3D true;
> +       else if (!strcmp(arg, "on"))
> +               kasan_arg_disabled =3D false;
> +       else
> +               return -EINVAL;
> +
> +       return 0;
> +}
> +early_param("kasan", early_kasan_flag);
>
>  struct slab *kasan_addr_to_slab(const void *addr)
>  {
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 1c373cc4b3fa..709c91abc1b1 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -22,12 +22,6 @@
>
>  #include "kasan.h"
>
> -enum kasan_arg {
> -       KASAN_ARG_DEFAULT,
> -       KASAN_ARG_OFF,
> -       KASAN_ARG_ON,
> -};
> -
>  enum kasan_arg_mode {
>         KASAN_ARG_MODE_DEFAULT,
>         KASAN_ARG_MODE_SYNC,
> @@ -41,7 +35,6 @@ enum kasan_arg_vmalloc {
>         KASAN_ARG_VMALLOC_ON,
>  };
>
> -static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
>
> @@ -81,23 +74,6 @@ unsigned int kasan_page_alloc_sample_order =3D PAGE_AL=
LOC_SAMPLE_ORDER_DEFAULT;
>
>  DEFINE_PER_CPU(long, kasan_page_alloc_skip);
>
> -/* kasan=3Doff/on */
> -static int __init early_kasan_flag(char *arg)
> -{
> -       if (!arg)
> -               return -EINVAL;
> -
> -       if (!strcmp(arg, "off"))
> -               kasan_arg =3D KASAN_ARG_OFF;
> -       else if (!strcmp(arg, "on"))
> -               kasan_arg =3D KASAN_ARG_ON;
> -       else
> -               return -EINVAL;
> -
> -       return 0;
> -}
> -early_param("kasan", early_kasan_flag);
> -
>  /* kasan.mode=3Dsync/async/asymm */
>  static int __init early_kasan_mode(char *arg)
>  {
> @@ -222,7 +198,7 @@ void kasan_init_hw_tags_cpu(void)
>          * When this function is called, kasan_flag_enabled is not yet
>          * set by kasan_init_hw_tags(). Thus, check kasan_arg instead.
>          */
> -       if (kasan_arg =3D=3D KASAN_ARG_OFF)
> +       if (kasan_arg_disabled)
>                 return;
>
>         /*
> @@ -240,7 +216,7 @@ void __init kasan_init_hw_tags(void)
>                 return;
>
>         /* If KASAN is disabled via command line, don't initialize it. */
> -       if (kasan_arg =3D=3D KASAN_ARG_OFF)
> +       if (kasan_arg_disabled)
>                 return;
>
>         switch (kasan_arg_mode) {
> --
> 2.41.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeHZ4%2B8GOn0untumM0TE9TeSHqja9kAsbEb-%2BjbEFNQQQ%40mail.gmail.com.
