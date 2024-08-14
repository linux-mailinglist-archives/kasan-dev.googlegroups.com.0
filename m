Return-Path: <kasan-dev+bncBDW2JDUY5AORBAVL6O2QMGQER27FFRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id C7F9F951F5E
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:04:19 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-427ffa0c9c7sf76873415e9.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:04:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723651459; cv=pass;
        d=google.com; s=arc-20160816;
        b=G+LVMabBeTibdx+x0MswIfoAaZEU+uZh41s2iKPLDe8p23+VfiO9c/sYYR8HM/GuLx
         rN2D9wnrJuDyW58NGgkJqCbxFthnrsiNbhH9rii0lqCD0G+EM8x7xMYBFTsdd1IHyG15
         c7uaTrVHS4ZZjyAUrEwa1/60pa0lVDq3yHPjkARqLBUpE1RBDDdfi2AWHMHjcVx5kypd
         1krqR7zOeO8E6buIbl3HHJJqpXo7bNl3RVW7rIfTNNNdQwr3/Wnnql6uisTQyflFVaWv
         Eh8L6vIAREd2FzsT1p26z3RpIQu4FaHr542MpehXwpbFPjpZejIGt7IVcuhUZEjlNgs1
         RhnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=I8dMx7R5XLgaLeG94h7H4MSKvmxWgRwDQj3vBId4EeI=;
        fh=JicuBQv+T9uFmHByVdDCkaUiiMM26IN3a8rzJmVl6/o=;
        b=SypROS+SlozE//La/O8SjtQYjfobdhHdE196SPqKbbo+91oJu0xchYLUet+c++HxvL
         Xk/OrwbzjtA+MStB3KtRx+oI91bf7A6XXukzYv0CqbJIkJgs58LMqCDAlW3k4U4h76Qo
         W6MICoLz+mnYf/zbzJXIvS/PwmqQPz465xLkAh1SFRs8U5d3PFskj10KP4JPNfMQrWx+
         4t5bewcV2o9M1Gku6nwBexhRRRZ6dLhbiaYHMZYVBuSO6QWOtPxijO/hM8gjX4TgfRzz
         CxeXWhsoiDMuuF2/zC5fw6j9QJ0q5SaKCfSjGGze8y+60BELt1aTb5cy5Z0zvyRxEqNf
         kWWQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jKXav+6T;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723651459; x=1724256259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=I8dMx7R5XLgaLeG94h7H4MSKvmxWgRwDQj3vBId4EeI=;
        b=GM2RZgo+S/2fpLP4/7u/b15Rw2kx0VarIFc387PA+zBwvJTzmC71UG0zTe1QV0/GbU
         kFdwn5CLkjMDxTsQXNXxcx4H510tdgL8gKUoAV07MGtTFjc6KzyrYZ5Zu1hc2JfYtydy
         xBNkvfVq/QzDGzYU91vYiX6lQABQ9R2tjWIOGigjErmdqz+X2OpxtMtt/F04YN8iscw3
         cg43qki+l3NflGMYJFvi1ClW++VmTNAvQkEoXHRppQFko3f8pBeT/JUb7XiKXCCGS6MJ
         KC68xL/eRgUcikTixBP6bg3sw+mikrNh/dHOPIOhx2vEsPvgRnKVLSZwS1+k2Xs9XbKy
         JX2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723651459; x=1724256259; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=I8dMx7R5XLgaLeG94h7H4MSKvmxWgRwDQj3vBId4EeI=;
        b=Yp/VxHP7lGc64Rkxm4Oa88TAisKAh16asKyKQAeS9Oytng/2IiwzUqZWRV3p6PYW7c
         lm8lVmjVHdoJJci+e/mOxkMJk2sPGRqaRJ40XSEyUNRf9fPDnNdOFr9eUgFQZWjRyfnZ
         xHAtfduu5JPk/Ppk5VZqu5p+BaSvsjYWW5Q6EDVIFNXL7/a9+U4ss31xwNakQsGaB0z2
         nQMuuQ2wzCg8MG7YqXM2W0pyjUviFhygw/aN/XtN5gqe1YucuAXWy1fjbYu96Mt+P8JB
         1VAlAPvzsN67outO+QZYu7nAGaWX8QRP/whTS5zy6Km8tgXqBcF+XG+fDqCB9u+ZXKnO
         GgYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723651459; x=1724256259;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I8dMx7R5XLgaLeG94h7H4MSKvmxWgRwDQj3vBId4EeI=;
        b=Y6Xj4M86VaexfHpK2M/R+XGBF8za4E1g6heRl4nL6jecIFp7LrBKw+9vyPmM5DNSEx
         V76I+KH6bhPYJbVYGlERuRt/IOv3KM3cdtGnjatxYpFTHcO++vXlSN0bw+ygXwF1UP4D
         AfRj0tJfhFRieX3E6/wbd9oHpX6qEHGRTnhenAC6RIvjR3M2APusc3N/7wdlELnVx+aO
         fm5tTRxhNUNltOPi2eevKtytGM4gdz5ZW4XtL43upDqp0alJ/pNZfdX0WgDfZGUBYqoF
         +DEyPt2GHKY7hXuA5p5LgFVdtmLFI+oP4FvrKwdhqVphXDT+xebzECLtOpZ6WXQly6MC
         sCXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUP+arxshGSHx9gEBrxDRGwksK5RolfgZS7yMEKMCNULKGWT0xoEYnm/QyjScsCEA4YhPBFsw==@lfdr.de
X-Gm-Message-State: AOJu0YzRHTdJXIk/ZS4mdpaNLj/ZMFsL9SF69Ih7X2hGmO52l7FLyqmx
	tfv1iBb58fhT0sM3+g6bFEQcNWHsuV1jio3BQhYeV2upM5+fUFs8
X-Google-Smtp-Source: AGHT+IEKCBK6kgD/Szcp5aSPQd7m84g+6y2iVfpmk81xvDvQHGwdsRLsf9O/835KLXk4I+At+ndZog==
X-Received: by 2002:a05:600c:450a:b0:426:5b44:2be7 with SMTP id 5b1f17b1804b1-429dd2365e9mr31602785e9.10.1723651458403;
        Wed, 14 Aug 2024 09:04:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5121:b0:426:6eb9:5098 with SMTP id
 5b1f17b1804b1-429e23ded7bls122205e9.1.-pod-prod-05-eu; Wed, 14 Aug 2024
 09:04:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWG0XaziAcJNO0vLNIilnyJd9TBXBw6MoM5SsyPlrwvCr9AkwQ1pH+/JPsjafIJaai+6HqiP2zx2ZA=@googlegroups.com
X-Received: by 2002:a5d:5109:0:b0:368:6596:edba with SMTP id ffacd0b85a97d-371777de5f3mr2603237f8f.39.1723651455843;
        Wed, 14 Aug 2024 09:04:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723651455; cv=none;
        d=google.com; s=arc-20160816;
        b=LK1vaoYDTI86q56Z9mqMEtJAd32MRE/byqBpcWo5mw/tt89VPW27IYC1xVVdvJ8+1T
         LhBDrKvLXdyY7oUuF/EClw9Q3rZapjNM0Su1EvZxa2Auz03eAI7b5JwP8ML9Koe7dyhj
         aRlyhD+NL9EsFGp+2haA3X3O64OLs+LyOs8i5IbAZcAwE6b+KaDfaCVKNW6PXvG9H6pV
         laH/qZGckyFS8qD5htaxaLgAlgqWrXDy3oOD5EWxgOfs6fuwZbc1Cgyo4kU8wDZfxxWv
         9erkQt/Z2U3qksQjwp3Jdvjw133tPN4P304A+IKsaQnhPWP9/Qi2V72okRNbN+fRSg/9
         TeqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9YUv+UEK7DbXaXmZeHJkOXNJ/5IGPTcl3OKytRpyoA0=;
        fh=BZHaFXl3RPT7jcIgeuKBSP6SHMNvAR/XBYI6ZGQYqQA=;
        b=S5D7TyoZgfMsYxLpx44fmgJ87BbBYorDixpNiHe0mKKcbO/XNnkbPpPYhzVx1dm/Dq
         VHnMN+EowNutydgdh9ktUqfKDsaEllmPTZXLJi1rAuvJS1MoQTlF0+A+bVPoNhUsdbNe
         NMLxhPO10Sn9iAgA55CypMlzCEc7pHCOaf5JetXbcK6JRmyqyhFR+uS1940PaSf1ahoi
         PBVJ73WFY7LRK2vD/oLph/ZKJyaBzpUNShP8BS0P7FMXyeibfvH/CTBEnWytJ7kESk9M
         CQwKdipG207b/vUqr8MLe9em4uWwvxAT2PBagbBSLX/sYiACdnYqyqYpf/URumsIe1Qt
         Tq8w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jKXav+6T;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x335.google.com (mail-wm1-x335.google.com. [2a00:1450:4864:20::335])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36e48b811c0si167465f8f.0.2024.08.14.09.04.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:04:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335 as permitted sender) client-ip=2a00:1450:4864:20::335;
Received: by mail-wm1-x335.google.com with SMTP id 5b1f17b1804b1-429da8b5feaso16842295e9.2
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 09:04:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU0jiMD/af0Y9vd9iy7yfk8sfti8NGcQ+PZEeAldXSPSyebK93lgAG7FvqVPjKkePQhfmUoVndqnts=@googlegroups.com
X-Received: by 2002:a05:600c:3b88:b0:426:5520:b835 with SMTP id
 5b1f17b1804b1-429dd22f28cmr29544235e9.5.1723651455149; Wed, 14 Aug 2024
 09:04:15 -0700 (PDT)
MIME-Version: 1.0
References: <20240814085618.968833-1-samuel.holland@sifive.com> <20240814085618.968833-8-samuel.holland@sifive.com>
In-Reply-To: <20240814085618.968833-8-samuel.holland@sifive.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Aug 2024 18:04:04 +0200
Message-ID: <CA+fCnZeHmfeQHDMFqELnPA-LNhWoKwxAKEPsEEBDCdoD9SEHwg@mail.gmail.com>
Subject: Re: [RFC PATCH 7/7] kasan: sw_tags: Support runtime stack tagging
 control for RISC-V
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-kernel@vger.kernel.org, Alexandre Ghiti <alexghiti@rivosinc.com>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jKXav+6T;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::335
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

On Wed, Aug 14, 2024 at 10:56=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> This allows the kernel to boot on systems without pointer masking
> support when stack tagging is enabled.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

But see a nit below.

> ---
>
>  mm/kasan/kasan.h       | 2 ++
>  mm/kasan/sw_tags.c     | 9 +++++++++
>  scripts/Makefile.kasan | 5 +++++
>  3 files changed, 16 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index fb2b9ac0659a..01e945cb111d 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -630,6 +630,8 @@ void *__asan_memset(void *addr, int c, ssize_t len);
>  void *__asan_memmove(void *dest, const void *src, ssize_t len);
>  void *__asan_memcpy(void *dest, const void *src, ssize_t len);
>
> +u8 __hwasan_generate_tag(void);
> +
>  void __hwasan_load1_noabort(void *);
>  void __hwasan_store1_noabort(void *);
>  void __hwasan_load2_noabort(void *);
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index 220b5d4c6876..32435d33583a 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -70,6 +70,15 @@ u8 kasan_random_tag(void)
>         return (u8)(state % (KASAN_TAG_MAX + 1));
>  }
>
> +u8 __hwasan_generate_tag(void)
> +{
> +       if (!kasan_enabled())
> +               return KASAN_TAG_KERNEL;
> +
> +       return kasan_random_tag();
> +}
> +EXPORT_SYMBOL(__hwasan_generate_tag);
> +
>  bool kasan_check_range(const void *addr, size_t size, bool write,
>                         unsigned long ret_ip)
>  {
> diff --git a/scripts/Makefile.kasan b/scripts/Makefile.kasan
> index 390658a2d5b7..f64c1aca3e97 100644
> --- a/scripts/Makefile.kasan
> +++ b/scripts/Makefile.kasan
> @@ -73,6 +73,11 @@ ifeq ($(call clang-min-version, 150000)$(call gcc-min-=
version, 130000),y)
>  CFLAGS_KASAN +=3D $(call cc-param,hwasan-kernel-mem-intrinsic-prefix=3D1=
)
>  endif
>
> +# RISC-V requires dynamically determining if stack tagging can be enable=
d.
> +ifdef CONFIG_RISCV
> +CFLAGS_KASAN +=3D $(call cc-param,hwasan-generate-tags-with-calls=3D1)

Let's indent this line by 1 tab (I already sent a patch that fixes
indentation in the other parts of this Makefile [1]).

[1] https://lore.kernel.org/linux-mm/20240813224027.84503-1-andrey.konovalo=
v@linux.dev/T/#u


> +endif
> +
>  endif # CONFIG_KASAN_SW_TAGS
>
>  export CFLAGS_KASAN CFLAGS_KASAN_NOSANITIZE
> --
> 2.45.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeHmfeQHDMFqELnPA-LNhWoKwxAKEPsEEBDCdoD9SEHwg%40mail.gmai=
l.com.
