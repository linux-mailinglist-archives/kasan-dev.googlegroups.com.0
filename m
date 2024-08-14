Return-Path: <kasan-dev+bncBDW2JDUY5AORB4NK6O2QMGQEYESAFSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5C1E951F59
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 18:04:02 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-5b77228abf9sf48816a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 09:04:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723651442; cv=pass;
        d=google.com; s=arc-20160816;
        b=Tzj/sER/CMvENtFkCAkVrUIqc6GHxjyOmHIqdDFF2hcfLSdJ6HyHjHNZugtScquJEA
         pcy04S9EI+ztTm9Fujmx9HtTpVY5vLFF6FxzF/gSbt/QHaNVGQyCLNioiu6xEqhBqZhv
         IyH/JCadSfO/ZWPQ9p/iaSHUBpH3Xmv7Cl3EwMxDA9nuPblFo8ub9A/a98Vmfdg18ZEr
         eR5Q+XzaaTcksdfIwgXdeKPPY2Kf9BLPvXlogRijl3UA2qao+bbR9HdpO48oPqvow5sP
         nCYHNYZzqn/kDtVlELqeAEOMLklfngPmkhafEoKvLkhwwm+JE6d7+5+3ZNNI7wd7SQa/
         dfYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=lWlLd4doR1y43MdwF2p2Ih+4UIUhGC3XUTZpFO+SFHI=;
        fh=a+rFt8H2fQQuII8u8lMySW65ATPhg7aDsFFy+uJq7ls=;
        b=sVYPvRBg+M46QgczhUfdOrCDvet2Hf4fsP/GzamNFY1jnDtdkKVDuBqmNolECnSF1G
         xpBecbiytRCssRHRjiOAA1bC1vx7DjGaG6vm4Pp/SqyIbnFOXNhINCFedc+AizSKpgiN
         ngQl4bpNJo3qAKxXjJXKNl2STey7HqtlvcOpcekT2r8y4UrhmZrC7FIabObeApsBeksi
         qnk05creKLnCBmTSWSdWM6D84M9HfViWs/xbwu6K69pWQv2DAdffmrwEy/iss86pzSke
         18uiem7CMLzk2Xp/sC5Mp7MRWmHlwOsnCvApXFOIigJJIfJmmvGTOuSboAt6DuKkXsP7
         AI4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ab4NhdeY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723651442; x=1724256242; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lWlLd4doR1y43MdwF2p2Ih+4UIUhGC3XUTZpFO+SFHI=;
        b=t5SHgEsNBcwJwIdOCwdrfz+uiMfj4iqfMsu4H6muubDv/xMW8bOGOsu6DChmebCeOD
         Voo/N5uZfF4q28pxd5tRChTP3ovPfNFGZIZEPWieNxOY5+IgoA7LaK9ZxjLKKJKfIKG5
         +fFDtBfiHFac2hwlV/clrDURRHXh6AIWm3kbIOcRQyCJXt6nmlgzIdSKJm+f3yuVDGFm
         qR0C4VlG3wNNfe1B1tj7BlBNoF860fUyEolF5wLzDFlIanB6nUn8KZC5sie0TVIcWAWB
         MCOCUcr3fe9TNf7Jq8oDPIHMaT3Yn4mbt6CWYahk+66p4HQ96Ec4CKdupKbvEFuifuKt
         rokw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1723651442; x=1724256242; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lWlLd4doR1y43MdwF2p2Ih+4UIUhGC3XUTZpFO+SFHI=;
        b=Bj7SH1xlMm9538mD2jPMpV+V6Dqf6WflRlOPPuNR4r1sP5fQO84Qpzp2OaVBK5WOw0
         bDWuoRTR2CD9wLgipYFqAng4PohrduK7OXh9fvon6ZNSBD2nTXc4mT7d3GlwpSCnlqMj
         V0BskmiNMF3N8k1TYl7HQeQglkKQ8TVtBCFfNoQG7eRcR19IUVDgv5HcUW3ve5La/yQ5
         G1HjSeG6pYiqS/TpxLH/6BlTx+m5INV0V2F7nkpdF7grT8X9/nCWbf3fDKfjvpLACAS8
         Nvrn0FEUEnC6DD/0KwavpaNdbkIc7U8D4h2SClwko2BZenz/9NEMWAu8jA1iYgRB2sVt
         zBWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723651442; x=1724256242;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=lWlLd4doR1y43MdwF2p2Ih+4UIUhGC3XUTZpFO+SFHI=;
        b=KyLVOP1S26zcnL/RdNi5E55heWpJ6m/eCxKDMQ4q3hSILE2Ft8PML2l1V+RxAurq2I
         fzfQABblzCb1HA6XSbmAzyCjHi0VPEuRXiYM0iwkfa4Rz05ZOhe5LGkbB5LFoy+SRd60
         oj9MhtNM0TYp1oS2wpzlzGODVrREF6GEGFyl6DgT2Qv3cgOLfquLbHoEG/H8LB3r5VDf
         beZ/hdGgTouTL2N87hopfnlO4hrxeBFkUcc6rSPFPPoXJqAXqdAd/U7UuauKkLz0YcSC
         f3MbjWmCdyWGGEi8xVPOWqA0nwdpZ7R30O2TqTtp8W5EDF979NN9smmckid3XbkeJGQZ
         FfRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV3CxhVLya3TbANbprCrotTAuI7GnP7fwzPIyowLqJnaAPPqjeuU2eiXxSaYORDh0Kc0Bb/fFEaBBtH4dITrdbFzweQDsm5pA==
X-Gm-Message-State: AOJu0YzU8yx21SfzDzHW8rpDss2htua7OEhDSRG8f8A36HfDDMWkAdnl
	69BQO8Ior+sc2gYmqzsIAMi4DDoY70g0e2fsFIM1gt8DGuBg5bEF
X-Google-Smtp-Source: AGHT+IEcCUCGuEZDxWmJgivaWYNj35QSEcV6b3Dnfyv49zWnkcQfxA6UYSa/3qDDequcKRaNRMrs+w==
X-Received: by 2002:a05:6402:26cc:b0:5b9:462d:c530 with SMTP id 4fb4d7f45d1cf-5bea1c6f790mr3126961a12.6.1723651441747;
        Wed, 14 Aug 2024 09:04:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:354c:b0:5af:38dc:9542 with SMTP id
 4fb4d7f45d1cf-5beb36cf814ls31934a12.0.-pod-prod-08-eu; Wed, 14 Aug 2024
 09:04:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXLXGXEIWUNt7c0vyzj92o8XxXxxP+SYgg9b/2r4/3XUl7XbHx0GzPropzjufKwdN3QmX043Hflf0d69F3mevq1/ONVqgPY3ZttYw==
X-Received: by 2002:a05:6402:42d1:b0:5a3:d140:1a46 with SMTP id 4fb4d7f45d1cf-5bea1cae14amr2506233a12.23.1723651439687;
        Wed, 14 Aug 2024 09:03:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723651439; cv=none;
        d=google.com; s=arc-20160816;
        b=C6dng9k+K6W4sfnY+GwQlaSfzUM4vSqut+kDIAw/ql1rqopKu1w3LZLBOPEBLFsCWM
         1bHosaDGA9S6nx/4aNq5QM//moc2ngOBXgkFDJ3lU+/BktgMpuCqYx1Zg+linup2OD2F
         j+jVlImwNhEhv36qhGVNS7GlSG0a5uqxk6CPE7Xhu1fStYNrn4ECLoqGQePzDd/GalM8
         0ewmiTMGgO8CPjbIeS38PG0223XZYRt7asyaLWy56eN9um9JLEdsWPa+dsS+I1IEt9xj
         jjNGO7vInlrEwxpOI3k4KuSzmp/+tyBTnX7XJgw1X1gaNCYUYa9tswIQAWNvg1vM6xIy
         KeGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dnVAjE8y+xk4uzYKyeuMufgQpUYFTpPW67lHJ8a/9Vo=;
        fh=iFxhNO2xPYENZuw8gPtc1lU2f+x2UsdiPaZyK6GWjqo=;
        b=ewDO7F7/ylAUuvlZZ+lO+9/68D3KAzF5m6uO6m7oSaDHiWdOBLdqWynq8bLzydkUHy
         cR0gD3Cr8m/AcbC2G0QqSsJzvrNq06j/zFoUie6Cx3MphEJXusg7W77+w4vbfGecL2Jr
         nvVfDhExWq4rnemyEMK3dLGgDSz1LkaintfrlPuUEncyVM47AUk8zU3oplueOljVYzJu
         oDXZ79TA6YtkL0kFGbJ6CNn/4mnmF3UsksVDHWYQ1q5T0rPZhTiHKUiFFTUE+zEnOPIQ
         bpKYzIfnkZXO0jn7Re4dyB0rAH+SSCv4v7uKw0mNSSBjZoOZaRYkSC7pmcfgrZ0GXyk7
         qDPA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Ab4NhdeY;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5bd1a5d73aasi319416a12.3.2024.08.14.09.03.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 09:03:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3684407b2deso41632f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 09:03:59 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXjFQyBDxPGmBxJ2fyNr4h0Ph6Fs3VU84RNEDFRGwjNMb2yYEyq+7htgOEI5GrSonoNXdyuFWbtpiTRqx2sox5dHjVLmuTEddW0Vw==
X-Received: by 2002:a05:6000:1542:b0:368:7f4f:9ead with SMTP id
 ffacd0b85a97d-3717775b981mr2772783f8f.7.1723651438898; Wed, 14 Aug 2024
 09:03:58 -0700 (PDT)
MIME-Version: 1.0
References: <20240814085618.968833-1-samuel.holland@sifive.com> <20240814085618.968833-3-samuel.holland@sifive.com>
In-Reply-To: <20240814085618.968833-3-samuel.holland@sifive.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Aug 2024 18:03:48 +0200
Message-ID: <CA+fCnZdqCSeSNeB+OpWFTPiTY0BguZKkWexiiELYt8TRqw4Vvw@mail.gmail.com>
Subject: Re: [RFC PATCH 2/7] kasan: sw_tags: Check kasan_flag_enabled at runtime
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
 header.i=@gmail.com header.s=20230601 header.b=Ab4NhdeY;       spf=pass
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

On Wed, Aug 14, 2024 at 10:56=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> On RISC-V, the ISA extension required to dereference tagged pointers is
> optional, and the interface to enable pointer masking requires firmware
> support. Therefore, we must detect at runtime if sw_tags is usable on a
> given machine. Reuse the logic from hw_tags to dynamically enable KASAN.
>
> This commit makes no functional change to the KASAN_HW_TAGS code path.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
>  include/linux/kasan-enabled.h | 15 +++++----------
>  mm/kasan/hw_tags.c            | 10 ----------
>  mm/kasan/tags.c               | 10 ++++++++++
>  3 files changed, 15 insertions(+), 20 deletions(-)
>
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.=
h
> index 6f612d69ea0c..648bda9495b7 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -4,7 +4,7 @@
>
>  #include <linux/static_key.h>
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
>
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>
> @@ -13,23 +13,18 @@ static __always_inline bool kasan_enabled(void)
>         return static_branch_likely(&kasan_flag_enabled);
>  }
>
> -static inline bool kasan_hw_tags_enabled(void)
> -{
> -       return kasan_enabled();
> -}
> -
> -#else /* CONFIG_KASAN_HW_TAGS */
> +#else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
>
>  static inline bool kasan_enabled(void)
>  {
>         return IS_ENABLED(CONFIG_KASAN);
>  }
>
> +#endif /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> +
>  static inline bool kasan_hw_tags_enabled(void)
>  {
> -       return false;
> +       return IS_ENABLED(CONFIG_KASAN_HW_TAGS) && kasan_enabled();
>  }
>
> -#endif /* CONFIG_KASAN_HW_TAGS */
> -
>  #endif /* LINUX_KASAN_ENABLED_H */
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9958ebc15d38..c3beeb94efa5 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -43,13 +43,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
>  static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
>  static enum kasan_arg_vmalloc kasan_arg_vmalloc __initdata;
>
> -/*
> - * Whether KASAN is enabled at all.
> - * The value remains false until KASAN is initialized by kasan_init_hw_t=
ags().
> - */
> -DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> -EXPORT_SYMBOL(kasan_flag_enabled);
> -
>  /*
>   * Whether the selected mode is synchronous, asynchronous, or asymmetric=
.
>   * Defaults to KASAN_MODE_SYNC.
> @@ -257,9 +250,6 @@ void __init kasan_init_hw_tags(void)
>
>         kasan_init_tags();
>
> -       /* KASAN is now initialized, enable it. */
> -       static_branch_enable(&kasan_flag_enabled);
> -
>         pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s)\n",
>                 kasan_mode_info(),
>                 kasan_vmalloc_enabled() ? "on" : "off",
> diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> index d65d48b85f90..c111d98961ed 100644
> --- a/mm/kasan/tags.c
> +++ b/mm/kasan/tags.c
> @@ -32,6 +32,13 @@ enum kasan_arg_stacktrace {
>
>  static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
>
> +/*
> + * Whether KASAN is enabled at all.
> + * The value remains false until KASAN is initialized by kasan_init_tags=
().
> + */
> +DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
> +EXPORT_SYMBOL(kasan_flag_enabled);
> +
>  /* Whether to collect alloc/free stack traces. */
>  DEFINE_STATIC_KEY_TRUE(kasan_flag_stacktrace);
>
> @@ -92,6 +99,9 @@ void __init kasan_init_tags(void)
>                 if (WARN_ON(!stack_ring.entries))
>                         static_branch_disable(&kasan_flag_stacktrace);
>         }
> +
> +       /* KASAN is now initialized, enable it. */
> +       static_branch_enable(&kasan_flag_enabled);
>  }
>
>  static void save_stack_info(struct kmem_cache *cache, void *object,
> --
> 2.45.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdqCSeSNeB%2BOpWFTPiTY0BguZKkWexiiELYt8TRqw4Vvw%40mail.gm=
ail.com.
