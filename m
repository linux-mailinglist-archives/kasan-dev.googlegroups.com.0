Return-Path: <kasan-dev+bncBDAOJ6534YNBB4N3Z3CAMGQEXB4VCXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BCF6B1CBDF
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 20:24:51 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-55ba198c6f6sf157656e87.2
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 11:24:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754504690; cv=pass;
        d=google.com; s=arc-20240605;
        b=JRgS+ubUIcl2cLm7RB5z8Rsf/fmDcUGdM4dhklSsWsDcjig8LvT9qDsl54k7zhuSKW
         0Rn7PyrOJvXVZJmJLJWD1YRPekEHARmw6R4rTUKEwGbYf6nrVMwrN6YrW9i8453iiIOO
         pKWftlEury1VljSqvFav8YR89xM0q5R3shicm7WclyTL1yPJ3FLSuxuh0+SpPzUoWH26
         vTdKxfFDV1HWSAPL4ZnhPFjrTpdKLdlwpMnVH8+i8jmbph9a6IMd3vHs+MClxePSTvS0
         teKnCvmcPcPpygl2+5TjPRYB+4ao4EvpMAcI3SapmXXXsn3tTTBJ0SDZXQFu08KpQpO4
         YV2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=TAn7PYAXiT4vYLlLYvJ8wl2MDC2sWIiPG2B+nP93AuQ=;
        fh=6e3KrPuDn6pqNA/Rykclijw2dsXCgLImhGzHbCAMogA=;
        b=hwit/RLTudJdPr/Je24ZgqTt1vo+mDWtVl+GZ3FrD6hgPQ7e+dRREmQsue2nNlJF/B
         oUWxmlxVvnwFbdG3tqJNEYQa5pdUkr22dv8GCphlfv4hw/Rmz5jEPWchwQ14L1qN78/L
         OdWzGJj/z1kCEt5pjunQqrbrE9ivuj+RYbB92TTKsZ6u6Rjat6NjXMyJBa7ZzA6NOphS
         SBnySDiyZq6lp53MdcPju7WYZL/84frKP49s4LrG6numtFXOtCEHy2c0UaRoCOcp3+8F
         GyOcg9M8mZqla5olAwkardtxQrC+6DP+vSi0OVs5u9YuZT3w4ufoeqc3qRUakAXYheXN
         rHmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KR3IeYXV;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754504690; x=1755109490; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TAn7PYAXiT4vYLlLYvJ8wl2MDC2sWIiPG2B+nP93AuQ=;
        b=gZCSRI5JzggCJHfHUsSNCGGTwaah4nEUNTPO1lKp+Y5TqjN4MfCk2YQfV7AcZQd+kd
         dlYe7T7qF/Yvtw/3wyJuwqyUF4A3lYoGk/WRbZR5m8/8NHlTfbY7x9ryqiNryprR1yON
         zym+yIzNox23kgsmTHrOGZNLrTQaQhIyvPXKy7MKRNKZYxnOawQ54HXxhuJRSKYpRQUC
         EIjlMKZztD626sKK0zZgsnquA7jA8/p2B9biqbstAoOGhrxMWWjS9CI+r37bPlGmm2j9
         rN8QDNdIOTblja8KlSLSuADMgYZbL2f/SyscjZ4OrR6wmbB3CrigLK0UKEhuz2bJnoE7
         UMVg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754504690; x=1755109490; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TAn7PYAXiT4vYLlLYvJ8wl2MDC2sWIiPG2B+nP93AuQ=;
        b=dJ2KptSgFkN3S6GxSl2zoZax+ZUqZC/f3sHQHVrwHea+3xC1bUeHrqompd/Yu19jx4
         bGyYmR+JmSosWci0fHAgVkf3zqWs1kW9WWs6E77Px3iSxjfD/N1clVYnnqNhIXLlZMoL
         KsOLghYU59IAXBwxz5d/mDr4q1ktIJe8ikITgKcwZj4mHZEAp1fGwzcwYEJmGeMkNATK
         P3EhF+PzmWU69X8UpkqtRJb4aqlpkh0hJAFmNFM6IfZJLHEYn9lzRp18jPjS5a9sx41T
         UYBzitw0olkErRxfsK8lHoehyCsJKPAehH2W0rB4XcwHl9YQBoFZvIswP18jMB4Mfa6s
         N10Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754504690; x=1755109490;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TAn7PYAXiT4vYLlLYvJ8wl2MDC2sWIiPG2B+nP93AuQ=;
        b=TlAr52dE+/6ZNzZfFGwEhbFbKqqo4SHkuXSjxRD3y6shJlugpiEmuKb1WYgRBLNu2Y
         qor1frTeS9T2e9ODjuxAQbk4DB2W9oyKXyy6HLYkiPDuyo5yzyJ3NA90ne+IE1RZ5DXt
         OXmTzvIys0x25aQvko78eJdN+F3ulnj1bw3KBntXwH9mF2YX3OphLwqLBE5V/Smj6jYz
         SJgaTdHNO38Ag9c5kn01fmNjh/jvGcSfsOky4sbOC7T6zx3QgfCJSBIvhJAVfKVkanhn
         EPzXcuv+XPV8VPqus+IFZcEnSeIrORAS0kbgcGkwr98pwoHYnLe9MKX1R36jEuWqhBmb
         R3tA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXVRdkaCIfIriEe9saNZblJr04LitoW/FX1LhRwXa++/LNI8ZoMFLZxVyfPTKQIm52ho90VwQ==@lfdr.de
X-Gm-Message-State: AOJu0YwwZ6Ew94ZSNljwV3brFirKAptIXM4/8MVIq6rD2w4bVaBJ9mq8
	SSz/NXYFNQhD9yhlXa8jwekMluvxZNwzr9mfFvxS0aPY6ygNS0ffETTT
X-Google-Smtp-Source: AGHT+IHdIBSI+mcu0wdm6sb0HEGhfv3fC/v/GFz5HxM3S6aPiNMgxsEE8Xxtt4k5/U1Cr+qj/+LaDg==
X-Received: by 2002:a05:6512:1389:b0:55b:8f9d:f78c with SMTP id 2adb3069b0e04-55cb68b6ae5mr47577e87.44.1754504689722;
        Wed, 06 Aug 2025 11:24:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdPwXzPr0jnDe8JwSEXX6pa8IK8duyc76HL+eIvx9nGaw==
Received: by 2002:a2e:b80e:0:b0:32a:5c14:7f1e with SMTP id 38308e7fff4ca-3338c4ca6b1ls807471fa.2.-pod-prod-01-eu;
 Wed, 06 Aug 2025 11:24:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0sljfxf2C3hziGMFg3oIBNiYv1sXol3hisbLx/03qNJOpRsrBg3NuWfP24BjnPdQBBQEdkSMgW7E=@googlegroups.com
X-Received: by 2002:a05:651c:1544:b0:32c:bc69:e932 with SMTP id 38308e7fff4ca-3338e879b6amr223301fa.7.1754504686658;
        Wed, 06 Aug 2025 11:24:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754504686; cv=none;
        d=google.com; s=arc-20240605;
        b=PBM7UGkHPQdtSITlZjDQ3rjFKtMKwvkiCh4XFr8Iuoj0LOhP7fJEgvnbV/SdWNB/Bw
         xMKwTysqMaVU5cr3LEjpMPAEfR2+e/vuN2rJeg38CtDKIMHKZEPXNRs789DKxatfp2lE
         1oaaDLS1KX1m/WYxu3Haq+O4m8p6nByJKv+WDMgfPxPzFAFD6/WQ/R+aoHKVwmyfOPed
         Y/IgOMlJ6U7pR0laGkcie5gAiHTy9+/ubrxGMr8mHHc8301yYyrqcPMtsLUjDBSLjEUw
         KeA+Sf2tps37oFYp3Vbc6m/+n3zYyLxpaPdXEoxmCFWv//typCv8Y0ScJograaskaAWR
         2Mdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Jzfnt4fl4r2JAvr3EQAhX7jF93WfuTFzsNkMkN0wipE=;
        fh=9qDDnAGYyAzT469k8rH4BUMF11H161J9OnUseob0B5g=;
        b=AFDbFjaKJfNqOjDsz9LXrqwEOfLupSj8Fm9GGg1osz1iNVAXuRSBCBGrJK/S0+K3zW
         Pehegs0JD8nCJ6i+vr4FyULG3Bg7wPhoE2AW3bruDsnWbqoi+bdWUh4MEjny9ky7dX+6
         wydlEOPhslUK6JGhj2k5ZJQLzDD2V+WemP5QjCYVEGKedh/gzSoqrw/ZZXA4BVvGs+aE
         Aup/q859+rqLo2o82LX3a9WDEHUT+Jwm6nPpElCK39C2Subt4cj1BhjvVS4xcN0QFTLz
         1yepEykN2l9LKtn9EG1UHeCKE4kXGZnXVg5+Bsk9nRLev6qLKKnt4iWGG9fWYpOirwBb
         xEQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=KR3IeYXV;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x134.google.com (mail-lf1-x134.google.com. [2a00:1450:4864:20::134])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3327023d5b7si1767671fa.7.2025.08.06.11.24.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Aug 2025 11:24:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134 as permitted sender) client-ip=2a00:1450:4864:20::134;
Received: by mail-lf1-x134.google.com with SMTP id 2adb3069b0e04-55b7e35a452so197698e87.2
        for <kasan-dev@googlegroups.com>; Wed, 06 Aug 2025 11:24:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUL8eFRN8Ja72VZjbUxZBK3t/b88sQS2hbmbhLNG06GGfHcZ7g5928god3bnsi4SJBmzf24338OSmE=@googlegroups.com
X-Gm-Gg: ASbGncs6PYj7JjK21ouUstUiJDbhn5ZA+8KlOn3eZCV6XlKYbeODeKCxaC5k/pskTc+
	CuhkSUGpr60q12rYd3IbE7vEQrlIXE/5IpAICJfBcFYjNN8BHnlwecmJyOkzTfPCgFS44E6z53u
	irZrpkNasvbmiBZtg7NGPgRdaHcYM4X+wFlTEYPv3i4obORiqMUTVX1FW62/yC70NfhnH+tIcd/
	K5my+4=
X-Received: by 2002:a05:6512:224d:b0:55b:7cb7:f57c with SMTP id
 2adb3069b0e04-55cb69c0452mr37793e87.57.1754504685766; Wed, 06 Aug 2025
 11:24:45 -0700 (PDT)
MIME-Version: 1.0
References: <20250805062333.121553-1-bhe@redhat.com> <20250805062333.121553-5-bhe@redhat.com>
In-Reply-To: <20250805062333.121553-5-bhe@redhat.com>
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Date: Wed, 6 Aug 2025 23:24:28 +0500
X-Gm-Features: Ac12FXwvECclFxV4j0m2efvjg_nqG0wG27nQYV0fVI0B5ZHzOZg6GczwOHM9vRs
Message-ID: <CACzwLxivXFYXuF1OkqcP9THar7UGQ3VVAQgQm=PU9Tohb8hnRQ@mail.gmail.com>
Subject: Re: [PATCH 4/4] mm/kasan: make kasan=on|off take effect for all three modes
To: Baoquan He <bhe@redhat.com>
Cc: linux-mm@kvack.org, ryabinin.a.a@gmail.com, glider@google.com, 
	andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, kexec@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=KR3IeYXV;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::134
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
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

On Tue, Aug 5, 2025 at 11:34=E2=80=AFAM Baoquan He <bhe@redhat.com> wrote:
>
> Now everything is ready, set kasan=3Doff can disable kasan for all
> three modes.
>

Hello,

I've been working on this already and a different approach
with the Kconfig ARCH_DEFER_KASAN has been proposed.

Please see v4 thread.
https://lore.kernel.org/all/20250805142622.560992-1-snovitoll@gmail.com/

It also covers the printing in a single KASAN codebase, instead of
printing "KASAN intiilaized" in arch/* code.
Also covers the enabling KASAN via kasan_enable() for all 3 modes.

It's up to KASAN maintainers to choose either version.
I just need the confirmation now if I should proceed with v5,
or your version if it covers all arch and cases should be picked up.

Thanks

> Signed-off-by: Baoquan He <bhe@redhat.com>
> ---
>  include/linux/kasan-enabled.h | 11 +----------
>  1 file changed, 1 insertion(+), 10 deletions(-)
>
> diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.=
h
> index 32f2d19f599f..b5857e15ef14 100644
> --- a/include/linux/kasan-enabled.h
> +++ b/include/linux/kasan-enabled.h
> @@ -8,30 +8,21 @@ extern bool kasan_arg_disabled;
>
>  DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -
>  static __always_inline bool kasan_enabled(void)
>  {
>         return static_branch_likely(&kasan_flag_enabled);
>  }
>
> +#ifdef CONFIG_KASAN_HW_TAGS
>  static inline bool kasan_hw_tags_enabled(void)
>  {
>         return kasan_enabled();
>  }
> -
>  #else /* CONFIG_KASAN_HW_TAGS */
> -
> -static inline bool kasan_enabled(void)
> -{
> -       return IS_ENABLED(CONFIG_KASAN);
> -}
> -
>  static inline bool kasan_hw_tags_enabled(void)
>  {
>         return false;
>  }
> -
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
>  #endif /* LINUX_KASAN_ENABLED_H */
> --
> 2.41.0
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACzwLxivXFYXuF1OkqcP9THar7UGQ3VVAQgQm%3DPU9Tohb8hnRQ%40mail.gmail.com.
