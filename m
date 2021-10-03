Return-Path: <kasan-dev+bncBDW2JDUY5AORBI6J46FAMGQED2AJDEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C82442030C
	for <lists+kasan-dev@lfdr.de>; Sun,  3 Oct 2021 19:13:08 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id k3-20020a05620a414300b0045e623cd1afsf21697634qko.20
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Oct 2021 10:13:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633281187; cv=pass;
        d=google.com; s=arc-20160816;
        b=WJ+Pkn4YDmY5sFWLK7D5snJeJPy8TDsdxPsPcADFwC7peqrFMWXNBdztkSoFdKEf/e
         XxX+d6CTzknvKvOs0fth7m4Ae3hjZzZ1u2Z2DvIr2IQRQU+yMGXmVFqaUoTfgwwbQ8o6
         iXUwb/1ABY5Oj1gguxX/HjtvKaxk/j/hMfkJqm0Rw1KUdmaIkOUJ+n9QyRDYVJNEj82V
         w8oNradFDn792UGl1LdwjFl2UYpxmqPczfy33vufzQLgjS+tl43UKyo+mkV6g0+QAkBz
         O82tMjQhXV70sXdbB59sEjRenZ6Qvnm73m7Eq7/tHnWi3zEV/vs/1ngAe30Ta4kra+1y
         xqNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=LSBxODMHxLyLGHMXxGpSP0hGnpSDQDalwxQkH7AVL+E=;
        b=eU//V7ilhhmoqGh1XNL4QOhfeNPT3uCwCS5c/oZtltNjMnzH+LaAMTmIhV8HqsBcW2
         c3CAo0ybbb5dNy+gawp4IFUYhxQHFfYhQpnv41LiVI6e4aMQ+KGyXGxa3lDbT21HEOmg
         9m4JLjSF807oprXLHyCxplTgN1WSO9PVI5mAzI8EkO8wzt8879teS2PJ5VYKzZtZnl4W
         tVAzbw8bpJQv3BOebMhMBAQJc9zbBPBefYTreIcMNKCVr2UIkm7FEY/OmSn9+nOwXMZt
         paFTSFARgbEQAse3bnghd6JN9Ddj7BBCcMlAaFE7qBKRRJD4XpnbtUu3eKn7yl9d56Qc
         Xaug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lnXzawzd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LSBxODMHxLyLGHMXxGpSP0hGnpSDQDalwxQkH7AVL+E=;
        b=WpnHW87E6CM4yZ/iVYC2z4aiIaN8EoELgjGByV35SjA8lKcE6V3fVgY0eMNoFZL3Wt
         GRFGxKBZNYfLVC2femPRUS5KiGDYgeqc04xh2KUIrAgPd3L5F2AS8gRJgT7Soovn3DCU
         Qp5QRBVHZ4+rxpVXy5Lz+Dv49EcA3A00X3IQNqRQ1Z/8KXWM5ZLG11tnTW2WLmNRJhwg
         5lz90L+B6hnDZJ8WfP+UrXkpIPOe7/dtg5dyDPJsA71m0i2/ecBx4fvT2ryHP4miTbx6
         jlOOl18gQsW9fepchU2dHAjv0tk9dYuNG2cOAxo/k6IiRcyzPQRWjz2cDNGTBu6nRqaO
         pN/w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LSBxODMHxLyLGHMXxGpSP0hGnpSDQDalwxQkH7AVL+E=;
        b=hCgyH4Z72W2ZTKBqDUkZXGYc5175O/cgkYBQWJdwIeIfvPbi/zuL8IfU+J1Nxbd4HU
         a//OLM7XbP5T8TrVgLDTRqmlysNGuWbIgDBzDUW4gEbnUWY26Frq5nCI55/+8yKAaRc6
         frndocEeekNo7xcLI4U/ups9YqMMiDgIXdtvXKnWcWTKX8Ox6o9EuHKhnQ9bU7SCMukx
         cNlewnsAeS3Jlhf00EdHYztn0924TTa9IE+YRU0xhuFotL5P1YSTrDojLNZ4tuoA7NZC
         b5AfScfOeW3ZDdvkIaqnIUuKSXRyBP+zs+NioPb7sBA9g5w+7Er15IhAeF/osB0SVJ1i
         hLog==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LSBxODMHxLyLGHMXxGpSP0hGnpSDQDalwxQkH7AVL+E=;
        b=0mnVNovqgbLyySbmxeVRtTrg6CGZHWHxg8t9dnHCL7yr/H9rRU49GhGdvUXJqtwWpC
         sAjb6lS/1kQ4enz0bSMMQ1qLGtxdQf2FLfO/eKBeBYAZExrS1d+eYzEGjHMUERLUFIRU
         txuwVIqQPoeslDAl6AnrhCV5stkL/GJ4ofGuNvQEjMXDYeVxM+Rq2ZTc+k7ZBEw8F3nv
         AWSJC1NzIrJz6cWvoN9WjDPyNkbtEusB/UjdFTXxpI89G+kTjmipTQ7kGvQCic40Shu6
         tFAeOdSOeZK43d6LDrtSLn2pOdYXNxmlwWK3UyH+nfJ1730gI+tBOYJ4eYrTjt5uLa9N
         bVgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WtUn0jCzoYOlWOrqtuvFuzzcUnDIHAUCam8eNGUBE1mzgEpw6
	Zdkb4CSys7AtGBSe0EO4+RE=
X-Google-Smtp-Source: ABdhPJwIlah11UqLmoD/cuprzjgiqI8N/CiZA4X18EGVjtVlNiGiJvgFpi+kV3T/Rz9osJi7Nt+xrQ==
X-Received: by 2002:ac8:7397:: with SMTP id t23mr9263374qtp.63.1633281187394;
        Sun, 03 Oct 2021 10:13:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:100f:: with SMTP id z15ls9033679qkj.2.gmail; Sun,
 03 Oct 2021 10:13:07 -0700 (PDT)
X-Received: by 2002:a37:2e82:: with SMTP id u124mr6664934qkh.58.1633281186950;
        Sun, 03 Oct 2021 10:13:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633281186; cv=none;
        d=google.com; s=arc-20160816;
        b=RM9bK6iLiWMyrXhd+BCT9IDaa+uYeQ8e0OCZa7+3WwOAeKBAM44K/HUmII8XGLboGS
         fym6snZPswi5Gi/2OdZRIkOZnrs/D1TYSm9qAdHjK7oMJHs+j749Sg8HC/ehMtMkpluJ
         BiAodqZU9BITJGzdyHC+BRSG4apMz7pW3+qbxX47PhykTbc6oy2JN1IIVqBM5KcFMa4A
         0mdmE7UhzqTsCQYDBU8kKHrEFDm3R42AuV1agTMzPH2Wsl9tpCZbW1vIeKyOgROJXERX
         +Sp8kMnrZaARdSfcsEsHw7VMZPGtiQUaCCcCYUuRvHVVHjCMlFkcMLkk4/kot4Grk5en
         51pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nQT2grhgRy79c0bM2yRcD+hXmQawHfrm6730jdCtlH0=;
        b=gE2okJ9dPXzf50K9bY7hzQDWGWMcagvZSVN0ET3ysnC2tqahkvaq5/ZitUf5AIPyLe
         /TlktnM/3xwKBEo6yjApRBYmVmmd48blWwR6ixK0TsT0B3uNanY9pcViEsOX5EX6cAF2
         vqqYUGRDULxIyR1O/uSq6h1N2jXhchg6GPql5HnRX320bA5rzkOPkTh1KsRZruEUaY6T
         IUYc48DYDXXuQTDaS2kPT4I6CBvVcrKpVkjen7BCJJEyULay5jtnYuezIIUwCy0BGpyf
         /f/FGaGfhkKT90ERQSqRhx6Zx7YQKJnFTxrbN1jhzj5VkW0ptzfzT2lCpcWUtRRX0eCg
         Ne3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lnXzawzd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd31.google.com (mail-io1-xd31.google.com. [2607:f8b0:4864:20::d31])
        by gmr-mx.google.com with ESMTPS id a1si1248537qtn.2.2021.10.03.10.13.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 03 Oct 2021 10:13:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31 as permitted sender) client-ip=2607:f8b0:4864:20::d31;
Received: by mail-io1-xd31.google.com with SMTP id y197so17588559iof.11
        for <kasan-dev@googlegroups.com>; Sun, 03 Oct 2021 10:13:06 -0700 (PDT)
X-Received: by 2002:a5e:db44:: with SMTP id r4mr6382777iop.56.1633281186706;
 Sun, 03 Oct 2021 10:13:06 -0700 (PDT)
MIME-Version: 1.0
References: <20210913081424.48613-1-vincenzo.frascino@arm.com> <20210913081424.48613-2-vincenzo.frascino@arm.com>
In-Reply-To: <20210913081424.48613-2-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 3 Oct 2021 19:12:56 +0200
Message-ID: <CA+fCnZffxd+nGngMQ+u6kJtJyGAScGocPwrU9yAPYKHRsU1Yjg@mail.gmail.com>
Subject: Re: [PATCH 1/5] kasan: Remove duplicate of kasan_flag_async
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=lnXzawzd;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d31
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

On Mon, Sep 13, 2021 at 10:14 AM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> After merging async mode for KASAN_HW_TAGS a duplicate of the
> kasan_flag_async flag was left erroneously inside the code.
>
> Remove the duplicate.
>
> Note: This change does not bring functional changes to the code
> base.
>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Evgenii Stepanov <eugenis@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/kasan/kasan.h | 2 --
>  1 file changed, 2 deletions(-)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 8bf568a80eb8..3639e7c8bb98 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -38,8 +38,6 @@ static inline bool kasan_async_mode_enabled(void)
>
>  #endif
>
> -extern bool kasan_flag_async __ro_after_init;
> -
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>  #define KASAN_GRANULE_SIZE     (1UL << KASAN_SHADOW_SCALE_SHIFT)
>  #else
> --
> 2.33.0
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZffxd%2BnGngMQ%2Bu6kJtJyGAScGocPwrU9yAPYKHRsU1Yjg%40mail.gmail.com.
