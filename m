Return-Path: <kasan-dev+bncBDW2JDUY5AORBEGT3G6QMGQEFSM4B7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 93911A3CD8E
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 00:30:25 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-5d9fb24f87bsf1196859a12.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 15:30:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740007825; cv=pass;
        d=google.com; s=arc-20240605;
        b=hZfZBLJMsac8sQMlzZLX90cJyVrxel/8wBoixfXBbBvYGQ1K1vbF7B0yxfYwiNJZL/
         I3OX2aWm9ULEuaKBaEs0K9++pupNFB3cVWiskZO9sSByj6e7dAjx5yhLgkaLadabwqYg
         epgW8JrzNxn7VRmBUeUcKiKlXy+stytyn8c4wmeo0mtGSJaNroIqOcBuEUVD1f1pKQsH
         mQcGmUwJaUzPWh5uokY/qGHYtzLuYn+UO9NRWYZYpZjbO6qY8w9qh+zzu33bXkr6bnNn
         01DrPL6CI74lpQ/qpsfP2Y6Ux6wh0stBOeEZkw0MrIq3t205xlGifSzbyoenMMDiGhB3
         X5lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=SJKrFPzffo3/xCAQ2AS+VxqrgvneyQSFw+3Ynk2gOI0=;
        fh=Peu9D34rJHsY6MBXHi2KncLfq08YE4E+0rwyozD3Kck=;
        b=EhDs6DmbKTFCGk0H/26gE58t6IPV1qedCgfhZMeZbPWUxZmHa0iQniITeCZ/LtuT+O
         1sjYyCzydEjq9Z+9ZNcjQSrKua/OlI5rV4jtFz3pIWoQqhbYxUkwqzPMzJVr2KzlsmLn
         REy2byYLZ3WnuORKtKePf/rmi+IyeSXg4xLlUr2Z6i5PA2VrZDhY7JTcqfjeeAf5FhlY
         bpmP4aUKy7+xPT0cmVL5eS3pct90JTrpZBqvrdlzgOeqxFHWzGCLlG9irABgv3MmUJI2
         +inSB5Fn2tUESkkUNEljc6nhWHcNg5nRfD+ApCgVZ4MCOHHr4wjy0jw6uMttsjrgzTr8
         5DIw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GkOtFKTZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740007825; x=1740612625; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SJKrFPzffo3/xCAQ2AS+VxqrgvneyQSFw+3Ynk2gOI0=;
        b=BPAjll/e52IIGIZRW/lpq4Au+m+vQQi+dh71mgZKhXbWvH9pROYuDREBIWhuV2C+gQ
         fbc3FqlYFPbV1HVq6nkQzgHa5jDrUJm2C5ea0lLALtqEJ/ps4wY4+hrkIq2SOgoO71Ej
         xhgwvFDxgddGrabh7evv12mTQbkgi3/NVywn5OsPwTPy0RG0vpAR0MF3RazN4sFpGk/G
         C6j26xrJxWw+nvgJDQnZQl87W0hEf7tlDX3Vzp/o2uWEfMZSzOwi/Su+XN3xQKhDNU+N
         JgNWRoB+k0yOzZWNi44J23KRprlK7cGjK+UtAWtL2QXyyHTIzHmO3EA1GuETofVWccvl
         rn1Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740007825; x=1740612625; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=SJKrFPzffo3/xCAQ2AS+VxqrgvneyQSFw+3Ynk2gOI0=;
        b=JTumzMalfZOTsSNt7ywwN87id7x2PjraH0ahE4X5uustixSbf1scP/woaPEZyPvhyx
         U2SJ3sRTgcalpj47Qzlj/xea8AvNssdMsX9PoEnWM3H4obw+YLkPTv8jL/RacfpaXmlQ
         y24mOHJa5pLwXUsPxI6LT4tI+bljITxrkUWYtwxJFvKH+nz0b9CMXNbvQ6LYrDvPIttM
         SP3YyKjhYqe4s2NEEzbC1tyTPOq+61T4U+IaukJRi6DgHwPsbT8N6VTk4bF4UdM2jc4H
         4nbj2prHDHMCnMp4SfQbB3H2KebwtunXfaD8i41/GLmWWqdY2Ng8As0TviNalRCYdl3T
         f9bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740007825; x=1740612625;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=SJKrFPzffo3/xCAQ2AS+VxqrgvneyQSFw+3Ynk2gOI0=;
        b=EBAfpehmSAEExDs+2Q4Gn3K1WG8Os3JA7DgwziGVa2NBzZ+xSO3iUTKqihpwQwX5K2
         nBu9BiEG1OX4WdBNf8C/FDtFd2D2UIqFPzXgfoXBuOilrwQ4s+NGmWpCCl3UmQ5y4xb9
         jTe2EyTFDV9RTNDGPobURcR22uDIfjPtOlfjKJUcMC1iBQqF94vCTk52G6ja2znqRfRy
         nCneyPPz5YZf16Rvq7s3QD4gbnG6UnKYsfY/3Gepcqx9V0xXQDL2i7gZpfaKi51ARvvs
         F2/eq05ZS0/sJEExc5tFXZVLCWhpYcc7TQdVoSNIO90ODQvKT9L2HItwzCoMclgSU9au
         kWUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5ydaAPkUzhRINHYeOdec+PnzEQ6E9lz250amiHzTXvRWwl2czJ3+zzBn42DR1beCroJP0Jg==@lfdr.de
X-Gm-Message-State: AOJu0YyJ/uXcbxrnkH64lHM5zyzazdWslQUAlF1XpCeTM/LdOuK1W/F7
	U73uuohvNXHgNDmNnaNXOkq4LUFSGTksPWc/pZKPEuv0ZjiAUjiE
X-Google-Smtp-Source: AGHT+IGEPA17iWZDWNvCWwDieSoTwLzI/PKFUjF94uZfkNj75vsuaGlEH9AsxzTQ8NjYb5XFOsjbaQ==
X-Received: by 2002:a05:6402:27cd:b0:5dc:58ad:b8d5 with SMTP id 4fb4d7f45d1cf-5e08950bc26mr4830226a12.9.1740007824593;
        Wed, 19 Feb 2025 15:30:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFQ5PRtExiMNmXKxXPFII5Z45LY/Zeqwp3Z9JS8M0hp3A==
Received: by 2002:a05:6402:c16:b0:5de:bc63:89f with SMTP id
 4fb4d7f45d1cf-5e0a0762afcls596673a12.2.-pod-prod-08-eu; Wed, 19 Feb 2025
 15:30:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU18GKPwqDkJGJaXVhdIRyPC9iGjOMHX7Q79B7lGORNSjfxdnEFwrRCS7Rj6KZA/dxMdbZroxUIxN0=@googlegroups.com
X-Received: by 2002:a05:6402:27ca:b0:5e0:8007:7497 with SMTP id 4fb4d7f45d1cf-5e08951d1e1mr5451029a12.17.1740007822119;
        Wed, 19 Feb 2025 15:30:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740007822; cv=none;
        d=google.com; s=arc-20240605;
        b=YFNWakvl1pY3Gdr1HNnZavtDRqritnApjeY8Laej3k1v80zZ9szy7JW4+rTAv89trO
         xxZQJX4SNXRLIx3jQo+xSO8HTMZdjDVHDwEaIqy8CE7S4Mf923ZxfAG1AsJ/a7aOWUiR
         3+1fomc2pM4BZUyDEOt/q+bMGR9OiGBgFJyy7bWni8tNBxTP3P14HATkFOcfa/O/gCJI
         N2aLUV28xkDOXoKEKx7nQlWAPrxuXYw4x9NvJOfosMJ/34ZAGqR87lWUD1XKFyHFnw6w
         j+3WquIlEigv0V/fG/MDe5285CkH/FTiC7CGU5/F/5/IJcldacqEn/54YF9SO30kmJzg
         wreA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=K1GGaSL1EMbBNY4X399BrJn+mN5UB9HBffE2l1nq9Fw=;
        fh=xDZOw89JUR9XdfsLBXVd0i3wkNMlrCMtX5n3bzWNZho=;
        b=Vv0utNesb/3P6tkf90dGJekXdXHWsXPDwL6HwG9ptCcqJfs1BNB0TZjBuwCYFxthlb
         l0sI8/DljtFsPfxaDnc4iY5QBP0qURtMmZk5h7fqMQb5Cw3BK35VOKMmNWelScjFiQi3
         QG64rYKXnN+ZzaBdDtJB+q3Jul2ku7R8CwhypUe6WUM9BxAGDiByVh5Rkr2vLe1Zbvyj
         pj9AT0AXHiYKC0D25TpjRENKc+UIjKitybOkEKrzZudTskmjfjS174bXvbrovkfGKlbN
         79bKm7o0xo3OdrI3FlYFi2RbKnW0vHadGn7qQ+cx95aD5oKTSz7Fp2yS+n3DBorHXtfm
         Mkrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GkOtFKTZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dece1c644asi291303a12.2.2025.02.19.15.30.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2025 15:30:22 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-38f31f7731fso163902f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 15:30:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUO/iLtvMhNQeGcWDCnon2NI76SRgP0Yt5zmjXx3nu6L9eXrk0mZ/whZ05Gsg5TECkvJvz9v3r6HVg=@googlegroups.com
X-Gm-Gg: ASbGncuPoJ/Ox74uPntl8gqaFqrRNCRbSflE2lEBsZruQuc99WMG+LYZnG963Jtht//
	ZurE3BwNYh5+aaZrEy+/TRp8irUxPwJ9KMRtScfy7iLSPNDLmLv47CAMSGk++IIDWQC3miJRfUW
	Q=
X-Received: by 2002:a05:6000:178b:b0:38f:443b:48f4 with SMTP id
 ffacd0b85a97d-38f587f3d8cmr4457835f8f.49.1740007821516; Wed, 19 Feb 2025
 15:30:21 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com> <b1a6cd99e98bf85adc9bdf063f359c136c1a5e78.1739866028.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <b1a6cd99e98bf85adc9bdf063f359c136c1a5e78.1739866028.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Feb 2025 00:30:09 +0100
X-Gm-Features: AWEUYZmNqej25uGq8URgfmDzBpW2RyznVfstivturY56XWT9sQs1qkeZ-eNhhZk
Message-ID: <CA+fCnZdRHNaxf02DXMm3q+Ecwd4XiaVZ0X9P-sdFfy+9jBMO=w@mail.gmail.com>
Subject: Re: [PATCH v2 02/14] kasan: sw_tags: Check kasan_flag_enabled at runtime
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, 
	will@kernel.org, ardb@kernel.org, jason.andryuk@amd.com, 
	dave.hansen@linux.intel.com, pasha.tatashin@soleen.com, 
	ndesaulniers@google.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GkOtFKTZ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
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

On Tue, Feb 18, 2025 at 9:16=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> From: Samuel Holland <samuel.holland@sifive.com>
>
> On RISC-V, the ISA extension required to dereference tagged pointers is
> optional, and the interface to enable pointer masking requires firmware
> support. Therefore, we must detect at runtime if sw_tags is usable on a
> given machine. Reuse the logic from hw_tags to dynamically enable KASAN.

Is this patch required on x86 as well? If so, I think it makes sense
to point it out here. And do the same in messages for other commits
that now mention RISC-V.


>
> This commit makes no functional change to the KASAN_HW_TAGS code path.
>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
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
> index 9a6927394b54..7f82af13b6a6 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -45,13 +45,6 @@ static enum kasan_arg kasan_arg __ro_after_init;
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
> @@ -259,9 +252,6 @@ void __init kasan_init_hw_tags(void)
>
>         kasan_init_tags();
>
> -       /* KASAN is now initialized, enable it. */
> -       static_branch_enable(&kasan_flag_enabled);
> -
>         pr_info("KernelAddressSanitizer initialized (hw-tags, mode=3D%s, =
vmalloc=3D%s, stacktrace=3D%s)\n",
>                 kasan_mode_info(),
>                 str_on_off(kasan_vmalloc_enabled()),
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
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdRHNaxf02DXMm3q%2BEcwd4XiaVZ0X9P-sdFfy%2B9jBMO%3Dw%40mail.gmail.com=
.
