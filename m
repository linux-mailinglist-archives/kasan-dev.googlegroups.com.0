Return-Path: <kasan-dev+bncBDW2JDUY5AORBG6T3G6QMGQESNJR5GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 28E0AA3CD90
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Feb 2025 00:30:38 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-4393e89e910sf1257275e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 19 Feb 2025 15:30:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740007837; cv=pass;
        d=google.com; s=arc-20240605;
        b=ghgt3mm5VP1Tz6mRogncaA9xUFjkJjl5FK1hcI1/4bOY4QRQrdGODSFXvVP25bCYWq
         P9/RJApE7aDLOzd0yA2dMgR6ymTpYBlrgZDDt9ezx42ivmrZVeTQ4oKr58JRLWUPL+my
         ggiSvu9iqNSpawsHIdT9+i9Pv8/cspN9V0xlFmsGWUzrKZ1tUhD2sqtdg1+Bamir2yU6
         b4daRiCznzzyqvVWOUHDkOxuXmoHVMjTbcbazCWrpuYr3LoX13/Tepq1TaaF4XduHZFn
         J/cOIjHhSlKy+vUVKO4qBI2w13W7DNV669UEMYSf3ACJSGCJJNz7M7xX/wd7I0U9snPC
         4zQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=RIKTWZ6uL0FQjJ5Bb/+piENyt2mv4sCuqfvglpLB+Jk=;
        fh=y0v6MHZyET3bhBT7dykk9mgdtqYnp0TWZTUmvK+UfJ0=;
        b=XIXXZKgylOcw74Gw+dHQJG1FgCJZOvSIkkDsjzt6EWmY67f24+pSLEAHKy3zMd/qMc
         86RmxUzzVk/fZT1I9ukdLlCPHwQUOU2XjkF3A4wqNfFxzkBUHZNzOMfli9p0XC9PLrGF
         bp38PjaMbKJVphX1parZDLYMtCpDfTnMt0og+itWkzKM9FW9sNezdagFVy7ZjllrKDLr
         UyyvXsJcW/4uGczaI9bIGHSSlz55+gBF35T/fx8VSE2MklK4RvWPaPczwycT6a5tjxuM
         cPaYFA089OLfj8DBGTZ4eALJU2/BuAxKdwivFgUsqUimjAJFcyN4bSFDu5zsgUP3w+4N
         hmNA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TMCQ3xXo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740007837; x=1740612637; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RIKTWZ6uL0FQjJ5Bb/+piENyt2mv4sCuqfvglpLB+Jk=;
        b=G2TDqRdatoxoRCx2q1Zymc3d88KZZHl583As+0jU1/oTPpn64pKDjyGVBglxBcXuDl
         FoyMNpGHiYmFbxBc7WZoJFud/kQQKkLF+CWob3xiQDyErJhOUR25TSfE/weadnxakBqX
         VpsV2fsytYXXqDoyLN8gyUoyedNFYgmlGP8zHnTKiqJ9FuV5rr9Pa2thbOlyo3iwDMOI
         DZQ4FPNrHhLPX2HOth6vKANAliDB0Gi5nI7rdYmvtv0vqUWLy+oa5He0I1gB/tTxl4eg
         R0Yb41xAy7N4dvjTFSJABuL1g4xVlsmDHCVPcu7ICRPgwqtcaaFlbAK8LgC9erJuQ/JN
         YGKQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740007837; x=1740612637; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=RIKTWZ6uL0FQjJ5Bb/+piENyt2mv4sCuqfvglpLB+Jk=;
        b=IjwZbbDG0XRLO9KKkGB1NeDtV2b4mIoz1Jx/ORhnT2C8DziP6EwvUEpXydA8LCASHv
         Yz3q4fK2ALI0dHmCwhAdVsU1Lz0iB2eWx09GsZqt6jOKLZPZNkyWZUjilv2Ceio4ynHv
         MwDqOGnbKZXGNGPEm+lKXkppTLpMOduoRzclwh2nJrVQX6I5G1sBvPx0qmQHVn5h+L4L
         +G/zhLE/Zd8wpu8R2+oNiDq7XybwJs7jMi+EDZ9xmRJHGfncNOY+uFI8X8nxu+nseiVf
         mPArq80+TzEprvPd8eBKdZitBcSMUBe+wdCG1EbznYv03ytUohZXjCh+I4Gw4yhziRgo
         Jmlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740007837; x=1740612637;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=RIKTWZ6uL0FQjJ5Bb/+piENyt2mv4sCuqfvglpLB+Jk=;
        b=H1tPFJjLTTZrtMqLr1sVPBt5Li2kp3Uwj7MwNGt+ib1JSysDQrCQIgA74CwJwE107E
         iwdnbksjcUMv1P99f7muD0JKfUzxOc9I1GPFK7nVFbz9nxDwiqh8FLpzVU97sTz8EOqT
         2OyyDx1DnsihPVl/j04eW4iuikK9V/RL6Q+L91qwUqgRfa57WsfUrUPQ2h4RGXpGF65c
         j8VH6kMU+1VIbEg1cC6u1AWC5tRqRoWpAdprJKYexQzca1fosV1Uo6yAOyNAT18VsTuI
         6+8RjfxH1sV5wQaabEKeeJeDUcqigItycEGjvEf0NVNcMOngDpohmqbT2v+RRKuSvPeH
         JvXA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXU4Qfwd5e/68v1FbMcSBEBXrddMjJ8jIND/gGJzGQ1Q9By4ImvwkgVccZzKb66w6LomNbbyw==@lfdr.de
X-Gm-Message-State: AOJu0Yy/29O71esdzwcuYk8IMiJrmNF7GosS9mABCttdvysGAgik6LHj
	MSznZid/moO2TbxkHBanfho1MEQNY376hxyiffVCRVVqLefcu1LN
X-Google-Smtp-Source: AGHT+IH56kkNwDXEGRqSJ1d/YiyMJhWUjMvOpvJTOZyBTpU8vjeXJyXDho2C69WGQEXlp20g0RSXLw==
X-Received: by 2002:a05:600c:1c04:b0:439:942c:c1cd with SMTP id 5b1f17b1804b1-439942cc318mr79649075e9.15.1740007836279;
        Wed, 19 Feb 2025 15:30:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF30WO4yjdsFx9eUjMcgtVXnV6Vd7FTMwO5U/1tXsJrmQ==
Received: by 2002:a05:600c:2ed3:b0:439:853f:efdd with SMTP id
 5b1f17b1804b1-439a30af30fls953945e9.2.-pod-prod-06-eu; Wed, 19 Feb 2025
 15:30:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVYx9gd4P26fdKRBoEL+j8GfoSyrt2+HiFqU5adCxH2Eb5mLVWXepC8Jue9QJsDYXATO/yQB57CNME=@googlegroups.com
X-Received: by 2002:a05:600c:3107:b0:439:98ca:e390 with SMTP id 5b1f17b1804b1-43998cae421mr56476455e9.27.1740007834179;
        Wed, 19 Feb 2025 15:30:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740007834; cv=none;
        d=google.com; s=arc-20240605;
        b=bgDnDjSteCwhJaTiqIuk1VagHfx9lHsk1MTvw/SKeZf161gfYr+sBsv0ozew7irBb7
         vBvtPB4NqyobteNun6ONEUOFPd1qvcw6873toWM32j5+F51R8NL8RWMrSWweh4gGGDL1
         9Ht4dzcFF7eCD4GIWu4p2+D3hnEOkKFqpgQLXx+xxiex5Ac8KJKGy2JF/GO6qvv0fUYF
         j1jby3xV5HV9Ieuqatyi8Bn3C8NciT0ShdemTtaitK7mrR4v8SkcclCQMGFfXw4y9QT+
         9HMBbUVT9rfD1BQPqFrvgR6+FuKghoOvy7USxW5ggrprLJkj5OP8oLYAQA0XSGUH3Ccm
         gszw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JKnTn46/4Y2PZeZ3N6KkyX0o2kLFr+MjBIJGyqLqLvg=;
        fh=CqrAvG2uejOUTjt9xMYG9qOgkX+Sd7UqdYzZqJdDQJU=;
        b=bRWrmro3sT2tT3SZfcpFwmU/gKHU3n5jkBYwZaWLPvXKr442HlhNk+je5KtT6aZ2kE
         FLBs9Q6Aqn0zfCa88vJmF6t2vMnBtiN6DHMBV58mKPw+Gik+CURj40kSyNWi9CtMx0pM
         E08/eZ2L86kZ+Lw0BpVhMp92V8GPDPP3AKJrJKPKD5vLV7L9UiApmvsxOBYN3N+Zlbsx
         /PQP0RBNdVBBcl7Cx0f3vGqgYMbU9kyAj2p1wvATP9UqcFBxeV1+fbWkyWxPHOLhGZaZ
         RMAydEmkLAttLKgxjLe6Ir4iuy+LEdVLzIzU7ZezB4NtGCCOGeu4NhuvmNEL37fNQ3MT
         a6Cw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=TMCQ3xXo;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43998ae50cesi995305e9.1.2025.02.19.15.30.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 19 Feb 2025 15:30:34 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id 5b1f17b1804b1-4399deda38cso1782245e9.1
        for <kasan-dev@googlegroups.com>; Wed, 19 Feb 2025 15:30:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUqZe6qsyCVoZzcf+eBfv5ZoRPJE+cGA/IlvUlsJH8dKZVmhW6cIo+uTuUB6XNr3Cmgv/EWCj6ljaE=@googlegroups.com
X-Gm-Gg: ASbGncvIiuI4P45V3sczuyIaz6/uYscy/raiCHXQ5vq6GydxH2vpZDERJFGfChbvm/b
	LF0qBlAj/FwsZFHtGcEltEuzkyr07uoGQVboZOfDSkCMcG0jMMy8XZKvM8i5uhEtkjuYbQTXVRy
	c=
X-Received: by 2002:a05:6000:402c:b0:38f:3b58:fcfc with SMTP id
 ffacd0b85a97d-38f3b58fe8dmr17435032f8f.13.1740007833626; Wed, 19 Feb 2025
 15:30:33 -0800 (PST)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com> <20f64170c0b59cb5185cfe02c4bc833073a2ebe6.1739866028.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <20f64170c0b59cb5185cfe02c4bc833073a2ebe6.1739866028.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 20 Feb 2025 00:30:22 +0100
X-Gm-Features: AWEUYZlmUvY8zJgQzvnlM_yf4TfmlW5I_F8Q4WL7EAI9RSu7Ct1C7vf6wwcX6ek
Message-ID: <CA+fCnZfyWE_g44tbbC5ugav-gufhjQiGugfdgWJV+Ae4Gff7WA@mail.gmail.com>
Subject: Re: [PATCH v2 03/14] kasan: sw_tags: Support outline stack tag generation
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
 header.i=@gmail.com header.s=20230601 header.b=TMCQ3xXo;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32d
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

On Tue, Feb 18, 2025 at 9:17=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> From: Samuel Holland <samuel.holland@sifive.com>
>
> This allows stack tagging to be disabled at runtime by tagging all
> stack objects with the match-all tag. This is necessary on RISC-V,
> where a kernel with KASAN_SW_TAGS enabled is expected to boot on
> hardware without pointer masking support.

Same question, is this needed on x86?



>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  mm/kasan/kasan.h   | 2 ++
>  mm/kasan/sw_tags.c | 9 +++++++++
>  2 files changed, 11 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 129178be5e64..2fb26f74dff9 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -636,6 +636,8 @@ void *__asan_memset(void *addr, int c, ssize_t len);
>  void *__asan_memmove(void *dest, const void *src, ssize_t len);
>  void *__asan_memcpy(void *dest, const void *src, ssize_t len);
>
> +u8 __hwasan_generate_tag(void);
> +
>  void __hwasan_load1_noabort(void *);
>  void __hwasan_store1_noabort(void *);
>  void __hwasan_load2_noabort(void *);
> diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
> index b9382b5b6a37..94465a8a3640 100644
> --- a/mm/kasan/sw_tags.c
> +++ b/mm/kasan/sw_tags.c
> @@ -71,6 +71,15 @@ u8 kasan_random_tag(void)
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
> --
> 2.47.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfyWE_g44tbbC5ugav-gufhjQiGugfdgWJV%2BAe4Gff7WA%40mail.gmail.com.
