Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWOKVOAAMGQEB2QV6HI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 023313005D5
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 15:46:51 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id u9sf2610360oon.23
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 06:46:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611326810; cv=pass;
        d=google.com; s=arc-20160816;
        b=A3qjZoRWIv8w9sRlE1QlhZNRdVfV84FCvKSM+N1YLdfqJH2QFHQ0rDkcJqkgkknIqD
         4q8MyPkqLcRZr8ghVLmw5floOQgqRiH4MDqvMGxfoRPPJXTx+QJWzk9gVcwkJ8Aul0cJ
         wHxtKDWklWW+vgbKRWzXvnh3s9FiciBqkcBSKn4dMVSSywW7/U056CKmTm8QKoaydPhg
         ajIX6NggRsXeNDtzTy5m+cBsXFus0vN3x3UtYPXCJQsc++v7TfHozSZHf0LV9rhaHqoq
         LznTZx/a5CDRXjGTYr5acmaZBWNYesLF8bXi/1ADKSmTicnIZRuf6DGPxA4tDIrqkbBg
         n2fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=AgjJeTfqSYlfP0CBcdp2igaCzYDbjw9TTZwK9qw9GBI=;
        b=jOfyVahihE0uQdRcC+TLujc7Bc2KbvyuR1v2yb2PYTVhrlG8Xix6E9CKHE4iOz4Uh4
         hAQhabWeBCKd5ouZ3tlUpEpSK2NMJF9DiNgK+c8MbC1b8dgypZ4RddaTiH3+al6iA8kR
         4GEumsCtl4LgkR0lrDWw8e4ov9cWyxsZxlUlg0lVpAW+T+66v+o2DWZdPR2bC6K9O5vc
         Ggrrqtc6HNj73a7QCrr2mE3BX1w0AooLhySVxbePEhMEjkYrNrzD4StuwOmIRgKPNxsn
         IpSG8rjdt6YZMjbd5q5SEQ3bfcuJUM18MmBnCZ27NY22L5r/ZLP/W3ZtztvEyyPKNOmS
         0sPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rpdT9oqc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AgjJeTfqSYlfP0CBcdp2igaCzYDbjw9TTZwK9qw9GBI=;
        b=bbgfmO2Nt6idZyUDKAm6MiTB0Y8A2GXJDADtLwrHuJKiFVyRX7jsACzoFBPyQ18tee
         B3jdlaoe6zbri7pRPqRg+N7AIQfHDnllDYiL194E5Nkqaq2pbdoF7Ls58EpNS52c5s7i
         7p36TdLNTH93vb3s3Onjlzn9QWmx/3hcykIZn0sWIc2wbku6Zf478z6zPhwLLjlgK48m
         /JQZNCH0S7gSlvoYhOrytylloauvIC/5g5J1Svy0hviOQ0cls0JSa31tXMw3vUh57gYz
         mnxUDCCyLMvkNq/0xqEdATcg4T7RqoAPEJZayg4gB8g4/QJ96BYXQWUQCpVWMXqKuvcf
         DlgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AgjJeTfqSYlfP0CBcdp2igaCzYDbjw9TTZwK9qw9GBI=;
        b=M+NgJZboSgd1b880QLDelbZEMLg4D44NNooUruImE8asc5ILGkGedI12hMv/NOd6aD
         yi0k20uo7X56vygEqDegpPbj0ik5cvP5JazUS+ae3YqBS7Ai39CxJGEQT4NbHBuQunaz
         cOOqPtvNXQTwFbRolY8yg9fY4ifxPVwECj/M5zDV4YdAiDRDXkGowPII4yQvdWkh6R0V
         OrZ44KLIDkACTx2rdFyu6J/gPeoHLR4ki/xFCg2j/jVTud7V1chDOs0nh7HS7AVNyExy
         yGzlf9uFzMoBlNcnsLZZHA3xgb/H9XXqM/DALGHBbOcvVJOeedLZXrgXwxOkfav4foFK
         vswA==
X-Gm-Message-State: AOAM532uJsGfdKpQfzpWRXgWBuFU0xd1OEzhXls9PedFK9vLkc1nCtgq
	5hJrgy4aK4Eu788PFUPjDlo=
X-Google-Smtp-Source: ABdhPJzqYI1cMBZ+I69tiwrfnMWrWBwZWVu0UgQ6yZEUuuD/rxcWMMPItahPW4e5XbqazmYR2hj38w==
X-Received: by 2002:a9d:5d02:: with SMTP id b2mr3555571oti.148.1611326809999;
        Fri, 22 Jan 2021 06:46:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fd82:: with SMTP id b124ls1542577oii.3.gmail; Fri, 22
 Jan 2021 06:46:49 -0800 (PST)
X-Received: by 2002:aca:dc83:: with SMTP id t125mr3492296oig.53.1611326809696;
        Fri, 22 Jan 2021 06:46:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611326809; cv=none;
        d=google.com; s=arc-20160816;
        b=u/T6n8rBDF5ynTPA+iBSyppOOyQHH+2tQ8YVl7wkOs8uKnIaknGWJqh4tajnRe9sjp
         DjXKAgaKybs88hvfEWytwtXarLZegj5RBcn6zqwY9ebwW3r1v+YTaMpaX2n7Wg/5IjGX
         WeK7q/4w4Q3sqJOKYuvHD/fihJDs+mp66taMOfOVX8z1sDO5eYzhmiKGJf7KFfKcbeZE
         77F+c/mzmtXEWouxdJPJnB/hRkGY6tTmUxGK3oZ7Qg4ZOWZllfXRlshshG7N9fUDW9ss
         eqzRWWjqldjUNYzi2lSDUcCmrzfhOHiMRwVubuHFkOztGkv4I4MkkiNs64MOjXHrZgrU
         PY2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V1AbIZrJERg8kpP9b2k7FTBNRitSl0TDoTbXm4ZySsk=;
        b=HnjBgHUBiUmAQMI2dyx0RkjhE32kjyig1XMiGryaSppevRLyUmWWMPRKPwbmY6yzwx
         sASgEsgfWC6hcmzrLbSKcNi2eOWsTOR8ektQ8OEWs4fCHKAvX7e3XqNzACS+1DvYMZ5d
         ZichWZrHB8wHB0yjWL8lXWgIRvDXV8Qw+IhDvbR4a37fsi2LT01ENlpllu5XdRM42caD
         Ph1B1yT1zo94V6QiEFihCcfb3d6oGxQrOTgT7fwbcfFiklRKDbYe75GCNMSbaIMOuAiO
         rAGiXYW04NvgLnYXWcZ9B3gM5KQvaKxY7V8H9qQJXWeYthILXEjCmSbKxOFguAv3a7Ni
         bIOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rpdT9oqc;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id r8si555974otp.4.2021.01.22.06.46.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jan 2021 06:46:49 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id q2so523328plk.4
        for <kasan-dev@googlegroups.com>; Fri, 22 Jan 2021 06:46:49 -0800 (PST)
X-Received: by 2002:a17:90a:ce10:: with SMTP id f16mr5863900pju.136.1611326808923;
 Fri, 22 Jan 2021 06:46:48 -0800 (PST)
MIME-Version: 1.0
References: <20210122143748.50089-1-vincenzo.frascino@arm.com> <20210122143748.50089-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210122143748.50089-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 22 Jan 2021 15:46:37 +0100
Message-ID: <CAAeHK+yyJia6zOCMpy6ZJDX-Brvr_s88gZ6HwG2TxfLgtw=SSg@mail.gmail.com>
Subject: Re: [PATCH v3 2/2] kasan: Add explicit preconditions to kasan_report()
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Leon Romanovsky <leonro@mellanox.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rpdT9oqc;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::62d
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Jan 22, 2021 at 3:38 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> With the introduction of KASAN_HW_TAGS, kasan_report() dereferences
> the address passed as a parameter.

It doesn't dereference the address, it accesses the metadata. And only
when addr_has_metadata() succeeds.

>
> Add a comment to make sure that the preconditions to the function are
> explicitly clarified.
>
> Note: An invalid address (e.g. NULL) passed to the function when,
> KASAN_HW_TAGS is enabled, leads to a kernel panic.

This is no longer true, right? Commit description needs to be updated.

>
> Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Leon Romanovsky <leonro@mellanox.com>
> Cc: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  include/linux/kasan.h | 7 +++++++
>  mm/kasan/kasan.h      | 2 +-
>  2 files changed, 8 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index fe1ae73ff8b5..0aea9e2a2a01 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -333,6 +333,13 @@ static inline void *kasan_reset_tag(const void *addr)
>         return (void *)arch_kasan_reset_tag(addr);
>  }
>
> +/**
> + * kasan_report - print a report about a bad memory access detected by KASAN
> + * @addr: address of the bad access
> + * @size: size of the bad access
> + * @is_write: whether the bad access is a write or a read
> + * @ip: instruction pointer for the accessibility check or the bad access itself
> + */

Looks good, thanks!

>  bool kasan_report(unsigned long addr, size_t size,
>                 bool is_write, unsigned long ip);
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index cc4d9e1d49b1..8c706e7652f2 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -209,7 +209,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
>
>  static inline bool addr_has_metadata(const void *addr)
>  {
> -       return true;
> +       return (is_vmalloc_addr(addr) || virt_addr_valid(addr));
>  }

Let's put this change into a separate patch.

>
>  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> --
> 2.30.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByyJia6zOCMpy6ZJDX-Brvr_s88gZ6HwG2TxfLgtw%3DSSg%40mail.gmail.com.
