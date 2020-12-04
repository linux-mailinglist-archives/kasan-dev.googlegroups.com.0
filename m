Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSO3VD7AKGQETXXC53Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 2C4CB2CEE3A
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Dec 2020 13:38:34 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id z13sf2443324wrm.19
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Dec 2020 04:38:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607085514; cv=pass;
        d=google.com; s=arc-20160816;
        b=YrYYJV7aA6+Vjwg0YL0runU1Tj9qwIqyOC8vljTL4tJ5flKzztbqmPYAHbxQF1xFpP
         ZLO3WYb+ZfBBfmn9OWYyP0cM6apsthHLmCvowgn/6eaGr6XtSAgfkbiTz9DBM0YSkW41
         R1HjDdPvAatNiG78YZ3WtFIkJl51i2Te+sM37OaDE+NoxfzMlkPgSZs1BzdfmvVLsvG3
         +9Y9Hm1hEUTkLWPAnwkyxbPW9XB9lD27ioqvKd5SSljJthkkLyl0bUBBgKkezq7SBHH2
         9vdMdVsCu2hDl7E+CP0nFSGzSICBBuJOX0PcwsEXaMVKn81C51U8XxcRhX7XLM8pmbKx
         yQ2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=WnFVBiV11/xa/iN6XOm1d728aX9k7vfV/esiCLd2K4o=;
        b=orP6PRUSlsBBW4qcZ4u8U2I6rzEeNIuIGrc0obGJQl0BrVuTVi8/JlhIMxO2nPdLwY
         i/GF+ddwG1JKGtlEuAWd1JuWveDHIvKnqsjFzPzTBrIP0fnZBDk1OLC5iLUKC/5plJXf
         kYktZbUv9dO9fNWUByeTOKlZ4BO56wKkGfk/fULuCKMx/f9qVjv0z6950DMBkOPltIMa
         hIpCf0ojGBKJYQa7rIXP3JLzE1TzAWWymJtmkWXlfu33yrMi9HiGoVVTcdGP1hNMguVH
         u33AU8D69+xZ4kq5BzHXnJJmZ+FMMiwvHIFodUnQh1ZCecT5CckG+VkySKUGsV7ywm5e
         kxNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XCefAFOR;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WnFVBiV11/xa/iN6XOm1d728aX9k7vfV/esiCLd2K4o=;
        b=Qss7KhvdcSQGw8rS/UDzu0/Nq9/TlK/K4Olg4r7cNKSisbBGTxTj8Lmk39xXb+W5kv
         xNDFKdnYRjXFU+0vli0eicu68HJsGKlWOP+3UrO0nmp5kU3SkZ37Myo7BggOlXadsj5o
         AZumj0zyVQbrPSD6AdKoPDaW6mXuF7tvmQMfvD121M0QbYH+K9pn5js7/uZW+Di0Dvqo
         OYm+0mTl3dv4LkSBA0B5HUPTSmp4Ms6qvaAhF5M+YYnKdF4O7a8VvO4XUy7Q7vXti+w8
         tepaIoKNUNWBgZBa1a+HsDSmDBp49sbb45K6RhN73tbThqNDD3agDvIQYws12srbWlms
         4liw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WnFVBiV11/xa/iN6XOm1d728aX9k7vfV/esiCLd2K4o=;
        b=T3dleTUxLeLTpZDWsbdK71R35O1mQTs3kQym8dO/GXgUTYhDZrAfr1P306uFelluD9
         AROUJyinKAURBC+Q9FV+z5VPD+NKU129KbUiVtg9cxeLPzoXy99Gy2K28O2Hypf/HvPX
         ZbiId4GiY3waJ7wmozPuvaiKzIU+3Cmlw5KwmsF+kmk/3MKsxNrvv/71EzDJ6qc8tOhV
         8H9CPCoCuRHt1YHV5URkoiJCbGvOXAFtb+uk5Wq/6JjvAyJ/3I+V6e/ApHK52iIGKsZJ
         cMfgNDdjYZ/Av/1917abCRnAeVzJzVSFRJm4RPlyOG/oC7zybp+owjmWSf37wW00kQ7K
         B3OQ==
X-Gm-Message-State: AOAM532MUJBteQ85bLJpkjR3xbE6JqtpDWfjFask+1jj25mTNLiN1Iqj
	Cngc1vYJ0AIGmON26hEA0co=
X-Google-Smtp-Source: ABdhPJyYbN6z99v6Skjbp9Y/6ryevmOftKBU95SiwAeKl3xrvSd3mX1KalKSVVQhk+hkVkqqRQMF4w==
X-Received: by 2002:adf:a3ca:: with SMTP id m10mr4777643wrb.228.1607085513935;
        Fri, 04 Dec 2020 04:38:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e5c2:: with SMTP id a2ls11012655wrn.3.gmail; Fri, 04 Dec
 2020 04:38:33 -0800 (PST)
X-Received: by 2002:adf:d086:: with SMTP id y6mr2242178wrh.115.1607085512988;
        Fri, 04 Dec 2020 04:38:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607085512; cv=none;
        d=google.com; s=arc-20160816;
        b=dg5fUtjZjF98luHxuowP0gskcseranW1gyZdOGip0px4w4Cfxt4OzGeZ+ydT1611ay
         BU4ZE4GkR0oJGo5zjiHMuN+Ihp9oVqHPjt7NLy4kQ7tRJ2PKoxFBFjpenTrQTWEzvBtN
         iBqb0vYTlw3uD2cXfkxiqDTQA2FJqUyT3FZFNfXoq6UWDbVy1qcL8Ur2uhq6upgOMfCj
         k/8n0PtHIYxzd32O5BcZYIpER3url7JR7ut/HnbR/GwOjE0MKySuNc89HXKfJScvcptn
         2uxxXtnVUQqV2Sh7K6zZJedUOVNj2SYWv+t6h3bSJN/CWsmPetAU1KqDl1LcZTVjep6D
         a2zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=uwxrq7FVASlmAXmPpYkbuc2zGaGpKZv2xlcdJf5cyHg=;
        b=f7mHI3nk/4JcIWQhRewcF93dZpNlGslnRz649fQ3j+coF9zMymPFEoBsbQ0+HILP06
         EJeQvauDTm18CIthZikfqRkHVxYARRR7hsKtwEK83PkSBmWXoLRihqaU7BrJU+xnrlgq
         WIOYJIGV1RXycOgCsidri9W75Vyeiak4/iuwy3DKvFG1/g71tBtb5srJgEJOzlfD1JCo
         z6PRBrho5lRvdfIJWUebIz+I8KXL1kjsud9AnzRJsv0A6jsDoyCo3Q+jOz6Is92/tRnX
         uA8edCnRDILAZIyNrjZ32OIzBwPV2thjM9Ie5zaDPfgi/01eDjld8AR0/P4E6ozLM1fU
         5H3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XCefAFOR;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id q142si99375wme.2.2020.12.04.04.38.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Dec 2020 04:38:32 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id k14so5191373wrn.1
        for <kasan-dev@googlegroups.com>; Fri, 04 Dec 2020 04:38:32 -0800 (PST)
X-Received: by 2002:a05:6000:105:: with SMTP id o5mr4937077wrx.164.1607085512394;
        Fri, 04 Dec 2020 04:38:32 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
        by smtp.gmail.com with ESMTPSA id w3sm3066245wma.3.2020.12.04.04.38.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Dec 2020 04:38:31 -0800 (PST)
Date: Fri, 4 Dec 2020 13:38:25 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Anders Roxell <anders.roxell@linaro.org>
Cc: akpm@linux-foundation.org, glider@google.com, dvyukov@google.com,
	catalin.marinas@arm.com, will@kernel.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, rppt@kernel.org, david@redhat.com
Subject: Re: [PATCH] kfence: fix implicit function declaration
Message-ID: <X8otwahnmGQGLpge@elver.google.com>
References: <20201204121804.1532849-1-anders.roxell@linaro.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20201204121804.1532849-1-anders.roxell@linaro.org>
User-Agent: Mutt/2.0.2 (2020-11-20)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XCefAFOR;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::441 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Dec 04, 2020 at 01:18PM +0100, Anders Roxell wrote:
> When building kfence the following error shows up:
>=20
> In file included from mm/kfence/report.c:13:
> arch/arm64/include/asm/kfence.h: In function =E2=80=98kfence_protect_page=
=E2=80=99:
> arch/arm64/include/asm/kfence.h:12:2: error: implicit declaration of func=
tion =E2=80=98set_memory_valid=E2=80=99 [-Werror=3Dimplicit-function-declar=
ation]
>    12 |  set_memory_valid(addr, 1, !protect);
>       |  ^~~~~~~~~~~~~~~~
>=20
> Use the correct include both
> f2b7c491916d ("set_memory: allow querying whether set_direct_map_*() is a=
ctually enabled")
> and 4c4c75881536 ("arm64, kfence: enable KFENCE for ARM64") went in the

Note that -mm does not have stable commit hashes.

> same day via different trees.
>=20
> Signed-off-by: Anders Roxell <anders.roxell@linaro.org>
> ---

Ack, we need this patch somewhere but we should probably fix the patch
that does the move, otherwise we'll have a build-broken kernel still.

> I got this build error in todays next-20201204.
> Andrew, since both patches are in your -mm tree, I think this can be
> folded into 4c4c75881536 ("arm64, kfence: enable KFENCE for ARM64")

I don't think that's the right way around. This would result in a
build-broken commit point as well.

Looking at current -next, I see that "set_memory: allow querying whether
set_direct_map_*() is actually enabled" is after "arm64, kfence: enable
KFENCE for ARM64".

I think the patch that introduces set_memory.h for arm64 simply needs to
squash in this patch (assuming the order is retained as-is in -mm).

Thanks,
-- Marco

>  arch/arm64/include/asm/kfence.h | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>=20
> diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfe=
nce.h
> index 6c0afeeab635..c44bb368a810 100644
> --- a/arch/arm64/include/asm/kfence.h
> +++ b/arch/arm64/include/asm/kfence.h
> @@ -3,7 +3,7 @@
>  #ifndef __ASM_KFENCE_H
>  #define __ASM_KFENCE_H
> =20
> -#include <asm/cacheflush.h>
> +#include <asm/set_memory.h>
> =20
>  static inline bool arch_kfence_init_pool(void) { return true; }
> =20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/X8otwahnmGQGLpge%40elver.google.com.
