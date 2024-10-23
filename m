Return-Path: <kasan-dev+bncBDW2JDUY5AORBCEH4W4AMGQEPHA2AZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2D1079AD422
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 20:42:18 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-2fc969f6e27sf281881fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Oct 2024 11:42:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729708937; cv=pass;
        d=google.com; s=arc-20240605;
        b=WQAKUdG4ONrg6zgFcytsWmT26mXZWnKK49srqOZJbSMMS9G4wxd+iDvs7FBdezMIZi
         Y87EzlaqOfCsr0vVmaSeSY01z2Mpc8UjCoy7s8zJ5XRVnQ3WrWBQBuaO/exUBqQ5jdzr
         dt4esdq9MIdgASWCfL4Yz7mj2hgNlwg9uDopR+gPu62HS+r7OFlipBIKvu1zzLNoTTnm
         QfPMOtc4lB3YAPKJaAwtVvUSrXnGuH7CcSemmtIRg+vAr2q0HvaLyU6a2KAzQl6/8pmO
         8BevJS9fDbTH/uSk+pHa/goCyux2ykdm5JPJIsAaDKoeBE/cCnQb1/QPBZPFEZvZOTKT
         dCJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=wKVsCCH63HpfhfDYVo+JUW1z3Ux/ejE86uw7YLkbNp0=;
        fh=GxPNY+yQBkxvZ/HlY7/GwNBlX8sZgo6jPUufMJYdwr4=;
        b=RvgKsdE03TV+qPGMA8/pObuyj0g3R8bXuwC3AYt2rrvJJ87I+U2iv+8TRF94EdoxnO
         2Zn9xyDJuQYTFf7uqVl9pkU4PnDeAwrbjp3w4QcDXZLa1atE4ezcVrm1vQtflKLn/YWd
         2+TafXkPDVClxe/1EgLDVMlWMP+sPbdydoYFWRFEIQLrfS2eTtg1KtVwKg2/dm+/uHSI
         hVHN+iL6MoiSg7oay/eeDYg/mGrqgPyL8B7xwD68eJFGcCsrKb42M8fdG34EKo1Yu1PL
         X4CZXPpeWCEwl5rBnlDjk8DGfeqwQQWbctt9wdi4UOVN8alC8823Nl2tFdmTiDOLlSG1
         4STg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VMqYkgo1;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729708937; x=1730313737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=wKVsCCH63HpfhfDYVo+JUW1z3Ux/ejE86uw7YLkbNp0=;
        b=g2onq50APKpBSZpkF7Bz0tcv4x+ThFmDGUlTiD685Ndb4iNH8yE8YvkRan8ExrCzRo
         QPLuKSOxDReCcXkqpHFueEXhmQiSlSqaKAu0uB6luKGxlwMmx+CnhSOyrlq27HZb7N/w
         DXnl1uXLSncI/Lpma9stKXX01uhPw0+1DmUC+14VsfJgQ7RMlarOsQt4iWLvOFZC7vVW
         LPEsm0jGIAAdYM6kjFDisdUdNEVuxnREhWzjAZfRkLoop+xgUyO4mSJD0YRtSEmSV57s
         RE80WbuAUueyTMQJoN20z4Ss+3NH5qzJvv1EK2jyJjiy25CAkOq+9OXwhHqi3lLTIkk/
         noWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729708937; x=1730313737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=wKVsCCH63HpfhfDYVo+JUW1z3Ux/ejE86uw7YLkbNp0=;
        b=igZef1pw6TF56cLXP98Vz8ebiQF/158ed32XqBla7TMs7FsG4XvJQujxOyRXEhykg2
         8z/oEB707lGKczULXujGA+2mN5hLJaIGUdF0aVdcJZE6WmDnXelj87hHMpc1DaEHKOqG
         8JKL59bH3I4RXmnjQ0a8XWHdwEuZbosNKhFd4B+0FO9CUboOHrAlgO/lg2SFIOeqq7o5
         nHpJ9JYb9CyO34Qgvs7erl3ff6b4gvlGsSct9vk4InY9yqxXyGE5R7E6IgUCTEJ+AuU6
         jXoWxQiUYZ4BJlSZKSPEYolTXzQM3kV7J0DRoaKrN+p5SP9SO0SdQsgOPTFnhwIQz7Cv
         Q4Yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729708937; x=1730313737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=wKVsCCH63HpfhfDYVo+JUW1z3Ux/ejE86uw7YLkbNp0=;
        b=O6A6yP8UAKQIdmHc0vfBVy54FzMvtgStkk106hGBuj2Bc/ttCmGNR9Lqp1gEI6nzAu
         oXzhsWgaoCiwd9R+sYXyE9BelUa5cRugw8sN7bqBi1Y9syW3lVBMaLl/uT071YyXYc33
         YDp66mlB2h79cy1qDpunPhLVV0WvPgLB1Yme5m0LT9y6b8vDgr7kL1Pdw3/1WMXdBb+G
         uYOlMHSmkYFnswGMrtI4rRcOengmVK63XYU0ZQq34ABfn9eT23S8ub8yPTGPKeswcOC+
         GHng4hukCHpWVSsGKhnQLKiw896WbswVuiTArZ/dkxVXV2BUI9o8OZcd03Hk+BReq0xx
         qmyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWRf1zqgS/RgiQZhZUKBifLtlhOZFUhkkv8Tf7G7iPihz8QrcmbpI8xO3k8wZJtnW1k7BiZ8g==@lfdr.de
X-Gm-Message-State: AOJu0Yzkyh/5liJHmftSSjzYCgy2Sz+B+q7dO4zc6XN/uDxpVUODGO8u
	uUq3feUAQ83cFzVZ/NL6tvGxNMZlxUbel6U/mEbNjSohCnalO7Bu
X-Google-Smtp-Source: AGHT+IEvVAj/uVmAXjGusvIpCBNFD03/ZxN3pIA06r7kqxqbUdtUZc6hf3Rs5MP7TCYzexqjae5s+A==
X-Received: by 2002:a2e:5152:0:b0:2fb:3bc0:9c7c with SMTP id 38308e7fff4ca-2fc9d342b25mr16349021fa.25.1729708936813;
        Wed, 23 Oct 2024 11:42:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a46:0:b0:2fb:48f0:2272 with SMTP id 38308e7fff4ca-2fca595257fls418501fa.1.-pod-prod-08-eu;
 Wed, 23 Oct 2024 11:42:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjjumCEYOgZhmQazNrKbIMd/DMC2LgYuqd6w7oPGZ9XVfpHs6VA0ml7/omUBwAIFhoxbzyyUXKcks=@googlegroups.com
X-Received: by 2002:a2e:6101:0:b0:2fb:5bb8:7c23 with SMTP id 38308e7fff4ca-2fc9d3441abmr16315601fa.26.1729708934805;
        Wed, 23 Oct 2024 11:42:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729708934; cv=none;
        d=google.com; s=arc-20240605;
        b=GpHaoy7e6QT12Ntz9YVSiaLW1tBWedX5lx7I4nYmd33W+5mrOE4rzrKfdCF8C716rh
         a4yr0EyanLfNkcYUSDn72rCK+M7s14PMloA+CZmLyx+m1PzdoYZdh2vtbfxZLK7DMSxi
         7YzgmjsoogJushnGPQLydJf4JpuxV6H/Tr0+lmTjrzs4cYqVZinfh9UMJwMGyYYJH9Ke
         6G4WjDGvetOGWBqekk3C2JnxlDL1cMrZuE8ePcIoW82opY+Bdl0xYjv9aOS7swGttXm3
         UsNAPEzs3q10WuDrBvXFZUcx/pmlKlcMpcn8ZL9W/xdxWvBA8NJwNvjeDQ/i0GTwb2Zv
         pTsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1Ay/OqGD2GTrz3V0tm8K+95EMKdw2lJQesOojfLv6f0=;
        fh=jlVHa9IXLAahANOpIqkIwJO2tu1rpWe9LvFa+oOz/Sk=;
        b=L07i+74oQIBzHJl2c8dfJ88CLoMrd725vlLPSnVnvKGrRJj19wx8yWyIgCQMvdUbVJ
         9wdonUo2J9R0qfNyYg5GWlXv1hjoatfBRxZaGCAnlL920SDkyZFBvyzWrxiScv//FISA
         FzfJMLB/nhjU/Wb4ZR6WUjv6Zp8IM9aUQwKr8uz2lKG+91bzoZQUfuSQ9Ux3JJzk2WHm
         XXweA0mniO4a7l6n6UTu+r/mfSqtB5WG7uOBOUPD7AF3tDL/FfGsvhgmeT9DmZAjyxTc
         lzvyZyIMHmZOw+jVmFIgXheJ9Yrc7MELOTsx2m9epO5Wcf2z1YBCOtSKGPx52QWzJUuU
         e++g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=VMqYkgo1;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb9ae0efcfsi1718361fa.3.2024.10.23.11.42.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Oct 2024 11:42:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-37d47b38336so11838f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 23 Oct 2024 11:42:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUhQKskXTdC3sbesk2Q6A/OKkCsxF8oiVh3jM8owxpuYKW0BzdngHWaKCUVxvBrzhSGKtGJ7nLGJzw=@googlegroups.com
X-Received: by 2002:adf:f5c4:0:b0:37d:5338:8733 with SMTP id
 ffacd0b85a97d-37efcf7ba95mr2248780f8f.37.1729708933928; Wed, 23 Oct 2024
 11:42:13 -0700 (PDT)
MIME-Version: 1.0
References: <20241022015913.3524425-1-samuel.holland@sifive.com> <20241022015913.3524425-4-samuel.holland@sifive.com>
In-Reply-To: <20241022015913.3524425-4-samuel.holland@sifive.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 23 Oct 2024 20:42:03 +0200
Message-ID: <CA+fCnZe49OGG_8J40_d9dTUBktY6qe-1dq1Y6Q+7hY9=xmUWQw@mail.gmail.com>
Subject: Re: [PATCH v2 3/9] kasan: sw_tags: Support outline stack tag generation
To: Samuel Holland <samuel.holland@sifive.com>
Cc: Palmer Dabbelt <palmer@dabbelt.com>, linux-riscv@lists.infradead.org, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	Catalin Marinas <catalin.marinas@arm.com>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Alexandre Ghiti <alexghiti@rivosinc.com>, Will Deacon <will@kernel.org>, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=VMqYkgo1;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c
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

On Tue, Oct 22, 2024 at 3:59=E2=80=AFAM Samuel Holland
<samuel.holland@sifive.com> wrote:
>
> This allows stack tagging to be disabled at runtime by tagging all
> stack objects with the match-all tag. This is necessary on RISC-V,
> where a kernel with KASAN_SW_TAGS enabled is expected to boot on
> hardware without pointer masking support.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> ---
>
> Changes in v2:
>  - Split the generic and RISC-V parts of stack tag generation control
>    to avoid breaking bisectability
>
>  mm/kasan/kasan.h   | 2 ++
>  mm/kasan/sw_tags.c | 9 +++++++++
>  2 files changed, 11 insertions(+)
>
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index f438a6cdc964..72da5ddcceaa 100644
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
> --
> 2.45.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZe49OGG_8J40_d9dTUBktY6qe-1dq1Y6Q%2B7hY9%3DxmUWQw%40mail.gmail.com.
