Return-Path: <kasan-dev+bncBDW2JDUY5AORBAW7YCJAMGQENBUMYCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 02EA24F9621
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Apr 2022 14:50:12 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id m12-20020ac807cc000000b002e05dbf21acsf7605069qth.22
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Apr 2022 05:50:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649422211; cv=pass;
        d=google.com; s=arc-20160816;
        b=TlKwgtet+cOJws4Q6yryNnTeDCyJdQlE757rVej0VLN8gRSd0Z+OoVI9dyIar+msSC
         L689IkKlMu641ojN2TJ4GLfS39tHr/jXrnqOete8ej1/XSHJ2UKZud84pyHJRrCjryxv
         ZVvJIEaBalRedHcXhyc6hauMkRs6lzQ7lT+SUeIn94mPPrs5hlkyu3wTh96u2IsUu11z
         +EaMiCGUYPYbEh6YA0w5hUdabh6+vkfzXAKx654z/MxNjuzWP3GFIvA2nRU51mP9Irh/
         xxaq6pVUsnXBlKEx294bDpO5LFWYAUQmCknj4TPf2Km50OAwgCwm8NSk2CifouyLYl8n
         4V3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=MNuksqlMkNK/glngTGCVG6LOnvyTWizvM/AkGYVmTMA=;
        b=q6rTfMxzxHYMNjzXdurHZPQVr8RPELO8uLIC+cxgrd2j3Qjpb4GKNgrhQpUcSZnFmg
         FJmwQuSM5aGmGrs8lnggdA2UymXEdEw4U0CsyRii+JqIq3Vx2iZhPc4psYAWcG+xlcpM
         Mbloj+Mc9mh5h1kTrX+NQeN4jzBZQi8YUzeNhBWk9G3IKDmU+dE75rGR5vuQjOJR0R1M
         9Vn0mZFoHgTGPKus3P+oCKxPCP0Vp5WtjEYNotO14R91WIeJyqKF2kzLuawNZl+hcHQd
         NAi3w5yniBGInTFB8Z+ujxPRKeDzyMPJZFSOsVVelUX1zcnCqvDHqEaFONU9vo7P77Ci
         6Pyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qpY9QBJF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MNuksqlMkNK/glngTGCVG6LOnvyTWizvM/AkGYVmTMA=;
        b=ZISONC81icxTZkyyCrWiR7MRurVuWeNlaGT1jqsb8LMvrCJj8DPYU4mAmju4hzv1zp
         ifiPxu6n3w2jQ6JJWEc88NfPE/SLsqe24Kn0FTq10WqQNP1TUnFxvvh3/EPsX+cGdbk/
         +3iV39wv0QZYtsMAbHOLzlxRcO2Yf2FCtJRbSqAQL1TxLtWlAxsQR8nA2BK+tMOVdH2O
         7qYniDUVDwsLAisNPXdWFEZyIKNMvlGM+GtU/9q81xsldVEIxK9V1upigltHs1OAXt8e
         nwAh435t1zW5+bYWGS3xfM+5d4tYrUsrvhwCHrbABQ/LVd6cR02/yxWXE/qjyCBmtT4d
         Yt2A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MNuksqlMkNK/glngTGCVG6LOnvyTWizvM/AkGYVmTMA=;
        b=bmr2fN792acCO+AUoRZmjzHgUrQtbUQoLXgzMFFfLnEoJksBSw3xTn8V2LarWnc5V5
         GYp4OVFQ4VQdfk9OXkRxOcm7YbwwRNkhWKglfMDLWWvX6+EfJiH16Z00lJrbRcp+Pmdk
         ck5C/OVoI2AX3eGbNJmjl2MOUAR2VLEyOnPCX0aFlAN9h+MWz7VR8HxgsQcuVoLs4HR7
         B+sK78TQlQ84thDtwhQIiyrOp8jN2kGlvljjnn/gxzZLoiwy78Tq6ZTb149Hwtx0oT2X
         81c4M4pKyNEBJW5YH7f7ZjPG6eMvB1OHkPQrca2KgRHcV0Op0WkMKNhsCjnMdE7r0/0g
         VzVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MNuksqlMkNK/glngTGCVG6LOnvyTWizvM/AkGYVmTMA=;
        b=xJayLmEE9jcw3T6I93XRi/VREH4/tELZX3T45M7ANwFJAPK2eAuK2JKHKQwxr8uV3y
         2OtbzxtDOVgee3a1I4UHJ+MqfwPdhxMPZnKWQXDddkg4D7J1YzWJUk2ryBje8qOdEQXa
         qUhZfvJpPUzo4u0HO0cbfWCi8JN5L4AujDt7AwMAQO6XeSf86YHL6W+ToYDPJJ2E/Dfk
         P3V4u/PLGIL6BNiMJ92tprZ/mPT7BY2TaI+q8r7raYf88jNOed7uabe+DAqYMeSFzw+b
         2NdLcuYSUaiEwHYJ92jDUmyHVwZ+X58czlqf55xFzjxGXtUnCzG1C7SopIZ/km5yOkei
         jD5Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338Bfn2JQeqh0nXxf3ZBK6BNS8nuvZ1MA/ouEdEWLHEdC2WejDV
	mM3gN8Ds9zEY3bvd/6P0e9w=
X-Google-Smtp-Source: ABdhPJwDVI1hwP9ckR7oxuzmtGAkJ8UoLg/Pn8A4INqRj4oCw76rPXkxKezbYFnK/Pg42Rnw3RxATQ==
X-Received: by 2002:a05:6214:4013:b0:444:8ab:954e with SMTP id kd19-20020a056214401300b0044408ab954emr7140155qvb.3.1649422210932;
        Fri, 08 Apr 2022 05:50:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4d59:0:b0:2e1:cd96:68ce with SMTP id x25-20020ac84d59000000b002e1cd9668cels955973qtv.10.gmail;
 Fri, 08 Apr 2022 05:50:10 -0700 (PDT)
X-Received: by 2002:ac8:5702:0:b0:2e1:ec8a:917a with SMTP id 2-20020ac85702000000b002e1ec8a917amr15673082qtw.682.1649422210328;
        Fri, 08 Apr 2022 05:50:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649422210; cv=none;
        d=google.com; s=arc-20160816;
        b=kK4E/ADFx3ucvsLB8VK+Pl/w/Hr6lOaboKG/t2doutoE+DFGKuaeY/L0sFZqsAUyRz
         IEGda3DNfa/PqIjrpC1luVa6bkbwbCiu3A6ZJyR2OPP0ZXmqPYPjoBCJi2ob6VaDGMmh
         eZTHVVgciErD1/7IJ9mRN2feQpj+5fZTOnKMVP7dJ8UPHCdFTiRIMsvOffUHKpVajh6V
         6MZw7l6kZyNmR8dJoBPY0RILV7bnPxYY2ZYrb4Ph4cDp4iuP2mpec27Ypm+vDSblHcBg
         lkUOaCEEmV0DnCWMZDaUSh17L5gBzTj3Y3fsgorIwrqHbK9vAU8ST3IA2VktBBKCTSoQ
         at8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gWnxP81Krl1/ek3smnFr/1fIQ4FLd2YLVlnmdEEfWNY=;
        b=BM68lkB+gObKEKRnvKNJNNHh7Ct+2zeq2zsK99mbE7RakNnFw+4l62nNuIfX5M93Bz
         aS54hIENmuP8i9/pG7nCUmhZuw78ilRkd1lpaQpBz2mqEmAuhqO7ooAxWNFU0aQUSym8
         OpFupT8q4xroC2E3S0Ctz5ATDMgBi5U+te+wv4ThNDloaoF9strw4VG4NWKtrv+hba0P
         8t9z+5/RiT5di4hK/I0FPVkg0vQwL2AeqYZXPk4POyFTriC2xt73YRseHXaG1aZar+Hd
         EM8D5y/SjlOdwmFtrTvVxAqEP4iJEV13HEpDwhp/fY2SSu1XPwnDwo5KCK+S02KNTR9e
         yBNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qpY9QBJF;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd35.google.com (mail-io1-xd35.google.com. [2607:f8b0:4864:20::d35])
        by gmr-mx.google.com with ESMTPS id 14-20020a370b0e000000b006999e9e7f77si86144qkl.6.2022.04.08.05.50.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Apr 2022 05:50:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35 as permitted sender) client-ip=2607:f8b0:4864:20::d35;
Received: by mail-io1-xd35.google.com with SMTP id g21so10387663iom.13
        for <kasan-dev@googlegroups.com>; Fri, 08 Apr 2022 05:50:10 -0700 (PDT)
X-Received: by 2002:a05:6638:cd3:b0:325:ff7a:4f79 with SMTP id
 e19-20020a0566380cd300b00325ff7a4f79mr874384jak.22.1649422209917; Fri, 08 Apr
 2022 05:50:09 -0700 (PDT)
MIME-Version: 1.0
References: <20220408124323.10028-1-vincenzo.frascino@arm.com>
In-Reply-To: <20220408124323.10028-1-vincenzo.frascino@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 8 Apr 2022 14:49:59 +0200
Message-ID: <CA+fCnZczFuOo0sxcrvihzJY_j0JQmH26J=4uMaz7-bsqnhakzg@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: Fix hw tags enablement when KUNIT tests are disabled
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qpY9QBJF;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d35
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

On Fri, Apr 8, 2022 at 2:43 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Kasan enables hw tags via kasan_enable_tagging() which based on the mode
> passed via kernel command line selects the correct hw backend.
> kasan_enable_tagging() is meant to be invoked indirectly via the cpu features
> framework of the architectures that support these backends.
> Currently the invocation of this function is guarded by CONFIG_KASAN_KUNIT_TEST
> which allows the enablement of the correct backend only when KUNIT tests are
> enabled in the kernel.
>
> This inconsistency was introduced in commit:
>
>   ed6d74446cbf ("kasan: test: support async (again) and asymm modes for HW_TAGS")
>
> ... and prevents to enable MTE on arm64 when KUNIT tests for kasan hw_tags are
> disabled.
>
> Fix the issue making sure that the CONFIG_KASAN_KUNIT_TEST guard does not
> prevent the correct invocation of kasan_enable_tagging().
>
> Fixes: ed6d74446cbf ("kasan: test: support async (again) and asymm modes for HW_TAGS")
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  mm/kasan/hw_tags.c |  5 +++--
>  mm/kasan/kasan.h   | 10 ++++++----
>  2 files changed, 9 insertions(+), 6 deletions(-)
>
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 07a76c46daa5..9e1b6544bfa8 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -336,8 +336,6 @@ void __kasan_poison_vmalloc(const void *start, unsigned long size)
>
>  #endif
>
> -#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> -
>  void kasan_enable_tagging(void)
>  {
>         if (kasan_arg_mode == KASAN_ARG_MODE_ASYNC)
> @@ -347,6 +345,9 @@ void kasan_enable_tagging(void)
>         else
>                 hw_enable_tagging_sync();
>  }
> +
> +#if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
> +
>  EXPORT_SYMBOL_GPL(kasan_enable_tagging);
>
>  void kasan_force_async_fault(void)
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index d79b83d673b1..b01b4bbe0409 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -355,25 +355,27 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
>  #define hw_set_mem_tag_range(addr, size, tag, init) \
>                         arch_set_mem_tag_range((addr), (size), (tag), (init))
>
> +void kasan_enable_tagging(void);
> +
>  #else /* CONFIG_KASAN_HW_TAGS */
>
>  #define hw_enable_tagging_sync()
>  #define hw_enable_tagging_async()
>  #define hw_enable_tagging_asymm()
>
> +static inline void kasan_enable_tagging(void) { }
> +
>  #endif /* CONFIG_KASAN_HW_TAGS */
>
>  #if defined(CONFIG_KASAN_HW_TAGS) && IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
>
> -void kasan_enable_tagging(void);
>  void kasan_force_async_fault(void);
>
> -#else /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
> +#else /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
>
> -static inline void kasan_enable_tagging(void) { }
>  static inline void kasan_force_async_fault(void) { }
>
> -#endif /* CONFIG_KASAN_HW_TAGS || CONFIG_KASAN_KUNIT_TEST */
> +#endif /* CONFIG_KASAN_HW_TAGS && CONFIG_KASAN_KUNIT_TEST */
>
>  #ifdef CONFIG_KASAN_SW_TAGS
>  u8 kasan_random_tag(void);
> --
> 2.35.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZczFuOo0sxcrvihzJY_j0JQmH26J%3D4uMaz7-bsqnhakzg%40mail.gmail.com.
