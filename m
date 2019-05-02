Return-Path: <kasan-dev+bncBDX4HWEMTEBRBW5TVTTAKGQE2AXTPMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x540.google.com (mail-pg1-x540.google.com [IPv6:2607:f8b0:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id E52D212010
	for <lists+kasan-dev@lfdr.de>; Thu,  2 May 2019 18:25:00 +0200 (CEST)
Received: by mail-pg1-x540.google.com with SMTP id 14sf1468172pgo.14
        for <lists+kasan-dev@lfdr.de>; Thu, 02 May 2019 09:25:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1556814299; cv=pass;
        d=google.com; s=arc-20160816;
        b=F4wY8Ca5uO39XypEyDWbWuL2xodzvmrs8enl1U5r9S9/XYBP7U3HnvhPGQCNjQHA7O
         i2VVc6ke5VLsiQb7SeJbOLsQEBYQIRDVLOZ25OdjW0jiSBEtaHx7t7/pEhKpf1LsbZ7D
         VhC2ZFsiIOPODTHy4uMY4rouq1hBnxsTPSbbnq1L/Js/J6nLgoMPFrEsvxZO9LQYY/1D
         FjzjUGzLFKXlhV9MhhMJYskKDSk33gH6S9oWMdSNfX96AvuPzg2jkoPrbWXimLXEuLGb
         zeNfIWvQTdOGkhoJ4zyy+m1dBZ9s7uQ6sOV4t5ybaPQLFVz6w6XbmONSfTfy7LnGt5Gg
         KyWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pVJ5i7SrkgJdHAYkUGb45LqCI/31u247YXtrBJTPqz8=;
        b=SAb/YP4sSNWnooOFXAGdnnMV/Zh5LKu2TRprALZktIFkm4NNvSve+yDCHHdr64KcSl
         JFIVG7fQCYKu1rtvI3xNBlL5iqzVxPFobqP65edg+TWBWaUbKUO7qZCFyfKvQaJxEQG6
         kIIzUSX7Lju0Q9JV2prp1xKVYplyUGoibH4MPVffsB2zG3TakyOsNxiK3Elc28Sq/psm
         +WiRrpJdljtDhLg6xReoiZXVTQ5ieWzmO5+mgL/QpFSCcfhmvxVf3x2MgeWqd4OqejYZ
         3Zb9ixseWqClTvU8fah3j9//iObvQfSle0cAHQnnF4oE9jKYpFATVUNUKQ3ZC/qlz+b0
         pGJg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LjkcsxEi;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pVJ5i7SrkgJdHAYkUGb45LqCI/31u247YXtrBJTPqz8=;
        b=JAUaFNCXLvLTJ1CdZsaUqydwf1ODCGSFGtp2x9OK2vB2xmtZABBLwR4QFTF91Kgb64
         /7Ye98phPP0MO+Akqh9c+CqHxIAUfdRlTFIZZRGRgJ+wqx0DUBZG5f6cD9pAMisBRHLo
         nMAH8j3B092/19VkyXghrzxL62XnSKUT+1nZWLa62LuR/ZPE9aSnrQbp6IHXemUTKjs4
         X9Y1lrAV2EqZ4jO7YbYEFF8iX2nvf3fIjv5DuxbKh5WpXpak3ZbEAehrvqA1GZD/3d55
         scj6pUPA/Nr2ekk2x4POrh07x+TB3Macsp0XcKLG0fEafaPQKu1v1o9YL3hgcOLtRbe+
         e+3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pVJ5i7SrkgJdHAYkUGb45LqCI/31u247YXtrBJTPqz8=;
        b=bYNK2BhnOju+dvlfszVmkoVA8/dilz1JhU1TwJvfCViCUjY20Zxy2C2o/FfvRqP0P1
         1kSMsC6Ei0b1x9qqA7Ca6XYGN4yEtx82r/6mUo2jO+/hMOH/NY9Vat0fn9GpkYnZGudJ
         3scvaGXS/2Tg99vw+LlteqNK1EHF5SmHfMFeBECK0KTJm0xLPNz7SUCcyQinFpY0GGd/
         YubqE4hWIoawL5j+ioxxNUzd5RMsRAehH4sj4TmrhFTZ/VQ6YRz1n9hRjHwgRSC1ZHXV
         mZbSQ7+2CPipahGnGkqAiRwxE7dTMiVWvpAOYB4Pi0QJOhhws4b6xdCgoUPnzl31trYW
         +16Q==
X-Gm-Message-State: APjAAAW9/bI0znF7pjr4YOO6EgpWePcyKi40Jw8WKFFw/JpgWAnu+Tof
	mVQHIeDeE27Undm4MP4Qv14=
X-Google-Smtp-Source: APXvYqxQE0n5Q6Sh7nbh7lQxO33hArsD8UafEPwkR1Z+NRVFEvmJMjjZfuCc+OmfNUZPuK1Mt9ScBg==
X-Received: by 2002:a17:902:b48a:: with SMTP id y10mr4745844plr.86.1556814299364;
        Thu, 02 May 2019 09:24:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:4187:: with SMTP id a7ls591580pgq.15.gmail; Thu, 02 May
 2019 09:24:59 -0700 (PDT)
X-Received: by 2002:a65:6205:: with SMTP id d5mr4904813pgv.61.1556814299022;
        Thu, 02 May 2019 09:24:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1556814299; cv=none;
        d=google.com; s=arc-20160816;
        b=gxJ6tcv3ybaqVIJhB70aQJQNd+Unvyl/SlbmPM3x4E891rTzUW7KBV3gvnirtt6Gza
         g3qwTQqkqxIxPfSbI/Gnb0jTdrwoy848R/0YgwzXgldL3q47U/f0TZjnM08QlTac3ZpV
         Hvof6B11biDDfKQzAZW9p3rIBfs767vQhw/nTz9nzyYiwle3+ydAKaaFLIEy5XUAB/i8
         dOPxrKjVV4lb48LMow2CWdNHOTa5f9Lp84Vsk0EwqpKHxlZlaBG2I04dvgcVKHSFBjQu
         Xedo79WlVPOICuvycGCvZKxe8cF3ucVzgKC4PEv9TMFJkXNNqAVqLgXkJ/IU32VPw1DM
         4Lyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rEKMwcrb+5WeSacp64Kz5FEoKnzrouBIBJCgUjJL8pw=;
        b=vvWXtdcpTnPVvZV9sCTLO+3amqv9S8iy+pi/Z6WwO/xJ2tA8enzYDToyA2lwENpCcw
         gp5MCw2OBzfBAeaoV+0oJ2a6q/uDcWV7DWpPUMOv7pyOxXg7qM/+QbEEM3RWzpVO1i67
         G66UCd5rWQQjGSGDK6qAL8BvYr+6svCsMW1dgbedNtd7RyY+JYd4pTiMcWWRcY3dRWGP
         UdEW3Ubre3HUtOHdwABXlG1rIJASyZLeeCiqpNW5r42kdKyW7LlplteA9Q0wjo4rrt53
         TfAN0iiw1S+uP5Ru5QFENRBP9j/asQiqklSPwLm53ZnsjN0NUbVOgRQDCX8gr2iVG6Sp
         W92w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LjkcsxEi;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id q203si2535921pgq.4.2019.05.02.09.24.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 02 May 2019 09:24:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id e92so1263374plb.6
        for <kasan-dev@googlegroups.com>; Thu, 02 May 2019 09:24:59 -0700 (PDT)
X-Received: by 2002:a17:902:56d:: with SMTP id 100mr1090671plf.246.1556814298380;
 Thu, 02 May 2019 09:24:58 -0700 (PDT)
MIME-Version: 1.0
References: <20190502153538.2326-1-natechancellor@gmail.com>
In-Reply-To: <20190502153538.2326-1-natechancellor@gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 May 2019 18:24:47 +0200
Message-ID: <CAAeHK+xb8oV_YuVHJivW9c1R0h=AWA_-G1K28GPiZmF9LO_FAw@mail.gmail.com>
Subject: Re: [PATCH] kasan: Zero initialize tag in __kasan_kmalloc
To: Nathan Chancellor <natechancellor@gmail.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Nick Desaulniers <ndesaulniers@google.com>, clang-built-linux@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LjkcsxEi;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643
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

On Thu, May 2, 2019 at 5:36 PM Nathan Chancellor
<natechancellor@gmail.com> wrote:
>
> When building with -Wuninitialized and CONFIG_KASAN_SW_TAGS unset, Clang
> warns:
>
> mm/kasan/common.c:484:40: warning: variable 'tag' is uninitialized when
> used here [-Wuninitialized]
>         kasan_unpoison_shadow(set_tag(object, tag), size);
>                                               ^~~
>
> set_tag ignores tag in this configuration but clang doesn't realize it
> at this point in its pipeline, as it points to arch_kasan_set_tag as
> being the point where it is used, which will later be expanded to
> (void *)(object) without a use of tag. Just zero initialize tag, as it
> removes this warning and doesn't change the meaning of the code.
>
> Link: https://github.com/ClangBuiltLinux/linux/issues/465
> Signed-off-by: Nathan Chancellor <natechancellor@gmail.com>
> ---
>  mm/kasan/common.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 36afcf64e016..4c5af68f2a8b 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -464,7 +464,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
>  {
>         unsigned long redzone_start;
>         unsigned long redzone_end;
> -       u8 tag;
> +       u8 tag = 0;

Hi Nathan,

Could you change this value to 0xff? This doesn't make any difference,
since set_tag() ignores the tag anyway, but is less confusing, as all
the non-tagged kernel pointers have 0xff in the top byte.

Thanks!

>
>         if (gfpflags_allow_blocking(flags))
>                 quarantine_reduce();
> --
> 2.21.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To post to this group, send email to kasan-dev@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190502153538.2326-1-natechancellor%40gmail.com.
> For more options, visit https://groups.google.com/d/optout.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bxb8oV_YuVHJivW9c1R0h%3DAWA_-G1K28GPiZmF9LO_FAw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
