Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFODT35AKGQECEWEOJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id CED0B2544B9
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 14:05:42 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id y10sf4025670pgo.6
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Aug 2020 05:05:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598529941; cv=pass;
        d=google.com; s=arc-20160816;
        b=t61Nqqn6r9WhvA2cvleDBIbix0HjDCgjiZRlwyNOx1bBhQVejVUAl5rwgWSYSsMC1c
         FKKO26CpqaaY9FpPjobYuGUf5+LN7kRXLPdAane+dWzeJ5Zbsb3pgeoFVH6XvlsS9iVm
         UA3sFCGb/RvfFkA1K8rb+eRo0+hvjfD0lD+e2vcdfAiGoGmj9ukDoj0EnG0jQP8Fb1Nv
         QieGMUFvwqen9tLKy0LweczB5a2qJM5704mJ63qoTIKcbKEYWbXnSq5PHtNZWxaP7xYh
         gyMO06exT7KOxE1cnuWtmJP8cwatoJfp6Cnb5T8APhxBHgFkCk6AP2R+i9hj6UXGPp0W
         /DcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hr9vlDzj/l+MFsGrNH8w8CneCCTg/Ls6ncivzSSNOlM=;
        b=OYpl6X2FsyhCmQ9WbD64KlbcgCNvNarL3fRQB8LuSqwGABTWZppcndtEDVLNRY1icH
         YCMxFQT1XKPHnlpQ7Fl6PYgAzPodu2qLcP4ezvS7qH0ynlNxJ3gJCrzNZesvCsv0Twqa
         3tjQFqmtsmaGXlrEUnZWYd1mY0cIyNap2ICi2hZ7enUFmBcEN4dFjgf3UP3rf37PBmb9
         eLcfpnYCSV3HmoHV6cuY6ozYBqSMRpy5tqGZs6aAZaUMkV0Jy/AEpBhjdorStZIsFDZr
         D0jAJzUOGVun4hSLSjQ7OIXJBfB/C8tNjOGDAflQ2fZjrCszbyVY3M9mX1JQZX1rYeEm
         hgJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BWaKBXCN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hr9vlDzj/l+MFsGrNH8w8CneCCTg/Ls6ncivzSSNOlM=;
        b=O99j3pFKGi88cMZ+Bd7QFDmgSMlNcrGzQyuBl1vAkistt72xdF2xDLJ8rMm0dgACd/
         09Y0XkaSMC2OugjFOGkYjbctutR2fAVq1PDRxgNBI0wgtNtd9HD0Cux2DQuV3ubcLg/B
         h6q8I+yIl2yqabMh+VilePJIxE4t2KmnYqguk25OTuhjXNbd7Txcq8mMhyrQoPLha3rH
         l+Zo32oIrAhs6iMkIce6cn18tjX1q+jSMv4oclSYE7kylR2xIVxbqD9rC8HYqKMF3JPW
         j1bhk926Fntrh0/rKyXJLtJhWfKddcGN7TYHlkAxpNURgsCoYg0zxJHmTSgpxW3U9KBu
         /O4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hr9vlDzj/l+MFsGrNH8w8CneCCTg/Ls6ncivzSSNOlM=;
        b=dEMJndHyon89dZxaW2j81+dzrA80NafnAKxMRzOWrv+DR1C915NVoFfieiszHoOuFb
         Mh+Ww8aVmENZnAYZvpWUCjEKekH1z00RLOjdAiFZnXTPIZO2FlrqOzXZaBh2xLHj5d9Y
         /rSYYeDdxaoqGbvLfCxUpqRK2Xq3aAxt6ZYFQf5uEV2mtE3kGLMOJnB+7VM04jgwxPb2
         SAq/2k9cKNDtpCcw+BYBrG3ujBP0KgaeYkk1H0Dkc5aSq6lIrLv5jerI4dzk+HM6JCsd
         qNK89Hk1g8x+C373Tw8X7+R4nS1bCtJV9eKcbPzPHji44/RjtvgPEZE6uoTHIH30t9pd
         8imQ==
X-Gm-Message-State: AOAM531xzBtY2rIc5W7CGa1WVwUnkAQdsdpycXeXJ7+tdWqXYq83zzTi
	Ftv9Rw4V5MhuB5+8mC6BzSc=
X-Google-Smtp-Source: ABdhPJz41MRavh24uLoLW2tE+1sPdqji9QbY7O3ZoL6Wca93Unp7bc6JroBbPPDxO+s3lnT7d7Fd0A==
X-Received: by 2002:a17:90a:f48e:: with SMTP id bx14mr9911675pjb.233.1598529941319;
        Thu, 27 Aug 2020 05:05:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:82c5:: with SMTP id u5ls1141512plz.2.gmail; Thu, 27
 Aug 2020 05:05:40 -0700 (PDT)
X-Received: by 2002:a17:90a:d510:: with SMTP id t16mr11054015pju.210.1598529940856;
        Thu, 27 Aug 2020 05:05:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598529940; cv=none;
        d=google.com; s=arc-20160816;
        b=KGlAfCNyWkSwqkrH1/+sWqwcRzKAEvUGVymLGJ4EnHnvcJumdRwSKAi3GBX30F+H7a
         pV1fcnEJ3rDt2FRRLl3SZzc0Vsh+pNWOQWSdZ5JKp7bggPsQkwfl8wi625Qc7TDcQN/n
         pK6ZuD+zgOHAjmXLnpfjR4jW/8UHP4PH89e2XPAL28Pp5huRefH//rXMHQUu3M11k9Qz
         oClJD+yFVYwRoSX+ESaa25D2dhW/uuhkL61kt+xj3FgnPTbTODbimZWk3NhJr2L6yMqD
         qiHlNAtNIzjKxLpx4nXLZM9GKg9Bs9ew1T7Z9wn0ZtxveyTcbCV2Xrsa43Mpa7jsnS4W
         pJYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rQWdT8WbkjggL+VwPZ1ejJL4JOhIunI/RdMzpXfnZIU=;
        b=WQxx9cLDKRODGyl8p/wlrzBmJsfUzuedQkV33fEWegmX7nTG6Ci76Kv71EGSP2fvtW
         QT+UDALS79DxPwgB/okv+zSA0qF6FSKxfF46NqpPXdOFvOe/1AmUFAjo0OciKrrQCiNf
         iHfJrnVFh4f16zZPWEEx0W12L3VMtlLwPIrMdopAo9vw72WWrmqLW+7+yvlBAKTWHpMJ
         pHZs1lepWV1gF6uSDNT+I7W4lQyQiSIMeQ6XuJ+1zZa8u2GGL1GE2kHI/FohsAG+POLM
         rvqdPDLr5FJrwUgzRAixw38Co3zftWNnx28Khfr9lDuUDKgXa59QCxTz7iEf5XejBiSS
         xxqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BWaKBXCN;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id kx12si329779pjb.0.2020.08.27.05.05.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Aug 2020 05:05:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id x143so3330079pfc.4
        for <kasan-dev@googlegroups.com>; Thu, 27 Aug 2020 05:05:40 -0700 (PDT)
X-Received: by 2002:aa7:8c0f:: with SMTP id c15mr4462254pfd.135.1598529940106;
 Thu, 27 Aug 2020 05:05:40 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <07455abaab13824579c1b8e50cc038cf8a0f3369.1597425745.git.andreyknvl@google.com>
 <20200827104147.GG29264@gaia> <c0319233-8985-8cc7-ea72-910b42b2b5d0@arm.com>
In-Reply-To: <c0319233-8985-8cc7-ea72-910b42b2b5d0@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 27 Aug 2020 14:05:29 +0200
Message-ID: <CAAeHK+wLVK_YG2gWVLk0YsoKozfZhht6zVzz=7N_yz0S=JgHEg@mail.gmail.com>
Subject: Re: [PATCH 28/35] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
To: Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BWaKBXCN;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::444
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

On Thu, Aug 27, 2020 at 1:05 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
>
>
> On 8/27/20 11:41 AM, Catalin Marinas wrote:
> > On Fri, Aug 14, 2020 at 07:27:10PM +0200, Andrey Konovalov wrote:
> >> Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
> >> KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.
> >>
> >> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >> ---
> >>  mm/kasan/kasan.h | 6 ++++++
> >>  1 file changed, 6 insertions(+)
> >>
> >> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> >> index 1d3c7c6ce771..4d8e229f8e01 100644
> >> --- a/mm/kasan/kasan.h
> >> +++ b/mm/kasan/kasan.h
> >> @@ -5,7 +5,13 @@
> >>  #include <linux/kasan.h>
> >>  #include <linux/stackdepot.h>
> >>
> >> +#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
> >>  #define KASAN_GRANULE_SIZE  (1UL << KASAN_SHADOW_SCALE_SHIFT)
> >> +#else
> >> +#include <asm/mte.h>
> >
> > You could only include the new asm/mte-def.h file (currently mte_asm.h).
> >
>
> Agreed, we should only include asm/mte-def.h here since after the suggested
> modification will be sufficient for the purpose.

Will do in v2.

>
> >> +#define KASAN_GRANULE_SIZE  (MTE_GRANULE_SIZE)
> >> +#endif
> >> +
> >>  #define KASAN_GRANULE_MASK  (KASAN_GRANULE_SIZE - 1)
> >>
> >>  #define KASAN_TAG_KERNEL    0xFF /* native kernel pointers tag */
> >> --
> >> 2.28.0.220.ged08abb693-goog
> >>
> >
>
> --
> Regards,
> Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwLVK_YG2gWVLk0YsoKozfZhht6zVzz%3D7N_yz0S%3DJgHEg%40mail.gmail.com.
