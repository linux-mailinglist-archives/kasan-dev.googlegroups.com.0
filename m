Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQOJRP6QKGQE6VVKT2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 038B92A6BA0
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Nov 2020 18:28:35 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id m8sf10064213plt.7
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 09:28:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604510913; cv=pass;
        d=google.com; s=arc-20160816;
        b=tu8CDBIeXhfiw2kbwga1Iuo+tkBnRuZhpdtYgDFIGXfORQsKUgsk4d7IU+JRDD/DB5
         An3jqj0CMFV0oqOn9C/ELhPnYTV+6Baeg+NlMnlAdCczIpiXgquI4B5LuZy/W5Fwl/TT
         6dtefWuBdwEHuuaMtRQu/K1XUdYmk5yj2zOq5copgVMgK0GyCcTUv0m8PPBKCL5hDKy+
         RQVoQcuE1IBf7/2ZZZKjAjoqrlrQixh7XOJx30zeI9AGisubj7mNvXytDVuu1FTleYoU
         vMB+7HFotP1CVcGZTpx7ShF6nVNXz3QdLCReDUm2XtHzcICJ/+cPx20lLcQT9NKxB1Ii
         8Nhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=SJs/JK9of9t2im7OTKob04SE7jxdXSsrqfmuK55pkCU=;
        b=EZ4zQIp850Y6qYJYWlpLYWpRWO+y2LYH0hstkN5dsm985arSWSyEDo0i4BP7rApIe3
         bYPvihF3wE65kdRYtETN88dOXrEmACTopdpLC0j1ySrkPuJb62lLyoeyiIsS8CVRoBfB
         HiDdyg8M4qHUC+bp+UXUwlkbMognKNTXMxe6Wp7loki0sMjkO3y2/Cq+Z3nDqolL1Lj5
         TED5RDJjq3x7byaMlUW+LexhGU3dnDqFiK9XnTpD2H81OvXrIgofkP3zhJhWnAfc5+i0
         iysGqk2Zmz8+wRU0osIESKtXc47Ika8mbSyyDL5v64n6JD5ym+ysxIHKVIVMikLYwXj0
         4NqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e94ed6x5;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SJs/JK9of9t2im7OTKob04SE7jxdXSsrqfmuK55pkCU=;
        b=eN6cinGw6laLfoc3ZacXLkD4KNdwmMBi58bh2Dc4XOwv/WOqSDQFbDwNxk04Vxbe51
         jpWiyFyt819FVoQjboSOtRRmZbDOAlsq4xOpzrpkHcH+yERQEmx7NCcysOTn2acYgy0H
         hGhuM2nkU07azLZdPN+ABO5bwHruahxK41DRS48ZnhsoH9E8tf3048ji7r4QcLG9ha9S
         TfrtoEoI16ib5MWsk9rHmplO4WFnjcLXb/5d6oh/zOiRc/Il8bq+yKpuIGNVf92QwGYw
         xB/Ha3GvTqlXJ2ajo+RKqd1JRpKy4SMnfoYk2wE+MBekVJSfpHG6num7yISHAxj9FNB7
         U0yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SJs/JK9of9t2im7OTKob04SE7jxdXSsrqfmuK55pkCU=;
        b=cDMzqA958lWS+manYmZVq8vRCcAHgOzK3jOss+ce1bHD40Eh7A/myvr3i3L7wh2aS4
         8/0N7+/R0EIsVfY1XSxrHqFYMz+vpHRKOFkCn3p2V6hcQWrtXhX+mhMVDWRmx2kziBnI
         qH1QcDmJSO0VhslgLLVbPxbooyF5tk2JEBLlucMBfBkJvHYSd0TCq1voP5AAAyKB5K6b
         9bi+LPTUQi42rhBBu5OIwjk23HY+8ycilnOUjRVJE7fyXj7PwiezX7rByWaY0ZWq78X4
         Gkh0c0xGQm4yxniiuT2D5uktXEG8pCfXaL/ideuvi9CWHhx+J4S/adFj/qyV/NCbHm/n
         w2sw==
X-Gm-Message-State: AOAM5302AnkOlFEdMocbhsjP4+MzF1PVTnHW/SBELBswzScnWiXHeaBT
	/8q3QzJdSExp2ccgjvPWuIw=
X-Google-Smtp-Source: ABdhPJz1faPB0FrVUl9JhtucQdHnfEhq13D438wfADQvBo7nWhJFtBInQynRK5K78AECJOrDniMi2Q==
X-Received: by 2002:a63:da47:: with SMTP id l7mr22566623pgj.417.1604510913450;
        Wed, 04 Nov 2020 09:28:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:451d:: with SMTP id s29ls1187579pga.5.gmail; Wed, 04 Nov
 2020 09:28:33 -0800 (PST)
X-Received: by 2002:a63:ff5b:: with SMTP id s27mr22502595pgk.383.1604510912775;
        Wed, 04 Nov 2020 09:28:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604510912; cv=none;
        d=google.com; s=arc-20160816;
        b=hx9n1wToIAu/BRvCzYEG+dRwxfCxqeCAyZoEOf8jCf0X7PDd/i/hv9W0cashBaWUZw
         8nuxJdXrSuwLwArkS8qbHuqdSJkQzosxYVU8RG80aHYAs5rHASUJEglU/rCGDFqQxug8
         tUfSceVWSmcr8Psy7SIEj9bpDgwA+pQHZ1tEzJj+V5PQgyar0ALpFDv/Q9jpUe1CiaCn
         958HhXEq0sofxz+1A5rgUR+nbmNZPbpH+et31AGoCJbAjXv0p+hoQqHM7uhb0XkZPxxV
         LrKbV0MoDYTZN1YYafpUzCLTTG24LdcAq8VnJbwoQKStNAm4ixpuLrBtnoT6iElg7FJG
         Gncg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oobUaTCyncltoWrqEBGvrcm3OQzVhlM1as7YFTDZv1Q=;
        b=cClThcfibze2qE4cN/yqP74kUgCJN+4PZYF3dut1ewOApnFPyPQd64+7xGGO/dbMwE
         cyNjQpSRsFKVzzAsAIDaN/iuJhz2nzfSDyTZ/1SXC1C7QH4eygqbY/e82uhx6QZ76XNK
         UweMApoR5pMc/dUe361p41tLf22JXlhmhlk/Ya8jkxjfOqBa+r7uC56lIbLtEkKaIAvw
         MO+DfNSXyCa4FZzwOwEKPHzw8+mk/IwJV+ZPujCoKv7+ITj33io3tyI2liHeq3mY6fPt
         m6UvJVF9gePehN/v/a77U4LcMcaVwRxziEZF4Zq2Srw8syXhPtqPT/VIcPgDbhnLSadN
         Pyfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=e94ed6x5;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id x24si154883pll.5.2020.11.04.09.28.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 09:28:32 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id b12so10617003plr.4
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 09:28:32 -0800 (PST)
X-Received: by 2002:a17:902:e993:b029:d6:41d8:9ca3 with SMTP id
 f19-20020a170902e993b02900d641d89ca3mr31778200plb.57.1604510912336; Wed, 04
 Nov 2020 09:28:32 -0800 (PST)
MIME-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com> <bd64e051e8e36ac25751debc071887af3d7f663f.1604333009.git.andreyknvl@google.com>
In-Reply-To: <bd64e051e8e36ac25751debc071887af3d7f663f.1604333009.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Nov 2020 18:28:21 +0100
Message-ID: <CAAeHK+z3vPpt5DXYU89Q_M1rorYEatV_yHVuGcHWWgC3UX8xmQ@mail.gmail.com>
Subject: Re: [PATCH v7 34/41] kasan, x86, s390: update undef CONFIG_KASAN
To: Vasily Gorbik <gor@linux.ibm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=e94ed6x5;       spf=pass
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

On Mon, Nov 2, 2020 at 5:05 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> With the intoduction of hardware tag-based KASAN some kernel checks of
> this kind:
>
>   ifdef CONFIG_KASAN
>
> will be updated to:
>
>   if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
> x86 and s390 use a trick to #undef CONFIG_KASAN for some of the code
> that isn't linked with KASAN runtime and shouldn't have any KASAN
> annotations.
>
> Also #undef CONFIG_KASAN_GENERIC with CONFIG_KASAN.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
> Change-Id: I2a622db0cb86a8feb60c30d8cb09190075be2a90
> ---
>  arch/s390/boot/string.c         | 1 +
>  arch/x86/boot/compressed/misc.h | 1 +
>  2 files changed, 2 insertions(+)
>
> diff --git a/arch/s390/boot/string.c b/arch/s390/boot/string.c
> index b11e8108773a..faccb33b462c 100644
> --- a/arch/s390/boot/string.c
> +++ b/arch/s390/boot/string.c
> @@ -3,6 +3,7 @@
>  #include <linux/kernel.h>
>  #include <linux/errno.h>
>  #undef CONFIG_KASAN
> +#undef CONFIG_KASAN_GENERIC
>  #include "../lib/string.c"
>
>  int strncmp(const char *cs, const char *ct, size_t count)
> diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
> index 6d31f1b4c4d1..652decd6c4fc 100644
> --- a/arch/x86/boot/compressed/misc.h
> +++ b/arch/x86/boot/compressed/misc.h
> @@ -12,6 +12,7 @@
>  #undef CONFIG_PARAVIRT_XXL
>  #undef CONFIG_PARAVIRT_SPINLOCKS
>  #undef CONFIG_KASAN
> +#undef CONFIG_KASAN_GENERIC
>
>  /* cpu_feature_enabled() cannot be used this early */
>  #define USE_EARLY_PGTABLE_L5
> --
> 2.29.1.341.ge80a0c044ae-goog
>

Hi Vasily,

Could you give your ack on this patch?

The full series is here:

https://lore.kernel.org/linux-arm-kernel/cover.1604333009.git.andreyknvl@google.com/

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz3vPpt5DXYU89Q_M1rorYEatV_yHVuGcHWWgC3UX8xmQ%40mail.gmail.com.
