Return-Path: <kasan-dev+bncBC7OBJGL2MHBBKNH3D5QKGQE63CM57Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4C976280585
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:36:42 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id x6sf1430773wmi.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:36:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573802; cv=pass;
        d=google.com; s=arc-20160816;
        b=VCC49UR7AIjnOTh6Wa80VLKrj8TNe6loJVkbCZvMWPD+ByymDlJF+rh5zf/OTWSLfd
         8v4CMT+XNfW0AaGy5b7dXCU68ssZRYLI/FmY473yBZVHIWavwnpYLnkKrG0ZlL+1bN43
         yWJhzxOh30kWVtW5SH4jhKhOB0rsZN+FsiAeXFTOiYPJc0uQ2lWTq0THvfqxSc3zTL2l
         IjX5+I+Ufzt06TQR9AamSQ4M6t7iZRfs1EvMaBHGeZv4ZEkDf1AHyw4vn9BAVTrIM35d
         gJnrMo+R5Nn3u4VgPnacbIxKnh3QEgSslu0pMTqYe0dDwfCVFFSlr2qOIyMdwr9PAfw+
         8mYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=fHXuDdHO9JAY4FlS/R3JRFQ6BGwhEflzAtspTiuGdec=;
        b=xU0i/YarjI2fWQEeGOZFiR2T8zqMWr4dIVqL+uYBMLlQcR0XHXI05eozh+NMsjKHg4
         5GAvRvQD82O34BQhXTZ53L6U/X9T1BbijMQiHVTzZSB196DE9lzdKNQAGrZtcBk62Agd
         Fl/6rI5rbfNh3y/3MULRnl3HTTm95qN2kWn4y2XLdDzI6G+aRzczK62sJfBkp07toq+S
         WFNTxg26vZe3tnr273CIwPAZ6DyKxl5KYePQtORZv4sU2HdXcDVTlkxSewKsCvAUYGmI
         k/axLnz5V8XQ6z988cwWP5114YAbaA2fFOhVpqLMJAhJjGWAscmg4IrEdwD3flNkM+FW
         4rmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LzQn1Qpi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=fHXuDdHO9JAY4FlS/R3JRFQ6BGwhEflzAtspTiuGdec=;
        b=FmYjsIST5QxxUgPWsmUsaDRUAVxKrX5waGjXcyadWNq3tgh4IhYDT8xFpJStSUm0gr
         aFMa3Z6DuSJoUDaU8upVPdGrKWLnsAdLLeAYdDAxhFyKzo81g5R6KEYvIxUqOiDLkL1O
         CrHVt4MYevC22oPji3CJ4ZklT0PYu5UWMJe3vwQiUWSbEdD0kWjtiTBu2K68JiBJ+w8S
         EfGQpGI4Qb0pmNkFevBtAwwyB6xMGJz58Bb9SlvGrR+YSKgidGLmQ/C1E5003/50x+f4
         /TfpuBG3mipfTZ17WbkrLjG89s7b+CyIyjQ9p3JDwffcpEssHbCYyZRiT5KGuSfjEbxp
         wCHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fHXuDdHO9JAY4FlS/R3JRFQ6BGwhEflzAtspTiuGdec=;
        b=WGpsPLRG2IkjWz638R1rv8H5SMw3kWURVs+n0/Br2MNtON7CfRPqk6Sn2kkFUXPs2Z
         +xP6AU8WATB0rXew2b6hqATPweo2T9VHjpQYzbcTKpAaoV7mbQFhAY0Hv2hlJIKma3au
         fBcbUYI5Vme1hZECkxHfhyTlIjdCFbs6jTbCogfLI0OWNMDsY+kU6/UjmpXLsg0xvrC8
         N+6CtV3cRmybdVBobO8rdxrHCQ+Tf2Yof9hLb/jPzdZV4f8MLsJBnvy6pXPVAT8Roi0Q
         MIEMYAdjoaZhH7FpY1VBxH6eRQwVErMpiix16119KHoKQusjp3CcpLI3u09b5uEVmyBw
         j3/A==
X-Gm-Message-State: AOAM532NIQ8DsaDNB6AQmsODefC47zO2oIswQUlQ6tckXo+RLnAip3O6
	jToZcJ2tlaGysu34wZkI3ZI=
X-Google-Smtp-Source: ABdhPJyBcLsnnRbRlKHbSk/P1xN8mSGRJg8z9gzp9hAOLzJVslketWKALjJVL1IiCKr8biNGyNgsRQ==
X-Received: by 2002:adf:ffca:: with SMTP id x10mr11001402wrs.342.1601573802040;
        Thu, 01 Oct 2020 10:36:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cbc4:: with SMTP id n4ls3290441wmi.3.gmail; Thu, 01 Oct
 2020 10:36:41 -0700 (PDT)
X-Received: by 2002:a7b:c84a:: with SMTP id c10mr1092067wml.139.1601573801051;
        Thu, 01 Oct 2020 10:36:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573801; cv=none;
        d=google.com; s=arc-20160816;
        b=I98riUR4UGbf474cfN57Wu4tk0/80PA8tYFSfHHFdNMoxViKZm08gUwchZifuMR+tB
         qJJPDvqb5IYhWzRE4kMgonszzRn3PFnPURtXx4Clr7FwbXGnOWuOpMbqqgZrB9BX2q99
         QTyuLPyCYgUR/vS98hvH/5wMa7wz5GSAj3xzjRRUnG0H4eK78tKrKBzx1pYXv/HhyLRK
         8HL/wOvIES22glay1BeGhrCx/KgpcLEZ4fbqr30vKbsjAtA6yDTCFqSzr28S7LZ4kSII
         Rr01483I1aDz2GK03qmqizMgXfe0krBIxG8Ft1u5TU6xdorRe2PoWxkBVeYWrKVHJadV
         GptQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=NY/d8Sdt044dx+t00rd3tTBrvBSb2aAmC1WWztjcgb8=;
        b=h6ZhoWsoZKJR85V3yl0VQWcaDJopHp3aVyqQhG2+Cf5zQO1OwqoSVloGp3YMJTmJr0
         sIZKWfNvi62LlxcJZWW/cQun/CguUnjgnZfwgjRvPD+BJiJMkQGRhKKrJ7XXr0Sw9l5D
         aw3hPuUp4hyrQ1pnn+eYMUJbtaF7yM8legZk9ibHWhfJUcGgTj4kcSzpaDoNtf9StsIo
         t7LwxNuc1UrB8V5ioMpEWK5cwPfyiBb2L+Zszf6IkUCpNme3hUlQxCW44G+hPRX2f7wA
         p/huSvwiuKUgvzRsK4mNM+FtBGl58rfJu3aWwn7yU/0F0yLjiRuy1MGPh5qtHikfoBlQ
         eUXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LzQn1Qpi;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id h2si128490wml.4.2020.10.01.10.36.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:36:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id j136so2722455wmj.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:36:41 -0700 (PDT)
X-Received: by 2002:a1c:18e:: with SMTP id 136mr1144534wmb.22.1601573800505;
        Thu, 01 Oct 2020 10:36:40 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id b126sm1015691wmd.16.2020.10.01.10.36.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:36:39 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:36:34 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 10/39] kasan: rename report and tags files
Message-ID: <20201001173634.GH4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <da4fc136c8cb6a44200dbe5bff4908f8c3835ceb.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <da4fc136c8cb6a44200dbe5bff4908f8c3835ceb.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LzQn1Qpi;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> Rename generic_report.c to report_generic.c and tags_report.c to
> report_sw_tags.c, as their content is more relevant to report.c file.
> Also rename tags.c to sw_tags.c to better reflect that this file contains
> code for software tag-based mode.
> 
> No functional changes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: If77d21f655d52ef3e58c4c37fd6621a07f505f18
> ---
>  mm/kasan/Makefile                               | 16 ++++++++--------
>  mm/kasan/report.c                               |  2 +-
>  mm/kasan/{generic_report.c => report_generic.c} |  0
>  mm/kasan/{tags_report.c => report_sw_tags.c}    |  0
>  mm/kasan/{tags.c => sw_tags.c}                  |  0
>  5 files changed, 9 insertions(+), 9 deletions(-)
>  rename mm/kasan/{generic_report.c => report_generic.c} (100%)
>  rename mm/kasan/{tags_report.c => report_sw_tags.c} (100%)
>  rename mm/kasan/{tags.c => sw_tags.c} (100%)
> 
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index 7cc1031e1ef8..f1d68a34f3c9 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -6,13 +6,13 @@ KCOV_INSTRUMENT := n
>  # Disable ftrace to avoid recursion.
>  CFLAGS_REMOVE_common.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_generic.o = $(CC_FLAGS_FTRACE)
> -CFLAGS_REMOVE_generic_report.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report_generic.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_report_sw_tags.o = $(CC_FLAGS_FTRACE)
>  CFLAGS_REMOVE_shadow.o = $(CC_FLAGS_FTRACE)
> -CFLAGS_REMOVE_tags.o = $(CC_FLAGS_FTRACE)
> -CFLAGS_REMOVE_tags_report.o = $(CC_FLAGS_FTRACE)
> +CFLAGS_REMOVE_sw_tags.o = $(CC_FLAGS_FTRACE)
>  
>  # Function splitter causes unnecessary splits in __asan_load1/__asan_store1
>  # see: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=63533
> @@ -23,14 +23,14 @@ CC_FLAGS_KASAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
>  
>  CFLAGS_common.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
> -CFLAGS_generic_report.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_report.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_report_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_report_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  CFLAGS_shadow.o := $(CC_FLAGS_KASAN_RUNTIME)
> -CFLAGS_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
> -CFLAGS_tags_report.o := $(CC_FLAGS_KASAN_RUNTIME)
> +CFLAGS_sw_tags.o := $(CC_FLAGS_KASAN_RUNTIME)
>  
>  obj-$(CONFIG_KASAN) := common.o report.o
> -obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o generic_report.o shadow.o quarantine.o
> -obj-$(CONFIG_KASAN_SW_TAGS) += init.o shadow.o tags.o tags_report.o
> +obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
> +obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index fc487ba83931..5961dbfba080 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -1,6 +1,6 @@
>  // SPDX-License-Identifier: GPL-2.0
>  /*
> - * This file contains common generic and tag-based KASAN error reporting code.
> + * This file contains common KASAN error reporting code.
>   *
>   * Copyright (c) 2014 Samsung Electronics Co., Ltd.
>   * Author: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> diff --git a/mm/kasan/generic_report.c b/mm/kasan/report_generic.c
> similarity index 100%
> rename from mm/kasan/generic_report.c
> rename to mm/kasan/report_generic.c
> diff --git a/mm/kasan/tags_report.c b/mm/kasan/report_sw_tags.c
> similarity index 100%
> rename from mm/kasan/tags_report.c
> rename to mm/kasan/report_sw_tags.c
> diff --git a/mm/kasan/tags.c b/mm/kasan/sw_tags.c
> similarity index 100%
> rename from mm/kasan/tags.c
> rename to mm/kasan/sw_tags.c
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001173634.GH4162920%40elver.google.com.
