Return-Path: <kasan-dev+bncBCMIZB7QWENRBIPF5T7AKGQEF6H5EPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F4AD2DCF76
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 11:27:46 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id f2sf31110751ils.6
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Dec 2020 02:27:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1608200865; cv=pass;
        d=google.com; s=arc-20160816;
        b=iqJsaYe+bJofRcOPczArebLkixS57rWZ3cbr+O0It5Fxls0s4u94gnedyK7wICWSDq
         yYlxqIt5ttckw6je7+MibKONL5RPBjVgZw6kvNpV5KpgBGAbQmXtp04ZGT24WDivsQr3
         Vkg0Ebk/rBJAHxF1/AqrV2GQIz5kzFz4BfLEEmNU3spGtdxH81jUEm2IaszZYS8imfGI
         PhX6znR1hT5eq/TMbmPodtnOkfuPMxXX45hrHsQEaafh1cW7OMPpXpHgHB3Xu1ZIjaji
         m9gUZRN8nsMLSi/1ZFZU++vz9fk8j9RPd3ehz1MS+MMylDi3d8WlCimGgiJ+Dgri1ojz
         rwiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Zf29eHFKDtxtdJtb1HGtsNLoPzh0TmoiNO+3u3jx7+o=;
        b=V35oM/aFEXr2/5dJvqiW/HPDweu6zK/eMvQ0nPk1PctA5C9Bt4/9QElf/AlqE4TuFT
         TPjX3ziVGNxcHGf84A2Wf1RepNOi5NZ2bSv9S+2CQTfZd5ExIIWycGYh6W4zKC4qNAOw
         fZDzTvlEpTL0n/yqtxykLHhhcZGlNCFTuJ5rIHyiD2DtiQ2J56VQeJQtHjfPGXkyKv3t
         VjZJxT9vXV5Td2VFYMdT34EyiCffAmNE+OpBGqyjblB6eJyoT9D8R7YeNKqybhXG9KI3
         xZsb7K6bcp9mYcnuu9VkQcx6bErNYaLW7m97vOvmyAlc61rmesMNVkgupHgF/wWrJQb0
         SvZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mJYqIDVd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zf29eHFKDtxtdJtb1HGtsNLoPzh0TmoiNO+3u3jx7+o=;
        b=RczuGeUgBG1hNF2QYMz0670yUpTJg4TCl9RMYtOaHPkbsQEuYVxNASFd6sVEIvifEi
         pWsEHqIugParjvW0KeQpkTGAyXKGxrJeJ7lNUSIPt+vjt2ICvadvROoBvbPaUcMoVtEo
         QsECm//NB4cto7LU/LaB+GFZkxlOF4bUGOj75YCFbsfp+vfChfQ5xSNkKKgRajorooMM
         kE7nvXfS8a/5BksVrTvYP8lX26EEHAK4rZT4FNgesHmjzB/e+IjBB8iYwHWY3uxdyBT1
         w8SWZslO3z/Ov/eplj4xpB578C1Cug3sprd3IaqUmOCIDQbx6tBGxpaVxwZDTSN08ewK
         RygQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zf29eHFKDtxtdJtb1HGtsNLoPzh0TmoiNO+3u3jx7+o=;
        b=YxTSBWYQlPkFslI/rGX6iEa33gUHonNfDwgZ3ptJFoKRGPp8pQNWWbJN8UZ+xCNF9G
         TAf++PCur9YHCRKTHsm2bWR47xVe1mA8xJc5KUTurmlo9I4nz4GWB4JWkSszKYc7KNaH
         ANQs6+xTGIRGFTTrOGE6Z7/uIJ4s+dRtmgfLKRoQVGyRjGzlsxHxJZic9O+VssT9C8oP
         nbFHKuuR3DMz40EEpsoMKW13Wt4qpdm5Bn5mFJupZbwlylid4uagUglOAmvHbVqnVDOK
         THayHuKSKdKOX/OW0t7L4N54R14atMC5yHgo9+WQwRK6HtVsoBVM+zQNc7sdL/2RUFf8
         AsHg==
X-Gm-Message-State: AOAM5311H7wmOdSvbzxYuhAdyb6ojOnrfHsqSnBb82gLx4hfsIDDIuRs
	eGTZqUnLwJPQpfRxInl7q/M=
X-Google-Smtp-Source: ABdhPJww/Z6fp0Y8yDGAxMamuRfi6yot9rb+NBsLwRAcwU1dtoyOPmYGZtotkGY4LVWN52itvIbPaw==
X-Received: by 2002:a92:ba08:: with SMTP id o8mr49088539ili.249.1608200865447;
        Thu, 17 Dec 2020 02:27:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d203:: with SMTP id y3ls7073130ily.6.gmail; Thu, 17 Dec
 2020 02:27:45 -0800 (PST)
X-Received: by 2002:a92:79c7:: with SMTP id u190mr12525448ilc.140.1608200865060;
        Thu, 17 Dec 2020 02:27:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1608200865; cv=none;
        d=google.com; s=arc-20160816;
        b=eeptEaIEEGWQoZJX4I7d2NDh+C3NNwzVwvj3scn6JbsJEFx34dXAAcuzRChe8/SLyY
         ISaj+2SH2OSPIYwwD3vEFx1VhTa7oMh6CEorRYrq/v8gBBPHH5RhiewZuliRuuDLrQBq
         S7yyxdRS6gcMy99d6X0naGopqpRJXIQQO5nHRGCUT8vd399wm1XCgMtxY54Ocm0o65Px
         jNPU3zHB6ss1nYeX435y9Jaj41uQ43uriwxxWRxfOaWKGF85Qn0YXdw7RycXGve4J0/N
         GSXeshAwE0y9RxaVZ+YtjpnYvEDfvlZqDflRhs7I2kGlSzvmoh8EhLK/HYZh2bxzyYZe
         AJdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NP6eSDSojqskqJOR93wsgn5AO7yZNqVnPL0uMhSoHsQ=;
        b=lHwAr34UmnWfEeAvRX5gpfsTWI811KIwYn9FRAo1OvijwY2TTtl0iPKwnoyt7LLF3i
         eK/XuF1tgplcdqYXBYENwCH/QTt8Vfcvar6hj7upbZvks8VT2S8KQ+7J+p29x82qaNau
         uSJ43NKDD4joR5igqd4xfeoSTFgKthZHGz2/I5PbSwAP29LHu3sqb+z2AKlQuVar8+6u
         Ir8J94hCnREUirUgUYL96QiIJ3OtSkdsK+4n1WP7q0tqOwEAein6tV91nM8fFhYjEkyp
         0XaZ4TVZermcgzzY6jzOW4fBBOuDXubkYnIMPG6ZZki634NsZHL2lOXklESaLPL9hmnO
         XGtg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mJYqIDVd;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id p8si523759iln.0.2020.12.17.02.27.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Dec 2020 02:27:45 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id j18so11100173qvu.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Dec 2020 02:27:45 -0800 (PST)
X-Received: by 2002:a05:6214:487:: with SMTP id ay7mr48227770qvb.37.1608200864306;
 Thu, 17 Dec 2020 02:27:44 -0800 (PST)
MIME-Version: 1.0
References: <1607576401-25609-1-git-send-email-vjitta@codeaurora.org> <CACT4Y+bO+w50rgbAMPcMMTdyvRRe1nc97Hp-Gm81Ky2s6fOnMQ@mail.gmail.com>
In-Reply-To: <CACT4Y+bO+w50rgbAMPcMMTdyvRRe1nc97Hp-Gm81Ky2s6fOnMQ@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 17 Dec 2020 11:27:32 +0100
Message-ID: <CACT4Y+Zgg7dTeDtt73dQG1+v7kmb58fA-DQGv2NetwQB2brANg@mail.gmail.com>
Subject: Re: [PATCH v3] lib: stackdepot: Add support to configure STACK_HASH_SIZE
To: Vijayanand Jitta <vjitta@codeaurora.org>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Minchan Kim <minchan@kernel.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Dan Williams <dan.j.williams@intel.com>, 
	Mark Brown <broonie@kernel.org>, Masami Hiramatsu <mhiramat@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@google.com>, qcai@redhat.com, ylal@codeaurora.org, 
	vinmenon@codeaurora.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mJYqIDVd;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Dec 17, 2020 at 11:25 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Dec 10, 2020 at 6:04 AM <vjitta@codeaurora.org> wrote:
> >
> > From: Yogesh Lal <ylal@codeaurora.org>
> >
> > Add a kernel parameter stack_hash_order to configure STACK_HASH_SIZE.
> >
> > Aim is to have configurable value for STACK_HASH_SIZE, so that one
> > can configure it depending on usecase there by reducing the static
> > memory overhead.
> >
> > One example is of Page Owner, default value of STACK_HASH_SIZE lead
> > stack depot to consume 8MB of static memory. Making it configurable
> > and use lower value helps to enable features like CONFIG_PAGE_OWNER
> > without any significant overhead.
> >
> > Suggested-by: Minchan Kim <minchan@kernel.org>
> > Signed-off-by: Yogesh Lal <ylal@codeaurora.org>
> > Signed-off-by: Vijayanand Jitta <vjitta@codeaurora.org>
> > ---
> >  lib/stackdepot.c | 31 +++++++++++++++++++++++++++----
> >  1 file changed, 27 insertions(+), 4 deletions(-)
> >
> > diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> > index 81c69c0..e0eebfd 100644
> > --- a/lib/stackdepot.c
> > +++ b/lib/stackdepot.c
> > @@ -30,6 +30,7 @@
> >  #include <linux/stackdepot.h>
> >  #include <linux/string.h>
> >  #include <linux/types.h>
> > +#include <linux/vmalloc.h>
> >
> >  #define DEPOT_STACK_BITS (sizeof(depot_stack_handle_t) * 8)
> >
> > @@ -141,14 +142,36 @@ static struct stack_record *depot_alloc_stack(unsigned long *entries, int size,
> >         return stack;
> >  }
> >
> > -#define STACK_HASH_ORDER 20
> > -#define STACK_HASH_SIZE (1L << STACK_HASH_ORDER)
> > +#define MAX_STACK_HASH_ORDER 20
> > +#define MAX_STACK_HASH_SIZE (1L << MAX_STACK_HASH_ORDER)
> > +#define STACK_HASH_SIZE (1L << stack_hash_order)
> >  #define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
> >  #define STACK_HASH_SEED 0x9747b28c
> >
> > -static struct stack_record *stack_table[STACK_HASH_SIZE] = {
> > -       [0 ...  STACK_HASH_SIZE - 1] = NULL
> > +static unsigned int stack_hash_order = 20;
> > +static struct stack_record *stack_table_def[MAX_STACK_HASH_SIZE] __initdata = {
> > +       [0 ...  MAX_STACK_HASH_SIZE - 1] = NULL
> >  };
> > +static struct stack_record **stack_table __refdata = stack_table_def;
> > +
> > +static int __init setup_stack_hash_order(char *str)
> > +{
> > +       kstrtouint(str, 0, &stack_hash_order);
> > +       if (stack_hash_order > MAX_STACK_HASH_ORDER)

Can interrupts happen here?

> > +               stack_hash_order = MAX_STACK_HASH_ORDER;
> > +       return 0;
> > +}
> > +early_param("stack_hash_order", setup_stack_hash_order);
> > +
> > +static int __init init_stackdepot(void)
> > +{
> > +       size_t size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
> > +
> > +       stack_table = vmalloc(size);
> > +       memcpy(stack_table, stack_table_def, size);
>
> Can interrupts happen at this point in time? If yes, they can
> use/modify stack_table_def concurrently.
>
> > +       return 0;
> > +}
> > +early_initcall(init_stackdepot);
> >
> >  /* Calculate hash for a stack */
> >  static inline u32 hash_stack(unsigned long *entries, unsigned int size)
> > --
> > 2.7.4
> > QUALCOMM INDIA, on behalf of Qualcomm Innovation Center, Inc. is a member of Code Aurora Forum, hosted by The Linux Foundation

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZgg7dTeDtt73dQG1%2Bv7kmb58fA-DQGv2NetwQB2brANg%40mail.gmail.com.
