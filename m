Return-Path: <kasan-dev+bncBCT4XGV33UIBBXFVU2MAMGQED6EFIYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 722875A3452
	for <lists+kasan-dev@lfdr.de>; Sat, 27 Aug 2022 06:17:34 +0200 (CEST)
Received: by mail-oo1-xc3b.google.com with SMTP id p6-20020a4a3c46000000b0044ada2fea24sf1572962oof.2
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Aug 2022 21:17:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661573853; cv=pass;
        d=google.com; s=arc-20160816;
        b=dmsWhERLEXR/eB9N6Azg8NFJCyCTA3gyfpixkGvFx/8AAyb3eTPftuFpVwp7x/eHG7
         RAnoYjXWcoQGD8unb+4wo+aJvKgzy7zEsA2iE2iH8AwdnY53jYUVa80aPw1GrJhmrNm2
         NOmMxMlkcKy7dSaGSokW4MCOH4e2Bt8IbtYAG8KbXiswybPviQGW/PJAH64XTsUF+fP2
         VsxT38ujeODNCdbEKkXzAd+PHLj8XgjNGLtk5la7EiL8HZv4fdtM8c2Xl/rabzjdTkzu
         lcj4ZaqQ4LQ+JD1T3XHT18IIuSrrGwOpMbqkUcRrpmnEB9oUjQjhzbFOYvGu4WGLehb+
         5V/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=a2tkwkP9yYiQUqlbYnyWCJ1jKQb5JqGjLhEilwvKqL4=;
        b=XhBZlZdZcdGStI6tmYgpRfqMr/a2CSE3UyRP9suCC+69o5DuTSeZHYPPh3nJvrO5Ul
         26XB5Rl5r6o0mj7Q5pU9F7k1Y6vAwsRIg0Y8uNVWjqPAdfEjn4Liwy6L0pl+rKTxr6zb
         Pgje1+9tP94bNJR6VdfSddvmRrPelxFj1HtZg8w8Fqf6Q17lfyUJlkLZHS03yAl35id6
         iAOhHyWEynCipvTmzQUqYv43qKCYdJBdlLYHIwsQEy2qyh+STZThXjhI+93O+3wdNA4Y
         XS2RSBkiKrVR3bXoNfVZ6iuDIeaop+QoWH0JG8/mWKmv7JOWUmbDeh3DRTJ82EBohQ7T
         A6jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=0wwPwPqY;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc;
        bh=a2tkwkP9yYiQUqlbYnyWCJ1jKQb5JqGjLhEilwvKqL4=;
        b=R3SDBxxY8CLVAT4FDH30HAJ8BSHAvoZX9uqvMeq7Aci0hU9rCtqJkupyAvbOFX049X
         +JmK4DKoAHTy4C4LlYOB1ALAI+inlyFPAEKxLM8mmSwAaN4IZKX4YzaMrj/RioJ5arrv
         sMOfYQClv99XO8sDMynlBZd9j/FzyEwSM/lxxLTAeFsZpmZ8OLP10ZbYwVjuKOa9Rra9
         NCxGcXHco+KklMyrCsYJFRw0JHJNiPcczIwgrRWNpvU5Ptg21k2sSZ2S1JNi1tmXzVJu
         FjBsewIYkDZtLS1EVh+74TIjSBoMEqXxLDv1kbmeyLB+pA262Y2A4psBYMHsyuMpv5o/
         sR4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc;
        bh=a2tkwkP9yYiQUqlbYnyWCJ1jKQb5JqGjLhEilwvKqL4=;
        b=QMfie5gZbtSmEDgIOqNY+Oi67ARDvUImrxXE2B8AzalNRoCU75pxxsK7vsZIxY8pBt
         7RLEuPTXQneSAKd0s/OuWHszTlgpRJJaHD3HaMAOYnuxzOhmR0cYVvOKFyKpc69K7uTW
         4NAMWi89zBK2/CTiVAgQl2O1D+Gqsf5vaDWF4INDc/0vzTeN9bPa9TLpS7XJbXFE3o/V
         mizWh8I/aeoZpwgchquL2+Ax54vBnD69R/SQH4fDL4KHvGxcYccXm5LJhTjkp1P9CyWN
         hNJLnzCIAqD03wTVxVo2QTI5riS7DA+0wn/hvUH5DGjEQMgKT4ekSCkeBdO5GMnxDkRa
         uNUA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0jKoMb7LvF245RnXx4TX6SYKuBkEzDjo2KeF9bwTTNUMl+x9tC
	AxjlchqYyZlQtThKL8+xnUY=
X-Google-Smtp-Source: AA6agR5Z88yUrKQcCUX3rqE9+RwSeM30eOgdlGSiQkTtza5XwtHabUVKXDcOth1Ws0CyYl314okukw==
X-Received: by 2002:a05:6808:1996:b0:343:5dd:c28e with SMTP id bj22-20020a056808199600b0034305ddc28emr2963723oib.20.1661573852824;
        Fri, 26 Aug 2022 21:17:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:987:b0:344:8509:3bb2 with SMTP id
 a7-20020a056808098700b0034485093bb2ls1168962oic.4.-pod-prod-gmail; Fri, 26
 Aug 2022 21:17:32 -0700 (PDT)
X-Received: by 2002:a05:6808:1b2b:b0:343:f1e:1df9 with SMTP id bx43-20020a0568081b2b00b003430f1e1df9mr3167817oib.74.1661573852335;
        Fri, 26 Aug 2022 21:17:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661573852; cv=none;
        d=google.com; s=arc-20160816;
        b=rbjQCv9EtQetCpGsRdrMlFmOofbpHBSD0PTLXdPr3jAIb6Uk0qlzQ+7D7q1eRoGLIQ
         ZAvs87JIo2eM6U4rtnKA5sUue9ScaV+kiBccE29EcwoQbyt4ONw7B0RxeC6nhRMniFOc
         3sNWGJIfdRKktf1dIIuEGQEdsC8VErDWkWp0820kigu1WATOS1ypaCrxSUsdFek0/d/F
         d5Vja+vXvS7OkkvJQ4G1sR9M5bChi7m+YTR5YYh5fi9kuFbkqFpo7r7zuzh3TymlDGo0
         ysApRVZhY+RQj3qRnNO2/svHHd081wb0REo8rBCUylWpSwWffRgHYpbDsCylzN8pdE2h
         yilA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YXKY7xUH+e8MljL5ktdAuQHuT8m/c8UeQSkKo/fZ3pM=;
        b=R+l9G15rIHraNx3jq8K8wBj/j99nHXjEBx8cH9G9IuWcnoes3s7jvFC7zRKxV3QC44
         qeAaOvDFBZRvTOPBaKeUo9i9UHugNDEGxQ6hvObBceU/3snNk3o/s/Ej7yRdgRwe3YTp
         Vk6+wRMuDwiUU4xaf+/JmOgpXYu2qeWH1nx8fkhO7sQM6mAXoTq5i698TN8ow5xY7bNM
         Camob+Q//Fr7GqEljoxBoelBoZQIaVO9A6RUz3Tx7D64c8drFclbs0rvB3s5bcc3v1ZI
         iP2FftGj069sR+qxjfaU30DPUASsNeZv7YmGwsMfUswEGkVEjU+MLi6fiMGia7ogdEwy
         DbWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=0wwPwPqY;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id l2-20020a9d1b02000000b0063919f5e270si117887otl.1.2022.08.26.21.17.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 26 Aug 2022 21:17:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id E7BBE60A2C;
	Sat, 27 Aug 2022 04:17:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 299E8C433D6;
	Sat, 27 Aug 2022 04:17:30 +0000 (UTC)
Date: Fri, 26 Aug 2022 21:17:29 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov
 <ast@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, Andy Lutomirski
 <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov
 <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner
 <tglx@linutronix.de>, Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum
 <vegard.nossum@oracle.com>, Vlastimil Babka <vbabka@suse.cz>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-arch@vger.kernel.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH v5 04/44] x86: asm: instrument usercopy in get_user()
 and put_user()
Message-Id: <20220826211729.e65d52e7919fee5c34d22efc@linux-foundation.org>
In-Reply-To: <20220826150807.723137-5-glider@google.com>
References: <20220826150807.723137-1-glider@google.com>
	<20220826150807.723137-5-glider@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=0wwPwPqY;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 26 Aug 2022 17:07:27 +0200 Alexander Potapenko <glider@google.com> wrote:

> Use hooks from instrumented.h to notify bug detection tools about
> usercopy events in variations of get_user() and put_user().

And this one blows up x86_64 allmodconfig builds.

> --- a/arch/x86/include/asm/uaccess.h
> +++ b/arch/x86/include/asm/uaccess.h
> @@ -5,6 +5,7 @@
>   * User space memory access functions
>   */
>  #include <linux/compiler.h>
> +#include <linux/instrumented.h>
>  #include <linux/kasan-checks.h>
>  #include <linux/string.h>
>  #include <asm/asm.h>

instrumented.h looks like a higher-level thing than uaccess.h, so this
inclusion is an inappropriate layering.  Or maybe not.

In file included from ./include/linux/kernel.h:22,
                 from ./arch/x86/include/asm/percpu.h:27,
                 from ./arch/x86/include/asm/nospec-branch.h:14,
                 from ./arch/x86/include/asm/paravirt_types.h:40,
                 from ./arch/x86/include/asm/ptrace.h:97,
                 from ./arch/x86/include/asm/math_emu.h:5,
                 from ./arch/x86/include/asm/processor.h:13,
                 from ./arch/x86/include/asm/timex.h:5,
                 from ./include/linux/timex.h:67,
                 from ./include/linux/time32.h:13,
                 from ./include/linux/time.h:60,
                 from ./include/linux/stat.h:19,
                 from ./include/linux/module.h:13,
                 from init/do_mounts.c:2:
./include/linux/page-flags.h: In function 'page_fixed_fake_head':
./include/linux/page-flags.h:226:36: error: invalid use of undefined type 'const struct page'
  226 |             test_bit(PG_head, &page->flags)) {
      |                                    ^~

[25000 lines snipped]


And kmsan-add-kmsan-runtime-core.patch introduces additional build
errors with x86_64 allmodconfig.

This is all with CONFIG_KMSAN=n

I'll disable the patch series.  Please do much more compilation testing
- multiple architectures, allnoconfig, allmodconfig, allyesconfig,
defconfig, randconfig, etc.  Good luck, it looks ugly :(

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220826211729.e65d52e7919fee5c34d22efc%40linux-foundation.org.
