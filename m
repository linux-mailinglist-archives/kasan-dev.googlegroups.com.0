Return-Path: <kasan-dev+bncBDW2JDUY5AORBGFZUGWQMGQEBYD5WTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id DA0DA830FEA
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Jan 2024 00:02:49 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-40e417aa684sf84362025e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Jan 2024 15:02:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1705532569; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ox2nXtJvT6d81M/KQ71/KWrmf/WcH6KxBUzegKThiT+4SRSQ18oi/ON03/2DQkEaT5
         gTu8xwk2V8urKPFi8bowrtEldribwVeXhi4eybzzuTFTPQoD3INABRgtS5Y6MtIy99dr
         GYrqDYZ7OwvHkPfThedGeg6fcLZLbm6tNEoNJVRv2JIT6fC8bowZo2pGHsQXSaBIy6z3
         CFQw2W5P7MCRMNzNASeJKPQq9R6kJH3kV0OFgYNaPIRVOk1DNUXksVkUlWNtQZ2//SPe
         7HpT8mZ8lnv3mDm1Y42/o9weHP/phMezfEIjD2bLA4PqJTRdznhQJDE1Pwd5hgsnhebJ
         6X1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=xiXGnOufqgSzicx2PYhNC6skYbyd333TOT6faqeI1wM=;
        fh=f4Ipbz2eCys6yF2ncPQnaMDCr5B3qrwsnm+lLy5ZEtA=;
        b=jP+nMcZg00ceHMcXFQfuBGuvPdvmTSzJtackZeCunliorrPgzot9cguIo/5miHZwFx
         gOWVl+mdwmINzkonCNqkdVhfXxp5NvmhxgKEeRM/m1cNOQtEYtIdfdytIPwvrkEf9c2K
         ifiJq5r/5PBzvTc0xVANo9HFS54M+Ko90ejHdDXwMou4Y30SPVITCHrzmeg0QDI3sVaP
         JBZLcfWSui701oc5Y14ICS6i4JUQDOi7OcjPHfRei6mWWwoummG7uhWJ769W6qixcgcz
         rj7dWYOeohz5Zg/L5fQ3zOheEjR7WrUmJz2AfR9GKIYYS8U/cdD7LF6zkkAOh9+WkkAR
         Tc6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jFneaIhr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1705532569; x=1706137369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xiXGnOufqgSzicx2PYhNC6skYbyd333TOT6faqeI1wM=;
        b=EHuE6kRX+qpNDG4S4yQpHfU8vYZl+Q8LAonFZ7Kunxiz/Tujlyy/NkIOpdC6RNmFuW
         s9jJN9nVBc7U+H7Ext34wKnMuTp9TND36SSPFRg+dOPrMB0eqNA5TX7hwvnph2vFsq7x
         gK2FLO3QyY6H0t7GWB2sKpereHQvi+SC1Rja4opeH7QLHURcmpJqG6Zigh7D7slux/Kh
         R8DNEekEk1REF2LxfQqK6V5SOUQlj/CmLnmjGAxsS1zQqPRZBWdmRI6o+1OsbTcFlIhe
         f7asLQu36cxAoQBaP1qs8B5SXfisd6HUheG2gP6NNYgyuC8PdnDRxvA+/S1RV4S5aBcp
         v+Qw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1705532569; x=1706137369; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xiXGnOufqgSzicx2PYhNC6skYbyd333TOT6faqeI1wM=;
        b=Ibw/L54YzRFfPMDa+9UcIYsKcfBwyqzpdEQnOkfV8MXaOyAKcfyRgozLuW3DCRy1Jm
         /a2Y0PaysWfyMXBRsci2O/i7AqzGhdYn5BbH6f3XWAYPwVW1WTWiX35RlIvVA9ZjwEAQ
         xH6WixAhumV3SPyAgBFgSPiSO9rypWptfJaYC+PXivYGDuC8gDdPie3mkxF0fqjN0+LZ
         cYf82c5hCzE+MuoCcaBIsjjBToHInjcly4Z9lpHWjuhKg6LHHoJmKo4cdCPIAycZ6gre
         wC/HjibSmXz32GD8eUrPCbQq3C7zf9HPGkKUQkIVYvUnlWTjsJTjJEsP9YBUpySUBXmV
         /ahA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1705532569; x=1706137369;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=xiXGnOufqgSzicx2PYhNC6skYbyd333TOT6faqeI1wM=;
        b=Z5m+2CbWgMdy4zJlSYlPvjXVwctG/+reIzk3wUsDotPgstgmXCqfLab3dsjdG74EfG
         fVTEkLT1NZs6Z3lyghwPJlATWmYnaqgODxA8UvtJirSUc/RbtpJ8X7dfiLeXsJsg9VMn
         gNEPqrpOJavzsHt3h+SEk7TwPauJmpb0UoM4xn8rSrTZgqdfTA750gGp72+sc0yG5xSP
         qGp7161D9sHJyGoMgWgeH/EY+rN87igR3N+8am46s/MHCWv/ppzO7kscvHYG5ZsUDZnO
         Bv3sigkr0vu3Yq8e0ypk2uYpVqkyV7VCA5DIgtG05qY2cWY+sTYChhG+b1qBxyeBG7+M
         YdWw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz15GUHJNEJwqmG3/sBpQFppphPZIrS9bYU1PqDT1FWnIzA7P4n
	I+/JdKPgR+mO2+kX1Gv7LmQ=
X-Google-Smtp-Source: AGHT+IGf2evqn6k91BC/W7W6KUBGnVSYLMudQ8uIoB5NqdWbjgCSoT0Oa2QXl/VvQPJrhvayDz5RuQ==
X-Received: by 2002:a05:600c:4395:b0:40e:5333:2024 with SMTP id e21-20020a05600c439500b0040e53332024mr5596067wmn.53.1705532569098;
        Wed, 17 Jan 2024 15:02:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6ace:0:b0:337:bd04:220c with SMTP id u14-20020a5d6ace000000b00337bd04220cls273519wrw.2.-pod-prod-07-eu;
 Wed, 17 Jan 2024 15:02:47 -0800 (PST)
X-Received: by 2002:adf:f152:0:b0:337:c504:912b with SMTP id y18-20020adff152000000b00337c504912bmr709296wro.82.1705532567462;
        Wed, 17 Jan 2024 15:02:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1705532567; cv=none;
        d=google.com; s=arc-20160816;
        b=Ibrs3AI1giXI9vIrfmgAks1stcssaDyI3NrlI8lCdrHcQyQxY3W9y7ZmlNsy2lRD7r
         j6/agZRPAv8g+cUSgjBeYSZ8g3Bg+1Knu6V71MchqAhxfZgkAm4YZFgw2Zbh6XzXjxB1
         9CxHndZa27kXnanuK0p7gD859wh2Xy6LLX/ogIDkaegC1Z15xj/8RTMVJjDXIQDw0zhm
         1J2uSHz3oeiTjGubnxQlaSaUPsGLC7yzaslJq0Bddqb85DwXsvEppNjviWIu1FrNfxGk
         loWhYV9N9yc+EKwKnH06hoCeJJs2vR9z4TJtZn8tr0Bu0F/+yGdbfKn8aY+ubvfqAU6l
         /cjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XVVQzIfswVI0WmMOjZbZ5Dux+OT+J5EfPrfiCiPsc9s=;
        fh=f4Ipbz2eCys6yF2ncPQnaMDCr5B3qrwsnm+lLy5ZEtA=;
        b=aY9l1NCUesvxalU596p170tvV2DuNc5M9W3D6PGUaizTQFitlGk8JaCSq1brilwEGq
         S17NqQe56zXcgvpfOO+d94aos6uFAah0Exe4Hh7uk3DP1hwQ22ACibjUGeH7Is3ZhgLp
         5mCSiVRXkkR8FploGSFE4SC7ccZ/6Elm1mrsp9tGudenIrgEGB8rrgP+BsCFz10r3Ow0
         xFFPYBn+FTyqb6wGUdeeSbxhk1wWbM6p8eARCGMjFdnK8grPEBSKxIYdG4iEsgOgxUes
         ZHjHj011Adk7iFVDgUd/alApFGUy4/bFoSw6z3ZmtD3W9+uZSmHQH64KGfyj4TuQMjQ5
         coYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jFneaIhr;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id v7-20020a5d43c7000000b00337bceeaf2asi83593wrr.4.2024.01.17.15.02.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Jan 2024 15:02:47 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-337cf4eabc9so6805f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 17 Jan 2024 15:02:47 -0800 (PST)
X-Received: by 2002:a5d:6446:0:b0:337:bebc:3f4a with SMTP id
 d6-20020a5d6446000000b00337bebc3f4amr1662482wrw.81.1705532566755; Wed, 17 Jan
 2024 15:02:46 -0800 (PST)
MIME-Version: 1.0
References: <20240115092727.888096-1-elver@google.com>
In-Reply-To: <20240115092727.888096-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 18 Jan 2024 00:02:35 +0100
Message-ID: <CA+fCnZfUiB67N_csOQuUMoLQ97WChaBm+FHdntmD63sL8xueyA@mail.gmail.com>
Subject: Re: [PATCH RFC 1/2] stackdepot: add stats counters exported via debugfs
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jFneaIhr;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
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

On Mon, Jan 15, 2024 at 10:27=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> Add a few basic stats counters for stack depot that can be used to derive=
 if
> stack depot is working as intended. This is a snapshot of the new stats a=
fter
> booting a system with a KASAN-enabled kernel:
>
>  $ cat /sys/kernel/debug/stackdepot/stats
>  pools: 838
>  allocations: 29861
>  frees: 6561
>  in_use: 23300
>  freelist_size: 1840
>
> Generally, "pools" should be well below the max; once the system is boote=
d,
> "in_use" should remain relatively steady.
>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  lib/stackdepot.c | 53 ++++++++++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 53 insertions(+)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index a0be5d05c7f0..80a8ca24ccc8 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -14,6 +14,7 @@
>
>  #define pr_fmt(fmt) "stackdepot: " fmt
>
> +#include <linux/debugfs.h>
>  #include <linux/gfp.h>
>  #include <linux/jhash.h>
>  #include <linux/kernel.h>
> @@ -115,6 +116,23 @@ static bool new_pool_required =3D true;
>  /* Lock that protects the variables above. */
>  static DEFINE_RWLOCK(pool_rwlock);
>
> +/* Statistics counters for debugfs. */
> +enum depot_counter_id {
> +       DEPOT_COUNTER_ALLOCS,
> +       DEPOT_COUNTER_FREES,
> +       DEPOT_COUNTER_INUSE,
> +       DEPOT_COUNTER_FREELIST_SIZE,
> +       DEPOT_COUNTER_COUNT,
> +};
> +static long counters[DEPOT_COUNTER_COUNT];
> +static const char *const counter_names[] =3D {
> +       [DEPOT_COUNTER_ALLOCS]          =3D "allocations",
> +       [DEPOT_COUNTER_FREES]           =3D "frees",
> +       [DEPOT_COUNTER_INUSE]           =3D "in_use",
> +       [DEPOT_COUNTER_FREELIST_SIZE]   =3D "freelist_size",
> +};
> +static_assert(ARRAY_SIZE(counter_names) =3D=3D DEPOT_COUNTER_COUNT);
> +
>  static int __init disable_stack_depot(char *str)
>  {
>         return kstrtobool(str, &stack_depot_disabled);
> @@ -277,6 +295,7 @@ static void depot_init_pool(void *pool)
>                 stack->handle.extra =3D 0;
>
>                 list_add(&stack->list, &free_stacks);
> +               counters[DEPOT_COUNTER_FREELIST_SIZE]++;
>         }
>
>         /* Save reference to the pool to be used by depot_fetch_stack(). =
*/
> @@ -376,6 +395,7 @@ depot_alloc_stack(unsigned long *entries, int size, u=
32 hash, void **prealloc)
>         /* Get and unlink the first entry from the freelist. */
>         stack =3D list_first_entry(&free_stacks, struct stack_record, lis=
t);
>         list_del(&stack->list);
> +       counters[DEPOT_COUNTER_FREELIST_SIZE]--;
>
>         /* Limit number of saved frames to CONFIG_STACKDEPOT_MAX_FRAMES. =
*/
>         if (size > CONFIG_STACKDEPOT_MAX_FRAMES)
> @@ -394,6 +414,8 @@ depot_alloc_stack(unsigned long *entries, int size, u=
32 hash, void **prealloc)
>          */
>         kmsan_unpoison_memory(stack, DEPOT_STACK_RECORD_SIZE);
>
> +       counters[DEPOT_COUNTER_ALLOCS]++;
> +       counters[DEPOT_COUNTER_INUSE]++;
>         return stack;
>  }
>
> @@ -426,6 +448,10 @@ static void depot_free_stack(struct stack_record *st=
ack)
>         lockdep_assert_held_write(&pool_rwlock);
>
>         list_add(&stack->list, &free_stacks);
> +
> +       counters[DEPOT_COUNTER_FREELIST_SIZE]++;
> +       counters[DEPOT_COUNTER_FREES]++;
> +       counters[DEPOT_COUNTER_INUSE]--;
>  }
>
>  /* Calculates the hash for a stack. */
> @@ -690,3 +716,30 @@ unsigned int stack_depot_get_extra_bits(depot_stack_=
handle_t handle)
>         return parts.extra;
>  }
>  EXPORT_SYMBOL(stack_depot_get_extra_bits);
> +
> +static int stats_show(struct seq_file *seq, void *v)
> +{
> +       /*
> +        * data race ok: These are just statistics counters, and approxim=
ate
> +        * statistics are ok for debugging.
> +        */
> +       seq_printf(seq, "pools: %d\n", data_race(pools_num));
> +       for (int i =3D 0; i < DEPOT_COUNTER_COUNT; i++)
> +               seq_printf(seq, "%s: %ld\n", counter_names[i], data_race(=
counters[i]));
> +
> +       return 0;
> +}
> +DEFINE_SHOW_ATTRIBUTE(stats);
> +
> +static int depot_debugfs_init(void)
> +{
> +       struct dentry *dir;
> +
> +       if (stack_depot_disabled)
> +               return 0;
> +
> +       dir =3D debugfs_create_dir("stackdepot", NULL);
> +       debugfs_create_file("stats", 0444, dir, NULL, &stats_fops);
> +       return 0;
> +}
> +late_initcall(depot_debugfs_init);
> --
> 2.43.0.275.g3460e3d667-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfUiB67N_csOQuUMoLQ97WChaBm%2BFHdntmD63sL8xueyA%40mail.gm=
ail.com.
