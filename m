Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMEW46NAMGQEPXAWTFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C21060ECD1
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 02:05:06 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id o1-20020ab01501000000b004058109e5d1sf4997096uae.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Oct 2022 17:05:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666829105; cv=pass;
        d=google.com; s=arc-20160816;
        b=XEraIglrWC8fKvSGERINBKvaOrWRojF7i6/QkeG4qnNSU4V6b/mZa/9GJO0TZpdVDF
         jKylu7cbnq5/gNhUc+5gyQtS5z2U0SHoQoisJEKEP0RNLRis7PD+v9UEgADEiNUnFk46
         CdRfVFxCg9LXYXfNxM8d8MPfskIodAs/1vuxeNll3GlPVStPhUYRu36pRlw5F5MIzpOF
         nvf+MZpGA35+FjD0P9+47oA/CUO1Qe2xLTYC7scnxdBeT0ddXVbeWcVYcK159iF0DfVE
         oCsqmdtw70IlkPZzaH05AFZ/wzwTKzNnGC3QyB+NJcB0dliXxEjqipasSdoQ/fAF+CmU
         fOxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3rv7aVvVtFkBx7LBw0ADy1XrusxSg5Ba6f2EYQosECg=;
        b=TPwUOKQuWRj/mxF2AbRGdsMh6jFTBoY9cwuYdrn1gumIjhRtOVPMPE67lwHW4ioUcM
         0xLmpXbfnCN5gyhZfN70AZiecA+8y9duHbP5Lov3VsIPA2vgYA0zDs/80QE034kzJE6M
         e5jzJHUUHis6S5PSU5jtTSpCafo+XvI0pouwRTYyFSI0lXb9I3HIV06/eSe9UZMJDtEm
         m/zSfwdp5VERuLER0CcgVOHBfhB0pBZMyVT0RKltMyPnHUfMllWNY3egYmlwL5C6wSf0
         wvPACpESIDjTye/x6qnbUCDxK7Eff9j1SCX4cYd6BJO2CCKeT/QKksSmkAOA4P9mrJLL
         oLiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lKQNO9bg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=3rv7aVvVtFkBx7LBw0ADy1XrusxSg5Ba6f2EYQosECg=;
        b=USGjh3xuzR1ElzRh1S6Vzf+vSi995Yeqyn9So2KryhTxZXhy/pMt8KIYXrAP5rjrLS
         FfuXSzl+DatpG0F/QoDvxduIKDRGlqXGRrkU/S/B9zStfuvjdF/Xov5SFy8WHD8AAMi3
         1l1wfdcvaNiS08YtN8FrbayP89O0j2Ht8ZPXqs2tQNnc6GnEdLDDksRfEa8Xho4oR7Nz
         B7XpsMVyqxhJDCMNg8M1mlNqTRSg0pppNe9YBWQdhlnuM80OfzO6K4/itVGdtpVC/8AE
         BZ/+RXT/zJ4UrG6tKgLg6ny+8rlGBA9B1iAtVL//aouU1dhuwd6R2qhwzdOk0mcn0SHz
         1J+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=3rv7aVvVtFkBx7LBw0ADy1XrusxSg5Ba6f2EYQosECg=;
        b=g6OgI28tLQJBJwNYjxI2JKERLfVqQQt29Otmrf4t2MWIFHVbf72PG/hP9qD3qnBbhn
         s0CowhgKKkXyOzQkFxiaQkwIZgiroAneH2lWz202HFQaRZm6+VqKP+fiNJgjsiizOTGp
         U9LACqsv2qlpQEyyw7OZWqSWpkf/2I9olMGnuH2BqOBSgjgxQsYhikPnbafigucUd61v
         9TqUfYHq6hVGMqUnngmkFxOC6z5v8clGaKtD5EUhCEg49lrtIWnUrAGB/HtvreNud/nw
         wB4Fck1n82GDTmKSj4oqI1tVGPGsaRcvaysWK/OQk2GMfH4+7HzxPgoT2zTNNCEolci0
         rO6Q==
X-Gm-Message-State: ACrzQf2alesCxWiyZLYM5MKF3/SMt27UWmldBjT8xkb0YIDcfDeJeiYM
	cn7hknZingU7WVG6+5z2CMk=
X-Google-Smtp-Source: AMsMyM44ff4wHDmN+jVFXmGn8fV/qz7p+/dicv6EU9OnfO838R+TimD5pw+r50YszGcTVw4r9eFYzQ==
X-Received: by 2002:a1f:9bd0:0:b0:3af:163a:72f9 with SMTP id d199-20020a1f9bd0000000b003af163a72f9mr26218725vke.0.1666829104955;
        Wed, 26 Oct 2022 17:05:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:278d:0:b0:408:c6de:ef4d with SMTP id t13-20020ab0278d000000b00408c6deef4dls970296uap.5.-pod-prod-gmail;
 Wed, 26 Oct 2022 17:05:04 -0700 (PDT)
X-Received: by 2002:a9f:2e16:0:b0:3e7:f488:e37a with SMTP id t22-20020a9f2e16000000b003e7f488e37amr27371260uaj.20.1666829104192;
        Wed, 26 Oct 2022 17:05:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666829104; cv=none;
        d=google.com; s=arc-20160816;
        b=EgD6tGaGyppM9ng4OnKkee5CAtRoco/bqGpOPcLMkMKgf3+yD1A7twKvbDPGsS7Nxv
         AdElOQQh7LUAyeuli4TLc+Kqbwvga6TLVs0CCS/oXfXaT1VZHzF1guZF8KsPvnyv9eHn
         jyyREoMFWr65fzF0O9BLssTzI+jZk4RB0Qa0SeQn5R1K23B9bUAnSZhMxdv/Qj5+u8H2
         DU+KulVzMH7mO1Cn8am36XM8Eqn6QJEbAS3wYxGkX7X8TVSFN9h6UDrz90PTY45MHt5x
         zqft6fKJUxGt70JCgtQ8fKTnJIkJdSb+h2InHz73e1eeW8oXgIlys1rVCPD64ecdFY+w
         NeMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5fCQYHP/s1K+a3B3xVNrAVIKsujOkSpQyFTVrdP9WZU=;
        b=itHbzH+Qg2V3l58uHTMrKHRKXyCWmXXmoZdmDfeom8W9A+PGSS46za7aQjwCxfn6nM
         ahGcAJ9v8V8zvzlg1neoQ3J/DMgY4721ucll523RjYtD6DiXl+L2cZIvy7RReqXKCl83
         +cShOE/3rTtIvCH+5p0HEMzQ9ggaoOzuYbIDJWjL+slGbZQ4fyirX97sXWJPgwwwPrFq
         QRNQS5Qb77F/LFP+tf+vb4fE/1sudXXAgED8B6ZGSueViIGTLy8pQOYLcnr5EQeTusr6
         olLClqwKidRleKLKhE87GTzKES3muU8/asmHg99+grguAD/7uaJT6llwkmNuU+MqptE+
         B8yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lKQNO9bg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2b.google.com (mail-yb1-xb2b.google.com. [2607:f8b0:4864:20::b2b])
        by gmr-mx.google.com with ESMTPS id h6-20020ab02346000000b0040ac33271e7si352609uao.2.2022.10.26.17.05.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Oct 2022 17:05:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as permitted sender) client-ip=2607:f8b0:4864:20::b2b;
Received: by mail-yb1-xb2b.google.com with SMTP id y72so21144955yby.13
        for <kasan-dev@googlegroups.com>; Wed, 26 Oct 2022 17:05:04 -0700 (PDT)
X-Received: by 2002:a05:6902:1542:b0:6ca:675a:fdee with SMTP id
 r2-20020a056902154200b006ca675afdeemr29400463ybu.125.1666829103682; Wed, 26
 Oct 2022 17:05:03 -0700 (PDT)
MIME-Version: 1.0
References: <20221026204031.1699061-1-Jason@zx2c4.com>
In-Reply-To: <20221026204031.1699061-1-Jason@zx2c4.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 Oct 2022 17:04:27 -0700
Message-ID: <CANpmjNMmHa04Fqf5Ub5-vz6HuqT_Gg8GmEfKD6rv8JeMfBZ32w@mail.gmail.com>
Subject: Re: [PATCH] kfence: buffer random bools in bitmask
To: "Jason A. Donenfeld" <Jason@zx2c4.com>
Cc: kasan-dev@googlegroups.com, patches@lists.linux.dev, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lKQNO9bg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2b as
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

On Wed, 26 Oct 2022 at 13:40, Jason A. Donenfeld <Jason@zx2c4.com> wrote:
>
> Recently kfence got a 4x speed up in calls to the RNG, due to using
> internally get_random_u8() instead of get_random_u32() for its random
> boolean values. We can extend that speed up another 8x, to 32x total, by
> buffering a long at a time, and reading bits from it.
>
> I'd looked into introducing a get_random_bool(), along with the
> complexities required for that kind of function to work for a general
> case. But kfence is the only high-speed user of random booleans in a hot
> path, so we're better off open coding this to take advantage of kfence
> particularities.

kfence_guarded_alloc() is supposed to be a slow-path. And if it were a
hot-path, I currently see no evidence that a call into the RNG
dominates the time spent there.

Do you have profiles?

What are the real benefits of this change?
Is it to avoid depleting the entropy pool?

> In particular, we take advantage of the fact that kfence_guarded_alloc()
> already disables interrupts for its raw spinlocks, so that we can keep
> track of a per-cpu buffered boolean bitmask, without needing to add more
> interrupt disabling.
>
> This is slightly complicated by PREEMPT_RT, where we actually need to
> take a local_lock instead. But the resulting code in both cases compiles
> down to something very compact, and is basically zero cost.
> Specifically, on !PREEMPT_RT, this amounts to:
>
>     local_irq_save(flags);
>     random boolean stuff;
>     raw_spin_lock(&other_thing);
>     do the existing stuff;
>     raw_spin_unlock_irqrestore(&other_thing, flags);
>
> By using a local_lock in the way this patch does, we now also get this
> code on PREEMPT_RT:
>
>     spin_lock(this_cpu_ptr(&local_lock));
>     random boolean stuff;
>     spin_unlock(this_cpu_ptr(&local_lock));
>     raw_spin_lock_irqsave(&other_thing, flags);
>     do the existing stuff;
>     raw_spin_unlock_irqrestore(&other_thing, flags);
>
> This is also optimal for RT systems. So all and all, this is pretty
> good. But there are some compile-time conditionals in order to
> accomplish this.
>
> Cc: Marco Elver <elver@google.com>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Signed-off-by: Jason A. Donenfeld <Jason@zx2c4.com>
> ---
>  mm/kfence/core.c | 32 +++++++++++++++++++++++++++++---
>  1 file changed, 29 insertions(+), 3 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 6cbd93f2007b..c212ae0cecba 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -356,21 +356,47 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
>                                   unsigned long *stack_entries, size_t num_stack_entries,
>                                   u32 alloc_stack_hash)
>  {
> +       struct random_bools {
> +               unsigned long bits;
> +               unsigned int len;
> +               local_lock_t lock;
> +       };
> +       static DEFINE_PER_CPU(struct random_bools, pcpu_bools) = {
> +               .lock = INIT_LOCAL_LOCK(pcpu_bools.lock)
> +       };

If I remember right, function-scoped static DEFINE_PER_CPU were
disallowed (but I now cannot recall why and where it said that :-/).

> +       struct random_bools *bools;
>         struct kfence_metadata *meta = NULL;
>         unsigned long flags;
>         struct slab *slab;
>         void *addr;
> -       const bool random_right_allocate = get_random_u32_below(2);
> +       bool random_right_allocate;
>         const bool random_fault = CONFIG_KFENCE_STRESS_TEST_FAULTS &&
>                                   !get_random_u32_below(CONFIG_KFENCE_STRESS_TEST_FAULTS);
>
> +       local_lock_irqsave(&pcpu_bools.lock, flags);
> +       bools = raw_cpu_ptr(&pcpu_bools);
> +       if (unlikely(!bools->len)) {
> +               bools->bits = get_random_long();
> +               bools->len = BITS_PER_LONG;
> +       }
> +       random_right_allocate = bools->bits & 1;
> +       bools->bits >>= 1;
> +       bools->len--;

This should be factored into its own function that returns a result
for random_right_allocate.

>         /* Try to obtain a free object. */
> -       raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> +       if (IS_ENABLED(CONFIG_PREEMPT_RT))
> +               raw_spin_lock_irqsave(&kfence_freelist_lock, flags);
> +       else
> +               raw_spin_lock(&kfence_freelist_lock);
>         if (!list_empty(&kfence_freelist)) {
>                 meta = list_entry(kfence_freelist.next, struct kfence_metadata, list);
>                 list_del_init(&meta->list);
>         }
> -       raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> +       if (IS_ENABLED(CONFIG_PREEMPT_RT))
> +               raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
> +       else
> +               raw_spin_unlock(&kfence_freelist_lock);
> +       local_unlock_irqrestore(&pcpu_bools.lock, flags);

Overall this introduces complexities that should be hidden behind some
new abstractions.

But besides that, I'd first want to understand what the real benefit
is given all this is supposed to be a slow-path.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMmHa04Fqf5Ub5-vz6HuqT_Gg8GmEfKD6rv8JeMfBZ32w%40mail.gmail.com.
