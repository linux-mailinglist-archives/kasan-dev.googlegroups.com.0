Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6MU66WAMGQEPJDLOXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E90E829001
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jan 2024 23:36:48 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6800e52d47asf84683706d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jan 2024 14:36:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1704839802; cv=pass;
        d=google.com; s=arc-20160816;
        b=j7sK4klPkUKk0myXMjlB83HmzyP66iXYf6YtLXW2pLnr7OAawFYAeSlRNIOClw43vp
         Io3aVESRXnTEHPU6Fk5zUJWkGwe9UFmSDVbnVSLs/HX8ktsFZXwSRuUGZ4KkQcuWzLoO
         t/JEk+naxLxarvPYJRTzaianyCvlN4gprmzJRy+oskcIyDi8FQPDVoVhViegcpF4rTYP
         U/v5notlLshF6oDKGtEjSw3iQxw9iC03MAhEXZn6n71uG8zKj/gUWTJZLAcWAUHVERPx
         3p2oUwFMoP5ORf5PL28j64Bq0NNWzogwh/gGXcux1b40b5CFunchR5ozsE9zlBeovmTa
         WMZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=rfbePCbc+MbL+hICLEVoNvBFLgvxys6tF3DKiUnE3yA=;
        fh=dj7fNEPdqON0Sr19FDcKDNkJeoUSfJOtq7qs7EdA858=;
        b=p9pbw5Nh5aY96VBacTqSCf/pjFQEiVKxn1pYF3Rf8swqkIvMOKWt0P9I91cUpEYxNu
         1NosBK/K3XXjCMAqBeUsG2TwNv4zk6DOfgGTwV82Ui54exFY2Vf/07l6Uck00nYIsmO6
         NScZukvXq+F5fzGxRBIX8SmlQlrYVealUMU9TX1GE43kvUyahqb9yv5r0jGoQAgEFlCq
         vNaUiQ7K00GALpF/w3bB0LDqgITKH5+sn73pW06CWRJHYJDftzacDmA84RZAmGXYGbrF
         cglLMlZtUClcRyWyedBBpqpLj4uVA5zBdrJ/VBI7hxqDlX3zRTFTZQoHvuFNMbwYcIcu
         X0Ig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vFoptFMM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1704839802; x=1705444602; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rfbePCbc+MbL+hICLEVoNvBFLgvxys6tF3DKiUnE3yA=;
        b=HrWZqx9/9gcNendpdHhoqPUG6B1S/paND83g1gvkY6tDBhlm+QSDt8JHyR+VTjQDS3
         dUJ33qEs74RvSvZuY0qiN+ePP+oAYJMN1fMlw1fdbtWGOJs3PQKeN5qTd+pviTCsLKgd
         Xs3rk1yV4gNYBLnvxnAhb+3CvTxHFeqvfgDGTUMu1N1cFfx1SnmhJGiBzNSOiqiH4UEf
         MdtsLnBZonGgBol9AhgluroHdaHlHhvGZT6/3hgpA2vn9uQJarRKIBpCz4gUuH2A+n/h
         OauWSprJIQ6535Lg+qIj4SspcWAz/9ejXuLEMViRyCZalbi1hbDdJzxJfC3YULsyqXmU
         cSmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1704839802; x=1705444602;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rfbePCbc+MbL+hICLEVoNvBFLgvxys6tF3DKiUnE3yA=;
        b=w/5TUPdSRqaWMUMjCXL7ZghwbYCfAEuxtfp9cXmRlj4u2JlLNJ3ddkekecVAQNm5PO
         KjzHGQb4N++SGbj6NFDksE4zb32cH9K7w20KzMRHKNxYHF2YaOEXy/yXwdaDs/RnOwsc
         JA0S+2C1xzA0RaV4tGU7dgGijhFZJ7nKf+7iPiGGYJkd575fmqRNoyIOvyF7AX/6/xK1
         Qk8chyH/LYAOoxOSEE27JrOkLqX5CKDXSazls+Vkx7xb8V7CQEgumzez/oEvFIdo0G2Q
         KCWb3GsnyandrNWEISWh351K9UqalOm83jTJyXr1ySIDWFwCmDo8cEP6EMPF3TJc6n35
         1TVA==
X-Gm-Message-State: AOJu0Yw/c08aIgYC8bAc2sW79Pbcmd9HmkLG+mst9ClqUmczNsqfQuLC
	woPIcR1vDZj50CR4oubyiUs=
X-Google-Smtp-Source: AGHT+IGXUV6AdzO6PuQpcdtgksz4rv174+bwPyYCom0vPmDaCvpOuWHQvryoSTvdJNBB1JHp6LFBRw==
X-Received: by 2002:a05:6214:e8b:b0:67f:8d72:8cb2 with SMTP id hf11-20020a0562140e8b00b0067f8d728cb2mr349808qvb.16.1704839801954;
        Tue, 09 Jan 2024 14:36:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:f69:b0:680:f611:4d92 with SMTP id
 iy9-20020a0562140f6900b00680f6114d92ls1213517qvb.2.-pod-prod-00-us; Tue, 09
 Jan 2024 14:36:41 -0800 (PST)
X-Received: by 2002:a05:6102:2c0a:b0:467:df57:6c07 with SMTP id ie10-20020a0561022c0a00b00467df576c07mr174328vsb.11.1704839800978;
        Tue, 09 Jan 2024 14:36:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1704839800; cv=none;
        d=google.com; s=arc-20160816;
        b=TVjxM2h0v7YJp2coxKwaAOLADhkYdLucwv+0vzZmYwcA9x/4AMDyKbGnpKXw+KEpR/
         IrZi1ixjsn+BydslR506D7yqAS/6wi13BVh96Abt8k62KAkUzff+aeFD6YcSJiP63ExW
         K+emq7rjFXuwIjfrvf8xpzEjrQrsLrT+DPb6Zfqfe84VI5lKh88Tqcuk+oh7MKYkBBFE
         eSDUesjtXacFYAagBuOMQRhX9ZPzKNEp/2AIC7VH3UUCiRTLCw60X05eLJ7NaX+HOEF4
         gv/sR6BVwhmltQN0AXWFbKdqKtDK+fusFhXdO+u+mWCNS/LPqFzdopjH6oNMviYbWp+2
         JLaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wkqH0kvhJZgtpeoRvV3BZL+94wcGjMIJhbLOpqO3e68=;
        fh=dj7fNEPdqON0Sr19FDcKDNkJeoUSfJOtq7qs7EdA858=;
        b=avs+EPDMNGfeUqNV5iTfzSeP3R7DMUlfCdAtzkeCA6TvAJbccTBeyeFwpsYg+ZYozj
         ICEbLDe27y0SFAv8yLqudqis9AXtk5Bhxmy4irZwDPSXJ3IwPXJgcqdb/BkVDvfwCo3C
         bR0Dkkt9VIbuEyIngFV2SFb0eOySxIu/YcyyQRKK+52dknc7ftK3L0IyLzvyWg6SALpA
         Pmq6VqWOKGJHhFB3wVRdLmvHssEzBiekFuie+a6ZIlaRhwxhSuZHmvY8c4K7Ob65MlSR
         kRgbwv52593aqqIO6T6SdSdpeBqXCC68uhWsG8BxoZ3hwptVrqC8Yd3cCv7NHf58jORF
         m2pQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vFoptFMM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa31.google.com (mail-vk1-xa31.google.com. [2607:f8b0:4864:20::a31])
        by gmr-mx.google.com with ESMTPS id o11-20020a0561023f8b00b00467c4d39496si443367vsv.1.2024.01.09.14.36.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Jan 2024 14:36:40 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as permitted sender) client-ip=2607:f8b0:4864:20::a31;
Received: by mail-vk1-xa31.google.com with SMTP id 71dfb90a1353d-4b77c844087so2043989e0c.1
        for <kasan-dev@googlegroups.com>; Tue, 09 Jan 2024 14:36:40 -0800 (PST)
X-Received: by 2002:a05:6122:2a0e:b0:4b2:c554:ccfe with SMTP id
 fw14-20020a0561222a0e00b004b2c554ccfemr156571vkb.10.1704839800511; Tue, 09
 Jan 2024 14:36:40 -0800 (PST)
MIME-Version: 1.0
References: <20240109221234.90929-1-andrey.konovalov@linux.dev>
In-Reply-To: <20240109221234.90929-1-andrey.konovalov@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Jan 2024 23:36:01 +0100
Message-ID: <CANpmjNMvixmGviZ+NTXdnBXxDxotXbjQ1Q9uB3kERX8rXN+Wkw@mail.gmail.com>
Subject: Re: [PATCH mm] kasan: avoid resetting aux_lock
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	"Paul E . McKenney" <paulmck@kernel.org>, Liam.Howlett@oracle.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vFoptFMM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a31 as
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

On Tue, 9 Jan 2024 at 23:12, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@gmail.com>
>
> With commit 63b85ac56a64 ("kasan: stop leaking stack trace handles"),
> KASAN zeroes out alloc meta when an object is freed. The zeroed out data
> purposefully includes alloc and auxiliary stack traces but also
> accidentally includes aux_lock.
>
> As aux_lock is only initialized for each object slot during slab
> creation, when the freed slot is reallocated, saving auxiliary stack
> traces for the new object leads to lockdep reports when taking the
> zeroed out aux_lock.
>
> Arguably, we could reinitialize aux_lock when the object is reallocated,
> but a simpler solution is to avoid zeroing out aux_lock when an object
> gets freed.
>
> Reported-by: Paul E. McKenney <paulmck@kernel.org>
> Closes: https://lore.kernel.org/linux-next/5cc0f83c-e1d6-45c5-be89-9b86746fe731@paulmck-laptop/
> Fixes: 63b85ac56a64 ("kasan: stop leaking stack trace handles")
> Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/generic.c | 10 ++++++++--
>  1 file changed, 8 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 24c13dfb1e94..df6627f62402 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -487,6 +487,7 @@ void kasan_init_object_meta(struct kmem_cache *cache, const void *object)
>                 __memset(alloc_meta, 0, sizeof(*alloc_meta));
>
>                 /*
> +                * Prepare the lock for saving auxiliary stack traces.
>                  * Temporarily disable KASAN bug reporting to allow instrumented
>                  * raw_spin_lock_init to access aux_lock, which resides inside
>                  * of a redzone.
> @@ -510,8 +511,13 @@ static void release_alloc_meta(struct kasan_alloc_meta *meta)
>         stack_depot_put(meta->aux_stack[0]);
>         stack_depot_put(meta->aux_stack[1]);
>
> -       /* Zero out alloc meta to mark it as invalid. */
> -       __memset(meta, 0, sizeof(*meta));
> +       /*
> +        * Zero out alloc meta to mark it as invalid but keep aux_lock
> +        * initialized to avoid having to reinitialize it when another object
> +        * is allocated in the same slot.
> +        */
> +       __memset(&meta->alloc_track, 0, sizeof(meta->alloc_track));
> +       __memset(meta->aux_stack, 0, sizeof(meta->aux_stack));
>  }
>
>  static void release_free_meta(const void *object, struct kasan_free_meta *meta)
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMvixmGviZ%2BNTXdnBXxDxotXbjQ1Q9uB3kERX8rXN%2BWkw%40mail.gmail.com.
