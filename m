Return-Path: <kasan-dev+bncBDW2JDUY5AORB6WL3CTQMGQEXRWKQNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B7F2A791D59
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 20:46:19 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-64977a67bcbsf19788066d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 11:46:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693853178; cv=pass;
        d=google.com; s=arc-20160816;
        b=bQB+xZPolG2oJvP73WXkR1yDoeQAghp2y7AF98owhvg+0Ktp4o1OuPMkCCb/m+Kh06
         uoT3JHDW+AXfzZiHxmlkK0Z5q/jI7N/CF36bQ2DtNf6rG2QwLv+0BCd+mjhk8B4hPWZC
         yulIfoy6/VQ9HhG7o+GPehzFK9qyL9M/exE63GSVmrn3ERT331P5jyOBcxgcjCkKRKAk
         nHvEg6c/zb+3iFGAhVj+t4ZGB/lpbCIg1QJ1JBW7eXkk3ffjxwff/EnkzB1VYJLC5ApU
         nVsXBXW5jiJqsPRmbGH1BoQL2ZfQIZWkco9Xo7D0eIqMe2JDewomLrA500Q1ZBQEGon+
         nzEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Sk6g85vQ6FBF7OXE2Jc0mnlzy29xg9PONNGFmBD8WYI=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=K5iEzV3Adz6/Nyv54X0+MiFA4P+tWPARV6kxNYhHBAc3JFxA2V8niU29MYqnDZlJWX
         D16mPhHd6KEzG9VZUMsT4H74WgcrYblkNPyzsssfReaSch4AClphRGXtRbshC+7ausc7
         yxT2tMDZyyPI2+at+Q/YL8AFPGwzJzjy361EY4aSL25GaB+SmpFGLrVUJd4vpy/Xr1+o
         quDnM2TsvuPahysuCcjQyDoHs8QK5fiBQoDzR+bKzWQMVTyjm2YV2ivU0u9cD6opIdTT
         d4BklQGeWsq8GSKaKSAiA1D12ik1FBpoPkzTp5LG6VV8/gYxBwJujOYwqkC3fZflKOO0
         KrRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=rj7VXlnd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693853178; x=1694457978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Sk6g85vQ6FBF7OXE2Jc0mnlzy29xg9PONNGFmBD8WYI=;
        b=V5CrbbJzTxICA9YdgCQwTUTRd2digLpWP2ZZskpurVTJNX8VTXxkkWz9t+IRnPWaLc
         MiATuCYWB59mjPCAM/KWw4AefCwS8SQROddbP1GkRDuS/3vBbUFCJBmpmxbrGP7dFUZx
         0rJlVkeYeD1z5zKN1YTc1becO7j4Nk2Mz4O1RpXna4lBVSiG4s10zkSX8Em4JASAvsgY
         NmxBFw24A3pHrweR1gWfNmrf49qsJvgoF/P4YQ5Gly9F2HRkfJx10Zt2f/kil/u/6c8o
         FlIYp3EKZt4fclLFMxgh6NJgtt26saOxLaBAowzFSzf0sE+rni+PTX59HPSo4sR0I+e0
         yYGg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1693853178; x=1694457978; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Sk6g85vQ6FBF7OXE2Jc0mnlzy29xg9PONNGFmBD8WYI=;
        b=gAw31UKcMu8hnT1PV3jf3r+zu8qJE8n7H7xiRc+nN7ugjOr6j9lB4ElLQMFATVgiwG
         hM+lRCKibZbR7ewTcLqd5hZbWGoSIXxgYKhyGj8EKUwu+2PAMMzKaqs3efzEMVdoAVBA
         FLOfTnbKAyZn+aNq/r0pPguqfgqzM8LQUummu33L+qBNou+i3ufZ8j6es+HxZ7SvYBxH
         EkS9CXfcFUJOSn4RmbKgUiCTYKbqvTn0BAT+4RdrVOcuqgwWZMsGhpinmOsQhHj4T6Pn
         dEcbilZ4t2WbobWQ2bTXL5f7VDRySl5hDRso3VrVKlkylqiqf/wOUZwHH2Hdsde0sit7
         +Cyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693853178; x=1694457978;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Sk6g85vQ6FBF7OXE2Jc0mnlzy29xg9PONNGFmBD8WYI=;
        b=K966fda8WVGwf7dp5R2TLno/FS1TsaAsJqXEWh9i91WE2q2Rfod7xxdH0+hfEoizGi
         O1eNwerPkOSKwCsfqEZlD11jbLo5U8zZlgkXMcW/XIeuA5S/jhVuKu8ryUYS45zVs6p4
         2BOlTBVRWdVlggancwPwrcVlJpkrxgyTxanwzcMVTqWKVEF2s1FRLy50sq2qCc5E+nBk
         JHum0t1Bg9qrNZkN7LDTxfDJJcMpmaFnxUw0hCIgZJLQYJOE9iiBDX1bol3IK0tZoX7t
         i2/w0b2zRzayeLK+8QXNrBDtiG5plC8aGi4Ej9Rbo+KWuPncFTrbeZ2KDUUt9iNwRDW3
         D32w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwcurlYO3bGlRt3ggqxsjiU1EIX3orVTAS61ginxsdojPnpJ9OB
	NYswzmiU4iszcE88qxPT3lU=
X-Google-Smtp-Source: AGHT+IFHUS1+HK+ES3sL1ooTIvdiH+L0V/JRum/NAnCJXplpxkADeVWUNRqnPyDvO6V1lJmdwkVmPg==
X-Received: by 2002:a0c:b452:0:b0:651:69d7:3d6a with SMTP id e18-20020a0cb452000000b0065169d73d6amr10252030qvf.15.1693853178565;
        Mon, 04 Sep 2023 11:46:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f389:0:b0:64f:4961:7c7d with SMTP id i9-20020a0cf389000000b0064f49617c7dls644403qvk.0.-pod-prod-06-us;
 Mon, 04 Sep 2023 11:46:17 -0700 (PDT)
X-Received: by 2002:a1f:dac4:0:b0:48f:b24d:21d3 with SMTP id r187-20020a1fdac4000000b0048fb24d21d3mr7339110vkg.15.1693853177823;
        Mon, 04 Sep 2023 11:46:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693853177; cv=none;
        d=google.com; s=arc-20160816;
        b=pk6Ic/e2pfMWkGWl2fY2ey4M1CkygAiU+3KWxYozh1Q9Ysw7okwcTbeJVkTR7XLDWB
         XZxnEXvzo7KABOEskK/sLM3xC3dkPI5dptjrpVF0xkBcJGz9oIyGlF8lOrnDqT1cAQti
         +kWZxZM4X0uvFst5VLa7r/zGOYnPt9EzO2Z9m2a466hpkGvwI2UABjF8Xo548QjfxAiW
         cA99hQPTLMF21Rs36CgsVtYGn1SJL7fXdKBnu4pIHUSxIfxqVMs0MVNnrewKost+GShA
         AKPftwFvSYtpypblR4Rc3e2dXpElPhjcUh+1s8ofEXEYWGjPlx5clmUC/WIjJAGX6+PU
         PlNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xPwa8jzfvAKIRzM093CaFHhTk58/oFuCdDDlLlEVSBw=;
        fh=vhyMgzwtVf8Cd+Xluz+kIPeaZIksHpPCItLJmpWVnQM=;
        b=hckJpCLay1uL+2C71+lVVqXaIkYx9GWBjA3g6ymq3Jv0OIlRFypJvbOTRez0iEAtfw
         kPOSAKvLEOXwB2STJh1MnGcoHgAckrHTzYEC6IWh//97v/TZ8XPqdU+use4y8zU19HlX
         yPsjHR2jS/SvAiX6dWZToBpfd17w0xRxo3xQlwof+oT+izVXjnnN+Hq/r0n3K8tTBGl9
         Im/Q6ku5lK/UXD39Ug8SFTg8rZrckpGPgmsqAYaJDMA8WUILgeDshc2KiG+S1u5e1Wu1
         lRpX/bkc6FCsIMM5LJ99v3oyOmuaqb2MwBZeSMe65V9udxpCueFeNgyYq8Ztl9dzVGHf
         WZlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=rj7VXlnd;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id cs9-20020a056122330900b004864d2cad2asi1946949vkb.5.2023.09.04.11.46.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 11:46:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-269304c135aso1164725a91.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 11:46:17 -0700 (PDT)
X-Received: by 2002:a17:90a:38a5:b0:262:fb5d:147b with SMTP id
 x34-20020a17090a38a500b00262fb5d147bmr9835987pjb.19.1693853177173; Mon, 04
 Sep 2023 11:46:17 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <6db160185d3bd9b3312da4ccc073adcdac58709e.1693328501.git.andreyknvl@google.com>
 <ZO8IMysDIT7XnN9Z@elver.google.com>
In-Reply-To: <ZO8IMysDIT7XnN9Z@elver.google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 4 Sep 2023 20:46:06 +0200
Message-ID: <CA+fCnZdLi3g999PeBWf36Z3RB1ObHyZDR_xS0kwJWm6fNUqSrA@mail.gmail.com>
Subject: Re: [PATCH 11/15] stackdepot: use read/write lock
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=rj7VXlnd;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1030
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

On Wed, Aug 30, 2023 at 11:13=E2=80=AFAM Marco Elver <elver@google.com> wro=
te:
>
> > -static int new_pool_required =3D 1;
> > +static bool new_pool_required =3D true;
> > +/* Lock that protects the variables above. */
> > +static DEFINE_RWLOCK(pool_rwlock);
>
> Despite this being a rwlock, it'll introduce tons of (cache) contention
> for the common case (stack depot entry exists).
>
> If creating new stack depot entries is only common during "warm-up" and
> then becomes exceedingly rare, I think a percpu-rwsem (read-lock is a
> CPU-local access, but write-locking is expensive) may be preferable.

Good suggestion. I propose that we keep the rwlock for now, and I'll
check whether the performance is better with percpu-rwsem once I get
to implementing and testing the performance changes. I'll also check
whether percpu-rwsem makes sense for stack ring in tag-based KASAN
modes.

> > @@ -262,10 +258,8 @@ static void depot_keep_new_pool(void **prealloc)
> >       /*
> >        * If a new pool is already saved or the maximum number of
> >        * pools is reached, do not use the preallocated memory.
> > -      * READ_ONCE is only used to mark the variable as atomic,
> > -      * there are no concurrent writes.
> >        */
> > -     if (!READ_ONCE(new_pool_required))
> > +     if (!new_pool_required)
>
> In my comment for the other patch I already suggested this change. Maybe
> move it there.

Will do in v2.

>
> >               return;
> >
> >       /*
> > @@ -281,9 +275,8 @@ static void depot_keep_new_pool(void **prealloc)
> >        * At this point, either a new pool is kept or the maximum
> >        * number of pools is reached. In either case, take note that
> >        * keeping another pool is not required.
> > -      * smp_store_release pairs with smp_load_acquire in stack_depot_s=
ave.
> >        */
> > -     smp_store_release(&new_pool_required, 0);
> > +     new_pool_required =3D false;
> >  }
> >
> >  /* Updates refences to the current and the next stack depot pools. */
> > @@ -300,7 +293,7 @@ static bool depot_update_pools(void **prealloc)
> >
> >               /* Take note that we might need a new new_pool. */
> >               if (pools_num < DEPOT_MAX_POOLS)
> > -                     smp_store_release(&new_pool_required, 1);
> > +                     new_pool_required =3D true;
> >
> >               /* Try keeping the preallocated memory for new_pool. */
> >               goto out_keep_prealloc;
> > @@ -369,18 +362,13 @@ depot_alloc_stack(unsigned long *entries, int siz=
e, u32 hash, void **prealloc)
> >  static struct stack_record *depot_fetch_stack(depot_stack_handle_t han=
dle)
> >  {
> >       union handle_parts parts =3D { .handle =3D handle };
> > -     /*
> > -      * READ_ONCE pairs with potential concurrent write in
> > -      * depot_init_pool.
> > -      */
> > -     int pools_num_cached =3D READ_ONCE(pools_num);
> >       void *pool;
> >       size_t offset =3D parts.offset << DEPOT_STACK_ALIGN;
> >       struct stack_record *stack;
>
> I'd add lockdep assertions to check that the lock is held appropriately
> when entering various helper functions that don't actually take the
> lock. Similarly for places that should not have the lock held you could
> assert the lock is not held.

Will do in v2.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdLi3g999PeBWf36Z3RB1ObHyZDR_xS0kwJWm6fNUqSrA%40mail.gmai=
l.com.
