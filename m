Return-Path: <kasan-dev+bncBDKPDS4R5ECRBQPNRGJAMGQEB7EI7QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id EF9CA4EA5AA
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 05:02:26 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id om8-20020a17090b3a8800b001c68e7ccd5fsf718647pjb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Mar 2022 20:02:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648522945; cv=pass;
        d=google.com; s=arc-20160816;
        b=zOOwW359P15+WvhmRZIPGz0wBwBbbWERE/UKz7EpR9IEBLFLhrY5A3dFe60EDOTuC1
         2wrX78qDQCnm7gUhw4vh/ztlHETW5IXRG5O27nLJ9+0w8qT+YJk8zxYV+v5QkNme3MgK
         xEkgq40hPeU9IYVdF1FCj/ipc5hUX6gKz33qDV5iFaPoY7o0oPLSkKVft2D18fKGiFfK
         J1jlDhmoVOl7oplIYr/1qgDSzHwP1u1Yv7+9g8uWcjmvwIMrZpkTBOLN1hlBemJ2igoc
         wycuEp2S4oTdX1qTbfrDt/XZb6IZBQ9IgY9t4micxLr67qJUECF6sq2fAr0GPB114WCc
         7KQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=vV1j0n4KPW2jjlZ4pH81hhoqmPiiouScml4t04SJsnI=;
        b=Q5J07WFlTegSLRTfHOvRebnlDwtwzu0ma0fO7QxV2oUQ9JhlQNktU6+TJPg0Jz7Fe7
         R3GYdezsAxfXdQEGg0Ec5FBCAEfLP6xthPwXQn/kDNjLmBLR/NbCI4IateQ74p2fWsIH
         D3Yq/YhTavdH+D6tjU2Is8qV8Ja/onRzo5X/Ru7NoO0P7eEldkt+3Nptpl3j4sWPidb8
         ZZE0lu02V/gZeJA7u5omK4m2gmB6Z2EbzEUis55wu0FnFOlQUdyQbKVfXKzeKXw+e+ZJ
         YauCO5dcpqDQRN6jFOZSZ/aK/JYg71ZodeeqB7IiPJVkDtJcFGZ3wvw5Wf4Yvi3nfYuT
         dDkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=gSJ30XwF;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vV1j0n4KPW2jjlZ4pH81hhoqmPiiouScml4t04SJsnI=;
        b=dz8zLdrUwgq9BCFa68lH0d8hnpjc6LH9nfOmfqvTMuO/R7+fgW0yHPs7rlnx7nxsef
         q4neTWlAPXG+14Ef3r2lNcUNBvKlmMMFSsFsvVk46p6fqTceHuwqcoI/QonJK90vjdMy
         jkGZS4ENxFYNgZNODQSYIRElmFwbHOdZJPLcjXXrcb4v1X5QG8s0LTOXlRM9+s9nkuK/
         kTpyW7WkfzuwbfYRVyq3bT5CxT7s7x8eQMIFPWNomJZXNJdol5f+9D2pZvRGLkh/HKjJ
         PnGVQOkMQlU5CeIH/VpF96ue02mYPkAQFGZYSkxfTagBdy+k5nZeVV0+1JweYYEevzGa
         7wmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vV1j0n4KPW2jjlZ4pH81hhoqmPiiouScml4t04SJsnI=;
        b=P8faiXEPnUo0uLyi4QJsCnXhJGRUsqiyS1EZAioU/nPnN0tLTJYzx/UnqMvD177Btf
         svFi6rl+Y9IFt/Kc7S51lRWluGl4ZbzdXAupqb7RXRPtf3CR1dOn9HF4Zg+gynLG7/ki
         ZBohNDQG7WS/+kQxoml5iyQou9E+3bMPWQmohSbBP+D/uPwr93tlrXv9745Yih0jCslJ
         nCRKzAs9fxZUKXEjPfwcJPP0SYSkAxFQjBdHnDLLQZLDa/GsS5rotFLXOTeD92je6FYZ
         w2fY0j3OBgfGgpOyXrg5WBEFaTYdxZ4iWFJys89d8duFNI8P+7bfpQkXJLRhKkZ+ogGB
         axew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532cPsrL1LkG6tk8Nptb5bDiRNqpw9Ug00AlBCSu2V09Km9fMAyM
	rLEfYBHdLDDSXBsY6uvfl3Q=
X-Google-Smtp-Source: ABdhPJw2HOCCAlXyZyMgXLPyM0gGS34CisF2s6+aLCyFFDu7RJyWG1N0ETDFDwh+PjVTRQCoomy3kA==
X-Received: by 2002:a63:ad45:0:b0:382:2459:5bc6 with SMTP id y5-20020a63ad45000000b0038224595bc6mr427630pgo.474.1648522945343;
        Mon, 28 Mar 2022 20:02:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c4f:b0:1c6:8749:f769 with SMTP id
 u15-20020a17090a0c4f00b001c68749f769ls886703pje.3.gmail; Mon, 28 Mar 2022
 20:02:24 -0700 (PDT)
X-Received: by 2002:a17:90a:880e:b0:1bc:650b:6be5 with SMTP id s14-20020a17090a880e00b001bc650b6be5mr2315372pjn.34.1648522944797;
        Mon, 28 Mar 2022 20:02:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648522944; cv=none;
        d=google.com; s=arc-20160816;
        b=iHWuUnOWWHGAzrIov2V6uYHSmQhzhr+IbYV5YzVo0XbzqNGWnPxfJyA+gi93EUHIiT
         nEb8lV/fx+tDl45DSpkFH5H9hgG+egNBZ7oJ1cI9TERBbAnja6zc8N0ikwae5MWlgczY
         p32xVherFiBjVA988/g71uc0jQZJqlU6Tu3VykTzNB+Al6l3AsIBfS1b7aJxSGKOUkHu
         4734khBPsm5xBhFS/8wfd+LBy7OPQpBN1iaLSSDPvr3c7YxgXQdktAduj3GX2/bFeMPY
         DbPs6E3sNNky9sSbmGqTm+2r7qP/rgPajxSG8CuPDjGEQHJKpDuoP3GGDhoB+GjtLawU
         eJjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZJF2ROwWswfObVh+2bG7an1ccg+/dGsZVnoMIY0qAho=;
        b=zcQEYZHbmsGc4kdTCqT+FopyCAv8wVE12dmDlOxyTVlqNGdTAwA8PlIuwGHkVo3KsC
         9V6Z6wuyzjLNOr/YJnCpdzpukeJOYzG3Cc8igOcEdjgOhh/5Lh2gVxeuLVbEzHwxYQRl
         XR8PyTLYrrazIz5OZP7WUI4RqPmQzwKqHJ1VCHwbjWyG2yATwm8Lt3Vy4/EwV2WcJ6oP
         5hs0jM26N/L4nTe/8jDdrLhBDU7V8U+3lSkuya3zZByjxz9/kthIgZ6IP4R4s2xdqw1x
         5f2vY9ER1JaYoHr+nU473XV6nHrbBNHQzzY+NTiq8htCb1TKAznzeLIKVem0A+f6b5NN
         xDEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=gSJ30XwF;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id t19-20020a656093000000b00363bc052cd4si855810pgu.5.2022.03.28.20.02.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Mar 2022 20:02:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id o5so29362042ybe.2
        for <kasan-dev@googlegroups.com>; Mon, 28 Mar 2022 20:02:24 -0700 (PDT)
X-Received: by 2002:a25:cdca:0:b0:633:c810:6ca with SMTP id
 d193-20020a25cdca000000b00633c81006camr26311135ybf.261.1648522944149; Mon, 28
 Mar 2022 20:02:24 -0700 (PDT)
MIME-Version: 1.0
References: <20220328132843.16624-1-songmuchun@bytedance.com>
 <CANpmjNO=vMYhL_Uf3ewXvfWoan3q+cYjWV0jEze7toKSh2HRjg@mail.gmail.com>
 <CAMZfGtWfudKnm71uNQtS-=+3_m25nsfPDo8-vZYzrktQbxHUMA@mail.gmail.com>
 <CAMZfGtVkp+xCM3kgLHRNRFUs_fus0f3Ry_jFv8QaSWLfnkXREg@mail.gmail.com> <CANpmjNMszqqOF6TA1RmE93=xRU9pA5oc4RBoAtS+sBWwvS5y4w@mail.gmail.com>
In-Reply-To: <CANpmjNMszqqOF6TA1RmE93=xRU9pA5oc4RBoAtS+sBWwvS5y4w@mail.gmail.com>
From: Muchun Song <songmuchun@bytedance.com>
Date: Tue, 29 Mar 2022 11:01:45 +0800
Message-ID: <CAMZfGtXoMhji2TeF7gC13DMD4r3md72-CRXFc2BTfwmOx-K=xw@mail.gmail.com>
Subject: Re: [External] Re: [PATCH v2] mm: kfence: fix objcgs vector allocation
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Xiongchun duan <duanxiongchun@bytedance.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=gSJ30XwF;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Tue, Mar 29, 2022 at 2:58 AM Marco Elver <elver@google.com> wrote:
>
> On Mon, 28 Mar 2022 at 17:54, Muchun Song <songmuchun@bytedance.com> wrote:
> [...]
> > > >
> > > > Btw, how did you test this?
> > > >
> >
> > I have tested it with syzkaller with the following configs.
> > And I didn't find any issues.
> >
> > CONFIG_KFENCE=y
> > CONFIG_KFENCE_SAMPLE_INTERVAL=10
> > CONFIG_KFENCE_NUM_OBJECTS=2550
> > CONFIG_KFENCE_DEFERRABLE=n
> > CONFIG_KFENCE_STATIC_KEYS=y
> > CONFIG_KFENCE_STRESS_TEST_FAULTS=0
>
> Hmm, I would have expected that you have some definitive test case
> that shows the issue, and with the patch the issue is gone. Were there
> issues triggered by syzkaller w/o this patch?
>

I have tested this patch with the following patch and without this patch.
Then we'll see the BUG_ON meaning both objcg vector and object are
allocated from kfence pool.

diff --git a/mm/slab.h b/mm/slab.h
index c7f2abc2b154..1d8d15522a2e 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -519,6 +519,8 @@ static inline void
memcg_slab_post_alloc_hook(struct kmem_cache *s,
                                continue;
                        }

+                       BUG_ON(is_kfence_address(p[i]) &&
is_kfence_address(slab_objcgs(slab)));
+
                        off = obj_to_index(s, slab, p[i]);
                        obj_cgroup_get(objcg);
                        slab_objcgs(slab)[off] = objcg;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMZfGtXoMhji2TeF7gC13DMD4r3md72-CRXFc2BTfwmOx-K%3Dxw%40mail.gmail.com.
