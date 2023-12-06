Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE4SYKVQMGQELGPXT3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x240.google.com (mail-oi1-x240.google.com [IPv6:2607:f8b0:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D4968072E2
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Dec 2023 15:45:42 +0100 (CET)
Received: by mail-oi1-x240.google.com with SMTP id 5614622812f47-3b9d2f0d732sf347229b6e.1
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Dec 2023 06:45:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701873940; cv=pass;
        d=google.com; s=arc-20160816;
        b=lZxJBhXWaEfY7m35j+QQ25M4NskjdJDn0tyu9haJ7OQfB0CEiEUDjaHFplI50Fj/1g
         3LQfars1a+C8iu+eeZvQLJeQ0SfNbg5WdaL39rEgI1Hv6xfIOVHumXmlc2uLOGzI3oBL
         oeHU+05d3x35SoQifv8G8kvKXSvfAODW82T9mEeIZP72zAzQEeo7cVzIV8Wh0cYihilQ
         8WeRL3umcs1qhP/QSqtaHCdwUKJ1lM1Hvxd8f5OQg5+v59klXsLnucb+PQJmNt23QX4Y
         wO/WIcQHnffWNu0F+OYFIc+Rmrd6OmR+k7QQjcwJJCQC98RojefVJHSUHbw9KmLGB8Uy
         mnag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=giGoSZT+L93C6+Ipr0HwG1DhvKXWOuSo6gXx7XjzoBo=;
        fh=go8Y/Z2zMKxw9GTvs/wrSRn4+U+QAqosGEOkKS4ggMI=;
        b=FzS92LVEivSbuBtqNM9YBQ4CIuAd9sdsNYPF7Vv8PtFgoCKjMjtV672JV2AHHqkoHM
         V+VQi1spP/TUifilX8JCq7DDHAL2IkckZDduTrxQaBNkpSxqGHjz61+VtryZ/YGttK05
         0gq0w0daQhBQMzPOk6CunVpCBqYKJ68UenKBGcDXuAbsdNNZ76Y9sHIw4ZTaLhoP15P2
         jYjLRQpwK4FSY0EfwD7SBTcquBotBNPeAYKUjqVWpbMeEc3fLarziHN1ph0HQ937OI1m
         /EZs0bo8fHv2qnlwSwSP67t0QmtbsBdooEdZywF9WUI3urWeAWkSzIjL308h5o7cEqkQ
         E5CA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V5xDZMTO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701873940; x=1702478740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=giGoSZT+L93C6+Ipr0HwG1DhvKXWOuSo6gXx7XjzoBo=;
        b=NgwcsDDUuCXndYciDJpXpbXk8x5CDrgD0SZxVrRtvRP/OQgSScBcOE49kBycrYWpbM
         sELrU9hLCi5OIYLx+zk3Av9AFELv3oFLWtl3cvfV/2XvjUOu7fRAy5ebDBULUTU5l4t9
         4D3OpU8F4io7iYSgfR5iiEl9ahDehkshLSIZWEYRxKkZPmgo6bNERVWXotCOqtFIoM1U
         QEu5p2cJXMLsK9d24IHzRq5twFcR8f0S/lAEBHaWT/Kqr1sQSBkiL3W2KiqxznAxw+ZA
         LmfZ1Ts702RysCrANEObk3V5XDYcZW59L4teEMcbXIh2hnGrFUYhkLcAk0RHxWzRN6VS
         6lEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701873940; x=1702478740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=giGoSZT+L93C6+Ipr0HwG1DhvKXWOuSo6gXx7XjzoBo=;
        b=jgmH5Lun23gO33n1vusJS9Oz/BuT3EaM65MrKP3KhuxeNlxNTtRFZ0fBn/SvELboXN
         4SlhbgjGHWx4lyrycwrYG39L5BArQzQTovsEsOy1lsH0qPMqd5FPbiyhni8+4CQaQMS1
         zOcldkgdoKHpWQbNW3J3xBGUX0u8cAp3d5jPRceV04p46G/AkGxVyYXNJKi21P4T7vHP
         MHTr702W+Ixa0wJu9ZADxuQMbXMngBrs0qBJNnGUCnSpDtNz7G+RmddLlIgcZ2rxj3ja
         P4yrUXql6uAocwET2FoTWOzzBHMrM5dAFyTLPJMEjP+7Li6XJyCFHmHqxgQ9s8Qv9yL8
         ZdPQ==
X-Gm-Message-State: AOJu0YyqoA/F0jaUIYMWIygRfKkAZ5zxzDriFk3Jywa1kctJ/hlUdH8E
	j16frT5bsgisE63SG7RQJ2M=
X-Google-Smtp-Source: AGHT+IFYnF+wvMBoHRTqF6igHZiKoNFmrAVMWQn2W0rl3gciaz8njaWVPe4vmKCzGy7rraPE/H+Nsg==
X-Received: by 2002:a05:6808:609:b0:3b9:d5e6:2f7c with SMTP id y9-20020a056808060900b003b9d5e62f7cmr123117oih.49.1701873940015;
        Wed, 06 Dec 2023 06:45:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:1c88:b0:58d:be41:d25a with SMTP id
 ct8-20020a0568201c8800b0058dbe41d25als1639148oob.2.-pod-prod-00-us; Wed, 06
 Dec 2023 06:45:39 -0800 (PST)
X-Received: by 2002:a05:6830:125a:b0:6d8:74e2:5537 with SMTP id s26-20020a056830125a00b006d874e25537mr502746otp.35.1701873939165;
        Wed, 06 Dec 2023 06:45:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701873939; cv=none;
        d=google.com; s=arc-20160816;
        b=XYKdc4Y64WwhhY3gInPqna5XVeP4zvCdzPdZ8HC8eod+b68NcNNRLy9pDcAiSGZuck
         VtX9BAk1VJ4H6zXCm1Gugc/8nxQ5tfS3xtEN1AYJ5enfRxXorasTS1RqrYRPxhHqZCzD
         xQLMA7WhU1RAiWkvV3isiFKWCHQEOQca+a4HZNOX74+79HQgFUSMGeykaY9puCvLnDRJ
         nsxlMIS7kVsCCdB58Vy2NKw8AI5yR0NpCONORddqKHTmKa1SE3uPstCBUWbcxzqsQ+jB
         ADeQR21E6iiLQMRJLL3pL6CM5XYN7Zd7nX2fwWhr4zDULQsbBohX8ZOnkd/RdF+M1CaF
         LyOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RvuRYbFdpoGcm/YpWzxHjiZOvKmQglmv2U2Hz0xPJx8=;
        fh=go8Y/Z2zMKxw9GTvs/wrSRn4+U+QAqosGEOkKS4ggMI=;
        b=ttiRIoZ3nALmatIRd3ToNpXf4pI2NyqOO98aJ2RQ2eHkV9fyltnQjI1iNhJcdwJfRu
         Ibwxe99Ze81+w4Tji+5V+aVGTjHbefKp020AUpEL7rxi84QyBCKdPBEiVqOA5p/ne7YL
         YbxJNEJIag6vwPcyYrUaUFrwxsD8qBIIpsFPhXoFgwCnq7abIWDEa1lCtKmT6EEpRVQ3
         JGlXpNTU8qx1lfKypow8eJzq1VPqrvRcqIQJyAZRCqPxxxkKlyn9Zo7dkvtuVzh3406W
         z3ccLa0RJNu/yL2kRzzmmjeF5Edg16SW+2Ar8PxTDknCc7scu9HlryFHCZRcu9D9osvj
         gVMw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=V5xDZMTO;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92c.google.com (mail-ua1-x92c.google.com. [2607:f8b0:4864:20::92c])
        by gmr-mx.google.com with ESMTPS id x9-20020a9d6d89000000b006d9a1ce50b9si364741otp.1.2023.12.06.06.45.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 06 Dec 2023 06:45:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) client-ip=2607:f8b0:4864:20::92c;
Received: by mail-ua1-x92c.google.com with SMTP id a1e0cc1a2514c-7c5524f258aso582297241.1
        for <kasan-dev@googlegroups.com>; Wed, 06 Dec 2023 06:45:39 -0800 (PST)
X-Received: by 2002:a05:6102:1901:b0:464:9f88:8310 with SMTP id
 jk1-20020a056102190100b004649f888310mr511241vsb.10.1701873938446; Wed, 06 Dec
 2023 06:45:38 -0800 (PST)
MIME-Version: 1.0
References: <20231204-slub-cleanup-hooks-v1-0-88b65f7cd9d5@suse.cz>
 <20231204-slub-cleanup-hooks-v1-4-88b65f7cd9d5@suse.cz> <44421a37-4343-46d0-9e5c-17c2cd038cf2@linux.dev>
 <79e29576-12a2-a423-92f3-d8a7bcd2f0ce@suse.cz> <fdd11528-b0f8-48af-8141-15c4b1b01c65@linux.dev>
In-Reply-To: <fdd11528-b0f8-48af-8141-15c4b1b01c65@linux.dev>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 6 Dec 2023 15:44:59 +0100
Message-ID: <CANpmjNO1_LxE9w4m_Wa5xxc1R87LhnJSZ3DV59ia3-SdQUmtpw@mail.gmail.com>
Subject: Re: [PATCH 4/4] mm/slub: free KFENCE objects in slab_free_hook()
To: Chengming Zhou <chengming.zhou@linux.dev>, Andrey Konovalov <andreyknvl@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=V5xDZMTO;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as
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

On Wed, 6 Dec 2023 at 14:02, Chengming Zhou <chengming.zhou@linux.dev> wrote:
>
> On 2023/12/6 17:58, Vlastimil Babka wrote:
> > On 12/5/23 14:27, Chengming Zhou wrote:
> >> On 2023/12/5 03:34, Vlastimil Babka wrote:
> >>> When freeing an object that was allocated from KFENCE, we do that in the
> >>> slowpath __slab_free(), relying on the fact that KFENCE "slab" cannot be
> >>> the cpu slab, so the fastpath has to fallback to the slowpath.
> >>>
> >>> This optimization doesn't help much though, because is_kfence_address()
> >>> is checked earlier anyway during the free hook processing or detached
> >>> freelist building. Thus we can simplify the code by making the
> >>> slab_free_hook() free the KFENCE object immediately, similarly to KASAN
> >>> quarantine.
> >>>
> >>> In slab_free_hook() we can place kfence_free() above init processing, as
> >>> callers have been making sure to set init to false for KFENCE objects.
> >>> This simplifies slab_free(). This places it also above kasan_slab_free()
> >>> which is ok as that skips KFENCE objects anyway.
> >>>
> >>> While at it also determine the init value in slab_free_freelist_hook()
> >>> outside of the loop.
> >>>
> >>> This change will also make introducing per cpu array caches easier.
> >>>
> >>> Tested-by: Marco Elver <elver@google.com>
> >>> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >>> ---
> >>>  mm/slub.c | 22 ++++++++++------------
> >>>  1 file changed, 10 insertions(+), 12 deletions(-)
> >>>
> >>> diff --git a/mm/slub.c b/mm/slub.c
> >>> index ed2fa92e914c..e38c2b712f6c 100644
> >>> --- a/mm/slub.c
> >>> +++ b/mm/slub.c
> >>> @@ -2039,7 +2039,7 @@ static inline void memcg_slab_free_hook(struct kmem_cache *s, struct slab *slab,
> >>>   * production configuration these hooks all should produce no code at all.
> >>>   *
> >>>   * Returns true if freeing of the object can proceed, false if its reuse
> >>> - * was delayed by KASAN quarantine.
> >>> + * was delayed by KASAN quarantine, or it was returned to KFENCE.
> >>>   */
> >>>  static __always_inline
> >>>  bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
> >>> @@ -2057,6 +2057,9 @@ bool slab_free_hook(struct kmem_cache *s, void *x, bool init)
> >>>             __kcsan_check_access(x, s->object_size,
> >>>                                  KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
> >>>
> >>> +   if (kfence_free(kasan_reset_tag(x)))
> >>
> >> I'm wondering if "kasan_reset_tag()" is needed here?
> >
> > I think so, because AFAICS the is_kfence_address() check in kfence_free()
> > could be a false negative otherwise. In fact now I even question some of the
>
> Ok.
>
> > other is_kfence_address() checks in mm/slub.c, mainly
> > build_detached_freelist() which starts from pointers coming directly from
> > slab users. Insight from KASAN/KFENCE folks appreciated :)
> >
> I know very little about KASAN/KFENCE, looking forward to their insight. :)
>
> Just saw a check in __kasan_slab_alloc():
>
>         if (is_kfence_address(object))
>                 return (void *)object;
>
> So thought it seems that a kfence object would be skipped by KASAN.

The is_kfence_address() implementation tolerates tagged addresses,
i.e. if it receives a tagged non-kfence address, it will never return
true.

The KASAN_HW_TAGS patches and KFENCE patches were in development
concurrently, and at the time there was some conflict resolution that
happened when both were merged. The
is_kfence_address(kasan_reset_tag(..)) initially came from [1] but was
squashed into 2b8305260fb.

[1] https://lore.kernel.org/all/9dc196006921b191d25d10f6e611316db7da2efc.1611946152.git.andreyknvl@google.com/

Andrey, do you recall what issue you encountered that needed kasan_reset_tag()?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO1_LxE9w4m_Wa5xxc1R87LhnJSZ3DV59ia3-SdQUmtpw%40mail.gmail.com.
