Return-Path: <kasan-dev+bncBC7OD3FKWUERBLNA7CXAMGQEMPV44UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C05869C60
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 17:39:11 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-5a04adc9c3fsf4750297eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Feb 2024 08:39:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709051950; cv=pass;
        d=google.com; s=arc-20160816;
        b=R74RGL6tXHEn+ZErBFhu1J3QbAjtluhxgDa76+LTt01qxQH7BtsyKVumi38aZj66cd
         pXKhGdgunjPhIsDNI/YM1HbaLIPL1CKmceYUYRBkaKNNJPeozQVPgJSwdknGgq7IQ8TV
         N/We7y/Tz/wVc3ozJgko9g+6Bn82svzkhh+cebenMyKHrI/vuFGKf8i2vV2wAVPpzn1q
         lGMFSKljJVEwpC5N8KS79CPL8QGsZP1u4lOlGKomFvsquTKgZAIYRoWPng1AmlkT9mbt
         WPklDHEfwQ9glat661MF99+3FMfJ9cLjNkV6R1PhKHImzWaucxzqpN8AhWZgNzf7ZEzm
         5+CA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eq8s0im0IKdZ1URUijsw/Q09oE6/3x15+EXD6Do+oZE=;
        fh=s9gr0V1SiHye03v8HKFkDP5pVxh2a+hCXZdiaDjakyk=;
        b=Vi1IZiqrddkE5vwSUx+z+Ldrqy/Fn4aye4gnEQ88bgamg4WwwsVwYXKI2RAWl+GQoS
         w2sCJZNwjcKK4VfKGkCUrJqMMMBDy0c1RYGrsRnrJ2rh8Ez6jCg18EJcg2C0bHclkRUf
         LUoHR5Uenv028GkFoniQjUoLwSRmCurIGN97T9XroHLaneFkN7dCTTLqkb1ujocl7YkN
         tQ1JWgiHSvW1R9SRQmTpN8ojktvoE3zH7j6ABtJgk68mFgiCGLguDLCtpht2ZBtuKxdE
         xbThpu0R/zK0mNgjnEnG0JD7QOHewN92r5TQ7LFjXXUBOKojHZpFy7+XqYtPyovubNsO
         o23g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WsMbTJhw;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709051950; x=1709656750; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eq8s0im0IKdZ1URUijsw/Q09oE6/3x15+EXD6Do+oZE=;
        b=QbirPU2EXM/LffC/xGIabxY8LcjVnI1AFVthmuZF06zAN1fTNK/dX26LGpI6XTWgt4
         XTfbQ8uGARhvVUG7F06ESbVGaz1DtxeWZkOEWFKYRKbQyXz76GafQ+2mJL/ENzIgG+hC
         mrK51XzXpPo1jMlmJHvEJmTtVeTNkuuL6t915TZcgkyjnfUAUOU+6n4sDlHQUSU8HN1g
         Bu6C2D/BwxoNTy/2iezE+ClIMOoxT2gm7zBmiI1Aa5IIH40fy+FwDHF0jSnTjhb0nBpy
         8b427yC7ommkqgP4tzREz4pSVAwSaBXXEieOdF5IlRVzIQfeJJMp1+h4Hml6C3n9lN3m
         b0CQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709051950; x=1709656750;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eq8s0im0IKdZ1URUijsw/Q09oE6/3x15+EXD6Do+oZE=;
        b=J1tIG0RnYXbWeJAZHPf7r+Ezi+DpYPfQ3bjcKVNvqtPnC9T1EvMklm9KfkXZYy8xP+
         Bkok1NAR/rtvJLOIsj01ivGREU7XJ8gqvYGX0t3/Se+4mU+rV+GpBhrUWP5aZ4Fz8VOi
         2Dvpm75wt3GY6NkItK+zK1bHBlH5KuQHTnhF4RT5DN1Z/rhfA7y45YFjY3Ft94/8uv/+
         UcYRCFpzsYDmfRCg51AKEADDSdE/MX485KZTNLAidBjBU4PMZ/vk1gWFl3wFtTfQCjus
         s9hHeSKjVxgvoIvUEfoVArE5lTsaIqEpLjKFO6GhEfc18brTs3x0rFZVe99bCsLYr6WC
         BKsw==
X-Forwarded-Encrypted: i=2; AJvYcCVYISSgR71fcIqlBRv6u3PVZajsMWRs5sbpa7OvrfJGuioHdpUxAdGMonwD/NiG7xugPNfSNNpQKx0WQ/I9kCa2F+LMbnXf0A==
X-Gm-Message-State: AOJu0Yx9m4C7+re6842pcFRp6pOwl6dg6+uG7HlZst96JV0mm5sjeINe
	lhJTgvrIq77ByufHULHJUToL/5OEh650SZgZxNVrJFSFTJbQrt7F
X-Google-Smtp-Source: AGHT+IEO8HeOtJYVtio9aebYNydxjSAUDslZZdckUAzVGIpUr4WB/rum8G7TQfgSV38mNmnroBiNjQ==
X-Received: by 2002:a4a:4481:0:b0:5a0:7cf6:3704 with SMTP id o123-20020a4a4481000000b005a07cf63704mr6029669ooa.5.1709051949841;
        Tue, 27 Feb 2024 08:39:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4b04:0:b0:59a:73f9:7f01 with SMTP id q4-20020a4a4b04000000b0059a73f97f01ls2687557ooa.1.-pod-prod-05-us;
 Tue, 27 Feb 2024 08:39:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXIexia0+SFrQhkLMdG3J9x4FUxxbOiMs+BoTvZDD+snO3yqW7TFhLQilrBx1JVOQ4TP5TWDBTTz1eY8ejCzKBpgZTpjM5kcMFBng==
X-Received: by 2002:a4a:3412:0:b0:5a0:a659:8b7e with SMTP id b18-20020a4a3412000000b005a0a6598b7emr3799210ooa.9.1709051949030;
        Tue, 27 Feb 2024 08:39:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709051949; cv=none;
        d=google.com; s=arc-20160816;
        b=fRtUZl+bemqAF0yilLUGATCX3+QPsA8i/Ryd9+ymhp1fyJ3EAda2gJdNuBUYKAIn4/
         zDs4iY/JbjYiDydPtuqgMOBiriEkdZGpMDlC4PlOXj4J3iaWDTvA/pTWsXm4ppaFlUnH
         sJjVbTsSd1uEJd2zAFoV1gN15A9XbKXEWMq/ipSFO2pGkxLd4KhsmNYq4pVdt5QRXTda
         oGj1KekBlGXJmVrDCJ/CEjzDTpeVSssXBjVNNEzg+zEq4GJlQljq0/mOB4wBZ9q+wk1r
         bDnMOpCkBZslqGNJUDMRchVUXrIM45BK3SlXVhs8AD0bC6DXKHr+DBh0ZzbA8todys9W
         sUIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z/ds6xBAyNMUyUudVMgCcZQOOdZHJrbf6LFZuMELU1U=;
        fh=egQLaVcG0QQEN2iezqDJHfsGxDjs4B6Tb8mfSZ8Lkj4=;
        b=EdOy7y6e2h5BTuvX7Znk2jsTscPIrX5tKkcoMXq+ZudHlp9NlxJGEdkPAnHs5kRAey
         cp9neqkK4c/5xWJROJ8Ia/ZEqriGz1lwdouStsLdS/+7zN/70mVPfPru8Jqga1kxpekd
         bKt/MOx3Xnd1kUPQooW7c4fGwLfWO1yfIOy9IwBkvefpPbRukGqqL8VDGLrpy3INwWyJ
         vsbqkYZK2TXXbGK5BEr7KSI+ppExPHRVqZVoa9gKkdkTnDf++hzcgaiNHHh0kWZ3ZNdD
         gyMoUGuTOHij0Vv8QgbgoUBXHWsp6jJJNPMTfPHHU2Xsvk8/RdeaykZhxQY+ZCNxHIG2
         lJRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WsMbTJhw;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1135.google.com (mail-yw1-x1135.google.com. [2607:f8b0:4864:20::1135])
        by gmr-mx.google.com with ESMTPS id n16-20020a056820055000b005a03384a96fsi314076ooj.0.2024.02.27.08.39.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Feb 2024 08:39:09 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135 as permitted sender) client-ip=2607:f8b0:4864:20::1135;
Received: by mail-yw1-x1135.google.com with SMTP id 00721157ae682-6089b64f4eeso44753377b3.2
        for <kasan-dev@googlegroups.com>; Tue, 27 Feb 2024 08:39:08 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWZc3R3rG7Bmi9D9YvQCZ4UfAMOf3G1rPGULUwJ6WbbHZ2rtcawhtqtWmEvKZ7/5hb1HPwmn8YjPW7b8E6FINq1rPvpRv74oD2+PA==
X-Received: by 2002:a0d:cc52:0:b0:609:2c38:4dd2 with SMTP id
 o79-20020a0dcc52000000b006092c384dd2mr1712145ywd.42.1709051948102; Tue, 27
 Feb 2024 08:39:08 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-20-surenb@google.com>
 <2daf5f5a-401a-4ef7-8193-6dca4c064ea0@suse.cz>
In-Reply-To: <2daf5f5a-401a-4ef7-8193-6dca4c064ea0@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Feb 2024 08:38:54 -0800
Message-ID: <CAJuCfpGt+zfFzfLSXEjeTo79gw2Be-UWBcJq=eL1qAnPf9PaiA@mail.gmail.com>
Subject: Re: [PATCH v4 19/36] mm: create new codetag references during page splitting
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WsMbTJhw;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1135
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Tue, Feb 27, 2024 at 2:10=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/21/24 20:40, Suren Baghdasaryan wrote:
> > When a high-order page is split into smaller ones, each newly split
> > page should get its codetag. The original codetag is reused for these
> > pages but it's recorded as 0-byte allocation because original codetag
> > already accounts for the original high-order allocated page.
>
> This was v3 but then you refactored (for the better) so the commit log
> could reflect it?

Yes, technically mechnism didn't change but I should word it better.
Smth like this:

When a high-order page is split into smaller ones, each newly split
page should get its codetag. After the split each split page will be
referencing the original codetag. The codetag's "bytes" counter
remains the same because the amount of allocated memory has not
changed, however the "calls" counter gets increased to keep the
counter correct when these individual pages get freed.

>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
> I was going to R-b, but now I recalled the trickiness of
> __free_pages() for non-compound pages if it loses the race to a
> speculative reference. Will the codetag handling work fine there?

I think so. Each non-compoud page has its individual reference to its
codetag and will decrement it whenever the page is freed. IIUC the
logic in  __free_pages(), when it loses race to a speculative
reference it will free all pages except for the first one and the
first one will be freed when the last put_page() happens. If prior to
this all these pages were split from one page then all of them will
have their own reference which points to the same codetag. Every time
one of these pages are freed that codetag's "bytes" and "calls"
counters will be decremented. I think accounting will work correctly
irrespective of where these pages are freed, in __free_pages() or by
put_page().

>
> > ---
> >  include/linux/pgalloc_tag.h | 30 ++++++++++++++++++++++++++++++
> >  mm/huge_memory.c            |  2 ++
> >  mm/page_alloc.c             |  2 ++
> >  3 files changed, 34 insertions(+)
> >
> > diff --git a/include/linux/pgalloc_tag.h b/include/linux/pgalloc_tag.h
> > index b49ab955300f..9e6ad8e0e4aa 100644
> > --- a/include/linux/pgalloc_tag.h
> > +++ b/include/linux/pgalloc_tag.h
> > @@ -67,11 +67,41 @@ static inline void pgalloc_tag_sub(struct page *pag=
e, unsigned int order)
> >       }
> >  }
> >
> > +static inline void pgalloc_tag_split(struct page *page, unsigned int n=
r)
> > +{
> > +     int i;
> > +     struct page_ext *page_ext;
> > +     union codetag_ref *ref;
> > +     struct alloc_tag *tag;
> > +
> > +     if (!mem_alloc_profiling_enabled())
> > +             return;
> > +
> > +     page_ext =3D page_ext_get(page);
> > +     if (unlikely(!page_ext))
> > +             return;
> > +
> > +     ref =3D codetag_ref_from_page_ext(page_ext);
> > +     if (!ref->ct)
> > +             goto out;
> > +
> > +     tag =3D ct_to_alloc_tag(ref->ct);
> > +     page_ext =3D page_ext_next(page_ext);
> > +     for (i =3D 1; i < nr; i++) {
> > +             /* Set new reference to point to the original tag */
> > +             alloc_tag_ref_set(codetag_ref_from_page_ext(page_ext), ta=
g);
> > +             page_ext =3D page_ext_next(page_ext);
> > +     }
> > +out:
> > +     page_ext_put(page_ext);
> > +}
> > +
> >  #else /* CONFIG_MEM_ALLOC_PROFILING */
> >
> >  static inline void pgalloc_tag_add(struct page *page, struct task_stru=
ct *task,
> >                                  unsigned int order) {}
> >  static inline void pgalloc_tag_sub(struct page *page, unsigned int ord=
er) {}
> > +static inline void pgalloc_tag_split(struct page *page, unsigned int n=
r) {}
> >
> >  #endif /* CONFIG_MEM_ALLOC_PROFILING */
> >
> > diff --git a/mm/huge_memory.c b/mm/huge_memory.c
> > index 94c958f7ebb5..86daae671319 100644
> > --- a/mm/huge_memory.c
> > +++ b/mm/huge_memory.c
> > @@ -38,6 +38,7 @@
> >  #include <linux/sched/sysctl.h>
> >  #include <linux/memory-tiers.h>
> >  #include <linux/compat.h>
> > +#include <linux/pgalloc_tag.h>
> >
> >  #include <asm/tlb.h>
> >  #include <asm/pgalloc.h>
> > @@ -2899,6 +2900,7 @@ static void __split_huge_page(struct page *page, =
struct list_head *list,
> >       /* Caller disabled irqs, so they are still disabled here */
> >
> >       split_page_owner(head, nr);
> > +     pgalloc_tag_split(head, nr);
> >
> >       /* See comment in __split_huge_page_tail() */
> >       if (PageAnon(head)) {
> > diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> > index 58c0e8b948a4..4bc5b4720fee 100644
> > --- a/mm/page_alloc.c
> > +++ b/mm/page_alloc.c
> > @@ -2621,6 +2621,7 @@ void split_page(struct page *page, unsigned int o=
rder)
> >       for (i =3D 1; i < (1 << order); i++)
> >               set_page_refcounted(page + i);
> >       split_page_owner(page, 1 << order);
> > +     pgalloc_tag_split(page, 1 << order);
> >       split_page_memcg(page, 1 << order);
> >  }
> >  EXPORT_SYMBOL_GPL(split_page);
> > @@ -4806,6 +4807,7 @@ static void *make_alloc_exact(unsigned long addr,=
 unsigned int order,
> >               struct page *last =3D page + nr;
> >
> >               split_page_owner(page, 1 << order);
> > +             pgalloc_tag_split(page, 1 << order);
> >               split_page_memcg(page, 1 << order);
> >               while (page < --last)
> >                       set_page_refcounted(last);

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGt%2BzfFzfLSXEjeTo79gw2Be-UWBcJq%3DeL1qAnPf9PaiA%40mail.gm=
ail.com.
