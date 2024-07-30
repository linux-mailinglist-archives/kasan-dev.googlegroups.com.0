Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB4MBUO2QMGQEPIX7URQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id C1EF7940F5B
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 12:31:14 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-5a7493ad70fsf3313612a12.2
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 03:31:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722335474; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kr/uY9mO1KfQgFLjXmNy8FqU3QCs0UGVN9eFsKicIkfB9jt2/WIBKGCsKLPdXZ5X2n
         lAI9PlRTUazAxi508chdSe38cKipyzJrag8ddesEeplFh4mK7xXbHGlFQ7fvmLycJHfq
         ll0+ucRflTyXY+2X85kLfwpDzQglulJGvdmuq+Z1K0ZDCK5v555tnYhtFtBxwhIq0TH0
         Pckv3UQPj7F7vQ88JGpG8R/X/RlvxU4ggTs3pwMdtVhRM0t7gtuuwK0crfGKKCXeSyaW
         7VbJdVpR3C0BiEKqHadtrPaWo3N3eC7I+MArWZM/rWIuCj3raBR2iJIbXe0e5dfH9A//
         dRfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AW/gAdUpHbQgjzFap8LTo1uxFsfWSH2O4J4saTVNPwo=;
        fh=UKvOUoEqQvgKDLSCLBuMwwfb3NcIc+QhZIxgLOrUGPk=;
        b=VwX8MTtry9bIf2M+Rfdm+/xYASlxW4OWjkkyLbcgbCHh7VePMJPe/nXCAevsIoYBOV
         11mE8NvIkXkXDBMmYORaSTJvOwx9iZdmp/X6ODkeaZt+tuZFa1p6MrzQ/BKLlJ6yFBT1
         dfPhXX3l6b3W4aqHC12p5BbSYW/TRYkk+fLcjv/s6HTSA57RifUjYH70efUcL8G8voq0
         eqVuP0+o7eYBDgteM04MEZTHzxlzU3fYQ1GSbZbIVOcGOdNXugpzOcHVzZX5TYVc912a
         pAD8Q0ikizv8GjjYz4FUu34mMSh1WhsUrajXywJ1wSISLFdMmk8oopS462ba+dvPEH+X
         XI8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UzAdAFox;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722335474; x=1722940274; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AW/gAdUpHbQgjzFap8LTo1uxFsfWSH2O4J4saTVNPwo=;
        b=s8CM1xytjHMPfgS7iglLKTS29aSlAAV+ZiFbgv2Fo9RDhEwXYkAp9AHaP+5G3nFaue
         uuHRAD2TRCjMPtyURcFaqC/rVsvJpNYQqEnFoe27Jj083JPL3BYWi7WEI8TsO0ByIk2B
         vgsWmtX1lDFz9IfrWQjfv1l0BTzcgeqvoJM0y6mDRiIdBHN5QOEThnz1VJpjTs3n55CG
         Mt0+VG+PjTteNk/5LpHWjgRfv/gGs+YFeDET2YKnxHdLQt15/TAloNkEi0d7TUetDLCu
         Ebrr+PvjpTqQyHfh6ZInDPR6l6+BNRSN2XLZkEeet5SBHC40JPKUnLdG09X8iMN2xGYY
         HAYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722335474; x=1722940274;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AW/gAdUpHbQgjzFap8LTo1uxFsfWSH2O4J4saTVNPwo=;
        b=izyNZzsxHzWxf1kQh5PNNAPO1P1AE+kuy1f1j1xaoFvmlXHxCQ+THrDgJE7YMiAqma
         txQAebXQdUqmgnzQ4zu24Ew8TbzoLxHjl3/DB05xQ855cf2+oM3hFyszz7UAl2AtpN09
         u2jH4IwMthCeEGkPXOtAqrQAjdhFx1NnTTB6K9pJF2arkXNWhYIMmTE2ru0Z0T5byR51
         F/hda+pJ6udRhX9HfBej5izG9CuOGjhIWaKOe1x5acK+pZ6/uYrcyzFBReAt7bEyQJWK
         i0GoiV9yBvRELHgXt7JXUxm72D61AT74zZ6lb/XYSRIhtvf/vcZdXDFN4DfxVb+uTF1f
         zXfg==
X-Forwarded-Encrypted: i=2; AJvYcCVFm4y8Mq8TYG5yMUZ3X9oVaZeqCvRwJ+YdfDI7Fku4KFUP8g+BdDw5VT080tQOh2OMsT8iCzWSmpOo5/gG/bZBOFDjLhduYA==
X-Gm-Message-State: AOJu0YwcKfDBTbbBrAYaMZBV/08P5m9scG8UWCoNtuS0kyYPEoiGZRUJ
	N+cSdmbSqCRA+x6gSt+1MrL3dIZ2g7OAXX4QGzt3ByyRNdWOWyyj
X-Google-Smtp-Source: AGHT+IH0eoRKdY+XUh8J4vNhPdf8YYb5P894dz09NumKob+BwXQlP1Z3bEHlxMflPfN2tiPu0yF9rA==
X-Received: by 2002:a50:c057:0:b0:5a2:594b:be56 with SMTP id 4fb4d7f45d1cf-5b020ba829dmr7174011a12.12.1722335473744;
        Tue, 30 Jul 2024 03:31:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4015:b0:599:9c73:c397 with SMTP id
 4fb4d7f45d1cf-5ac0d2d997els2739850a12.2.-pod-prod-09-eu; Tue, 30 Jul 2024
 03:31:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWXAvMvQ6/CAYaFZ3xF5pUerCJ+lggnmNUl8IquIBZsng+mDzTLWSR1vLoVNuF7Bebrn19beG3HQ587wHLJEIkFWlQZHsuee46k2w==
X-Received: by 2002:a50:9f83:0:b0:5a1:21df:752d with SMTP id 4fb4d7f45d1cf-5b020ba822cmr6538441a12.10.1722335471802;
        Tue, 30 Jul 2024 03:31:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722335471; cv=none;
        d=google.com; s=arc-20160816;
        b=trfvP4+yGZ6mkAvwDqzWTtz2wESAtF6GfRfmmT6uyD9l7ON2e/pXb4F9XTd8Oq1q+x
         0jEND6SEgdoHscpi4wzdPFHBjHwl45jwqSAxSyHRVoXcMO8cvLMwtEcf/MOskoojGUjP
         c8Tl7WZmHyKPcwSX8mLhne1LJ0Ks+1DfFO/prrYDvcatXzOrEmH9zGrWICALACjmwGNt
         ksoSA/bCfUcMWi4BOTKIx3P3vehPsWFg1N2t1ie95inydDWcFH5HQ1/JiVwDpvJ48Ba4
         zRC7mrVJoeh3JcOkkwJVjzujP5ubFapCYB1xQpcWfrfP50jgzQgMTOEAC/qdpqqY1sN3
         UJSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+0SgFk0UCcjyFQ1ag4543DDdAqZ4f+PJCAgSBXmnExE=;
        fh=bPHattUGQyVJWuRU2tIrzlK0jy+QdP+5mavsONXEn2c=;
        b=0j6P72/EUdJyOzYS4MxAxy+VGig7EfWy8vYM+bo5nB5XjzcE7Lkygzm7kshISE7MkK
         C+EfvImND5eBIbN7W1evhPtScnWmtsgWf9ruIGX/6YnzToYrLH2XmNup68Qq9smP8L9b
         c7+3iahjnEcY5kgN9I9eB4AZr/ce04cPZFYozV/QQI9bPxemwxgvFL/BhOsAuKSNjbun
         YUCuSaKkxe5DRyseliGjtlFo0w0ySpUo8q8kMWAIoRssKnD9CRNxWsIDTj2hpZO+zbka
         hx4zAbRvFWEMiL0M6Sfftsg6UWpYbZPYq5Fcnsw6uC8K2s3+S7+zGzn3ka5/aHYv5Mkx
         vdzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UzAdAFox;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5b4961b3d15si25788a12.0.2024.07.30.03.31.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 30 Jul 2024 03:31:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-5a1b073d7cdso12549a12.0
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2024 03:31:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWqIZ0yQhR+FGJSIlOLKGYHE0KHNkhad5v5Vo6Fx+woVnu8c0ZVtYLdR6+a20a5GEeuF0qTcUt23bgSCR6/UeoXgyYo1wkE+M0HVw==
X-Received: by 2002:a05:6402:35c3:b0:5a0:d4ce:59a6 with SMTP id
 4fb4d7f45d1cf-5b45f835dbbmr100114a12.2.1722335470822; Tue, 30 Jul 2024
 03:31:10 -0700 (PDT)
MIME-Version: 1.0
References: <20240725-kasan-tsbrcu-v3-0-51c92f8f1101@google.com>
 <20240725-kasan-tsbrcu-v3-1-51c92f8f1101@google.com> <CA+fCnZe-x+JOUN1P-H-i0_3ys+XgpZBKU_zi06XBRfmN+OzO+w@mail.gmail.com>
 <CAG48ez0hAN-bJtQtbTiNa15qkHQ+67hy95Aybgw24LyNWbuU0g@mail.gmail.com> <CA+fCnZckG1Ww9wNcXRuCwdovK5oW3dq98Uq4up-WYOmddA9icA@mail.gmail.com>
In-Reply-To: <CA+fCnZckG1Ww9wNcXRuCwdovK5oW3dq98Uq4up-WYOmddA9icA@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 30 Jul 2024 12:30:34 +0200
Message-ID: <CAG48ez17_Etm_-AMaJHENq=QjtCRqNcCe9VUDvNw8En49wKybg@mail.gmail.com>
Subject: Re: [PATCH v3 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>, 
	Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UzAdAFox;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::532 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Sat, Jul 27, 2024 at 2:47=E2=80=AFAM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
> On Fri, Jul 26, 2024 at 3:52=E2=80=AFPM Jann Horn <jannh@google.com> wrot=
e:
> >
> > > Do we still need this patch?
> >
> > I just tried removing this patch from the series; without it, the
> > kmem_cache_invalid_free kunit test fails because the kmem_cache_free()
> > no longer synchronously notices that the pointer is misaligned. I
> > guess I could change the testcase like this to make the tests pass
> > without this patch, but I'd like to hear from you or another KASAN
> > person whether you think that's a reasonable change:
>
> Ah, I see. I think detecting a bug earlier if we can is better. So I
> don't mind keeping this patch, was just confused by the commit
> message.

ack, changed it in v4

> Adding on top of my comments from before: I think if you move
> check_slab_free() out of poison_slab_object() (but add to
> __kasan_mempool_poison_object()), and move is_kfence_address() and
> kasan_arch_is_ready() to poison_slab_object()'s callers, you won't
> even need the free_validation_result enum, so the patch should become
> simpler.

right, makes sense, changed in v4

> You can also rename check_slab_free() to check_slab_allocation() to
> make it be named similarly to the already existing
> check_page_allocation().

done in v4

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez17_Etm_-AMaJHENq%3DQjtCRqNcCe9VUDvNw8En49wKybg%40mail.gmai=
l.com.
