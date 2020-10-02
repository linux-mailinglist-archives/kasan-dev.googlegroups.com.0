Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBBVC3X5QKGQEWWKTAXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id A5E20281785
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 18:10:46 +0200 (CEST)
Received: by mail-ed1-x53f.google.com with SMTP id c3sf815841eds.6
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 09:10:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601655046; cv=pass;
        d=google.com; s=arc-20160816;
        b=mJOFFa91VNaXSuX/cBf1b2h3/C2gL0MIFzftcJrrkpfwcQEaBZklxAmnPUVB8MYrS5
         wTQPLg6t3KfXS7ptOlH5dyoesEw7nbmO4XdmqStDp6XFXgvvZzxzU6drjvOWRIOG8Q0y
         j/jGFJ99UQWVyeVLKGifPIfDczzElLWyoVblgjGZFlBOvmLwVSR4Zp24/DNZrckhz+vE
         GT2s3InCxTHZ0J9jhytRDexKqwvybIinAlyF/V5//R4Dl1j4tTNYFVTk1SDosV8rvv0k
         uj3CJ+pdI8l6eH4rrgrw9QqaLdx+VwPWDL/69MOaKqfvp/oqoPddT46rW7HtePMkG8hL
         ULzg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=vhM7Z6sIPvtQ5KpHmRE39XD3+XenwTCWCu7x0aiQzFw=;
        b=oDeDtOLpD54cu4RroSLyk2Ln2EHAY93gYGwo+3ZoAPUw3uDhFuUmcdzWVEQaSpqfSz
         nn0nSLYaM7RvVEIEOfNm3X/S00OF8QOT8Gk8mD7JkiRnoRY022+Vo/sYivkZH6OCjXnz
         IG9GtMJ96HOYgi4wIGLjtKS9lrMZhZAU1UWYKM2+xZRHMOkTcMM/NzMmzBflv5sUsfMz
         uT+k7xjCuH1A/SyVeSqQFcvDo6lZVwEpbC5exbuWvtqz/dmTTZHMJrz9iruGAFuCVX9t
         KWu+TuusrPverf0ewsVhQdTNfVSNwJCQdy0D6TXxYfTb0RtALqMYEEEBw9HlPPxI7tag
         5AUg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IwPpPrdN;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vhM7Z6sIPvtQ5KpHmRE39XD3+XenwTCWCu7x0aiQzFw=;
        b=DtT2QIuX1ntbkp6SQ12iN6NFjce6NQo++HwrElZLv2MMZzipLzAhXcBzt9WpqynyPt
         MWryZbJgV/uclUpVXRe2YWpZoNlCs0IDPbiadEUs3uyO8pI1+R6K/YPUadLsTs6MO8yX
         0CmDKmrwF2WDgRMHpsBAIL3UAw+TWMTWyJnerdpCN331PTq1D/4DoMwhEFgP9foZ8m/Q
         oLdCLpp47sYBi+MAvKFImS53wU98wfyakydQt+gY1/jU4F0XD9KKmkH5blaYmyeuXOhv
         zHoEY9ZIt8hU8ZVcTq/abcDaJ2p1yUpd2aqcFHDaaJzo57qaoO+t1O+JyehkVXVvWCOS
         1hoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vhM7Z6sIPvtQ5KpHmRE39XD3+XenwTCWCu7x0aiQzFw=;
        b=rkvR552D62uElGVMgozK+uEUVtsr3EJMkMgo6P262aTTU/blYLmqMCvgbWmeBBqafm
         UulgV89iD9IEoGQH7uhRpb/dbdIfWDpbObdbIPUvc57JAsvc3gV0Dq/xJUwu1aKN8BLJ
         QJOZRQ2OZYShMlQpMJUmzXt460gI1a1l1ycA3ucjvPlf36VhJs5uWy+6jNT8xbPItOee
         t2UmwSoYQGadeOOLieu3W2bUwAjyW8ntcNaU79GI7/y+72rnDkAmJyvh75VS/Nei6W+g
         D32SqbAWGU91hK5DsAFc58khAQ6Gvu86M+SJ/lJ9gKXCcc4MqEogU0hMxM48mijPZlTr
         SMmA==
X-Gm-Message-State: AOAM531a2xt8Ddty6nCFTFWt4OgUHc24hchazAMwrA7RorwPkAKB4kY0
	9N+chb5dv4gktBiglm+WhvE=
X-Google-Smtp-Source: ABdhPJwFSCxWvGBpXFVsruwCNSiUKda32m/V9+rDDr+fDqO/11rLXbUmAkXVNkSu7DtqHcKohzeSpQ==
X-Received: by 2002:a17:906:131a:: with SMTP id w26mr3112861ejb.271.1601655046438;
        Fri, 02 Oct 2020 09:10:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:af96:: with SMTP id mj22ls980035ejb.5.gmail; Fri, 02
 Oct 2020 09:10:45 -0700 (PDT)
X-Received: by 2002:a17:906:7d0d:: with SMTP id u13mr3179143ejo.448.1601655045069;
        Fri, 02 Oct 2020 09:10:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601655045; cv=none;
        d=google.com; s=arc-20160816;
        b=KX2924XGtT2ROSxml/BBa11KD/ZYaZ1lpCkGBjo6l+8mEXMO1lJoOKTVOMqQ294DHg
         jhZ4JNPzz2nt7jKrT12JwwJT/M+cvsy1M/Ha4dXFiw37963PFfclrrJdMF3TvXucg66e
         ZuXtsT8dC9UlrSn0pIDyer+0XDEMGaAyM1sKbkkXKeC+hOozGzuOpyvHnELWZxyMUOME
         MghB/S9GJ1eDqSgIlod3TUI0VWtuzc31dn848LTCXf83NLZG1LjHvdaubz5xP2jlzq8I
         Zwd+7qJIry28gZkpYozTRm6nyDWvw7tkt8oVxcTJ5Cn80Ch1d/llfKKVaGECTMfpF3y3
         jh9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TKrnU8OMrTP2HnfeDQ36W4jlkOILiDTjG4Jt9zQv/MU=;
        b=0dRaMwtZ4U6YLKltjwe2qnAS5Xm4dLjsMIX2n3KXRkDWhG2xb3atJIZqiRnS9POF4j
         RxlOomFJ4uJUV0YVYaxVT/aizwfUbyEuCSNprM0yov84dLXdwhEcXFgNgufdXZVhr4Ee
         X31p+5o90J2D9Vk7XLUEKb6Ap+LecSY8Z4SaHC1+rggltb2zk1TaP2RPUEWsYpwiRLMA
         i2Lv1EgEVWSBHzzIOUyOXKtim6o/tY+FuRNftceDkdsL7+8Orpi24sib91ElASPkD6pr
         mhsS3chZ5sS8kTnVPdBu3pdNzRyrrjlJa3mNhvTS7vl8UEpSxTzAxhOP6gndIKT1HxUU
         AG4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=IwPpPrdN;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x543.google.com (mail-ed1-x543.google.com. [2a00:1450:4864:20::543])
        by gmr-mx.google.com with ESMTPS id dk15si73239edb.2.2020.10.02.09.10.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 09:10:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as permitted sender) client-ip=2a00:1450:4864:20::543;
Received: by mail-ed1-x543.google.com with SMTP id n22so2213512edt.4
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 09:10:45 -0700 (PDT)
X-Received: by 2002:a05:6402:b0e:: with SMTP id bm14mr3217947edb.259.1601655044643;
 Fri, 02 Oct 2020 09:10:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-4-elver@google.com>
 <CAG48ez1VNQo2HZSDDxUqtM4w63MmQsDc4SH0xLw92E6vXaPWrg@mail.gmail.com> <CANpmjNMcdM2MSL5J6ewChovxZbe-rKncU4LekQiXwKoVY0xDnQ@mail.gmail.com>
In-Reply-To: <CANpmjNMcdM2MSL5J6ewChovxZbe-rKncU4LekQiXwKoVY0xDnQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 18:10:18 +0200
Message-ID: <CAG48ez37Mi+4rRY7v3P9uTgV+35oTT+dpb4Xe=V_Nb=pdMosbA@mail.gmail.com>
Subject: Re: [PATCH v4 03/11] arm64, kfence: enable KFENCE for ARM64
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=IwPpPrdN;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::543 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Fri, Oct 2, 2020 at 4:19 PM Marco Elver <elver@google.com> wrote:
>
> On Fri, 2 Oct 2020 at 08:48, Jann Horn <jannh@google.com> wrote:
> >
> > On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > > Add architecture specific implementation details for KFENCE and enable
> > > KFENCE for the arm64 architecture. In particular, this implements the
> > > required interface in <asm/kfence.h>. Currently, the arm64 version does
> > > not yet use a statically allocated memory pool, at the cost of a pointer
> > > load for each is_kfence_address().
> > [...]
> > > diff --git a/arch/arm64/include/asm/kfence.h b/arch/arm64/include/asm/kfence.h
> > [...]
> > > +static inline bool arch_kfence_initialize_pool(void)
> > > +{
> > > +       const unsigned int num_pages = ilog2(roundup_pow_of_two(KFENCE_POOL_SIZE / PAGE_SIZE));
> > > +       struct page *pages = alloc_pages(GFP_KERNEL, num_pages);
> > > +
> > > +       if (!pages)
> > > +               return false;
> > > +
> > > +       __kfence_pool = page_address(pages);
> > > +       return true;
> > > +}
> >
> > If you're going to do "virt_to_page(meta->addr)->slab_cache = cache;"
> > on these pages in kfence_guarded_alloc(), and pass them into kfree(),
> > you'd better mark these pages as non-compound - something like
> > alloc_pages_exact() or split_page() may help. Otherwise, I think when
> > SLUB's kfree() does virt_to_head_page() right at the start, that will
> > return a pointer to the first page of the entire __kfence_pool, and
> > then when it loads page->slab_cache, it gets some random cache and
> > stuff blows up. Kinda surprising that you haven't run into that during
> > your testing, maybe I'm missing something...
>
> I added a WARN_ON() check in kfence_initialize_pool() to check if our
> pages are compound or not; they are not.
>
> In slub.c, __GFP_COMP is passed to alloc_pages(), which causes them to
> have a compound head I believe.

Aah, I mixed up high-order pages and compound pages. Sorry for the noise.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez37Mi%2B4rRY7v3P9uTgV%2B35oTT%2Bdpb4Xe%3DV_Nb%3DpdMosbA%40mail.gmail.com.
