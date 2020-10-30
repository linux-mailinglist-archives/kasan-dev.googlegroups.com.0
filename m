Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVHL6D6AKGQEMWZU3RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E1C42A0A39
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 16:48:37 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id t10sf5190619pfh.19
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 08:48:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604072916; cv=pass;
        d=google.com; s=arc-20160816;
        b=C2C5yuVTUVt6dKU0GuhV6ZR03MPqY4sX/iu8w9hJzpz4DGpgwcMi73nuH/O2jGWMRb
         7j2JabQzpNP3Cop9h2WXBhVznJeshvhUxqgd84OOkdpOtlRsTFMOwMD2hfYGuNIOaujz
         5vhw3FqQ/alJffDULpVu0vlTWiBPyoIVkS7Xot2T6XwOKB9FwyyOjfcsr81RN5zKhYUB
         PLFx4dmRdFkDsNEGrIXJ2XMmAFjmptjcCK3Q057zLbPG3q37xANr10Ohw8IcWWWOEvVZ
         sCKiikQrUctCHXchHz4xEiYIKaMafY9nKH80Iq0riEMqwEHpzxcgx3Evq5DX0tVD9UTO
         qOMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VL/iC0vxTwZzvURW9oNofE9i6xzSnpQwQP1kiDZ7FJg=;
        b=fh1ww32LZAgKpttDPZDSTudmL2nDL6/8mMOFLb1sirLvb3ixjKl3G/zpUQcuk/cgiu
         GzDjMti1+30L8kY3GrjYgVMLCWNKCJjzwW+elldy7Ao38GASCyFmqJouHxs+8zWvKXk2
         bLT2KENZ7fKsA8cjmx5eWIA0qFo2EQdL++4zVvKyuWIJtWLkS6lAuoNVr2hUsmIdC/BG
         6Fvd+0vv02tlGto9HXeVy5Oq7Q1CYNBoqI03da09HxjmJ6FV8IdxgaDt0Gt/fqyuAST8
         p1wsLzPNPc/lh2Azhz9EYgX2YGQ7BiJOluLlgPuBFSVEuMVDn0rkhiEyJI1GzTMrFQ14
         tmjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n8Ybetdb;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VL/iC0vxTwZzvURW9oNofE9i6xzSnpQwQP1kiDZ7FJg=;
        b=MYmL4cgI/fMj/wH8IZxTFDwPfDEbeuPbWp/QOCtKylsZ2OMJ5AY1X4dafDyuskkmWS
         jZEve4Ugj5iIxtlC1g1UpJDuBCsC2tQCuB9bQiP1ARwJMmNX3ihFCzKzWrbpI+N5nx6B
         P2R1nor3bJsYzXvBg7ar4k/e46A/K9W/Xvt5qoWUW8qZ7GH3hp7O3Gbf1RNmWUAQKbkx
         /Z+C4gUVcbA6qOEdvm7hm+Ln6q5jfODIH25iloniD9kqWljsxDqzy7TuMrcElWSLb2MT
         ed9hPUSvoP5Cr3BZMP+sA8jff1zVDWyhzyKBZDCwi0pa9AQoRZuZVbc6WtZ/t6Ov6mAs
         fgVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VL/iC0vxTwZzvURW9oNofE9i6xzSnpQwQP1kiDZ7FJg=;
        b=eTsURsMGk/vssHKmY3y8mIZVH+Qbw1BhSfZAID2+0ZVCYAuDCUtMGKdPYqw2Vxu/9O
         SYhPHFbScpfYQnQWNwUQL7g3LIo3kmRWk3nwUCr4JUhMRN89y+63a6w3mZQwM6y3sSHA
         4Nhyfy1JhrfoTwkK8V28WraHT7pehE70Hdu0Ru9rtxgotWC52O3EIpwdDz/ODrveWmbP
         JcXoOh1A7lZUlmue0iEC/KuwYVliA6xiJyirzGO2UlXMzFib/rhoRUXI0sXPeEX+Pl0T
         6CWUITtarkX5zEaqSqnFWWCsM4AFEbcsL5TP+DbrXSKWyveb7v5NVWhmx1a2m3o7zC/3
         y8VQ==
X-Gm-Message-State: AOAM533Yv3tVi/okjaaFClpTsFCVRuBfieZig5L/F1ZC+GQ/5+kNBEQE
	Kp6auZG4N2cJt5Yl4+ttCTc=
X-Google-Smtp-Source: ABdhPJxjW2AUPLA9qp/Wab2/9tfdP+i3OexCP/XK3aOu9bJmJP/bQXF+x7XSXSjjUsJ8BuUnGVxHFQ==
X-Received: by 2002:a17:902:bcc1:b029:d3:9bdf:32e3 with SMTP id o1-20020a170902bcc1b02900d39bdf32e3mr9366724pls.1.1604072916310;
        Fri, 30 Oct 2020 08:48:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f13:: with SMTP id a19ls2443103pfd.9.gmail; Fri, 30 Oct
 2020 08:48:35 -0700 (PDT)
X-Received: by 2002:a63:5323:: with SMTP id h35mr2816994pgb.325.1604072915807;
        Fri, 30 Oct 2020 08:48:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604072915; cv=none;
        d=google.com; s=arc-20160816;
        b=wne5HW5z84tcXKHImppqoh1Hrfj/fWepM18vyfqQ34J3Tvkgy1vs+SbsQ3GDBaEnAY
         g/B5kQcE7Fatp2oyNOrHHhHjTuU/dyI5Y132uVFrH4zR52AGBksFv+zMnq3FxrOD6Bnz
         CDFI4CJC7R2CnJLxFNq41/kGtL+iFBn7mO3EJbwk5mjpA+HqWtyp9LlWF/M35/HUjZHo
         wJbCST710LPvvZ7fCOx8kEUgO4uWSBxPHRDdmFxFN4thnUR9PI1EATgboI9wwwo2o0cv
         KVAExlQ8Fihnyt/4O9L8NMQuNccRXnDeBVxtZHyfMwQ4defo1WhjNyzspQvtKOkQzo+G
         TIlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2vQT2iQtNVbEevXMap0BKv0WHD5DBzsJ42aVxPlssZQ=;
        b=aCN/5J312Q83FquNL4ay0o75KPkDUMGssZyPjDbUdZSzpZUMXMN6+ZN4rmialHj5KR
         +4BknNfOtlklmhN42ofRVq95hJD+ZuamvZd13VHQLpM9Mg4BOJcTDtNW74qMIxdUlwCG
         CoM7KiR+Z7fomyPQgsmKShd+Fs+GVyCITdYMSFeDydXXn3RZ+tvsKwN+zlNHlLvTENCa
         9CkgSTtjEeXd0CU31q/rhd9ho4+rFWwMkywD0p0crK10dAs+FSpRzylYG3/vvFa46xR6
         6KPoDpZTg+fiCkh6ghouyL1K/zZRX3wb6XqT4KyFJkyJfdjQ3r2oMr1omwln4KP24K1q
         7H6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=n8Ybetdb;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id v8si483654pgj.1.2020.10.30.08.48.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 30 Oct 2020 08:48:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id h6so5550547pgk.4
        for <kasan-dev@googlegroups.com>; Fri, 30 Oct 2020 08:48:35 -0700 (PDT)
X-Received: by 2002:a63:1906:: with SMTP id z6mr2767197pgl.286.1604072915294;
 Fri, 30 Oct 2020 08:48:35 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <56b19be34ee958103481bdfc501978556a168b42.1603372719.git.andreyknvl@google.com>
 <CACT4Y+ZVjEQaQExenOPg-tXQKRE5wUEm_iDn5DUQH_4QC-DBzg@mail.gmail.com>
In-Reply-To: <CACT4Y+ZVjEQaQExenOPg-tXQKRE5wUEm_iDn5DUQH_4QC-DBzg@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 16:48:23 +0100
Message-ID: <CAAeHK+x+5EcgiS8wZ9mbh-a32w4_CVOdrzw8yrtpPuquaJrPQA@mail.gmail.com>
Subject: Re: [PATCH RFC v2 10/21] kasan: inline random_tag for HW_TAGS
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=n8Ybetdb;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Oct 28, 2020 at 12:08 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Using random_tag() currently results in a function call. Move its
> > definition to mm/kasan/kasan.h and turn it into a static inline function
> > for hardware tag-based mode to avoid uneeded function call.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/Iac5b2faf9a912900e16cca6834d621f5d4abf427
> > ---
> >  mm/kasan/hw_tags.c |  5 -----
> >  mm/kasan/kasan.h   | 37 ++++++++++++++++++++-----------------
> >  2 files changed, 20 insertions(+), 22 deletions(-)
> >
> > diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> > index c3a0e83b5e7a..4c24bfcfeff9 100644
> > --- a/mm/kasan/hw_tags.c
> > +++ b/mm/kasan/hw_tags.c
> > @@ -36,11 +36,6 @@ void kasan_unpoison_memory(const void *address, size_t size)
> >                           round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
> >  }
> >
> > -u8 random_tag(void)
> > -{
> > -       return get_random_tag();
> > -}
> > -
> >  bool check_invalid_free(void *addr)
> >  {
> >         u8 ptr_tag = get_tag(addr);
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 0ccbb3c4c519..94ba15c2f860 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -188,6 +188,12 @@ static inline bool addr_has_metadata(const void *addr)
> >
> >  #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
> >
> > +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > +void print_tags(u8 addr_tag, const void *addr);
> > +#else
> > +static inline void print_tags(u8 addr_tag, const void *addr) { }
> > +#endif
> > +
> >  bool check_invalid_free(void *addr);
> >
> >  void *find_first_bad_addr(void *addr, size_t size);
> > @@ -223,23 +229,6 @@ static inline void quarantine_reduce(void) { }
> >  static inline void quarantine_remove_cache(struct kmem_cache *cache) { }
> >  #endif
> >
> > -#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> > -
> > -void print_tags(u8 addr_tag, const void *addr);
> > -
> > -u8 random_tag(void);
> > -
> > -#else
> > -
> > -static inline void print_tags(u8 addr_tag, const void *addr) { }
> > -
> > -static inline u8 random_tag(void)
> > -{
> > -       return 0;
> > -}
> > -
> > -#endif
> > -
> >  #ifndef arch_kasan_set_tag
> >  static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
> >  {
> > @@ -273,6 +262,20 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
> >  #define get_mem_tag(addr)                      arch_get_mem_tag(addr)
> >  #define set_mem_tag_range(addr, size, tag)     arch_set_mem_tag_range((addr), (size), (tag))
> >
> > +#ifdef CONFIG_KASAN_SW_TAGS
> > +u8 random_tag(void);
> > +#elif defined(CONFIG_KASAN_HW_TAGS)
> > +static inline u8 random_tag(void)
> > +{
> > +       return get_random_tag();
>
> What's the difference between random_tag() and get_random_tag()? Do we
> need both?

Not really. Will simplify this in the next version and give cleaner names.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bx%2B5EcgiS8wZ9mbh-a32w4_CVOdrzw8yrtpPuquaJrPQA%40mail.gmail.com.
