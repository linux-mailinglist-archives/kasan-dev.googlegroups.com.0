Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4WOXKCQMGQEBFDU4MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id CEA0639212C
	for <lists+kasan-dev@lfdr.de>; Wed, 26 May 2021 21:54:27 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id cv23-20020a17090afd17b029015cdd292fe8sf955256pjb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 26 May 2021 12:54:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622058866; cv=pass;
        d=google.com; s=arc-20160816;
        b=N5m6216hpVBRtnj0rnEBsw929WLlRTaZ4JTNetB/A/Vf+c/XqxDzcHe3D3GwqvJyrb
         Mv225R5Sn6JiOgyXah8cYTWnxXrBtTnTYGbA1gxt88KBCw+pY7nhn0gE5ZiEn2SzPI5x
         VwKbXNFUTfrOCVydMVMwDMfUeWZqTVybIQ1asYaMjE66OhbEA1N/eaWSMSzD1Mf46OmM
         rnLFSfr2uQDm+oPQsiJo7WZXDQXPJHdfd0x/J30+Ct0C0pqENBMYCSL+X5DcTbM8uJHG
         VGrMU1MGTgbcNTFmo2MuGe+4JLM/D0dzNoYsf838uZiStbt4ya/twuehfqkqOom3UIQI
         y3Mg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RF3di/X0IpVwKbf+pNNBWqqYE2HiN8IaWaYT5QfqzLc=;
        b=cejupcjZ+85NQjffmK0RWZglOk6/EhCe88mjvhbgQgYhZLKIIvY5EuutKl6I2t3Sgp
         fVxyLIjpij+MyEQ6RxwuMpTl5oeSEDi0p3vMLVQ8ZTUvYsZPJ5zcBk/RRh63ngNsiUiJ
         TDtP51OnorOkajXIpplnlqpsHghgcdOScY6i6VQLIB/7jCVIIVlAMpkriNgwGGhLbjcR
         CmuhMsbfkwB8d4eqkfTFtkyOcOHtWmg+2EFtU8oB3VPcAYiWC8DA5Uzd7rYmVp59/k2Q
         4gMmnDdRiKV3hikFRW4KyegDsOGgm5UiZv/QwGJJaKYEM+IH6YjUBLhyKWm27LMj8K0B
         BLfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J1m7oJ6Q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RF3di/X0IpVwKbf+pNNBWqqYE2HiN8IaWaYT5QfqzLc=;
        b=JFNVwr+LrIQxesNZ93tXGpOO1rOdSwpOTyvUaRVKGQTgnNXy9uuXLLPy0PKPzfvdTJ
         Of0/2sG5VBEH1hxgqKq0wSfxaFpLaftGRTWzT0h+EAZXnHY04zfsMS4p1G2JBH1gZXy+
         5EM98cvNtM7WXdWmCpD6KZldMf+JjNAUYQUoEbQqUaP+V8l7WfQRYxIsx0+5VGyWrpis
         AnqBGkn70U87YsjZVfz9W1aPg2w59r8YEbPdSGGGbVwmqP2NebNmypJtICrWgA+hhyuX
         fdYhKhUHq0MEyE4sLTOnvC286uMTGvGaFTu7r8Xdx7K7YW9oirmXeE2fXl7N4olcF5jd
         Cx4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RF3di/X0IpVwKbf+pNNBWqqYE2HiN8IaWaYT5QfqzLc=;
        b=BP5qVjxdcHRxEYNIQM3H/FyZMaD03jie5TGZ39zM/L6QsEzZr6P0kTb9g2RwNGfk30
         UnHQ+8KSylTUhZNwVIwFGBxfiFPBIFLsC6bcG3K5mxqIKdYm8ue5g28wP66MHILuWvY8
         BIxms3CduijDrd0I8a/GZ7VQmdFOyhqhFWAAJXVLG8OG1jR1m4rrIlSoMH9cIxdEvVNv
         IyOfuxcobs8TP+uls/g8dkxcaGEMETIcXklr1j853szN3zPS2L61D+m3fFM7n8XaR/wN
         pbbmOkCHkCyYCKFjMkVW5Pjtp4ig+CN7fvapiKNxCFbxZIxyafiqhCKOuNBaBvuRmXm3
         QM1A==
X-Gm-Message-State: AOAM530EDK1M+ZbbgcnTRfp8/UJrTqW/I2hN5I3HGi0MvWEhVFNU0ExV
	pqEwDCXj9nuYyCkOQc4R2wo=
X-Google-Smtp-Source: ABdhPJzu3yTa7eoBhcT3QIeUjF2wpJBgPYl5pUPbfh0tEiXOf7OSGCWmRl39ytefDrZoUhfizKsf9w==
X-Received: by 2002:a63:7703:: with SMTP id s3mr76604pgc.339.1622058866221;
        Wed, 26 May 2021 12:54:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:164e:: with SMTP id il14ls519394pjb.0.gmail; Wed, 26
 May 2021 12:54:25 -0700 (PDT)
X-Received: by 2002:a17:902:e20c:b029:fb:40da:649e with SMTP id u12-20020a170902e20cb02900fb40da649emr13723430plb.6.1622058865549;
        Wed, 26 May 2021 12:54:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622058865; cv=none;
        d=google.com; s=arc-20160816;
        b=zL42BklkVtgiTuqDYVWk39CZabWoJRd+B8EmEx8nPERuF0+QcSHaElZKivNudkq24O
         XPH/Mr31+oQR8Cv7RbDefUrxLAr0fHSZOfBFfVcqpjngTM4/+0cbM3N03w1VjTuPrsr/
         TeA34gARsBLzLJt+DprwUSIHOT8I6Ye+ylJqZ8rlB6aYZ8apXyLC0P2e4t6Bg6Uawhk6
         vtycM7oBaWTZyoPut6Q4zde+X+XsHkqtXmw5lsvc/I5Lon84Axm+xdD8OOSP3IkD/W3E
         6qddQfXts5GP1bEnQrmGYKwwivB2Syz/o9DIsSP7UHDFCPXy06YE+sMsiutthZUiqRQu
         LzTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sv2g/1M156gg2Bg7bv3uu9uWPD2yQBzbsOC+trFxIgA=;
        b=EiT8CdZAzRsjcR2vtu/nsHlVZF7l+cpF0OvgZ0YuxD2b5tgoViZYeVPzkCeBomiCGA
         HBymxxqZQRYw4EC4/J+U/VEm8G1WsoI48z9qPZCqJIIDXhlk4TaUPO5LXO/6PDcZI5SF
         gzPvn/9e4U0+tHEwvbQCoQjwlUWH2jkWcFcX8kIHni7IyuypPRs8YYULcdwzksEa9Y5h
         UevTIwhH2frg2gaWrH+H8hz93VgpgrKHLOWduS0SiMs85c6xs/m+8QoDuGvj+5FmbbVg
         n8SzSO/alu/AG6WhaxsBOIpTrxnTnihiB6gye0CMeffMvCSOGlPAyCE6+JcxsBxCErsA
         hWYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=J1m7oJ6Q;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x333.google.com (mail-ot1-x333.google.com. [2607:f8b0:4864:20::333])
        by gmr-mx.google.com with ESMTPS id k4si1254492pfc.6.2021.05.26.12.54.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 May 2021 12:54:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as permitted sender) client-ip=2607:f8b0:4864:20::333;
Received: by mail-ot1-x333.google.com with SMTP id 69-20020a9d0a4b0000b02902ed42f141e1so2177217otg.2
        for <kasan-dev@googlegroups.com>; Wed, 26 May 2021 12:54:25 -0700 (PDT)
X-Received: by 2002:a05:6830:349b:: with SMTP id c27mr2675otu.251.1622058864720;
 Wed, 26 May 2021 12:54:24 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1620849613.git.pcc@google.com> <78af73393175c648b4eb10312825612f6e6889f6.1620849613.git.pcc@google.com>
 <YK4fBogA/rzxEF1f@elver.google.com> <CAMn1gO6e_CG9FLoy-xDom7VgjrnPWAUNMMJNbsBz+3kiATdy8Q@mail.gmail.com>
In-Reply-To: <CAMn1gO6e_CG9FLoy-xDom7VgjrnPWAUNMMJNbsBz+3kiATdy8Q@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 26 May 2021 21:54:13 +0200
Message-ID: <CANpmjNNaPTMZSyQxaNbH-zLGaUDHCwZoHuruSRD+s9OA+jGFmw@mail.gmail.com>
Subject: Re: [PATCH v3 1/3] kasan: use separate (un)poison implementation for
 integrated init
To: Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Evgenii Stepanov <eugenis@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=J1m7oJ6Q;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::333 as
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

On Wed, 26 May 2021 at 21:28, Peter Collingbourne <pcc@google.com> wrote:
[...]
> > >  static inline bool kasan_has_integrated_init(void)
> > > @@ -113,8 +113,30 @@ static inline bool kasan_has_integrated_init(void)
> > >       return false;
> > >  }
> > >
> > > +static __always_inline void kasan_alloc_pages(struct page *page,
> > > +                                           unsigned int order, gfp_t flags)
> > > +{
> > > +     /* Only available for integrated init. */
> > > +     BUILD_BUG();
> > > +}
> > > +
> > > +static __always_inline void kasan_free_pages(struct page *page,
> > > +                                          unsigned int order)
> > > +{
> > > +     /* Only available for integrated init. */
> > > +     BUILD_BUG();
> > > +}
> >
> > This *should* always work, as long as the compiler optimizes everything
> > like we expect.
>
> Yeah, as I mentioned to Catalin on an earlier revision I'm not a fan
> of relying on the compiler optimizing this away, but it looks like
> we're already relying on this elsewhere in the kernel.

That's true, and it's also how BUILD_BUG() works underneath (it calls
a  __attribute__((error(msg))) function guarded by a condition, or in
this case without a condition...  new code should usually use
static_assert() but that's obviously not possible here). In fact, if
the kernel is built without optimizations, BUILD_BUG() turns into
no-ops.

And just in case, I do not mind the BUILD_BUG(), because it should always work.

> > But: In this case, I think this is sign that the interface design can be
> > improved. Can we just make kasan_{alloc,free}_pages() return a 'bool
> > __must_check' to indicate if kasan takes care of init?
>
> I considered a number of different approaches including something like
> that before settling on the one in this patch. One consideration was
> that we should avoid involving KASAN in normal execution as much as
> possible, in order to make the normal code path as comprehensible as
> possible. With an approach where alloc/free return a bool the reader
> needs to understand what the KASAN alloc/free functions do in the
> normal case. Whereas with an approach where an "accessor" function on
> the KASAN side returns a bool, it's more obvious that the code has a
> "normal path" and a "KASAN path", and readers who only care about the
> normal path can ignore the KASAN path.
>
> Does that make sense? I don't feel too strongly so I can change
> alloc/free to return a bool if you don't agree.

If this had been considered, then that's fair. I just wanted to point
it out in case it hadn't.

Let's leave as-is.

I also just noticed that we also pass 'init' to kasan_poison_pages(..,
init) in the !kasan_has_integrated_init() case which might be
confusing.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNaPTMZSyQxaNbH-zLGaUDHCwZoHuruSRD%2Bs9OA%2BjGFmw%40mail.gmail.com.
