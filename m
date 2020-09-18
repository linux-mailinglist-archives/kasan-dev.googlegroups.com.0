Return-Path: <kasan-dev+bncBDDL3KWR4EBRBYFESP5QKGQEWGUD53I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 31BC12700FB
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:29:37 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id 6sf2757083oix.6
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:29:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600442976; cv=pass;
        d=google.com; s=arc-20160816;
        b=mtICho1ZMh000awEjhpzVt4zRHe0LIZl9SQY9VVwARh23+0DPQJlHY6PEjK/Lyb5hF
         ZCyNpTcdzzDpEFHZ1LrODbrCW0exGC+w0S/H/XQPudJRfWlHLbbNZHYOwYoni9h5ahnk
         d7oIlye9e9G07Re/upYPnNGDahsuz3Ba6axIU7NYP02U+rY9Mj7hjhKCk3WQe/+uf7lr
         L4Lp7usPLiD+mZPeyBOmYxbiP9qpsW98dzN6g4mjG287Tur41GoAw784m1K8utCqY6Uo
         AX2mWYTnm5BrsxN0rnF8V4OPJ1f7UBKHgvBHnkQXxG82PWE7TCF1Le3t7JBxb4pVUQe5
         wVaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Z9YwHDff5+k1/XtUbAesATV3vh+4Xo31Gm+BP+Rd2+s=;
        b=BxpCJ59/kUfmTkSVBnBRoCHgMG/SqbVc+pD6tAh1ENm4w3206ZevwURHvNS2gsV4so
         /XHWF8payerUqrN4LI83qEsyDJXJMNzUxgd0hwO846gFJu3LIumaUe78+Hk05RBEJMV2
         8r9ARqmZt/yGJQeVVx6YDkGr3GlgL+c+r5tbdCRst6XbQAfkv0SEQBCZWt7Y/B1fbLN8
         T4EmEEXFHX+VEMrwBvVU1FpFNw/VoqoGott1sxOBOuowWxAfWUhh/bkxgVqOXfXpcxT9
         eDrpWwunTbjHoSATWQUC8+DQEdG9j752PnuYdfpp1kD+mUg0o45ff0U74Z/6H7Vb7s64
         8b0g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z9YwHDff5+k1/XtUbAesATV3vh+4Xo31Gm+BP+Rd2+s=;
        b=bDbjon7IrQXNQ4LiIgxIWVokLJx1sNvM8ugYaNQdG9OXsco1nzY+VOA/YL/Ew+mzma
         gw/aoDT/tqJP92B+CPknL3ffdICPdX0ADVpuHO9g5086Vr8IDR7M9iJyrgZZc/RQ0rlT
         AN3J6Hg9b1I8cOomEiywQnjiPo+cNrPWzS8DwUR9tV/YWJKzlH2TNUtGnTpbIniUo1kC
         YSCWmNunwhObgR0U0zVziJh3CHyXDmqUAP/MAjliFKWcWOk+e1b4pIACO9fL3sErPXbj
         f5drez6+L2tpc1v/LESCdsjoWBBerketo1Dl07qV9eKtF94ywBsWigLAYHH4fHYhJAZC
         OsOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z9YwHDff5+k1/XtUbAesATV3vh+4Xo31Gm+BP+Rd2+s=;
        b=KQ9L5gY68vLbL5ZLe04RYf7sN/zEDC7DSQRFI43OJYOEwS4aI838+uzZamFV+//RF6
         AwoBmOKCnzu6Nfok4HLFXeW9BL+2qfEDQ/R09UNeQNWLDLCtKiASudBzJEoinC9s3g+7
         QllaCW11KhVdgOwCWPvfWxZAnqIqPSfTIc/2WiNOHGp5xHvv7kerDzfbEBqhjnJzW/kX
         w7zk2vLfqYhMAVCLMpluCsK0WKgahWS2FOyhe7LtMGRgzZFC69JOvbUAUmcZbMTSplii
         IAlz0jkB2QILHR1J1NnOyK+1eiv4Xp5CP3tLm5Dd+m9O3r7efd9SDzgQAHSdghSC7dkL
         jp8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532QdWWZ/GKxeCX/VBUPFzWG4i5VnyQ34DcUBzW9zb6HSfGkQqYH
	+LY8EUb9gcVUUHPJMATvEms=
X-Google-Smtp-Source: ABdhPJx9c5tdHfqpQ6+5O0Wghcix3Q+joRH5Ivt3xTM6a+IkHfbqvtrUksguxWsfT17cj/cIeJUr+A==
X-Received: by 2002:a05:6830:1408:: with SMTP id v8mr23837244otp.120.1600442976120;
        Fri, 18 Sep 2020 08:29:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:2513:: with SMTP id g19ls349952ooa.0.gmail; Fri, 18 Sep
 2020 08:29:35 -0700 (PDT)
X-Received: by 2002:a4a:6255:: with SMTP id y21mr24460728oog.19.1600442975558;
        Fri, 18 Sep 2020 08:29:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600442975; cv=none;
        d=google.com; s=arc-20160816;
        b=PNCICX+hXCR7Ew6ekYwm5PjneuoBvMD7eNZQLRBCkXhq6UU5pEH+ui8YAJOwKBJSCE
         vmSwEC+aKETpmjdoNLJQVuvrBsuwkd2X64DLlPKxYDO8k8adZGyGggadUlpLR7sexx1c
         gK9S13mKi4a4xNe9JQQxkenQsBtms08SY7k2xxgP/rXwWeqSsefujQtcXfAVjBjAq0EA
         yseCZF4IyNPke2dTfk/H+iImvsxHzI7da9YOyxEniWnqF2C8Qq9vWWW8pJcLGKXmJPha
         BBge4bJdrSecChfy8naErzq2+OWR4jL8b1w2mldB1EObs19TI8zgOONrpIxjd5C9IxOo
         5vhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=1ks3JMEy8saQovm8fQrG4EdfqcDHyg9BvAUQFyCdKEI=;
        b=pFt7YsZIEHsCEYewSrKz2f2v7D/UkiUfFbYZSNAiGhE2wVwrUnZDmmgYYifsEkqxWu
         R1pK7djF2d6orjG2g9wh7+uQWSYcC8U8fJJUB+bUMxL74+S01gAjKA1P4ccxvYbxFcnk
         AQ+rBHBu9R06wWvqsndfpWgPh6jKIAN29bMxaFvw6je5uCoGXuSji3gFU1N/j/+zpE69
         sMDV+pOQHKU/s98Nxmg5PsbTYaPHMUAxsTJ3h+fUG1VCnjmg4egLNAYGep5WEyIrLc4w
         QqGV5vRLxaiTEWdz2rLuP6G+2kBETLQIRGGlUgHcwPiUeMebcbZjcPYURsd35OqtbGq+
         b/9A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q10si313765oov.2.2020.09.18.08.29.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:29:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 559FA2388B;
	Fri, 18 Sep 2020 15:29:32 +0000 (UTC)
Date: Fri, 18 Sep 2020 16:29:29 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH v2 35/37] kasan, slub: reset tags when accessing metadata
Message-ID: <20200918152928.GF6335@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <f511f01a413c18c71ba9124ee3c341226919a5e8.1600204505.git.andreyknvl@google.com>
 <20200918144423.GF2384246@elver.google.com>
 <CAAeHK+yJ=86KfVN5bSvXpawjNtLuG4zvsPVtcYCBQR_PPfV4Bw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+yJ=86KfVN5bSvXpawjNtLuG4zvsPVtcYCBQR_PPfV4Bw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Fri, Sep 18, 2020 at 04:55:45PM +0200, Andrey Konovalov wrote:
> On Fri, Sep 18, 2020 at 4:44 PM Marco Elver <elver@google.com> wrote:
> >
> > On Tue, Sep 15, 2020 at 11:16PM +0200, Andrey Konovalov wrote:
> > [...]
> > >  static void set_track(struct kmem_cache *s, void *object,
> > > @@ -583,7 +585,8 @@ static void set_track(struct kmem_cache *s, void *object,
> > >               unsigned int nr_entries;
> > >
> > >               metadata_access_enable();
> > > -             nr_entries = stack_trace_save(p->addrs, TRACK_ADDRS_COUNT, 3);
> > > +             nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
> > > +                                             TRACK_ADDRS_COUNT, 3);
> >
> > Suggested edit (below 100 cols):
> >
> > -               nr_entries = stack_trace_save(kasan_reset_tag(p->addrs),
> > -                                               TRACK_ADDRS_COUNT, 3);
> > +               nr_entries = stack_trace_save(kasan_reset_tag(p->addrs), TRACK_ADDRS_COUNT, 3);
> 
> Ah, yes, it's a 100 lines now :) Will do in v3, thanks!

Don't get too carried way ;). The preferred limit is still 80, as per
Documentation/process/coding-style.rst (and commit bdc48fa11e46), unless
it significantly increases readability and does not hide information.
The checkpatch.pl was changed as not to make 80 a hard limit (and so an
arbitrary higher limit was picked).

What (to me) would increase readability above is aligning the
descendants to the open function parenthesis rather than increasing the
line length. Anyway, it's up to you on the kasan code, just don't bother
changing the patches for longer lines in arch/arm64.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200918152928.GF6335%40gaia.
