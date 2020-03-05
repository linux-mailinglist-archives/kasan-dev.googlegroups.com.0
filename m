Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNEXQTZQKGQEPOFLABA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A78C17A755
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 15:24:54 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id v11sf3312149pgs.10
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2020 06:24:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583418293; cv=pass;
        d=google.com; s=arc-20160816;
        b=FARFh0o9x+pF+hEEUC2ixHYVy/riC5A+HTU+MsjrfqU8v9/+x3sh07Z9WldZ+pW+UG
         dRjZIO3p7TBLvmke86r/78BgLLLKMT+99VRJcgDP3trBj3MXESGVRZrKvUGBb98+uWN1
         nuHwZ8tjgtjCgzwdWqd90/UeqbbzooU+1ganIKZrggZMYFNrwksAYEjt9xyhJ/5ej/WH
         az+F3j1kijmmz+1Gu5J5lNGIIqqcywW6e4+b2ESm7UavBZRSuoTToM4T25CTcMgFotY/
         eukl80/xDx5a8WdNLQJfSBD606H4w+iYcqDp6La+IbE7XIY88TXga8PKtChOgHBlDwnS
         AHmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=GzWdjosLU3DJRP7zTP35bGVbt7tDLd/WsuoMep0Fna8=;
        b=H7gQMAPN3f2kVxFo/JilVDSjlgA7SeD58p8gVTj4DhtT3LHedvCbU/B7ow22Hq89Oo
         aoscgjA3TENfHHvk78KdhZU1R/MkyhkusKnISt2+EpNHJFhO7h4Pl77bSk7Gew4MwYhO
         o6s4OZDjZ+vJ9iV1wpzR1v7fmeJNvOmhYqAQvH50luroUkKwYEXTkOpryDPu9gqQZHMp
         hmqS26iiX1KqHAKzbMbJGD2fBreWBope2o/+VvWWnfy1oid+rSTcJ2Z+oMpgzjHvRzLV
         g1KJrkzmLqLCkUD/VyqxzzWSYO9aOnL6xoB1IzhC9DfzK9fiJUhifIti4f8ZcxcZmK3o
         +4sQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OM4RnwdM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GzWdjosLU3DJRP7zTP35bGVbt7tDLd/WsuoMep0Fna8=;
        b=QwnSb2Azp4EmZp1lEtvYUpJBIbUae8X0CanL6rEDaqvHCApnMnGa4P3/rk/7RgcyfZ
         4Djxk+BJvirYZqmjuZTUVxiRXhs/TIiJFr6tNnz1oNOcbBk0jwgQbo6AfTdhGbc6JP6E
         RgbJRlWBzTYdMILxw+327SiwpgJmtjfiBYw2uLYLKtEPdyZr/N2V1zsXvQv1Aq/smD6g
         dmLbC7mY1uQDTj2GEvrEgZzyKG4oXlot79WK/R2m9STmsOSe/8Gu6SEZX7n3zDToBiR5
         eyZoQlGJyFHv5us92E1cBYmxV1npx8SlvneSfZEz2bQ0vj1t6N2khhhTDBr7f5PkUf98
         VAkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GzWdjosLU3DJRP7zTP35bGVbt7tDLd/WsuoMep0Fna8=;
        b=ePRrIq+/NGaTYMdpmLxNJJySxCGb8or4p0701UYdcLx21U4otfkhyGUUyNwIJOcq1t
         Ch5EoxZgX0oWwVKmz2wx2zeNmr+sw4qsqiMNYZo+hpCLRIRzO8VbF281xFwEoffthnqN
         XSXbbSaG3HvsFZUoEt4xeZWPo68Tah1JoGMe5QLECN1T/Wlj0GCvk+0N/YdqQ018kFOo
         Bx6k0eETM/RgQ7AytGtwXg2vGjyK71q2EWNsf43cGNCnenL21m7ZQXiIHN6GtFy1pmf9
         bN58axBFTdPN9i6Dtncu9td1C8rPq4vH2fM/Ubgx9LBjCeEM7LCjj4cPI840/CJBqnR9
         4dwg==
X-Gm-Message-State: ANhLgQ0AQUnR6rh4hvoFcc2Hu2hv+ttE1etFht8u/zAsjqGXD8OUdXzX
	s8WqR2dhdQEtPJomHyw4pV4=
X-Google-Smtp-Source: ADFU+vuN5SLNFvgZMfunlFIetQkAPayoLEXFtt0dr0IKh7rE20ZVLv8ilfSb76AJ+vgTjUQA+C2peQ==
X-Received: by 2002:a63:f311:: with SMTP id l17mr8096004pgh.142.1583418292757;
        Thu, 05 Mar 2020 06:24:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7744:: with SMTP id s65ls846961pgc.3.gmail; Thu, 05 Mar
 2020 06:24:52 -0800 (PST)
X-Received: by 2002:aa7:8191:: with SMTP id g17mr8750436pfi.25.1583418292251;
        Thu, 05 Mar 2020 06:24:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583418292; cv=none;
        d=google.com; s=arc-20160816;
        b=GRgiV6jifO5RafsgPBn8/jc8FwdyUHBripqe2UO3dFNrNTy3eGRDcH01ZoWKuPQkIy
         MrlLsenKli6l7QEtqwvubXMfpSPRJicsHVraU+SF8CQ0CFV2MjEAWgUi+VmARfxX0LsM
         3Nnco7ZOOitWsg7CmDFFc4zEM3ZSq49tcI4yMqGCXs6UAMQ0WBcA5pzBUNKGP5VABPUj
         l06Cfz1eRmevtqaGro2Z4TFBmE8HEIdSE2rVBu33ReGw+jHYeYgk/PXcvBDFxklfwXQJ
         js5fbhGmc42MO/Ydy5NLFtCvSwkchRTXi8G+AFqjXcyduWR8nfI4kqy5O04herj478sL
         9c8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WdOkNe1i6CaMq0tiqi6obtIyviMmK0f4VHBh6zrGclw=;
        b=W0npRA5gKeGg84zPy5dxjhhzdnhqMcnfT8c48WEeUD9xSR/yomFN8SYbSVhuH3FUrv
         /2VfU4iL/xZXl+Pp4b9VGZCVUazC1nKOUlULaIfONVwVtd7LY3riG0xiLjWEWxnU6lSS
         qczM7NgTxhBpb7hZdPH1q/zriz6pZEQiPn9pXIWgAQC88NJUG9ykSq+Am+cWEP4U/4rM
         9OCQs3Dap4nRQJEF4SyrvItANMDYA1h6Wut2bDQ2Nffj4PajNn0tQSKwfpI92oF9HDzv
         PqUQM7Ky0eQdWkGImOUE3GiywZx19cY6JnewCiwEVxpRc+VdMKT0oPLIjwVVT4w8GHIN
         E1FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OM4RnwdM;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id i4si248463pgg.1.2020.03.05.06.24.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Mar 2020 06:24:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id i1so6093705oie.8
        for <kasan-dev@googlegroups.com>; Thu, 05 Mar 2020 06:24:52 -0800 (PST)
X-Received: by 2002:a05:6808:8d5:: with SMTP id k21mr5897489oij.121.1583418291263;
 Thu, 05 Mar 2020 06:24:51 -0800 (PST)
MIME-Version: 1.0
References: <20200304162541.46663-1-elver@google.com> <20200304162541.46663-2-elver@google.com>
 <1583340277.7365.153.camel@lca.pw> <CANpmjNPKjbCi=m+3Cqyhh9o5xrmLOzB6O48vtAP9KMsEsgzNrA@mail.gmail.com>
In-Reply-To: <CANpmjNPKjbCi=m+3Cqyhh9o5xrmLOzB6O48vtAP9KMsEsgzNrA@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Mar 2020 15:24:39 +0100
Message-ID: <CANpmjNMXFyhA23WrTTAjzGcjvtXz-1y5DQi6a0xgSxzg_7bGEg@mail.gmail.com>
Subject: Re: [PATCH 2/3] kcsan: Update Documentation/dev-tools/kcsan.rst
To: Qian Cai <cai@lca.pw>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Jonathan Corbet <corbet@lwn.net>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OM4RnwdM;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Wed, 4 Mar 2020 at 17:57, Marco Elver <elver@google.com> wrote:
>
> On Wed, 4 Mar 2020 at 17:44, Qian Cai <cai@lca.pw> wrote:
> >
> > On Wed, 2020-03-04 at 17:25 +0100, 'Marco Elver' via kasan-dev wrote:
> > >  Selective analysis
> > >  ~~~~~~~~~~~~~~~~~~
> > > @@ -111,8 +107,8 @@ the below options are available:
> > >
> > >  * Disabling data race detection for entire functions can be accomplished by
> > >    using the function attribute ``__no_kcsan`` (or ``__no_kcsan_or_inline`` for
> > > -  ``__always_inline`` functions). To dynamically control for which functions
> > > -  data races are reported, see the `debugfs`_ blacklist/whitelist feature.
> > > +  ``__always_inline`` functions). To dynamically limit for which functions to
> > > +  generate reports, see the `DebugFS interface`_ blacklist/whitelist feature.
> >
> > As mentioned in [1], do it worth mentioning "using __no_kcsan_or_inline for
> > inline functions as well when CONFIG_OPTIMIZE_INLINING=y" ?
> >
> > [1] https://lore.kernel.org/lkml/E9162CDC-BBC5-4D69-87FB-C93AB8B3D581@lca.pw/
>
> Strictly speaking it shouldn't be necessary. Only __always_inline is
> incompatible with __no_kcsan.
>
> AFAIK what you noticed is a bug with some versions of GCC. I think
> with GCC >=9 and Clang there is no problem.
>
> The bigger problem is turning a bunch of 'inline' functions into
> '__always_inline' accidentally, that's why the text only mentions
> '__no_kcsan_or_inline' for '__always_inline'. For extremely small
> functions, that's probably ok, but it's not general advice we should
> give for that reason.
>
> I will try to write something about this here, but sadly there is no
> clear rule for this until the misbehaving compilers are no longer
> supported.

I've sent v2 of the comment/documentation update series:
   http://lkml.kernel.org/r/20200305142109.50945-1-elver@google.com
  (only this patch changed)

Please check it captures the current caveat around "__no_kcsan inline"
with old compilers.

Thank you,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMXFyhA23WrTTAjzGcjvtXz-1y5DQi6a0xgSxzg_7bGEg%40mail.gmail.com.
