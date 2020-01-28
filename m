Return-Path: <kasan-dev+bncBCMIZB7QWENRBIXUX7YQKGQE6BUC6JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3e.google.com (mail-yw1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A978914B17D
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 10:08:51 +0100 (CET)
Received: by mail-yw1-xc3e.google.com with SMTP id v126sf10022401ywf.7
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jan 2020 01:08:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580202530; cv=pass;
        d=google.com; s=arc-20160816;
        b=b88jxLCywiLPwsa9nKC8Q+nVyKb1ubmKLCzH0fsKthaL7VeEkuRT4PuOpYswlYHfA7
         jQLwPqJIIMKx2E6E7/pEv6wfij8k/58IN8jhxAG8B6m7A78TJaNiqHAHFLdCm2zF4DZl
         VETMbzeUVbzG0IP/G4noMz3oQxypXF5wsBlzRgvd5+Q6tp7+L74b19daOq1g9piqNvGe
         U8BNTzFzPTwxUjhLKq2iZe/+6V4G1lGmGFNDzm+4QH7s26hXaUGPodXumhaZSV45gsov
         Unxd4+4dM5s+tsU0WPEWkcSQX8nHzS9g1vx9K9PQJxZzfxpr0/5UJ+A/a79ol3oAEXTK
         VxXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fCv7cA6uOzaslxHJ17okzANXCCVn8Xa8Ckcb5K/Imlo=;
        b=OMl+H8roomFu4bbRv9aWnpQwKzz1aPTwqsTfadSCNANwbHt547zAa8bcABb0X8WC+Q
         CqtDT5gkwHRTD40plmusuKQT1BVzx3dH0wWtjDByQbJhrlQWlsYymsFIVO2KajyGhgkT
         XrcXOExTeII21LGJqJPkluR0nReb4thd5Yf9F+zuvcvi4vMF/UaDWDK3WoqlO9UNu/OO
         2gMMAtE1FH7t2/MjU5F3D6NLeFsMRWiSyMlpeeABqkZ/OVyVCOXIMJ5/c9CAhgVNMnXa
         jb+4kdeoaV7vSBhZ7pzTbw9sX8mw0Co7l5TUUiX2AlPZHyTnJUKFD2ypj/2zmF86ihna
         ZnGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UBM+ALw8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fCv7cA6uOzaslxHJ17okzANXCCVn8Xa8Ckcb5K/Imlo=;
        b=WLNLHCfN1HyJfTjU4WzViw7PsjmAMb+OSNS2wDlVmRdNb/vI3nHw/P5MbZ9OMKBgU/
         6tL7THnVNTpTF5PYki5bIS/C6SuGaFItHxclVKEvejinukVtqNoqFRf1FQKe6ifR8ShV
         2uZ+w7qiTJhjVFpzuG3czWfusn33UObRLfrLsapNSORoXnHTd6JQfKJ1lQktHVEVAgfa
         cIlzMnImb3hhRa2fa2FDi003fhwPo/cW6yv7jUQw/2Td+cuRi4z2RERKT96Qp85Ta+uy
         L3+sUxzc30C5Y2dGwZuTRGNAtCGVUIod2fJhwDhIAS67Faj0LaGo2rSZClYRT69Fnf4H
         TzQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fCv7cA6uOzaslxHJ17okzANXCCVn8Xa8Ckcb5K/Imlo=;
        b=T75oajS/Sy4HjvLvuBkezAO4poBZB3oLHiEH15OvEawEfO4tUvoKe20YqE8xT8CqzV
         Y1Me4lM9DomsIFrRzUhRdD6mfkqW6O96qHEeeYRd4VFSz3lB+9UAYdzzI80IJF14q2Q8
         vPOMfKEGDN6+/u26DrnIrzx2lZc3NvDgVrWHDifQ2I1kTUw1gH2GkKgVCSche4b/Nfue
         mreSMSzwXhsu9e9bU+zU5xCPdt9w03lVKIcfv9FxJBEidBkn7iyStYEd1KMtXpIxYNlw
         RKr2g/lMhe5iDviY1SIDXMHInoizjJDhzZ0bTr9kMgz5tJ22+C+ADgpoCfdrN09yCPxS
         xXHw==
X-Gm-Message-State: APjAAAVlHsX3bg1zpCKWBPMN5dMzbDIbeQEm2j9dszt+9kVIDR09mwK2
	f+yhtme3KPUcI1NwY3jdnQs=
X-Google-Smtp-Source: APXvYqzi1fIGYafK6+tbvSzKNRMTnirmIO/w1BrLXGg2NWRB+o4P8gvf2Tbu9BWtmPxJ//vKv75CmQ==
X-Received: by 2002:a25:8389:: with SMTP id t9mr16344468ybk.294.1580202530328;
        Tue, 28 Jan 2020 01:08:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:107:: with SMTP id 7ls2664650ybx.1.gmail; Tue, 28 Jan
 2020 01:08:50 -0800 (PST)
X-Received: by 2002:a25:c7c3:: with SMTP id w186mr16084148ybe.467.1580202529934;
        Tue, 28 Jan 2020 01:08:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580202529; cv=none;
        d=google.com; s=arc-20160816;
        b=OpqJbeX90EVOR3ay03/m/N/3NwDyCdBZqtx3NLuXMDObybe8yTyOUbmkVVg6u4v73w
         PQvzOaUt0sNL84tXbZlAEa/GRPyRcabNp09KSKEWh+mIUp1+W6VREUrMBxi79ZdRPZ1m
         SKmmnwOHlv8GxONIY2rKNi4Lwm3CoY+35NxoFRzDonhC2OSzpmOQBxv39zJSnJzxg128
         j0dvH+rUmBEWttOo38UzHjAOp1rDmN6MDmCt8AFhAJZ36LG3JXriR6c4rFvORON8podo
         dGIRUZ9xJQSZRSfs99cdPAjTvMCOVgFdhCMQX/9T2LoOeZC5zPLLjOJJUJ2GFUGWT3YH
         z/dA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=V9xAyfYvshxDtwWMgT0zgZJ0j7N3J44CYOXm6ENX55s=;
        b=E6WDCjO4bpitkvJL0I2sfkTSY6i0mGMwXZX5/QIrSnLtc9p4SLMIupVFVU6NinhOH8
         jJ3k2fcsigzoTAOqFAOpD8gq8v2KzYGQ0t/ainTTpHjNrcOAeupjcuicqypPz7YjWhnL
         iNVuNhlCJ0EdU9YmesLt48RbpE6DM/k32VNrRRCm1foGzdZOgXJ/VNV+HQRpAvJ18lcP
         AhgsbbEw2doKD6sgDKUBrjFws3Goa4bsGl7tJNLXyZ3QafkVk8dPr7BjrhZlFCGlERPK
         vz3dRJ4h6hF5Sm04OARxNInhXIpPprSKMb7jOXR/3L1l9PdDenEIvZcc6smGhwx8SUKO
         W9sQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UBM+ALw8;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id n11si951797ywd.5.2020.01.28.01.08.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jan 2020 01:08:49 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id o18so5900459qvf.1
        for <kasan-dev@googlegroups.com>; Tue, 28 Jan 2020 01:08:49 -0800 (PST)
X-Received: by 2002:a05:6214:1874:: with SMTP id eh20mr21684750qvb.122.1580202529263;
 Tue, 28 Jan 2020 01:08:49 -0800 (PST)
MIME-Version: 1.0
References: <CAKv+Gu8ZcO3jRMuMJL_eTmWtuzJ+=qEA9muuN5DpdpikFLwamg@mail.gmail.com>
 <E600649B-A8CA-48D3-AD86-A2BAAE0BCA25@lca.pw> <CACT4Y+a5q1dWrm+PhWH3uQRfLWZ0HOyHA6Er4V3bn9tk85TKYA@mail.gmail.com>
 <CAKv+Gu8ZRjqvQvOJ5JXpAQXyApMQNAFz7cRO9NSjq9u=WnjkTA@mail.gmail.com>
In-Reply-To: <CAKv+Gu8ZRjqvQvOJ5JXpAQXyApMQNAFz7cRO9NSjq9u=WnjkTA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 28 Jan 2020 10:08:37 +0100
Message-ID: <CACT4Y+Z+vYF=6h0+ioMXGX6OHVnAXyHqOQLNFmngT9TqNwAgKA@mail.gmail.com>
Subject: Re: mmotm 2020-01-23-21-12 uploaded (efi)
To: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Cc: Qian Cai <cai@lca.pw>, Randy Dunlap <rdunlap@infradead.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Brown <broonie@kernel.org>, 
	linux-fsdevel <linux-fsdevel@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Michal Hocko <mhocko@suse.cz>, mm-commits@vger.kernel.org, 
	Stephen Rothwell <sfr@canb.auug.org.au>, Ard Biesheuvel <ardb@kernel.org>, 
	linux-efi <linux-efi@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UBM+ALw8;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Jan 28, 2020 at 8:33 AM Ard Biesheuvel
<ard.biesheuvel@linaro.org> wrote:
> > > > Should be fixed by
> > > >
> > > > https://lore.kernel.org/linux-efi/20200121093912.5246-1-ardb@kernel.org/
> > >
> > > Cc kasan-devel@
> > >
> > > If everyone has to disable KASAN for the whole subdirectories like this, I am worried about we are losing testing coverage fairly quickly. Is there a bug in compiler?
> >
> > My understanding is that this is invalid C code in the first place,
> > no? It just happened to compile with some compilers, some options and
> > probably only with high optimization level.
>
> No, this is not true. The whole point of favoring IS_ENABLED(...) over
> #ifdef ... has always been that the code remains visible to the
> compiler, regardless of whether the option is selected or not, but
> that it gets optimized away entirely. The linker errors prove that
> there is dead code remaining in the object files, which means we can
> no longer rely on IS_ENABLED() to work as intended.

I agree that exposing more code to compiler is good, I prefer to do it
as well. But I don't see how this proves anything wrt this particular
code being invalid C. Called functions still need to be defined. There
is no notion of dead code in C. Yes, this highly depends on compiler,
options, optimization level, etc. Some combinations may work, some
won't. E.g. my compiler compiles it just fine (clang 10) without
disabling instrumentation... what does it prove? I don't know.

To clarify: I completely don't object to patching this case in gcc
with -O2, it just may be hard to find anybody willing to do this work
if we are talking about fixing compilation of invalid code.



> > There is a known, simple fix that is used throughout the kernel -
> > provide empty static inline stub, or put whole calls under ifdef.
>
> No, sorry, that doesn't work for me. I think it is great that we have
> diagnostic features that are as powerful as KASAN, but if they require
> code changes beyond enable/disable, I am not going to rely on them.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZ%2BvYF%3D6h0%2BioMXGX6OHVnAXyHqOQLNFmngT9TqNwAgKA%40mail.gmail.com.
