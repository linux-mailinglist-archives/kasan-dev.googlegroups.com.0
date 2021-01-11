Return-Path: <kasan-dev+bncBDX4HWEMTEBRBA436L7QKGQE3AN7WYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 059052F1CA9
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 18:40:21 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id j28sf219118oig.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Jan 2021 09:40:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610386819; cv=pass;
        d=google.com; s=arc-20160816;
        b=zQJTywMu+sNvZpJJhfGXZsR/elJ8olXE8+mhAtY+yOwDl6jrFSKkO6tKvX6VEP4TYw
         xTNF+GOdOXAm0g3bpbO0MgfpHwoho7KgXlXPLxAAC9dsZRHU6Xn0Kc+TWgPPIgbkuavx
         5s6D/ZLOA95CoHg2FKGZYZ6CrY97Lj+OCb5av3Cx88HZuxGt3XhsMB4778GmNd4OeNDw
         NetTY4apaXF2a9rUDBFfQDwOU1V7F5KmrEAjxXdt+S8U05hdg4V9GBZNQprzQEFzFN4X
         QzFjU5Kn/PTG+hBrTgeSJW/TJeRugF5tJQxJqlKg95qlsQQmgAv/lvfQVSAk33ksnzwv
         GhbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=dV3RJEiB3ELyz+qEeLjYv3Nb3K0e3wuhiecky4lhkhc=;
        b=LJ8d7chypOCJfiJRQH3QVzUqGGw8Vqe3R2E/NCy1EsHxJ9J+9oAcwrtd3Vh5b2gWLS
         9zZuBtTIUiyc+jF4pHu7NiqqdhlyKMQ/4CMpm0SNUMBmr+6TQYBPBwsqkOdNp6glBG34
         elYYObdoO6ASPpXrMJFrvxkoOu++yK8fI5emYhe+fBjw9RHUxKl4vAzKuCJplzXLQ8Cq
         P7qji6ASbO9l1Aezi96g++8F9pKr0wwlR1q6S2H6ZjKKtm8OdGuQ7zic/w6AtM1B276W
         xmJkXe6gVIah0ehNKDrmOV0sx2ZP95NW/ENpAFf8mKzbu/6ZfvF98rDLI+jc8cQ2uqZr
         +MYg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vMdJQPxB;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dV3RJEiB3ELyz+qEeLjYv3Nb3K0e3wuhiecky4lhkhc=;
        b=BcztInBp4uA9u74sIe7mk53Gjep+Ed/UMVV8TCy5tqGTf1sIBLcEud+4IqL32zXMbV
         potAAcxNPwPmus46gP3RdHw7kaW0OXKjEl04o994nhVM0dcVAfQHnydpcCgvCCINWVpB
         BSkIbx5FW6dBBzb65+lB1i/kGRHbbKYyiLNODkPng4mvIyd+TAgJnS319IRp4ynT6nwm
         CJRwSzQrs+jxzf8rmco4MdcPC22g5FotKH0ZwLxT9ovPBB85t7fVlMz04ub17AZl3Xud
         5XSvqKrAJbydUW5uSpTaL/ybzMVU9YfK3aVG1B2IwB0d1809XVLSpH7csZvYoa7/oKdu
         Gcew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dV3RJEiB3ELyz+qEeLjYv3Nb3K0e3wuhiecky4lhkhc=;
        b=ucvV1SAy/HT1ySOfwLgoFHx3kWpuq8c0NNquLbCHENZ8VHahGvjRJaJoENpxxq7s1D
         hYK41rVuSzgbDSu1+8ZxqBZZFdg80AArGy9PFnG2xXPY17DNlfMBiyWubszWuNB92I7R
         k7zk+pCNkqdQN/LyldEBDuFtYBKM1CHsVPQXZ/cvzSkFqfeMc6QICEgiVEuSvcBRNldf
         wof0sf+j4EOBkQKasJ+/1Cx045WmEhknHVakwN2a9LklIaok3OQ0tVWI3wazitpAi10i
         Dv/2Z9cwutsAfzkazEyoyHRwD2Krotetne0689ngkliwG0IXAV57/enoV6aOXCAL6L6S
         1GHQ==
X-Gm-Message-State: AOAM533iV+FEDHCgewx3pID7VmU+AL9njnAWjnQfztOuYbj8blVU4bfR
	zz1+LJPgJ2iUQHLV+wvX3ss=
X-Google-Smtp-Source: ABdhPJwHixZ5A0nKRXSyKIJ43rW4qWV/0kCwc/yqYfR1mtL9Y4oMKgTs6sDjHQKavsVM4DKT3VFpNA==
X-Received: by 2002:a4a:520f:: with SMTP id d15mr262205oob.29.1610386819853;
        Mon, 11 Jan 2021 09:40:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:758a:: with SMTP id q132ls71901oic.4.gmail; Mon, 11 Jan
 2021 09:40:19 -0800 (PST)
X-Received: by 2002:a05:6808:1a:: with SMTP id u26mr305156oic.77.1610386819557;
        Mon, 11 Jan 2021 09:40:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610386819; cv=none;
        d=google.com; s=arc-20160816;
        b=pfiIlqc/RPJo3/RfO7wbxV+OnfxRK+z/aLH6YasD/cBfoxuaV9JjZt+HlM+2jv+bik
         jp3UlJ11Fc7dHwfCyTb1CvN2ikJfemtrMWwxfqnTQvsEkn2I/F7o5AS7V3n2g6MWSn2N
         La6mj6O/I9NxsDJKw8EaBNrQoCl7RJyTX/N3mRFcjA/4XHECrS4/Pzz56fD/8SQ5xQz4
         SmCXwFmuet8t2r5kWxrBt4pQdtCREqSfXANotkZJdCMevBnn1lDzzNenrbaytP5FaVak
         jbJPzBbOpTNFUVdwppHBZ+wo8SPwgbn7f3cFhOpykpXH6plHbTRZM1nBuPKYzTUVIaOq
         WfXA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qjQEnNzMbx9jfPqlYY0N0jYj1R3Q/O+LmSxzsF9dUuI=;
        b=k3RAv1zQnXsjG3TFcsyTzvyF2pxlrYMIzJKmgako04WDB2p1dZfzh75AZ2wL193LlR
         4oYjDieWgcqp+IJcYP0/AAKfAuMHq73WiorrPt514p+fIlj+E6AO6Mt4lzqY3PpJV/0E
         qwZrwRawyOVFJUoEV5LAkxAlE1jKhqde9Zg6Wui6XeOw1tHnNs6/6v0BoRC1CrU5MLA0
         jm2a5NedHSAK2Xca8DyUCyYNGvpq8uIeCCYZ9BnMzCVS50lCNJalIAoSbcXSvK0jE41a
         lX/+c0EZ+IPNvn3pAvcsqxoszNhOkMqm4kYZyhlFiWT4yXC3/wE+Ked/ZrwujXvxU2+b
         g0pA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vMdJQPxB;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id c18si31321oib.5.2021.01.11.09.40.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Jan 2021 09:40:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id n3so238020pjm.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Jan 2021 09:40:19 -0800 (PST)
X-Received: by 2002:a17:90a:f683:: with SMTP id cl3mr383204pjb.136.1610386818720;
 Mon, 11 Jan 2021 09:40:18 -0800 (PST)
MIME-Version: 1.0
References: <20210108040940.1138-1-walter-zh.wu@mediatek.com>
 <CAAeHK+wW3bTCvk=6v_vDQFYLC6=3kunmprXA-P=tWyXCTMZjhQ@mail.gmail.com> <CAK8P3a3FakV-Y9xkoy_fpYKBNkMvcO7DPOQC8R7ku7yPcgDw3g@mail.gmail.com>
In-Reply-To: <CAK8P3a3FakV-Y9xkoy_fpYKBNkMvcO7DPOQC8R7ku7yPcgDw3g@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 11 Jan 2021 18:40:07 +0100
Message-ID: <CAAeHK+zB0=eBgrWTxcUK8GkxmUAn-W44NWDFE4zEB79CxVpwXg@mail.gmail.com>
Subject: Re: [PATCH v3] kasan: remove redundant config option
To: Arnd Bergmann <arnd@kernel.org>
Cc: Walter Wu <walter-zh.wu@mediatek.com>, Arnd Bergmann <arnd@arndb.de>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Nathan Chancellor <natechancellor@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, 
	"moderated list:ARM/Mediatek SoC..." <linux-mediatek@lists.infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vMdJQPxB;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1036
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

On Fri, Jan 8, 2021 at 9:31 PM Arnd Bergmann <arnd@kernel.org> wrote:
>
> On Fri, Jan 8, 2021 at 7:56 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> > On Fri, Jan 8, 2021 at 5:09 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> > > @@ -2,6 +2,12 @@
> > >  CFLAGS_KASAN_NOSANITIZE := -fno-builtin
> > >  KASAN_SHADOW_OFFSET ?= $(CONFIG_KASAN_SHADOW_OFFSET)
> > >
> > > +ifdef CONFIG_KASAN_STACK
> > > +       stack_enable := 1
> > > +else
> > > +       stack_enable := 0
> > > +endif
> > > +
> >
> > AFAIR, Arnd wanted to avoid having KASAN_STACK to be enabled by
> > default when compiling with Clang, since Clang instrumentation leads
> > to very large kernel stacks, which, in turn, lead to compile-time
> > warnings. What I don't remember is why there are two configs.
> >
> > Arnd, is that correct? What was the reason behind having two configs?
>
> I think I just considered it cleaner than defining the extra variable in the
> Makefile at the time, as this was the only place that referenced
> CONFIG_KASAN_STACK.
>
> The '#if CONFIG_KASAN_STACK' (rather than #ifdef) that got added
> later do make my version more confusing though, so I agree that
> Walter's second patch improves it.
>
> Acked-by: Arnd Bergmann <arnd@arndb.de>

Got it, thanks!

> On a related note: do you have any hope that clang will ever fix
> https://bugs.llvm.org/show_bug.cgi?id=38809 and KASAN_STACK
> can be enabled by default on clang without risking stack
> overflows?

Not sure :(

I've filed this on KASAN bugzilla to not forget:
https://bugzilla.kernel.org/show_bug.cgi?id=211139

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzB0%3DeBgrWTxcUK8GkxmUAn-W44NWDFE4zEB79CxVpwXg%40mail.gmail.com.
