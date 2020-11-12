Return-Path: <kasan-dev+bncBC7OBJGL2MHBBN7KW36QKGQEXU3EL2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id D362A2B114D
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 23:20:40 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id ca17sf4805287qvb.1
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 14:20:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605219640; cv=pass;
        d=google.com; s=arc-20160816;
        b=0/JB/6sdelRIW4TPjKQTwIWngwVLiMyK4PC9XkfqtZxEQWtW6ke9Jq1fvppjWHt5Vu
         S4V5Fu6JA5UJftL5OSX6Q8ygAJ27mMnup1SOigjQ6ZcPLUrXhOjJO+9ZcINxiwEo77S3
         pGWb2XbQCRGpjRZoeQlvSv0zFk69p9h+evVmlESQJdafqE84OnEkCTIHwG8kEQifZ1O8
         C8PwPEvpDULPE9QkjVcD7y0ErVXbb8crFshsJFrFuvG/GI9S+o7b+nlEDp2dLuSdToml
         NE5FkvetwT35ohJaZd4IlzIUioE9oFVmtQ8mBFkYbN+N2vDoBh25ot9Nr9OKnAAFYnon
         dXUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ScpzUs0Grpd9QYms/gR76cE7oycPpmw17UJrXOV/BBY=;
        b=een9boft9MT+HsBsDAZ1BaQG/b7thCyIHbUmP5wMc5MZqS/BhkEWlIHim+3U68EILP
         1tctH6yxpg4ecZYrYjXXK9Rhcme81GpbasKDPeBa2Yg4F0TWVubpHHibjn3pYF31N4JF
         l/8AmI2mhBlWOKeP7PTw9Or8F10D/t4MGscBNi/cPmZuSkXiosb9iLag1RspWbjIo4W3
         +cHkTEIhfcNy4i7SePFezcGs34d4IV/OAegNUEWzt/XWFyDEf2RQ4/bFg9acSe/HsEL8
         1yDgvKc1sHZvq9Et3B6v+hmvm9tuY1OmIifEsT3+n2F3HocijIVAToDJeNx0foEt3Q7T
         KvRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dFN+5nhP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ScpzUs0Grpd9QYms/gR76cE7oycPpmw17UJrXOV/BBY=;
        b=liXT9UjkPobMem13XGMQKkLzFgG+DlhCBpg3n9YQjsayQ2u7+vCrxhb/AgRpWNfnz9
         hXOfWp067DlryjY1l4wvhPI3zZHoZlNQTEmk/8I5ftuMHmPbuHWbBrZ1nJkAUhLGtQFl
         FhFXs2TpRO7p949UnW6g2AD3JdxH1kcviBzEiyU8CuvrjWuuNDl2r76JLCV34zlmK+GA
         iDYMCaefAcgJ0/zMwG7Xg7sQeC0dfYkxXRwm40VG3ddeV2pCRgaNohVdLj7b4JAIK9Zu
         dRRmkRF3Bcjq7LAuvcqsxSgnYygKX9TdNfQn44ARET8SiueTI1mkSbyteB481aMHO753
         cpfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ScpzUs0Grpd9QYms/gR76cE7oycPpmw17UJrXOV/BBY=;
        b=p0fXV6+ICFcVvAG4Efrt58YtDvc13P1AZPcAz94tK8j4dqZ8DtoO+tGPr0u2ab1/Xs
         Xt31/eK3jevUzFPNwW4rn/i6+3RoEtaEmQD4P23/TXQBSujwW5R6j1T4i7XxFLUcxbrB
         woObHgevIp5RCXKvgGIftLBkxoyzrPALZzDJdRy8+6RBcS71yX6wUKYQhHh58X1Mwpm5
         y8kGmS028vpe+qBIoMkw9DV7mKaj7+nVsaT5PpOog58m4bFX44/TzpYIy8cDTSkZih01
         9yByzkXkaWOI71JHBgrs4D+zjMjId8OLXut4Tdrwrsn5jR76B/wtk54EDob660ySbAiz
         wcuw==
X-Gm-Message-State: AOAM5332BCgeYPTIPI1Q8Iuk+SZNR3tF0IvKPP683bJI7YV+xW0WDlcp
	AWXq5U9fHP/66H5E8bL0yjM=
X-Google-Smtp-Source: ABdhPJw+bOU9LFKLMdczWEoSu29r41vATxM+Qtx5r+a0flKt6pVoqY5d4Dtj24S/d0dNRT2Ns1d7AA==
X-Received: by 2002:a0c:e608:: with SMTP id z8mr1721726qvm.2.1605219639846;
        Thu, 12 Nov 2020 14:20:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:7006:: with SMTP id l6ls1994382qkc.5.gmail; Thu, 12 Nov
 2020 14:20:39 -0800 (PST)
X-Received: by 2002:a37:a312:: with SMTP id m18mr2186216qke.268.1605219639219;
        Thu, 12 Nov 2020 14:20:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605219639; cv=none;
        d=google.com; s=arc-20160816;
        b=mwr5HOzDwP+ud6YRYurCtk4cagpYvLbhjVOssOQK0Ssj5lCqNwQ2ul3Azg+qBpR1wh
         6sjuKXCdxzVEIQ/sajOIF2o+4gmR3QYdWEBNcoc2Md0FxHveJCo/09wU0vWcMfCNud90
         G1FD7Oc1YlpMbg7g5IEuHjhW3aHKFkdyGqcabpXH9VCKbcjtLpgc7B5PIiYVi437RwFP
         eM248S6iMdVytSXWLQIEGejk7gtGNDKipwEv2h9zXFFDoYUbAd7dsEy7e1tQ4c2kVq4w
         kZfz0iXXci3A486ZxdaeBMddfQbCyAwddupzhDpwtQbFC2vLTvYIcq2AMVFhDGhlxsGV
         zV1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qTAA2mjTH1s5gJvXfoqFOnb2RIhffz7/HPf/PMilg1s=;
        b=Tn952UNDkemXxSYBkfIIlc1UuY+66d398X5tZM6NhiZc3o+/BJjvlSclqeEV5uklwS
         dN/5OZj+BVKFc4PmLe1oYvkns75yVNmcmFeI+Ntqktektdekl2J/J2+RCLv2QE5xGhzx
         y4M3np4AVcaD1stP4rbKDbBzzXZ265DYaxZxfcRrnjnKjvG36tgtB/zQMSDpiKBrgadQ
         EzU4w+dvKpJxzt4BQBnsCA/4aZxkYG6KttwGAnNWHQm5v7EZM+aJWRVnhbLUYay+dE+8
         fiG/tkbxvr3WKzKdQgb7+SzOsZxf0+uezAmqld6KFNoof3+V1KCVoxU2IowkbJmrR0jj
         xNgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dFN+5nhP;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x341.google.com (mail-ot1-x341.google.com. [2607:f8b0:4864:20::341])
        by gmr-mx.google.com with ESMTPS id h1si516327qkg.5.2020.11.12.14.20.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Nov 2020 14:20:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as permitted sender) client-ip=2607:f8b0:4864:20::341;
Received: by mail-ot1-x341.google.com with SMTP id z16so7170794otq.6
        for <kasan-dev@googlegroups.com>; Thu, 12 Nov 2020 14:20:39 -0800 (PST)
X-Received: by 2002:a9d:649:: with SMTP id 67mr1045852otn.233.1605219638578;
 Thu, 12 Nov 2020 14:20:38 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <0a9b63bff116734ab63d99ebd09c244332d71958.1605046662.git.andreyknvl@google.com>
 <20201111174902.GK517454@elver.google.com> <CAAeHK+wvvkYko=tM=NHODkKas13h5Jvsswvg05jhv9LqE0jSjQ@mail.gmail.com>
 <CANpmjNOboPh97HdMGAESSEYdeyd9+9MVy6E3QsvVAYuWVReRew@mail.gmail.com> <CAAeHK+xhjUQAtJThUHcaGmd3muBZHiJPfTqj59CMxo44hbDniw@mail.gmail.com>
In-Reply-To: <CAAeHK+xhjUQAtJThUHcaGmd3muBZHiJPfTqj59CMxo44hbDniw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 23:20:27 +0100
Message-ID: <CANpmjNPxqOi8QCJ4VY6vfVkktEWO1=S5hcOBvTQcWhhL0L9B-w@mail.gmail.com>
Subject: Re: [PATCH v2 10/20] kasan: inline and rename kasan_unpoison_memory
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dFN+5nhP;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::341 as
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

On Thu, 12 Nov 2020 at 21:54, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Thu, Nov 12, 2020 at 8:52 PM Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 12 Nov 2020 at 20:45, Andrey Konovalov <andreyknvl@google.com> wrote:
> > >
> > > On Wed, Nov 11, 2020 at 6:49 PM Marco Elver <elver@google.com> wrote:
> > > >
> > > > On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > > > > Currently kasan_unpoison_memory() is used as both an external annotation
> > > > > and as an internal memory poisoning helper. Rename external annotation to
> > > > > kasan_unpoison_data() and inline the internal helper for hardware
> > > > > tag-based mode to avoid undeeded function calls.
> > > >
> > > > I don't understand why this needs to be renamed again. The users of
> > > > kasan_unpoison_memory() outweigh those of kasan_unpoison_slab(), of
> > > > which there seems to be only 1!
> > >
> > > The idea is to make kasan_(un)poison_memory() functions inlinable for
> > > internal use. It doesn't have anything to do with the number of times
> > > they are used.
> > >
> > > Perhaps we can drop the kasan_ prefix for the internal implementations
> > > though, and keep using kasan_unpoison_memory() externally.
> >
> > Whatever avoids changing the external interface, because it seems
> > really pointless. I can see why it's done, but it's a side-effect of
> > the various wrappers being added.
>
> It looks like unposion_memory() is already taken. Any suggestions for
> internal KASAN poisoning function names?

I still don't like that one of these functions just forwards to the
other, but we could use it to also give the external function a more
descriptive name.

I propose 2 options:

1. Name the internal helpers *poison_range().
2. Name the external function kasan_unpoison_range() instead of
kasan_unpoison_data().

Anything "memory" (or "data") in the allocators might not be too
helpful w.r.t. descriptive function names (i.e. stripping "memory"
from function names won't lessen descriptiveness given our context).
Perhaps kasan_poison_range() for the external function might in fact
improve the external interface (without looking at its arguments).

If we need to keep the internal helpers, I'd probably go so far as to
suggest renaming them to simply kasan_{poison,unpoison}(), and then
building the external kasan_{poison,unpoison}_foo() on top. But maybe
that's too much for now if it doesn't fit here. :-)

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPxqOi8QCJ4VY6vfVkktEWO1%3DS5hcOBvTQcWhhL0L9B-w%40mail.gmail.com.
