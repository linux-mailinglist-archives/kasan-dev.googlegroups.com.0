Return-Path: <kasan-dev+bncBDW2JDUY5AORBKNDRWJAMGQEGNOHQZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe39.google.com (mail-vs1-xe39.google.com [IPv6:2607:f8b0:4864:20::e39])
	by mail.lfdr.de (Postfix) with ESMTPS id 879154EB36A
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 20:36:26 +0200 (CEST)
Received: by mail-vs1-xe39.google.com with SMTP id w5-20020a67c905000000b00324c7bafd3asf2767988vsk.16
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Mar 2022 11:36:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1648578985; cv=pass;
        d=google.com; s=arc-20160816;
        b=c3kyucqIi4swA2U0NTkNj2S9DKOZ9h1tkfXAcqoJtqt5H2EuPcyZZZmyq+DCGjg3Gb
         0+ePplj0eP97qBoSYyZbN86knX2AW2sdUiCkWD35sYMcL7hbsF0SLK+wIQ4OQfgdmqqX
         lV06MR7XGjgWlVme1WhseWnliFfu029xJ2c8/I+OiYNj9Jm8ZhAvrj0hUqqhZLm1QuqA
         2rS+CBZFTTQM4sEomPj/YK7foPXXtq7ykkDE4yJ0ddg3J9SNL1uUXbmHnmCyfMo0hKfe
         j2r437Y9dWUXKeXs6/1srjnTVdSp8B7cASMml/2nKdsILtZZmc8lvjlTXgWDMVHjal+4
         OfZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=oa5yL+LG/6hMlx8sJ6eUdXk8H8NSqRj8fkPiJ1PytFw=;
        b=CYF7gIFMle4hrEFg+zH/txcKy7ZukETrO0E2/kONt/aVU0gU9L8wEtqWlkAThoHV0G
         Mhi+5GHebvM4RVrbbLWwQa/rJAPgf64e67v+0YILFG7x8lhAd8hWpldNSbLEmfc+Anwe
         7LlfiPs9wgaKszyWsAWFEoDh1tVlUM9S3shoqPV2pfYmoBymkDaUAy1oJRrD9GGlfnPg
         ZVwysYdU0ZvlSnO5F2x9+EJdz177ISI0L3R7eiFh4KtRduTGjUfli6leXf6HWsW5hu/M
         o0JVk7LfMB6Mmz0lOXk4UNXtfKduEbG//ESlI7tHTMI4Xck+1L6/dDLSEm1aGZCZXwci
         l6FA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="nj4/aW6K";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oa5yL+LG/6hMlx8sJ6eUdXk8H8NSqRj8fkPiJ1PytFw=;
        b=PRsimIYi8aQit8ZgI/Sg/jr8Ld+HD2sWdqBakgY0+kN+C+MToecfxHCAALNuSLbjvY
         aWAI/N/A4AHJq2xvKC9JAKvL0Zm94mzGSdxDkgQcbJGDSv/Okfax/0JBfrikVVwjPeAp
         QPlbFvn+up97M1kzCxMpDXLAIGZqzrzP8l04oIQzX6dGWkkMIstZuq/o/gklfRSTS4el
         oZlKQuw3Ff0laYOCTQKShY9PoZKQhbCGPMvtjkaZnaOP6kckSwfUntQhLfQU+3CQwLNo
         ZMETkcUv7OQchcro45J/kzeQs79f1UfyjhZLMidzOmWLR0AqsO1kbvy2nayq+SpxTAAL
         RqWQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oa5yL+LG/6hMlx8sJ6eUdXk8H8NSqRj8fkPiJ1PytFw=;
        b=lDEsI36Nw/HcGruk5I3ET3Wi7rLD687pVRYMhTDXlUP9vjaMX8K/7fyv1HCHMEP5kO
         CD5WtoJFBAqMXaDbaF5wHANbJBSp9GfoB+x4QC0XqPOa5iqjr4RV570YeBWfxAZfa08K
         HPUb9P7P0OOxrMDmTyo84WomM0VHRwYHBlZnUQbr82T06vF+LmIZhRhv3YWWHke8ML9i
         KPB4WCdQ0N+uTSfei/AkGEGg6Dm5QGpT3zvgPoudRt85wNL8J5TlrOCk3lmJhVRcIwXM
         bDHtoJpLllVoYDapcZ/jhEa2BdsoqgxQHdESmOJvPy9AqbXCO+jZiNhwhGs2ogVTezOn
         oGdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oa5yL+LG/6hMlx8sJ6eUdXk8H8NSqRj8fkPiJ1PytFw=;
        b=n2by3CTFoA8VVgVljakOQXF6vdRH+Qls5ixOtbxsGovjAVP56i/anTjKR/+oxkRuUS
         4uGnEw66Ze/I3jyVLkr/V3PCqMYGNIVcmv3K/JbfrjOLlGjVIt+VY5FuhP+0/OLa0YHa
         Cn7KXZRlYIBReK+AFoqyLb0adg796xLE81zI7yIZb1j4FCtDs9vBL1gjJrInEvvUe1xL
         vK3zQ6MmfhwMqoaVEkJnULJ5z1uCQRdfTN1ky/Se2T2vMxTwAvC5onIQQiecxt5au6yq
         HeqmjNTe5f7GdbqYIPT+RUXRVZRB2+3R0Frhff/gMg08pQRxvOnrZxOuJwnT/ubOs+5n
         jk8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OxGozl/wOM5/hu8+GymH9DB4Hjz13Cj4tvED3YqC6MslPFcij
	75q2jtTsIdTGgq07lVKNtl4=
X-Google-Smtp-Source: ABdhPJzsJEpuzyDLpRuClKk2zssvFjufs/KMJCPkxC2kIQw3y2LV5YKumTEG68GLE8l5OtCE9eR+2g==
X-Received: by 2002:a67:f601:0:b0:325:5b5d:d1d6 with SMTP id k1-20020a67f601000000b003255b5dd1d6mr16310478vso.4.1648578985459;
        Tue, 29 Mar 2022 11:36:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:206:0:b0:33f:be82:da69 with SMTP id 6-20020a1f0206000000b0033fbe82da69ls2059402vkc.11.gmail;
 Tue, 29 Mar 2022 11:36:25 -0700 (PDT)
X-Received: by 2002:a1f:a40d:0:b0:33e:cc56:70c6 with SMTP id n13-20020a1fa40d000000b0033ecc5670c6mr18548558vke.27.1648578981207;
        Tue, 29 Mar 2022 11:36:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1648578981; cv=none;
        d=google.com; s=arc-20160816;
        b=MHX5rHRNfPNIq4Dxy85ix5bt1/IdvBLdzmDnsQBg3K7A+UM1gYHr+Nm0Etrj6OP7dq
         QxmXq/iJEPbukEV6s+Vytpw/fKOkFMHbY5sWNgCpAYiF4rRheWEc0mWJoBQrHYD3LKJK
         otK2HNs/yGI5cfWB8KF6voB+pB0nXpxaEdKXZ7moPs+jJWzPUk3MrPvKFm1nFLXboQfP
         Ty58iXub1i15tmNAIGxmHXtRXyW7E7aKV9LEC1aa1f/cdw+M41ErdkmmiFO4ZjX9N2Tr
         wETzqgzDeowVtp1074iaVnwiynglyjTrC8RCfc1bNVyGlIdX+sqaXI0DqhJ32MngbuZn
         vNfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JUrhq9evNqA9x3IGobvT5hE7CTLMIVYRzbuHHy97Qyw=;
        b=hkwRNZY5ufxH/FLBrIcic85gEEfELtgCqRZCWCBJ2y40m+YorKu032eJ3XR7NtXU7k
         Ij5Z9M/YYD/gNNasxPugCEAlOuvrURkXqAJ98cnWsRCwPHmCJas+n2B33wad2ndn7uIU
         inUm/G6JtXebwNhbUu7ouatF7wW5xXs9xOgO3LDAcElECi/VeYq3dzDYt1lly1r1jTCo
         H3nN31s17qALizSKUh4krwA0e9Lok5baSIQ+FrEYC8jGpN29vASQNZwc2Tu3yMMq+kxK
         6P+VGvzFOcyf5i7EwPVp8YHKtjIFNOqWYFap4oazBm1k6ZHxPQ9PFV5WOy2mNXq05T9A
         egdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="nj4/aW6K";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2d.google.com (mail-io1-xd2d.google.com. [2607:f8b0:4864:20::d2d])
        by gmr-mx.google.com with ESMTPS id o13-20020ab02a0d000000b00345c6ac388bsi263389uar.1.2022.03.29.11.36.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Mar 2022 11:36:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d as permitted sender) client-ip=2607:f8b0:4864:20::d2d;
Received: by mail-io1-xd2d.google.com with SMTP id x4so22058579iop.7
        for <kasan-dev@googlegroups.com>; Tue, 29 Mar 2022 11:36:21 -0700 (PDT)
X-Received: by 2002:a02:b687:0:b0:323:60e7:121a with SMTP id
 i7-20020a02b687000000b0032360e7121amr8803432jam.22.1648578980752; Tue, 29 Mar
 2022 11:36:20 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1648049113.git.andreyknvl@google.com> <21e3e20ea58e242e3c82c19abbfe65b579e0e4b8.1648049113.git.andreyknvl@google.com>
 <20220325134629.99699c921bb8c8db413e8e35@linux-foundation.org>
In-Reply-To: <20220325134629.99699c921bb8c8db413e8e35@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 29 Mar 2022 20:36:09 +0200
Message-ID: <CA+fCnZfbDnC+tii5g+FGMDrMAz2vPmp-3LJG8q3T4psRJi3N4Q@mail.gmail.com>
Subject: Re: [PATCH v2 1/4] stacktrace: add interface based on shadow call stack
To: Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Mark Rutland <mark.rutland@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Sami Tolvanen <samitolvanen@google.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="nj4/aW6K";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Mar 25, 2022 at 9:46 PM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Wed, 23 Mar 2022 16:32:52 +0100 andrey.konovalov@linux.dev wrote:
>
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Add a new interface stack_trace_save_shadow() for collecting stack traces
> > by copying frames from the Shadow Call Stack.
> >
> > Collecting stack traces this way is significantly faster: boot time
> > of a defconfig build with KASAN enabled gets descreased by ~30%.
> >
> > The few patches following this one add an implementation of
> > stack_trace_save_shadow() for arm64.
> >
> > The implementation of the added interface is not meant to use
> > stack_trace_consume_fn to avoid making a function call for each
> > collected frame to further improve performance.
> >
> > ...
> >
> > @@ -108,4 +111,16 @@ static inline int stack_trace_save_tsk_reliable(struct task_struct *tsk,
> >  }
> >  #endif
> >
> > +#if defined(CONFIG_STACKTRACE) && defined(CONFIG_HAVE_SHADOW_STACKTRACE)
> > +int stack_trace_save_shadow(unsigned long *store, unsigned int size,
> > +                         unsigned int skipnr);
> > +#else
> > +static inline int stack_trace_save_shadow(unsigned long *store,
> > +                                       unsigned int size,
> > +                                       unsigned int skipnr)
> > +{
> > +     return -ENOSYS;
> > +}
> > +#endif
>
> checkpatch sayeth "WARNING: ENOSYS means 'invalid syscall nr' and
> nothing else".

This is done deliberately to mimic stack_trace_save_tsk_reliable().
I'll mention this in the changelog.

> checkpatch also picked up a typo in a changelog.  Useful thing to run,
> is checkpatch.

My bad, I ran it on diff instead of the patch. Will fix in v3. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfbDnC%2Btii5g%2BFGMDrMAz2vPmp-3LJG8q3T4psRJi3N4Q%40mail.gmail.com.
