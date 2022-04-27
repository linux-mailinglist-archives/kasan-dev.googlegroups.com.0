Return-Path: <kasan-dev+bncBCNY737244PRBLMFUSJQMGQERZHPZDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BD3D5113BB
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 10:45:34 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id t20-20020ab04ad4000000b003627cd606a2sf572027uae.11
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 01:45:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651049133; cv=pass;
        d=google.com; s=arc-20160816;
        b=WbRz2GJoEYSxbbl8Q/CQDS27ri4Y0mVeaVMcZG6UcEEaqB35G2HiQiZ0ieA0SkekbM
         QV/agBPhBRN5DZPzIqLOAsIBmfVjmh2a0hstlxMycwCD9icA1nbAoaJ4WUjpwqZ/18fc
         b0Eaa1p6d0cSFg0aZKY7rzZa+ydvezlp/Fn+7AXfUWwNAdWfcWfOk9O3INroBDdQrWdt
         FHOIDirJ9LCCTphi5PsW9uDvZH71hkzJFtxQN3dDqDOQL59pIQQ1d76v5H/aqLtkbpBL
         c4rOLMqFAXbVze3QqyWQSG8nf6zkjCM8uUSzPqeDQfdC81vp9gYMUG0EsnyWz2KHJcDR
         M7+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:subject:cc:to:from:date:message-id:sender
         :dkim-signature:dkim-signature;
        bh=ocan3NifAyCCRsTIkYnHblHuE/xa8qPy9toJTy58Ixc=;
        b=G8CysGWAFnTV92ElNEszpL2Rir6T2kD3QQomyhppZNeJ5fPg2s6g8nePRPFCLwr7o3
         eRmo639qJPjfMuu7fpLR830RcPFXjqvywlSNH7L8OSSXdlP2NeU9JC/88O1IVuGhjATH
         4L+GrCiDv9sxZurcVa2lruTS3VM/L8fBVUi+wV8YEqIvUhj5v3agw4SilNloJ5ySwfgv
         OjoQ+5EAvz2hFLs7bwR2y17YwTrSPyTtJKbWDpa1uUHPFJiZHCh1BzbIjBbhskf6YV4U
         bBvycDvUtloxDDktoYW/PdsrEQ7toGu0dhgIYF4xoJr1M8XmSaFFNNpLgzifa7OtfI/w
         9Ltw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YiudLauj;
       spf=pass (google.com: domain of cgel.zte@gmail.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=cgel.zte@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:from:to:cc:subject:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ocan3NifAyCCRsTIkYnHblHuE/xa8qPy9toJTy58Ixc=;
        b=czPUrIhIf31MWcp5BytfNNLA488ko/hOoJyqEnk5NoRs4+k0VCxYVA3+/jm2lMM63+
         eED03HRbQVvMH5sBd1z4CJNauUd/BUdUYcO9+1jdv9+1+3tT82xhFgvfdiD4i7qpVAv3
         aA+FGCt7FHSr5ggH9gOXodum7HUeMCY66OAgFj5O1KE6CeUVYOz5gVndtdb+41MmtZSI
         FoGx193eoQzekFM8uB2MaApIKz9ILmn5v+kRPo+YvnnZ4ZBpamD/q0quHVN+CtslhgXV
         YUns+qIrbGkm1/GTzklDe8AyG9ouZuHNPitve0w1Yx8koZUuPOHNBOsLJ595nV6MZL4j
         74+A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=message-id:date:from:to:cc:subject:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ocan3NifAyCCRsTIkYnHblHuE/xa8qPy9toJTy58Ixc=;
        b=KjmEp8lwzRfG+3TJorn8uXKFFUqADLHvt4LD89gTQPa6AuvyntkSc0cB2lQIMbRid8
         Pq5uT/gyuzmARjIQJP7Rm1PlRyh0x+Fd/aFXBS52THNDMNDnlGaHQlYxbYHUm6e0i1Hc
         PNpv3Pw5b9uTYrOKL0LB0QG0Itqy8vP8pUxrMAxX8OfpWl+RNHawJTtv3C7sdtPaFTHf
         1eLfKCGT+m7YsQ7gUW3Z2thbuW1h6DwQ3Yol/nCQaoBPkq2jlRTdO75b3QGdAGxdOpT+
         SqUvYexxYL3+3i3c9iVGlskaqnIliVFYA8YvfBfcHQKT7Rnv7WjGC2Bt7xagl0BazEvA
         DVdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:from:to:cc:subject
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ocan3NifAyCCRsTIkYnHblHuE/xa8qPy9toJTy58Ixc=;
        b=G4dz45LZTN3FGeXhArLCHbRSwpgcOkNBigD+ETMWqOz/6gVjXVebLBMEQaARVuv0IA
         rzXIwUwkeB6zk5MtN/hrtg2mGwXO5kKoGZjt9xDmRPom3LfUF12xfX3Lsahb82DrPIhB
         iMvnHuv6xmPV+HiO4iKrwPpKBDOtxMeFgvLbPRpQeUkTAXmRD19seuHuZiFR4XTEJSQh
         1Nh6BnzPD9P9o+PlnoL/Edn14Qf0ue1J7i84DtNLAy+0K5jzei6sAxxH+YoQ//Iv2kFT
         y8aUwVm5gfp5XaNbsJt8r7s3tI9nhPFMLGm17BHdD5iniF+Eundx4cP61XvTz1s6c5j1
         5cWA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530P0aeSM4pNl4tItzWvTyZu9hhCzdQfZufIzsKKZMueR/SE+GWP
	P170FQH2RQtuDWBqA8yAzt8=
X-Google-Smtp-Source: ABdhPJzHFE3dcz7w4oi/YzcHoBuFXAUpb2eicSxQuypZh4D8EwDgLsqCC0JVpA0EoJmNm/O89t0Taw==
X-Received: by 2002:ab0:d95:0:b0:35d:4d4b:c59b with SMTP id i21-20020ab00d95000000b0035d4d4bc59bmr8150083uak.97.1651049133392;
        Wed, 27 Apr 2022 01:45:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:1945:0:b0:328:1375:9d3f with SMTP id 66-20020a671945000000b0032813759d3fls377273vsz.9.gmail;
 Wed, 27 Apr 2022 01:45:32 -0700 (PDT)
X-Received: by 2002:a67:3312:0:b0:32c:b9cd:6c97 with SMTP id z18-20020a673312000000b0032cb9cd6c97mr5744219vsz.62.1651049132757;
        Wed, 27 Apr 2022 01:45:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651049132; cv=none;
        d=google.com; s=arc-20160816;
        b=DgsFO1DjmHTcYj/0+TOxG9gTPUV2N7w1367QpD2UeZK1wiRFWqrC9IU2XxpqtDceKQ
         aZHPpfyKq69TQmiU4ssJlxfzjJfT1NggKVTSNLKhqgk52ODVe/19v6NevOQUYPvVgTnV
         X6e0+qnzwgV+l3uRRsUfIgOxRFeFuhQD916xk1nTe4N0MedyvQGg4PBB366mN9wdKprO
         9usRJPjJHVuSLMVhzyKpuUCrmzVMNiSWiEZJ/ykm4iCT8ymy8XXRr28rv2LznICfEzwc
         repbrMC9udq9w/MXgC3WeqboeffDUJ2RN0nOiw18A4i26XLltiQunk2FezPLn2eJRi+m
         JGyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:subject:cc
         :to:from:date:message-id:dkim-signature;
        bh=RB8+FqJ1IEgAxvX3bqMX+LwZyBF33/dYNV+lewufcOs=;
        b=Bi1OcEYcIpYbN3V314ffeQC4WwygSVAYfV2eAQS2KWBPG2igoUTs5P8YB1E8Ch8b94
         7Pgghn5+JSm0QcMeOpRAMIe4vxrV4g+3BNSjKvQKS0a3X3FJZEap3br0YGCXj2I28MMf
         2qKiYSGarSSu1BzCcLJhwiKBWRwv7sY83mtV1PzPdQ2828uEynAH2f19ynzDPFOKo+xu
         P3zB4j7aOmZzisWC626Y8CYd0vBI5yJsNpTm/TPOdPHBNdwwMIiq9ZvPbSrvw102Vxh3
         p6m/PqflNqT7PiwcwGverEayJeMjn1Dlc82QHo/rXkyky1e7mDfVKlEbzBITbU8qP8om
         ZE4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=YiudLauj;
       spf=pass (google.com: domain of cgel.zte@gmail.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=cgel.zte@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id m2-20020a0561023e8200b0032cddd78670si149649vsv.2.2022.04.27.01.45.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 27 Apr 2022 01:45:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of cgel.zte@gmail.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id hh4so642209qtb.10
        for <kasan-dev@googlegroups.com>; Wed, 27 Apr 2022 01:45:32 -0700 (PDT)
X-Received: by 2002:a05:622a:284:b0:2f2:bf5f:4bd9 with SMTP id z4-20020a05622a028400b002f2bf5f4bd9mr18174425qtw.503.1651049132446;
        Wed, 27 Apr 2022 01:45:32 -0700 (PDT)
Received: from localhost ([193.203.214.57])
        by smtp.gmail.com with ESMTPSA id p12-20020a05622a00cc00b002ebdd6ef303sm10061443qtw.43.2022.04.27.01.45.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Apr 2022 01:45:31 -0700 (PDT)
Message-ID: <626902ab.1c69fb81.44f01.9c06@mx.google.com>
Date: Wed, 27 Apr 2022 08:45:29 +0000
From: CGEL <cgel.zte@gmail.com>
To: Marco Elver <elver@google.com>
Cc: glider@google.com, akpm@linux-foundation.org, dvyukov@google.com,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, xu xin <xu.xin16@zte.com.cn>,
	Zeal Robot <zealci@zte.com.cn>
Subject: Re: [PATCH] mm/kfence: fix a potential NULL pointer dereference
References: <20220427071100.3844081-1-xu.xin16@zte.com.cn>
 <CANpmjNM8hKG+HH+pBR4cDLcU-sUWFO6t4CF89bt5uess0Zm3dg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNM8hKG+HH+pBR4cDLcU-sUWFO6t4CF89bt5uess0Zm3dg@mail.gmail.com>
X-Original-Sender: cgel.zte@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=YiudLauj;       spf=pass
 (google.com: domain of cgel.zte@gmail.com designates 2607:f8b0:4864:20::829
 as permitted sender) smtp.mailfrom=cgel.zte@gmail.com;       dmarc=pass
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

On Wed, Apr 27, 2022 at 09:33:52AM +0200, Marco Elver wrote:
> On Wed, 27 Apr 2022 at 09:11, <cgel.zte@gmail.com> wrote:
> >
> > From: xu xin <xu.xin16@zte.com.cn>
> >
> > In __kfence_free(), the returned 'meta' from addr_to_metadata()
> > might be NULL just as the implementation of addr_to_metadata()
> > shows.
> >
> > Let's add a check of the pointer 'meta' to avoid NULL pointer
> > dereference. The patch brings three changes:
> >
> > 1. Add checks in both kfence_free() and __kfence_free();
> > 2. kfence_free is not inline function any longer and new inline
> >    function '__try_free_kfence_meta' is introduced.
> 
> This is very bad for performance (see below).
> 
> > 3. The check of is_kfence_address() is not required for
> > __kfence_free() now because __kfence_free has done the check in
> > addr_to_metadata();
> >
> > Reported-by: Zeal Robot <zealci@zte.com.cn>
> 
> Is this a static analysis robot? Please show a real stack trace with
> an actual NULL-deref.
> 
> Nack - please see:
> https://lore.kernel.org/all/CANpmjNO5-o1B9r2eYS_482RBVJSyPoHSnV2t+M8fJdFzBf6d2A@mail.gmail.com/
> 
Thanks for your reply. It's from static analysis indeed and no actual
NULL-deref event happened yet.

I'm just worried that what if address at the edge of __kfence_pool and
thus addr_to_metadata() returns NULL. Is is just a guess, I'm not sure.

But if __kfence_free make sure that the given address never is at the
edge of __kfence_pool, then the calculation and check in
addr_to_metadata()  is extra performance consumption:

	"index = (addr - (unsigned long)__kfence_pool) / (PAGE_SIZE * 2) - 1;
	 if (index < 0 || index >= CONFIG_KFENCE_NUM_OBJECTS)  240
	 	return NULL;"


> >Signed-off-by: xu xin <xu.xin16@zte.com.cn>
> > ---
> >  include/linux/kfence.h | 10 ++--------
> >  mm/kfence/core.c       | 30 +++++++++++++++++++++++++++---
> >  2 files changed, 29 insertions(+), 11 deletions(-)
> >
> > diff --git a/include/linux/kfence.h b/include/linux/kfence.h
> > index 726857a4b680..fbf6391ab53c 100644
> > --- a/include/linux/kfence.h
> > +++ b/include/linux/kfence.h
> > @@ -160,7 +160,7 @@ void *kfence_object_start(const void *addr);
> >   * __kfence_free() - release a KFENCE heap object to KFENCE pool
> >   * @addr: object to be freed
> >   *
> > - * Requires: is_kfence_address(addr)
> > + * Requires: is_kfence_address(addr), but now it's unnecessary
> 
> (As an aside, something can't be required and be unnecessary at the same time.)

Oh, I'm sorry for this. In my opinion, inner addr_to_metadata(),
is_kfence_address is executed for the second time, so not necessary here. 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/626902ab.1c69fb81.44f01.9c06%40mx.google.com.
