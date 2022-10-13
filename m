Return-Path: <kasan-dev+bncBDW2JDUY5AORBMFUUCNAMGQEVUCKA7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id BFA2D5FDBD6
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 16:01:22 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id a20-20020a17090acb9400b0020aff595f9esf1122780pju.5
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Oct 2022 07:01:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665669681; cv=pass;
        d=google.com; s=arc-20160816;
        b=PSssA1MAlJ1o0ECAX0JxNdkZfoHGQ4v9/aNFtXBvurdX4PZaLVuA3MhFMWKZ4JgaK6
         DveMRQcgOElq7NqBcj7ZL+emJHdSDzDdDIIM72pExXF6rhIYhbgaAANk0xRgGeojv8FE
         t+zVud+c0hAvSQMjV1O/uhS+k+99/jGTTQEW4G1072oYzkOYA1o9lP59jnbh+028ZJe8
         /+HY4+RGCt8KibUorUYNT4U6CQGe3uaCp59qpOo94S00/W009N32lDLxaCf3U77BHtXp
         EBeG5cYavTGo/pGUBH1Xnt15O77vIIPfru8pNH+uZHpfo0wM66ks5kImWjlmn6nW9gVF
         170Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=As4GO+bMitRSzn6io3o/F9OFqgUqw30fFsFwY974pLU=;
        b=HzYcrjVsKKiz3THjOq+diqzr3dnzkLusi7RvN+QuZVG1Yz2nycOHrQWn4zcEnIAmU5
         JfZN/MVRthtsLsUYlGkJK9eCMZS2Ddtx41nl/e6hYj+UrCnzOwmIRDUVM4izLHcrzRaK
         oQOertgLlnDyFyuz4JDKatI8AF784vLSBif3hVAmCp4/UgrPnTtTbNBfKNbulUCowRjv
         J26HFMP2WH28ai14pLPam4RgoVWoBa0yBzCN9cqj85oSjyXjFahsycEqDWdD+l+aB+27
         d+vIqGohIJEbOOQeca64KvbRxG6flCw2DknfbiBWE2b+eTuUARDsvb3lbQlqtg2PZ8KD
         6RLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Kcak6tm0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=As4GO+bMitRSzn6io3o/F9OFqgUqw30fFsFwY974pLU=;
        b=CDo2G3MydXIgwspjUNvLHl0BrSGumT5+d8T5uI/OBfdxDiP/gNR8smAeAjy9EppXPQ
         X0DMSnst9XntsIl2KjYdHRLxdTWEWqpo4fgyKlGLHPJ1tep56of8ffHI6UE1K+qYFev2
         gQuu9r5x0Lh0SGjGEiRyb3ytxRtPN5dSAR3qA5TnbWWDBPukiDZBmUFomSBv39jvkY19
         k4NKhdCeTJ76aKmfQ3G2mg296zdkNDCBqlW+sjal1XLm3wiMRT8UAn3K0nK/Bs7jZYvN
         jg2FC2gi9LXrciC0Y9/ltja5TKXQbIhYGgMul/wcnxDUYGbucvRsKpOQlMEpHIAfNBnf
         /PBQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=As4GO+bMitRSzn6io3o/F9OFqgUqw30fFsFwY974pLU=;
        b=B84Ngo5AxhTdSeQqZc70MtxfYenWgC/qIa2c9csO9c1y3+8V+puE3RAJ+niKzSY1Rj
         nqhx/TaV60XVvUbiNj7Hc0KPpI5oRx0X7IGVEXRIca7OH23DUPimJg0h2iJSi8mMF2+e
         Qq7yEQVG7CGvB+/yrE2vhxtU0RIB0WrjB8rd52grko3MPjhjjAVW97RuDbr761HcOeYp
         5VZCbP9be2nRBWZFb7gxixsUK/CroY/sXrLu/Zvgyqp5foxHE3kdWTlN3MUukrSTEvVP
         Q3l0a2lAxBxgPhS0QlH0ZvF6wu2x4SnijzEpvmDF/UXL1hIh775iTmcwO/4MN8nlmuMs
         7Pfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=As4GO+bMitRSzn6io3o/F9OFqgUqw30fFsFwY974pLU=;
        b=37mpuDrDyntt1wHaLIloK4+4zohEGj6hl3ZVTLu7TGgwZz/0V112bvNcuUcYiPRbkk
         VlTZ0XHB0YAf0PYebEEKbjGaekbtd518hBNEUxkDHR/c/74N34kzkgwSUqf9uONZH1RE
         QHGvu1NfelMHLCw8tSjdaRml74qK8DHQ5i+tLc4MyORCqi8dCbp1pTaHcSVTb6DcEVvv
         SgRl0DU/3AZNg5P1HAFyaWOdiq5DQXNTG1te/wrGZYMDTF2FONl6oT1ZSThUJWWus/TO
         5eTWdH85XfPh4WXfiK9Gxa5vPSHwyYLjZNGEXW5lQ9525P47E+B6GjXfonKDOnkZYe0d
         BGSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2mezuNGCpS0tdae5vwb5EyIAkdpanwICF8gjw3jIv29QTnAC3v
	BqRF8tHPorZeYOwspXEqgWY=
X-Google-Smtp-Source: AMsMyM7tpVHSy/lykIg6Y8KpJeJUxFqVsIkjx5k9YnV3zu72YWUSuI/EXLdTbZf32heElz4jTa2OSA==
X-Received: by 2002:a05:6a00:705:b0:562:b9e1:d0e8 with SMTP id 5-20020a056a00070500b00562b9e1d0e8mr34766414pfl.0.1665669681062;
        Thu, 13 Oct 2022 07:01:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:198e:0:b0:541:d22f:4f4a with SMTP id 136-20020a62198e000000b00541d22f4f4als1228978pfz.10.-pod-prod-gmail;
 Thu, 13 Oct 2022 07:01:20 -0700 (PDT)
X-Received: by 2002:aa7:8299:0:b0:562:4c48:a0cb with SMTP id s25-20020aa78299000000b005624c48a0cbmr37704237pfm.66.1665669669625;
        Thu, 13 Oct 2022 07:01:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665669669; cv=none;
        d=google.com; s=arc-20160816;
        b=GUAy5IjwQDrhUBKwfTRrFLmgIHVTr6TWLYvurt5g1STpwu5n3XRqK618j8MzMWyDHr
         q2quXV07457FN1uFjkZLZlj62+3rs+gWCWjRwz94qP/4v484Ga55J5mwfh0H7PljQM8/
         /r49D7vv9ywe6ukbiPw6Z0g2N9dqiRc4WuA5ycOvWiBU4UAs9+A89CVCov8/3tNpJx4Z
         39znE4t3XBwDjNMxeCteJIgf+DaucRFmZ4ZnOfnwxl3FbNVY1HXKFqIIwb3KEWaoMSib
         MTXQIvT6t62wi6smOkicGOR17aqOifZmnVX55xIfdMh79joXok/EJ0t6kSacrGL8Skqc
         fRxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/q9HFSGdoaZv7OXKTbYpwwK8nkInj5DxOSaXWkZAU+U=;
        b=pz6sarTDcIzKbAGNapLHfdvzvS1iI7+jt0PHQytwgsZynUZKsQMWDs1kSSQ7HxxxLK
         qVXeCdgISith4twOMdGwSuyiyMJOcjrBG2sxyZFwvDx7VpepwbGdraXqJr+bIFvI7EMK
         5i5r+frWULx8RXKe1FqQKTGlpnRgfbLq1r1GrC0pb8o40X59JzgILsyUIM86W5KG1mXY
         sEDW2O80/qGCPa4PJt30dbYH5owcXqvXArAjmCL6UGdDcuZb91MDwXPZ0oLhB/UMlAc3
         DCd7IyEjLHLg2C0+uU8+hQ8lFa7Vd85SFbTnPAYkMVvOrlPkpeJ63HTIUyBd5PCd30b2
         HXUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Kcak6tm0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x82a.google.com (mail-qt1-x82a.google.com. [2607:f8b0:4864:20::82a])
        by gmr-mx.google.com with ESMTPS id l12-20020a170902f68c00b0016bf0148e25si677722plg.9.2022.10.13.07.01.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Oct 2022 07:01:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82a as permitted sender) client-ip=2607:f8b0:4864:20::82a;
Received: by mail-qt1-x82a.google.com with SMTP id g11so1144038qts.1
        for <kasan-dev@googlegroups.com>; Thu, 13 Oct 2022 07:01:09 -0700 (PDT)
X-Received: by 2002:a05:620a:d94:b0:6bc:5a8c:3168 with SMTP id
 q20-20020a05620a0d9400b006bc5a8c3168mr38151qkl.56.1665669668750; Thu, 13 Oct
 2022 07:01:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220913065423.520159-1-feng.tang@intel.com> <20220913065423.520159-3-feng.tang@intel.com>
 <CA+fCnZfSv98uvxop7YN_L-F=WNVkb5rcwa6Nmf5yN-59p8Sr4Q@mail.gmail.com> <YzJi/NmT3jW1jw4C@feng-clx>
In-Reply-To: <YzJi/NmT3jW1jw4C@feng-clx>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 13 Oct 2022 16:00:57 +0200
Message-ID: <CA+fCnZdvqZzCU_LO178ZsPDvs-Unkh2iZ4Rq5Amb=zS31aWFpA@mail.gmail.com>
Subject: Re: [PATCH v6 2/4] mm/slub: only zero the requested size of buffer
 for kzalloc
To: Feng Tang <feng.tang@intel.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, "Hansen, Dave" <dave.hansen@intel.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Kees Cook <keescook@chromium.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Kcak6tm0;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::82a
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

On Tue, Sep 27, 2022 at 4:42 AM Feng Tang <feng.tang@intel.com> wrote:
>
> > > @@ -746,7 +747,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
> > >         for (i = 0; i < size; i++) {
> > >                 p[i] = kasan_slab_alloc(s, p[i], flags, init);
> > >                 if (p[i] && init && !kasan_has_integrated_init())
> > > -                       memset(p[i], 0, s->object_size);
> > > +                       memset(p[i], 0, orig_size);
> >
> > Note that when KASAN is enabled and has integrated init, it will
> > initialize the whole object, which leads to an inconsistency with this
> > change.
>
> Do you mean for kzalloc() only? or there is some kasan check newly added?

Hi Feng,

I mean that when init is true and kasan_has_integrated_init() is true
(with HW_TAGS mode), kasan_slab_alloc() initializes the whole object.
Which is inconsistent with the memset() of only orig_size when
!kasan_has_integrated_init(). But I think this is fine assuming SLAB
poisoning happens later. But please add a comment.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZdvqZzCU_LO178ZsPDvs-Unkh2iZ4Rq5Amb%3DzS31aWFpA%40mail.gmail.com.
