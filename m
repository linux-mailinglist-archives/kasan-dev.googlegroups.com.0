Return-Path: <kasan-dev+bncBDW2JDUY5AORB36K4WPAMGQEJ7RIB2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 573A86835EE
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 20:01:05 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id z2-20020a626502000000b0059085684b50sf7688511pfb.16
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Jan 2023 11:01:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675191664; cv=pass;
        d=google.com; s=arc-20160816;
        b=TkMmZgcWGuaIYXcFTtXSARE3MdYr606bEJN/e/hGibM76tvpoW5l63aGQUapwLwZ37
         QGKn5Asi46kz+hI9uJIpVpTpXe00EP62URExHvruN+TKmy8DNZLd2o8o/7XeTANnfhIC
         HQVDLPWNavd2zY2iFU0jPjb4m641Zh35TXlDewMvNh2Ro0Aw/bDEKveBYWt9BvlR5Pjs
         8ojLvwFEghlcyZfdKy/3+qnuErKvuwDtQ/JzuAh+AHGflDx1TyxER8HwM9YavUp4QZYU
         zOhzA4npAkpJ7IOyCC8YBl0zTwSv/Mna/CeiDDoPsIiAOtoRauyRtfhxXhUQNf9X480h
         h1Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=S5VVqK0vh3J2pZvHrpIg6DmoOCH9dlJvDGzMxIgTyy8=;
        b=y09Zs06mNPX0HrgNC+BrbQmVKfaL1k3GMMQCEmklN0EiH75Fye2BvuomPn1YDc/hfz
         5R/8+pxnMhZKFoKd3Vlfbdox9a8DRfjLutTSepWPYaIHMwH068+qQDbK7HMUmY8Dg6eA
         hn+94hSnui6Gj7H/kgmmKL9w7kfoZJ1hdJGVQf0JCUQ0coh+yAWcgzb2Xw58IOaQVp4T
         AF/fRq/gx8ZXzvsG7Dkl004jkWvHOdjkfulxMEdw3XwbA/Ghee47FehX9Bl8pJkBWjYy
         dykrw6wpobSWIJDE0EXz0qYQQz/8fzFaB2+caDsN3H9rgOCtlt2aC094wD1MUx/YV3W9
         xBwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=POpr6rtU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S5VVqK0vh3J2pZvHrpIg6DmoOCH9dlJvDGzMxIgTyy8=;
        b=K5yWZuBWCwQB/u62kx2z+o5iqOhvRkHd8QuLmGE0h2vrzeP9FhYcPnuiWefjqzfukt
         zoB4uYJFz2pZR9TVyKw2kcUdvVEh0VWsDtIoN0LBBO13yW8EEHAdXsyo3NFCD1bCnJAW
         ju612HQ2ex4NNQBfpay7HtgAJvAXBNJfs4fefqueQ6SQDKAsubqiAbD0xhn7uYL9l7z1
         TxSNmTCfpsINTXeJIB7UF6QpCwVuCTKDZZ1TUXdHVCa0SBFDCTVcVqL4FIVrouKGNilx
         rVHZhiy/MQdAF/LeqNxEdUb8ZnEybVrV3Kbj+qY37tKkiPLaY3CEkQx9mwrVJdwt0Qw1
         Kg0g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=S5VVqK0vh3J2pZvHrpIg6DmoOCH9dlJvDGzMxIgTyy8=;
        b=bu1Ehvt/5PFXSX3c87SaA6aZ4+GMPI/gyTL/k/oneu0gVtP6f/y/deblRA5yc5qvq6
         HVBDBFeKcAtW2tc8MAR/aT/yjmvECauAIhw3qwU6b5EpeSt78b/LV1hLtHD6V00poXxx
         gcgAvsbU1Zu9XJQfmwYsQNNS2Ni27hkg1zKu9Njfb3qummy8oA+vzRDKFUdcnP6SBlv1
         Roqb25gkNWBGZmaBdqQ10Am+0EhhpcO190GJwIFnxATo501BZpIo1IZIzHQWdgSnRUln
         P7nsynGCUK1oe0shPcyy8NW5+ffmX4DjNI5k6pCkaFFLTQtKf62vLIT8mLM82vUGoglJ
         YjFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=S5VVqK0vh3J2pZvHrpIg6DmoOCH9dlJvDGzMxIgTyy8=;
        b=OFWUfuoTX+kH2A9up1Ttj+ko1ALy9eM2LLQoaxJQ4Ns8DuxglRSFR+K1TBAc2nUdRR
         IsH+oPslOYGwFWCPoVGFOdL6YWaz9C1u5RNgGjx09SB1ka/gKwbFY5QLthHh84/Z7r+1
         3R3+cFl0kG77IW/wMOrTKJrLOA9N6LzxhZF7nVBzNtCNYwmfs/R9U1t7tcGjWsteB/su
         2jpQkNR6lbHq7oI8FU+SUonIwddDC9fpBcGg/6cNp0ZZ+ck3kWwVUvKTSao95xahWDbr
         D9XDO3c+dfOsByiCHY4TstUOoqSGlEb8uhke73re2HcPaoEYbgUoc57mn2rNIA98eOq3
         eeHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKWyESsa9bWtFvccbTnYhV7aBJ+gsTAWn+TP5AQeqiFM759MDHuw
	4q1xBqh7AfH2s8d+UOYFe7U=
X-Google-Smtp-Source: AK7set/zsFovmfP6RispwiwuxiFmQWargnNhG2bKC9q4xe4PvSChfUkVMSC+Kkl4OUVmT9Qz226Xuw==
X-Received: by 2002:a17:902:ff0f:b0:196:1c45:6fa6 with SMTP id f15-20020a170902ff0f00b001961c456fa6mr3730197plj.25.1675191663939;
        Tue, 31 Jan 2023 11:01:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7c88:b0:189:b2b2:56d5 with SMTP id
 y8-20020a1709027c8800b00189b2b256d5ls17407809pll.0.-pod-prod-gmail; Tue, 31
 Jan 2023 11:01:03 -0800 (PST)
X-Received: by 2002:a17:90b:4c0d:b0:229:4dcd:ff61 with SMTP id na13-20020a17090b4c0d00b002294dcdff61mr121061pjb.28.1675191663151;
        Tue, 31 Jan 2023 11:01:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675191663; cv=none;
        d=google.com; s=arc-20160816;
        b=pfHRfsyyJm+V/xaZVD6u6QvvbBIT86QO9RZIkyJV/ZhNUV26MJhwp8uKEAAUA5HAwq
         W+sXE8Sg2b18ow+lehjnvyIHDMahLzhlwk4TpeGtF+pt79VAkZ8RYz/QnxthhdndCISK
         /XAe03smBbTlREx7//6UeF5vKHlrzOMBhW66W1aUbabpz6LFDRvl2vxxow/LAyhjPtc8
         2jBt4+jc2+78q8+NCQ5qJWORKo27aM+RpBGSXmRZkP+P4RKcaRmNZTS+W74XZJ5ATjhi
         AaVyO4xj75zalkx9m8lWcMGi3gPq4M4/sFVNqOJudXqYmcQTbdsJY4oawT9EW/Kh4oQb
         03Xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=b1NzJQj+IlX2uUKAqxA9aAlIl32T8LLkBO2KdikgTrw=;
        b=HIzXPlbueP66CKVwmzlcdNlXXwssA2izsC0hzt8/hDYon+bMPxuskbB4PBFof0JebG
         7yticnXlen/9p3EEdB7iPb4bbmQfJc/l0Hr0Gt9KArRXEyf9G5ZXTjjlzZbZKJUey7u3
         IhDX6nTpaWhdwSY7rnW6zq1FSI96iuhFQ95potS79K+GBS6OcVOo7Rokfe9IrdQmnW/T
         MFBk4DfLkoZqCXEBW0+pfY0d4OCJ+2JbXEgy6pdYxHy6Z6c8cvIS+BjHwno6yY5zuF/K
         VHxxq9+imyO6qSF6UZGCzO5AgKFgE7Ub5THsh1fYULdL2yttqo0glyYd2KAnxQKbtZIp
         SvpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=POpr6rtU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x102e.google.com (mail-pj1-x102e.google.com. [2607:f8b0:4864:20::102e])
        by gmr-mx.google.com with ESMTPS id gz18-20020a17090b0ed200b00229ee755cffsi191696pjb.2.2023.01.31.11.01.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Jan 2023 11:01:03 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e as permitted sender) client-ip=2607:f8b0:4864:20::102e;
Received: by mail-pj1-x102e.google.com with SMTP id cl23-20020a17090af69700b0022c745bfdc3so8806025pjb.3
        for <kasan-dev@googlegroups.com>; Tue, 31 Jan 2023 11:01:03 -0800 (PST)
X-Received: by 2002:a17:90a:cc5:b0:22c:4462:fb92 with SMTP id
 5-20020a17090a0cc500b0022c4462fb92mr3207848pjt.44.1675191662752; Tue, 31 Jan
 2023 11:01:02 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <9fbb4d2bf9b2676a29b120980b5ffbda8e2304ee.1675111415.git.andreyknvl@google.com>
 <20230130161817.a13365bca60543e34da27f48@linux-foundation.org>
In-Reply-To: <20230130161817.a13365bca60543e34da27f48@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 31 Jan 2023 20:00:51 +0100
Message-ID: <CA+fCnZcu8hjK8GQ0j2UnWFjyED9ys52pFG7zbnuRkUzGnP2BGg@mail.gmail.com>
Subject: Re: [PATCH 01/18] lib/stackdepot: fix setting next_slab_inited in init_stack_slab
To: Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=POpr6rtU;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::102e
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

On Tue, Jan 31, 2023 at 1:18 AM Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Mon, 30 Jan 2023 21:49:25 +0100 andrey.konovalov@linux.dev wrote:
>
> > In commit 305e519ce48e ("lib/stackdepot.c: fix global out-of-bounds in
> > stack_slabs"), init_stack_slab was changed to only use preallocated
> > memory for the next slab if the slab number limit is not reached.
> > However, setting next_slab_inited was not moved together with updating
> > stack_slabs.
> >
> > Set next_slab_inited only if the preallocated memory was used for the
> > next slab.
>
> Please provide a full description of the user-visible runtime effects
> of the bug (always always).
>
> I'll add the cc:stable (per your comments in the [0/N] cover letter),
> but it's more reliable to add it to the changelog yourself.

Right, will do this next time.

> As to when I upstream this: don't know - that depends on the
> user-visible-effects thing.

Looks like there's no bug to fix after all as per comments by Alexander.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcu8hjK8GQ0j2UnWFjyED9ys52pFG7zbnuRkUzGnP2BGg%40mail.gmail.com.
