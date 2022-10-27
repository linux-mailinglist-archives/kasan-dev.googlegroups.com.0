Return-Path: <kasan-dev+bncBDW2JDUY5AORBXO55ONAMGQEODGNVQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EA3161034A
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 22:49:34 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id cf23-20020a05622a401700b003a4fe88a9casf1473642qtb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 13:49:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666903773; cv=pass;
        d=google.com; s=arc-20160816;
        b=SbZKBTESWydmIVMObSqU1qYn0oMsWH+CLaviUfkbt/MUjqdeAJMhMAcH8b8NBxUfZR
         MiXu/E1OYKmVUl6A1ievsz4AE+n4MJR3WATVGTd249IIIFi1mWuN+FQr+iUskg9072sj
         ewEyA/mTxKaD4q9cj46pITjg26JQgxmGgfbFctCc36pF7bFxMS0S5yoNgLOXuK7PtOoM
         6C2aMs/TKsjVVSLRQ1kdxj28XX7GuuTYCbeCJs6k2Q1ijJ3SpnhaS4J2SlFHa2y6nBJf
         OQDZ2P43+nVM+FQXgbl+7KHg6masBoH6WVnxFut2IHtrxGZbHa+eV331693mMMv6B/eT
         +6lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=Faw/XM1FD5ro5uMJrd2qhU/+MVmVl+VzM1vg+xPs2aQ=;
        b=R1/kDJLwjGkBMjAchtry32MayLOJzrH80AhQkiFC3zwgs7XsBsOUir4F39che6GB2L
         yfD8bvr03xcqsrx3onX1heCb8I6W7F0Xv74KrAnnOeJlPv4vFCaPa15XN/a0ZhLzTLKO
         URsbt7kDee84BhLxoi949QGcq4xvrAj2E/lkPiPSmkIaVg0av3mBBdRYq7WnFoxVnhfC
         o+J6f6XAHHO1aquVw/I1lOcy3x4Uk6ct9KYI2i3hCKfy2JiFatBbQJsjFG8mq7rlbENz
         qsKZk0VkB5M9EqV/tUcvfor0MYhda4OIiPlwwRgE11kxoyW1mfBcUrghVwxHYKhia8Os
         lDIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lGZ+sBWR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Faw/XM1FD5ro5uMJrd2qhU/+MVmVl+VzM1vg+xPs2aQ=;
        b=fs0Y476A+iV4i4yHcvDxfHyHSWgKfHWXM5dEwGol3rqoBky5C4P0bg+iyce3X5hm0+
         BPE4Yg6mV9lSLgF2bHoVlYklgH58r7I3ahV80WC1075FbgcpjitrTLuW4US8C4msB+Nc
         8V1srqsMYyI7Z8Plv87/F/GdMS34lNnhIjK0BjFnq1bGwnrcBw6TVESNJqDDKAqLVHKb
         SRcJ1IH/a+BkgmfyRdp3nIyUQPY76kByrh558O99YsM6zeZrsTPbdnq9EKszOmKlQkLV
         2bRoiazFqGGE1wVUylAxji62TgG7huKzb4Cghk0TqBIcuq+6mcFhxcSEdwit4KX2v9oS
         7FwA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=Faw/XM1FD5ro5uMJrd2qhU/+MVmVl+VzM1vg+xPs2aQ=;
        b=pzYAiPg5peiEe/JJGS8tvYg0omMgnJ0mPcV6qLFU3s4jLZrlbVyy8ygKgYQNKASM7i
         OrRkZowvZcGB//gDmvndtjKKIwui5xj+7TCDxT7lMT68fPNpdFHiA/X6xJVxnFN2yHbh
         u5GlDdm18MuehSG/k9xN0ZUdEIBeZt3Kn2a/IruyvDBiQp5O3BLVDDJc2+fq4xVsKHgZ
         gB1WuKOS9pY/4sYEpjqh1gK3j60VDFNvbHOWb69YjZZfua44DPf3nn1EYcjPR1lIv9QX
         JZ9gcEMrcnc77NTPOlNXdTdaj73mV/+2aJUxC8/k9v6TM03AyjtEFH99dfwkpWCmQ2lY
         t5wQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Faw/XM1FD5ro5uMJrd2qhU/+MVmVl+VzM1vg+xPs2aQ=;
        b=z3aOQn7SrfYUffke6Rd2Zy7DgOLWuEl10R/Jq//S4zKSsLGWivvBcqIiIYQM2rkgQX
         PZN+ctYDWEj7CGbDQfFnw4PGOZWH789WXMG7cCtF6JvIRRVhlvtjyyhOIMQK1/Ljar9k
         aQ1em8o1CiNXMeX0/bUY2WksSzp0o78TVpKSz2NQa5krMXXknG7xf82WCd/l8XbYY9RV
         jlbdquJ/WW8CUuRO28ylJcfYiCbGdIHFJVsSNG3gsUd6b6frtgkhDBnyid83droIuaDc
         PyzXD4qMORIS8tZUQQt8maU+RX8Djt3KkBkrOxP6FwA9jVkuB8YHo/xg0S3mK3W48yHe
         W69g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2K6B5GVOsjVwbhAGuRjraPCKob08bRqSt7HRyk8ormTLcvb+tm
	/JQtBdDkvJx6T1JGYN8A22E=
X-Google-Smtp-Source: AMsMyM7z92iyn+aDlrUy4+wRjxr5ppoXT5uyrJCYIuP6QTVXeGjws0MVcZp8aGqCOG/guAKXnP3Blw==
X-Received: by 2002:a05:6214:c21:b0:4bb:9fea:f545 with SMTP id a1-20020a0562140c2100b004bb9feaf545mr4796660qvd.73.1666903773245;
        Thu, 27 Oct 2022 13:49:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4d0a:b0:393:55f2:caab with SMTP id
 fd10-20020a05622a4d0a00b0039355f2caabls361470qtb.10.-pod-prod-gmail; Thu, 27
 Oct 2022 13:49:32 -0700 (PDT)
X-Received: by 2002:a05:622a:389:b0:39c:e87e:903b with SMTP id j9-20020a05622a038900b0039ce87e903bmr43621985qtx.392.1666903772760;
        Thu, 27 Oct 2022 13:49:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666903772; cv=none;
        d=google.com; s=arc-20160816;
        b=aeY/E+AeDI5z7J+3DUHglF75y1+msGJvI9aZkByD76AJsrHTRm1I4HZ5shs2FM9Xg5
         XPcYCuPILp7Yrf7rsiXJALBNffQCL6XGOqd8VZGic5CdpAAfE7l8HW5Wk9qEc6FpXeLP
         s7dxs31vLyyPxZc+L8/lJjcbRGWh/bOO2cLW4WpQPdaCYhf0mdEHOnOgpl9QRvVfqBmx
         v5+deOLmBbc3qa/wTtEkwaJVrJvq+J5BQssxD2Xu5Q9E4yDUVKlzJIjT3fYROEnoTU0h
         C9Jc2ETA6H9suUMsqTlOnmrfQYx/doYLC+Rn5tZ2ZZbPqCMWD1qfOCuwLrBONUOXQqpr
         hn+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6gMhKdjIcVkb7+wRScD/tsvQKFhD8+gTEKVp7SkZezo=;
        b=M+8yzbl+TdtZ+WNzMsiyOhfOxyR+3ZgyOxXW4g6z9egEUwoIIhGaNcDwCFndMWm4ah
         V3Kc5qsBBO6rxdFZyQZleJVmVFwZmhGJ7aqs5hcVoTD4VFmR9e9jH2pIHqnlmSZkJzxi
         7SmHNkieotggNwWOfnXZyqZBzc1fUNeOEQb8kh/bkn3Kj59lX3kuim7W+stxqKX8Xod2
         yN8x4skrJdxvxKL4XrqmrlSg2UzSbwnLmgQDAkBcJg+1bOCgYwShwBRArzWf/GEvXwR3
         uElWF8OimiaXRr5bWa1QZEMa6ZzXIKWS0lNCGrfO4wQcQg0lG6Sn3Vp6NEQAFce58gpg
         T1qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=lGZ+sBWR;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oa1-x2f.google.com (mail-oa1-x2f.google.com. [2001:4860:4864:20::2f])
        by gmr-mx.google.com with ESMTPS id z2-20020a05620a08c200b006eeb0d15906si100117qkz.6.2022.10.27.13.49.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 13:49:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2f as permitted sender) client-ip=2001:4860:4864:20::2f;
Received: by mail-oa1-x2f.google.com with SMTP id 586e51a60fabf-13bd19c3b68so3872838fac.7
        for <kasan-dev@googlegroups.com>; Thu, 27 Oct 2022 13:49:32 -0700 (PDT)
X-Received: by 2002:a05:6870:c182:b0:12a:e54e:c6e8 with SMTP id
 h2-20020a056870c18200b0012ae54ec6e8mr6661840oad.207.1666903772503; Thu, 27
 Oct 2022 13:49:32 -0700 (PDT)
MIME-Version: 1.0
References: <c124467c401e9d44dd35a36fdae1c48e4e505e9e.1666901317.git.andreyknvl@google.com>
 <20221027134433.61c0d75246cc68455ea6dfd2@linux-foundation.org>
In-Reply-To: <20221027134433.61c0d75246cc68455ea6dfd2@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 27 Oct 2022 22:49:21 +0200
Message-ID: <CA+fCnZfKmy1TTFEodbPG52ktXk819_zo4S5e6rcLyfQYJDPjWg@mail.gmail.com>
Subject: Re: [PATCH] kasan: allow sampling page_alloc allocations for HW_TAGS
To: Andrew Morton <akpm@linux-foundation.org>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, Florian Mayer <fmayer@google.com>, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=lGZ+sBWR;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2001:4860:4864:20::2f
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

On Thu, Oct 27, 2022 at 10:44 PM Andrew Morton
<akpm@linux-foundation.org> wrote:
>
> On Thu, 27 Oct 2022 22:10:09 +0200 andrey.konovalov@linux.dev wrote:
>
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Add a new boot parameter called kasan.page_alloc.sample, which makes
> > Hardware Tag-Based KASAN tag only every Nth page_alloc allocation.
> >
> > As Hardware Tag-Based KASAN is intended to be used in production, its
> > performance impact is crucial. As page_alloc allocations tend to be big,
> > tagging and checking all such allocations introduces a significant
> > slowdown in some testing scenarios. The new flag allows to alleviate
> > that slowdown.
> >
> > Enabling page_alloc sampling has a downside: KASAN will miss bad accesses
> > to a page_alloc allocation that has not been tagged.
> >
>
> The Documentation:
>
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -140,6 +140,10 @@ disabling KASAN altogether or controlling its features:
> >  - ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
> >    allocations (default: ``on``).
> >
> > +- ``kasan.page_alloc.sample=<sampling frequency>`` makes KASAN tag only
> > +  every Nth page_alloc allocation, where N is the value of the parameter
> > +  (default: ``1``).
> > +
>
> explains what this does but not why it does it.
>
> Let's tell people that this is here to mitigate the performance overhead.
>
> And how is this performance impact observed?  The kernel just gets
> overall slower?
>
> If someone gets a KASAN report using this mitigation, should their next
> step be to set kasan.page_alloc.sample back to 1 and rerun, in order to
> get a more accurate report before reporting it upstream?  I'm thinking
> "no"?
>
> Finally, it would be helpful if the changelog were to give us some
> sense of the magnitude of the impact with kasan.page_alloc.sample=1.
> Does the kernel get 3x slower?  50x?

Hi Andrew,

I will add explanations for all these points in v2.

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfKmy1TTFEodbPG52ktXk819_zo4S5e6rcLyfQYJDPjWg%40mail.gmail.com.
