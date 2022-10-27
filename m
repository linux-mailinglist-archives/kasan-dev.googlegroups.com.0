Return-Path: <kasan-dev+bncBCF5XGNWYQBRBU5Q5ONAMGQETAXBGAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93c.google.com (mail-ua1-x93c.google.com [IPv6:2607:f8b0:4864:20::93c])
	by mail.lfdr.de (Postfix) with ESMTPS id 3C6F4610145
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 21:13:35 +0200 (CEST)
Received: by mail-ua1-x93c.google.com with SMTP id a43-20020a9f376e000000b003eac6b97cf1sf845430uae.11
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Oct 2022 12:13:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666898014; cv=pass;
        d=google.com; s=arc-20160816;
        b=Fb36UX3zNZ6o4oAcrkroe0/SUeYmUKMuVrJdGqKaUJS3sW84mjC5JcnM1cX/DIDI2z
         puZr5jHjndRHayPFxHlkIXViCSoVL25U9TpP7fCOJQRb3idiz5b5e7uWfFDrGG9tG+K+
         teL7YGz3/F42Y/XSQl3hQO77wbFTFplL1STBXhrYQzLNoLkVttG8k+7JLLMIxbCZqLkL
         63vxo1B2/mtrDecVl+blwApWpteHQF+3O28UfQ3K/DOHdwi722bwgI5E8vluKQ+NeXAS
         KlnChfSuQndDjf2v/eY8HE/tK25/4cwt3J0Nnj6h9qQ4ZNSP4b6cNhIcBBYX3DsuZnHV
         vQZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZGW6dmZkRHDGw1REd5ESHcR8xXqC2GOJ5n7tfGmcI90=;
        b=RwmLF/8da8PnnWowZ2qKX6PFiE0ltSGnHG+wjAYHIjIaxr9oN0MK3cMBWyQj/UvaqC
         gCb8TjLAXF4M3m3YKoXLzkglGri0gL7caFje/YMfUchLFc299y9zOC64Ai472p9fmA6O
         5Qd0tEd2lAkEXFBKlDJyG7/7lq8M4gsep8zsfwnCb5OdOIg8UwQQXi7jxk7ljHnTSSE7
         LHpsnH72R4lXs+lc/dvwoVj3eRTegVhVyv/1ojDBPt/wGiAwatUohH+Kx3jvdk3Cysym
         EamIUrurrmcv3NKAh4DvOWXptJzP8FqYG9DO0H2nhTtWBenFS919/BqKoI5QW6uwUIwl
         Vspg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ePBvbYsq;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZGW6dmZkRHDGw1REd5ESHcR8xXqC2GOJ5n7tfGmcI90=;
        b=N4Du0pqs+XfUgSInQntIaomzEXXT3d6sQY1IIAT2v/OOVWYv/5b06WpS8hLOIeZ2BF
         6oZ28sV65LwJlleDXWYbAhujKg82z1CxpCA1uPu88BwjtGJarEdXE5R82WlnNc1fJkiP
         nJuC6pHRQsYGVEbB3nsDEaDXeUrMBK8ISwXlfY+5voGtdNaNfWooMZ+nuIdOOXpn8QGi
         c6LzjdhWmYZX3OZhNYuGvIvUdWNxWKNTJduB5PTsLdKi0clr896bceCzsws0XHFGROtm
         t5v117p0VsGoyvVJPHxVPPMhVih4te29SfDs5nyNZd0vnqf343MSOJqEKQEMYtosBRJK
         zAYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZGW6dmZkRHDGw1REd5ESHcR8xXqC2GOJ5n7tfGmcI90=;
        b=MqZUuJ6OIpjnjMOrcBKAB/sKAPy0G7QxURmWJiofRa7ZwLvYn6ZTH2YO40p2qvJVnW
         ob0ewuNmuxf0zpxYq6MlGaQZEmCKNiQso+Ejx8Tp/rrGyDbBv54mr/ergGAKNI/juTFH
         po/IyJu33d8TGx0nuT3b5uahB5TyvQlCpfRPucl3EVcwOSZgW1nQ4R2Dgn24CNGvurYR
         lAC8Q0JP63Z+gdiX204s8q60SfV1OYW14ETuN6M8E/AQDz+3diX3N+ovYOJhBJH6pgiI
         lRma1Osl8PV+VJKfVRQP6IHB4GyoyLjvut5ESCLkj7zQ1bH+id90VTH3/EWf9M5Vyy7L
         /BKw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf1OLqreMYh6N8diFqInWl9EtI4uPfOqjEetx0PMJ8RP/xDqmN2D
	RhxD1Yqi+UouNUU6T2D7v6Q=
X-Google-Smtp-Source: AMsMyM7qRUuoQCV8cz/+CAHYqauiA9NEL6yxJbHAphUlsokiVBzgP+wX8thS3nHQqP6GU6eEjQMlgQ==
X-Received: by 2002:a17:902:ce91:b0:183:610c:1df3 with SMTP id f17-20020a170902ce9100b00183610c1df3mr49402050plg.51.1666898003357;
        Thu, 27 Oct 2022 12:13:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:17c4:0:b0:561:e77b:c7c2 with SMTP id 187-20020a6217c4000000b00561e77bc7c2ls14998pfx.4.-pod-prod-gmail;
 Thu, 27 Oct 2022 12:13:22 -0700 (PDT)
X-Received: by 2002:a63:1861:0:b0:462:4961:9a8f with SMTP id 33-20020a631861000000b0046249619a8fmr43890553pgy.372.1666898002602;
        Thu, 27 Oct 2022 12:13:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666898002; cv=none;
        d=google.com; s=arc-20160816;
        b=Of5m4RamdplrVMK8UaXTJfELCS6Y9mUHRsTeTc+Z5oUSVZFt7Kr+bxYNHDI2677Atq
         k6CgGF6BHqo1WwTCTSaZSYY37HU13xUJJEA2cpnmCb4XsOu6W06qbW3flz4LHPtGowWP
         IR0KFVQg159WnZJvIiO7u3rPkTZOvz6uSqHlp0hf1IkzhV2nkfW2tV54aqAMM9rvhoTF
         hAC1mAHj4aknfNYyH4GZYVK5CjfrK5lxJ4IneEbd+RFxkSb5iPZ8AYSOiHOPsi/gaGK1
         biKn0dVae3oLJjw3UMi33EBscnxKT7JrS6rgUPcG8EtJDvxDTZPacPdnKj5opEmFFHGv
         KXQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KRy9sqvf0ZM2bZpgrnftqxmIbppdN+rJl6H1sXbtcEA=;
        b=swSyBJpgPA4ZbgxGeGKOoQdrngmNOIABRIyabzf8x+1nmmpPcBaBIMOEV8v5m/kXmj
         4oe0zlzodDpzYwBA+g3IAhZiZUN4Qc1+zmM2rD2FswLM8RDf22+p2VxpAwVPNWX/fGOS
         gYeLv20byTfsNmUXJJA2+2yUTxbQIqPYp3qtoG/KLpIWFciKTJnQqGYvgjkwyoNwa3db
         WDy9UFcPN2xVLmhCNauHYkOyq8GjF5XMc/L/iQRXtdNAZjDL3ghHbRl9dY+T2ChGhuXT
         VlwlGBvYR5C6YQ7V8sJtHt63csfj50y0vWKOuzY6UIUbq5lOUpZUlUgeshpQJKRexGtN
         y0ZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=ePBvbYsq;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id nm8-20020a17090b19c800b00212caf6f066si233510pjb.0.2022.10.27.12.13.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 27 Oct 2022 12:13:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id d10so2584927pfh.6
        for <kasan-dev@googlegroups.com>; Thu, 27 Oct 2022 12:13:22 -0700 (PDT)
X-Received: by 2002:a63:7909:0:b0:458:1ba6:ec80 with SMTP id u9-20020a637909000000b004581ba6ec80mr44062420pgc.414.1666898002301;
        Thu, 27 Oct 2022 12:13:22 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id q10-20020a170903204a00b00176e6f553efsm1525222pla.84.2022.10.27.12.13.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Oct 2022 12:13:21 -0700 (PDT)
Date: Thu, 27 Oct 2022 12:13:20 -0700
From: Kees Cook <keescook@chromium.org>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Christoph Lameter <cl@linux.com>, Dmitry Vyukov <dvyukov@google.com>,
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, netdev@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] mm: Make ksize() a reporting-only function
Message-ID: <202210271212.EB69EF1@keescook>
References: <20221022180455.never.023-kees@kernel.org>
 <CA+fCnZcj_Hq1NQv1L2U7+A8quqj+4kA=8A7LwOWz5eYNQFra+A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZcj_Hq1NQv1L2U7+A8quqj+4kA=8A7LwOWz5eYNQFra+A@mail.gmail.com>
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=ePBvbYsq;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=keescook@chromium.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On Thu, Oct 27, 2022 at 09:05:45PM +0200, Andrey Konovalov wrote:
> On Sat, Oct 22, 2022 at 8:08 PM Kees Cook <keescook@chromium.org> wrote:
> [...]
> > -/* Check that ksize() makes the whole object accessible. */
> > +/* Check that ksize() does NOT unpoison whole object. */
> >  static void ksize_unpoisons_memory(struct kunit *test)
> >  {
> >         char *ptr;
> > @@ -791,15 +791,17 @@ static void ksize_unpoisons_memory(struct kunit *test)
> >
> >         ptr = kmalloc(size, GFP_KERNEL);
> >         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> > +
> >         real_size = ksize(ptr);
> > +       KUNIT_EXPECT_GT(test, real_size, size);
> >
> >         OPTIMIZER_HIDE_VAR(ptr);
> >
> >         /* This access shouldn't trigger a KASAN report. */
> > -       ptr[size] = 'x';
> > +       ptr[size - 1] = 'x';
> >
> >         /* This one must. */
> > -       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size]);
> > +       KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr)[real_size - 1]);
> 
> How about also accessing ptr[size] here? It would allow for a more
> precise checking of the in-object redzone.

Sure! Probably both ptr[size] and ptr[real_size -1], yes?

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202210271212.EB69EF1%40keescook.
