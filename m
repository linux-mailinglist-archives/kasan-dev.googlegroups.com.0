Return-Path: <kasan-dev+bncBDW2JDUY5AORBGPS2CGAMGQESZ744BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AA4F453C85
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 00:04:59 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id d27-20020a25addb000000b005c2355d9052sf906216ybe.3
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 15:04:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637103898; cv=pass;
        d=google.com; s=arc-20160816;
        b=gyg2YvL8HgqCQqbxZhyJY+aLHllFffuF7bKePcY1lyTG/Q1VlVVEKuW5f5Cw9hbfXD
         qoWzev5hmyyFWMFsCIxgC+lkPg5sL3B51Py7kWiKIGYwz65HxIK8F+kSog7izun/597c
         AxPLoVwg6861PdALOUsvJ/RhBYFLnU6oFRZWHkbtZ7syc0DQa6IOXr9V/bgzAmplCQzu
         0dPp8V63iYl0DoI+Vv+uS9S+dBHoaeoLrTflcXSWPdf6KWAmJ5PsDolawL3iUXYf4uTO
         t6Jq6UuH64nl4IejOfZsXHyEuTLyNrVDThd/7KI50CIoyWGOLGKtjz1iYt/nAj5lRUVQ
         sS8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=53omGn+9V7zctNlomqy41E/A6qAtfi/anwEFGJbma2o=;
        b=B2MDk6O4uYsb/QXKRURSRKvHWoahow4lakWjpTIZeSugsYTg1+yuoYkMG31IhJZJau
         4ghMbYwp/4ttGGq8bcW5CuCa1k7kYkzP5wno9PG3d2pejNLBfuhJ99uaTxWg+Qpa/w+E
         atMAldgJ7jTgL2uPLMm4+CRbwnTsInKOFS0+2uCjqG8XP6wdEKj5hcp6Xzb1YHyqsXA4
         4A9e3UvsVNQmfgrK+KTptH7ly+w82EWewQhWUElASO8eZlx5k6gVGrx0Xon7Bz/0CiLX
         OrFuE48+CbbbduT47d3BZigTdUiCXESeoeB0Vf/1/qB+Gt4tIcx6XMVeOFZ55hIIWNPj
         LT1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="S/WK2x3j";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=53omGn+9V7zctNlomqy41E/A6qAtfi/anwEFGJbma2o=;
        b=iO0NAZTPjI+HIhZJuiKFfIkKHTvTnl36tgGT0c6ciJgR7bMikObqdi2oO2SsLb92OL
         wZnB2bpxFnUZAQpny5aVAZy3LyybHTnWeLqxbnTeBbWvW7ZGXHUxteyuPn50uIN2UiB5
         y7lmeIhrTmh/mAvmoev2guSIrrRczC3lxHinxxUsQrComRBAh6JJ5WYajnn+s2hU1mM2
         gFFQMxCE2643PRXMPdZjzi43qhq+IvEr/iX0gOmumHcKKYe7S5AvBwyQcr7tKX56hPfq
         iO50oUZSKsxulNYGvZvoP7R38+4RmR/kKMAvMnUfJT93jJOVa4lJsPArFNL8qR8YP81r
         BIUg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=53omGn+9V7zctNlomqy41E/A6qAtfi/anwEFGJbma2o=;
        b=MQ5gxnWxo84cEGIdoQTAX1Hh7j6+1CxKs0CktJ7a1SoW/qQKWS74oju8F4dzQ7Jfu6
         2EsZvEwxsmAIUI3mKfoKisS/tK8CtTZFIuZgscpOavpLjBUMexG0bGuHU064pJIuGKju
         ZAyYHGV533WXFIEvzbnHebcfEykaQ2i4Yno5f2sFlZBcAWE0qacjF5TLdPKdD0SV3Y1+
         rWe+fo6/x7LVYODWTtS/9MuxyrNElS7m9YwYjhYekc7LD5xVq5DJKTKA7EaLxbpenuqO
         COWhoPMeHVOyZTfMqNisWDauYCbnRbRr+/aqeWtR+tcyK05s0BhcSZWuIaJ/P4oOocTi
         jdkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=53omGn+9V7zctNlomqy41E/A6qAtfi/anwEFGJbma2o=;
        b=P0HZh16aZ865RV/kn5nkr4J3P4G4tWhbRN3E9AmwdRZoAZzfU0B+kQK6I31hafHhj+
         xMmA7xNKOE3/2scUMSt4uiQX1pt9wWYk5PgGU6zTh8V09pzBS/qvy9vCQG1Y6Bd9fMKJ
         Z7zSrxqMAJbhGolxn3F6hmQV5njb5YTeBTQY/IwL/7NZzsC0cJkGYKQPvNayLxiFkpWI
         qIGClatltZE5ero3B+wSSU3iCfp1Id4ekRdI1AIXBwPxdncgU4ad7FyH0WROfiRxmDUE
         pZxvWhcS9r6iNI2aczuD0gN+dpo2hEtxgmApH/OHCuO8e5A6Nq6u1z4ldWUdNP1ay2C9
         P/DQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531xf14nACuYCJyZgJDQyon8Widj2thDYhkG0D8NtsQ8SPQGkVJb
	4EhN8/dAxpMsRig8iccMzCI=
X-Google-Smtp-Source: ABdhPJy8UIyxaw+wkk7UC6Bw4wXyHIqsvhYNvdZOBIhKOZYMNAeSsBqEb9Hu+p5dCXuCaHrKPc4zug==
X-Received: by 2002:a25:d187:: with SMTP id i129mr12223975ybg.2.1637103898128;
        Tue, 16 Nov 2021 15:04:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:38d5:: with SMTP id f204ls12362750yba.2.gmail; Tue, 16
 Nov 2021 15:04:57 -0800 (PST)
X-Received: by 2002:a25:5941:: with SMTP id n62mr12102352ybb.420.1637103897645;
        Tue, 16 Nov 2021 15:04:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637103897; cv=none;
        d=google.com; s=arc-20160816;
        b=IssHRHvsMvkYY0PFOPH0P++xTYD11vqQCnQIGrjVBdpE473BTIJtRPeJ3QD1OIaR6A
         rj1OmMCAS+rmB+lxWMbzOQ2ud4VSFIcvYfYMrP7UN8q/SMnlUMOsPPIbOYKUtuXapZy+
         dNvUajGOqkld/RoeKoyo9Qtb2mx+Y2CFAXUKMNKPXG1G18clcN5hnBnNLrfzED5pliKq
         R0qs2OMq7H+rt9WDVFYsMx1UFpWS5Qv42uTVWHbnCZf/dnuzRdllVzKK8xxbDKI3y4DD
         xM3tlVEwqtFRbCpPzLITjE+mP3DZLt4XOJvCwgLP2UNuR7A/PlUV/e1UISNvnrKuTUqf
         p7ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=NCLmpq3O2WgfnqHHONPo5k+Xb63HO8UeUsJwn/lUkKw=;
        b=dFZXhqD+bsKtIwT2AL8kTTfrNgs472jqtnC/QdzR0A0cifMmzHWtF/9EXfOQS7Ii0J
         dqJ1hJk+KgxOG2UvAM4A1eJOM14KE66JlzYzKEj9JD7rOJV/siN9zKKPWaoIkwbwFPNF
         vWHT3P9DJdGu/sQ0oW/fwxWxwxXByp0v+CBMjyfOBLb1ttsx89f1VWbctl4hngva8PVA
         aiM+88dz3Oa1ntXPapseBLPQx+0H8htjKB3O6U3AJ6nIZb7YvvRdI4ckONIM/cBKOzFD
         ozZTnZHfpWr4w1Lg4v6/l4UbeOSIK9NZFJ3HL4w2KOuHG0/Nub6Lcw7GI34NQ54b+GSp
         xEYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="S/WK2x3j";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2b.google.com (mail-io1-xd2b.google.com. [2607:f8b0:4864:20::d2b])
        by gmr-mx.google.com with ESMTPS id a38si1384003ybi.4.2021.11.16.15.04.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 15:04:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b as permitted sender) client-ip=2607:f8b0:4864:20::d2b;
Received: by mail-io1-xd2b.google.com with SMTP id w22so688321ioa.1
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 15:04:57 -0800 (PST)
X-Received: by 2002:a02:b813:: with SMTP id o19mr8818638jam.130.1637103897457;
 Tue, 16 Nov 2021 15:04:57 -0800 (PST)
MIME-Version: 1.0
References: <20211116001628.24216-1-vbabka@suse.cz> <20211116001628.24216-22-vbabka@suse.cz>
 <CA+fCnZd_39cEvP+ktfxSrYAj6xdM02X6C0CxA5rLauaMhs2mxQ@mail.gmail.com> <6866ad09-f765-0e8b-4821-8dbdc6d0f24e@suse.cz>
In-Reply-To: <6866ad09-f765-0e8b-4821-8dbdc6d0f24e@suse.cz>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 17 Nov 2021 00:04:46 +0100
Message-ID: <CA+fCnZcwti=hiPznPoMNWR-hvEOQbQRjEcDgnGbX+cb=kFa6sA@mail.gmail.com>
Subject: Re: [RFC PATCH 21/32] mm: Convert struct page to struct slab in
 functions used by other subsystems
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Matthew Wilcox <willy@infradead.org>, Linux Memory Management List <linux-mm@kvack.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Pekka Enberg <penberg@kernel.org>, Julia Lawall <julia.lawall@inria.fr>, 
	Luis Chamberlain <mcgrof@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Michal Hocko <mhocko@kernel.org>, 
	Vladimir Davydov <vdavydov.dev@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="S/WK2x3j";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2b
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

On Tue, Nov 16, 2021 at 5:33 PM Vlastimil Babka <vbabka@suse.cz> wrote:
>
> On 11/16/21 15:02, Andrey Konovalov wrote:
> >> --- a/mm/kasan/report.c
> >> +++ b/mm/kasan/report.c
> >> @@ -249,7 +249,7 @@ static void print_address_description(void *addr, u8 tag)
> >>
> >>         if (page && PageSlab(page)) {
> >>                 struct kmem_cache *cache = page->slab_cache;
> >> -               void *object = nearest_obj(cache, page, addr);
> >> +               void *object = nearest_obj(cache, page_slab(page),      addr);
> >
> > The tab before addr should be a space. checkpatch should probably report this.
>
> Good catch, thanks. Note the tab is there already before this patch, it just
> happened to appear identical to a single space before.

Ah, indeed. Free free to keep this as is to not pollute the patch. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcwti%3DhiPznPoMNWR-hvEOQbQRjEcDgnGbX%2Bcb%3DkFa6sA%40mail.gmail.com.
