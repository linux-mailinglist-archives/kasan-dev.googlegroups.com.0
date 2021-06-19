Return-Path: <kasan-dev+bncBD7JD3WYY4BBBONCW2DAMGQEOVDI7YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C52A3AD82B
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Jun 2021 08:39:54 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id g17-20020a0caad10000b029021886e075f0sf6423200qvb.15
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 23:39:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624084793; cv=pass;
        d=google.com; s=arc-20160816;
        b=ig5/z05+kzRAMqfSjFCMy2r2Xau4gD1Rvgs+bH1P4dNl64MMW7ajeFS4rGAmO9aVN4
         eTdhKhXUWBiqac4ZQBVNeZ8WIoGeRJRZkdKbjmS7UPDdW63LOYZ/qAePjycxotZUVkB9
         Rc7glzLg89U9l/YCk2w8xStqTmnC9hPLp93REGgSVflOnyoKko2Xjyab9Zp6cZf7Mvc0
         Q/YUs8alwh+XhHXWz7YBHO6pIsogMaQXt89ueQyjgde7PUjr4avx5LdCmvta6Y4m+mgD
         mm4Of5X1gE7Y3G1LyJtUmJmhO3zMaddKsMR5tXxlhKuWVOFfh6NsSxbsSQuHC4y8s03f
         j1Zw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=WbisxdDrafHL8Z3tn/FC9DezyoYWehmMgqEKahXDoIw=;
        b=xaJaLWcBAqs3EfxKdKVYUhtejGlmMyrxVmxJ4tjUeMZum67tKBYydsopE2/AhEcMrF
         lch26AhIpTzXxq4XO7Xde2hWD7Km5CNgnWuquqw0gG6cF29nnN9Tvv5AADZ2lZ12HviB
         IXQSfbDBwu3xfrdcPEU5TYbQaNySmTmaOXlDlrvJsrlb6I/njh5t6TK78nSZBgwpyaKG
         JKyOvG86jr79L9ll7WwGlK0YCsJU1uw0+4OSpeego1R2SiiGvTxi+XLlm60GFfNM8/DK
         9h/CUF1zOELHSRpJhcMvOep3jRdde/Qm+PZU6g9NZ/U8iFjDAHArVddtqO5zzo2pn+FL
         1A5g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="Tq/B3Mqq";
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WbisxdDrafHL8Z3tn/FC9DezyoYWehmMgqEKahXDoIw=;
        b=YNyRLVZ8h/LJet7MKDGxQJAGirQPq8OtjsICmF1WN9rtqcI6OvWdpYAnhrqXp33zHH
         79q6Lh5N9zfYZhL/RKLHaCz8xyqDys+EzPlBnx18lM+kkx77wVDd5OkuG25fKb89UrHQ
         +r0TBpUaV3fHIpziUw8xOrTcXoN1Useyvie1c5/0pSf3NO5zD17qDMT+G6ylsH5j2Mu8
         CoFPG8LwDNMlhJq3jrPpQfgBPYqLgEKUejq9UP87GSbHAbeEMvc0tOK7A0ajcA6fZroT
         yzRjgRiQKSD1HO4F22Lwxr5rYd4fI4xQ2QFbSRFxnSf1GaMHasTYaW0d2d5epnoXmVXf
         TCkw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WbisxdDrafHL8Z3tn/FC9DezyoYWehmMgqEKahXDoIw=;
        b=Uso4Vr3Bzz6OR6WcjC3Ey2Vrvm3Hkdeu/dI5QcuV17U4IXN5rQgKrHVQ20o9Zc9RRu
         BHBmsIu1lEMeoUcZBhIWgGwRnJ2ClVbbc7E4YAzLynwimAZwf0BCp8D6YUJTUqfRZie8
         ecLfVjs3fVX8nHv3M5jdwq/KFIstreB0SJssOq1U81wC1kmd9B6UzHtQRxWz5H0ai5A2
         YKYzDvyB6E6+6ukm78wbywk3NaLQ0iNAYhwr0L4Fj9RGATFxCl0gHGE0yoNyI0FuiKG9
         +gza3pagVdCL8OB/3V1Y8Q7dUkYlKNmuhYeXajRB703aEI2R6PzcnFmsFpA1zAYm0Svi
         6JiA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WbisxdDrafHL8Z3tn/FC9DezyoYWehmMgqEKahXDoIw=;
        b=KYbUPZgnMZe3XWfK/wGtLLncv8+doWPDFWIoZAsXDpbhwQpvzIeDAGMUWudxO10bms
         TB0g7NPAbuYU5X5vkeK8/8Pgn1pJ2dLosn0r+6PNfTNX7P/zfomlG0Nbgu9iR3EDBOj6
         muh8lXS9pKANYDyv5l/L8IHR7b/AvzJGMZdCIiIF5T6uaQQcor8FOT5Ay6m7CTrUEdc4
         GYIeumM1KT8vXnvRKTSxh23RAqyH6Eu9PHI/WO+ktzViTRlTRRFRgQomXnBadeubmimh
         vv6Tz8+QzgMWheL6i/k2hWOL22lNstqYA4yVuA228LFGRSuOcgP+NRiaxSBrG8Ae/1by
         gYLA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5316WBzO3on5/mtHV7fs4mjECmtqFrlWVcl+hr1GhKk6eCVJo3Mh
	MZKfSf8IKWNj9FYmK6immX8=
X-Google-Smtp-Source: ABdhPJxLwsiNCB87xF7ARI/WRFT8kkgUrDF6UypoZEUzvvfRL3YaqxqWpaOZv1LR/iwaDbkbs9Ks3g==
X-Received: by 2002:ae9:ef10:: with SMTP id d16mr9080577qkg.200.1624084793205;
        Fri, 18 Jun 2021 23:39:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4e96:: with SMTP id 22ls6232595qtp.1.gmail; Fri, 18 Jun
 2021 23:39:51 -0700 (PDT)
X-Received: by 2002:ac8:5ec3:: with SMTP id s3mr14068086qtx.312.1624084791714;
        Fri, 18 Jun 2021 23:39:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624084791; cv=none;
        d=google.com; s=arc-20160816;
        b=RQvcpgmDsKhHSIUQkelj9FL1vVcat3a92zUgS7RYBZpN7n+24wOQSqw9e0brZ2wU6k
         kawNi9g5//MnWx4Rj4RjrHr0NGPMBPZxhI/f0B46tJ2wDiluIMZsusvkNmtxc8cTLxZn
         P0RpzebxWlXydkl+a32PmHGhc0PVY14PLhHHrITPWOmdv2TogPlrK6jDVAVxutoymWJH
         b6wNiUetoQMUTQMexyE/YXJLFjQon+bL/SSIO/HpHVVK2MMZ8WKyJHUff2XyEOQYPbKh
         BRQDOUArabksgtibG79qOB82UAPGYB7nvlJRzoLiKBluIXi+j0bOYgoqpf9YuCL59zlV
         KWag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=7O6NiC7BTr3eVGuJkmQkcqtgkrwhWl7/Qlj0XvSRQpU=;
        b=mtVKz9ZZ/dybKQrl9vaaEm1frOvmBNBIYCq3GSSn1GyTUtvNmiwK/XlkEhIwPncC9q
         4pb+jstZ/x0cri1xSC3J5nQX1DJzfQRHd1a3rrlDEjBuVHY43GyMdSMuJxtDtNRQlAJO
         9+wYdIx+OuiAVSvt20+wQydIC0LvXhgPXfSWD6zSvTEarQba3fZNbG+wrIw9Kq0Y5L42
         ISf1Fj5hT62SHc7Kg4HICcaMst/M44eWVv8BETm/wCHSdQWmhl7ZN+WpvHl/fyBsTOwy
         DFNk05vV1Xcfix8gBHKtRF7NwZncx06uLizjFq8W+EOIYNA8hlCsPzQ2gf8KIGifbnj+
         RDrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b="Tq/B3Mqq";
       spf=pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62c.google.com (mail-pl1-x62c.google.com. [2607:f8b0:4864:20::62c])
        by gmr-mx.google.com with ESMTPS id o20si551070qtm.2.2021.06.18.23.39.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jun 2021 23:39:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::62c as permitted sender) client-ip=2607:f8b0:4864:20::62c;
Received: by mail-pl1-x62c.google.com with SMTP id x22so4259252pll.11
        for <kasan-dev@googlegroups.com>; Fri, 18 Jun 2021 23:39:51 -0700 (PDT)
X-Received: by 2002:a17:902:9a8c:b029:113:d891:2eaf with SMTP id w12-20020a1709029a8cb0290113d8912eafmr8117146plp.61.1624084791379;
        Fri, 18 Jun 2021 23:39:51 -0700 (PDT)
Received: from DESKTOP-PJLD54P.localdomain (122-116-74-98.HINET-IP.hinet.net. [122.116.74.98])
        by smtp.gmail.com with ESMTPSA id t13sm3566599pfq.173.2021.06.18.23.39.49
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 18 Jun 2021 23:39:50 -0700 (PDT)
Date: Sat, 19 Jun 2021 14:39:42 +0800
From: Kuan-Ying Lee <kylee0686026@gmail.com>
To: Marco Elver <elver@google.com>
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux Memory Management List <linux-mm@kvack.org>
Subject: Re: [PATCH v2 2/3] kasan: integrate the common part of two KASAN
 tag-based modes
Message-ID: <20210619063942.GA67@DESKTOP-PJLD54P.localdomain>
References: <20210612045156.44763-1-kylee0686026@gmail.com>
 <20210612045156.44763-3-kylee0686026@gmail.com>
 <CANpmjNMLzxMO0k_kvGaAvzyGoyKxBTtjx4PH=-MKKgDb1-dQaA@mail.gmail.com>
 <20210612155108.GA68@DESKTOP-PJLD54P.localdomain>
 <CANpmjNOf8i6HPxFb3gjTrUWMh_6c4zdsh29izrSrHDi9ud4+gw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOf8i6HPxFb3gjTrUWMh_6c4zdsh29izrSrHDi9ud4+gw@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: kylee0686026@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b="Tq/B3Mqq";       spf=pass
 (google.com: domain of kylee0686026@gmail.com designates 2607:f8b0:4864:20::62c
 as permitted sender) smtp.mailfrom=kylee0686026@gmail.com;       dmarc=pass
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

On Mon, Jun 14, 2021 at 10:48:27AM +0200, Marco Elver wrote:
> On Sat, 12 Jun 2021 at 17:51, Kuan-Ying Lee <kylee0686026@gmail.com> wrote:
> [...]
> > > > diff --git a/mm/kasan/report_tags.h b/mm/kasan/report_tags.h
> > > > new file mode 100644
> > > > index 000000000000..4f740d4d99ee
> > > > --- /dev/null
> > > > +++ b/mm/kasan/report_tags.h
> > > > @@ -0,0 +1,56 @@
> > > > +/* SPDX-License-Identifier: GPL-2.0 */
> > > > +#ifndef __MM_KASAN_REPORT_TAGS_H
> > > > +#define __MM_KASAN_REPORT_TAGS_H
> > > > +
> > > > +#include "kasan.h"
> > > > +#include "../slab.h"
> > > > +
> > > > +#ifdef CONFIG_KASAN_TAGS_IDENTIFY
> > > > +const char *kasan_get_bug_type(struct kasan_access_info *info)
> > > > +{
> > > [...]
> > > > +       /*
> > > > +        * If access_size is a negative number, then it has reason to be
> > > > +        * defined as out-of-bounds bug type.
> > > > +        *
> > > > +        * Casting negative numbers to size_t would indeed turn up as
> > > > +        * a large size_t and its value will be larger than ULONG_MAX/2,
> > > > +        * so that this can qualify as out-of-bounds.
> > > > +        */
> > > > +       if (info->access_addr + info->access_size < info->access_addr)
> > > > +               return "out-of-bounds";
> > >
> > > This seems to change behaviour for SW_TAGS because it was there even
> > > if !CONFIG_KASAN_TAGS_IDENTIFY. Does it still work as before?
> > >
> >
> > You are right. It will change the behavior.
> > However, I think that if !CONFIG_KASAN_TAG_IDENTIFY, it should be reported
> > "invalid-access".
> 
> There's no reason that if !CONFIG_KASAN_TAG_IDENTIFY it should be
> reported as "invalid-acces" if we can do better without the additional
> state that the config option introduces.
> 
> It's trivial to give a slightly better report without additional
> state, see the comment explaining why it's reasonable to infer
> out-of-bounds here.
> 
> > Or is it better to keep it in both conditions?
> 
> We want to make this patch a non-functional change.
>

Got it.

> [...]
> > > > diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
> > > > new file mode 100644
> > > > index 000000000000..9c33c0ebe1d1
> > > > --- /dev/null
> > > > +++ b/mm/kasan/tags.c
> > > > @@ -0,0 +1,58 @@
> > > > +// SPDX-License-Identifier: GPL-2.0
> > > > +/*
> > > > + * This file contains common tag-based KASAN code.
> > > > + *
> > > > + * Author: Kuan-Ying Lee <kylee0686026@gmail.com>
> > >
> > > We appreciate your work on this, but this is misleading. Because you
> > > merely copied/moved the code, have a look what sw_tags.c says -- that
> > > should either be preserved, or we add nothing here.
> > >
> > > I prefer to add nothing or the bare minimum (e.g. if the company
> > > requires a Copyright line) for non-substantial additions because this
> > > stuff becomes out-of-date fast and just isn't useful at all. 'git log'
> > > is the source of truth.
> >
> > This was my first time to upload a new file.
> > Thanks for the suggestions. :)
> > I will remove this author tag and wait for Greg's process advice.
> >
> > >
> > > Cc'ing Greg for process advice. For moved code, does it have to
> > > preserve the original Copyright line if there was one?
> 
> Greg responded, see his emails. Please preserve the original header
> from the file the code was moved from (hw_tags.c/sw_tags.c).

Ok. I will do it in v3.
Thanks.

> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210619063942.GA67%40DESKTOP-PJLD54P.localdomain.
