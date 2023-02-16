Return-Path: <kasan-dev+bncBD52JJ7JXILRB3MYXKPQMGQEZ3LV3RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 446DC699D56
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 21:05:03 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id o11-20020a170902778b00b0019ad833d8a4sf1566664pll.15
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Feb 2023 12:05:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676577901; cv=pass;
        d=google.com; s=arc-20160816;
        b=mN/0mNioHPV/xyILcIuMGQL8IJQS9bcOIWPPmsmJdRkuYI2yOAjlOGpZK2wP/Z6ZOY
         PdEM/3FPvZDhwx6U09mmqAZ/Ifkxz+XAnsyeT2A9WOagNaJWyZS638EwT6+36rqx041R
         oMT/SRx9pZRMV0NNRCpUt06i7uvMnDR4NGfc2nYjZqrOB5de+uNjl0tntYRiYehsnW5o
         4Ck4ctXtv1jRBFqciZIeJmA7eSNRxe6z2bKK477F4xwk2sV8li0obFKdmkE0kFoaTRv5
         ZxkIqHA5PiLQdpBty64npcRUTnx+tqcW4rXo3wXSA7aV094+Mitgss+L3c5ndvc1Ogq+
         BBBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Yp5/xq9T5jt48Z5eLcAx0VfwJi6PCUGNiofNObNa75k=;
        b=Lja/GWTD+6G9Qj0F3j5r8lvxDVJI52OjFHNDFvlR01kmHa77zCnH8Efana8jamSeva
         Wy56ahivZqhJcKSsa9fhBrgnTrUztC2YZbL8rAc+HOxq0AyjiCqJYFHqp6BNgpBZrUAD
         sOl+eRcYIr3FAKmHhF/lskjV6ZS/tFlHQ+knshIqpR9XhKFxsmEK26+d+edVmr6AzUhL
         Cqez4ObzSDYoZBCfwxWrhEayjOOnGteXFckOAxkCNOXJCmcE/XF02yI1Ux9luMxzJzPG
         o3wWhr+fQxCVwbcKKcbRYPGDfEIwd8V1E9Lw2cEq0xVKNGhYIezkMmV/MzshpbXfE38s
         /Sag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="IO7Z/ogd";
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Yp5/xq9T5jt48Z5eLcAx0VfwJi6PCUGNiofNObNa75k=;
        b=eD5QWu4oBLYCDSovKD54smkax5pyOqGbo6pipHWB9d5GzJ1W/QpmFIJNAkNQhTCGFh
         pWSy1M5nE87fXesarupo2HsIsLReX5WzMCKJl8mv9zCzHrDbxDPCKJ2XVhpWr5lcwMaC
         MLLEJ1JvCOZgZ2vz95xY8bAzG2nLalDDEBJhq4Fvg9ROC4PYbieWlB2FRS9dYQ8ABl94
         /d8c7xfqKfF1nzU9RRJVbYnip73/qBUk42FUXz9IHEAgLnI08DT0qSb4TXPh9RVliLHY
         pDe7Q8aJTzz5172Sk49y2zri8mm5fvoqD7W/jAsVhu0cM6MdutL/cIrBUkNzoMWaV2Y8
         epGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=Yp5/xq9T5jt48Z5eLcAx0VfwJi6PCUGNiofNObNa75k=;
        b=XJuW89wM5mWxoYqP6HQnkCJNUcCvLVLFWTOkmOM5d1HhJL1uPR9HqZZLD5JNpW1Piq
         p1IHXcuJc5eN6gcfJ5F1y/nwX8XPywWXZJ4KoUmeZwsW2Q9nHj0gBCERs8vHEHKRtHou
         axBI2bHtrnwTikCsoc/4G1L0YUTrVzCgc4JbxQhmByKlGNzdWPYHuq4rsw31Bo8JhfBI
         kofoTFJunP0DeGBaYCSg7Ufu32/IPIbDRFhmtNGnM/8u8ZkaAWpDg0c1XpHM7H9vJl0A
         iB+h0bxVxdieD6391P0iehNKfZpGN9LgYBdQ6sNQaurh3qhZt2YkuPZeCgHlnh+tJRHn
         D5xA==
X-Gm-Message-State: AO0yUKUH1jD1CsI7KkJkDepVw49pR8ZTILm8Bibqc9ZZ3doVsknDIZtF
	mDz6ZnpX9Vx/Rbf/33yLjJA=
X-Google-Smtp-Source: AK7set/fTjd++f4RoeOQfIvXWZ2Zf6GvLtk9R81O1k9uhaEp5fgeKGKa1Ft309Eu12mNXg4hlXk1Ug==
X-Received: by 2002:a17:90b:1bcf:b0:234:8e6:b56d with SMTP id oa15-20020a17090b1bcf00b0023408e6b56dmr1050604pjb.18.1676577901486;
        Thu, 16 Feb 2023 12:05:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c8f:b0:233:cf4f:61f4 with SMTP id
 my15-20020a17090b4c8f00b00233cf4f61f4ls6993888pjb.1.-pod-canary-gmail; Thu,
 16 Feb 2023 12:05:00 -0800 (PST)
X-Received: by 2002:a17:90b:4c8f:b0:234:84ca:7f7f with SMTP id my15-20020a17090b4c8f00b0023484ca7f7fmr4143325pjb.19.1676577900706;
        Thu, 16 Feb 2023 12:05:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676577900; cv=none;
        d=google.com; s=arc-20160816;
        b=P+LJl7+U9GX6l5zuOMj0OyjiKuObRPwZwSNirhh8k2qC3ha56rrdEhVSKdoPanW0aX
         Kr5lj9/Numv/0emgKx0JT6vQ+Z6eFX/gfrLXdsj+POqYTR5A7ilWDdijSR0xTZNBpHfp
         TpOdpa7YvinozmDEkFeUZefYFYtv5RCIY6a/lkLTuxIqnOpHhbrYr7xX08ayKQEj+ZQ5
         N3YRePG7yd2slmW7fRRoujNfw8JZVk83Z0E4JN+cfuqsr9PJdRfkLAxOl2VsV1MMvopM
         l50JdWjYn2IfOB2TtC8EyRWd4jTec8DxPee0jCXC06MPGTUUqQ5xpUzp188VfAKU7hpl
         MGCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZXLBzcq5UslgJ00UvUCCU57RnpwIblDHU0uzHLJsyPE=;
        b=rZVHHPN7dyXMqkvjx4IQzovpS98TLRY/jP8ZBVh3YIxq+65cY1lhOtpQV7LVqPi9El
         Q/cT52k4NtgztYGj2D3+OkPQSu3i3mwOj5MMhRqpfLHu3V9c7IQJF3oByYEpwDHZTSPG
         bcITS1te0zgL/wCThH6SH60ZBnfPNWh1w3KEZ27xMIDvFXDVioqKEI39qXXa7qBcg9Ly
         ScB1U5zTYarqplIHHgksBYm2xKQQ903lZdtd8V7HWFQe5D49/DIyPOFdmZvpGUfvdwLO
         ely5wSgFQm+PmJv9paMXql8BrjSMbEIZVoZvcwsPXzImlH1mKE9y/+Pq8fxZUC3etTXZ
         +VZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="IO7Z/ogd";
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2c.google.com (mail-io1-xd2c.google.com. [2607:f8b0:4864:20::d2c])
        by gmr-mx.google.com with ESMTPS id gf15-20020a17090ac7cf00b00234c0192837si51191pjb.3.2023.02.16.12.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Feb 2023 12:05:00 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d2c as permitted sender) client-ip=2607:f8b0:4864:20::d2c;
Received: by mail-io1-xd2c.google.com with SMTP id bl9so1113182iob.7
        for <kasan-dev@googlegroups.com>; Thu, 16 Feb 2023 12:05:00 -0800 (PST)
X-Received: by 2002:a5e:dd0b:0:b0:713:f12d:40ba with SMTP id
 t11-20020a5edd0b000000b00713f12d40bamr2021885iop.72.1676577899906; Thu, 16
 Feb 2023 12:04:59 -0800 (PST)
MIME-Version: 1.0
References: <20230216064726.2724268-1-pcc@google.com> <Y+49Y4lD4GmDP8fc@arm.com>
In-Reply-To: <Y+49Y4lD4GmDP8fc@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Feb 2023 12:04:48 -0800
Message-ID: <CAMn1gO7xmYrrHzW+C0TSC1D8PUut6y=VJgiuO+nS+g0dF1SbCQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: call clear_page with a match-all tag instead of
 changing page tag
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: andreyknvl@gmail.com, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	ryabinin.a.a@gmail.com, linux-arm-kernel@lists.infradead.org, 
	vincenzo.frascino@arm.com, will@kernel.org, eugenis@google.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="IO7Z/ogd";       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::d2c as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Thu, Feb 16, 2023 at 6:27 AM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Wed, Feb 15, 2023 at 10:47:26PM -0800, Peter Collingbourne wrote:
> > Instead of changing the page's tag solely in order to obtain a pointer
> > with a match-all tag and then changing it back again, just convert the
> > pointer that we get from kmap_atomic() into one with a match-all tag
> > before passing it to clear_page().
> >
> > On a certain microarchitecture, this has been observed to cause a
> > measurable improvement in microbenchmark performance, presumably as a
> > result of being able to avoid the atomic operations on the page tag.
>
> Yeah, this would likely break the write streaming mode on some ARM CPUs.
>
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > Link: https://linux-review.googlesource.com/id/I0249822cc29097ca7a04ad48e8eb14871f80e711
> > ---
> >  include/linux/highmem.h | 8 +++-----
> >  1 file changed, 3 insertions(+), 5 deletions(-)
> >
> > diff --git a/include/linux/highmem.h b/include/linux/highmem.h
> > index 44242268f53b..bbfa546dd602 100644
> > --- a/include/linux/highmem.h
> > +++ b/include/linux/highmem.h
> > @@ -245,12 +245,10 @@ static inline void clear_highpage(struct page *page)
> >
> >  static inline void clear_highpage_kasan_tagged(struct page *page)
> >  {
> > -     u8 tag;
> > +     void *kaddr = kmap_atomic(page);
> >
> > -     tag = page_kasan_tag(page);
> > -     page_kasan_tag_reset(page);
> > -     clear_highpage(page);
> > -     page_kasan_tag_set(page, tag);
> > +     clear_page(kasan_reset_tag(kaddr));
> > +     kunmap_atomic(kaddr);
> >  }
>
> Please don't add kmap_atomic() back. See commit d2c20e51e396
> ("mm/highmem: remove deprecated kmap_atomic"). I'd duplicate the
> clear_highpage() logic in here and call clear_page() directly on the
> address with the kasan tag reset.

Right, that's how I originally developed this patch. As you might have
guessed, I was developing against a stable kernel, so I was copying
the old version of clear_highpage(). Done in v2.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO7xmYrrHzW%2BC0TSC1D8PUut6y%3DVJgiuO%2BnS%2Bg0dF1SbCQ%40mail.gmail.com.
