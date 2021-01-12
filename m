Return-Path: <kasan-dev+bncBDX4HWEMTEBRBDGM677QKGQETUIVIMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id F21592F37F3
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 19:10:21 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id 67sf1249887otg.15
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Jan 2021 10:10:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610475021; cv=pass;
        d=google.com; s=arc-20160816;
        b=l+AyaxtJfN3I4wRseg3lN1AImRbIHih4+Yq/7I68/B/A+esMD6DVyvcanonjYZgPFl
         V7LQuh381N+u1m4+YT+/Sf7F3a/HYjy/1Q8tMA2weQPSPfOyBQ3VVyB2GnkdqzAnmQQ8
         dquy2h3ees993wj2j3GCUTOfUBkhFAZMltJq6Qp+PrehOUsSX5wOD+j2ZGOFQ4w+zlXj
         7knyhfmmOSLfzCizdKdFJyCm6coccOvKwcVv3p4sU0L2TlEfZAJoYsjaptsxcUjTcG7J
         hjRGSnk06xHZYgt3cHh/7alTxFUwv/45EuauJigJgUIO6JvldhJ1oStdGLL5C7+uRBIi
         3w0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=YExKk9VRfrBKED6A5+WaZ9TQyFlnZljFhBHLik8A+fA=;
        b=jvBPOco9lKGUDu5EhVWY948ON3Owo8ygb8371nzvfJYRmSip453dd2qMYiNNg8VPQy
         jEaXewJkiXPQpPOuFR8ubpLhwnVb7pKRzGTQQ/ufAhUN2eo2J9mgWhYvcFctyb8xY8yY
         KZXMUNkKdPMcJAvlhtREDf8vOsNN0N+h5Vejial75BUzAK6yXlnwzM/MQSPQnDOc4nW0
         I8caQL67IYuIlGLhk0OwORHadm15nWdr3Yj+hTS55V9J2kqewRIOWo/+op5lYlipTkCO
         gWN6rgMYRTOTPa7DgcxnrqllQZE13vctYx2zgWDL8GbLSZuXjD35YON0Pg7z4cH5dhkT
         TAIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JM8ZOsGV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YExKk9VRfrBKED6A5+WaZ9TQyFlnZljFhBHLik8A+fA=;
        b=ISopVRfgetBRjqaDW3lhgdaWWKm1vfKXeMp0PogcVKDNQnyyXzxmtKIRaurYqbIj9W
         gNvgaEr788Oq0fpwlxcfzjWMNJBEriV7S9YtzJds3tt1OMK+0A9i005RFTGP+72tRPEf
         /5S++nvRZNioZ0Z+sKVWdwAvB1pQmnkTHJTfoDIYWHIvJidXIRP3z8vNDWkPZKmRSX4b
         2iQbwg6+uo5p39NMat3PRNlBbJicHjaivONeOZpAzSZf+gaUC6W1/xRMsOKPLDZVJeMf
         er4td5VCjK+GZIJXDRIqKrR16144gqvXz9KvOycQaLE4m2+Ex2wVbcG53CggNf55Fpwd
         1+wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YExKk9VRfrBKED6A5+WaZ9TQyFlnZljFhBHLik8A+fA=;
        b=b/vmqQZmqsisX+EcvM4Bu96r30VrJkL/LFzSVeA2mwOSMSQejFkA+d7ugY5MsKV/oW
         lpKeO8e2Ul0uEOI5ZaKuZ0G/2w4FPnnHWJ6Nu5uomUnk9c4OQbhq35LtRF/EOYKZ8Sqn
         BRIvIRTlxyJPa8Wq+S68QQI9215MVRIn1D1l0emOIaJIHxVgg+gL2FCNbYF5aEqqZWlb
         gbHhCu98ee4BOvTuG/LKgnkC4NE8IeSGvAlLC6LlzJZmbGqa19CBPq2O4edRJ4HMbnHq
         gvQtF9V2wA62swwKE6ikKGOZQKG8qhEN7uHNj99pDGUDfGxXp2iY+d6HuGG/Ok9f8JHl
         pkRQ==
X-Gm-Message-State: AOAM530YyOecDLvjGuDrT/kokJKpCr4Lqi0nzh+Vsc2EXg3SN53q5HI8
	qje91Jdg7OBur7lDo1A0Rts=
X-Google-Smtp-Source: ABdhPJys1GI6iRopPPp28xuYtALD0zQy1dPcwFHXAYwaN2vrzW4Tcx4zy9y3/uZdn0eAbAoM7FB1zA==
X-Received: by 2002:a4a:bc8d:: with SMTP id m13mr184259oop.63.1610475020898;
        Tue, 12 Jan 2021 10:10:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:72d3:: with SMTP id p202ls940504oic.9.gmail; Tue, 12 Jan
 2021 10:10:20 -0800 (PST)
X-Received: by 2002:aca:4f47:: with SMTP id d68mr251466oib.135.1610475020581;
        Tue, 12 Jan 2021 10:10:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610475020; cv=none;
        d=google.com; s=arc-20160816;
        b=J+SbejfxlbLjhPIPXWqiZNEWSNOhhzqnmTFastvTQZ3z6v0uYPc54bZkwOviBRFQK0
         Uk2SqOp9bCV+WnAfh/MlqRS9tMl9vXBJsnrqXmw1EH36jnthX2gwN9J60uRXOnkJzUBp
         rpzNnc0VsyV6By907oM+yQfw0DHj5fE/Mn6jahsYK2EcvV5ZKZOPJjRQN3DIW02tIpGS
         Pp06uJtoJw6x1TTXIRGtlrQnqzagckaKSkpDVZFHV3R36gNGfHgaxOhZ5zP2eBmaoRpD
         IxVh7zWqGYX+oRkLUhI9nV67E2vaa1+l4rFnj6valkI53FAYUa+Mk6hfapLYFZ4Z9e+V
         IZkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=A5gCy8U+Pj2XIzaMO6G08RY3MnWe8pOVDCWwBl512KM=;
        b=B9cUvlFb2H2n1vL28oXWW+9gc1GFdsDB8PMFkaTYnNI+t2YPX/0Bhu9uhXYbBZRtbW
         IBqlFxd7g+/hhnfVMlT2E5ckba0wpLLDvC+kOyRKikyMPECU3+tf1OY6rQv2hCBZsDOZ
         4jySRAzl/2IGeUx+Uvbss2F3cPIisUP0SSY1/jsOV/K4oACdn+LEJGRGajLxKplkXVWU
         IizVRcVONmDhQ160sa70Q+79mnX8xfaD/qW8ZGYtXY7Yls2zTbYZg794T/nwnCpSU+ab
         +wvbLl/aJOtzAS8XJr6wX8FBfld44Pd+aJXs0qainxnM9w+f3K6tyUxt/FLYPWazTYc6
         /HfQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JM8ZOsGV;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1034.google.com (mail-pj1-x1034.google.com. [2607:f8b0:4864:20::1034])
        by gmr-mx.google.com with ESMTPS id r8si267911otp.4.2021.01.12.10.10.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Jan 2021 10:10:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034 as permitted sender) client-ip=2607:f8b0:4864:20::1034;
Received: by mail-pj1-x1034.google.com with SMTP id cq1so1920535pjb.4
        for <kasan-dev@googlegroups.com>; Tue, 12 Jan 2021 10:10:20 -0800 (PST)
X-Received: by 2002:a17:902:c144:b029:dc:292e:a8a1 with SMTP id
 4-20020a170902c144b02900dc292ea8a1mr376024plj.13.1610475020053; Tue, 12 Jan
 2021 10:10:20 -0800 (PST)
MIME-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com> <0f20f867d747b678604a68173a5f20fb8df9b756.1609871239.git.andreyknvl@google.com>
 <CAG_fn=WX5rGMHKPrDVCUoTNFwygW9AP7QrVwrco1R70sZ6MqQA@mail.gmail.com>
In-Reply-To: <CAG_fn=WX5rGMHKPrDVCUoTNFwygW9AP7QrVwrco1R70sZ6MqQA@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Jan 2021 19:10:09 +0100
Message-ID: <CAAeHK+yJ4SsbxEyYj8+bucUNb1wSFwrLgUuLJ09mOyGw04NF0Q@mail.gmail.com>
Subject: Re: [PATCH 04/11] kasan: add match-all tag tests
To: Alexander Potapenko <glider@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JM8ZOsGV;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1034
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Jan 12, 2021 at 9:05 AM Alexander Potapenko <glider@google.com> wrote:
>
> On Tue, Jan 5, 2021 at 7:28 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Add 3 new tests for tag-based KASAN modes:
> >
> > 1. Check that match-all pointer tag is not assigned randomly.
> > 2. Check that 0xff works as a match-all pointer tag.
> > 3. Check that there are no match-all memory tags.
> >
> > Note, that test #3 causes a significant number (255) of KASAN reports
> > to be printed during execution for the SW_TAGS mode.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I78f1375efafa162b37f3abcb2c5bc2f3955dfd8e
> > ---
> >  lib/test_kasan.c | 93 ++++++++++++++++++++++++++++++++++++++++++++++++
> >  mm/kasan/kasan.h |  6 ++++
> >  2 files changed, 99 insertions(+)
> >
> > diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> > index 46e578c8e842..f1eda0bcc780 100644
> > --- a/lib/test_kasan.c
> > +++ b/lib/test_kasan.c
> > @@ -13,6 +13,7 @@
> >  #include <linux/mman.h>
> >  #include <linux/module.h>
> >  #include <linux/printk.h>
> > +#include <linux/random.h>
> >  #include <linux/slab.h>
> >  #include <linux/string.h>
> >  #include <linux/uaccess.h>
> > @@ -790,6 +791,95 @@ static void vmalloc_oob(struct kunit *test)
> >         vfree(area);
> >  }
> >
> > +/*
> > + * Check that match-all pointer tag is not assigned randomly for
> > + * tag-based modes.
> > + */
> > +static void match_all_not_assigned(struct kunit *test)
> > +{
>
> Do we want to run this test in non-tag-based modes? Probably not?

Will fix in v2, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2ByJ4SsbxEyYj8%2BbucUNb1wSFwrLgUuLJ09mOyGw04NF0Q%40mail.gmail.com.
