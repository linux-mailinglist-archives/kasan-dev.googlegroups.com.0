Return-Path: <kasan-dev+bncBCMIZB7QWENRBNNJXSBAMGQEN4AU3DY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1389B33ACF1
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 09:03:02 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id g126sf1552071vsg.17
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 01:03:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615795381; cv=pass;
        d=google.com; s=arc-20160816;
        b=CKIcHJDtF1P6DkvGDZpDhn2Re2gu5jpqN+5DsSeuAbh+XBZCvLGcQ+LN45XtB+3/Ao
         s5MJ8CTFclML2AJ/VJe+/NQzGa1UMcjL6f2pp7F79rYlU9nGOLOuiK4Apao1tSb/lQmg
         kJcPvAjxZLlQR6pCCzQXG3S9+apbiqW3wCcOUFTcNCpaLfHh4O7rQjnneUqsCpGCS8Fw
         kLz/P8iT06Ve/uiRKCdHaPVt3E9mS9Ew6rNNX1dWVIjBv4Tia2fxBWdi6njLgKhFK+CT
         2NbzAd0qZiQA3OE3rVLAa8FLifKdvVlI2yi6DM7DULAfO5EWL6sjtoxCyYWeTkL1xdZE
         fE8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CYHRa7TBXKvhJlfG3+bCkX2ZXOXyttkyoNJPsGnZIYA=;
        b=vqmMsHlLgHy7kxh7zkttdnBPLGLcUY/tY58W5cjVSHfZCyj9Kk5gml6PByQGJlTh6y
         044tJZ8GQi1WUFU8+ox6AXe/owXwEHRgV9LOxYVESas/PxJ6wjWI16IRY7amPrm0YUVD
         iLmj2/z4+M0W2/vmkTh9hdLCF/Ah8FoPn3y3vchmfQgUN4zceYHlizmWo7oxdbYTTilY
         5hUmokjIAKy0t8Nq9EAv5N87PNBMFQ59yQux7VUpkAh/TC9QgtAQpaeNJ24fhPrcKMCP
         L42hFpmX5KpNns4kf/VAUUWZtNWq6DpEBORi02ODw7Cymz7OjgH/QyQP85zrR4Yv5cy+
         Xi9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eNoy/sAs";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CYHRa7TBXKvhJlfG3+bCkX2ZXOXyttkyoNJPsGnZIYA=;
        b=nyfHqqcRmqGiih66AawW13WScNO3226VJANa0dVKS3gGE+eeYPnbfeBc6jgvBflOQQ
         HSHXPDcoDrCwC52miNhj7550wvjW/kMrsMYTiV6bVOnvUCIFrxalPjbXI+6BdBvzOQbE
         YVCBSrN6ONj8855Qvs3c1I8CXZvbu0q8i3zhMSE9xwqZNVA64yYSMJ274FZZHpDxVeQe
         kXUAnZirgvbBmcNJQJ3337xUYquWmc79ce7lCUNAEozhZrj8CQHWXLe3Misd0jsLrLa6
         6qnD8SFif9vrfUEzdd52e6RHs/RMGGewKC5kPTPz8gn5HcPinO9y6T3x+MDbe2TutpGc
         ZZdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CYHRa7TBXKvhJlfG3+bCkX2ZXOXyttkyoNJPsGnZIYA=;
        b=jU2PRgrO/0I113VIePUEUH5TXNumBnbs1AkYuGOhypeIE8tmP0TdoL0MxgE4Oufmmq
         6l1FpmXZXrSBwkVd64W1E34ZMMjGlPG8Bx+Qz6DcZSK+Kny738tQKFVpVdZhxMs0Q0WI
         EecdXI5/9eJpHWe6DcZScPnXI77YawtpGo1bqkprtGzvnFQxczlkrx03GAK5sWrOI81t
         nC1QlSfoIC/PxGnXXsRVHp/jEqTPLhVYCVdGNTot722uSXP3dlWQEcCldXvtGpu3vnsR
         Mr89gu6Xwi82cDh/LIBXRaSRk+jgq8R+fSZYG65+n8gJeuW7j0IFbWQyUhKFt2dTrEUd
         lO+Q==
X-Gm-Message-State: AOAM531b7aIIJl2XrS036pQrc0yX+MheRsK77lwG9ei2D8OLkwaC3rx9
	uKhsTWxQDTWlCyPxv2wOqbs=
X-Google-Smtp-Source: ABdhPJxnp+gGBrVHeS+yOoPwmp8AMelxvnbTulOWTaNRI7lM49K+KIIm15pXL6PuoEAK4g8TCY/KuQ==
X-Received: by 2002:a67:794b:: with SMTP id u72mr3769703vsc.16.1615795381116;
        Mon, 15 Mar 2021 01:03:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:525:: with SMTP id m5ls1870529vsa.3.gmail; Mon, 15
 Mar 2021 01:03:00 -0700 (PDT)
X-Received: by 2002:a05:6102:208:: with SMTP id z8mr4272256vsp.2.1615795380607;
        Mon, 15 Mar 2021 01:03:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615795380; cv=none;
        d=google.com; s=arc-20160816;
        b=UW/W5XouorTC58k5x81QqKaDChMCraN+HLBuKRnPY5IxYWlRzk3TwCEbfa5ERNKFns
         JIgCUe1a/9K7D5Iorp3ngHHOGMBniqxXsO4HrXs6cVl6orhoDmVeUc4mwcqpi054XOEh
         QEZb/TAtN6v+UIyHVdYRKLVteQbQhxoCfSAyfaPEZWAsKxRq0Tu6OA+wgfJxVrKXYK0y
         lawcVe02SohlGsTtp2E6lvHBeoy8PqSOOaPSDOTNl1/AGv47mvc3mAcuJHO28FXMcMyx
         zbQE/t952Q+r/ObX5PJJSSIGZ7RkEtTAPVtZDem1Iezmh34uk2XlHna122Y/7JQXadae
         rcXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=KtsjY55Jb9isqHKR/wLdGTjwveZYY37X0uZAq2FcZYY=;
        b=ELUxiwN7Z6lrsy5mCHgDvSaXK9RO2ss7Ycr//qBB6+ybaaFfJyGUbjynp3day5iPXa
         FBbEso4TgLOleOlMtEYsEAArfzyw9zj2sykJHb2ZkiY9oDRdsuSOMNkgIiUMws+pIRgE
         VHh2rc1uU53ZyxxyFMHw+2S1EsPZY+PGzNGIOSQfhujBBxgOB4V3jmhpPBUIwDo+DZjL
         wXoyinDwaKHrAH85mJUnrS4zrhY6K+LjWhR5S2N5gofesZ/+viBZ2MsyJuy0w9dkqZur
         vyoLu/hZ+iXR4ZWXpzGO/GMDZSF1/NAvb2iHWFCBYAJo76buTRLE4vq7NaS8wB7sbrhp
         8fGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="eNoy/sAs";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id n3si905511uad.0.2021.03.15.01.03.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Mar 2021 01:03:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id by2so7338598qvb.11
        for <kasan-dev@googlegroups.com>; Mon, 15 Mar 2021 01:03:00 -0700 (PDT)
X-Received: by 2002:ad4:50d0:: with SMTP id e16mr23756584qvq.37.1615795379822;
 Mon, 15 Mar 2021 01:02:59 -0700 (PDT)
MIME-Version: 1.0
References: <20210211080716.80982-1-info@alexander-lochmann.de>
 <CACT4Y+YwRE=YNQYmQ=7RWde33830YOYr5pEAoYbrofY2JG43MA@mail.gmail.com> <01a9177f-bfd5-251a-758f-d3c68bafd0cf@alexander-lochmann.de>
In-Reply-To: <01a9177f-bfd5-251a-758f-d3c68bafd0cf@alexander-lochmann.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 15 Mar 2021 09:02:48 +0100
Message-ID: <CACT4Y+ZPX43ihuL0TCiCY-ZNa4RmfwuieLb1XUDJEa4tELsUsQ@mail.gmail.com>
Subject: Re: [PATCH] KCOV: Introduced tracing unique covered PCs
To: Alexander Lochmann <info@alexander-lochmann.de>
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Wei Yongjun <weiyongjun1@huawei.com>, 
	Maciej Grochowski <maciej.grochowski@pm.me>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="eNoy/sAs";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2b
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Sun, Mar 14, 2021 at 10:29 PM Alexander Lochmann
<info@alexander-lochmann.de> wrote:
> On 12.02.21 13:54, Dmitry Vyukov wrote:
> >
> > I think we could make KCOV_IN_CTXSW sign bit and then express the check as:
> >
> > void foo2(unsigned mode) {
> >   if (((int)(mode & 0x8000000a)) > 0)
> >     foo();
> > }
> >
> > 0000000000000020 <foo2>:
> >   20: 81 e7 0a 00 00 80    and    $0x8000000a,%edi
> >   26: 7f 08                jg     30 <foo2+0x10>
> >   28: c3                    retq
> >
> So ((int)(mode & (KCOV_IN_CTXSW | needed_mode))) > 0?

Frankly I lost all context now. If it results in optimal code, then, yes.

> >>  }
> >>
> >>  static notrace unsigned long canonicalize_ip(unsigned long ip)
> >> @@ -191,18 +192,26 @@ void notrace __sanitizer_cov_trace_pc(void)
> >>         struct task_struct *t;
> >>         unsigned long *area;
> >>         unsigned long ip = canonicalize_ip(_RET_IP_);
> >> -       unsigned long pos;
> >> +       unsigned long pos, idx;
> >>
> >>         t = current;
> >> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> >> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t))
> >>                 return;
> >>
> >>         area = t->kcov_area;
> >> -       /* The first 64-bit word is the number of subsequent PCs. */
> >> -       pos = READ_ONCE(area[0]) + 1;
> >> -       if (likely(pos < t->kcov_size)) {
> >> -               area[pos] = ip;
> >> -               WRITE_ONCE(area[0], pos);
> >> +       if (likely(t->kcov_mode == KCOV_MODE_TRACE_PC)) {
> >
> > Does this introduce an additional real of t->kcov_mode?
> > If yes, please reuse the value read in check_kcov_mode.
> Okay. How do I get that value from check_kcov_mode() to the caller?
> Shall I add an additional parameter to check_kcov_mode()?

Yes, I would try to add an additional pointer parameter for mode. I
think after inlining the compiler should be able to regestrize it.

> >> +               /* The first 64-bit word is the number of subsequent PCs. */
> >> +               pos = READ_ONCE(area[0]) + 1;
> >> +               if (likely(pos < t->kcov_size)) {
> >> +                       area[pos] = ip;
> >> +                       WRITE_ONCE(area[0], pos);
> >> +               }
> >> +       } else {
> >> +               idx = (ip - canonicalize_ip((unsigned long)&_stext)) / 4;
> >> +               pos = idx % BITS_PER_LONG;
> >> +               idx /= BITS_PER_LONG;
> >> +               if (likely(idx < t->kcov_size))
> >> +                       WRITE_ONCE(area[idx], READ_ONCE(area[idx]) | 1L << pos);
> >>         }
> >>  }
> >>  EXPORT_SYMBOL(__sanitizer_cov_trace_pc);
> >> @@ -474,6 +483,7 @@ static int kcov_mmap(struct file *filep, struct vm_area_struct *vma)
> >>                 goto exit;
> >>         }
> >>         if (!kcov->area) {
> >> +               kcov_debug("mmap(): Allocating 0x%lx bytes\n", size);
> >>                 kcov->area = area;
> >>                 vma->vm_flags |= VM_DONTEXPAND;
> >>                 spin_unlock_irqrestore(&kcov->lock, flags);
> >> @@ -515,6 +525,8 @@ static int kcov_get_mode(unsigned long arg)
> >>  {
> >>         if (arg == KCOV_TRACE_PC)
> >>                 return KCOV_MODE_TRACE_PC;
> >> +       else if (arg == KCOV_UNIQUE_PC)
> >> +               return KCOV_MODE_UNIQUE_PC;
> >
> > As far as I understand, users can first do KCOV_INIT_UNIQUE and then
> > enable KCOV_TRACE_PC, or vice versa.
> > It looks somewhat strange. Is it intentional?
> I'll fix that.
> It's not possible to
> > specify buffer size for KCOV_INIT_UNIQUE, so most likely the buffer
> > will be either too large or too small for a trace.
> No, the buffer will be calculated by KCOV_INIT_UNIQUE based on the size
> of the text segment.

Yes, which will be either too large or too small for KCOV_TRACE_PC
enabled later.


> - Alex
>
> --
> Alexander Lochmann                PGP key: 0xBC3EF6FD
> Heiliger Weg 72                   phone:  +49.231.28053964
> D-44141 Dortmund                  mobile: +49.151.15738323

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZPX43ihuL0TCiCY-ZNa4RmfwuieLb1XUDJEa4tELsUsQ%40mail.gmail.com.
