Return-Path: <kasan-dev+bncBCMIZB7QWENRB7U7SHWQKGQEWJMYUPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id CA3EED6058
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 12:37:51 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id q127sf13107993pfc.17
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 03:37:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571049470; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y0w0mw+SMctD4vT1z5KHrqTEx+l8OJlcVX2vf36qYH8+Ybse6kWQPfynHRXN6MFu73
         ezQg2zNZhL+ZalOsqxQkmijFovT2VE2Ptx9vNpeHwThL5TdbWhGmW1D5+5x3NSZach3k
         K0jWMfzYCgfAY4U/9EC+tsdTs2PtT64zV0IXru4Dl2g1d6F4wlQT6NgBj9p0wX6TEJOy
         KB1nLr4njBrwoFaMHoH6NQkG3yHxMzwFxRXqdT6RNsxWTdwPh/bHKt6GBkTYBK1mh13z
         gCEGv4UVN3PFIFCZTneOrUsHgqc3YVnCJtGcCi9AbjfmMy/YWGk/KhVpo8C0LOKnNnAJ
         6mHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iKxJEvE4tctENsRQgq3kvUIA3Dt14BOZBuZ2lpWFKyw=;
        b=liu66SuO9mcdYEaSIjHCUMw64MNJK4YrEUubIucbhmk1d3lCO20xTuJUZAlPWO4wME
         xRU3fYn1kIDu/fyEI7Emp870UsHC9/+u4hfsIgHRm/W783AdKStY1hcXKwlLCYeJtLS9
         W+xu1qkBkEtP9cWLTnFUB7fys6m962C7d/OXeyORlE32fA7Nj10ypsUoa+RW1oCHaWL8
         acwtAPHv9SH5Mjanh5s1DhTYGwUnjSJRJQxilEamsBqkRRFmqQIyBWdZJhyFOmiKc5Sj
         MtopcUlZy0qdfFPSb/9E5iJVlRKhajD64s8nxG82qNjwB0hcR7Xdt4PmOP2jkfOzwaLY
         2uoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ncAdm5p6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iKxJEvE4tctENsRQgq3kvUIA3Dt14BOZBuZ2lpWFKyw=;
        b=o839xp3pMVl5dHMxS7DCnO22WCumuRGWKpo2QSER8rHj62AOBXo7UfAx8Pdfq4+EM4
         8xcNN+p3pSYMN74+SKo14Z3vE7cTsS2lIlpB0WHnn+6rq20Mop2/XzLNb2TFwjjwLIZf
         PadMaspe/BMd6f6NXPhh/0VZM3hePfd0Q1iWKPK7cX93zeKLoRpzBlpIqgSxcqyUPvbj
         DqdDpUm9mO0uY5nbS6xdBenQlP3eMI6Fh+TgTWbnOmC1nTpBtjdHg3k2siUVlvojx4ME
         fehr7nQVxyngh9x6l2psxsnpo1i+U4oAqb4VVfdZHxv7rMAR7TGCcAl5/qFgmUzhyAZe
         IQxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iKxJEvE4tctENsRQgq3kvUIA3Dt14BOZBuZ2lpWFKyw=;
        b=oXfmL9yKFvl1WuiOdPXDs8nbHEy+0cyApVyPKtbnuUNzuU9qGCNOV+GU3AbXFXwPEo
         L2pmNaG9TmiZNVyUwCPi1o2jv6aO4yPhycmLJ7Hhf7GMc3usdE2ll0mwi0ZO3GUYAGEh
         nXUP62zUGf7+jtQ702THTOK6FNyUc4vV0FQAwMdpRq+TJkTtGuVVwZ1XuiUyeVlM6ZJn
         N8QOA+LckOdVt0k8EQziTkuIDhn2btXrcJEjJ/+rbx9D3avGdZYP1vC0w3TvnYz4Ws/a
         DVAeIsJrVSG6rq9QkW9g6qQSge64xinrlC1z4c3wTf43v8IZom4BFltk6nNbKbBVzmB/
         TaiQ==
X-Gm-Message-State: APjAAAUJC8L2ByI8nLGbUHa57jd8xShecmrjm1ZIGfVayFLN5TrT6S85
	KGCoWk+wqTCyZ/LIvu2eWys=
X-Google-Smtp-Source: APXvYqyW4MKFHx4cNWQWmBFTHfwLgqRT3pYfpjAoPRVxMYmhsYTX/yL+UyNXmNy2xZUHj+ZRmua4TQ==
X-Received: by 2002:a63:a1d:: with SMTP id 29mr14421044pgk.218.1571049470471;
        Mon, 14 Oct 2019 03:37:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6853:: with SMTP id q19ls4002609pgt.7.gmail; Mon, 14 Oct
 2019 03:37:50 -0700 (PDT)
X-Received: by 2002:a63:9255:: with SMTP id s21mr33343684pgn.325.1571049470029;
        Mon, 14 Oct 2019 03:37:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571049470; cv=none;
        d=google.com; s=arc-20160816;
        b=ToflhiCE7SMGFp4YPiFgmreGQkueNJhTbO679gQIealLhKGj5oC+X6rZye5+zDkIDs
         NVqQpBVAtMe7AE5gcaUP+7bC6igloaxMQb92JqpHEOcK+ynF8SRRdzR7BfREIalw0kQM
         lIC5skxMcX5Me15LvZyyjLEdmiDQE72vIHI4BC9Lvjrb8tw7uS0PVrYAL4KHjX+3oHgq
         M8ko2NPLwl/E+6cImRtDXirZteJuDLx0wqKexpD6/QAHOUJaiMrvo1UxpiXl6w/c3ZjI
         H13PTIQeyR6/O45u2IWa/tOUkAR2c6ANXUxU5nz4qDn0EfdZNHCqbCNrPIwdFLNCHPq1
         aALQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Xb4r1wuhDtOoPbUBnl8EutTh4mh6Tp7aWVqMVQujZhw=;
        b=gTL4mUpjPInDHHjnccrW6enF+HoRzlzXy8rJTw7L2VwKM+qFQojIYMUxm4Bv7F1Egi
         Xv+W1nnie9VnTZUGZ58eYe0k/jzAR8/vH6S7dD1SV2DZMgPnrAcwLJ21hPVMwwsgsomF
         0+OrqubA07T++lRpZLe5A6OLBulOw3MbCiFt/Pu/ccGnzf6ZJIhVeP93DzqcZBYSG1cd
         zgerKHD+9IGodyjly+eyFRQu6ulHYzw25IZQxugAiPTXd4Ws1KvLtKUs5gJlaYNRxdqX
         ULmCbGN03W7qcM/T9REWVlCmhqQPj/TLx6NrL3589qdwuA8u5+YzyblKs5uuqr5cpNpF
         VhYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ncAdm5p6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id h1si793202pju.1.2019.10.14.03.37.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 03:37:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id y189so15435520qkc.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 03:37:49 -0700 (PDT)
X-Received: by 2002:a05:620a:2158:: with SMTP id m24mr29448433qkm.250.1571049468723;
 Mon, 14 Oct 2019 03:37:48 -0700 (PDT)
MIME-Version: 1.0
References: <20191014103148.17816-1-walter-zh.wu@mediatek.com> <CACT4Y+aSybD6Z0YHuhbaTKK+fd4c3t4z8WneYdRRqA4N-G0fkA@mail.gmail.com>
In-Reply-To: <CACT4Y+aSybD6Z0YHuhbaTKK+fd4c3t4z8WneYdRRqA4N-G0fkA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2019 12:37:37 +0200
Message-ID: <CACT4Y+aj20xfJ4nSR1piWcZTmANJ-kS8+ZcBfz6jG4ZTjR51yw@mail.gmail.com>
Subject: Re: [PATCH 0/2] fix the missing underflow in memory operation function
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, linux-mediatek@lists.infradead.org, 
	wsd_upstream <wsd_upstream@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ncAdm5p6;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Mon, Oct 14, 2019 at 12:36 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Oct 14, 2019 at 12:32 PM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > The patchsets help to produce KASAN report when size is negative numbers
> > in memory operation function. It is helpful for programmer to solve the
> > undefined behavior issue. Patch 1 based on Dmitry's review and
> > suggestion, patch 2 is a test in order to verify the patch 1.
>
> Hi Walter,
>
> I only received this cover letter, but not the actual patches. I also
> don't see them in the group:
> https://groups.google.com/forum/#!forum/kasan-dev
> nor on internet. Have you mailed them? Where are they?

OK, received them just now.

> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=199341
> > [2]https://lore.kernel.org/linux-arm-kernel/20190927034338.15813-1-walter-zh.wu@mediatek.com/
> >
> > Walter Wu (2):
> > kasan: detect negative size in memory operation function
> > kasan: add test for invalid size in memmove
> >
> > ---
> >  lib/test_kasan.c          | 18 ++++++++++++++++++
> >  mm/kasan/common.c         | 13 ++++++++-----
> >  mm/kasan/generic.c        |  5 +++++
> >  mm/kasan/generic_report.c | 18 ++++++++++++++++++
> >  mm/kasan/tags.c           |  5 +++++
> >  mm/kasan/tags_report.c    | 17 +++++++++++++++++
> >  6 files changed, 71 insertions(+), 5 deletions(-)
> >
> > --
> > 2.18.0
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014103148.17816-1-walter-zh.wu%40mediatek.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baj20xfJ4nSR1piWcZTmANJ-kS8%2BZcBfz6jG4ZTjR51yw%40mail.gmail.com.
