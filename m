Return-Path: <kasan-dev+bncBCMIZB7QWENRBYU36P4QKGQE6UATZRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 53FAC2495E6
	for <lists+kasan-dev@lfdr.de>; Wed, 19 Aug 2020 08:59:47 +0200 (CEST)
Received: by mail-ua1-x93f.google.com with SMTP id x12sf5678283uai.23
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Aug 2020 23:59:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597820386; cv=pass;
        d=google.com; s=arc-20160816;
        b=ILmuDlNS6FZzwdEBdh4hGpUVLkH/BVsqZZBMjbY7K5GX7l/jk03iPovNLl2T7sr0Al
         jdTjIKnSf2IMH8oX+e8yRrQc+nC3gIG+W+ji6dcqQ3ip8/ZXqY0NUQg1HQUmaisdlo6v
         lEN03fDJy+cXE6xrAMrtDqtRcQ4IAabGAN9Y5tnpSAhTHcmsOqpHZd5111jFJmgaKf0H
         7nZHFd/hMOtXiYLbuRKQOFWT+nYdGPn3LPj3A0h1kmWEGj3kCBtu6/KLEyc1Mxnu+jyJ
         5VDIIVfCPW5946dau5Tkz/yjaWZVDd0QnUv3yZ+zTiaKyNgmhctR6UoI15oHZHZ3JtqM
         P9nA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:in-reply-to:references:mime-version:dkim-signature;
        bh=As20KS7hp6p3CwKKgugSBVHQyzBSC9oRVtjZzT12D0s=;
        b=rWgzaIOIGhmimilGTOfBnn9k7V+Wdb+l8KmzSklCwga1JxIOJTl+kHcZi8ORNse7DM
         smqv8cnMOlIdV+ha4urjAjrF7OAj4MFbGSM762c/Dv0H+h0dzqaxUeYo47TU3y0fl+PQ
         VudGbMORJ9DpCd3/rnRMpT5ec48pSbRyyra1H2n2GEc4U9dI+LdEK8a3HFfHleFxiSpM
         +QU70OKeJ56OrXVdtzUy35SFzIjvNQnvpw873JA7FwMHAcPgvOgt4M/BB2ijmUqRSetG
         9HfUKH/4DPjj/GbKqGAlV5KIAfLIgq1QJqUweP/3X18jYTAw8l3Z4XmJhhjPWXSGso/8
         rwLw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GC7fTOoM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=As20KS7hp6p3CwKKgugSBVHQyzBSC9oRVtjZzT12D0s=;
        b=LjU6GRvr84O1wcihu9YxhrZN1zgMog+Jak8Izrqo3ksmEPP5bzoGc/FFDQd70MNFdY
         9WvRJ+ppA2WXF3srLFQwGAHV37DHzrI7l0c+X3lePH8hOL/gOcm4qYrhKPcL+/eS5Tdy
         0o+IFEhhKjoI9tJ85zC0g/Rzsnqe3JGTk19MY2kvvJRb+7Eosq6Ac5ComZOp9xCTwq7n
         mdr1tQ3gwXyPYNiMttBnW1nC3q1Yp91miSzD7lTh28Oiw3QjOe1IMEbkY8SH7Pno0EbJ
         lt1vENS8LABomza61/vx1mGWhbiRneMXYztcBs3mIZ7qxe3FOfipASDP+LmcEJRUYIhS
         g70Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=As20KS7hp6p3CwKKgugSBVHQyzBSC9oRVtjZzT12D0s=;
        b=FeOFVtSa/pYo6Q8rradFRSztHcm6UYIP/4UDDgXwop1ByZi2xlAJsvbAexW5YPjcCi
         hiOUD/2/f1t6/AokiBiM6FAQ62Zb20muq1XB//4PXUJVvU46dLqOHkUY1u0sHlHIgJ9m
         4tVOKHV1VknqjrkbTsT7qVwE6ZdafIM1h+G6wSrDsT+jp/BguCx+ylqjKDbdDhFmDnDe
         ZvQunslCxzmJOxxP+vUP+yQKmRU9GZV8oAD5p9COqndtWrosKvNGTuVEWF7VTbsDcq55
         zBTmPj0a6sheV8aZ8fkxNV1OaGnOqbriwbxTDwAmCyQQ/8O5qWst3iRp3xepxrRFm+48
         Q5Yg==
X-Gm-Message-State: AOAM532XO6eJ/35EJk2IiC+ithKyCPvEfDaKaKr2ePYvaTOtR9RJ4a9s
	ZuC6OeO5MtuZu98zVdeB2rk=
X-Google-Smtp-Source: ABdhPJzojedLgrIACLhNY1sKdlq3IVuVlMlJZsKhpPaqQsz4KFzKwizqZ3FNcLCyW2WZ5d3YHAI6Dw==
X-Received: by 2002:a67:8c06:: with SMTP id o6mr14206470vsd.200.1597820386262;
        Tue, 18 Aug 2020 23:59:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2254:: with SMTP id i81ls1143426vki.6.gmail; Tue, 18 Aug
 2020 23:59:45 -0700 (PDT)
X-Received: by 2002:a1f:9d85:: with SMTP id g127mr13564619vke.101.1597820385814;
        Tue, 18 Aug 2020 23:59:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597820385; cv=none;
        d=google.com; s=arc-20160816;
        b=jHftSdBG6oE3mOZbVYyfdINSpp/FLjNub6nIqKm1XcJdyZf9ntSpMrmqe6WmpWLfvJ
         n1nrFGl1tMY2his7zgsFD4cN2FvU0bbgCCxsrFloY89sGGXv4IaTRqB+qGoAIQyn3xgi
         7j0TSHiYxsMKx/TCDJhr2zpshoTkQUIaZCgdeVmnvx4iYZwAaw1OqY/MP2PL7nD1QTJp
         2YbXa9bfbKH85l1uDECf1hVjjmHHLAPxnP9XHaATre4EmfAxM0b5Nz2V+GE9qK9lk68C
         4g1URKIMNyMMxp2/9BJcVakhL2msdAF4tLMxK4fMSvqx+FTPfQj+A5ufqylNwQocsNVv
         Hdew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=JuSFfpGHG3DlPnQNv9HyCO0YdIZiFBSDiGjB7b71oRs=;
        b=ak5uoVpIL5OUKu3j3zOmbSqnVC/sVrMXMyOup4rfA08NBZavMXlxy7D0t3XF4BbeQV
         CemMeLib6wJsAw7dRIoxwQorTpARFXeiyy/eoFfw/aup1ffZ5u1rkRMrry03kcSimh00
         90lQ4/CxEZS8s4r0OuwTYyYFuJ+JYHypLi2WpKJR4GFSu8zuW9whHKrwYTzDPRE8Dy1a
         4wyGynRTJhORchqGnV1HtdPo9YFjpVWj4CNpP8ss0Uv9zqUcKTSIFJkAWcUyVsv09d/g
         beAR1xKW/C7LE4/2H/1qh42m2ZwMya9uxoZO0lhDB54AykZ6B87tbTQmQM450ZgS6uHD
         YA0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=GC7fTOoM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id k201si1209924vka.4.2020.08.18.23.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Aug 2020 23:59:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id c12so17083581qtn.9
        for <kasan-dev@googlegroups.com>; Tue, 18 Aug 2020 23:59:45 -0700 (PDT)
X-Received: by 2002:ac8:545a:: with SMTP id d26mr22013248qtq.50.1597820385218;
 Tue, 18 Aug 2020 23:59:45 -0700 (PDT)
MIME-Version: 1.0
References: <CAJSYYSUZFTWakvGWVuw+UYdMNs40zCSQt=mszp4H=on4YaZsnA@mail.gmail.com>
In-Reply-To: <CAJSYYSUZFTWakvGWVuw+UYdMNs40zCSQt=mszp4H=on4YaZsnA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 19 Aug 2020 08:59:34 +0200
Message-ID: <CACT4Y+bLNzbhkJi10v4pqffaRjTsPTwNe+RmB1cjgqSdbHbGaA@mail.gmail.com>
Subject: Re: Hi ! I have a question regarding the CONFIG_KASAN option.
To: V4bel <yhajug0012@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=GC7fTOoM;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::844
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

On Tue, Aug 18, 2020 at 9:03 PM V4bel <yhajug0012@gmail.com> wrote:
>
> After downloading the 5.8 version of the Linux kernel source from
> here, I checked the .config file after doing `make defconfig` and
> found that there was no KASAN_CONFIG option.
>
> These were the only options associated with KASAN :
> ---
> 4524 CONFIG_HAVE_ARCH_KASAN=y
> 4525 CONFIG_HAVE_ARCH_KASAN_VMALLOC=y
> 4526 CONFIG_CC_HAS_KASAN_GENERIC=y
> 4527 CONFIG_KASAN_STACK=1
> 4528 # end of Memory Debugging
> ---
>
> However, in the 5.5 version of the kernel, I noticed that the
> CONFIG_KASAN option was present. How do I configure KASAN on a newer
> kernel like version 5.8?
>
> I'm just a newbie to syzkaller. I hope this email doesn't offend you.
>
> Thank u.

+kasan-dev mailing list

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbLNzbhkJi10v4pqffaRjTsPTwNe%2BRmB1cjgqSdbHbGaA%40mail.gmail.com.
