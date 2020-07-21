Return-Path: <kasan-dev+bncBCF5XGNWYQBRB3FT3X4AKGQEQW344QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A39B228A60
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 23:11:09 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id w10sf14368915ilm.16
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 14:11:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595365868; cv=pass;
        d=google.com; s=arc-20160816;
        b=RivyTs2GdJbGfJZus/SR/8Tf9hsIvVQeMvHFFv4HejUZHuUdzPfVKpWMsqdzwX896n
         g5bjwO24S90adh3fe8nRdqPD4elUOt5JnAwuJlPPqjDVJt0fJIyW9tztkjL1Cnx8qC0f
         lwHXAhA41p50x9isWZc6DfpdEDHTq5edv8/Qn6fFIN/hX6iqHWpJFoA/Ak6qRu8sz8DT
         q7gdRFPf20QYNUrhxcJMkEejNQS5Jsxy/V7yMz/QCJusW9bY60kxTwSysW+q3grsU6Cu
         zIFltaZ6QApinXRJcgZdsxRyxVeqfvQrMHg4ojQz4U48jPXUFkbqvyu883lJubgXMHgy
         0zXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:to:from:date:sender:dkim-signature;
        bh=mLJv6NmyN+hmnZMrI4rvBqAFNGR1jOHD2QQ8hZGWyMQ=;
        b=sA6oOsbYYoAZ0GvMiu2+MQpW+/POAksqOFwLgV4v1wYfMJHkB2UjRYkwyDA/2D2jW0
         844czjHx8Qh1WH2EGE2CZdGTcBm6/UYrxU7cUYxxXlo+0rpZWyvhEdYJH+ZR8biiMPnI
         jvHbKcaD4QoFXalydxWPiNfzdX5tD61qupWG9876gZErPeFQJ4rsRDTuK1gveiPhVOn/
         N0w2nP2aSoip/RLcAqBPIgyDbMS9kpmUkug92AE2kiMRVeqDETO+tpjX3KQmbQQoU2q9
         r/281IxcLiiDRMAed70T8d/dWEUGqbYOBKAAiMae9KEZ0YYtiBadNCsk0fTA3D1iiO8G
         xFkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=B9VIphMm;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:subject:message-id:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mLJv6NmyN+hmnZMrI4rvBqAFNGR1jOHD2QQ8hZGWyMQ=;
        b=FETI5gaL9dkoE3SRBiFzgEt7oJXmE6ZLQjZMLT5dtPmscjmBuLKlOGrE3lYUgvGGlK
         roKFFTAAAcqFsyFOBRvg+sV8QGW3UWwSmD/LTKwSTGZKS1BhAkKUO2btJdJQx+G3ra7j
         jf1ZXEkJU/Qd/kLF/PCN40MgcfVPNK4yuyymHNgEoXlxksWcxNPqVXxrrVpP4GiHc5Ra
         aPEXsJfkv/lr7C9MWKJILUxChhtt5UuVuxpCIJhxfMuG/xQaK29Ct4aeHWZEIoECUDrk
         q1u/jGnrA/Slu3VqwqGP30Pqr6NbDKaYS3aoDvZyZds41Szo28HGw9UgnsUm/nAq+LUg
         rn2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:subject:message-id
         :mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mLJv6NmyN+hmnZMrI4rvBqAFNGR1jOHD2QQ8hZGWyMQ=;
        b=HNjh8i/kwoqlsENBlPc1V7BiVsJdinoPMARjLCHefYMSCKNskfe9DcMoloHqhOXToH
         ZXU+n7IAps0JRo/drGMTVgU/FNu59S1AvDiiO+U0L2V/ZaEfw1YRFwAi04zWOGC64vl6
         9RZFhqLWcahNuc87+bf7DRiSTfi2wgfkLTRBp4mEDK/sIiiKaC6ZltqBv2jci7lPKwsN
         /kUUjjzxfDKA9Yc9XKhq2AeLVy0ho90F1Spc5SJcmda8AJwRZisBYeDWr0ax8SyifsKx
         hnQbWC8mN/DV/raNYvnAy0N9Q3mu4xLFEop3F1e5vdRGJPCvteRcuGFXd3VNpNNc9xvv
         l3eg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SgS8y23fYzvIYuinZawk9Rnm242QvBZ9TxOQI/KmpZhJrVaKu
	lFkd1P5gSAH9RYbNgnaFaKY=
X-Google-Smtp-Source: ABdhPJySvZfTtEdZpKoxNhDvwzu9qdBHGGQcsQ44PGTjdnI1O1iKkab6vIix+G+ILWe3ByK5s9FAEA==
X-Received: by 2002:a92:d2c6:: with SMTP id w6mr28588131ilg.24.1595365868104;
        Tue, 21 Jul 2020 14:11:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:e54:: with SMTP id l20ls8126ilk.0.gmail; Tue, 21
 Jul 2020 14:11:07 -0700 (PDT)
X-Received: by 2002:a92:dd0b:: with SMTP id n11mr30988926ilm.241.1595365867790;
        Tue, 21 Jul 2020 14:11:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595365867; cv=none;
        d=google.com; s=arc-20160816;
        b=TGh4tkQurr6qfXkN25OTgmskAVIPLTdL/DNTWCRE/PCyt5NF1nG6cO4mpSfGX62NIH
         F3QX48IEznQ6DxV6R6wJYkMOx4uVRs7Z8AlM5W860+Yr0k2YfpisXc0LIq99TsGLU6Ux
         Uglyf0kZ87I5WRR7LmSPFn6Clc4Q0ILhfT+tjq2NR5/x+0Hnv8Sy/Xtsf91nCuywiku0
         EWNV2gJ3xyA8wnE1/3m187jRjCWtHFoAUYKyFEP0zM+YR3HK36V++M9vu6v2KEK2hYK9
         yZTZv2nXmTe/rmazpbMjoYlmUhg/3/ROcXKC31J7ykha+yKPURcYr5Y+mwjzpfECFsjx
         yn/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:to:from:date
         :dkim-signature;
        bh=q4bxXq4ZBaU2bS9tizYwKGxutClF3in7UiQAtOJNZCQ=;
        b=MXW4ObulRD2foJVZhiebkQsBHOWW9+D6DiWzdLaQ91ZXJeP5oAP44e7zEF3pSxwoU1
         WxjinmLp8G3mThMU2fT6l8XedXKve+4CV7fYPNC4/GU6tLCDij4PpdBVkG6yIkVliaqB
         pDJjniGTeuvC3Ei2FU2mwrmUSN4ncquqyC49yakIBRSM18qqTiESMlVxCA3ui8FdmLmk
         Nysfq+gEcS15rCuxhSH2qvuhshDgxynQ2njn82Lv4rLBEiE+1EqgYfhfAJ1Zq3wVMvcx
         xU8MdFKSH8IURgUZz+jiW2zt7MR1ZUbXltO4Gg5fmrKkD69KkukKgLEvw/XGGrIIwDNJ
         Z9Hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=B9VIphMm;
       spf=pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) smtp.mailfrom=keescook@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pf1-x436.google.com (mail-pf1-x436.google.com. [2607:f8b0:4864:20::436])
        by gmr-mx.google.com with ESMTPS id e20si180612iow.4.2020.07.21.14.11.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 14:11:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436 as permitted sender) client-ip=2607:f8b0:4864:20::436;
Received: by mail-pf1-x436.google.com with SMTP id u185so60058pfu.1
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 14:11:07 -0700 (PDT)
X-Received: by 2002:a63:df01:: with SMTP id u1mr21967976pgg.401.1595365866195;
        Tue, 21 Jul 2020 14:11:06 -0700 (PDT)
Received: from www.outflux.net (smtp.outflux.net. [198.145.64.163])
        by smtp.gmail.com with ESMTPSA id b128sm21375276pfg.114.2020.07.21.14.11.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 21 Jul 2020 14:11:05 -0700 (PDT)
Date: Tue, 21 Jul 2020 14:11:04 -0700
From: Kees Cook <keescook@chromium.org>
To: kasan-dev@googlegroups.com
Subject: alloc/free tracking without "heavy" instrumentation?
Message-ID: <202007211404.0DD27D0C@keescook>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: keescook@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=B9VIphMm;       spf=pass
 (google.com: domain of keescook@chromium.org designates 2607:f8b0:4864:20::436
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

Hi,

Is there a way to enable KASAN's slab alloc/free tracking (or something
similar) without turning on all the "slow" instrumentation?

Specifically, I have a corruption that is due to a race, but using KASAN
to see it doesn't work because the race stops happening. However, I have
another much cheaper and specific way to determine when the corruption
happens and I'd like to see what thread called kfree() on an address. I
didn't find any other existing tools that would track that kind of thing
besides KASAN...

Thanks!

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/202007211404.0DD27D0C%40keescook.
