Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLXWVKLQMGQEF4IORGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 80AB9589215
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Aug 2022 20:15:11 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id co4-20020a17090afe8400b001f4df09d662sf4486650pjb.2
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Aug 2022 11:15:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659550510; cv=pass;
        d=google.com; s=arc-20160816;
        b=LooAojApCB55lTrwRQf+h0FvSn+DwEzjMGUMOsWY7pSnYVl5bbIIwyqhaXqgdnoznr
         MhGSD+YJ/OebleyFtPI7OxhRfULZcMhJXfiF50J+sZ3n3jZ6bcMVxp0ObyABINYbz6cC
         /wG2bDTt0UepsTLRR47EH2EWP4ACRx9Az8Xh/Iz+zKoFi0sbo4ODTwW70OPBtUeW+zcO
         ZAtRbzXZMaekPl7yrHFRbY19aC8Y2MJwHUTsAv+5qstCyGOMJKTIqA64rx7QmW4Fa+bM
         NKzvtIiukhtsqEO2JXVjNI87zTH3tUagsvkUT6Iaq4KnxtfbdJnekxRKNX76fa3SF7H0
         sA4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aMhhlreEsajs+tA+u5T5j73AchKHhOPkcjAWIg1gsqQ=;
        b=KbSF8ESKPYE04H26aO+1GPUd66PenCl6Cffv+5ZUcaK4Pmilsegy60XVT8cNTxLiAl
         /emynbrVE3s4BtyiTyHzuEbKwVCOnuOcJBN/9XQkc8alSGatuHliupnBG7VuaPZN7TSm
         +0HagmIKqMyNgMqXCuiBHWkdNrhKus+F8uFcdub3PByugmDMLiM0icQi/h8SvmF0Z6QK
         nFiG7tGSJd9bBQ4tzQZ5c0LRci/U47yW8hQ0VG8ILp99OQVlPTlFYcTizJLWP+SZVJxW
         OCJRMIukDj4ZgJm5iSLqMAyptulOE13ZmU68w8AD5vz2M9vccI+PaBowSko+rW2kKTYF
         vUGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sRaUcFSt;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aMhhlreEsajs+tA+u5T5j73AchKHhOPkcjAWIg1gsqQ=;
        b=mgm58qgsljuNP8e+7XYo0H7VS5LG6QTrUcWw0hHUE7qIR5lBcX0h1Plvxt3Sdx+v/g
         Uxa01i8KSiI/YhEpUWg8DnwQDJgTLrHj0d5h0M9b4U6T0yUaSGN1hvDT4f+87v3Be1Ea
         ABCa7yQD/+NDt5GaSxokqWJtuJvJDguJxTdKDCCZmzOkNFt1CAcdPQuJgWd3/ge2SmpF
         PO5XIHoAHzI1Qduc5grA5gDW/IP/hY0gg5LxOhvzR32cqTfk/jiJ83CKnAa/7FUOz0ia
         rA6421ARvi708l6hQmBsUvhWdxaKf0AoMHE7v4wP0TIR9PhkOp9NS/B2XtXBbGSCMNfD
         LLxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aMhhlreEsajs+tA+u5T5j73AchKHhOPkcjAWIg1gsqQ=;
        b=rTUnYpudGXnjaGb68m6HNdSe1m7NXlg6x7LIQC53n0eDNsoZcd3jdM3Dk5Dl2iQ2hl
         Z7xhHesudYn8CFDt1EoJufXev2wF9QwMW/2waTOU8O3bhz0Ba6QPvIVzQar2ze/+o2uN
         0lCvLY5+vaYc/+YqahcdjnYXD1FjWRwohOxxdEMCVf8mAfCjI468RJ7YvI2jShlGlRfk
         B9+ZJLPuSD0K/bn+woVjHNhbnoSSLhbamrMEVyZGwoeL+AmVCM+vt5yoQa0Xl7UoLdZx
         uDcUl/RPJ1MEP+9AIrDsFqCkTutwYEa1IYWLkHB1wn4PiFECEKNGcSUwOJoFSpu6YonF
         mUWw==
X-Gm-Message-State: ACgBeo07erGKj9Dkcco8SjwhhKRamqwecQnsoVsfoa2e68RbkXJ8mPKz
	tubndkWa0zkuEGj+SNMni/g=
X-Google-Smtp-Source: AA6agR60JCXWijNGDbJjLlkWmHCKUyFDUeOi/dUwfsM7v4ZZlpCvY2uHip2BhE/NU+k8UOX/O9vPmA==
X-Received: by 2002:a17:902:ec88:b0:16d:d156:2bf2 with SMTP id x8-20020a170902ec8800b0016dd1562bf2mr27195731plg.40.1659550510135;
        Wed, 03 Aug 2022 11:15:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2c8a:0:b0:40d:4b5d:70b8 with SMTP id s132-20020a632c8a000000b0040d4b5d70b8ls8846979pgs.0.-pod-prod-gmail;
 Wed, 03 Aug 2022 11:15:09 -0700 (PDT)
X-Received: by 2002:a62:1687:0:b0:50d:3364:46d4 with SMTP id 129-20020a621687000000b0050d336446d4mr26852625pfw.74.1659550509478;
        Wed, 03 Aug 2022 11:15:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659550509; cv=none;
        d=google.com; s=arc-20160816;
        b=lS3ZfixS2EeS4wFQCFVmFW3gfVTeSAo/1K0+zbguODG8AQEvRuisTfTjpL+9feO6n6
         iL//z7BtsFtAyIehrhOrak99NzFuW7ZB9W5Ksul8Jxh+MIAoUk99jSwe+UtIxi5YZqlH
         8OwMGCLk1H+k8NMYa7a8Ozxd73C4OLKUNN9BXAxL3+AIpckvFg4L3wL5gnCeoX6m/wsc
         I4vyEr4GocTLsKRMBK5ogClWJlU5K8oJtS8MSn0Vy1LO2qy60I50wVQHwaNeHJXMgtpD
         QQpBPKMeaI266m3WbGAoCXFLGAhplWaN/iMpKpp70ypkWA+Dxxf6D6+GX/SmUMfJJov3
         RTjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=y92UH4xk+JPW8aVK6dnuw9Im2HL19mMdvEh4kg2bK0g=;
        b=g2YkSPLIDelZgdZ7LZ1ht6t4pFUilQw1q3c9BlxFBEvUumnN/c3L8c6zifk9vazssi
         oJGixYiKhSh4k1Tq/K0T14UL8kyy5a0VgXU9deld2Po4xqy+OtQgJhutVIAf3KC7sYZH
         KzWapdyAmtFN3jKfKqm0ms+QYN2Ycwy0F93Pemlj4EqL715qWtnNeJpko6ZCryDXhrOq
         QQJohrxaqzxyUcscgcDQbPYKotxBd4c9yohcli0a9dCxqep3ukRJODMmrgfGsJVJEtvY
         frxxMkQZNi8PK340wEu8P0mMq51Z2WJqSBenzZ0zFVhFuFUgs+Km1vk3Km3+Ugo/NrNH
         8pNA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=sRaUcFSt;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb35.google.com (mail-yb1-xb35.google.com. [2607:f8b0:4864:20::b35])
        by gmr-mx.google.com with ESMTPS id s3-20020a170902ea0300b0016ed64d3908si122082plg.8.2022.08.03.11.15.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Aug 2022 11:15:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as permitted sender) client-ip=2607:f8b0:4864:20::b35;
Received: by mail-yb1-xb35.google.com with SMTP id i62so27809942yba.5
        for <kasan-dev@googlegroups.com>; Wed, 03 Aug 2022 11:15:09 -0700 (PDT)
X-Received: by 2002:a5b:982:0:b0:63e:7d7e:e2f2 with SMTP id
 c2-20020a5b0982000000b0063e7d7ee2f2mr20837859ybq.549.1659550508989; Wed, 03
 Aug 2022 11:15:08 -0700 (PDT)
MIME-Version: 1.0
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-12-glider@google.com>
 <CANpmjNMrEdNdsz6rxkrpiJNREB+GSkx4B=LwPLWYmwVhdjVA4g@mail.gmail.com>
In-Reply-To: <CANpmjNMrEdNdsz6rxkrpiJNREB+GSkx4B=LwPLWYmwVhdjVA4g@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Aug 2022 20:14:31 +0200
Message-ID: <CAG_fn=UZ9MLLu9zos2Daba+DB__HidgYRT-27CxB2PwV_t=KnQ@mail.gmail.com>
Subject: Re: [PATCH v4 11/45] kmsan: add KMSAN runtime core
To: Marco Elver <elver@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Alexei Starovoitov <ast@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav Petkov <bp@alien8.de>, 
	Christoph Hellwig <hch@lst.de>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu <herbert@gondor.apana.org.au>, 
	Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, 
	Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox <willy@infradead.org>, 
	"Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg <penberg@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Linux-Arch <linux-arch@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=sRaUcFSt;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b35 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

"
> > +struct page;
>
> Either I'm not looking hard enough, but I can't see where this is used
> in this file.

You are right, this declaration should belong to "init: kmsan: call
KMSAN initialization routines". I'll move it accordingly.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUZ9MLLu9zos2Daba%2BDB__HidgYRT-27CxB2PwV_t%3DKnQ%40mail.gmail.com.
