Return-Path: <kasan-dev+bncBAABBWWJXHWQKGQEHGN2MOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id ABA37DFB69
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2019 04:09:31 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id a17sf3919990ilb.20
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2019 19:09:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571710170; cv=pass;
        d=google.com; s=arc-20160816;
        b=Re4BcacM+j/J0Sqmv+34b+8MQRoAeqIGAuoR+JYM545PhuDGsh645ehiAo/LdWMKOe
         Rzp7qkROAK1HMPjuiWcQxiJVid5sFeXS4sm1jTTHy4poe+FPr34+TZcgKG+uXCHvKN2F
         T3c8jmoiWCEB4+6eoKLPfx0Y1nifOZ7TBh6GHMHBKI+33aLCOZvgSo86rWjxjKHyH+qE
         rNPT2V+8Mq0PR/JU3V576XMSu2NAtN2kAVV+ikLBsw5X/2lR+J0BdFHicYLIiKV0Yvsz
         42B0qUdUR7WnAg3c66wgAjpHSvFozxVrF0yzjkkM9SrfmWAjr/ZwRMGDxYBcHPRok8ni
         pzRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=WMJtrO1iHWw4DpdQ064zmvXsKuDRSyN3PZ1NioYUQ9U=;
        b=mkbDQzBrAXiA5MId383mcYjvOha9IqOHlsoOciqA6zwUvwd0CfYgS4ZljUBNj9x+sI
         VCeabJB2iNLsgLxyGL8Gr8KSlEw1ldF6tyk/poUGR7ub1NaVEMPvgG/oMpHYbK2kYt6g
         Mv2nnobMi7BeKLl3QKD3VzB2rYGnm1z5dDz1aUFxb5L19b6aSiEzB7q79mhuDw+fygsE
         1ZI+iij5UtxP7AL7RZV6PTLcP7fw8az9HFVaOBpvO69u/riPLlWLNxZuQKj7GiUZLtYT
         l2iMzPodRMlxcPIejNoaW0c6mCuAyDq93bcIESJJG0yc+cYD1ouw0+NHs5Yrgjs6tfp+
         UHig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WMJtrO1iHWw4DpdQ064zmvXsKuDRSyN3PZ1NioYUQ9U=;
        b=nG4dI7cT5UNGizmed765fD6a3+XRa/meg3rRYG413rBJmAaJsLJPrwCaFm/Nkm24+q
         ogpEVJXM/Zs3mOe33jnLfaQI9/8539CrcsJqddamRSgFlpLHKT/uhsDjagXBZngWIeOI
         FXe829wBFll0BpZ4ROVLAVu6yX95pYkpYAzSSTopXwFcs9DyG195wJQCknc0+LZJNumE
         /w+xqvAV5NLzWrmWoF+c91LGRbBbKf5AGzhWP6FMIFx+TcYCmaDLORuZ8v5a+oKUI9DX
         BMGBi8XfoqciwB5Etgeakr0UndKRQEcEggtIGH7dtZ9Ty0KNVLHTSL8VmXILBqcB26aH
         oUpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WMJtrO1iHWw4DpdQ064zmvXsKuDRSyN3PZ1NioYUQ9U=;
        b=W9po2iJOmkam2HfkTqS72YOOMmUvN9SZajaDQ/lLYDETrk9ki/HPp8NalUP7GIiNW5
         oouNCvMVX6LfFpFuGgCCjVJAMYMON2tS0X2Zr5lCDdYWg+G1+rd1EydXtvnTfvyWLoSM
         zJf4Nf2OPfwu3oFbm1UZBx6U9Q9MCGUcYjuNzkh2Uir847bfSVHjo9/KxedtfBMSTOlh
         mv08DUuKR5fIH6eG+vR50czj9mDLqOgO59CEepp4uU8YDIvHhbAdHyFLR5i9MkDb3x+A
         f1q3AZyDB3xVqZyFDZdtgdNOf93zAAxPtT8zrBcVICVFRUiP6gId7Hkz4hBwzkmsA2yM
         BzcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWIQVaPLSZRUmh+Eeaams533b2u1eV7aGFuDZ11Bqw1Q55CAZxu
	hig1NBGcInzIbR8F6pUje1I=
X-Google-Smtp-Source: APXvYqyLWMlTUbBovVXWHgfFdXsT8U3QlDBuxap82vuJPKWXl00U8qsHRMCrl8tk/8Z3AthdJPAGIQ==
X-Received: by 2002:a6b:3a88:: with SMTP id h130mr1277451ioa.217.1571710170446;
        Mon, 21 Oct 2019 19:09:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:db48:: with SMTP id w8ls3616829ilq.3.gmail; Mon, 21 Oct
 2019 19:09:29 -0700 (PDT)
X-Received: by 2002:a05:6e02:c11:: with SMTP id d17mr28809023ile.128.1571710169864;
        Mon, 21 Oct 2019 19:09:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571710169; cv=none;
        d=google.com; s=arc-20160816;
        b=zDNqq2UMstBiW+77kywpo1MJ7FzSMw9ZmiXLVBWY7MIiCOB1P6xd50CgpOrT1qzuzc
         vItIhTdZq6z8zyaoANQgrEH483BdAQU5ng3RWj8kHKGnZdhgM6RPhQnOruFElUX/7UzG
         LiCin8k+Nj2Cd40SCtQP2xuKRB70noaZGuoN2cDQlQnBGfyB2D0QpETpzS1i/7C5nLiX
         NOtvQphyzuS5YcjfGRpxLUtMWFd+oDVGCMr8hIl5pp/ut2zUpx9zXABZ7rQfSorrYD8G
         jOJJwEDBm48gOXX+iMNH9wPt7ZTKXYCnCNakmC7z9xUgnGOJtrJSrts0ACyuNZls1wvb
         b93g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=vEmMhVBM1YV7KFkQj0iOkwem92MxoUAoaOyMvEVsU6w=;
        b=PN5s5qRBjrwh4SGQEy4HIrytAmWCHBjDadSXck+uzQiaoZDDWcouIXiemR+0FhXBnh
         P7swm/Ndf/vTFNwivh3ckxyxuvnVNqRpWU37OETocQBSaCazK4wu4ChIrOj3vhemUSF2
         R0A2Gq65/YfOjGz10I5FsizENLc07DOwj+sc80g4WlVAR5uq0EU5/uCZ2a9GwsKStKPs
         wdiFEe15LdFfhklFOZ4zZRMqvd3LZrSjy/wdmgmz0+2wTZRVqUJ6mbRukC28a7ZQK6eX
         GN1pp8APCX4ko6D/wynVQdogcdPWDriQ68t5uqOyBpBX4Dz/+DajnADwJ0RNZqqzSl6s
         5TrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id z130si639107iof.5.2019.10.21.19.09.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 21 Oct 2019 19:09:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x9M1q10Y068205;
	Tue, 22 Oct 2019 09:52:01 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Tue, 22 Oct 2019
 10:09:00 +0800
Date: Tue, 22 Oct 2019 10:09:00 +0800
From: Nick Hu <nickhu@andestech.com>
To: Paul Walmsley <paul.walmsley@sifive.com>
CC: Andrey Ryabinin <aryabinin@virtuozzo.com>, <alankao@andestech.com>,
        <palmer@sifive.com>, <aou@eecs.berkeley.edu>, <glider@google.com>,
        <dvyukov@google.com>, <corbet@lwn.net>, <alexios.zavras@intel.com>,
        <allison@lohutok.net>, <Anup.Patel@wdc.com>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <atish.patra@wdc.com>,
        <kstewart@linuxfoundation.org>, <linux-doc@vger.kernel.org>,
        <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
Subject: Re: [PATCH v3 1/3] kasan: Archs don't check memmove if not support
 it.
Message-ID: <20191022020900.GA29285@andestech.com>
References: <cover.1570514544.git.nickhu@andestech.com>
 <c9fa9eb25a5c0b1f733494dfd439f056c6e938fd.1570514544.git.nickhu@andestech.com>
 <ba456776-a77f-5306-60ef-c19a4a8b3119@virtuozzo.com>
 <alpine.DEB.2.21.9999.1910171957310.3156@viisi.sifive.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <alpine.DEB.2.21.9999.1910171957310.3156@viisi.sifive.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x9M1q10Y068205
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

On Thu, Oct 17, 2019 at 07:58:04PM -0700, Paul Walmsley wrote:
> On Thu, 17 Oct 2019, Andrey Ryabinin wrote:
> 
> > On 10/8/19 9:11 AM, Nick Hu wrote:
> > > Skip the memmove checking for those archs who don't support it.
> >  
> > The patch is fine but the changelog sounds misleading. We don't skip memmove checking.
> > If arch don't have memmove than the C implementation from lib/string.c used.
> > It's instrumented by compiler so it's checked and we simply don't need that KASAN's memmove with
> > manual checks.
> 
> Thanks Andrey.  Nick, could you please update the patch description?
> 
> - Paul
>

Thanks! I would update the description in v4 patch.

Nick 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191022020900.GA29285%40andestech.com.
