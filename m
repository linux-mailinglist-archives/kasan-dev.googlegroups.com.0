Return-Path: <kasan-dev+bncBC7M5BFO7YCRBZMTRGDAMGQEPDLJIUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A25F3A31F0
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 19:20:39 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id t8-20020a17090aba88b029016baed73c00sf4199032pjr.5
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jun 2021 10:20:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623345637; cv=pass;
        d=google.com; s=arc-20160816;
        b=uDa4VpweSqrYNzmXy8EoGhyc0i/5SrY1h7Ag8Uzz1F9iCbVfSPvLvGoPCSdOKt5les
         t6q4XkvNmDD6KEEvIxwpx/boQ60UyD/041LRnVa68/ezJSW/iNWZ452P892kJnc24txD
         ojFFqt5eW6y47UFss3k6T2jpomhE91rNrcB/fjRehCf8P/OrcPzw5XUTRuE0HMg70/Tx
         4N4Ca4DTjQMw+5tQfr941LCRduP3QJG7RYCWnWQfAoPITeg2ZsTjQOOEL5PuFv+ifhq9
         j0GCC+TaaY2yjxrPIP39LqSSzRfJAHopUh85cLRDAyfR/Z/NMMvSSu9gIwUjCcHXOxbM
         yhIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=+fFsT+yhbsyjf/bQBZA6TTrMmT1qgXyQ/hDTqgradSU=;
        b=l64xE+FlucNy0gybF3/gk2XILzj/MJGwsKmh06cOu74RvBhTNuEV81AntJ4PUOZ0S6
         3XgXG32f261k55pc+AW9qI4PRsDFvHheBwWwABrbj43xUdG3S8/u4SCPBiuFYEkQqPG5
         t5Y1tAfZVSzqWXGrPsY6BLvCFRF3Ro85ImnwqJnbHNsgr5fGbqmFoYjZQtESNy46qTGp
         lt3Nr8azCM5raVPacrZTP5C1GrXS1W9oHrDfdtmSu5vg8qVJdJTPevo2K8n1ncyK3VRt
         SrfZMqCzltKWKIeA8p8aRhIzjMacmZvj4RbCQAjrP5S0EtPg2l8TzFTPa/84yJvCzxs9
         BrIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XskWsx9d;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+fFsT+yhbsyjf/bQBZA6TTrMmT1qgXyQ/hDTqgradSU=;
        b=YEiMUmoCE85qJjzjhcZ7yeIFF654SyceA3iP61fSPTlvvHzLoVvov+dFSRECUuFSeo
         cu5RdR67NGLkitul9qHfaO+GVhsm9fEu+4bT6606jhX/ROX3CfaxNvuf5I4X99viYe4E
         Yf5XKx4xTkw6J1a/QpidIAmpUptG9dAdgJpJj3EMS4bAhd2Izrxf5hW+EG+fPU9oCAru
         xLYXHpkYocEgO/t3xen+KWtln3ncGvHExsUkC0tN16JlRQITPAad2m5SxEkwUFzRHzIf
         hI+pgsS7CAiREFqwrvI9rpfsv4KeGrQablQdF/7nGQe4WmpFwBkZTWJ1JMNEB84KBhoE
         9HQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+fFsT+yhbsyjf/bQBZA6TTrMmT1qgXyQ/hDTqgradSU=;
        b=VYEmI/ifgXxX3b3knDeXFNV1bqE1hkbqMjhVnrmELmhe1T3tt9dDBbwgGbU8lNZD+D
         fkPSgdUYZFi7S4w/cF+UrXAt/YZ20/vsKUSDTjh0xANtXlZVwwfJYs2meS5S4CuFhLdy
         s/CNpfWIXLSvlqqMmLi5KP8sz5i47mCB+mxxMGLcm7fLttjI9QhpeC9U9mPJGzUcO/7Z
         EYXxQuNSjLxFot9S2YIw3kX6W3sXfRHdKN2xYPL09KvEJSd4Elu6Jsch3hZxmnemzgJ1
         VN+UEqdw386t/KPjodiHQeRP56xTDubzDZgmE0wTjAQfboVO/KDTTFCvELjAyktLDcg6
         rUgQ==
X-Gm-Message-State: AOAM531PWHs2ovtifIztFd6KANIgXgpbNKGo0HIY0Bu/su8fhessR/rr
	NJLi/QY6B1I6tROF2T51sv0=
X-Google-Smtp-Source: ABdhPJwDKRi0un7vZ++CAFbPoC4/7UgBehFA4gOihXprSwEDKSAPADvoZErMpNpavzS6VHKZkCR/9w==
X-Received: by 2002:a62:78d4:0:b029:2ea:ba:234c with SMTP id t203-20020a6278d40000b02902ea00ba234cmr3994923pfc.53.1623345637721;
        Thu, 10 Jun 2021 10:20:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6487:: with SMTP id e7ls3188919pgv.7.gmail; Thu, 10 Jun
 2021 10:20:37 -0700 (PDT)
X-Received: by 2002:a63:4b59:: with SMTP id k25mr5910759pgl.252.1623345637030;
        Thu, 10 Jun 2021 10:20:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623345637; cv=none;
        d=google.com; s=arc-20160816;
        b=iuP8V+aBUROSiCRbvEd/+YCN2kzvcNtEYjTLgYRt73LXVMrPqFsG5Ea34J8Le5xRO4
         dvM8FdEECXpvpST0EtCqILZDlW8oZwNnQVcXpV/mhk45VAXy6ipMYPB5V92iuFm/EEHr
         z/2VhPilazUt2nnwEVAXvdqIZkooEgHJ4i28WkFts2+LQUZcSeZaHdM126bWEkSlzsvH
         JIf7SgHMvcSQN/NSj3TdWVjCloS8rbZdK6isWwSIPYzXVGY5VXI5HLnwHBsHDsu9q4dK
         MtwILfMLLowryw/tOGRbP3+POz8MLw7qwavXnGNUPdRlPaD/Yx+TL1/7cAVPcmR4aPn4
         a/mw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=g6SU8s5JZXBpJRY7xHwXt52gkhZm/7vIqjpkQlZi7O0=;
        b=Mn+PMgNp8046Inl/BVoa4blZYes5wWqsjzSrPjmDOif5qilRCztB+RG0egUpN1tveN
         arxFh83UmMnFaJh2UY/2X3jKqeBJZh9QNohbzNHb9WWZJLmUPSVNDH3MjZY0+Xbvsxzd
         wBj/EU35gm0jJ1G69Ll1J2ckWH8YDSWgCImIk38vGq+B3a4OmbsTYUhVkEHeKD0nFA68
         B7tO0OvnkJuqsuIF5AQPo5ltOHi3EwQHqyUWWJjjn1cq6iHK+fNb5L91mvqJcae1AhQ1
         6xSUAhQE3Wsqt3hvfIHEy8syY2aq2ij++4lo5bfkQ7lpd6eTFqgs50zLB/6WOl1QRjIr
         V4CA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XskWsx9d;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::32f as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-ot1-x32f.google.com (mail-ot1-x32f.google.com. [2607:f8b0:4864:20::32f])
        by gmr-mx.google.com with ESMTPS id y10si366307pgq.2.2021.06.10.10.20.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jun 2021 10:20:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::32f as permitted sender) client-ip=2607:f8b0:4864:20::32f;
Received: by mail-ot1-x32f.google.com with SMTP id 6-20020a9d07860000b02903e83bf8f8fcso391286oto.12
        for <kasan-dev@googlegroups.com>; Thu, 10 Jun 2021 10:20:36 -0700 (PDT)
X-Received: by 2002:a9d:7282:: with SMTP id t2mr3382022otj.288.1623345636778;
        Thu, 10 Jun 2021 10:20:36 -0700 (PDT)
Received: from localhost ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id o2sm634382oom.26.2021.06.10.10.20.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jun 2021 10:20:36 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Thu, 10 Jun 2021 10:20:35 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: Andreas Schwab <schwab@linux-m68k.org>
Cc: Alex Ghiti <alex@ghiti.fr>, Palmer Dabbelt <palmer@dabbelt.com>,
	corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>,
	aou@eecs.berkeley.edu, Arnd Bergmann <arnd@arndb.de>,
	aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
	linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-arch@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH v5 1/3] riscv: Move kernel mapping outside of linear
 mapping
Message-ID: <20210610172035.GA3862815@roeck-us.net>
References: <mhng-90fff6bd-5a70-4927-98c1-a515a7448e71@palmerdabbelt-glaptop>
 <76353fc0-f734-db47-0d0c-f0f379763aa0@ghiti.fr>
 <a58c4616-572f-4a0b-2ce9-fd00735843be@ghiti.fr>
 <7b647da1-b3aa-287f-7ca8-3b44c5661cb8@ghiti.fr>
 <87fsxphdx0.fsf@igel.home>
 <20210610171025.GA3861769@roeck-us.net>
 <87bl8dhcfp.fsf@igel.home>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <87bl8dhcfp.fsf@igel.home>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=XskWsx9d;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::32f as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Thu, Jun 10, 2021 at 07:11:38PM +0200, Andreas Schwab wrote:
> On Jun 10 2021, Guenter Roeck wrote:
> 
> > On Thu, Jun 10, 2021 at 06:39:39PM +0200, Andreas Schwab wrote:
> >> On Apr 18 2021, Alex Ghiti wrote:
> >> 
> >> > To sum up, there are 3 patches that fix this series:
> >> >
> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210415110426.2238-1-alex@ghiti.fr/
> >> >
> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210417172159.32085-1-alex@ghiti.fr/
> >> >
> >> > https://patchwork.kernel.org/project/linux-riscv/patch/20210418112856.15078-1-alex@ghiti.fr/
> >> 
> >> Has this been fixed yet?  Booting is still broken here.
> >> 
> >
> > In -next ?
> 
> No, -rc5.
> 
Booting v5.13-rc5 in qemu works for me for riscv32 and riscv64,
but of course that doesn't mean much. Just wondering, not knowing
the context - did you provide details ?

Thanks,
Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210610172035.GA3862815%40roeck-us.net.
