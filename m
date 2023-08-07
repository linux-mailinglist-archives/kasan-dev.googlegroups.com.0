Return-Path: <kasan-dev+bncBDZKHAFW3AGBB7MQYSTAMGQEFMPV2YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C37E7728A3
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 17:06:38 +0200 (CEST)
Received: by mail-io1-xd3c.google.com with SMTP id ca18e2360f4ac-790a9d5b74csf361029639f.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 08:06:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691420797; cv=pass;
        d=google.com; s=arc-20160816;
        b=svuJ9innyaxR9AMVFSwyyE2vrqZYkPeLk0jgZTFODPycCRaWYlIcT15ERVAx5j2vep
         fu9KDygAwi2PiadMqVB5fskmutbPWusj1IynjN63Xvh8xyKJlVmJ0A488mFGBDG4x5/o
         1L7QxhVpcstypkcTfhVlBHTSGlECWeJDNEtAe7tQpPqq3ctWqESTohNShkUf5jcULSR6
         q29bgseW+MP/3+SOXmgk0Owl7p+Zx7Xhmb2RXFCe9QhjP2ik3adipazLWgEQ5ZNHx73B
         TAzVMGdyMDrs6Zr52mlBEsYva77/wNE6NGDJr0g3dLKCTZEGB4+7wZufvXpqLt7LgvSA
         /JvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=MZgIaSqKNqquuAZB18ud85U0PKLUCWS2rOoQUKF4xuY=;
        fh=GyiYDglD9h29HXXbD45R+obMNrZsHNJsyw6W2UMF2tI=;
        b=OMUXPNCjIKfZIvLyQFjhrvXRplEUnepvgyoJuyANmp0TqpYrrhFoU4ZZJoQy66TxNq
         Dk0luboPwgMpeOelMHn6b/nBDKFITQ0yrDDyTB6g5uJxu9a8CaplUPIjcT9Z/VBCoOtS
         h8uxuep3MWmM3hgkgsqnDI0HE8XKomQUZ+JmOX0d02++mJh+t1BkxuOklVNTpfwemqZJ
         WXDu2H1X39TPR5jsJevy9olzxCi334sFqjQOLWQW4WU8DUp0huMxApTkL0fy6TEsqEnt
         bmcKZz2wlkj8o2wK9ExMmqxoyeRSIuz8UaH3KWZ69+J5jNmkOplgsdG4Ue3x9XoUYyqx
         9iLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=hfz9kNXX;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691420797; x=1692025597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=MZgIaSqKNqquuAZB18ud85U0PKLUCWS2rOoQUKF4xuY=;
        b=i24Y+zr1os2C8Xc4MHi9UDItjLnVUzM8om2MSeoQu//hbKHEekdNOExeZE5Q3XfucG
         g9FwGyHPGSDzgXP+smJYtuY9HECxnUobr2VeQblto7YaWwjffMTFysl7lL+abA8qMz+O
         muHkA7TvUm9/CzGiA26XbYWLB3jpf4IwqTzLgGbj5LnJ19NZc3K5ODRK5AhywRL0bx3h
         zu/3C7Y/Q4HH9m8EGq19YqP2vBLVS06cvjyBWOp9aYdb+OMf5FDLRvco4GRdCeaRKTJc
         SifAkWhVD0R7UubjmetcPQR6y95nKHENjUQP+HlijRxiGyRp7sNZAdu8GbOtxvtfK83T
         VIoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691420797; x=1692025597;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MZgIaSqKNqquuAZB18ud85U0PKLUCWS2rOoQUKF4xuY=;
        b=RK20CVNLnpH9V6sDtNnrawyYpJ5v9BuaQ+yc/SeOHTYUAtbq939TfYt1yyJ27TKeJ8
         G7Put1+Tcbb/9uJ1EXQXvTzRsm40X3GVfNinLphE79pbQRyLBuao4Fdzq9oJWy26DSDb
         RtujfgduvOF643tVA3lNHxO4U3eISSfRzgD41WWyArM3JRgvH/E/ksvbIEfvNcViODNf
         1Vbp79Wa+hbDFNfk9GcQQRcQUx3BCRUvxn/WSdgo567QIEQMdmNQhJZbw2a6Njf6TSwm
         nB+0LN60BbBKrL9zQ9FJmJdHsZezOn8XJIXwpJ50WLwenf7K8jkfw8SvWc4Fy4t5mnAp
         nJ6w==
X-Gm-Message-State: AOJu0YzqQGs5BfAtnq9uwdZOWXvBv9SZPdhmIt/za42F6FW3a+II1pVu
	rmS6e+gwhirDh2XGl3fmZSE=
X-Google-Smtp-Source: AGHT+IFLOZ8c+iW1wTnqygInGm15AdF9W1E/HwnTUQ7ylV2vqYOSTOW+N4ISJTYW9iUVlVYcBFpQdw==
X-Received: by 2002:a05:6e02:1102:b0:348:797d:169e with SMTP id u2-20020a056e02110200b00348797d169emr6941315ilk.1.1691420797167;
        Mon, 07 Aug 2023 08:06:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:7608:0:b0:349:3672:b265 with SMTP id r8-20020a927608000000b003493672b265ls1472713ilc.2.-pod-prod-00-us;
 Mon, 07 Aug 2023 08:06:36 -0700 (PDT)
X-Received: by 2002:a5d:9e50:0:b0:790:8157:bc10 with SMTP id i16-20020a5d9e50000000b007908157bc10mr8496646ioi.1.1691420796460;
        Mon, 07 Aug 2023 08:06:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691420796; cv=none;
        d=google.com; s=arc-20160816;
        b=DinojURPXfDURiUvskQvfoCcMt8evklsbOYwHaPkTo8g0GmFvtzhzsbS/2a8+qn+9u
         XCsbqKzupfIZPspe/CIYYsR03kpnXscXsddqXLMb0F4a/BXsWBelfRIGPtL0ZYnufLuk
         PoM7XdiyHMaXNMxRDuW3syHUPce+chUgPaV6TQS457LnE9ilmQdU+xlfgzC0CeAgpmIx
         K0ReSBSMAOU+5tmeAhfLiW/d9WkZN2dkmOKMX0oqLLUdcqXW7fY3r5aszuYchgd7iA8j
         cD6nEkuvqIuGv0CwaEqmEZmbUoqzlKayPrrxP4pM/tLpWaKqqwpVLOalGN9+5hm/OZU2
         lT7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ORrKyaZwOQ/jexEB7RQEGSlaUvsbs8g0ZAVVA+oTshk=;
        fh=vmUQn/KoiKBz0TN4QXh4zrTyMSy/18taF2m5XcOxj7k=;
        b=C4N6bL1buGlmflDMkb7LjMY6UXGbwZC0CpHlmcFnT3E2mEF7Dkxe1kZAJsedNCPBNI
         TbSm7dxpt6AHsjG+oVOhPPjUuiagiWwRhosAIeESfwRebHvph0TiyKo6gJimyXV0alQO
         G/zVy1ta0y7Ub7diGeJzX2zBsiykKpWxWlWC2X/rTKcS3n8+DnHBU8lUf9hbJ9GK6eua
         pEFHoICrkQ0czcbk5CJiiG6AYojTJHHcRG7rte6daULZKfwAV8HNUG+rFlADGHUjcHk6
         M7E8u/OPI6I3qDPfCm75H5DW8GuUAFUjASGFHpXFolCChcLd0ZVgyCywiKNZrz9QpnTd
         anpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=hfz9kNXX;
       spf=pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.220.29])
        by gmr-mx.google.com with ESMTPS id e11-20020a056602158b00b00790b8bc4303si448692iow.2.2023.08.07.08.06.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 08:06:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 195.135.220.29 as permitted sender) client-ip=195.135.220.29;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out2.suse.de (Postfix) with ESMTP id 8C89E1FE4E;
	Mon,  7 Aug 2023 15:06:34 +0000 (UTC)
Received: from suse.cz (unknown [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 4E9952C142;
	Mon,  7 Aug 2023 15:06:34 +0000 (UTC)
Date: Mon, 7 Aug 2023 17:06:33 +0200
From: "'Petr Mladek' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
Cc: Marco Elver <elver@google.com>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	Steven Rostedt <rostedt@goodmis.org>,
	Rasmus Villemoes <linux@rasmusvillemoes.dk>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Subject: Re: [PATCH v2 3/3] lib/vsprintf: Declare no_hash_pointers in
 sprintf.h
Message-ID: <ZNEIeUOHoOIZJ6UE@alley>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-4-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230805175027.50029-4-andriy.shevchenko@linux.intel.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=hfz9kNXX;       spf=pass
 (google.com: domain of pmladek@suse.com designates 195.135.220.29 as
 permitted sender) smtp.mailfrom=pmladek@suse.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
X-Original-From: Petr Mladek <pmladek@suse.com>
Reply-To: Petr Mladek <pmladek@suse.com>
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

On Sat 2023-08-05 20:50:27, Andy Shevchenko wrote:
> Sparse is not happy to see non-static variable without declaration:
> lib/vsprintf.c:61:6: warning: symbol 'no_hash_pointers' was not declared. Should it be static?
> 
> Declare respective variable in the sprintf.h. With this, add a comment
> to discourage its use if no real need.
> 
> Signed-off-by: Andy Shevchenko <andriy.shevchenko@linux.intel.com>
> ---
>  include/linux/sprintf.h | 2 ++
>  lib/test_printf.c       | 2 --
>  mm/kfence/report.c      | 3 +--

If we agreed to move sprintf() declarations into printk.h
then this might go to printk.h as well.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNEIeUOHoOIZJ6UE%40alley.
