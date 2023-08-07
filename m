Return-Path: <kasan-dev+bncBDZKHAFW3AGBBTEAYSTAMGQEEHNFYWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 54B1C7727CF
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Aug 2023 16:31:42 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id 38308e7fff4ca-2b9c5cba6d1sf45117351fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Aug 2023 07:31:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691418701; cv=pass;
        d=google.com; s=arc-20160816;
        b=XKLjiFmvWvUN2+089AIwLCXzJA2OzEFeQknOWy0jsVvkU7IsFLy36QmKxS3ezq7guE
         rHbvWZ+jq3xblXv+clVUehbUuga3W3J6JHJPksql+GQvXjL9qxcxphn4yISPIpNJ+B61
         IUutTlr+8LziTRw/Rtau2RvK/t905YS84DFx+xMTOzqxZJsE94MJIiFOFYhYYnP6UdeL
         V3UDMLBaoQ6eXFxup17x2kBVEu9rh6ZSL1rYLmX/rd/LJaM+2iZmLP/ANXXABSZ3jLX3
         ZzlMeMr+YvWoAN4y3xkoddoKoo/+TOJP0lmoUxlzTWoZ3+pAZcnZWBPIy1sACrhOnyjw
         8gJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=S7QxlDhgp+XNDbyIR3MB/jlyCYhhE8lfJ+esqpqao8c=;
        fh=GyiYDglD9h29HXXbD45R+obMNrZsHNJsyw6W2UMF2tI=;
        b=E9yFXAgs7QSZi3tm/+8tndqWPRA7kME7Q33N2WUj2czBQ8XxhXM9DoQgtV5r0PhFNM
         O63faP8jUggjLetWFeC0kUmL4aNFvHgnePZ3rXxn0jxCh9nvQHV7u0V/ZcQbQeBeDPnu
         Gj1jeWpn8FAuXWM7dGaUh52TGddPrMxuh+1JgiwT7zV0g4NZSg5WkMwNltRepP4E+mEZ
         KSPooOTaS34EXBnXeOsMe5IMZHizllstWyTSsn2TN3FXJPsKHbHQQOOgOGp7XeV1RjO9
         xHT5hAN4irPxh39ac5zfc1kUKjUCyTRY8A2zYs2CDRcpUwo/XLElQBxZHLyIRcA7+Itk
         ap3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=puqzPyxh;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691418701; x=1692023501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=S7QxlDhgp+XNDbyIR3MB/jlyCYhhE8lfJ+esqpqao8c=;
        b=AwzYkc3ztqcsEwJNAVdSU740dNpVaM2NIba12HQ/GmAXF73wBXrKHN6mIkcUwrvggV
         rhcfVkZk2aQR0lpASg/1f5KlNSqQyz3qiff7+t6QiH1i6PYa7go4eRT3plfpVMi83YbY
         LvDRqQ3Bxa6u5bkyjEzJSfqwpuzcBPl9qCnjmrmrpi3zYSwC9lF9T01CNXz15AwhC2+I
         pggyQgnvWzZR6SUqX8NwVoxQi8Tqu8bxiNRuwQLfWD0xDM0g8zHTAoOMwCxwItQl2smr
         zsFXwy1GNfv3U9qACB7guPSEWT0dr4Yw76Rhq4T7mRKyKzqJVy+BJ9sS9gjiZP226e64
         D92A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691418701; x=1692023501;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S7QxlDhgp+XNDbyIR3MB/jlyCYhhE8lfJ+esqpqao8c=;
        b=J6XGN3bwma4RMhMY0kZzS4v+mArl4Eh+g0iGA/3QFVLBHRCcduX5KBf4asFgnZxkKk
         xSkxVFsB/+jWnS8axXSrZ5KcdSsT5Of53MhbS13h/DBTrsELLbmAZ83DE/R8DgLCCtCu
         YN/laf9jWyJhmes0FhpPBiAbf95nAyI09a6Xo81OVMEyqmfP83UdJCNdz40/FNHr6euJ
         RF+hMcXMwwlTVewzd55RZD+687bOGL++8B6UUBhd3wBIMFufrjFSbSVngPJQKzefOg+V
         R4Hdo4YApStk5oGgkseScZ1TAEKurxsQRrFfblxZa5n2cOcq2CzU/12IikRyxVIo+NdE
         31ZA==
X-Gm-Message-State: AOJu0Yzl9BxzWmSvAhQFdwhl1Bco1Al3Kgj/r3xQ+71nP0WgxiDlD0+j
	PcLzRYTiODcqm1Shd9bGIbY=
X-Google-Smtp-Source: AGHT+IHMCZZCenql2EanShqL4n8nVUd0F4yzunER8arYOeqMMEgNB9GdUZFh1JP+wzkpFIvQ/IqAMA==
X-Received: by 2002:a2e:7a0f:0:b0:2b9:c046:8617 with SMTP id v15-20020a2e7a0f000000b002b9c0468617mr6217350ljc.5.1691418701172;
        Mon, 07 Aug 2023 07:31:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:10c7:b0:2b6:9e60:5995 with SMTP id
 l7-20020a05651c10c700b002b69e605995ls37359ljn.0.-pod-prod-07-eu; Mon, 07 Aug
 2023 07:31:39 -0700 (PDT)
X-Received: by 2002:a2e:87d9:0:b0:2b9:54e1:6711 with SMTP id v25-20020a2e87d9000000b002b954e16711mr6137485ljj.7.1691418699351;
        Mon, 07 Aug 2023 07:31:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691418699; cv=none;
        d=google.com; s=arc-20160816;
        b=CXvfkAavtLQaGZUXQ1mwyW6vSd7U/6NAE7M/5Oy2LVBqNNHDzRoez2PG31XEI3bdCa
         Ovn79xhH8x+bz6CE+7gjdcr+sF44qJNwLbnCsVHqtG7lQUpLCjgvzTOolbRjhtMDYPJE
         Yruz1vDF7b6+v7PGNdgJPYb01LRUgORyo31vYf1Ga1rZ0GbYfJnoBRcbDWM9N1Y+wug3
         SbNBWgRvZeEfqBF6F/L2re98lkEdP74YlXyTq+u2suS9W4OqTa4Sl6jrjf8V04YLFsuu
         McpN6laotBvCK4ExeuuK8CfsvQ0TSj5+iVNSNInvrg719ZveG5LzeyRcI55nWV6Pj3vm
         gb3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=4fOeICDyT7K2QTKRJ6MV/fDafXjEn/AufQ8OCjlhJmc=;
        fh=vmUQn/KoiKBz0TN4QXh4zrTyMSy/18taF2m5XcOxj7k=;
        b=RvGkW/VbaMOk8Tt/Nja1mcKW35cNS97buxVyNrq2498kfWp2zqSysqmS8rAPi2EMqf
         QaqD2FL/yZtdQxSHplV0ifA3NzvA9PuCI6zZ/04MUjHBI88bMpb0iC6eW0RiAzP330gZ
         d0/JMiq/XZUbnNfrmvCN0bwZdFudNLY39ZPdn31TrK3yYUro6WTvz+YLwLeFuJitfefl
         Xxe7wchnMDUBZ8E9I51uLIl3gdh7PRw+xJBtPb9Uno0K9nbAymPcUy066XtmPE+2tr/z
         RFt4iqrM0poyb1kGjfyb/O5JyhENFtHA9hUbbuYk+MItWwT48wzXdxI1F6w5+ZoWSNx8
         upXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.com header.s=susede1 header.b=puqzPyxh;
       spf=pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=pmladek@suse.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=suse.com
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id k8-20020a05600c1c8800b003fe1c5703bdsi1253259wms.0.2023.08.07.07.31.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Aug 2023 07:31:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from relay2.suse.de (relay2.suse.de [149.44.160.134])
	by smtp-out1.suse.de (Postfix) with ESMTP id 04FCF21AD5;
	Mon,  7 Aug 2023 14:31:39 +0000 (UTC)
Received: from suse.cz (unknown [10.100.201.202])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by relay2.suse.de (Postfix) with ESMTPS id 5E5292C142;
	Mon,  7 Aug 2023 14:31:38 +0000 (UTC)
Date: Mon, 7 Aug 2023 16:31:37 +0200
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
Subject: Re: [PATCH v2 1/3] lib/vsprintf: Sort headers alphabetically
Message-ID: <ZNEASXq6SNS5oIu1@alley>
References: <20230805175027.50029-1-andriy.shevchenko@linux.intel.com>
 <20230805175027.50029-2-andriy.shevchenko@linux.intel.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230805175027.50029-2-andriy.shevchenko@linux.intel.com>
X-Original-Sender: pmladek@suse.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.com header.s=susede1 header.b=puqzPyxh;       spf=pass
 (google.com: domain of pmladek@suse.com designates 2001:67c:2178:6::1c as
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

On Sat 2023-08-05 20:50:25, Andy Shevchenko wrote:
> Sorting headers alphabetically helps locating duplicates, and
> make it easier to figure out where to insert new headers.

I agree that includes become a mess after some time. But I am
not persuaded that sorting them alphabetically in random source
files help anything.

Is this part of some grand plan for the entire kernel, please?
Is this outcome from some particular discussion?
Will this become a well know rule checked by checkpatch.pl?

I am personally not going to reject patches because of wrongly
sorted headers unless there is some real plan behind it.

I agree that it might look better. An inverse Christmas' tree
also looks better. But it does not mean that it makes the life
easier. The important things are still hidden in the details
(every single line).

From my POV, this patch would just create a mess in the git
history and complicate backporting.

I am sorry but I will not accept this patch unless there
is a wide consensus that this makes sense.

Best Regards,
Petr

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZNEASXq6SNS5oIu1%40alley.
