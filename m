Return-Path: <kasan-dev+bncBDPYNU65Q4NRBD4R5SKQMGQEHCGYWXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A820555E51E
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:56:32 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id y35-20020a0565123f2300b0047f70612402sf6275833lfa.12
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:56:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656424592; cv=pass;
        d=google.com; s=arc-20160816;
        b=SbpxlkTsXrsPgXduB5rm6oz+wdVJiwMD59VAMmdyworCCDcftW1xan7gh8Yag/viaH
         5C/Q7ZVpzYagnFhbcc3P0qzdwTG3JkVauBMk7Ot8tWraJlmlfmA4tyekQK5oFH08jAKZ
         jwF0ICfytVWradTPNCJpQUVKjKhC3KdxE24ffSTYdVdRUIBfktG0pJRJt83HmX4zDLg9
         OYCel768D5zD/RdLfF5wPXMhkm8yH1ZhC+hSXcu/7A+lvlHB1G6c7OFdcrJ/ygKuqZkg
         FGg0Cte2Te+oCsN1QeFDIpejGj5KUkdJXM/RkXGDj8cAfWbRwj21ADoDl2W6xphH0H/h
         EUSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ey7vGa6JC6YVhlktrSyBkw9XQvKVjUaIe02udIMuqBE=;
        b=ilUudeipUBp7q6K+h13FPW1KmzwYVXWDoxcbi3BKBPYNRChcMbQUf6Xq2ydXLeE5h9
         XOYxMPvmYHhp0NcSYXmBGjbzp+PAcazhJuUWKYowxbYJQviK1MF0hSGPJ3ryhjunRBHr
         II/b222kU53HZhYW/XBTvtDkXnHTd8h3ci1kqIlHKEeGwQTMnETY/xXXvuR3gx/7wIyf
         MV0kKeYT0RgnWy6K0kYXce42UiBs69+EJp7ddlknTbdUXyNyQvrZo++lSegg8NX0+DEi
         zGMwgQpibPy2OeeEssQzifnDu8F7RADrJWoUfRWHf0h5Q4eFmnt3SqZRcJQHU6G6CX+q
         TnRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ipH9xLLO;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ey7vGa6JC6YVhlktrSyBkw9XQvKVjUaIe02udIMuqBE=;
        b=HjOCqhWIQFwmvWzoD7kbP17lgo+mdmAykwVLqZlP/FyzCk/2kbu+n3xQQyeMiLzF7v
         S3oN8o3kyASt8F93Q2AHrqO9J6fnajbSMkGHtJ/Yx0hg3NGHOfuKbgZcWyF6jX9jugcb
         O47571OjnBbRQ+nxUdGT6dyKD/vqdxq75jGnrMi7lTQyF7n52oILTA2zYLgxNfhrQ4E4
         o7yar8HKKkzZXNOPIx5YtL2pfTDxZ68Knhv4iuGHp8SrKjAkjPSOtMWERWUTWnoMMhbK
         7B1JK4+Y2Qdb+NZCWTWKA7omv7RAtUP0+vnP4sXW/ywmFtpExcHspme3KkQuS3tPdOvW
         MoCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ey7vGa6JC6YVhlktrSyBkw9XQvKVjUaIe02udIMuqBE=;
        b=gg4uOEqnQUYF4rjttHNgIitKo7eWrNtAx/yrbL0SERDRXBq+7opQYjQSsYEPgqVJdQ
         eI8VZGpi39XSQIwfxWFrI8Ml8Rrimp2q+688M3l7L2TYwRtqvY26zsI79Epd6tSKzcob
         lqOj+NGnqEQbJdUKzqyIDS+1KwqbIZNkR1pmWGHlAJAcPu+SwGBQH4dddwNmMixh8Ers
         tz5ioZsoPYvLJ+nAlTx2VpN/pjxD9bQ9uzGBeTLrgvBc4GuuUQVItn2WT8OBNd1/z/R1
         UzZQuSRMcu5gMx4dkqQYio/Wd5uktFBt161v5LvU8CNA/7XWeZVyQE0Qb9JZJB8eK3pI
         YumA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora83jkXDEq8BpN8govW0GpJ/S8LuzukUiA2UZLYy0PI8JLuCR8H/
	hKgBKE5Cpp/osFuScAMQtoI=
X-Google-Smtp-Source: AGRyM1v9a/lgWS3FeN1xKC3yKFENDRv7W1+/LVz+P/dvmtUW/p2MkkoO726B3+fvTCSMiDGZnCCe/g==
X-Received: by 2002:a05:651c:12c6:b0:25b:cab8:cc2a with SMTP id 6-20020a05651c12c600b0025bcab8cc2amr3992345lje.110.1656424592031;
        Tue, 28 Jun 2022 06:56:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b041:0:b0:25a:7050:86fb with SMTP id d1-20020a2eb041000000b0025a705086fbls3965935ljl.10.gmail;
 Tue, 28 Jun 2022 06:56:30 -0700 (PDT)
X-Received: by 2002:a2e:86d4:0:b0:25a:c3ab:5bae with SMTP id n20-20020a2e86d4000000b0025ac3ab5baemr9808996ljj.405.1656424590616;
        Tue, 28 Jun 2022 06:56:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656424590; cv=none;
        d=google.com; s=arc-20160816;
        b=SBfAIuCy6ap0tmDvrJ/fFLO7nY1/d/uG4fmQVicJQ3uPO3TDEtPW/1fdW0wKBaCh00
         eo4GGHI73AON1TXW5wQrUCdySNBpSXH8r+UDefY5Ob29fR5Jb/MgOsQvXPl9FpjJE9st
         +ulyNbgB/y8fIIEURrPmK24E4ujauer7Fc8q080A5kQp/F9AYw+9IPAVS1CoXXfddJSx
         pWByL+17b156g3BbihzmY0oN2pJTy8QlooP7Mww7oNudUKFUfOGgqAraK2M3HmZBgAU+
         Q++WS7VIvCKmA9QpZ/72VMrwBFrE5P7/vRGI3DTGYNFUNd5eGHws/Zwg1gPrdtKvlWXJ
         JeDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=c/hsOFU8NZChn1cDgCBCh+5A62UGWSMcJpUCxlWJ8tk=;
        b=ETkpTt1lnmmrrZgwLhmC5GzHiL81nIDLoXxG2dlzIZvzZ8/TZLOQrjsb5mdXsU+FOA
         Ug0bP9byw4ThobPDZeQvKYVs3DjF1oWZ9J2h8bY/y6HplHyqTXUlEPPhu/DLzGcvPvtk
         p0wwlZ/1cm+IBbA9Q4Cn9BbP6Q7W9JaAKY0D6mEVbwG4YbrRaL47Lsy+6oKY9CBcNyrx
         b3q+5ngVUxaI2dJF74tpe275DECDPPpuXL6J2T5TMcFQoyhqNRhRAruD6M5a9KWkjJki
         gu/WDr9kuHkHI6Zb2OLE86nBhXN0N+BOwWBThVmVTh2kEAcawCieTXlH1pqS6cLreC13
         6j7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=ipH9xLLO;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id k10-20020ac24f0a000000b0047ad98bddbasi702242lfr.0.2022.06.28.06.56.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:56:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 0A731B81B97;
	Tue, 28 Jun 2022 13:56:30 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C80ADC341CA;
	Tue, 28 Jun 2022 13:56:25 +0000 (UTC)
Date: Tue, 28 Jun 2022 15:56:23 +0200
From: "Gustavo A. R. Silva" <gustavoars@kernel.org>
To: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Daniel Borkmann <daniel@iogearbox.net>,
	Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	x86@kernel.org, dm-devel@redhat.com,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	linux-s390@vger.kernel.org, kvm@vger.kernel.org,
	intel-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
	netdev@vger.kernel.org, bpf@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-can@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux1394-devel@lists.sourceforge.net, io-uring@vger.kernel.org,
	lvs-devel@vger.kernel.org, linux-mtd@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-mmc@vger.kernel.org,
	nvdimm@lists.linux.dev, netfilter-devel@vger.kernel.org,
	coreteam@netfilter.org, linux-perf-users@vger.kernel.org,
	linux-raid@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	v9fs-developer@lists.sourceforge.net, linux-rdma@vger.kernel.org,
	alsa-devel@alsa-project.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
Message-ID: <20220628135623.GA25163@embeddedor>
References: <20220627180432.GA136081@embeddedor>
 <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
 <20220628004052.GM23621@ziepe.ca>
 <20220628005825.GA161566@embeddedor>
 <20220628022129.GA8452@embeddedor>
 <20220628133651.GO23621@ziepe.ca>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220628133651.GO23621@ziepe.ca>
X-Original-Sender: gustavoars@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=ipH9xLLO;       spf=pass
 (google.com: domain of gustavoars@kernel.org designates 2604:1380:4601:e00::1
 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Jun 28, 2022 at 10:36:51AM -0300, Jason Gunthorpe wrote:
> On Tue, Jun 28, 2022 at 04:21:29AM +0200, Gustavo A. R. Silva wrote:
> 
> > > > Though maybe we could just switch off -Wgnu-variable-sized-type-not-at-end  during configuration ?
> 
> > We need to think in a different strategy.
> 
> I think we will need to switch off the warning in userspace - this is
> doable for rdma-core.
> 
> On the other hand, if the goal is to enable the array size check
> compiler warning I would suggest focusing only on those structs that
> actually hit that warning in the kernel. IIRC infiniband doesn't
> trigger it because it just pointer casts the flex array to some other
> struct.

Yep; this is actually why I reverted those changes in rdma (before
sending out the patch) when 0-day reported the same problems you pointed
out[1].

Also, that's the strategy I'm following right now with the one-element
array into flex-array member transformations. I'm addressing those cases
in which the trailing array is actually being iterated over, first.

I just added the patch to my -next tree, so it can be build-tested by
other people, and let's see what else is reported this week. :)

--
Gustavo

[1] https://lore.kernel.org/lkml/620ca2a5.NkAEIDEfiYoxE9%2Fu%25lkp@intel.com/

> 
> It isn't actually an array it is a placeholder for a trailing
> structure, so it is never indexed.
> 
> This is also why we hit the warning because the convient way for
> userspace to compose the message is to squash the header and trailer
> structs together in a super struct on the stack, then invoke the
> ioctl.
> 
> Jason 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628135623.GA25163%40embeddedor.
