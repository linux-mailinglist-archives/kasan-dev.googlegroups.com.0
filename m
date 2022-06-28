Return-Path: <kasan-dev+bncBCUO3AHUWUIRB5UH5SKQMGQEVEX2ECA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B90D55E359
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 15:36:55 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id o11-20020a6bcf0b000000b0067328c4275bsf7199065ioa.8
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 06:36:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656423414; cv=pass;
        d=google.com; s=arc-20160816;
        b=yqfIdvApJY2gaR2+Ozebet0FiknGcMmhRuQdpIVXrJpSg6VFpgjqiXq4iLgmtYymB6
         QEZAm/E9O/cjIXYH1TKBthy9C22JpcLe2+NQqHJrgJSMnLP+8FOId9OAHZOKa8h5IuNG
         UrQwj+cHyd9p/efGCVOWI2hcyIKYFw5NvD8IVz0Kfu4F7ttgBO2Gh3dEnCXMdOB/7OcQ
         0+aJWgZeDdMFIoTfuu46mgICcyJSG5B0qSJDB3gWcIJG03sUi5R+J6W/kQZCAV9Dmw+W
         AxvQhOKMep7VVS8U7RSCUCRB0Pp27uD0Wpuf3u/N7SAwoqiJ7C5xJQml/y+9ypxfoTia
         gZ+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=c6+4wR2yO+DYtgN3dJ7bUCWR2k6b3ReZ0CRr9naCz0k=;
        b=AIhOXLQ9OeYywakUXdxDKU1eZ6h5CwSiO/PEfOQqmH9T6bNzWOweVjwvp1s9eaRq4j
         rv1KLu/4s7bBbzbWzqJWdIyHBDZgT5nFHjct/1Fd8HH3SKiZIH0KCpWB0iXMzJCH0CMj
         PoPUnKP7CUjpGp6gTtz1Esp8J/OUyHO9CbJVz2DchUBRWM1NFKBEUR042VZ4dlXNiTDb
         ZchsmeeAFdb62Al3SSJOovrVsLJuVWVkyiPki4WdFtIhzIOCPyDo1G02PE+0P/Gq19DW
         7AvY3651pU18nyc3P6YcrztNTCp6rP2NkLpJHSet880in1+Ysdb7fG2q6xXnHCmnQyQD
         XtlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=SRPS2zIE;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=c6+4wR2yO+DYtgN3dJ7bUCWR2k6b3ReZ0CRr9naCz0k=;
        b=fFtpSx5ZGkA7Txw+FjUlmGvAiOWGrQAzRTVulsji5ESvCPx0u0tYszEfKtkAz8rGOa
         iXamDAjEaraBqR64sXai53GvUV3DVuQxqCxhKhofqyu22z3WE3AlbS9sL4H5EZbjb1O9
         t25wtFHkSqWyLKcKxpvf5C1+wRxth0fwTcJHXUCvrWhxKVZLOZysTKcByRUcj7Iz8FlE
         uALczLbVzQbZeoLrijktzzFB1EuzWUp2So8TMS0rAs7WIrTeRfyPLi+GmEu7+Nf4ugxs
         KNFyLBwGOXYOyQ9wyosPa4X4YN5J1c/WYINmaqSj3seIkx3/fT5RnhS6XZz/KQnRvm2l
         NS8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=c6+4wR2yO+DYtgN3dJ7bUCWR2k6b3ReZ0CRr9naCz0k=;
        b=TgxyvUR6+bhg1Pc4u7Pl2DppDdW8ter8BmqBivjfI0vdGbo7vcaT3R0jlbPCIHw711
         rqYUXheXpR08jpQF5sIhgIp4hXVcH6n9+nh1aorRnDnOkkBBwX7VzHsehPAO9Fj1rHeD
         QzP/GKb/+U7+1zbQmMY3H58nd3SMydXKmA4heovNemvUy+BnoDkwrL7AH2sf1S4Sn+1o
         VwotTVoD1CD4K8eWv+1hdp5E6YXrcKXgSRkdOH6HcCEXsCZOcpI/8fmD7fNSkbsrSTq9
         sRDm//dIs9W6GbdZpgzkezWAGavMZPgiM2hjHvg9rJGAuDuUTRZzDhzcPh4+NDDI97/r
         FUTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/VveE4WLt321kChqNi0BjG/UjgkxInks5JTkGMIwTEWFMW5xJw
	IZyv91G4wRBOaraZVgeDaRA=
X-Google-Smtp-Source: AGRyM1ueL8GIHHUaRgtUWfJc4U0HTOHMqId2W3kS/A5o7iXPfvkE+x1DeELyuuaBqKLztaCi9jBpDg==
X-Received: by 2002:a6b:ee09:0:b0:672:5167:f0c with SMTP id i9-20020a6bee09000000b0067251670f0cmr9675703ioh.214.1656423414117;
        Tue, 28 Jun 2022 06:36:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2243:0:b0:331:ec7b:5891 with SMTP id o64-20020a022243000000b00331ec7b5891ls5527019jao.9.gmail;
 Tue, 28 Jun 2022 06:36:53 -0700 (PDT)
X-Received: by 2002:a02:2348:0:b0:331:b83a:f860 with SMTP id u69-20020a022348000000b00331b83af860mr11475887jau.297.1656423413690;
        Tue, 28 Jun 2022 06:36:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656423413; cv=none;
        d=google.com; s=arc-20160816;
        b=J8hw5iV3i4usR8tfIOq6kK6udAWlQC/CuRQMkTLkwadH2zro2RyD/uhCEOltOlSnHT
         tx3V7zMqg4dxAH2nCdaXfU1kfYIhptSXLQhQctzMfPBfmxBXbsPdgmiuG24RZZ9shtsi
         x5ZJ9Slt+NPMY2g/+yI/TwzImvHlAGw/jkNFQBO1hUdojqqib/AezhzuTQSW7lj+7I6z
         gmP1Dj1TEVQejRWmmJi2lSgmYrPGkH8+8bf8Z01m9stY4xW8UHEpsCJvkmvIwcddtzez
         goF+dmXk6fQGOfgWRkkUI/A/TLEfRvr1/EZBaP1898nc4AjiMx6uiGsGm/YVUxI44ja+
         LenA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gN4ZNyT9GRZ46Vwx3CUzNgwGxKE3ptwelsb3O/2waMc=;
        b=xVo5jHahoAWNt0JaBDTlU8osinq75AWBRuzgJ6ZB16ijIYYtLxk0GBU8GbyiYUgqeZ
         pGTgSHOAQ/phxunDZ/lR0pdRIQj5z2sU1USlpSzJLftcB09AbfVQJ7pLj1YrZCHP8k0m
         0sFr7kAok+c30vcH3EUS7pD+kFG7Dq3dGqOnYu7EknBavXx+kOMm/aTfYQkqBwD9Gb4b
         shJwQ/EbNFluZFteEDAddvjRslo1k3DuPXOvDcKO+V8AC+iAzXCfbb/8MGupsXOkAyVp
         PA7LNLU/5sPv8Ffgd5JIKE7kj8e2BKQ6o+LqWhy/JWSoQqhgFLKpY761ErNMUJ6YoexW
         spew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=SRPS2zIE;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f35 as permitted sender) smtp.mailfrom=jgg@ziepe.ca
Received: from mail-qv1-xf35.google.com (mail-qv1-xf35.google.com. [2607:f8b0:4864:20::f35])
        by gmr-mx.google.com with ESMTPS id f13-20020a02b78d000000b00330ebfb4c33si709333jam.1.2022.06.28.06.36.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 06:36:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f35 as permitted sender) client-ip=2607:f8b0:4864:20::f35;
Received: by mail-qv1-xf35.google.com with SMTP id q4so19914397qvq.8
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 06:36:53 -0700 (PDT)
X-Received: by 2002:ac8:5b0d:0:b0:31b:f519:4107 with SMTP id m13-20020ac85b0d000000b0031bf5194107mr1237416qtw.331.1656423413317;
        Tue, 28 Jun 2022 06:36:53 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-142-162-113-129.dhcp-dynamic.fibreop.ns.bellaliant.net. [142.162.113.129])
        by smtp.gmail.com with ESMTPSA id s10-20020a05620a29ca00b006a79479657fsm708363qkp.108.2022.06.28.06.36.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jun 2022 06:36:52 -0700 (PDT)
Received: from jgg by mlx with local (Exim 4.94)
	(envelope-from <jgg@ziepe.ca>)
	id 1o6BOd-002vAA-VA; Tue, 28 Jun 2022 10:36:51 -0300
Date: Tue, 28 Jun 2022 10:36:51 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
To: "Gustavo A. R. Silva" <gustavoars@kernel.org>
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
Message-ID: <20220628133651.GO23621@ziepe.ca>
References: <20220627180432.GA136081@embeddedor>
 <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
 <20220628004052.GM23621@ziepe.ca>
 <20220628005825.GA161566@embeddedor>
 <20220628022129.GA8452@embeddedor>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220628022129.GA8452@embeddedor>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=SRPS2zIE;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::f35 as
 permitted sender) smtp.mailfrom=jgg@ziepe.ca
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

On Tue, Jun 28, 2022 at 04:21:29AM +0200, Gustavo A. R. Silva wrote:

> > > Though maybe we could just switch off -Wgnu-variable-sized-type-not-at-end  during configuration ?

> We need to think in a different strategy.

I think we will need to switch off the warning in userspace - this is
doable for rdma-core.

On the other hand, if the goal is to enable the array size check
compiler warning I would suggest focusing only on those structs that
actually hit that warning in the kernel. IIRC infiniband doesn't
trigger it because it just pointer casts the flex array to some other
struct.

It isn't actually an array it is a placeholder for a trailing
structure, so it is never indexed.

This is also why we hit the warning because the convient way for
userspace to compose the message is to squash the header and trailer
structs together in a super struct on the stack, then invoke the
ioctl.

Jason 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628133651.GO23621%40ziepe.ca.
