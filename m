Return-Path: <kasan-dev+bncBDDL3KWR4EBRB7WDT2RQMGQEJQMRLAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id A6FB0709C44
	for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 18:21:19 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-75786909338sf270428085a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 May 2023 09:21:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684513278; cv=pass;
        d=google.com; s=arc-20160816;
        b=OkFE86mJJ+B/K1AtHxzRBekvn1YhCYrwfbyWrmK2ghffKhE2t/7tXMKjqjAa34mGMW
         mQWfmnWhnj5bd7RQG5QZSoROyJxFhqihCbZDRsaMlSPCqW5F4AWyttziAj8bSBQ5WoOC
         Hx+9rmtreDlbVcLE/x2+mJPN/ycl4kkjewgRwdNxB1VfU7TtQPZw0PO/uwhwgVvOnpOZ
         V4rUHDFG7vSMFnWuXSTxzvfrLSLpfzdXIGpFbPo3D8+IeVciyLRMi6oeTFAvumMjuqKg
         /65xBFJWl2ROuKO9GpFu0Bx0Gj72T0tmR5gqaVFEcpj/rP65RLT1ry7nPXdr8rJjh21m
         tP5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=xnCX54zlK3HyTbqO5vlGB6wYdOxIrxz0Bv19m+zs+Rc=;
        b=xjq9WAUcAesZZFcTU2WGfTzQ4zQuuWgjA5Tl4FkIoEq6ob7jV/SlU2bgBVsxxTvUoa
         kzXEzQ0wOs0LDgZ6wBT+t2Leoa57+UV059sWccW+lUncwsZiwBtAwxoH+s0onqAtKNLF
         xi0rP7tXOP3gEd3B/5Ym68vhNNkBrzIakPhbQFhom8EXpesd79cpJemlZHO8gQwiSObH
         rVKrj7xfC9lynSzNdqfVWvimp90TSURfrLLZpwVzzGBuE4bEuw/amlD8ji0JUIqKmidg
         V7DRDk8V+hUphRAsRT4vKSXapmn4G/UObA77Bx67RQV+ST9fA4dryreGWtulrOM0omMM
         i+XA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684513278; x=1687105278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xnCX54zlK3HyTbqO5vlGB6wYdOxIrxz0Bv19m+zs+Rc=;
        b=mSn569/VA1NnY8BrCskxIAUHQjJw4jqqShvpDA5EfK43o2wZIBRNPVE8vSwlfQMhpj
         yq+AJgoMMhXZ9uxjWSOMHXGspoSq9aScr7iPJOT1NqEiKXa4vYIx5qGIAj3brmTIcWFl
         JaUNxfUZIjnx/qa5uXnmFlasA0Yw5JI2X2i3twAxjgRH1UQ+KKb7zz1SQ2lkxx4W9Eut
         Co1EyAnVUiT05Euh7gNRGI562tgHXTHLzh96lTE+VTRVbE9rIk4r5oZwPtIbz1leNGe6
         gfFvhOB9oNHKcuukGrSVg7icyOB5eq8TMoDRzcJegnDtHRyJxlpSKhz23kIVKF2ZuAi3
         WUYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684513278; x=1687105278;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xnCX54zlK3HyTbqO5vlGB6wYdOxIrxz0Bv19m+zs+Rc=;
        b=BNYksi7Aw/jBroG5fedwGZN1hVDE3iZXyX9hKRn/ySPtVvpnADXbzCctUDEVP04og4
         i2qrvl0sqhrl/xcVZmLDyA4empuPvC3RX/YbiPhp48vrOdu+dwY5C24wX+A6fdcvo4N5
         btYUCHwE98+ZEVuX23v/q6F9XXF10PJktabErmlpzZlKtXwA3IsK9DWQBaS8WDogPqU3
         WNaAqZf31lMYXe7I8MBhoqcX6iQnOofr5P+H6ioHpzzBex2YidCbDBGBsK2MLdCpunjv
         1hgKxN7i1SY5BY2lGAPkYXTh2PUxsc6s6n3VTp3yi7IsQ0lmi3MvmWQJMdcMQDnHITgk
         pfRA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDy76luJZyXX3K2PAJZBiXa2sDf4tis+5BDC/lophKNHlHx6TUOK
	bF7OtHx1yd/tbFiqmQ5H5V0=
X-Google-Smtp-Source: ACHHUZ6h/jyWLPXgq5IugmhUah/urAEvUSCYftSeFoDGM99+5T30isY6ST+XG055cQuOsfcQOVcJOw==
X-Received: by 2002:a05:620a:179e:b0:74e:2e3:8e24 with SMTP id ay30-20020a05620a179e00b0074e02e38e24mr693873qkb.6.1684513278273;
        Fri, 19 May 2023 09:21:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:a53:b0:61b:7bf0:7dcb with SMTP id
 ee19-20020a0562140a5300b0061b7bf07dcbls2327992qvb.0.-pod-prod-05-us; Fri, 19
 May 2023 09:21:17 -0700 (PDT)
X-Received: by 2002:a1f:5fc9:0:b0:456:a3bc:3daf with SMTP id t192-20020a1f5fc9000000b00456a3bc3dafmr1057859vkb.9.1684513277668;
        Fri, 19 May 2023 09:21:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684513277; cv=none;
        d=google.com; s=arc-20160816;
        b=V0vcmLkA7tlUXLfWALSGXtoyxoz9Y6Gmu5jbd/Mwhq23ErnTf+U+jc3MbQHGVPtqab
         1xu6vXo9UD8HmGakF93blYKYYn4n0eeyiTnaN5KXQoVJgita4z3IxB0yXxuVeclUehzx
         NMjoYZ2/o9gR/rRHXGya2/SpMZgqVJhaj3ORyd3DnHN/lFshzvwfuU63Vx9NzIN4nxll
         HvFVyFQptCEyJdBvhF35TpVnJ1FglLVmwl3bW1jT9pus8X10vFhwSUjoq9YJwkSYao4D
         aJ28ZqFL+HJRji6n2xu1Ymegxz3NfwnsDp+vY0Bm1ZdpGwE+0GxN11IZrm+UVC3hVnsE
         wRjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=2vDnzHQB9aPGY01kAbFiYHB/+o+ke0Sr0xEkRU6So+Y=;
        b=lf5C/J2GMbqu4Ub1JGObqHKasd8pJ4+XheK2sTQ3WInydiX4dnvP8Awt7UpHt4K49Z
         ywi4fI4lKnTM2QjFi13d5E3OJ39q0CCYXi7Jxb/OkNNv1RohJvXCvWatf1a1D5jiQhUX
         sDOrDme9mr0h6dKmB2OvTInHRgeIUtxksZLvMia1h6PkwvcwvKVZUAQbaMdF6nYJGu4n
         PbqRB4P6+EJ43oyCxA12bE9PKupYB+/dQxzMpODGtn0cUuvD8skAiEtSUjVAZJeFp/y3
         JAC3HXEkcki4ZMEjVDj9oWjR55idWb4A/dEwWZEAvFTF3a/GLKmtIoctUByFG62p32Bt
         r32w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id y197-20020a1f7dce000000b00456d8fcc97csi504542vkc.2.2023.05.19.09.21.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 May 2023 09:21:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 580B76591A;
	Fri, 19 May 2023 16:21:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B48C8C433D2;
	Fri, 19 May 2023 16:21:12 +0000 (UTC)
Date: Fri, 19 May 2023 17:21:09 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: David Hildenbrand <david@redhat.com>
Cc: Peter Collingbourne <pcc@google.com>,
	Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	"surenb@google.com" <surenb@google.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
	vincenzo.frascino@arm.com,
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org,
	eugenis@google.com, Steven Price <steven.price@arm.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before
 swap_free()
Message-ID: <ZGeh9SSz9DZpfnhC@arm.com>
References: <20230512235755.1589034-1-pcc@google.com>
 <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com>
 <ZGJtJobLrBg3PtHm@arm.com>
 <ZGLC0T32sgVkG5kX@google.com>
 <851940cd-64f1-9e59-3de9-b50701a99281@redhat.com>
 <CAMn1gO79e+v3ceNY0YfwrYTvU1monKWmTedXsYjtucmM7s=MVA@mail.gmail.com>
 <c9f1fc7c-62a2-4768-7992-52e34ec36d0f@redhat.com>
 <CAMn1gO7t0S7CmeU=59Lq10N0WvrKebM=W91W7sa+SQoG13Uppw@mail.gmail.com>
 <80f45fec-3e91-c7b3-7fb4-1aa9355c627a@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <80f45fec-3e91-c7b3-7fb4-1aa9355c627a@redhat.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On Fri, May 19, 2023 at 11:21:35AM +0200, David Hildenbrand wrote:
> > > Sorry, I meant actual anonymous memory pages, not shmem. Like, anonymous
> > > pages that are COW-shared due to fork() or KSM.
> > > 
> > > How does MTE, in general, interact with that? Assume one process ends up
> > > modifying the tags ... and the page is COW-shared with a different
> > > process that should not observe these tag modifications.
> > 
> > Tag modifications cause write faults if the page is read-only, so for
> > COW shared pages we would end up copying the page in the usual way,
> > which on arm64 would copy the tags as well via the copy_highpage hook
> > (see arch/arm64/mm/copypage.c).
> 
> Oh, that makes sense, thanks for pointing that out!
> 
> ... and I can spot that KSM also checks the tag when de-duplicating:
> pages_identical() ends up calling memcmp_pages(), which knows how to deal
> with tags.
> 
> Interestingly, calc_checksum() does not seem to care about tags. But that
> simply implies that pages with the same content have same checksum,
> independent of the tag. And pages_identical() is the single source of truth.

That was my assumption at the time, there would be a memcmp_pages() in
case of checksum collision.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZGeh9SSz9DZpfnhC%40arm.com.
