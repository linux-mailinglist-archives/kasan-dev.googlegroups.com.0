Return-Path: <kasan-dev+bncBCK2XL5R4APRBHMAY3VAKGQEAHVZAZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 619568A1DA
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 17:05:02 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 137sf2776163ybd.8
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 08:05:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565622301; cv=pass;
        d=google.com; s=arc-20160816;
        b=f/ijLXlLnSnvGj/IKB0zhskVK2ED46faaIWJ4c29XZp1XIagqJCEMsHz573378916g
         m+9ySUFBdz5Fs4MrVxkUSFw3dE8bp9APvolq3xH/UQ8etgr9Ppjbv1MnBYvbpBH/XNEj
         MYryyfHTrqDfLxvVUBGT2ZX6IAawiQzwI0uXW6HET5mDEf+syPk8GxnUhmjvL1kjWnKB
         Y/3yCZ521rqdK68tZatgo4RjN5MOnI9PM7l3iiyY6EV03yimKWHw7rJ0mjnMVGwA9+SU
         bH2NxVjLlC9aY+cX+ZnDf2E/4xL82kMEmFwvftElFSoXX224Xv2v7EaeMc1uIgscI1i1
         xSuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=lFvZ8EyQKMy4Wh8GUEipH8VSaFIeL+bjLQvpdoK/2PA=;
        b=S90O5iwgmKBKTOCtDIpOXfj9BswOtwrtPEKRXTTX9HRsDQuMcEKhaIdZ0ob3OKXK5i
         K9Q0BCZStohhwSAuC6HmplgnebxgFudZZEsOOqOgK6MUf0s10yI4Nq7qmTDiDflex+Qt
         nAKWYABdmIgl6Hy9Ke86PHxbL4F3uwcSK2xJtcEg4Uc4/gpK+/OkXKLMtcBjKMXhCWqq
         V/rhjJFBF7JHgWup0//QJbhIbxcAl1RsmC240MOf60Io9v1aZrTwzu+apA8vN1H/d00K
         CvMdisjJyK1axOlUPDNdGXPexONd/rWpMH5/933nYjnozbNfasLEhd5/0g179bbWwWR6
         NnEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="MKEH/3uB";
       spf=pass (google.com: best guess record for domain of batv+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lFvZ8EyQKMy4Wh8GUEipH8VSaFIeL+bjLQvpdoK/2PA=;
        b=BlxJjqXGfnSPb/NRaCjHqIH0EwUBhfW0ay0ptX3g3pRxeHI0wtEzy+XfiKeNO838fg
         Ljg3pTIrze8Rj2XyR6yYU2QXmCwxZMhZCXuurx8OyqhtVeP0jeou9dkR7L/NzP5w/Wcj
         ZeqCV/s3ru+GbCJo9FlJKgHTTmxFXhYl/+wPAjTxdqgSgDIOdX/ZKOmOUJglHgTQ5Jex
         WeiEjICTPVeRrOQC3FYze1DPpf9w97FDcxwPtAxY8+rO9tF0arohnDqeSSVn3ua2acIj
         qATFjV6Lx/L4Ks/gnh78d7vyEEIyx3qLX0LHEj+CUqcL/isTKF0JABymQbMXOwGRV0SF
         jJZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=lFvZ8EyQKMy4Wh8GUEipH8VSaFIeL+bjLQvpdoK/2PA=;
        b=kPWijXEpBr8aywJ++VCYHNQmDc8B5k4++efR3xaIfqGiTgWrTfbpvOmTpr6GnbqOuu
         ARW3fqk+/kxr+c5hsYCqTBolU4/sH2iArs9fSwYT65jLLjC1LRGXOImw1rpJR2ZplKJr
         haL9r1Z5QizAY5m5E5THak5jlDE/E0P9k4Nyd7gNgPSRaXLdJzYNFuDdtZinZCjqepOC
         psCk2yITw1L2WiG42rF7Gd+hupiUnSC+f3felDos3PihT/lDCKWLHWj8WluGE7PvTakX
         abUFAv1vmkwjFysPq/R38FP2wv46QLMGMMxKe8xGV+NHQlfod2vCqE9VrrEWUr8P6BlG
         0yDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUFaabNu5dEWXbwLegYVjEabr6MjRvA4b5e0IGyGUU6Gedni4f4
	1RvQAoV9XwzxH8Sk3CRhWsk=
X-Google-Smtp-Source: APXvYqzg1ubiGpoQZrWwRIC9KgExUHnWBcAB38iGaGQqHxxq94QRmzFCM0vhVZ2OF50EyWa9/f20qQ==
X-Received: by 2002:a25:1e57:: with SMTP id e84mr23597263ybe.220.1565622301243;
        Mon, 12 Aug 2019 08:05:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9382:: with SMTP id a2ls6817054ybm.14.gmail; Mon, 12 Aug
 2019 08:05:00 -0700 (PDT)
X-Received: by 2002:a5b:591:: with SMTP id l17mr9334404ybp.457.1565622300917;
        Mon, 12 Aug 2019 08:05:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565622300; cv=none;
        d=google.com; s=arc-20160816;
        b=SHI9A5G41K9MWepcXeUlrfE32EjJIQDm7aA0/GVO9ZwRK+oitVhI1Yf1NxxdWRIIwO
         FPgn8wqEOZuvkoO5PxJhdUebaLMvWCEKjUz9UeVFPtBRr1mDAgP8EK/F8eCQXmoHOHEH
         F7T22V0AB0Fjsw9bVMNEWeqZx5XVlqd/uXZ0lPQ/Fn914w65uoSHPBBLp63nZN//HndL
         4hR3oXzpkIlgmM2fGwY0uYemtqayEzpqnZWlvPikp4kwlAiBIOghQ3xXezgyVmFgIi2w
         1jRt7UPv2KEydbw5pCoqIVC13wKYCYxbfkkk6UjxaYEKEsZea4ewSClDvESSaF7N8sI9
         auJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6aCiFlnKco+0K9lO1zC0yDoDsxtxBScYx2o5eR9m57E=;
        b=zj/HdjMtLtrJCf4gXUtyXs2Z3S+2IbTDwEvFXt5cBg1VWld9bIYoDFSwl0W4wybl+C
         4X6188KVCa7gB2G0VyCGv28MpgOSlZ+PiUpztVnUi3WBF3Lsj8PLuDrr4nyeMTM9v2Op
         WyAAj5JIeWl88xgqL2IoNQjzBer+ls33xJlb1US5cvIjQaRSc9u2BioteFttI0vYkXMl
         CNTF+XWQl9X8cJHjxH7C84laXCzTRTXPukTXtUfFu0Iu1nMzq6FQ8h1Mm1od00QsEuXB
         aX5H5Y/+KqUcdYEjUFdSERKO+cpCkH3mxouYV5ch8TDNkIob/zxFbkFL6/Ok4xwf37jR
         CkRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b="MKEH/3uB";
       spf=pass (google.com: best guess record for domain of batv+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id n40si159284ywh.3.2019.08.12.08.05.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 12 Aug 2019 08:05:00 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of batv+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from hch by bombadil.infradead.org with local (Exim 4.92 #3 (Red Hat Linux))
	id 1hxBsN-0006Xf-19; Mon, 12 Aug 2019 15:04:47 +0000
Date: Mon, 12 Aug 2019 08:04:46 -0700
From: Christoph Hellwig <hch@infradead.org>
To: Nick Hu <nickhu@andestech.com>
Cc: alankao@andestech.com, paul.walmsley@sifive.com, palmer@sifive.com,
	aou@eecs.berkeley.edu, green.hu@gmail.com, deanbo422@gmail.com,
	tglx@linutronix.de, linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org, aryabinin@virtuozzo.com,
	glider@google.com, dvyukov@google.com, Anup.Patel@wdc.com,
	gregkh@linuxfoundation.org, alexios.zavras@intel.com,
	atish.patra@wdc.com, zong@andestech.com, kasan-dev@googlegroups.com
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
Message-ID: <20190812150446.GI26897@infradead.org>
References: <cover.1565161957.git.nickhu@andestech.com>
 <a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu@andestech.com>
User-Agent: Mutt/1.11.4 (2019-03-13)
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b="MKEH/3uB";
       spf=pass (google.com: best guess record for domain of
 batv+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org
 designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=BATV+498385331390b106b35e+5832+infradead.org+hch@bombadil.srs.infradead.org
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

On Wed, Aug 07, 2019 at 03:19:14PM +0800, Nick Hu wrote:
> There are some features which need this string operation for compilation,
> like KASAN. So the purpose of this porting is for the features like KASAN
> which cannot be compiled without it.
> 
> KASAN's string operations would replace the original string operations and
> call for the architecture defined string operations. Since we don't have
> this in current kernel, this patch provides the implementation.
> 
> This porting refers to the 'arch/nds32/lib/memmove.S'.

This looks sensible to me, although my stringop asm is rather rusty,
so just an ack and not a real review-by:

Acked-by: Christoph Hellwig <hch@lst.de>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190812150446.GI26897%40infradead.org.
