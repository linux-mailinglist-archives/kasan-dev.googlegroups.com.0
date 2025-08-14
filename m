Return-Path: <kasan-dev+bncBDV2D5O34IDRBY557DCAMGQE7YQBKQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E991FB26DCF
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 19:37:40 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-76e2e9a98b4sf1144020b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 10:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755193059; cv=pass;
        d=google.com; s=arc-20240605;
        b=EXF0noV+LVI1d55sRhb5OjzdzyxQpVRZ12fBKDAIZPWJhESi9UeCtgHjjiToBCHrtg
         NYn2pWYKYn55n5E9A7PqfV66JDFRSWPBlWqx3ptn06n8RkefrwqBsUXvDCi8y0HhKxKS
         OpLqPSATF2yI9zt1r/7EwWY9i8lyBWn5stUslBA/1f6h+glqIFIRge3pw8CQk52XegS8
         NdD2G0N8TEnU5SurxXLK0hnJdRiYY9bgRZgDX2/Rs1TtFu+BY95i3KyMEN6Czv48GJ3E
         lSz8OdB3rD6s46Ftc4p5IvFR6b0I/je3C6656plCO1c+zEfd2N1MaB0OW6YDr0Ogbccr
         0FZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=+f1YZtqRVD48EE3xTmhhCOQJ2AbtS3x0gYt8ZzpPruk=;
        fh=9XTeUyXCg1WBcjoLcLYCoBxLUpxO2MMVmchpm5DZ7aE=;
        b=ePvCyAhQI2h84Q9CClZXNxrHu1ghUZwEHoDlRLMXtC1AS5ivnR658r9vLLb8DyskcW
         CCdqfqOa9RmubGf3AH2ojOi+UyWelT/fsNtSwiWemeY4becHrMmcYeWJw/lFkt4BpWiL
         VszRBjBhlmbQ5deb3PQISOhir0sIl/9/H+HgiQofw3XjYzqYSy4XH+eDfMvlj68ZXDx2
         +9rxxW5FDvtIJsO6FwmUxTo/u9wfS0ywZRUkGoEHcAu4a7cCVU4ZGFULKT53jv5lMzv4
         TXHq3C2QZgJh+nmR2vSR+B9IEYYBqbHvpBmRcFJOLM0Q/RPjI2IIsBLjjry/BdRYHlW1
         jZDg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="4KLyFDU/";
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755193059; x=1755797859; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+f1YZtqRVD48EE3xTmhhCOQJ2AbtS3x0gYt8ZzpPruk=;
        b=D5WswgO0tFusVuzYCKYTOV9aWIWE+PQZXDLn0w9frC5Y78keAMsI1Pwi230/qlaP9s
         KRVsUcO8uW9opKI6Qr3dXE6IJzGu8BOXtqYXlUI1GMUsUXP2qDBi9PCvGqnabPfMd8gC
         bq63zu8uI8T8JX66hF6fCvC0zZE398HeYzPP16XbSvBp2RELblq57/fhoJhFNWK3Rko7
         pX0JFLTxo4BNTO1EJa7yg0n58D1JyaW17/vJSgpRhTCSClJGqX0ZbxxzzPZe7qrzppRt
         u6Pm+3qTNXpzzcGe/aixfOPFzGLJuye/Li876U2S5xhdnrxqIzoy7qKyz00u0F55ldU9
         FmIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755193059; x=1755797859;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+f1YZtqRVD48EE3xTmhhCOQJ2AbtS3x0gYt8ZzpPruk=;
        b=EWe8HVHw59BR+AxpV99bg+lR/whHYXViWaz3bEiiwE92B3apYc9iQxBbbF/9IkhyhM
         F6bYJmTgWSdGDCkk29kG+kQ55pqrDBWsUEI+4yoWYHjOG4lGN87xLBHJ7y24h2FlwKUA
         vYHNpKdLJ+I4cPgDfs0oQwYFy3+JFehELZnZ1PVWsUdfTLjWmm5kSL4KoFzbhC1QeZmK
         WzuSfkXzsIeeZIxLUxb40zOqQNM4JRbsQbzKYYVp+wAfaY0b1OFUMhdY9d2JeagYDVzy
         5glgBsBMtNiIw+NEDQtkUWUug9vSj0Q7ES7btlEq0aRM9Fhz5BWMqxWy3qvulQriQW38
         +P2g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWb5CWSqZnXw1VdGIBwHdbkcyXZNOVPwGuOzxtXRxf301P86aj/LjU1YYTxbY8bHJVZUOxuZQ==@lfdr.de
X-Gm-Message-State: AOJu0YwpCMdZMSc4RTSXKk4kEAlw+T7EEI2SFcqOppsjI2q+tefvMvys
	4yYaov9iT3a4XGerXVuGKv8N6DM/99/fWn1hi3VjOcMfj1NtKVFi8QOR
X-Google-Smtp-Source: AGHT+IFJIajOKWtIzTzftLSawC+2abo4m3+Re1yj9JVKgNQ5YPy4TenhSc9lYBY69QLaThxiDqWBig==
X-Received: by 2002:a05:6a00:a8e:b0:736:4d05:2e35 with SMTP id d2e1a72fcca58-76e326c1914mr5046564b3a.3.1755193059385;
        Thu, 14 Aug 2025 10:37:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcarhYTl/mvvj6sfif0eb0AHW4IJ7TQZ6NcG+FYdNS1wQ==
Received: by 2002:a05:6a00:b90a:b0:769:bb89:eea with SMTP id
 d2e1a72fcca58-76e2e78f371ls539037b3a.0.-pod-prod-00-us; Thu, 14 Aug 2025
 10:37:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWPZWpNgfoC2EyqEetjIrnO/UI6LSRlOd+qUai68CyIwF93S31WuUjCJ0eNVTgDE3tzGLP7uAb2bhw=@googlegroups.com
X-Received: by 2002:a05:6a00:6f61:b0:76e:352a:a640 with SMTP id d2e1a72fcca58-76e352aa78fmr3613092b3a.6.1755193057978;
        Thu, 14 Aug 2025 10:37:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755193057; cv=none;
        d=google.com; s=arc-20240605;
        b=EkR9Iklf3j+lKensaA7YEMET7X4vv0fMKPKGCOq5M4ZturVJYBVw4ItVfnjdAzmc/+
         I6uPvvXeqOYwacq77HvtKENJwmF2zByP3d35C2IEYCr5mxnVw26vpYUCTAa/ESEUbh4H
         aaCqHx28g2A75ptT1qqkFcIMLmxKrAlCanhJLqqt+hsnMpEgDmD/YRmP+BSMSJ0lIP7e
         82LgzYpeUdA3l2QVooW4iwdfTsrcismPQHpBA0WtsxrlVNeHrGf3ojtjz0OFSuoIv7N1
         eAsYdsW2AOT68Q+PETFuK/96h3RyWdnJhboAoBTfL8361AMpFziV7wXVjf/WlegkEKkP
         QKDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=OE4LAchkYGbRbWIAPtKdq4yp8AV8hBrJ1qdnR14GXT4=;
        fh=Izw91PIx6aTQe6KfLLHIKoM6ITrAgZZ8JX99faQHeLI=;
        b=YMGt+AYvNDb9/fdwQFTW5NuVfxIcjSKNNXZjOxm55WbqBKEHwt9NBWRO36z5d7PWJ7
         HIzgcY4MoHuhz9arbqf5I27IVPOJM5LxTM6rg33OCKx9OnC95mgt/cVkMdScXyv64Jtt
         pqt2clz7PpLENzyqORDWynFhMQyhpL+7RfFkjfFXWLabCUDyVzflm8TpQBILnRKK2cXt
         IXef9cxIkWcJ7DZkHRVYneZzJ+fysZUaghEtldn58ydvvqVGSrRnNwS21JtThF4VndOw
         KRObP1leHEQoN19KA+5o9ZVIGaYKIjwKgx6/z4bG3fiOA+toe5wwp81u77v4fVDn0/gy
         jvyQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b="4KLyFDU/";
       spf=none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-76c2d61d1e9si298731b3a.0.2025.08.14.10.37.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Aug 2025 10:37:37 -0700 (PDT)
Received-SPF: none (google.com: rdunlap@infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [50.53.25.54] (helo=[192.168.254.17])
	by bombadil.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1umbtD-00000000E9n-3MTt;
	Thu, 14 Aug 2025 17:37:23 +0000
Message-ID: <c855a4f9-4a50-4e02-9ac6-372abe7da730@infradead.org>
Date: Thu, 14 Aug 2025 10:37:22 -0700
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 01/16] dma-mapping: introduce new DMA attribute to
 indicate MMIO memory
To: Leon Romanovsky <leon@kernel.org>,
 Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leonro@nvidia.com>, Jason Gunthorpe <jgg@nvidia.com>,
 Abdiel Janulgue <abdiel.janulgue@gmail.com>,
 Alexander Potapenko <glider@google.com>, Alex Gaynor
 <alex.gaynor@gmail.com>, Andrew Morton <akpm@linux-foundation.org>,
 Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
 iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
 Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
 Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
 kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
 linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
 linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
 linux-trace-kernel@vger.kernel.org, Madhavan Srinivasan
 <maddy@linux.ibm.com>, Masami Hiramatsu <mhiramat@kernel.org>,
 Michael Ellerman <mpe@ellerman.id.au>, "Michael S. Tsirkin"
 <mst@redhat.com>, Miguel Ojeda <ojeda@kernel.org>,
 Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
 Sagi Grimberg <sagi@grimberg.me>, Stefano Stabellini
 <sstabellini@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
 virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
 xen-devel@lists.xenproject.org
References: <cover.1755153054.git.leon@kernel.org>
 <f832644c76e13de504ecf03450fd5d125f72f4c6.1755153054.git.leon@kernel.org>
Content-Language: en-US
From: Randy Dunlap <rdunlap@infradead.org>
In-Reply-To: <f832644c76e13de504ecf03450fd5d125f72f4c6.1755153054.git.leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b="4KLyFDU/";
       spf=none (google.com: rdunlap@infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=rdunlap@infradead.org
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

Hi Leon,

On 8/14/25 3:13 AM, Leon Romanovsky wrote:
> diff --git a/Documentation/core-api/dma-attributes.rst b/Documentation/core-api/dma-attributes.rst
> index 1887d92e8e92..58a1528a9bb9 100644
> --- a/Documentation/core-api/dma-attributes.rst
> +++ b/Documentation/core-api/dma-attributes.rst
> @@ -130,3 +130,21 @@ accesses to DMA buffers in both privileged "supervisor" and unprivileged
>  subsystem that the buffer is fully accessible at the elevated privilege
>  level (and ideally inaccessible or at least read-only at the
>  lesser-privileged levels).
> +
> +DMA_ATTR_MMIO
> +-------------
> +
> +This attribute indicates the physical address is not normal system
> +memory. It may not be used with kmap*()/phys_to_virt()/phys_to_page()
> +functions, it may not be cachable, and access using CPU load/store

Usually "cacheable" (git grep -w cacheable counts 1042 hits vs.
55 hits for "cachable"). And the $internet agrees.

> +instructions may not be allowed.
> +
> +Usually this will be used to describe MMIO addresses, or other non

non-cacheable

> +cachable register addresses. When DMA mapping this sort of address we

> +call the operation Peer to Peer as a one device is DMA'ing to another
> +device. For PCI devices the p2pdma APIs must be used to determine if
> +DMA_ATTR_MMIO is appropriate.
> +
> +For architectures that require cache flushing for DMA coherence
> +DMA_ATTR_MMIO will not perform any cache flushing. The address
> +provided must never be mapped cachable into the CPU.
again.

thanks.
-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c855a4f9-4a50-4e02-9ac6-372abe7da730%40infradead.org.
