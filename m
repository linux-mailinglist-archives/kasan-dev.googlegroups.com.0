Return-Path: <kasan-dev+bncBCT4XGV33UIBBWUSZDEQMGQE4SJOETA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BC3ECA59C8
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 23:21:16 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-880441e0f93sf39183916d6.1
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 14:21:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764886875; cv=pass;
        d=google.com; s=arc-20240605;
        b=iXBvgMa02OvnPdYMxWNpCD8dK2Q3Ibf/kh+dE0+AETOStj4orW+1TPcfWvlZ/+6InN
         BeT6pgPk151eGgSM8JqVHl1VCJ5dRF6wPhEStEm+TlVn69fa8WytGzbtUkeuo9ScalBd
         hvuMgxsNBiLo8cBmLQkNV9gInyyqCkRninboyBEyW3nsGnKXkPge2oexYlro+c37ZyON
         aHTnjaMcbU9v5Cv6VWnTSnco4750l53qB+k7BWrXDCu0JY66eC2WgGzB+JGvNfViJfcQ
         U5ugXB6WenSfyKnX3KPajTKRPSdc+dHU44kBAiAIBzaImWyjJrsfXLS+F0LYLW6XuaCX
         k7Xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=RfhEbKOl7d8lh4iXpGJecrJkhVa0CPMVDLEC14mRH9E=;
        fh=hmVtVdiqr5lidAuBH2os+ZmWS+vm1gFczyyUwk54h/0=;
        b=Eh4gJL0f8s5EWHltmI1rirMIPX/5MuuD8HCbAfQlYvD5q3LzxUkiNGtvGQXvxaKmcj
         XcDAkEGNsoY7NYMkPQAdFIucqiYWswcAnHt+JBIP5rq/QOSuJWOuvdZ6qx1+s49s+Vz8
         oTzAzwugwE7nGY7Z5XDXyHjubCAtrwB/dFLofCSYteWh0aDRmtUPpV8i+Z6ZR+Z4Eo1u
         UkZF4odIr63fN4V3wk3c1swv2l1WFEOSF2OPGPI18dI8u7Z2st9tExdytKVBaNAy+nEX
         w0jn6Z9WYxFi+m4QFt9bdhGZSJ3ieyt0VpvDuUEwBjBj1Fm27qBdV5fjB52vClPxw6KE
         l1WQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=a1dLCnLF;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764886875; x=1765491675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RfhEbKOl7d8lh4iXpGJecrJkhVa0CPMVDLEC14mRH9E=;
        b=u9Ry7xH/auKf1w6FB0qw4veV4uTZz+ztJBjFFZniHnZzdyMBjm3EEvbDK6NqO5IPgM
         6Eh/yIxdsE64Gv6D45QMj+rEm3v0eBZk4eyBU2cvI8bGmdhTYy7pUuCyGTcn6aqy8tlv
         m84Um/zpYywvKPN1rFal/ZP5SWZYrJAs6VCK5lUVnUfGGavNN6r/uwwp0NwUCe36FXFN
         TrqBUyCeBuSJBIkbIJkYSPQAzIU3WUiOfcmlL8/GVJUskLnsWXdY9t2W+jsg9bptF8KS
         kNdv4B+4f2m/T4+DA4zKc71KzEFIaiqzlnBnFoHs36emEYf21+T6pYWCx9CCwifUFCOf
         TVVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764886875; x=1765491675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RfhEbKOl7d8lh4iXpGJecrJkhVa0CPMVDLEC14mRH9E=;
        b=ZxtCXjqv2lPRDT6nr2MKH+UYP0j/eOZm+1LmlA9edi/X/Xr6ATjQs4vIGX2blHJhl6
         rk2jWRQmhTVxFDiLvfl2eiCXLVj6ArjvRljeSkEFIjaWk9tDlbVl2Z9gykAgU9UH0z0o
         oPkaZGnuPJH1pzqJt+jCK+hHPHkL2RSocsakVxcVoGliR5YukaFty6J8figq1NXTq5pD
         HhrdBCDqZdi83l/zl4irV7W31DG8jTqAaT0X2IVtS7yezdeIK8OLXMsmZJbzXIHvsW1X
         DZykqH91NLY51f0ZeSIu/ttzmjm+S1avdyUO3+IiNqXdW3EOoLsPSf31PGYJmAhbZz0s
         FzIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3C8TN9OxthIgF63XrkLgvC4SAQzxu5Puc6eyUhRZsr/phJtWfqWhSrpF1XPKZbRTx2pZmLQ==@lfdr.de
X-Gm-Message-State: AOJu0YzC/gUi5RPTVOa2bbDfJXg959pN20BScS9fCVkgacrZ6CnQoB91
	lcouCf1ST9DzOHyVWqRnuXaan8nPzj3MdCUCMR704u0j/WB1kazhe3W/
X-Google-Smtp-Source: AGHT+IEscNDgQac0MG3AhXMS2UhgJSZuL/NjJkSg3fuWjkfPuQZ8aZLu10lv5VY88Osai+4Xi7iPNA==
X-Received: by 2002:ad4:5dca:0:b0:880:5249:be4b with SMTP id 6a1803df08f44-888245536a1mr89242616d6.12.1764886874944;
        Thu, 04 Dec 2025 14:21:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YRjUDq9iPltnXktM8HQr4796FUrhFdJarjxmTOCdtjgA=="
Received: by 2002:a05:6214:6002:b0:880:5222:360 with SMTP id
 6a1803df08f44-888173d4b3bls26585626d6.1.-pod-prod-00-us-canary; Thu, 04 Dec
 2025 14:21:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVbT2LLYun3uRCjErJlQkCG3OXCG4yRUZRdxee6ngue0pCv7JmhFyXfF99Lxfqn39bUD+scyZ2lQOk=@googlegroups.com
X-Received: by 2002:a05:6122:5008:b0:556:a243:8a72 with SMTP id 71dfb90a1353d-55e68676aeamr1879761e0c.5.1764886874184;
        Thu, 04 Dec 2025 14:21:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764886874; cv=none;
        d=google.com; s=arc-20240605;
        b=ADafwdUboGXYjaW4aEYKMWa65VsjHl5ONzsxD9TK5QBkoh4YE2NWROs4Xuk1PZxYsy
         w4rh28Dgy4foj6Ptab6l5rrI0hnhZbWojKo5qKtoid6vqFJf5VRXNIFalHPGKxpRZetS
         qSr6pnqen09IzMlfB/gFbITgFKkrlq2TG9Y9875rRaY5ohZVMYsDV4M1HWJMc6/VoLtd
         rgADcXAY5qyjBV8cO0/dmaolIs4CDb5ljdVEdPFhyo7qM+ThRB6ndV5VLgT4idVFJRwo
         96Tg/uWcsXUYeADgCGoCn/dJT03uuSgTsSAc6uE183V9c96m2ikSetkC8B3z1uzhvXL2
         SYhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=95nZyTX0fEu9Dl1Mbw8dMRShkCl8bUTc5udqACUtJrM=;
        fh=XuU5XqEoFocoPAObHOv1aWKAkqHBNFBVWK5R66xuhFw=;
        b=J54GNVtx1JPun3oxpx+dQSLNHDsMUaLacmh0BwgDk9nKkjdNwAeryYWsPTPDvNMLGX
         WCIadvIK5mdB0BtJOPwV6Rojk3kNbwQVvJt3/rUN6nr2ZeE6++eiTJbzMcFtQ8h9byTX
         6R/a807RkdC+E4pvfBK7FuA/2jpy9knQeCgMXnxv/oPI7lUlT6D2gxEMvhhu1S7rp7l6
         TBvUotDNFPIIfx440VlZzAhB5ZIKh9z2hDvyED+pFVJbhYzBcQ6N52ilc7IyYsAKiPLY
         fEGF7CuCnsOVNcWln/x/lMhRcT0aTKJuR5yMXCzfsV8rmz6NJCT/yTx0XbyyK7px3MfT
         71hw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=a1dLCnLF;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55e6c937a5fsi120824e0c.3.2025.12.04.14.21.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 14:21:14 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 3B99342A88;
	Thu,  4 Dec 2025 22:21:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9C36DC4CEFB;
	Thu,  4 Dec 2025 22:21:12 +0000 (UTC)
Date: Thu, 4 Dec 2025 14:21:12 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: urezki@gmail.com, dakr@kernel.org, vincenzo.frascino@arm.com,
 ryabinin.a.a@gmail.com, andreyknvl@gmail.com, kees@kernel.org,
 elver@google.com, glider@google.com, dvyukov@google.com,
 jiayuan.chen@linux.dev, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 0/3] kasan: vmalloc: Fixes for the percpu allocator
 and vrealloc
Message-Id: <20251204142112.fc11c55e46bd0017c41b49e1@linux-foundation.org>
In-Reply-To: <cover.1764874575.git.m.wieczorretman@pm.me>
References: <cover.1764874575.git.m.wieczorretman@pm.me>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=a1dLCnLF;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.234.252.31 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Thu, 04 Dec 2025 18:57:44 +0000 Maciej Wieczor-Retman <m.wieczorretman@pm.me> wrote:

> Patches fix two issues related to KASAN and vmalloc.
> 
> The first one, a KASAN tag mismatch, possibly resulting in a kernel
> panic, can be observed on systems with a tag-based KASAN enabled and
> with multiple NUMA nodes. Initially it was only noticed on x86 [1] but
> later a similar issue was also reported on arm64 [2].
>
> ...
>

I added cc:stable to [1/3], unless its omission was intentional?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251204142112.fc11c55e46bd0017c41b49e1%40linux-foundation.org.
