Return-Path: <kasan-dev+bncBCW677UNRICRB3P52DVAKGQE66CABMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 366DC8D8DE
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 19:03:43 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id l11sf47235934pgc.14
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 10:03:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565802221; cv=pass;
        d=google.com; s=arc-20160816;
        b=gotidsUa7ftZ55M3X3f1IVf8x9LNP5H7iqV3ATpsgfLbUfw6COtllOqtOjiJKV/dn/
         9ISHpIGCOc+t2iCYOnmkVq0oXueTN7X6T6CS/vXNIY/UdSPV9dBzHAcRT+2c324bp6W3
         Yv/f3ku1LuJvEm5qTqpWh768IlhsiA7Bt+c6mXI3P73vqVaeGnIH9xgJHzbp9Vp55S+n
         VqjF7JWuZCWWVwAb4TsxdtN4xqJbRf1i+Rff4IeWbl0cCqbxnu2jTNlbLNg12AcI5sYo
         y99q4LVShO53/mL2fWlZxEZV4PxY5E5GaWajLvkVkJBbB44hQlubMz5M0rHfcENEDBQI
         cxtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=9vsuLoSObgSojPLAyFCzdUF+g9CtNNDY+7uKk5SdOC8=;
        b=VH/Ncd/kfo3Q2FSNha7tbySwwkWFN5R/shqt9Agv5AzEST6CJRLSCni0EgZZYj7kqb
         MbSR/U/CX0qdg6XndF/+4QqmNUOVUvCZXVoAqIHJjGZQrBinytYRKiT30P+VL9fY2ZUp
         E4YNQmNFva4uT7wb5efKql9YfpceTH3RJcl05ah99ubkqi3jDtfQwGGTL9vtd7K4yRk4
         aDXqpkwF0sYSyt6QzpPD//Yd8VWImDj5hXO0YLSPXIIKxXILCU+P7W7E9dlH8EYfNoOF
         vJ8ezDHo0bd4aR/vyNu2IrkQ+SoVzdI4JsnTBL4BYZJkQATqyVp2HVoMZx3Un1HlQFOk
         W0lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=KqQ8A8lx;
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9vsuLoSObgSojPLAyFCzdUF+g9CtNNDY+7uKk5SdOC8=;
        b=kmb7W3mTKiODwrpQ+t8M5bvnFjm8AKcKjuMtQXWbIEMAaGh0Qu7uuB67CMzqr8c+5W
         fo3YJEYrF/kyrmLRjZYbxWtx91W5CUt20Sv1g2Qs5coxCP/FQUEc33oGWph8v4r66NPI
         /DR2U4F0XvkhkfNYs5QHeaGcexW539LEUMY3Ngm1cW6EyhioshZ5To3z92aKzCDwqCmL
         EvjTIEiZfzcJXlQvS4hVO9E2ZNk52hT3MpK+2YmlmPf22agnM0Tk2MXSw9G1vMzwNQ0W
         9SoyxT4PQ3qlvlQiUGrkZ8T/g+rJv7/zE9JbmSq1lm4Ha17eRaU5BadsOfINQLcSj9G2
         3I7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9vsuLoSObgSojPLAyFCzdUF+g9CtNNDY+7uKk5SdOC8=;
        b=Ak5biWaaiawCQF8LtevhLLL3sxD3QWwkwR24CkoDfFi51CKG2jtRHB1hodSWwKdWP5
         UYNxs+9rzAhljniZfvkO5vfjVzE55KyAkpvPT3SQ6VujTdeXO8k++ZXyMlVPEGB4cMpJ
         x8c69+CECHX8xrBDwPILj97H0KbChvGk8c7q3vJaNZWSYD7wTBLhMV+9ke7Rp/PvzhXA
         j/ZRM2ZzIuLSg22p6LOlaPpbdyWezGFtjPm1zvj7UbGxfMbqLgYrHe7gh+HRocfSWJ4L
         1P8nlyLdZs1jOB6b037YkO3xvXZS/7fzaZ4rvOO8u5tiHX3je5rlR1m90JacONBNXFKx
         oRUQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVLF2lfi7HYGrkOlNAlTy5iytjRuCjLe+dPgROlHQ4eC3vXckz3
	pqE2VzYIbSCCgZVf4xMOnXo=
X-Google-Smtp-Source: APXvYqzgohi+xMVkLRU3QrX+r6BLwc1WdceaabJq4QBWLhbyDzw2Rzq760UhcKbgT8NTlqDvDNKQPQ==
X-Received: by 2002:a63:c64b:: with SMTP id x11mr134177pgg.319.1565802221406;
        Wed, 14 Aug 2019 10:03:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3fcf:: with SMTP id m198ls587139pga.10.gmail; Wed, 14
 Aug 2019 10:03:41 -0700 (PDT)
X-Received: by 2002:aa7:8c4c:: with SMTP id e12mr961303pfd.258.1565802221082;
        Wed, 14 Aug 2019 10:03:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565802221; cv=none;
        d=google.com; s=arc-20160816;
        b=DhJ0WNzIU3AvP5xLEiwEzautz/7Gs/PwXQCYBLLPKV0UGeRmqZXxiDhV6ANignaFef
         9xgGwOpQw0hYbk4OjvEfLc6t5LzufdzbbGXFx9PPRqC/plsBeTm/LIbc0vlICWtHr85/
         t0qkPS283iDLPhFvCqzrm7kISrvr/lMHS2rJ4GED9gObuOdj/7i/lyZYOfnCK2olexIR
         dc93JelhCozgYquPJ7D+HxME6JSyLclASBbgV9lziMBymV0mQP/L0yFbUTok6AaF9PJw
         e4rF6kwxPqUDBn3dp6UUJ5uCePiWrI/q+q0hskqHGWYuOJwpZMwtzudu2c19mbdmFr8/
         BzTw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=VPLCSa9Mg0xoV570EQzBhdB+yL6SWWFzgzVz0WEOMmM=;
        b=xhMacYwp/kjF2FpsUSTyawrmi8TdEMMrdeCcIL1zj7sfj3LKwrb1Z5rdrIo/9OnRlV
         zpGLMV58TK2NDwkQUhp+gDhzJJJxKle8yEBfT2N29zazLbZfuS9QOt1YxWYtN6KwNqUC
         ORJgrNmqU4bvnc3hXtJG2ZHOi6SJAZpf+ZVlwmcySwpvM69YU+49odD2PP9wfGEfomfU
         cK+o6kKgjkJ5wYXNi0lSkaQYvq+ESwad3veYpYke36uXEKnS4HVRf8jYk+cDNrBh7c/6
         Mzkp4Z+V3aAV9AggNZuKhTrjYv/hECNFS+iPjW9esjUSJhmal1alCE53obMxM9q57o09
         mJOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=KqQ8A8lx;
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
Received: from mail-ot1-x343.google.com (mail-ot1-x343.google.com. [2607:f8b0:4864:20::343])
        by gmr-mx.google.com with ESMTPS id j6si14249pjt.0.2019.08.14.10.03.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 14 Aug 2019 10:03:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::343 as permitted sender) client-ip=2607:f8b0:4864:20::343;
Received: by mail-ot1-x343.google.com with SMTP id q20so31175533otl.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2019 10:03:41 -0700 (PDT)
X-Received: by 2002:a6b:8f82:: with SMTP id r124mr1023322iod.6.1565802220297;
        Wed, 14 Aug 2019 10:03:40 -0700 (PDT)
Received: from localhost (c-73-95-159-87.hsd1.co.comcast.net. [73.95.159.87])
        by smtp.gmail.com with ESMTPSA id x23sm428250iob.36.2019.08.14.10.03.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2019 10:03:39 -0700 (PDT)
Date: Wed, 14 Aug 2019 10:03:39 -0700 (PDT)
From: Paul Walmsley <paul.walmsley@sifive.com>
X-X-Sender: paulw@viisi.sifive.com
To: Nick Hu <nickhu@andestech.com>
cc: Palmer Dabbelt <palmer@sifive.com>, Christoph Hellwig <hch@infradead.org>, 
    =?ISO-2022-JP?Q?Alan_Quey-Liang_Kao=28=1B$B9b3!NI=1B=28J=29?= <alankao@andestech.com>, 
    "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>, 
    "green.hu@gmail.com" <green.hu@gmail.com>, 
    "deanbo422@gmail.com" <deanbo422@gmail.com>, 
    "tglx@linutronix.de" <tglx@linutronix.de>, 
    "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>, 
    "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
    "aryabinin@virtuozzo.com" <aryabinin@virtuozzo.com>, 
    "glider@google.com" <glider@google.com>, 
    "dvyukov@google.com" <dvyukov@google.com>, Anup Patel <Anup.Patel@wdc.com>, 
    Greg KH <gregkh@linuxfoundation.org>, 
    "alexios.zavras@intel.com" <alexios.zavras@intel.com>, 
    Atish Patra <Atish.Patra@wdc.com>, 
    "=?ISO-2022-JP?Q?=1B$BN%=3F&=1B=28JZong_Zong-Xian_Li=28=1B$BM{=3D!7{?=
 =?ISO-2022-JP?Q?=1B=28J=29?=" <zong@andestech.com>, 
    "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
In-Reply-To: <20190814032732.GA8989@andestech.com>
Message-ID: <alpine.DEB.2.21.9999.1908141002500.18249@viisi.sifive.com>
References: <mhng-ba92c635-7087-4783-baa5-2a111e0e2710@palmer-si-x1e> <alpine.DEB.2.21.9999.1908131921180.19217@viisi.sifive.com> <20190814032732.GA8989@andestech.com>
User-Agent: Alpine 2.21.9999 (DEB 301 2018-08-15)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: paul.walmsley@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=KqQ8A8lx;       spf=pass
 (google.com: domain of paul.walmsley@sifive.com designates
 2607:f8b0:4864:20::343 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
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

Hi Nick,

On Wed, 14 Aug 2019, Nick Hu wrote:

> On Wed, Aug 14, 2019 at 10:22:15AM +0800, Paul Walmsley wrote:
> > On Tue, 13 Aug 2019, Palmer Dabbelt wrote:
> > 
> > > On Mon, 12 Aug 2019 08:04:46 PDT (-0700), Christoph Hellwig wrote:
> > > > On Wed, Aug 07, 2019 at 03:19:14PM +0800, Nick Hu wrote:
> > > > > There are some features which need this string operation for compilation,
> > > > > like KASAN. So the purpose of this porting is for the features like KASAN
> > > > > which cannot be compiled without it.
> > > > > 
> > > > > KASAN's string operations would replace the original string operations and
> > > > > call for the architecture defined string operations. Since we don't have
> > > > > this in current kernel, this patch provides the implementation.
> > > > > 
> > > > > This porting refers to the 'arch/nds32/lib/memmove.S'.
> > > > 
> > > > This looks sensible to me, although my stringop asm is rather rusty,
> > > > so just an ack and not a real review-by:
> > > 
> > > FWIW, we just write this in C everywhere else and rely on the compiler to
> > > unroll the loops.  I always prefer C to assembly when possible, so I'd prefer
> > > if we just adopt the string code from newlib.  We have a RISC-V-specific
> > > memcpy in there, but just use the generic memmove.
> > > 
> > > Maybe the best bet here would be to adopt the newlib memcpy/memmove as generic
> > > Linux functions?  They're both in C so they should be fine, and they both look
> > > faster than what's in lib/string.c.  Then everyone would benefit and we don't
> > > need this tricky RISC-V assembly.  Also, from the look of it the newlib code
> > > is faster because the inner loop is unrolled.
> > 
> > There's a generic memmove implementation in the kernel already:
> > 
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/linux/string.h#n362
> > 
> > Nick, could you tell us more about why the generic memmove() isn't 
> > suitable?
> 
> KASAN has its own string operations(memcpy/memmove/memset) because it needs to
> hook some code to check memory region. It would undefined the original string
> operations and called the string operations with the prefix '__'. But the
> generic string operations didn't declare with the prefix. Other archs with
> KASAN support like arm64 and xtensa all have their own string operations and
> defined with the prefix.

Thanks for the explanation.  What do you think about Palmer's idea to 
define a generic C set of KASAN string operations, derived from the newlib 
code?


- Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.9999.1908141002500.18249%40viisi.sifive.com.
