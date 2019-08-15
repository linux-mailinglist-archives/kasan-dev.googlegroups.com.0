Return-Path: <kasan-dev+bncBCW677UNRICRBKOI23VAKGQEE63EB7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AA1B8F35A
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 20:27:55 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id a9sf1574945pga.16
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 11:27:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565893673; cv=pass;
        d=google.com; s=arc-20160816;
        b=h3COmhiDjMZfho/s3KRylrULNAR1yemM+UNWixoeS4fMcxHGzD178iieS1ECKe2wp5
         SJvqBJPiZrQtuWRafI7P4zftbkeNb4hP1petwXkAGqmqaM61EXQJC3iby+rXCGnLmLd6
         5H+JjJKjpl4x4Iugmbqu4uNQXX/TZ71AGRtfIforsq5CReYdKKx8JmTQ0pTcXv7vBnq0
         IIYdkuRssiIegTOXBdnt5L0hSKGPhTWWk5BARpIFG+JXs4oG0P6BKr0OaJq+YoTz0Lb9
         8KXdNjIkikmZXE6DLuSne5dX/cOK1tJfZnPV7aTpRb4+NMAFrMtCSF7tL9ubDPE8ePvB
         2PCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :message-id:in-reply-to:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=V5W7bYUIRJGhoZ3Mo9tUV6fpYJ2CXWD0692fPMifT1s=;
        b=woQeBnhkH8Kl4VYqa7DziUrmdnyfKl4BoIs8WnSZ42xaoZ4E+ZeqlLHc9i/1s4HKD8
         mIYxYDqfcMQSpEi6vn90zFwyMNWXWkB2rV23G94Wm/dtc/3Al57J86RXv6AdYiY3JGzp
         suVWu4UdDeiq1Ei4+somsz5U6MepiPKAdrqzj46UxHVbJFj0L7Bp1t8yn/Cqdu6VSkbJ
         zImm3IWkk+n2vKnWH6wiCWoGYz6OLjUUrTcOixH6d7MASLNuNiNmk/F/1pMCRe95kJUE
         xNAuFQadMTOEU15dR35otuPizPzAcJ7GZbAg7HWJAD3tV3pa+f4M1IDv8PxzbCHZuDPL
         /aGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=gDgg6nSx;
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:in-reply-to:message-id:references
         :user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V5W7bYUIRJGhoZ3Mo9tUV6fpYJ2CXWD0692fPMifT1s=;
        b=FzHusFifwZrrSvdF26odSjaNCdfhJnzm83vN9tBr0Je/6qiN4DTlD8dWI4/ub/Jt2Z
         veMhEOcxrQeopaVcEXfk8eUPXQDWnfDoUuoC8wGtwymv/BXi2FjBpNUCBeRwuRvoI1+Z
         fhbLb96LFFNbDUXYBuPuPU16qkncrn6AcCEhOcg2VaC3V8eVXQk+op71bYFZ9jUyHCDj
         Pk3cvKBjNIk/ifKZLfbjlfDsLuzZ8PRszT4jTWDdwL8JJPsxGPFxHSV+kFAQP3HhgHcT
         4TJvSgWpvnN/urkkbPRYaUFE0egJoqwJu836jzHOqu4r/I1okaegv/8pTXtwfkEFhYTR
         U9zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:in-reply-to
         :message-id:references:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V5W7bYUIRJGhoZ3Mo9tUV6fpYJ2CXWD0692fPMifT1s=;
        b=hy5PgF1MsDaukM59rTJEziGpuDux9YQdlmzQSeeYp4F9iZbuN0mjTce0dVhdvGDQlH
         1kA5TJwK9qOAGbmOd/qM/nG/rYYtn3zCimbIs+xjBSp6669TwkAYxbSdZFWf+s2Bmr69
         1aB8rkv07Efi9XtHBXcL8pjArK1P9dKrUyxKWq9hOrPd6orrq4JUexS7GRMbkiwpZoF9
         xC5P13bZPPCDycw/nXrizBzYBT3qFzu/8rK7sCFu/lGPA0oq9AFbCzapgh+Y0gen2gp7
         YCwgrepAOQ2upfaGzO+Q0LTmCSHbD9Sja2Ai7XM8S2OK1QDNqAacEUu0rbsCjIe3zd4Z
         2u3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVLlPviT2NEmZF09fj82pMaMqQSy3aUZuJnMORbsKOdBN3KOx6C
	U/gZZ7t7ITV29cRxF7l7kpg=
X-Google-Smtp-Source: APXvYqzbuVMqqDgUnWB33uITvMMy33wwXeLYCTdwBHSt9kt/E0SkQF0M3IEQXXA/Y3f5ODfUBKMZxA==
X-Received: by 2002:a17:90a:7f85:: with SMTP id m5mr3463592pjl.78.1565893673718;
        Thu, 15 Aug 2019 11:27:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a9:: with SMTP id a38ls1423671pla.5.gmail; Thu, 15
 Aug 2019 11:27:53 -0700 (PDT)
X-Received: by 2002:a17:902:40e:: with SMTP id 14mr5717019ple.323.1565893673429;
        Thu, 15 Aug 2019 11:27:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565893673; cv=none;
        d=google.com; s=arc-20160816;
        b=lVA0SM3V5OitB01DUKayHyYziAjvd159z1jTgR+K6QwE3va8tT4bYuZYaS4A2zr889
         gaYkZnCDNaQJPv+yqI1WTFvbfkfa8ER3orZyH7dFR0jZ/2aJvG3dnsfJm42feuYY52ZZ
         I1v6LaJnNNEF7w7WrM49YBHHsVtS6C0RB4I80riQjAkz7zrU7FtmucOo7SuDTmZjNYhc
         Th8AAC8XkB8s7TiyD6r1DbBR3A3qYtCqCHoHiGZ+FAZHPLUr3BHsqfadFrX2j33ULouJ
         G+rPTPcJNtx2QeDP9PHuy1PLulgzVe94bG7uM0dA8UcKXUSTHOzDl5Pei8Ez+GXmEMn7
         yTkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:references:message-id:in-reply-to:subject
         :cc:to:from:date:dkim-signature;
        bh=pLl7QP5PeHPo2FeqUfN5ecFJOdQWP0U1sgEUiznfkZs=;
        b=R/RnbZjAjizSwLGaUF4yHWoS0I1uwEWD/XvlFIKLGG5emt7Nko1o1MJKynttLcfsvN
         H345jt0fAz6aK0R8eW4eThjSW9hWw9NVnOrUH9tJ298e6i1+mC/UhWpY9MZvJXlXpBmw
         tet+yZmvcMnoEEX4NZjiq4+VR/fBjJlNKVdd2/u++9U5RMfqmbCPiDnqRrq+lZSB+8eS
         v7LCj9cs0xyTNvUrupZ9Ygp0GittOYofLsAoU1BqrsBYYMMSeRLgV9yAeChDOsAVn+Wn
         dqBf6cuZ2o0J3k9Dkdr0L6Lrxf4jamhJo2kA4iKnlG/KGSzda7gf01s+Kj8CyArfCrn8
         BqJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=gDgg6nSx;
       spf=pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
Received: from mail-io1-xd41.google.com (mail-io1-xd41.google.com. [2607:f8b0:4864:20::d41])
        by gmr-mx.google.com with ESMTPS id c11si65820pjo.1.2019.08.15.11.27.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Aug 2019 11:27:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of paul.walmsley@sifive.com designates 2607:f8b0:4864:20::d41 as permitted sender) client-ip=2607:f8b0:4864:20::d41;
Received: by mail-io1-xd41.google.com with SMTP id z3so1065255iog.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Aug 2019 11:27:53 -0700 (PDT)
X-Received: by 2002:a05:6602:2413:: with SMTP id s19mr7027115ioa.161.1565893672828;
        Thu, 15 Aug 2019 11:27:52 -0700 (PDT)
Received: from localhost (c-73-95-159-87.hsd1.co.comcast.net. [73.95.159.87])
        by smtp.gmail.com with ESMTPSA id w17sm4430608ior.23.2019.08.15.11.27.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Aug 2019 11:27:52 -0700 (PDT)
Date: Thu, 15 Aug 2019 11:27:51 -0700 (PDT)
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
In-Reply-To: <20190815031225.GA5666@andestech.com>
Message-ID: <alpine.DEB.2.21.9999.1908151124450.18249@viisi.sifive.com>
References: <mhng-ba92c635-7087-4783-baa5-2a111e0e2710@palmer-si-x1e> <alpine.DEB.2.21.9999.1908131921180.19217@viisi.sifive.com> <20190814032732.GA8989@andestech.com> <alpine.DEB.2.21.9999.1908141002500.18249@viisi.sifive.com>
 <20190815031225.GA5666@andestech.com>
User-Agent: Alpine 2.21.9999 (DEB 301 2018-08-15)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: paul.walmsley@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=gDgg6nSx;       spf=pass
 (google.com: domain of paul.walmsley@sifive.com designates
 2607:f8b0:4864:20::d41 as permitted sender) smtp.mailfrom=paul.walmsley@sifive.com
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

On Thu, 15 Aug 2019, Nick Hu wrote:

> On Wed, Aug 14, 2019 at 10:03:39AM -0700, Paul Walmsley wrote:
>
> > Thanks for the explanation.  What do you think about Palmer's idea to 
> > define a generic C set of KASAN string operations, derived from the newlib 
> > code?
> 
> That sounds good to me. But it should be another topic. We need to investigate
> it further about replacing something generic and fundamental in lib/string.c
> with newlib C functions.  Some blind spots may exist.  So I suggest, let's
> consider KASAN for now.

OK.  Here is the problem for us as maintainers.  You, Palmer, and I all 
agree that a C-language version would be better.  We'd rather not merge a 
pure assembly-language version unless it had significant advantages, and 
right now we're not anticipating that.  So that suggests that a C-language 
memmove() is the right way to go.

But if we merge a C-language memmove() into arch/riscv, other kernel 
developers would probably ask us why we're doing that, since there's 
nothing RISC-V-specific about it.  So do you think you might reconsider 
sending patches to add a generic C-language memmove()?


- Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/alpine.DEB.2.21.9999.1908151124450.18249%40viisi.sifive.com.
