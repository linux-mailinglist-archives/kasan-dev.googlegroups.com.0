Return-Path: <kasan-dev+bncBD4LX4523YGBBE432KBAMGQEWFYWFUI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 076E4341BA5
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 12:40:05 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id i1sf24246924pgg.20
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 04:40:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616154003; cv=pass;
        d=google.com; s=arc-20160816;
        b=SsBmFlEJWBIPBik8aZfa2XTDzuENwfwB9E9JTYiBASpP2LvOZ3TMzaRt3+A/r/jEzj
         3OC5mX231TSFoKJ6XVF4fHIlIvN3f5HHtnb4omkIcV4kJ9raLDqhKufEkBCPtpKjVuJ8
         P85P8Lrji7qmkb5ykUD306QIhVO5FXE5DjFYBR3XFFgKQbCdPKmy0bzG6yC9cToU1x9h
         d6Un+9KhR38fHN8CpxR1EARxYUiZgIOouidFDPAIFJWXNprYkxlFD0XxB9AJhSk+gRuU
         VSc6YtMCY2qqHCXhAaoVSEIn6siebTXwVuAH9U2dhva8hmUKfc0hVw4KQYvykaeWyDpZ
         14wQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=6BP1pIaiwjvVxmHnYPM1LYNltRHvFYQd8kfdLyv+UZE=;
        b=MsKDRCpn8Co4TTLoINb0n6BZ5qgIth5jR9NLAajR49CEkTHpbZX94Oh5IMs7LbCgiG
         oXpkGldpIBbKBBuReb2z0sKzKowjCoAQqIwfql4kZ+JoYWOmdWkWPu569bE9csIUGaEN
         9Wf0W1loZ+I95SsYDb25f+USS+VOQEci1aPDbjMVmH8vp5S8mAVgtNUogM4UvfvBNcpR
         u2uu7aZ+fjmUm7jw8cp95LNEgLtbFGwPaD4jpk9bQO5i+QuvPy5yxMDgdy3YrR85AtH2
         Bi2ZoCyAifIwJKB1y7J4L4wDKWQwuzAh/EJEUt3L1rH5bNApAToyCXmJ6rYF9EK7qIdZ
         9UVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6BP1pIaiwjvVxmHnYPM1LYNltRHvFYQd8kfdLyv+UZE=;
        b=lbclL37ylN+2pnZ7kMZsPM2bkKSyjzpGtAxi/lQjXThH9BI//dQdldx3nUs1T1zr8O
         7d2IrZPgNvow19SWL3+n9KI+fL/OBS0dZ7Jl7ZOvV2MkM40w7wkvZfFDskaEOZHR5zru
         xdhN3A1W+WZIdvokE3VrA2dM+Qk/SZAYj5KMNEkUXID24zJ2nQR1sLkIj4ZJCyPbt1Th
         /TFOkET6ZWeYD5KT47b3Ri1739Z4q8s1r4uiarscI2WW1/L33rBNymsEmAykMQ2emp1r
         1DCqoFs/jg/YcPTvEQosJN1MWHF6HILRmU6bviTAawPaMpmO4y/cap/BzarcjrwEwbx5
         17nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6BP1pIaiwjvVxmHnYPM1LYNltRHvFYQd8kfdLyv+UZE=;
        b=LAYIE88w5pwrB8dHY1NwdHRwigcbpei9eF9yWqFxx+pSy8NIM687pQ0HwRG1YSgz8g
         /KlT00JFr+bcdYR+2ctjTDm1KSckzhdgxYgTskDQLp344+VGck6lvCjUBH0bzgpwnYE3
         IUA9iLVcURoCv12SjGPSrLswwQfOm1wRmm8A7955/3NMGGaUna/ioNjdvIGR38CMsn1R
         thg2SphwPx1S+ZfhozEXAAlwHhPorSxzSc/yi/Q7ikOJqDmg0Bm+1bOdI4GyXEGsuwAU
         tqnL7OxA3isbwvUKgwrhloVAuGwC0lncJUZZGBMH+KdjwfmZlVPt7rAXH+RRZGjGVdpa
         Ou0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5300/z+xojBT+ap7Kvbqx229yImFIjKaUKomFzStglY0OMZkF+3X
	owSet46e+05ppX5zKXQ3r4Y=
X-Google-Smtp-Source: ABdhPJyFgQs+/VGwg1YatPx7ymlN/CaJ/5SNUa8xKtMIxZhPkE0Vo25BglPkK9PdzZ1V7Oe4v3jlLg==
X-Received: by 2002:a17:902:7fc8:b029:e4:32af:32da with SMTP id t8-20020a1709027fc8b02900e432af32damr14498208plb.24.1616154003666;
        Fri, 19 Mar 2021 04:40:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:2147:: with SMTP id s7ls1898108pgm.3.gmail; Fri, 19 Mar
 2021 04:40:03 -0700 (PDT)
X-Received: by 2002:a63:4658:: with SMTP id v24mr10954524pgk.258.1616154003051;
        Fri, 19 Mar 2021 04:40:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616154003; cv=none;
        d=google.com; s=arc-20160816;
        b=E0BSAnJIzwsplopI6uWA6oPYIp5vvsnmz+5YhPZdzNJzRxeaRnD7jRdTPPC1A4Ref5
         yUvD6ucG5Us98yanQjBws+jMjuo5EgM6mCf2rNOW/A0Q5fDiCIpf4sUb1wQ03DXVNwRd
         VtcgnkkJWKktwZBibPaah7E3PQCeJ3/mmo8DAEOnELq1BV8+KY5aSmjgD4LUKv7cZwDp
         f44gOtRqgXRBZHRtK0hBfFb0D4a9tHsPpFWdA2pLl68eRNbxS3mvGaiahOaINB8BpwfL
         QFf8x2mkgE/tC83RHJKSsmb4BlN6oEAQJAPEpKy/iMgUO5KZaPvpFwuC6HmoZjWgXP4u
         U22Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=vY2ggs2A8ajZ4mRUb85FvBFlLAko9QDY4VMPlZsm8Ec=;
        b=DBtQR6zP7p/SiIwAnWAOSTgcTuRkOUPS8mkAE72ZmRmyVNv+Kqvw+1opz+jl2iO0lm
         rfqBQfPMcwiI+mhIaRuziwpXdgMulPMHqI63G8NsMgcRi6p7aw6eykl9EHHzsZ0HakIA
         qiqLVoxFKSFDmr7o5ZvrgCBgyjjl/lIpLpUoxm356nZgjb/3haA2/pvlr6T1eiM9HAuu
         OuweJM5uKwmvQhvymmCU3LTYTU2qHLn3oHmaBs0plDUEIwYCYrAwM+p3UboowJoAFlsm
         i7+gPIS0N7lc5viDT5d+O5naagefNqEMXo4bdNmbXQNEesbaiCDFJmXcWFLmjEbF8VWn
         dOtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id r23si252364pfr.6.2021.03.19.04.40.02
        for <kasan-dev@googlegroups.com>;
        Fri, 19 Mar 2021 04:40:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 12JBbiIL004557;
	Fri, 19 Mar 2021 06:37:44 -0500
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 12JBbeiG004554;
	Fri, 19 Mar 2021 06:37:40 -0500
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Fri, 19 Mar 2021 06:37:40 -0500
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: David Laight <David.Laight@ACULAB.COM>,
        Alexander Potapenko <glider@google.com>,
        Marco Elver <elver@google.com>,
        Andrew Morton <akpm@linux-foundation.org>,
        Dmitriy Vyukov <dvyukov@google.com>,
        Andrey Konovalov <andreyknvl@google.com>, Jann Horn <jannh@google.com>,
        LKML <linux-kernel@vger.kernel.org>,
        Linux Memory Management List <linux-mm@kvack.org>,
        kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH mm] kfence: fix printk format for ptrdiff_t
Message-ID: <20210319113740.GL16691@gate.crashing.org>
References: <20210303121157.3430807-1-elver@google.com> <CAG_fn=W-jmnMWO24ZKdkR13K0h_0vfR=ceCVSrYOCCmDsHUxkQ@mail.gmail.com> <c1fea2e6-4acf-1fff-07ff-1b430169f22f@csgroup.eu> <20210316153320.GF16691@gate.crashing.org> <3f624e5b-567d-70f9-322f-e721b2df508b@csgroup.eu> <6d4b370dc76543f2ba8ad7c6dcdfc7af@AcuMS.aculab.com> <001a139e-d4fa-2fd7-348f-173392210dfd@csgroup.eu> <4f7becfe2b6e4263be83b5ee461b5732@AcuMS.aculab.com> <e4577151-bc73-5033-a9ed-114dd0c1aaaf@csgroup.eu>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <e4577151-bc73-5033-a9ed-114dd0c1aaaf@csgroup.eu>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Thu, Mar 18, 2021 at 10:38:43AM +0100, Christophe Leroy wrote:
> Yes it seems to be wrong. It was changed by commit d27dfd3887 ("Import 
> pre2.0.8"), so that's long time ago. Before that it was an 'int' for ppc32.
> 
> gcc provides ptrdiff_t in stddef.h via __PTRDIFF_TYPE__
> gcc defined __PTRDIFF_TYPE__ as 'int' at build time.

(On 32-bit PowerPC Linux.)

> Should we fix it in arch/powerpc/include/uapi/asm/posix_types.h ?

I think so, yes.

> Anyway 
> 'long' and 'int' makes no functionnal difference on 32 bits so there should 
> be no impact for users if any.

Except that long and int are different types, which causes errors like
what you have here.  There may be similar fallout from changing it back.


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319113740.GL16691%40gate.crashing.org.
