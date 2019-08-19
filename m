Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBV55DVAKGQEWPBEICY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 3490691BA9
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Aug 2019 05:59:04 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id m19sf1740360pgv.7
        for <lists+kasan-dev@lfdr.de>; Sun, 18 Aug 2019 20:59:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566187142; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lt2bdopG2Zg1N6QDFzgWPk66UK5NLZd4zIEIvtIAdCNH3asZzc3Sap+JVt6deMRu0y
         S5MQWVGiih4QOMwm+0zrXckQg31S0LLILxQwEnf3didsRSdVbqdS66ypsrtFgWJMv92p
         ibxtONsvvlw+zKX61nm3V0iXqieoYGjJZh8COcxMbsFwVW+y/dR1fY8zjzJPA2NWXas0
         5/oUQvl9sQjJfpxfQbD2YXdO2fXaZo2qBQXMISmUhO3iB1uuDQJZ3Xg7/qSwH7lj5uq/
         fvuYTZp6O36gW2Rx+pyLSf0jVmJQyDgGawP7nmMQtp14l18GWqxBOT/qCygdlnsSkHPZ
         lxBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=B7c2f4KLCX4TFv81ecR4RAfGuHUBuoRV75J0UyB6lig=;
        b=zJxj9iULEdtZSyZxXn4zxGnFuzMhpt+Nu0Am4h6v98Vt2pynSfxIhqfs45FIkLbTVO
         UTbF4AC0hxtChSvwTAgGeAmIHQLBsbdzGQugc6hb3Q8uWNXvTOFoBwi31yNCQ5q94r0j
         o4SLk6tMB9l9IrMUm349kw7bePRzHvrtX/GuAnlj5ML6J09dLh4goo9zzQccjGAOdwlA
         ocWegsDEr9KxewvDOQKnhlce9bNW8O4PDRhYIADSu9VxGJTY7wTgQqqUWWWyEzbYqawp
         NgrzsA9CvmTeodU6gg0M4cciO7orhvX/iXT8RuGBOlh8qLLvabx2F0VGykM27gAFM+hs
         3OoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZA6XLzRF;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B7c2f4KLCX4TFv81ecR4RAfGuHUBuoRV75J0UyB6lig=;
        b=X7yf8CF0d6WVxscvVNhBPd6PdDzRMgeecCLhI9kWGtfVvEjWAbp83+cOCgoPQfCyuW
         paahjZ8kblSfVq+Y80NED9oRrMKxbDlCmlcKMfYugngmcTIUaHcTpjuhwbb2XLaym1lZ
         mn35zv0hFO5fn2vmvuRQriJcKLuELvVbkfMyY31dwIYU+R6WXaY6z3VM6lJQ2zTGuBJf
         Ez4R91HIo7+jULHK8sLZNVWoKxSSzIiYjgHQGJtEboO94xfY2eOYkmfmcsAuTiT/WKHF
         x+vF6i9B9VJYIA7JeddJ7VyRVfhQ/J9QsRwDrhs4NREBiFL+FFJuyOYnsk5nW7M4fz3Q
         F2wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=B7c2f4KLCX4TFv81ecR4RAfGuHUBuoRV75J0UyB6lig=;
        b=hGRjsOh3M4s9JSt+5tXaMvgtH21x9Jycx60gktA/Dd4FTkBnHt3CElpE0xnl4CnWCY
         mV24x8kY7TJeMElXRJWAiEcegp2K8J3oJCVyTPszpgN+ov43o/hrV2TAnF0boJaUgruv
         xh8PSImg8vOVYfh5EVn4Y7xbRSP/UvXhQ61IiPF0TUXUBhgUVU+jPWhWY0cE/M6HCIL8
         grQhwDk3fyN60RQ63GlYzd7LI8Hmj0E234/hRv5IxNnF2l5CjJr6npc/hvIY2261+cRq
         Hz76aF3VOa+bBSK0lkacfUOl6nfi/PV40cM5yCq0r+WBaioJJ3DCACiRBS7S1KAKLtGG
         RndQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWsUjd+Iy9rnXnr6dxl1oexJE+keQswEVOWSZnIbG4NBXx07lLL
	J2B6zQ2iSQsca5nWCK0Viq0=
X-Google-Smtp-Source: APXvYqz72/Vx2qXQOsoZfhZLQO9FfTtGCqjHJ9sYQZPSxdPGv+Uq3fwmgsaZa4aVRgerHr+qip+y+A==
X-Received: by 2002:a17:902:7202:: with SMTP id ba2mr21089850plb.266.1566187142523;
        Sun, 18 Aug 2019 20:59:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8042:: with SMTP id e2ls3002914pjw.4.gmail; Sun, 18
 Aug 2019 20:59:01 -0700 (PDT)
X-Received: by 2002:a17:902:12d:: with SMTP id 42mr19562701plb.187.1566187141683;
        Sun, 18 Aug 2019 20:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566187141; cv=none;
        d=google.com; s=arc-20160816;
        b=OX8yje+alvuv3q2cDGtD8CODXGz5KBglEu/rr4EVNozjvtrkAv4suWuRHm4GxVN+/F
         AJ+1X/9fnGkjiqYGP34rU0V6l/neXUE0YVwv8yNNZw3xpuCPGHjYKp1drEETaWONLmva
         Q0yPvroBWZgCRMlJNP08vs87/xQPSNK6+frjWV9aQ4WsWmCUJzskXNOnVePpZc9R/fDW
         zfMkKqYLux7qbImcAU+xBxb5+1ebAs/3dRDA3HqUO3qphqHiYyh9xPl2GMBM8BpCRW+f
         gDpcmsORWw/WxakGZPbTkWMoeNHjyzmt0F7IXEXNxvF7hzl4fdH5nYDFpOqgl3qkZTGZ
         JIeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=qkepw2mcByNh/XDFWlSo/1pf2rJV4AneuZO+UsdnIoM=;
        b=m/sgMDusj8aXWRWIr1YS6Hm5J7DYO5OQh1lb71ulVGZapnBXH3ZtNkkoXxL3o6KYSD
         NYvErWf3ULNkMZDMyW/uHNl0t43jsIbZ/IrvFLmeaC1Y1gqpy85F87eF1h+JXJ4sF0r/
         c9JfCfOSsi8a4IlfrpQesD5aqRYABKZRykVjc/4+VWLQni1+2CkdkyziywPGEXoBNlhI
         T7EaFAnQL2OBvFiRKMGH+2zJpltdaXkeelXWRJwEBNzab2PjLeaWqLDMLDREpD5NVn+8
         rczwTKG7rfvKHpBr6STjsSZwnxaPH6u000FUn2yMkld9zePjKj5sEriE6rbXwupbmYml
         g2Uw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ZA6XLzRF;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id f125si652070pgc.4.2019.08.18.20.59.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 18 Aug 2019 20:59:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id e11so369889pga.5
        for <kasan-dev@googlegroups.com>; Sun, 18 Aug 2019 20:59:01 -0700 (PDT)
X-Received: by 2002:a63:c203:: with SMTP id b3mr18301448pgd.450.1566187141292;
        Sun, 18 Aug 2019 20:59:01 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id t6sm12987903pgu.23.2019.08.18.20.58.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 18 Aug 2019 20:59:00 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>, Christophe Leroy <christophe.leroy@c-s.fr>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v4 1/3] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20190816170813.GA7417@lakrids.cambridge.arm.com>
References: <20190815001636.12235-1-dja@axtens.net> <20190815001636.12235-2-dja@axtens.net> <15c6110a-9e6e-495c-122e-acbde6e698d9@c-s.fr> <20190816170813.GA7417@lakrids.cambridge.arm.com>
Date: Mon, 19 Aug 2019 13:58:55 +1000
Message-ID: <87imqtu7pc.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ZA6XLzRF;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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


>> > Instead, share backing space across multiple mappings. Allocate
>> > a backing page the first time a mapping in vmalloc space uses a
>> > particular page of the shadow region. Keep this page around
>> > regardless of whether the mapping is later freed - in the mean time
>> > the page could have become shared by another vmalloc mapping.
>> > 
>> > This can in theory lead to unbounded memory growth, but the vmalloc
>> > allocator is pretty good at reusing addresses, so the practical memory
>> > usage grows at first but then stays fairly stable.
>> 
>> I guess people having gigabytes of memory don't mind, but I'm concerned
>> about tiny targets with very little amount of memory. I have boards with as
>> little as 32Mbytes of RAM. The shadow region for the linear space already
>> takes one eighth of the RAM. I'd rather avoid keeping unused shadow pages
>> busy.
>
> I think this depends on how much shadow would be in constant use vs what
> would get left unused. If the amount in constant use is sufficiently
> large (or the residue is sufficiently small), then it may not be
> worthwhile to support KASAN_VMALLOC on such small systems.

I'm not unsympathetic to the cause of small-memory systems, but this is
useful as-is for x86, especially for VMAP_STACK. arm64 and s390 have
already been able to make use of it as well. So unless the design is
going to make it difficult to extend to small-memory systems - if it
bakes in concepts or APIs that are going to make things harder - I think
it might be worth merging as is. (pending the fixes for documentation
nits etc that you point out.)

>> Each page of shadow memory represent 8 pages of real memory. Could we use
>> page_ref to count how many pieces of a shadow page are used so that we can
>> free it when the ref count decreases to 0.

I'm not sure how much of a difference it will make, but I'll have a look.

>> > This requires architecture support to actually use: arches must stop
>> > mapping the read-only zero page over portion of the shadow region that
>> > covers the vmalloc space and instead leave it unmapped.
>> 
>> Why 'must' ? Couldn't we switch back and forth from the zero page to real
>> page on demand ?

This code as currently written will not work if the architecture maps
the zero page over the portion of the shadow region that covers the
vmalloc space. So it's an implementation 'must' rather than a laws of
the universe 'must'.

We could perhaps map the zero page, but:

 - you have to be really careful to get it right. If you accidentally
   map the zero page onto memory where you shouldn't, you may permit
   memory accesses that you should catch.

   We could ameliorate this by taking Mark's suggestion and mapping a
   poision page over the vmalloc space instead.

 - I'm not sure what benefit is provided by having something mapped vs
   leaving a hole, other than making the fault addresses more obvious.

 - This gets complex, especially to do swapping correctly with respect
   to various architectures' quirks (see e.g. 56eecdb912b5 "mm: Use
   ptep/pmdp_set_numa() for updating _PAGE_NUMA bit" - ppc64 at least
   requires that set_pte_at is never called on a valid PTE).

>> If the zero page is not mapped for unused vmalloc space, bad memory accesses
>> will Oops on the shadow memory access instead of Oopsing on the real bad
>> access, making it more difficult to locate and identify the issue.

I suppose. It's pretty easy on at least x86 and my draft ppc64
implementation to identify when an access falls into the shadow region
and then to reverse engineer the memory access that was being checked
based on the offset. As Andy points out, the fault handler could do this
automatically.

> I agree this isn't nice, though FWIW this can already happen today for
> bad addresses that fall outside of the usual kernel address space. We
> could make the !KASAN_INLINE checks resilient to this by using
> probe_kernel_read() to check the shadow, and treating unmapped shadow as
> poison.
>
> It's also worth noting that flipping back and forth isn't generally safe
> unless going via an invalid table entry, so there'd still be windows
> where a bad access might not have shadow mapped.
>
> We'd need to reuse the common p4d/pud/pmd/pte tables for unallocated
> regions, or the tables alone would consume significant amounts of memory
> (e..g ~32GiB for arm64 defconfig), and thus we'd need to be able to
> switch all levels between pgd and pte, which is much more complicated.
>
> I strongly suspect that the additional complexity will outweigh the
> benefit.
>

I'm not opposed to this in principle but I am also concerned about the
complexity involved.

Regards,
Daniel

> [...]
>
>> > +#ifdef CONFIG_KASAN_VMALLOC
>> > +static int kasan_populate_vmalloc_pte(pte_t *ptep, unsigned long addr,
>> > +				      void *unused)
>> > +{
>> > +	unsigned long page;
>> > +	pte_t pte;
>> > +
>> > +	if (likely(!pte_none(*ptep)))
>> > +		return 0;
>> 
>> Prior to this, the zero shadow area should be mapped, and the test should
>> be:
>> 
>> if (likely(pte_pfn(*ptep) != PHYS_PFN(__pa(kasan_early_shadow_page))))
>> 	return 0;
>
> As above, this would need a more comprehensive redesign, so I don't
> think it's worth going into that level of nit here. :)
>
> If we do try to use common shadow for unallocate VA ranges, it probably
> makes sense to have a common poison page that we can use, so that we can
> report vmalloc-out-of-bounfds.
>
> Thanks,
> Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87imqtu7pc.fsf%40dja-thinkpad.axtens.net.
