Return-Path: <kasan-dev+bncBDQ27FVWWUFRBPUO7PUQKGQE7R2CB6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DB2078978
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 12:15:27 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id x5sf33811793otb.4
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2019 03:15:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564395326; cv=pass;
        d=google.com; s=arc-20160816;
        b=frenxeawgl1YIJSDFxcmzM+fKP09GVhQPoTGyXEFnKooq8qKyC0OiLZq6XIpWmXGNb
         wLSjXcENn1jtG82AgJUPkBbY5RyQe3x1Ka0LXpgy3SChic+L/+/jIXd9j1kHzTnklaK/
         vitFarL5COfJcckKZMYyXfitUr0hEt3J1a9QdrYSl0AuDqZ9+osUkqVprL6GcScoa9V2
         8WbxPw6CSJT2eUkun/aP8W0PVAasC3AnWUcbpJc8DnvNK5N+vLzAD/C/VouqUKOqOY0g
         Ms9z+LBgToN1hobtJRMO75s1+bFBv273ts9HU2aB9z9jLJU093WVtJy1reGnWPC/szLi
         3DiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=m7Fr3Eq+k3KaWM5cOQJ3hecLco9dG2M3OcDQSdWdXQg=;
        b=ICUx/V9/UkZs4wwGNbvjxbNrpq1FR9RNI5GoZZxhchLwrjffHu6l4O6dVzbbJIdSPI
         umlPuvqu5PrUXEyjHQtwoPT0o9LGr2w2rSO2bYRE6ePJMWqVPmc7PvcGpPdItB8FVHUJ
         WuMvR46mVi6yVkuSE/SgZ2+guOoql4F0VeO31ONiEmyGaDBARJbB8eKUkI1o4lUSnQXX
         d6SkV0EuRzLNCp9JwU4anOrQBuU9tzYqzxUNKbCQUY0e7MeVTJm4bSSaQ/PsVmV94rFi
         2YLjJ7AjdGYmhhyQo05Qb6lGt4rowAthdJ0ooq9WDjCEfRdhE2t/luYlLgXV+y1/mH7s
         rNRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=NB0yJ7s+;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m7Fr3Eq+k3KaWM5cOQJ3hecLco9dG2M3OcDQSdWdXQg=;
        b=DrqyoT2NNhH4Y2Tep0vll76cTHv1AdQGr9kUOBT8Le/wpi4Om3z1xCZN0i+Dn9jaiG
         dbwk31iGTlMs8yFt7Oqg2puYhQ+Vqf9QPVvLdVUXcukh+mP/GbSHCwQWZPe7gKeXSFgs
         psvZr5uPMVbyP0c2FI5SJb2IG8Yf2/lps9l4oX80bLyal6iTaUg44Jdcl4MXRimLIS18
         ruCN8xjTcAxbvxyBkzTt0S9du+xhIF7r+91gm7HQ0NPfU7e2z61NDspCTDphXEbcXiEB
         fyWx4VTkWA9YV89nQlxHfRo4mNBQYPfP5t2ZdP9rjzU4qOyMlBysAgrWWtPeewI0oHSx
         9k+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m7Fr3Eq+k3KaWM5cOQJ3hecLco9dG2M3OcDQSdWdXQg=;
        b=a1MA5tG0yJSNMfft2YC+NN2cTxcfuQImErgc5rZ0UCWVD7ItN4OwUo8ThgkPipoars
         DnPThYoQ4RdVpKUQqnlKvpCNCMKA4taZhwNPdMDTbkrzDRKq+LTwwm52QAJb5gcaKK/j
         NQKUAUimINEkBEYBNhwAOo4aSmN9uc3mbHRMXL7CTyb29EF6bCpvbvey3eptIgdqJnlx
         3jKJZhzwQOh3xCIw8LJ2RRqPHOZmNEtECBiZwsMTtpMQ1nl4KCPe9WfaTL+OmeG0GB+c
         givTuZJ4JXJ1/mVWq+mzW75mRHcUxEj458AELQWjVV8VQgZmPHWdoInafJkYbKmgN8lT
         dRYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWSmjyC0WHM2fc3Ct/Cg0Vn9UpPFjGMgHkaIbSX4vbrx262UGTK
	iBS4dyhvggn20PWwawW8Hp8=
X-Google-Smtp-Source: APXvYqzgRhmV6802pViXKCek8AnOzApxr3Br7PikfQ3VvEUicuP/dTnQXqagYik53Hc9ALp/ELK8vA==
X-Received: by 2002:a9d:2969:: with SMTP id d96mr82536794otb.85.1564395326195;
        Mon, 29 Jul 2019 03:15:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:b803:: with SMTP id i3ls8736505oif.4.gmail; Mon, 29 Jul
 2019 03:15:25 -0700 (PDT)
X-Received: by 2002:aca:d40e:: with SMTP id l14mr41654321oig.72.1564395325865;
        Mon, 29 Jul 2019 03:15:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564395325; cv=none;
        d=google.com; s=arc-20160816;
        b=Xp1VIQ9T2hGV3YhRI7h5aXQ7JbvD/XCxmgp+gtqKdElpUiQ2G4ZkzMsY5LDG8FQNzg
         +rEi5y73V8WpOLuUcRBiN/irzjGjOTlIeVs5iq3cloroiTJciGhhfmHG3LWA9p3FY6J3
         KalBgqA1LR6YnH5iB6dLX0I1fJOpO65OqcLQkfDwFu/y7EYCQzmATc7WScnN3Y2hfUWk
         mWETyT4aGf8aUdIkyQ9LZ4bo0w4ltX5n1kUMILDcOsAJkDmFMNZm5FXptsSQPUPVyPUp
         XSAT8aV68GEsIcOfHtHSeQZb1k45ehRQy8vwJ6Ut5g42huKECrtM/SGZe2Mlhmin9fYm
         ApMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=TeABIY9Sypa15BDJaEG/kpYb1fIC9bRaLEhXhSyew+g=;
        b=fXXjTqeXpZ/GnvIJXEIqypeVGaO/vwhzLQHMGy8bWVuSWHEwvDsBrbvOkYNeW0A9aA
         2C6Y1FK+GLru5H6HLcpsvao10cz46VyPLaQThdJ/aXdGakTRkVBWDNvEFxR+EXEADEw8
         8/N6tGRK0KdfVGfGAb8BltOorpkZ03u7+XyU5MxEmUg2Of4h9eGKzcwsA0e+9JFB6pbd
         UvcvfostMyBMUf+kiAPZPq5Xa9srcm5ZXbSSsqc2P7MQa2PEsxsuFjezoVSZHh8mB+Rw
         J2pkXwrCq87FPijs/WGtLMTjYpC885WD0oOchjZs6rbaYOW/GFFH9XM6Asp7fQxwrgBq
         LQIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=NB0yJ7s+;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id d8si2473167oth.2.2019.07.29.03.15.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jul 2019 03:15:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id s1so21710573pgr.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2019 03:15:25 -0700 (PDT)
X-Received: by 2002:a63:3203:: with SMTP id y3mr104769085pgy.191.1564395325067;
        Mon, 29 Jul 2019 03:15:25 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id o3sm113898745pje.1.2019.07.29.03.15.23
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Mon, 29 Jul 2019 03:15:24 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, the arch/x86 maintainers <x86@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>
Subject: Re: [PATCH 1/3] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <CACT4Y+Yw74otyk9gASfUyAW_bbOr8H5Cjk__F7iptrxRWmS9=A@mail.gmail.com>
References: <20190725055503.19507-1-dja@axtens.net> <20190725055503.19507-2-dja@axtens.net> <CACT4Y+Yw74otyk9gASfUyAW_bbOr8H5Cjk__F7iptrxRWmS9=A@mail.gmail.com>
Date: Mon, 29 Jul 2019 20:15:19 +1000
Message-ID: <87blxdgn9k.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=NB0yJ7s+;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
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

Hi Dmitry,

Thanks for the feedback!

>> +       addr = shadow_alloc_start;
>> +       do {
>> +               pgdp = pgd_offset_k(addr);
>> +               p4dp = p4d_alloc(&init_mm, pgdp, addr);
>
> Page table allocations will be protected by mm->page_table_lock, right?

Yes, each of those alloc functions take the lock if they end up in the
slow-path that does the actual allocation (e.g. __p4d_alloc()).

>> +               pudp = pud_alloc(&init_mm, p4dp, addr);
>> +               pmdp = pmd_alloc(&init_mm, pudp, addr);
>> +               ptep = pte_alloc_kernel(pmdp, addr);
>> +
>> +               /*
>> +                * we can validly get here if pte is not none: it means we
>> +                * allocated this page earlier to use part of it for another
>> +                * allocation
>> +                */
>> +               if (pte_none(*ptep)) {
>> +                       backing = __get_free_page(GFP_KERNEL);
>> +                       backing_pte = pfn_pte(PFN_DOWN(__pa(backing)),
>> +                                             PAGE_KERNEL);
>> +                       set_pte_at(&init_mm, addr, ptep, backing_pte);
>> +               }
>> +       } while (addr += PAGE_SIZE, addr != shadow_alloc_end);
>> +
>> +       requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
>> +       kasan_unpoison_shadow(area->addr, requested_size);
>> +       kasan_poison_shadow(area->addr + requested_size,
>> +                           area->size - requested_size,
>> +                           KASAN_VMALLOC_INVALID);
>
>
> Do I read this correctly that if kernel code does vmalloc(64), they
> will have exactly 64 bytes available rather than full page? To make
> sure: vmalloc does not guarantee that the available size is rounded up
> to page size? I suspect we will see a throw out of new bugs related to
> OOBs on vmalloc memory. So I want to make sure that these will be
> indeed bugs that we agree need to be fixed.
> I am sure there will be bugs where the size is controlled by
> user-space, so these are bad bugs under any circumstances. But there
> will also probably be OOBs, where people will try to "prove" that
> that's fine and will work (just based on our previous experiences :)).

So the implementation of vmalloc will always round it up. The
description of the function reads, in part:

 * Allocate enough pages to cover @size from the page level
 * allocator and map them into contiguous kernel virtual space.

So in short it's not quite clear - you could argue that you have a
guarantee that you get full pages, but you could also argue that you've
specifically asked for @size bytes and @size bytes only.

So far it seems that users are well behaved in terms of using the amount
of memory they ask for, but you'll get a better idea than me very
quickly as I only tested with trinity. :)

I also handle vmap - for vmap there's no way to specify sub-page
allocations so you get as many pages as you ask for.

> On impl side: kasan_unpoison_shadow seems to be capable of handling
> non-KASAN_SHADOW_SCALE_SIZE-aligned sizes exactly in the way we want.
> So I think it's better to do:
>
>        kasan_unpoison_shadow(area->addr, requested_size);
>        requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
>        kasan_poison_shadow(area->addr + requested_size,
>                            area->size - requested_size,
>                            KASAN_VMALLOC_INVALID);

Will do for v2.

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87blxdgn9k.fsf%40dja-thinkpad.axtens.net.
