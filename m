Return-Path: <kasan-dev+bncBDQ27FVWWUFRBH5W3LWQKGQEBVP5SOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C652E6D5F
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 08:39:12 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id o184sf9552047qke.0
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Oct 2019 00:39:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572248351; cv=pass;
        d=google.com; s=arc-20160816;
        b=ntd9sLb81Df0o8nSvuc10SwBBL6ErrdiLU/RC+F+OoPfhZN/c0WMzAofC+smKZRNxx
         6DQ/zOujGrLJHhmd3xxG8iCWyeJFJdwKARDjOy3vKIVdeE8jHY7qi0kkLYYDwDuDqsL7
         koBQl6B8twbgxiYrmCg+PvasZJcfcA6S6flWF/mOsGEcaGiW58KMG5AeG4clltworYXN
         /ReImOtjGfCjzrevfQHJstjfeLDykrv1SKKPQRjPgSAm+zEf2zGmRLclu5t/dpFNyqUX
         BiC+InOyOWWVGS2BMyY/S4FvpCo1kOxgR3eY6GIRc27EYDM73Rquw3LIx/IWTEvQIPFX
         sagQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=FHA6rK/3LYu62owqNT6qPpeuy+FoSsX9LxTeBjzEY64=;
        b=bS3E81oJWG52LNwO6sS0hHkrq6gzvF7Fm/L8jcdC97MV/kDbmXCEpi7o/lS01r4f5X
         SON/tIVQDUBnX6Rf574cu0d9q2c1ExDhwxKYF1WrLQIrUwQrLPYIvs9uQisj8XxuOaYj
         bJBCHqQBma0kWPb9ttGACqzif+rN/Zv3jMvFc78SPXG/8Yu1JgxyeAeEY6KAe4aKbgUq
         1Cijb/L8aOQWpJe2YXeI6qtVeuyb4c+KR7G0FFRVd7n6v1NHZg+i/v8hzf6zSNa7AyGB
         lbN7GzIBLqzw24PQsutwOeI8cA1838vMblFjBHz2sOc80MF1okHBIsWdS+HYlkM6RFG8
         1/Wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=A72Ecndl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FHA6rK/3LYu62owqNT6qPpeuy+FoSsX9LxTeBjzEY64=;
        b=j9KhBf8yTrYgVZYuZYXiZtYT2dKASO/bQIW+3gwfLjPA1sBrKYMljS/aq7/2jGepf5
         rFyzacxZEjSLzNufsW3wHXfTgrAGfmam80dimtJjX8h+1O+ea0i97qljqDDlvM5hqCiJ
         bIdXfKzmvjFwja+Pa8o2UbiPRzry77r8AUiktbdWKyHJCA9TcLymuyYOnlu47skwbSVM
         StCPuRCgD5JPorr0VGuM3vxECb5xPqK/2UrOzZffZ+KCUh0MJu1Y7bZeF8e24nASadRy
         QXNOci9bMvmRoANmu16qVJkh3Vmjj7NToEx2HPa0XdiLHzpnjXoSSZ6FkURngyKyXrKu
         iKSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FHA6rK/3LYu62owqNT6qPpeuy+FoSsX9LxTeBjzEY64=;
        b=l1n8CG8ng+4S3oCecsGa7+ilI1E6IJ0n7Cf4b7QU3ewKMh1rKyT9AEwPNFYpdm3Gqu
         my0xEmjfvybwrYoLH8DZHmPuL89zqSHx1Tan6ImrbQKJZNX3rcqepWz4j8AV9PdGqOJc
         kpvyIbOjXCdyajGHmW+EVrESPvvcgn1r7Dqt6C8bAXJROJCi2jfk/zszhUyc94ky8YzY
         a4Q0DJ9Io2EFepQTQr9AsrwUMe+fzCjDuJapKi2md47X6u9WEIPqnveyhww9OGLMGjG7
         04nPHAdmU0UN+7lm5HWhNhQd23edaxpXjjTgNR9JdMCsj+C1yI6FAjpdGqcMyFI4fY7b
         6KqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUOyqzpyeQeAwVVk56+XyGFkEB+170u1ip7nOeFdzBY17E7zdyo
	6vpd9xOWAS6ajVb23JMMec8=
X-Google-Smtp-Source: APXvYqykDIJyUeLajxbQICQR8MmPifAhTbY+IHF2MnOPi0cObJWv8mjshIixtVA+mMDnkBeOiKDXbg==
X-Received: by 2002:a37:8245:: with SMTP id e66mr14841225qkd.355.1572248351263;
        Mon, 28 Oct 2019 00:39:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3c70:: with SMTP id u45ls5125845qte.16.gmail; Mon, 28
 Oct 2019 00:39:10 -0700 (PDT)
X-Received: by 2002:aed:3c24:: with SMTP id t33mr16316516qte.186.1572248350954;
        Mon, 28 Oct 2019 00:39:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572248350; cv=none;
        d=google.com; s=arc-20160816;
        b=gYPCB1ki1qOoo7OyO6ouTxUPAyHldd+lxIx8pwCUHDnR4WyS0pOzdUveYmbT60BQh8
         Seyq3biduyZ7DSiEHdz/vpKxNo/hFeZqtDY3IH0qICPD4IcEnmh7UwqvVSAcRoPF8rSz
         eici+pmI0idVD1M72AhFVxkk6MuBua4ew6UrVb5PIXrWZp2LVk5aQw9OUnB4C3LYqwg/
         fYxL3jLl/hmOPYsfqIN6a6wCZz6Na97M62Z8muBI7yvRKPkJdUVIWs3fYWNf5xxxlDVr
         wJkov4mrTdGBtE2ceF+wUypIDY5tjzAWdcgnHvd4tp+bjmdW67lyIy5EXTq6c4X58iqC
         wb/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=W6KtXbeNB73L7K8HlIwOcgcuJ+P24gHi6K3WdunG+G4=;
        b=0tmlWEtQiu5iVssyBiDUXhwCzTdXqDNXXYuNf9tSCVKvO520PMGv9yg3JhwlLIOpcW
         xshepFrXuMkwHwWyaaa2w0tccwANRrfibUoCzt2XpDtV0yra73kNfw3qiUmcI2vbxAvz
         fkdLh+hbkheDjfrrYeBQF5wSV3x2fFjkORgcEbX9/hl9UONonOQZtmZzCavgtTpmwRpJ
         2weR8BtOkDufdBbncMTjapp5Ax1QsKzy/c1LkLFHmedLVuq+5jJlsp79a0YHlUL/B0Y2
         ZvCfZv4G7b+xaEWe7Jp2yon8VUB+U5YCAgDNzzMydRATM2f6IkJGlHGtjAPxu9lVFivW
         YMNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=A72Ecndl;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id y41si462917qtb.5.2019.10.28.00.39.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Oct 2019 00:39:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id c8so6340692pgb.2
        for <kasan-dev@googlegroups.com>; Mon, 28 Oct 2019 00:39:10 -0700 (PDT)
X-Received: by 2002:a62:e312:: with SMTP id g18mr535124pfh.250.1572248349944;
        Mon, 28 Oct 2019 00:39:09 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id 184sm10426925pfu.58.2019.10.28.00.39.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Oct 2019 00:39:09 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com, christophe.leroy@c-s.fr, linuxppc-dev@lists.ozlabs.org, gor@linux.ibm.com
Subject: Re: [PATCH v8 1/5] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <95c87ba1-9c15-43fb-dba7-f3ecd01be8e0@virtuozzo.com>
References: <20191001065834.8880-1-dja@axtens.net> <20191001065834.8880-2-dja@axtens.net> <352cb4fa-2e57-7e3b-23af-898e113bbe22@virtuozzo.com> <87ftjvtoo7.fsf@dja-thinkpad.axtens.net> <8f573b40-3a5a-ed36-dffb-4a54faf3c4e1@virtuozzo.com> <20191016132233.GA46264@lakrids.cambridge.arm.com> <95c87ba1-9c15-43fb-dba7-f3ecd01be8e0@virtuozzo.com>
Date: Mon, 28 Oct 2019 18:39:04 +1100
Message-ID: <87blu18gkn.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=A72Ecndl;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::541 as
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

> Or let me put it this way. Let's assume that CPU0 accesses shadow and CPU1 did the memset() and installed pte.
> CPU0 may not observe memset() only if it dereferences completely random vmalloc addresses
> or it performs out-of-bounds access which crosses KASAN_SHADOW_SCALE*PAGE_SIZE boundary, i.e. access to shadow crosses page boundary.
> In both cases it will be hard to avoid crashes. OOB crossing the page boundary in vmalloc pretty much guarantees crash because of guard page,
> and derefencing random address isn't going to last for long.
>
> If CPU0 obtained pointer via vmalloc() call and it's doing out-of-bounds (within boundaries of the page) or use-after-free,
> than the spin_[un]lock(&init_mm.page_table_lock) should allow CPU0 to see the memset done by CPU1 without any additional barrier.


I have puzzled through the barrier stuff. Here's what I
have. Apologies for the length, and for any mistakes - I'm pretty new
to deep kernel memory model stuff!

One thing that I don't think we've considered so far is _un_poisioning:


|	ret = apply_to_page_range(&init_mm, shadow_start,
|				  shadow_end - shadow_start,
|				  kasan_populate_vmalloc_pte, NULL);
|	if (ret)
|		return ret;
|
|	kasan_unpoison_shadow(area->addr, requested_size);

That unpoisioning is going to write to the shadow via its virtual
address, loading translations into the TLB. So we cannot assume that
another CPU is doing the page table walk and loading the TLB entry for
the first time. We need to make sure that correctness does not depend
on that.

We have 2x2 cases to consider:

{Access via fixed address, access via unknown address}
x
{Access within object - unpoisioned, access just beyond object but
within shadow - poisoned}

I think we can first drop all consideration of access via fixed
addresses. Such accesses will have to be synchronised via some
external mechanism, such as a flag, with appropriate
locking/barriers. Those barriers will order the rest of the memory
accesses within vmalloc(), and I considered speculative faults in my
other email.

That leaves just memory accesses via an unknown address. I'm imagining
the following two cases:

[Access of Unpoisoned Shadow - valid access]

CPU#0                                   CPU#1
-----                                   -----
WRITE_ONCE(p, vmalloc(100))             while (!(x = READ_ONCE(p))) ;
                                        x[99] = 1;

[Access of Poisoned Shadow - invalid read past the end]

CPU#0                                   CPU#1
-----                                   -----
WRITE_ONCE(p, vmalloc(100))             while (!(x = READ_ONCE(p))) ;
                                        x[100] = 1;


---------- Access to the unpoisioned region of shadow ----------

Expanding the CPU#0 side, let `a` be area->addr:

// kasan_populate_vmalloc_pte
...
STORE page+PAGE_SIZE-1, poison
// Mark's proposed smp_wmb() goes here
ACQUIRE page_table_lock
STORE ptep, pte
RELEASE page_table_lock
// return to kasan_populate_vmalloc
// call kasan_unpoison_shadow(a, 100)
STORE shadow(a), unpoison
...
STORE shadow(a+99), unpoison
// rest of vmalloc()
STORE p, a


CPU#1 looks like (removing the loop bit):

x = LOAD p
<data dependency>
shadow_x = LOAD *shadow(x+99)
// if shadow_x poisoned, report
STORE (x+99), 1

Putting the last few operations side-by-side:

CPU#0                                    CPU#1
 STORE shadow(a+99), unpoision           x = LOAD p
                                         <data dependency>
 STORE p, a                              shadow_x = LOAD shadow(x+99)


While there is a data dependency between x and shadow_x, there's no
barrier in kasan_populate_vmalloc() that forces the _un_poisoning to
be correctly ordered.

My worry would be that CPU#0 might commit the store to p before it
commits the store to the shadow. Then, even with the data dependency,
CPU#1 could observe store to shadow(a+99) after it executed the load
of shadow(x+99). This would lead CPU#1 to observe a false-positive
poison.

We need a write barrier, and Mark's proposed smp_wmb() is too early to
help here.

Now, there is an smp_wmb() in clear_vm_uninitialized_flag(), which is
called by __vmalloc_node_range between kasan_populate_vmalloc and the
end of the function. That makes things look like this:

  CPU#0                                   CPU#1
STORE shadow(a+99), unpoision           x = LOAD p
smp_wmb()                               <data dependency>
STORE p, a                              shadow_x = LOAD shadow(x+99)

memory-barriers.txt says that a data dependency and a write barrier
are sufficient to order this correctly.

Outside of __vmalloc_node_range(), the other times we call
kasan_populate_vmalloc() are:

 - get_vm_area() and friends. get_vm_area does not mapping any pages
   into the area returned. So the caller will have to do that, which
   will require taking the page table lock. A release should pair with
   a data dependency, making the unpoisoning visible.

 - The per_cpu allocator: again the caller has to map pages into the
   area returned - pcpu_map_pages calls map_kernel_range_noflush.

So, where the address is not known in advance, the unpoisioning does
need a barrier. However, we do hit one anyway before we return. We
should document that we're relying on the barrier in
clear_vm_uninitialized_flag() or barriers from other callers.

---------- Access to the poisioned region of shadow ----------

Now, what about the case that we do an overread that's still in the
shadow page?

CPU#0                                    CPU#1
 STORE page+100, poison
 ...
 # Mark's proposed smp_wmb()
 ACQUIRE page_table_lock
 STORE ptep, pte
 RELEASE page_table_lock
 ...
 STORE shadow(a+99), unpoision           x = LOAD p
 smp_wmb()                               <data dependency>
 STORE p, a                              shadow_x = LOAD shadow(x+100)


Here, because of both the release and the smp_wmb(), the store of the
poison will be safe. Because we're not expecting anything funky with
fixed addresses or other CPUs doing page-table walks, I still think we
don't need an extra barrier where Mark has proposed.

-------------------- Conclusion --------------------

I will send a v10 that:

 - drops the smp_wmb() for poisoning
 
 - adds a comment that explains that we're dependent on later barriers
   for _un_poisioning

I'd really like to get this into the coming merge window, if at all
possible.

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87blu18gkn.fsf%40dja-thinkpad.axtens.net.
