Return-Path: <kasan-dev+bncBAABBKOXXW4AMGQEOU23PII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7C6D39A0297
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 09:30:50 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6c5984bc3fdsf78648346d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 00:30:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729063849; cv=pass;
        d=google.com; s=arc-20240605;
        b=VROhBFjOgSl7xZKqISI1mhjjrB+vo1iBqMwyd/zoS2pkYz4Li87DVZu1cIClnRpvol
         02P+hNI6REntutmunETMsPpVrAW/7sBUIoHMYVaUXLJjI9gUVhUCiYpA6/yX0sHndK0f
         r/W8T+hyBYRfUfJ2WlK7KZgmAO8fEZu4oc85y87PMMaE3HlMOWWe2Qmh46LJ9P3znGX4
         nSFseZIP+zafDlMbyhXRVZW4hzQS+mEnOoZd5lWBV48qZ414VX+hFvddYAWF7BIR2YsE
         1BqYI4JyoDDVUypGMBfLvOLqkG+Gllms9vXEW6NZzFo7tUP+SCevWIWg0qyaUnGsw/XI
         LFcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kwCsaKdGVwL4CiTEoLqjIwStK8QKe68tgsUBICuHaIA=;
        fh=Ngsc1SQa24N3/B2EEwtdaaGr8x6VD0AgDdWo5XVwabs=;
        b=dGJoD+giL+Ecj9/ySTqwq5cn/JPMM/3YfEkwnaMriCRlSsa9/gZTPWqxCUXQutPLma
         ZqygGUrLyl64xDci0L79YxcEKNycCf3orr7zKLum0M459+Vxv/0m9J+Ar6iR0Sa7gwlV
         eAkgiHZsaslqiqaPEISR1s5Mgo60o+A1RsBz1qab63YBEldcNS6TOVl2KyA0ZnO+KgI+
         kOg5L6LveP6X43XZvVhvkc0MJ4mNnQZoiI0K7pLr+WsfcoyWV000K279Rz2rMdxCxvlV
         OyDAMmu8J0SSm0wOmg6UhyuMeHIntO9x0cSJlXrf71JF43jYUI8mstfx3TnXbQXUFws+
         dIAQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CwGflVpJ;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729063849; x=1729668649; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kwCsaKdGVwL4CiTEoLqjIwStK8QKe68tgsUBICuHaIA=;
        b=ZLl0Zj+50VGSPa1bQ6PnMZKnlh+NmeBLQv/Ou3rBppv/K1KLIRdcFKtuKonMEE1UcY
         GjI+R3u8e49z5x3xlLdi91cF1rsCW2MEcfhFbFXaLyXvKMZSa3yoABMqTNIALXkNVK+J
         nXjpAdAi1ekkgP3Q/1HmFug/w+R14zyB6jraRv1u7y6SYUnU4Xe5hVdFDQjUssh7nxba
         7tJaUSreGb6kowQQ/wyPmixlpTprvJDRRP4rQnfD0M4AhEESVlupG1VHEmXkqNc89TUQ
         tpryJzpA/2D9UxkHzFDbZq6p8i6/t1f8lkBVm3290rAEfAVfJJDgqh9i2jzHsgAOlHvh
         RRdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729063849; x=1729668649;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kwCsaKdGVwL4CiTEoLqjIwStK8QKe68tgsUBICuHaIA=;
        b=fPPEAEMoKuvkQDbYU8EJMKveaDoKk5rGbIy1qApXJwEpOlvZ0PShLQtn8L2ZmK6hHH
         9iDJYf66UxWlvLRftG3go/t5KuoPCSe4Al0uoxc/TeTPzPFJo0m5+E5ndtkFX/TZdmR5
         Rl6F/gnjjGA0To+Vh1MVgUfytFMSP1vFF4xTI8UUF5XIB/Ln+leNUWqG5kIfB9faYL4n
         qD+euPQuRiE31l0ZAtPDmLltMqtucQ1dZyvILvMbF3Ax+oweJlVutdPCOPHbeq0ZJibb
         q307TDBjrquiuYLC9TG8puhuAs0IoZUV4QWq0j3reLlDthIu/qF6IoHg6F46kzY9l3eq
         wLrw==
X-Forwarded-Encrypted: i=2; AJvYcCURPHXifRs/RnzpSy7IWQ6PvPLYsU7RzUIgS0xdbrX/fCeUygCvLI2Q529Lacl0YLg02obEGA==@lfdr.de
X-Gm-Message-State: AOJu0Yx3A7q60Vr4ZV6ML7lp09H/YPulfNL60Kpl+FfnX6dh6TTYIC7i
	yIeV1l+n80RRLW8MUaq0OiaIBKkmnWmVGOcJHW1C+aOKtQ6SLNwQ
X-Google-Smtp-Source: AGHT+IEP7zhlxcYIa3hrRVk05aQfE+Lqf7fES4N9ubRIa5u7EAnI90CV1hQ3kRE0mSkzjgnZQ8bM7w==
X-Received: by 2002:a05:6214:4303:b0:6cc:3a:a7f0 with SMTP id 6a1803df08f44-6cc2b91e86bmr37168896d6.44.1729063849141;
        Wed, 16 Oct 2024 00:30:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:21e4:b0:6b0:8881:bc19 with SMTP id
 6a1803df08f44-6cbe565a704ls13271956d6.1.-pod-prod-08-us; Wed, 16 Oct 2024
 00:30:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbsJLqIBvNg+q8qF6n7UQr9VaZzdYCP6x9DNgP/V3B4A+epx+JM0cv75vkTO4qKTQCSD334gCJol0=@googlegroups.com
X-Received: by 2002:a05:6122:4592:b0:4fc:e3c2:2c71 with SMTP id 71dfb90a1353d-50d8d2122f9mr2196231e0c.2.1729063848436;
        Wed, 16 Oct 2024 00:30:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729063848; cv=none;
        d=google.com; s=arc-20240605;
        b=dg4YMqtnjpecO+asTQBuxxVwoqtK9jzFpbatDN+55ud2Nfdn4K5RDeSdFR68Xigb5E
         PfEOjLvUJrLGDpq0BNKkbdCe9ehnPDHCasf4jn8Eaj5CuBYSP7JMVnap5kVLK7PAki/P
         wGWZ0RjvEP2250aH7rU4SvyPBq9MahFXgFzlIJDJi1kLsWvh57TxctBcO9MBwCfZMB6r
         lkLwPuUBbd9uip5X4CZjy4PXCNQmEdxPd0NQj5WlwXUJ3gLrxEH2sc2dHOByiwNmSVfK
         nrHhDH90NJ1uKDTkeOrleGn6jBh+bkgI5RtdoLmwdXMAtYpiZf8/bKk+QbGZ0pb64reA
         8hSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LgdzTsWg99eVncVlxKZZP2cIXfC3Obm6mBBGKa9DLas=;
        fh=Z1YP8Vkk6dKstNk0Gf8hghlnFuJl7CXH4dSk+IpQ83k=;
        b=DejBHi21QIh5gAkRvlFZ5HOQmn5mwd+6ApDxwzggoYAbrAo1Nmjsm+2200xswe5Nqf
         k3n67Y+lyO+wFOZU0ObIvQUkQNghuCYQqLgJM5lWvnA0eJe5fbor99vAoROyj+Mr8yI8
         LbNFUoFD7P2HhkqnXNDUPCemLrh6Urd1erRqQ0XqjrDh/R/Z16jNyvYt/GSp5Tk6eiY1
         FqnYGyd9cLl7ylZZ+UppsYv8kgsbRJhRfrlqg/HQDgGynyxTzRZMmBmpF+3PiSDNv+8+
         PiD8oiyOvJTt0bnFFJaOJ5YOmAU1bBKNsrH3DHH+PHLyfIsM+VDEhW6fE4sHThFgr56N
         dadw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CwGflVpJ;
       spf=pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=chenhuacai@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-50d7b2f4a0csi139579e0c.4.2024.10.16.00.30.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2024 00:30:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 88D415C51B5
	for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 07:30:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9BF01C4CED5
	for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 07:30:47 +0000 (UTC)
Received: by mail-ed1-f44.google.com with SMTP id 4fb4d7f45d1cf-5c9454f3bfaso6813992a12.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2024 00:30:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWxfjeXU73iFEyO/Fm63gXG9CbwebIbOBluEBqYUbGvWU7z0LpeIw5cn4MQmSniGXOmwC8/i57UJ8A=@googlegroups.com
X-Received: by 2002:a17:907:848:b0:a99:3318:e7c3 with SMTP id
 a640c23a62f3a-a99e3e4c294mr1543126666b.43.1729063846118; Wed, 16 Oct 2024
 00:30:46 -0700 (PDT)
MIME-Version: 1.0
References: <20241014035855.1119220-1-maobibo@loongson.cn> <20241014035855.1119220-3-maobibo@loongson.cn>
 <CAAhV-H6nkiw_eOS3jFdojJsCJOA2yiprQmaT5c=SnPhJTOyKkQ@mail.gmail.com>
 <e7c06bf4-897a-7060-61f9-97435d2af16e@loongson.cn> <CAAhV-H6H=Q=1KN5q8kR3j55Ky--FRNifCT93axhqE=vNMArDaQ@mail.gmail.com>
 <1b4070c9-921e-65e3-c2a7-dab486d4f17f@loongson.cn>
In-Reply-To: <1b4070c9-921e-65e3-c2a7-dab486d4f17f@loongson.cn>
From: "'Huacai Chen' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Oct 2024 15:30:34 +0800
X-Gmail-Original-Message-ID: <CAAhV-H5fx14iUM_5e36sO-kd8VWpFLG_Qmi5JUHKiPRqrPQsoA@mail.gmail.com>
Message-ID: <CAAhV-H5fx14iUM_5e36sO-kd8VWpFLG_Qmi5JUHKiPRqrPQsoA@mail.gmail.com>
Subject: Re: [PATCH v2 2/3] LoongArch: Add barrier between set_pte and memory access
To: maobibo <maobibo@loongson.cn>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@redhat.com>, Barry Song <baohua@kernel.org>, loongarch@lists.linux.dev, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chenhuacai@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CwGflVpJ;       spf=pass
 (google.com: domain of chenhuacai@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=chenhuacai@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Huacai Chen <chenhuacai@kernel.org>
Reply-To: Huacai Chen <chenhuacai@kernel.org>
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

On Wed, Oct 16, 2024 at 2:09=E2=80=AFPM maobibo <maobibo@loongson.cn> wrote=
:
>
>
>
> On 2024/10/15 =E4=B8=8B=E5=8D=888:27, Huacai Chen wrote:
> > On Tue, Oct 15, 2024 at 10:54=E2=80=AFAM maobibo <maobibo@loongson.cn> =
wrote:
> >>
> >>
> >>
> >> On 2024/10/14 =E4=B8=8B=E5=8D=882:31, Huacai Chen wrote:
> >>> Hi, Bibo,
> >>>
> >>> On Mon, Oct 14, 2024 at 11:59=E2=80=AFAM Bibo Mao <maobibo@loongson.c=
n> wrote:
> >>>>
> >>>> It is possible to return a spurious fault if memory is accessed
> >>>> right after the pte is set. For user address space, pte is set
> >>>> in kernel space and memory is accessed in user space, there is
> >>>> long time for synchronization, no barrier needed. However for
> >>>> kernel address space, it is possible that memory is accessed
> >>>> right after the pte is set.
> >>>>
> >>>> Here flush_cache_vmap/flush_cache_vmap_early is used for
> >>>> synchronization.
> >>>>
> >>>> Signed-off-by: Bibo Mao <maobibo@loongson.cn>
> >>>> ---
> >>>>    arch/loongarch/include/asm/cacheflush.h | 14 +++++++++++++-
> >>>>    1 file changed, 13 insertions(+), 1 deletion(-)
> >>>>
> >>>> diff --git a/arch/loongarch/include/asm/cacheflush.h b/arch/loongarc=
h/include/asm/cacheflush.h
> >>>> index f8754d08a31a..53be231319ef 100644
> >>>> --- a/arch/loongarch/include/asm/cacheflush.h
> >>>> +++ b/arch/loongarch/include/asm/cacheflush.h
> >>>> @@ -42,12 +42,24 @@ void local_flush_icache_range(unsigned long star=
t, unsigned long end);
> >>>>    #define flush_cache_dup_mm(mm)                         do { } whi=
le (0)
> >>>>    #define flush_cache_range(vma, start, end)             do { } whi=
le (0)
> >>>>    #define flush_cache_page(vma, vmaddr, pfn)             do { } whi=
le (0)
> >>>> -#define flush_cache_vmap(start, end)                   do { } while=
 (0)
> >>>>    #define flush_cache_vunmap(start, end)                 do { } whi=
le (0)
> >>>>    #define flush_icache_user_page(vma, page, addr, len)   do { } whi=
le (0)
> >>>>    #define flush_dcache_mmap_lock(mapping)                        do=
 { } while (0)
> >>>>    #define flush_dcache_mmap_unlock(mapping)              do { } whi=
le (0)
> >>>>
> >>>> +/*
> >>>> + * It is possible for a kernel virtual mapping access to return a s=
purious
> >>>> + * fault if it's accessed right after the pte is set. The page faul=
t handler
> >>>> + * does not expect this type of fault. flush_cache_vmap is not exac=
tly the
> >>>> + * right place to put this, but it seems to work well enough.
> >>>> + */
> >>>> +static inline void flush_cache_vmap(unsigned long start, unsigned l=
ong end)
> >>>> +{
> >>>> +       smp_mb();
> >>>> +}
> >>>> +#define flush_cache_vmap flush_cache_vmap
> >>>> +#define flush_cache_vmap_early flush_cache_vmap
> >>>   From the history of flush_cache_vmap_early(), It seems only archs w=
ith
> >>> "virtual cache" (VIVT or VIPT) need this API, so LoongArch can be a
> >>> no-op here.
> > OK,  flush_cache_vmap_early() also needs smp_mb().
> >
> >>
> >> Here is usage about flush_cache_vmap_early in file linux/mm/percpu.c,
> >> map the page and access it immediately. Do you think it should be noop
> >> on LoongArch.
> >>
> >> rc =3D __pcpu_map_pages(unit_addr, &pages[unit * unit_pages],
> >>                                        unit_pages);
> >> if (rc < 0)
> >>       panic("failed to map percpu area, err=3D%d\n", rc);
> >>       flush_cache_vmap_early(unit_addr, unit_addr + ai->unit_size);
> >>       /* copy static data */
> >>       memcpy((void *)unit_addr, __per_cpu_load, ai->static_size);
> >> }
> >>
> >>
> >>>
> >>> And I still think flush_cache_vunmap() should be a smp_mb(). A
> >>> smp_mb() in flush_cache_vmap() prevents subsequent accesses be
> >>> reordered before pte_set(), and a smp_mb() in flush_cache_vunmap()
> >> smp_mb() in flush_cache_vmap() does not prevent reorder. It is to flus=
h
> >> pipeline and let page table walker HW sync with data cache.
> >>
> >> For the following example.
> >>     rb =3D vmap(pages, nr_meta_pages + 2 * nr_data_pages,
> >>                     VM_MAP | VM_USERMAP, PAGE_KERNEL);
> >>     if (rb) {
> >> <<<<<<<<<<< * the sentence if (rb) can prevent reorder. Otherwise with
> >> any API kmalloc/vmap/vmalloc and subsequent memory access, there will =
be
> >> reorder issu. *
> >>         kmemleak_not_leak(pages);
> >>         rb->pages =3D pages;
> >>         rb->nr_pages =3D nr_pages;
> >>         return rb;
> >>     }
> >>
> >>> prevents preceding accesses be reordered after pte_clear(). This
> >> Can you give an example about such usage about flush_cache_vunmap()? a=
nd
> >> we can continue to talk about it, else it is just guessing.
> > Since we cannot reach a consensus, and the flush_cache_* API look very
> > strange for this purpose (Yes, I know PowerPC does it like this, but
> > ARM64 doesn't). I prefer to still use the ARM64 method which means add
> > a dbar in set_pte(). Of course the performance will be a little worse,
> > but still better than the old version, and it is more robust.
> >
> > I know you are very busy, so if you have no time you don't need to
> > send V3, I can just do a small modification on the 3rd patch.
> No, I will send V3 by myself. And I will drop the this patch in this
> patchset since by actual test vmalloc_test works well even without this
> patch on 3C5000 Dual-way, also weak function kernel_pte_init will be
> replaced with inline function rebased on
>
> https://git.kernel.org/pub/scm/linux/kernel/git/akpm/25-new.git/tree/patc=
hes/mm-define-general-function-pxd_init.patch
This patch is in Andrew's mm-unstable branch. As far I know,
mm-unstable is for next (6.13) and mm-stable is for current (6.12).

But this series is bugfix, so it is for current (6.12).

>
> I dislike the copy-paste method without further understanding :(,
> although I also copy and paste code, but as least I try best to
> understand it.

I dislike too. But in order to make this series be in 6.12, it is
better to keep copy-paste, and then update the refactoring patch to V2
for Andrew (rebase and drop is normal for mm-unstable).


Huacai

>
> Regards
> Bibo Mao
> >
> >
> > Huacai
> >
> >>
> >> Regards
> >> Bibo Mao
> >>> potential problem may not be seen from experiment, but it is needed i=
n
> >>> theory.
> >>>
> >>> Huacai
> >>>
> >>>> +
> >>>>    #define cache_op(op, addr)                                       =
      \
> >>>>           __asm__ __volatile__(                                     =
      \
> >>>>           "       cacop   %0, %1                                  \n=
"     \
> >>>> --
> >>>> 2.39.3
> >>>>
> >>>>
> >>
> >>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAAhV-H5fx14iUM_5e36sO-kd8VWpFLG_Qmi5JUHKiPRqrPQsoA%40mail.gmail.=
com.
