Return-Path: <kasan-dev+bncBDDL3KWR4EBRBPFTSCEAMGQETUVJ3GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 53BA23DBC32
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 17:24:46 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id k1-20020a17090a39c1b0290176898bbb9csf10104498pjf.8
        for <lists+kasan-dev@lfdr.de>; Fri, 30 Jul 2021 08:24:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1627658685; cv=pass;
        d=google.com; s=arc-20160816;
        b=QOfWuRGjbCVIiHaWS8K1UV2Tr4QWC57ACQw06OyqHW9qKSD4Uf3nnnovzIzSo7atNy
         4Q+EHQGpOmlV9W9khyNOKy8eQ88fbeNhkfl1lWbF9wOr0JyebiMp/0UWFF6CghdIC3M7
         r0byiTi5hJYXR59ok55uVmGBkDWJPfnk/H+2zVCLvz2GINyW/3MlJq2JDH+ar/CWowDo
         F94MNbMoABBa3HedfBLtBtNvREu0wBEGKjgZtLp5EFBER2K9O0fMvIM70d3Nx03fu0b7
         8SB7vSgBNzAXcDDcFxbj1NsYsaGYCuE3p4KPdJ8Ny4II58QzNu4EzdD18ig+K3D2efTC
         yl6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=3RqgUayz5ay4w4WoANeXdHfGbkUP/6L6KMwJB2YW+fk=;
        b=UBTPmlZeZmsIzIN5/kLA5bpA9i60iVVLwIWRK1VV7XUvG/oMchKC5Qy9aenwsxpPOM
         bk7prG5n8RDdG/Bpbn9u0aFjwE0BviaQJGwd8axNbnLr6Xk+DqB3Av0neyQxshPgxENr
         Yb0n1vFxQ7o6t//YxrhVbPth40rvG0KhWINYQQamJ8JYBYegBpPuuegKrK/z6cMwaFop
         yTbutKnqfVypE7FCreoLAlvpSqj4kUo71EDL08EWmkExptyddB2/JYkykGbxh/6gmNi0
         G+imHm+XEc/YVMpm56xEeVrV4cmJtB+gUaWCTqaf2oYuKxhKUbJPVJstQITE/nnMu4Nh
         nVRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3RqgUayz5ay4w4WoANeXdHfGbkUP/6L6KMwJB2YW+fk=;
        b=o4IET5HLtNvLp6zX7gIJsfoFjCUk3VziZXA0kLSYkZRduGUkh2oW0rEXwcBwg7vl7G
         JmwxOfPsDVquTdiDC3GFYegFII0FORnFp/YZFKpampShBLbgViKu+QGk/5RA4nlJms25
         jyTK85QCvXTKto0xf52MypP/B3d8MdzDH4Lzwb8D/ylLZJb0i/1CGhvWzRCihI1B8cB6
         yZO8z1MGvXLe3YMZxkyFLr1UpgKTXjKP8qRmUfLxEfnaJsqAHdd+wtxUwzZ65/lzF03W
         phyyH4uZ9FGhLKbMxQesQIhMGUb6k77UwO6I32ow9mHe+fstIHjYQmBRIjj/LwsfPG4k
         0ohw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3RqgUayz5ay4w4WoANeXdHfGbkUP/6L6KMwJB2YW+fk=;
        b=Z2b8lBw86rBez98hQRIsayCgr8nmsl3OEuMHuO2cXi3oK7zV+Lq5SvLJ+bvBJW/mDL
         YOz+7rXz1B4kWq59q4pgAKs4ucqAIYW/1nMDuY40IfLdPngOma1AOROiaE2UiMQQwGXp
         m0FgjoPJczXMQlNwztTIVad6uAG09ym0I8MskcaRuU8Fq0eSj6kHMJqC3SHSdlmQZ5ru
         hI07VDZsxE0eeHVFqEsst1vWBKmbzCWwPiQz4rDJ1mUP0VdXc3gWTn/su/ULrlzJy1f1
         NOykOC/uCfXAcLMS5n+6UfyYi2jgmVygYRflXzsbqqHZBqK++qcr/r4LKKnuP+5eyfWC
         KOUg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530cZydsA141s5hiseoCuemH9PwTMqG3fuB9Mt2vDC2AbUs2zGaR
	jPEJm2PJ9YSt+OrcL3w4dGk=
X-Google-Smtp-Source: ABdhPJxTTm98wg7XAH6hsZnR3pkd/dZYlBw7unriVEer9+uuqDnxJnd52uCL/F2uxFtuaBZiNHSVHg==
X-Received: by 2002:a17:90a:ba8e:: with SMTP id t14mr3652152pjr.176.1627658685029;
        Fri, 30 Jul 2021 08:24:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bb8f:: with SMTP id m15ls1154385pls.3.gmail; Fri, 30
 Jul 2021 08:24:44 -0700 (PDT)
X-Received: by 2002:a17:90a:5141:: with SMTP id k1mr3499453pjm.185.1627658684426;
        Fri, 30 Jul 2021 08:24:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1627658684; cv=none;
        d=google.com; s=arc-20160816;
        b=e/Xig/lstu3ujh40aBzH+nii4byFF0jWc2aH2r8JdmVBMq9fGiEVwHe0320L+h0dCU
         TxjEM1qWgFGWIcv9bWCsZsmNkxKGJ1/bLQwps/JIeBy3sLbRStND1jZfr3GGcmJpR8qt
         jMfZAN0I1BeSbPSOseUNjURPkeGTBka3CL0SCWHN9kpYegt8tMjnMzDfK/c9qz8e5dqH
         rDB4AB7RE4NaZpmymH9XpQEyjTYTAItYPAUfNB4G9R3SeABJ4cy/nQbepNAgGgyAWQ2j
         tFTLTwHo9kNdzizu5+at+Pfn+NHmKWgQ5UIpoAR3XBFfbhOVtlBhbsO8BUdvvNR/+HuE
         EefQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=13avQRiQubdP72K/fSFTr5Bfht9EwiRMW9GGBl3Hg/Q=;
        b=mcJ0/EeIQ6sPJAFvm5q9MrpsM9+lZfTaLauX4zd9il5PIM8GgM5CEldsZA3wz8qQ0b
         LyLnqoAvHNjm0NQfB9EyQg02+lOVGd6KN6o+UoxzlNhP0GIGQh8UEg+brZ+qlQGaeDWV
         TcwBlwq/xAwjMRVpIHLyugyVDMyngo+2DYzKP/6EdwJ6xcPtbyJ7hEH/+uoDQA/TUA71
         YTnme/8nA8VFM8hIVDwwbnP/IUuEmuaFFadRw8K6ftC7P8d7hiWqehkyhDmgxc99e7vk
         EAda4wwzKcn6ZgpV+wkrPeUU52fuWBYoM9zoEu34TXYSv9jDfq+JJum9rb3g+F/sov19
         10Fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p1si101190plo.3.2021.07.30.08.24.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 30 Jul 2021 08:24:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id F2A2260F46;
	Fri, 30 Jul 2021 15:24:41 +0000 (UTC)
Date: Fri, 30 Jul 2021 16:24:39 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>,
	Marco Elver <elver@google.com>,
	Nicholas Tang <nicholas.tang@mediatek.com>,
	Andrew Yang <andrew.yang@mediatek.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Chinwen Chang <chinwen.chang@mediatek.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	"moderated list:ARM/Mediatek SoC support" <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH 1/2] kasan, mm: reset tag when access metadata
Message-ID: <20210730152438.GA2690@arm.com>
References: <20210727040021.21371-1-Kuan-Ying.Lee@mediatek.com>
 <20210727040021.21371-2-Kuan-Ying.Lee@mediatek.com>
 <CANpmjNM03Pag9OvBBVnWnSBePRxsT+BvZtBwrh_61Qzmvp+dvA@mail.gmail.com>
 <b6b96caf30e62996fa3b75ae8d146c9cc0dcbbf6.camel@mediatek.com>
 <20210727192217.GV13920@arm.com>
 <CA+fCnZdprormHJHHuEMC07+OnHdC9MLb9PLpBnE1P9TvrVisfw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdprormHJHHuEMC07+OnHdC9MLb9PLpBnE1P9TvrVisfw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Jul 30, 2021 at 04:57:20PM +0200, Andrey Konovalov wrote:
> On Tue, Jul 27, 2021 at 9:22 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> >
> > On Tue, Jul 27, 2021 at 04:32:02PM +0800, Kuan-Ying Lee wrote:
> > > On Tue, 2021-07-27 at 09:10 +0200, Marco Elver wrote:
> > > > +Cc Catalin
> > > >
> > > > On Tue, 27 Jul 2021 at 06:00, Kuan-Ying Lee <
> > > > Kuan-Ying.Lee@mediatek.com> wrote:
> > > > >
> > > > > Hardware tag-based KASAN doesn't use compiler instrumentation, we
> > > > > can not use kasan_disable_current() to ignore tag check.
> > > > >
> > > > > Thus, we need to reset tags when accessing metadata.
> > > > >
> > > > > Signed-off-by: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
> > > >
> > > > This looks reasonable, but the patch title is not saying this is
> > > > kmemleak, nor does the description say what the problem is. What
> > > > problem did you encounter? Was it a false positive?
> > >
> > > kmemleak would scan kernel memory to check memory leak.
> > > When it scans on the invalid slab and dereference, the issue
> > > will occur like below.
> > >
> > > So I think we should reset the tag before scanning.
> > >
> > > # echo scan > /sys/kernel/debug/kmemleak
> > > [  151.905804]
> > > ==================================================================
> > > [  151.907120] BUG: KASAN: out-of-bounds in scan_block+0x58/0x170
> > > [  151.908773] Read at addr f7ff0000c0074eb0 by task kmemleak/138
> > > [  151.909656] Pointer tag: [f7], memory tag: [fe]
> >
> > It would be interesting to find out why the tag doesn't match. Kmemleak
> > should in principle only scan valid objects that have been allocated and
> > the pointer can be safely dereferenced. 0xfe is KASAN_TAG_INVALID, so it
> > either goes past the size of the object (into the red zone) or it still
> > accesses the object after it was marked as freed but before being
> > released from kmemleak.
> >
> > With slab, looking at __cache_free(), it calls kasan_slab_free() before
> > ___cache_free() -> kmemleak_free_recursive(), so the second scenario is
> > possible. With slub, however, slab_free_hook() first releases the object
> > from kmemleak before poisoning it. Based on the stack dump, you are
> > using slub, so it may be that kmemleak goes into the object red zones.
> >
> > I'd like this clarified before blindly resetting the tag.
> 
> AFAIK, kmemleak scans the whole object including the leftover redzone
> for kmalloc-allocated objects.
> 
> Looking at the report, there are 11 0xf7 granules, which amounts to
> 176 bytes, and the object is allocated from the kmalloc-256 cache. So
> when kmemleak accesses the last 256-176 bytes, it causes faults, as
> those are marked with KASAN_KMALLOC_REDZONE == KASAN_TAG_INVALID ==
> 0xfe.
> 
> Generally, resetting tags in kasan_disable/enable_current() section
> should be fine to suppress MTE faults, provided those sections had
> been added correctly in the first place.

Thanks for the explanation, the patch makes sense. FWIW:

Acked-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210730152438.GA2690%40arm.com.
