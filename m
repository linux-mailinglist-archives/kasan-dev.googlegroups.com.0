Return-Path: <kasan-dev+bncBDX4HWEMTEBRBWMDXSAQMGQEWZWQL7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3b.google.com (mail-vk1-xa3b.google.com [IPv6:2607:f8b0:4864:20::a3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 38BC431F33E
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Feb 2021 01:10:03 +0100 (CET)
Received: by mail-vk1-xa3b.google.com with SMTP id n196sf436054vkn.23
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Feb 2021 16:10:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613693402; cv=pass;
        d=google.com; s=arc-20160816;
        b=SEiXk8Qjvh7RIoCrfa8Bob4iDbs8GMmWqiRpm1sYhJBjNUWEAhMAov/N4QEwxO/whg
         TKBmK37hqeItDfbbXrhpdM4shvnc+c4Xq/ejQcyXKt4BkK16MrjhL53y/sQj2PAyfvnn
         v4wVbeHduDQoVqyHgJZV6bEtRP6/BvTJZNI0mZJIK+hv7oByKSZriKSq2nef39uvRmxx
         /ZXIiZ8xq5gXmATS5F1b0gCxEpYBxDUBdBJFWaUrWVkjjCpQU+CDTjAvlxkSe4GQ1p2F
         A/s/B5DyO3FxT7XEbkpzxl8Uxx11OOisYhGVEDpbrNWaF0TyFeXf56wMWhDBtrNtndJ+
         aFEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nBnomzgUO+KjD1Hchbn4W4YaLS7AOry6GAbNEGfwzss=;
        b=Qwks30tirqKUe1s3bJTQpDcF0H5NoA6sSpfCSalfJ2bSfAEIYfssPVu0x3Cd3PFkyo
         c25rlYSgpOGxkgeCArIHiECLfwGneszG4rktxE8zbqK7ilXyy+gfqbvaHcPjG+p3aJO9
         956qr8SARY4CsL75wXElUMsA8COxsWLf6SknST3RuQWW/PzHFWKa5PFspJNXKlDDiIP4
         smQUwXkU2Seg335rIxVK5jqt4YitKlwGiyWWrjPbFmuL5AtUHMSNMPibFA60CDk5ATVw
         s8/Dcmtx0p+MGNcsiR1Kojx+MzX2hPkn3Cww/BCMaa7wZkG6d/kNo3musuOCl/+nrfat
         gIpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BC6tuzv2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nBnomzgUO+KjD1Hchbn4W4YaLS7AOry6GAbNEGfwzss=;
        b=F+1ejTSUfRV8BMtW/U8+oJuOuwZ0iq5pnEMRdyhoqio1ih6Z94qDRjBVrBcGvvoEWj
         5g8KRpfQYixQCu/NIS1r40RBSoPHrlTpwY0WU2XKoFnaCj7CdfEbMMLvrh4rk+b6ncC8
         w8TR4o4o4eEdNF+2iZPGf7eUXJ/c3RUtyUuAXGR7X++3Gt0mNF8+6G077SaqYJVAspr/
         weB2ipPo4hOaMOvL1Ml923/08EAyA77ZcJ5tkJUpUCsS9q888v+vr8uQLd4RXeT1Bwom
         lrP8ogkKFDrCml2W21v8yUbdfFjDn13EYvIAMMML/IzSp0rCMn+oUOTmbhbSBEQ7v5iw
         lDdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nBnomzgUO+KjD1Hchbn4W4YaLS7AOry6GAbNEGfwzss=;
        b=BXb59/T98iUCGfqB5dFkyU1xJBA49vl1LaLWOxVVUnpljIq4JHp6Dy7pDwFqRAQ+k9
         PQXPyCTJDRGwW3zwBl1Xet7Kw0hGa9vZxL+Nx2f+JxfB4PV2HM63oQSs1lJeUU/+p01f
         MqntaNiP8vYfw2fvlaB5tPGGKDAYSu2ID3otBfP/WJ1GWlC1rWn5oKtUVRip3FU7O7o4
         9KZDvy5g81K1qQ/kYRp9SxMXYNxj06sgxe/V0GdIgZczEIEpc4xXq8S+5uj2unYwRIkz
         PsvvqxBH4xcMQsmkrqa/VJKVl9X0iXIVl/1zLYhENLHGU/FyhwpMdG+RiKp/uP47bh5j
         rU3Q==
X-Gm-Message-State: AOAM533a/RibUwcKtMySPHZQZrO745tD0I6pZxUe02jWIetA5o6OP4qR
	GN9Mt2X7bRXoP5ADOh/Slyo=
X-Google-Smtp-Source: ABdhPJzpOe9i6S+s0z5uvs4cvrmW8TyosS2FXp0vkwmMohtj9b2sbiytVLYUcLc35weD/u4OeMNRvg==
X-Received: by 2002:a67:4341:: with SMTP id q62mr4813210vsa.17.1613693401965;
        Thu, 18 Feb 2021 16:10:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:8886:: with SMTP id k128ls912371vsd.4.gmail; Thu, 18 Feb
 2021 16:10:01 -0800 (PST)
X-Received: by 2002:a67:f318:: with SMTP id p24mr4763131vsf.54.1613693401558;
        Thu, 18 Feb 2021 16:10:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613693401; cv=none;
        d=google.com; s=arc-20160816;
        b=c89/vRV9+V6C07g60M/GdDzIpUids2srkrysUujcPXbYL7KDaLNGhXk7AMNyjLm+YH
         jg2aHwH6sjhnn27KsJIfcFL2+NfeZCdWeQRMcIpx9G/u50tLI/Q2v0jBLatVoe6pgVPe
         Lc7ztWM1MWychtGVMu8iWY4P920xB0ARsNMa2+tdDz0LZAkzdiFRbGHKP8dDTxp1B6ES
         7/KDgxVRvl2g1rRkQnMnUbJ5VeA8bBHqVaSdRL3fRbmQIKJ49bamXHd9iqvKq6vL/AXA
         AriK6QejcYavGD7b7m5M/1QKTibTHkO+C6HctI6symFysoUkHhIXOZh1N4hHwY9A5gei
         WYiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7mNeKDWUCPWRjksxHsm0Sl4Ar+FMbcH9wO3bpUG9+dU=;
        b=LJZ+mwZtMiFCkSieXMOtx+kyxiBOKKGvzcpXTfJa3+3BMkJ6Ci9KyYPjmyWEET54zU
         wIBl1ME4zqLWiQyBaGgcTkK0cJz5kmARV3Vewlo81TYzZsOOBthU+WfgdH4xfvC33nPH
         lEZOO/+25ax6DP2HVXoy3wCbxNxpFk4ybe5qUwBzI2qQfm+ckpEScpGzdSycGS10Cxxj
         L/BSD74AaFUbjvSWlTA8k8Zn6rfHbIxVBskd3yP92JA2iY05sy545ZMaxjgbxx+wSoSP
         8EPaFoedAgJUsobl6Cm6a7pnRK1m0QNzAJrOORJPbpODoAYe26Od2VkIXJztmXKV3ON4
         V9Qg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BC6tuzv2;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id q23si717417ual.1.2021.02.18.16.10.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Feb 2021 16:10:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id u143so2623915pfc.7
        for <kasan-dev@googlegroups.com>; Thu, 18 Feb 2021 16:10:01 -0800 (PST)
X-Received: by 2002:a62:7c55:0:b029:1dd:8c65:1ed8 with SMTP id
 x82-20020a627c550000b02901dd8c651ed8mr6639950pfc.24.1613693400570; Thu, 18
 Feb 2021 16:10:00 -0800 (PST)
MIME-Version: 1.0
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com> <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
In-Reply-To: <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Feb 2021 01:09:49 +0100
Message-ID: <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
To: George Kennedy <george.kennedy@oracle.com>
Cc: David Hildenbrand <david@redhat.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Konrad Rzeszutek Wilk <konrad@darnok.org>, 
	Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Christoph Hellwig <hch@infradead.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Dhaval Giani <dhaval.giani@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BC6tuzv2;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Feb 19, 2021 at 1:06 AM George Kennedy
<george.kennedy@oracle.com> wrote:
>
>
>
> On 2/18/2021 3:55 AM, David Hildenbrand wrote:
> > On 17.02.21 21:56, Andrey Konovalov wrote:
> >> During boot, all non-reserved memblock memory is exposed to the buddy
> >> allocator. Poisoning all that memory with KASAN lengthens boot time,
> >> especially on systems with large amount of RAM. This patch makes
> >> page_alloc to not call kasan_free_pages() on all new memory.
> >>
> >> __free_pages_core() is used when exposing fresh memory during system
> >> boot and when onlining memory during hotplug. This patch adds a new
> >> FPI_SKIP_KASAN_POISON flag and passes it to __free_pages_ok() through
> >> free_pages_prepare() from __free_pages_core().
> >>
> >> This has little impact on KASAN memory tracking.
> >>
> >> Assuming that there are no references to newly exposed pages before they
> >> are ever allocated, there won't be any intended (but buggy) accesses to
> >> that memory that KASAN would normally detect.
> >>
> >> However, with this patch, KASAN stops detecting wild and large
> >> out-of-bounds accesses that happen to land on a fresh memory page that
> >> was never allocated. This is taken as an acceptable trade-off.
> >>
> >> All memory allocated normally when the boot is over keeps getting
> >> poisoned as usual.
> >>
> >> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >> Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
> >
> > Not sure this is the right thing to do, see
> >
> > https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c529860@oracle.com
> >
> > Reversing the order in which memory gets allocated + used during boot
> > (in a patch by me) might have revealed an invalid memory access during
> > boot.
> >
> > I suspect that that issue would no longer get detected with your
> > patch, as the invalid memory access would simply not get detected.
> > Now, I cannot prove that :)
>
> Since David's patch we're having trouble with the iBFT ACPI table, which
> is mapped in via kmap() - see acpi_map() in "drivers/acpi/osl.c". KASAN
> detects that it is being used after free when ibft_init() accesses the
> iBFT table, but as of yet we can't find where it get's freed (we've
> instrumented calls to kunmap()).

Maybe it doesn't get freed, but what you see is a wild or a large
out-of-bounds access. Since KASAN marks all memory as freed during the
memblock->page_alloc transition, such bugs can manifest as
use-after-frees.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2By_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U%3DxA42ek3Lw%40mail.gmail.com.
