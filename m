Return-Path: <kasan-dev+bncBDT2NE7U5UFRBSVNRKZAMGQEHV547LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C7CE8C49AC
	for <lists+kasan-dev@lfdr.de>; Tue, 14 May 2024 00:40:12 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2b2d29dce36sf4081606a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 13 May 2024 15:40:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1715640011; cv=pass;
        d=google.com; s=arc-20160816;
        b=pJlE8c/qAkkUo6mEvF/9bvXbgFRi+KGO8pvvqTiQbpq2xygix73l7NsP9/Gat32BQZ
         Uer7svYd/s37b5a+Hi0IIwE5C0nWrPR+XUeeSi1xajt9q3JP/gGdiI0XK7FQTxW0bE3W
         Q64+ZSQPmFifVEPDL/sfpPemfjDJbM4jlYbJSHctriaufdlX1aIRbdFMFfUfwTwoqHut
         NSpcibysWsQ/45g1X5SxK7ccOfORtlHVhLs4skkTk9uTba6Nkg1AecMU/znVpY4WUd2O
         PFCQWf5n5joLlHUoGAaTP16+fmkIOtcKcJQZDgx1TFnKs2irWSSEODGc7jNHO2K5mh+e
         LFgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=B625btL044fZSLswQLE3wTTupYfOx+HyA+pQOcsEojU=;
        fh=Ee/ep23m/SuU8OR2/e2s/mDb8PkE8z57X0LOSiSSPRU=;
        b=HWB3yp7Fz7o+Wo/dPLYJBJ/2UVisa07LoDqkLP0DlBjA7l+qqj5YpEBfCXtJOA/BlV
         Yz5/SFhW/IDvmOGlcBmmihKOqX5aNufO67m4M2wU7mcNDrWnjSd3kAFV5e3RCwInAm9G
         1VcqYVow+ozD/W2eELoNinw96ntabfx7qHdjXOFkhWbhWyhSy0LvdJWH6whZZ8Ax6XT5
         fQcYO8JYkgpLwgJS7nk3/jRnXSfXwMZ7uUWAUSmlZuqjZhbvj32loZ2nEQRUNjNs8kZk
         uLHVrEBcwp5ry9HGIkNME3tf3meVLDRc3sxm/YMQ3YJjTk1eOmXYVkI5ego7iVoYR+cu
         VpwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eROTGHQI;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1715640011; x=1716244811; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=B625btL044fZSLswQLE3wTTupYfOx+HyA+pQOcsEojU=;
        b=bm9M0kvwfRWfzX55JNsnrxVAR3ByFaePBUlSAP4mdjgJNDqoQSEHK7KWdyPrDkCeWD
         l1NKqJ5bVVDCFZINZh55Jj2SbyIrsIcyBEYLutTCWy4hP48WXB5mxFOvITb6Dd2zEUfE
         Q47FopresZjoXRhfWUk1u3QLpHO3+h3EqYOcB0eCvluVf5hjdz7kPmaEAf1jUqaMNVfj
         1lAZ2RJolHLkZaIwAXQaF2F1gW1oemJue1pFE62w3+IZ9FTMA6OPL5te+9TtKr9Vt9WI
         EGr1CIuZqDEvgOxbdN6XrLNHmDxyANXShXW3kiHCC1Nw/y92l02+CAOMI29gZ0jFtj/O
         GZLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1715640011; x=1716244811;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=B625btL044fZSLswQLE3wTTupYfOx+HyA+pQOcsEojU=;
        b=rlNBy1Z9gCRdIvdvl/0MX+iodNRgGGcjB1d0+I7U25A6v8mDx8oG2rufs6pdzbCO6W
         fOgS83RkBvL6cr363wOkLvDL9XGrFjBxQOQ8BZi/WI/c3Gmmf8+x4iZuSbl3MnAZ1elj
         06+nazbA7NJFijYJHUfS93Se+EEqUIfzWi1CWZhpaBO21l16UzYsu+awql4ns3nahWHX
         bUd1yuKTmaDi3j6pGJwTrpT+ZmHvRh/yOofL8atRcfaLD+NLc2ZvvPSKsoH0yGA6Ou+M
         cfVuu6LSbTCc96ewsGHtPZ93Zrt5APLgU4Re/DbokXe2BEJVL3fod042Rqpp0c3Q+npJ
         VgsQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVkHJ/UysiXkzhqFKYeUUn6Wh0Nwxsydv7rYwBJzlhSQZDeJRhSR9FVFCwVUGKlEf/LxFkV22cWCjXAuNz/6Yyre4pgh5Quiw==
X-Gm-Message-State: AOJu0YzD9osyu17VDVoalBLvrGCpJ3ITc0SMJfL6QXAYwRNwR+glV2a5
	+Akg1hX0+UKiFQyFHNJJ5K0iXhokGX15UPKPcUuWSxdOT6ilJ20P
X-Google-Smtp-Source: AGHT+IG5+dHkZP50XcvK7xLDrvxJ3wedS3gHzsGJcZEUn+KeB874TvL/5OsGtmc6WJXGCZ/mKW9Tzg==
X-Received: by 2002:a17:90a:d48e:b0:2b2:7e94:c5fa with SMTP id 98e67ed59e1d1-2b6cc144814mr9519749a91.5.1715640010896;
        Mon, 13 May 2024 15:40:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:d815:b0:2b5:af18:4777 with SMTP id
 98e67ed59e1d1-2b6623aef24ls640395a91.1.-pod-prod-01-us; Mon, 13 May 2024
 15:40:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUXaKhSvIaiIINCCys33XscEdnDZbglD1Zw31fYCHIEqOS2FqxacXPR+GFAzhaluYKNbBpUzli6S5L7ifx269kH7CAG2ShnIqdJaw==
X-Received: by 2002:a17:90a:ab02:b0:2b4:39cd:2e0e with SMTP id 98e67ed59e1d1-2b6cc76bdd5mr9332100a91.21.1715640009518;
        Mon, 13 May 2024 15:40:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1715640009; cv=none;
        d=google.com; s=arc-20160816;
        b=gJq5vFIEZBm5QtpN8140mQ8wS0qRXU2GBcLs7w90hM14g8B94Vi4Ozb9KLrIrHcMyB
         oUB2oG1xyIeTNZAAF8lQ7cttPlNt6jQ0MIy5zIcSkSx48Lj4QgIHDuz7C0pNQ0FIIYdW
         wBs+NcmBgkvLosO30F7bdwO4fczC22HlLLaQe3j91mcCwwx2oVSfUVGc+2Xyb+BpWGJJ
         MqoNE2ax8n3hnuEKAL4Wg+Bptoe+C/BczMQl174gdh5rUKKRlDbQPFSlZIDfhrpQaYFU
         okMrcUDCbIcYzwTyAw+alhiwhbjbPCDXOR2yAOz1ksQBXo7BzmsWIfFHzDRizZvNZd2k
         UlJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lDU1Ng8TWUtDxaw/RakO06hRasPavlzQcHKZN28JJLM=;
        fh=N6NvAiO31E0U4WuLdUubCSC/xFXXbMfWWyQUkyOIsgI=;
        b=XfNnxRhtNevB5ei8FjtbaX/Xhslm243O7QkBwXPOub8gCKU5mkCqsONCPGAiJ84koj
         dkcWMH2vXJ+2Q+RjKw5G+W6GPPHyucqGQI6kugcGUfjfRRAD9f+PFOdO4wHm7EnlcGBC
         EDON9p+dVUcQZ/7ihY0exmU6UoiZL67pZ5EuidQPcpo7TCgRa683EqJKAxWjRkKDlie2
         bBFmuhOo1CqZzLV9qg0Q/v46kmESkaca9Dgne9N6X7vilmoSHd5oXN0dK2wpGrmvxtgc
         KMMPpBMO7uelrOPha37kkUDlLPaE7iUUf+HRs9MiEBpxq6X9q8RnKMJyOKy0hnAnKCh4
         UJEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=eROTGHQI;
       spf=pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2b85f893b2bsi639168a91.1.2024.05.13.15.40.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 May 2024 15:40:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id C68EF60FA9
	for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 22:40:08 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7E1BCC32781
	for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 22:40:08 +0000 (UTC)
Received: by mail-lf1-f48.google.com with SMTP id 2adb3069b0e04-51ff65b1e14so5390477e87.2
        for <kasan-dev@googlegroups.com>; Mon, 13 May 2024 15:40:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWHYIeXvShzxIP2n/M0KHsTjLfca2L58SvryFgdVff1ePDJ4dFVD6JLrK5F+pDb92fKu2gQ8Xy9aJsbDLEPmvnbaKxUuEK601qzrQ==
X-Received: by 2002:a05:6512:6c7:b0:522:2dd4:bb30 with SMTP id
 2adb3069b0e04-5222dd4bba8mr6686133e87.54.1715640007187; Mon, 13 May 2024
 15:40:07 -0700 (PDT)
MIME-Version: 1.0
References: <20240506133544.2861555-1-masahiroy@kernel.org> <202405131136.73E766AA8@keescook>
In-Reply-To: <202405131136.73E766AA8@keescook>
From: Masahiro Yamada <masahiroy@kernel.org>
Date: Tue, 14 May 2024 07:39:31 +0900
X-Gmail-Original-Message-ID: <CAK7LNARZuqxWyxn2peMCCt0gbsRdWjri=Pd9-HvpK7bcOB-9dA@mail.gmail.com>
Message-ID: <CAK7LNARZuqxWyxn2peMCCt0gbsRdWjri=Pd9-HvpK7bcOB-9dA@mail.gmail.com>
Subject: Re: [PATCH 0/3] kbuild: remove many tool coverage variables
To: Kees Cook <keescook@chromium.org>
Cc: linux-kbuild@vger.kernel.org, linux-arch@vger.kernel.org, 
	linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Marco Elver <elver@google.com>, Josh Poimboeuf <jpoimboe@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Peter Oberparleiter <oberpar@linux.ibm.com>, 
	Roberto Sassu <roberto.sassu@huaweicloud.com>, Johannes Berg <johannes@sipsolutions.net>, 
	kasan-dev@googlegroups.com, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: masahiroy@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=eROTGHQI;       spf=pass
 (google.com: domain of masahiroy@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=masahiroy@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, May 14, 2024 at 3:48=E2=80=AFAM Kees Cook <keescook@chromium.org> w=
rote:
>
> In the future can you CC the various maintainers of the affected
> tooling? :)


Sorry, I was too lazy to add CC for treewide changes like this.
Anyway, thanks for adding CC.




> On Mon, May 06, 2024 at 10:35:41PM +0900, Masahiro Yamada wrote:
> >
> > This patch set removes many instances of the following variables:
> >
> >   - OBJECT_FILES_NON_STANDARD
> >   - KASAN_SANITIZE
> >   - UBSAN_SANITIZE
> >   - KCSAN_SANITIZE
> >   - KMSAN_SANITIZE
> >   - GCOV_PROFILE
> >   - KCOV_INSTRUMENT
> >
> > Such tools are intended only for kernel space objects, most of which
> > are listed in obj-y, lib-y, or obj-m.
>
> This is a reasonable assertion, and the changes really simplify things
> now and into the future. Thanks for finding such a clean solution! I
> note that it also immediately fixes the issue noticed and fixed here:
> https://lore.kernel.org/all/20240513122754.1282833-1-roberto.sassu@huawei=
cloud.com/
>
> > The best guess is, objects in $(obj-y), $(lib-y), $(obj-m) can opt in
> > such tools. Otherwise, not.
> >
> > This works in most places.
>
> I am worried about the use of "guess" and "most", though. :) Before, we
> had some clear opt-out situations, and now it's more of a side-effect. I
> think this is okay, but I'd really like to know more about your testing.


- defconfig for arc, hexagon, loongarch, microblaze, sh, xtensa
- allmodconfig for the other architectures


(IIRC, allmodconfig failed for the first case, for reasons unrelated
to this patch set, so I used defconfig instead.
I do not remember what errors I observed)


I checked the diff of .*.cmd files.





>
> It seems like you did build testing comparing build flags, since you
> call out some of the explicit changes in patch 2, quoting:
>
> >  - include arch/mips/vdso/vdso-image.o into UBSAN, GCOV, KCOV
> >  - include arch/sparc/vdso/vdso-image-*.o into UBSAN
> >  - include arch/sparc/vdso/vma.o into UBSAN
> >  - include arch/x86/entry/vdso/extable.o into KASAN, KCSAN, UBSAN, GCOV=
, KCOV
> >  - include arch/x86/entry/vdso/vdso-image-*.o into KASAN, KCSAN, UBSAN,=
 GCOV, KCOV
> >  - include arch/x86/entry/vdso/vdso32-setup.o into KASAN, KCSAN, UBSAN,=
 GCOV, KCOV
> >  - include arch/x86/entry/vdso/vma.o into GCOV, KCOV
> >  - include arch/x86/um/vdso/vma.o into KASAN, GCOV, KCOV
>
> I would agree that these cases are all likely desirable.
>
> Did you find any cases where you found that instrumentation was _removed_
> where not expected?




See the commit log of 1/3.


> Note:
>
> The coverage for some objects will be changed:
>
>   - exclude .vmlinux.export.o from UBSAN, KCOV
>   - exclude arch/csky/kernel/vdso/vgettimeofday.o from UBSAN
>   - exclude arch/parisc/kernel/vdso32/vdso32.so from UBSAN
>   - exclude arch/parisc/kernel/vdso64/vdso64.so from UBSAN
>   - exclude arch/x86/um/vdso/um_vdso.o from UBSAN
>   - exclude drivers/misc/lkdtm/rodata.o from UBSAN, KCOV
>   - exclude init/version-timestamp.o from UBSAN, KCOV
>   - exclude lib/test_fortify/*.o from all santizers and profilers
>
> I believe these are positive effects.




--=20
Best Regards
Masahiro Yamada

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAK7LNARZuqxWyxn2peMCCt0gbsRdWjri%3DPd9-HvpK7bcOB-9dA%40mail.gmai=
l.com.
