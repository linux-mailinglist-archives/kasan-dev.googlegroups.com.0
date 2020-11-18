Return-Path: <kasan-dev+bncBCCMH5WKTMGRBIMC2X6QKGQEONDSD4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 316E22B8101
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 16:43:31 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id o10sf1412805pjr.1
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 07:43:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605714210; cv=pass;
        d=google.com; s=arc-20160816;
        b=oqFVRJYCAeXPAHV+Ll+U2dRHm6OpAcx3DsKCoa4PkQ6Vd6gRi2lx4CuWf4RDy7utOu
         OwRAwQXvQNgIvfRi/LpJsyWEIMBHGe5LMGAZKDmsZ3mwOoguNbNn01zKRF0H663YFWW7
         sRzlbW/a+YnmYbyHSxDOhMdwcz2OmLhtDv2YZosYh2Axn/MLuosbKg/yrOj1/vrY2A5Q
         euWOSk91aluXmTosHerVRcwHF2z9eGRV4tQQKVYp2jeFLEBTF9JhoToj1menwyOBA4Qb
         rHl4oPVGIgCSkbZKshWDUGCGLZrAa+4XS1oX5Q5DNSx6farnJsflD2G8rWL8VS/I1Mz3
         q2iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mRJTHGy8rCckvGZ7G5zcI9lLf+Bx8+VtylKUDoDZP6E=;
        b=yZ4HWQ9H4mr4OXv7iTnc20JiQlXN/CmZ4omzwgz7TMwBtgcnprl3sjlOFw3+EEAYPt
         vq/IZTi++/tggkbkYwxl35/FfO0Re3hmXOGUOh0hF7xLwyCeFvQ7Es/d0+sbXaiqzNJs
         tTD0E7reMlKx7AUerrro6PBOMUZz8UB9uKc+mwuHMafoH7/sl5ITNvskd+7C5IoQShZ1
         2STU6nikfDN3yFDz/1ieY3UvWkBs6zjY6bN72sppl9QTv1Ia9GmiD+0ElPUelUKHZksI
         lKTdfWifi0nKwreAfQvuInTgaU6c8DVkr718/Bk/fup77TFNvprDjz9ZNzXdHfQWdqgC
         3GOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o2elT4rI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=mRJTHGy8rCckvGZ7G5zcI9lLf+Bx8+VtylKUDoDZP6E=;
        b=dpT2IEzEJkaESq0mYRaPJ8j9uqHQ81NT5XEukJaT5SmIL3c2EKEjV+RyhcKfOlbp+a
         ZXOAlXGOZOpNYMsZMRDTH/I4KwKcwsHHHqVpCvJlFcC9pQXxMzFYSVqnjegDyZzGcawN
         FxqKH1yyaY9ZqU1mzPbXumFZFhvKRlERErVm1aFafxFHgOzaSWgCuLz/NRxK5ie0/LNc
         S/S3kwK6V37ia21SGNJXdFIWdJdC+NvvSNAaVmzQ3L5Yw6QGsev6q/8knYRpxlzAuECL
         YOuv/4tfjJcHMUCeWvtk6UEhLS+NWO7FfePf/ygnpaY+peEUUNB7+zTVO3BgBaoMxciF
         hHSQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mRJTHGy8rCckvGZ7G5zcI9lLf+Bx8+VtylKUDoDZP6E=;
        b=fiq3F2lMz5GQNxTnqb9RW7S1gO4+vSXRtZQqVlEy4ixRW3UZcHqDhfnsNSAnNSiyun
         TtCNfvwl7DM9PRNnzO7qLziSWzWSUvjPKpISeoC7k9Dxyo8Dk4IbgDiquzmS2R12olUa
         Vh1xkhMI8EiQnQT6DtQkYZz89tXuy+NDZq/Cc8MgDqdujQWrtZsXk55ccSG5tMZU3+VH
         Y3Oi8gHxFR7rWEC8TnXTldpsZnRcsIHpdAZSAUcwqK2sRPLNoCtRUh/iHq68IxNAFGqK
         qoGhT/1IvLcRKtL+gdnmgKdhL4OL7WutDEllkny0EGEm9/JB9dE/u/uP6ZzmEIY884Op
         rnjw==
X-Gm-Message-State: AOAM533IpdMPoLfdMjTviKdUwv/qfz/FLN34tasW6hDpe6ASvLJw3WCH
	fFjfAJXTxAzzXxSAo8drHZ8=
X-Google-Smtp-Source: ABdhPJxu+SOMVngxqX5/8I2vX+eQmp0ocL9jfdwqRS8QJ+kNa6SNwY5XOYs164N2JwGSa2ICki+RcA==
X-Received: by 2002:a17:90b:11cf:: with SMTP id gv15mr508287pjb.11.1605714209946;
        Wed, 18 Nov 2020 07:43:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6a85:: with SMTP id n5ls9900428plk.9.gmail; Wed, 18
 Nov 2020 07:43:29 -0800 (PST)
X-Received: by 2002:a17:90a:f292:: with SMTP id fs18mr489486pjb.222.1605714209394;
        Wed, 18 Nov 2020 07:43:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605714209; cv=none;
        d=google.com; s=arc-20160816;
        b=eG9tTYZCTa3xhimxdinWMvQrTVWSf26hrBDKP4Yzyxf8W7DvAo6sosLrZ/3kgAIHOJ
         OHTxkYx9ElHY6EHPCHJEwfLoigx2F8kkX/wmEdnC3vJGyuTjAmzyHTJdYY2GELvQ9nLO
         ftbRk9JYYufsZaRYfnbSffIidmlboGVPvT1zZPJXNaNPeeJE0vFbkTLNYw4B6WUWSHMP
         iON6i/F06MWyskhoF6QZGoEZsZYMsqBPD2tMHXAcf0a2prDJmuwR+U84hFqTHh1meGvY
         at4ByT/w90YWUpQCMOIVTymIND1lGM7Y5PEfzlfdt8vDwCb8q20Cwc/nAjA0bX95A3kX
         SV4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ii8uMwZ11exGNZ0QuXQOuB3dAaW5Ak4GBCBwnjIahGo=;
        b=aOw6zKxG/77ckPK7fCMi7NbR1D10zJ+PxJPwyakZ5U0UqPLYehW68qSF60ZrNGaFgX
         rne4pCchKZ9IIg9Fgkmb74Dxp6ASMGuXymUUN7TyOFm0SKS9wsvXmowKZKkGR/ngum07
         1e+1yaj8F/FXIOGU6EZG7FcTj670OuPxzbf29IlnzVSJdQJ7/J+ualfWlS/hvtNPQ7Wx
         B7f9WKKbWgFWC8SiOxz2bFCXu5DHVPZrt0a1uZiA5eCFF/bfawx8zdH/uTmq44LANBFW
         mBHGep7074XT65pS7hxYN3frZCbLG1JNnrgtsdHiwlVLrj2p+VHuMoT23WdBHVSlc0Wh
         ghLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=o2elT4rI;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf41.google.com (mail-qv1-xf41.google.com. [2607:f8b0:4864:20::f41])
        by gmr-mx.google.com with ESMTPS id d2si1813748pfr.4.2020.11.18.07.43.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Nov 2020 07:43:29 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as permitted sender) client-ip=2607:f8b0:4864:20::f41;
Received: by mail-qv1-xf41.google.com with SMTP id v20so1219396qvx.4
        for <kasan-dev@googlegroups.com>; Wed, 18 Nov 2020 07:43:29 -0800 (PST)
X-Received: by 2002:a0c:9e53:: with SMTP id z19mr5380322qve.23.1605714207999;
 Wed, 18 Nov 2020 07:43:27 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com> <f10443693b4dfd63477519e5f2e4fdc439c8c3c8.1605305705.git.andreyknvl@google.com>
In-Reply-To: <f10443693b4dfd63477519e5f2e4fdc439c8c3c8.1605305705.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 18 Nov 2020 16:43:16 +0100
Message-ID: <CAG_fn=We3geXieMD1PzFGj+d6wj8_uEpkE=UOn=jfFEciQM2gQ@mail.gmail.com>
Subject: Re: [PATCH mm v10 41/42] kasan: add documentation for hardware
 tag-based mode
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=o2elT4rI;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f41 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Fri, Nov 13, 2020 at 11:17 PM Andrey Konovalov <andreyknvl@google.com> w=
rote:
>
> Add documentation for hardware tag-based KASAN mode and also add some
> clarifications for software tag-based mode.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

> ---
> Change-Id: Ib46cb444cfdee44054628940a82f5139e10d0258
> ---
>  Documentation/dev-tools/kasan.rst | 80 +++++++++++++++++++++++--------
>  1 file changed, 59 insertions(+), 21 deletions(-)
>
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/=
kasan.rst
> index 2d55d788971c..ffbae8ce5748 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -5,12 +5,14 @@ Overview
>  --------
>
>  KernelAddressSANitizer (KASAN) is a dynamic memory error detector design=
ed to
> -find out-of-bound and use-after-free bugs. KASAN has two modes: generic =
KASAN
> -(similar to userspace ASan) and software tag-based KASAN (similar to use=
rspace
> -HWASan).
> +find out-of-bound and use-after-free bugs. KASAN has three modes:
> +1. generic KASAN (similar to userspace ASan),
> +2. software tag-based KASAN (similar to userspace HWASan),
> +3. hardware tag-based KASAN (based on hardware memory tagging).
>
> -KASAN uses compile-time instrumentation to insert validity checks before=
 every
> -memory access, and therefore requires a compiler version that supports t=
hat.
> +Software KASAN modes (1 and 2) use compile-time instrumentation to inser=
t
> +validity checks before every memory access, and therefore require a comp=
iler
> +version that supports that.
>
>  Generic KASAN is supported in both GCC and Clang. With GCC it requires v=
ersion
>  8.3.0 or later. Any supported Clang version is compatible, but detection=
 of
> @@ -19,7 +21,7 @@ out-of-bounds accesses for global variables is only sup=
ported since Clang 11.
>  Tag-based KASAN is only supported in Clang.
>
>  Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa,=
 s390
> -and riscv architectures, and tag-based KASAN is supported only for arm64=
.
> +and riscv architectures, and tag-based KASAN modes are supported only fo=
r arm64.
>
>  Usage
>  -----
> @@ -28,14 +30,16 @@ To enable KASAN configure kernel with::
>
>           CONFIG_KASAN =3D y
>
> -and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN) and
> -CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN).
> +and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN),
> +CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN), and
> +CONFIG_KASAN_HW_TAGS (to enable hardware tag-based KASAN).
>
> -You also need to choose between CONFIG_KASAN_OUTLINE and CONFIG_KASAN_IN=
LINE.
> -Outline and inline are compiler instrumentation types. The former produc=
es
> -smaller binary while the latter is 1.1 - 2 times faster.
> +For software modes, you also need to choose between CONFIG_KASAN_OUTLINE=
 and
> +CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation typ=
es.
> +The former produces smaller binary while the latter is 1.1 - 2 times fas=
ter.
>
> -Both KASAN modes work with both SLUB and SLAB memory allocators.
> +Both software KASAN modes work with both SLUB and SLAB memory allocators=
,
> +hardware tag-based KASAN currently only support SLUB.
>  For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
>
>  To augment reports with last allocation and freeing stack of the physica=
l page,
> @@ -196,17 +200,24 @@ and the second to last.
>  Software tag-based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
>
> -Tag-based KASAN uses the Top Byte Ignore (TBI) feature of modern arm64 C=
PUs to
> -store a pointer tag in the top byte of kernel pointers. Like generic KAS=
AN it
> -uses shadow memory to store memory tags associated with each 16-byte mem=
ory
> +Software tag-based KASAN requires software memory tagging support in the=
 form
> +of HWASan-like compiler instrumentation (see HWASan documentation for de=
tails).
> +
> +Software tag-based KASAN is currently only implemented for arm64 archite=
cture.
> +
> +Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64=
 CPUs
> +to store a pointer tag in the top byte of kernel pointers. Like generic =
KASAN
> +it uses shadow memory to store memory tags associated with each 16-byte =
memory
>  cell (therefore it dedicates 1/16th of the kernel memory for shadow memo=
ry).
>
> -On each memory allocation tag-based KASAN generates a random tag, tags t=
he
> -allocated memory with this tag, and embeds this tag into the returned po=
inter.
> +On each memory allocation software tag-based KASAN generates a random ta=
g, tags
> +the allocated memory with this tag, and embeds this tag into the returne=
d
> +pointer.
> +
>  Software tag-based KASAN uses compile-time instrumentation to insert che=
cks
>  before each memory access. These checks make sure that tag of the memory=
 that
>  is being accessed is equal to tag of the pointer that is used to access =
this
> -memory. In case of a tag mismatch tag-based KASAN prints a bug report.
> +memory. In case of a tag mismatch software tag-based KASAN prints a bug =
report.
>
>  Software tag-based KASAN also has two instrumentation modes (outline, th=
at
>  emits callbacks to check memory accesses; and inline, that performs the =
shadow
> @@ -215,9 +226,36 @@ simply printed from the function that performs the a=
ccess check. With inline
>  instrumentation a brk instruction is emitted by the compiler, and a dedi=
cated
>  brk handler is used to print bug reports.
>
> -A potential expansion of this mode is a hardware tag-based mode, which w=
ould
> -use hardware memory tagging support instead of compiler instrumentation =
and
> -manual shadow memory manipulation.
> +Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses =
through
> +pointers with 0xFF pointer tag aren't checked). The value 0xFE is curren=
tly
> +reserved to tag freed memory regions.
> +
> +Software tag-based KASAN currently only supports tagging of
> +kmem_cache_alloc/kmalloc and page_alloc memory.
> +
> +Hardware tag-based KASAN
> +~~~~~~~~~~~~~~~~~~~~~~~~
> +
> +Hardware tag-based KASAN is similar to the software mode in concept, but=
 uses
> +hardware memory tagging support instead of compiler instrumentation and
> +shadow memory.
> +
> +Hardware tag-based KASAN is currently only implemented for arm64 archite=
cture
> +and based on both arm64 Memory Tagging Extension (MTE) introduced in ARM=
v8.5
> +Instruction Set Architecture, and Top Byte Ignore (TBI).
> +
> +Special arm64 instructions are used to assign memory tags for each alloc=
ation.
> +Same tags are assigned to pointers to those allocations. On every memory
> +access, hardware makes sure that tag of the memory that is being accesse=
d is
> +equal to tag of the pointer that is used to access this memory. In case =
of a
> +tag mismatch a fault is generated and a report is printed.
> +
> +Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses =
through
> +pointers with 0xFF pointer tag aren't checked). The value 0xFE is curren=
tly
> +reserved to tag freed memory regions.
> +
> +Hardware tag-based KASAN currently only supports tagging of
> +kmem_cache_alloc/kmalloc and page_alloc memory.
>
>  What memory accesses are sanitised by KASAN?
>  --------------------------------------------
> --
> 2.29.2.299.gdc1121823c-goog
>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWe3geXieMD1PzFGj%2Bd6wj8_uEpkE%3DUOn%3DjfFEciQM2gQ%40mai=
l.gmail.com.
