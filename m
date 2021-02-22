Return-Path: <kasan-dev+bncBCW7LPVNTAKBBGGZZ6AQMGQEELK3KUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 52C6C321E4F
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 18:40:42 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id f5sf5803pjs.6
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Feb 2021 09:40:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614015641; cv=pass;
        d=google.com; s=arc-20160816;
        b=c0ffzhlPaegE59elIglau05EybNxOXTa5WmHO3MTQm5nk5hdux38sPbFQdmnmf5TR4
         /mGtviXRom7SWY5kJOgVCdpkiIB9UpP9o5L1S4NwpAqXVZ+fomEjE10tDyKIsDofKwmW
         h0LAv2F/HPDwgXeyANGCHhPWsKWHT3JXY+Pxm4gTFmMBW6kz6o16khoaazF2deUq2RdP
         4ReMwtQ5AEJXiW2WPqaXYcH46p3QbjhU64k4eCSoF1iQ3Ud2n2Sl7bQZKcYI1xrjb4ID
         IV/H37xyr6cJElRo3XJ6oCUPuWRkA0qm5D76x5xUToP11CSuhF1cWL/u2IsBbzNf81Eh
         fzLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=nJZ6V58ixekW2ToIgq1eJth5YSaS2tjS5iR+2sqPOoE=;
        b=nbLAsp7VchmGxoke/L2aD5RrbUsxyw9wyUFvEzSDOpZhTyJ/Mq+Tb+hEexOjkj8HXI
         qLPUHva4fl1NampxthVwrFVfnAYP/yyiVoT+SvY3dO7gr3cE7Va8LgPslel68rX/ioua
         TRps7HxgKFcczUHPyv0BjlJjfL7FwJtGUAVsUjONwfb2l5I0DnjR/Ys3l1Lt6m46TGc/
         JOd6mG2vhDXR4LP245DUM9V9UyCE7jQ6yA+szY6XZnY+PBXLbmTAf137WU55XROGxrvN
         VqK1CZb0rtlGbigxGzAJ4imEBSl5xZi1WRk9ASOnEcs9lHdM+0/Z1PwQKmXm5mdIjn6d
         Qbjg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EhROeVtM;
       spf=pass (google.com: domain of konrad.r.wilk@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=konrad.r.wilk@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nJZ6V58ixekW2ToIgq1eJth5YSaS2tjS5iR+2sqPOoE=;
        b=WXeEF5R1HqFIfLBk9mmoI9X/DgKXYGiRUCNi/qZvzga4hkKWiWAO+SLmel14U7iMZH
         J1S0b+fbmQk/jWYzNBGjl4bQ6oGxqnCJPcGxN2OmPQwm3Y/avpYNJL/UcKNv29X1Znb6
         EK0HSyg4yYtw0GkQsZovIWQl4GkMdS3lvVSQnyyz/kAMlPivTDvoq8X/pfyucm8zWyO1
         O6WDjcDUae66XpIlC1BtHOPHq2Pj6YqvqmfXP2JxUJ8Xyc6KGZ4Sl0NOzqDk1kHRQTJP
         45X6a7wOugL3HbmWgYW9bV+UWrtKDkDHncgKSLVhoO/5marEEMZ2TIj6a/DvnD1pBnlm
         VD5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nJZ6V58ixekW2ToIgq1eJth5YSaS2tjS5iR+2sqPOoE=;
        b=Y6AiSDv7BX4JKauvbdcBALrbSa/9lnAbVLejhG1ffoDKSsD3tWpSU1ac18V85fh9ur
         rPXPw671DWlwYr51hWCV9tmGiHK+vrZcz9G1EINETwimZytKUXL5EMWKKNmpYHnlnnZv
         0Kk6JdNq5B+xNKS2qVmSRszsyhKVMCN8dhbGVYmgVMyXX2w/fP0sptQhBpEWcj6pMUoT
         Tlw7rJ90MFINEb9uMUe/FcuCC5kVxt3LJ3g6fQU65UvhJMgJu/v/Us0aD2sWFR7wcAla
         C0aZuzwOxJL5v4+CfErUhtDbo5YF/93HCQ58hzZJOyuS3fD4n4Gm4UkFJ8af3f1b7+Cc
         o8hw==
X-Gm-Message-State: AOAM532V1KO/1qXLXxzheJXvgtyOZsy6yXTNAnwCNSKXDGKg4pawTFvX
	KgDgWEn36kDjRUmZ1KgL5r0=
X-Google-Smtp-Source: ABdhPJzPJ/uEq+e/cgirOnIZ/2eoHzxGRAu9AIPOPs4qb7kiIx96nWyDM9A0ZCora6CqGsHXLIIjrg==
X-Received: by 2002:a17:90a:928d:: with SMTP id n13mr24783289pjo.12.1614015641061;
        Mon, 22 Feb 2021 09:40:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls6506361pgu.6.gmail; Mon, 22 Feb
 2021 09:40:40 -0800 (PST)
X-Received: by 2002:a63:5416:: with SMTP id i22mr21109813pgb.43.1614015640228;
        Mon, 22 Feb 2021 09:40:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614015640; cv=none;
        d=google.com; s=arc-20160816;
        b=eafh5XxAo8CunD+f+N2mQYsLYfhE8PmrG/G05ADf96U8IluwDRCly2DmGDWrgxtffC
         HuVaGNbtB2n93/d6xxFDHpcyGQItuRkz8mYCoJ1aO3eI1tYLvmY94aYE1SFUgHemmW6+
         iG9/GdVRE1uc6EIo9i/KhV0aWl7c02o2w9M1f3iSf9DRICEEB5fIWN0qyh96zkJKib9z
         cbj1WK64Ns6srIMTY4qodnb01oOJkt3JgNyYpTJ9z+1if6bV6JHB7OaYVtMNz7do5Dj/
         g4X7bnYegZxUvot+Ae6fymnZo48DN6zXsoegRGtFKloQT5/zyElZC7w//FQUWlMCB2NR
         bPkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bUxy2tCwU4OV+6MXdFIf9MDJ8sFuj2MZRqKqAUO9jLI=;
        b=m551PA5hd+D440F4njvQNqwxH/f5EiaTEZ/r5o3U/CR40zpp8c3brCq9qN3w2mhMZj
         PFsC/ou4tdypSoLYQnkSXvnNTAhuUS4KbyzMNUfvB0H4ntn8fpgpOYEdVDL1Bl+RDenV
         7aNqzVzw0m0ePCTYbQDd22goAR6gXXF9kZ+iNqBP7PtIsjjZ9LJS3SVLt8racGqsPWa/
         Y5yIhvUuFan6GliMzx0No6SzYurIJ3JVVnGGIqxmJrBH+IO/8oQrlcBu0q5gqdVLbUaK
         Se6vJk4toSgVrLmZBOBDX7z7NH0FmqYykQIkvDwBDZGFWrdOFqYRMlStVNW+7psDAqEd
         s0YQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=EhROeVtM;
       spf=pass (google.com: domain of konrad.r.wilk@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=konrad.r.wilk@gmail.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id k6si368627pgt.2.2021.02.22.09.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Feb 2021 09:40:40 -0800 (PST)
Received-SPF: pass (google.com: domain of konrad.r.wilk@gmail.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id f17so13413780qkl.5
        for <kasan-dev@googlegroups.com>; Mon, 22 Feb 2021 09:40:40 -0800 (PST)
X-Received: by 2002:a37:aa94:: with SMTP id t142mr23039952qke.40.1614015639559;
        Mon, 22 Feb 2021 09:40:39 -0800 (PST)
Received: from fedora (209-6-208-110.s8556.c3-0.smr-cbr2.sbo-smr.ma.cable.rcncustomer.com. [209.6.208.110])
        by smtp.gmail.com with ESMTPSA id m190sm12716464qkc.66.2021.02.22.09.40.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 22 Feb 2021 09:40:38 -0800 (PST)
Sender: Konrad Rzeszutek Wilk <konrad.r.wilk@gmail.com>
Date: Mon, 22 Feb 2021 12:40:36 -0500
From: Konrad Rzeszutek Wilk <konrad@darnok.org>
To: David Hildenbrand <david@redhat.com>
Cc: George Kennedy <george.kennedy@oracle.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Christoph Hellwig <hch@infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	Dhaval Giani <dhaval.giani@oracle.com>,
	Mike Rapoport <rppt@linux.ibm.com>
Subject: Re: [PATCH] mm, kasan: don't poison boot memory
Message-ID: <20210222174036.GA399355@fedora>
References: <487751e1ccec8fcd32e25a06ce000617e96d7ae1.1613595269.git.andreyknvl@google.com>
 <e58cbb53-5f5b-42ae-54a0-e3e1b76ad271@redhat.com>
 <d11bf144-669b-0fe1-4fa4-001a014db32a@oracle.com>
 <CAAeHK+y_SmP5yAeSM3Cp6V3WH9uj4737hDuVGA7U=xA42ek3Lw@mail.gmail.com>
 <c7166cae-bf89-8bdd-5849-72b5949fc6cc@oracle.com>
 <797fae72-e3ea-c0b0-036a-9283fa7f2317@oracle.com>
 <1ac78f02-d0af-c3ff-cc5e-72d6b074fc43@redhat.com>
 <bd7510b5-d325-b516-81a8-fbdc81a27138@oracle.com>
 <56c97056-6d8b-db0e-e303-421ee625abe3@redhat.com>
 <4c7351e2-e97c-e740-5800-ada5504588aa@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <4c7351e2-e97c-e740-5800-ada5504588aa@redhat.com>
X-Original-Sender: konrad@darnok.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=EhROeVtM;       spf=pass
 (google.com: domain of konrad.r.wilk@gmail.com designates 2607:f8b0:4864:20::733
 as permitted sender) smtp.mailfrom=konrad.r.wilk@gmail.com
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

On Mon, Feb 22, 2021 at 05:39:29PM +0100, David Hildenbrand wrote:
> On 22.02.21 17:13, David Hildenbrand wrote:
> > On 22.02.21 16:13, George Kennedy wrote:
> > >=20
> > >=20
> > > On 2/22/2021 4:52 AM, David Hildenbrand wrote:
> > > > On 20.02.21 00:04, George Kennedy wrote:
> > > > >=20
> > > > >=20
> > > > > On 2/19/2021 11:45 AM, George Kennedy wrote:
> > > > > >=20
> > > > > >=20
> > > > > > On 2/18/2021 7:09 PM, Andrey Konovalov wrote:
> > > > > > > On Fri, Feb 19, 2021 at 1:06 AM George Kennedy
> > > > > > > <george.kennedy@oracle.com> wrote:
> > > > > > > >=20
> > > > > > > >=20
> > > > > > > > On 2/18/2021 3:55 AM, David Hildenbrand wrote:
> > > > > > > > > On 17.02.21 21:56, Andrey Konovalov wrote:
> > > > > > > > > > During boot, all non-reserved memblock memory is expose=
d to the
> > > > > > > > > > buddy
> > > > > > > > > > allocator. Poisoning all that memory with KASAN lengthe=
ns boot
> > > > > > > > > > time,
> > > > > > > > > > especially on systems with large amount of RAM. This pa=
tch makes
> > > > > > > > > > page_alloc to not call kasan_free_pages() on all new me=
mory.
> > > > > > > > > >=20
> > > > > > > > > > __free_pages_core() is used when exposing fresh memory =
during
> > > > > > > > > > system
> > > > > > > > > > boot and when onlining memory during hotplug. This patc=
h adds a new
> > > > > > > > > > FPI_SKIP_KASAN_POISON flag and passes it to __free_page=
s_ok()
> > > > > > > > > > through
> > > > > > > > > > free_pages_prepare() from __free_pages_core().
> > > > > > > > > >=20
> > > > > > > > > > This has little impact on KASAN memory tracking.
> > > > > > > > > >=20
> > > > > > > > > > Assuming that there are no references to newly exposed =
pages
> > > > > > > > > > before they
> > > > > > > > > > are ever allocated, there won't be any intended (but bu=
ggy)
> > > > > > > > > > accesses to
> > > > > > > > > > that memory that KASAN would normally detect.
> > > > > > > > > >=20
> > > > > > > > > > However, with this patch, KASAN stops detecting wild an=
d large
> > > > > > > > > > out-of-bounds accesses that happen to land on a fresh m=
emory page
> > > > > > > > > > that
> > > > > > > > > > was never allocated. This is taken as an acceptable tra=
de-off.
> > > > > > > > > >=20
> > > > > > > > > > All memory allocated normally when the boot is over kee=
ps getting
> > > > > > > > > > poisoned as usual.
> > > > > > > > > >=20
> > > > > > > > > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > > > > > > > > > Change-Id: Iae6b1e4bb8216955ffc14af255a7eaaa6f35324d
> > > > > > > > > Not sure this is the right thing to do, see
> > > > > > > > >=20
> > > > > > > > > https://lkml.kernel.org/r/bcf8925d-0949-3fe1-baa8-cc536c5=
29860@oracle.com
> > > > > > > > >=20
> > > > > > > > >=20
> > > > > > > > >=20
> > > > > > > > > Reversing the order in which memory gets allocated + used=
 during
> > > > > > > > > boot
> > > > > > > > > (in a patch by me) might have revealed an invalid memory =
access
> > > > > > > > > during
> > > > > > > > > boot.
> > > > > > > > >=20
> > > > > > > > > I suspect that that issue would no longer get detected wi=
th your
> > > > > > > > > patch, as the invalid memory access would simply not get =
detected.
> > > > > > > > > Now, I cannot prove that :)
> > > > > > > > Since David's patch we're having trouble with the iBFT ACPI=
 table,
> > > > > > > > which
> > > > > > > > is mapped in via kmap() - see acpi_map() in "drivers/acpi/o=
sl.c".
> > > > > > > > KASAN
> > > > > > > > detects that it is being used after free when ibft_init() a=
ccesses
> > > > > > > > the
> > > > > > > > iBFT table, but as of yet we can't find where it get's free=
d (we've
> > > > > > > > instrumented calls to kunmap()).
> > > > > > > Maybe it doesn't get freed, but what you see is a wild or a l=
arge
> > > > > > > out-of-bounds access. Since KASAN marks all memory as freed d=
uring the
> > > > > > > memblock->page_alloc transition, such bugs can manifest as
> > > > > > > use-after-frees.
> > > > > >=20
> > > > > > It gets freed and re-used. By the time the iBFT table is access=
ed by
> > > > > > ibft_init() the page has been over-written.
> > > > > >=20
> > > > > > Setting page flags like the following before the call to kmap()
> > > > > > prevents the iBFT table page from being freed:
> > > > >=20
> > > > > Cleaned up version:
> > > > >=20
> > > > > diff --git a/drivers/acpi/osl.c b/drivers/acpi/osl.c
> > > > > index 0418feb..8f0a8e7 100644
> > > > > --- a/drivers/acpi/osl.c
> > > > > +++ b/drivers/acpi/osl.c
> > > > > @@ -287,9 +287,12 @@ static void __iomem *acpi_map(acpi_physical_=
address
> > > > > pg_off, unsigned long pg_sz)
> > > > >=20
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
> > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_=
to_page(pfn);
> > > > > +
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 if (pg_sz > =
PAGE_SIZE)
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=
=C2=A0 return NULL;
> > > > > -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __for=
ce *)kmap(pfn_to_page(pfn));
> > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 SetPageReserved(page);
> > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return (void __iomem __for=
ce *)kmap(page);
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 } else
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 return acpi_=
os_ioremap(pg_off, pg_sz);
> > > > >   =C2=A0 =C2=A0}
> > > > > @@ -299,9 +302,12 @@ static void acpi_unmap(acpi_physical_address
> > > > > pg_off, void __iomem *vaddr)
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 unsigned long pfn;
> > > > >=20
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 pfn =3D pg_off >> PAGE_SHIFT;
> > > > > -=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn))
> > > > > -=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(pfn_to_page(pfn));
> > > > > -=C2=A0=C2=A0=C2=A0 else
> > > > > +=C2=A0=C2=A0=C2=A0 if (should_use_kmap(pfn)) {
> > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 struct page *page =3D pfn_=
to_page(pfn);
> > > > > +
> > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 ClearPageReserved(page);
> > > > > +=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 kunmap(page);
> > > > > +=C2=A0=C2=A0=C2=A0 } else
> > > > >   =C2=A0 =C2=A0=C2=A0=C2=A0=C2=A0 =C2=A0=C2=A0=C2=A0 iounmap(vadd=
r);
> > > > >   =C2=A0 =C2=A0}
> > > > >=20
> > > > > David, the above works, but wondering why it is now necessary. ku=
nmap()
> > > > > is not hit. What other ways could a page mapped via kmap() be unm=
apped?
> > > > >=20
> > > >=20
> > > > Let me look into the code ... I have little experience with ACPI
> > > > details, so bear with me.
> > > >=20
> > > > I assume that acpi_map()/acpi_unmap() map some firmware blob that i=
s
> > > > provided via firmware/bios/... to us.
> > > >=20
> > > > should_use_kmap() tells us whether
> > > > a) we have a "struct page" and should kmap() that one
> > > > b) we don't have a "struct page" and should ioremap.
> > > >=20
> > > > As it is a blob, the firmware should always reserve that memory reg=
ion
> > > > via memblock (e.g., memblock_reserve()), such that we either
> > > > 1) don't create a memmap ("struct page") at all (-> case b) )
> > > > 2) if we have to create e memmap, we mark the page PG_reserved and
> > > >   =C2=A0=C2=A0 *never* expose it to the buddy (-> case a) )
> > > >=20
> > > >=20
> > > > Are you telling me that in this case we might have a memmap for the=
 HW
> > > > blob that is *not* PG_reserved? In that case it most probably got
> > > > exposed to the buddy where it can happily get allocated/freed.
> > > >=20
> > > > The latent BUG would be that that blob gets exposed to the system l=
ike
> > > > ordinary RAM, and not reserved via memblock early during boot.
> > > > Assuming that blob has a low physical address, with my patch it wil=
l
> > > > get allocated/used a lot earlier - which would mean we trigger this
> > > > latent BUG now more easily.
> > > >=20
> > > > There have been similar latent BUGs on ARM boards that my patch
> > > > discovered where special RAM regions did not get marked as reserved
> > > > via the device tree properly.
> > > >=20
> > > > Now, this is just a wild guess :) Can you dump the page when mappin=
g
> > > > (before PageReserved()) and when unmapping, to see what the state o=
f
> > > > that memmap is?
> > >=20
> > > Thank you David for the explanation and your help on this,
> > >=20
> > > dump_page() before PageReserved and before kmap() in the above patch:
> > >=20
> > > [=C2=A0=C2=A0=C2=A0 1.116480] ACPI: Core revision 20201113
> > > [=C2=A0=C2=A0=C2=A0 1.117628] XXX acpi_map: about to call kmap()...
> > > [=C2=A0=C2=A0=C2=A0 1.118561] page:ffffea0002f914c0 refcount:0 mapcou=
nt:0
> > > mapping:0000000000000000 index:0x0 pfn:0xbe453
> > > [=C2=A0=C2=A0=C2=A0 1.120381] flags: 0xfffffc0000000()
> > > [=C2=A0=C2=A0=C2=A0 1.121116] raw: 000fffffc0000000 ffffea0002f914c8 =
ffffea0002f914c8
> > > 0000000000000000
> > > [=C2=A0=C2=A0=C2=A0 1.122638] raw: 0000000000000000 0000000000000000 =
00000000ffffffff
> > > 0000000000000000
> > > [=C2=A0=C2=A0=C2=A0 1.124146] page dumped because: acpi_map pre SetPa=
geReserved
> > >=20
> > > I also added dump_page() before unmapping, but it is not hit. The
> > > following for the same pfn now shows up I believe as a result of sett=
ing
> > > PageReserved:
> > >=20
> > > [=C2=A0=C2=A0 28.098208] BUG:Bad page state in process mo dprobe=C2=
=A0 pfn:be453
> > > [=C2=A0=C2=A0 28.098394] page:ffffea0002f914c0 refcount:0 mapcount:0
> > > mapping:0000000000000000 index:0x1 pfn:0xbe453
> > > [=C2=A0=C2=A0 28.098394] flags: 0xfffffc0001000(reserved)
> > > [=C2=A0=C2=A0 28.098394] raw: 000fffffc0001000 dead000000000100 dead0=
00000000122
> > > 0000000000000000
> > > [=C2=A0=C2=A0 28.098394] raw: 0000000000000001 0000000000000000 00000=
000ffffffff
> > > 0000000000000000
> > > [=C2=A0=C2=A0 28.098394] page dumped because: PAGE_FLAGS_CHECK_AT_PRE=
P flag(s) set
> > > [=C2=A0=C2=A0 28.098394] page_owner info is not present (never set?)
> > > [=C2=A0=C2=A0 28.098394] Modules linked in:
> > > [=C2=A0=C2=A0 28.098394] CPU: 2 PID: 204 Comm: modprobe Not tainted 5=
.11.0-3dbd5e3 #66
> > > [=C2=A0=C2=A0 28.098394] Hardware name: QEMU Standard PC (i440FX + PI=
IX, 1996),
> > > BIOS 0.0.0 02/06/2015
> > > [=C2=A0=C2=A0 28.098394] Call Trace:
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 dump_stack+0xdb/0x120
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 bad_page.cold.108+0xc6/0xcb
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 check_new_page_bad+0x47/0xa0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 get_page_from_freelist+0x30cd/0x5730
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __isolate_free_page+0x4f0/0x4f0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? init_object+0x7e/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 __alloc_pages_nodemask+0x2d8/0x650
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __alloc_pages_slowpath.constprop.103=
+0x2110/0x2110
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? __sanitizer_cov_trace_pc+0x21/0x50
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 alloc_pages_vma+0xe2/0x560
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 do_fault+0x194/0x12c0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 __handle_mm_fault+0x1650/0x26c0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? copy_page_range+0x1350/0x1350
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 handle_mm_fault+0x1f9/0x810
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 ? write_comp_data+0x2f/0x90
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 do_user_addr_fault+0x6f7/0xca0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 exc_page_fault+0xaf/0x1a0
> > > [=C2=A0=C2=A0 28.098394]=C2=A0 asm_exc_page_fault+0x1e/0x30
> > > [=C2=A0=C2=A0 28.098394] RIP: 0010:__clear_user+0x30/0x60
> >=20
> > I think the PAGE_FLAGS_CHECK_AT_PREP check in this instance means that
> > someone is trying to allocate that page with the PG_reserved bit set.
> > This means that the page actually was exposed to the buddy.
> >=20
> > However, when you SetPageReserved(), I don't think that PG_buddy is set
> > and the refcount is 0. That could indicate that the page is on the budd=
y
> > PCP list. Could be that it is getting reused a couple of times.
> >=20
> > The PFN 0xbe453 looks a little strange, though. Do we expect ACPI table=
s
> > close to 3 GiB ? No idea. Could it be that you are trying to map a wron=
g
> > table? Just a guess.

Nah, ACPI MADT enumerates the table and that is the proper location of it.
>=20
> ... but I assume ibft_check_device() would bail out on an invalid checksu=
m.
> So the question is, why is this page not properly marked as reserved
> already.

The ibft_check_device ends up being called as module way way after the
kernel has cleaned the memory.

The funny thing about iBFT is that (it is also mentioned in the spec)
that the table can resize in memory .. or in the ACPI regions (which
have no E820_RAM and are considered "MMIO" regions).

Either place is fine, so it can be in either RAM or MMIO :-(

>=20
> --=20
> Thanks,
>=20
> David / dhildenb
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20210222174036.GA399355%40fedora.
