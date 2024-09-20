Return-Path: <kasan-dev+bncBCZP5TXROEINZONUW4DBUBAE2VU24@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id C52CD97D15E
	for <lists+kasan-dev@lfdr.de>; Fri, 20 Sep 2024 08:57:33 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e1ce191f74fsf3503868276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 23:57:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726815452; cv=pass;
        d=google.com; s=arc-20240605;
        b=ILBkJ8t6LZCs1/H9FqiHOaBIrGrs4T9+jV4we+mbtrizDl9Q23lIxZwvEam41rZ8Kz
         BwRgHmTdQZqFIcE023jqZO71DqQtw1OZ83LMHChHgYPLOcGX5XwjpXQefKTwIYpd81uN
         OILDkewVeCdXilkF7fK0uDWg8qH5so6Ws6GGviozjDUQnUgw26e1scxUn0dsXLx7fV+y
         gAUigNTlLlysBvpnZ5LDTXPi5ywrnNT0BHapN+YZ3Ak01G+gU+OdwhLtMGuuk3RhG3tG
         M4pVw6Oku2WjClRrMcpK8AQUr7xbDxmPv5EYBp+L2VPVqtSS3oePXGyYOje+jGrloNGs
         foSQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=Fo0j1cZ1i9dsh0ckNU4w5JmfkUgwfQR4Kvtbuab3FWI=;
        fh=yC0R9aW3Y/g8VJwXMrtimgdWDxzEX+WsfyeUO2/mqHg=;
        b=BJdErTlnAa/zHdLGs2HIhUOAP4NuU3XMYyMHOPRhBP3AsQoHsa3RSx3MbapX8EQRQ4
         vfmF96S2fzXULx43Np3iAztkiI2JssDRYtqkojk5K/RkEkfD8Rz6c6JSVnWYW0iwTURz
         rBEa2Razly/tOwh4VV424pNw22b2Nomrpex56UwQxaJ1iq3QJ6y7H04EaceZNiSOcZZe
         iM8/rCvR/oYZ3jBF9ajIc3C8XaY8ikClF1MbQQTTTkHIyn372bDzBdd56eXfy58ZrKOo
         bvENedCPfO5kpnzfoQdebhvD0nefvan+kdhVqkPP0QaXTzmzb6qWn3/f2XhLHlI8NSJ/
         FClA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726815452; x=1727420252; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Fo0j1cZ1i9dsh0ckNU4w5JmfkUgwfQR4Kvtbuab3FWI=;
        b=kX0hecMLFa/zUhyBUZpzVRwnfxF+MUTF48HKEXJRV4k43omgZplRpXSZxPYeeIsiE+
         rm1oQ67fEEu5krTVTDreMkpqmQfJ+NeztAQL3Ggl15dB7dEeKG4oY1SAEiVUFSwKlnqw
         Tz3yi57RTYybdI8tKZ2TIw0rrmOQbzLHx3YC6eRSNhmjCyXEUKk+JyOQw66I8rOi4L8t
         YzkMyKthYmv0yH/13skivTJI4wGbQotx1rXIF5b37CQ8neZqn/atpN/lWx+D4/sMCgYY
         QuAMRztkl6ApOVzmm+V1w7hVfn50UiVBFnrCo5tBSw/JGkpHYRYFf/T+jCBpa+LJ4cPW
         93GA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726815452; x=1727420252;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fo0j1cZ1i9dsh0ckNU4w5JmfkUgwfQR4Kvtbuab3FWI=;
        b=IgBUQkJXaIeTnBYqTnu94oLd/l/DuyqOk2w9e33sCS2iBpKA40lXPy8FgPbYPTQYpQ
         xni3m/Rq/nCSPPJCWnUg4Nf5/x7gt8S31G0rOfnw7l/CQAoOA2x+U3ad989OHwgSLZLg
         PgexAS9dT6ZkWvKji250Zmdqiq2jNt4aqQvepy1i3C9TANPktNPA93qTmKg19lkuQ41M
         s2UUAdy9t0C0Fh78g5LFwZl0QCoQjne2zh5EFlAsS0qPJ1aIPW9VL9gRt5wIAlFQck4X
         /J280Fbch4mCZR0HQ3UnS7jdnnqEQdxb5Jc89QSEhfXLhTa3d3EfZ4p5MPcKhsy+afxP
         uMjw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqmTU8wn09HATLsZU0zMCo0xAteWlkfFP28t74dT3elwkxIGkZHUiN8AhJVsDKkT9LGEQJVA==@lfdr.de
X-Gm-Message-State: AOJu0YwFC3wLTb50gntU7gaVZqIvPmaZzLjZ+vsi6/pGf54FPJ9yO/IP
	wQd0RRIIdL2SMj88wphdIgxERmTA7e7Tu4PQpV09Shx7kP6EoSWl
X-Google-Smtp-Source: AGHT+IE5bNQCTvIn92BX2kXL6385uBSfli8S+TDmM7/LzSfGq9XICSazHGmz1XHFJEzv6FcJptmodQ==
X-Received: by 2002:a05:6902:120f:b0:e0b:b2a7:d145 with SMTP id 3f1490d57ef6-e2250ce4575mr1594573276.55.1726815452278;
        Thu, 19 Sep 2024 23:57:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:c7c6:0:b0:e22:59c6:5d26 with SMTP id 3f1490d57ef6-e2259c65fd2ls109783276.2.-pod-prod-01-us;
 Thu, 19 Sep 2024 23:57:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdJQHoGPgzOKmxUaE6tmzbF763fBT8D72cA/GtJ9EAABzJI45edRjQex1x+b5jWrlSNPDQzN9A7fU=@googlegroups.com
X-Received: by 2002:a05:690c:38b:b0:664:7fb6:a5f9 with SMTP id 00721157ae682-6dfeed61a27mr22759467b3.21.1726815451410;
        Thu, 19 Sep 2024 23:57:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726815451; cv=none;
        d=google.com; s=arc-20240605;
        b=FNkM0URq7qpkXhHIL5sSC/xG1tmlnC/jsnkjW8D8QMigREb690XjD4C+zum2vMF93M
         XKHjwYIb9ZY7nhXThliw2G/Kd87tdfYeTIE391/KeK1UUZONKJflI9NU843vJ5XYI/KW
         LTmfLXOa2MKnTnlY+ReaD8QmWmIqWocUtafKDXe3YWtAepQPr5SqZeF0/eZg9x+PKMrK
         AwB1V4x/jvL6Yivot9Dtuf85ZbNMaTzUMsNDxLwvF9X2fcRuYoxk8J54j22lgZomQEE5
         947m+g/i8DIe45K8n980QpKp9f8RN8RsbVPVFtq6cGV/VcH+cbx+oMvXpoZnBPqatTdY
         V2/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=RQ6h6fwYmYOO6/JWb/UQia9oNQ5fEUDap9PwoZTqzLQ=;
        fh=GF0OURt1aobVVYo7M3iRXWSqWc1A5XkS9a4tiebN1YY=;
        b=jMilH6BqjOC60pm/cJkMZljkdlZTSy5rNWiLYq9fwM7797mWGtwlQcmwvwzoTnajuf
         xi0S87vC5OktTFZhju9JAJ6Sk8Ig4DokCv2lQeTy7AjTK0XysrEYQLGLDgpJEML8vYmV
         +6f5nyz/HfudU2ZH3orDYWzcBoeZIotTR2q0cg65t2lUtl6yvaUkxapejaYqTnD1pYKg
         wJRowHWWrjFl9Ks10nEd8lgGj0doN/rm86suvDbZNrc8o4dhfjxv5O3USZdqu27XP/3s
         AM6ZVxG8xZJ+hvpfSh0YZmZGHQv+irJazRa9ZIvTWoUCyVucA2orCfkmdnyndPWOZIVQ
         MZsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=ryan.roberts@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 00721157ae682-6dbe2ab5736si8235617b3.0.2024.09.19.23.57.31
        for <kasan-dev@googlegroups.com>;
        Thu, 19 Sep 2024 23:57:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 17D7EFEC;
	Thu, 19 Sep 2024 23:58:00 -0700 (PDT)
Received: from [10.57.83.252] (unknown [10.57.83.252])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 887063F64C;
	Thu, 19 Sep 2024 23:57:25 -0700 (PDT)
Message-ID: <9e68ffad-8a7e-40d7-a6f3-fa989a834068@arm.com>
Date: Fri, 20 Sep 2024 08:57:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH V2 7/7] mm: Use pgdp_get() for accessing PGD entries
Content-Language: en-GB
To: "Russell King (Oracle)" <linux@armlinux.org.uk>
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
 kernel test robot <lkp@intel.com>, linux-mm@kvack.org, llvm@lists.linux.dev,
 oe-kbuild-all@lists.linux.dev, Andrew Morton <akpm@linux-foundation.org>,
 David Hildenbrand <david@redhat.com>, "Mike Rapoport (IBM)"
 <rppt@kernel.org>, Arnd Bergmann <arnd@arndb.de>, x86@kernel.org,
 linux-m68k@lists.linux-m68k.org, linux-fsdevel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 linux-perf-users@vger.kernel.org, Dimitri Sivanich
 <dimitri.sivanich@hpe.com>, Alexander Viro <viro@zeniv.linux.org.uk>,
 Muchun Song <muchun.song@linux.dev>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Miaohe Lin <linmiaohe@huawei.com>,
 Dennis Zhou <dennis@kernel.org>, Tejun Heo <tj@kernel.org>,
 Christoph Lameter <cl@linux-foundation.org>,
 Uladzislau Rezki <urezki@gmail.com>, Christoph Hellwig <hch@infradead.org>
References: <20240917073117.1531207-8-anshuman.khandual@arm.com>
 <202409190310.ViHBRe12-lkp@intel.com>
 <8f43251a-5418-4c54-a9b0-29a6e9edd879@arm.com>
 <ZuvqpvJ6ht4LCuB+@shell.armlinux.org.uk>
 <82fa108e-5b15-435a-8b61-6253766c7d88@arm.com>
 <ZuxZ/QeSdqTHtfmw@shell.armlinux.org.uk>
 <5bd51798-cb47-4a7b-be40-554b5a821fe7@arm.com>
 <ZuyIwdnbYcm3ZkkB@shell.armlinux.org.uk>
From: Ryan Roberts <ryan.roberts@arm.com>
In-Reply-To: <ZuyIwdnbYcm3ZkkB@shell.armlinux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ryan.roberts@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ryan.roberts@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=ryan.roberts@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

On 19/09/2024 21:25, Russell King (Oracle) wrote:
> On Thu, Sep 19, 2024 at 07:49:09PM +0200, Ryan Roberts wrote:
>> On 19/09/2024 18:06, Russell King (Oracle) wrote:
>>> On Thu, Sep 19, 2024 at 05:48:58PM +0200, Ryan Roberts wrote:
>>>>> 32-bit arm uses, in some circumstances, an array because each level 1
>>>>> page table entry is actually two descriptors. It needs to be this way
>>>>> because each level 2 table pointed to by each level 1 entry has 256
>>>>> entries, meaning it only occupies 1024 bytes in a 4096 byte page.
>>>>>
>>>>> In order to cut down on the wastage, treat the level 1 page table as
>>>>> groups of two entries, which point to two consecutive 1024 byte table=
s
>>>>> in the level 2 page.
>>>>>
>>>>> The level 2 entry isn't suitable for the kernel's use cases (there ar=
e
>>>>> no bits to represent accessed/dirty and other important stuff that th=
e
>>>>> Linux MM wants) so we maintain the hardware page tables and a separat=
e
>>>>> set that Linux uses in the same page. Again, the software tables are
>>>>> consecutive, so from Linux's perspective, the level 2 page tables
>>>>> have 512 entries in them and occupy one full page.
>>>>>
>>>>> This is documented in arch/arm/include/asm/pgtable-2level.h
>>>>>
>>>>> However, what this means is that from the software perspective, the
>>>>> level 1 page table descriptors are an array of two entries, both of
>>>>> which need to be setup when creating a level 2 page table, but only
>>>>> the first one should ever be dereferenced when walking the tables,
>>>>> otherwise the code that walks the second level of page table entries
>>>>> will walk off the end of the software table into the actual hardware
>>>>> descriptors.
>>>>>
>>>>> I've no idea what the idea is behind introducing pgd_get() and what
>>>>> it's semantics are, so I can't comment further.
>>>>
>>>> The helper is intended to read the value of the entry pointed to by th=
e passed
>>>> in pointer. And it shoiuld be read in a "single copy atomic" manner, m=
eaning no
>>>> tearing. Further, the PTL is expected to be held when calling the gett=
er. If the
>>>> HW can write to the entry such that its racing with the lock holder (i=
.e. HW
>>>> update of access/dirty) then READ_ONCE() should be suitable for most
>>>> architectures. If there is no possibility of racing (because HW doesn'=
t write to
>>>> the entry), then a simple dereference would be sufficient, I think (wh=
ich is
>>>> what the core code was already doing in most cases).
>>>
>>> The core code should be making no access to the PGD entries on 32-bit
>>> ARM since the PGD level does not exist. Writes are done at PMD level
>>> in arch code. Reads are done by core code at PMD level.
>>>
>>> It feels to me like pgd_get() just doesn't fit the model to which 32-bi=
t
>>> ARM was designed to use decades ago, so I want full details about what
>>> pgd_get() is going to be used for and how it is going to be used,
>>> because I feel completely in the dark over this new development. I fear
>>> that someone hasn't understood the Linux page table model if they're
>>> wanting to access stuff at levels that effectively "aren't implemented"
>>> in the architecture specific kernel model of the page tables.
>>
>> This change isn't as big and scary as I think you fear.
>=20
> The situation is as I state above. Core code must _not_ dereference pgd
> pointers on 32-bit ARM.

Let's just rewind a bit. This thread exists because the kernel test robot f=
ailed
to compile pgd_none_or_clear_bad() (a core-mm function) for the arm archite=
cture
after Anshuman changed the direct pgd dereference to pgdp_get(). The reason
compilation failed is because arm defines its own pgdp_get() override, but =
it is
broken (there is a typo).

Code before Anshuman's change:

static inline int pgd_none_or_clear_bad(pgd_t *pgd)
{
	if (pgd_none(*pgd))
		return 1;
	if (unlikely(pgd_bad(*pgd))) {
		pgd_clear_bad(pgd);
		return 1;
	}
	return 0;
}

Code after Anshuman's change:

static inline int pgd_none_or_clear_bad(pgd_t *pgd)
{
	pgd_t old_pgd =3D pgdp_get(pgd);

	if (pgd_none(old_pgd))
		return 1;
	if (unlikely(pgd_bad(old_pgd))) {
		pgd_clear_bad(pgd);
		return 1;
	}
	return 0;
}

So the kernel _is_ alreday dereferencing pgd pointers for the arm arch, and=
 has
been since the beginning of (git) time. Note that pgd_none_or_clear_bad() i=
s
called from core code and from arm arch code.

As an aside, the kernel also dereferences p4d, pud, pmd and pte pointers in
various circumstances. And other changes in this series are also replacing =
those
direct dereferences with calls to similar helpers. The fact that these are =
all
folded (by a custom arm implementation if I've understood the below correct=
ly)
just means that each dereference is returning what you would call the pmd f=
rom
the HW perspective, I think?

>=20
>> The core-mm today
>> dereferences pgd pointers (and p4d, pud, pmd pointers) directly in its c=
ode. See
>> follow_pfnmap_start(),
>=20
> Doesn't seem to exist at least not in 6.11.

Appologies, I'm on mm-unstable and that isn't upstream yet. See follow_pte(=
) in
v6.11 or __apply_to_page_range(), or pgd_none_or_clear_bad() as per above.

>=20
>> gup_fast_pgd_leaf(), and many other sites.
>=20
> Only built when CONFIG_HAVE_GUP_FAST is set, which 32-bit ARM doesn't
> set because its meaningless there, except when LPAE is in use (which is
> basically the situation I'm discussing.)
>=20
>> These changes
>> aim to abstract those dereferences into an inline function that the arch=
itecture
>> can override and implement if it so wishes.
>>
>> The core-mm implements default versions of these helper functions which =
do
>> READ_ONCE(), but does not currently use them consistently.
>>
>> From Anshuman's comments earlier in this thread, it looked to me like th=
e arm
>> pgd_t type is too big to read with READ_ONCE() - it can't be atomically =
read on
>> that arch. So my proposal was to implement the override for arm to do ex=
actly
>> what the core-mm used to do, which is a pointer dereference. So that wou=
ld
>> result in exact same behaviour for the arm arch.
>=20
> Let me say this again: core code must NOT dereference pgds on 32-bit
> non-LPAE ARM. They are meaningless to core code. A pgd_t does not
> reference a single entry in hardware. It references two entries.

OK, so there are 3 options; either I have misunderstood what the core code =
is
doing (because as per above, I'm asserting that core code _is_ dereferencin=
g pgd
pointers), or the core code is dereferencing and that is buggy, or the core=
 code
is derefencing and its working as designed. I believe its the latter, but a=
m
willing to be proved wrong.

>=20
>>> Essentially, on 32-bit 2-level ARM, the PGD is merely indexed by the
>>> virtual address. As far as the kernel is concerned, each entry is
>>> 64-bit, and the generic kernel code has no business accessing that
>>> through the pgd pointer.
>>>
>>> The pgd pointer is passed through the PUD and PMD levels, where it is
>>> typecast down through the kernel layers to a pmd_t pointer, where it
>>> becomes a 32-bit quantity. This results in only the _first_ level 1
>>> pointer being dereferenced by kernel code to a 32-bit pmd_t quantity.
>>> pmd_page_vaddr() converts this pmd_t quantity to a pte pointer (which
>>> points at the software level 2 page tables, not the hardware page
>>> tables.)
>>
>> As an aside, my understanding of Linux's pgtable model differs from what=
 you
>> describe. As I understand it, Linux's logical page table model has 5 lev=
els
>> (pgd, p4d, pud, pmd, pte). If an arch doesn't support all 5 levels, then=
 the
>> middle levels can be folded away (p4d first, then pud, then pmd). But th=
e
>> core-mm still logically walks all 5 levels. So if the HW supports 2 leve=
ls,
>> those levels are (pgd, pte). But you are suggesting that arm exposes pmd=
 and
>> pte, which is not what Linux expects? (Perhaps you call it the pmd in th=
e arch,
>> but that is being folded and accessed through the pgd helpers in core co=
de, I
>> believe?
>=20
> What ARM does dates from before the Linux MM invented the current
> "folding" method when we had three page table levels - pgd, pmd
> and pte. The current folding techniques were invented well after
> 32-bit ARM was implemented, which was using the original idea of
> how to fold the page tables.
>=20
> The new folding came up with a totally different way of doing it,
> and I looked into converting 32-bit ARM over to it, but it wasn't
> possible to do so with the need for two level-1 entries to be
> managed for each level-2 page table.
>=20
>>> So, as I'm now being told that the kernel wants to dereference the
>>> pgd level despite the model I describe above, alarm bells are ringing.
>>> I want full information please.
>>>
>>
>> This is not new; the kernel already dereferences the pgd pointers.
>=20
> Consider that 32-bit ARM has been this way for decades (Linux was ported
> to 32-bit ARM by me back in the 1990s - so it's about 30 years old.)
> Compare that to what you're stating is "not new"... I beg to differ with
> your opinion on what is new and what isn't. It's all about the relative
> time.

By "not new" I meant that it's not introduced by this series. The kernel's
dereferencing of pgd pointers was present before this series came along.

>=20
> This is how the page tables are walked:
>=20
> static inline pgd_t *pgd_offset_pgd(pgd_t *pgd, unsigned long address)
> {
>         return (pgd + pgd_index(address));
> }
>=20
> #define pgd_offset(mm, address)         pgd_offset_pgd((mm)->pgd, (addres=
s))
>=20
> This returns a pointer to the pgd. This is then used with p4d_offset()
> when walking the next level, and this is defined on 32-bit ARM from
> include/asm-generic/pgtable-nop4d.h:
>=20
> static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
> {
>         return (p4d_t *)pgd;
> }
>=20
> Then from include/asm-generic/pgtable-nopud.h:
>=20
> static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
> {
>         return (pud_t *)p4d;
> }
>=20
> Then from arch/arm/include/asm/pgtable-2level.h:
>=20
> static inline pmd_t *pmd_offset(pud_t *pud, unsigned long addr)
> {
>         return (pmd_t *)pud;
> }
>=20
> All of the above casts result in the pgd_t pointer being cast down
> to a pmd_t pointer.
>=20
> Now, looking at stuff in mm/memory.c such as unmap_page_range().
>=20
>         pgd =3D pgd_offset(vma->vm_mm, addr);
>=20
> This gets the pgd pointer into the level 1 page tables associated
> with addr, and passes it down to zap_p4d_range().
>=20
> That passes it to p4d_offset() without dereferencing it, which on
> 32-bit ARM, merely casts the pgd_t pointer to a p4d_t pointer. Since
> a p4d_t is defined to be a struct of a pgd_t, this also points at an
> array of two 32-bit quantities. This pointer is passed down to
> zap_pud_range().
>=20
> zap_pud_range() passes this pointer to pud_offset(), again without
> dereferencing it, and we end up with a pud_t pointer. Since pud_t is
> defined to be a struct of p4d_t, this also points to an array of two
> 32-bit quantities.
>=20
> We then have:
>=20
>                 if (pud_trans_huge(*pud) || pud_devmap(*pud)) {
>=20
> These is an implicit memory copy/access between the memory pointed to
> by pud, and their destination (which might be a register). However,
> these are optimised away because 32-bit ARM doesn't set
> HAVE_ARCH_TRANSPARENT_HUGEPAGE_PUD nor ARCH_HAS_PTE_DEVMAP (as
> neither inline function make use of their argument.)
>=20
> NOTE: If making these use READ_ONCE results in an access that can not
> be optimised away, that is a bug that needs to be addressed.
>=20
> zap_pud_range() then passes the pud pointer to zap_pmd_range().
>=20
> zap_pmd_range() passes this pointer to pud_offset() with no further
> dereferences, and this gets cast to a pmd_t pointer, which is a
> pointer to the first 32-bit quantity pointed to by the pgd_t pointer.
>=20
> All the dereferences from this point on are 32-bit which can be done
> as single-copy atomic accesses. This will be the first real access
> to the level-1 page tables in this code path as the code stands today,
> and from this point on, accesses to the page tables are as the
> architecture intends them to be.
>=20
>=20
> Now, realise that for all of the accesses above that have all been
> optimised away, none of that code even existed when 32-bit ARM was
> using this method. The addition of these features not intefering
> with the way 32-bit non-LPAE ARM works relies on all of those
> accesses being optimised away, and they need to continue to be so
> going forward.
>=20
>=20
> Maybe that means that this new (and I mean new in relative terms
> compared to the age of the 32-bit ARM code) pgdp_get() accessor
> needs to be a non-dereferencing operation, so something like:
>=20
> #define pgdp_get(pgdp)		((pgd_t){ })

I'm afraid I haven't digested all these arm-specific details. But if I'm ri=
ght
that the core kernel does and is correct to dereference pgd pointers for th=
ese
non-LPAE arm builds, then I think you at least need arm's implementation to=
 be:

#define pgdp_get(pgdp)		(*pgdp)

Thanks,
Ryan

>=20
> in arch/arm/include/asm/pgtable-2level.h (note the corrected
> spelling of pgdp), and the existing pgdp_get() moved to
> arch/arm/include/asm/pgtable-3level.h. This isn't tested.
>=20
> However, let me say this again... without knowing exactly how
> and where pgdp_get() is intended to be used, I'm clutching at
> straws here. Even looking at Linus' tree, there's very little in
> evidence there to suggest how pgdp_get() is intended to be used.
> For example, there's no references to it in mm/.
>=20
>=20
> Please realise that I have _no_ _clue_ what "[PATCH V2 7/7] mm: Use
> pgdp_get() for accessing PGD entries" is proposing. I wasn't on its
> Cc list. I haven't seen the patch. The first I knew anything about
> this was with the email that Anshuman Khandual sent in response to
> the kernel build bot's build error.

Here is the full series for context:

https://lore.kernel.org/linux-mm/20240917073117.1531207-1-anshuman.khandual=
@arm.com/

>=20
> I'm afraid that the kernel build bot's build error means that this
> patch:
>=20
> commit eba2591d99d1f14a04c8a8a845ab0795b93f5646
> Author: Alexandre Ghiti <alexghiti@rivosinc.com>
> Date:   Wed Dec 13 21:29:59 2023 +0100
>=20
>     mm: Introduce pudp/p4dp/pgdp_get() functions
>=20
> is actually broken. I'm sorry that I didn't review that, but how the
> series looked when it landed in my mailbox, it looked like it was
> specific to RISC-V and of no interest to me, so I didn't bother
> reading it (I get _lots_ of email, I can't read everything.) This
> is how it looks like in my mailbox (and note that they're marked
> as new to this day):
>=20
> 3218 N T Dec 13 Alexandre Ghiti (   0) [PATCH v2 0/4] riscv: Use READ_ONC=
E()/WRI
> 3219 N T Dec 13 Alexandre Ghiti (   0) =E2=94=9C=E2=94=80>[PATCH v2 1/4] =
riscv: Use WRITE_ONCE()
> 3220 N T Dec 13 Alexandre Ghiti (   0) =E2=94=9C=E2=94=80>[PATCH v2 2/4] =
mm: Introduce pudp/p4dp
> 3221 N T Dec 13 Alexandre Ghiti (   0) =E2=94=9C=E2=94=80>[PATCH v2 3/4] =
riscv: mm: Only compile
> 3222 N T Dec 13 Alexandre Ghiti (   0) =E2=94=94=E2=94=80>[PATCH v2 4/4] =
riscv: Use accessors to
> 3223 N C Dec 14 Anup Patel      (   0)   =E2=94=94=E2=94=80>
>=20
> Sorry, but I'm not even going to look at something like that when it
> looks like it's for RISC-V and nothing else.
>=20
> One final point... because I'm sure someone's going to say "but you
> were in the To: header". I've long since given up using "am I in the
> Cc/To header" to carry any useful or meaningful information to
> indicate whether it's something I should read. I'm afraid that the
> kernel community has long since taught me that is of no value what
> so ever, so I merely go by "does this look of any interest". If not,
> I don't bother even _opening_ the email.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9e68ffad-8a7e-40d7-a6f3-fa989a834068%40arm.com.
