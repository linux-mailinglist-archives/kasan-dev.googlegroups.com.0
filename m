Return-Path: <kasan-dev+bncBD53XBUFWQDBBRGC2XEAMGQE7EGCLIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A298C55AB1
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Nov 2025 05:40:38 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-4e88947a773sf16248131cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Nov 2025 20:40:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763008837; cv=pass;
        d=google.com; s=arc-20240605;
        b=CeAn+c3VVwGNe+JHj6/8NV0Eror9zC0tAmuaavLkUh4KLd3M1WhtopL8e5U+cHcfIL
         QvBLTMriCk8OXRdmyHf80qUHU64T+EGYFqTVT0OGUFEOS1CnWnzoiBG3sr6Y0STfL4R2
         RSABlnZ9NDQH1l4Uf8HL565V0dw2m1Fqa6X7Sp7DSjxndd/zJk55ozznKnsZIUo0dSQn
         hVNxllFGA6VZOe8ngDlV3w+Z8hIDBZZRvriYWpmzBXt1vFZj1/BE9nH15BUIDF+0v1vU
         A5l4s6InF6eGVc/Wc+S28AmwjRwE3Alj55Wrm/0UlmYhH2Ts0NPo0vbQgIXud9bcSpyx
         q/rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=3QsBtQIYU6goBXDUMr/nsD3cXsgGhTPnETJI/WELJCM=;
        fh=PfALkE2pLj09ZjbejbZp3vge/kUmI9ylIDZBG9T/YNw=;
        b=iP61wX2naRwYq8qV4ws4FaxF9NJvLfyE92QSnaCQR6f1QXYtsYVbzvfuyhYr7u82Bh
         gsDCpkzWbaO8axMpgmJLtQtHQugpvovUrVTK0M6PMLZdpDhfDMSJ6rOXu2ifC2P2pNHZ
         BajShBoTDCQ/CJvRVh8As/DZqdYT3nn3IdgwjtFHQLdw3f6jR2gF9wQdbC9LROmCgJF1
         wJhG6UkEJ7ul9sWiehr6IpJQpl8GVktZqbTyin5/fsDHNqeFrLQnEKS6b8oG5F/ty8gE
         pxR4J2RMLlMLtnb0M9uqrk88c+gjFMi2hoN8mQqc1yJvwzHIhmJfNm50TZmvpVJWP7ud
         CerQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a9JMBYBC;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763008837; x=1763613637; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=3QsBtQIYU6goBXDUMr/nsD3cXsgGhTPnETJI/WELJCM=;
        b=B7oa4o2GCiukSXdaDwl2kyvVW/v94eZ/fze2uoWNhNf2+F+3G5ZaK64gr77oXnIdzK
         buVP4xhSmmXEngDY5KmA4ZazEYNpL+kncG/ACuq/vhUs2oThTbZ2PM7RbrqUfSlQdEAi
         VIQvzDC1EPBlFW6bzLTf1Oqa3ZLElxeTADn3InXF1nTLhHIiEddyNTrt/je+lr3hkM+F
         XRHPxCtZejucmTWldAi7/VjHXkUYKLyjtKpwGurLB1YWQaXq37u7ecB+Cboguqv0osvC
         6wYtuL5h8Ulr7fY2DoBeEok4BkkNRlIAnh2/2yxMjDorwr/yv20ufLpwmLMb0PICLqOc
         27Wg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1763008837; x=1763613637; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3QsBtQIYU6goBXDUMr/nsD3cXsgGhTPnETJI/WELJCM=;
        b=Wr4GmSAaQ81SF2XNaNeDndiv6UAiRoR7WZaOBheRgISuLsSB6qFtemhIql+L15ut7F
         xwSxO8iGnxkrI5hjlr8ictG0xZs2icLD73frXVBA9Nes8EeImq/u9RMGbd49ponvvKH0
         89GnKFBaLU6Ga7VX5wcDOfqoi4JMZ0CqBz4g2N1PFEZ5Mp1bEtS0FdFopiRj368alCvP
         viHrvhCPQdc5Qq+AuSt3lYWkwNUWXsuck5cKQNmrh5XqUYIvtGXOnqNCABItLuvbO4Nc
         sW6SaxerCwiWy0ikbc5NpBuucKn1wQyoBhIN4RZ5j6UOD120eJr6NJ1am2wDOahsK4kC
         bkhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763008837; x=1763613637;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=3QsBtQIYU6goBXDUMr/nsD3cXsgGhTPnETJI/WELJCM=;
        b=ofrKmANaALcExwHUG8/8uFjuWiCQ1I4eGaNVNYi8fbnuiH1aULYYHih1eeRnVkXVGk
         bO+WJp7sRmK7drGwndG9kwUesd8N4AozmXluPBTWFWm9yrjoId5i59ObyajsJAKZ/in/
         pcAb26Q/mNbk4vBSMFG88NUKswEBPxrkt7vYjNbDS1ZdhTv19eWApx62i3WIxUa2pVed
         S0IoQerQ8tf7lTFqkNanZedmtHGT1RmHRS1/NfVausjBGvH0EyZlB6L7SgCZvn8LDzLz
         K5RDze7uz44MuKut8iHVrdx54c+bLPKrA0+hLsgnqshuRmbAiLm6A2zzBPmDr34GRo5b
         mJyw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXa0SNRVW3qK/BL6y/rL1AN5sEqAljE69oO/LOZiqmbmmKgDLZv0BzpFgKfrTWZPcz190+xew==@lfdr.de
X-Gm-Message-State: AOJu0YyF9WMFgDudZ5Ro7jJHuNqdt+ip50/q9EME6ciydmCHhLvqmam9
	iCLC+bUcmYRGNVMjtAPA2z9IUoD0v0sLBFsNwe3nRjNUIX91p+X48Ir9
X-Google-Smtp-Source: AGHT+IHp5vsUm9DQniEkf63X3xg5oJ3cKfUMu3C7vxzFjXUJP6lAXJw1FQh1zxjAkghmk+2Q1IIATw==
X-Received: by 2002:ac8:5e11:0:b0:4ed:b4ae:f5bb with SMTP id d75a77b69052e-4eddbdb5c31mr71840031cf.65.1763008836968;
        Wed, 12 Nov 2025 20:40:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+belsYsHZcUIXGAtrrbJK8Mhqc/29HM8xykTK3vV70ZwQ=="
Received: by 2002:ac8:5905:0:b0:4ed:79e0:cd99 with SMTP id d75a77b69052e-4ede6b96641ls10264381cf.0.-pod-prod-06-us;
 Wed, 12 Nov 2025 20:40:35 -0800 (PST)
X-Received: by 2002:a05:620a:191b:b0:891:5527:8ef9 with SMTP id af79cd13be357-8b29b7679d4mr715205885a.20.1763008835504;
        Wed, 12 Nov 2025 20:40:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763008835; cv=none;
        d=google.com; s=arc-20240605;
        b=hWoOoY0dcF6X54jSLYTznbIPusyEuli6ELOYyFVs/P0rS84ecL4094vkMIx4pZd6Zf
         /ESzzyxN4bfHv1ybODLsJ3EXXjUPf0p8NuPr4j6sZVkz5D2snLAk1rIHUPruM98mIksq
         ArwAtSarGCcLvtRZA/MIf5PueW6VOjGJluaGksKBOuEAb/WSpazZ04Z9wdmDngfAVmIN
         9A9uz/OHwMoML3fs9fI4on/tPZAE1YVIT5UCYkUv/3DcHut3phd8k4K5Q50lVRTJ00Xb
         E6Z+JYV6J72OFokw4yXWuxCDgipsGOl6G58sLrE+6cr+iWhPwcZrFP8/lNpTsXmKlN+9
         mFiw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=FDmPn0Nf9DwhMNzLqfPhzr9P36pEvch2Q8c/oMsgpUY=;
        fh=S3vLt38ePgqDicWj+a+7/q9C4Av2wAu4t144BReYX0o=;
        b=RhXVZlIvQ9pkAz294Z/7ng4TV5QcaYzpMANRI2QaoLhmpeIxI8gHgO9wcT2tNxt5oA
         G4UnUjiNQf2KtsP2o8Lc0Ma8UyxwslkbJQ5M+X7y1dNckIj7F86EI66WvjZnkdiAUF0D
         trGIK6AmeofwaV9iWBUv2jNhqnFMjAG0pDx20LNyPdnNJ7YoIIqOLqk3e3s7Fu2vpl4x
         Ik+7YNajivHg25D8hF9E0RBu3J4smSoyFCLzpEMOcwBRZVopzKsrRcFShSHrEPFNl6g+
         4O0+GbX2wR19TBXJeeCW/gEr48wHu6wALOe+my4meVZVU/D7WBeYjIU3pAvz9iYsh/Xd
         fsSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=a9JMBYBC;
       spf=pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8b2aeccda28si992185a.0.2025.11.12.20.40.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Nov 2025 20:40:35 -0800 (PST)
Received-SPF: pass (google.com: domain of wangjinchao600@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-297f35be2ffso5422465ad.2
        for <kasan-dev@googlegroups.com>; Wed, 12 Nov 2025 20:40:35 -0800 (PST)
X-Gm-Gg: ASbGncuQuk6qZ8oZ/s1nsJyVQMAYJfhJwC6idZly4yQQLkznnzFaHFQ4J/gKVkZMT4N
	scTfs35ygoqogiz193SlC872gKa1kpc8fOdJX+mA5rTWIZYTHc4jFuGQ09re6lVYe73uaas9kaf
	rfKFWFnCGs/eS2mBi55ykc02x4XBvJM/i6A7nIa4WIPS65W6jSQtoNtfvGK82SmqiUQu49G2tyw
	CAnYqkfhERm6V+jeICJ9dpqGORqXTSMTENtLc6NyHc6DN69ruALq8JL0DAdOqNybA3T8DhVFJXX
	NU/0mgEMpxRMaUp+LHPAp47n3PCtYol1Z6hOYKwpuI7podW+axhB6L2oY0BvOBK9772AoVYwm9p
	o9Q7kBNe4rfJA688u2zt+DujjE1MbnNOuv+1qzV60mzZ9O9QyuQCmO9fm6PRj9fcHBja6tS/bF0
	ZKAmG7DDaz2UT4gWVOI+MEgA==
X-Received: by 2002:a17:902:e788:b0:297:e69d:86ac with SMTP id d9443c01a7336-2984edc8d1bmr74152995ad.39.1763008834480;
        Wed, 12 Nov 2025 20:40:34 -0800 (PST)
Received: from localhost ([45.8.220.62])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2985c2b0d68sm8683655ad.61.2025.11.12.20.40.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Nov 2025 20:40:33 -0800 (PST)
Date: Thu, 13 Nov 2025 12:40:30 +0800
From: Jinchao Wang <wangjinchao600@gmail.com>
To: Matthew Wilcox <willy@infradead.org>
Cc: kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-perf-users@vger.kernel.org,
	linux-trace-kernel@vger.kernel.org, llvm@lists.linux.dev,
	workflows@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/27] mm/ksw: Introduce KStackWatch debugging tool
Message-ID: <aRVhL91rSZXyZ83D@ndev>
References: <20251110163634.3686676-1-wangjinchao600@gmail.com>
 <aRIh4pBs7KCDhQOp@casper.infradead.org>
 <aRLmGxKVvfl5N792@ndev>
 <aRTv0eHfX0j8vJOW@casper.infradead.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <aRTv0eHfX0j8vJOW@casper.infradead.org>
X-Original-Sender: wangjinchao600@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=a9JMBYBC;       spf=pass
 (google.com: domain of wangjinchao600@gmail.com designates
 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=wangjinchao600@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Nov 12, 2025 at 08:36:33PM +0000, Matthew Wilcox wrote:
> [dropping all the individual email addresses; leaving only the
> mailing lists]
>=20
> On Wed, Nov 12, 2025 at 10:14:29AM +0800, Jinchao Wang wrote:
> > On Mon, Nov 10, 2025 at 05:33:22PM +0000, Matthew Wilcox wrote:
> > > On Tue, Nov 11, 2025 at 12:35:55AM +0800, Jinchao Wang wrote:
> > > > Earlier this year, I debugged a stack corruption panic that reveale=
d the
> > > > limitations of existing debugging tools. The bug persisted for 739 =
days
> > > > before being fixed (CVE-2025-22036), and my reproduction scenario
> > > > differed from the CVE report=E2=80=94highlighting how unpredictably=
 these bugs
> > > > manifest.
> > >=20
> > > Well, this demonstrates the dangers of keeping this problem siloed
> > > within your own exfat group.  The fix made in 1bb7ff4204b6 is wrong!
> > > It was fixed properly in 7375f22495e7 which lists its Fixes: as
> > > Linux-2.6.12-rc2, but that's simply the beginning of git history.
> > > It's actually been there since v2.4.6.4 where it's documented as simp=
ly:
> > >=20
> > >       - some subtle fs/buffer.c race conditions (Andrew Morton, me)
> > >=20
> > > As far as I can tell the changes made in 1bb7ff4204b6 should be
> > > reverted.
> >=20
> > Thank you for the correction and the detailed history. I wasn't aware t=
his
> > dated back to v2.4.6.4. I'm not part of the exfat group; I simply
> > encountered a bug that 1bb7ff4204b6 happened to resolve in my scenario.
> > The timeline actually illustrates the exact problem KStackWatch address=
es:
> > a bug introduced in 2001, partially addressed in 2025, then properly fi=
xed
> > months later. The 24-year gap suggests these silent stack corruptions a=
re
> > extremely difficult to locate.
>=20
> I think that's a misdiagnosis caused by not understanding the limited
> circumstances in which the problem occurs.  To hit this problem, you
> have to have a buffer_head allocated on the stack.  That doesn't happen
> in many places:
>=20
> fs/buffer.c:    struct buffer_head tmp =3D {
> fs/direct-io.c: struct buffer_head map_bh =3D { 0, };
> fs/ext2/super.c:        struct buffer_head tmp_bh;
> fs/ext2/super.c:        struct buffer_head tmp_bh;
> fs/ext4/mballoc-test.c: struct buffer_head bitmap_bh;
> fs/ext4/mballoc-test.c: struct buffer_head gd_bh;
> fs/gfs2/bmap.c: struct buffer_head bh;
> fs/gfs2/bmap.c: struct buffer_head bh;
> fs/isofs/inode.c:       struct buffer_head dummy;
> fs/jfs/super.c: struct buffer_head tmp_bh;
> fs/jfs/super.c: struct buffer_head tmp_bh;
> fs/mpage.c:     struct buffer_head map_bh;
> fs/mpage.c:     struct buffer_head map_bh;
>=20
> It's far more common for buffer_heads to be allocated from slab and
> attached to folios.  The other necessary condition to hit this problem
> is that get_block() has to actually read the data from disk.  That's
> not normal either!  Most filesystems just fill in the metadata about
> the block and defer the actual read to when the data is wanted.  That's
> the high-performance way to do it.
>=20
> So our opportunity to catch this bug was highly limited by the fact that
> we just don't run the codepaths that would allow it to trigger.
>=20
> > > > Initially, I enabled KASAN, but the bug did not reproduce. Reviewin=
g the
> > > > code in __blk_flush_plug(), I found it difficult to trace all logic
> > > > paths due to indirect function calls through function pointers.
> > >=20
> > > So why is the solution here not simply to fix KASAN instead of this
> > > giant patch series?
> >=20
> > KASAN caught 7375f22495e7 because put_bh() accessed bh->b_count after
> > wait_on_buffer() of another thread returned=E2=80=94the stack was inval=
id.
> > In 1bb7ff4204b6 and my case, corruption occurred before the victim
> > function of another thread returned. The stack remained valid to KASAN,
> > so no warning triggered. This is timing-dependent, not a KASAN deficien=
cy.
>=20
> I agree that it's a narrow race window, but nevertheless KASAN did catch
> it with ntfs and not with exfat.  The KASAN documentation states that
> it can catch this kind of bug:
>=20
> Generic KASAN supports finding bugs in all of slab, page_alloc, vmap, vma=
lloc,
> stack, and global memory.
>=20
> Software Tag-Based KASAN supports slab, page_alloc, vmalloc, and stack me=
mory.
>=20
> Hardware Tag-Based KASAN supports slab, page_alloc, and non-executable vm=
alloc
> memory.
>=20
> (hm, were you using hwkasan instead of swkasan, and that's why you
> couldn't see it?)
>=20
You're right that these conditions are narrow. However, when these bugs
hit, they're severe and extremely difficult to debug. This year alone,
this specific buffer_head bug was hit at least twice: 1bb7ff4204b6 and my
case. Over 24 years, others likely encountered it but lacked tools to
pinpoint the root cause.

I used software KASAN for the exfat case, but the bug didn't reproduce,
likely due to timing changes from the overhead. More fundamentally, the
corruption was in-bounds within active stack frames, which KASAN cannot
detect by design.

Beyond buffer_head, I encountered another stack corruption bug in network
drivers this year. Without KStackWatch, I had to manually instrument the
code to locate where corruption occurred.

These issues may be more common than they appear. Given Linux's massive
user base combined with the kernel's huge codebase and the large volume of
driver code, both in-tree and out-of-tree, even narrow conditions will be
hit.

Since posting earlier versions, several developers have contacted me about
using KStackWatch for their own issues. KStackWatch fills a gap: it can
pinpoint in-bounds stack corruption with much lower overhead than KASAN.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
RVhL91rSZXyZ83D%40ndev.
