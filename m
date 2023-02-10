Return-Path: <kasan-dev+bncBD52JJ7JXILRB4GDS6PQMGQEO4JC7TI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A51B691871
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 07:19:31 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id h16-20020a63df50000000b004f74bc0c71fsf2118692pgj.18
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 22:19:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676009969; cv=pass;
        d=google.com; s=arc-20160816;
        b=gK/GicENLX5kekxiFDd6fHyboo+xy/bK01ZwDUS/aIADSSUI/n4Ot1IA4Qgl2ewFCQ
         JTs0s9iVuwNfZqLVDuus1WICJXn9O7OyjAmseFB1sG1iRlUG6YXLj9IM0DT23Euon3Rt
         zt6io7blIPx/f/tw24U8I+edE4jq3FmFd4tq7+Ff6Do3g6V1FiuBC5jDWXlmYPxjjvGX
         YAbaVAaN00yZuuSWaLOJ30SJvlOsDHz5wTmX4GnShU29LzLfvoWjgANR/jQqL/HFdHdf
         CP84WbqTFmrI1VfAwbbemLSR4j1erAikMxpIoFB2r7Rn/kZkujZ7nvYyKa6NZ5ScdDIn
         3UzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=jtrHhBazH/V6J/xt+xJqYxuUn6AOxSHZ9E98KjAKWIQ=;
        b=p10LAppXoZVRMlx7gpzHL1R3nRerM12al+PQCD8OXZuZg3+t3MRB1HqsCVfdWpoxPv
         C+IiggagFaZ0ffdNO3xRJq7PzAnYFLv2HFcmVrrfRYPjE9wACouXOMfY57KcqEGy3XU9
         2Ytjeso83oPJETUbhU42N3FfhFw5/QeH+9Kcqko4Qv+di8Z+CLS3mSzdzSq7DrVrtg50
         3HqQEcoujufUNzrn+TwawdzSZHqdvedpQnedShSS2s0BCjoC5OG/dGbAkV/Vhchf9pOn
         J8NZO6K7DFWyrxicMjRtUlq7W2dUuwWZBKfI6tG+jpet50TK6feFJdozQBu588FCRdml
         1R1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LDs6u0nY;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=jtrHhBazH/V6J/xt+xJqYxuUn6AOxSHZ9E98KjAKWIQ=;
        b=bBJs4FCxJXewdD4GqjBbMxmDfspgvNo2SgWRC0/Dm4otM1ACr4cJt0+fjvXSsJKw10
         PWUJpwLWzYoWgukBjfWFHBMwn1QQQBfJcrKwE0RJrVXsN67n6RDC8WhI/ezCs8nFJ4dD
         J7mZh8FPyISJBf7hi9UdqT9qQZzf2oOR/PZBBWRgKMEdQFi+mkXAArccr8YgKcD71KFz
         in/qSCIicg1sOepftZ9TugTAcZza4WZqNo8tdCiHMyNz5f/rGywKOS78mti3BhMnxaxb
         OwZQ/jB/TivtsUOJQ1H04jE7MBbc+9LRNHg6I6BB8gYIB8f7NKS8InKNoXdwBipL95+K
         mgIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jtrHhBazH/V6J/xt+xJqYxuUn6AOxSHZ9E98KjAKWIQ=;
        b=M2RIP5yvJkdsOp5RHSXrC2CjpscBNJlJDLzmOwpQ2QTMA4lvLDqebEa4lCdrmb8cHl
         9twNnJaIxM9o1C5olHPMpSmBCQZdYcefspCi8GHJlNpJHuyhFCrAKICZGkv8HSr6zY8A
         YO1rAhPKhcptcBXrniptbXEbFdvgYBHLF/wvQ5CgLr0aqFYC8ZoFsCsYPU38EJYSrMXM
         CLpKdorCgBqsm/kfmiEIYexwYqPhl3Mkc/YqYIX70iQ5ozuQdZMyLOcUMBSTGo857yLd
         +ly50Pj62XbyNXGsbcNDmAoJ3zLPsBqtMgjb8Fde3ZXwmshoZX5hBcwRCIFHLRrNyzZU
         8KBw==
X-Gm-Message-State: AO0yUKXZJxmWwiQCj8tYylOroVSryUUUHGT11zweNUdOT6cXNzBXX3mQ
	ahvwQM8PYunVMFPlw2xJpHM=
X-Google-Smtp-Source: AK7set8El3nS7xwQyCRnCconiykWGVoaltNbbvtbatJbFqKtqZhX7UOwwO6sYrr7uLs4bUdciZVjjQ==
X-Received: by 2002:a62:6c2:0:b0:5a8:515a:eba2 with SMTP id 185-20020a6206c2000000b005a8515aeba2mr1157521pfg.2.1676009969065;
        Thu, 09 Feb 2023 22:19:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d650:b0:196:751e:4f6e with SMTP id
 y16-20020a170902d65000b00196751e4f6els4769485plh.10.-pod-prod-gmail; Thu, 09
 Feb 2023 22:19:28 -0800 (PST)
X-Received: by 2002:a17:90b:350f:b0:22e:61ad:19a4 with SMTP id ls15-20020a17090b350f00b0022e61ad19a4mr15679203pjb.39.1676009968263;
        Thu, 09 Feb 2023 22:19:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676009968; cv=none;
        d=google.com; s=arc-20160816;
        b=V2ZDxdE0SDRjPuo2wduxy3J/m8wsSnx3drxJuE1LP9fiidP+a6DuVqPI5VKZMzQzoZ
         BKIpFdAYzB3cJ85DnTbWzPJd6hMRXXgUHzzQ9wv5Xxx7u4bH6NC3eXvJm9ePMzoLxNwC
         ahei2DI8zAZEj10DdEgCN0MIGkAMuUmHbAJ4sMa1SHAq5odAy1nGlSRZmOI7fyt4shZg
         8UHYeKjV3TmGAp7shiAur3P8t392CYUuk/g1lU6/wVD89EXPO7xS2d/v3lapxxiVVFzb
         kZ7gF3xM/VzPy5qRNp9IlX8U95wBqzTCEdTaC9RGX3uQh/AF9eXqdoHCql5sqDMRkqBT
         5Y2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=/Dla9NFpkg9I5+DoaafZ7yizNZzus0cnFIKPt3aRDXE=;
        b=pti8bSNReqLY+9gN40/KaxYeVEykPu4ZuMxjpG9qKY9wTHAXJ7CoFz4sYuSXaaNkkz
         /Fyfn9EINTNYMdJ/r6bRir/+rtiiv3tSKco4vaYxUunewe/jkkoh79ajB2ErNjfEoeKJ
         +VlQcbz/ewXLthY/FB7Ergp1ERjjFDoX7Wu3YJnktehR9hYL39uLKTCc5n7BQZzi8URN
         uz5701hEV3486cB6tl4RAOeqtNL2DuiFeDR/OjqJ2Mh5bPX3hCH4dRZI9P+ByAc/nctF
         gYaH43Fthy+HJ8NimYhpkg8uDkGADp04pUvV/SsCou/OfkHIgU0ik2aeFyZV1MMKiRx/
         jIlA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=LDs6u0nY;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::102f as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x102f.google.com (mail-pj1-x102f.google.com. [2607:f8b0:4864:20::102f])
        by gmr-mx.google.com with ESMTPS id c24-20020a17090a8d1800b002309f8d0078si857740pjo.0.2023.02.09.22.19.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Feb 2023 22:19:28 -0800 (PST)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::102f as permitted sender) client-ip=2607:f8b0:4864:20::102f;
Received: by mail-pj1-x102f.google.com with SMTP id on9-20020a17090b1d0900b002300a96b358so4597139pjb.1
        for <kasan-dev@googlegroups.com>; Thu, 09 Feb 2023 22:19:28 -0800 (PST)
X-Received: by 2002:a17:903:48a:b0:198:af4f:de0f with SMTP id jj10-20020a170903048a00b00198af4fde0fmr94142plb.15.1676009967534;
        Thu, 09 Feb 2023 22:19:27 -0800 (PST)
Received: from google.com ([2620:15c:2d3:205:de7e:1ef:cb76:d198])
        by smtp.gmail.com with ESMTPSA id z5-20020a633305000000b00499bc49fb9csm2241572pgz.41.2023.02.09.22.19.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 09 Feb 2023 22:19:26 -0800 (PST)
Date: Thu, 9 Feb 2023 22:19:20 -0800
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
To: Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>
Cc: "andreyknvl@gmail.com" <andreyknvl@gmail.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Guangye Yang =?utf-8?B?KOadqOWFieS4mik=?= <guangye.yang@mediatek.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"catalin.marinas@arm.com" <catalin.marinas@arm.com>,
	"ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"vincenzo.frascino@arm.com" <vincenzo.frascino@arm.com>,
	"will@kernel.org" <will@kernel.org>
Subject: Re: [PATCH v2 0/4] kasan: Fix ordering between MTE tag colouring and
 page->flags
Message-ID: <Y+Xh6IuBFCYZhQIj@google.com>
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <66cc7277b0e9778ba33e8b22a4a51c19a50fe6f0.camel@mediatek.com>
 <CA+fCnZfu7SdVWr9O=NxOptuBg0eHqE526ijA4PAQgiAEYfux6A@mail.gmail.com>
 <eeceea66a86037c4ca2b8e0d663d5451becd60ea.camel@mediatek.com>
 <CA+fCnZfa=xcgL0RYwgf+kenLaKQX++UtiBghT_7mOginbmB+jA@mail.gmail.com>
 <a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <a16aa80c371a690a16e2d8bf679cb06153b5a73e.camel@mediatek.com>
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=LDs6u0nY;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::102f as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Wed, Feb 08, 2023 at 05:41:45AM +0000, Qun-wei Lin (=E6=9E=97=E7=BE=A4=
=E5=B4=B4) wrote:
> On Fri, 2023-02-03 at 18:51 +0100, Andrey Konovalov wrote:
> > On Fri, Feb 3, 2023 at 4:41 AM Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=E7=A9=
=8E)
> > <Kuan-Ying.Lee@mediatek.com> wrote:
> > >=20
> > > > Hi Kuan-Ying,
> > > >=20
> > > > There recently was a similar crash due to incorrectly implemented
> > > > sampling.
> > > >=20
> > > > Do you have the following patch in your tree?
> > > >=20
> > > >=20
> > >=20
> > >=20
> https://urldefense.com/v3/__https://android.googlesource.com/kernel/commo=
n/*/9f7f5a25f335e6e1484695da9180281a728db7e2__;Kw!!CTRNKA9wMg0ARbw!hUjRlXir=
PMSusdIWe0RIPt0PNqIHYDCJyd7GSd4o-TgLMP0CKRUkjElH-jcvtaz42-sgE2U58964rCCbuNT=
JE5Jx$
> > > >=20
> > > >=20
> > > > If not, please sync your 6.1 tree with the Android common kernel.
> > > > Hopefully this will fix the issue.
> > > >=20
> > > > Thanks!
> > >=20
> > > Hi Andrey,
> > >=20
> > > Thanks for your advice.
> > >=20
> > > I saw this patch is to fix ("kasan: allow sampling page_alloc
> > > allocations for HW_TAGS").
> > >=20
> > > But our 6.1 tree doesn't have following two commits now.
> > > ("FROMGIT: kasan: allow sampling page_alloc allocations for
> > > HW_TAGS")
> > > (FROMLIST: kasan: reset page tags properly with sampling)
> >=20
> > Hi Kuan-Ying,
> >=20
>=20
> Hi Andrey,
> I'll stand in for Kuan-Ying as he's out of office.
> Thanks for your help!
>=20
> > Just to clarify: these two patches were applied twice: once here on
> > Jan 13:
> >=20
> >=20
> https://urldefense.com/v3/__https://android.googlesource.com/kernel/commo=
n/*/a2a9e34d164e90fc08d35fd097a164b9101d72ef__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmu=
nRcQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745_3o=
O-3k$=C2=A0
> > =20
> >=20
> https://urldefense.com/v3/__https://android.googlesource.com/kernel/commo=
n/*/435e2a6a6c8ba8d0eb55f9aaade53e7a3957322b__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmu=
nRcQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745sDE=
OYWY$=C2=A0
> > =20
> >=20
>=20
> Our codebase does not contain these two patches.
>=20
> > but then reverted here on Jan 20:
> >=20
> >=20
> https://urldefense.com/v3/__https://android.googlesource.com/kernel/commo=
n/*/5503dbe454478fe54b9cac3fc52d4477f52efdc9__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmu=
nRcQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745Bl7=
7dFY$=C2=A0
> > =20
> >=20
> https://urldefense.com/v3/__https://android.googlesource.com/kernel/commo=
n/*/4573a3cf7e18735a477845426238d46d96426bb6__;Kw!!CTRNKA9wMg0ARbw!kE1XiSmu=
nRcQb9rTpKGkFc1EFJA57qr1cj7v9EZAjUBzXcSzMl-ofCI2mdtEQsxn3J4n7Lkgxb0_G745K-J=
8O-w$=C2=A0
> > =20
> >=20
> > And then once again via the link I sent before together with a fix on
> > Jan 25.
> >=20
> > It might be that you still have to former two patches in your tree if
> > you synced it before the revert.
> >=20
> > However, if this is not the case:
> >=20
> > Which 6.1 commit is your tree based on?
>=20
>=20
> https://android.googlesource.com/kernel/common/+/53b3a7721b7aec74d8fa2ee5=
5c2480044cc7c1b8
> (53b3a77 Merge 6.1.1 into android14-6.1) is the latest commit in our
> tree.
>=20
> > Do you have any private MTE-related changes in the kernel?
>=20
> No, all the MTE-related code is the same as Android Common Kernel.
>=20
> > Do you have userspace MTE enabled?
>=20
> Yes, we have enabled MTE for both EL1 and EL0.

Hi Qun-wei,

Thanks for the information. We encountered a similar issue internally
with the Android 5.15 common kernel. We tracked it down to an issue
with page migration, where the source page was a userspace page with
MTE tags, and the target page was allocated using KASAN (i.e. having
a non-zero KASAN tag). This caused tag check faults when the page was
subsequently accessed by the kernel as a result of the mismatching tags
from userspace. Given the number of different ways that page migration
target pages can be allocated, the simplest fix that we could think of
was to synchronize the KASAN tag in copy_highpage().

Can you try the patch below and let us know whether it fixes the issue?

diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
index 24913271e898c..87ed38e9747bd 100644
--- a/arch/arm64/mm/copypage.c
+++ b/arch/arm64/mm/copypage.c
@@ -23,6 +23,8 @@ void copy_highpage(struct page *to, struct page *from)
=20
 	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
 		set_bit(PG_mte_tagged, &to->flags);
+		if (kasan_hw_tags_enabled())
+			page_kasan_tag_set(to, page_kasan_tag(from));
 		mte_copy_page_tags(kto, kfrom);
 	}
 }

Catalin, please let us know what you think of the patch above. It
effectively partially undoes commit 20794545c146 ("arm64: kasan: Revert
"arm64: mte: reset the page tag in page->flags""), but this seems okay
to me because the mentioned race condition shouldn't affect "new" pages
such as those being used as migration targets. The smp_wmb() that was
there before doesn't seem necessary for the same reason.

If the patch is okay, we should apply it to the 6.1 stable kernel. The
problem appears to be "fixed" in the mainline kernel because of
a bad merge conflict resolution on my part; when I rebased commit
e059853d14ca ("arm64: mte: Fix/clarify the PG_mte_tagged semantics")
past commit 20794545c146, it looks like I accidentally brought back the
page_kasan_tag_reset() line removed in the latter. But we should align
the mainline kernel with whatever we decide to do on 6.1.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/Y%2BXh6IuBFCYZhQIj%40google.com.
