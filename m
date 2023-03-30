Return-Path: <kasan-dev+bncBDDL3KWR4EBRBD4RS6QQMGQECUZAFLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 91EA06D0CF2
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 19:36:16 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id d5-20020adfa345000000b002d716fc080fsf2142229wrb.22
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Mar 2023 10:36:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680197776; cv=pass;
        d=google.com; s=arc-20160816;
        b=zVipHQ1oc4vzxaINhZp0GNxCu1CcSENa5qRSBiO2zNf26mMIG0YsJzAUdWK6CqqZsY
         5fwlO32Ib+6krIFdrty8Bvl+Gpfrop0hWqo8yaqfV5qWHbu/UnqUcSBG6PwNXFp46htu
         1N5pIMRgn7HU/ApD4WkUP+CXBYEpBYkMy6HmP+RJzqeKnAlT+F3kgO2Kh6ofdvdL6OZe
         hGqHhK9hyWGXKcqXh9089mbIWMmzCJdBpyDd3ybUsSU8ANx7Ap6KpEFEX510KrkJrdH6
         ciQUHW02F4lPMconMpGiyXSGRrCBwQjz8Mx6ZJ/38tRU/zAmeGiH8U/KMiVk/kvADjzE
         imDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=KUonZr+ooP92Z0BPKdJgZfFX1ZPJSb9xt34NyAltPHQ=;
        b=Udo+zlIHD50wsYnvYsB7bpE9HFI9pDpQkDjxmCwfj3NdOu3q78puGC88kI228vQV0k
         9UkggXrtaSvgv14hTdjfII6Vdp1NXWwbkzKNHqvfpu11Q6YuuKed/K7RmjVagAA+IhQ6
         tkkXoVpDFVBzAZyO953CSqe86clX3GLRYOZC6MMC8mxYafdbXW4ajegCQ9ZsCUqmNdG6
         pq/f+wvv3pYTHZ3fJsJ5roiMYq/RQC9u+xdAZVFUQOnypp1M1TteTQOH+OIXJD9nsD1v
         +m4/FSconwEzKU5PSw1PYPjxW5he9WACmht9aeQbCaqhfNlBut6bAgVahq7lhQZao1MQ
         sRRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680197776;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KUonZr+ooP92Z0BPKdJgZfFX1ZPJSb9xt34NyAltPHQ=;
        b=I4uXMvsalvR8nRKTPToY21mlG1zK9s7PZzqu9qTIUfYTexu7gWIaQ7PxN5rfcfhQT1
         IUoNbccEU9aAArq/iv9R7Qv4jfhfieHvIYyuQR5dSfi+7c28SBgBm4dflRqJrgpojmM1
         VavB+95KSvXh8d9XPwcreeq9TqPtMHjffCr/owmDKmsn+ySjAjW+/lLfzrGqhy3Z2iMi
         9mfAS2QD1BBAlF7ZvrwewDfl7KoU5IKhdeFrBx5FruVTlm6RE0V0XqiDVYiodAa8WJVd
         YYsyzuJ5GlHxsCJSdqVoofOBIODUonEOodlYF65rlYqsquXyceUymxCQ0xTTYMcF3I3z
         gCKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680197776;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KUonZr+ooP92Z0BPKdJgZfFX1ZPJSb9xt34NyAltPHQ=;
        b=Zd2VrDToc0E1xgxWHcrZ9uh7cs73qZznhPU+bhs/qyDIou09HqeyKOo65aC/TCjblO
         kUvlrBYp9BPs7dJ2fhaGlB/Rs7ByN1TxAFtW9w0wafdWHQeHulOEyfY1ttoVRd7qZ3Ds
         D/r6vsClF6jg76Dt0nvA6mj8YwB26DL0WhPgaQopyCycSVfeYtGFMEa+t6jNbnt9e7yd
         gk2Gpfr60YzeauOd9V/6yWx2fjl6UxPdVqwQCd4kk4AIHXZljpD1XjuqRLM+X4b0MbeI
         MHnbFUpKndY19Rd5noca/1cc2rCH222+jVsxiItlL+r4EbnJIDAj9+/nMeIqx1PS2mJK
         a4xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dvUUNm/7cAEzZK77eu7EWQCfjQfaJGSqGGL3eXNVdeqguqMnEF
	OS6Uqgt0hERD3pzShqfiMSw=
X-Google-Smtp-Source: AKy350b/XIPQ349yYsoeOyCZ+6fXIW4OYdu4ewybDu5fax3pk6uHD1PlcaDyogLiCte23Q4j0EHEuQ==
X-Received: by 2002:a05:600c:20a:b0:3f0:39db:2c78 with SMTP id 10-20020a05600c020a00b003f039db2c78mr568038wmi.7.1680197775902;
        Thu, 30 Mar 2023 10:36:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:79c:b0:2d0:a74b:1d65 with SMTP id
 bu28-20020a056000079c00b002d0a74b1d65ls104826wrb.1.-pod-prod-gmail; Thu, 30
 Mar 2023 10:36:14 -0700 (PDT)
X-Received: by 2002:adf:dbc1:0:b0:2e4:fe3e:8590 with SMTP id e1-20020adfdbc1000000b002e4fe3e8590mr1978726wrj.19.1680197774376;
        Thu, 30 Mar 2023 10:36:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680197774; cv=none;
        d=google.com; s=arc-20160816;
        b=Fld3ATmWM3UMisM3AtyHkPVXQU3DbO6eR8j4Fpf+QXV6RAJIHeIV/xRd2dXe1vi+QG
         +IYB1Xsb4HtyqrdE2BHpvl2BYtfNW5B8GzU1//M9Ts/GboTLMTbBFraZAqExboZ5SjAe
         uoBAWXnQPpPObGTZAZ79tBLgDdEqf2ANd+ee/SeSnUuFCOgcjKjRgZFfWXjcwiSoJadD
         QdJ9LIALxZ47TBmpmrH4dovloUCKuiB+dua9lfXIdUIi2rJrhC/JcaLmHHzY4BNmlZGK
         21qJPDtUutbaUXLtS1FMysBCT2AmNC50PtkWbZ7zTYvV+Ouv2qx0G2GP5AA49NVGlqWt
         2Skg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=FBtNuWw+wF4D9IE00grL+pO/d/DypJsFApa227hRub0=;
        b=uiKz2YqtnvLp4bWq/Qtth4btJxhXpLiPwR1JO5ZUGyF3v23150zy8VgcP2dLxjIesB
         4RURR81CeMf3kywMwxbbkHAe7dKCJzCZtGQwwMf5YVOK8h8O04IlIilGwQVcLPYOobte
         QzvXlCYH8fe+GJ2MCeccpG7ZerGvSo4Ii04dCj4cX519gXR5h7pzSUJaeTWbB7ateIE/
         eTtzIBNSwGHx7pWZCHKBEAi9aZ1yYzxGAw2KEvvUz/KEnNeiNrbdW9C4FXJjNxhy4e7w
         BO2YfP8cKxoCoq4blUwMuWIeXX+HKDQia5bRFVcyOnuUjmxfj8TId4/rqZQLJPHkdgHq
         MqqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id bn30-20020a056000061e00b002ceac242c41si1820760wrb.4.2023.03.30.10.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 30 Mar 2023 10:36:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 16125B8233F;
	Thu, 30 Mar 2023 17:36:14 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D232BC433EF;
	Thu, 30 Mar 2023 17:36:10 +0000 (UTC)
Date: Thu, 30 Mar 2023 18:36:08 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Steven Price <steven.price@arm.com>
Cc: Qun-wei Lin =?utf-8?B?KOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>,
	"linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	"surenb@google.com" <surenb@google.com>,
	"david@redhat.com" <david@redhat.com>,
	Chinwen Chang =?utf-8?B?KOW8temMpuaWhyk=?= <chinwen.chang@mediatek.com>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	Kuan-Ying Lee =?utf-8?B?KOadjuWGoOepjik=?= <Kuan-Ying.Lee@mediatek.com>,
	Casper Li =?utf-8?B?KOadjuS4reamrik=?= <casper.li@mediatek.com>,
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>
Subject: Re: [BUG] Usersapce MTE error with allocation tag 0 when low on
 memory
Message-ID: <ZCXIiCtjFt19wBAM@arm.com>
References: <5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com>
 <ZCRtVW9Q0WOKEQVX@arm.com>
 <f468f934-40b6-3547-d3ea-88a0aac5bd6a@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <f468f934-40b6-3547-d3ea-88a0aac5bd6a@arm.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
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

On Thu, Mar 30, 2023 at 02:56:50PM +0100, Steven Price wrote:
> > On Wed, Mar 29, 2023 at 02:55:49AM +0000, Qun-wei Lin (=E6=9E=97=E7=BE=
=A4=E5=B4=B4) wrote:
> >> Having compared the differences between Kernel-5.15 and Kernel-6.1,
> >> We found the order of swap_free() and set_pte_at() is changed in
> >> do_swap_page().
> >>
> >> When fault in, do_swap_page() will call swap_free() first:
> >> do_swap_page() -> swap_free() -> __swap_entry_free() ->
> >> free_swap_slot() -> swapcache_free_entries() -> swap_entry_free() ->
> >> swap_range_free() -> arch_swap_invalidate_page() ->
> >> mte_invalidate_tags_area() ->  mte_invalidate_tags() -> xa_erase()
> >>
> >> and then call set_pte_at():
> >> do_swap_page() -> set_pte_at() -> __set_pte_at() -> mte_sync_tags() ->
> >> mte_sync_page_tags() -> mte_restore_tags() -> xa_load()
> >>
> >> This means that the swap slot is invalidated before pte mapping, and
> >> this will cause the mte tag in XArray to be released before tag
> >> restore.
>=20
> This analysis looks correct to me. The MTE swap code works on the
> assumption that the set_pte_at() will restore the tags to the page
> before the swap entry is removed. The reordering which has happened
> since has broken this assumption and as you observed can cause the tags
> to be unavailable by the time set_pte_at() is called.
>=20
> >> After I moved swap_free() to the next line of set_pte_at(), the proble=
m
> >> is disappeared.
> >>
> >> We suspect that the following patches, which have changed the order, d=
o
> >> not consider the mte tag restoring in page fault flow:
> >> https://lore.kernel.org/all/20220131162940.210846-5-david@redhat.com/
>=20
> I'm not sure I entirely follow the reasoning in this patch, so I'm not
> sure whether it's safe to just move swap_free() down to below
> set_pte_at() or if that reintroduces the information leak.
>=20
> I also wonder if sparc has a similar issue as the arch_do_swap()
> callback is located next to set_pte_at().

SPARC has a potential race here since the page is made visible to the
user but the tags are not restored yet (I raised this before). But even
ignoring this small window, arch_do_swap() needs to have the metadata
available.

> >> Any suggestion is appreciated.
>=20
> The other possibility is to add a(nother) callback for MTE in
> arch_do_swap() that calls mte_restore_tags() on the page before the
> swap_free() call rather than depending on the hook in set_pte_at().

I think we should move arch_do_swap_page() earlier before swap_free()
and in arm64 we copy the tags to pte_page(pte). I don't think SPARC
would have any issues with this change (and it also fixes their race).

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZCXIiCtjFt19wBAM%40arm.com.
