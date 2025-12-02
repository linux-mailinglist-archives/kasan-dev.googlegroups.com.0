Return-Path: <kasan-dev+bncBDCPL7WX3MKBB27JXXEQMGQENR36KOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3A257C9D539
	for <lists+kasan-dev@lfdr.de>; Wed, 03 Dec 2025 00:23:47 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-8823f71756dsf75950126d6.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Dec 2025 15:23:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764717804; cv=pass;
        d=google.com; s=arc-20240605;
        b=FNAz0bMUPh4tgV2coGcE45R3NQGlmVA8nA8QO1fOTPBD6FYZ7+DG66dyEGfL6VFqK3
         tZLC1CczfYigK/zfDB9NnCudf/M8RA+TWmxW9pD4iWiQ8qParqyhsIsajD78g1K0D5HW
         sfVsZ162HD8wnUEsn1d8oeNAt3dMtk1ANebZItdK6C9+f8XFYecpcIHF2hfhxRe3rnR6
         WPWZJVQCOj5a+o8kGEXcXGfaPAOuFQuNnFVZZ5zETCnzXKaHiFFTGrxTMfi0IIzqllmX
         y9scpfORBsPOl8C03DE1KzcLdmI4i1mK7i9JPLDMVNdGrLv32H0LhKmpfqtR8LbS3+Ev
         aWwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=0jzBGyWmyBIbyR/4PPe2pPaJjUanKr7YMN8REFbza+U=;
        fh=k5SMMiyGsPHzNBWbIrGO4DNMlFAbGaGk5q1HrjVr0D0=;
        b=WXqXYXZrQTNQRWSC3Fva/zVDGfc9dxdy+ENYsMIDOCrkjFBi9lkvvmNPsYuRncj2EX
         RX5IDJoPB0aSmYrKEPkrAmPlZma5I/fdg1Kplv0jYU/OERaV88OauaSbsQ0fKS4SJufs
         cmEBiQ76SxHFnlCZhAwPs6tsg405aTSGoqyABUJ7iKR5koEdcHfN2Ls0l9b0WqLbTTxj
         fT76DDVffbbrnXrpq+LYiHShRp1ZR2IpImUdgCxwSXHf5d0VnHDXS+EUScroV3Ozuurf
         u7cUkxODYHNIKOCdTempZM9vTWFNpj7mLhcOdzv2NzgkiXTC5kv+hrZRJ1kkdu1EnnOF
         gBGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j1+RzGCp;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764717804; x=1765322604; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0jzBGyWmyBIbyR/4PPe2pPaJjUanKr7YMN8REFbza+U=;
        b=PrpRN1fEBNccqezA4wVAHlvIqntuT7TX6RQLpwNy0v/oFIEvYqucdNQTOt447ZG+lW
         kMLTyUWZve4aOUSl+uAZHb6tmT1qePv+M0HJ+58amvyQuN78Dqd3CsK8paVOad+L/UM3
         qQacWGZQMtfCtvcITrpmdwtwLgU6Cw4iyZOX2pRi36tpaU3Jv3Bpq8n1hCOe9mxpbsPy
         Y5YM/Bi98RQH/bbeWaSGRrzHPbPIQQ0d4Z2ZumikhsQYFE7ZjKtBmZUv4JeL3rDZea6T
         rugDsFkzIC08ZgR63UG199lIeRaNOt2dW9Ybw8o38/YOMre9cJBsroxVG4KTX5UmDJkM
         SP5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764717804; x=1765322604;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=0jzBGyWmyBIbyR/4PPe2pPaJjUanKr7YMN8REFbza+U=;
        b=wnmFZ1RXZderDw0n3VwijcJRA1YuVN9SSjNS0i3tquihPmw7oDpZEZqvXp6vlUnrf2
         d7jyvMzeY9R0rSjVZbsDSWPW/RBl5ajYZLAQdju6Ag5nkDzWdiOmYnXbYcXcXqbK3oJI
         nJ9u2AKWdaEfM+sldJJymTS0RLMe170GY4Fe4f/RjOgKtgFaFl8XSfdurwlAdMPmni1q
         PGUEtrkBGGy0UfNapVrhaQAcOWo+gNPnNaPpV2hmFEVjoPfZi++kUPCvtLwCJkVJA8zB
         aBG+BalmSATHwhmWlvVMLAm8o3qujgIFP8yR/I9pkRgI3yBeszRB9C6PqdKV2BGbS4tK
         /fbQ==
X-Forwarded-Encrypted: i=2; AJvYcCU4XihK4LP0WglVrFflCDkCCZS/kDrgQ9KBI5Mc3rDAms174LywkDrDTH3O8COPws64DLaltA==@lfdr.de
X-Gm-Message-State: AOJu0YyhfwryzUUOsRwW2nuLnFkDkt2e6fiWZXtF7HCTQ4maOD8S7Y8m
	OtoWjyYMJSVm0EdPlZ/VsBCm7bVfNOYbSNUMDaACc+TpMJPgJiQ0KXqo
X-Google-Smtp-Source: AGHT+IG8NbbSSkip88dq6C7kYe0pw1nYztktY2fw089Ryk07RlYKhJD93ro4XbiirYeexfQe5yETUw==
X-Received: by 2002:a05:6214:2486:b0:880:621e:3b4a with SMTP id 6a1803df08f44-88819496d60mr4087226d6.11.1764717804488;
        Tue, 02 Dec 2025 15:23:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Y8JnfTwFD/ItcKdoeEHlBtoTaMJ8aXfkj/5pDBQuW5DQ=="
Received: by 2002:a0c:f14d:0:20b0:882:4be6:9ace with SMTP id
 6a1803df08f44-8864f8bcdb4ls70044386d6.1.-pod-prod-08-us; Tue, 02 Dec 2025
 15:23:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV+sUR0MMDLecKVfXksMHE4pQbsbVxkbpkvfr2rnO6eci75YySiet9otAQw/HZ6IGygQQqhDV8lWew=@googlegroups.com
X-Received: by 2002:a05:6122:3307:b0:557:d6d4:2f51 with SMTP id 71dfb90a1353d-55e5be89c3emr149244e0c.8.1764717802858;
        Tue, 02 Dec 2025 15:23:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764717802; cv=none;
        d=google.com; s=arc-20240605;
        b=KL2yjuBuGpE/LiYVODGTu4lr0LTmzUaKn1Hy2WgJSKs1lMjqvH4YraGIcVhHU0U5cw
         scZVbKcEhs8ONIVzFTkX97qh2ZrlBhPjm8Hf0/exVI49E7NEyDA25sH3PuFMDlk02YA5
         QdN1/BnxWEBgmNj/uap6oHjoZPFAZ9odoAk5BHyzPShUh4ixfwmOXDIpPFetizv4YfaQ
         qNjheMuE3/AiKkqK+hdYq/NccWVdYi1EWTMody2qtuHyTMykIngHz359r8YkjO3Hmej8
         mDqhVgDWJhGBy6gJl85VkHEZIAJiAOl5OIDAPU5/mEDHY3PCgrkXFQCIAZVVDSvG/4KW
         0zRw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=wvBqm8+lzXFa5X/EA075FJ2SCYaupMK+njsfDl+P8ak=;
        fh=wekz6SndFESddiivQLPFblS4MidHD5DMDIcR0GGJ8FM=;
        b=LKpGQYvx4rch5xzw22MneJ0elhWFbSG3qru0HJJIF0NYSygwT9c6kiVt6/3VjgE/T2
         sAHvLwpmZ6lNlSV3E7d44/gwKatnzsArVLQrIyVo+vesyscHc33fXd49vPRrnK56E694
         mqXMb010xycw4NOHjJQZ4HIb7bPLq84po5LrOIB4LSeBzKMcDHyuAeUzaNrVj067/B7w
         IyLE32b+dl2PxfbaKLWuQldKMvo7o86IWq4B4P5/jIVT5VPwCYrktN28ZB64EXOiw1Vq
         H68rglMxTjGAioRwHPEL3Te0TByGCrOue0S0hOHgaA6zTZruB47PGjPq6ltqbD/SEisa
         qbAw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j1+RzGCp;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-55e5d5988d5si812e0c.3.2025.12.02.15.23.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Dec 2025 15:23:22 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 1E9EC60144;
	Tue,  2 Dec 2025 23:23:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C042DC4CEF1;
	Tue,  2 Dec 2025 23:23:21 +0000 (UTC)
Date: Tue, 2 Dec 2025 15:23:21 -0800
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jiayuan Chen <jiayuan.chen@linux.dev>
Cc: linux-mm@kvack.org,
	syzbot+997752115a851cb0cf36@syzkaller.appspotmail.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>,
	Danilo Krummrich <dakr@kernel.org>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v1] mm/kasan: Fix incorrect unpoisoning in vrealloc for
 KASAN
Message-ID: <202512021522.7888E2B6@keescook>
References: <20251128111516.244497-1-jiayuan.chen@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20251128111516.244497-1-jiayuan.chen@linux.dev>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=j1+RzGCp;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Fri, Nov 28, 2025 at 07:15:14PM +0800, Jiayuan Chen wrote:
> Syzkaller reported a memory out-of-bounds bug [1]. This patch fixes two
> issues:
>=20
> 1. In vrealloc, we were missing the KASAN_VMALLOC_VM_ALLOC flag when
>    unpoisoning the extended region. This flag is required to correctly
>    associate the allocation with KASAN's vmalloc tracking.
>=20
>    Note: In contrast, vzalloc (via __vmalloc_node_range_noprof) explicitl=
y
>    sets KASAN_VMALLOC_VM_ALLOC and calls kasan_unpoison_vmalloc() with it=
.
>    vrealloc must behave consistently =E2=80=94 especially when reusing ex=
isting
>    vmalloc regions =E2=80=94 to ensure KASAN can track allocations correc=
tly.
>=20
> 2. When vrealloc reuses an existing vmalloc region (without allocating ne=
w
>    pages), KASAN previously generated a new tag, which broke tag-based
>    memory access tracking. We now add a 'reuse_tag' parameter to
>    __kasan_unpoison_vmalloc() to preserve the original tag in such cases.
>=20
> A new helper kasan_unpoison_vralloc() is introduced to handle this reuse
> scenario, ensuring consistent tag behavior during reallocation.
>=20
> [1]: https://syzkaller.appspot.com/bug?extid=3D997752115a851cb0cf36
>=20
> Fixes: a0309faf1cb0 ("mm: vmalloc: support more granular vrealloc() sizin=
g")

Is this the right Fixes tag? I didn't change the kasan logic meaningfully
in the above patch, perhaps it should be commit d699440f58ce ("mm:
fix vrealloc()'s KASAN poisoning logic")

--=20
Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
02512021522.7888E2B6%40keescook.
