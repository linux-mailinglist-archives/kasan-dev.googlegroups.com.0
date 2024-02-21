Return-Path: <kasan-dev+bncBDCLJAGETYJBBXU33CXAMGQE7D43XQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 4273685E03C
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 15:51:12 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id d9443c01a7336-1d542680c9csf89953565ad.2
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 06:51:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708527070; cv=pass;
        d=google.com; s=arc-20160816;
        b=wGacWyncnOV09YaViEELTT59Nf7Imcxi54AhiehwlvFrJerpelkQvfiPkZQ0HaQHJ7
         e6lHVMJxxHIv2c/ziRT6h9LTOQzRYbBvYk9mj18WnvxFACY/pgUpfml9zPSKKOt8Adwk
         ytKol0HZvpkVEgc+LbrIdo/nWGCkhu/qsl9Nm3TF/a7492DEZ4vpVS8/bbK3A7ZyQ6uI
         CfPo3I6Sun++N6HCa3o2TLbgIAcCevbqqA1YMi9x4A611aA4sU45DMjaIug5oMNzSXqE
         RRLef3R8YEVhmPif9EUlRu7rLv8rDswOtyRHB62BvG6p436JJpswHOZY6He+aXioV+3z
         aDmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=XtJpRSEB0viBiTAEa5OgfNxpmACIgQ3aMC/GaQYSdE4=;
        fh=XCVhOPhcx3CIfPHrL3cCru23lHhPzXSOMNU6YjY/KgU=;
        b=h7fLonOs4Kgf1ERfoFZOjCP5qnfgdpSjgbzPdfekRFNrwCvjkIUXN2imM6Xb4wrUHM
         gTS4SXzemoA+zqEVYCCk0SANKemhH3QkYzrSMwjbCvwaL1J+kiRX/w67SEI/kVA5mpIO
         dffbYCv4owGQ22uaA7xXEjZebt3btdfe/pTCHoWuRDriiLHPALg0rJa3V6AoUjbNheFr
         V9KNVOWkquHIe0R93cktjN+7SbPUpJWMZCwYu4byW0BkYxmQdCNeiNqMm3aYNoX1MS5q
         9uB/RvKHXDKGqAoq6DraI9fwZCZTz9BSCLrycIl2ZJocCkWOTbqn7SfjqlirB6R5+7jb
         u/Qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WRDAvBZz;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708527070; x=1709131870; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XtJpRSEB0viBiTAEa5OgfNxpmACIgQ3aMC/GaQYSdE4=;
        b=UvCQ86foPG0bmXaR5q9JhkaTE0noRMqynMzmzFSTtQlO/1dWvSYq+iLwCzj2Kxf5GL
         ulRHyXisumBq2fD3+A3mViHcpiUiaps56wmrdLtsY3oPnXiT6Q4AbVAcn1dMmPu0CsaL
         zbnSracCB+5eqRh6izR4ZePkZcmGvQNJTG521CpisGwdlkY9vBa/O0EsSOq7vQzaoUpp
         +SpkiZ55dsJOGomHemWksV7TcExtHZBolriuSsql/QpQ7yOb2VvR6j6G/2ts72ggW/zz
         UpZ+wbyijtrCvWCY+8g2XANtU/b/OVVnvfPjG/0zF1CI7ZyoMMdqS1mRmnBI0K3Pj0a7
         7Y8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708527070; x=1709131870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XtJpRSEB0viBiTAEa5OgfNxpmACIgQ3aMC/GaQYSdE4=;
        b=EmoDNv5Z3cJuSEfGgfrCMN4Vid5kO9Uk4sOmeEb7ih9K2e0yEFEkigMfQDU6xQa9+E
         8PnJTGyc7KUOzA/0oQGxR+wngNzRfhz6UhWUBbIwnMOGTotNDxfOqs1gN3ERB5OjeG0u
         fXlwC84W4Z/b5yAnQFKe0R8QZt34h6jXi3G/XpOZMtr9UJxNGPd6kBsubfJCfPNBoboQ
         7tTcVHPtfwWgySWEbdAmly3C4US+Yytj7WkfPs6C/re4eijtB12PhYdqmJ1tYn13cTMk
         bg1zhYFaX0eew0UVdMROZym6/Ar/JjtJeuVO46McPIAaABVhtvwPGimpGqOk74Jjtq/s
         ydGw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWS/GmvuQeoYe1ylGgoE7vDqBizIXzZ7bITXiXHYTZ5nfhCeqqtBldms2p+fJYL4C4Ey0vSTp9SF8yUufTLPsSNxhYQhJdFZw==
X-Gm-Message-State: AOJu0YyU3oRal/XOtSsflecBZlI4bx47sKegfjwY2q5+dQ5hu4W0UEJR
	N307A2bVeZXcF3vPOzNARoIX58p4VYFjy7XbR2Fsy9KVbiq6kL0V
X-Google-Smtp-Source: AGHT+IEFDrO60+YcqoVJa5HnIdF4Xjj7rRQdSwbjZjeUHyiMI5APN87KCUkZAoIJpgNZPCAvw/WQtg==
X-Received: by 2002:a17:902:ec81:b0:1db:e453:da81 with SMTP id x1-20020a170902ec8100b001dbe453da81mr10198166plg.29.1708527070503;
        Wed, 21 Feb 2024 06:51:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2443:b0:1db:e880:ab60 with SMTP id
 l3-20020a170903244300b001dbe880ab60ls2325828pls.0.-pod-prod-01-us; Wed, 21
 Feb 2024 06:51:09 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVHAqutdCa8ltCNJ9HY3UrqGtrKq8yOJ1tbTuiSXnMrPl+ZrfqO2gOV1Tp1E6DvZNGpojuwgMIouoaU4iRkSLt1hmwA7StLjzbsYw==
X-Received: by 2002:a05:6a20:9f91:b0:19e:b614:48ad with SMTP id mm17-20020a056a209f9100b0019eb61448admr19221304pzb.5.1708527069226;
        Wed, 21 Feb 2024 06:51:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708527069; cv=none;
        d=google.com; s=arc-20160816;
        b=V3CAipKAkb9gyaUPyDL8R6mvCy0hTD1tA66osmbLV0valbnc1fH6HoC7lo3eL00vQC
         ry8lV4WanF4KJ0q5Clbi5XtwCPLEGVNbHelXfhpAJOb+SLz7GATV36uFPkSDgJWJyc3e
         aHEUktyfolxiXjawRhgMITbYblTxAibNstM6E5j7DilO04uNMj39AzC+MI1qh8Hqt9do
         B0UZTp5r8XqCov7YLeHSoTNd+Dg69XNCFu5xtQlxvx0WhHKm64nyGEQf4CZZlQrJK13l
         0WD+p/jeoujqIzi1QEMGQWRxpXrbQytWEgG5uXzBVH5s4LucwvhqQtdx5voIFfR3uhSr
         AZUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=k/EDsctm9f3qsHdkHy3AwXxKagl52ERkO5Trzon9PYc=;
        fh=7/z9zmeYkoXUueapOSgui460TkV6KRIVopvmtyxGt58=;
        b=iN7DewGXBe1hYkMDn9WMXf7dUMxoSkVx9HlCQoCt7nrNDDkhWdN5FagEiJeGoTYe59
         ypYbJ2FGW0NjCZ8xP3FWqOEGy3W59WNqxAX7OXuCN59LpVH+VM1F/jlLp6jnrF3lr5yk
         xxzUJY4jZoa+00nCs/vjooslfZi1g5lr/psbpUnRShj4a1Vqyku4I6Etj5qPYBBQPqi+
         /zNO3C9TBrIQQPKr3R+jGEitt3qKqY6zSlPNGxERMcHeQ9L+70byxt/Q+btfjJk+CSUx
         2ulPM+g9PgIh/ULgkxzQbSz8sSeEuKaUdjHmr4Zc+Em11VyLkGtYRXw9A6V1K18crUCR
         179Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WRDAvBZz;
       spf=pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=conor@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id fd14-20020a056a002e8e00b006dbdb227dd5si778758pfb.0.2024.02.21.06.51.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 06:51:09 -0800 (PST)
Received-SPF: pass (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 06B79CE1E05;
	Wed, 21 Feb 2024 14:51:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8107DC433C7;
	Wed, 21 Feb 2024 14:50:53 +0000 (UTC)
Date: Wed, 21 Feb 2024 14:50:51 +0000
From: Conor Dooley <conor@kernel.org>
To: Maxwell Bland <mbland@motorola.com>
Cc: linux-arm-kernel@lists.infradead.org, gregkh@linuxfoundation.org,
	agordeev@linux.ibm.com, akpm@linux-foundation.org,
	andreyknvl@gmail.com, andrii@kernel.org, aneesh.kumar@kernel.org,
	aou@eecs.berkeley.edu, ardb@kernel.org, arnd@arndb.de,
	ast@kernel.org, borntraeger@linux.ibm.com, bpf@vger.kernel.org,
	brauner@kernel.org, catalin.marinas@arm.com,
	christophe.leroy@csgroup.eu, cl@linux.com, daniel@iogearbox.net,
	dave.hansen@linux.intel.com, david@redhat.com, dennis@kernel.org,
	dvyukov@google.com, glider@google.com, gor@linux.ibm.com,
	guoren@kernel.org, haoluo@google.com, hca@linux.ibm.com,
	hch@infradead.org, john.fastabend@gmail.com, jolsa@kernel.org,
	kasan-dev@googlegroups.com, kpsingh@kernel.org,
	linux-arch@vger.kernel.org, linux@armlinux.org.uk,
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	lstoakes@gmail.com, mark.rutland@arm.com, martin.lau@linux.dev,
	meted@linux.ibm.com, michael.christie@oracle.com, mjguzik@gmail.com,
	mpe@ellerman.id.au, mst@redhat.com, muchun.song@linux.dev,
	naveen.n.rao@linux.ibm.com, npiggin@gmail.com, palmer@dabbelt.com,
	paul.walmsley@sifive.com, quic_nprakash@quicinc.com,
	quic_pkondeti@quicinc.com, rick.p.edgecombe@intel.com,
	ryabinin.a.a@gmail.com, ryan.roberts@arm.com,
	samitolvanen@google.com, sdf@google.com, song@kernel.org,
	surenb@google.com, svens@linux.ibm.com, tj@kernel.org,
	urezki@gmail.com, vincenzo.frascino@arm.com, will@kernel.org,
	wuqiang.matt@bytedance.com, yonghong.song@linux.dev,
	zlim.lnx@gmail.com, awheeler@motorola.com
Subject: Re: [PATCH 0/4] arm64: mm: support dynamic vmalloc/pmd configuration
Message-ID: <20240221-ipod-uneaten-4da8b229f4a4@spud>
References: <20240220203256.31153-1-mbland@motorola.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="r+os/L6iBAa0yd7x"
Content-Disposition: inline
In-Reply-To: <20240220203256.31153-1-mbland@motorola.com>
X-Original-Sender: conor@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WRDAvBZz;       spf=pass
 (google.com: domain of conor@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=conor@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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


--r+os/L6iBAa0yd7x
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hey Maxwell,

FYI:

>   mm/vmalloc: allow arch-specific vmalloc_node overrides
>   mm: pgalloc: support address-conditional pmd allocation

With these two arch/riscv/configs/* are broken with calls to undeclared
functions.

>   arm64: separate code and data virtual memory allocation
>   arm64: dynamic enforcement of pmd-level PXNTable

And with these two the 32-bit and nommu builds are broken.

Cheers,
Conor.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240221-ipod-uneaten-4da8b229f4a4%40spud.

--r+os/L6iBAa0yd7x
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQRh246EGq/8RLhDjO14tDGHoIJi0gUCZdYNywAKCRB4tDGHoIJi
0gMuAP9F/qaVnaevMHMAFC79aMoA7T8MPtngzCYgeGKGkodjfwD+LfeSF0KgFWRs
XPWMo+0cR11PZYg4ErTvrYapXzyvsgY=
=uABL
-----END PGP SIGNATURE-----

--r+os/L6iBAa0yd7x--
