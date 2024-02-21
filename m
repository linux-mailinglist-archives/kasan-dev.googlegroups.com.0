Return-Path: <kasan-dev+bncBCK2XL5R4APRB54222XAMGQE3DAAHHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9276685CFE5
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 06:43:21 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-29999b97b39sf1264804a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Feb 2024 21:43:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708494200; cv=pass;
        d=google.com; s=arc-20160816;
        b=nB3gmOtunYNSKo+iv/In37cApEimAQ0szONY2M5Dbv+IF22pu57Zz7oLumsZ507iq8
         JioJXsguQh3nEAv1NTK1Yr0cXoYrKBPY2T8Fr36Q9HJ9o6g4TU4+qoKhV5FjNXGDqtTU
         XSqIlssFc/80QdU5JnKv5RMW1U8rFvT6mwn0SRKePJjgmMvfzIEcdjUBur6lpwuT+yqb
         GnDfDpPYeOU5PkcmKIpV81rMcz5S+Gm1UvoN00tVkYGFjxY+oTCN/QgBMif1v4dxtu7W
         fhi4pZvHxFQCiAkLDrXoUy6v6SViLpRMTVtN2PAh6M1hbquCus+p9GtWwrNoHt5asPpV
         jQWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=o4kJ1Lf3eornkXRFiqRdN71YUsSIKgneIKdfX99fqK4=;
        fh=zI1WnFavezWavS2sjrHTNoWaIhP2gx2I6+Rq5urKqPo=;
        b=nmBHSoRx8GBl4ygOnKWqI7rcptAzSsxnd0D38umxddcMI/7ruZzXVCv+FPZoVBTteW
         9XpajIXufpJrRfZ7v8/HxeLWraqxD8F8jO8AphX105NGBdCqoUa3C6xa1godfTLVrlSA
         PcJhLnKkaCEgjcmrL3xupY9jj9CLPYnpLWxQy17ge89kRzEHdDKfWpWngBOMJQu/jTJ4
         r3NhikQuo5j/xUmIJg46GNw45BwAr1Jv4yqGF9XA7pI4hf+xuVcuWNB7W1UyM0/bQjlR
         QphsLW17XDBYlkLVp4R+QbDN5PTYCYVFlRmrGYHGlM2MxlJCPDVB2IVWtFH1MtCSMeF5
         /htw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=2fExemH9;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+bafd7931fd2c4139f05c+7486+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708494200; x=1709099000; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=o4kJ1Lf3eornkXRFiqRdN71YUsSIKgneIKdfX99fqK4=;
        b=fhsPJGAd4Gh3Fxy3h+Wr0lGIZYELLnTZUXvq5PjrbgTc+drUmNcxlyRX0Kp75Xwgl3
         zgKy5obNYo+5KFy0G1EARNWDyIa6RQxVn21DLSGFZSecJG4gH0Ev/0ddja/F88fmwpSN
         pA5RVvnC4UWJwi48pkKMUE99UwLbvebc9xEE+5bfz8JM4cK/+AyCeIhD5wa5d0urjVyf
         NjVqwyIWwqH+6DxCA5eg1jdafQkcWZ46bZ1Z3wi3UlKRsmDnpzRT1evSEn7vRcMHOQcZ
         6gTm39NHw2JkwRVEDFLRfU9iRrTdzVa628gIftWHR8cMXUDUGySLAp9AwIOFHHn2ETyS
         SZxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708494200; x=1709099000;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=o4kJ1Lf3eornkXRFiqRdN71YUsSIKgneIKdfX99fqK4=;
        b=pzIfvRuliZbWZVgv/7/ZoFd6mAkLfAQwIUi3qaX7vWKpAZpY1xIUvzcESIwzo1xTc6
         7rCBLRFHmv9NyuuZff5mdYlUpPwOUFmEI3vGjzz1TVtOmem1JRPxh1R25ZLEKMYxtwrP
         NhlcDzvEDLi/I0FPMNkv/zntp6/xH4K8sqz3fLP00pKSdgtLE0rzy6zG0SPvtNTTrco1
         hU4X8A1CGlUpYxKYhdNPfcOU6G0U0A5t3LHh6e8lQqR2ZtcyB33x1mplU8qE4uSUEHmk
         0eUeG5m2EMWKUvLiy31A8RZ2R5pX5mBki7hNJOHmTsZHzHY7mBER+tCstZUSn6RmfqEK
         9Iuw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWfI5zyakU3QgJdQp/nwhB1vPLje6Pf7VsyASlOgfqyRjJDmGz82Rr0o2kGx0yGUkf4yGGtac7rFCClFb2F/oCxVftjLOw7Qg==
X-Gm-Message-State: AOJu0YwnFHN3Gm386FCvk4UdRQQETyusDgeamlEpJdOfDmfLiD080gYH
	84VIJiH10GwD4dBbnJD+kRGvlphlrG2KUyLv8NaCZiXjLo5ABKFV
X-Google-Smtp-Source: AGHT+IH8s7vHihQWFlpgx6K/Ofemf9UJxuPciZ/rUpX/yCN0cW/OsTvaKyLWkzVOIgrKYd1nbuXDQQ==
X-Received: by 2002:a17:90a:985:b0:299:3258:fdfb with SMTP id 5-20020a17090a098500b002993258fdfbmr12072503pjo.4.1708494199756;
        Tue, 20 Feb 2024 21:43:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4fca:b0:297:2e05:795 with SMTP id
 qa10-20020a17090b4fca00b002972e050795ls3775491pjb.0.-pod-prod-08-us; Tue, 20
 Feb 2024 21:43:18 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXILmVq20xt+N7eBnKHxemMO7I0je61AlwJXgDHKvqYIInMbFW2Zk5f4nFfsKotSiNFc6FfZN3MEaFBGbQWOYk0XgwJsuXXdjpIRQ==
X-Received: by 2002:a17:902:a385:b0:1db:9e2a:7e24 with SMTP id x5-20020a170902a38500b001db9e2a7e24mr14434677pla.15.1708494198712;
        Tue, 20 Feb 2024 21:43:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708494198; cv=none;
        d=google.com; s=arc-20160816;
        b=DLFwHDQQqN/eRhRI9Gu2+3+KzKZG7Q6OfWfxj17zGdVu7OwjlHdq51osKFUuyUlKA5
         SeaGll+CUND7OHCVJDt3WF82Fs01ZnjNMJ6aa1rorkxAFrmo6g2sBrI2H8ntmLOeNHFt
         92a5xyyVywtelhDlMsb4ekjPCoHFikS/yGiZB0LEB1aWvewZw9RjTEIo0oh1I++jZ+67
         pfwXG42SjGdPHFvTV46xEP03PqU6pn+IIIcRzC1t5OvJDQ5PXmdsnK+5sNutAxOyZv21
         Fa6C2sugEKEvEUYO6aJI26eHwxNQSd2fTwduTQaY48zOZOWv/pjJU8JeMNuGXfqvgA7J
         +vyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vQxW7nd7WTaydKIv2J5Y5kbM61+Nggklag6qseDgVeA=;
        fh=7/z9zmeYkoXUueapOSgui460TkV6KRIVopvmtyxGt58=;
        b=HFVEIJq58io0GpUfl6T6zgtISdFU7cy0vNhz5M2NGUebFgGocUyK1mn2GtezNAY/aK
         7pIWJ2ARhOqGtV3Gmy1ETQotJm+mBhZsiPDbNVWhjS7VWq6b6sbiDXflQEDmOFIoncTd
         3GwZnAZHXTN3m9/ICQRdxNVzR0g0nyrt9oBFSqjMB/3sMIKGyYPS8gFI4GvW7RqKTCBt
         K4guldQOT3P+/EoLLn/4hPzJxL9Tkf7n6AC/kuoRyEOyqLiaqIQxGPxff13zzBEPozYc
         Xu8JrjgkydMZaEipBf/H0+tZSOwtXNr30EBWmVk3JYBkkVtvQrgYT7jHjW0ZgOUVrRGP
         V0wA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=2fExemH9;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+bafd7931fd2c4139f05c+7486+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id kv5-20020a17090328c500b001db63388676si562678plb.8.2024.02.20.21.43.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Feb 2024 21:43:18 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from hch by bombadil.infradead.org with local (Exim 4.97.1 #2 (Red Hat Linux))
	id 1rcfNq-0000000HEmM-23vn;
	Wed, 21 Feb 2024 05:43:06 +0000
Date: Tue, 20 Feb 2024 21:43:06 -0800
From: Christoph Hellwig <hch@infradead.org>
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
Subject: Re: [PATCH 1/4] mm/vmalloc: allow arch-specific vmalloc_node
 overrides
Message-ID: <ZdWNalbmABYDuFHE@infradead.org>
References: <20240220203256.31153-1-mbland@motorola.com>
 <20240220203256.31153-2-mbland@motorola.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240220203256.31153-2-mbland@motorola.com>
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=2fExemH9;
       spf=none (google.com: bombadil.srs.infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=BATV+bafd7931fd2c4139f05c+7486+infradead.org+hch@bombadil.srs.infradead.org
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

On Tue, Feb 20, 2024 at 02:32:53PM -0600, Maxwell Bland wrote:
> Present non-uniform use of __vmalloc_node and __vmalloc_node_range makes
> enforcing appropriate code and data seperation untenable on certain
> microarchitectures, as VMALLOC_START and VMALLOC_END are monolithic
> while the use of the vmalloc interface is non-monolithic: in particular,
> appropriate randomness in ASLR makes it such that code regions must fall
> in some region between VMALLOC_START and VMALLOC_end, but this
> necessitates that code pages are intermingled with data pages, meaning
> code-specific protections, such as arm64's PXNTable, cannot be
> performantly runtime enforced.

That's not actually true.  We have MODULE_START/END to separate them,
which is used by mips only for now.

> 
> The solution to this problem allows architectures to override the
> vmalloc wrapper functions by enforcing that the rest of the kernel does
> not reimplement __vmalloc_node by using __vmalloc_node_range with the
> same parameters as __vmalloc_node or provides a __weak tag to those
> functions using __vmalloc_node_range with parameters repeating those of
> __vmalloc_node.

I'm really not too happy about overriding the functions.  Especially
as the separation is a generally good idea and it would be good to
move everyone (or at least all modern architectures) over to a scheme
like this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZdWNalbmABYDuFHE%40infradead.org.
