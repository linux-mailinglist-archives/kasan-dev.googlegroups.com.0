Return-Path: <kasan-dev+bncBDV37XP3XYDRBO5UVS7AMGQEMXKRKAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 322F2A56D30
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 17:09:33 +0100 (CET)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6e8c4f5f477sf35515346d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Mar 2025 08:09:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741363772; cv=pass;
        d=google.com; s=arc-20240605;
        b=lHnN/FVxIpymCQiPBTmLvMPNcS3LwCV7pW8oVfIySHB7PD4EdPVt6QRGYkSuxJ2hND
         2r9CNsK3WX3nZDA+UWWdUjvnaLuzHxhl3hYGuxgRE4Yl2FNwosmRqqsoSXNs8Vkd5gU9
         RSCbpaMNXmP18rq/d1Z96QnkINZ1ajohrDU//6QEHTOp52PFC/0UPghF4hwHzdTb3oRr
         5DwMvoY+Vvt0TKl2x7oxeCkTM6unJ0i2sjgG0MofiXPdjcpIWeCBD4dU49J56M1E47K2
         H8icjS28GO5eaNr3DWBjQ5rWPGc8thLmlOsY72cIqMROts13boIX5zjGIIadpvUypYQR
         70EQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=IwtQ0nWeHHoOFogd2fGxCv/7FCBNBDfOxXJC1IhCOpY=;
        fh=vCzoVOVcIt28snn2P0R1Vy4L5SUCbcfPkFtAj2XlUjA=;
        b=NDOGdwouXzjg9m8Q4q8RYSuWTeHXn/UYKrK8CqOdowKweurDKbc0R0n8kTnpHxUAyO
         grG2PLp1s1aYiFZD/8E/MnGXOp+v2OvJ2cCfwz2s6qf6xLjwwUgBGQPj6dfF3mwPKnS3
         gcGxWZxDl+/F6SzFcns9gDdOZiBIBKgQ3ZGny2Ef49zSa18PHrRu0xQ2KrfmoAF+df/P
         JUhvAxJzaAsxbXQ/TlZpYYWW7JJ+C4KAsadv8cHSdmqH1PhqkDyRD/0QC6N8JTf3LIZh
         J97YEZFAzw5VpOT6kjxhvA75V0NtK3RMjAO41+u/gRJZMNsp3fpNrIX8f1C9trCTys6T
         ZzBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741363772; x=1741968572; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IwtQ0nWeHHoOFogd2fGxCv/7FCBNBDfOxXJC1IhCOpY=;
        b=YJhdaK3YDOQLF2X94eC/FDxqrwZy/sHj1VjMaZRV/yE3Q5IMDH0Y4Nu1ZwOsmCZVVE
         flH3Jm3hAKzkwWGzfBx4nolBIeGhjNDmI30WRFOAvxRmvXBXyfhfkXXZG64KwoNFVr+P
         BOLaAL5c3vWx5B0QinbooO5lE5tvgYJjIMbW1UwQsaoZ2+TBqt4NFik67j2qMSVAs7P1
         GmS+y9mlY5MZZROJVAXWj4hP67wTNUSPC05u1+GzKckXWHFDLcNRWh1G0OA935bO4lVq
         x2YFsnpGTNIRQua60wGyDdJR7S3HLh06CIjbVe0A8tng75Jf59JFxxv3ryLfOkJRM/g1
         omPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741363772; x=1741968572;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IwtQ0nWeHHoOFogd2fGxCv/7FCBNBDfOxXJC1IhCOpY=;
        b=FVIRcXwn9CP0CISfjvrHsMz1zNaTDy4ZTn6WYrTYSpg8SX70zVngxJnEP6qhP4LYHT
         oPpbMXn7y4lRhBF2NXkZNn5SienlaHHa0155ebpN0oHpw9d0nf98yMqmbZ2IN5BDDLIj
         ku0f1oxDrKYuT3H8ne2UP16DwiOKIoTGFqIyR/SCMGz3FV2Bt6epZIW7Rv+FMYe/j9Yw
         Xmpck9ozhb5SCKpW2AtEonEWaeZDmfZoXO5miuJBZPk5iBqscDMpMY3CudqcCki8lWrV
         ICJviZBOFhqXgVlXvtamZvxZUj5kopVVB9zzYCxx3UTJYGu1bV87h8pMDYGR9HoC4JnD
         nfMA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV9TnBUa4T1X+ja61mSevxiy2gipglsszXm8cvNLuepVi4DNIqPil7N5D8qvXPb9hd1nHESYA==@lfdr.de
X-Gm-Message-State: AOJu0Ywkjo0uOQay1FKlSUackfPEo7A9/ZK52jELd4oDCeWfW2SDgXL4
	QK3hts2hLxqRKVA7Q8C7A0VSgMJsdIZqQy5bcH9iI6HsVZQ6rq1v
X-Google-Smtp-Source: AGHT+IHhvo3RoavIVblinZXUQLDKNM6O+mwLRfP43VSjj5eMo1EnMpjn1S5wyniqyfWAsxbQSQUkww==
X-Received: by 2002:a05:6214:230e:b0:6d8:9c92:6555 with SMTP id 6a1803df08f44-6e900671219mr39084346d6.29.1741363771901;
        Fri, 07 Mar 2025 08:09:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFRDTRYNmqUXX7xY96UsxrrmJyrF/fM/5yycCAwOWN+Dw==
Received: by 2002:a05:6214:5ec7:b0:6d8:f5b9:2be3 with SMTP id
 6a1803df08f44-6e8f4d85f57ls35948656d6.0.-pod-prod-07-us; Fri, 07 Mar 2025
 08:09:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV18QLTD+H6BpY4SVExgUKv7czQwmdO85iRnni/eH3SnYPdlgnKMFTTK4vDgwrlM+HkO6IfjwrHDx0=@googlegroups.com
X-Received: by 2002:a05:6214:528a:b0:6e8:feb2:bad9 with SMTP id 6a1803df08f44-6e900670d1cmr38699216d6.30.1741363770848;
        Fri, 07 Mar 2025 08:09:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741363770; cv=none;
        d=google.com; s=arc-20240605;
        b=GpvbhRawYqPAZkRdR6pXF/aKo5h4vPR+Awf4TFJGcUUAXYuVYq1hMf0LUXWoZpCw/G
         rksdJHH+wLARxxXrlPawXK+RyMZQw+q4rg8gZyiNyEZkBfnkD0rH3r/qvQ3v2e3nKNFe
         z+31FHn/qb8J/6OOkJGJSLtM9YOIwTtPAagl+oOb/Y/GTivWu6wvRcpVWT9XpsDs6Kjk
         cDplvT1gYrnYe86LL1airuY6KxeBcxKHVjHr9yvNQT3lBqtVoNhSaTfh4C3Qw+RgMwLE
         AtR0e9gGIoSDjLesVQD9RBqrzw1MdqE8FZGISEf4SdnDCEYravmwv2fRL6lx4W+2BJ8e
         YIIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=QQCeoUjMBLTYpmAs11rMjACGL42XfpmjLxOtQHXk+DA=;
        fh=Gubn4XR2857kDQZxT8DtgDuod10sjGoOIFNGcyC1UbE=;
        b=hQKz0h+iFhdgfMU56bqaeiot6qNJSJ/xzyKVDMVJjfq5d5UOP7rnuKm6K5cHxt1rLV
         5E+i1b2jLlZjXt/3DhZQCkUjCiFkrQT6czwZ0wrPp/3caPpP4uEpjgMflzBLsUNc/Nzg
         IBHz4PtdIRpJVVOT/rOyT6Scg3OnpC6M3LR5MHjYjlMxq3rbWlT6QacdYOw5GGpcTQNZ
         2Wu+lOKzsgJHUaMKn51H8H8w3l/AXX5fH8pns6Z89xcrm4k4UzjqG/AMx2GM6eIaOMnC
         95C+h03RFmAPisEnowIr/FHnQXxekxDSDpfX0X/HVdxzbQMAMTZSjzDpm6FIq79jLUz4
         prXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=mark.rutland@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-6e8f70819d0si1663386d6.1.2025.03.07.08.09.30
        for <kasan-dev@googlegroups.com>;
        Fri, 07 Mar 2025 08:09:30 -0800 (PST)
Received-SPF: pass (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0495C1477;
	Fri,  7 Mar 2025 08:09:43 -0800 (PST)
Received: from J2N7QTR9R3.cambridge.arm.com (usa-sjc-imap-foss1.foss.arm.com [10.121.207.14])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 962E43F673;
	Fri,  7 Mar 2025 08:09:28 -0800 (PST)
Date: Fri, 7 Mar 2025 16:09:23 +0000
From: Mark Rutland <mark.rutland@arm.com>
To: Anshuman Khandual <anshuman.khandual@arm.com>
Cc: Ryan Roberts <ryan.roberts@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] arm64/mm: Define PTE_SHIFT
Message-ID: <Z8saM94ixmDNjZzV@J2N7QTR9R3.cambridge.arm.com>
References: <20250307050851.4034393-1-anshuman.khandual@arm.com>
 <17931f83-7142-4ca6-8bfe-466ec53b6e2c@arm.com>
 <c3dddb6f-dce1-45a6-b5f1-1fd247c510ab@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <c3dddb6f-dce1-45a6-b5f1-1fd247c510ab@arm.com>
X-Original-Sender: mark.rutland@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mark.rutland@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=mark.rutland@arm.com;       dmarc=pass
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

On Fri, Mar 07, 2025 at 02:50:56PM +0530, Anshuman Khandual wrote:
> On 3/7/25 14:37, Ryan Roberts wrote:
> > On 07/03/2025 05:08, Anshuman Khandual wrote:

> >>  #define EARLY_LEVEL(lvl, lvls, vstart, vend, add)	\
> >> -	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
> >> +	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + \
> >> +	lvl * (PAGE_SHIFT - PTE_SHIFT), add) : 0)
> > 
> > nit: not sure what style guide says, but I would indent this continuation an
> > extra level.
> 
> IIUC - An indentation is not normally required with a line continuation although
> the starting letter should match the starting letter in the line above but after
> the '(' (if any).

Regardless of indenttation, the existing code is fairly hard to read,
and I reckon it'd be better to split up, e.g.

| /* Number of VA bits resolved by a single translation table level */
| #define PTDESC_TABLE_SHIFT	(PAGE_SHIFT - PTDESC_ORDER)
| 
| #define __EARLY_LEVEL(lvl, vstart, vend, add) \
| 	EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * PTDESC_TABLE_SHIFT, add)
| 
| #define EARLY_LEVEL(lvl, lvls, vstart, vend, add) \
| 	((lvls) > (lvl) ? __EARLY_LEVEL(lvl, vstart, vend, add) : 0)

... and ignoring the use of _SHIFT vs _ORDER, I think that structure is
far more legible.

With that, we can fold EARLY_ENTRIES() and __EARLY_LEVEL() together and
move the 'add' into EARLY_LEVEL(), e.g.

| /* Number of VA bits resolved by a single translation table level */
| #define PTDESC_TABLE_SHIFT	(PAGE_SHIFT - PTDESC_ORDER)
| 
| #define EARLY_ENTRIES(lvl, vstart, vend) \
| 	(SPAN_NR_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * PTDESC_TABLE_SHIFT))
| 
| #define EARLY_LEVEL(lvl, lvls, vstart, vend, add) \
| 	((lvls) > (lvl) ? EARLY_ENTRIES(lvl, vstart, vend) + (add) : 0)

... which I think makes the 'add' a bit easier to understand too.

Mark.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z8saM94ixmDNjZzV%40J2N7QTR9R3.cambridge.arm.com.
