Return-Path: <kasan-dev+bncBCT4XGV33UIBB26RSLDAMGQE5N6KEMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D46DB559ED
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Sep 2025 01:13:12 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 41be03b00d2f7-b4d3ab49a66sf3296158a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Sep 2025 16:13:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757718764; cv=pass;
        d=google.com; s=arc-20240605;
        b=jMX1y1VkelyxEwbeRiBjb6ufmuN7IlyG4+82fQ7Fe/M12KFn+I5BQeFizKM6LB0wn8
         Kz43KE7uxpBPLIHHNiW2X1rCbQIuBoHPzYUc0pdiyKXOgkTVNYLFgx188H4uFc0N6af+
         xqVAMXkgJd6xOM518J6lvApT7xhBHXN2UQbtk3j0AL2qoqccfw2udE2fW1NH2LhCXtsN
         W0vPbrhHKlrFSlfvb9etkjr0RgoJ4e1G53tkDXJBAt1CUhtIcgkotj2Gd4LgvbLxWqbc
         xLRhKqIhDBeryILi+VOXv5XpKw3m4yvLQB/KXXYOTKZ3lnd9CZaRkbLMdqNAAhQW1Au1
         oXMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=WVOLnDQYH11ktJjZwEkMr0ZaLa/iG3e+mezOIIIqkW8=;
        fh=ZnPtZexsFlIOQFWa0JWbq3UVNSd4kFGm9iqzK6XenXY=;
        b=G8bti6bzpSm4WHtBIGXeKEICCMgGVbuTYW3NSn+bl8w7i9Ma9AXBvyvw4l0EgfuMuv
         VHHmxne55ZgtF3FUHNHfESOARPT3Tt1hIlhxthwdDsqv9B57+o0e+LMR7MBIHKo8BlIp
         OfwhwYxJdQmUWeHZmeuXSmMWsRr7CgZTOpTqT+x/mk3MtW4PqO93MpkKEmnjAGkjCYf6
         7lBoy+HmlZ7xzw/JjHQ3hs9LU+KHwCPjhYB6vRTNNoIdQ8HcOqrAOiTrtHj1CdZ2gadT
         UDUbiGRaLr0PIkk8EGiuENBU8VMRvS/6jrKGKWroshQ0a+zNjBg878GFT6m3LL9zquC9
         nSKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uPvN51zy;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757718764; x=1758323564; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WVOLnDQYH11ktJjZwEkMr0ZaLa/iG3e+mezOIIIqkW8=;
        b=llV+C/+blPKQl4G4nX0bB8nCVA28QNHlUBCEP3GZjSW951cUQ/rEtAjhZ9cZAO0rMG
         s6W56ouXhqYBg2mTBqvGkdr5oKHGMd66pFyh7VNsrEC+ws65VS/uL25DlcBn/GonS+qB
         pdBEOqLu97gF2VuGUdv+UKeHRcv9WIcHaXfQQztwzu3jkO4cRaGCWq9PLXCU1lquEz2f
         i+0zUl1p/0NL3ElC6hzyG89vnE5XUgYeabSDNB/4U5IvLseSuts3KVLq1HjKgIeXFm4p
         jg5jTCBT/tKF3gXgjgaxWfUow8AUj1o4tdH4So4l4/6XyCtSzzfmrvuMOmeGhwSGSmQ8
         MhBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757718764; x=1758323564;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WVOLnDQYH11ktJjZwEkMr0ZaLa/iG3e+mezOIIIqkW8=;
        b=H9CGZWq2avbgV0fhErsw8RaEUKkoo3JlpzklnlfZNNCiwGE2F/SOgt9McJsj6pygdB
         om6KBxv0LAVC095uMFwXXWGe7lgzmQ+qizRPzfV+c4+Wt7f66H5yI/e+IpMZg44RNnJb
         nv9o/dwXRnF/MZWlaQ0ToSMqYHetXaILP5Ho++b0Bb/XA3mlC16rpzFy1GPmQlouPGnk
         9oJEQdzCE31ES0gzlldOh5umkn7Rq2QMva9mIWZB+sOLO7GW4UydybMBjX2/8qcn4pq2
         1HoKjriZPazbfOcJs9CMrU20yC5sWmStYF84wHEzebJpupsY9br94Wus4/AAGb/+kDmm
         OMcQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWvQTSmv7UWkC6CGQbutE3biLvPSRPZF5zlNnrDYEeWjJXbmYMS+Up9Q2SvyETc6l3BrfdG/g==@lfdr.de
X-Gm-Message-State: AOJu0YyTiwhy63gR8dFLFejnfeFIUArWJsk+Ix6fxMucK5wcozpN6NfZ
	06IE5wwMQSbU9prGSqMuy6KqPj9ttx/3uaKmoVZXM2EFARGydO2W+xau
X-Google-Smtp-Source: AGHT+IH8mF1MYOzf6TPaC/FRwF6emEY7bCx4CjHu8ueUXoWmyZkhY9kvjjjEua5HVaZcms9ujoH3Hg==
X-Received: by 2002:a17:903:2ecf:b0:24f:5447:2197 with SMTP id d9443c01a7336-25d2587d2c9mr46057985ad.14.1757718764559;
        Fri, 12 Sep 2025 16:12:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd4HYQZQWZBHZNuQR5ja+pg/MkWKu7iLEMgXMjnLDbS2HQ==
Received: by 2002:a17:90a:d16:b0:325:9869:709f with SMTP id
 98e67ed59e1d1-32dd4c9573cls1857662a91.0.-pod-prod-08-us; Fri, 12 Sep 2025
 16:12:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX5gPCJmn14RLU/6u7DTl8bHj6aIwichYsX0CCsNGTesZ6XmRPK82g79JewR1u45Y/NMmHKjr79owE=@googlegroups.com
X-Received: by 2002:a17:90b:3b42:b0:32b:c9c0:2a11 with SMTP id 98e67ed59e1d1-32de4e5cca6mr4836383a91.4.1757718762611;
        Fri, 12 Sep 2025 16:12:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757718762; cv=none;
        d=google.com; s=arc-20240605;
        b=EiU8pd+MsJGJkA4Zv/wSOsAu5JOv8RLwq/Tauo+4Afe4PgW4sJ0OTsQVd0LTJq3nbw
         bA6QZrtliufMDgXo4R03boztQH28dHHPgZhroWEbea6yZ1na8R9w56xTH5s2Hgm8ZXd4
         dthEH1CBTFxk2bwnsECIzhwrl9ZIQiwSHwbpgiN7WacXMLbMTkvyKNiHDu6JmH++1fLl
         X70WNzB91oqk86B2+0dr8zJyzawaE2/k6njAYVB16/7mFrtxChnLxfNh5bTkttp4+He1
         kxCf4zAuxRzghYJgBpQp7xuBHMX4HrDJI1lxcSshuVC5+72NKjGilKpm7Yk99U4ZWtpX
         NOZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=6hRiCf14FcN2dIcM8kd/jn4varhB8P9bDU9Ojl/fz2U=;
        fh=FG2r1zb9h/tMZDvXp+MJF4kTRcsR18p52npi3nIm+VA=;
        b=ZGHefkv2Q8mQ+NX34lH1XGOcfTbp7zWsmjbselUUDhHwUKhqLiQKPNf9NLxdPPKKRf
         FwU+0omcP11lM7DvgcHdt7XR9YVVTyAOGGPj19BKfVGk6OafezZOt5Flxy9/UbIHO94r
         llgIB2w2NHK9UcYgHptExkis9KCqCmMIAgWuNqCYNkL8KhVJmlkpQ029L1qOU3tKbn72
         wXDofxAd0WXf2UVpAzWuORc1NYXJfTkH+w5Jui6i2PIeQufv2ws/X9cwEKeyzxSxJelP
         kVccAkvTfQ8vZ6eDW1hidBf2Ke5p5mf7e75WQ45li2uuS1mc79LrHd5AVBaBaukzFo8x
         7Omw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=uPvN51zy;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32dd62f8033si236709a91.3.2025.09.12.16.12.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Sep 2025 16:12:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 9324A6000A;
	Fri, 12 Sep 2025 23:12:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C0316C4CEF1;
	Fri, 12 Sep 2025 23:12:40 +0000 (UTC)
Date: Fri, 12 Sep 2025 16:12:40 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: David Hildenbrand <david@redhat.com>
Cc: Naresh Kamboju <naresh.kamboju@linaro.org>, kasan-dev
 <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>, open list
 <linux-kernel@vger.kernel.org>, linux-riscv
 <linux-riscv@lists.infradead.org>, linux-s390@vger.kernel.org,
 lkft-triage@lists.linaro.org, Linux Regressions
 <regressions@lists.linux.dev>, Andrew Morton <akpm@linuxfoundation.org>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Dan Carpenter <dan.carpenter@linaro.org>, Arnd
 Bergmann <arnd@arndb.de>, Anders Roxell <anders.roxell@linaro.org>, Ben
 Copeland <benjamin.copeland@linaro.org>
Subject: Re: next-20250912: riscv: s390: mm/kasan/shadow.c
 'kasan_populate_vmalloc_pte' pgtable.h:247:41: error: statement with no
 effect [-Werror=unused-value]
Message-Id: <20250912161240.0a5fac78fed5ed8ddc32450a@linux-foundation.org>
In-Reply-To: <d7a03a2b-d950-4645-80f2-63830bd84f76@redhat.com>
References: <CA+G9fYvQekqNdZpOeibBf0DZNjqR+ZGHRw1yHq6uh0OROZ9sRw@mail.gmail.com>
	<d7a03a2b-d950-4645-80f2-63830bd84f76@redhat.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=uPvN51zy;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 172.105.4.254 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Fri, 12 Sep 2025 13:34:37 +0200 David Hildenbrand <david@redhat.com> wrote:

> > [-Werror=unused-value]
> >    247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
> >        |                                         ^
> > mm/kasan/shadow.c:322:9: note: in expansion of macro 'arch_enter_lazy_mmu_mode'
> >    322 |         arch_enter_lazy_mmu_mode();
> >        |         ^~~~~~~~~~~~~~~~~~~~~~~~
> > mm/kasan/shadow.c: In function 'kasan_depopulate_vmalloc_pte':
> > include/linux/pgtable.h:247:41: error: statement with no effect
> > [-Werror=unused-value]
> >    247 | #define arch_enter_lazy_mmu_mode()      (LAZY_MMU_DEFAULT)
> >        |                                         ^
> > mm/kasan/shadow.c:497:9: note: in expansion of macro 'arch_enter_lazy_mmu_mode'
> >    497 |         arch_enter_lazy_mmu_mode();
> >        |         ^~~~~~~~~~~~~~~~~~~~~~~~
> > cc1: all warnings being treated as errors
> > 
> 
> 
> I'm afraid these changes landed in -mm-unstable a bit too early.
> 

OK, I'll drop Patch series "Nesting support for lazy MMU mode", v2.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250912161240.0a5fac78fed5ed8ddc32450a%40linux-foundation.org.
