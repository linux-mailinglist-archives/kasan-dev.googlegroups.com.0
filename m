Return-Path: <kasan-dev+bncBC24VNFHTMIBBMNA4GAQMGQE2BZOGDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 480D3325B54
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Feb 2021 02:34:43 +0100 (CET)
Received: by mail-yb1-xb3d.google.com with SMTP id l10sf8556049ybt.6
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Feb 2021 17:34:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614303282; cv=pass;
        d=google.com; s=arc-20160816;
        b=m8DbQTNWgEV2+aS0Ip2omwxmGRYwnNKLGgGMwj4ndB7jzhs0ypsn2ZzLH1el5zXJpx
         y8cDpTs9UZcb1Vz0i89cd2C0xuO2y/qz13DwUTFoomCnFtL5s7Zz1i4n1JR/2/g9B86J
         3i7Wa5DGbAeYAhuCcNK3W09sDTeHHA7RtsQw7fZTqZGhJuHVmQbrjLcLF5nwSNdkVI9m
         EkXGinzFgtG8H1sIBQokkW2eHvhKSGffngqfFNUvIytYIrMbtlFMirSg1lIlMLqH79W2
         ofBwK0sZ0NgArrG241oj84NOBuCrAubs1ZwvWAcBIuClMwapRSEowYu1ceTifl+d/8qH
         4F7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=UjfuBy3YrfA5MnwYwIC7sx1BxALdlhTen7/TUWI1wAg=;
        b=Zq6TpcqKnQlzrvFzbXmqpF2jmJBHLtBMuMiZ4WPfL/ZXKlLFPWyaCokV4FNgKlsELx
         vvN1tM1jAn4/0SKYsf9PyiN17EHE8XQzapK8JkHYD261H8jEYS5f3JuGaEOVTWs5n8h8
         M+yYc2UFrk2XaSHQK/FqyiVlLtPPWvSID5nsp6aUTQzJy7xvB7I4htJ0rRvR3x/vsabn
         1aJSIQzIS83qzrLnZt9xHDAB3GfONmmShnGuddXSFtovviVW/XQtiYOispcUTVy3EiB/
         UpPDkSh65c6T3PHE2nErm0R9IVEPpl1+a1KLQIZC58ReTHz+kILlUK88jxMsXxmkxciw
         ikoQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RopCAHhO;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UjfuBy3YrfA5MnwYwIC7sx1BxALdlhTen7/TUWI1wAg=;
        b=CLVjouLdQLdrk3qz11iflA6tf3plLBbSPDgxd1TeszCH7fx8tBeyY3qsiA9q/FIoTR
         kOv2crQIG/jhUAjOlNZrTjgqtcma2+neLBQyRpuz4R3+vEP8b0MQN/QFYi1VwF1QWR31
         Pf8QB/2nvdJqO1kCzLoFofG7Q+hFWBDbDOaZjcBdW8fDSyJoJKCuOqYkxlPInaX2YqEw
         YLdk0aAwr8LW79j8a0PBG17F+NWiRxli0C5plDmJnNKuEWE6mKK5Ox8xEcNsST9Fylpq
         Q2CcbNFzYWnaKHUYqLD7FeOwpMTcO1YVNAVfLLIpvxVobZRp5J7iS7vtN2L2N3W2xwnW
         NS5Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UjfuBy3YrfA5MnwYwIC7sx1BxALdlhTen7/TUWI1wAg=;
        b=nJolB+bVAKjd3UgaHmkJ3r2vMuUKSoiMH5unPj+UAXLmAb1oyXoXNq2rYnrQxPbKAM
         E3lefNnv+EX32z0j30Mt9nAmyOdpRIvqLg8X811Y2AKMS5BJtmytz5t6iekzmhIz3d9V
         uYtzvGy545C5InSxJEmpJJ0RMpCYinw0VualNjkA5U8ktUGpZM0dHvM6f2LX2n/wa0ct
         1tGK/pgsjrDCN2gcG3nnO88diX1zOTOAK2SFCUqLZ6EW0m8uUKlVo+dVyZCM2/pDl3nB
         hx6jzzSotxxPc1DWNdYNZ2nnUfSvxLB24Mr7m7HI4brcBuiD7dLoW0Cm+iHwPxVUuH6E
         qKZw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RH2o0g1PfIzIoZKd4IlqwzPyZyiSrp2CmAFjdiAYZogT5nvvl
	aY3sAlqCLxhVRw2AKG+Qgtg=
X-Google-Smtp-Source: ABdhPJwaUHRpsIDCi6Lk11azF+/XSLJBca7k591ppfm/bXqJSotgXsjheK7t9kQ9zMvUeggXa9sIiA==
X-Received: by 2002:a25:254a:: with SMTP id l71mr1053602ybl.125.1614303282144;
        Thu, 25 Feb 2021 17:34:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d8c7:: with SMTP id p190ls2349126ybg.6.gmail; Thu, 25
 Feb 2021 17:34:41 -0800 (PST)
X-Received: by 2002:a25:6d8a:: with SMTP id i132mr1016327ybc.337.1614303281683;
        Thu, 25 Feb 2021 17:34:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614303281; cv=none;
        d=google.com; s=arc-20160816;
        b=s2F6ExIPYu9FWRENtBvG9eAhZRWahm6jdTiufL37mBuiPnvFc5hNPY7s3to5XDcG3k
         YPy5xzVvpdNnb8ybWPqwFqrXHyyIWupvx+hN5wd7tMfpmAOXgWBEhlaP8lbJT4OWLe0/
         m0Sn8wJHOUAaTpR8tVBsIMSggho/6Gq+/KOl/5LLIiRDE6whiXMS/jzYJiuv1i2pFs30
         00SZznwNosUXFymTd9lXtYzMxqa/oGQbcOnRZcSEoG91Od1U7F8zSlmyKNuqyqcYVC0N
         s4l2NeWpFZv8YwMx7PdhdLZTzocfBIr6gkRztBtvpjTlzfPpGKJALb73QP1qAVlbQYn8
         KxPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=O9880s4Cc4/jCuPGwmyCsxTKQbfRwH0tlTg3nfkmZo4=;
        b=gcEUIsmP4oBMFsfOOwGJVKq4QcHtUgodmorc47JEtork2DfbG0ejuG2Ulusqs1FSGd
         jf6lOYVh+xQaI1HshpfK0TIL+p2+0+LDBtUIBMCYtJUdXYq1vUZQQ/9P8tucqCb8jZq+
         Ywivd56MFDZCjiuJRA1xC5mEDSimvTHC6ilsK+SCoyd2DAClpAXFbP++ibD4jKZ6TezV
         /70geovanwr9xDaJkFmWI2IFk21fwHcEliR5NdvPsV8UHU0544ZhrsqBVYP//2vYIHv8
         AoQibISuj18aJO4ru51OAeSNkLRcrAbOV8bb+tIv5pIGKGvqMrmqUNhPCl9RvEjBnZuN
         WaaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=RopCAHhO;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c10si550208ybf.1.2021.02.25.17.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 25 Feb 2021 17:34:41 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 3A18F64EF5
	for <kasan-dev@googlegroups.com>; Fri, 26 Feb 2021 01:34:40 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 2002165381; Fri, 26 Feb 2021 01:34:40 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211817] KASAN (hw-tags): optimize setting tags for large
 allocations
Date: Fri, 26 Feb 2021 01:34:39 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-211817-199747-zQ1xj2KNUj@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211817-199747@https.bugzilla.kernel.org/>
References: <bug-211817-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=RopCAHhO;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=211817

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
From Catalin:

"""
A quick hack here if you can give it a try. It can be made more optimal,
maybe calling the set_mem_tag_page directly from kasan:

diff --git a/arch/arm64/include/asm/mte-kasan.h
b/arch/arm64/include/asm/mte-kasan.h
index 7ab500e2ad17..b9b9ca1976eb 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -48,6 +48,20 @@ static inline u8 mte_get_random_tag(void)
        return mte_get_ptr_tag(addr);
 }

+static inline void __mte_set_mem_tag_page(u64 curr, u64 end)
+{
+       u64 bs = 4 << (read_cpuid(DCZID_EL0) & 0xf);
+
+       do {
+               asm volatile(__MTE_PREAMBLE "dc gva, %0"
+                            :
+                            : "r" (curr)
+                            : "memory");
+
+               curr += bs;
+       } while (curr != end);
+}
+
 /*
  * Assign allocation tags for a region of memory based on the pointer tag.
  * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
@@ -63,6 +77,11 @@ static inline void mte_set_mem_tag_range(void *addr, size_t
size, u8 tag)
        curr = (u64)__tag_set(addr, tag);
        end = curr + size;

+       if (IS_ALIGNED((unsigned long)addr, PAGE_SIZE) && size == PAGE_SIZE) {
+               __mte_set_mem_tag_page(curr, end);
+               return;
+       }
+
        do {
                /*
                 * 'asm volatile' is required to prevent the compiler to move
"""

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211817-199747-zQ1xj2KNUj%40https.bugzilla.kernel.org/.
