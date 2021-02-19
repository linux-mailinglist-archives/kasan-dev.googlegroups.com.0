Return-Path: <kasan-dev+bncBDDL3KWR4EBRBUGRX6AQMGQELUVVC7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5679A31FD2C
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Feb 2021 17:35:30 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id a1sf4143220ios.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Feb 2021 08:35:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1613752529; cv=pass;
        d=google.com; s=arc-20160816;
        b=quCuOvHsBKDrTZz6YIdCg+X4na6gGoWu1gKFW8T9LyvKVR22IxcngBQ8htyqVN3Lod
         lfTJkWLSuhoKnfB2TJag9J1/KpGuX4N1A8h11JytJYgwYdXjrNvSjlKamO7+E1gi8pYm
         BafeXCE3XDQsGDaVm2+hR1IaKD0rhZynJ5PUAl0LDNFPMcjR78FKUGIA1+03/e1MhEtU
         E78otmMpOQkiOXtIM8RA8MwhJ+O0Z8bFrGeVHvGhXcsOaIL8DTANSkP/5mzWAJzH/Q3U
         vGocSAmJVTx+mCQGKcm0NDdDik6bYejmceVYVHgI0DGJLcb2xwdYLd5Nv3b2+lDjqNjQ
         p5Lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=geXYzqVAhWCEzSYTyItYhCgWMAQ4eWxaYxsKa/q36Vo=;
        b=qSba179Ry0T0WVdiYrltEnshJRaxornnzUq27ob6Dk0vjN9/hyrcQeDiyp/Bvfsq8z
         EoSPVT1hIOoEDzfwv5OwGgOOwq3r+QfjUxVANo04NmCNskuMAGmjxilNhwd6mHPS2Fcc
         Bsb6xCMaAlOgQW3HDbwZwnkWO+sGnPSlDT4IbU6clJOWCWL2jnUTlcyTj9vErCx7j12N
         qHD6aETmLBMyvZQUVYovtf+DN9V2S8MkjpoGW4YrA/iv1hfJrrNc/gHwq4pW0QqCc4e3
         RdhDooobe9LvMGEE9us1W+dnJDAKh3lT9zAcdqgGYnkAgeeFmFzujCCs59z4BLZBFULp
         +c+Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=geXYzqVAhWCEzSYTyItYhCgWMAQ4eWxaYxsKa/q36Vo=;
        b=QbHJAFdExKlKr5xwhMnvxDLHyUHDK7T+qOe5LRx4OahWcoNcD82eu39nO4r5SmQA6V
         TVH6vT+ZgtUlWxCxFJeAuIk2jPkGBO2O6bOmg4DZ3dQdcbf0cDpDLvfyhzmL/HJ0KTgO
         TdWBi8Ash07c4ngLbOnl3MhNqgOgpei53Vy+bcFjsQCJaxeN627elKKaqhuNhXmAwapB
         3pU6JSVNiW5WfB3oFU6xIxNVdVT54Tra5+FJmjtHb9MTfpSyCeMftiim/MWRkjHfVzts
         6xn+Esh8r6dUxXuDn520y07p6oCz1E71gbCw5Y5QehtekrOwAiKg2HFHzOiy8LnaDne/
         NzDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=geXYzqVAhWCEzSYTyItYhCgWMAQ4eWxaYxsKa/q36Vo=;
        b=k6gmDupA0TU+9cwQBq8VfnP6zb9fMoIwrLr0EfY4JLeEIuN6TtkWbXCnsuCAycgSQr
         k4j9rFW2wClD3iA1zE0Sq0Fp60bM23kOz9ccsqF5GCFSt7YqoWn5a3c8sN88AEKv5P6Z
         kBm19HB24UDFrqJ+A8SQ2vWvLMip2ry1Z47+5aG7D9Wz2bbFevTF5Mp8wwz276b8ivWl
         4w20UWc+keKyDNWSG14TlrYEVTvKst6GN9gk6oGlHvmPZr6X4DR1zbT1s0TaJgBisYFk
         c4CvP+s3zsTeLLhlAg+v3kBnQbtvPlAgIuOgkRW5hblOkhnnDsd3u5QYLFmV6ElMLFft
         o1fQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tEZwD5hiSNMroWb7biIKvAYWjWmHlorqzIjiBg7IgwyGg1AWW
	G1nBVtdCbzbDUPAxWV9IVwc=
X-Google-Smtp-Source: ABdhPJyU6HUpC+jenXE5KHjQ6J7TENRG3ZHca8HDe0E691ow/poj1XyHM5zqzm5lyDZA+r5gsBcOeQ==
X-Received: by 2002:a02:8815:: with SMTP id r21mr10645589jai.117.1613752528756;
        Fri, 19 Feb 2021 08:35:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:860b:: with SMTP id f11ls1759261iol.10.gmail; Fri, 19
 Feb 2021 08:35:28 -0800 (PST)
X-Received: by 2002:a6b:8f97:: with SMTP id r145mr4641456iod.133.1613752528247;
        Fri, 19 Feb 2021 08:35:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1613752528; cv=none;
        d=google.com; s=arc-20160816;
        b=OcnVeKCXXUES/Ya26dSqB4AnKmifKQT0uZk50BsavM/ht7rU7YSYg14ZSg/hdNUl3d
         OjgtgwOhzazKa4WohT7ut7RgmLY7FRJc/sEEJnECDqN64ejlSkaMhHxYUHfsYfBaYuY6
         fHeNh/14/jqiTO+5SkoOpJpg1/ddjMJfAxhxNb5daOnRodCZurC0n+4yLq2RvTbDb97r
         Q9BOFDVdNnjEL1i2I8E4mw9YvnHVN9nFNVURQqNKyK2LzYA01RlSI/rJO93k3K1OaC1R
         Nc+Yw5h1Nr0zmbZhTtrWfoqD3ZYQ6zW06pBoOsnbcvUwtlSa2hg52ZVzW0yu2VkkrHar
         js2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Y8WUeVCSfZ0MLyF0l+HhKZtFOCIfftBPcvPseN2dtyc=;
        b=NTDyP5xvLu3Nr+LYyJ69kmREi9NkfFgjRnYbSLOQ+D/wsMHyLDLfkBbHEO+a2Sogub
         nQ8ctf2XxvHvYbLPtjRXr1htqEpGukqsUNZJ5FVL2e+p1C4ZQh/ZoMz2p/Ga6x6C5bQ/
         2qhZEnJMGr67zUeCNY28LT0FmIQQvOEdyFFF9NBpYS3CnkV/FKQO8enaJyIKB9x1nT1b
         5hhHBNzEZijg4N7JjmxPtf6fj2t4rmCZ9i1c0ZNN079zuVmAfPt6TQ21Z7zjmjnlDkGi
         5kaOCM/4guAMF7IfyCuqVuCSao3hfE/bX0psaTbTK/5yRPdyG6s6yzyS5L1J3KQD/GQk
         Womw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 207si406455ioc.2.2021.02.19.08.35.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Feb 2021 08:35:28 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 4DE4564DF0;
	Fri, 19 Feb 2021 16:35:24 +0000 (UTC)
Date: Fri, 19 Feb 2021 16:35:21 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Christoph Hellwig <hch@infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>,
	David Hildenbrand <david@redhat.com>,
	George Kennedy <george.kennedy@oracle.com>,
	Konrad Rzeszutek Wilk <konrad@darnok.org>
Subject: Re: [PATCH RESEND] mm, kasan: don't poison boot memory
Message-ID: <20210219163520.GA18049@arm.com>
References: <8d79640cdab4608c454310881b6c771e856dbd2e.1613595522.git.andreyknvl@google.com>
 <20210218104626.GA12761@arm.com>
 <CAAeHK+z-Vsuombjed8OYYpFoL4rENpf1J5F3AzQF8+LsqjDHUg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAAeHK+z-Vsuombjed8OYYpFoL4rENpf1J5F3AzQF8+LsqjDHUg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
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

On Thu, Feb 18, 2021 at 09:24:49PM +0100, Andrey Konovalov wrote:
> On Thu, Feb 18, 2021 at 11:46 AM Catalin Marinas
> <catalin.marinas@arm.com> wrote:
> >
> > The approach looks fine to me. If you don't like the trade-off, I think
> > you could still leave the kasan poisoning in if CONFIG_DEBUG_KERNEL.
> 
> This won't work, Android enables CONFIG_DEBUG_KERNEL in GKI as it
> turns out :)

And does this option go into production kernels?

> > For MTE, we could look at optimising the poisoning code for page size to
> > use STGM or DC GZVA but I don't think we can make it unnoticeable for
> > large systems (especially with DC GZVA, that's like zeroing the whole
> > RAM at boot).
> 
> https://bugzilla.kernel.org/show_bug.cgi?id=211817

A quick hack here if you can give it a try. It can be made more optimal,
maybe calling the set_mem_tag_page directly from kasan:

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 7ab500e2ad17..b9b9ca1976eb 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -48,6 +48,20 @@ static inline u8 mte_get_random_tag(void)
 	return mte_get_ptr_tag(addr);
 }
 
+static inline void __mte_set_mem_tag_page(u64 curr, u64 end)
+{
+	u64 bs = 4 << (read_cpuid(DCZID_EL0) & 0xf);
+
+	do {
+		asm volatile(__MTE_PREAMBLE "dc gva, %0"
+			     :
+			     : "r" (curr)
+			     : "memory");
+
+		curr += bs;
+	} while (curr != end);
+}
+
 /*
  * Assign allocation tags for a region of memory based on the pointer tag.
  * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
@@ -63,6 +77,11 @@ static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 	curr = (u64)__tag_set(addr, tag);
 	end = curr + size;
 
+	if (IS_ALIGNED((unsigned long)addr, PAGE_SIZE) && size == PAGE_SIZE) {
+		__mte_set_mem_tag_page(curr, end);
+		return;
+	}
+
 	do {
 		/*
 		 * 'asm volatile' is required to prevent the compiler to move

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210219163520.GA18049%40arm.com.
