Return-Path: <kasan-dev+bncBCSL7B6LWYHBBY4M7PBQMGQEICP2EIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 614E6B0CD62
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 00:59:49 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id ffacd0b85a97d-3a4eeed54c2sf3111068f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 15:59:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753138789; cv=pass;
        d=google.com; s=arc-20240605;
        b=A6GOj/b1WejWwlO9/1cFJDqhiV0vT4QDQ0IEvA82ShIjr7IP/Wk8PRPEJRvMInRCE5
         DC0+sjD3P5p+lFXOYqyyce652IHHsxkph+SSkIVcIoo1fkhPcRubVjiCX1yh94FaFxW1
         epST0dPQsSwa062fmxVyMVljSALACko9iSuEcyDcsHH4er1Q0jV/xUe9rE+/XMY9nSjE
         UE3Vq7HQjJII7U1d/3ZKX7g1MUNpabJjBSlCfdz598RX4rI89cyYSijelSCGwAcr10ad
         MAFFlK1E25h9EdGdmtxNey1eL3nAjX3IWWu62puoEPLZ+Ntm+gEtT7XejVMZKD4FeXBd
         l+fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=9a5wMMaHpau0R9nrKoW5GK1O7UeI3YUk5ZWrqSeJInc=;
        fh=6oSbcyx51EQxxIm6+mZ+UZdb0cZ/cOsQRxlvGo4pHnw=;
        b=GxHR32qx9FH/MVsNG6ejlhBcl8/XL73PRiKVaIGrnT0PGNlJijwSLRFtH/sXjXfDEh
         BvyuKGvp2Z3yU+N8OMQk4oo+ChMocVxcg+hbh9xvpQvz3RnVc955XtuLvssbADr1j2AM
         OFE0UOAQeCzQchdRREKAAqhRDPdeHeGREtvoY1JLfGmgHFvSRxPpGtd4z11RrfREg+8Z
         583vqJprbzMJRKQznvgvydoSSrKl4lyBKwSjiUWEv9NTNOg7AeH14eiehpLYOk++MwUw
         VvrIHB26QRJBdmlvAawhqIn7ZfAXo/4G4X9vzc+/Zzx18OnZx6aJj0qRXOYsMk/4Do5I
         qKfA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jz9q8A0L;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753138789; x=1753743589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=9a5wMMaHpau0R9nrKoW5GK1O7UeI3YUk5ZWrqSeJInc=;
        b=SWISZBS9CBiqaBL6lq242QUs0c4ADRVT6iCXgG68A6ibUSRmqiZbiOwV8AtABqxj3D
         81TPCBaoQl+9KFsC1moZt0a6DzaG3C4cFoQpR5VFJ8yavGApJH8HaaG+p+LvDyGksO0T
         9f8d/EDRSjaSZRGcmdYSj1HHETmEGtsJf8QTJ8kJpam1urBTAibNslOMdcMERTMuBRV0
         OOvvjCAYUmL1TISDTnM24p5v5HOhQofOdJfwO7YF5gA/Y7KE/W1ignHT2uw3OBh5EAgi
         ce/PWV7IroSJRtaQHP4Th7fhi0evLFyW9RskcsTTZy4hPGnvRJg2D881G86ez637aFPR
         uKiA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753138789; x=1753743589; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=9a5wMMaHpau0R9nrKoW5GK1O7UeI3YUk5ZWrqSeJInc=;
        b=nDOb6bQFXMP0JpgvG2xXxq556x5ZV3jtrarH4xXLq7pQa002KOEZR8b2gp8caTx+0y
         xRc6Dz7bsiYb9HgkmzfLGqmgiWGNI55Z5/6G3UdbwvzYalZrTIhicKOPERfnTovCzGkl
         3guiun9seTZUO2lSCnSnp+4JQTWKUgPsfqe7aE5gHjHbK/tw1FUXd0htVS2G3rWstQd2
         RWOvIguwJecEkjESuczJfiGPgK5J2t4lLfGaInobKdacRCvAdIwYjnk08jFwAutEVN7+
         H8Wrh/3M7i4uCsqUMr5YKjhMmzZ+MI8Emek5Fa+jxYhOdXRqF/s0uD41QfBc/yKDkmAw
         BiKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753138789; x=1753743589;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9a5wMMaHpau0R9nrKoW5GK1O7UeI3YUk5ZWrqSeJInc=;
        b=o8tMmogDBY5JT5bNkfcs7rUAA07oOTuwmcGmyOjnrHf4X06LlD4sz6qethh4kRAm91
         uhkZr12Y0E8KjV8dAo9844qvj/clKpwGLTVWZKpf+rF2gJ54Wzd7jAEEIGpeOimh+t36
         QbVq9N2zJNHoax5QvKg3vnY4nI34G0O1UWjQB2EJsAU56Llq/ntTyJZLP0fPfxlnpgqR
         LhHvsM40D0/P1alrVIxgT8tBzzWSTPU1XDQwlxaGi8nwtX7vNn3m6VAbVls5bBPfL1uL
         iskB6pzVfbg08UDwB1YDB3O/DqmCemfrXygzy0afevZYSjbu3cEpHCkeqeDIBUe0WK3L
         POZg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXRaC1efncEBTJiYzeoHXF8xAV0aKzESF+Q7o7LojJfV4352AyzWtqOFG6chxc02HkTKAgK8g==@lfdr.de
X-Gm-Message-State: AOJu0Yxrp2NXpgE3dzJLfSl7xU6jfOWX/tDYAHUh6dFTk065+uHzDT0I
	GT09fXgkFhvuZqy3z8egGdB33/CYjtCIln3xwgBG04YKsB09AcMO2kw/
X-Google-Smtp-Source: AGHT+IFzC5zNwL6ADdDDi20juJj1bnat3hDlngjOOkQhs+A9vXt9+ChOC4k/GXctQ/JUvWfoNl3Zkw==
X-Received: by 2002:a05:6000:2c0f:b0:3a0:a0d1:1131 with SMTP id ffacd0b85a97d-3b60e4bfdaemr17920974f8f.7.1753138788340;
        Mon, 21 Jul 2025 15:59:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe3LG37wdSfHNJFZYXF/Bjf2+gCvrpZLFnzZoHPZQI+RQ==
Received: by 2002:a05:600c:a009:b0:43c:ed2c:bcf2 with SMTP id
 5b1f17b1804b1-456340f396bls28532635e9.1.-pod-prod-05-eu; Mon, 21 Jul 2025
 15:59:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFnWv9GrWYtrQfDlOoXyUZU2rZxgMp9kpE2/AF0uVqUkgmDcfIJsaTjJbhgGZKLf4WZz6e+7GN2hc=@googlegroups.com
X-Received: by 2002:a05:600c:4fc5:b0:456:1156:e5f5 with SMTP id 5b1f17b1804b1-456359ee0a4mr176586195e9.31.1753138785225;
        Mon, 21 Jul 2025 15:59:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753138785; cv=none;
        d=google.com; s=arc-20240605;
        b=DztMYLT37Jn9i4+3BtIHi5V/oeif7YK66Mj7IpmnXdh9ihOpzb044n2X5u6yi2voXK
         PMCXK4pjtEzbG8ZJVB/b1GAdrDY9zwpxRYPMr9wcN4SKhuCeT4x73FUmN+i+c25+Zo3E
         6wDXj0NpJv85eKoItK92FZwDoxilhlMcHas719tfvSWZ+fN2G9OUo7A9RYsWYMntDOMM
         EHWNXEwWeKg/lfBM1VlkcZJKOlhYgUdR6PJTqfm8vb2JEtOtHA7rlATFkZS+Tt4eq//4
         NncvFdTPkO5vnURn/g8kZ2ba22VfTELCkg5+Xq99I7QC9VCYvhMTS7FOknnxlU5YfJyA
         tVcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=qziS/qpONFFAWWmGEcjsGqxLtdqROLsiMhv3HQa+DVo=;
        fh=FgyOUuzqOis+ETOVioNkKgJaOxedvpj/gRWIDX5f65w=;
        b=NCH7fmvGm0Ej+4nW1jgS8OBWrTMEnTsMCqRIMdRrCWaTdMLk1Jtovz84gi7NKnwJth
         AfIfQnX8PCEc9Ifxp6stAmZOJSn+JUBTzR2z1jwa/3xPilhW0KwsgkPcQa/W1JPfcznr
         D3fsD52w6wv1G9b0N12U+YAGUNlgz8C9XrlcCrpwCwD7UZ7g9LyLR6KU/3N5+K5kVkhW
         VjPPb36sQuIvavw4U9O+PQkEtNQQyoBIV/ZV+2yoNfj0YWpdSMs7K93QKUfv9R/7o1kM
         TRTS4V36vtYkMYktAINIoopbLtXjEPMHGc8L90Nk3nNs9chrgfIVNAjhE6D7R5oL1rR3
         HHXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jz9q8A0L;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x531.google.com (mail-ed1-x531.google.com. [2a00:1450:4864:20::531])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b61ca4bcffsi185382f8f.8.2025.07.21.15.59.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 15:59:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::531 as permitted sender) client-ip=2a00:1450:4864:20::531;
Received: by mail-ed1-x531.google.com with SMTP id 4fb4d7f45d1cf-6075ca6d617so943904a12.0
        for <kasan-dev@googlegroups.com>; Mon, 21 Jul 2025 15:59:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU5PSqZif+Jhu9wDCJAy3YHRov4K8PbaWmWKjXUPDg+gasqhnjfjNtj3DqdVtmSqX2CpsN0AkxXFj4=@googlegroups.com
X-Gm-Gg: ASbGnctNzbVkooUV7gKr0BskoIpAo4bilvAb+6vftJIz9JucevXcGye82HIkQx8e8Ov
	bfpjJpxuL6JbRYNHmrhq6EPulM/ujvKCMFmkPls9ZFOZ/5sXzyfnQaSA5ZeO2MARHq15FLOOMp+
	TxXjBankrJMjEJ47wKJhPQ8qaui+/mZHRrMWQgQppqNj/oaInyIRTetYsfmxsEHmj0/200oABu1
	s4plP1UiJ7eAdUvKNDsjUhQaN4+YzQagtDfJWFvTRPjKZKN/R3W10qAO+hO/uDrpQUfxxtOVGhz
	hELo4xlU3I1Pat5dKxWAxo/rceCLq2AkqNbZcoiNnHJtyzYVX5qLo0cmJNMV2YubbPio14vPtap
	TerLeR0hF9hEKcQYbYk0rSqBkqE5rRiR9WCoas0kVMmoeJBFnNDy6fReOlRdfpfHPCmV1
X-Received: by 2002:a17:907:1b05:b0:ae3:bd92:e6aa with SMTP id a640c23a62f3a-ae9c99adb7amr852181266b.6.1753138784434;
        Mon, 21 Jul 2025 15:59:44 -0700 (PDT)
Received: from [192.168.0.18] (cable-94-189-142-142.dynamic.sbb.rs. [94.189.142.142])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-aec6ca7d330sm755829066b.126.2025.07.21.15.59.43
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 15:59:43 -0700 (PDT)
Message-ID: <f10f3599-509d-4455-94a3-fcbeeffd8219@gmail.com>
Date: Tue, 22 Jul 2025 00:59:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 00/12] kasan: unify kasan_arch_is_ready() and remove
 arch-specific implementations
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, hca@linux.ibm.com,
 christophe.leroy@csgroup.eu, andreyknvl@gmail.com, agordeev@linux.ibm.com,
 akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250717142732.292822-1-snovitoll@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jz9q8A0L;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::531
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:

> === Testing with patches
> 
> Testing in v3:
> 
> - Compiled every affected arch with no errors:
> 
> $ make CC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm STRIP=llvm-strip \
> 	OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump READELF=llvm-readelf \
> 	HOSTCC=clang HOSTCXX=clang++ HOSTAR=llvm-ar HOSTLD=ld.lld \
> 	ARCH=$ARCH
> 
> $ clang --version
> ClangBuiltLinux clang version 19.1.4
> Target: x86_64-unknown-linux-gnu
> Thread model: posix
> 
> - make ARCH=um produces the warning during compiling:
> 	MODPOST Module.symvers
> 	WARNING: modpost: vmlinux: section mismatch in reference: \
> 		kasan_init+0x43 (section: .ltext) -> \
> 		kasan_init_generic (section: .init.text)
> 
> AFAIU, it's due to the code in arch/um/kernel/mem.c, where kasan_init()
> is placed in own section ".kasan_init", which calls kasan_init_generic()
> which is marked with "__init".
> 
> - Booting via qemu-system- and running KUnit tests:
> 
> * arm64  (GENERIC, HW_TAGS, SW_TAGS): no regression, same above results.
> * x86_64 (GENERIC): no regression, no errors
> 

It would be interesting to see whether ARCH_DEFER_KASAN=y arches work.
These series add static key into __asan_load*()/_store*() which are called
from everywhere, including the code patching static branches during the switch.

I have suspicion that the code patching static branches during static key switch
might not be prepared to the fact the current CPU might try to execute this static
branch in the middle of switch.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/f10f3599-509d-4455-94a3-fcbeeffd8219%40gmail.com.
