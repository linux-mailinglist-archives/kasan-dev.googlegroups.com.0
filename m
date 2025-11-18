Return-Path: <kasan-dev+bncBAABBYVU6HEAMGQENOY72LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B503C69202
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Nov 2025 12:37:08 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id 006d021491bc7-657501e1dcfsf3070564eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Nov 2025 03:37:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763465827; cv=pass;
        d=google.com; s=arc-20240605;
        b=lXK/dJlQBRgxHv0T3xRrJjcPhy+/FrSQQ/T/0iKNHcquHhfHP3VPvCTnwhrpxS59ZM
         Lz9R6Cdb2WxbDYYe9kExaww8qQDl1cGl0rzAAN0uOrMdbz1YqB0UuYgYozTkB5WuNJsa
         c/b5UImKMe5s+UAlR5B+iLXYuBbOJhvoGeD2gc8sZngrFCUFSN28WDNwhuGca3qSqrYd
         FwIABiGGvkWKnz7c6BRZVeauIgtVbSMOgJtGO1pcaLsGW4pR9pObPugW0grE6A5Dds0C
         xO3DGNbc0vDZX19fmReOpgZVm5UZ07LA4YM3iQe6YkOgWw48HqGasJDL6jUGddJbXPqE
         Myjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=Ldg00UsxPaKqhSlV/zTH/cfkF4BtInGY4ks7mVUZLDA=;
        fh=PM2ITNh3yXw4ZYRJKe3xJPjAuQ9ZD4cx/HHTu9/n3g0=;
        b=bbwrfU2dIbpDhPar9bRlGxd4WgqculQ7t+PZGFPc+/eI305cO8qHeWMej4emJdK6p8
         qN0E8R7KWu0BnkFEG76ACN4HVGK4Dm0PaacilPYo0lCNYcz40Ik7LTNvbtw35BpV3bbB
         ZqQST3I4n29luuc2K3iOKBaJdRNKpqhNrO2otIfA33reZ3KpFJ+EgbOdZOZX23Xc5UX2
         xQC/sV6R8O2I7ghwEpAvCbMrECrk7hRJ7EpgymGTqC6nHqObpHeo3YqHSmGvJwykxA2k
         1wD8p16WYlk7CPd32gLEOrKqC/PEkJ6OvOI/BKPCMNaE7exE/MJRyPaUu9zik2EFOH2c
         1iOg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=A62qJ3HV;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763465827; x=1764070627; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=Ldg00UsxPaKqhSlV/zTH/cfkF4BtInGY4ks7mVUZLDA=;
        b=bygP50+g+HYFOejAyxeWc5wUaR137NZeA0tPhGfXbWdSeT3t2+UxfX6BDem1H3gFFk
         Rf2Zul5Cd5bdzz/kV47vnvXmhdTLrkzuy6Z8ZWhKsTZcV1/TnmY2TDujZWzakprK3xIy
         /47oBpNEv1UzSbXwUVUPp2fk6a/qwNt6JFHxOqpGG+3N4z6WUHAKDLCGxI+gpxUhkQdD
         CgVZ4cIGr6+AixoriVpfELaKnvagIoouw4L0Pm9O+kP9A6HrkJKYdpEltQdjG9rmMPXY
         T6uWYHSGAOOx+Mu4wk6/5kl4tidt2gOows2H++Nt8iK+Q8Yq/ujvysKFfjegG4bZDBVv
         Bq9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763465827; x=1764070627;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Ldg00UsxPaKqhSlV/zTH/cfkF4BtInGY4ks7mVUZLDA=;
        b=UfDesAHnTsZaY9nQPFhcg+WBkU3MDZdxk5AE4J7Mb3IXam3aKAnlmg6v66Ss35N+HS
         8HkEHTmq5jLbkgkMyKhdXXFfZKVvoprvD7/QvqUivw/aRqEDtng7Q2H2MmS9rJebUxBp
         8QTSGyI3JeuMTxG6uIoFc8GL1dtQGFIP4BbDtpLXijFjlG5KnzLBYdlOGUSasG2PVH5Y
         xjyR3eTKtBT7sJEPVpP887xSKmGOJiBIdXfMOKbQ7gpV/p7fDhjcUfI0/AHLtJD4aOUX
         6kdzx8MieAxDzFcEQcf3Gtxa5kBpSo+MMpGnfBe/2QDjEvxbB2MSAkt3w4yBI4e0/ssT
         FIow==
X-Forwarded-Encrypted: i=2; AJvYcCXc+nsfHGGnYwSA5gQ6bUbkVK3U2uif/KVFI2kp6TyJoQ4YGadlzwD1iIQTSI73boOXsL4GVA==@lfdr.de
X-Gm-Message-State: AOJu0Yxjg/Z7hhN6mvQ23M7gOUKns6TEP8WUZ+EJRXhSkAOLtrDxg5lN
	ik5bi4u4eay6ZOi/skL3EPs7ubLStSUIAdZ8UlTsM2T/STxesaXFVf9M
X-Google-Smtp-Source: AGHT+IGosJ1DxPdKWrkdRjg+TIscUZ7+T145rzehTt5s8a4+CEGo+HMk43sglOTP4DhZzlfqB5tUjQ==
X-Received: by 2002:a05:6871:9017:b0:3ec:321c:b2ac with SMTP id 586e51a60fabf-3ec321cbccbmr4751576fac.37.1763465826796;
        Tue, 18 Nov 2025 03:37:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+b7BlfVFQ7UQEx0+48TSjSWaS7uumn5gVXHKMABd4RoPg=="
Received: by 2002:a05:6870:400d:b0:3d5:92b8:659d with SMTP id
 586e51a60fabf-3e84b360976ls3534901fac.0.-pod-prod-01-us; Tue, 18 Nov 2025
 03:37:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVMicqFuPxBvJToWWYqKyxJvtRvcqVoNiNaCV9gvc3yNuCn/RWBzm2I9UR060802R9mDl5Af1/XtmM=@googlegroups.com
X-Received: by 2002:a05:6870:9a14:b0:3e8:8e56:674d with SMTP id 586e51a60fabf-3e88e56b23cmr4972354fac.55.1763465825583;
        Tue, 18 Nov 2025 03:37:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763465825; cv=none;
        d=google.com; s=arc-20240605;
        b=J1KQw39MbiB9k/VwG9Wr27rbx5IkkL5xcIoREMj4tufU4vA86EN8orJ0KAVKbVcQVL
         DkW6oSqv1WugB1ZeLOaQdXcXnbu32UTPvh391nlIf55C13KZBR3iFNOoUi7oZC+U/C4t
         dWoufmIq+iCE5YCz32JJMYf4zjkvlJ/NLFEWQYvn4wZi+sMaDuZiG55eXAMV4qTDh1y0
         VC1ahU7GOKLvNDw4BtDYe7npzbnNCUPOmG76w7yaQy677fzWNZqQ1wYiumhVLe8rJcQx
         4xK5Y/FYaq+XwynZ2wwAVPMIXfqUwxTtlGtGapnZhY/wJpWf6jG3SkFL4QzoQsvCRQw8
         ljrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=DE/tg0nJoToaNRa0UqK6uA3/ue+ZalTDQdxOe/ZUB5I=;
        fh=k/v3HmGt1ClsgCYHhLlDuddeI/n3RsPAzSnvJM/IeI0=;
        b=lJxcgv+Tiud2twvru/8GKGEY1J8nhnYoCcC89LRlD4OSMaCO/p+lPhF68J4L1ntvXR
         R3GRqhCstIB9+LcRMczDLMQRZ04xOKouDvmZGNenkABU/P39HJPPuud5M+B1NqNKMiJj
         Ho0Fj8ycvwlZ/ACUvRTu1nlXUbboctBjsbXoqKTuqk0IYNUfIg0X2zfFvtI8BDksOMz6
         Q76elYfbG6kX1uGdXEB/dqVkAwbjJkWLRmla9SZaN15eRpxHo3iwLxWAIC6d0hrOLh9S
         VdapZM6yGvGnqWDP47d6odfhOw4VCM81GIaqRKwW9Q4r1Shefb1K3QJ8RXdiaDDkOFQI
         g0vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=A62qJ3HV;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-24418.protonmail.ch (mail-24418.protonmail.ch. [109.224.244.18])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-3e898b6b3bdsi284683fac.2.2025.11.18.03.37.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 18 Nov 2025 03:37:05 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as permitted sender) client-ip=109.224.244.18;
Date: Tue, 18 Nov 2025 11:36:54 +0000
To: Alexander Potapenko <glider@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 14/18] x86: Minimal SLAB alignment
Message-ID: <wzxmteswfsj3idgwyai7m3ou7kulfmxerxkq56xfhoqhvpz3tq@omy5z7eb3esp>
In-Reply-To: <CAG_fn=W033hGM7_jnj0irwW0gc6McLw2nbhfZROWfieqKTxVdQ@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <0ca5d46e292e5074c119c7c58e6ec9901fb0ed73.1761763681.git.m.wieczorretman@pm.me> <CAG_fn=W033hGM7_jnj0irwW0gc6McLw2nbhfZROWfieqKTxVdQ@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 91807d56d4653d1f85cedcda318ac58c40da2783
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=A62qJ3HV;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.18 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

On 2025-11-10 at 18:48:35 +0100, Alexander Potapenko wrote:
>> diff --git a/arch/x86/include/asm/cache.h b/arch/x86/include/asm/cache.h
>> index 69404eae9983..3232583b5487 100644
>> --- a/arch/x86/include/asm/cache.h
>> +++ b/arch/x86/include/asm/cache.h
>> @@ -21,4 +21,8 @@
>>  #endif
>>  #endif
>>
>> +#ifdef CONFIG_KASAN_SW_TAGS
>> +#define ARCH_SLAB_MINALIGN (1ULL << KASAN_SHADOW_SCALE_SHIFT)
>
>I don't think linux/linkage.h (the only header included here) defines
>KASAN_SHADOW_SCALE_SHIFT, does it?

I revised all the x86 and non-arch places where ARCH_SLAB_MINALIGN is used and
all these places also include linux/slab.h which does include
KASAN_SHADOW_SCALE_SHIFT. So there are no cases where it's undefined.

The minalign makes sense defined here but including kasan headers causes
compilation errors all over the place. And I don't think moving
KASAN_SHADOW_SCALE_SHIFT here makes much sense?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/wzxmteswfsj3idgwyai7m3ou7kulfmxerxkq56xfhoqhvpz3tq%40omy5z7eb3esp.
