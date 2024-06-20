Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5XR2CZQMGQE6EXFIXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id AD8549107AD
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 16:13:12 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-25989b941e9sf1520182fac.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Jun 2024 07:13:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718892791; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ig20p3eB74PV55TcI7RbwfiYpUu1ujuKw1xP94B2YMsJZc6b4nU0zTCCOhQzWW+JiT
         KmOYGxD4qRq4AvQ4ZCNuystCgZ+BXdX7iKA9wZWtvTyfXhrir+ctFh7PbF0x3jBgvGAM
         fA/JA//oOa4aE08P9l+2WYWm9yQTsAieOkuIiMWPejVIoqWCKAKSkhE6K2UKYA6x72j7
         TNyFo59N36shgDiY+UeLrrshDJBLnmK8jts43Vw9gFwVernJkgBHR9lTW4cUPYNEtK8g
         oE27VglY7kceSQ0PtHZiZbqp2YfhZxUksDxOy5psZ6DwJIJitCGKC3mOfwimUvnMm5IB
         eb5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=S+K07QJBM8XYs2xSN+z51K2yzaEANpBXcWA4yueNi3o=;
        fh=ySKS1qggzJTaxAKt5zA93I6R8CdfMXpgfrNGCcXsemk=;
        b=g86EKFlUdS8X2or3eewY3ZQ7HyVwpic6sjrLorhM3abiL1PGF0+crrhVaTG2Anp9Vn
         8/T47Zb9iIISGIFFVVBYHj4BS9JWLKPU1i5xGz0M9IqYPoGGnMmDWwtFDnVi6g2U/IQ4
         tg/VPpft4kZ8e703VPjxbvEDeVo87Ir7BuyUiGUMDgxAFgtRUgXydb8szQZkKtJXL1nm
         2PuWnuJYlMc5kJg347+inbC7FWidXZnUzwTeqWK8AQmAGCAwzZKx1HfubIDPg9rE0gMW
         UiPTKhoyxM+IBTTC9mMFs2vITHC3449syi1N2N/sQnR20x4oIC+Q079veCbQwHS2md3Q
         IB5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CCfMv3rr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718892791; x=1719497591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=S+K07QJBM8XYs2xSN+z51K2yzaEANpBXcWA4yueNi3o=;
        b=eNwDx1E4u/wIz7wX7Y2FN4y4EiT4WbBWaVK1/4i/m4Ij+9v39efMRCyAMbIZH0zbeu
         T6Vy4g9i97e01NOMznz79NW1lkJ1hqiERFgt6y47CHLuOyD8jxaz6F+EyclMNDsbcMhY
         c/8RAMIEOsDwUpY9fQlprTtoJv87vr4Dh4TqCNooBWrwn2f2/EAItuFlY6eWIs+Rckl5
         QpzLEosap0Nrwe+fxnQINkgazDzm6ktPs60ahQ2R/XzKeyvUqVwlQru5UHZt8iV+HPGl
         jWFVdus9rBP6b8ljr2OMqED5k9l6nDBWzdxHc1Xk9rpzR13CdN60Jokc5Acl0gxYdVve
         fzfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718892791; x=1719497591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=S+K07QJBM8XYs2xSN+z51K2yzaEANpBXcWA4yueNi3o=;
        b=BoKpt1QVzdR/O7rFBH29IlAItkW+qUzlQ6kV0ZZvUZUwiSN6OhiKafVwA+PnS/li55
         v8M8PzW7J6RFRzhCzxqRuD0jpHLpqXiPAVxYEZFyygCdPToqn0Hdw+xDj+9YJRbJBoqW
         +kZmOCfNwSlFKqf76JApUvdi4wLTHZCDJdz/o5YvgvNP7ZufIx1kO6rloSAODKX3sxde
         sCWktOgtIc72rhIUG6gOXSJJeHFC1HaMBpFRrOfkeBX3Gf7rAD/pj3w7kS7ER81cwpCf
         S6y2Fp/nc7iunQusAfzbZmhx2KsxYyfifW/UrnR8P0ga9+kZjhJDcf5R0wVlXWalvBRR
         HkGw==
X-Forwarded-Encrypted: i=2; AJvYcCU4ze8NIX7b+oag+ZOLlnL/e3BmYefoarUm9WI2/G6bb6eFNLeEBZS3crisoyx7aipPizrU6EV/GvpMyJKhAij1gYrEZv6yJw==
X-Gm-Message-State: AOJu0YzsNfmLjwFM6scFsSWZZINOGoAFzwXiztNOpGjKYClifobxxjVK
	X+a4FRtLX9408YjO6BRztgW1rcTYSPCGp1cA86TTzpacYf3lWr8t
X-Google-Smtp-Source: AGHT+IFRsZBiW6IZfLcM2BCWmnJQpzTrjCobKAbt+cuTNzUKDaVMVK/ujk+8ZjgRipO90KGA83oOhA==
X-Received: by 2002:a05:6870:96a3:b0:251:2c3f:7a2e with SMTP id 586e51a60fabf-25c7c6e2482mr2609677fac.2.1718892791053;
        Thu, 20 Jun 2024 07:13:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:60e:b0:251:cbd:f69f with SMTP id
 586e51a60fabf-25cb5f3ea71ls88817fac.2.-pod-prod-00-us; Thu, 20 Jun 2024
 07:13:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVrdvc4P3haD2ywzNegzjSJaOriC90NpdSXI6E0cjIC2nIh8tjC6KVh72Nqfw9O8lVIA67srYKZHTEWMvlfXXYqxJbR5/Z9CO0MmA==
X-Received: by 2002:a05:6808:1a0e:b0:3d2:1755:bc40 with SMTP id 5614622812f47-3d50ef9cb63mr3992239b6e.6.1718892790263;
        Thu, 20 Jun 2024 07:13:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718892790; cv=none;
        d=google.com; s=arc-20160816;
        b=pIBXxP0t/2eo/Rw53zcrViSejJyjjtwcyindcS+B4ylHkVHnYf22ItOylPauy5f2z0
         cFbxvqGkTXdx7AADHzgbF95LgTCp6s2HQJtKRzO/jCk5PRqkhaFiX9cNfTU87GUCy7B+
         iW31uS1dHTT9hHYLuMTUvWabZnagOZRdVPNFDL/O+Nv458RRciOzf3Wi36qbCQ9ibOok
         lmsHpsP0v9hsBOSS5ZMwlNJ+pK9kZIe+oWYuRHGmwQneI0nFiDvMSJWdQgNqsvb4/YUt
         ozl4ksFHz31V8ELO1JVbQbl2AIGXSPj+0ZE6hlukJfI26KhNUq3FEXSBDgaBjTjRMcxq
         eTlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=u3mtQdfb9A11JyTlqi+Y0vHD4FYCjBVw/J95DOMDijw=;
        fh=gKl6j5BVcmxT7Vt12DqfDDQoAG0NW4HAd/GOzTLu59M=;
        b=bQfbA/f4iRo3MEJJfENw38UNUbLjlMyo5/9/SVtz/2aFTrXkRbxNZ8aLWZGRcidDez
         DWfJ+AOvTMMFJIk4aRjYN5K7YgmMKBDrhkyugmieomQEHXrcfTiaUVYnBhO70w8okEzC
         SZg5nKRj5+qOdELMv7JnTUge+3/t7dWz4/EW/tCHAlHKPo6Zjpt5QVMqSRWtorgpMB5c
         pP9Q33cPVRwef1iz2SIaJO+9YzC72PmbfHsldZZANePfoPyAGhKb8Ixm64LX3ezu8GnP
         xslk6jKB4aaAnqwdGCzZzfZ6quszuq0JpnCVZnQIGzIGw+1y4tv5QoykZ/RSHSlsPE8Z
         lI5g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=CCfMv3rr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf29.google.com (mail-qv1-xf29.google.com. [2607:f8b0:4864:20::f29])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-3d2474fecadsi849113b6e.0.2024.06.20.07.13.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Jun 2024 07:13:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as permitted sender) client-ip=2607:f8b0:4864:20::f29;
Received: by mail-qv1-xf29.google.com with SMTP id 6a1803df08f44-6b4ffc2a7abso7808846d6.1
        for <kasan-dev@googlegroups.com>; Thu, 20 Jun 2024 07:13:10 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWA7fdyNucLBeysU1e35+IdpnIbgIvWVlwto9xpjMzisyJNBiGJJpv2dcEpy9ZxTvGqyMBJ0TcssuhAJ2c361R/gi9R30WokhqyaQ==
X-Received: by 2002:a05:6214:411c:b0:6b0:6b4f:b17d with SMTP id
 6a1803df08f44-6b2e2494d91mr144823496d6.32.1718892789486; Thu, 20 Jun 2024
 07:13:09 -0700 (PDT)
MIME-Version: 1.0
References: <dgsgqssodokkzy6e7xreydep27ct2uldnc6eypmz3rwly6u6yq@3udi3sbubg7a>
In-Reply-To: <dgsgqssodokkzy6e7xreydep27ct2uldnc6eypmz3rwly6u6yq@3udi3sbubg7a>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 20 Jun 2024 16:12:28 +0200
Message-ID: <CAG_fn=WvsGFFdJKr0hf_pqe4k5d5H_J+E4ZyrYCkAWKkDasEkQ@mail.gmail.com>
Subject: Re: KMSAN stability
To: "Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	x86@kernel.org, Dave Hansen <dave.hansen@linux.intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=CCfMv3rr;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f29 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Jun 18, 2024 at 6:42=E2=80=AFAM Kirill A. Shutemov
<kirill.shutemov@linux.intel.com> wrote:
>
> Hi,
>
> I attempted to use KMSAN, but I had difficulty getting the system to boot
> with the feature enabled.
>
> The kernel boots successfully in my x86-64 VM if I enable KMSAN on top of
> defconfig. However, if I try to enable *any* of the following options, th=
e
> boot stops:
>
> - CONFIG_DEBUG_VIRTUAL
> - CONFIG_DEBUG_LOCK_ALLOC
> - CONFIG_DEFERRED_STRUCT_PAGE_INIT
>
> The kernel becomes stuck just after KMSAN is initialized. I do not
> understand the internals of KMSAN and I do not see an obvious reason for
> this failure.
>
> I have a feeling that the list of problematic options is not exhaustive.
>
> Any ideas?
>
> I also noticed an instrumentation issue:
>
> vmlinux.o: warning: objtool: handle_bug+0x4: call to kmsan_unpoison_entry=
_regs() leaves .noinstr.text section

Hi Kirill,

KMSAN has limited support for non-default configs due to a lack of
extensive testing beyond the syzbot config.

CONFIG_DEFERRED_STRUCT_PAGE_INIT:
This option conflicts with KMSAN's assumption that all pages are
reclaimed simultaneously. A pending patch by Ilya Leoshkevich will
disable it when KMSAN is enabled.

CONFIG_DEBUG_VIRTUAL, CONFIG_DEBUG_LOCK_ALLOC: These options cause
virt_to_page_or_null() to call instrumented code, which should ideally
never happen.

KMSAN calls kmsan_get_metadata() for every memory access, and this
function is usually fast because it's mostly inlined and only calls
non-instrumented code from mm/kmsan/. However, debug configs can add
checks to virt_to_page_or_nul()l that call instrumented code from
lib/, potentially leading to deadlocks (if locks are involved) or
stack overflows (if memory is touched).

For CONFIG_DEBUG_VIRTUAL, I'm preparing a patch to selectively disable
instrumentation of arch/x86/mm/physaddr.c to address this.

The issue with CONFIG_DEBUG_LOCK_ALLOC is more complex and similar to
a previous issue where RCU calls caused infinite recursion
(https://lore.kernel.org/all/20240115184430.2710652-1-glider@google.com/T/#=
u).

Possible workarounds include:
- using kmsan_enter_runtime()/kmsan_leave_runtime() to avoid recursion
in kmsan_get_shadow_origin_ptr() (this _might_ lead to KMSAN false
positives in lockdep, as we will be ignoring writes to the global lock
map);
- using a separate per-CPU counter to detect nested calls of
pfn_valid(), which is already called with disabled preemption.
The latter option sort of works, but doesn't eliminate the impact of
lockdep checks being introduced to _every_ memory access. Given that,
I am not sure having CONFIG_DEBUG_LOCK_ALLOC together with
CONFIG_KMSAN is worth it.

I've filed these issues for tracking:

https://github.com/google/kmsan/issues/94
https://github.com/google/kmsan/issues/95

Additionally, I'll send a patch to fix the objtool warning about
missing instrumentation around the KASAN call in handle_bug().

HTH


--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWvsGFFdJKr0hf_pqe4k5d5H_J%2BE4ZyrYCkAWKkDasEkQ%40mail.gm=
ail.com.
