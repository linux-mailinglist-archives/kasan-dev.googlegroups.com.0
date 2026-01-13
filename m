Return-Path: <kasan-dev+bncBAABBMEDTLFQMGQEVKOJUPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 57334D1AA57
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 18:32:34 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-3f55d1efcefsf15384289fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 09:32:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768325552; cv=pass;
        d=google.com; s=arc-20240605;
        b=QffQXwQdeb1P6F3ND6cjLLB8w3VzIUAr+8aD4CcY9bnc4YERzic+SHbgKreinImfhs
         AIqg9BA6K2m+n8yh70IRSYympL2PP3zNroQB36KF6VMwhG9hFaAoSoJv1Z4Ped7JdI1B
         Nf97lFLId9zCEdir+QGi+6CPMb29307lKt2le1vbmKy2MGsM2k5blqvACHPt2yTnf7eP
         DDdtRuMqVYNCAzbBOGfDFdTl2EzhJHKaCEyhS1sX2njLyGAzrlbRzLVo4C7f8M4Ja+P8
         RxtfFvgyFfmKYSEpbNLUHWXxM7A+FnLAqo0KEcPVoWbEIuQa5+A852P+fzvKRBsYj2WB
         g2ag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=mlqG8ZztP2VtqLgAjCQjPZ/TAivy+kQ4Oi4oVW1KVe8=;
        fh=vrdK1MuutyMljcjjONhOjDn9jg1u2szelYoWZAG8/bA=;
        b=h+qWQpZtYW9lfP0jPCONVr3ibtDx6nK1wwD/IvmoXEm1Q38JCtk5OREr9Q6CODpo+K
         RTpQV2jG1tMYL0SP/tq+a6LERltoX/3rR8sH0XVbPElxFH3p3zMjeEDiPoBn9E2eDO7z
         WgScRPE5lTzlW1bt3yGhqCuGqev/Jbv/ugKRlxBJjlVcehxS/17JUoEC9PEGYnKYowNc
         Lxs+ZZHFzOJdmlZH9CqwKguLM0cIzCNdBob1KCiKi3i2OlrNcrGSWnvGl/CBo3ITU+mT
         SLJ0b5aPHCzd+EFYaTj5PDF1sgrqMg/Rn2vOpStvAygDn1kmRyp7+UPBBkAlmhw9zDsN
         faJA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=gdXMnEdZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768325552; x=1768930352; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=mlqG8ZztP2VtqLgAjCQjPZ/TAivy+kQ4Oi4oVW1KVe8=;
        b=qfdpWevX6IDIJ9ZW1XFpGtwyH/lGpqwta+wzhuO8ruEsMOktmc2uOue3SsoD75vMJa
         Qh6Ibr623HnVgy9SYXY9XU1crXzrwjjRcBd2qKq/3EGLybMb2RoG+fUGbjs6SnzX8sMz
         1tnXyO+xyBYW8N0gPe5hwzKNmqONLwT7sY1C9Jaiwg5hswq6NmWy7oNbRCBsdTN9UO4J
         TSQyGPquQQyPIATZj3cRJhKXVk7o8JQKWCtHzl+vwoWM4lAyrqWXGphEaPLDZcpwG0Cy
         bsdV48K0bQnJI1fcJZyRuCdfDKpFNHo9SJ5kQL3QvdB1gPMaYg/YtH+LsxAa27NA7vjQ
         fYbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768325552; x=1768930352;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=mlqG8ZztP2VtqLgAjCQjPZ/TAivy+kQ4Oi4oVW1KVe8=;
        b=gJLK08e/khEi2HkMU1N4D1UEVPvifiJkY3Ez4zN5xpAED7dhLaeOI6dJWe9W8ZT86O
         ri/JhLPomv4Ul/OhN9tMRObsLOXMVAmBqo1SeEHb+7m3BUYjhpM9mwyK8wMYHsyzG2sR
         X36/y9fvnNUoVRom+Xo5dwm0B3f3qJIVszREb9nQoo44r8ktqvwb2IAZfAZGA8Fuj8UC
         wmJuf8fnuUnYQJw3W9DWA1fZOUXV1aR+D0k6qb231JNCLIwunRW/d2IeYvYxDVi7+Bgk
         r+mFgP0aK9+DmDgFL9UfRQiIL3L4H+tioqLJHjoB0LqdnrOIFdw8NcuB3Rluej8O05eh
         GeWw==
X-Forwarded-Encrypted: i=2; AJvYcCUNX8GmISxBvM7zN/yZkMIS86pEEQkfTclfqFjtSo8CWUm0EBwBUsAbtX7XuWJMkiz9g9/H3w==@lfdr.de
X-Gm-Message-State: AOJu0Yzcn36i8tjpZUHOFyn6mEU+hrwaJIWxnBv8bPJ0yx9TReK+wZt+
	MIZJtGUnTQT8ean4UuslipK0JLGb/Q5BMLJPDlbAw9d5rxYc3mrNEVVU
X-Google-Smtp-Source: AGHT+IFZDaSbsISZoodLkpz3GOWMP0JQuZ2OcKMEYOkzM2YXuqx1rcMccuXLg6rD9I8ejQDcWOgn6w==
X-Received: by 2002:a05:6820:6e81:b0:659:9a49:8ece with SMTP id 006d021491bc7-65f550a6b58mr7189340eaf.82.1768325552532;
        Tue, 13 Jan 2026 09:32:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E8r/cbqXUHlsowP2wQf2XCjIRpdDhyQqSwcb+uhdvvaA=="
Received: by 2002:a05:6820:1948:b0:654:f519:683f with SMTP id
 006d021491bc7-65f4729b4e2ls3775612eaf.0.-pod-prod-08-us; Tue, 13 Jan 2026
 09:32:31 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXsPlSElhL2f3ozAvMMRZpC4oBqpjo2dK7dvYeYSJvczUCAcqN2NmLpYRJMbFPwsuRCetDrmMG4RHA=@googlegroups.com
X-Received: by 2002:a4a:bc94:0:b0:65f:75e4:3478 with SMTP id 006d021491bc7-65f75e43829mr3223741eaf.76.1768325551520;
        Tue, 13 Jan 2026 09:32:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768325551; cv=none;
        d=google.com; s=arc-20240605;
        b=dnJjb3QL5WvlRoZgutYdplFpaQ7kUYP1shaWmSbKUBnnwV5QQEUVxS37jS/2SX/gou
         leel0oOFas19ClfBbXGrXyJxBoJrVDC+f/dmHW23qU0V29EDCwxO9+9rEDzC8Rc7OrvN
         4Vbe8VmHXyRDAXeEpxrMOc87dQXnR8/zd99z35miqi3fsmalteWZo+OV1ogqvQw31Fzi
         PNBQDne0TmjCY03oyZF/TA1QgQh7IVkCCztIh0Zs0Aka/tHak/P+bKUt90NxO0F8GyCD
         eYxuKoEGURuw1NLKpwZak6aqqB65yDvnkqTaFVUqL2Jm3ftsjuXd7vu9jnxihAoYp89+
         4p0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=7QZm1CZeu8P4ksfxFy+d8iaWyvI0I3DKeA/oH7Yr3/E=;
        fh=1jHhoyONoZMTD7YVb/QYqHVWqFJh22gwx5Kb4tgXXXA=;
        b=KWP4odpYyQVUk/cCHa9OGUn0kVk6AcJ7ZhPvkvakpMrbqazEI71bGa3cIbyqz4J8DP
         IOlkcNb/b9slhW0hpQ/bh4WQPTuHPGHv5wbgj/9RsgMnlRzZI33u0dkwkyvKgN9L3A/C
         MmXXZutVXFu4pYoieWu62be1HixrelnOd8K+7ORh4/e+ph8nPX6HOoXHK/pEVVg+6WRl
         288RHM9hKWCtrNG6XADa0vhDSj4ap9bjFDHOf4PTpot0tIU3YCLMZofDT//PyhDiNzao
         hpDCq3WshJbAY9FfVPzPVEwM3YQnEPvMmbEGEDUZpynWGNwu1QtowV5/g1VaJagvFPyE
         K9Qg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=gdXMnEdZ;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244123.protonmail.ch (mail-244123.protonmail.ch. [109.224.244.123])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-65f4978d624si730810eaf.3.2026.01.13.09.32.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 13 Jan 2026 09:32:31 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as permitted sender) client-ip=109.224.244.123;
Date: Tue, 13 Jan 2026 17:32:23 +0000
To: Andrey Konovalov <andreyknvl@gmail.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH v8 02/14] kasan: arm64: x86: Make special tags arch specific
Message-ID: <aWZ_aRFfWNWiqzik@wieczorr-mobl1.localdomain>
In-Reply-To: <CA+fCnZfQmhSyF9vh3RzreY7zrQ4GbQOp5NbA0bXLHUMG6p28QQ@mail.gmail.com>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <be136bf8d1a6ae9ef98686c3ba0b6a4e2ea2e780.1768233085.git.m.wieczorretman@pm.me> <CA+fCnZfQmhSyF9vh3RzreY7zrQ4GbQOp5NbA0bXLHUMG6p28QQ@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 023a5d308556f78925918902544da2df5131a718
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=gdXMnEdZ;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.123 as
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

On 2026-01-13 at 02:21:07 +0100, Andrey Konovalov wrote:
>On Mon, Jan 12, 2026 at 6:27=E2=80=AFPM Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Samuel Holland <samuel.holland@sifive.com>
>> diff --git a/arch/x86/include/asm/kasan-tags.h b/arch/x86/include/asm/ka=
san-tags.h
>> new file mode 100644
>> index 000000000000..68ba385bc75c
>> --- /dev/null
>> +++ b/arch/x86/include/asm/kasan-tags.h
>> @@ -0,0 +1,9 @@
>> +/* SPDX-License-Identifier: GPL-2.0 */
>> +#ifndef __ASM_KASAN_TAGS_H
>> +#define __ASM_KASAN_TAGS_H
>> +
>> +#define KASAN_TAG_KERNEL       0xF /* native kernel pointers tag */
>
>One thing that stood out to me here was that for x86, KASAN_TAG_KERNEL
>is defined as a 4-bit value (0xF). Which makes sense, as
>KASAN_TAG_WIDTH =3D=3D 4.
>
>But for arm64, KASAN_TAG_KERNEL and others are defined as 8-bit values
>(0xFF, etc.), even though for HW_TAGS, KASAN_TAG_WIDTH is also =3D=3D 4
>and only the lower 4 bits of these values define the tags.
>
>This happens to work out: for HW_TAGS, __tag_set resets the top byte
>but then uses the given value as is, so the higher 4 bits gets set to
>0xF and the lower set to the tag. And for saving/restoring the tag in
>page->flags, everything also works, as we only store the meaningful
>lower 4 bits in flags, and restore the higher 0xF when doing ^ 0xFF.
>
>But this is not related to this series: I think the way x86 defines
>KASAN_TAG_KERNEL to be 0xF makes sense; we might just need to clean up
>the arm64 implementation at some point.
>

I suppose while there is only one such mode that stands out from the other =
two
there is little hint as to what should be generalized. As you said so far t=
his
scheme we have works - altough it is somewhat convoluted.

One thing I was thinking of was cleaning up all the #ifdefs for different m=
odes
into a more ordered structure. I think there are ~24 ifdefs in mm/kasan.h a=
nd
include/linux/kasan.h and many of them could potentially be merged.

...
>
>Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thanks :)

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WZ_aRFfWNWiqzik%40wieczorr-mobl1.localdomain.
