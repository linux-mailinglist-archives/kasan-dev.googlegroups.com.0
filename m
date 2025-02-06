Return-Path: <kasan-dev+bncBDW2JDUY5AORBN7WSO6QMGQE5ODZZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 514E5A2AFE6
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:11:06 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-436379713basf6430185e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:11:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865466; cv=pass;
        d=google.com; s=arc-20240605;
        b=RQ0fN4TGfC4ozWcRw4Gp99cFf4fBRAkEhjpPBMHbimfQMMCxselrDHiydTo9MOzj1I
         T5sWtLETvvjEpajknc6vHaMTwsyqw9FRJQG5g9YYV7XZugYjiOoV7e/m92q+kE0lAY72
         zHQaXieqqG3QsKW2L6iV7xeMOeK9BNQIUN3lHjYKTPj5N9s0Mb3xXe51H1avOf3kvuAt
         6wCaqYX6CdaTdLddeqL8JGwuDAQMc08wDGOJczbtXNYxv/78ZZqliypAI5dazaz9i4x9
         8SyfROSGqrQQRYNBqycLiCVmqTAUIndrQz/uMJbsENCaRTUZiAxM8T/k6nkkMCTWy2qQ
         OuKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=z/IujdnACFvmg9pid3AjfR2+XDSfjSFR3o7Dmar6e9Q=;
        fh=zUbCKn/9sjOBEoyJj1UxpdVHB7L7CY8fWC3O8YXgPMs=;
        b=EqhGa3hkjXIq8VTPXx2MDig+p2dI32B6ZbEaTAa1j8MuVAYAcpa3y0cf2dshgriUwC
         nx32J8zH6PxftJNRp6QzyN05v7hOxM2UVqHjNuz8N5fRpZyuXhq1PwT85cZDwf/NykvS
         OHbDWvRboTOBGy2muCdAYxnrPA55uF9g9RCBaPMP2z1vnpYs3rONOU6l9HnGGKDrmkHo
         +aL+S2w3k1iUlZWLGMgmV/nrv23ZStvLZceWq6EFWe+nFsCkyPVCJdFAwUwVYurwNQQO
         SXOITzfOtsDJ+Eq+DM0wJH5Ak/GisjIZBsMqU2DmzWqQ7vn4gfSS8Nsn+OS//kbEqLu5
         G2Hw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gygMFrCH;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865466; x=1739470266; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=z/IujdnACFvmg9pid3AjfR2+XDSfjSFR3o7Dmar6e9Q=;
        b=Cvt1ye0rpT5RzSrzwz6rZexhPABKmj6qpRkWC27rQFef3gaXTQq8hCQqPWI8RuFUAb
         miRC4JBnvJsMlFwDj47MJijotl8ihPOjGkXOBJLqAQ2J5TrK3tKfj7+ldyKXnc1LBbZh
         0mTQbaBcM+PAW8X9znojGQaSoYL0YYVarO8hdjZsHe0a1Q2ZEnDU61shgqGdGlk3Rr/P
         pLBuoPa4pv+astRmW5ZRCnBrw2flDNV8Mra/1YVeRZDSEP0dd4SQi9sxWxjqME26Dg/w
         a/JMgx3uKlMcX4RPfadV38e+R1qBGHy6IpYhMXN1rRCLsXNXUVlx39ootqybcm+MPvZF
         uAYA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1738865466; x=1739470266; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=z/IujdnACFvmg9pid3AjfR2+XDSfjSFR3o7Dmar6e9Q=;
        b=Bh4/qpg8KiTkiUWM40saRz7lzzGjXpy2biU/Z46HePyylFGiENOjQce6qKjQcuY6Kp
         o1vkL7uOmQ9/BSYGAVz/RmwueFeBmoUH9/GZPA2ku2g/oxRovoUr+leLgYxuIgsPxKgh
         CjnbRaIicxRGIJZD+80HTs6iCtanUAIZeA1BKDS2My8f5yWUjpmW/J5Bae9VupnDS8Wx
         UBW/A9vUJbGfq/KOpMztPERn/+QAxm9okon4CDi2FQqDS0fhoms0st1lBBAUf/0wpIj5
         E7q52kDNsmMsAO+eaDu0H4nSv+ks9REtjKou+zaT8Td/xX1HPVjzmeM/2syfy9KjQ7pv
         4O/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865466; x=1739470266;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=z/IujdnACFvmg9pid3AjfR2+XDSfjSFR3o7Dmar6e9Q=;
        b=CUvBvjMQLRNZMI1tzFJpNdQohNaq44RvzPK/5q0v4HaIgeWiHkF92NTabtVzlkr4kc
         T9Tiv0LtRt+VixmDutsmIL4vC8Mjr1U3Y6utTSan7lS4JEdTbUQywbJ0MDTTa9ztIGNT
         mwJu66u4t5ZJlZmAEeYlMr+gKSAQ/gxY2P2rBA8J8giK3fm/VOJfgg2DvAGqHHhWr2ax
         T2uEa6DgZZC+HOKPpUt3x9G1unli30qyHPg+9h59gCGb+E4YSyWfv2PbbNTkvcfMKu/x
         QjnD6uSwtzVAKmLFOLJaFdKUWWYCi9AjMEXewtEIBpXvu1JxnKDY/LA0EAsbIGgT0Umf
         i7GQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURXf0WFHr92uw7OfWrlCI2s5XSat87bbzZmXoSm+KpmBkRJQMbMXbiAThoaDolVOS/Fr2+YA==@lfdr.de
X-Gm-Message-State: AOJu0YxLvvT0LBuS1aWtYTiZkS2N8d/zumuIZ4ca5n8nzNgw34bmjvfY
	zNoGri7MSdvq8t9AfDzDFF4wMMKt7Fmy9VuK2sWm1WPwxH9q1CaM
X-Google-Smtp-Source: AGHT+IFEbXbWhJfxq60f3R6YQ6ct8DRb84lVJQuo8mgwetaD7EUG9d40vwXF3vRDh5Xc1TG57NY/Fw==
X-Received: by 2002:a05:600c:35cb:b0:436:a3a3:a70c with SMTP id 5b1f17b1804b1-439249b2cfbmr3273695e9.28.1738865464319;
        Thu, 06 Feb 2025 10:11:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c8d0:0:b0:434:aa6f:2408 with SMTP id 5b1f17b1804b1-43924c3fed1ls230045e9.0.-pod-prod-03-eu;
 Thu, 06 Feb 2025 10:11:02 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVCYDaEvFytxzXVw+ig7CAoiiwcbwrxAina+rvcQ0Ej0IGG5HtKLxzOwnb3GiTUUO/gMqjX+ZIYR/Q=@googlegroups.com
X-Received: by 2002:a05:600c:1e83:b0:432:d797:404a with SMTP id 5b1f17b1804b1-439249a4028mr3301615e9.22.1738865462172;
        Thu, 06 Feb 2025 10:11:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865462; cv=none;
        d=google.com; s=arc-20240605;
        b=UWx1VBBUHGwqCYIv4LUKYUP5G+nVoYCQ6idOu7sHuth6edHuMXUQ8TAlWl0VXK2MB9
         UaT5NUmP4REjBOlvATiUZX7eLMX2oyeOnGaxlHO5hSSJ2AUfOJ05njs8u924P0naemyp
         X9xBPO9YaMLBqJFmwlnEasVJFzWfDm/sXPwDu7/IdszgVT8Y9qucgiC+KJJelC3Xio4w
         PDgvCYfMGoRzQdA8xXwXz+1+p+3DRT0qalW8kCofoZWfb7jCRCa1f4g4nHORMXLwPFt7
         U+tSBxmL6zaRKVrEHNdgUSfyE+Ff0J0sB86BQ2vETKGDoe2Le6sGTMuh+S6ZEJNrVwbb
         WRDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0ttuWAvJobLlg56YrOVOmHOt13ZH7wD3gGicocchpzQ=;
        fh=FEt3ATS8KdhU5IdqFZ5oXW0NRsOgfob/HJsuOdopbQU=;
        b=Hhv0H765j3I02BH/wmMBb2aqMop1FZ8tYHEH89dz0zngC+Chwegu3YONQH7nqlttTa
         pLqioyCY0phtjYszQvdEkJSrWbWSwG5oyrQDbzYn+y0gCqzi7cK1Fh4WtqOdJeWopUuG
         HGUDB71OAzU/rfO0x0UiIJDJDU8gNu14ToViffTcpuDRZG4O65PPTblK+qlLPDV22w75
         pmYtVPwY7+4+U5tUKLHaCMgykDSouijOQG+5CaybNcq0woMEKm7BfTqDbhwp77nGKWrW
         /2QXXir+xUhybRpN2Su8ED1wYT6lrboUhAvS2/QoQthykxMGEiBb66+YUXepEnRGmzay
         UNLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gygMFrCH;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43907f1b57bsi3246395e9.1.2025.02.06.10.11.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:11:02 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-38da66ce63bso696367f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:11:02 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVoUFrmILoIVHl8Onx6UsPyPi5yhH559P2CgeW6NDUKNF04G6B31b25Ad6uxI3xiV3Xx/+lJTeJmO8=@googlegroups.com
X-Gm-Gg: ASbGnctDBtBLBZ/4L3UPEwr2abYBjTMi9w2I3+IT9ugJ7vSY/r0C/UqfJT/23zoXlgZ
	MYlBFhUvWXR6EooaE1sfDAiCw/lMg3Ma554ORFOKu7BRJMk4E3L0LmFsxjNmUJK8OwqBgb5IP8Q
	==
X-Received: by 2002:a5d:6da4:0:b0:38c:5b52:3a5e with SMTP id
 ffacd0b85a97d-38dc8dc342amr4349f8f.8.1738865461496; Thu, 06 Feb 2025 10:11:01
 -0800 (PST)
MIME-Version: 1.0
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZd1dpqv+rM2jD1fNGvhU_0+6c8MjzsgEsi2V-RkHVteJg@mail.gmail.com> <cj2w476ui6g6bjtrnmhozgruhudjx7dbeifxtx4q26c4sqmobt@ill63v5yc3ke>
In-Reply-To: <cj2w476ui6g6bjtrnmhozgruhudjx7dbeifxtx4q26c4sqmobt@ill63v5yc3ke>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 6 Feb 2025 19:10:50 +0100
X-Gm-Features: AWEUYZkYq87i7dcuraqL9nv2V2zM6XbkuTsSw_RSaFUD-ppNitROYVtIB8RMtyU
Message-ID: <CA+fCnZfTvFzX32ZU=Xa0qsNACM4Y1vA1xQDtJkhhk1fYH1QxRA@mail.gmail.com>
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for x86
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: luto@kernel.org, xin@zytor.com, kirill.shutemov@linux.intel.com, 
	palmer@dabbelt.com, tj@kernel.org, brgerst@gmail.com, ardb@kernel.org, 
	dave.hansen@linux.intel.com, jgross@suse.com, will@kernel.org, 
	akpm@linux-foundation.org, arnd@arndb.de, corbet@lwn.net, dvyukov@google.com, 
	richard.weiyang@gmail.com, ytcoode@gmail.com, tglx@linutronix.de, 
	hpa@zytor.com, seanjc@google.com, paul.walmsley@sifive.com, 
	aou@eecs.berkeley.edu, justinstitt@google.com, jason.andryuk@amd.com, 
	glider@google.com, ubizjak@gmail.com, jannh@google.com, bhe@redhat.com, 
	vincenzo.frascino@arm.com, rafael.j.wysocki@intel.com, 
	ndesaulniers@google.com, mingo@redhat.com, catalin.marinas@arm.com, 
	junichi.nomura@nec.com, nathan@kernel.org, ryabinin.a.a@gmail.com, 
	dennis@kernel.org, bp@alien8.de, kevinloughlin@google.com, morbo@google.com, 
	dan.j.williams@intel.com, julian.stecklina@cyberus-technology.de, 
	peterz@infradead.org, cl@linux.com, kees@kernel.org, 
	kasan-dev@googlegroups.com, x86@kernel.org, 
	linux-arm-kernel@lists.infradead.org, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gygMFrCH;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Feb 6, 2025 at 11:41=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >I started reviewing the patches, but this is somewhat complicated, as
> >the dense mode changes are squashed together with the generic ones for
> >x86 support. Could you please split this series into 2? Or at least
> >reorder the patches so that everything needed for basic x86 support
> >comes first and can be reviewed and tested separately.
>
> I'll try reordering first and see if it looks nice. Since the dense mode =
would
> make some parts arch specific I think it's better to have the two parts i=
n one
> series for easier reference. But if it turns out more convoluted I'll jus=
t split
> it as you suggested.

Yes, please do. I also think if you split the series, we can land the
basic x86 support fairly quickly, or at least I can do the review and
give the ack from the KASAN side. For the dense mode part, I'd like to
also hear the opinion of other KASAN developers wrt the overall
design.

> >Also feel free to drop the dependency on that risc-v series, as it
> >doesn't get updated very often. But up to you.
>
> Okay, I was mostly interested in the patch that redefines KASAN_SHADOW_EN=
D as
> KASAN_SHADOW_OFFSET and then gets shadow addresses by using a signed offs=
et. But
> I suppose I can just take that patch and prepend my series with that? (af=
ter
> applying your comments from that series)

Sounds good to me!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfTvFzX32ZU%3DXa0qsNACM4Y1vA1xQDtJkhhk1fYH1QxRA%40mail.gmail.com.
