Return-Path: <kasan-dev+bncBCV7JPVCWIDRBN6PRK6QMGQEJ5CE2MI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DC75A27FC3
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Feb 2025 00:50:17 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-53e3a872187sf3317431e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 15:50:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738713017; cv=pass;
        d=google.com; s=arc-20240605;
        b=kdmNW8sJkX0hCkfbULp3k6aNW32b92Y+Adyz1tKLXejw1gv3myd4iOaSKr5VNoZcJY
         2zTrcuk9P1veKTZFhjVLL2KcsVKqz8d11bFPy5YmGHhjcWKfPAGbsnJPpbLSI3CrAXfJ
         gShlncuj1+60TufibGzjAfwbfYMYE17EBMIcd19xN/wv+NQ8JdsHiKZLdnFJonJSqdfs
         f2yPKr/+Q9QXZmMlDdzKGIMNp6HixtHu2GnTtMqUJ5S0/z7+CIe4r+ZHXgoCqZ/hi2UI
         XxEv0Sr8e/kW8sgHkm4JMBMsnWUq+HtLdZ/mZpZGcT99H0JXp472nde7Q0NXHMiLmRVy
         cbVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=Alk3LupWhNboeVFWr6Hlv12oJZ31utx8lYLKc9tBTbM=;
        fh=614c3AV6iiqTU9lIRxT+o+MbIqCpdJVxcKiqUI4Gvxk=;
        b=Gyz+xr6hVDrpN0WHZhm39jrMKWTMiDLw812zQDRu9Rxv6eo8H9NKeuutygU6QXZ8oi
         Jo/Hd5dZPceaWyZhrn/eAMP4VrzVl9sP3nP0yGGZ65xCNNSFEAgRQdvH6VyYCKzmdqvt
         DOI9eL2vjDftYKYijyx4M6pHSkapyMcgUvQHvhkQaOyxU6Qq+923I3IHLfEubrBkAcYa
         52U38R+hw5nTXG6eAGgEXp5ZjdBQ607tM4Euxowqdkc8Qp1XJCs+S6Spw0xmUxQ8PTyw
         zev/Z8tHO+3+UF52Ixh92VlPrraYhOpYPo5V4x+gsEz7NwjvuwTUQTmDWT15veks6h2R
         lYEA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=Yf3xHuxL;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738713017; x=1739317817; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Alk3LupWhNboeVFWr6Hlv12oJZ31utx8lYLKc9tBTbM=;
        b=KMuNQnwno2Y4vXkH2I/oXt2jTKg+ZniQVd+3WpMfTS56Zrdk7SBieWToLepEqZ3FUf
         rzbqf2Ez/tGh3kKq+awqjq1NEqtT+td8AdM6+4W1ZWrGKzR+qLEdR9k2wkZzuRYxCrKI
         mmvYwnKP8UIf7dvLbIcA78SAdTgmDH2WspjdWRd7vfAmxNviiaBS3x2XAaaHF3wutsZb
         /mZhZ4ovnfd3pgY3WtwHtWIqAypBJ5miZ5FtaIzGE/Jlb8Kmi4Q7CCdfSByQBkD4RJBH
         We2in/oQr6J890VbHCsHZDjawBXn2A1cjDhhTK+cSEUC41eQh0e0N1lFqM5URqBNan1F
         NHHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738713017; x=1739317817;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:content-transfer-encoding:cc:date:in-reply-to:from
         :subject:mime-version:x-beenthere:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Alk3LupWhNboeVFWr6Hlv12oJZ31utx8lYLKc9tBTbM=;
        b=rhmKVx5Is9AveRNKZIbfgiuUoHPo0P+XlhMcHuWPoEs7TsAMKKw1eA9oxsf/r9doyj
         NjsCbtLjwg+T1yDieoeiLX3u/pm0IjG3Pbt2MkY6U7DFKxzDC6Ph/p69caBxY2X1gbwj
         oXjOOWaiCfX7Jp9ja4YUMNbZ6l8UHQE/oL/H/+xu6o9XS2CRQupEsbzbgjv/XvwGc/Ng
         SWHCWW0mDXfY9F6ybXGh0ZI8aC/8ly6OM4/dSduMX0d8/t8GxWkKzrWNcEaD2bOUrvWK
         TZeC8wcneVT6E3p/UgtmZOVQyEPN8DM0fXctrZUasv56nDFL1O4F3fgbCRR6uH+pSc+f
         SNqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbS8+5yTAHuEfrQ8czqnOaNTYdtI8T3zNFnP4aFkADRI2HOzwm0e7WiPxD9RbCdHYTyWbYXg==@lfdr.de
X-Gm-Message-State: AOJu0Yz58J4JCgiI84Fhpgg6MH1lRYK64/+tgxDAH+bRxpdbSeNrJnJs
	SrpWVvcR4zD1cW2tNHj4OkECBTW6xFZPN0hQOUG62vJ6bxLEwL+L
X-Google-Smtp-Source: AGHT+IFs6DaUzjV3xxlFwAaws+Upm64dHt1qfzdcI+jCidGldxcOIMrEgsishck4VkBkLtxF0+llSA==
X-Received: by 2002:a05:6512:3f1f:b0:542:672f:a3c6 with SMTP id 2adb3069b0e04-54405a42452mr145555e87.36.1738713015763;
        Tue, 04 Feb 2025 15:50:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:32c3:b0:540:c34b:91f3 with SMTP id
 2adb3069b0e04-54404f001b3ls119203e87.2.-pod-prod-02-eu; Tue, 04 Feb 2025
 15:50:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQY/O88uAHAchCH4XGdfnxnAn6gRCzASrTo/ZjbKRwate6ZCsftPdzx8nw+lk4NLb1kdhsFvWqGPw=@googlegroups.com
X-Received: by 2002:a05:6512:2387:b0:542:1ba3:984c with SMTP id 2adb3069b0e04-544059f7bdfmr168085e87.6.1738713013435;
        Tue, 04 Feb 2025 15:50:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738713013; cv=none;
        d=google.com; s=arc-20240605;
        b=kZcqDJM+DaUNCwCmr3btJvI/2t/wJr+EImUlizujyQBpTILGcstpLkXXIKQZHteObP
         i5qKkE5Bq4TmpmuVR1AIaVw+Vvwj3wMMLsCSCVvQb5VNnmRIcWomWBOm0pbMSnqWiR0r
         U7WsTagPOdn0UrvDQSbB5QCWvF356KPOhaVvwTjL0aGdf9SIaClbcD3SF5JqijHIxdRl
         EgRyfIFjOJBchbb/XZV0V2NX/WdFRfqdYyPuadPyLkIWb1SNJH1OMxKxEc29NRdBOJ4K
         /aaeRQa06X3Cs0Kk/EuQOrKVHiPkEQQ/sg3O50AoHZLwiDr77Llgy1MW9Rl2QYvo0e2B
         yOog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=QjEre/G3BLqcrCF5wreFajQVoRGv9unmtvDg4S23UQU=;
        fh=8/vcxfBGpbsOD1lCNIT/VMS+7o3prLjVTPvPqmGvaV4=;
        b=Yd134hDylxliLPbXmFywNK+JZH/15GtEllmnKIqebQ2Y/hW55SFYgjrl1MVdKaXbEq
         t/Z43B0RG8iaMavq+QwCCM55x1FnYfS/n3HvyxnOlScsNZLgiTPhtdpGvkpZSyRDljdr
         dCAtez9dmRsZb9PpqCCJ5J/VcG69XRFx1ShTKxqOT74DbR6vqUF183H0JTI/HqObXR7n
         EQ2yaiJ6F3bohBqw7NbUXr1IZ7KBWPUvLp3Z1i69BnMIaHnnUE4MPj+h5JMuYa2T+qsh
         8dF4b3GcB3hQ//riHC1Pcs6Uru+BS/MN+5ySU3mI4Q+tB0X7qLDYE6Oc3ltYGu3ovXNV
         NpFg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=Yf3xHuxL;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x434.google.com (mail-wr1-x434.google.com. [2a00:1450:4864:20::434])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-543ebeb535dsi358702e87.7.2025.02.04.15.50.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2025 15:50:13 -0800 (PST)
Received-SPF: pass (google.com: domain of jrtc27@jrtc27.com designates 2a00:1450:4864:20::434 as permitted sender) client-ip=2a00:1450:4864:20::434;
Received: by mail-wr1-x434.google.com with SMTP id ffacd0b85a97d-38634c35129so4856139f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2025 15:50:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX/Zh7SjhuGJoXHZOIlMfAtkH2A9lvCWD2T3F2IuNZdBJbS9OeJZrFkXcnC6mCli7nhIpMR6s/AC2M=@googlegroups.com
X-Gm-Gg: ASbGncvojyIUIQlXbCecrgvXZGf3xzWeGIIjV8NBuu69BTIzI9iTPxp2VLJH2Akiaw1
	huX9s2n0jc5MJnWndOHNvicQnIb64CrGQCG7ORVx2N987GpPIL+8JBVkUISDAU+ePmMKZIhRRic
	2aNKSp+GlGxsRaUmw8059XZipJZrSUN75dgGth8gQDoWbx1E1KLPi+vxkND3u/NWgrpGWxMoqj6
	2oU/x2K6m1622/NqW/IFunb+fv9/PlU1Ey86+RvEXFOol/JPAfaEd/i72zqnkt56LDJighmVMBZ
	0lcOHb/2n2LX7O46IXeyuVKRurnR
X-Received: by 2002:a5d:5f56:0:b0:385:df43:2179 with SMTP id ffacd0b85a97d-38db48bccf9mr352139f8f.17.1738713011907;
        Tue, 04 Feb 2025 15:50:11 -0800 (PST)
Received: from smtpclient.apple ([131.111.5.201])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-38c5c1cee41sm16885326f8f.81.2025.02.04.15.50.09
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 04 Feb 2025 15:50:10 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3826.300.87.4.3\))
Subject: Re: [PATCH 00/15] kasan: x86: arm64: risc-v: KASAN tag-based mode for
 x86
From: Jessica Clarke <jrtc27@jrtc27.com>
In-Reply-To: <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
Date: Tue, 4 Feb 2025 23:36:23 +0000
Cc: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>,
 luto@kernel.org,
 xin@zytor.com,
 kirill.shutemov@linux.intel.com,
 palmer@dabbelt.com,
 tj@kernel.org,
 andreyknvl@gmail.com,
 brgerst@gmail.com,
 ardb@kernel.org,
 dave.hansen@linux.intel.com,
 jgross@suse.com,
 will@kernel.org,
 akpm@linux-foundation.org,
 arnd@arndb.de,
 corbet@lwn.net,
 dvyukov@google.com,
 richard.weiyang@gmail.com,
 ytcoode@gmail.com,
 tglx@linutronix.de,
 hpa@zytor.com,
 seanjc@google.com,
 paul.walmsley@sifive.com,
 aou@eecs.berkeley.edu,
 justinstitt@google.com,
 jason.andryuk@amd.com,
 glider@google.com,
 ubizjak@gmail.com,
 jannh@google.com,
 bhe@redhat.com,
 vincenzo.frascino@arm.com,
 rafael.j.wysocki@intel.com,
 ndesaulniers@google.com,
 mingo@redhat.com,
 catalin.marinas@arm.com,
 junichi.nomura@nec.com,
 nathan@kernel.org,
 ryabinin.a.a@gmail.com,
 dennis@kernel.org,
 bp@alien8.de,
 kevinloughlin@google.com,
 morbo@google.com,
 dan.j.williams@intel.com,
 julian.stecklina@cyberus-technology.de,
 peterz@infradead.org,
 kees@kernel.org,
 kasan-dev@googlegroups.com,
 x86@kernel.org,
 linux-arm-kernel@lists.infradead.org,
 linux-riscv@lists.infradead.org,
 linux-kernel@vger.kernel.org,
 linux-mm@kvack.org,
 llvm@lists.linux.dev,
 linux-doc@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <F974BA79-80D8-4414-9DFD-1EEF9395143C@jrtc27.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
 <8bd9c793-aac6-a330-ea8f-3bde0230a20b@gentwo.org>
To: "Christoph Lameter (Ampere)" <cl@gentwo.org>
X-Mailer: Apple Mail (2.3826.300.87.4.3)
X-Original-Sender: jrtc27@jrtc27.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@jrtc27.com header.s=gmail.jrtc27.user header.b=Yf3xHuxL;
       spf=pass (google.com: domain of jrtc27@jrtc27.com designates
 2a00:1450:4864:20::434 as permitted sender) smtp.mailfrom=jrtc27@jrtc27.com;
       dara=pass header.i=@googlegroups.com
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

On 4 Feb 2025, at 18:58, Christoph Lameter (Ampere) <cl@gentwo.org> wrote:
> ARM64 supports MTE which is hardware support for tagging 16 byte granules
> and verification of tags in pointers all in hardware and on some platform=
s
> with *no* performance penalty since the tag is stored in the ECC areas of
> DRAM and verified at the same time as the ECC.
>=20
> Could we get support for that? This would allow us to enable tag checking
> in production systems without performance penalty and no memory overhead.

It=E2=80=99s not =E2=80=9Cno performance penalty=E2=80=9D, there is a cost =
to tracking the MTE
tags for checking. In asynchronous (or asymmetric) mode that=E2=80=99s not =
too
bad, but in synchronous mode there is a significant overhead even with
ECC. Normally on a store, once you=E2=80=99ve translated it and have the da=
ta,
you can buffer it up and defer the actual write until some time later.
If you hit in the L1 cache then that will probably be quite soon, but
if you miss then you have to wait for the data to come back from lower
levels of the hierarchy, potentially all the way out to DRAM. Or if you
have a write-around cache then you just send it out to the next level
when it=E2=80=99s ready. But now, if you have synchronous MTE, you cannot
retire your store instruction until you know what the tag for the
location you=E2=80=99re storing to is; effectively you have to wait until y=
ou
can do the full cache lookup, and potentially miss, until it can
retire. This puts pressure on the various microarchitectural structures
that track instructions as they get executed, as instructions are now
in flight for longer. Yes, it may well be that it is quicker for the
memory controller to get the tags from ECC bits than via some other
means, but you=E2=80=99re already paying many many cycles at that point, wi=
th
the relevant store being stuck unable to retire (and thus every
instruction after it in the instruction stream) that whole time, and no
write allocate or write around schemes can help you, because you
fundamentally have to wait for the tags to be read before you know if
the instruction is going to trap.

Now, you can choose to not use synchronous mode due to that overhead,
but that=E2=80=99s nuance that isn=E2=80=99t considered by your reply here =
and has some
consequences.

Jess

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/F=
974BA79-80D8-4414-9DFD-1EEF9395143C%40jrtc27.com.
