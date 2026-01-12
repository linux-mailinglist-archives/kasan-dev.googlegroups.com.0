Return-Path: <kasan-dev+bncBAABBRVJSXFQMGQEVC43DHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 97E2DD15279
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 21:08:39 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-64d264e09c7sf7651922a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 12:08:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768248519; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q18G1X/QjPRZAcPTzbM48hYd34HSZvXU6r3aoT03ThnSvThKx8aW+BFaOAmD1d9Zpn
         C+RMXDncvHNV1o99d/p0e8SvQEjoF9DYfv+AV1fRMvn2VlXRzd/T+iJXYtjsF7E6FOZz
         3MYohz09/nuTyj6PQClGvlkJONpMaEKnV6UNhkmhoa2aoZi7IIAxHfwO1X+UQzR6VBph
         8RzvpFxoCyGygh+X4RXPMSlszwZ4IgUvEMisXO45MvlrbbkXzC3AOF0qdhUEM4StHHr7
         oH9NSTQJRnSKxhHQtZQnccZ7nu+re3cas8TX8XMLBKp9MYu1GeoNkJelYpov2rwryhqE
         mkrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:feedback-id:references:in-reply-to:message-id:subject
         :cc:from:to:date:dkim-signature;
        bh=yC1n8HkfBEZi7xI2CRC6skXxybmD6aO/1N7CIEVUrgA=;
        fh=VKxwKm3fif7EQFmKECNZxsK93+hjKEp6m4WcsZioL8Q=;
        b=iyZ7i4XfRQXYL6tM7VKWCzOEjoUpVIvkSliCfoUJ4/qgF3QU2OclUKU6NS4SpapFu6
         8FXdbP79RQ5gVfyZf0y9gxnDQ78hWzRRn6+qul+y1K0tS9mTxU4qVLm5gj5i4eM7ZPEq
         6YPdFksr1a0hHb3yZDkIl3CIsR7Zc/CgkfUdmg5+aEPSbhmyZOkvOjzfE5tPiyQRKltw
         tT/TyyRVM1xrI72Gv4yy8d9sfI81F4UVCHFGv4QIGFD8VPlN6ZuOXknp9zxVrNjxOm6M
         mLB6O4bd280DrWHR8V9grQni6vV7XSfcxkh8yNf4rSiYKFjiEOqv5Pn5eXywb+v1A57g
         CzAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=QT4Gpkfe;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768248519; x=1768853319; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=yC1n8HkfBEZi7xI2CRC6skXxybmD6aO/1N7CIEVUrgA=;
        b=tCxDiTtUut/knCJzzL1H9CiHLRpZ8mFs7nxuzRr3xRwFj4UxWCqg2aU7mg09k3qnm9
         njsZ1VRu8cIhDOdCzFCPDRwgpNeS1YuSr8QAN9nATeEyurGxDo65G0cgdm9nOQLhaFzL
         Xnt7yxOXgKMg9jpqLeqOC1eKxJYvrU0Pl9TmJs+ODnOKMgD3Mq8MHHVQxZqR02msxho5
         +rI3WX1KL5vFiN4z4rXh9chHBFnwsd+H/s3/vgjuXZ6A13BMYPlOPMc8sZrkp1g02QmA
         ewm0rmVoduxhbfw8i7uv8BAZb67CXgzSqn6ZzOmHwZS28s4lJwb46EbgFXKje1jQKzZ+
         S2aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768248519; x=1768853319;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=yC1n8HkfBEZi7xI2CRC6skXxybmD6aO/1N7CIEVUrgA=;
        b=QsePI66Hkh6XqvRoOv2mZ/YftA0LbKNUkJaRHRyNXYKliVPUFtmMGbG9vqKwX37iNQ
         /ZKI5//o1M5iHgpsrgsbchNKv1xX6h54R7hegmhNILSLsxPTUKr0gkxmr4zvCJD6UYPu
         F5F0h2EE2+vwappncO6KhymYwaFTSYmqMpe6/9xU75aT6DfjqUoWLrFe9GGFp8e5Wklc
         +LUho3ATSjex3kKk1ouwVE1w6sc+WmDnA3YybpD/yu4UsytPoFCiHvWKScTwqmCdiyBO
         W6rczCX9u7C+R/Yo5YPWioFbyCgykKd08SiiXHmt++fkiQt1VZs7y0MdaWK1NTy90mQy
         tCng==
X-Forwarded-Encrypted: i=2; AJvYcCVrwm6rwYfcyrjVL8Df4HKRioqX9kY9GJMFYPeVut7SzoSzidoi7tFGvAP+FRQT9QhHuOnGMg==@lfdr.de
X-Gm-Message-State: AOJu0YzhuwbK26ov5fZZixA6bHJXNpb/svsad57bkt6hyEYBCpp/h4SX
	NDQpc9gpliwx2aqd5IEGjj18fXJ3kchm/bAmGPVFmXxcKeLBFDdEkXg3
X-Google-Smtp-Source: AGHT+IEuyOlGAD4tZ/mQhdEZ3aHhN2sKVPRKw+fxBPd+ua3eEmaHzhyfuE4k2xMtb/16W7R2pRSNgQ==
X-Received: by 2002:a05:6402:40ca:b0:64f:cfa0:9024 with SMTP id 4fb4d7f45d1cf-65097e725c9mr18453396a12.34.1768248518514;
        Mon, 12 Jan 2026 12:08:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Eka2A80Zmgobvx9gLvjgLGamisU1BbF5Zecsv3R7ZhGQ=="
Received: by 2002:a05:6402:553:b0:64b:a8b0:ba67 with SMTP id
 4fb4d7f45d1cf-65074317c8els5511178a12.0.-pod-prod-07-eu; Mon, 12 Jan 2026
 12:08:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX9cmmEOrhmeyHbr4/OW9foJeSEN33Y2XpZ2Sscz0M8UXP0hLp/b+xQHCM0zP53PKHVbk3rRpLy/c4=@googlegroups.com
X-Received: by 2002:a17:907:3f9f:b0:b87:298a:da9c with SMTP id a640c23a62f3a-b87298ae04emr239647266b.6.1768248516640;
        Mon, 12 Jan 2026 12:08:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768248516; cv=none;
        d=google.com; s=arc-20240605;
        b=H0H6whVGM9dXORvR1F5GswmM6Sea9TTCcBSnLOJLW92hTPx0LI87M89hok6/Zx8kVt
         jm5G58z/9xSy6cSiCldLiOrGTGng/wDCvsK9RLr8V8pT3iCzUdEWZO+zDok0i4mC/iWF
         73IuOBGKxjsWy8CZrqaQR7B/xfqR3LNnpwyAuFW+HzzexXkZILj1z5STGE5cNtQP+TNr
         UsEqIFegO01pwlk+wS7Q+T2ARZsuRPJ23QVsZdzgj7wj0OkBZZKEF6TAvORFjMOwPcle
         kV/hfW4uWX/5ftIxRhHKEaMnsw3BZ+JFVuEWKuar0jok06X2R8r58MO52qT0RpFaiVkM
         XioQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=0xx91FMArzFMWklxJ23UJVUdtYrv0ESnhx5I4mmt2rU=;
        fh=kpcTpH6dE9eMPQdbbaGSqivEDxAvoR1GjxiB2R5Vvrw=;
        b=SStVqhh/FmGrQqyivXSVCTrCCqGUtEC/XK08qeFLI9h1WqrBBi+61475CcXr0XEG/E
         KWrJf6V0YP/3eTaV7sIrV6eNBT1K/pyP1nrcNZBaBLICEQUi8gSIQNAWiIEn12nJyogu
         zVMpGgeUY6RF/cnTSsM41mbnZBggaw38yPrv0C7YDWJd6Mw1vmTMtCnd0+3PHfp9Lqru
         JKiYpJQVxKiUbVfaihyKB7VTdKqeVTCIxYzt8k28nIKwawYj6O+OUMtS6MxXWuvLnoZr
         RSC6/rfiwbTQFv2ENFCMYSRbYT/S+7owvPC3WlwxcO/PeiDw/TWlagiezu33CzvhS7Hw
         kX1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=QT4Gpkfe;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10631.protonmail.ch (mail-10631.protonmail.ch. [79.135.106.31])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b8440d439a5si34353166b.3.2026.01.12.12.08.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 12:08:36 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as permitted sender) client-ip=79.135.106.31;
Date: Mon, 12 Jan 2026 20:08:23 +0000
To: Andrew Morton <akpm@linux-foundation.org>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: corbet@lwn.net, morbo@google.com, rppt@kernel.org, lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com, vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org, catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org, jackmanb@google.com, samuel.holland@sifive.com, glider@google.com, osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org, Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com, thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com, axelrasmussen@google.com, leitao@debian.org, ryabinin.a.a@gmail.com, bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com, urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com, andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org, vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com, samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com, surenb@google.com, anshuman.khandual@arm.com, smostafa@google.com,
	yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com, kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org, bp@alien8.de, ardb@kernel.org, justinstitt@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, llvm@lists.linux.dev, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
Message-ID: <aWU-oL8oYS_PTwzc@maciej>
In-Reply-To: <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
References: <cover.1768233085.git.m.wieczorretman@pm.me> <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 74b6155b55c4853d5925984570fe14ed71d1c92c
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=QT4Gpkfe;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.31 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2026-01-12 at 10:29:57 -0800, Andrew Morton wrote:
>On Mon, 12 Jan 2026 17:26:29 +0000 Maciej Wieczor-Retman <m.wieczorretman@=
pm.me> wrote:
>
>> The patchset aims to add a KASAN tag-based mode for the x86 architecture
>> with the help of the new CPU feature called Linear Address Masking
>> (LAM). Main improvement introduced by the series is 2x lower memory
>> usage compared to KASAN's generic mode, the only currently available
>> mode on x86. The tag based mode may also find errors that the generic
>> mode couldn't because of differences in how these modes operate.
>
>Well this is a hearty mixture of arm, x86 and MM.  I guess that means
>mm.git.
>
>The review process seems to be proceeding OK so I'll add this to
>mm.git's mm-new branch, which is not included in linux-next.  I'll aim
>to hold it there for a week while people check the patches over and
>send out their acks (please).  Then I hope I can move it into mm.git's
>mm-unstable branch where it will receive linux-next exposure.

Thank you :)

>
>> [1] Currently inline mode doesn't work on x86 due to things missing in
>> the compiler. I have written a patch for clang that seems to fix the
>> inline mode and I was able to boot and check that all patches regarding
>> the inline mode work as expected. My hope is to post the patch to LLVM
>> once this series is completed, and then make inline mode available in
>> the kernel config.
>>
>> [2] While I was able to boot the inline tag-based kernel with my
>> compiler changes in a simulated environment, due to toolchain
>> difficulties I couldn't get it to boot on the machine I had access to.
>> Also boot time results from the simulation seem too good to be true, and
>> they're much too worse for the generic case to be believable. Therefore
>> I'm posting only results from the physical server platform.
>>
>> =3D=3D=3D=3D=3D=3D=3D Compilation
>> Clang was used to compile the series (make LLVM=3D1) since gcc doesn't
>> seem to have support for KASAN tag-based compiler instrumentation on
>> x86.
>
>OK, known issues and they are understandable.  With this patchset is
>there any way in which our testers can encounter these things?  If so
>can we make changes to protect them from hitting known issues?

The gcc documentation states that the -fsanitize=3Dkernel-hwaddress is
similar to -fsanitize=3Dhwaddress, which only works on AArch64. So that
hints that it shouldn't work.

But while with KASAN sw_tags enabled the kernel compiles fine with gcc,
at least in my patched qemu it doesn't run. I remember Ada Couprie Diaz
mention that passing -march=3Darrowlake might help since the tag support
seems to be based on arch.

I'll check if there's a non-hacky way to have gcc work too, but perhaps
to minimize hitting known issue, for now HAVE_ARCH_KASAN_SW_TAGS should
be locked behind both ADDRESS_MASKING and CC_IS_CLANG in the Kconfig?

--=20
Kind regards
Maciej Wiecz=C3=B3r-Retman

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
WU-oL8oYS_PTwzc%40maciej.
