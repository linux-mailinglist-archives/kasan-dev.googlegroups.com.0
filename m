Return-Path: <kasan-dev+bncBDW2JDUY5AORBCVLQ67QMGQER5J2XCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id ABA33A6E603
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 22:58:36 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-39979ad285bsf2608046f8f.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Mar 2025 14:58:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742853516; cv=pass;
        d=google.com; s=arc-20240605;
        b=dRzSY+H+c0xTIyHm3B9O+oOJXSz4xKjZz9i9/XU0/N2PBSBF2IsmGp3EQexcFYqE/A
         vuuIWP3w076Gwfc0at3PkI1RL8J79zmidOG9aNPiV79ZnRBzbzNf8oD2SkdhFGPmb5Ik
         SLdEqXaAld59EIxAYRJD2m/ugdcF1O0zPHlneCqu5F9M5tygjq3u8yjnTWvnR4NNHoM2
         6NZ8/G3nMpYfdGYTHKee5zHv84OxrkKhPdYl3uhRmp8R4dolDK9Qo3QTFTCTla5OYfoP
         vNpWggaTV071rGqSI8XxxHvNwtOBBp8fwU7Ebu7DYi3EnNgAslc/7EgEXKi95pfcb0HB
         9SLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=YmFdSwgham8rQh2YaCMuYeMwSU69Vwfljqy3m4yBD9k=;
        fh=vb6WXMqZHdaIBgm8y4rJs7T1YEEdbRio70f5/LpXvUA=;
        b=gx+8U8eA8NIhnSlOfBsDFecX0qb9enJ8DaJ5SnrvplC+JrA0Db8BlRK4hrJsSEyRpG
         GOeLtjSnNM0P3jGLnEiv9esL5+lq0LIcolc+HXZobTI6ARQ49Oh545RzD8W1JxrFx2Da
         FpwYbnyi2phn3Nj3FYUwFK06/xGQbrav5iNrM0aAgXEpjSYRRGQ67rSEeznuiJppOfCJ
         2N8pIuALBnz4oqNB78SdSVe4KJ00nCc+2ZSMBRO0p2secPqV/j+YfRMrMkaCnim2uE/q
         YNelQlYPgOObbh3flx4xVqnEf5u4y3TqLIE4JvjhuzPznewYjKs8RR1f/NtDETWQdRWX
         zBcA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=N3iNFOBI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742853516; x=1743458316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YmFdSwgham8rQh2YaCMuYeMwSU69Vwfljqy3m4yBD9k=;
        b=GXzpKTuQl7Uy4TItAor0ka/JUinI4eLyDb9n2elAkNTp6jUMBsKCUWxZ35P+F3dFh2
         I3kKckbRrJfGBtbetfkJL3O0Qq54KuALb7lCQKMXRb50ELr9ovUR6winvxbbbXARTrin
         bSt7MWlyKptXa7Gk6quzQyAWrgkxV54xXzQVJ/mJ5y80rPsm/9kVaj+rNmkR3TyHPOUT
         K9dcuFMHLM05cwdItVS61lPP3r8yqhJRfo94yZkqLvjYHRtgaSIcMUChCp0vOw9AIJmC
         vtsgZTxui1+bXuSQvFPmVXfJ2nyfUBLa8JsWsYbj19e++eKYgnQ7ij0E6q9Yic3nS2jv
         VFLA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742853516; x=1743458316; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YmFdSwgham8rQh2YaCMuYeMwSU69Vwfljqy3m4yBD9k=;
        b=BXw/XFgSfB7jAAMqCCaZ6+qBGFGQQ2336ht28wSXhAlSVH8PElUuCgJbKDnMAVdQo2
         SZsscVNOtwIn9FvcgRvy6usK04WzbHQ1xCKhczsH5LxRr7TSSPWLT/gqVuBgmnZcuKGq
         +T7ov8UALZdD9yFmqXur82l2FQUhZ+ZzmhKF0I8/XL9JFzcetBjJ654425FYzEfy2AUd
         RgHlJ3X7/M6y5p0cNA1Ea5x7ZShoMzQgQsRS4rDSVve2ZInIz5ZSE0FLQ04JdOb0p3J7
         duz3D+Qpam6wDtCXkiO0x7MPyZ2PnjGEQAWF7YfY/MGy98oDlHTi+F96v65oNyhwm+rL
         EUQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742853516; x=1743458316;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=YmFdSwgham8rQh2YaCMuYeMwSU69Vwfljqy3m4yBD9k=;
        b=OleVKlFZLdhjHGwPe0xCwpL3EIFwes44s+olEICjs12GqMkyb5W3OfMCVV0+2R0c80
         whQ/LfRjsbCMayaO8QvkQA8+bbv3sv8M1yr2DZavnHTB8JQPnqJ3kH8vTUVOQCukEPbr
         rsL9PnvvjUJliy6pjYUA7gX0IAlvtHlkiP0BsSzufZ5BLYjV2oDo02mzK0OgUvvquFDv
         dHjM6SWra+aOts9/Yky08PQmw0F5aR6jtczGFa6B36hHDsshHq3on4MyVMMhCFm+9zWa
         JxzvMP/VVE/S9jvYkYvKQ3QKFQXOWjJmRgt11hkAeCk/j0+nIwp7wdZGqWCH683hkFzY
         dAxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU2fYBMwhdadxLnxGdRCP64YSMxz4vA5is1ndOUde8RVePpFRN9mNYpAAE3Ugy47XUUBcDKqA==@lfdr.de
X-Gm-Message-State: AOJu0YwRH3PXvDy3HUfYsL5w6/vrffqqkYLojL8cX5c38cpKubUH6HzH
	zCGxvylck3ZRmttb6TqkqtllnoJjqOt4RzlUf3t7uhzPmkoryag5
X-Google-Smtp-Source: AGHT+IH5yV4D2MOJdWwq4RCHgAlHQGPAqWOmOj1bMqmUWIKuEevbnIjgwhi6/Xio9JBDTajYgz6twg==
X-Received: by 2002:a05:6000:178c:b0:391:47f2:8d90 with SMTP id ffacd0b85a97d-3997f9017e3mr11833728f8f.20.1742853515487;
        Mon, 24 Mar 2025 14:58:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJvGXtEKdmL/AwzIZgtSTXRQU2gYRtuot65J+heYkE4SQ==
Received: by 2002:adf:e50f:0:b0:38d:c0d2:1328 with SMTP id ffacd0b85a97d-3997ec0e976ls1614120f8f.1.-pod-prod-09-eu;
 Mon, 24 Mar 2025 14:58:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXG2aZaa9tSe5v6yylvvg6at5UsMZYVCse8fSaOyxysHQuyLOdjPYEXkHy7lrxkxRTDpbbBSegWlVo=@googlegroups.com
X-Received: by 2002:a5d:64ce:0:b0:398:fd9b:b935 with SMTP id ffacd0b85a97d-3997f9407b6mr13879280f8f.53.1742853512819;
        Mon, 24 Mar 2025 14:58:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742853512; cv=none;
        d=google.com; s=arc-20240605;
        b=gP6VXIBdKEyAz3K2He79ue2IwTBpXcDvLiU2L7XfzIJWBbV6qbDDLFIkm98Kmbs3+b
         MQU5ADPy4kU7IZOLGR2Z/fODlfVD7372XPN31lRXBXqrwrz5+MbugjVypBKT480fEzej
         pRwDeKNq4UNzxY67bBX2FPyjlCx3HbuSi/IB2YBiaY67KCrim1XhCywnKOIKd1Fqwz+r
         B7cmAH1w7fA0Vvd8Bk+bYfWXtpNrswaGm7QjejpPK22HYqrhcFI3WawYgUGoTXn4cg3r
         u52VcdcrRJClP27T1iiSiLwhdUuL3NZo7NyVSGgK0tUPk3uAQNUpPumRYkjjJAdvHh8g
         WfiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Ot1DfOQiy27nUyF1DlyhAcVDQgk2TuJxclhmeyMz1OM=;
        fh=3rwal3TshBMufLUdwcSlfCH7V9XSglTUlUcvSDYSqoQ=;
        b=STQgeAqiTjLzzm1MDYg6ouAOmMx/zy/v8MwBweTu3ndvb/xk1WGQ9t1QnQ/rTyx+/G
         sTrASXJNTNoUJuX1AEQgevqY+wKvoRNvYdDHOOPAU4FrU4BZmssPleL9wg+NvIbTdWcm
         tnykWr4PIQT5JFok4bnbM6cmCjFJLKy/ZizS9F6q22DIa/9+jd+71kMcNOEie4v84hDM
         sRjjejgHxcjyEzQxpP5kDfbmdFd4r6KWhdbmYyg7W7RD9nSdgx83H9HpvaC0L2ypKi1b
         mqWmoLW1Vhej8MMjoCK01a7nOljdXteLN39o0LKyh15iM//HYhCkO8X8q9wIFoRAZrJE
         qaSQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=N3iNFOBI;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x331.google.com (mail-wm1-x331.google.com. [2a00:1450:4864:20::331])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43d4fce64efsi1216675e9.2.2025.03.24.14.58.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Mar 2025 14:58:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331 as permitted sender) client-ip=2a00:1450:4864:20::331;
Received: by mail-wm1-x331.google.com with SMTP id 5b1f17b1804b1-43cf3192f3bso42336715e9.1
        for <kasan-dev@googlegroups.com>; Mon, 24 Mar 2025 14:58:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWGBCIe9e01ltRiJaPY7PS8cXRBKEDq9NEs2HwNiskvXg/P5DxCgInZ/k9j4ux2DdmMMZWN3AgWNcY=@googlegroups.com
X-Gm-Gg: ASbGncvwm+CpVex6O4xQSSlyZbK7rdAQKRrUIK4e5wmZ3WHdHC4tXOLXOxbvFU6mYA5
	AGDvZ1kpcx5mVHR5Y27MFbIE8unl2h8pbLlbmhsxyrlyAKajZXTGlx7vSL8NzcoHpG1o5ZBjOe/
	crGUWn9rCxSs8TPP1mUWQYqffgRas=
X-Received: by 2002:a05:600c:4ed3:b0:43d:db5:7b21 with SMTP id
 5b1f17b1804b1-43d5dc40c1dmr56681635e9.28.1742853511979; Mon, 24 Mar 2025
 14:58:31 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZdtJj7VcEJfsjkjr3UhmkcKS25SEPTs=dB9k3cEFvfX2g@mail.gmail.com>
 <lcbigfjrgkckybimqx6cjoogon7nwyztv2tbet62wxbkm7hsyr@nyssicid3kwb>
 <CA+fCnZcOjyFrT7HKeSEvAEW05h8dFPMJKMB=PC_11h2W6g5eMw@mail.gmail.com>
 <uov3nar7yt7p3gb76mrmtw6fjfbxm5nmurn3hl72bkz6qwsfmv@ztvxz235oggw>
 <CA+fCnZcsg13eoaDJpueZ=erWjosgLDeTrjXVaifA305qAFEYDQ@mail.gmail.com>
 <ffr673gcremzfvcmjnt5qigfjfkrgchipgungjgnzqnf6kc7y6@n4kdu7nxoaw4>
 <CA+fCnZejp4YKT0-9Ak_8kauXDg5MsTLy0CVNQzzvtP29rqQ6Bw@mail.gmail.com>
 <t5bgb7eiyfc2ufsljsrdcinaqtzsnpyyorh2tqww2x35mg6tbt@sexrvo55uxfi>
 <CA+fCnZdunJhoNgsQMm4cPyephj9L7sMq-YF9sE7ANk0e7h7d=Q@mail.gmail.com>
 <s7wo5gqrvqfiq3k5wf2pwdurtdrzixlubmck5xgrr4eoj33hi4@vjexcwpp7g4g> <zmebaukzqlem7qrskdbqyzdsqcgpp6533vvfbo4vh3vtyeh4iu@yghuqyloverw>
In-Reply-To: <zmebaukzqlem7qrskdbqyzdsqcgpp6533vvfbo4vh3vtyeh4iu@yghuqyloverw>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 24 Mar 2025 22:58:21 +0100
X-Gm-Features: AQ5f1JqkwSi0yThMsOGpogsoWYqU98B_Blb_P24sQK5qkQMRfsxA3HC1ACSj060
Message-ID: <CA+fCnZfzA8f2rjq0CAYBvGtQLxZKOWk+3BWwjrdP-T-ncdeLpg@mail.gmail.com>
Subject: Re: [PATCH v2 13/14] x86: runtime_const used for KASAN_SHADOW_END
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: Florian Mayer <fmayer@google.com>, Vitaly Buka <vitalybuka@google.com>, kees@kernel.org, 
	julian.stecklina@cyberus-technology.de, kevinloughlin@google.com, 
	peterz@infradead.org, tglx@linutronix.de, justinstitt@google.com, 
	catalin.marinas@arm.com, wangkefeng.wang@huawei.com, bhe@redhat.com, 
	ryabinin.a.a@gmail.com, kirill.shutemov@linux.intel.com, will@kernel.org, 
	ardb@kernel.org, jason.andryuk@amd.com, dave.hansen@linux.intel.com, 
	pasha.tatashin@soleen.com, guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, 
	mark.rutland@arm.com, broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, 
	rppt@kernel.org, kaleshsingh@google.com, richard.weiyang@gmail.com, 
	luto@kernel.org, glider@google.com, pankaj.gupta@amd.com, 
	pawan.kumar.gupta@linux.intel.com, kuan-ying.lee@canonical.com, 
	tony.luck@intel.com, tj@kernel.org, jgross@suse.com, dvyukov@google.com, 
	baohua@kernel.org, samuel.holland@sifive.com, dennis@kernel.org, 
	akpm@linux-foundation.org, thomas.weissschuh@linutronix.de, surenb@google.com, 
	kbingham@kernel.org, ankita@nvidia.com, nathan@kernel.org, ziy@nvidia.com, 
	xin@zytor.com, rafael.j.wysocki@intel.com, andriy.shevchenko@linux.intel.com, 
	cl@linux.com, jhubbard@nvidia.com, hpa@zytor.com, 
	scott@os.amperecomputing.com, david@redhat.com, jan.kiszka@siemens.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, maz@kernel.org, mingo@redhat.com, 
	arnd@arndb.de, ytcoode@gmail.com, xur@google.com, morbo@google.com, 
	thiago.bauermann@linaro.org, linux-doc@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-mm@kvack.org, 
	linux-arm-kernel@lists.infradead.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=N3iNFOBI;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::331
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

On Mon, Mar 24, 2025 at 11:50=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> >So I assume that if outline mode works, inline mode should be fine as fa=
r as
> >kernel is concerned? If so perhaps it will be more time efficient to pos=
t v3 of
> >this series (once I'm done with kasan_non_canonical_hook() edge cases an=
d
> >unpoisoning per-cpu vms[areas] with the same tag) and work on the clang =
side
> >later / in the meantime.

Generally, yes.

The inline mode also might require adding some __no_sanitize_address
annotations. Typically for lower-level function that get messed up by
the inline instrumentation. But the annotations previously added for
the Generic mode would work for SW_TAGS as well, unless SW_TAGS
instrumentation touches some other low-level code.

> Oh, I guess I also need to add a patch to handle the int3 (X86_TRAP_BP) s=
o
> kasan reports show up in inline mode.

Ah, yes, for SW_TAGS, need an appropriate handler here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfzA8f2rjq0CAYBvGtQLxZKOWk%2B3BWwjrdP-T-ncdeLpg%40mail.gmail.com.
