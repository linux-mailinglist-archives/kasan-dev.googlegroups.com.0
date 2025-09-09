Return-Path: <kasan-dev+bncBDW2JDUY5AORBP73QDDAMGQEZH5NMNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 62D3AB4FFDE
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Sep 2025 16:46:43 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-55f6f4dea68sf4466869e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Sep 2025 07:46:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757429186; cv=pass;
        d=google.com; s=arc-20240605;
        b=OgswHYPqoLIP7p6nAThzPfPN48Ur58xi1uq56BEJ6TUZGTeN3zs/yNVTHD6Ine/Mjt
         HWC1n41M5kPQTMoATwsXBJqZLtKx73uv7WuGsnxtas7DkkMty4NRdy/UGGdo1GkYxbnb
         d2LO3z11mT1hVxSNV6vZoxLt0mhDW8YDPh59E8DsTrmcuQb4PwhiAapBeT21QZZDn2qc
         reIRQ1xt0E0iAosVXFCAjEA1OlIootdUt5bCNDuvqp/99jjwWdBK246hmhIdz1DjZiZz
         MGi0A4bLE0I0MyLacQ1xRQ2mzU6uRNt7PfFSoKyp4P+c4qpBYa68TTh2p75hcojiltNq
         75fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=EM7RPnM8oK0Mvx9mXuFPRPzFJF7V8PAh/xFHYDYiCjE=;
        fh=DUqONPs86bT17d6gRCqy9AGePAbRJaF4ffiMLJDXOMQ=;
        b=NG48I/VdfOYORMcudApBll44Q968+i5OQ39six0U82gxPWAc2cLan96KM1tqd/fMzL
         hHfIwNP3fhzJa/k8fDH6y9sYoVzJmpcRNHERguM2VTk4mSa0ztZMGBa3l2W1O3HfiNHy
         1ergAHD3z4+6xdTOnBBMvXw9NIP/Kiu6YYjTgJC1y5YprWTiOiPpzKiM2hD4k5jDBtnC
         z8T/kp3kxz7+GQ23X7TMZUFPYKBbZ23qWT9881Wqd5xRC/QdmQXS9+oOuWeY97qNwj7u
         OlkLVUArBYjFaRjq8/yEdBSHcYUPlZYpdd7drxqV0RiahFUyYKmhnMvhb6CHk0VPAu6j
         /j5A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QmXL9jo3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757429186; x=1758033986; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EM7RPnM8oK0Mvx9mXuFPRPzFJF7V8PAh/xFHYDYiCjE=;
        b=HUEQJky0OmPkrGGz36TFvilCtvcl3/P5T1grkj5E5bJ8HrZ29vOoRQTYz1p5WSz2CE
         QRPqYge7swc/2d5rE5VK9JXMxLudzZ+mzTEjlHWzcMwvm2OZn9B9hJLSbvU857QoJtk5
         SG0bpSeUQ5A+fjTc9IHRGLsRCbj0F4PeteposP+ltbA1BadG/d3++iUl+OnVQmWHTDNq
         vIKLrXypb7IukvK9IQ76w6mWSyqLopqf9rS/xEidLYE/YHEJiJ4dcZIGit6Ke3elyg2K
         XC7Dromb7DJVCkZda50LeUlZKAet7lLRDYBOcTPuluemDl4VeNYp7961T9/07LzZ6DpQ
         fyoQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757429186; x=1758033986; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EM7RPnM8oK0Mvx9mXuFPRPzFJF7V8PAh/xFHYDYiCjE=;
        b=WQ/GLGMEAEtxAXI+z0cD9F4cq92AyFiQyp8V9yVa5YqvrAQGP5eTFTLThSOyfxqrKB
         nXiWLgom8OvOgQKfK+FQMtjSpIFUVXs41TQiRi+Akq+G/7XsZICOYXjCH+LTbxOiK9bJ
         I2kYf8cX+x9EeLARC5MBu2moZw2u+p5CFGHfHG13UJbiw4x3nGG2l+STtRzQPqWxalse
         rfSrJdOc9Zrp8H3vUURgEnbZpXwhA1P8weeaw8L2BAxYVVwoImWMv0M1L6bZyvasLv57
         CMTHUd/R6eA/LypqnKVeUeP8zKUd8YPH3Rx8vgAghEezmrmIyMe4bZi7hRAP1OP97iSp
         a3Ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757429186; x=1758033986;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=EM7RPnM8oK0Mvx9mXuFPRPzFJF7V8PAh/xFHYDYiCjE=;
        b=xPAT/fliKy1TVAElI6MW6tzpXefq3MHtrtmrZd377KdJ4p2iY4o7gYSV7lyBo0f4QR
         +S/BFhHg7ZQSVv1ilWNW5URA+c/+ZymEMkHdVWvYjGOQOkv75dv1ZdPINvml1pxkHYxn
         2ZMaVIVO1w0pjVwZm1kNHRChqXlhnu3W8XBt5HVfnSsPQdLzGLDYOb+6EM2+wBFV7dOp
         cAh0sPStaSPuPEr0KZrZ+3U1GPW9VU126AM74iG3T3PQwqJp4jJXhmtrTSL3V7X7vmcq
         eC2Xnb955n1i+nOVb6O2OOuP8rZPsG4G4+KGYI8csIzstc7PNeWvHTTd5JID4vYp/ZGq
         sGFQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW572x71h3R+yZZqVBSmumxrqXt8aLUe6AZmOZLVlj6KLtBSjMZEVXdOmNwvkJVDhRw7oVXrg==@lfdr.de
X-Gm-Message-State: AOJu0YyGY4aUyUy8yq8HhU1jusuwaC2sm++sDiDN0GqNL3K3khQUf5yH
	OcDplF0ckqOD21KxF0Kx5WliaVNi4yya3i+6QHW3yHgpebzs1oBtwehG
X-Google-Smtp-Source: AGHT+IGTjhHjo9J/hCMzPw+7MJQQYvk/xyvdO4GGcUig4+5F0K2vrgYGnIzskR67cra8Jn17qmmtBw==
X-Received: by 2002:a05:6512:3ca7:b0:55b:96e4:11b5 with SMTP id 2adb3069b0e04-5625f62abb9mr3558050e87.1.1757429184476;
        Tue, 09 Sep 2025 07:46:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc8lzbCNTmvsgeOHcXWw4OBZQyqDoGvKg6dAhvSBOacqQ==
Received: by 2002:a19:4358:0:b0:564:2d64:8e50 with SMTP id 2adb3069b0e04-5642d6490c2ls719469e87.1.-pod-prod-02-eu;
 Tue, 09 Sep 2025 07:46:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyrpioHx2wNIhHFcRemazsYR5t974CPsHC7/8z7sBNkEjKZB8zDdhxnJ147EyBPhC0mMVC1uKA66M=@googlegroups.com
X-Received: by 2002:a05:6512:2905:b0:55f:435e:36bd with SMTP id 2adb3069b0e04-5625c041677mr2973160e87.0.1757429181524;
        Tue, 09 Sep 2025 07:46:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757429181; cv=none;
        d=google.com; s=arc-20240605;
        b=hMCfKGGgUaHHb3WgCI/GbDPq+IplF1VnrXy27Z9tJzOoVKKCublsw14dD2cLilIWt7
         GzeHRB+XpcxA99rHf8VNo/KdujUnk0oG16Lp6J57j1QSWSlostBjISLcjK0DXW/KMzuQ
         eFd6WK5GV4XbzqBIEJYCn6GixHawdkQFEpeHaBHSm5bEMXSg51ul2sE3+dD53yP+Dhfv
         kbcNFt6LruhFtxkydvKARY2GgViTcybHqWsUztsFv/hSZU4cXa8y26hMaZ3/eNf5YLzB
         8N93QwFZ2ZSjd1DHFdc2DDSRsGhYQsaETw+rempXkoUcJcwrqexScym83VKefQIOPjcd
         by8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DQ6pjHDMM+suXT8naiE9csEpW818jUZBYVFNTfCYGno=;
        fh=FP05XeZNuIpZRV5EBdgT53UqsjzwD0aBSSE9+cyPlrA=;
        b=CgzbvWZGjlQEVxSUVVAzLyN79ieTBB6HJCrO0cI5iZgqhW9IMQLcTB6eTxLlJcz4pa
         ZWBXQHxRsxHj4APUPgHp11coPsBrS7Yswp8OihQdiKXQiSRpjvt4R5IXxecCtSRUyfIN
         9DJYeutWV23jVauZ4wcII+7ek8qD0IarNDeX4wqr8DVcKbp5ZlnV8mbfBA/uQ/fj8/ZS
         8GBL9wgha+b8g5a/ixQ++lQ22kenQAvfDi2riUfSMm4mIzn4d1nkGjf+Yt28J+Eeky6R
         5UYsa62frYf6xof6pEW+/mE1Ip97gSa7RYaNNhRyuAL+Q9Bf2hwvWC4loUVtybnK7UE2
         Guwg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=QmXL9jo3;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-56807035b15si41418e87.1.2025.09.09.07.46.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Sep 2025 07:46:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-3b9edf4cf6cso4886637f8f.3
        for <kasan-dev@googlegroups.com>; Tue, 09 Sep 2025 07:46:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXbU4rN0BiUnqUS3xAP7CFYLKNNOzbtPYMvwVsTWSyB9Hd+9krzY5zQK2tbf/v3SgL16EhG46ZN21M=@googlegroups.com
X-Gm-Gg: ASbGncs3R+csRGnrRzC37L/bVA3nFdOX6i8XKdTuzowkcopPOXFBnRndZREwgcY2qrU
	1+Li0nKONFePugTmc7JfU07s3AMEaHfr6Rfyd90lSVpiGerjjcDUqIVvjZMl9ia93Zv/y5c8kKg
	hKdDwjSTvf4Hs+wgI7BisoO246xjJklA6m+/2IK/lmsCQOhh1VBYzS+eajG3CxO8B9KsuOjhwV4
	IMYTZvQuRJnAWaUyC0=
X-Received: by 2002:a05:6000:401f:b0:3e7:4991:87c4 with SMTP id
 ffacd0b85a97d-3e749918b76mr5400755f8f.61.1757429180544; Tue, 09 Sep 2025
 07:46:20 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
 <2f8115faaca5f79062542f930320cbfc6981863d.1756151769.git.maciej.wieczor-retman@intel.com>
 <CA+fCnZf1YeWzf38XjkXPjTH3dqSCeZ2_XaK0AGUeG05UuXPAbw@mail.gmail.com>
 <cfz7zprwfird7gf5fl36zdpmv3lmht2ibcfwkeulqocw3kokpl@u6snlpuqcc5k>
 <CA+fCnZe52tKCuGUP0LzbAsxqiukOXyLFT4Zc6_c0K1mFCXJ=dQ@mail.gmail.com>
 <m7sliogcv2ggy2m7inkzy5p6fkpinic7hqtjoo22ewycancs64@dnfcl2khgfur> <CA+fCnZc3ZY43KeQcWSw4kgcCqJpAvNj6gKd+x0AkjhuE2R8Hdw@mail.gmail.com>
In-Reply-To: <CA+fCnZc3ZY43KeQcWSw4kgcCqJpAvNj6gKd+x0AkjhuE2R8Hdw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 9 Sep 2025 16:46:09 +0200
X-Gm-Features: AS18NWDf03t8X97flQzZHTvir2nukoTD6nPxpyweIbo71u3mhN5KV1t_32mprjc
Message-ID: <CA+fCnZd6qJRcSukbCuvH5n0KcGYxmrLi=_9vRA7HvRpSbYJNmA@mail.gmail.com>
Subject: Re: [PATCH v5 15/19] kasan: x86: Apply multishot to the inline report handler
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: sohil.mehta@intel.com, baohua@kernel.org, david@redhat.com, 
	kbingham@kernel.org, weixugc@google.com, Liam.Howlett@oracle.com, 
	alexandre.chartre@oracle.com, kas@kernel.org, mark.rutland@arm.com, 
	trintaeoitogc@gmail.com, axelrasmussen@google.com, yuanchu@google.com, 
	joey.gouly@arm.com, samitolvanen@google.com, joel.granados@kernel.org, 
	graf@amazon.com, vincenzo.frascino@arm.com, kees@kernel.org, ardb@kernel.org, 
	thiago.bauermann@linaro.org, glider@google.com, thuth@redhat.com, 
	kuan-ying.lee@canonical.com, pasha.tatashin@soleen.com, 
	nick.desaulniers+lkml@gmail.com, vbabka@suse.cz, kaleshsingh@google.com, 
	justinstitt@google.com, catalin.marinas@arm.com, 
	alexander.shishkin@linux.intel.com, samuel.holland@sifive.com, 
	dave.hansen@linux.intel.com, corbet@lwn.net, xin@zytor.com, 
	dvyukov@google.com, tglx@linutronix.de, scott@os.amperecomputing.com, 
	jason.andryuk@amd.com, morbo@google.com, nathan@kernel.org, 
	lorenzo.stoakes@oracle.com, mingo@redhat.com, brgerst@gmail.com, 
	kristina.martsenko@arm.com, bigeasy@linutronix.de, luto@kernel.org, 
	jgross@suse.com, jpoimboe@kernel.org, urezki@gmail.com, mhocko@suse.com, 
	ada.coupriediaz@arm.com, hpa@zytor.com, leitao@debian.org, 
	peterz@infradead.org, wangkefeng.wang@huawei.com, surenb@google.com, 
	ziy@nvidia.com, smostafa@google.com, ryabinin.a.a@gmail.com, 
	ubizjak@gmail.com, jbohac@suse.cz, broonie@kernel.org, 
	akpm@linux-foundation.org, guoweikang.kernel@gmail.com, rppt@kernel.org, 
	pcc@google.com, jan.kiszka@siemens.com, nicolas.schier@linux.dev, 
	will@kernel.org, jhubbard@nvidia.com, bp@alien8.de, x86@kernel.org, 
	linux-doc@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, 
	linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=QmXL9jo3;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
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

On Tue, Sep 9, 2025 at 4:45=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.c=
om> wrote:
>
> On Tue, Sep 9, 2025 at 10:42=E2=80=AFAM Maciej Wieczor-Retman
> <maciej.wieczor-retman@intel.com> wrote:
> >
> > On 2025-09-08 at 22:19:11 +0200, Andrey Konovalov wrote:
> > >On Mon, Sep 8, 2025 at 3:04=E2=80=AFPM Maciej Wieczor-Retman
> > ><maciej.wieczor-retman@intel.com> wrote:
> > >>
> > >> >> +       if (kasan_multi_shot_enabled())
> > >> >> +               return true;
> > >> >
> > >> >It's odd this this is required on x86 but not on arm64, see my comm=
ent
> > >> >on the patch that adds kasan_inline_handler().
> > >> >
> > >>
> > >> I think this is needed if we want to keep the kasan_inline_recover b=
elow.
> > >> Because without this patch, kasan_report() will report a mismatch, a=
n then die()
> > >> will be called. So the multishot gets ignored.
> > >
> > >But die() should be called only when recovery is disabled. And
> > >recovery should always be enabled.
> >
> > Hmm I thought when I was testing inline mode last time, that recovery w=
as always
> > disabled. I'll recheck later.
> >
> > But just looking at llvm code, hwasan-recover has init(false). And the =
kernel
> > doesn't do anything to this value in Makefile.kasan. Perhaps it just ne=
eds to be
> > corrected in the Makefile.kasan?
>
> Recovery should be disabled as the default when

Eh, enabled, not disabled.

> -fsanitize=3Dkernel-hwaddress is used (unless something was
> broken/changed); see this patch:
>
> https://github.com/llvm/llvm-project/commit/1ba9d9c6ca1ffeef7e833261ebca4=
63a92adf82f

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd6qJRcSukbCuvH5n0KcGYxmrLi%3D_9vRA7HvRpSbYJNmA%40mail.gmail.com.
