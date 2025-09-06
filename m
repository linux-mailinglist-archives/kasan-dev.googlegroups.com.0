Return-Path: <kasan-dev+bncBDW2JDUY5AORB5WZ6HCQMGQESOHDW3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id E03F1B47579
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:18:48 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-45b96c2f4ccsf18565695e9.0
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:18:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179128; cv=pass;
        d=google.com; s=arc-20240605;
        b=XWplHraKglV3GLpCEaom0mjH0seslZ/ErkCAzrFgznKoEeJJphD+IhYyzmb0xdvypH
         nqeyESZum4ih31VM86qSTquZ8Zu1gK7iQ4qOttaUrRb6b4yUWKoDyzv0ivdoU8Ovr8es
         EGJoPeIBeY7tMvpBwBHCePrLdjfWumLm8mU91wY8BOHsphzB1kUrJCA09on+lvvdFHI6
         KSArK6NnhiKIEAITsty4D48G7vzT0QpmJIf184u+fx0YnEMHh93o7IGjVuLyBJunK6Ti
         rQ2+UaZDo4ss76Q4I1ZkGdtBwJXmqvY1rs3GCz3rHk9J3Go8Im1RK9/XDNjc8Kk5VZ2s
         mLSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=83DD0rG5tZUzmzd184A8s6pXAgTfs9VLrCBXQaTP5Gw=;
        fh=Q2SwkN9Ce4tXSGEqarlHfIYbiprpmkX+/9EO+SaTsY0=;
        b=bY/9Wn9/nFdSaFtAHMrIfXeWKja9mXY0KhfJhjK9Kt0/FCFZDVTnO+VGYVIrxD5pz4
         YnVYUckWplsiYIGSK5+PG+LjYeMCZRZ2Suypei4MdT6vzu1LrR+ZvnN4lQQwgdmsjNV8
         qspGsGuJMGcEGLR2E4l89JZQUlTJW3NcSvJFrMqSnFB0NQ6aeSVcXYF3mcuTX5qec4Aq
         nyi7bKCH/0c5+aS5bBK1cztAF+zhSjlmZtMMoSdjtNW7M2zFe5XtkM36m1r54e8OP5ue
         7O6OBdcZysvZaLDftC4yIQyv9rzmEs0qSaf/gOsGJE9NlTShol+usqLl5ZnuNvncR9YO
         HJ4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Amr+vYkC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179128; x=1757783928; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=83DD0rG5tZUzmzd184A8s6pXAgTfs9VLrCBXQaTP5Gw=;
        b=b+L6OFQiXlvii+OJRa9gahkAqr2UxjV6/WAv31A372ZAhysoK/gZF3rBOAlrr17NM5
         WFcLbvxN/ZAK4lZ6DUkQPkPGozR+SXLQsj6A1e93QrIaTbUMzjf48lWMOR/3kFniP5pw
         k9WZh+Y+TK9zrrNbrGWYXF82ajRgytWRpilo2BK6zRVniuXb56npPB+ey3NDhLdDr05w
         5sPOScyshk6diIPPPB3rrbf7mgzb5EoTlfsOoQ/sBP/causd+u4gT0UjDRrXo27D2tIm
         xstUhJHIKqLWSfp7OQ9F3SJyyVvmeYQK0mAzyE+i8RaStck858jegh9CIy2IR+ghXSo7
         z6gw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179128; x=1757783928; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=83DD0rG5tZUzmzd184A8s6pXAgTfs9VLrCBXQaTP5Gw=;
        b=id/uBvJdBbvkeqLD8kiHnOmD9OlmvfkW9rRAzWyDJbkzq7hG7pomdCqaU8JFX3pxba
         kM0yWfwT3mUH8pWauwlQC0BrCdHSc3m4rSJOzbTBXm02LpOg9zpjhfoF7tVRjKpQtyqn
         BGQ6renLznpzFLjkiRMrIi1lPXmuqVB3SLpoIzkQejVB1m/4Ilil+h1SXkzNZIILdCAN
         B0u/c3atrdWI6X9NcOwYJb50PlOMs0jAQmm+dcVfHAWoMMXFwvA+nfjPxJrbYaafH6aL
         hY+t8wcvjwH6gDudppsscYrlINS1Nsh7UUdV2r31fYChpAfuEz4sZRieF/QMpCwwBcYN
         Vq9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179128; x=1757783928;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=83DD0rG5tZUzmzd184A8s6pXAgTfs9VLrCBXQaTP5Gw=;
        b=UwysLPwu8sWQ7KZdj/myGThbsCVWnK94Q5o3vp9rF3SRk+QgSNp0vDGTuEDm0SfyJo
         xVDbJJZV9XjjSB2gBnyetcTZ8ScugLIMPMlTFr5JzFwFoQs0GmpVQq7w6e1a0mz/fYut
         P5QRTeZCqFhDpcCOtShEob/Azp1/4LFMn9fuzbs1OwOuI/3RuxeUpy0Q7naBOlnuNELI
         AUxvLC+kscNh/hxIvXhUwb+/1Fou89zXInjjxzM8mFy/2TT5bkSWYuRMscpcxfS3uLdR
         iIam4YwXN3xYUdsrjzy/HojlFNdwGfLN82tEzeyMhsWDT0meO299GTM1pJYuAEqFtcUz
         eCXQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUhwMwtUNXnsXH5qCQsH+NKmkRCJ00LdiA9uOW8b7suy9jdXPrMZ/tbcFd6WL26r6h4OBKtWQ==@lfdr.de
X-Gm-Message-State: AOJu0YyoHK+ajqgCMM6KhwMyshu/x80A+t0SxYFqI02Km6D5RLWJPTBQ
	DFtFyi/ICTjHUnkphoJHOdeEMF6M04uIBDPLssoTkGsZ14s16cDzQg8E
X-Google-Smtp-Source: AGHT+IGdoPOvZKc09mNodsnhvnO1pP1yyXwblyUxnn+HUlUaaOouIQL8h8ZguUkMzrxlB1nuN8quVg==
X-Received: by 2002:a05:600c:548a:b0:45b:64bc:56ea with SMTP id 5b1f17b1804b1-45dddee9076mr19786945e9.23.1757179127612;
        Sat, 06 Sep 2025 10:18:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd+/aV0EJ+hfjTApJHErN0VYsDtcs4xegiIYTB5fEpPgA==
Received: by 2002:a05:600c:3e07:b0:45b:990e:852b with SMTP id
 5b1f17b1804b1-45dd83ed809ls9255075e9.1.-pod-prod-03-eu; Sat, 06 Sep 2025
 10:18:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVqDwLAQ7+iXkbMPlyo2Ck+bVAKeHI9KDMOMrTvex8wDp1tsOf30U805N1cLN/N9CBqjPCoR1kB54A=@googlegroups.com
X-Received: by 2002:a05:600c:4e13:b0:45b:79fd:cb3d with SMTP id 5b1f17b1804b1-45de19f4ea7mr12458125e9.36.1757179124885;
        Sat, 06 Sep 2025 10:18:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179124; cv=none;
        d=google.com; s=arc-20240605;
        b=ejzWV+LdddJm8sPhyI+eJgZILVk32Vzh2pyOZv3uXTfkEVsrgXC8dkKR/Xk4dWg5ff
         ZvVSzr3MH4taNmXHMQ1FfxLZgLvbR+GpG4xmJTMuRtYCQriAwsCbyYPvtZpJB4S3A4jk
         7/UP8lz5rgT5QbgHr8EeusVlB7+amZBu4riiHMj+gGiuaJjJQYF9x8z1gurX5P/1WSVI
         XkJuTWrCr2HN30KMPv5I9ymGKyyIZi5WdizVGqAvg4sdwkUipeCcbsnQLfqam4h2w9Rz
         5kST6/sL0i0D8vyAL+RzKr9lCYaRKbuereXKUhGjDPvvBop48IWtaZG0YmI5kiTZWhet
         swHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XRcDWNpUUbZTeol9QRv1WeubB1y1xQlfIP4m0Tbtx6c=;
        fh=M6hCg5MUI+sqYHt9ddvg4j0EI/wH6UiTCfMTSrKxVNk=;
        b=iAHB74uOGfV1fRNnKCxYIin7MRk1Kn3trvgap2PhsjgM2CgGjAv68BTvfSOrP2mzez
         +Ci4gB8H0+acF+hGMywFdA1mmCCJrYYm+pmAXp8K8i4jZ0KFZIFqXVhUruwiJE+cm0To
         waDlVNmr1cuBOKsCql04nFYP3Jq4JyUObieKkaXVJOp0c8xYOW0x4vZBqw3xnINt5C+5
         8/HPkMEGPavCDDZobpCqsCHWPLAqKm+HborOJFZ7+zQR/91QpDYNhW0/YOrLbPr4J8ku
         uC7OsOh2j28wFzPv1ecl/FqBcryBbpGmq1GcFSFhiZTxgPxL4F+PmkIDVxNqolZsam3h
         skvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Amr+vYkC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dd058fa6csi2242965e9.1.2025.09.06.10.18.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:18:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id 5b1f17b1804b1-45ddcb1f495so6510965e9.1
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:18:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU4l8HUQl0tGZyvWyVSa6gA53fze+2Al6IvleHDLcCCIKaJ3PVXwR0AwkVyFDc5sUbB6iUQCBMx2S0=@googlegroups.com
X-Gm-Gg: ASbGncvlyWHZFqMZFi4cWUJRQfc1Pv7Dh2urs/eegfPT7KSCfnzpiF5iXQai4CFngOZ
	eSfkhAJRzk+LVQFmQwd6OZOaG7V8/Pi3ZfDc7wePrhozd71Wu8hATYAepbfO+DL2yZIZQZYzSO2
	A7W/w4fJ49HO0kacZu29xf6/NS8X8LKZkliSw0jChPi9k62Cei4ChxTS2VgrOC3FdZWhCNX5Mxf
	rgn3JJh
X-Received: by 2002:a05:6000:1a86:b0:3d7:cd09:ae1e with SMTP id
 ffacd0b85a97d-3e6425eb1e9mr1335076f8f.17.1757179123944; Sat, 06 Sep 2025
 10:18:43 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com> <7a85ceb0918c6b204078e6d479b85fef6a6c1768.1756151769.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <7a85ceb0918c6b204078e6d479b85fef6a6c1768.1756151769.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:18:33 +0200
X-Gm-Features: AS18NWA_eEHpTXTQ0knIVmmRfCpxcK6aFKCLGMxVUA2hte0L9DlCgBnRDAv5G6o
Message-ID: <CA+fCnZecdx5QsYcwn6ZyNoOkQRqmonUmSmfiihYTF8Ws_0O9KA@mail.gmail.com>
Subject: Re: [PATCH v5 05/19] kasan: arm64: x86: Make special tags arch specific
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
 header.i=@gmail.com header.s=20230601 header.b=Amr+vYkC;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::333
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

On Mon, Aug 25, 2025 at 10:27=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> KASAN's tag-based mode defines multiple special tag values. They're
> reserved for:
> - Native kernel value. On arm64 it's 0xFF and it causes an early return
>   in the tag checking function.
> - Invalid value. 0xFE marks an area as freed / unallocated. It's also
>   the value that is used to initialize regions of shadow memory.
> - Max value. 0xFD is the highest value that can be randomly generated
>   for a new tag.
>
> Metadata macro is also defined:
> - Tag width equal to 8.
>
> Tag-based mode on x86 is going to use 4 bit wide tags so all the above
> values need to be changed accordingly.
>
> Make native kernel tag arch specific for x86 and arm64.
>
> Replace hardcoded kernel tag value and tag width with macros in KASAN's
> non-arch specific code.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v5:
> - Move KASAN_TAG_MIN to the arm64 kasan-tags.h for the hardware KASAN
>   mode case.
>
> Changelog v4:
> - Move KASAN_TAG_MASK to kasan-tags.h.
>
> Changelog v2:
> - Remove risc-v from the patch.
>
>  MAINTAINERS                         |  2 +-
>  arch/arm64/include/asm/kasan-tags.h | 13 +++++++++++++
>  arch/arm64/include/asm/kasan.h      |  4 ----
>  arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
>  include/linux/kasan-tags.h          | 10 +++++++++-
>  include/linux/kasan.h               |  4 +++-
>  include/linux/mm.h                  |  6 +++---
>  include/linux/mmzone.h              |  1 -
>  include/linux/page-flags-layout.h   |  9 +--------
>  9 files changed, 39 insertions(+), 19 deletions(-)
>  create mode 100644 arch/arm64/include/asm/kasan-tags.h
>  create mode 100644 arch/x86/include/asm/kasan-tags.h
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index fed6cd812d79..788532771832 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13176,7 +13176,7 @@ L:      kasan-dev@googlegroups.com
>  S:     Maintained
>  B:     https://bugzilla.kernel.org/buglist.cgi?component=3DSanitizers&pr=
oduct=3DMemory%20Management
>  F:     Documentation/dev-tools/kasan.rst
> -F:     arch/*/include/asm/*kasan.h
> +F:     arch/*/include/asm/*kasan*.h
>  F:     arch/*/mm/kasan_init*
>  F:     include/linux/kasan*.h
>  F:     lib/Kconfig.kasan
> diff --git a/arch/arm64/include/asm/kasan-tags.h b/arch/arm64/include/asm=
/kasan-tags.h
> new file mode 100644
> index 000000000000..152465d03508
> --- /dev/null
> +++ b/arch/arm64/include/asm/kasan-tags.h
> @@ -0,0 +1,13 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_KASAN_TAGS_H
> +#define __ASM_KASAN_TAGS_H
> +
> +#define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
> +
> +#define KASAN_TAG_WIDTH                8
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define KASAN_TAG_MIN                  0xF0 /* minimum value for random =
tags */
> +#endif
> +
> +#endif /* ASM_KASAN_TAGS_H */
> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasa=
n.h
> index 4ab419df8b93..d2841e0fb908 100644
> --- a/arch/arm64/include/asm/kasan.h
> +++ b/arch/arm64/include/asm/kasan.h
> @@ -7,10 +7,6 @@
>  #include <linux/linkage.h>
>  #include <asm/memory.h>
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -#define KASAN_TAG_MIN                  0xF0 /* minimum value for random =
tags */
> -#endif
> -
>  #define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
>  #define arch_kasan_reset_tag(addr)     __tag_reset(addr)
>  #define arch_kasan_get_tag(addr)       __tag_get(addr)
> diff --git a/arch/x86/include/asm/kasan-tags.h b/arch/x86/include/asm/kas=
an-tags.h
> new file mode 100644
> index 000000000000..68ba385bc75c
> --- /dev/null
> +++ b/arch/x86/include/asm/kasan-tags.h
> @@ -0,0 +1,9 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_KASAN_TAGS_H
> +#define __ASM_KASAN_TAGS_H
> +
> +#define KASAN_TAG_KERNEL       0xF /* native kernel pointers tag */
> +
> +#define KASAN_TAG_WIDTH                4
> +
> +#endif /* ASM_KASAN_TAGS_H */
> diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
> index e07c896f95d3..fe80fa8f3315 100644
> --- a/include/linux/kasan-tags.h
> +++ b/include/linux/kasan-tags.h
> @@ -2,7 +2,15 @@
>  #ifndef _LINUX_KASAN_TAGS_H
>  #define _LINUX_KASAN_TAGS_H
>
> -#include <asm/kasan.h>
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +#include <asm/kasan-tags.h>
> +#endif
> +
> +#ifndef KASAN_TAG_WIDTH
> +#define KASAN_TAG_WIDTH                0
> +#endif
> +
> +#define KASAN_TAG_MASK         ((1UL << KASAN_TAG_WIDTH) - 1)
>
>  #ifndef KASAN_TAG_KERNEL
>  #define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index b396feca714f..54481f8c30c5 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -40,7 +40,9 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
>
>  #ifdef CONFIG_KASAN_SW_TAGS
>  /* This matches KASAN_TAG_INVALID. */
> -#define KASAN_SHADOW_INIT 0xFE
> +#ifndef KASAN_SHADOW_INIT

Do we need this ifndef?

> +#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
> +#endif
>  #else
>  #define KASAN_SHADOW_INIT 0
>  #endif
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 1ae97a0b8ec7..bb494cb1d5af 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -1692,7 +1692,7 @@ static inline u8 page_kasan_tag(const struct page *=
page)
>
>         if (kasan_enabled()) {
>                 tag =3D (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MA=
SK;
> -               tag ^=3D 0xff;
> +               tag ^=3D KASAN_TAG_KERNEL;
>         }
>
>         return tag;
> @@ -1705,7 +1705,7 @@ static inline void page_kasan_tag_set(struct page *=
page, u8 tag)
>         if (!kasan_enabled())
>                 return;
>
> -       tag ^=3D 0xff;
> +       tag ^=3D KASAN_TAG_KERNEL;
>         old_flags =3D READ_ONCE(page->flags);
>         do {
>                 flags =3D old_flags;
> @@ -1724,7 +1724,7 @@ static inline void page_kasan_tag_reset(struct page=
 *page)
>
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
> -       return 0xff;
> +       return KASAN_TAG_KERNEL;
>  }
>
>  static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
> diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
> index 0c5da9141983..c139fb3d862d 100644
> --- a/include/linux/mmzone.h
> +++ b/include/linux/mmzone.h
> @@ -1166,7 +1166,6 @@ static inline bool zone_is_empty(struct zone *zone)
>  #define NODES_MASK             ((1UL << NODES_WIDTH) - 1)
>  #define SECTIONS_MASK          ((1UL << SECTIONS_WIDTH) - 1)
>  #define LAST_CPUPID_MASK       ((1UL << LAST_CPUPID_SHIFT) - 1)
> -#define KASAN_TAG_MASK         ((1UL << KASAN_TAG_WIDTH) - 1)

So we cannot define this here because of include dependencies? Having
this value defined here would look cleaner.

Otherwise, let's add a comment here with a reference to where this
value is defined.

>  #define ZONEID_MASK            ((1UL << ZONEID_SHIFT) - 1)
>
>  static inline enum zone_type page_zonenum(const struct page *page)
> diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags=
-layout.h
> index 760006b1c480..b2cc4cb870e0 100644
> --- a/include/linux/page-flags-layout.h
> +++ b/include/linux/page-flags-layout.h
> @@ -3,6 +3,7 @@
>  #define PAGE_FLAGS_LAYOUT_H
>
>  #include <linux/numa.h>
> +#include <linux/kasan-tags.h>
>  #include <generated/bounds.h>
>
>  /*
> @@ -72,14 +73,6 @@
>  #define NODE_NOT_IN_PAGE_FLAGS 1
>  #endif
>
> -#if defined(CONFIG_KASAN_SW_TAGS)
> -#define KASAN_TAG_WIDTH 8
> -#elif defined(CONFIG_KASAN_HW_TAGS)
> -#define KASAN_TAG_WIDTH 4

This case is removed here but not added to arch/arm64/include/asm/kasan-tag=
s.h.


> -#else
> -#define KASAN_TAG_WIDTH 0
> -#endif
> -
>  #ifdef CONFIG_NUMA_BALANCING
>  #define LAST__PID_SHIFT 8
>  #define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
> --
> 2.50.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZecdx5QsYcwn6ZyNoOkQRqmonUmSmfiihYTF8Ws_0O9KA%40mail.gmail.com.
