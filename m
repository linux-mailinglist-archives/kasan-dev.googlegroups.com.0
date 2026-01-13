Return-Path: <kasan-dev+bncBDW2JDUY5AORBEN4S3FQMGQEGUFSZWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 32406D16241
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 02:21:23 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-430f4609e80sf3745488f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 17:21:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768267282; cv=pass;
        d=google.com; s=arc-20240605;
        b=H+vAynkMV2AytktS8snvzDcuO0pEMM95XfO5ahWHwNioCF0tiE9js/P7P14zqioreR
         Kpd/o1O6uVNM5DIDwzolAzk6ctL3nxDmVVg7kd9OF28105M8sQg2LOGq1eSy9ZvgDbz7
         SVVeZU3Y1KGwCJ5SR1mS5lEbVjWzVIlKLIKAdNSWAhLSZNtIKwLIEVL/2uUhuxzvRPNB
         yUEt46DUDQQzCcqy8Pi9dOXUeXVUWvtHOm6aleuG7fRLuzRMf189MjY9WDV+mLZee3gS
         bH0a2yyxGFQwLiVnti/L7njh5MQUJ6SH/nxt4x4kMUIImtQ4+SuXx8xPOa82LJWrm1dz
         zZUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=m/T474uD32k1TLYcUp3cr13Us1PMstNkacKn1uExWhw=;
        fh=ZlbcJJHao0TH1/yj4OAoBNUxL+wkq1DRPnQk1HS3ups=;
        b=cTZgtVXLJK8IEtiFAJXcFP9LdQSAYcAXNI2kCKOhD0aUf/mpkbN+B6w+3uhPEucq7Z
         0eXaIKHVh74B7QVeheAwsXNJ8mzNl34mI7DpcsRAaZkBMrE13zIwxdt7bllcPQjC5czj
         bQWAAi++X2nx9AcMN1X+1azYOMJeXHXKt9A5KMEdVN1E4WmR5Nsv5ZhFIm65AJIZCvZ/
         mhFryN4ZVpI3KiBZ4VGQjrQn9X1Uj6iwlWzH9dwJgGtU5F1Wtc9RHkfobZcA5p07VDei
         MswCuHAo6074SS/pP0cqmPJoOeKkGBTkfxEWvAG2kJvid1qjPpX+OeHlZerWTjWSGoaj
         n49Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=J7ZbbyC0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768267282; x=1768872082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=m/T474uD32k1TLYcUp3cr13Us1PMstNkacKn1uExWhw=;
        b=V4LQOnYYhRVMD3EXKxRGZqWpJB/xQhGma8BVvoJdwHBOp0oaMLIZgmHew21YU9d+tv
         5hwceupXK00N59rnCiThvdPiSmbPflkLG4im5kJJKbVDL3tiorEtwshrBF1nEFfNVCDs
         mWKFSToSJ2iFboS5S4AsBgLBNheohZt64PZccUfeb0pGCZH0zk7k7fQakSRJkhoUokAe
         gsuAcvkTK+dzbdTJDd0GHPrMgGImu6MfDfaOGdl37lyl+EWhdNpHUBXpi5+eDNqnH/Ch
         Fto3RU2qV1nY+8Ef8mNazLIIBNjHzheMsg21f8n/0C1IFdwFivkrTqzRV2z3QspjcyO5
         BKug==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768267282; x=1768872082; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=m/T474uD32k1TLYcUp3cr13Us1PMstNkacKn1uExWhw=;
        b=SClK4i4Nc8TLS7hIBUUUzmbiGcrGPl8Ity632ZhBG5eO9mu/EEFBj81XoipA5mdbFJ
         9COR2P5P/X9CLcZi6n6fm14Vlin3lw1L7C/vdZOBnngAv9jaSBj3p/S9meEwOI62Div3
         Cxspl8IyoYPfgwpFZMHaSzWYh9tKH5BQPxTSpwsYefPP2L2HgSQckYOCRuNNbjkps4ni
         2O5lAH/cdIr5FxiY42mJ7S83P41Xu5f/NWVYZUD0eY2LtjEtphHWsVyOGP7ZAWI7pVJz
         neU5cbITp8m3Ax4Qn7f7o5F2ZLsuhQdZWsHGvxqtfXiu0nKrV7UP6LH4PB2dTtjm2Kwx
         IIew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768267282; x=1768872082;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=m/T474uD32k1TLYcUp3cr13Us1PMstNkacKn1uExWhw=;
        b=JUl4rAAyiqtPDJhrDevjft0FqW/a9IC6gG7qxJJMashEzJEUqZTfsKYjMudFgqpVWp
         hRdQNkPgOyXAz+TWvHHt53kzahoh+RYPto8f0Is+tss0veqoTEpW/B/iJAZuxW51xHDM
         y1e4ONe5sqziK1Th17Dfd5rr08Q25mDPy5uAlT7j59tPMG0NA1Q/kg5n1624aSKAzoFo
         tc1W7BzUYlzdFpx2fvS4+waXkTLsbb92/aLAYIbsmtjK49HswF/sdvWbDokOEe5+j+Xp
         u6plMD/xcslAnO+5KziqwMzHm3VqcxUFXaMI2Y8zjoRp3QVLjtpXrwSS3GzdiOGkaEQ/
         zGVg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWz01Hg9v8MOET/RHSqtQa9lXu8Vr5Uye+IjP4DbPZaOA2+zH8SM6f20mLVJcP9Kz7zzF4uow==@lfdr.de
X-Gm-Message-State: AOJu0Yy/WGgditF95mPO4CCctF9XcgNJGEhJITnKp70Vbp3xiLSAySAL
	rRU6uS9O9Nh+jIDLCNi1KAixV+mjjQgIODJU8rZHvi6YghCz8eHwy3en
X-Google-Smtp-Source: AGHT+IEm+PPKIpxnHXGNB0JXFKB37Zd+TRN/HGWxFSWeAI8x1fWSBCt8JpcYLsaS7RZEgN0PJRfZ1g==
X-Received: by 2002:a05:6000:200d:b0:432:84ee:1882 with SMTP id ffacd0b85a97d-432c375b055mr22812357f8f.36.1768267282296;
        Mon, 12 Jan 2026 17:21:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EZu6QsmPr2KS/syt7oCMe//83Sg+H7zM71gSvsy3kKWw=="
Received: by 2002:a05:6000:40e1:b0:425:57b0:537d with SMTP id
 ffacd0b85a97d-432bc8e24c9ls3978273f8f.0.-pod-prod-04-eu; Mon, 12 Jan 2026
 17:21:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVydc6CIhrpvfUQr8yhbfraoABRLniDpF5jJ20y1aEib233kom1YauK2FbvREJ3/fJ1/cIUmvESFOw=@googlegroups.com
X-Received: by 2002:adf:f609:0:b0:432:5bef:ecf7 with SMTP id ffacd0b85a97d-432c375b500mr19550247f8f.37.1768267279726;
        Mon, 12 Jan 2026 17:21:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768267279; cv=none;
        d=google.com; s=arc-20240605;
        b=IV7xKgNW9asw2YU8tszOQk724npc21iAiY1sV2zicJ+7Pz7La6BaNHPRTGEdmdarxG
         ifDAqT31AkIR0KSASq62zQw4ZYg/rQPrJwr1oop2+JWXz+M0KIaDSP0hilJNFar3PJPG
         FqMHha7Yg+iQJri+fx9r8a2azy2DBUe3hUqtTWIlFecqbxziRWYx6hTAgOgSdDiNtshg
         EUdHe2x7zd/XGvRmTps6mQ9fHAg5m4zvkVKZBppsD8mhPxHttkQsYkxFan3/Efm2ZsaT
         IYXdIzXN90WoWCY/K/S4FWvi82BxmwNPIg4pLUUHVPREDeYjzlu5EnQ3+vPHao/DMApq
         9dkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=e0/waOmhHsYmDL/6HVvoGGIYHZETE02HxsKl6ODkF3o=;
        fh=/0av83RU6gcvb6/vJX3MOfadlVwq9CxPEu95U2pqetA=;
        b=XqfDwifewQJ3gn0gV2VwlmWHR5d6TikwGdecqrO/PmrjPKd536k5zLcZzPp6iI3078
         ZCfd0tKR8BzzAIruQ9mi/GPgrn5MrPjmjci+sch9YDCJfcCrcfNt/2kugwNkg1+rlhT4
         X0yFHmWU9xlNPg6Wb/zGx+R2AIm9yJVR2noghES/KZ2Jzm6dz20bl0MWSfv8OqEpEMn5
         MGLeDNAYxHyYhTVC14089tZapF5Flu4YjjVpVn4lhyaIO8cBgaeNGEPcus/tmrfgYNda
         6PMxKdceEDBuh7Mdufhja/e8XAeveHok8ZPX/dgqXgE7I2WBBMNoGDSFtHPSfyxFHUW/
         NUvg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=J7ZbbyC0;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-432be35a16csi329975f8f.3.2026.01.12.17.21.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 17:21:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-42fb03c3cf2so3728050f8f.1
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 17:21:19 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXc13uvVt8RjpBuhakoEaih3B63ioWTxpZcsyBwJjp1Ce9q3ghZWgJsuMPQIdrvqekQ4XEqdsDzAfw=@googlegroups.com
X-Gm-Gg: AY/fxX4CcI8DwNpP7NjCtrby3PyEtxnP3SJxO0aPzzKn2gGvcr7q+b+VpMNjPwhxHOD
	RaJsxtcbV2A9lDDQ7Kp3cGTqkNuC0FGBN1NkkOOvDvFALPbuk35q0DILqFezu/dYA23Gbj3EVL6
	gb7kYGY1NHIm9QAvxh23FXWITVV0NsJUvij5GCI3I0S/MVa0aHcNunK/DY9mCcaJSQ3mkUTARPW
	bNGeu4QxsVL1C5LO1bGKmqyQH4MudRckvZlvEgZGk/qUvRfKNlzgGbAHBlQrZ7dhgFY9odUQJNG
	3Nafa5zvnvfWU6qsHPCkKaN9e2bcvA==
X-Received: by 2002:a05:6000:26ca:b0:431:808:2d60 with SMTP id
 ffacd0b85a97d-432c3629aebmr24541037f8f.12.1768267278856; Mon, 12 Jan 2026
 17:21:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768233085.git.m.wieczorretman@pm.me> <be136bf8d1a6ae9ef98686c3ba0b6a4e2ea2e780.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <be136bf8d1a6ae9ef98686c3ba0b6a4e2ea2e780.1768233085.git.m.wieczorretman@pm.me>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 13 Jan 2026 02:21:07 +0100
X-Gm-Features: AZwV_QjCoIAxOzPZYukp_TYwCHn5QSJvAWN-Df89pT1TOcJPzRbvNO1VkRAILAE
Message-ID: <CA+fCnZfQmhSyF9vh3RzreY7zrQ4GbQOp5NbA0bXLHUMG6p28QQ@mail.gmail.com>
Subject: Re: [PATCH v8 02/14] kasan: arm64: x86: Make special tags arch specific
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	"H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, 
	David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, 
	Samuel Holland <samuel.holland@sifive.com>, 
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=J7ZbbyC0;       spf=pass
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

On Mon, Jan 12, 2026 at 6:27=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Samuel Holland <samuel.holland@sifive.com>
>
> KASAN's tag-based mode defines multiple special tag values. They're
> reserved for:
> - Native kernel value. On arm64 it's 0xFF and it causes an early return
>   in the tag checking function.
> - Invalid value. 0xFE marks an area as freed / unallocated. It's also
>   the value that is used to initialize regions of shadow memory.
> - Min and max values. 0xFD is the highest value that can be randomly
>   generated for a new tag. 0 is the minimal value with the exception of
>   arm64's hardware mode where it is equal to 0xF0.
>
> Metadata macro is also defined:
> - Tag width equal to 8.
>
> Tag-based mode on x86 is going to use 4 bit wide tags so all the above
> values need to be changed accordingly.
>
> Make tag width and native kernel tag arch specific for x86 and arm64.
>
> Base the invalid tag value and the max value on the native kernel tag
> since they follow the same pattern on both mentioned architectures.
>
> Also generalize KASAN_SHADOW_INIT and 0xff used in various
> page_kasan_tag* helpers.
>
> Give KASAN_TAG_MIN the default value of zero, and move the special value
> for hw_tags arm64 to its arch specific kasan-tags.h.
>
> Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
> Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> Acked-by: Will Deacon <will@kernel.org> (for the arm part)
> ---
> Changelog v7:
> - Reorder defines of arm64 tag width to prevent redefinition warnings.
> - Remove KASAN_TAG_MASK so it's only defined in mmzone.h (Andrey
>   Konovalov)
> - Merge the 'support tag widths less than 8 bits' with this patch since
>   they do similar things and overwrite each other. (Alexander)
>
> Changelog v6:
> - Add hardware tags KASAN_TAG_WIDTH value to the arm64 arch file.
> - Keep KASAN_TAG_MASK in the mmzone.h.
> - Remove ifndef from KASAN_SHADOW_INIT.
>
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
>  arch/arm64/include/asm/kasan-tags.h | 14 ++++++++++++++
>  arch/arm64/include/asm/kasan.h      |  2 --
>  arch/arm64/include/asm/uaccess.h    |  1 +
>  arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
>  include/linux/kasan-tags.h          | 19 ++++++++++++++-----
>  include/linux/kasan.h               |  3 +--
>  include/linux/mm.h                  |  6 +++---
>  include/linux/page-flags-layout.h   |  9 +--------
>  9 files changed, 44 insertions(+), 21 deletions(-)
>  create mode 100644 arch/arm64/include/asm/kasan-tags.h
>  create mode 100644 arch/x86/include/asm/kasan-tags.h
>
> diff --git a/MAINTAINERS b/MAINTAINERS
> index 0d044a58cbfe..84fdf497a97c 100644
> --- a/MAINTAINERS
> +++ b/MAINTAINERS
> @@ -13581,7 +13581,7 @@ L:      kasan-dev@googlegroups.com
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
> index 000000000000..259952677443
> --- /dev/null
> +++ b/arch/arm64/include/asm/kasan-tags.h
> @@ -0,0 +1,14 @@
> +/* SPDX-License-Identifier: GPL-2.0 */
> +#ifndef __ASM_KASAN_TAGS_H
> +#define __ASM_KASAN_TAGS_H
> +
> +#define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
> +
> +#ifdef CONFIG_KASAN_HW_TAGS
> +#define KASAN_TAG_MIN          0xF0 /* minimum value for random tags */
> +#define KASAN_TAG_WIDTH                4
> +#else
> +#define KASAN_TAG_WIDTH                8
> +#endif
> +
> +#endif /* ASM_KASAN_TAGS_H */
> diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasa=
n.h
> index b167e9d3da91..fd4a8557d736 100644
> --- a/arch/arm64/include/asm/kasan.h
> +++ b/arch/arm64/include/asm/kasan.h
> @@ -6,8 +6,6 @@
>
>  #include <linux/linkage.h>
>  #include <asm/memory.h>
> -#include <asm/mte-kasan.h>
> -#include <asm/pgtable-types.h>
>
>  #define arch_kasan_set_tag(addr, tag)  __tag_set(addr, tag)
>  #define arch_kasan_reset_tag(addr)     __tag_reset(addr)
> diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/ua=
ccess.h
> index 6490930deef8..ccd41a39e3a1 100644
> --- a/arch/arm64/include/asm/uaccess.h
> +++ b/arch/arm64/include/asm/uaccess.h
> @@ -22,6 +22,7 @@
>  #include <asm/cpufeature.h>
>  #include <asm/mmu.h>
>  #include <asm/mte.h>
> +#include <asm/mte-kasan.h>
>  #include <asm/ptrace.h>
>  #include <asm/memory.h>
>  #include <asm/extable.h>
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

One thing that stood out to me here was that for x86, KASAN_TAG_KERNEL
is defined as a 4-bit value (0xF). Which makes sense, as
KASAN_TAG_WIDTH =3D=3D 4.

But for arm64, KASAN_TAG_KERNEL and others are defined as 8-bit values
(0xFF, etc.), even though for HW_TAGS, KASAN_TAG_WIDTH is also =3D=3D 4
and only the lower 4 bits of these values define the tags.

This happens to work out: for HW_TAGS, __tag_set resets the top byte
but then uses the given value as is, so the higher 4 bits gets set to
0xF and the lower set to the tag. And for saving/restoring the tag in
page->flags, everything also works, as we only store the meaningful
lower 4 bits in flags, and restore the higher 0xF when doing ^ 0xFF.

But this is not related to this series: I think the way x86 defines
KASAN_TAG_KERNEL to be 0xF makes sense; we might just need to clean up
the arm64 implementation at some point.

> +
> +#define KASAN_TAG_WIDTH                4
> +
> +#endif /* ASM_KASAN_TAGS_H */
> diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
> index 4f85f562512c..ad5c11950233 100644
> --- a/include/linux/kasan-tags.h
> +++ b/include/linux/kasan-tags.h
> @@ -2,13 +2,22 @@
>  #ifndef _LINUX_KASAN_TAGS_H
>  #define _LINUX_KASAN_TAGS_H
>
> +#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
> +#include <asm/kasan-tags.h>
> +#endif
> +
> +#ifndef KASAN_TAG_WIDTH
> +#define KASAN_TAG_WIDTH                0
> +#endif
> +
> +#ifndef KASAN_TAG_KERNEL
>  #define KASAN_TAG_KERNEL       0xFF /* native kernel pointers tag */
> -#define KASAN_TAG_INVALID      0xFE /* inaccessible memory tag */
> -#define KASAN_TAG_MAX          0xFD /* maximum value for random tags */
> +#endif
> +
> +#define KASAN_TAG_INVALID      (KASAN_TAG_KERNEL - 1) /* inaccessible me=
mory tag */
> +#define KASAN_TAG_MAX          (KASAN_TAG_KERNEL - 2) /* maximum value f=
or random tags */
>
> -#ifdef CONFIG_KASAN_HW_TAGS
> -#define KASAN_TAG_MIN          0xF0 /* minimum value for random tags */
> -#else
> +#ifndef KASAN_TAG_MIN
>  #define KASAN_TAG_MIN          0x00 /* minimum value for random tags */
>  #endif
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index 0f65e88cc3f6..1c7acdb5f297 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -40,8 +40,7 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
>  /* Software KASAN implementations use shadow memory. */
>
>  #ifdef CONFIG_KASAN_SW_TAGS
> -/* This matches KASAN_TAG_INVALID. */
> -#define KASAN_SHADOW_INIT 0xFE
> +#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
>  #else
>  #define KASAN_SHADOW_INIT 0
>  #endif
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 6f959d8ca4b4..8ba91f38a794 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -1949,7 +1949,7 @@ static inline u8 page_kasan_tag(const struct page *=
page)
>
>         if (kasan_enabled()) {
>                 tag =3D (page->flags.f >> KASAN_TAG_PGSHIFT) & KASAN_TAG_=
MASK;
> -               tag ^=3D 0xff;
> +               tag ^=3D KASAN_TAG_KERNEL;
>         }
>
>         return tag;
> @@ -1962,7 +1962,7 @@ static inline void page_kasan_tag_set(struct page *=
page, u8 tag)
>         if (!kasan_enabled())
>                 return;
>
> -       tag ^=3D 0xff;
> +       tag ^=3D KASAN_TAG_KERNEL;
>         old_flags =3D READ_ONCE(page->flags.f);
>         do {
>                 flags =3D old_flags;
> @@ -1981,7 +1981,7 @@ static inline void page_kasan_tag_reset(struct page=
 *page)
>
>  static inline u8 page_kasan_tag(const struct page *page)
>  {
> -       return 0xff;
> +       return KASAN_TAG_KERNEL;
>  }
>
>  static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
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
> -#else
> -#define KASAN_TAG_WIDTH 0
> -#endif
> -
>  #ifdef CONFIG_NUMA_BALANCING
>  #define LAST__PID_SHIFT 8
>  #define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
> --
> 2.52.0
>
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfQmhSyF9vh3RzreY7zrQ4GbQOp5NbA0bXLHUMG6p28QQ%40mail.gmail.com.
