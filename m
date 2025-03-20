Return-Path: <kasan-dev+bncBCSL7B6LWYHBB45F6G7AMGQESAXQG5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id F32B1A6AC30
	for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 18:40:05 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-549aec489c5sf541379e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Mar 2025 10:40:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742492405; cv=pass;
        d=google.com; s=arc-20240605;
        b=NiXbm0FGlLJIyWNZft6VtuU+pUptq/8bTa82u9lZ4vcfvbIe5B74+6K44oPqS0oQIB
         0+5TCsB2gdfF3SrN/N8QPeyl/sA5kqF5GIxR1wBnGvbrOAlmjEzNhNwofvhcAwLrqrx3
         euf8IVmHqLhHKW1YxZze/g+Cj0OtdhMGV102aYwqcQKGdUVzx4P8lqjMYxmwNpuKBRaZ
         BNxmBk9zdGEjUolQo0952MY9HxtINFDYxFqOEJEE18/uUVxFNcb48ckvXex9X8ZZoUwz
         MFayi5hugYg1RkYIgggRXUeCAOjEwLeABA84FvP+AxjawyrYhsheKHiLWMes7A7KPRPd
         dbaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=OzfKZ4P59xcFoaG5vMrZ+2PbYzvaBAXs3Els3+OGDB0=;
        fh=1T5q0Kd0oLU0VNRsZ6UDdROfNFfjINAM9HD4o5Ka3ZE=;
        b=JGljO6tRmjwNwPIHVd0b/cgNqZE4GunOPA52q4NvUqey8VbbrOSt1DkXJNvUCMjlMb
         SqmQuvKnL8pySgQczxbieIegjuLzNlDoQiDLp05OAjsJJ/gO1gF5sTCmuGH9mx9V25zU
         /YaR5SQcClNMYUL6R0W/kxyg3afUyZhCfsizBO3o0ptlaA+ua3AEPlYTwQZvoLgNrxlT
         x8OrwqTB7k5wmsMLgzKN6rN9YCA7xPFdZEo0BR7KqOCDha/L6bfaFP207p8I0AenaTEY
         H9lOKOhsQVyuYMfteRsFaCq2W1hKM2CwWkDyuMbgRB0sN1ReomJUCLUv6VSTBa7R6v3d
         GDXg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bpD0LqsD;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742492405; x=1743097205; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=OzfKZ4P59xcFoaG5vMrZ+2PbYzvaBAXs3Els3+OGDB0=;
        b=M/C0eBUzB495M5EEgoO0AJ+/kMHV6GEYTTPUTgDziw+DiR5o3+5TYrnBxyTcAp1l/E
         hzlNqxxON8hM+h3V06I2YWNfg+5xcAdwW+CNmGsCC1NYgiaeYKC+hzLXR4Ucp8J9tWi9
         OJ48cd+eMhW7a1jORAMDpn65Ab3Q1hSmWxlyhubmeJ9+V0QiivM8gKeO+PDbe8GFSDLA
         voRF6QGq7IS7dCa14gNcGF0/x4x2umlI2aGNXAoayXDrKo15bib+eEaxsxxC3WEUG3jQ
         f5I3QbiREiDemfgOwdr7UysnHb3B9giUa1wJv/NHmwRkeAUENnxUzGZQm0W7XxLvZ8Kc
         6c0w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742492405; x=1743097205; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OzfKZ4P59xcFoaG5vMrZ+2PbYzvaBAXs3Els3+OGDB0=;
        b=B1FFMDzkarfimlYoHt2Eh5i3UWuRK1fuLzY328jw48XkrUSFbJeWGUlG1Wx4iBWBI2
         6IGDORG/qmrMdIumg11f6Hl4K2pk3kWhpVEuImNC5cjmSNaMmxh6mA6vxUCoq0tAkWZI
         r99lR1mCow0abQbiCekrUfvdREo9Hq20qDj3ZCWtpq9cd50LnSZ27F32xmqXffKP4U+C
         NXZUgpZL8fTn/lMvhAsJSmJTwylXi9AybuOu3TUtHJ4ZxFw4RfUHuVLSBZHA2tKV+XYK
         E2TRQAuGoSKt9Hd8CCIzZ+ks5LToO1VmPFj7ecdJDzd7jg4KRwTkbS7hZ+O6v5uZeoHe
         jZ+A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742492405; x=1743097205;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OzfKZ4P59xcFoaG5vMrZ+2PbYzvaBAXs3Els3+OGDB0=;
        b=YSBT8z1hHWKV/V5yRLkao3pLfVzkEw+BkpgamwZAodpo1AaA321CpqBU+JI72WxYan
         QkizBDFJSjiTx/fU2ZOqyeMU90V7aqzufPh54GzfqrvcvvwAyYY+7N0g5VPaG52z9q9z
         /u8pT7NCIjd29fRyCG5CHYdT699HvhszMps6QAyGKUWr8S/zwbvZhXxfMkdyvnudPCBE
         wQmGvxChOelUnVkoIUo0sVXTDzirNi5FU3PIeo1kPdpyo7TVc7oA00FmnzooUI6s/fz7
         3WUKZcYKTbRsVg1vbmHMk5yFrgmGF9njT40SfangKUXSrFLxyWTdxi9euZHSUZCQn+RH
         cIRg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXb+I3dsTyuNJ99hvDjSOlDMl7y4u3um3SinGb3vj5YKlo7zRfxVxXlQvjbDQJZ7UthqdmkEQ==@lfdr.de
X-Gm-Message-State: AOJu0Yxjp9mTzUPiTWOLjtTXrhFVmbBD0VjpJuwJ4nY3EbaoM3nPyuGO
	CEylaN3/SWkwU2PHt+4oyw5H6nf1I1FBeTC4PJ+qlN/Zy71Kd547
X-Google-Smtp-Source: AGHT+IEoU2AzEVKedjxeYT3kf/XxovZzZtxwroMcKs9TQMtmS6rcjrvMdyNSxX5O/HHh9konepdpAw==
X-Received: by 2002:ac2:4e07:0:b0:548:e44d:f3ee with SMTP id 2adb3069b0e04-54ad646cdf7mr82547e87.10.1742492404295;
        Thu, 20 Mar 2025 10:40:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAKOUHUDPKBaJ3jCiEK5xVbu45n4XogkL29MjhKCjo7r4Q==
Received: by 2002:a19:3812:0:b0:549:9b17:deaf with SMTP id 2adb3069b0e04-54acfafc166ls232310e87.0.-pod-prod-02-eu;
 Thu, 20 Mar 2025 10:40:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXl5GXf//qC6RuOhpQKI25hf+ArEFzJmAwDe6joD8WD/duZ4/SThrkyKo2CwN1xWlEn3oPCs41Mryw=@googlegroups.com
X-Received: by 2002:a05:6512:1148:b0:549:9078:dd45 with SMTP id 2adb3069b0e04-54ad648f673mr85078e87.28.1742492401068;
        Thu, 20 Mar 2025 10:40:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742492401; cv=none;
        d=google.com; s=arc-20240605;
        b=KKuhIobEbO7rY7lVR68A+9FKcgbCypuZ3aVAWJwmPI3fpo7lee8qmoZzh0SnLYGhF3
         vWcc/c6iL8FjZ8H/xBCzizMqO4TOGY4c2/AxnB+XXVlgUSoAManLeR0Su5tNCbpr3l8W
         bdy6pNyISxUcI6c8yaOCZ/cdwIVHByg6/1bzswOuqU3E+zpN1us5+hhAS+0o2R5mqzaj
         4GhzXVyZB80KSIDwImiSVxXPLTKW1T7voZhclOD4ZmFUFI2thb2Fzx9fvGVvNKECmBfZ
         cx/0BTwbnJzAMh1nG4yV21hlzT7Uc15bwo1n5Jx12wXq/GFJVT/MeL0Gz0h1ft3KgfMH
         btAw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ICJPfH1Men5qwSYszeUMQ6QRHz5SpwAhZQR7oJ7/pJ8=;
        fh=ywipjPmVP5+4zlOElr/WauoYgj2f9kvsvTwqG0MJs+k=;
        b=Xkb3HgPqNIELL134BPWeNEgqQGZ/DRs9bQcsWGiHiFALThecVboRoLuiEINWFM2ChK
         AOZn3a3sb+rBuMB1ajEl7+J9qHtSiBUnvLlV2WznVV9W1LJTuu4yiMDLi1yMKwwyDnvZ
         XFed7mK14AolR716/szzkdZ4X/AscKs9AiNyvCVNpL4k3fsp9+LzVBibsRo9FakVOW14
         lUiXzGL+v5sWvnrYGE3Ha3747DhZehr2QGcf2x12K4ybbzA/UalDmQ9028cUbGvn8mwV
         UjOMNtrDlwsgeBRGcjXCd7AUQr6XM+xbUWPFPMk3DjGv9TgRSPGV/StIQCDjvnvso1Ql
         5n0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bpD0LqsD;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32a.google.com (mail-wm1-x32a.google.com. [2a00:1450:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-54ad6473ef3si1188e87.3.2025.03.20.10.40.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 20 Mar 2025 10:40:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32a as permitted sender) client-ip=2a00:1450:4864:20::32a;
Received: by mail-wm1-x32a.google.com with SMTP id 5b1f17b1804b1-43cf89f81c5so1245035e9.2
        for <kasan-dev@googlegroups.com>; Thu, 20 Mar 2025 10:40:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWimvXu3sF/FqHQOo78X3wTPk4V9+3z6MRB00QVCe5CmgOoQRf8Dz6ZzaW0pDjegtIKB1m2WqNDfOA=@googlegroups.com
X-Gm-Gg: ASbGncvFyzXhesBTQgAT4Z9qZGC+XxQG35lZqe9xXLwt7p3bSQquStK83lLrLndpuMB
	DhD3Q0hEOQwJAq1v9R5NGeyDNh/sgnDHZLDiuiRgWLMwCXoMVzJsKORRm3DmSlTV59ZILfxh3qd
	cxO9N5ym2ygwDbVcWDCWeOY/FSDUeyeMVjkXH0Ku74aN9YzHUrRoseqQWg
X-Received: by 2002:a05:600c:46c3:b0:43b:bbb9:e25f with SMTP id
 5b1f17b1804b1-43d44d75804mr24674625e9.6.1742492399899; Thu, 20 Mar 2025
 10:39:59 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com> <383482f87ad4f68690021e0cc75df8143b6babe2.1739866028.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <383482f87ad4f68690021e0cc75df8143b6babe2.1739866028.git.maciej.wieczor-retman@intel.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Thu, 20 Mar 2025 18:39:35 +0100
X-Gm-Features: AQ5f1JqCTLk6bw5pMZNlmkGp7az-6cdHmNjgmKBcGwH1kgc8PZz3csgjGnMk__8
Message-ID: <CAPAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw@mail.gmail.com>
Subject: Re: [PATCH v2 09/14] mm: Pcpu chunk address tag reset
To: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Cc: kees@kernel.org, julian.stecklina@cyberus-technology.de, 
	kevinloughlin@google.com, peterz@infradead.org, tglx@linutronix.de, 
	justinstitt@google.com, catalin.marinas@arm.com, wangkefeng.wang@huawei.com, 
	bhe@redhat.com, kirill.shutemov@linux.intel.com, will@kernel.org, 
	ardb@kernel.org, jason.andryuk@amd.com, dave.hansen@linux.intel.com, 
	pasha.tatashin@soleen.com, ndesaulniers@google.com, 
	guoweikang.kernel@gmail.com, dwmw@amazon.co.uk, mark.rutland@arm.com, 
	broonie@kernel.org, apopple@nvidia.com, bp@alien8.de, rppt@kernel.org, 
	kaleshsingh@google.com, richard.weiyang@gmail.com, luto@kernel.org, 
	glider@google.com, pankaj.gupta@amd.com, andreyknvl@gmail.com, 
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
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bpD0LqsD;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::32a
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

On Tue, Feb 18, 2025 at 9:19=E2=80=AFAM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> The problem presented here is related to NUMA systems and tag-based
> KASAN mode. Getting to it can be explained in the following points:
>
>         1. A new chunk is created with pcpu_create_chunk() and
>            vm_structs are allocated. On systems with one NUMA node only
>            one is allocated, but with more NUMA nodes at least a second
>            one will be allocated too.
>
>         2. chunk->base_addr is assigned the modified value of
>            vms[0]->addr and thus inherits the tag of this allocated
>            structure.
>
>         3. In pcpu_alloc() for each possible cpu pcpu_chunk_addr() is
>            executed which calculates per cpu pointers that correspond to
>            the vms structure addresses. The calculations are based on
>            adding an offset from a table to chunk->base_addr.
>
> Here the problem presents itself since for addresses based on vms[1] and
> up, the tag will be different than the ones based on vms[0] (base_addr).
> The tag mismatch happens and an error is reported.
>
> Reset the base_addr tag, since it will disable tag checks for pointers
> derived arithmetically from base_addr that would inherit its tag.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
>  mm/percpu-vm.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/percpu-vm.c b/mm/percpu-vm.c
> index cd69caf6aa8d..e13750d804f7 100644
> --- a/mm/percpu-vm.c
> +++ b/mm/percpu-vm.c
> @@ -347,7 +347,7 @@ static struct pcpu_chunk *pcpu_create_chunk(gfp_t gfp=
)
>         }
>
>         chunk->data =3D vms;
> -       chunk->base_addr =3D vms[0]->addr - pcpu_group_offsets[0];
> +       chunk->base_addr =3D kasan_reset_tag(vms[0]->addr) - pcpu_group_o=
ffsets[0];

This looks like a generic tags mode bug. I mean that arm64 is also
affected by this.
I assume it just wasn't noticed before because arm64 with multiple
NUMAs are much less common.

With this change tag-mode KASAN won't be able to catch bugus accesses
to pcpu areas.
I'm thinking it would be better to fix this on the pcpu_get_vm_areas()
area side by replacing
this
    for (area =3D 0; area < nr_vms; area++)
        vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->addr,
                                             vms[area]->size,
KASAN_VMALLOC_PROT_NORMAL);

with something like
    kasan_unpoison_vmap_areas(vms, nr_vms);
which will unpoison all areas using the same tag.

Thoughts?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APAsAGxDRv_uFeMYu9TwhBVWHCCtkSxoWY4xmFB_vowMbi8raw%40mail.gmail.com.
