Return-Path: <kasan-dev+bncBDW2JDUY5AORBHG26HCQMGQEFTX7FYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id D31C9B47587
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Sep 2025 19:19:25 +0200 (CEST)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-6232f49fe2fsf798566a12.0
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Sep 2025 10:19:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757179165; cv=pass;
        d=google.com; s=arc-20240605;
        b=TUf+dcHQLWcAKQo6XOjmSN068rEXaPWf7j7QOK4gHQxwxcFUZO932xdyUJczYZTfJ0
         6+K4PdolPGyFc6v8yPXKdYQDWSXLzQfbsH6/X1lVILwM7hFIL+IsNTiy0fI4sh4Ikxar
         9NN4u6uIcPG4pqtCHFzOnL1pIh3g03wNcimHxZm/vN39QzvToeK4HZN/JLvfGeQ+6vrN
         GTCGBhCmWJYEwnDwyLev2WUx5oRf5Xw3QgeBDC2nWAxRuiC+LzUbHfSEgWCLgkqfT5tP
         8Pe15IcKsQ89VyfpBpQX7DAzGIdo8rlyvAAoeatgia/zZPpIY3w9khx1Qocdl7tPJjSv
         rFCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=LdPoSrYVcvPK4IUPvEWTF0oxbS/UJCUr5LkB8xMlnN4=;
        fh=K3C/uVzQRLAz81UApo0oD0d2XzWvXRFhdDxk63JWRhk=;
        b=RzVrCaw7UdapKP2W1bSM//jr2UjeE9RUFETD/clNjjdIt2yzx1uqNP+EyEFS+ULufa
         PgP3xo8z6jasLwqeqfWpAlLielTolfs4v9+H2hehDbghQp4CAht+GsdbXEgZowsdyUs0
         bmsIUuYDwNvLOI8p8tBzf1EgI2PcK/8CFFyZwiVvXiFs8UyDixxrc3nhRlmZ0vX9tbSg
         w96QlIPk/dgBw02hPyu+myCp1DA/w9ODR4aCAopUuuH8N1GpOU55PBB6g+m01+KOXjqj
         7eb5339Rz+nVFWfTRit3FtIWmjLHkB3Tud0/8XEMniP8UuY+jvKSVF0dNzZkOUu+kzeo
         eJDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CDyryifX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757179165; x=1757783965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LdPoSrYVcvPK4IUPvEWTF0oxbS/UJCUr5LkB8xMlnN4=;
        b=FpRv6/oxJ6G67XmsO0x+Q9Qze2ysQlGOq/77TCN+ninSYNbehMvU8ED8oTcmEuwdfm
         5i3zW7dSup4tNoAfONBdOxENiixi5WXT1iHb6chtl/fTyk2YoRLFJoJyxiEvBxOBZ0Qz
         +uYA/Lk25diPzNduoYRUH89uwFXBHvavIUysHI1p4Eh3ABZ8DaQ+SijiwTBXqREnlWE8
         F25RH32qUJDXLpM8DrJe9cZfQdjlVGROmNpWgFeFF8PuwaJv7oMZnS1uf28HYaMTSqnA
         mozC8ACpUz3ISH2gJHDbAwtUvchh7ZCVM+UT+uG2dLo4W9hBlbZyWX0v4h7D9O9OvYFt
         +iRA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757179165; x=1757783965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LdPoSrYVcvPK4IUPvEWTF0oxbS/UJCUr5LkB8xMlnN4=;
        b=i/vz0uf/NzPR4cOJKJ/S95/6sAO5G+uMm83NJQ8hCJ/XHU2xkkazF/6AiFMEDoY3kc
         IGSFEQ7SFBPDjLuFRh3nV8177JXtiGv5vR8KCq6ciZlMzVlBRQszH5SnKHdlzCj/krXB
         LJxA0tX8CqiVxRrNP9PY4dN1w2QxfJtnIkiU/9JHkBPaX4pzpmGKO+poBl7cnBAXd0VI
         aG3Iozflcq3+xdSMC589kRBaKPPFWoHy8UnWJDSeMzUB9SvA4PtjbxuI4FoDv/JTkMbF
         C3w3K7hfVr40nsmInB5pbYrhwWuw4skL64RvT2epZ+aUJg81xxfpa8ywogA0LRDKG1Pf
         H2ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757179165; x=1757783965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LdPoSrYVcvPK4IUPvEWTF0oxbS/UJCUr5LkB8xMlnN4=;
        b=wCQpAYN4ncYFfnJbNFMjurfB+dha9QhvmxAwn8E+NHJdePL32bgRWMEKQssDb0aDgv
         1vA6VdipYUgbpAaeAk9FJItbbY0F14YZbggdr/Mo8x3VsSaGbhaQw8wbcdcbfteOg1Xr
         PUFPsYAlDM1sLP+cvdl9RkX9cbqVclasoTtxYNXvheCzZG3Eb5rJAsY18YFdtf1nBapF
         k448cP/BHrHY7PTGoOUrC9BlRMo/T8Yo3P1sAsETco6+brohaKfRUMoiNqm2C3hCPRjN
         Ysq3FzBa+yWpGgCuHHDyH0OyyjajscIV3lPg+UklZnLgk1HDGleIaCrGUVoOKe+EP3Ma
         jQHg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzhrI6a4UXde4zptcsyEvOlFtBFTPm1X2IFU+Kp82hUgnlxmyssHzQm05OMh9VmosipVQahg==@lfdr.de
X-Gm-Message-State: AOJu0YzQysc5qJh2T7Uf+gsJ0z9AeOgAW/tQqVMquV4wu+f/bkz1aTxw
	kXp0erxPyy/U6CuTf+cOodCvJ/RI8IE2V8KW4VW7LK6201yaK5Y9hhxL
X-Google-Smtp-Source: AGHT+IFmAqoSPUZM5VNPGPwScJ4n+If/gaESwkyjtfLVb6Oto8HqDY3IebUrk8Tci3Q6ztJqa/W6Lg==
X-Received: by 2002:a05:6402:2102:b0:620:e309:6c67 with SMTP id 4fb4d7f45d1cf-62376d2c9b6mr2561878a12.2.1757179165161;
        Sat, 06 Sep 2025 10:19:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeqR81b0ntcVb6BslcyTOgokUHfBQlgWWmubVTFHtp+AQ==
Received: by 2002:a05:6402:5048:b0:61d:6bd:6699 with SMTP id
 4fb4d7f45d1cf-621472e5952ls1768383a12.2.-pod-prod-07-eu; Sat, 06 Sep 2025
 10:19:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbQNmcsSHsAGuMHwu9OhUEjIopdEVDuBfGJrM4hDaiMjGQZRnAmNTGWf9ZM1Gv4VwsmkrtOwuML4c=@googlegroups.com
X-Received: by 2002:a17:907:3cc9:b0:b04:6e60:4df1 with SMTP id a640c23a62f3a-b04b17672femr287312366b.53.1757179162697;
        Sat, 06 Sep 2025 10:19:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757179162; cv=none;
        d=google.com; s=arc-20240605;
        b=YeYpRib/a21E/+UP/UlrbgdL1afUgzF2WwTUQhK7BFDELqvo43SbCeAelPpePV7sz/
         EsfRphSnLfZyuL48xIyLCcxQYlqz9disuLws6gBrREHHB0SaRXwTPoUjtQZJn8fJ7z/Q
         3kGnaU/6McDQ8Rtc4lHCNhSLbdAZtjYYtYXzrDvwgFccgTRuM4SGCkgNoAOFommDG+UK
         dUZX2S5EeFBvvHE+BRMnYDV2LP1b8R96EHWFGeUn7eTwXaylyLBGQ9P08EEorgFw8zw3
         gLraMC2mx839EGRKOwyr7Z1zB9zS8PkiR//CK1SHZrunom0kVg6MgQguUuzR4vDkwzHT
         wE7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1/VsaAZE8BZZcz6ps/gV/vx/aBIFb7Atd0DyuiuXeeQ=;
        fh=NkB5bG9dGHDbgVh99RO+tC2y/mTq161XXYHWrf1LP/4=;
        b=P9FbkeLsZuRq2/y85IGxnVuESGbW3jTbIEgvAymYKKwVKpcDYZJpNzkE8wvwrJ9eRe
         Rax0weDVkJY7LPdCQn3xTH9PH8PBJdm2+3I/6s1tOkR92lUkqijbC+YgsaYK2ldyHw4z
         SI/CdGLJywJ8pvzwKjEjkLzaRoGNhnLRFDEjxUE8lY4SG+OfMYEc2WIOiC/fXoc/U8I+
         DMM0dYi7LG9s+nsCQxKPUdT8bqs2l5ISjSZ539Y89oxyOODT3Y6TS+ms0pXQGpfC3t0O
         2Vo5/xezDbmL4B3o8pqGMGjfy1fAJKKoyyxA8xRBLPlzGU405OwjUsWZXIJ20D0lA6oQ
         p8nQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CDyryifX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-aff04cdab8csi44054766b.1.2025.09.06.10.19.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Sep 2025 10:19:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-3e537dc30c7so1145603f8f.3
        for <kasan-dev@googlegroups.com>; Sat, 06 Sep 2025 10:19:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/Z2XEfVJyT7HWnOmMK75034bCQh+KY+f2GZnhbyrqICza9uJLXW8G+XV/p2zmytuNjqTst+LuwX8=@googlegroups.com
X-Gm-Gg: ASbGncv8rO9jPEzEJgiVf0wWDhFugWiBUe8muDeQCg5BbrJdfQChgQ8nDTGuBhYiJNr
	SiN7QC9EEt0NCFaJF6e9acOTTnLzsfgc6EgbVNtC/gpAPPzOQMwHuahjYeOfGeRw048bf1ZB+ay
	II4T/pXqR6Y6mbjnV894RqYdmjDSahzSBypAySBemBitD6NApFhDY5lm8jlvcFkO+ZShsA9OApS
	yNIY/Bj
X-Received: by 2002:a5d:64c5:0:b0:3e5:47a9:1c94 with SMTP id
 ffacd0b85a97d-3e645e858b9mr1560400f8f.49.1757179161926; Sat, 06 Sep 2025
 10:19:21 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com> <3339d11e69c9127108fe8ef80a069b7b3bb07175.1756151769.git.maciej.wieczor-retman@intel.com>
In-Reply-To: <3339d11e69c9127108fe8ef80a069b7b3bb07175.1756151769.git.maciej.wieczor-retman@intel.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 6 Sep 2025 19:19:11 +0200
X-Gm-Features: AS18NWDcebDXZ0CncnyAGPmg6m7DGHRQKjrUi3A45HP3A_5pPACdVmuNY1mdCAs
Message-ID: <CA+fCnZedGwtMThKjFLcXqJuc6+RD_EskQGvqKhV9Ew4dKdM_Og@mail.gmail.com>
Subject: Re: [PATCH v5 18/19] mm: Unpoison vms[area] addresses with a common tag
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
 header.i=@gmail.com header.s=20230601 header.b=CDyryifX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
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

On Mon, Aug 25, 2025 at 10:31=E2=80=AFPM Maciej Wieczor-Retman
<maciej.wieczor-retman@intel.com> wrote:
>
> The problem presented here is related to NUMA systems and tag-based
> KASAN mode. It can be explained in the following points:
>
>         1. There can be more than one virtual memory chunk.
>         2. Chunk's base address has a tag.
>         3. The base address points at the first chunk and thus inherits
>            the tag of the first chunk.
>         4. The subsequent chunks will be accessed with the tag from the
>            first chunk.
>         5. Thus, the subsequent chunks need to have their tag set to
>            match that of the first chunk.
>
> Unpoison all vms[]->addr memory and pointers with the same tag to
> resolve the mismatch.
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
> ---
> Changelog v4:
> - Move tagging the vms[]->addr to this new patch and leave refactoring
>   there.
> - Comment the fix to provide some context.
>
>  mm/kasan/shadow.c | 10 +++++++++-
>  1 file changed, 9 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index b41f74d68916..ee2488371784 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -646,13 +646,21 @@ void __kasan_poison_vmalloc(const void *start, unsi=
gned long size)
>         kasan_poison(start, size, KASAN_VMALLOC_INVALID, false);
>  }
>
> +/*
> + * A tag mismatch happens when calculating per-cpu chunk addresses, beca=
use
> + * they all inherit the tag from vms[0]->addr, even when nr_vms is bigge=
r
> + * than 1. This is a problem because all the vms[]->addr come from separ=
ate
> + * allocations and have different tags so while the calculated address i=
s
> + * correct the tag isn't.
> + */
>  void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
>  {
>         int area;
>
>         for (area =3D 0 ; area < nr_vms ; area++) {
>                 kasan_poison(vms[area]->addr, vms[area]->size,
> -                            arch_kasan_get_tag(vms[area]->addr), false);
> +                            arch_kasan_get_tag(vms[0]->addr), false);
> +               arch_kasan_set_tag(vms[area]->addr, arch_kasan_get_tag(vm=
s[0]->addr));
>         }
>  }
>
> --
> 2.50.1
>

Do we need this fix for the HW_TAGS mode too?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZedGwtMThKjFLcXqJuc6%2BRD_EskQGvqKhV9Ew4dKdM_Og%40mail.gmail.com.
