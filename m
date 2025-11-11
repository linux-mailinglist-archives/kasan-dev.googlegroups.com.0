Return-Path: <kasan-dev+bncBCCMH5WKTMGRB674ZPEAMGQEORAHX3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 95D48C4C940
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 10:14:37 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-787dd35fb9dsf18644417b3.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Nov 2025 01:14:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762852476; cv=pass;
        d=google.com; s=arc-20240605;
        b=MKU7LnCQs6sAFXga5HOL7iO7JI6fzrxCO69aiYUksNOuWMpsT0sRT1xgHF8vI4x3Wx
         i4TcEUOb3ryvF76rx4Og0VVCG653f/58HWkBJuUkfn+tnGeWiJEOVt4X1APHRQmUWSxi
         k2b86icurXORFN1s2TA60D4hFa8qrQtdix1g/M2SWcKYkyobOAiUmSyRW96wCTkqY2E3
         hjwnQD/05zf/k/NK+QTDs9PhjH/6Z1xOz6KyU4mvPuI+SPEWXmCww9e1XNx+QMq4sExH
         ifL+EpwspTE+s7/KdAWfBmX9hOrQ9SXB+S/S9aGU8ZpSm5t213xw3r2WW+Gxr6ogDJQX
         b1xw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vAE1EP9NjSKS4Ujhqu34Wlz/B7BFuoWLSeOK7e8EqfY=;
        fh=PndzG1ONHBKwoi0f8PXEjL4noFCvXUS2wiWL9XBjlvU=;
        b=E+p46taXNDahfx3EOVQYQoS3dM7bRV1eofe9KxBmRVtHRGovPJ0+MhBpHskwahSpCM
         y9BxsI44UN9ts6lwU2nodgVxNXyuBAEEEXIt5LWK2i5swX1r8ZWC99aInJ96V58P+Ngn
         TmteQXE+g/vqC1QGlkynFN6X685uK1MB+6r9VfV3s+3mSgBo+21qhEbxM0megIvLmNw4
         Zxk2e1B2l4VhIsxaV2voW8/tytLj4fUURh2UUysET5U/1DwtO5bVuAioQ0z6GK6iQsEM
         /7XPjOkMcNBeOgUPHX+LiMZCdCr/d/OHZseh/euEh+u4dNuWltnvnMC1+oldg9gSJsd8
         Zd3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RTKxS2az;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762852476; x=1763457276; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vAE1EP9NjSKS4Ujhqu34Wlz/B7BFuoWLSeOK7e8EqfY=;
        b=gSM+OxMCgNdFLPP2MfFPkboU3hRjaU2giFwiFmdo/ScKm8X0pIQWgb1ucfpV3Uq64U
         cKSbKs1reNY5p+p0w7uNur19u+KgYoty+8xPObcsUtwcT1lEEfJQPM04yvcqws8E36VQ
         YlbyvsyHQ06pca1RfKCIf0t7I1TACvNhfLpfBjgFmsv4VIQRd78Aaa9q4PIi14nf8af4
         eUthGCMSaY9iOltBhVJsu6od3SbO238xXMMd9hCnjPn3ssEarj/JQDZVk71ZOFMrAxol
         RGvkdMX1mmy/GiucdZOWa4CIijmzDEQ7DL6mIQ4kTEue75Os6o9RjnCcPOMprwnrZ2Zn
         /TsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762852476; x=1763457276;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=vAE1EP9NjSKS4Ujhqu34Wlz/B7BFuoWLSeOK7e8EqfY=;
        b=vANBfjKELivglVI1bi4szhf2BJeaajeryfyXlcVeM38jKzr0HegH5IvfRjik2kUMcz
         dcwLJfLKIyMOc1IHFZQPlg0PdeoXGRDCVY0XeNxlzWdY/LcJhgASUsmhxg1nhXFRePW2
         flSeA3/9gZfsnT+Rtm+y3za7MvIme/qkGoKYUb1mIfdMZGz2uw4sKS+p9L4SraezO/BW
         ez+PvzDba4Wg06mIv8fh6HF5e7etfb4+nHq5ibarvi4pguyqCW17Du3zMNvVIxJSgmug
         NSwhiLDSKk2i3InIU6qYMtEWUZkd6ZWqfcoI+z79cAiQdgicPsjMTcY9IaB+DA32tEY7
         IIjQ==
X-Forwarded-Encrypted: i=2; AJvYcCVUVctfz1LDJd+TFnhKontpOOuw7gbpp4A9yQK82lQy4gOkj/emWBWhcZNUJuzQydsPoV/PMg==@lfdr.de
X-Gm-Message-State: AOJu0Yxvx88hHb7xG81/RQQ5IqGtU5JXQPMTZ+8qbECCFRZwh1Ni3yhb
	XSjRqgQSyWBBK/QSJHowe/kShp9pHAqxCYwcqitlCtlxMLyaLYTJpIFq
X-Google-Smtp-Source: AGHT+IHooWIPAkpZiDMSAhEODL5iWSsPthL/T6pz17GYUjJXOwIIDZh5lra7qUImipVFN5mXvxKbcA==
X-Received: by 2002:a05:690e:2598:b0:63f:2bc7:7074 with SMTP id 956f58d0204a3-640d45e595fmr7214327d50.60.1762852475690;
        Tue, 11 Nov 2025 01:14:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zr37HTTxUFjrhQ+vzrVtdNgcuTo0YW0v/0TPNyQyKn6w=="
Received: by 2002:a05:690e:12:b0:5f3:b863:1e52 with SMTP id
 956f58d0204a3-640b55311f0ls4881983d50.0.-pod-prod-03-us; Tue, 11 Nov 2025
 01:14:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV+kDbmAacfppRcZl5WnCuImakoVsJ3Wdpp+Sq6ARjIx731mXEOK8PmjC9sgnc+grA1DrcWoGMB/6w=@googlegroups.com
X-Received: by 2002:a05:690c:6104:b0:786:5fb0:3c08 with SMTP id 00721157ae682-787d547235cmr110908587b3.63.1762852474915;
        Tue, 11 Nov 2025 01:14:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762852474; cv=none;
        d=google.com; s=arc-20240605;
        b=OJPNAVuNX9QAOMYDGpdaa8VG2CsDjEZrqy74AG1J+JRrBoRaq0iHadl2hhxYJKc+j6
         /6SUt4DOk7oxr9XzqLN5vjvq29bRS21/kLpdUBeLOXxxb+PPDe0vyBPEy70D6+9yMOQm
         MPf6SSIJX0pou/FM4oEtZWvBpy2LJAF8Rhn0CHKrVvldo5sOMQIlFj5+jsqD36p5dw8H
         U3Z3MiDpDCe6yFt8xZMi8ifZycXAW78y+5+rjI9ahyjbXaD1eenDD6URvayDA0LShvzT
         OV6NVS5ZvS7N6EKDJgIF74Dogle8SN7XSu+VVzwxZ+KJBp+H3zfOZ4vZW4QMun5wp/o7
         KvWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lZTy2q2TNTCA3OHKdlCs5XdCV4IXpZdhN+lpNGYPqtA=;
        fh=ie1qpTQhl9w34Gi6XQCCalXK9CFMq33VgczVOg9aQ4w=;
        b=MCTbB+1JA3nbzv1u78FquSDnPuKzPXeTKFWQ7mmb7sbWfeiK1ZTeXDB1uv/LhvRbun
         pfp2yOrNeqC/V0b8/eZjazRcTVwYBrOuXqYYiEgvxR6ARrYZDrX9nfzX+xg5nLyH+f3q
         bX0lCbmG5KmWZyVWCRXy+hPXEYZcnkAXfdzJ+JBWXmTq+dYq6kmYvvo0zYNsK1LyFp95
         pgCWZZziFfgnkjpxgeLyCD7BwX2BTAo7VmrSqNw6tiFPNQQjCYs3SshkTpz9VODle+rB
         hjfVhHjKIjcryNDVvVTavQr2CXtiWnkuaoWYyVNwBbZ0jGEJSCfCpi/86IW2J2JOkiuC
         HRDw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=RTKxS2az;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-787d643a6cbsi5583847b3.0.2025.11.11.01.14.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Nov 2025 01:14:34 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id d75a77b69052e-4eda26a04bfso39094731cf.2
        for <kasan-dev@googlegroups.com>; Tue, 11 Nov 2025 01:14:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV/fHgJZ7SGu7WidzTbcfVlItessReZQAjDSuTkEt7rxZTL3Tkt5lAfGNep5dEt6EEX6gJtunOho9c=@googlegroups.com
X-Gm-Gg: ASbGncuOY3wPmRHYGmCXNdL4ZsIgdeHpY69leJ1i6UgQZoGvDU482Fz7vHpy3Aucgt9
	7KhuFQRcEDQlpHbUwEQEh5PEPevK43bZu3ZnoX5kxW7dN7LmXmLAZSBdd77ADBn0YgScMZ37uhx
	guz+tWrUuYe5XICLFfVUb/5emqMUFb0rbMRyvMId5m00M/p2QP6Wg124+zSm8DpFfV5mr86AAJS
	eFx5+1HDMc1YV8UxsAT2iczz5QHiNfzgdbwVA9E/MqvySzM9UGFFJv0stuQZR9oDSXXo1UxWPdD
	VZqc+o98Zgu01efNaiIHXgPwWGx6lwlXcnhZ
X-Received: by 2002:a05:622a:205:b0:4ec:f151:6559 with SMTP id
 d75a77b69052e-4eda4ec1851mr145606591cf.27.1762852474078; Tue, 11 Nov 2025
 01:14:34 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <d6443aca65c3d36903eb9715d37811eed1931cc1.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <d6443aca65c3d36903eb9715d37811eed1931cc1.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Nov 2025 10:13:57 +0100
X-Gm-Features: AWmQ_bknFBa8gAhB6UE8n7ZlyUgSKcguUN9eypJruwNRSxK5vCFPizbRNuQ2qaE
Message-ID: <CAG_fn=V4jVyS41MDxJeN-A2zk6WhTnxp7m3FRWmkXMpy5f+haA@mail.gmail.com>
Subject: Re: [PATCH v6 09/18] mm/execmem: Untag addresses in EXECMEM_ROX
 related pointer arithmetic
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, 
	kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, 
	ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, 
	morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, 
	baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, 
	wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, 
	fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, 
	ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, 
	brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, 
	mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, 
	thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, 
	jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, 
	mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, 
	vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, 
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, 
	ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, 
	broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, 
	maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, 
	rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, 
	llvm@lists.linux.dev, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=RTKxS2az;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::82d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Wed, Oct 29, 2025 at 8:08=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> ARCH_HAS_EXECMEM_ROX was re-enabled in x86 at Linux 6.14 release.
> vm_reset_perms() calculates range's start and end addresses using min()
> and max() functions. To do that it compares pointers but, with KASAN
> software tags mode enabled, some are tagged - addr variable is, while
> start and end variables aren't. This can cause the wrong address to be
> chosen and result in various errors in different places.
>
> Reset tags in the address used as function argument in min(), max().
>
> execmem_cache_add() adds tagged pointers to a maple tree structure,
> which then are incorrectly compared when walking the tree. That results
> in different pointers being returned later and page permission violation
> errors panicking the kernel.
>
> Reset tag of the address range inserted into the maple tree inside
> execmem_vmalloc() which then gets propagated to execmem_cache_add().
>
> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Alexander Potapenko <glider@google.com>

> diff --git a/mm/execmem.c b/mm/execmem.c
> index 810a4ba9c924..fd11409a6217 100644
> --- a/mm/execmem.c
> +++ b/mm/execmem.c
> @@ -59,7 +59,7 @@ static void *execmem_vmalloc(struct execmem_range *rang=
e, size_t size,
>                 return NULL;
>         }
>
> -       return p;
> +       return kasan_reset_tag(p);

I think a comment would be nice here.


> --- a/mm/vmalloc.c
> +++ b/mm/vmalloc.c
> @@ -3328,7 +3328,7 @@ static void vm_reset_perms(struct vm_struct *area)
>          * the vm_unmap_aliases() flush includes the direct map.
>          */
>         for (i =3D 0; i < area->nr_pages; i +=3D 1U << page_order) {
> -               unsigned long addr =3D (unsigned long)page_address(area->=
pages[i]);
> +               unsigned long addr =3D (unsigned long)kasan_reset_tag(pag=
e_address(area->pages[i]));

Ditto

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DV4jVyS41MDxJeN-A2zk6WhTnxp7m3FRWmkXMpy5f%2BhaA%40mail.gmail.com.
