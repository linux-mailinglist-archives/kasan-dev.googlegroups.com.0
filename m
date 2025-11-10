Return-Path: <kasan-dev+bncBCCMH5WKTMGRBTGDZDEAMGQEU6NYURA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x537.google.com (mail-pg1-x537.google.com [IPv6:2607:f8b0:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id BE7CAC4859D
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 18:33:02 +0100 (CET)
Received: by mail-pg1-x537.google.com with SMTP id 41be03b00d2f7-b9b9e8b0812sf7733572a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Nov 2025 09:33:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762795981; cv=pass;
        d=google.com; s=arc-20240605;
        b=RuNl0PG9jGMndIUMrU+IgE/i+AaS+GZCbWxHQRgNPnHgqW9xhWfZiN2L4vffEmRlGl
         cLJdWoqRI7vLlUu+Ak8otXvSlU4pIhxbfqly0fEUAtIUAJfQZPUhfQvd7A/DBMN2a/dg
         DHBl+dFUxfVh2W4wfW3WUY05qoYXPiHOhDw83UC7EsIswdzEkLbttuS5dQFL/l//H+k+
         ZZ9E2sgJK1fy/S4JG6MkjQa5QCEWowJJ5lty1zqswJ1lKOD1A8bkwYjOZjsKOwPLQiQJ
         C7ajTwx0MvmuNfQ4Q9dyeiZbTL5r9BmVK/6uFFbkmG9u2aP6f0HdEO+yawXgNSn3F+Rw
         mqrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k7t4cB44QSSQ3l9//izclMVR18p7okhFwVRWDIlLTiw=;
        fh=baOn/G2VJxQWSg+oAfJRTlPco0q4PoNsq2CT4xG81ao=;
        b=gv1YK/SIHaGjeF90m5GdeL0V7x+rJX9XKsuQwxoZ3g8+6q97HMutiwRHTAipa5QogT
         93s8CJmEe2rSd1HfaiAYEaBahmxo/G9MCSKUEm5oThzQ/q+Ss8K9AS/bX/PLzUihNsXh
         /8/NgxNNHgjTL9eRxjQJZcHKEmFoRyoHND63FTiTNIC+Uh/GnttCuPnGMXVFcB0xpCz6
         kAoqCjWbPiqy/1ajU+0Qb1jbA/ezoeNjpRITFMQipVviWGn+DH/4KACQnDoqUcEBkXad
         Z8IGBjRzGJ2wboyMzxWOltcrjhOUfJJ4fCVc0yGxAc4Kyv0SLsqInifV6AXCjJD22jBe
         eChw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hIFVHSd+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762795981; x=1763400781; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k7t4cB44QSSQ3l9//izclMVR18p7okhFwVRWDIlLTiw=;
        b=eBwzPp3otyjiKmJtaqhVNHXP/ugboXS69EeVApKpza1xkdCQGLiHxd8+PC5zC7jLPr
         R5/RAvfLO8UN4REctcf5ywcD+GQdOgZ0J/dJgnoQEbDLZSdQha0ttpXeIVtShyfd7V6D
         UzrLcWQsh+4uRABi5hZiEWvVljVTsY2WFr59HJzrNhmpl0FSItn5hCgRMEYlYRZWlZ1M
         Ak61Pb9XLgCzskxsZxCy/bJPu2wPNqzOWnHDybyogY6Z5jdc5qjbiCcqVmZaZk7Hqmge
         /w8L7p+W0I8G4zEKy4bX4PB8YMdJfRctPxcVEjX0KXPrD5dvm1nYClu4XOLzsYMQFbQK
         44fg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762795981; x=1763400781;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=k7t4cB44QSSQ3l9//izclMVR18p7okhFwVRWDIlLTiw=;
        b=kdcMaOxUdVtXJp8vc2j7fmECZ3B7p1crZgkExLG1MwsEasnoQKvEdcNbj1JiTuMaQO
         DKcs0lctQOS610iMTONG1aVpOfVSp4+F+UCP+ZRWapjXjLUVI6/v91f81oBGb3tcUrXz
         UMX+t87UB1NpMa1C2KsGO95FHCnAxJjplS2XCbu73e6LS9ifWBoKC7qEcCvXNcwlOCHl
         uYxYBxlftuLGy+43EQQveslLC6FIa4YOFuw+9b4B6iKOxe0DsQgTKnSyINa9JFGhUJgt
         U1mnSDw32u/WE/ngbovEsZigbe93h909JgABUogxzzKd1yC+3EoxR+sQiHry/2j/CL8L
         lAiw==
X-Forwarded-Encrypted: i=2; AJvYcCV1Wlmc6Uz3ReTA9YCWC6H7Q9Hy4TuZwdk/F3cuQr5FmxuqwSuYAuOjQXb+cdKuYv4r/IWEyg==@lfdr.de
X-Gm-Message-State: AOJu0YyZHLCVtmXanTnlFGn2UGiLL/Vyh4JWPXzj5cASY89iPVNdw4wi
	6c+SXolORc3cI46/cJWUhals9uYzYx8TqB8G690+ybVIKFMsg/CVlT4b
X-Google-Smtp-Source: AGHT+IHpouOZE8UwqC/Yeym2i2izI+1ScCu9eK3YSHLo8Js7j6HTygECRiS9rSg5UrzEdFNexAEk5g==
X-Received: by 2002:a17:903:2281:b0:295:9cb5:ae2a with SMTP id d9443c01a7336-297e53e79damr95337285ad.9.1762795981217;
        Mon, 10 Nov 2025 09:33:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZlVflFbn4DcSFOna7yJll0/HqupTYThmLqPO0pJPab1w=="
Received: by 2002:a17:903:41d1:b0:298:f12:862a with SMTP id
 d9443c01a7336-2980f128932ls16058805ad.0.-pod-prod-03-us; Mon, 10 Nov 2025
 09:32:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWw9MqzxuJdgMmhZv8gGePbKYT2T8vwc/QllfMcqE3Z9OH8t30aMBd5MdSp7rTpl68mzx+KCs2eZB8=@googlegroups.com
X-Received: by 2002:a17:902:ce10:b0:290:ac36:2ed6 with SMTP id d9443c01a7336-297e5606ed3mr114693305ad.14.1762795979645;
        Mon, 10 Nov 2025 09:32:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762795979; cv=none;
        d=google.com; s=arc-20240605;
        b=O5FhGbBoiv0deNGsUzx+cEPdDpFxLiPnhMOiwHFMAP/6EFlJVMBc+Y+EkTYAKds/1u
         siAmlAQKyfE9iTOyjV9MzlxPmVvQnAXrduF6RHppTchxkKYzPRphGf7mFNVUj/dfaO4I
         7h6RuJKXj27llwL3CN2npCQwSzo3McmqKwDNfTX9Xhn7nBA1hbje2Sa4b2kYj8itJtNW
         kLAzidcUCWySSm2CsVrudqMprGxr2707Y5r3BPxchlsDbHXynsIwlGlPv5qD1qXM1pcz
         ktI3EraJIiK+c2YRqjCXWe8kzL/HldwYdNI+ycK1eTncKitLO5uqg5ZDi54qo4YhbyVO
         +6uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=auNNYNeszcnW8UxlPsUXlu6HqCk9VFPDDrt3cDy7QDk=;
        fh=HLcD8byC7u/vvRhu6ri8odIcDBLyhF4vT3giX3QzNYU=;
        b=Vfy5jU9Jcwz3Q1RlyM00F3vZB767qHzzEVFFluYyVbURhrfsG8RKysAd7eb0rfwYrm
         h5eJgxSi25tWDtz8pbRmSAqZJ9k4waEnyM9YzwhAxPribhaOmco3NYGv6y+6H51lITwM
         iwL7FKUsNXJk7cewf3osX60yEfFJfaZmByYBuBxGcBxqFput8rjBTmQacgF71So1kaX1
         ilT1AIkxvHiR6//qd8COtAVrsuYvNPGu4velOQVhOMeuOSAQNsVZlEPSrerk+5+QRAGz
         1pLumqmRLXH0ujggvJL4nn3YpZTk+RVebIw9bjmgtBR4ZFyqSq5doMiKV3P+L34/UuF3
         p82w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=hIFVHSd+;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf34.google.com (mail-qv1-xf34.google.com. [2607:f8b0:4864:20::f34])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-298147dc082si2816335ad.7.2025.11.10.09.32.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Nov 2025 09:32:59 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as permitted sender) client-ip=2607:f8b0:4864:20::f34;
Received: by mail-qv1-xf34.google.com with SMTP id 6a1803df08f44-882360ca0e2so20145706d6.0
        for <kasan-dev@googlegroups.com>; Mon, 10 Nov 2025 09:32:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWcxP1IBR7wxhiDa/8f/wpthjK9qqhQ/+q2Cuhrag4ttpCDFHHGCXAZ3X0mSJT7Rmo6/uUG/kT1L+Q=@googlegroups.com
X-Gm-Gg: ASbGncs28W1sp8J3dEHCrmOYOGHFyaXS+Joz01jP4kXgBSqzt/oQ2b5ItHDs7S/PLN8
	JFXG+95u/R9qZ8RlpZZd+Rfk5YCoQ0RdkJXJffqGlCpI2SfReJ2LRSwxHYoGwLRF3RyKbsFBpnX
	7t4Zo9BMSv6HHBx1mEmJChVF+olGVyoBydBL9lO+XG6Pp6ypPlPpqXEyEbjD7IDA9jCjAM69m95
	MUGgdHbG//hN139XOeHpjefSBP37tcdrzVYhZrAmKU2kAXYeIl8/5YfXvtVYTBMyswwDaL1oAVg
	htnKWeF1b1q+JK8=
X-Received: by 2002:a0c:e00a:0:b0:882:4660:3724 with SMTP id
 6a1803df08f44-88246605291mr69808466d6.63.1762795978283; Mon, 10 Nov 2025
 09:32:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1761763681.git.m.wieczorretman@pm.me> <fbce40a59b0a22a5735cb6e9b95c5a45a34b23cb.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <fbce40a59b0a22a5735cb6e9b95c5a45a34b23cb.1761763681.git.m.wieczorretman@pm.me>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 10 Nov 2025 18:32:21 +0100
X-Gm-Features: AWmQ_bmUvxxbg_c-XB1Dy80QL57feg4coPRIZHNTl9ervff8Rzi8S1pGrWY59Fo
Message-ID: <CAG_fn=Wj9rB0jHKT3QKjZsPYce1JFcb1e72QBOBP52Ybs3_qgQ@mail.gmail.com>
Subject: Re: [PATCH v6 01/18] kasan: Unpoison pcpu chunks with base address tag
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
	llvm@lists.linux.dev, linux-doc@vger.kernel.org, stable@vger.kernel.org, 
	Baoquan He <bhe@redhat.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=hIFVHSd+;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f34 as
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

On Wed, Oct 29, 2025 at 8:05=E2=80=AFPM Maciej Wieczor-Retman
<m.wieczorretman@pm.me> wrote:
>
> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>
> The problem presented here is related to NUMA systems and tag-based
> KASAN modes - software and hardware ones. It can be explained in the
> following points:
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
> Refactor code by moving it into a helper in preparation for the actual
> fix.

The code in the helper function:

> +void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms)
> +{
> +       int area;
> +
> +       for (area =3D 0 ; area < nr_vms ; area++) {
> +               kasan_poison(vms[area]->addr, vms[area]->size,
> +                            arch_kasan_get_tag(vms[area]->addr), false);
> +       }
> +}

is different from what was originally called:

> -       for (area =3D 0; area < nr_vms; area++)
> -               vms[area]->addr =3D kasan_unpoison_vmalloc(vms[area]->add=
r,
> -                               vms[area]->size, KASAN_VMALLOC_PROT_NORMA=
L);
> +       kasan_unpoison_vmap_areas(vms, nr_vms);

, so the patch description is a bit misleading.

Please also ensure you fix the errors reported by kbuild test robot.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DWj9rB0jHKT3QKjZsPYce1JFcb1e72QBOBP52Ybs3_qgQ%40mail.gmail.com.
