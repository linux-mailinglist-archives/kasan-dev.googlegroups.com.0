Return-Path: <kasan-dev+bncBDXY7I6V6AMRBJNAX2PAMGQEK6RSCUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 204E1679274
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 09:00:39 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id by38-20020a05651c1a2600b0028b8260999esf3093452ljb.7
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Jan 2023 00:00:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674547238; cv=pass;
        d=google.com; s=arc-20160816;
        b=zYQdIVT+qbxXwMCsl0Qr2Oh53NVBgf2zvqR/yeNEtfPOeS0zscv9hRZb+e948lKAK1
         6jFidgErREu6FB3TQ+vxnga1xyywmxZZV1dE5z5Yc18x0dR22BUPt/2OyjI5BRxRSbGH
         ne0X+3tp6QoBj8KyR9aQathkeBSzn+FeN7DuVppShbCf26h0UW6KQ27vnAbDvYdOcCyH
         7/ub0l7B9INw8iWLg5m89/kaemuOruFWMgO4zAmVCtkdO/+rlwaIASZKOdByw0q0MtRZ
         xfpZiIuFDSzVreFVSWct0nIiWqHDy64Lven74uzYem7Cf3Gqv1zZUKWFSEObGp7aR/HI
         sdLg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=Fpn/P5H5Ep765RpY/uMyUla2IDOK0m5ho1OYgE9nMac=;
        b=kNoXO516n13dqVXfDjk6nnifcceDOsHkB6JLu8JEQ9W28ZVFnLH/dUrjIK2SzNOR5d
         PN2jPCFUNMF8lJtxTExA3Qb/p1cYldFsLL49NbyTA4iOv0kHkS130WHoFmVIaj4KOlLg
         5j3WoatdawGL9NJ5WID+JcESvlyxmeZT0kLQlrtaO+k5LMzyprsjJvCETe5eBdcPQDR5
         2gJ5Swg/DWk9rzN0q3ki+EODXOzgc8WkWHbK/Z66kfLGlNgPgbaM+IsoXAQTGX1rZ4CM
         +8Cj7I3rE6D/uxhGC1in7lQTJBd9xepV4spfMvDi04grajiI9Oc3jXASVBQFTF9SyNUr
         KDeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=b6H059p3;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Fpn/P5H5Ep765RpY/uMyUla2IDOK0m5ho1OYgE9nMac=;
        b=PdT+AQesU1o9dIplfneLehDNVpHXKTCQj61H0eSJYFs+fAu+iCc3i6IFaclXrgqyDp
         oNR3eCthSufOAPQWb7pAv8UkuXYlQpXlfrdXN654M00SIAwkNFl1XwITcKofCPmg5yX4
         lUTks97p6CxL1EsJ28L8Dp8AQ0t63cMpDTQOzp/BRc6EJ07pN8SwRivVn4zYa5/5cOeH
         GOuLq9je2bFRz0yol4eOd4U5dKjVsFNbYVSkfPxVhvT0lCyiwbys1UGXdppP6uQBxvLm
         DDWSmuGFnZhej/2ngJ/skLDDP704POZmRu8fiSdAk/phTRcNFPRZlBoJgNd1nzijOmX1
         NFmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Fpn/P5H5Ep765RpY/uMyUla2IDOK0m5ho1OYgE9nMac=;
        b=DjE4lv6sWc5Mte7VotzoMkNf+Q0N8YI/TjiZ9ipixGvikDQFDfK2X3yqTrJ2sdAd65
         hypZ+Qs+OFummowSKQp859jZpBn7whYdO/eCH/gl/NVgIO7HM6S+65W9J6D8O/hyW//K
         9J6+ou9Fjz9lSxearC0iB+BF73ch7YDRUbB04fDg4eJ6KAkDIgdo55Z37Wu82Ztt0FHA
         60nB+TZYc7iKrnkkMpzSFOX+k3VdN9HPSF78rhmvVJ/UCqhpd7uO4w6LnrAuTLcdTwT0
         HTCB3BGj9N7ttRMYZXklgw3o2Rqk7knsYVzed4qtQfUuLVrKAsqE63KjE31CT4mlbq/1
         FrPA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krPZLJXAFrRTWZH/jbP6EAx7GtQ6O98h9Umz5PudK+cNKJHzi0c
	SySkkmvts3KDcp6I2+caSv8=
X-Google-Smtp-Source: AMrXdXsk+3g7QJDJfhJSJ43vsWA690ZcFtGGN33cKK0u2dTKz0+ofssUQ60BW4IltoPCvnOfg2XXIA==
X-Received: by 2002:a2e:93c9:0:b0:28b:953f:c3d9 with SMTP id p9-20020a2e93c9000000b0028b953fc3d9mr1371568ljh.382.1674547238307;
        Tue, 24 Jan 2023 00:00:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:314c:b0:4d5:7ca1:c92f with SMTP id
 s12-20020a056512314c00b004d57ca1c92fls6289177lfi.2.-pod-prod-gmail; Tue, 24
 Jan 2023 00:00:37 -0800 (PST)
X-Received: by 2002:a05:6512:368a:b0:4b5:d:efb2 with SMTP id d10-20020a056512368a00b004b5000defb2mr5545360lfs.14.1674547236962;
        Tue, 24 Jan 2023 00:00:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674547236; cv=none;
        d=google.com; s=arc-20160816;
        b=bB0psuGPRvAzKA/oi5/CdWxJDgUvLXXRDlxMXZMEUIPmHaRusstmQLDQSe8S/T/d4u
         bIrxFYACgm7WvBxbJJ7ZVVY8i5RulXAOEtQAgupZEohA1yKu/EBQT0xhunpd15kWPE4F
         j2gxpmgFtI/tDDvr5FhQmqboIiVIrvXlcEaMKdjbSzbbd3StczIOH6EpT3J/glSxgihF
         8LqsLePAmJuR25GhE18776HkSLjb7hJUPV2yvmP4N60n3kFqFM4EcZONiU1aPi1YjDUV
         FJaAtUoFHSw7hxe7mv96NSGZwfE6v8dmLLvWFuIR+GV7Qm57ezCVZfXar36lwvBpum9i
         cujA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CqSZybdUuskI+UDVH1j93jvIbGoD0+XsFL55JSeaP+k=;
        b=D4ZOHJUy0Nj8GdNrx8cnavw/fs/Lou3/fqC2GhDgWXBEj1aG/aFQ/aBvWJWqB6oJYr
         WFycW9tUXSjmB+RPVo33X3lF9l6TM4cjASmpaS/fijretO86/MsTPSeArKRNG8jSJ+iQ
         EFZKKmBBgKrFCKzHppNFnRPyQobWIrX053dRg5IXDaE8DS05WvGLg1Nq4zVohmWzIRIa
         UU0Umqcl+WEHuyWy4eoT/l73wuyxe2UpxvU7jOnVO5wEZ7cnkJ1zvAkykIhi1f2fFrAf
         /GQOqK6cuAz2CzJ50RFVCw5Kh1ajKogZdtBgvrbgB68jUbFqJEsjPh50PJaQ8A8PY6zW
         gatg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=b6H059p3;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x435.google.com (mail-wr1-x435.google.com. [2a00:1450:4864:20::435])
        by gmr-mx.google.com with ESMTPS id x13-20020a19f60d000000b004d34d4743c0si59074lfe.2.2023.01.24.00.00.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Jan 2023 00:00:36 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::435 as permitted sender) client-ip=2a00:1450:4864:20::435;
Received: by mail-wr1-x435.google.com with SMTP id d2so12998446wrp.8
        for <kasan-dev@googlegroups.com>; Tue, 24 Jan 2023 00:00:36 -0800 (PST)
X-Received: by 2002:a5d:5190:0:b0:2bd:d6bc:e35c with SMTP id
 k16-20020a5d5190000000b002bdd6bce35cmr1218375wrv.144.1674547236441; Tue, 24
 Jan 2023 00:00:36 -0800 (PST)
MIME-Version: 1.0
References: <20230123100951.810807-1-alexghiti@rivosinc.com>
 <20230123100951.810807-2-alexghiti@rivosinc.com> <Y88HD2ocLQilIuDr@spud>
In-Reply-To: <Y88HD2ocLQilIuDr@spud>
From: Alexandre Ghiti <alexghiti@rivosinc.com>
Date: Tue, 24 Jan 2023 09:00:25 +0100
Message-ID: <CAHVXubiSJMyeuy253wyFALQ0DzDn_yuuR4HWKy9rmGYLNeXpKA@mail.gmail.com>
Subject: Re: [PATCH v2 1/6] riscv: Split early and final KASAN population functions
To: Conor Dooley <conor@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Ard Biesheuvel <ardb@kernel.org>, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=b6H059p3;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::435 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

Hi Conor,

On Mon, Jan 23, 2023 at 11:15 PM Conor Dooley <conor@kernel.org> wrote:
>
> Hey Alex,
>
> FYI this patch has a couple places with spaces used rather than tabs for
> indent.

Damn, I forgot to run checkpatch this time...

Thanks,

Alex

>
> >  static void __init kasan_populate_p4d(pgd_t *pgd,
> > -                                   unsigned long vaddr, unsigned long end,
> > -                                   bool early)
> > +                                   unsigned long vaddr, unsigned long end)
> >  {
> >       phys_addr_t phys_addr;
> >       p4d_t *p4dp, *base_p4d;
> >       unsigned long next;
> >
> > -     if (early) {
> > -             /*
> > -              * We can't use pgd_page_vaddr here as it would return a linear
> > -              * mapping address but it is not mapped yet, but when populating
> > -              * early_pg_dir, we need the physical address and when populating
> > -              * swapper_pg_dir, we need the kernel virtual address so use
> > -              * pt_ops facility.
> > -              */
> > -             base_p4d = pt_ops.get_p4d_virt(pfn_to_phys(_pgd_pfn(*pgd)));
> > -     } else {
> > -             base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
> > -             if (base_p4d == lm_alias(kasan_early_shadow_p4d)) {
> > -                     base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
> > -                     memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
> > -                             sizeof(p4d_t) * PTRS_PER_P4D);
> > -             }
> > -     }
> > +     base_p4d = (p4d_t *)pgd_page_vaddr(*pgd);
> > +     if (base_p4d == lm_alias(kasan_early_shadow_p4d)) {
> > +             base_p4d = memblock_alloc(PTRS_PER_PUD * sizeof(p4d_t), PAGE_SIZE);
> > +        memcpy(base_p4d, (void *)kasan_early_shadow_p4d,
> > +                sizeof(p4d_t) * PTRS_PER_P4D);
> > +    }
>
> ^^  here.
>
> Thanks,
> Conor.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHVXubiSJMyeuy253wyFALQ0DzDn_yuuR4HWKy9rmGYLNeXpKA%40mail.gmail.com.
