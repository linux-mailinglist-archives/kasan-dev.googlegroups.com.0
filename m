Return-Path: <kasan-dev+bncBDXY7I6V6AMRB34D56PAMGQEDXZS6OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id D4E43687F74
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 15:00:15 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id i9-20020a0560001ac900b002bfda39265asf235029wry.13
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 06:00:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675346415; cv=pass;
        d=google.com; s=arc-20160816;
        b=bMPboEEs7vzD3Nn9kpbr0uWFEdgvSwqeLloeHsmDm1vAf3mBlQ4Jc8ZfBdm9oyuVG0
         K9/FHd1P16ErX4HD2VFpMgEAWxQdroFPtDoUTK43ZLtuBhrilSBUcjp2szGv0/Jrxc9W
         nlnrXXPfCEmsjAbn3TFhAlreo9KaKfOMxAEnFYyGEFu6PP8GYEsTKWAZjO008AOT62ot
         IX/mQZpMDRHLVvsErHwVXyLtRhJ7ykCa+HLeNvgE4uPywXgv33aljlUltOy4QhBxaA9r
         kZHJdHHoX+kp3r1POUx85KwrWzENcrrDrkEXiuF0PTr4OZYfd6Kgzk+JQPvKh0Cc9mZa
         PgpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=AJFwYaSEdcQI1c5qj2l2GydePIGeMaVWsHSlb9r3vbI=;
        b=wYUpW0wLOFbiYl+IRmhOO+2KGXUsgGMczkFDJrfjf934UlxdOA4VblnqOXigQQIEvZ
         yeOcgDz2FaAgv/39OMV0Ib5/MtDDm+nZBqhKh9s83sMnVt7ypHP87L41Wx3tUEv1YtNk
         wK95mukwvgxSX6+SIrzu0YrF8T75nB8tpooiL02Totuak5XtNvuONKmviZQNBt+YsXU9
         q6338B/SkuLkrDND4c+ciSSnb8JVseXKZxVMmVQR0XywHe9oBA9Z9d47AzshrFIuKYlO
         skrDkWhkysybnA78/x537u48ogN/nlUallMD7xo8eZNYm9wpsXBcwp759Dq7n8s/T6Uu
         jG6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=aX1rwy2Y;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AJFwYaSEdcQI1c5qj2l2GydePIGeMaVWsHSlb9r3vbI=;
        b=baurAZoEpYa8fSAHIjgwLMmisyRM3Y2z4X6Mf7OnEQz26FubkwDeVTjfgGyqos2UJQ
         wS+WI8lJ2DOMgeKXp5jEync+Q9981siPLwZ6ktWlahW8J7sxenUND8gQ5htWAhU2eDb9
         wxZo0WIfhA5mnknfURa5oLur7+XMqY1trmw/yNV5zCa9LAUI2llxXaoWmpMZOgUkNmXE
         gPcum17geE8ir42csxJr43mNfCaUflA1cqzW9IfLebcbcxTj19uuqDx+aJwxwssp4wh8
         X4Mx8rvKXLHJ7+z85mIBEaxOiMrExYVS+rWnrwkmyMF6ewkRj3LetDJJhKR/cxitALSw
         289Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AJFwYaSEdcQI1c5qj2l2GydePIGeMaVWsHSlb9r3vbI=;
        b=Xun3epB2VsS0qFu+z/45iMTZLDLxrB91eV2qRfZ440DK4Qk1BVHGlU+MLVLv7hP2nm
         UgOkQjH/FzTn/g+5+7+/ukg41USIU1bsBBRj96xYUsHST+vkzRAlB6ZDVgqtzyA5EHX8
         d/r+guavI0XVWwPtMbW2KgB56wbk1ORG1uNGWh90xeIt8KLvXNiP4FB/aCNEErag2Esa
         HzEiEG5+wJfs1NZBKQqDJ43oo5xdOm9gpDGsebctBO3ALfFAXNxrfwze0PTGgO7eoymh
         5CLHuCNRzdq61e+keGqSUWQILRPkmQcfQ8gJW9XVNINomX6iXsp3O+3G8+R+8R0vV8ip
         rUoQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXGoSY/6nE45jKhWVo2vdWGAzInylOF/afGYsvkIvq0wKIAgqAK
	9UzWFiHQ3d5/1iOsN8HKi9Q=
X-Google-Smtp-Source: AK7set+c8DIatskhGeHATYur6fuuwiMNJxoiquxZ10xGKmdy5im118En18FbBNp78amgbFMVMbxDcA==
X-Received: by 2002:a05:600c:1d8f:b0:3dd:1c47:1e3e with SMTP id p15-20020a05600c1d8f00b003dd1c471e3emr260062wms.64.1675346415424;
        Thu, 02 Feb 2023 06:00:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1f1a:b0:3cd:d7d0:14b6 with SMTP id
 bd26-20020a05600c1f1a00b003cdd7d014b6ls1074487wmb.1.-pod-control-gmail; Thu,
 02 Feb 2023 06:00:14 -0800 (PST)
X-Received: by 2002:a1c:7906:0:b0:3d3:49db:9b25 with SMTP id l6-20020a1c7906000000b003d349db9b25mr5985643wme.26.1675346414147;
        Thu, 02 Feb 2023 06:00:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675346414; cv=none;
        d=google.com; s=arc-20160816;
        b=b7vpo4OfeGS36SJKPz7Qigfk51fQtsdP0XzJdEtAHzzscpeXXj1aU9fEMXgFUVWTMH
         DlSrQhpoIsUg2QtbCyjmKhgTPz3JZdfoXaVrROnOxU3/9urtO5ZCEnBDWnMNqf3WklXB
         0d1SyX5dY+mPv7czja80mCQbMRASFLDMjRkqqVjrx7UKd9ntmZEPV2jBepG4lvnWPa/X
         6kYoPiA3on9/RJ/2FwCI4opoWdmL81++JXqjO1jsIrzuj5sfoYHKs/1rsmoRxOAki8Dj
         isBunLBC1Gsl3BZlf1ZdI8VRJxv5GCoFVSJRFHA90A4KqKNrUWYyECLsJz2EePYy1ivY
         Bskw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eMycSpSWqkLdJLuPU1kAliRBYKe3vnTJI8phLtEWdDI=;
        b=bUKCpAE1O0NtFU3jGURCFoFfEJ6j9BHeAoCpUPN5/49QSM3K1tA8XA5OCVJW+XznvQ
         I22lMCAhZBOhAMAO/nvArgDU+nuqmaXmbOhyQMtxujIyN8Wkd6K6rOxmKu3YrTuSgrE2
         0rCrIzy9FT+gXGD8vKKkkNFYbcQJcBjQXWA/15SJ7+Q40C5yre1I4aMd+ysr65K3rTpT
         D7V2ukwIj8Ruuc9vHdZeE/pV/Y5vib0XY7d97JsiSaclLeTuKO6ccKs5GqhFxbdj1UAV
         Kz1bHG5fJ/coa2kw59Px6dncB/iP39j5XSc0EmEgnAAkLIYoay2ztyJ1Er/Id19tL4Cz
         J1nQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112 header.b=aX1rwy2Y;
       spf=pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id l4-20020a7bc444000000b003da0515e72csi293597wmi.2.2023.02.02.06.00.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 06:00:14 -0800 (PST)
Received-SPF: pass (google.com: domain of alexghiti@rivosinc.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id h16so1769399wrz.12
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 06:00:14 -0800 (PST)
X-Received: by 2002:adf:ffcb:0:b0:2bf:e95c:9918 with SMTP id
 x11-20020adfffcb000000b002bfe95c9918mr211434wrs.330.1675346413910; Thu, 02
 Feb 2023 06:00:13 -0800 (PST)
MIME-Version: 1.0
References: <20230125082333.1577572-3-alexghiti@rivosinc.com> <202302010819.RAsjyv6V-lkp@intel.com>
In-Reply-To: <202302010819.RAsjyv6V-lkp@intel.com>
From: Alexandre Ghiti <alexghiti@rivosinc.com>
Date: Thu, 2 Feb 2023 15:00:02 +0100
Message-ID: <CAHVXubht443DmB6qZMJ=Hyxz=xi65Dkd=PuN_2i=uf783z0B=Q@mail.gmail.com>
Subject: Re: [PATCH v3 2/6] riscv: Rework kasan population functions
To: kernel test robot <lkp@intel.com>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Ard Biesheuvel <ardb@kernel.org>, Conor Dooley <conor@kernel.org>, linux-riscv@lists.infradead.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	linux-efi@vger.kernel.org, oe-kbuild-all@lists.linux.dev
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: alexghiti@rivosinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rivosinc-com.20210112.gappssmtp.com header.s=20210112
 header.b=aX1rwy2Y;       spf=pass (google.com: domain of alexghiti@rivosinc.com
 designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=alexghiti@rivosinc.com
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

On Wed, Feb 1, 2023 at 1:16 AM kernel test robot <lkp@intel.com> wrote:
>
> Hi Alexandre,
>
> Thank you for the patch! Perhaps something to improve:
>
> [auto build test WARNING on linus/master]
> [also build test WARNING on v6.2-rc6 next-20230131]
> [If your patch is applied to the wrong git tree, kindly drop us a note.
> And when submitting patch, we suggest to use '--base' as documented in
> https://git-scm.com/docs/git-format-patch#_base_tree_information]
>
> url:    https://github.com/intel-lab-lkp/linux/commits/Alexandre-Ghiti/riscv-Split-early-and-final-KASAN-population-functions/20230125-163113
> patch link:    https://lore.kernel.org/r/20230125082333.1577572-3-alexghiti%40rivosinc.com
> patch subject: [PATCH v3 2/6] riscv: Rework kasan population functions
> config: riscv-randconfig-r006-20230201 (https://download.01.org/0day-ci/archive/20230201/202302010819.RAsjyv6V-lkp@intel.com/config)
> compiler: riscv64-linux-gcc (GCC) 12.1.0
> reproduce (this is a W=1 build):
>         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
>         chmod +x ~/bin/make.cross
>         # https://github.com/intel-lab-lkp/linux/commit/c18726e8d14edbd59ec19854b4eb06d83fff716f
>         git remote add linux-review https://github.com/intel-lab-lkp/linux
>         git fetch --no-tags linux-review Alexandre-Ghiti/riscv-Split-early-and-final-KASAN-population-functions/20230125-163113
>         git checkout c18726e8d14edbd59ec19854b4eb06d83fff716f
>         # save the config file
>         mkdir build_dir && cp config build_dir/.config
>         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-12.1.0 make.cross W=1 O=build_dir ARCH=riscv olddefconfig
>         COMPILER_INSTALL_PATH=$HOME/0day COMPILER=gcc-12.1.0 make.cross W=1 O=build_dir ARCH=riscv SHELL=/bin/bash arch/riscv/mm/
>
> If you fix the issue, kindly add following tag where applicable
> | Reported-by: kernel test robot <lkp@intel.com>
>
> All warnings (new ones prefixed by >>):
>
> >> arch/riscv/mm/kasan_init.c:442:6: warning: no previous prototype for 'create_tmp_mapping' [-Wmissing-prototypes]
>      442 | void create_tmp_mapping(void)
>          |      ^~~~~~~~~~~~~~~~~~
>
>
> vim +/create_tmp_mapping +442 arch/riscv/mm/kasan_init.c
>
>    441
>  > 442  void create_tmp_mapping(void)
>    443  {
>    444          void *ptr;
>    445          p4d_t *base_p4d;
>    446
>    447          /*
>    448           * We need to clean the early mapping: this is hard to achieve "in-place",
>    449           * so install a temporary mapping like arm64 and x86 do.
>    450           */
>    451          memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(pgd_t) * PTRS_PER_PGD);
>    452
>    453          /* Copy the last p4d since it is shared with the kernel mapping. */
>    454          if (pgtable_l5_enabled) {
>    455                  ptr = (p4d_t *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_END));
>    456                  memcpy(tmp_p4d, ptr, sizeof(p4d_t) * PTRS_PER_P4D);
>    457                  set_pgd(&tmp_pg_dir[pgd_index(KASAN_SHADOW_END)],
>    458                          pfn_pgd(PFN_DOWN(__pa(tmp_p4d)), PAGE_TABLE));
>    459                  base_p4d = tmp_p4d;
>    460          } else {
>    461                  base_p4d = (p4d_t *)tmp_pg_dir;
>    462          }
>    463
>    464          /* Copy the last pud since it is shared with the kernel mapping. */
>    465          if (pgtable_l4_enabled) {
>    466                  ptr = (pud_t *)p4d_page_vaddr(*(base_p4d + p4d_index(KASAN_SHADOW_END)));
>    467                  memcpy(tmp_pud, ptr, sizeof(pud_t) * PTRS_PER_PUD);
>    468                  set_p4d(&base_p4d[p4d_index(KASAN_SHADOW_END)],
>    469                          pfn_p4d(PFN_DOWN(__pa(tmp_pud)), PAGE_TABLE));
>    470          }
>    471  }
>    472

Ok, I have to declare this function static to quiet this warning,
there will be a v4 soon then.

>
> --
> 0-DAY CI Kernel Test Service
> https://github.com/intel/lkp-tests

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHVXubht443DmB6qZMJ%3DHyxz%3Dxi65Dkd%3DPuN_2i%3Duf783z0B%3DQ%40mail.gmail.com.
