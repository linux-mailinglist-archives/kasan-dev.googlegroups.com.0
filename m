Return-Path: <kasan-dev+bncBDPZFQ463EFRBI4B4GOQMGQEDAQYDTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 39394660373
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 16:39:17 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id h1-20020a4ad281000000b004cf6ab29266sf859521oos.2
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Jan 2023 07:39:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673019555; cv=pass;
        d=google.com; s=arc-20160816;
        b=FUxmD+w1RozJRceZmIIFgd6ERlNsC8uMJmfxYIG6MpZHKTQs4CNu+kabMXnGFFLiiT
         7sfmXl/NL7l4BQvDVxz2CNLXMnQWs3LGaSrD7OK2bJZgdCllsEVxnXQkc9WG0/8xzYTW
         tUkTBUehHVngjrXuF6ZLvwBN2YTllK7q9PH22TJlWoXornUGxxT2KkW58Gz6KsjDUjHY
         yTU+Z7iS/mn4fgmFZAJD7S15diFC30STzuPa6MkKH50EQ5L8yigOrbYIeT4is9F4hwPU
         nXMdnCP7uF1IbD+o/a0TuAtY96EoCCEiYEpBXlQ9QhLM/nRK8Vu5SCIPrUnUYf66b6jM
         zGOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=KtOJWcqUGpYHiaLWMZogSNqSE/52RDASInjBX62awEc=;
        b=vxPPwlwhfE1I41SiBZ6yAm9nt3tR8FZX5sShf6C+vg1+hLnvhNd0FsdlZBAN47jJWT
         z/l1US4xSd674X/fupktyFV2e7yOwk5Gsdr7MR4a5WV6QCpPWVMDBuVFCMkfJQy8z7g6
         /6JQG683rzAR4SUxkYgL7yzgz6YTvxMt4cwyv4iNYzRzLAQ/OB6l00/2o2IZkgP1fRws
         h6vONziavxvXr5/8YZ6NLucpo65TztQ1X7IG8EIA40ZHfnIqER+chKKrU8uQUOniZ9OW
         sOH4Alzk8hZgmcZ5SpuPAZxS+aqc4Ydvvl0n87zJxUmAI4Vy09J+5LVZ5TWaNxAAfI89
         0h9w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="kCHCa/r/";
       spf=pass (google.com: domain of alexdeucher@gmail.com designates 2001:4860:4864:20::2f as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KtOJWcqUGpYHiaLWMZogSNqSE/52RDASInjBX62awEc=;
        b=DO8q6ZwTZmV0GpOaKsVrgjIUEJsggSur0mM/5zPL5v0AUFG6fXlespWOa/vDhZSJib
         hUjNxwjj+/zKnSAZhuhlz7zI4MKsbPUqF3BLCtIwxvilBPdeszEQ87N+sw9n57FiGiHu
         IlbcY3hECj5TaDVaQfrb9fwqd+lqNDHizq4rnF16csPxSmuD2/nFvwBtnoUTyYaHfxel
         8VpX2EQJ90ySmn2So6ygQTUgwHPpiz00LD9UHy//y6hbKzX8UAtLp8bP9iBRm1Zi5w+C
         7z7utlDm+RDobJoSBeWJZC64URUc963Thbi5RQwUKEvmyaEZ1oVKC5qSakLkrFmmqZdO
         WHqw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KtOJWcqUGpYHiaLWMZogSNqSE/52RDASInjBX62awEc=;
        b=kP5oJePJKbLj5E8bc/X9Fuf6auPibl54YY2Uphw/CKqhNRQJlSvHH2BezUftnvr+bk
         5JOdZWhEwHlTCIg+gt54vLoRBheDEDCB38/R+exVER9bpr4+1cJx/TJqus7NCInNkItD
         dx0H5a/h+i5NdzoNO7DoiQTvbKo8lh0xjTK4a/VOsZL7Xypaf3rUjFcNkytsK6xQLifo
         vO8JAYdKGo9gcFAh1CLvRbl2HA2R82JFpzzK19n0YWOW0Dq0WCGknkIXGpH+rbrUb7Xb
         avOyusX19mMh6+oPs5G9Y+c8UwLk6UD78O3ZF9+mY7UCWAJ6Vu6ESZnAg+ApF/OnLfny
         N7+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=KtOJWcqUGpYHiaLWMZogSNqSE/52RDASInjBX62awEc=;
        b=CnqrmLOHFguVM7auOaMayx74Kcvq3Bx7z1tf87EiJPKuC1AzcSzLErAcvEyzRyqjGF
         bElV4JXbRSoSjyKjN7QjNJZUXGKSM1Kol6zKerRtpYQvXp8yMrKcCaVaTYfjCtHIZeWZ
         GZLsDhBJiX4KdbDItcqn/mDiYx62qxUBEuM8K9h4ZFjXTDIhbvWfcLC+6vAhDcf/3bXt
         HxGVttQYfQL3neG7b3/FMFO7XMRtCoi1FaaRC91CGQYHO9T+0YTTXuztx9PS0DZ6bYic
         UCZFN1MPS5RbNtuj3BGshVSdVFfYVaRQ2xuTFQEvxWxmPht051jYAbCzUBuvEhuhAkFq
         N6HA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2krKopiFS+0YWVy/t1UAqwpa7cBMF4xNsenQMLS/4gLCZP3xhp5q
	NXq53/OL01SsDrgYt/ZPnfk=
X-Google-Smtp-Source: AMrXdXucBcTiG5WdtdOze9CjokNs31DiFE2JhWA4uGFJGvNtn4ymagbVLtOBTE0ax+WzLY4qhhycCw==
X-Received: by 2002:a05:6870:459d:b0:143:58c3:e6c5 with SMTP id y29-20020a056870459d00b0014358c3e6c5mr5307350oao.182.1673019555565;
        Fri, 06 Jan 2023 07:39:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:503:0:b0:363:b56:297 with SMTP id 3-20020aca0503000000b003630b560297ls11052337oif.1.-pod-prod-gmail;
 Fri, 06 Jan 2023 07:39:15 -0800 (PST)
X-Received: by 2002:aca:1a18:0:b0:35e:c197:4810 with SMTP id a24-20020aca1a18000000b0035ec1974810mr23202403oia.33.1673019555185;
        Fri, 06 Jan 2023 07:39:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673019555; cv=none;
        d=google.com; s=arc-20160816;
        b=zCWhuiESQ4P+iATGQAgknGAr9dgDTTmQ4kMBwQzRpJC30fLCUb3B4zMjG3rRKZHjah
         blAC+3tRvQeQvnK9zu0pcCSCJTUf6qZe6DietVrHkD7MPNsQw+jYpYKT4KHQpHC7GqBi
         ywSLEaucb1NwLRIYlHSCF4oQtBJhXqtvAfGbRCPo0vDT27y++73tyVwNbsrMUQBaq0dI
         +LxWthvVNXHKqjOuctYpJZszUgEX8hCji+2vmXA4WWKdODrio7AP4lxuEE0qjcUvM+79
         X0dZHg9uAny68b00LkqYST/o43OGlYU1r3Xmfdo9YwzAtzGUdX2WXw8mHHtNtjhbY4Tf
         W5HQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=nOU74MfLltUT+h+F/CrT1EH2iRW8ZoWBGIJbj4ikcZg=;
        b=fPtSnU6fM9Eith56Fek7r2xNXF5EBmerq/3BoIeersh05w5XqPRnIQIIvvsbikfQEl
         H5oUiAlT2wOSysxvAAGNoLBvCNMbCuQysD+rCca984DlMofdk51hq7sg6aE19Z1SxiHj
         83/IqVFcuTRS2gR90rDSWCv5fJsKvXNhGl9jDu8RlMebLr7jAGsAxj3GQ8EcW8HfgUkO
         N+kHCEbuX1AGauIcsfL30VzMjcmslXtk6BK7rsUkfm6V1g1TT/zST7q1z5LttrCUxPjg
         Et+XWY64l4G9Td0ib8eZegt0HrHaP/e+8GhT+LFONmk9ca8u5Fuf9vIEvh6RLq5JIfcm
         tVYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="kCHCa/r/";
       spf=pass (google.com: domain of alexdeucher@gmail.com designates 2001:4860:4864:20::2f as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oa1-x2f.google.com (mail-oa1-x2f.google.com. [2001:4860:4864:20::2f])
        by gmr-mx.google.com with ESMTPS id e19-20020a544f13000000b0035c06b99516si144818oiy.3.2023.01.06.07.39.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Jan 2023 07:39:15 -0800 (PST)
Received-SPF: pass (google.com: domain of alexdeucher@gmail.com designates 2001:4860:4864:20::2f as permitted sender) client-ip=2001:4860:4864:20::2f;
Received: by mail-oa1-x2f.google.com with SMTP id 586e51a60fabf-150b06cb1aeso1847925fac.11
        for <kasan-dev@googlegroups.com>; Fri, 06 Jan 2023 07:39:15 -0800 (PST)
X-Received: by 2002:a05:6870:c59c:b0:150:d9aa:4011 with SMTP id
 ba28-20020a056870c59c00b00150d9aa4011mr1145315oab.96.1673019554943; Fri, 06
 Jan 2023 07:39:14 -0800 (PST)
MIME-Version: 1.0
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org> <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
In-Reply-To: <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
From: Alex Deucher <alexdeucher@gmail.com>
Date: Fri, 6 Jan 2023 10:39:03 -0500
Message-ID: <CADnq5_PtJ2JxAH7vaQsMHomUmiAxhiOqn4suf1SAQkaqt=sg+g@mail.gmail.com>
Subject: Re: Build regressions/improvements in v6.2-rc1
To: Geert Uytterhoeven <geert@linux-m68k.org>, "Siqueira, Rodrigo" <Rodrigo.Siqueira@amd.com>, 
	"Mahfooz, Hamza" <Hamza.Mahfooz@amd.com>
Cc: linux-kernel@vger.kernel.org, linux-xtensa@linux-xtensa.org, 
	linux-sh@vger.kernel.org, linux-wireless@vger.kernel.org, 
	linux-mips@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	linux-f2fs-devel@lists.sourceforge.net, kasan-dev@googlegroups.com, 
	linuxppc-dev@lists.ozlabs.org, linux-arm-kernel@lists.infradead.org, 
	linux-media@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexdeucher@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="kCHCa/r/";       spf=pass
 (google.com: domain of alexdeucher@gmail.com designates 2001:4860:4864:20::2f
 as permitted sender) smtp.mailfrom=alexdeucher@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Dec 27, 2022 at 10:34 AM Geert Uytterhoeven
<geert@linux-m68k.org> wrote:
>
> On Tue, 27 Dec 2022, Geert Uytterhoeven wrote:
> > Below is the list of build error/warning regressions/improvements in
> > v6.2-rc1[1] compared to v6.1[2].
> >
> > Summarized:
> >  - build errors: +11/-13
>
> amd-gfx@lists.freedesktop.org
> linux-arm-kernel@lists.infradead.org
> linux-media@vger.kernel.org
> linux-wireless@vger.kernel.org
> linux-mips@vger.kernel.org
> linux-sh@vger.kernel.org
> linux-f2fs-devel@lists.sourceforge.net
> linuxppc-dev@lists.ozlabs.org
> kasan-dev@googlegroups.com
> linux-xtensa@linux-xtensa.org
>
>    + /kisskb/src/drivers/gpu/drm/amd/amdgpu/../display/dc/dml/dcn31/displ=
ay_mode_vba_31.c: error: the frame size of 2224 bytes is larger than 2048 b=
ytes [-Werror=3Dframe-larger-than=3D]:  =3D> 7082:1
>    + /kisskb/src/drivers/gpu/drm/amd/amdgpu/../display/dc/dml/dcn314/disp=
lay_mode_vba_314.c: error: the frame size of 2208 bytes is larger than 2048=
 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 7127:1
>

@Siqueira, Rodrigo @Mahfooz, Hamza

Can you take a look at fixing the DML stack size here up?

Alex


> arm64-gcc5/arm64-allmodconfig
>
>    + /kisskb/src/drivers/media/platform/nxp/imx-jpeg/mxc-jpeg.c: error: a=
rray subscript 2 is above array bounds of 'u32[2]' {aka 'unsigned int[2]'} =
[-Werror=3Darray-bounds]:  =3D> 641:28
>    + /kisskb/src/drivers/media/platform/nxp/imx-jpeg/mxc-jpeg.c: error: a=
rray subscript 3 is above array bounds of 'u32[2]' {aka 'unsigned int[2]'} =
[-Werror=3Darray-bounds]:  =3D> 641:28
>
> m68k-gcc8/m68k-allmodconfig
> See also https://lore.kernel.org/all/CAMuHMdWpPX2mpqFEWjjbjsQvDBQOXyjjdpK=
nQu9qURAuVZXmMw@mail.gmail.com
>
>    + /kisskb/src/include/linux/bitfield.h: error: call to '__field_overfl=
ow' declared with attribute error: value doesn't fit into mask:  =3D> 151:3
>
> In function 'u32_encode_bits',
>      inlined from 'ieee80211_mlo_multicast_tx' at /kisskb/src/net/mac8021=
1/tx.c:4435:17,
>      inlined from 'ieee80211_subif_start_xmit' at /kisskb/src/net/mac8021=
1/tx.c:4483:3:
>
> mipsel-gcc5/mips-allmodconfig
>
>    + /kisskb/src/include/linux/compiler_types.h: error: call to '__compil=
etime_assert_262' declared with attribute error: Unsupported access size fo=
r {READ,WRITE}_ONCE().:  =3D> 358:45
>    + /kisskb/src/include/linux/compiler_types.h: error: call to '__compil=
etime_assert_263' declared with attribute error: Unsupported access size fo=
r {READ,WRITE}_ONCE().:  =3D> 358:45
>
> In function 'follow_pmd_mask',
>      inlined from 'follow_pud_mask' at /kisskb/src/mm/gup.c:735:9,
>      inlined from 'follow_p4d_mask' at /kisskb/src/mm/gup.c:752:9,
>      inlined from 'follow_page_mask' at /kisskb/src/mm/gup.c:809:9:
>
> sh4-gcc11/sh-defconfig (G=C3=BCnter wondered if pmd_t should use union)
>
>    + /kisskb/src/include/linux/fortify-string.h: error: '__builtin_memcpy=
' offset [0, 127] is out of the bounds [0, 0] [-Werror=3Darray-bounds]:  =
=3D> 57:33
>
> /kisskb/src/arch/s390/kernel/setup.c: In function 'setup_lowcore_dat_on':
> s390x-gcc11/s390-all{mod,yes}config
>
>    + /kisskb/src/include/linux/fortify-string.h: error: '__builtin_memset=
' pointer overflow between offset [28, 898293814] and size [-898293787, -1]=
 [-Werror=3Darray-bounds]:  =3D> 59:33
>
> /kisskb/src/fs/f2fs/inline.c: In function 'f2fs_move_inline_dirents':
>
> powerpc-gcc11/ppc64_book3e_allmodconfig
> powerpc-gcc11/powerpc-all{mod,yes}config
>
>    + /kisskb/src/kernel/kcsan/kcsan_test.c: error: the frame size of 1680=
 bytes is larger than 1536 bytes [-Werror=3Dframe-larger-than=3D]:  =3D> 25=
7:1
>
> xtensa-gcc11/xtensa-allmodconfig (patch available)
>
>    + {standard input}: Error: unknown pseudo-op: `.cfi_def_c':  =3D> 1718
>
> sh4-gcc11/sh-allmodconfig (ICE =3D internal compiler error)
>
> > [1] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/1b929c02afd37=
871d5afb9d498426f83432e71c2/ (all 152 configs)
> > [2] http://kisskb.ellerman.id.au/kisskb/branch/linus/head/830b3c68c1fb1=
e9176028d02ef86f3cf76aa2476/ (all 152 configs)
>
> Gr{oetje,eeting}s,
>
>                                                 Geert
>
> --
> Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m6=
8k.org
>
> In personal conversations with technical people, I call myself a hacker. =
But
> when I'm talking to journalists I just say "programmer" or something like=
 that.
>                                                             -- Linus Torv=
alds

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CADnq5_PtJ2JxAH7vaQsMHomUmiAxhiOqn4suf1SAQkaqt%3Dsg%2Bg%40mail.gm=
ail.com.
