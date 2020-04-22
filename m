Return-Path: <kasan-dev+bncBCD3NZ4T2IKRB4M4QL2QKGQE4HH5OAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 472F01B4CB6
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 20:35:31 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id a6sf2813777pfg.18
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 11:35:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587580530; cv=pass;
        d=google.com; s=arc-20160816;
        b=C1Z6gu7Qo2dynBWYVm7Tamn3o0nuJXhrDdrQf+zzM0jbUFXFdE0loB7IHiuvhIzJlG
         oWedhMgmkgCeHuLeoMLL3vWYuJEd+37UPIrkzObjfSLqOSkvE4DGTkSDBTTznU57RmiY
         maOUYgdpXFcrT5Spw9Ugs8te//0Yw6EspFZK6qDbuhrx0UH/KW3/K/5yPb0tYlhGJCIX
         rVy7JfL4uND5KJZiYaW2uFyVAAsAlAxCaw0VMokjYH6L0gXidySHiBPH7GWSWJno+uLg
         S/lPTlAFoJvPKQUNhV5YlImmr1ciGt2eo6X/mIsw9slvk+Yb/9buGDgvPvl8GFh21OY+
         jAdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=/2Qxv7C1CmCfI2mCmdjSarXa7R8BRb6rSFXcBaT0lps=;
        b=yfI549kB00yERcLkofZZVRHHsMflT35UgykWQENBzymDRJjBnVhXCsQKxslZna78V+
         SEpv93CDAueIER4yzVv88kx3qrvXGXKwTZ5M/8bnBzQHgE+iaKMyiFl85S8c/XwKUXi9
         3GEwB/fQypNcBb+bz9XbRekOvezbcLqKCxxI5LSg0+nnw4BpI748k/tTww+ea5hrUpCF
         3M4IbAzcmixoXHNVgocfjxevXTQBkZiQ5QhNK4DnY73dEoC5MrGRCEPBthyvbhjF/zQC
         i79BXcSthmHBxvPwHstEVBC7ldjnQJfgN2W0AG8xTcC2ezzRYdXPbkDLhX3IdZ/3DSxn
         A4+g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=KaI0znSO;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/2Qxv7C1CmCfI2mCmdjSarXa7R8BRb6rSFXcBaT0lps=;
        b=OpgYuFw59plRBk9JZKd7sUfjNQgleBoTZAQtX0sB5Qa+uctauT2yRwGMfuONgzuqUv
         S7yt7fTgBfrhfrJS9g20XEWfChXsqYoQ/FnPBbX3Yzkn7ojT7wYmNoOKLJpGLVWMwhLI
         OmDTbcr7OjdJaVgfjpJ/3gZQgGl5yRzS/Zq6Y57TcwXQ/JWKA+9fulu3GSHM2mCs7lgS
         O/vQcs4k3z7l9RefKPczaj+TT1cH5VO/OHVhBRNw8fE0GgVK8FM2lmc/Da3icQrCgRyz
         7zxu/8sgImuGF+X6o8fJOma8xRuBbvcxPiDX9p819MAk70k4ElMgQXL/MBJekrLzaO+x
         NAUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/2Qxv7C1CmCfI2mCmdjSarXa7R8BRb6rSFXcBaT0lps=;
        b=UJlCfkMpLSL9SuUqud4PE5ZMurVV+JEHo1oeI1YDzA+t+SNBnwOvtzzmidFl5HZ+gQ
         STIUrJDYXbpp3MXfm3G0DiEehAbGkU9c2bxMRO8xCVPJorQFJ/VeLEYN7XV2/lEhLZB9
         22VOX5qdvmuN8cey1VWKkPQKabcrWTPesU3MgkGHpidvQT0JGsRicK/D9uQ9jKKe1aVf
         sIa2X9faDRgGbF/7rCc9PIR63t02w2WwcOGRKMX5LEkKtHs3QMtp77zM0Uxz4XppaNCl
         +mxElEIAvKC9y1jn3erPI2+yxaszoVJy8j3iUgJpoktt7rLDnRUbnxLL8zz0hDmoZh/A
         YZtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYy71KIw74CKodg3JHpaQNpscg4bBt9jIgAz/hHWyehaFT9GbTM
	hHDnRsA7bdyAceJAlNt0A1U=
X-Google-Smtp-Source: APiQypJleAPjDDjKZa5m9leL1u5hEBDDTtQpnAhFNvJV+i6ZfkwGhhwJT0R1UNVZAUyROyf5bPHvhw==
X-Received: by 2002:a17:902:ba89:: with SMTP id k9mr27517708pls.199.1587580529981;
        Wed, 22 Apr 2020 11:35:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7b5c:: with SMTP id k28ls1625499pgn.4.gmail; Wed, 22 Apr
 2020 11:35:29 -0700 (PDT)
X-Received: by 2002:a62:1452:: with SMTP id 79mr2849497pfu.108.1587580529494;
        Wed, 22 Apr 2020 11:35:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587580529; cv=none;
        d=google.com; s=arc-20160816;
        b=NsenU7AdInnxkS1a4AbkDY8xDzwWD9ZgDGUJkke1Scefy05zOnctFS1om+elXSi0kj
         +wfhU2p3WpNXxRs9Bv5/exjTPCJuTOVAhov+e6UZqaatOIAMTlOSmtgRu9Z8iIEgkl8a
         G6a9ba/cs4U52+ftI8yOkcVujThn5BgeLoWcX04sB0Cr8bCdzSrdkCaDG/dPt7Ff4tBI
         ulxyPQkun+mKYPAxP09W6Ud1CPySHaVxJQpa++Ah32z9n6FJ2eZ6N68ncUV2jXn4Kfyv
         PlCriWXAE3vs+m+kOKmPp639vR3vCPa3Z5Q1mbqYCdgSKQFxT6lgA9JA3fqqU5Qrlj9C
         ayRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=KFMe5jf+SqPXjS3cNqNcR09qpXqrclNV90ZAafesRSo=;
        b=LiWr4jAgTgk6BNF01QDJcX2riqNarEoPa/rO3aUjbGVnKTVv/FXAnhnW4x8DQhG7R8
         Utn7GoBqLS/5YVaL2NaSepLujzwCUbUmRDX5T4eXpNo4VpzCcSEWWUTuO3qpFA16/Gcc
         vnyePPrMS9ItqI/MQzcXojd0IlAJR98o/8GgZ23uMUTK4iwmyeaKy2NylyIwATY7CyeN
         P8rzqi7lhXpu7AUEEI4MghKNMTAfKCawd59pLhk4GBPqwiSzmTonTAQ5TOU2Kwqedips
         YsprvU0UZUaxl4qZYXRCPWbrrjZrr2USEkKPaaPYUKlNvRWZGDKLkVSEUcciallRUHgK
         4AKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=KaI0znSO;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id a13si5725pjv.2.2020.04.22.11.35.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Apr 2020 11:35:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id 92so2574457qtg.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Apr 2020 11:35:29 -0700 (PDT)
X-Received: by 2002:ac8:35e2:: with SMTP id l31mr28306687qtb.104.1587580528321;
        Wed, 22 Apr 2020 11:35:28 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id x55sm33045qtk.3.2020.04.22.11.35.27
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 11:35:27 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20200422170116.GA28345@lst.de>
Date: Wed, 22 Apr 2020 14:35:26 -0400
Cc: Borislav Petkov <bp@suse.de>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>,
 x86 <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Content-Transfer-Encoding: quoted-printable
Message-Id: <10D18276-0485-4368-BFDE-4EC13E42AE22@lca.pw>
References: <1ED37D02-125F-4919-861A-371981581D9E@lca.pw>
 <20200422170116.GA28345@lst.de>
To: Christoph Hellwig <hch@lst.de>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=KaI0znSO;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 22, 2020, at 1:01 PM, Christoph Hellwig <hch@lst.de> wrote:
>=20
> On Wed, Apr 22, 2020 at 11:55:54AM -0400, Qian Cai wrote:
>> Reverted the linux-next commit and its dependency,
>>=20
>> a85573f7e741 ("x86/mm: Unexport __cachemode2pte_tbl=E2=80=9D)
>> 9e294786c89a (=E2=80=9Cx86/mm: Cleanup pgprot_4k_2_large() and pgprot_la=
rge_2_4k()=E2=80=9D)
>>=20
>> fixed crashes or hard reset on AMD machines during boot that have been f=
lagged by
>> KASAN in different forms indicating some sort of memory corruption with =
this config,
>=20
> Interesting.  Your config seems to boot fine in my VM until the point
> where the lack of virtio-blk support stops it from mounting the root
> file system.
>=20
> Looking at the patch I found one bug, although that should not affect
> your config (it should use the pgprotval_t type), and one difference
> that could affect code generation, although I prefer the new version
> (use of __pgprot vs a local variable + pgprot_val()).
>=20
> Two patches attached, can you try them?
> <0001-x86-Use-pgprotval_t-in-protval_4k_2_large-and-pgprot.patch><0002-fo=
o.patch>

Yes, but both patches do not help here. This time flagged by UBSAN,

static void dump_pagetable(unsigned long address)
{
        pgd_t *base =3D __va(read_cr3_pa());
        pgd_t *pgd =3D base + pgd_index(address); <=E2=80=94=E2=80=94 shift=
-out-of-bounds here

[    4.452663][    T0] ACPI: LAPIC_NMI (acpi_id[0x73] high level lint[0x1])
[    4.459391][    T0] ACPI: LAPIC_NMI (acpi_id[0x74] high level lint[0x1])
[    4.466115][    T0] ACPI: LAPIC_NMI (acpi_id[0x75] high level lint[0x1])
[    4.472842][    T0] ACPI: LAPIC_NMI (acpi_id[0x76] high level lint[0x1])
[    4.479567][    T0] ACPI: LAPIC_NMI (acpi_id[0x77] high level lint[0x1])
[    4.486294][    T0] ACPI: LAPIC_NMI (acpi_id[0x78] high level lint[0x1])
[    4.493021][    T0] ACPI: LAPIC_NMI (acpi_id[0x79] high level lint[0x1])
[    4.499745][    T0] ACPI: LAPIC_NMI (acpi_id[0x7a] high level lint[0x1])
[    4.506471][    T0] ACPI: LAPIC_NMI (acpi_id[0x7b] high level liad acces=
s in kernel mode
[    4.901030][    T0] #PF: error_code(0x0000) - not-present page
[    4.906884][    T0] BUG: unable to handle page fault for address: ffffed=
11509c29da
[    4.914483][    T0] #PF: supervisor read access in kernel mode
[    4.920334][    T0] #PF: error_code(0x0000) - not-present page
[    4.926189][    T0] BUG: unable to handle page fault for address: ffffed=
11509c29da
[    4.933786][    T0] #PF: supervisor read access in kernel mode
[    4.939640][    T0] #PF: error_code(0x0000) - not-present page
[    4.945492][    T0] BUG: unable to handle page fault for address: ffffed=
11509c29da
[    4.953091][    T0] #PF: supervisor read access in kernel mode
[    4.958943][    T0] #PF: error_code(0x0000) - not-present page
[    4.964797][    T0] BUG: unable to handle page fault for address: ffffed=
11509c29da
[    4.972395][    T0] #PF: supervisor read access in kernel mode
[    4.978247][    T0] #PF: error_code(0x0000) - not-present page
[    4.984102][    T0] BUG: unable to handle page fault for address: ffffed=
11509c29da
[    4.9917age fault for address: ffffed11509c29da
[    5.481007][    T0] #PF: supervisor read access in kernel mode
[    5.486862][    T0] #PF: error_code(0x0000) - not-present page
[    5.492713][    T0] BUG: unable to handle page fault for address: ffffed=
11509c29da
[    5.500314][    T0] #PF: supervisor read access in kernel mode
[    5.506165][    T0] #PF: error_code(0x0000) - not-present page
[    5.512020][    T0] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.521193][    T0] UBSAN: shift-out-of-bounds in arch/x86/mm/fault.c:45=
0:22
[    5.528268][    T0] shift exponent 4294967295 is too large for 64-bit ty=
pe 'long unsigned int'
[    5.536916][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G    B         =
    5.7.0-rc2-next-20200422+ #10
[    5.546434][    T0] Hardware name: HPE ProLiant DL385 Gen10/ProLiant DL3=
85 Gen10, BIOS A40 07/10/2019
[    5.555692][    T0] Call Trace:
[    5.558837][    T0] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
[    5.568012][T0] BUG: unable to handle page fault for address: 0000000a2b=
84dda8
[    5.961699][    T0] #PF: supervisor read access in kernel mode
[    5.967550][    T0] #PF: error_code(0x0000) - not-present page
[    5.973405][    T0] BUG: unable to handle page fault for address: 000000=
0a2b84dda8
[    5.981005][    T0] #PF: supervisor read access in kernel mode
[    5.986856][    T0] #PF: error_code(0x0000) - not-present page
[    5.992708][    T0] BUG: unable to handle page fault for address: 000000=
0a2b84dda8
[    6.000308][    T0] #PF: supervisor read access in kernel mode
[    6.006159][    T0] #PF: error_code(0x0000) - not-present page
[    6.012013][    T0] BUG: unable to handle page fault for address: 000000=
0a2b84dda8
[    6.019612][    T0] #PF: supervisor read access in kernel mode

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/10D18276-0485-4368-BFDE-4EC13E42AE22%40lca.pw.
