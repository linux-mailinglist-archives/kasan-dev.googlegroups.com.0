Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBKXH63VAKGQENCGX6KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id DE15F9864F
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Aug 2019 23:12:11 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id x28sf3553976qki.21
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Aug 2019 14:12:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566421931; cv=pass;
        d=google.com; s=arc-20160816;
        b=sugY6oE8zvPzbVbdWvgAu8CbzHaGo1yHn0EyoRAMjTXpFzmjPvmYPjddCqhCm1y6Ak
         m6uRciElIZYpMfT4/A57zFZLRFkpGKKNR8Uqw8AAGND7xu3dlEcqvWjpUtHxRidXi1sE
         ZVvLhhjSI6pZ52Quk+fkGqAe4SoSki8Kj2Iam7LAMAp8MuBvOF61ladB8lTpqM6FRj4s
         VQTvENd1B2mX4DFIZjVaunB0V9tdZstT1WjIPuDI/fr/PuTtjggNRnncDoaT9sArxZrz
         /+c3PZ7i8hncHBMZ4dY3GLp9u4dRc0XMrEeGTfidty7j+qGxJDHtqz9w6liXBsk2UPYR
         BAyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:date:cc:to:from:subject
         :message-id:sender:dkim-signature;
        bh=AKChQNIgoEurGw6afTqmCq+EC/tLagbkyQNia2yRyrE=;
        b=WFpsEUbvx7OW5kJs8yLP+TGGIYS1HCZ9xh53c0eOufXDz8JWcBfAmViubKlDN1qTv/
         yn4c54U665ADwmF+mC3Wq4BzkGuJQGkqwX14tkI4p6JAE1/0Ecv+A+hC9e1rvDYvzSgS
         jHtQxKLmFs2QtciXlXROCq0wACaw9bA0gg/LN2HYwqBuXZZejBkBcQco0KDtI9zPnbyy
         V4HWBBMmxojbeoiacXdyFlGRLu8DSb0UVWq5D52p4Ko6TrfjGxg7OhcClFUtfj3s1cl5
         yJr6HMa0BOy+0p6Ggpsek20iSAZHk4WHX6HX89BqohV/V6SHFge0akwSjAFNodEnJff+
         QVcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=jWiovE0W;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AKChQNIgoEurGw6afTqmCq+EC/tLagbkyQNia2yRyrE=;
        b=jbUeTwFcOv3CAPymaQusy8HvebX+BWf0ERNcAfqDCucsbtOPATm8umgWHh8pTE0/yH
         rbKMoB9m4g64gkOznlJj0BePap3ANK1PyV91d+hpRqVL3LO+xAZV3BXxqFLPmSSXbCxd
         tpPhX9LUpmqWsVvUV7ckB2bfog8jSYhl7iMlYqViBGPSqvYbBRheCfxneIWrPf0wAB/7
         xR31qPhWKaimFPOiCzxmNV98DkoWQbdVvqEiNmjnsm6f4JwWLwsIKiT6ngx9rbKimOdw
         eOF0g+ZGnm6qqJkFa3eN3+Waih+QTzce2VCICJjbLnWxPsWALNRGgAxE8uZZyKd6RkKQ
         KOvQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AKChQNIgoEurGw6afTqmCq+EC/tLagbkyQNia2yRyrE=;
        b=DsUd5/gBFW10bo5hbEq9Wm3SVWSCuONegx4g4lKQmYnBrZ7R1n19lbYgzPvqfaWY5H
         muJzx8YxoZge0zHCIDXp184tri8U/ZGKxZNltuCVWcfZRQh2mSEJedi/kJvtZes+xwEF
         b2zSdY4iQISvHqHA/9IAbS/RnsA8qHZrhXBo7quILFEw7zGUF9DRcJDnsGt8LKKpwtbZ
         gb9sq85GgudR+8HycXfOeocdo962JQlxgNBnPaY6MOGcXgqjeMAjDneoGs8gE+ZRQDbq
         HSZdgwKZH2el716wqM1SgCmoY1PrH7lGywPJFVF/jTfrxegystye6jRymQU0PEaS9Tfb
         KJqA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWWcR1YgyFNiyEKAm6gTwurW/bdkiItQTDZ2Wlpy5CSDseVlPnS
	LoL0fsCbqcPa5ycNhcRghm4=
X-Google-Smtp-Source: APXvYqyTCGx7gcpfQueg+l5ZCurR+ePS3g6wQU4x0sfu4LiPV1HlXh3U990pRdhHD+eRtugNdQEKPA==
X-Received: by 2002:ae9:ec0d:: with SMTP id h13mr3815283qkg.407.1566421930932;
        Wed, 21 Aug 2019 14:12:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:8b44:: with SMTP id n65ls1088988qkd.16.gmail; Wed, 21
 Aug 2019 14:12:10 -0700 (PDT)
X-Received: by 2002:a37:afc6:: with SMTP id y189mr34044943qke.7.1566421930638;
        Wed, 21 Aug 2019 14:12:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566421930; cv=none;
        d=google.com; s=arc-20160816;
        b=cc6PAyHeHrj2lUEIkv2yzjS0ZHf/SLm76Yfgyo2k6LKOa7PMgD5UVudb9fcoxLU4KB
         2l5ytWRAMCPApqtu4SdqJprmj3WP9kr6mJNln2+pXkw+I7AljdoJu8Wy7CST6Ardtvif
         u/4CJ5xzFNUPE3n2K4BEF8b+5e8HlFo/TEI+OIFj+DkpZvjVFHcUXwrr0yeOAAzKNb0I
         IgnflpiGJrlkiiM4RWlZz/lSFOKrGGIpTgPgUqB5gMxKBQj9lK/mEp2yEPjSXJvpwAFu
         VSqkQnPdgrujA81XuWoaj0gIlgFKVfEfiZcK4GIszvCAUC7BTeGNiaBG41vcT0V3FUsZ
         JeJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=wKfoGD8n1EExPN/R416sVnt2YzIc0+Wi95CWXfv+Qwc=;
        b=VUDlqIM1O2hB3yQ8uaUYXKRM+B+R0kL4KqAAIpEE70yTNOWJYmFllZPZZRyOpNp1af
         I57ahAgMA6D8yqGL47XauOFetuukh7c4Vc1XuzOlKSAFg6rO0N/SyeuzNbQQrr2l8/Iz
         fC9N9b5sddiRsYVw4bY/aOrAMq8gxW11ucf3pTM3/VOBd4b9WLq12BofN85EyXUDfmm8
         OITyY1cDP9TnrBnoigH0pehgC3eOYz8q5ryqQqsHgOipwgyZJKAaGRN5G6Ba2gxRiDvD
         b5s+CF2IcckIk3Eiu+f6+JTb8dJhpovd4A9JvPfHewa3EjsFgbxgomqgVyysScud/LNF
         ZECQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=jWiovE0W;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id a26si743099qtp.3.2019.08.21.14.12.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Aug 2019 14:12:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id m10so3200876qkk.1
        for <kasan-dev@googlegroups.com>; Wed, 21 Aug 2019 14:12:10 -0700 (PDT)
X-Received: by 2002:ae9:ef06:: with SMTP id d6mr33003385qkg.157.1566421930297;
        Wed, 21 Aug 2019 14:12:10 -0700 (PDT)
Received: from dhcp-41-57.bos.redhat.com (nat-pool-bos-t.redhat.com. [66.187.233.206])
        by smtp.gmail.com with ESMTPSA id z22sm5710821qti.1.2019.08.21.14.12.08
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Aug 2019 14:12:09 -0700 (PDT)
Message-ID: <1566421927.5576.3.camel@lca.pw>
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
From: Qian Cai <cai@lca.pw>
To: Dan Williams <dan.j.williams@intel.com>
Cc: Linux MM <linux-mm@kvack.org>, linux-nvdimm <linux-nvdimm@lists.01.org>,
  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, kasan-dev@googlegroups.com,  Baoquan He
 <bhe@redhat.com>, Dave Jiang <dave.jiang@intel.com>, Thomas Gleixner
 <tglx@linutronix.de>
Date: Wed, 21 Aug 2019 17:12:07 -0400
In-Reply-To: <0AC959D7-5BCB-4A81-BBDC-990E9826EB45@lca.pw>
References: <1565991345.8572.28.camel@lca.pw>
	 <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
	 <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw>
	 <CAPcyv4h9Y7wSdF+jnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA@mail.gmail.com>
	 <E7A04694-504D-4FB3-9864-03C2CBA3898E@lca.pw>
	 <CAPcyv4gofF-Xf0KTLH4EUkxuXdRO3ha-w+GoxgmiW7gOdS2nXQ@mail.gmail.com>
	 <0AC959D7-5BCB-4A81-BBDC-990E9826EB45@lca.pw>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.22.6 (3.22.6-10.el7)
Mime-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=jWiovE0W;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::742 as
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

On Sat, 2019-08-17 at 23:25 -0400, Qian Cai wrote:
> > On Aug 17, 2019, at 12:59 PM, Dan Williams <dan.j.williams@intel.com> w=
rote:
> >=20
> > On Sat, Aug 17, 2019 at 4:13 AM Qian Cai <cai@lca.pw> wrote:
> > >=20
> > >=20
> > >=20
> > > > On Aug 16, 2019, at 11:57 PM, Dan Williams <dan.j.williams@intel.co=
m>
> > > > wrote:
> > > >=20
> > > > On Fri, Aug 16, 2019 at 8:34 PM Qian Cai <cai@lca.pw> wrote:
> > > > >=20
> > > > >=20
> > > > >=20
> > > > > > On Aug 16, 2019, at 5:48 PM, Dan Williams <dan.j.williams@intel=
.com>
> > > > > > wrote:
> > > > > >=20
> > > > > > On Fri, Aug 16, 2019 at 2:36 PM Qian Cai <cai@lca.pw> wrote:
> > > > > > >=20
> > > > > > > Every so often recently, booting Intel CPU server on linux-ne=
xt
> > > > > > > triggers this
> > > > > > > warning. Trying to figure out if=C2=A0=C2=A0the commit 7cc786=
7fb061
> > > > > > > ("mm/devm_memremap_pages: enable sub-section remap") is the
> > > > > > > culprit here.
> > > > > > >=20
> > > > > > > # ./scripts/faddr2line vmlinux devm_memremap_pages+0x894/0xc7=
0
> > > > > > > devm_memremap_pages+0x894/0xc70:
> > > > > > > devm_memremap_pages at mm/memremap.c:307
> > > > > >=20
> > > > > > Previously the forced section alignment in devm_memremap_pages(=
)
> > > > > > would
> > > > > > cause the implementation to never violate the
> > > > > > KASAN_SHADOW_SCALE_SIZE
> > > > > > (12K on x86) constraint.
> > > > > >=20
> > > > > > Can you provide a dump of /proc/iomem? I'm curious what resourc=
e is
> > > > > > triggering such a small alignment granularity.
> > > > >=20
> > > > > This is with memmap=3D4G!4G ,
> > > > >=20
> > > > > # cat /proc/iomem
> > > >=20
> > > > [..]
> > > > > 100000000-155dfffff : Persistent Memory (legacy)
> > > > > 100000000-155dfffff : namespace0.0
> > > > > 155e00000-15982bfff : System RAM
> > > > > 155e00000-156a00fa0 : Kernel code
> > > > > 156a00fa1-15765d67f : Kernel data
> > > > > 157837000-1597fffff : Kernel bss
> > > > > 15982c000-1ffffffff : Persistent Memory (legacy)
> > > > > 200000000-87fffffff : System RAM
> > > >=20
> > > > Ok, looks like 4G is bad choice to land the pmem emulation on this
> > > > system because it collides with where the kernel is deployed and ge=
ts
> > > > broken into tiny pieces that violate kasan's. This is a known probl=
em
> > > > with memmap=3D. You need to pick an memory range that does not coll=
ide
> > > > with anything else. See:
> > > >=20
> > > > =C2=A0 https://nvdimm.wiki.kernel.org/how_to_choose_the_correct_mem=
map_kernel
> > > > _parameter_for_pmem_on_your_system
> > > >=20
> > > > ...for more info.
> > >=20
> > > Well, it seems I did exactly follow the information in that link,
> > >=20
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-provided physical RAM map:
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x0000000000000000=
-0x0000000000093fff]
> > > usable
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x0000000000094000=
-0x000000000009ffff]
> > > reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x00000000000e0000=
-0x00000000000fffff]
> > > reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x0000000000100000=
-0x000000005a7a0fff]
> > > usable
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x000000005a7a1000=
-0x000000005b5e0fff]
> > > reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x000000005b5e1000=
-0x00000000790fefff]
> > > usable
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x00000000790ff000=
-0x00000000791fefff]
> > > reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x00000000791ff000=
-0x000000007b5fefff] ACPI
> > > NVS
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x000000007b5ff000=
-0x000000007b7fefff] ACPI
> > > data
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x000000007b7ff000=
-0x000000007b7fffff]
> > > usable
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x000000007b800000=
-0x000000008fffffff]
> > > reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x00000000ff800000=
-0x00000000ffffffff]
> > > reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] BIOS-e820: [mem 0x0000000100000000=
-0x000000087fffffff]
> > > usable
> > >=20
> > > Where 4G is good. Then,
> > >=20
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user-defined physical RAM map:
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x0000000000000000-0x00=
00000000093fff] usable
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x0000000000094000-0x00=
0000000009ffff] reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x00000000000e0000-0x00=
000000000fffff] reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x0000000000100000-0x00=
0000005a7a0fff] usable
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x000000005a7a1000-0x00=
0000005b5e0fff] reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x000000005b5e1000-0x00=
000000790fefff] usable
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x00000000790ff000-0x00=
000000791fefff] reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x00000000791ff000-0x00=
0000007b5fefff] ACPI NVS
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x000000007b5ff000-0x00=
0000007b7fefff] ACPI data
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x000000007b7ff000-0x00=
0000007b7fffff] usable
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x000000007b800000-0x00=
0000008fffffff] reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x00000000ff800000-0x00=
000000ffffffff] reserved
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x0000000100000000-0x00=
000001ffffffff]
> > > persistent (type 12)
> > > [=C2=A0=C2=A0=C2=A0=C2=A00.000000] user: [mem 0x0000000200000000-0x00=
0000087fffffff] usable
> > >=20
> > > The doc did mention that =E2=80=9CThere seems to be an issue with CON=
FIG_KSAN at
> > > the moment however.=E2=80=9D
> > > without more detail though.
> >=20
> > Does disabling CONFIG_RANDOMIZE_BASE help? Maybe that workaround has
> > regressed. Effectively we need to find what is causing the kernel to
> > sometimes be placed in the middle of a custom reserved memmap=3D range.
>=20
> Yes, disabling KASLR works good so far. Assuming the workaround, i.e.,
> f28442497b5c
> (=E2=80=9Cx86/boot: Fix KASLR and memmap=3D collision=E2=80=9D) is correc=
t.
>=20
> The only other commit that might regress it from my research so far is,
>=20
> d52e7d5a952c ("x86/KASLR: Parse all 'memmap=3D' boot option entries=E2=80=
=9D)
>=20

It turns out that the origin commit f28442497b5c (=E2=80=9Cx86/boot: Fix KA=
SLR and
memmap=3D collision=E2=80=9D) has a bug that is unable to handle "memmap=3D=
" in
CONFIG_CMDLINE instead of a parameter in bootloader because when it (as wel=
l as
the commit d52e7d5a952c) calls get_cmd_line_ptr() in order to run
mem_avoid_memmap(), "boot_params" has no knowledge of CONFIG_CMDLINE. Only =
later
in setup_arch(), the kernel will deal with parameters over there.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/1566421927.5576.3.camel%40lca.pw.
