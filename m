Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJU2ZO4AMGQEUYSRSNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 778719A48AC
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 23:03:35 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e2928d9e615sf3942073276.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 14:03:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729285414; cv=pass;
        d=google.com; s=arc-20240605;
        b=XYi9Tf1xY5lQOIaDqgbZ5b6y22+C4CkhjEytqyhLIMU/xd8GO6c23Cb9gu8dciDWFb
         R2MuVxfPRk2grHcQK/F8yc+gbVsVaqOumYazVFj0hofw83OWCyIiMwNCyqqgR8799vrd
         MVcZr12UASD2M/ElsMblq4gSW4bnZP0Ub7XG2wNB7PtKNQ4qMRB8gN7dXIHOSamVYhZf
         iRfS/aurkGZyBgarD1SqQX+nBNyOMANFewOfcBrivOF7Q3mbngZ5S/CYlNzun0UZ4qXI
         GLUIi0rggAQu+aJsuKI7mlq2DlGeoUJAfu4E48LHqnnAn/QVtChdAuahDFPncbnXNGqz
         tsIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7fAUnDeqt3tf03rhO+0NV7U1D4W9vR+NEretGyHNQII=;
        fh=+q63t2Xd0Zcn4xxNrU9B2Bjzi1JlygrqoVa1F2cduHU=;
        b=Y8AmqFg1R2/M0yg0wJnYcBfbpWCVq/Lp3h7Y/AdmhKyjseC15L2CEl/UKOw7S8mpla
         5gI6PeZC/7kZRk5+HPi715nNN6twNrTV/rdrhYrA6Hr/GRXiLxJ9uXofvhYQs6o33+K5
         3MLo28Vn900ruWvyl+t6Vul5z6OygxLw+nusowTwBeOJ6mXWbi3wE3A2CD535nxarRCr
         rVzVhgyAsedd27tloH4pc3qNferEqOmsArb5HwA9ydMVXfMEhQYg+YntB25CjGa+TUJ6
         /B3ZFKvxD3qhdHHLmXMtgYRFn+NOSMFZUESzAp/KlTS5Af57YqekrctHDKaKYaPSlKOj
         wVMA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DtcRyZva;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729285414; x=1729890214; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=7fAUnDeqt3tf03rhO+0NV7U1D4W9vR+NEretGyHNQII=;
        b=ts2qZW1Rxp809atBHa61AJUBjCKs8HY5CxQEVkSWunmJvemZBeDYjFzZw2Jbsu75y8
         3FhNr5Kd2D9skUYH9EIPXP7jzucCQSiiFB1N1dIzrZscOVaP9RNKIaCeE9OqITEPRqiV
         QoetXKzE3/vxhfs2mOp8rQ7/0lOVVsC5CLacpvIiF3Q+7vyUJjMGzim7Ew2GpcxfcVlp
         CrbxEUVTfKpCSV61dritd02pQdKxLV8oXVE3IcakLxDU21qHOpqJg5SWJNant8zNNd+b
         q/hvWFq/72ycu8cgbaqrIq+np0/LTH60aLzloRsO6+5G1oGDwBtS+x1OESZCe3AYn71U
         XQOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729285414; x=1729890214;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7fAUnDeqt3tf03rhO+0NV7U1D4W9vR+NEretGyHNQII=;
        b=S078Q84IgrySNFLDv65By4MTYMK0edd4JsYCUofAcH+Vkg4KvUENTDyZ6kg8Eq2LUj
         a/AVKY4nXIdH1LmjV+Yei19NDcjJUULOhgOTSKqBwQouSCj7EYNxjy5DNXQlyJb3IboJ
         hSo+UD+K8dx0enDRRemBp0DP+jWJCOOzalJ4ZrpMGvaoGBfI9Z06OOmEvqxVbNvdHkL2
         /VA4Ketlra/LetN1kiB7yUB7/iyfVetQm4aiNncYNT5fccJsHhr6H0R6cha5gvchCHGZ
         hIHPfozwMUH2+uQvDa9yaIlB08PTAtWfOUAD1emAEfAbOfcLpExKUQKRocAPtWfwcwZ8
         dXRw==
X-Forwarded-Encrypted: i=2; AJvYcCXBTSUFXldh01Msl8wVQVxR5dJMnkudXQz2uLi5huEwQLX3jE65k0XJnCrBF9SqT217ZFP8qw==@lfdr.de
X-Gm-Message-State: AOJu0Yyhv5tVv3z7JOXHdD3kv2rfT/cHhkODBqUcxgmpUASoDnEKmP4w
	oyalptjnB5uIn2vxXcOgiuaIx0RZNRmgoaKBExgt0eIc18daqXOB
X-Google-Smtp-Source: AGHT+IEGTm0LXDE5C5wAmTC+jhDgw8YrP87xmIRukZy9oCKItCpXUlfiQ7jHuAd9zODJkGH0EzrUPQ==
X-Received: by 2002:a05:6902:2186:b0:e28:f31f:5f72 with SMTP id 3f1490d57ef6-e2bb1309f6amr3416910276.19.1729285414211;
        Fri, 18 Oct 2024 14:03:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1893:b0:e24:96b1:6ae with SMTP id
 3f1490d57ef6-e2b9cc5eff1ls2980893276.0.-pod-prod-07-us; Fri, 18 Oct 2024
 14:03:33 -0700 (PDT)
X-Received: by 2002:a05:6902:706:b0:e2b:a885:2e51 with SMTP id 3f1490d57ef6-e2bb1441274mr3954086276.34.1729285413376;
        Fri, 18 Oct 2024 14:03:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729285413; cv=none;
        d=google.com; s=arc-20240605;
        b=ZFs/gb2HYSlstXx8bkVCF2egdQR+DDu+g7u2+BBdgi6/l2dzOW8J2QK/MYZJC289Pe
         SuMxPtP7o+DZ3w0KauDui6dLtsR6rOaP61xehYIXEdOUvQYz5cksnciw8sbJmOfePS66
         U7SstbqiqQdbpP0D48hPfcv7V19hXFtJwcT6xLECcjMbjbXFCH2dipWSU1r9pXuZ0+9Q
         /8UWncZ+6I6sFxE1nTTKA02gWG8/Lf0CyOW4b7SqQXOtZczClcFssOFuKABLZ7gJqZDO
         UmUr9JZS5nuy0RD79cIAn1pDR+xOOzA1BS6o+6QdamzgHpLJ8spJm+UEqKxrMfsYHJwp
         RVOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nt+dAjhuzZ5n+ygaPAn3gZpiBolEQtWHa7Naom0sNUY=;
        fh=AC1SxOa8KpLGXCeHZJ3/L0jtg77yaUqoqfjDym9pAjs=;
        b=BpvRqbkKMCqt5V9E1Gp9zft5IOgIg27aZsJ5iwsWkItvfwbLGhhC7Tg9a2G4tZgCPy
         41Z4cTQwzquvnXxKGRqAot8buGNBrRh6/LIJ9DMblmqXQzbUFAqYMqbshR4VZxOeqHfD
         UCdAxG/v6+R8U8TlK3vURfnDrL4SeLyxP4pXygXp2P4l5UgQ8DLheTiT3N2yQ8rWQwO8
         sXv5mFnPGr7cHl7AHaitiszTkGMaibA0D3mo4ApHfhr+WRy0zBSe4+n27et5UyLnFUhZ
         ip+hiFF80WB7EkyCY2QSKRvH+KBfO/MIs0HEjkAzHceq1WJSXG2C9uhjkYp+9z1RgkD2
         hnlg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DtcRyZva;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e2bb03c241esi122347276.2.2024.10.18.14.03.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 14:03:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-2e2e88cb0bbso1895862a91.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 14:03:33 -0700 (PDT)
X-Received: by 2002:a17:90b:f87:b0:2e2:d821:1b77 with SMTP id
 98e67ed59e1d1-2e5616509b4mr4435772a91.24.1729285412125; Fri, 18 Oct 2024
 14:03:32 -0700 (PDT)
MIME-Version: 1.0
References: <210e561f7845697a32de44b643393890f180069f.1729272697.git.ritesh.list@gmail.com>
In-Reply-To: <210e561f7845697a32de44b643393890f180069f.1729272697.git.ritesh.list@gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Oct 2024 23:02:51 +0200
Message-ID: <CANpmjNPQtAMbF2BZbUVOL+Sx2+VSOwxgxzXR8yFvDBH4Euu7Ew@mail.gmail.com>
Subject: Re: [PATCH v3] mm/kfence: Add a new kunit test test_use_after_free_read_nofault()
To: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Cc: kasan-dev@googlegroups.com, linuxppc-dev@lists.ozlabs.org, 
	linux-mm@kvack.org, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Nirjhar Roy <nirjhar@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=DtcRyZva;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1033 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 18 Oct 2024 at 19:46, Ritesh Harjani (IBM)
<ritesh.list@gmail.com> wrote:
>
> From: Nirjhar Roy <nirjhar@linux.ibm.com>
>
> Faults from copy_from_kernel_nofault() needs to be handled by fixup
> table and should not be handled by kfence. Otherwise while reading
> /proc/kcore which uses copy_from_kernel_nofault(), kfence can generate
> false negatives. This can happen when /proc/kcore ends up reading an
> unmapped address from kfence pool.
>
> Let's add a testcase to cover this case.
>
> Co-developed-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
> Signed-off-by: Nirjhar Roy <nirjhar@linux.ibm.com>
> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
> ---
>
> Will be nice if we can get some feedback on this.

There was some discussion recently how sanitizers should behave around
these nofault helpers when accessing invalid memory (including freed
memory):
https://lore.kernel.org/all/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7qeeeAp_6yKjwKo8iw@mail.gmail.com/

It should be similar for KFENCE, i.e. no report should be generated.
Definitely a good thing to test.

Tested-by: Marco Elver <elver@google.com>
Reviewed-by: Marco Elver <elver@google.com>

> v2 -> v3:
> =========
> 1. Separated out this kfence kunit test from the larger powerpc+kfence+v3 series.
> 2. Dropped RFC tag
>
> [v2]: https://lore.kernel.org/linuxppc-dev/cover.1728954719.git.ritesh.list@gmail.com
> [powerpc+kfence+v3]: https://lore.kernel.org/linuxppc-dev/cover.1729271995.git.ritesh.list@gmail.com
>
>  mm/kfence/kfence_test.c | 17 +++++++++++++++++
>  1 file changed, 17 insertions(+)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 00fd17285285..f65fb182466d 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -383,6 +383,22 @@ static void test_use_after_free_read(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +static void test_use_after_free_read_nofault(struct kunit *test)
> +{
> +       const size_t size = 32;
> +       char *addr;
> +       char dst;
> +       int ret;
> +
> +       setup_test_cache(test, size, 0, NULL);
> +       addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
> +       test_free(addr);
> +       /* Use after free with *_nofault() */
> +       ret = copy_from_kernel_nofault(&dst, addr, 1);
> +       KUNIT_EXPECT_EQ(test, ret, -EFAULT);
> +       KUNIT_EXPECT_FALSE(test, report_available());
> +}
> +
>  static void test_double_free(struct kunit *test)
>  {
>         const size_t size = 32;
> @@ -780,6 +796,7 @@ static struct kunit_case kfence_test_cases[] = {
>         KFENCE_KUNIT_CASE(test_out_of_bounds_read),
>         KFENCE_KUNIT_CASE(test_out_of_bounds_write),
>         KFENCE_KUNIT_CASE(test_use_after_free_read),
> +       KFENCE_KUNIT_CASE(test_use_after_free_read_nofault),
>         KFENCE_KUNIT_CASE(test_double_free),
>         KFENCE_KUNIT_CASE(test_invalid_addr_free),
>         KFENCE_KUNIT_CASE(test_corruption),
> --
> 2.46.0
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPQtAMbF2BZbUVOL%2BSx2%2BVSOwxgxzXR8yFvDBH4Euu7Ew%40mail.gmail.com.
