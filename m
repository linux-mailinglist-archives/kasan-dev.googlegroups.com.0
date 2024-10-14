Return-Path: <kasan-dev+bncBDW2JDUY5AORB6FGWS4AMGQE5YK2AIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BF7799CAA8
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 14:50:02 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-43057565db5sf22648095e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 05:50:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728910202; cv=pass;
        d=google.com; s=arc-20240605;
        b=OEcPAwKSZKBOM60kl/+rqSKnWXGj25ebtUX/QB38qCuSz0xf8OCRF0yUvyCp7O/nWd
         SNyRkWPFk2aNepMATNbguifwcLwxzAyTjKsmzWPmdXY21RkN1IL2oLJU2BJIbqB7ZMda
         SQ9SfIsRTdE5kOoPvhmoobOyGWsQjb5FptaHFrhtgWuElNKa2jQ4MkQ+t3fpJQN6sbGO
         eTcQ7vHRA9UH+0vGGmYDMP6EkAhnS8e4x+5wOiRlvfzFMQGSr8JqWutivh6I7mSO0dwg
         rO1mDZZw1tnuUMSSXt5xTxaAlnmoll+bfQzKw2JjI4I/X3N7hv5KHLfFOLVKXKtbs/4v
         Wm1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ZRZqYV4w88e2kNxDBxHbMJskvT/uPTXOyUAtzQNgSJg=;
        fh=/iR7B07ZOvql3Oc1Lq6f/I6HBDyjkrAggBi1Q0dp+GA=;
        b=hQKDG71clBmSMUmEbyr/sMOhNpUQaZNk7eop/A7jqRd4Rroe4FetN1A1H60Tz7j0VN
         uCfaTMQPgHJm9e58z4Erpn/w8+r3mZ9BZOam1nHaEM5O3PUmhfaaZ0IwY6u6NoXb7KDF
         DmeFLIR8+XzAnaGSbqAmwjnnPvOVYytt3vrAmnJlHVx2ajCEG4f8Qj9OloUQl0+rDxsv
         Xive4kUSB3n0uTeTsSOqldIYmcwdMcgPiv/4KTy54hs7Od/IOL/1OIunkeSvzgEG1+LA
         K0iw2wraKcEZG5jgOk/5I2OgiK5EgSYjyB1YkysGtdX+/jR6eOk/kfAxvFml66KNef6U
         4u7g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ezuQqHaf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728910202; x=1729515002; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ZRZqYV4w88e2kNxDBxHbMJskvT/uPTXOyUAtzQNgSJg=;
        b=hRzt2KGGTsA0GZIvEDKNFrQdGqlBvAduE33H+q0cbAFCfD6z0I0l/syTfai5NLzxIe
         nhPJXjjpikzeSOi5ppcL1VVUzyDT2Cjy3A/OqMC924V0WXob2MMc/4vF4evF5yWT/rfh
         TMtY36QdN1tsOoc2D2hl+THgCvKviDdRDKrbH28o8YRouG/Ee+fDl75UP1oFUS+sSznW
         qjqL5WwLSOxR5D44/bnfUHpL1Mbgs3CasNhBp/Zxl3paDpmr3DSRFWRVUtbMTyeFDUoH
         I/XmVE345aFXM7Igew9Ll+E9E6k/ElkMEBZbnQYIscSSGEBfLerEMtZYZDag8dqiYIGN
         MynQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728910202; x=1729515002; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZRZqYV4w88e2kNxDBxHbMJskvT/uPTXOyUAtzQNgSJg=;
        b=VxPbusxVl3nVhIq11old5iQEFKi03ATDmNnbd7+AAIK5FJY5LCd5SsJ8G4Rt1XsD73
         ALYHknXT7m9LEoWHEkeMh/rg2IX5P/hKtjm6NtdZhicJ9krbH7tkiRWT+Z5vkG+0fahG
         TVhNxhoViADyyYSblYTfi/prJoqonUsz0EMKR+xrapICiPzbL59IKlGKMgcZS2jgrn52
         Zza+NPuNFj6M8QO7D/qmzsW/KS1D1lDpB5y6jwe8GaJz6VaB+qijyLJe0QcwR1lm3iNB
         Vod2RkA+j4o1962WvVBEwg1XS83m9VtzGrFSCMySRNoNdz3d8cgpqbaHszR47UdkuDvK
         b0xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728910202; x=1729515002;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ZRZqYV4w88e2kNxDBxHbMJskvT/uPTXOyUAtzQNgSJg=;
        b=O641BEfmpXng1ZZD0trjXaQlCxb8Y8rV2mGb9x5eLmknuWRde4B7xkRbrsLZs+EKdM
         u+2zEZiajGssvdBUrb/H2Heqgnc4WV8o6KbgOQz9d88klcenZhCVA9KKvax4yY3r6XEC
         aaA8kGb0yXOCT88NkSHiKwvwsU++LsV8IvKXmKGyHN3d+u42d27zkD6tAfWacr52l5dB
         FHQiE4TW8DDBIMpNfVtMMFGwHGYyutQI0bpEbDNGC4bdYrccZ30XPxIE9MzzLb0bi8hv
         sKRZ669RmZpcPWt7s0+SnLpiGdPMNmdEU4ZQcfA/u2q3ZaBWGexcYzHbd+/10AsJEOB4
         iyuA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWEJ4yWTypMplPkoL5vdxEFNIHNMgvh5zOP10ok6/7Gs0VVeo/9Wq40rMdRWjeEZJlUW+wHmw==@lfdr.de
X-Gm-Message-State: AOJu0YzEEqdEdltDtH5uJX+HVHu2CQ2MfRsl8z731MuffUey9yMpH2Jm
	22UC/xm/cW3OQF9z2bRXcJSaybIJTEEKW/hlYJrvezG9TZBClybf
X-Google-Smtp-Source: AGHT+IFNDok90At/ImBySFJAUvcS+D7URebxxi5Ie119fihi6Ezv0t9zQ+oz2+jnlqJaIqzG/zMDZw==
X-Received: by 2002:a05:600c:45cd:b0:42c:b377:3f55 with SMTP id 5b1f17b1804b1-43115a96e9fmr133881125e9.3.1728910200681;
        Mon, 14 Oct 2024 05:50:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8a:b0:430:549c:8d59 with SMTP id
 5b1f17b1804b1-43115efb83fls15224325e9.0.-pod-prod-00-eu; Mon, 14 Oct 2024
 05:49:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2t/FPmXy4DgSZcuntiWRxj1SL797QdaXH18DzT2jgt/9M9lx/OjjXdDzUpBiVjA6tacn5WjekUxc=@googlegroups.com
X-Received: by 2002:a05:600c:1e18:b0:426:5e32:4857 with SMTP id 5b1f17b1804b1-4311d710e52mr91083565e9.0.1728910198384;
        Mon, 14 Oct 2024 05:49:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728910198; cv=none;
        d=google.com; s=arc-20240605;
        b=BGci/R94JLcy3hQJQJqyfqZejQOgtsU1L0hcaGWizE43da5gvbiRJFhe2KyyCAegHb
         JSuFPuiv/4MHQRSK/O7aGqDfeXAOAbTKCSfRbVVMUXd4g02yyB4Ieleh5uXJgvb5u6Ck
         bwAWJfmdam6C29D4hnTAvRjaqgHPXMpq2hBMYw/ojOGHQT9woqc1Gb/ghorrYJBY1o1N
         zYp0l+cRT3OmVp8CTtcEEh+xwvlKeTrRzKaBc6M+qLaq8ubb/175Wju3Y+EKQsU904mi
         RwYyxuB1ZO/kBxPUNwX5NP9WPIV6kPhN2faMcQwu+g5dEQR3SSX+eyeZYiDhLZYltxyP
         1Tjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=uf/5MkNv+WtzfCbJoY+JemC4YRAIn9jKsl/phx7FKjQ=;
        fh=1aNbk1Iqhf+tj4FvNBZE8R2I+xFveqz5PITB+35+pXo=;
        b=bdq4vsrKqPuAb10vIPKdPJvgin2VQWuHrPoLITKRMX6VxeNcI1z1oE1lXq6kj+ihjs
         YGjDI+MDS8gi/xLX1Wy/CbSvg2qJ7POA9jK0g1hU+kOV72Hl4+6BLRDlbhrPT7e/FrC1
         lMFF3f041nERjo81qnGYEO1lfFebKnoILgBzoS5UYBfGuW0MdnlwZc9+0+M1ZFo0RAKu
         DnFOH/fKtrSR88+XP/RHWSL2Btl+xQuoc98v3MrJg70otf2SQ2V6qdBJj7zBoZ2MUhKN
         tR2swK/Ex1ntC0X8ui5NO4EKaCUTzjl1r4SzHSOLfruO2YgNkHncg1Dp1dlJw4iaSl+u
         fUQA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ezuQqHaf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32b.google.com (mail-wm1-x32b.google.com. [2a00:1450:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43118357425si1649565e9.1.2024.10.14.05.49.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 05:49:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b as permitted sender) client-ip=2a00:1450:4864:20::32b;
Received: by mail-wm1-x32b.google.com with SMTP id 5b1f17b1804b1-43056d99a5aso33894475e9.0
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 05:49:58 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVlavzvyYo4L20Xh9WwDYHln6zcL0Tc7Glj+HFcuc4saDadI8+bh91QJdgfAVwkaNHSNQ/yGSvbnE8=@googlegroups.com
X-Received: by 2002:adf:f985:0:b0:371:6fc7:d45d with SMTP id
 ffacd0b85a97d-37d5519d62cmr8625616f8f.2.1728910197530; Mon, 14 Oct 2024
 05:49:57 -0700 (PDT)
MIME-Version: 1.0
References: <20241014041130.1768674-1-niharchaithanya@gmail.com>
In-Reply-To: <20241014041130.1768674-1-niharchaithanya@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 14 Oct 2024 14:49:46 +0200
Message-ID: <CA+fCnZex_+2JVfUgAepbWm+TRzwMNkje6cXhCE_xEDesTq1Zfw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add kunit tests for kmalloc_track_caller, kmalloc_node_track_caller
To: Nihar Chaithanya <niharchaithanya@gmail.com>
Cc: ryabinin.a.a@gmail.com, dvyukov@google.com, skhan@linuxfoundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ezuQqHaf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32b
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

On Mon, Oct 14, 2024 at 6:32=E2=80=AFAM Nihar Chaithanya
<niharchaithanya@gmail.com> wrote:
>
> The Kunit tests for kmalloc_track_caller and kmalloc_node_track_caller
> were missing in kasan_test_c.c, which check that these functions poison
> the memory properly.
>
> Add a Kunit test:
> -> kmalloc_tracker_caller_oob_right(): This includes out-of-bounds
>    access test for kmalloc_track_caller and kmalloc_node_track_caller.
>
> Signed-off-by: Nihar Chaithanya <niharchaithanya@gmail.com>
> Fixes: https://bugzilla.kernel.org/show_bug.cgi?id=3D216509
> ---
> v1->v2: Simplified the three separate out-of-bounds tests to a single tes=
t for
> kmalloc_track_caller.
>
> Link to v1: https://lore.kernel.org/all/20241013172912.1047136-1-niharcha=
ithanya@gmail.com/
>
>  mm/kasan/kasan_test_c.c | 32 ++++++++++++++++++++++++++++++++
>  1 file changed, 32 insertions(+)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..62efc1ee9612 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -213,6 +213,37 @@ static void kmalloc_node_oob_right(struct kunit *tes=
t)
>         kfree(ptr);
>  }
>
> +static void kmalloc_track_caller_oob_right(struct kunit *test)
> +{
> +       char *ptr;
> +       size_t size =3D 128 - KASAN_GRANULE_SIZE;
> +
> +       /*
> +        * Check that KASAN detects out-of-bounds access for object alloc=
ated via
> +        * kmalloc_track_caller().
> +        */
> +       ptr =3D kmalloc_track_caller(size, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +       OPTIMIZER_HIDE_VAR(ptr);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D 'y');
> +
> +       kfree(ptr);
> +
> +       /*
> +        * Check that KASAN detects out-of-bounds access for object alloc=
ated via
> +        * kmalloc_node_track_caller().
> +        */
> +       size =3D 4096;
> +       ptr =3D kmalloc_node_track_caller(size, GFP_KERNEL, 0);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +
> +       OPTIMIZER_HIDE_VAR(ptr);
> +       KUNIT_EXPECT_KASAN_FAIL(test, ptr[size] =3D 'y');

What you had here before (ptr[0] =3D ptr[size]) was better. ptr[size] =3D
'y' with size =3D=3D 4096 does an out-of-bounds write access, which
corrupts uncontrolled memory for the tag-based KASAN modes, which do
not use redzones. We try to avoid corrupting memory in KASAN tests, as
the kernel might crash otherwise before all tests complete.

So let's either change this back to ptr[0] =3D ptr[size] or just reuse
the same size for both test cases (or does kmalloc_node_track_caller
require size >=3D 4K?).

> +
> +       kfree(ptr);
> +}
> +
>  /*
>   * Check that KASAN detects an out-of-bounds access for a big object all=
ocated
>   * via kmalloc(). But not as big as to trigger the page_alloc fallback.
> @@ -1958,6 +1989,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
>         KUNIT_CASE(kmalloc_node_oob_right),
> +       KUNIT_CASE(kmalloc_track_caller_oob_right),
>         KUNIT_CASE(kmalloc_big_oob_right),
>         KUNIT_CASE(kmalloc_large_oob_right),
>         KUNIT_CASE(kmalloc_large_uaf),
> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZex_%2B2JVfUgAepbWm%2BTRzwMNkje6cXhCE_xEDesTq1Zfw%40mail.=
gmail.com.
