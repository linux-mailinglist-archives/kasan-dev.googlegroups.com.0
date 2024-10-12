Return-Path: <kasan-dev+bncBDW2JDUY5AORBHHYVO4AMGQE5UQKLHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6991899B784
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 00:45:50 +0200 (CEST)
Received: by mail-wr1-x43b.google.com with SMTP id ffacd0b85a97d-37d5ca192b8sf735133f8f.1
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 15:45:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728773150; cv=pass;
        d=google.com; s=arc-20240605;
        b=g2BU9fERXK3zpdjbsb4P+16piYXgzU8jUouP/RNc0YxVW9On58kmRLtJcLebw5HbGl
         Vo6egPEiAu4mGX76F22lvg+ajBwcTIg8+7JACe+0rbyOKlpZrtYYcrYA5RpwWDU7a6tK
         +G/6xDLdaXatmayQx6Di3xO5SnrVF1MjSucURFCwKH+U57c310vu0bsXthqBWA6exDcW
         gvxbh/8qB8qy612ZrnZ8FR6Ykus7SeDQOG5rhwfPEDETNPuYLAJIfkrC4PYDbpPISe1n
         6+flj1d10nnBKK3HNAi3KRcto1FpCUMTN9h3I6mQZXo0aZAGcqWWcx6qixXEZ5hVRuiW
         9Q0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=PwLq0L8J0p+34gQpaY4pasf9qR6Xfr+W2SyQDUX1Pbc=;
        fh=eQF0ukXdMIUGMPJkOOc8VXgOXQReSGy/MUWYseql3w4=;
        b=aYdOfcdfhPB4zEIs4Cwzp5FAqPUOzoY8miQ+fU7ksRHuYVtAIPO1bA5/3XKSNnPi3Z
         V3SR1wzPK8HxjqpglL9/8ed0pjIY1T82s7JNrt5mx6nRHnA7iAQHmnZONrBkIjUI52qt
         CZxxkPHRapUXVrKZFuE+on+rySctkk/34LAQZVBsgMwT+Wd49JE6m1Y0NehvjE83RAu5
         pnJJ2n3XaaZiTImJoB6ODD+13B52I9qQpECTz7nJomrjG1pxeliQRR3CI8jUtOThT2LP
         H7ZjKxI3OAgSIC7m2X0tekWse14uaOZI3JZGAKLQJBLmNVBp1DjJOHQDLFq2WKbEGlCh
         /U9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q5tHijD4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728773150; x=1729377950; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=PwLq0L8J0p+34gQpaY4pasf9qR6Xfr+W2SyQDUX1Pbc=;
        b=BdgJ6nKmpZ7vMHHXQMm219LpGO5YfOpmnR26wvY9+PfMw65rWx73KhZo5IP0GVLo7x
         TPGSJ78DT+5odDbk8KhlhZ7XNFLdoiLgWboG3jkwhi6nrCtzDyW5+3tLN3XXYhWtVPjB
         e5sryku8HoO2QBYYsDjydBVEgUem7BYLiAZWx2pq5UL95e0Xn4UeqDO6MBPJq3/T9Jn7
         izFBeQsEf83u+jpgkuDAMAwvlvaE3fjXFM2yIFyVvuxsGvHlg3l7m8w1YlQSq7LE0/Yo
         wGBrhs6c0NTbq9tQQ83v4cy1TcM6EyJpDyE0xEmZt7LuButwmXGPCifaesY8PGHqE6cr
         UQsA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728773150; x=1729377950; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=PwLq0L8J0p+34gQpaY4pasf9qR6Xfr+W2SyQDUX1Pbc=;
        b=Dciilh7t++2du1z1pcDPGMFIKrMgH7a+g28sSUSafmNU52e72uWvno/umk1SUr5vXp
         g0lHs8j6t5XNKTF26Nx9KzExzQhnaxfBxwwrcMwZvf33Yg1kseMK/i1Ef46vRcl3E4zb
         kXbtWbaCmBzN94IiQWExJAEMHc0Y6eVaGR27cQBUYEK2X3859vED5+iEnOpVZWWAoYj7
         fBib86xQjOLgAzU5NYXsvkZSIWo8zWAPz77gRz7qdsF+LF7SDW0HHpKAsRpqrn6LKlpk
         n+vsGeC8FxCppCo1VJHfEZ/XebUm4WAZ09djbl7KOySXSAhjQY0Dn/iVs9ZRJEh3eUgX
         7rEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728773150; x=1729377950;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=PwLq0L8J0p+34gQpaY4pasf9qR6Xfr+W2SyQDUX1Pbc=;
        b=JAYcPLx0HAGrylkcYYfa/O/GqHaxoWmz1ChVHrldkZ/MJAzPHpa5QkG5cKDZwMm27Z
         lm0tO64orKGLHnYMYrL0AMebNScXMk341FPSqTpIJrvoYxQ8bLElEUr8oYIId25EKnOu
         4kTeq46JX/zO3Tm0Q771opsbRXWdwDh2+TghfxAWSPTrROj2B589idxFioBM79bEaxac
         30HpbeN/iNqc49ZL2VYuBbK7t4xHqEJ9SskFmSKbwuWQFCUiWZjRrZbFKTmZHKf/3evM
         GzpOb2jOAs+UzEastnCyGlpDowoo1TCPV4VoOAPtBPYk6ZBNuuHq5yiwfJ4RQsWrAfHl
         Y+Kw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVhXtJ4xsss0DrJKujLbh6x7PsbDh7g3rVtPuVBBdUzib8w2txi1rN+f5Da9mOGd9XxAEGrGw==@lfdr.de
X-Gm-Message-State: AOJu0Yx9sT7mvw3OYP2LDRpGQO/Ipiq80s2FnzIwriidNDeXHRJIBtW6
	Ch/7k5Rq/SEWb6sNW8fKkfQxCRNFmYBsYgJCUX8pKLdgsdOB4yil
X-Google-Smtp-Source: AGHT+IG2/0RXx+s2xKrCNc+lu3N1j2fl58NR1ENnZDgGKQNcbffZDcZgtR2vps5TaEjbY6mr2cmA+Q==
X-Received: by 2002:adf:dd82:0:b0:374:cd3c:db6d with SMTP id ffacd0b85a97d-37d4815f33dmr9456864f8f.6.1728773148384;
        Sat, 12 Oct 2024 15:45:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:5121:b0:42c:b037:5fb1 with SMTP id
 5b1f17b1804b1-43115fd9c61ls11079965e9.1.-pod-prod-00-eu; Sat, 12 Oct 2024
 15:45:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVFJ9nXMJ42TqCZWidUiNmBcSQjGRSqSY8HGf6sykGBTPtB9cAuADIW8RIO3EPR/1bh2YgqUgvqrKE=@googlegroups.com
X-Received: by 2002:adf:fccf:0:b0:37c:bafd:5624 with SMTP id ffacd0b85a97d-37d481d2a89mr9133015f8f.25.1728773146576;
        Sat, 12 Oct 2024 15:45:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728773146; cv=none;
        d=google.com; s=arc-20240605;
        b=ZtgcHwc+9I3owuCnUcNvXDLHUkYmsWWbeQ9kEcs4QRcYnNwWHucMBwRTMmRiMYk+yr
         6Z5VGdcfclp9ziGb9tgJWviXJgnPtD3aYZ3T7wVEJjesQssCDrad0+sqsz2dOuQglN0C
         WswyF+0UxqGBUw93MQby4CjdfDZuEV8lERmLvrwSmS9zC8JSO+1BPZLX7JD4vaXhSlj/
         BNZ5ogh1yp1uqvrlYH7ZkoGHORXbDFK/l90fpBrrpS2lsqPOQpP4L4JbJhIUkWJjkb5n
         9cYVFIWZydbvYG/NXWH72FVO4Jzmu/vwu2oAhLjhitXihzQ/DSboq+Y6id8CNyILq6Wc
         pbVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=QrAqah5calgIhNd5J2K0kgxnrRY1RxWPFw2HfKMPoO0=;
        fh=iwFLKN1ptTqhmC28+5a0Jct0a4ASvDV2WO9MGc5xHF4=;
        b=Ua6CO2xJNgq7O4CueWzl/a0Td/MlPh6t4sOmbA5NL6lJNA49KFjiSS/qImuh2z1bqc
         jetywCYodOf8Kb+HUpLaOUgBD4bU9qz9OaJr2qWhvFuAiLunyyffLZIFfB1Jr4vDQ2Nc
         kkBOTAOaxYWi5yi/adpbpqVmSD5OQAzVmf0lHCgaSynu67humnAlS5/0dKvddCIaHz3m
         UtcZbsIp6jex+yVugrCsWhJ8v5ck99cHHBi1MAZGMiaBCJvLdDP5gEfXqLb52ko4U9wj
         wiixFYx8RH3woA8L0TqnV/BzlrctngnhfH/S0D/ARxjftF5uV0EggvNTizS++Z9ac/ao
         Pijw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Q5tHijD4;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4310c3bf494si3750095e9.1.2024.10.12.15.45.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Oct 2024 15:45:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-37d3ecad390so2537144f8f.1
        for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 15:45:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU7xrXMPte6r+6M26DTg26VJgfCdcylCfTKGTNTwJ6Z5yEdSDKrhT7lOjU/w8gbsvCzjqdSLP+jymI=@googlegroups.com
X-Received: by 2002:a05:6000:18e:b0:37d:3f81:153f with SMTP id
 ffacd0b85a97d-37d551fc17cmr5735258f8f.17.1728773145741; Sat, 12 Oct 2024
 15:45:45 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZfs6bwdxkKPWWdNCjFH6H6hs0pFjaic12=HgB4b=Vv-xw@mail.gmail.com>
 <20241011035310.2982017-1-snovitoll@gmail.com>
In-Reply-To: <20241011035310.2982017-1-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 00:45:34 +0200
Message-ID: <CA+fCnZfznvJ-zaJg+Oeddt7OOPhnvkJ4z4N35rq5KXx2N=HBFw@mail.gmail.com>
Subject: Re: [PATCH v6] mm, kasan, kmsan: copy_from/to_kernel_nofault
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, bpf@vger.kernel.org, dvyukov@google.com, 
	elver@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, ryabinin.a.a@gmail.com, 
	syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com, 
	vincenzo.frascino@arm.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Q5tHijD4;       spf=pass
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

On Fri, Oct 11, 2024 at 5:52=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> Instrument copy_from_kernel_nofault() with KMSAN for uninitialized kernel
> memory check and copy_to_kernel_nofault() with KASAN, KCSAN to detect
> the memory corruption.
>
> syzbot reported that bpf_probe_read_kernel() kernel helper triggered
> KASAN report via kasan_check_range() which is not the expected behaviour
> as copy_from_kernel_nofault() is meant to be a non-faulting helper.
>
> Solution is, suggested by Marco Elver, to replace KASAN, KCSAN check in
> copy_from_kernel_nofault() with KMSAN detection of copying uninitilaized
> kernel memory. In copy_to_kernel_nofault() we can retain
> instrument_write() explicitly for the memory corruption instrumentation.

For future reference: please write commit messages in a way that is
readable standalone. I.e. without obscured references to the
discussions or problems in the previous versions of the patch. It's
fine to give such references in itself, but you need to give enough
context in the commit message to make it understandable without
looking up those discussions.

> copy_to_kernel_nofault() is tested on x86_64 and arm64 with
> CONFIG_KASAN_SW_TAGS. On arm64 with CONFIG_KASAN_HW_TAGS,
> kunit test currently fails. Need more clarification on it.
>
> Link: https://lore.kernel.org/linux-mm/CANpmjNMAVFzqnCZhEity9cjiqQ9CVN1X7=
qeeeAp_6yKjwKo8iw@mail.gmail.com/
> Reviewed-by: Marco Elver <elver@google.com>
> Reported-by: syzbot+61123a5daeb9f7454599@syzkaller.appspotmail.com
> Closes: https://syzkaller.appspot.com/bug?extid=3D61123a5daeb9f7454599
> Reported-by: Andrey Konovalov <andreyknvl@gmail.com>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=3D210505
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
> v2:
> - squashed previous submitted in -mm tree 2 patches based on Linus tree
> v3:
> - moved checks to *_nofault_loop macros per Marco's comments
> - edited the commit message
> v4:
> - replaced Suggested-by with Reviewed-by
> v5:
> - addressed Andrey's comment on deleting CONFIG_KASAN_HW_TAGS check in
>   mm/kasan/kasan_test_c.c
> - added explanatory comment in kasan_test_c.c
> - added Suggested-by: Marco Elver back per Andrew's comment.
> v6:
> - deleted checks KASAN_TAG_MIN, KASAN_TAG_KERNEL per Andrey's comment.
> - added empty line before kfree.
> ---
>  mm/kasan/kasan_test_c.c | 34 ++++++++++++++++++++++++++++++++++
>  mm/kmsan/kmsan_test.c   | 17 +++++++++++++++++
>  mm/maccess.c            | 10 ++++++++--
>  3 files changed, 59 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index a181e4780d9d..716f2cac9708 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -1954,6 +1954,39 @@ static void rust_uaf(struct kunit *test)
>         KUNIT_EXPECT_KASAN_FAIL(test, kasan_test_rust_uaf());
>  }
>
> +static void copy_to_kernel_nofault_oob(struct kunit *test)
> +{
> +       char *ptr;
> +       char buf[128];
> +       size_t size =3D sizeof(buf);
> +
> +       /* This test currently fails with the HW_TAGS mode.
> +        * The reason is unknown and needs to be investigated. */
> +       KASAN_TEST_NEEDS_CONFIG_OFF(test, CONFIG_KASAN_HW_TAGS);
> +
> +       ptr =3D kmalloc(size - KASAN_GRANULE_SIZE, GFP_KERNEL);
> +       KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
> +       OPTIMIZER_HIDE_VAR(ptr);
> +
> +       /*
> +       * We test copy_to_kernel_nofault() to detect corrupted memory tha=
t is
> +       * being written into the kernel. In contrast, copy_from_kernel_no=
fault()
> +       * is primarily used in kernel helper functions where the source a=
ddress
> +       * might be random or uninitialized. Applying KASAN instrumentatio=
n to
> +       * copy_from_kernel_nofault() could lead to false positives.
> +       * By focusing KASAN checks only on copy_to_kernel_nofault(),
> +       * we ensure that only valid memory is written to the kernel,
> +       * minimizing the risk of kernel corruption while avoiding
> +       * false positives in the reverse case.
> +       */
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(&buf[0], ptr, size));
> +       KUNIT_EXPECT_KASAN_FAIL(test,
> +               copy_to_kernel_nofault(ptr, &buf[0], size));
> +
> +       kfree(ptr);
> +}
> +
>  static struct kunit_case kasan_kunit_test_cases[] =3D {
>         KUNIT_CASE(kmalloc_oob_right),
>         KUNIT_CASE(kmalloc_oob_left),
> @@ -2027,6 +2060,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(match_all_not_assigned),
>         KUNIT_CASE(match_all_ptr_tag),
>         KUNIT_CASE(match_all_mem_tag),
> +       KUNIT_CASE(copy_to_kernel_nofault_oob),
>         KUNIT_CASE(rust_uaf),
>         {}
>  };
> diff --git a/mm/kmsan/kmsan_test.c b/mm/kmsan/kmsan_test.c
> index 13236d579eba..9733a22c46c1 100644
> --- a/mm/kmsan/kmsan_test.c
> +++ b/mm/kmsan/kmsan_test.c
> @@ -640,6 +640,22 @@ static void test_unpoison_memory(struct kunit *test)
>         KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +static void test_copy_from_kernel_nofault(struct kunit *test)
> +{
> +       long ret;
> +       char buf[4], src[4];
> +       size_t size =3D sizeof(buf);
> +
> +       EXPECTATION_UNINIT_VALUE_FN(expect, "copy_from_kernel_nofault");
> +       kunit_info(
> +               test,
> +               "testing copy_from_kernel_nofault with uninitialized memo=
ry\n");
> +
> +       ret =3D copy_from_kernel_nofault((char *)&buf[0], (char *)&src[0]=
, size);
> +       USE(ret);
> +       KUNIT_EXPECT_TRUE(test, report_matches(&expect));
> +}
> +
>  static struct kunit_case kmsan_test_cases[] =3D {
>         KUNIT_CASE(test_uninit_kmalloc),
>         KUNIT_CASE(test_init_kmalloc),
> @@ -664,6 +680,7 @@ static struct kunit_case kmsan_test_cases[] =3D {
>         KUNIT_CASE(test_long_origin_chain),
>         KUNIT_CASE(test_stackdepot_roundtrip),
>         KUNIT_CASE(test_unpoison_memory),
> +       KUNIT_CASE(test_copy_from_kernel_nofault),
>         {},
>  };
>
> diff --git a/mm/maccess.c b/mm/maccess.c
> index 518a25667323..3ca55ec63a6a 100644
> --- a/mm/maccess.c
> +++ b/mm/maccess.c
> @@ -13,9 +13,14 @@ bool __weak copy_from_kernel_nofault_allowed(const voi=
d *unsafe_src,
>         return true;
>  }
>
> +/*
> + * The below only uses kmsan_check_memory() to ensure uninitialized kern=
el
> + * memory isn't leaked.
> + */
>  #define copy_from_kernel_nofault_loop(dst, src, len, type, err_label)  \
>         while (len >=3D sizeof(type)) {                                  =
 \
> -               __get_kernel_nofault(dst, src, type, err_label);         =
       \
> +               __get_kernel_nofault(dst, src, type, err_label);        \
> +               kmsan_check_memory(src, sizeof(type));                  \
>                 dst +=3D sizeof(type);                                   =
 \
>                 src +=3D sizeof(type);                                   =
 \
>                 len -=3D sizeof(type);                                   =
 \
> @@ -49,7 +54,8 @@ EXPORT_SYMBOL_GPL(copy_from_kernel_nofault);
>
>  #define copy_to_kernel_nofault_loop(dst, src, len, type, err_label)    \
>         while (len >=3D sizeof(type)) {                                  =
 \
> -               __put_kernel_nofault(dst, src, type, err_label);         =
       \
> +               __put_kernel_nofault(dst, src, type, err_label);        \
> +               instrument_write(dst, sizeof(type));                    \
>                 dst +=3D sizeof(type);                                   =
 \
>                 src +=3D sizeof(type);                                   =
 \
>                 len -=3D sizeof(type);                                   =
 \
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Tested-by: Andrey Konovalov <andreyknvl@gmail.com>

For KASAN parts.

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfznvJ-zaJg%2BOeddt7OOPhnvkJ4z4N35rq5KXx2N%3DHBFw%40mail.=
gmail.com.
