Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBWGR7C3QMGQERQME7LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C16398E94F
	for <lists+kasan-dev@lfdr.de>; Thu,  3 Oct 2024 07:17:14 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6cb375efe56sf10092656d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2024 22:17:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727932633; cv=pass;
        d=google.com; s=arc-20240605;
        b=c4mFIVKeTlIwyZ64fW4NQZS58ux7PqLU9cvS3wvUUoSNgTcuCKCLpKuqs9tJXkElEd
         vc36LqIX0R1u962eDgUMqObND3vObWPHjVKHtPQZyQlpLraEF6RoP0rHk7TzPAKClRZp
         /0YiNGJ5SFbkXGJ2z0NGQ7BiLx83IydNJFe4N+YIteNqZ2iBgVVCyBhGru76TJht1Hup
         DxZHxrAxyFm2beczri3PETmpoalvJiUSCg4Mop7hp8sr0zhH02ChQ328cK0LfAmZaDRJ
         Umh8eiKNOqEplVtF6tw1SFnSjGW/rojgxcV4smX1sWwF7DvIbMfnnM9jV3qDMmVuz/kz
         xUVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:message-id:date
         :in-reply-to:subject:cc:to:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=kYWLNntNyH3uWISBpTzw0XIufNU1NwW+VOUD/zjoCUM=;
        fh=wmfmRmWLHRpjOL5mStLcNahrljHtUY6IXTxkvQ7RUWI=;
        b=jUGjxHzmnrWjFh0OjFZJ+ScHvvv5FBObPRK8SrhcJIxbDpXtVno3i78UCPDp4Rp2JF
         N9SmrII6jFiW9fbXS1HcNsb6Uj/2ZNaZDpf0JNj8v0so05g3RdYSHSzcVGKs223yWfq4
         9ExRSo20IyI6/nRrKMRaMV7/M27X0fB0PJZGIHTWzdwh2pDoTg8+Sg3C6zUld+eQ2AlP
         64EeeCRQZWhzQABrZz28SHu9BFHCPY+rBUhqL5cVy33N40ifRTOIJq1lgBelAiH59SIz
         QCyr0k+CEZ1HQQXf0bMM3aqvzXdcehAIjFE15HnYHb4HvmoTblSG5ObIhdoltDC4iECM
         qlQQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L6QXVcoH;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727932633; x=1728537433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:message-id:date:in-reply-to:subject:cc
         :to:from:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kYWLNntNyH3uWISBpTzw0XIufNU1NwW+VOUD/zjoCUM=;
        b=o0KJoUsdeYAttOLiUXMZZPe4/ERgzz921pBGe6JCTtdeTI9/yEhW2P1Pb3zJkrXkhX
         s0ZZttt89WzlEcZyG+OmBIhhvMgs13sO5xFz2qdjF+BHBcGMVp+VmbaOiGDEh30DnL3a
         X58PgULhP4xCddokzb4Wsz5dQqvwuCVYeuzjwQDtAwBKr7gqD1sdZmisjyPOHU5nuUwa
         2EKgSKR1X8pAhAv9CY3YxKeEq6jcnrNpn6SiRyIWm3MAuJ9aUFCR7iM+6+Xm41MwoW2Q
         WIhtaADt00EYmk7k33+IPjjxVOhuofSGpLcZhlMVDZxCYebAbL9DUjkH7n9i/UzfTZag
         +QcQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1727932633; x=1728537433; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:message-id:date:in-reply-to:subject:cc
         :to:from:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=kYWLNntNyH3uWISBpTzw0XIufNU1NwW+VOUD/zjoCUM=;
        b=GFRWciBVa6VVXmFP3ALzeLnmdiyvJJNI7sLNkocy8r/tknDWVlXGrpQ5o+YEVeCpme
         i09v5eXmWRZFp1Mot9K9EAspWHgrSzML6koKyb3RSvVKrGIC579+hIecexAjO9QwEKxD
         Edf3VBiLW1EiMiUCGLJXdR40lhsqsRMMM1YlEzc6SaGDDyj2JnyHg2i6/SYtyijEHoja
         qeOOPJrhTnxsc3X2v2uFIbrPxXerEetEX/myLDRsGOiIVV+7R/oxnhZwha2KmJbgDjLb
         wmA0X006aGbJBVgjgvaCeFxKamZuqKi21srYsJz2SiYDVqIowjhEWierdpdJK7OwcchI
         KisA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727932633; x=1728537433;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :message-id:date:in-reply-to:subject:cc:to:from:x-beenthere
         :mime-version:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kYWLNntNyH3uWISBpTzw0XIufNU1NwW+VOUD/zjoCUM=;
        b=QON4gnsQp0l4M5wP23QA0nMLQUH3f8bs5cRuW18WvAT84CD9XM6r5xyyz1WLs3jaD6
         GWkpjN98hw1uAKOqRVrtdUzPFFqYtXrtekYdRtAjELUmgnA5e6De4trJUVOConvn61Fw
         m0geMlCZtMW2HbBSWLIrDaQ6uIst8Z3MPsQAgp/JEDXiqU0X8nOHQID73IJVP63CnScu
         o49Pu+s4GRFdS6y29O82kUMHVwMpzsue/4NKYte7DblH5mUktAD0CDTryfrpVOld8Ulv
         6NMXGFEoaFTtefeDQ+EhA5XKWJdiqXistPjdEsxzXJkOb5U27s/O35UwL9uudFZ4rzve
         i5OQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWjIShlT567PtjLmQfTjAD8Aoearj01R7G7puqyP3jL4J/tJ1sX+b8aWGIor96awR9VKS/LLg==@lfdr.de
X-Gm-Message-State: AOJu0YxIQbiDQzLAzuWeH/vX1InakCaPaJs5HzhcTRc4Tqwg/K3G6e5e
	IOSEQGZVLDGr+xMTKoF7gKmM3j9Fcd37HDoQCWG6pb7czSEnSDNw
X-Google-Smtp-Source: AGHT+IF3cuyclL/9taX49++Wc0Tsu/W9fw60+lJBTuQcZBOZo5jvMxJ8S7CPTPGv+8SS8TpcRFzCDA==
X-Received: by 2002:a05:6214:5408:b0:6cb:3643:3370 with SMTP id 6a1803df08f44-6cb81a23e91mr90273596d6.23.1727932632544;
        Wed, 02 Oct 2024 22:17:12 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:194b:b0:6c3:5462:e5df with SMTP id
 6a1803df08f44-6cb8fe26736ls10113266d6.0.-pod-prod-05-us; Wed, 02 Oct 2024
 22:17:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV1+kafIhCYKDmfbcZ8D1nI7b7Cg/2ftIqYNEEL7auZJK3OJx6wnEQ1+Nw1TMUnErodvxczHYdzQtQ=@googlegroups.com
X-Received: by 2002:a05:620a:4093:b0:7a6:5cfd:cdfe with SMTP id af79cd13be357-7ae626c1bd1mr834445385a.25.1727932631667;
        Wed, 02 Oct 2024 22:17:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727932631; cv=none;
        d=google.com; s=arc-20240605;
        b=LOkCYrO+TfTrhw1rfriiCC01pwA4s/k8Qyptr5U37zfXUUbSE7+LANjXVgVSuXXbN4
         HhE+GBnr94uT75zaAYa42cgbFFjgl5utBxMh5ZkY8lJ0cVMxQtvE+Xfv9DE+sbTz+42h
         CjKCn+P3UYwjrwuPt8r4aPpf4CQvBpULl6lltC7M+sqsMWa4AGDCuQAWw74LItPMcUVW
         fESy5aAACdtTMWibIr/VH8R+fEV4vAoIPbsfnCaWLQnlk0G8HY59ZBNc/SW7TBkBECh3
         s7NZ9M1lXHvKkB81shmwRsP/CeI59RQlUughidV1VCofsDByMOJnKGU/Y9BH2Rlgxxde
         2E0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:message-id:date:in-reply-to:subject:cc:to:from
         :dkim-signature;
        bh=P61WjNBevRMtAfuGcNIvU5lX9OAgdg1UBpDmxbARpHY=;
        fh=7hEZuICUsKs+jqGIZ4dnv4as7zsmLkSzuYkfZ9cOqvg=;
        b=balhE4ssRBAuMZ+fbchQRseEKEhiFEgdhcZPoYFn/pwirJWInyInWZCoB+P3aS7OVV
         jWlrbK+nmYWI19hnw58NESUr1d39Q8aB9uuHMxAHBWC3PdbbBXTZeXxM6Q4JFmcnxik/
         k/9kASkpF7qZPOf0zWOr/W6zQnDhvml07zIHkrkcxZVMocev5NwmRuaBgSRPXF/ZY9H7
         E4GLoD3EbZaAJBiIGHFTP34VoLGkHE/VCC0kMMreNFUY8Y0QSod2s6EZ78hUxWpSmD8S
         cUuGthTMJXOZjFFr2g3QT4HAbr4s896k3gQ8mUAipTU2X4KEX5zc7y22vMXkUwE5tf79
         f4og==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=L6QXVcoH;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7ae6a197e64si1942985a.4.2024.10.02.22.17.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2024 22:17:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id d2e1a72fcca58-71b8d10e9b3so429558b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2024 22:17:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVKcb2b8wWJF7B4KyUxrZraJWERUxmpppyKHTenLJzrISOEpvi0ONkF4+aP9tPPNf6mEq8WE64tTKY=@googlegroups.com
X-Received: by 2002:a05:6a00:1915:b0:717:8489:6318 with SMTP id d2e1a72fcca58-71dc5c6756bmr8301952b3a.10.1727932630532;
        Wed, 02 Oct 2024 22:17:10 -0700 (PDT)
Received: from dw-tp ([171.76.83.199])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71dd9d7e54csm444461b3a.67.2024.10.02.22.17.04
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Oct 2024 22:17:09 -0700 (PDT)
From: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com
Cc: Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>, Christophe Leroy <christophe.leroy@csgroup.eu>, Hari Bathini <hbathini@linux.ibm.com>, "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>, Donet Tom <donettom@linux.vnet.ibm.com>, Pavithra Prakash <pavrampu@linux.vnet.ibm.com>, Nirjhar Roy <nirjhar@linux.ibm.com>, LKML <linux-kernel@vger.kernel.org>, Alexander Potapenko <glider@google.com>, linux-mm@kvack.org, Heiko Carstens <hca@linux.ibm.com>
Subject: Re: [RFC v2 01/13] mm/kfence: Add a new kunit test test_use_after_free_read_nofault()
In-Reply-To: <a8ca8bd5eb4114304b34dd8bac7a6280d358c728.1726571179.git.ritesh.list@gmail.com>
Date: Thu, 03 Oct 2024 10:36:08 +0530
Message-ID: <87cykhydvj.fsf@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com> <a8ca8bd5eb4114304b34dd8bac7a6280d358c728.1726571179.git.ritesh.list@gmail.com>
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=L6QXVcoH;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::434
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
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


Hello Kasan/kfence-devs, 

Wanted your inputs on this kfence kunit test [PATCH-1] and it's respective
powerpc fix [Patch-2]. The commit msgs has a good description of it. I
see that the same problem was noticed on s390 as well [1] a while ago.
So that makes me believe that maybe we should have a kunit test for the
same to make sure all architectures handles this properly. 

Thoughts?

[1]: https://lore.kernel.org/all/20230213183858.1473681-1-hca@linux.ibm.com/

-ritesh


"Ritesh Harjani (IBM)" <ritesh.list@gmail.com> writes:

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
> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
> Signed-off-by: Nirjhar Roy <nirjhar@linux.ibm.com>
> Cc: kasan-dev@googlegroups.com
> Cc: Alexander Potapenko <glider@google.com>
> Cc: linux-mm@kvack.org
> ---
>  mm/kfence/kfence_test.c | 17 +++++++++++++++++
>  1 file changed, 17 insertions(+)
>
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 00fd17285285..f65fb182466d 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -383,6 +383,22 @@ static void test_use_after_free_read(struct kunit *test)
>  	KUNIT_EXPECT_TRUE(test, report_matches(&expect));
>  }
>
> +static void test_use_after_free_read_nofault(struct kunit *test)
> +{
> +	const size_t size = 32;
> +	char *addr;
> +	char dst;
> +	int ret;
> +
> +	setup_test_cache(test, size, 0, NULL);
> +	addr = test_alloc(test, size, GFP_KERNEL, ALLOCATE_ANY);
> +	test_free(addr);
> +	/* Use after free with *_nofault() */
> +	ret = copy_from_kernel_nofault(&dst, addr, 1);
> +	KUNIT_EXPECT_EQ(test, ret, -EFAULT);
> +	KUNIT_EXPECT_FALSE(test, report_available());
> +}
> +
>  static void test_double_free(struct kunit *test)
>  {
>  	const size_t size = 32;
> @@ -780,6 +796,7 @@ static struct kunit_case kfence_test_cases[] = {
>  	KFENCE_KUNIT_CASE(test_out_of_bounds_read),
>  	KFENCE_KUNIT_CASE(test_out_of_bounds_write),
>  	KFENCE_KUNIT_CASE(test_use_after_free_read),
> +	KFENCE_KUNIT_CASE(test_use_after_free_read_nofault),
>  	KFENCE_KUNIT_CASE(test_double_free),
>  	KFENCE_KUNIT_CASE(test_invalid_addr_free),
>  	KFENCE_KUNIT_CASE(test_corruption),
> --
> 2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87cykhydvj.fsf%40gmail.com.
