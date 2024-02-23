Return-Path: <kasan-dev+bncBAABBKH64OXAMGQE75HCJKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id CBFE7861D8C
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 21:25:13 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5648a1a85aasf2975a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 12:25:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708719913; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yxe1JbuZUIuLMj7YDPVPXkzAkbpjF9FmQM3P9tqlBDy6/ZiLHMfI0zzgEBeW6I6i0H
         2S1cihbcrudUnMs+0ShgJJwHLD17XvhnoCfiMHe6Kpgp9BXEII1cWm4y1doPLNV6cmwF
         eJnAJz9NocYmGHszMew+hwDlqMuGm9GjnHLXdeXzn3GJTqg1NSuLiAPxRLwvCfsnJskT
         qFNvpbl089YYjyx7DcfEIQPCq+k5SmPI8iIXqdMrumNdD15h2fcmdwHvD/4pPGUxPUh7
         mLAFtn7QIunn5A5avjYyUhoEF4VagJCKRosCtzsE0xeQIRbgK4ACj5mpedmZJHzvasy1
         4nWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=oAhP8RJBstgJZ/QsuDbrg1yr4AfROOKo4PsUbZnIJaY=;
        fh=EGpVEeBD5AlOm5cXpsrGNo92waubMlQN/9SNx1sioxg=;
        b=UMQW7leo43Fjz8mlbby4W5Lw736I2ikE3hnFDYBwZGtBzuMMQC7lh4wJvSkMJbArCW
         52RLtJyuaIbJ38DlWOrs2iMdqo2syzM7g7yZNekgzadq5d0i/H/zHOKlXJXB5IxIKvyu
         TpMbC+6Rxp28srugyWPE/yBgOJ1FlfZvaFY9eTlQm02sn65jQSz4ds9Hz58uVIot/LNJ
         U8YPZvIuOafMMHylb4Mzwf3jKNV2ZhlUu+JcwTIE1H+sQgALbT/nYN7udiWCVi5ThhO+
         7KbN/XlJKjjypzdPVUx81E64opPxUTainu7ADJaA9VvkMTE73wRyYLmmJa8yVUn2Kf9L
         wkxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=QdGni1Nl;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708719913; x=1709324713; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oAhP8RJBstgJZ/QsuDbrg1yr4AfROOKo4PsUbZnIJaY=;
        b=MjrnsxTbZfaSud6KnnJkuHtGkBoBdHTUrW9UpxeD06p151xeVHilx4wJSg4acTegzl
         K73weBhjjK35GdfyTrEWrdARz+ocTRGSCxhjQaKDfqy8tnkSRyJDlVYHlxq09hFiJypR
         mpiSBs8DqDfBHsuZq7WQRG4NtDw+Oxk3Dqcab0ktcOTrOrvqIhkgtv3SbgNLC5UBboZ0
         RWoN589oYm7YCzWl7XKkBYy0SokDlYKZ5YkUydPhXfCHC+l0LdCt3uQww3eC/14LlWTL
         KUrCUFLOm8N/dmDYs3EYdt/SRYZ37pMoYtCUtS6E52QLS5325ATyIMGpVkjMk7GuFOQ4
         45bA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708719913; x=1709324713;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=oAhP8RJBstgJZ/QsuDbrg1yr4AfROOKo4PsUbZnIJaY=;
        b=KM8ebwRqnxO1vxQuLref38UxetwJRE2GuGhpJDCnD47wFqAVFv6gcLavGhiY24RCL4
         ZYJoxE9jFfAxk4AA9zJUgM/0uhXWvt9qS/7Hhx8OvCFRNE7yEunh8VYaGdc9U3OYGT93
         +7S/1/noF7cjp9G56hP8P4yMP5+Z3yGXPRG/Kf04ZEE8BlsPpUVrRHm0pILxGtBUKj7m
         rKV7mAJtFIKhFrYqbjUymJdTZgxiLNWdQZbgR2nuCntemNLJyrIwf2pw9dBUjhTObUl3
         6q9jmBolaAboSwjdNcPLHmwMCTl1bsnJZO+zzVS9uj8hFNit9YkLxEBgc2L2Sfi63cgB
         IDtQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW1LPPkRw2ELWHx2kSvW7Z6m917g2VBAyBheHW401tGDV5K8zPqpio/4KRI/toSPqhe4Le0OoY9K8ugOZr1g30QPzpehfQBlg==
X-Gm-Message-State: AOJu0Yytzk9gVu9JbjuV4wrDzGkZtWhSDUU2v6es1wvCaCbCufs3aFbE
	cDs7n1dR6dlQvfwYs3mshSWC9Y6oAjKfmB6jOAhWv149opetwSkT
X-Google-Smtp-Source: AGHT+IFlY25XGgvoNsZ2LN26vKXX5nmkqjakYlwHd89G4pS/UuWOV+6SpHLIcZP3SlP5jDeeCl4I+w==
X-Received: by 2002:a50:9549:0:b0:565:4c2a:c9b6 with SMTP id v9-20020a509549000000b005654c2ac9b6mr54936eda.0.1708719912554;
        Fri, 23 Feb 2024 12:25:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:3217:b0:563:94d1:8216 with SMTP id
 g23-20020a056402321700b0056394d18216ls463247eda.1.-pod-prod-07-eu; Fri, 23
 Feb 2024 12:25:11 -0800 (PST)
X-Received: by 2002:a17:906:3193:b0:a3f:5628:e364 with SMTP id 19-20020a170906319300b00a3f5628e364mr609049ejy.24.1708719911084;
        Fri, 23 Feb 2024 12:25:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708719911; cv=none;
        d=google.com; s=arc-20160816;
        b=uxd7xa6QURA9T3SasZKoMwN40wVoDjwiuLiKLceWDAL1ZrIOOgweVb4TVAWI4xh1gl
         e7tbXBDVUxS2Edy2iGJVNnkGDjR83iHLQEtRYnc6a4vaQkmo2GHbxkDw05PyEUuZE8x1
         qLBNzdHuaRpA8btAKIbkVQWHOEHXeVp2s6xkXpiwgtYsHPb3zTe60C/l8u/Iqqqo7F4h
         +TYYfJhBOY365TfmnguZkb2RKIcErcbDXiC8L8P7iBPUCxaAHqDkmdJH8NX4MXXM66r2
         caGWej0M5wNPbqrFHXkDSv+D7VSmu7FRWENil3eJULtdiDKbocVtUqvaekIxyEAKn7lx
         nuCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XogPvV4ziidUn001lArst0K7vLGykcShOSoSCX7zFXA=;
        fh=DsMEC6pwqxvqQRauiD/TJuj6zI3N54VfC8LiA1awRpg=;
        b=LApty9+bY0UUn7qN8hak2hW7y51gKX6ejYDIpfdfQFKQKTvKWC0hAkdGMbt2Ji/ocy
         lINp5aVKT+jsoB3hnefwxBvFHViJL2PWoouH0398niDm5M8O1kFjVN2cS/h3cZJW1zt9
         D/UlTQZSoHUSIWPQ4SqV/NQ4ERLFhzQ2CVH7bBDQ3g6h2HfmxsryJRQ1z/3hczGCUSkz
         wgeLwKDbqw9OfuyThnPYxxP1kiorOYqZd73FKgLHa/hko+UlcbeLaNDeNeR/myYEVdxG
         7IP2DV51lOoudpLf4G8fX+YXGZ8Jyj+yzJvl91C9/v7WWVProFHM9xD4mwTZ7qEoL1BJ
         YrXg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@tum.de header.s=tu-postout21 header.b=QdGni1Nl;
       spf=pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=tum.de
Received: from postout1.mail.lrz.de (postout1.mail.lrz.de. [129.187.255.137])
        by gmr-mx.google.com with ESMTPS id sh32-20020a1709076ea000b00a3f4f819503si186114ejc.1.2024.02.23.12.25.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 23 Feb 2024 12:25:11 -0800 (PST)
Received-SPF: pass (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as permitted sender) client-ip=129.187.255.137;
Received: from lxmhs51.srv.lrz.de (localhost [127.0.0.1])
	by postout1.mail.lrz.de (Postfix) with ESMTP id 4ThM2G0WTdzyRZ;
	Fri, 23 Feb 2024 21:25:10 +0100 (CET)
X-Virus-Scanned: by amavisd-new at lrz.de in lxmhs51.srv.lrz.de
X-Spam-Flag: NO
X-Spam-Score: -2.882
X-Spam-Level: 
X-Spam-Status: No, score=-2.882 tagged_above=-999 required=5
	tests=[ALL_TRUSTED=-1, BAYES_00=-1.9, DMARC_ADKIM_RELAXED=0.001,
	DMARC_ASPF_RELAXED=0.001, DMARC_POLICY_NONE=0.001,
	LRZ_DMARC_FAIL=0.001, LRZ_DMARC_FAIL_NONE=0.001,
	LRZ_DMARC_POLICY=0.001, LRZ_DMARC_TUM_FAIL=0.001,
	LRZ_DMARC_TUM_REJECT=3.5, LRZ_DMARC_TUM_REJECT_PO=-3.5,
	LRZ_ENVFROM_FROM_MATCH=0.001, LRZ_ENVFROM_TUM_S=0.001,
	LRZ_FROM_ENVFROM_ALIGNED_STRICT=0.001, LRZ_FROM_HAS_A=0.001,
	LRZ_FROM_HAS_AAAA=0.001, LRZ_FROM_HAS_MDOM=0.001,
	LRZ_FROM_HAS_MX=0.001, LRZ_FROM_HOSTED_DOMAIN=0.001,
	LRZ_FROM_NAME_IN_ADDR=0.001, LRZ_FROM_PHRASE=0.001,
	LRZ_FROM_TUM_S=0.001, LRZ_HAS_CT=0.001, LRZ_HAS_IN_REPLY_TO=0.001,
	LRZ_HAS_MIME_VERSION=0.001, LRZ_HAS_SPF=0.001, LRZ_HAS_URL_HTTP=0.001,
	LRZ_MSGID_LONG_50=0.001, LRZ_MSGID_NO_FQDN=0.001,
	LRZ_NO_UA_HEADER=0.001, LRZ_SUBJ_FW_RE=0.001,
	LRZ_URL_PLAIN_SINGLE=0.001, T_SCC_BODY_TEXT_LINE=-0.01]
	autolearn=no autolearn_force=no
Received: from postout1.mail.lrz.de ([127.0.0.1])
	by lxmhs51.srv.lrz.de (lxmhs51.srv.lrz.de [127.0.0.1]) (amavisd-new, port 20024)
	with LMTP id nRFE3cd62g-f; Fri, 23 Feb 2024 21:25:09 +0100 (CET)
Received: from pine (unknown [IPv6:2001:a61:2510:5501:544b:4b32:4119:3827])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by postout1.mail.lrz.de (Postfix) with ESMTPSA id 4ThM2D07zKzych;
	Fri, 23 Feb 2024 21:25:07 +0100 (CET)
Date: Fri, 23 Feb 2024 21:25:04 +0100
From: Paul =?utf-8?Q?Heidekr=C3=BCger?= <paul.heidekrueger@tum.de>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, vincenzo.frascino@arm.com, ryabinin.a.a@gmail.com, 
	mark.rutland@arm.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	andreyknvl@gmail.com
Subject: Re: [merged mm-stable] kasan-add-atomic-tests.patch removed from -mm
 tree
Message-ID: <xk3hvszpeg3ttyexcm5s7ztj64nx5gxfwp6ivmobvfzogqjwn4@wicwiqm4bw7z>
References: <20240222000304.8FA56C43390@smtp.kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20240222000304.8FA56C43390@smtp.kernel.org>
X-Original-Sender: paul.heidekrueger@tum.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@tum.de header.s=tu-postout21 header.b=QdGni1Nl;       spf=pass
 (google.com: domain of paul.heidekrueger@tum.de designates 129.187.255.137 as
 permitted sender) smtp.mailfrom=paul.heidekrueger@tum.de;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=tum.de
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

On 21.02.2024 16:03, Andrew Morton wrote:
> 
> The quilt patch titled
>      Subject: kasan: add atomic tests
> has been removed from the -mm tree.  Its filename was
>      kasan-add-atomic-tests.patch
> 
> This patch was dropped because it was merged into the mm-stable branch
> of git://git.kernel.org/pub/scm/linux/kernel/git/akpm/mm
> 
> ------------------------------------------------------
> From: Paul Heidekr??ger <paul.heidekrueger@tum.de>
> Subject: kasan: add atomic tests
> Date: Fri, 2 Feb 2024 11:32:59 +0000
> 
> Test that KASan can detect some unsafe atomic accesses.
> 
> As discussed in the linked thread below, these tests attempt to cover
> the most common uses of atomics and, therefore, aren't exhaustive.
> 
> Link: https://lkml.kernel.org/r/20240202113259.3045705-1-paul.heidekrueger@tum.de
> Link: https://lore.kernel.org/all/20240131210041.686657-1-paul.heidekrueger@tum.de/T/#u
> Signed-off-by: Paul Heidekr??ger <paul.heidekrueger@tum.de>
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=214055
> Acked-by: Mark Rutland <mark.rutland@arm.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
> ---
> 
>  mm/kasan/kasan_test.c |   79 ++++++++++++++++++++++++++++++++++++++++
>  1 file changed, 79 insertions(+)
> 
> --- a/mm/kasan/kasan_test.c~kasan-add-atomic-tests
> +++ a/mm/kasan/kasan_test.c
> @@ -697,6 +697,84 @@ static void kmalloc_uaf3(struct kunit *t
>  	KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)ptr1)[8]);
>  }
>  
> +static void kasan_atomics_helper(struct kunit *test, void *unsafe, void *safe)
> +{
> +	int *i_unsafe = (int *)unsafe;
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, READ_ONCE(*i_unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, WRITE_ONCE(*i_unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, smp_load_acquire(i_unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, smp_store_release(i_unsafe, 42));
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_read(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_set(unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_and(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_andnot(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_or(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xor(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_xchg(unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_cmpxchg(unsafe, 21, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(unsafe, safe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_try_cmpxchg(safe, unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_sub_and_test(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_and_test(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_and_test(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_negative(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_add_unless(unsafe, 21, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_not_zero(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_inc_unless_negative(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_unless_positive(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_dec_if_positive(unsafe));
> +
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_read(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_set(unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_and(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_andnot(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_or(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xor(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_xchg(unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_cmpxchg(unsafe, 21, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(unsafe, safe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_try_cmpxchg(safe, unsafe, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_sub_and_test(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_and_test(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_and_test(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_negative(42, unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_add_unless(unsafe, 21, 42));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_not_zero(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_inc_unless_negative(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_unless_positive(unsafe));
> +	KUNIT_EXPECT_KASAN_FAIL(test, atomic_long_dec_if_positive(unsafe));
> +}
> +
> +static void kasan_atomics(struct kunit *test)
> +{
> +	void *a1, *a2;
> +
> +	/*
> +	 * Just as with kasan_bitops_tags(), we allocate 48 bytes of memory such
> +	 * that the following 16 bytes will make up the redzone.
> +	 */
> +	a1 = kzalloc(48, GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +	a2 = kzalloc(sizeof(int), GFP_KERNEL);
> +	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, a1);
> +
> +	/* Use atomics to access the redzone. */
> +	kasan_atomics_helper(test, a1 + 48, a2);
> +
> +	kfree(a1);
> +	kfree(a2);
> +}
> +
>  static void kmalloc_double_kzfree(struct kunit *test)
>  {
>  	char *ptr;
> @@ -1883,6 +1961,7 @@ static struct kunit_case kasan_kunit_tes
>  	KUNIT_CASE(kasan_strings),
>  	KUNIT_CASE(kasan_bitops_generic),
>  	KUNIT_CASE(kasan_bitops_tags),
> +	KUNIT_CASE(kasan_atomics),
>  	KUNIT_CASE(vmalloc_helpers_tags),
>  	KUNIT_CASE(vmalloc_oob),
>  	KUNIT_CASE(vmap_tags),
> _
> 
> Patches currently in -mm which might be from paul.heidekrueger@tum.de are
> 
> 

Hi Andrew!

There was further discussion around this patch [1], which led to a v3 of the 
above patch but might have gotten lost in the wave of emails.

I'm unsure what the protocol is now; do I send you a new patch for the diff 
between the above patch and the v3 patch, or can you just use v3 instead of the 
above patch?

I hope this doesn't cause too much trouble.

Many thanks,
Paul

[1]: 
https://lore.kernel.org/all/20240212083342.3075850-1-paul.heidekrueger@tum.de/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/xk3hvszpeg3ttyexcm5s7ztj64nx5gxfwp6ivmobvfzogqjwn4%40wicwiqm4bw7z.
