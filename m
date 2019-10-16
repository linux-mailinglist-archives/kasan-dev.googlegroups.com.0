Return-Path: <kasan-dev+bncBC6LHPWNU4DBBF6MTPWQKGQEK7KDW7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6107BD8CCE
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 11:42:48 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id o34sf24273521qtf.22
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 02:42:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571218967; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4Z+67mJ4ozGw3PdaF2hh6O21m5LthfEfjdp6Qz6UQuq6yNWjpV0BHtOQ/XDJaZDCo
         KMOh02t4hN72DMI5IcVsH/a29urfR1EEmLY04PO8IAhygvTTdej8e6bIrmoTFh5L4/OA
         GE6oIYZKxxLkvsCyY4PCVMwKBFm3Ubc6cIa/wecFS2m/Tgt/FjNTkKHS17LLwSwOYHGI
         tGu/1NgNmfYsqZaP7Fds1sYgO0K39OBb69pSusiiWBtxzRC1ZFgn0xymsRELvXlJMrEC
         IUizSqz5GeIPOMS27QOD1I9DNLv6K65xrRLRXoWBIlGQ2DVbo2jmDinbfOfEU0SJ8bo3
         A5Gw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature:dkim-signature;
        bh=Z4/qwyoKVwXKDcTSi45fYqfhWpM2gFKV+FNFkrnRvwA=;
        b=fxDi29G3COATk5KLUonnueFn+c/JgXqM/PijFz+0jxv0aLhW6WCpgfrcl4bONX5KxT
         w+b55JP1xe9OrMgHjgJluluf3cGzwicgY7M/8Rq0yKA3RPHmZz6UoHEFNKdebQWuePAq
         j8cVNTuuexasrAGDCfWw7BsGIy1GmhL3ULs8grkPLtrpyrnMpJrQT6f0PMqwjnfjr2hS
         jWqF0tAP5IHR10wo/XXXig4dvNzMWVTq1cQZRCzwrRsaMqp5vUeOOEyg8tn29Otn7jH7
         r60XkGZnT++RktbXrtw2EGKKy79+n90DRF1IMmOLnR9U4W5vxKcbRyCJW3sldxUjLAfL
         CKTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=PsAp2aMF;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z4/qwyoKVwXKDcTSi45fYqfhWpM2gFKV+FNFkrnRvwA=;
        b=sY+7cPGNyvkkcAszwOg2/p5gZGKFHUM+uoP+5Kdt7xUznDB8UE7vpmETtUzFkIUnao
         ibXRHGWsqiBdcIaw+ZEi3YH1+jySGZXZWgWY7yoKPWGia8xiuuw/6RHQgYYuCqoKmAV3
         ieSRSw0j++fvMFnM1gOriW7keWydLgSAbCe/ABl/I00QS3GCHKF7mHB7y4oVvd49bUH+
         xS77TTIB0i9F1WjgacFZraQ7c11Ltti8vq/GR81UKFYdTE5+w5eczDXxa3s/1AlCE34h
         9vlHZ/J20jEwBY20xlmMxT6BPTpLqM6Xb+zbeg1893AP/HmnAME6WD6dNuOXe5oQhzTh
         A5tQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Z4/qwyoKVwXKDcTSi45fYqfhWpM2gFKV+FNFkrnRvwA=;
        b=mB7ZYT/nGa02r0NcaOASn+VFXTa4I7eZuKGbI33uZXK8UcxQ62XUpuMOW4mYP06Kqe
         okQXtYTtCbD4u/cAPl3A5LzZSoPyxOvdjzSTE7zOdRCAhh5RbNgb2J0wmXm6ZQjF27RV
         /yZRpKpeiJ1486JzDGQLNZ7xxXgF8O7GPaHZOZZZDmwOJiJy6PspuuYZkM7cVM5rprLf
         L6KqbKdSo/nzbqgX13ACVY0IcvCLMEXOX5VIXmsrcbSqRVIBAYrkwEaxMH7ntMupUmxP
         n+sJn8+5xvXafeXAGfSBYcz/NqlaoBMpUFa8TUq7vXwloOf3+iC8m90/PIs53jexOsd6
         ObWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Z4/qwyoKVwXKDcTSi45fYqfhWpM2gFKV+FNFkrnRvwA=;
        b=tgHb/zip7GlppE279ZRcm8J7gZJkqnI97Ax0WKI4nLRDA2Q1/Sko0fQsCG5C3Sg+aH
         a7kyZGJUOCCMOVEB/dcxgbOe/UBByImkJZTsT37oEobXBJvak6pIAIenI91UcQ2szO1H
         CRpJgcmt+UmQ8rbj8DwjveVTsjeq/ZdTYXW4a9uEJKRCr5nIeoqyQf/2sKXfc350P+IQ
         kilYERr4hWRzUtKm1gwitTPDgpQAG3GLnEp21vlUzTXp5AyRvgjHtldN5FRz65IxdFOh
         JJt3gLZntuuGqR2hGjIM/lJo9hljS1ZvPSNZeNtmXSLMxspvIUJShvC1gdIIaHobYXU/
         NONw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUI/L7EtiKHz0I8t/uFFiBVyi7N13ACkeB1/tl1h+9YOCBe/mZF
	mm6cf8SOsgaq1z2Snhm2MgY=
X-Google-Smtp-Source: APXvYqySdNTrFtk72SmuZ3SYQdG7vJoLebryI6TU78l1nndaRjRnaXUE6XG6u0WPcXszj+Y6H5+tcA==
X-Received: by 2002:ac8:1e83:: with SMTP id c3mr43682037qtm.294.1571218967398;
        Wed, 16 Oct 2019 02:42:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:131b:: with SMTP id o27ls6561982qkj.12.gmail; Wed,
 16 Oct 2019 02:42:47 -0700 (PDT)
X-Received: by 2002:a37:9dd8:: with SMTP id g207mr40850911qke.471.1571218966019;
        Wed, 16 Oct 2019 02:42:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571218966; cv=none;
        d=google.com; s=arc-20160816;
        b=wTp/5r5A8KckdVI0GZV6FCs0xoqtSIHWthqTWogWydxJBR4xY6lgqywZtwTk3YXL4t
         pRvN9WzeqUHkNe/AnBlazCQFslyx3qSP9RJyR2yRR37iC/NttAsmIWj8Z1tBuOD5LlVW
         ATjNOu5JE/fSXtYGwdi/LnQ4iCEJ34QdfmAkn6xrfT2CoJMeEe9BailU94ZyRE4zsL5i
         CpQS09wONhCM3C6zSv6po+A9g6daRk5ZYrVGjHC2bJjQCC0C08wzRxIL6IdtirdSOYX+
         zTPOn70LS1s7AzuLKDuJxwCCAODq/k+bGt+34EPbV09IFM54iXowlGqSVZgOxYu/IEcN
         At1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Tc+bjrFvCm99dkdh8oHRuyC3BtBT5HBjTdr0g9Rtqkg=;
        b=AEj6Hyu0aXElPRPk6aM2kxLA/7absST+Z+zjGq05WqJcaGG8ihlvwSrcneD+Dr39z4
         ZD1Crp8tFl71uymLC01jOYp969wlbKd3Z6wKBpLeqvaXj+rSxxyM1j27YhnHeXPFCJns
         mn7FZOkE/S91X4oRqJ7PzOQ1VQml1yqJ2g+aoYFe7ZJBM0hzVF0FpvCATGnsTrf7LgZt
         +fP2tIXRHRQO8dWxWQwSeH3NMS4tViK2dTVPrFl3YbkWAaA5JbyXadlsjmlgeBpNdXvj
         oKMunCDPO/s7MaZmGI8HwuruNjrQls/Esyn6suaFu/2A/5AL81TvEbTtXl2Eism8gdpb
         Eu5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=PsAp2aMF;
       spf=pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id u44si2666903qtb.5.2019.10.16.02.42.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 02:42:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 3so35205442qta.1
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 02:42:45 -0700 (PDT)
X-Received: by 2002:ac8:7084:: with SMTP id y4mr44279072qto.146.1571218965731;
        Wed, 16 Oct 2019 02:42:45 -0700 (PDT)
Received: from auth2-smtp.messagingengine.com (auth2-smtp.messagingengine.com. [66.111.4.228])
        by smtp.gmail.com with ESMTPSA id p53sm12956733qtk.23.2019.10.16.02.42.44
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 16 Oct 2019 02:42:44 -0700 (PDT)
Received: from compute6.internal (compute6.nyi.internal [10.202.2.46])
	by mailauth.nyi.internal (Postfix) with ESMTP id 5433120931;
	Wed, 16 Oct 2019 05:42:43 -0400 (EDT)
Received: from mailfrontend2 ([10.202.2.163])
  by compute6.internal (MEProxy); Wed, 16 Oct 2019 05:42:43 -0400
X-ME-Sender: <xms:EOamXau1beLCvey8giMNfWrS5u-M98SOlPG_UcrFJ_Y4lqdSeQSxrg>
X-ME-Proxy-Cause: gggruggvucftvghtrhhoucdtuddrgedufedrjeehgddulecutefuodetggdotefrodftvf
    curfhrohhfihhlvgemucfhrghsthforghilhdpqfgfvfdpuffrtefokffrpgfnqfghnecu
    uegrihhlohhuthemuceftddtnecusecvtfgvtghiphhivghnthhsucdlqddutddtmdenuc
    fjughrpeffhffvuffkfhggtggujggfsehgtderredtredvnecuhfhrohhmpeeuohhquhhn
    ucfhvghnghcuoegsohhquhhnrdhfvghnghesghhmrghilhdrtghomheqnecukfhppedutd
    durdekiedrgedurddvuddvnecurfgrrhgrmhepmhgrihhlfhhrohhmpegsohhquhhnodhm
    vghsmhhtphgruhhthhhpvghrshhonhgrlhhithihqdeiledvgeehtdeigedqudejjeekhe
    ehhedvqdgsohhquhhnrdhfvghngheppehgmhgrihhlrdgtohhmsehfihigmhgvrdhnrghm
    vgenucevlhhushhtvghrufhiiigvpedt
X-ME-Proxy: <xmx:EOamXXISM7AZAGOysAqNwFrwskFK4GyvXEMAUK76sMQhyalLITrueQ>
    <xmx:EOamXX9WFyjbGgP8fN1v2SsFAsuaS2nvq57_d3YoSZKkDj0uzpSfrQ>
    <xmx:EOamXT5zY7H9WLM1B_lOpw2bBnMmL1VKQXk25rKbr0sGwMbHc8WAiw>
    <xmx:E-amXT59VT5qlyQTUsleQCVd7IBHXi8qe1VOu-Vf8i4ehTQfx0geLQQ1pB0>
Received: from localhost (unknown [101.86.41.212])
	by mail.messagingengine.com (Postfix) with ESMTPA id 78764D60062;
	Wed, 16 Oct 2019 05:42:38 -0400 (EDT)
Date: Wed, 16 Oct 2019 17:42:34 +0800
From: Boqun Feng <boqun.feng@gmail.com>
To: Marco Elver <elver@google.com>
Cc: akiyks@gmail.com, stern@rowland.harvard.edu, glider@google.com,
	parri.andrea@gmail.com, andreyknvl@google.com, luto@kernel.org,
	ard.biesheuvel@linaro.org, arnd@arndb.de, bp@alien8.de,
	dja@axtens.net, dlustig@nvidia.com, dave.hansen@linux.intel.com,
	dhowells@redhat.com, dvyukov@google.com, hpa@zytor.com,
	mingo@redhat.com, j.alglave@ucl.ac.uk, joel@joelfernandes.org,
	corbet@lwn.net, jpoimboe@redhat.com, luc.maranget@inria.fr,
	mark.rutland@arm.com, npiggin@gmail.com, paulmck@linux.ibm.com,
	peterz@infradead.org, tglx@linutronix.de, will@kernel.org,
	kasan-dev@googlegroups.com, linux-arch@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-efi@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, x86@kernel.org
Subject: Re: [PATCH 1/8] kcsan: Add Kernel Concurrency Sanitizer
 infrastructure
Message-ID: <20191016094234.GB2701514@tardis>
References: <20191016083959.186860-1-elver@google.com>
 <20191016083959.186860-2-elver@google.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="yrj/dFKFPuw6o+aM"
Content-Disposition: inline
In-Reply-To: <20191016083959.186860-2-elver@google.com>
User-Agent: Mutt/1.12.2 (2019-09-21)
X-Original-Sender: boqun.feng@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=PsAp2aMF;       spf=pass
 (google.com: domain of boqun.feng@gmail.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=boqun.feng@gmail.com;       dmarc=pass
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


--yrj/dFKFPuw6o+aM
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

Hi Marco,

On Wed, Oct 16, 2019 at 10:39:52AM +0200, Marco Elver wrote:
[...]
> --- /dev/null
> +++ b/kernel/kcsan/kcsan.c
> @@ -0,0 +1,81 @@
> +// SPDX-License-Identifier: GPL-2.0
> +
> +/*
> + * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
> + * see Documentation/dev-tools/kcsan.rst.
> + */
> +
> +#include <linux/export.h>
> +
> +#include "kcsan.h"
> +
> +/*
> + * Concurrency Sanitizer uses the same instrumentation as Thread Sanitizer.

Is there any documentation on the instrumentation? Like a complete list
for all instrumentation functions plus a description of where the
compiler will use those functions. Yes, the names of the below functions
are straightforward, but an accurate doc on the instrumentation will
cerntainly help people review KCSAN.

Regards,
Boqun

> + */
> +
> +#define DEFINE_TSAN_READ_WRITE(size)                                           \
> +	void __tsan_read##size(void *ptr)                                      \
> +	{                                                                      \
> +		__kcsan_check_access(ptr, size, false);                        \
> +	}                                                                      \
> +	EXPORT_SYMBOL(__tsan_read##size);                                      \
> +	void __tsan_write##size(void *ptr)                                     \
> +	{                                                                      \
> +		__kcsan_check_access(ptr, size, true);                         \
> +	}                                                                      \
> +	EXPORT_SYMBOL(__tsan_write##size)
> +
> +DEFINE_TSAN_READ_WRITE(1);
> +DEFINE_TSAN_READ_WRITE(2);
> +DEFINE_TSAN_READ_WRITE(4);
> +DEFINE_TSAN_READ_WRITE(8);
> +DEFINE_TSAN_READ_WRITE(16);
> +
> +/*
> + * Not all supported compiler versions distinguish aligned/unaligned accesses,
> + * but e.g. recent versions of Clang do.
> + */
> +#define DEFINE_TSAN_UNALIGNED_READ_WRITE(size)                                 \
> +	void __tsan_unaligned_read##size(void *ptr)                            \
> +	{                                                                      \
> +		__kcsan_check_access(ptr, size, false);                        \
> +	}                                                                      \
> +	EXPORT_SYMBOL(__tsan_unaligned_read##size);                            \
> +	void __tsan_unaligned_write##size(void *ptr)                           \
> +	{                                                                      \
> +		__kcsan_check_access(ptr, size, true);                         \
> +	}                                                                      \
> +	EXPORT_SYMBOL(__tsan_unaligned_write##size)
> +
> +DEFINE_TSAN_UNALIGNED_READ_WRITE(2);
> +DEFINE_TSAN_UNALIGNED_READ_WRITE(4);
> +DEFINE_TSAN_UNALIGNED_READ_WRITE(8);
> +DEFINE_TSAN_UNALIGNED_READ_WRITE(16);
> +
> +void __tsan_read_range(void *ptr, size_t size)
> +{
> +	__kcsan_check_access(ptr, size, false);
> +}
> +EXPORT_SYMBOL(__tsan_read_range);
> +
> +void __tsan_write_range(void *ptr, size_t size)
> +{
> +	__kcsan_check_access(ptr, size, true);
> +}
> +EXPORT_SYMBOL(__tsan_write_range);
> +
> +/*
> + * The below are not required KCSAN, but can still be emitted by the compiler.
> + */
> +void __tsan_func_entry(void *call_pc)
> +{
> +}
> +EXPORT_SYMBOL(__tsan_func_entry);
> +void __tsan_func_exit(void)
> +{
> +}
> +EXPORT_SYMBOL(__tsan_func_exit);
> +void __tsan_init(void)
> +{
> +}
> +EXPORT_SYMBOL(__tsan_init);
[...]

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191016094234.GB2701514%40tardis.

--yrj/dFKFPuw6o+aM
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iQEzBAABCAAdFiEEj5IosQTPz8XU1wRHSXnow7UH+rgFAl2m5gMACgkQSXnow7UH
+rjJegf/Rrq3dKwfP4Vyd25nX8MIlEeiMrDXyxhCS2tQFw7EfcgilRD8INFnob38
H/FZ9xR3ndkcpXmoq64gGCN+dEULY78jI7Zg1fpnvUcoVI+q7Hc43PWERvU3otLo
c65FZXO36WKdEg0PJ//SWfSgwQBDfUdjmJ+17YBUd/78SleSsDk9PQNm+A6yb+u5
5jsmrV1uo7vDA+B7/n8Pn06Zu8Uwi0qZn9aWQzoGwmAFrwaF7KRbvWX86p2SMr6k
Tqi7Rpp0uoJDTBFyZg3Dmnizqh81BsHEEQtI3Yjh6bKUpGdre0tyMNUVRYHpQaYX
oVHK6bV3bKlerxpvUT/SE2yOUOBGtw==
=zQTb
-----END PGP SIGNATURE-----

--yrj/dFKFPuw6o+aM--
