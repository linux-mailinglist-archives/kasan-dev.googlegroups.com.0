Return-Path: <kasan-dev+bncBCJ455VFUALBBOHU3KMAMGQEVP63HOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 34CAD5ADDCD
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Sep 2022 05:10:50 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id o15-20020a056e02188f00b002f01f1dfebcsf7689171ilu.10
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 20:10:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662433849; cv=pass;
        d=google.com; s=arc-20160816;
        b=Vue5VyMY6DiaOx59sLwFuuTSJ1R5aNmhVkp7xL9XNI4H/g4CQFCrUO3acOyQGd8He2
         f46odvu8/Pl8FbygevMS1M1/XCHy4f3FHizEGfmVsSRruZbbvTv/FNP+HKOhPwyoI5N9
         wCqUbda4jXkCsafcrwMp93fv9o3R/owR6ynEsHUfV/+r94RFxchU6AtUc2VLMWA6DIHq
         VwkYHPeeWxnbszhiOlYSIxbBjDDiXO5Ukmife7zs3aZlja4bN3HlvI3LHEy7lHS4tNJC
         eaQu7H5gUjvK13Sr2ChNVPSRxduweRnKjV2V5u2joJH2AZFi70nfuMANPR75fXrRbjih
         xzrQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=nkUAcaQDxV10hI7RCEo6ug9JLNJnJI1edX8ecARzpYE=;
        b=IA5U6Omu6qlXPUKJn/SkgVWLQfycR6SAmKLy2piMi9zxY/uvbbxHdpHXP/jYRNXndj
         GpFqQYCsEHoNodiIjsYPigFTzlkCPYXXp+cAXF6U5zRqcU3Fr8bEHTwLlEgDPn8/u9ZK
         Q2/QUj2hA8LSwDqZInfzizxAkyx+8mx0t8wuubu2UIZ5ariQQPXP5AsQYuvBxs602y/y
         aHuUJY9P8m60iis8Kq17x/4YggS3HzSwQ+hqFdhQCeRw1aYxbasGyhRhEHdC+N1MNrPX
         AB84hf6C3l3CGaGDsCDILj4NRdsObI+40lk2HOkhLP34mB1A2pfwizG5JTkKkMwwdB4+
         m8PA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=J64gz2Kz;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=nkUAcaQDxV10hI7RCEo6ug9JLNJnJI1edX8ecARzpYE=;
        b=KtwGUucPe679XYUK05DSvNIaobiWSNQBw3VFtxRLe8BoOGzdk4z99MFSCS2ytP3hzz
         2vRlGQG2rF2JDaEWYKXJX62ffDQA+RoFGgilPAxnX2TV1GFkOfBcKWmEd0//NPeROOks
         8k/IohqoPhqYtdlXak8REwkZtqtsCsLnhvZZxj2LSSrc0KLwS7CSQYNT8IOsiYAf5Blt
         QWTg3HHX73Gn4VAXIdo96K0ef3KKVfX3lPggLuwPHwMTb6GHG82xNwdITM9OTtJK4RpU
         59/MNkZRKK0hbAq+H3MiQtQn5mtxKq59Aa8OFHEbMjGH9A7MTptCQwK46KyPjEw2/pLK
         Nb+w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date;
        bh=nkUAcaQDxV10hI7RCEo6ug9JLNJnJI1edX8ecARzpYE=;
        b=cDEd5wO2KtORRIwBw3RV7agitoCAQCdvExFD7Wga9x4SrZMP4YWfFfXTivdtg98RjV
         skWYGQ9OJgwcufSZ1v39izw0rwFWxevR1nKgyW/SCqbUaPzszKS8a0HtslImwEhsm14b
         yG8+6qrdppGVqjiogM17WpeiZUkLa88N5CmCyNbOY3ExeQUndtTddwup+3J8vzX/foCl
         718IBdCv5J/YuyPsuMSyYhXKtc5eILE9CIsjj3DH1DAIi7xS7O9xnIIAgTX0qGaKkx1n
         phF+ztXfzDkAMnBEbyW4cgwz4szf1+PFWe7Qw6q0eLYKQnOLBSWZLFhyyA0Te477Xxu/
         55TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=nkUAcaQDxV10hI7RCEo6ug9JLNJnJI1edX8ecARzpYE=;
        b=zxaFeMuRzZ69HsRO+01geXR88Np39bAO8XADuWUY92+hHwMK0PdleqAJ7YbHYTfVGB
         WHpWqC14oHsCB7beJGcfbGjCgQjxBbILCtRvKBT8kO2zvw+dKZS1WJxDKNXRxDbOoJ2h
         Gz8m4BFt0LxU8Zq/OCq0u/Z8be99iRWLe8wfZ0Amee9C5lSBK0x1V0vAB0zeBrBTdbec
         Ur3NICWhQme4PQWCvbi99qe00wdeO4vIZruKcdV5d0TIuvollVvHJHfQJoNQUoq7Umo/
         cdbLAncbTrF9B5mQLv2gj3zAwoJaZO+u4e0v+3v5ZcvK7/HS9f6+rIwvvbJKPjy+y5ec
         D2tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1VIo7WIFkI+42AY6sUjXYB5wBhT6EDBMY8Hm7OLPl8YkhJFFXE
	SoDN76QviYAapqk8Jx0CKpo=
X-Google-Smtp-Source: AA6agR6L+FamuYCV140DOA19fk8RacZS35ZJASlEiin+abKoJb0Mv2tVdAAtk8FXV5W/QL4bbEwLDQ==
X-Received: by 2002:a02:c487:0:b0:34f:3b8b:6ba1 with SMTP id t7-20020a02c487000000b0034f3b8b6ba1mr9277675jam.291.1662433848825;
        Mon, 05 Sep 2022 20:10:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:2305:0:b0:34a:4271:878f with SMTP id u5-20020a022305000000b0034a4271878fls2835485jau.11.-pod-prod-gmail;
 Mon, 05 Sep 2022 20:10:48 -0700 (PDT)
X-Received: by 2002:a05:6638:358f:b0:349:ff25:3dc8 with SMTP id v15-20020a056638358f00b00349ff253dc8mr26801231jal.85.1662433848190;
        Mon, 05 Sep 2022 20:10:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662433848; cv=none;
        d=google.com; s=arc-20160816;
        b=icNFS6UxLvQgMgfmEE8EwGw92b3P/LJBUtDpxKcOAZ3pkcSIpnFS1mcoCBNPb38PaC
         bGYOHiR/3d7poQng3tPnNljDoF8+8/anvmxyU2xxUtqMRrNcP8Dzx84c7poK4JH8plKm
         7ZL9XKrNSSJhI8Ak1sCJoxECiLPnsn6ZZO94/4R7ZM86pZbN+iWrhiHMGIs0bdzfcBd6
         CHqcErj43iwNcI8I/ZPdqMFAD8/zF4G07CDUmCH0gpEsqsI/SxaeBF2ebY0NXwl0qWZ9
         tY7x+0KiYCxdD82Ko63uNs1nZoxMwooyoDrzKqEjlJQTu0stDz7JJXxxgQS83s9Tppyv
         o7Lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0q5/g2xqSDjoX1m4bFjC22V5UplGI4w9R+6ExEXxELc=;
        b=RUq0oUlz4TgUTy11hW33yASC27or17ftLRF5GJJNAGVriHgHo+3cFBB92PfQCBJwDb
         YY1sfr8FqbOAhPgMQnzOeffAuy3kJfA6k0bokcho/awaHHRg2lRa9jULTGZydSHs+aQT
         4ln9FaTyIxt7MJUNucV7jWEykDCFXCiCXjdQDZCPJ628Eg/7rTgPyFqL33upKHvtnCWq
         HBTMSfjVFGqU0b32chHbANbrwx7N5x9wA1RFYYcUEaMw0vbTzA+jScNU+yrQ5/ZRrWIa
         qYkiTx5QNeCuFVwtOjoxswG78bfRbvNmX3SYSY4BdbI76GfU2Fc3uC9cajOQVT/VAorL
         UTSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=J64gz2Kz;
       spf=pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42b.google.com (mail-pf1-x42b.google.com. [2607:f8b0:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id n13-20020a056e02148d00b002eb65811b1dsi648143ilk.4.2022.09.05.20.10.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Sep 2022 20:10:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b as permitted sender) client-ip=2607:f8b0:4864:20::42b;
Received: by mail-pf1-x42b.google.com with SMTP id y29so10116978pfq.0
        for <kasan-dev@googlegroups.com>; Mon, 05 Sep 2022 20:10:48 -0700 (PDT)
X-Received: by 2002:a05:6a00:1145:b0:52b:78c:fa26 with SMTP id b5-20020a056a00114500b0052b078cfa26mr53065753pfm.27.1662433847595;
        Mon, 05 Sep 2022 20:10:47 -0700 (PDT)
Received: from debian.me (subs03-180-214-233-83.three.co.id. [180.214.233.83])
        by smtp.gmail.com with ESMTPSA id k12-20020aa79d0c000000b00537d7cc774bsm8583585pfp.139.2022.09.05.20.10.46
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 20:10:47 -0700 (PDT)
Received: by debian.me (Postfix, from userid 1000)
	id 79773103CFD; Tue,  6 Sep 2022 10:10:34 +0700 (WIB)
Date: Tue, 6 Sep 2022 10:10:26 +0700
From: Bagas Sanjaya <bagasdotme@gmail.com>
To: Alexander Potapenko <glider@google.com>
Cc: Alexander Viro <viro@zeniv.linux.org.uk>,
	Alexei Starovoitov <ast@kernel.org>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>,
	Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
	Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
	Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ilya Leoshkevich <iii@linux.ibm.com>,
	Ingo Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Matthew Wilcox <willy@infradead.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Pekka Enberg <penberg@kernel.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Petr Mladek <pmladek@suse.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Vegard Nossum <vegard.nossum@oracle.com>,
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, linux-arch@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 6/44] kmsan: add ReST documentation
Message-ID: <Yxa6Isgcii+EQWwX@debian.me>
References: <20220905122452.2258262-1-glider@google.com>
 <20220905122452.2258262-7-glider@google.com>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256;
	protocol="application/pgp-signature"; boundary="8SFVSXRZNTT5RY83"
Content-Disposition: inline
In-Reply-To: <20220905122452.2258262-7-glider@google.com>
X-Original-Sender: bagasdotme@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=J64gz2Kz;       spf=pass
 (google.com: domain of bagasdotme@gmail.com designates 2607:f8b0:4864:20::42b
 as permitted sender) smtp.mailfrom=bagasdotme@gmail.com;       dmarc=pass
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


--8SFVSXRZNTT5RY83
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline

On Mon, Sep 05, 2022 at 02:24:14PM +0200, Alexander Potapenko wrote:
> +Here is an example of a KMSAN report::
> +
> +  =====================================================
> +  BUG: KMSAN: uninit-value in test_uninit_kmsan_check_memory+0x1be/0x380 [kmsan_test]
> +   test_uninit_kmsan_check_memory+0x1be/0x380 mm/kmsan/kmsan_test.c:273
> +   kunit_run_case_internal lib/kunit/test.c:333
> +   kunit_try_run_case+0x206/0x420 lib/kunit/test.c:374
> +   kunit_generic_run_threadfn_adapter+0x6d/0xc0 lib/kunit/try-catch.c:28
> +   kthread+0x721/0x850 kernel/kthread.c:327
> +   ret_from_fork+0x1f/0x30 ??:?
> +
> +  Uninit was stored to memory at:
> +   do_uninit_local_array+0xfa/0x110 mm/kmsan/kmsan_test.c:260
> +   test_uninit_kmsan_check_memory+0x1a2/0x380 mm/kmsan/kmsan_test.c:271
> +   kunit_run_case_internal lib/kunit/test.c:333
> +   kunit_try_run_case+0x206/0x420 lib/kunit/test.c:374
> +   kunit_generic_run_threadfn_adapter+0x6d/0xc0 lib/kunit/try-catch.c:28
> +   kthread+0x721/0x850 kernel/kthread.c:327
> +   ret_from_fork+0x1f/0x30 ??:?
> +
> +  Local variable uninit created at:
> +   do_uninit_local_array+0x4a/0x110 mm/kmsan/kmsan_test.c:256
> +   test_uninit_kmsan_check_memory+0x1a2/0x380 mm/kmsan/kmsan_test.c:271
> +
> +  Bytes 4-7 of 8 are uninitialized
> +  Memory access of size 8 starts at ffff888083fe3da0
> +
> +  CPU: 0 PID: 6731 Comm: kunit_try_catch Tainted: G    B       E     5.16.0-rc3+ #104
> +  Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
> +  =====================================================

Are these table markers in the code block above part of kmsan output?

> +A use of uninitialized value ``v`` is reported by KMSAN in the following cases:
> + - in a condition, e.g. ``if (v) { ... }``;
> + - in an indexing or pointer dereferencing, e.g. ``array[v]`` or ``*v``;
> + - when it is copied to userspace or hardware, e.g. ``copy_to_user(..., &v, ...)``;
> + - when it is passed as an argument to a function, and
> +   ``CONFIG_KMSAN_CHECK_PARAM_RETVAL`` is enabled (see below).

The sentence before the list above is rendered as definition list term
instead, so I add the blank line separator:

---- >8 ----

diff --git a/Documentation/dev-tools/kmsan.rst b/Documentation/dev-tools/kmsan.rst
index 2a53a801198cbf..55fa82212eb255 100644
--- a/Documentation/dev-tools/kmsan.rst
+++ b/Documentation/dev-tools/kmsan.rst
@@ -67,6 +67,7 @@ uninitialized in the local variable, as well as the stack where the value was
 copied to another memory location before use.
 
 A use of uninitialized value ``v`` is reported by KMSAN in the following cases:
+
  - in a condition, e.g. ``if (v) { ... }``;
  - in an indexing or pointer dereferencing, e.g. ``array[v]`` or ``*v``;
  - when it is copied to userspace or hardware, e.g. ``copy_to_user(..., &v, ...)``;

Thanks. 

-- 
An old man doll... just what I always wanted! - Clara

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yxa6Isgcii%2BEQWwX%40debian.me.

--8SFVSXRZNTT5RY83
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iHUEABYIAB0WIQSSYQ6Cy7oyFNCHrUH2uYlJVVFOowUCYxa6FQAKCRD2uYlJVVFO
o5TjAP4pqdJtF2silbpITwEaYJyueteQAD2tnShYfmi4k/CwmwD+Kf2knjEANX/1
NS87UnfEtAMR4Gyq0gGFXh2B5ITIaww=
=3svA
-----END PGP SIGNATURE-----

--8SFVSXRZNTT5RY83--
