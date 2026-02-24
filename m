Return-Path: <kasan-dev+bncBDCPL7WX3MKBBRNZ7DGAMGQESEUVMYQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id NhvvCcgcnmlyTgQAu9opvQ
	(envelope-from <kasan-dev+bncBDCPL7WX3MKBBRNZ7DGAMGQESEUVMYQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 22:48:56 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id B105018CF22
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 22:48:55 +0100 (CET)
Received: by mail-oo1-xc38.google.com with SMTP id 006d021491bc7-679e57a60f1sf637368eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 13:48:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771969734; cv=pass;
        d=google.com; s=arc-20240605;
        b=edWmM+beZMZZ3fNOi5i553Z2W6pr69ui98r+CZs3rXqVUzRRxcc2zZ7TD2NVsNhHCE
         XqQm+Jb5CM8P64Jr6/dFj6iC1jU62pvTME64g5fn34BSgz4PKlhn1JTdaW4M8jqH1vfF
         cTDSfA8ewTryeKEmN4gaL1RBQ0ILrJCSox16uDTU3gQIFVEXSD9ADQqJQ+DNwRrv0w2o
         UF83q+rLHFn2eCB5U141jD8850BfuFcpFdDIHyzGepW27vMnC6nllXARM4GHSzjttLZW
         6aKuue/uP5+XJFF1gHBoox50vK6fTwTrZHuIDD8+g2M/g1HuDXIBNmL1WVlcWSKSpoio
         OD8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9ZS+td5FWuFno+RbLolw9Zj/qNoODBqufSRw4qNp7Gc=;
        fh=fa9H2xbTnjc1cvo2BeVMcOVMaB4xuBst4/0hZ8u81qc=;
        b=IdaWEMtVkRxM78k5UUKk7tB+ujQrJNieu+6S6Moqj3vRgjggrBeimHuvVx75oLrefX
         RIo7HuvDFTjfdg4Bu1z1YC7z5RY2zL3wYLmVkkQpw3SmjtNvemhKRklXVhRg+ei23zrw
         aRjqSb+n4JQv95WUNtSkGteDkT/s9tg8j9z0JiXXt9jLGVs7ygM8fOY6n/WH0QpXRcJK
         7RkTOogK4e+DhjhJQjccewOImVdto1cjtdGvVhWJ0PQ7mlQ9CJhR/u3bPDJCnKnDmhxH
         Pa6NNlABrbCfLSx/KcJSNdloDLel/dgq8MW5YA0fE1wUWuMh8TVdjZxcUVT6Q5RhrkKv
         9RbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dRLuFxup;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771969734; x=1772574534; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=9ZS+td5FWuFno+RbLolw9Zj/qNoODBqufSRw4qNp7Gc=;
        b=GnwOjbZ8RDjoN3AkMhsRqi/JJkZSeeGZQrGx/MX5reIJKibZYdo5EW4AE3aKc9ieeg
         yVaR2edD4LecuZmJZ/Q0GzTttLlQ/3bLENkeLDYb+O7o+OYRaosC0I3FUSS3pWBrgDo8
         +k9fiNSzl86ni29zTgPh/jKDkVcxFu3VKyqXpiHerIlgTuqyrnB4tyZKHyVcfstJFgvU
         xXYTJTZqdb84j+PRHiVFPXZNl5UD5augnB9BSG34JwY2gRoXBVgH6cWXrqs38G9GZ3jo
         JLl2mxdU2AuD2/Kl9iWa3XLFDe6jOjboMKX7b3dPyRCQv1IP3ZpJxCfy9aobjRQ+h1Ba
         BcBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771969734; x=1772574534;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9ZS+td5FWuFno+RbLolw9Zj/qNoODBqufSRw4qNp7Gc=;
        b=RmjKdF9GxIEuSKemSY/hDmI+Rg8mMf/t5t1+T0mJtBzZ3AcpYCnIlyDkTwv/JQ7mWu
         qMLurknVUjW6g+8XPCW6FOk2FfaQjkJvFIrLNLHHBkGUatDmSzGYbgBsz+VzUxzCAI0F
         Ej/hL/TtEQiXHj6JSmJd3dS++O7DNnRfT1DAcJNR7/dbzz1xo4zy2+2PMod9bJsTa+U5
         J3GwfIAJsm4I7vszJzR/3KWJhpg4PlphaQjYKLxfLof9umQDCxLakVQxWglgFdK1wAkQ
         OYwhqcCn9UqwDunEzsp9fDGhedRR+eYdOfKTgjzFSG5ixOFj9sVRHgK3rbEKXsyqoA5K
         /VBQ==
X-Forwarded-Encrypted: i=2; AJvYcCWKl9CY4sI009SggOAkCflyiFuWEsZdVjZxyqIM++yINek6Lx8E5wCKgvhR2d2/L8xQWRks/Q==@lfdr.de
X-Gm-Message-State: AOJu0YzxS7ApDresCCFcTfmv2y5kq+Wj5PHrWsf5MgQtcxV6OYTRfFc+
	yb3PTkXa7bE2x1MwlYRY+jkB16beVCVWh4sVYBH61wuQeZGRBhBSbQAZ
X-Received: by 2002:a05:6871:ea:b0:404:9a5:acbd with SMTP id 586e51a60fabf-4157b13393cmr6684751fac.6.1771969733930;
        Tue, 24 Feb 2026 13:48:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E+/ohxbNIcKhypAXJpQOeCmyXCjmPE5meikxDXIJbsGA=="
Received: by 2002:a05:6870:21cc:b0:3fa:9f2:b79b with SMTP id
 586e51a60fabf-415ede7d060ls13582fac.0.-pod-prod-00-us; Tue, 24 Feb 2026
 13:48:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXD1zln32v18b30SDVm9Zdut/05oSCCVLmjkUpYUk/MdwGDzqzpb73BHlA1jPD02Srnn5WRHZyJAnA=@googlegroups.com
X-Received: by 2002:a05:6808:17a0:b0:462:a91b:b080 with SMTP id 5614622812f47-4648bc3193cmr767673b6e.1.1771969733047;
        Tue, 24 Feb 2026 13:48:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771969733; cv=none;
        d=google.com; s=arc-20240605;
        b=kF+ZYBW0T82xH2cWiBvm8cRgJHDf9Hvfe4ac3uHmOi6zukcg7ln0/x2RZXedqLWNIA
         cUaG5/inAb0d2PJpVc05u8TbFi5G2lyT14p27CRlPFRN4iC7e4j/E68yAdZoORHNe5Bw
         kHctmFDV8RiY6Vk7KNA0uojIpPunxpTdxvbqsPHffKnPTWb8dxTvgG3RbGgSnCIplmjC
         bNCL775f78a6RreJya02TgIPPE1HB+RxBISx70oY0+OWjdmGTslHCtAyASylMfWd3kcc
         PdvRMugSlkUE/OkQwgTHKa8dL1udpvEys/YXQcFQEwIO+3ik4BR5FOetrXM8Dx5kOv2R
         /d1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=uX9DlEVKKojJexkUdBw6YOZKnzbbFl0NIFFPSJr89AA=;
        fh=N79l3JJ/JpQkjLdBAS4x2O+gTcUEzMBEZ+F6wZlk9dA=;
        b=CKAdotHm1Nmjf8M0CG6OAh18qBeaGlCID+rO3NJqbuLCurvAn2QVv+RjHkztyV+oNK
         nmnCg3pPiR3/cnMu34nkY1Pgr6dcWyAn1FmKLrs9a4TGtX8UR2cBY2ya4yl821Jvi/qR
         KczoooOAlRm4lypPvjoj0+dd4/yE/Scfrk9ErCGMbdpM1A8FpWBw6XKlJu9FxJosX07Z
         I4hYoSeRdGTax+1ZlM8uJ7Lll1J8XeiagyK+ZEIBKwzjrq09eJyU3+u5tiI3u0wOAzIn
         dgUKxIky7YiF/5reyj+qHo/EHDTaqPufFuVCJ03z39Wbvch9fj8lTS/1jey2k1R7cesx
         dOHA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=dRLuFxup;
       spf=pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-4644a158b78si336370b6e.5.2026.02.24.13.48.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 24 Feb 2026 13:48:53 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 5921960051;
	Tue, 24 Feb 2026 21:48:52 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 05C2EC116D0;
	Tue, 24 Feb 2026 21:48:52 +0000 (UTC)
Date: Tue, 24 Feb 2026 13:48:51 -0800
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Nathan Chancellor <nathan@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH] kcsan: test: Adjust "expect" allocation type for
 kmalloc_obj
Message-ID: <202602241316.CFFF256ED6@keescook>
References: <20260223222226.work.188-kees@kernel.org>
 <CANpmjNOpXe7tCP7tyR04Hm+a8zdiBWWQdK=US-qTL31mm+Yzkw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOpXe7tCP7tyR04Hm+a8zdiBWWQdK=US-qTL31mm+Yzkw@mail.gmail.com>
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=dRLuFxup;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MID_RHS_NOT_FQDN(0.50)[];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDCPL7WX3MKBBRNZ7DGAMGQESEUVMYQ];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MISSING_XM_UA(0.00)[];
	RCPT_COUNT_FIVE(0.00)[6];
	RCVD_COUNT_FIVE(0.00)[5];
	HAS_REPLYTO(0.00)[kees@kernel.org];
	FROM_EQ_ENVFROM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-oo1-xc38.google.com:helo,mail-oo1-xc38.google.com:rdns]
X-Rspamd-Queue-Id: B105018CF22
X-Rspamd-Action: no action

On Tue, Feb 24, 2026 at 11:09:44AM +0100, Marco Elver wrote:
> On Mon, 23 Feb 2026 at 23:22, Kees Cook <kees@kernel.org> wrote:
> >
> > Instead of depending on the implicit case between a pointer to pointers
> > and pointer to arrays, use the assigned variable type for the allocation
> > type so they correctly match. Solves the following build error:
> >
> > ../kernel/kcsan/kcsan_test.c: In function '__report_matches':
> > ../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
> > [-Wincompatible-pointer-types]
> >   171 |         expect = kmalloc_obj(observed.lines);
> >       |                ^
> >
> > Tested with:
> >
> > $ ./tools/testing/kunit/kunit.py run \
> >         --kconfig_add CONFIG_DEBUG_KERNEL=y \
> >         --kconfig_add CONFIG_KCSAN=y \
> >         --kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
> >         --arch=x86_64 --qemu_args '-smp 2' kcsan
> >
> > Reported-by: Nathan Chancellor <nathan@kernel.org>
> > Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
> > Signed-off-by: Kees Cook <kees@kernel.org>
> > ---
> > Cc: Marco Elver <elver@google.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: <kasan-dev@googlegroups.com>
> > ---
> >  kernel/kcsan/kcsan_test.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > index 79e655ea4ca1..056fa859ad9a 100644
> > --- a/kernel/kcsan/kcsan_test.c
> > +++ b/kernel/kcsan/kcsan_test.c
> > @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
> >         if (!report_available())
> >                 return false;
> >
> > -       expect = kmalloc_obj(observed.lines);
> > +       expect = kmalloc_obj(*expect);
> 
> This is wrong. Instead of allocating 3x512 bytes it's now only
> allocating 512 bytes, so we get OOB below with this change. 'expect'
> is a pointer to a 3-dimensional array of 512-char arrays (matching
> observed.lines).

Why did running the kunit test not trip over this? :(

Hmpf, getting arrays allocated without an explicit cast seems to be
impossible. How about this:


diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 056fa859ad9a..ae758150ccb9 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
 	if (!report_available())
 		return false;
 
-	expect = kmalloc_obj(*expect);
+	expect = (typeof(expect))kmalloc_obj(observed.lines);
 	if (WARN_ON(!expect))
 		return false;
 



-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/202602241316.CFFF256ED6%40keescook.
