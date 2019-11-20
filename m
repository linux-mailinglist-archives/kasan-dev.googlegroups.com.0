Return-Path: <kasan-dev+bncBDQ27FVWWUFRB7642PXAKGQE33ABCFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id AD984103556
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Nov 2019 08:42:56 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id c67sf17838069iof.22
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Nov 2019 23:42:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1574235775; cv=pass;
        d=google.com; s=arc-20160816;
        b=TgSwAVDsVVNcd+2t2gxnf4AViWeeumz5DqoCqCwpsa7v8mBNKqFm5rA3UxVBBRGbZW
         sHPP+PNHsbBgHfJRA3IwLVoMS/YwupV/N+56+i+WIIlH67dSjuNIj6FotKvXOvcd03SZ
         j2/3eNcyd1GYpsdtIV/kYGmmNJmDanPDcS97I8tPxPaPrI1N6b7QKfUJOcdnZUhmPAUr
         SyXtqvVvDgwSgPINoV5eMggOBZYdKomQkWfCs1xzsKkHPVzHl+epMxodpbJkiAyYE0zT
         hWGWhqUk5n36hYxwS4PdxoAx8woVSqsm+iDODuBueliHT6rBK2JZ6+KEdvmasyGFQt9O
         uc5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=+cCqxa9oZrGFHwEE7dqO2mMNRQBCUgnIceewTsTZIxE=;
        b=Ag9uOdxQDrsyHhMRUQel27BeuNXMefgme49HaX4Su7oHWn0j6ueFqRM/Y9vpX4gVP0
         lt4TCjLmxoB21yZP92q/ze9sdoIzjxjDt42j0ALl3UKCE1PI2p9dt28QziSyB+uoZl7M
         l70XjyHD6HlB51Sx2sfv/v+C6iCvLkI57q1Ns0nFHFprJ+gkZlA8JiDs37Q7WknBeK+y
         Zb3Pku0RsVT5NoR4YFuLrnaa17P3+IS3G6EZ5/q+J2C3IT0UWcnHwF1M3SlKiuIaWqFv
         lPZwFxrguFWZzlckHSSvfDJ53gssh3id/REx4z9BoCHskLMIo6z4TAyJ9fVz6Bn6HwoD
         BQtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=D5sJ4Q1D;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+cCqxa9oZrGFHwEE7dqO2mMNRQBCUgnIceewTsTZIxE=;
        b=cU3nBxuDL7ZgjR5x1U01LvbI/mHjaX30R0OPt/zE+eWGNsohrtZ3LO36hASvmPEcwW
         6FGjqjVwZKv3eCazVepX5Ub3K4dxYJ1OYAOWDdD+bbn2k7vhSmefKV1jazOuQyz78yer
         PSxEIOAKp2+1wk6s1KX3xidSjsLFkSBJdLimPtEsW2Ea8qG1CIBrf73yo2YoHbREt+bz
         o4i+n6A7KWBLegNM0y7SuS6+fJrjZtZh0jJ3xKqrTUOmruiGcd++E9YpvxamAwsG97jV
         ZMD9mynLjYIix9ZMYCJxtOooQUAouiA8n7JDTEA9qrnoh54pPlIW91I/vCl9BhDGZvBZ
         YCzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+cCqxa9oZrGFHwEE7dqO2mMNRQBCUgnIceewTsTZIxE=;
        b=c6zteM26PWc6j1GeW4qRqSyfiQw77uS0xFduV1MBKpRPuouaEhau0urDW1d/JW8VTX
         QgSJVLJ9bCeFn1HH4EN6Hu5pzyyctzwiPtW99dND47zUdm26oM3W3/8fFFCpt9h6Nt6d
         175qE9japTZUSnrxMtyIL413vSGijWUPd5tUrRrnykKHvNhlAjVaHm83c9vSNRKZiMIB
         pe2L1Tw2UBl+15eF5Gqnrhs6kPwxi51J8YIg6j6JDJgPgoqHbjY9m0kWpV4uvJF1rH6G
         q3iZTkmiFHQwjwBDPlNeAK9Kj6HMKxHYXi9HuAgWAsazEBBxi2GZaCTDnM/Q7pKJHxJM
         ua8A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUejDtvtk9CQABk+PkCVyN7AyE2swzh2nC1JaBoNc9zbW2XMVDJ
	tJefbwXlpX9f5h2i1bm31wk=
X-Google-Smtp-Source: APXvYqz+OvPOpN6FtigBRnwCq1oBaZvPRaFaEkSxqpeCUc2+4BGEDl2xStdyru/13Ftrs7YYelFBAQ==
X-Received: by 2002:a92:3ac5:: with SMTP id i66mr2127041ilf.28.1574235775424;
        Tue, 19 Nov 2019 23:42:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9e06:: with SMTP id q6ls232645ili.5.gmail; Tue, 19 Nov
 2019 23:42:55 -0800 (PST)
X-Received: by 2002:a92:3b04:: with SMTP id i4mr2000979ila.211.1574235775114;
        Tue, 19 Nov 2019 23:42:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1574235775; cv=none;
        d=google.com; s=arc-20160816;
        b=UCNQOwxU5YclPCOyZUPSHGQqf7QtalTFDlojypK/chk8ls054xUz0GpQUiSPv5PaZF
         usWEfZCTRnjyhovhfZhbVmCOf6ffUJG95DRft25AcSBVIO6PqvEZqlmCH/GMqek79vWr
         SkmitKa2HKUFUmOtpjMst/hBFytb0rG36ug0XG2IFwnZI6gjgaRv2kM0LKfdbj/pE79S
         PI2ukm6kDMkCXb/gZ0m/ISYoaBx9CABSjnv7inhxCRnBBBg+9osh7AV+BvVadChYueET
         KjTODOho5Wu/SQZIn7T65gpaG1pRfUpn5+enub0CeR0O6bMJ3S/enPmljWKdSbzABUqY
         jluw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=02fPVIRaO1XujNDxX9CuuJM8AmBmXK/c/uAOUSL7B7k=;
        b=gnMfbQK/WaByXn/pPy73lwR3tMNfSyS8W5ZZutAy6kHXZw+D3k5jMyGhgZks3mghI/
         s0sZ2Z9R93u8PLmHoGSkwE6ommJHc/YoET/5R+rIXQXiuBZLGLBRcKMOC4kPFBKaXHlK
         kdDyD1V7FGAf9kWVQtZOJvS9s7ynM2ByrZOauYQkz7qMFoPapE8+Mg5woRwLVKWENL/o
         e2dsTHEJ+uduWYFAOPws5I7BryNv/KvffBnieRKgYMHCqGYm/J5tWFCVeeHGcFtxkpX6
         8Zzb79eRQS2Kc54X3uAb9pa7tDM6zONJKxKmmiuir0gXPE8JIDLui+WWUo/4GJpVQiLO
         z/0w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=D5sJ4Q1D;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id x18si1424581ill.2.2019.11.19.23.42.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Nov 2019 23:42:55 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id b1so3427845pgq.10
        for <kasan-dev@googlegroups.com>; Tue, 19 Nov 2019 23:42:55 -0800 (PST)
X-Received: by 2002:a62:7847:: with SMTP id t68mr2372866pfc.140.1574235774458;
        Tue, 19 Nov 2019 23:42:54 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-9c57-4778-d90c-fd6d.static.ipv6.internode.on.net. [2001:44b8:1113:6700:9c57:4778:d90c:fd6d])
        by smtp.gmail.com with ESMTPSA id 186sm31138852pfb.99.2019.11.19.23.42.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Nov 2019 23:42:53 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Marco Elver <elver@google.com>
Cc: christophe.leroy@c-s.fr, linux-s390@vger.kernel.org, linux-arch <linux-arch@vger.kernel.org>, the arch/x86 maintainers <x86@kernel.org>, linuxppc-dev@lists.ozlabs.org, kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [PATCH v2 1/2] kasan: support instrumented bitops combined with generic bitops
In-Reply-To: <87a78xgu8o.fsf@dja-thinkpad.axtens.net>
References: <20190820024941.12640-1-dja@axtens.net> <877e6vutiu.fsf@dja-thinkpad.axtens.net> <878sp57z44.fsf@dja-thinkpad.axtens.net> <CANpmjNOCxTxTpbB_LwUQS5jzfQ_2zbZVAc4nKf0FRXmrwO-7sA@mail.gmail.com> <87a78xgu8o.fsf@dja-thinkpad.axtens.net>
Date: Wed, 20 Nov 2019 18:42:50 +1100
Message-ID: <87y2wbf0xx.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=D5sJ4Q1D;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

> But the docs do seem to indicate that it's atomic (for whatever that
> means for a single read operation?), so you are right, it should live in
> instrumented-atomic.h.

Actually, on further inspection, test_bit has lived in
bitops/non-atomic.h since it was added in 4117b02132d1 ("[PATCH] bitops:
generic __{,test_and_}{set,clear,change}_bit() and test_bit()")

So to match that, the wrapper should live in instrumented-non-atomic.h
too.

If test_bit should move, that would need to be a different patch. But I
don't really know if it makes too much sense to stress about a read
operation, as opposed to a read/modify/write...

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y2wbf0xx.fsf%40dja-thinkpad.axtens.net.
