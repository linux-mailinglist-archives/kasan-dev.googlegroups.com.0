Return-Path: <kasan-dev+bncBDDL3KWR4EBRBWG5Y6QAMGQE2CBDA2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B6296BB941
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 17:14:17 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id 7-20020a5d47a7000000b002be0eb97f4fsf3365629wrb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Mar 2023 09:14:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1678896857; cv=pass;
        d=google.com; s=arc-20160816;
        b=m1XjwwMqGc/OUdaEz7ICSXScQnXIPqznba3o+pgVoljzspP5+4SP4U+pIbLLHOXyYm
         6VZ0emQ1Yc/cJ8MTc+QQua7FWZwcMZ5UNNvBYxyHbhVUGoddHFyeCf9Jhuxuzgyd4HGn
         2aZ4gs1ZnMJQLWfX5qNK8roNA+IBiY5grGU9dmNHk3WAY2x2Oi5+sG2Lx4r4w+nf0z64
         f2qMfc4GMfPQPh8s3Lfep1fXVkRSg/2pM0mGA5x0Pfv6sq9NlBRv/yyCu3QeTAWWfoYH
         wNXi6LHtovpCFQSa/55BAlYJnumnvb5aEji1tBSl/gLy7ncT0d7qVpsqFN9eD61Pi9mk
         w4Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=BBud5JXCcdanWsHG5jB4oNFqA5bL2iYVQYuwzHjcg98=;
        b=gFSaKY4m4+hs3zAKZi58PkU+OHkRAbAhf8IgPfAZx1UsIwBG/9wooai5gNnNNDZMsk
         eSSzIIIXrp9wDocKHYTNMKskwIIXocWWpiM6agyXMuMWq3W4wFEP7lf0NpfM9ONPIxpl
         XNSOv0k/pgYN+O7xQREzZkreUXqXim9dxjT/cxJgaarCTd/o52bN0aIq1YgIQlEKH61a
         A3jqq73CB6Sjqp2DcY6FGXbeeSXOWklCLO07X5DH7vuS6u/AkU0NwxCuEppS9ZjkaMc+
         hKoz4cbZ3DZMfseUc42JeSTj8Oj9OLHFWGIRFIEF8yue2lUNIgzYHFAYm8Mu49C0ldYm
         Qn6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678896857;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BBud5JXCcdanWsHG5jB4oNFqA5bL2iYVQYuwzHjcg98=;
        b=pq79sP2c4wQ+WchONFNnkADEpHkMlK1jjOJPilPAMTDgaV+rweSBXeZpYca/Xd7dk2
         fkZhTHn23mvgn+3OLSWGlLShApwGlg579lLL9AeoGY7QgdqLGI5Ha/IqRa3kRUqnaz5w
         bdPRjH39evyPzidsn8OmX9yjHqM5pQZHxpMmJnVB4VLotkqEyFdNKjNl1Zcy2Cw1asnn
         kUdYzcCwzAitcSfcNg9L1NnYZw5/rYLWXfGkJW4Uq9g2/nqOGpfwNZGfH6wWqAJVyEnW
         xV9jDVJ2o2ojWGmxpSu8JuotYKZ8U5dD+B255o827CqF9BaIokDTNfox39HVrVdYKjnr
         V6/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678896857;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=BBud5JXCcdanWsHG5jB4oNFqA5bL2iYVQYuwzHjcg98=;
        b=PdbFlXcX+6hxqbYJABA03/NaXyFIWF1rvj7T0wy2UamJ4YccdgnnYRAXtdKc4gtj4a
         HH9UkkKQccLU+W970YSF7O6mvptVGXP+yNyn1fPZwEuMN6TIwZLCvjDCmyjfXJNVvKhP
         v684VVp6T8qR7jyW7JXOcfbHcikj7DhpDDunJpItulSmMthlmCsVAJsA3YrxIPsrQvCR
         ivTSeaiPWJBDqSVzvpWYYMw6VGN7OSlP6gfVYwiRoVIXnpRR+HNWVcAIhgMANGuQTk+P
         aupL0qR5yXJNiCq2prymffG+MD1d2F5l9AFV9HW8IEQ6d0QxY4O9+F2tjrm9U1caP9hD
         wzHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVFsxuFJPDg5oz48gzJULBG+zcx0YXDMvyyzfdZRnuLVrOCD2+R
	nx+A22cLJpi/zRx4tZh+jwU=
X-Google-Smtp-Source: AK7set+p81R57jk7fIvBWbD1vroKT+iv+9aDaZwC37PKftCZ5ht1n4hWhEk8sQ51Yp3dlaEox8U/ig==
X-Received: by 2002:a5d:51d1:0:b0:2cf:e6d0:6379 with SMTP id n17-20020a5d51d1000000b002cfe6d06379mr688233wrv.6.1678896857038;
        Wed, 15 Mar 2023 09:14:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1992:b0:3ed:2f3f:8597 with SMTP id
 t18-20020a05600c199200b003ed2f3f8597ls1431998wmq.3.-pod-control-gmail; Wed,
 15 Mar 2023 09:14:15 -0700 (PDT)
X-Received: by 2002:a05:600c:3ca7:b0:3da:2ba4:b97 with SMTP id bg39-20020a05600c3ca700b003da2ba40b97mr14822942wmb.19.1678896855484;
        Wed, 15 Mar 2023 09:14:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1678896855; cv=none;
        d=google.com; s=arc-20160816;
        b=mwt9yxAGhnQeBqs9adMU1MXnJO3GbnAV2h5IOfagVqGFh3PEOosehXrf7QNnj9gk+p
         ZacyRTMI/ww+Nn3zTYxHFpeffPAyngNWVKHGJ3Nqxar3kXSLoPlnRY8sJ4xeJJj86tZD
         JoaMEtk6vC4eda8UkCVE7NdZd5/FzdZGXsH3xIuMarDteUWU8WdmJ4SuMASBzoMDrvxo
         1PvTqyGNTp4Hbs0sOu8oVQ95ClRgedIxoYCtn3DdQ8wYGee08QpcOCB0qkwjwfeNIw9B
         f4nK24upxTYAd3E6c0761OG2/mSO5+oZNQxulmjmx1RZauTlUbKxEw0aaFcKlpmOBvQy
         nPyA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date;
        bh=nZthY0/asZyctHEIC32DoXuEUzPdqSM1HWUTVNHBwls=;
        b=Z8+M3aL5a00yQNi1xZDouqn1MpiPNDYKUbu8UTai3MJbii39IORYNEYmTvCmo15O7y
         7Lj8LF91clyN/m4OWTcboo2c3w2817gRYcRGiMLZaaj2OBjZ6Cvp5Sr5AqSHvXTpluJc
         WfPmNVZO8jx0ASCVU+MszirbleXreycYJvNbmN64bUbBI86b+BHsjqS4YVgFaa5oYSkM
         /5Thro4fQ+b2tY04eY8X1bsW32rPO+wRbKcQz5VGV7kEWC11oGh47nhWj5QDr/WrFTL3
         6Qj6aLDaqQrPRWvYnKXzu1guLLpUicX0AAXrEy1lkPk4cICLmuf6Nemc837gyxI54NWL
         oRqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id az35-20020a05600c602300b003ed2382d2fesi127530wmb.1.2023.03.15.09.14.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Mar 2023 09:14:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 33603B81E67;
	Wed, 15 Mar 2023 16:14:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4CCC9C433D2;
	Wed, 15 Mar 2023 16:14:11 +0000 (UTC)
Date: Wed, 15 Mar 2023 16:14:08 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>,
	=?utf-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	=?utf-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>,
	"linux-mm@kvack.org" <linux-mm@kvack.org>,
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
	Weizhao Ouyang <o451686892@gmail.com>,
	=?utf-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
Message-ID: <ZBHu0Jk/erSOhD7e@arm.com>
References: <93b94f59016145adbb1e01311a1103f8@zeku.com>
 <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
 <b058a424e46d4f94a1f2fdc61292606b@zeku.com>
 <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
 <CA+fCnZcirNwdA=oaLLiDN+NxBPNcA75agPV1sRsKuZ0Wz6w_hQ@mail.gmail.com>
 <Y/4nJEHeUAEBsj6y@arm.com>
 <CA+fCnZcFaOAGYic-x7848TMom2Rt5-Bm5SpYd-uxdT3im8PHvg@mail.gmail.com>
 <Y/+Ei5boQh+TFj7Q@arm.com>
 <CA+fCnZdFZ0w33GcUWRfWhNmYkhszQ0gwVKGeY0uSOzBEJJe27A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CA+fCnZdFZ0w33GcUWRfWhNmYkhszQ0gwVKGeY0uSOzBEJJe27A@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 145.40.68.75 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Sat, Mar 11, 2023 at 12:42:20AM +0100, Andrey Konovalov wrote:
> On Wed, Mar 1, 2023 at 6:00=E2=80=AFPM Catalin Marinas <catalin.marinas@a=
rm.com> wrote:
> > Yes. I'm including Vincenzo's patch below (part of fixing some potentia=
l
> > strscpy() faults with its unaligned accesses eager reading; we'll get t=
o
> > posting that eventually). You can add some arch_kasan_enable/disable()
> > macros on top and feel free to include the patch below.
>=20
> Ah, perfect! I'll send a patchset soon. Thanks!
>=20
> > Now, I wonder whether we should link those into kasan_disable_current()=
.
> > These functions only deal with the depth for KASAN_SW_TAGS but it would
> > make sense for KASAN_HW_TAGS to enable tag-check-override so that we
> > don't need to bother with a match-all tags on pointer dereferencing.
>=20
> Using these TCO routines requires having (at least) migration disabled, r=
ight?

Not necessarily. The TCO is set per CPU and disabling preemption (I
don't think migration is sufficient) would work but these routines are
also called on a uaccess fault path, so it needs to be preemptible. We
used to clear TCO on exception entry prior to commit 38ddf7dafaea
("arm64: mte: avoid clearing PSTATE.TCO on entry unless necessary") but
we restore it anyway on exception return.

I think the only problem is if between these routines, we invoke
cond_resched() directly. Not sure what the kasan code does but disabling
preemption should avoid a reschedule. Another option is for
mte_thread_switch() to context switch the TCO state.

--=20
Catalin

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZBHu0Jk/erSOhD7e%40arm.com.
