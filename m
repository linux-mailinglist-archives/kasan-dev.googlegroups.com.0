Return-Path: <kasan-dev+bncBAABBEFRRT5QKGQESMXQ7UI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-f64.google.com (mail-oo1-f64.google.com [209.85.161.64])
	by mail.lfdr.de (Postfix) with ESMTPS id 800AB26D591
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:04:33 +0200 (CEST)
Received: by mail-oo1-f64.google.com with SMTP id e9sf783525oos.3
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 01:04:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600329872; cv=pass;
        d=google.com; s=arc-20160816;
        b=VlQNhHFgG+rWMlN3tRTasEmowIXahTRoyMC1zvd604fwuVOOauXpkVfoWFRTkUYors
         dSO8NiqSriDNpqlqh7pTfRQWdotHwT51s/EEaSNQLIWjQWm+l76lhRAm2oCdVo4fVZjb
         sjfWTi7Iih7LSaJrPOf1yvhhSdCYkq2Gc7LXEOXFTkbyEh2CxkaOWC/+GS/MgoQ8hWZi
         oksV4Xr+Xnm5LgaBXOM6hcE6L3kQ2wfJr7S+G6PzPyZf/KScQHBim4qcfInJkqvozKim
         pQrDAodKaR3TPpcyxFkmNIkX1GR3r6cqCPZgf407pULUP9Vm7Eqtl1czPmHPCakCNXzU
         BpGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:mime-version:message-id:date
         :subject:cc:to:from;
        bh=4ZfFaUO3fMdVcHLeG/f3bmquR1ZYMcBs51Ehi/lDhm4=;
        b=vjQofj68e0UKCI4eW/t8QF8zfn4GXCpGHhPlhKaVZ97t1QfL1tatjIBxzixEY51jxZ
         LtccTxsQo9mLvSVDVLVY00sK2/cbsGklOK4CP+fd1v+f5hzcwS/aJBakC2yXI3piYe8d
         E5sqni7fEpJ7BQNAmvoCCz1v/wNM31iPOV9gGylq0GoJBfjITmsJyh2AR6Ju9j8+IS5y
         suXaK004ETHXwjRguSsuSC9366x7AHBxAThAFDSkFdKKHHT5EhHGY9+uE92a2cHonE7/
         RNvL8Ey3FD1HMM7lqjPb/SJdMif8ekurAviE6XpSZUHlaX1Pmid8lXG/Fs6U9UcFg3jc
         gP/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=JwMinYkF;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :sender:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4ZfFaUO3fMdVcHLeG/f3bmquR1ZYMcBs51Ehi/lDhm4=;
        b=AcCIHhUqawSyQSe6Ss61g5ih0oh37lZC5+5z+pCPLXrDjJXxaWsrA09jdkBmCe3cL/
         UVGTv/6We9afYhLhiDiUaFXVJ5kdcj0U2SkLwBkgRFqQ6NXNlsarPI7CzLzQotf80q5F
         SfFiaCIMQhkTBCxwSXQyUgGziLNPEqJFdWZ/BmZCSOeQzCcv7ITdVUe8BjmnUudXPx4I
         /HtxwUAw/s8Gz+8eMiKgy1YMULuc9omxgoZjppFCqBDehjuWH10ke0FXo8jkWqsCD7xO
         R19SOH36rv9AUmGnK1oEbCwL9zU7ve0H6jpWdbOWOPwB5yd9wBawC596UAFeiy822/C/
         FpAQ==
X-Gm-Message-State: AOAM531cY7rCgy3fBn1VYU3is4gC/Tkx4EKBBi6TmO213u1S/4P6d3qi
	7O74bDn3Q49v7n8TIHea224=
X-Google-Smtp-Source: ABdhPJwXY9JND29ke6ZYrnNOTDP6M8YLU5DPrLCpjcQJniraDRA705iK5bGkhdZ5mxb4spqHuGlTUg==
X-Received: by 2002:a05:6830:453:: with SMTP id d19mr6070927otc.130.1600329872186;
        Thu, 17 Sep 2020 01:04:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:3a07:: with SMTP id h7ls275024oia.1.gmail; Thu, 17 Sep
 2020 01:04:31 -0700 (PDT)
X-Received: by 2002:a05:6808:b03:: with SMTP id s3mr5750628oij.28.1600329871849;
        Thu, 17 Sep 2020 01:04:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600329871; cv=none;
        d=google.com; s=arc-20160816;
        b=Xl0S+8Ny6/xy7fIJiMYzqViKP4QT9JTMBlZONjRp6ycC08s5uZspDJ9GgVFP/3OzwT
         fiPwOJHqaw9DJEO0+kfr63czt1KdzDBn8/aUCsxR9C4KooLHsS6zs0nWW6nuokudO5hN
         Hb56sBMckYce0X6z4sEliUgI7ob0YHeqOvtyRP5r58w6dWlUo0u1BFLmqydomphbExww
         6oHhBvqcnqCUmVXQQiWJfCDxwK4fgXpanB6lhoZa5tmLSnDyI4JIQ3ThTJMlVwi4Gohg
         2BWpn6a44x1F/Kw+XSopDq4qLGWOGWaEyrNVFW0F6Ms0c3CFw2fkBDunlcgRS1L1Ledb
         bTtw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:content-transfer-encoding:mime-version:message-id:date
         :subject:cc:to:from:dkim-signature;
        bh=MRUWLuD3Kucl+PKAgp1jMstJi6HI4ov4qpe3oBcRKDc=;
        b=Qq569c23RSYe0W72nEA/qJscK1xU51s/2nCiXJ0HisF7arKhJxPbkYvVVeTA573RSl
         Lmv0gf4VKIswLdBEczt8pvaK7Z+b1oyBWwP3dBUtsotMMd7SZOqrfG24KP8M8Y6axFME
         sFkg6pKoZZHO2xyBj2ME2DkC/j6IQo84jXl2+L5QYYM2v7bNJxuy9BlS6ZnEy5RpGBaJ
         f4qwY4IrfecCv1CQG37FAdnoj7CdlqeAam6ojHXzDjOlIOOFXuvnuHUGTNUbnjXAcBJk
         rQ0gGS1KHMGENKmJ/Hg0yysrcG9+zo3w+pgshu95q94i71tBkA69l7Mg22jd7NXmn9lM
         qjZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=JwMinYkF;
       spf=pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=mchehab@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d11si1860839oti.2.2020.09.17.01.04.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 01:04:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from mail.kernel.org (ip5f5ad5d2.dynamic.kabel-deutschland.de [95.90.213.210])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BC07920707;
	Thu, 17 Sep 2020 08:04:30 +0000 (UTC)
Received: from mchehab by mail.kernel.org with local (Exim 4.94)
	(envelope-from <mchehab@kernel.org>)
	id 1kIou4-0051LO-6j; Thu, 17 Sep 2020 10:04:28 +0200
From: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
To: Linux Doc Mailing List <linux-doc@vger.kernel.org>
Cc: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	linux-kernel@vger.kernel.org,
	Jonathan Corbet <corbet@lwn.net>,
	"Matthew Wilcox (Oracle)" <willy@infradead.org>,
	Alexander Potapenko <glider@google.com>,
	Alexei Starovoitov <ast@kernel.org>,
	Andreas Gruenbacher <agruenba@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Andrii Nakryiko <andriin@fb.com>,
	Daniel Borkmann <daniel@iogearbox.net>,
	Dmitry Vyukov <dvyukov@google.com>,
	Guoqing Jiang <guoqing.jiang@cloud.ionos.com>,
	Jens Axboe <axboe@kernel.dk>,
	Johannes Weiner <hannes@cmpxchg.org>,
	John Fastabend <john.fastabend@gmail.com>,
	KP Singh <kpsingh@chromium.org>,
	Martin KaFai Lau <kafai@fb.com>,
	Song Liu <songliubraving@fb.com>,
	Stephen Rothwell <sfr@canb.auug.org.au>,
	William Kucharski <william.kucharski@oracle.com>,
	Yang Shi <yang.shi@linux.alibaba.com>,
	Yonghong Song <yhs@fb.com>,
	bpf@vger.kernel.org,
	kasan-dev@googlegroups.com,
	netdev@vger.kernel.org
Subject: [PATCH 0/3] Additional doc warning fixes for issues at next-20200915
Date: Thu, 17 Sep 2020 10:04:24 +0200
Message-Id: <cover.1600328701.git.mchehab+huawei@kernel.org>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Sender: Mauro Carvalho Chehab <mchehab@kernel.org>
X-Original-Sender: mchehab+huawei@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=JwMinYkF;       spf=pass
 (google.com: domain of mchehab@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=mchehab@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

There are a couple of new warnings introduced at linux-next.

This small patch series address them.

The complete series addressing (almost) all doc warnings is at:

	https://git.linuxtv.org/mchehab/experimental.git/log/?h=doc-fixes

I'll keep rebasing such tree until we get rid of all doc warnings upstream,
hopefully in time for Kernel 5.10.

Mauro Carvalho Chehab (3):
  docs: kasan.rst: add two missing blank lines
  mm: pagemap.h: fix two kernel-doc markups
  docs: bpf: ringbuf.rst: fix a broken cross-reference

 Documentation/bpf/ringbuf.rst     | 2 +-
 Documentation/dev-tools/kasan.rst | 2 ++
 include/linux/pagemap.h           | 8 ++++----
 3 files changed, 7 insertions(+), 5 deletions(-)

-- 
2.26.2


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1600328701.git.mchehab%2Bhuawei%40kernel.org.
