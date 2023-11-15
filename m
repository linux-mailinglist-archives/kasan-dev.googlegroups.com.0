Return-Path: <kasan-dev+bncBCT4XGV33UIBB2MW2WVAMGQEB6J4GRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 529F67ED7A0
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 23:51:23 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-27ffe79ec25sf142606a91.2
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 14:51:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700088682; cv=pass;
        d=google.com; s=arc-20160816;
        b=PYhUIeB00TOraYLJIk/aOfahqw4H5N+GITtEPqhlYZmfF1Zo7C14KAfY7jlEDvaGLg
         VLKCuFDU4IpHHZexckMIWNNmDPi4oq9lf3jEQhnJmg/XMUve8WRbW2+VgV2qMHgJV+KU
         FGoPrLXd9EChK4sOF9GJNKk8P1xeMjrNLRHeVU9MWdZAB9DhW3YCbInD4WeoaXzyQZjX
         7hgB4IJ/GLCjTT6rbGuENP2q8yFf5UTYOSWbRjVYFeLAaZlWV928FiDN77WvgkMFnPd6
         Kjmi5iii+Krp0XmI/s2oSHxUiXPxdZGWFmdRPBV559dG/SLOZ6VZKkwY5VAmMFk5BIdb
         WRJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=kk1iPNoaDTrlVyIHPsUYO86l2mywL62ZudIzpEioBRg=;
        fh=Ebco3sQwiihu9q0KSiqctefkc1akemW7Tbv5qqbuQx8=;
        b=Hl6iODYkg0Z+UgKF6J+nAEpTJAFw1mG2WOx6fNin8JP0VsP+Jg9A7gTUezPdoQxWD5
         9i6Q3iqBdUTwRFVXyuLghS6Eru5yQwCSq34JQa9NrKB3c0Z1xtGnMLNIefFHWBsaZ3zc
         6jZEZEnoQygAwWCVMt1NY12eUMosnsCmalrQw6h8AGIfuO43ZLukuuo4pL64AIClMJjU
         Psucz/JJHEK/QTjhY8/ExnZUKXQ8IyGqSxk7Zl/hhVjp/VjZWFEgPkkDaokmzWymL1F3
         hdDknDKEm24UEGggO1od71O8Xb90abVTBOY8nxf8nnv6k6fwJsKtmiYRGe/wT4nEeRZ6
         kXqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=iWPZ+3c+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700088682; x=1700693482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=kk1iPNoaDTrlVyIHPsUYO86l2mywL62ZudIzpEioBRg=;
        b=qopXLwv+oIGDHdoxrm1ioTK4WWznla0Yk0yoNR7U0ROM2tlT/JFXodWrkY30E9dXk3
         DCvOXrk+NotsU4a7cJJujzYHCw4wLlWeI4Nd02qfNhdo3zy2PRMTlCokRDxDq00DTawJ
         iFHbcRM68JFNJ6z5LZPBF89pkLseAIsHa+Ao2iNpan98Yk1MXfurK2qxCMSsKvN7RpdT
         KCdhHLB22eu47z07Ij0BoPoGEBIHAiUN2E4miX6CxPDKrqmV/D8lroXI6kIY66MbWVfd
         cYwhTpAa2jHdHClh3AnWTVis1Ogl4pf0AeSfYkeBPKx6fDIkjjlm/0Avla/CG9mi2lwR
         UlbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700088682; x=1700693482;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kk1iPNoaDTrlVyIHPsUYO86l2mywL62ZudIzpEioBRg=;
        b=LFQ3CpNgVdXRNWpOFuTD4qmP7N0clMNlpkPZonRUd7sDNirwurZCMOh1BsPhXfRX1K
         O4xhqsCBS0d6lLGOcI6Gp52JFyKqDTDnnK34LbQCnvN/yXcOUdAzvp3ZedLqx2WRrENw
         NA5w450k4GPTUsnH1ic2amvjMWAUZ2DbFjU9W6Ue/+NZtQ8V4FHMviljHG7XVST+/qE4
         apy8Yc9t3JQY9rjhAhE4GzH0Cj8wlSCxqZJycNt/OpGHoBzuwj42M5b6wTOUoXUWVwQi
         79DvkY/PSSudrgl17S3L2WiIWI86eL3dPSCyfIoNupyYJCt1vl148B5pKMolc9hm9DP4
         nhgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yyve2LeczI5DQ2l5vlOEFK6EbLOjIO64Q+NXtBeuqTKfurf5H3p
	yKiaEPawuUrji71wiwH2Nhw=
X-Google-Smtp-Source: AGHT+IFuQDNnC5ojYbBEiZG/Hwi0/K0BjqtRpOAD1BWaaQf7q8loILYqIwJUsd72X+XtcKOXZZ4eZw==
X-Received: by 2002:a17:90b:4a05:b0:27d:1d1f:1551 with SMTP id kk5-20020a17090b4a0500b0027d1d1f1551mr11421961pjb.29.1700088681810;
        Wed, 15 Nov 2023 14:51:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8a0d:b0:280:8f13:2e91 with SMTP id
 w13-20020a17090a8a0d00b002808f132e91ls155463pjn.2.-pod-prod-02-us; Wed, 15
 Nov 2023 14:51:20 -0800 (PST)
X-Received: by 2002:a17:90b:33cb:b0:280:1df1:cbc7 with SMTP id lk11-20020a17090b33cb00b002801df1cbc7mr12387056pjb.19.1700088680627;
        Wed, 15 Nov 2023 14:51:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700088680; cv=none;
        d=google.com; s=arc-20160816;
        b=uC2onRjq9DWJM4zoTlhZrLmN3TUeSylIugYeLsOZb8Dm+T+gc6fmTYROjDRAt3bG5G
         KvD5OvbaWJFH9T2/vDN9DNYGeOCshoKZJ136gl20fj9Hndhtw1aY0Nx/AL7NhB25vkAz
         ZfVYun1E0Ke32wS5CBTZRnmoGlI2l9+ds1/mVir2aQlNnsA9DZkaQINRFy6h7xrQqmVS
         AMOuErRiQdHDFbj4Zm83v48veMypGEu9Z5c93AaJaEFc6ho0kZKfMDEqsVl5DFmQc/oa
         Jb4y4KaF7NUrVHXeJpa3cn3G5GSqbABCYUvKfFz82ACg92nd/LOAhVNv56yrxSEQDcJv
         ZyEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3gSaGtmpb1CmRUgvNgduujzpSfoAMkMs/HNCCkbGd5o=;
        fh=Ebco3sQwiihu9q0KSiqctefkc1akemW7Tbv5qqbuQx8=;
        b=YxOM+yIQwMibOeoJs+h2QBoJIiQrJLWLwcAqUPYxufTGpQegBdxnvi33DrZdXlI92T
         mIQ6w5rLoGmmADUqK4zokJAphjDDsUxLoun6gt5mKa25/75T3PJYSXwJmYm3QEmh+Y4t
         UnHpZQl5P8UMQbKuVdKcIM0wSFMpiERBjH+IX1Ct8ROQZy4sUdeHoq6HAFrKyHXzkzYA
         T026ffGKNPmiuZNg6aBV5XF/j0D4IW/yc25wIzxScVjw6u/aZe0C70Hf8lVvQgQ8iIYj
         iKcWaNJh+7xCyrT3+J6RI7g3/vsLjdNyBXdSFvkyN5Bffnoz7EtAsg5OvKci0zY+2L3N
         xQYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=iWPZ+3c+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id j15-20020a17090aeb0f00b0028000e8c2absi231949pjz.0.2023.11.15.14.51.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Nov 2023 14:51:20 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id DA90061841;
	Wed, 15 Nov 2023 22:51:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3F15DC433C8;
	Wed, 15 Nov 2023 22:51:19 +0000 (UTC)
Date: Wed, 15 Nov 2023 14:51:18 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Joe Perches <joe@perches.com>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Paul =?ISO-8859-1?Q?Heidekr=FCger?= <paul.heidekrueger@tum.de>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: default to inline instrumentation
Message-Id: <20231115145118.76b226d0ba4bf059203ebe1b@linux-foundation.org>
In-Reply-To: <f9f628a0685b948898a83e7946833b2f5c5a1e7f.camel@perches.com>
References: <20231109155101.186028-1-paul.heidekrueger@tum.de>
	<CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
	<CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ@mail.gmail.com>
	<20231114151128.929a688ad48cd06781beb6e5@linux-foundation.org>
	<918c3ff64f352427731104c5275786c815b860d9.camel@perches.com>
	<20231115143410.e2c1ea567221d591b58ada1f@linux-foundation.org>
	<f9f628a0685b948898a83e7946833b2f5c5a1e7f.camel@perches.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=iWPZ+3c+;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 15 Nov 2023 14:48:38 -0800 Joe Perches <joe@perches.com> wrote:

> > Would that alter the get_maintainer output in any way?
> 
> Not really.  It would allow someone to avoid cc'ing reviewers
> and not maintainers though.
> 
> Perhaps change the
> 	S:	Supported
> to something like
> 	S:	Supported for the files otherwise not supported

That's OK.  I actually like to see what's going on in lib/.  Sometimes
I discover things in there that surprise me...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115145118.76b226d0ba4bf059203ebe1b%40linux-foundation.org.
