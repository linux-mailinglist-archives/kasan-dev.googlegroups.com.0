Return-Path: <kasan-dev+bncBCT4XGV33UIBBZMO2WVAMGQEBGXR66Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id D299D7ED753
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 23:34:15 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id d9443c01a7336-1cc252cbde2sf2811045ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 14:34:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700087654; cv=pass;
        d=google.com; s=arc-20160816;
        b=IkOchUoB08FIFrm6TyVl70fdBn5Hu3W0jSVKg6HASmVptST9imGsv/jZ6PT+sdeA5Y
         tnTCM0vddq1iLiAJFB5819LKzNTC1NV3TtkWD6cGm3gH9s9zMpdRw/x1D/XBENRPU1GP
         6k5FIVePtiCp4B3MZ+Fb0K3KqQSUyu0QZblaRk+Rmua0wENt45kXJsGDOso0wsRTUj3R
         ErZ2BpXpI0GCwsr32f0QEXPZ17/03vCm4peBpESDnKiSD/W9Ximkp3tsInU45ARdhOI1
         AXOmpx4H3zqQvpUHdUBFQcFtjnUW1+1gb1ex2B5+MjAkwJ5HlKi/AxhUigobBmu4JrYD
         UvUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=1zvadCayYJj4zYfEOG0oGLVFowKVzIEI3ukh3spkPUs=;
        fh=Ebco3sQwiihu9q0KSiqctefkc1akemW7Tbv5qqbuQx8=;
        b=RUm7N3cb0g3c4IIv66fsTUqiBc32oAAj8/OgYmaE0rqW/liDlJP0S66CBiBSZRxUtI
         rb2rtCWUojcvgkbt7+ejBDu7MqGjQ8bmqeGRnePV4Vk4J6fuRxDdqZIt3lUvmq+2nOFk
         1jAxrAMg9m8Dm7GggPdOFbSOnyOQUHDgs9IM6Z0O7WmmGwu3tod9e/1/R8QjW0AXG1VY
         PKa3r3I+R1C8sIBqpGbUInWV39jDo5+u1C7l/6JNo+0GnUP8KzsjdkRl27M2B7nnIOfk
         EhB9Lr4zLF9SNfk3ljabXzu0vjh0GcPSP84S8rM3G0EkKpQ9U8y5vxU1Xxm50c9XwnTM
         XWcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="ZxcdXi/8";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700087654; x=1700692454; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1zvadCayYJj4zYfEOG0oGLVFowKVzIEI3ukh3spkPUs=;
        b=FVGHCWwgdEP+SrktOvIDS+4F8ryiiLanWClNs0sq5AKnuvGN/zBPJKh3BTRvmeaxqC
         Ur/GTYpK2Dugw0GaWBaMhWv5oDBP5xAcPsF8c4eSiHGlaWomuN8+3lo0Sxq4/X9G13hB
         ZfGLjCTKtZW9IxxD/u8xm9pcB35vQRsAyBsZuLun0YIYPox3uZ0S0Ho1EcmSvgj7NaiQ
         zdK5NVKWGOvRAVQanibJH1Y4tbOhvLBHb1/nj/V7RsTDWepClNYpV0mVTxRN2g4Plxr6
         RyVlDn88ies/zF/hXy3ksvbdDxIhOtvEpulh/UV5nhbZn26EDsQNqKw3Yf/tcXT6fcAA
         963A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700087654; x=1700692454;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1zvadCayYJj4zYfEOG0oGLVFowKVzIEI3ukh3spkPUs=;
        b=VlnFUQ6Q9U4ibGzkLfwI18WSBwP+cxTJ1RwZKP1nqePydscbgbj1oUGXb3tjMDg4x3
         JUT8nKAPB2UP7Bnc0sGwOluGDxpH1RLNubQZskAlJV0kWdcibEKv85sTyiyZ6SqpbUFi
         mf2iLPM6zW+wTCPktcFOeYD9ryOypBCD5Puf/3EhA62VI7c21QvGCPgO4xHkvRLsKuBg
         Yoghlp0+ar7nJmPPqQKsHtUGd6eQ9YSGf75fG0G3wbbSuSzakhRGiW7Tn6ArLnLVsELP
         ACQnOQF5vrYabqqL2NeOA2hB03rL815ZPrlxkkuqgBAhfYB+mzcajFmbgYvQ32BWkf1E
         zHSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxGqX31lY6MKuPUNDq1FwvMctWQUpmaQQt5VpY6jVvTbA5EmToz
	4O4o1GSZ+xlhqmubKBVEjwY=
X-Google-Smtp-Source: AGHT+IHsg1cNuQ+wA+dkEp3W/DUICYetDAoK5zvhF27OsTSpuMANzDUSIe+z7Vugvss2Q0yf5kyLow==
X-Received: by 2002:a17:902:f685:b0:1c9:d948:33d5 with SMTP id l5-20020a170902f68500b001c9d94833d5mr6365365plg.64.1700087654116;
        Wed, 15 Nov 2023 14:34:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d48e:b0:1c6:1fac:915c with SMTP id
 c14-20020a170902d48e00b001c61fac915cls206152plg.0.-pod-prod-04-us; Wed, 15
 Nov 2023 14:34:13 -0800 (PST)
X-Received: by 2002:a17:902:7e88:b0:1cc:3ac5:57dd with SMTP id z8-20020a1709027e8800b001cc3ac557ddmr7042089pla.9.1700087652964;
        Wed, 15 Nov 2023 14:34:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700087652; cv=none;
        d=google.com; s=arc-20160816;
        b=EnduphA4JGjBytAO8sLnCG6UAHsRH5mUdrFreL/fcRw3taWi5EnDsQeElFrmJuUoWE
         JnrjIo59zy8nH+rmQdazmrk3yo28+4vOW4ez90XwsxjfQYiWsmXXHn5jOuibO3cevtG5
         IiPszgztwEgrxyfqIpRF2UsBJwSsy4JBUlhB4PugMnndskWeck4L+qx+rZFHQ4grF36N
         RjfZ2SELx/HWkmoytuKvKjI+gz9teS0OW1gFwNIk1KLktQQy2bG9k+uPDcKIPjcp1GZE
         Mi+OFFADSyqH+O1Ir1bVo3ZnhYBCg1t8WRn2pxWMSotqbZkZN79NI0Agt2PXsJ/2lZg7
         SD5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=sE1fpMefd8k+7Ak5xqXXC+uAK7Y4A27kQqA1FCoAyvE=;
        fh=Ebco3sQwiihu9q0KSiqctefkc1akemW7Tbv5qqbuQx8=;
        b=Lcimokz/sj2RfoDRRVwUp2RVLo0s1VhCm9qm0ryNyZRqrS7o1zD9gFtiE9AsXvuagr
         0XWRC3UkG0osom9apV6NRlM/pcSwoSsmpHGwrtxjYWydjU1luSDSedLb53vARvILiprA
         NoWpYn5pnS3iCQia2l98/uwEKMpDb+pdnA79OHJVF0BDpfA9GqK5rDWem0ygO1HaUMYW
         Pn5o0BabMcGcW8wuNO6NSOV3JmqS2fNzVfhtmIdvkREEJFSfTpKJPEKe+MGSYj0BBQW/
         IctHr2HktZCmDTINdFyin1rEU5EAoUqYgwXZBnukjjH/BM3vyFtsALN0lGeEX/84Roba
         Md7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="ZxcdXi/8";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id jx15-20020a170903138f00b001c9dae59993si576741plb.13.2023.11.15.14.34.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 15 Nov 2023 14:34:12 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 39B1A617DA;
	Wed, 15 Nov 2023 22:34:12 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8C64AC433C7;
	Wed, 15 Nov 2023 22:34:11 +0000 (UTC)
Date: Wed, 15 Nov 2023 14:34:10 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Joe Perches <joe@perches.com>
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Paul =?ISO-8859-1?Q?Heidekr=FCger?= <paul.heidekrueger@tum.de>, Andrey
 Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kasan: default to inline instrumentation
Message-Id: <20231115143410.e2c1ea567221d591b58ada1f@linux-foundation.org>
In-Reply-To: <918c3ff64f352427731104c5275786c815b860d9.camel@perches.com>
References: <20231109155101.186028-1-paul.heidekrueger@tum.de>
	<CA+fCnZcMY_z6nOVBR73cgB6P9Kd3VHn8Xwi8m9W4dV-Y4UR-Yw@mail.gmail.com>
	<CANpmjNNQP5A0Yzv-pSCZyJ3cqEXGRc3x7uzFOxdsVREkHmRjWQ@mail.gmail.com>
	<20231114151128.929a688ad48cd06781beb6e5@linux-foundation.org>
	<918c3ff64f352427731104c5275786c815b860d9.camel@perches.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="ZxcdXi/8";
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

On Tue, 14 Nov 2023 21:38:50 -0800 Joe Perches <joe@perches.com> wrote:

> > +LIBRARY CODE
> > +M:	Andrew Morton <akpm@linux-foundation.org>
> > +L:	linux-kernel@vger.kernel.org
> > +S:	Supported
> 
> Dunno.
> 
> There are a lot of already specifically maintained or
> supported files in lib/

That's OK.  I'll get printed out along with the existing list of
maintainers, if any.

> Maybe be a reviewer?

Would that alter the get_maintainer output in any way?

I suppose I could list each file individually, but I'm not sure what
that would gain.

btw, I see MAINTAINERS lists non-existent file[s] (lib/fw_table.c). 
Maybe someone has a script to check...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231115143410.e2c1ea567221d591b58ada1f%40linux-foundation.org.
