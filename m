Return-Path: <kasan-dev+bncBCV5TUXXRUIBBNE33L3AKGQEP2SFYBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F0951EC0FE
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Jun 2020 19:34:45 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id n37sf14745443qtf.18
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Jun 2020 10:34:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591119284; cv=pass;
        d=google.com; s=arc-20160816;
        b=vAzWFMEimdVhckLGal3QG/CsYdoKqos0tPOwq9YkGHxYVi4fIxMS6HdzcjCupLn41J
         C6u1D9vzvXDgKQ6BHAosBBhQPtCZAaZ6NoXj5wF27//1b5teEL4Yf4nxJNcpqfb9xMM7
         X7+v75jXvQnUfCAVBuQvlz/ZgsZs+UOx/DvRgTSw7zMWN6DBFTM3uITC4WcTNIxtdb2f
         GUKCPOmGtGfLzNU6/u1kpaloPSgDCUaiL0eaCaMSgDwRDZxbjoK0zhLE2NG4yDJO4IXF
         Oz+pl3TtYNiTg1Buz0hc2skG3KqB7uWeeo9jgIey5WyvGL+cRan16pTJ3qDpO0tU2xi9
         XiBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:cc:to:from:date:user-agent
         :message-id:mime-version:sender:dkim-signature;
        bh=h5GAQBaN5UEhk4Q8XNG8N/XR3SuHMvmxPj2P4slIJec=;
        b=GLyItA3US1ulImDlfFBW+mEnMs2aHNeB7UvEvlrq59lmbnvPvhVZ3fWD8UJbGu3nTE
         B4GxtPK21RMh/ettdaRSApKoL96Skd5AIxXHkedppWyatK4s6m9IUTSRrl2+BhyFZZUX
         xojil5r9L6baQDRigbdiC1xGdXcr/Jtu95ySoNXEU3z5z2IyidV68ox6C/SqL8PjMrvU
         eKGmGbhxYMg/JGiA8fKupw4FPH1Pu+ozXW+SffWbY5SczdCq2AibF8nmzs18IP0StfHk
         wKkLratH1Vw5HGo/bsdkKvogHzVI+J3JkjfqnUAniCL8GR8tfDjnT+A2pGNhAGb9SR/N
         4sTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=bgDNsT7I;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:user-agent:date:from:to:cc:subject
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h5GAQBaN5UEhk4Q8XNG8N/XR3SuHMvmxPj2P4slIJec=;
        b=IAdnKl72ELwoR26O/a+YROYBh04OwzMrtfq7JF0/8evoDOaresHtraKUUCLHReLkZh
         An4J316C+f/5sy2m9R7mKa6ZNdtKKokp3jzo2tg1tNBKfay9Dc7oXL0wpzCdHe009bql
         ypctAHH++s0mdSz8uBHshYscx8Pyf9zkPbiCaThM6TXaRQEzRpTAaQfl2O1TCkwjzYCb
         Hb+JKj/N2ExZO5551CVLfc2jXBVulIneNGdh9AIoLOHfugYAcLIL5xyCCBAi6DXQ2E38
         ztPrZjErtqUW90QziHXU48HYaQMhx5FCmd2WlKx/JR0yacS06rS+0nvUiadOVFTH8Hng
         U53Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:user-agent:date
         :from:to:cc:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h5GAQBaN5UEhk4Q8XNG8N/XR3SuHMvmxPj2P4slIJec=;
        b=Cb2ITLo6wE6AfiX/+NctBo43OB8etIXsM0N2x709PGyc2gijG2jeQhLsD9+svRGMHy
         otqBljoJFCxeBf0FU70nD1YrlQU5zULwm7B5ksp3UfJbvgUuaxb5uDXCVWD9VFQ2Gk6E
         5pP3qF5gY0/6e8ZxYnRlZ6G1k8mpMBl1o0BPNVS8LvoyT5Vx8Llzb144d9APG2BgHtKD
         1mVTzgZl2zdKyqJ/wjiSkeK96KYSULF4FD9nH94GbNYWnNX77QFsX31fyjdT/9xNHH3h
         suMoBrEaSr+1hGxE1FRdzyDuc49ZuGAK5mXOHZO6DzsTWL6atZJjJqtoG/1lEiuqqxyv
         pHOw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532f8eSbxedvOBDveiBEYK6zKVIR6wSa/0cJElplT4R7SjTMfHRX
	FjBr3fEhXWSl7eoDKf77NLk=
X-Google-Smtp-Source: ABdhPJy+hZJgNm61lgzi8r6ipgWOx/okgGAVdeYV50aHqLSPkgcIDGscnjPtTy/faErS+Grjtgb+FQ==
X-Received: by 2002:ac8:263b:: with SMTP id u56mr2945485qtu.388.1591119284458;
        Tue, 02 Jun 2020 10:34:44 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:658:: with SMTP id 85ls8925535qkg.4.gmail; Tue, 02 Jun
 2020 10:34:44 -0700 (PDT)
X-Received: by 2002:a37:74c:: with SMTP id 73mr25977962qkh.75.1591119284106;
        Tue, 02 Jun 2020 10:34:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591119284; cv=none;
        d=google.com; s=arc-20160816;
        b=gpa23UGtZp8X3xvFEAhd/GYWhLAwmWbn8kYrUDw3mGx0LmWaq5629zmAvhocaPKmDl
         kdIU65Ehv5Sx9cNxs8iVKT2HH7Eg2D1or6TOc2tOtiMoKYeCIk2d+v5cHL4VPrPn3suS
         GD5TTJabUXtxtuel1TuHdH+/V4NJYIsDGnY2mhhXMX3mNEHboRRwoQUqlxd7kgNmDuT3
         emOqymsyqXy+vkr/gcTMvxQDCOuwBYs5+IrXpfSMLZUoPjFHvAO0aWR5g94eQRpKUbGG
         sv9rCPDh268zkar6PeBCPjYTHOGjqwL3AtIFtDlBPJVS3iN97tb7Znqar+U6dkKPrtZN
         jSFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:cc:to:from:date:user-agent:message-id:dkim-signature;
        bh=CRY2i7oTTcHsoBGlkd2B0oUO1HOZbzEReMqjQzmMN0o=;
        b=SfTdSpFXFq8NQXYWiWUonPGXklmial104rHRUYDA64ov/34fDgpWCkwAt/U5eU4C/T
         zsWK7n3FhewZV4W/4qJXwUZ2fz73BDi/8nByVR3q+Pv0bOuxB825RGDL2hBCDM2ujDBx
         Bv7pMfAwQ4ah9VFwbGRymWTbXEwIYL2GwYa2PKihE/XVEvuEDzzBe1umrH7CPwuRbN/u
         wwh9Y+NvtAU5rErSVB9deJRGmWzJH+qm2MUIG7ad3/NKSeI+4GPSz8YMWt31cuDMwlQq
         pS8fuEr5lnI5/SCMFSekeZQ/w0nr32qvUU63BRGnw25mcTt/fBAv2jOhkVnMSy1D2plk
         2K/Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=bgDNsT7I;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id v16si148113qtb.3.2020.06.02.10.34.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Jun 2020 10:34:44 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1jgAoC-0000Q5-QK; Tue, 02 Jun 2020 17:34:41 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 22E5A3011B2;
	Tue,  2 Jun 2020 19:34:38 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 0)
	id F2AD02022DEAB; Tue,  2 Jun 2020 19:34:37 +0200 (CEST)
Message-ID: <20200602173103.931412766@infradead.org>
User-Agent: quilt/0.66
Date: Tue, 02 Jun 2020 19:31:03 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: tglx@linutronix.de
Cc: x86@kernel.org,
 elver@google.com,
 paulmck@kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org,
 peterz@infradead.org
Subject: [PATCH 0/3] KCSAN cleanups and noinstr
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=bgDNsT7I;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

Hi all,

Here's two KCSAN cleanups and the required noinstr change for x86.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200602173103.931412766%40infradead.org.
