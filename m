Return-Path: <kasan-dev+bncBCT4XGV33UIBBLG7SLTQKGQEJCB3ZEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3BA7B25BE0
	for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 04:10:54 +0200 (CEST)
Received: by mail-yw1-xc3d.google.com with SMTP id b189sf641322ywa.19
        for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 19:10:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558491053; cv=pass;
        d=google.com; s=arc-20160816;
        b=hiFu8ZVgyNnFna8/Uvp2oKc2YVxNOPjWCJCZj+RoOujZpw2PguZ1qMJPNpetACnhGu
         4U+cOYuBrgIKX5xO0x9WxkwueNFmF2O5tLFZFHr8n9HlE3HOzUGYSqVbh3rqfPh8tsyj
         dOOYA8nY7hu5XDhoHNduOpXxyAeQXtUpoU6f49xmXiyUfNnffpsj4lFz6+TraepF0dmH
         LPSohhVLrrWWLjlr4/26Y4/7kPdeOxqrImB1DnopBWqscimqzT9Xn9MB3cSK793ANzVN
         jEFlrjMD/d/mVQ+3p5zDZldt4DL4xq8AQWjQ2fmuNHcN2p27WArBGjiAMCB02ni0ZSps
         S0kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=oCtuVQ/FDUc3d71ERqhqQbjmg/XItJ/kCXsKBe5bwv8=;
        b=VQnF0Hz9YGxGolgDTJwjBA02QazUNn+F1pmRLJ4wknFxCPO6XQVJqCAN3Y6mU26/TH
         c1fUc1JxOE/4kcHl73E2OuluGIYReDYBO8AwacwG6/CGYKGy/svhPFfZoDBKYKhDvSyJ
         vfmea2VHpom7H6ugAKhroOS487DYcKf+gY9MPk8KgIDAMXznjalm7+45McooY/awq2JR
         h3pUYvPjUQAY0UrIkeShUdiYy0MXytZ47AfL3erWcuM7+yiE35BGcDw8+OZirRCnV8wH
         hLhy8T5DoKM7cpIfwV+/XMq6BWKs/VBs91O9uqBjI6qJ5w/qnFiNBye0S3Cc8V/EKROW
         Zv3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=KIGFNpsD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oCtuVQ/FDUc3d71ERqhqQbjmg/XItJ/kCXsKBe5bwv8=;
        b=Oht10djKEapEA0ieb/HYz3x0VVbhw5vTNwnULp6CVTSZ8fTra2DYE8j27EaWX4XrHF
         mT9kb43H6/ACsQVyNUQULTFwdzKGJ4SByrfeVfxt+cFMWO1hmcHV8tRQG6qJv9NUKF+q
         dWxGbI9jSqvZbttR+4k4Ufhxr8Yo5P1j+avy3ax3i93+wzeQRd7gZJud33lSW0Nb2wUe
         kx9qmTSYlFc1K1fN+ORCkR/f2U3LzCLOBjTrVu2MQ4MUONKY6E5b3hN/RSnijz77MrYO
         2QooyGnSOXRQumh7C7RyantdpWnH2a0tA6lQGMA+do8V0NKB1LbGbu/g8rCzW9T3oZ+1
         m4mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oCtuVQ/FDUc3d71ERqhqQbjmg/XItJ/kCXsKBe5bwv8=;
        b=Fw8paZuKP1Hr0JgAzljj6IxQPHbpYYSTei7vM6qgSMJ4LRvtM2r5903UQKMEvQgCQw
         0Fs//XfUXOVundtW40Ot3B40waGVKWMzSRvH84+4y2Gn4djxuIK0IjkDabsqQu25LiOg
         wnmLBp1ti2GBuD7eVLWgtoRdmTOXfnyVTaoGMCXUEbGe9a3/c4jOqPNHBwgoS1M/f9wB
         87m4OoBAIhB9Y14XEqsmdf0UoM8yKSw9D8AKcRixvyssdMu8CZZGUomTYT883iNfaiPS
         BxTadqthd+ncR8ttOtt8rfAbT2XCrs5ZwC+0fv+7kDTRAv7JLcEwdCWrxeLnAmCS6qkx
         tZPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW7fbQnBHgX6pTCfr5wHmwAKhPe0DU9MEFMr/CLIC6gep9DScFq
	wMupA69Gnh9tONW4YpNVyKk=
X-Google-Smtp-Source: APXvYqx84lnRWslyHL0cM5KUkR0o0eSli06se+a4Daij0H9TpkxoATksCgDfUkP4hHhNJEmt1gZJKw==
X-Received: by 2002:a81:6386:: with SMTP id x128mr38836012ywb.331.1558491053019;
        Tue, 21 May 2019 19:10:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:6b0e:: with SMTP id g14ls71848ybc.13.gmail; Tue, 21 May
 2019 19:10:52 -0700 (PDT)
X-Received: by 2002:a5b:9c4:: with SMTP id y4mr5365158ybq.17.1558491052557;
        Tue, 21 May 2019 19:10:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558491052; cv=none;
        d=google.com; s=arc-20160816;
        b=M7REszzFHqt/IMdEx50Mg3JWHFZdx6qqXjlIcTYF89TZpxiD/8qIgofz4msX5Sf9js
         WHx0Z7LWUnZbdpSostxQIgmU6Jo6o98/3LmGB+9EFnchbwUFL31A34vkpkrpqEIHJfMg
         WxxfhsvUXTeU8aw8qmnujX10sFNNlLyQsRq6CpYm1ygB/DN8aBFmI1C7gvai2t40s9uz
         Iupo1ETL6v40IgIl18dIiVTr1PnVydQBk7v2502XAzbBbdC4XCZSniAX3/F23Cdr3sKb
         vikyUTez4e4jduPjxxOFik8MuwntABiVgOXpwPVeiegheZaiz0DaCu5QmqEXddz1ha4Z
         8+HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RVmoZC3/WwvW7DNufwo4WuA5HxB5+/gVkqe4H16ZSn4=;
        b=oNmPogKrvT/m7quNZEns0AVG3kiklHMApJMOqejM1iStisjWVgKVRn20PJdYFMW4Lw
         aJ8nw5iRb7dVjjzy186PPDgD2coPbC0Ad6J5Uto+1m/jvWl5z1jxH5zkgj8+GMgyBgya
         q97BJGp1TwdI0ANvrUarX8SwDR9p30q8Ycv9KPYVBVAsjIKk5KxMBfz1JmK2ouLzgcbC
         wUdqUP1abVaCsQQjFFnQBIxR75YjQoe1W+uqM3Q/65N3d9wD/SbDkmBVIuWjwn6tMeBd
         HXzvm7R8LvQwZbPg71skwwrwJZ1VndhjKFkF4v3qa/a2P3wQ0HO2yMuc1QRmCc9DxQFk
         K07w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=KIGFNpsD;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d74si49648ybh.2.2019.05.21.19.10.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 May 2019 19:10:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from akpm3.svl.corp.google.com (unknown [104.133.8.65])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 157A6217D7;
	Wed, 22 May 2019 02:10:51 +0000 (UTC)
Date: Tue, 21 May 2019 19:10:50 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: kbuild test robot <lkp@intel.com>
Cc: Marco Elver <elver@google.com>, kbuild-all@01.org,
 aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com,
 andreyknvl@google.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com
Subject: Re: [PATCH] mm/kasan: Print frame description for stack bugs
Message-Id: <20190521191050.b8ddb9bb660d13330896529e@linux-foundation.org>
In-Reply-To: <201905190408.ieVAcUi7%lkp@intel.com>
References: <20190517131046.164100-1-elver@google.com>
	<201905190408.ieVAcUi7%lkp@intel.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.31; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=KIGFNpsD;       spf=pass
 (google.com: domain of akpm@linux-foundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Sun, 19 May 2019 04:48:21 +0800 kbuild test robot <lkp@intel.com> wrote:

> Hi Marco,
> 
> Thank you for the patch! Perhaps something to improve:
> 
> [auto build test WARNING on linus/master]
> [also build test WARNING on v5.1 next-20190517]
> [if your patch is applied to the wrong git tree, please drop us a note to help improve the system]
> 
> url:    https://github.com/0day-ci/linux/commits/Marco-Elver/mm-kasan-Print-frame-description-for-stack-bugs/20190519-040214
> config: xtensa-allyesconfig (attached as .config)
> compiler: xtensa-linux-gcc (GCC) 8.1.0
> reproduce:
>         wget https://raw.githubusercontent.com/intel/lkp-tests/master/sbin/make.cross -O ~/bin/make.cross
>         chmod +x ~/bin/make.cross
>         # save the attached .config to linux build tree
>         GCC_VERSION=8.1.0 make.cross ARCH=xtensa 
> 
> If you fix the issue, kindly add following tag
> Reported-by: kbuild test robot <lkp@intel.com>
> 

This, I assume?

--- a/mm/kasan/report.c~mm-kasan-print-frame-description-for-stack-bugs-fix
+++ a/mm/kasan/report.c
@@ -230,7 +230,7 @@ static void print_decoded_frame_descr(co
 		return;
 
 	pr_err("\n");
-	pr_err("this frame has %zu %s:\n", num_objects,
+	pr_err("this frame has %lu %s:\n", num_objects,
 	       num_objects == 1 ? "object" : "objects");
 
 	while (num_objects--) {
@@ -257,7 +257,7 @@ static void print_decoded_frame_descr(co
 		strreplace(token, ':', '\0');
 
 		/* Finally, print object information. */
-		pr_err(" [%zu, %zu) '%s'", offset, offset + size, token);
+		pr_err(" [%lu, %lu) '%s'", offset, offset + size, token);
 	}
 }
 
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190521191050.b8ddb9bb660d13330896529e%40linux-foundation.org.
For more options, visit https://groups.google.com/d/optout.
