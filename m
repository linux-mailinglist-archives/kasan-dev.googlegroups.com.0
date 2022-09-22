Return-Path: <kasan-dev+bncBDGIV3UHVAGBBW5DWGMQMGQEISKSYAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 883085E6214
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 14:15:24 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id p36-20020a05651213a400b004779d806c13sf3059500lfa.10
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Sep 2022 05:15:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663848924; cv=pass;
        d=google.com; s=arc-20160816;
        b=qUOr41AYeJQNbMLuOdlWVX+8VlC/dwYlbxFy08oDS2e3CeuVqX68zaGKMeNzT4cPTO
         cxV1ZT08ff7EJE9UNDyrmtp4hbthTdWWBLr3Mryt9+hYRjfMgmUhpBrVqUo6snJMzRD/
         Uw3eJgOVIVMG4T5QQnJjUqKlLax5l2Vy47NSsv+tqJnP+1Wonzo2u9JmbKP3VvvyOgNT
         LJ8GE3JD1QJg4jTjvhTA+GjeKyA/s03BjiaN7x3nP/M5GEQ980/NO5kiJIyU8TBMqvnU
         /kzv5Mu6cIvm9MCMAE3Keopd/YhggdOuNnxDDHa74BelE+IClG6b734VEFcOgrtMWEDy
         u85A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zjrpZknfleZZSZ3sgE7grJQSNnuA1ga3HpRCjvxLAP4=;
        b=D0i7K8At64gSY7xZnF2ADRcaeWq5irQ/QmLSNbRxFCuPyBL1HOhqV+xTYOz5NgSIVx
         wKoNj8tnxdjCmL3nga/jpYwjQqYizD+tZT37kujIizaJjFnZXlEdc8k/hf66QEt/Wi+Z
         B9nVBXF2rQSfUpidqPknoEnnkEMSEEEoen3UB9rLbRHzv4Gy/06ijgs3bevPgqSp3oZR
         e3kZ8NYEgAXQUz4G2Rq9+9jTSCvED4NMhPmpRaYmVEPzj57qusLohveZmWhHEaF++URL
         JqOA3cD6FN91ju9WMDTGOYmXIQ2j/R5ifXsc6mdD7SniQCzEI29iEMVfg+wsWh8FGqfQ
         yWYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=be0zNAMx;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=msx7L8Tx;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date;
        bh=zjrpZknfleZZSZ3sgE7grJQSNnuA1ga3HpRCjvxLAP4=;
        b=CcxP35UN6p90Cr/YFUjzntwPCx03aohY3DHcIFETdTC3KEzEwKlqbsjujSgTTcyAkI
         P+mkqbn/aAYeZLIlNKUd5D7SHUjtWwmOKNwDnT0loVTw9CJCsTg0dAbTHpmpOpUiV/S+
         tZ+I4R00ZFshzs7p5KdAwT9eYo45lBQ7hDSobJyHECkqKcMNFL8jt7ZmnEg1JSPwrw6x
         5dWiPpksoLPhSbLUNi4lagSFTVp7koSvZK2Nt8chQ2HIZ+AleGE5Xa7M0yfFJQu24grq
         YLs+sOHxB7kzx9QEBQo9bXbLoUHK4t3RMflsXyf+jVmUtV1X51lJyHMLCeFJTsOuTjya
         YbKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date;
        bh=zjrpZknfleZZSZ3sgE7grJQSNnuA1ga3HpRCjvxLAP4=;
        b=vERG6Rh7iJvR1Zs6WA5vumZRJZKPT2CbnUCncSiaCnDFeWQlRUsACvwnnFGyIGSRa0
         RKzXjVVf+x05AHoLa0KPmKtWtdLCGXOEj4Ofl1pzEt8lOyjuyDH81mVaMEWDxrbKPYDd
         3OOInprc2IzZ6UzzLU/iA2K/hBv/sVEgf54mn7sUEHwpi191cPkYP3fe9Cn54PsYIpf+
         V+r9regY1Sww9jWqsHtgI1GokXhWz3UyxEAXTDld+qR/r8byhyMVSiXYjNMeRqYNP6HU
         DbaYts4OKFDFFb4LD2JiDpc6DttXeKeNkxRfBNw6P7OHDBaMhjNESbGmjLDqISJwZuV8
         dt0Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf3yGH2kf8Ol6b8AU4wnFJyB+N06sfeF726ISQOAkTFC91PcMyV0
	SBF3Hyk9Ha4y05oc5GWohQU=
X-Google-Smtp-Source: AMsMyM65nwU1RyKgtcrAGhD7OIpeXQCHyJYmFmYqkFWTQmxba+qfcQWEc1n7SUCgBxQOUTAKCkmAeA==
X-Received: by 2002:ac2:5d25:0:b0:497:a280:9825 with SMTP id i5-20020ac25d25000000b00497a2809825mr1055203lfb.409.1663848923642;
        Thu, 22 Sep 2022 05:15:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5e7b:0:b0:48b:2227:7787 with SMTP id a27-20020ac25e7b000000b0048b22277787ls1865181lfr.3.-pod-prod-gmail;
 Thu, 22 Sep 2022 05:15:22 -0700 (PDT)
X-Received: by 2002:a05:6512:3f05:b0:497:9e06:255b with SMTP id y5-20020a0565123f0500b004979e06255bmr1049072lfa.175.1663848922471;
        Thu, 22 Sep 2022 05:15:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663848922; cv=none;
        d=google.com; s=arc-20160816;
        b=o2LP2c4QFy1j0zqbZqHFUEXTcDdGFg8YldrKhUCSMfXIdCtzChPGdO6FXzvpDUZj+J
         1m8S8EDSs1Ld6CQ1CwW/469faLEneBN+ctjkijIQv9uJgJ7KbK2ykwQJRORAmePTIxKt
         SldBL3S2MeUxQ34IqyHSgkq3Ykua6cV9BOQCo8YoKyKLRuaYUHY25CgRzqLgMBRo8+Ie
         ZaEdgqZ1N7hw5j83FcWO62oytFC+tTTtsVWx762FUyYjMtSEP0cYY2Y5FL8cSGneHwVp
         ReljIXTZp0bsGseSbtU/Ccrm0wFjKgizRAihhvVJSivpkJbvulJ0Jo9W/Uu9uGrW16ew
         05fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:dkim-signature:dkim-signature:date;
        bh=EqMQeAG3qnEpASlej2J8TmOifczthv2gPHe9GbktIwE=;
        b=VaaTs/5w/cF7eX7BdFqp2UW7iWb2lEab7EB1Rj9j7kmAAg+0icBKqIfrAkNRXvUk+V
         c/RXmzHEg3uZVHpIzl6BGBz7l8kPnFKrt10ontNsBrgs72TeHNnOofGsBJ+UQYrIK+vK
         2t0V/H2MtHmztfce1s1ZAawV7QlStEBLIIw2IKs6A1VNRIZctiTrEt8ncigZ53Pkyzga
         3ZzvaVHIHUavYFmQAHWY98xbs2I/y/lpOHcoyCNjatRjfE0/y5fwXL7fzOOiLpQO6Hla
         v83zUXApgx6ZW/cmWCNNVm7NesCVBrVH+NX1e5Jvxyjy6gYs9X2dcGE2FDCLSszSmCzm
         obrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=be0zNAMx;
       dkim=neutral (no key) header.i=@linutronix.de header.s=2020e header.b=msx7L8Tx;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [2a0a:51c0:0:12e:550::1])
        by gmr-mx.google.com with ESMTPS id i15-20020a056512340f00b0049ba11e2f38si210574lfr.11.2022.09.22.05.15.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Sep 2022 05:15:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of bigeasy@linutronix.de designates 2a0a:51c0:0:12e:550::1 as permitted sender) client-ip=2a0a:51c0:0:12e:550::1;
Date: Thu, 22 Sep 2022 14:15:20 +0200
From: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
To: Chen Zhongjin <chenzhongjin@huawei.com>
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	liu3101@purdue.edu, nogikh@google.com, elver@google.com,
	akpm@linux-foundation.org, andreyknvl@gmail.com, dvyukov@google.com
Subject: Re: [PATCH -next] kcov: Switch to use list_for_each_entry() helper
Message-ID: <YyxR2ErlHj6wrR6m@linutronix.de>
References: <20220922105025.119941-1-chenzhongjin@huawei.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20220922105025.119941-1-chenzhongjin@huawei.com>
X-Original-Sender: bigeasy@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=be0zNAMx;       dkim=neutral
 (no key) header.i=@linutronix.de header.s=2020e header.b=msx7L8Tx;
       spf=pass (google.com: domain of bigeasy@linutronix.de designates
 2a0a:51c0:0:12e:550::1 as permitted sender) smtp.mailfrom=bigeasy@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On 2022-09-22 18:50:25 [+0800], Chen Zhongjin wrote:
> --- a/kernel/kcov.c
> +++ b/kernel/kcov.c
> @@ -133,10 +133,8 @@ static struct kcov_remote *kcov_remote_add(struct kcov *kcov, u64 handle)
>  static struct kcov_remote_area *kcov_remote_area_get(unsigned int size)
>  {
>  	struct kcov_remote_area *area;
> -	struct list_head *pos;
>  
> -	list_for_each(pos, &kcov_remote_areas) {
> -		area = list_entry(pos, struct kcov_remote_area, list);
> +	list_for_each_entry(pos, &kcov_remote_areas, list) {

so how does this work if you remove pos?

>  		if (area->size == size) {
>  			list_del(&area->list);
>  			return area;

Sebastian

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YyxR2ErlHj6wrR6m%40linutronix.de.
