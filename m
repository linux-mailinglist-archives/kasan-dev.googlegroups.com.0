Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBSWM6SLQMGQERJ5YBSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CB75597521
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 19:32:59 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id o19-20020a05651c051300b002605bf9706asf4517296ljp.19
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Aug 2022 10:32:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1660757578; cv=pass;
        d=google.com; s=arc-20160816;
        b=l9PaWJRVM0r7ZlHO7AIiIhlWkI+r1f0xXViiKSb4o73TE/f6vccvu4X9Jgb3pPDMvn
         E5buY/cfFjHdNLgP5rxXq9IN72+1usbxQBBfEg+GWioP0jgNeDC9sAMjDO5xRUDgebVV
         C31GmM+EH/JP7T9dZ+jU+q+t/VOU9apiskNy31Lc8AzZbw7+mbtwR8dpij7bJbJBV93S
         7YDcPgbs2pAkipaJwD9yT7q3eQX3/qlMf6C01NijOBBJlKU0qnN4y9rHYinLFwSZ6F3L
         PN/TCa7ozbRNJfy7+pgH9pO89IkbHrtcjtTbHi4wkgBYfsbUvAfsNoTIxupgf4Q1H9NI
         oWuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=moJoB7YQTzLi1G+mJZwLoObI/CHe0iWPVEMjZbFvfaQ=;
        b=ul1yBNWlw6//KyhABZvV6SXrp7bhY69czu7QYqcn9cVaz9pZlMwkY4YbN/CZAQDzxh
         WrYTMFmv4TCo49r4ggCIbnwrYG5fr/Qr5o7/KUQOrjq/RpiQUPsf01CH+z0Ofx/Zuybo
         rJNVljLveyRgBjTkWxL18VVeGhOt1T1UpVeNnjJFVuyS31nm1NoXpJF4S7pukHnKGDyX
         lbpwtzhJSWM9bUIUWpM2hE2WkZyNQ2KvYzCvXwL8vteAHyTh6XbFcGyVIaq7cdNeZ1V0
         QvXzZgYEJnioC+XDjL0Cob2UK2AhsqoQs5tsob7fNlgTjtxzmI1wO+whD10cEfpw7N62
         rSQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=YMpGH2Oq;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc;
        bh=moJoB7YQTzLi1G+mJZwLoObI/CHe0iWPVEMjZbFvfaQ=;
        b=fSUrS4o8IqTzTGTZZQzTX/QD1BCYoGPjZw8Jz13k861KjD/9kbw74ug8hHFktZffQf
         dwhY9axN54rbrKdnNfTcFeBsn16fNlrTLwQDaLfNmQFQeOdzwGCSufaIgTjIWCemA80X
         tKOUTKY0C/pifQhVxzBIjd0nN17+x/gsHImK2l+EX+7AJsPG8b0ht7Vag+enDF5iUSML
         yPhLsm/m2N+oi1MzpaG5ROBkt9ty/MqnlYY6rrISAIsQGXYF/XZuTrOgKZOhDlMsczEb
         rKNWcgZfBXaU6TL8HrAELeSBvcVWEZUsuP6ak/u79gW2K3LXrqrUF3ItJKN25LIguzxL
         RPxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc;
        bh=moJoB7YQTzLi1G+mJZwLoObI/CHe0iWPVEMjZbFvfaQ=;
        b=Aa8B6ZVgY6L2ZCUT+xoRYItvQIobs8trBg0XRx62KOyUboIt/3gmhwoizRGCxmn035
         X7P81qd9vjd3dadwF6LCGYi4u/BtDg7fqWMUT5b/c9HxZ/qClrTr5Ff53dc27Ksj2+c7
         PLz3NWSfCnNwZU9BHN3fHSuHirsbMx9n3gMBgemPfU2f7TcH7bUWUk05kLq0OePYRFtm
         E+6W6snepFV6UNCOCyl1oJykMmVZWfP7sl5LisZGRE8PGGUjKyZRP/PBlorInfUBtcVl
         IKm72BXuml/Q/AnkGvWXYtY9LyAOrukmlRZ/MCOkxDTCgyUA2OuNjGvU1f8esXKU3lpo
         aYAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0szorlLpeElt+aDJ8o12B6IjtAzFgvk3sqMpcdTgeTvth0OKI2
	bCVGKOety+35oxDlGWDQfIA=
X-Google-Smtp-Source: AA6agR7M9y9PBLYrrabNJwos7GKFHVuql/Rv1LeOQ5/T3pl63+kp5jB1kNaw9/SKtUFhvgG9aS/1Lg==
X-Received: by 2002:a19:5e19:0:b0:48d:d87:b734 with SMTP id s25-20020a195e19000000b0048d0d87b734mr8966093lfb.579.1660757578840;
        Wed, 17 Aug 2022 10:32:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9c8b:0:b0:25e:58e5:b6d5 with SMTP id x11-20020a2e9c8b000000b0025e58e5b6d5ls2700042lji.1.-pod-prod-gmail;
 Wed, 17 Aug 2022 10:32:57 -0700 (PDT)
X-Received: by 2002:a05:651c:1501:b0:25e:c393:f2e1 with SMTP id e1-20020a05651c150100b0025ec393f2e1mr7783932ljf.341.1660757577883;
        Wed, 17 Aug 2022 10:32:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1660757577; cv=none;
        d=google.com; s=arc-20160816;
        b=Bxcpd61/HIMSOg8Y6GIs5EMc4zWqYEbqS+cmg95sV4xrAj4DNwKuwFu4Xc5BnseK+k
         jfFOLpPBislEQIrd+fRysQUpco+vcSpI21Wpz+gl4cGFv5+ntL22n68cfd3biSuwaQOG
         N958dadPh9XD78sDLnx/xeSAdRzKTGI7z5qF2z/2VU0isVYaZ8w2X6mQEuWldZqZKV+K
         w/dr3vumde10ktUAUG9/6UndhLDuQKnegiJ3gJsI9nBODJMdg2Yxd7j1RwI4aS9doC41
         WhVTcQntskCwOfsHqQgCx3rfHBONQyEPztmdtRHHSQ9zQGz5RnNV6mRIWHOIhPiXlDiZ
         7BFA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Yt3AY4t6IMDKtoS4oS2pxr+XC4iNeaFzq4wqPlcyaC0=;
        b=Jdzyk8mM9tmBii1ATfTpX9UGlYz4PLt0fZSHliuJPTZddmylEsYgUvC7cJ7j6ilz+7
         Le5ydpGxRSCkRy7Mgs3hqIVRl/z4FupVHZMX1XC9MwkNzUYEvbb/XdXqj97jq3H/f2cL
         RtYX2PR2vkY5Er64O/BPujadCK2ggJMnN2jXcBOFDzzVEB6WXZQIxL5mWOnrMWDqD9TR
         yJ4shXOO1WzIfz6G92m2W8rfKHfQvr+/fXK3oRl6qlHRSP7MrnHU9Y54j5tOoMj/A9RH
         6DOIP3Wj4G7kSFRbZWr7eL7uO53waFmrxERmB40tzk9wmvNPZDKDrLeoDLFU5fjGuPjL
         YvSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=YMpGH2Oq;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id i6-20020a2ea226000000b0025ebe667378si1240010ljm.6.2022.08.17.10.32.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Aug 2022 10:32:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 3A743B81E81;
	Wed, 17 Aug 2022 17:32:57 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 49D9FC433C1;
	Wed, 17 Aug 2022 17:32:55 +0000 (UTC)
Date: Wed, 17 Aug 2022 19:32:52 +0200
From: Greg KH <gregkh@linuxfoundation.org>
To: linux-kernel@vger.kernel.org
Cc: akpm@linux-foundation.org, catalin.marinas@arm.com, dvyukov@google.com,
	elver@google.com, glider@google.com, kasan-dev@googlegroups.com,
	linux-mm@kvack.org, max.schulze@online.de, will@kernel.org,
	yee.lee@mediatek.com, stable-commits@vger.kernel.org
Subject: Re: Patch "Revert "mm: kfence: apply kmemleak_ignore_phys on early
 allocated pool"" has been added to the 4.14-stable tree
Message-ID: <Yv0mRPKRB6iEY9kh@kroah.com>
References: <20220816163641.2359996-1-elver@google.com>
 <1660757029198205@kroah.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <1660757029198205@kroah.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=YMpGH2Oq;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Wed, Aug 17, 2022 at 07:23:49PM +0200, gregkh@linuxfoundation.org wrote:
> 
> This is a note to let you know that I've just added the patch titled
> 
>     Revert "mm: kfence: apply kmemleak_ignore_phys on early allocated pool"
> 
> to the 4.14-stable tree which can be found at:
>     http://www.kernel.org/git/?p=linux/kernel/git/stable/stable-queue.git;a=summary

Oops, wrong branch, this is now dropped, sorry for the noise.

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Yv0mRPKRB6iEY9kh%40kroah.com.
