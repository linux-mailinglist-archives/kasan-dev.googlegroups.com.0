Return-Path: <kasan-dev+bncBCMJ35XEQQGBBROR2O7AMGQEIARQORA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D868A624C9
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Mar 2025 03:41:11 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6e91054ea4esf46086846d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Mar 2025 19:41:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1742006470; cv=pass;
        d=google.com; s=arc-20240605;
        b=i7EeMyvV/WqkRC4mqx2ljocimbpxI+sUF+SoNuXdABdPgoll5PwX4PQItLhOTijinH
         g/a2h2bMKptwx/G5IkA66TmGjr3nT8z7J1Gqdv32J+F+peXmk7fKRzn/1f1tMioqM4zM
         Rub6PLel+lZI+5DQ4ECFlmQQ+FCQhEVExoBVuul296TtKGMBaXLVLKunG+z8o0aIwtqb
         s8/cRu7kKI3aZVM2Yuuqxm42LdabcrXddzNd1mQBqkCV4MtlWPduudlyLPq0+hkciWzM
         pIVWaX7ce7OZffy2rOj+N3860T7S8Sg89Ay0uSu7aOXjHRNEnYpH5IOTwjMXznKeVd36
         Ti2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :subject:references:cc:to:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=EhNEYuX+P2dkLWiyPJS6LdvoGDInIx+EYXHIuArr1OI=;
        fh=/CJ9Q4gSpCNCsC50XwdJtOxHjhmmT0H5GfwI/X2Zf7c=;
        b=HjKEdpucW+jzbGG6phy4pWKpoffv3ut+ATZwPx/su43EIxjV8thx4oM4EZ8rzfe+ms
         k+m/nDiq5el/jKzlxHt5T/oMCV7+34gR9coya036rKje/Q5+Qabxw/7n61aO62CQ+8Ro
         08rx9dWHjvXV9BZgihWUeXJRxMIDgXKwHLFolwYU07FRUJUToqeAxavf13zJHXhpwcwc
         o5xZtIZb5xb80pOij51QRRD5l+8sSlECp8ecHdBdiUJgHbIY13H5aiGpr5slDiVE8MEF
         EbcmMVdlRKS2RWwKQD+IkwtMPwNURJPodqaZiECjFJFh953dsNL9zspDNSk5CIM45sKz
         YJMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bwbm9EFd;
       spf=pass (google.com: domain of akiyks@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=akiyks@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1742006470; x=1742611270; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:subject
         :references:cc:to:user-agent:mime-version:date:message-id:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EhNEYuX+P2dkLWiyPJS6LdvoGDInIx+EYXHIuArr1OI=;
        b=kSthHN4ppLeYd271WAjyT5CuRCRcllvMn0zyJRIWm6b9hVWibkisFuW6FgTD/C56Rq
         SS/P0/Ih08bDpnajaLldPohRrmhAejoF31s2yElOA5Vdw9seHq2DK4FezVNZ0Pyx0iux
         bGXvQGVtnZ9B628fKYDsg4Li4RSEg8tLWrUPL7YVvpZnQ2lYToy+vqjAWPa39RGIv6To
         8wzdTUiOjkEKTKtRZaxczzOQ1l5qMd/726trg6gkNquV9x2i9oVS35ISkGqkRbtLxFx/
         dlpmfs7cWgBIs3+m+ZegdNagAkpnfX6cMNyHFcU3V7AzQSNh5a77nJ1BgA6f3Qc0a2E/
         Hrzw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1742006470; x=1742611270; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:subject
         :references:cc:to:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=EhNEYuX+P2dkLWiyPJS6LdvoGDInIx+EYXHIuArr1OI=;
        b=M2Xk29YRjM1QVQYTyxWTzqopybAJTrloOlNctnB0zof5kJsILGw4a6MzarxZ+V0XBy
         X536kE+/ydY4Xeu1iU/hX7sTlqBW+PNTmIDivo7IT76WyKv5FLWgP/x0iuT9Is5G+XTJ
         Nh6pWNk2nKsnocLFBVwFaWrisvKrWKMllCSNY+TlpQJ7FWkUrUGTfTSonbKkFvbu/QyJ
         Nd0ATsAXh9hL4kjaaVJxcrpSIGHFswS9gm+3y1Jt9d6dN9M47m0TsF8I3F9Mhzje0lws
         q5s03zqshSR05w0zp9uzY8JvhMTHTR3Q95oy7IRhzrDFuw/+gGx8HRifgXllpn+5GJcD
         mtXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1742006470; x=1742611270;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:subject:references:cc:to:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=EhNEYuX+P2dkLWiyPJS6LdvoGDInIx+EYXHIuArr1OI=;
        b=fEEDpYDOL864a+lA/6z9l+LTZdT9WmAGyG50SbZLAdYObkR4a60bimnEwEG9Drhf0W
         3S0JkbAYVeKfLnudgpIuuEljtpFsrtlnsOsHGLMgv5K7Zw8wPdr7CDE1QB6F8LDF8Q5w
         ObkTvrFdTIh2x7I8dn2MWAoDWTVUeHXyuD13KlyJ/ANXO1ONh7bLZvUxNSwzuDxLOXh1
         /ij9hOihM54JN7MNhbLyqt6kKViUlkoBZgGB+lgFEDPH1KoNKQ0T11Waqijieqldcs7V
         GjwgAojzM42WfDfa7R7uiVo6jwOZbH4TXBbKaV0bSj7jrRUUzpFYYDNXJGJ7LOY8Y7Jp
         nM+w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUUn0g8/U2FWcO8ttTmr7tV/PaP0CJj1xBBuQLpahFxrv/cfY9WiC2g/khmeCuhPoAUl23gWA==@lfdr.de
X-Gm-Message-State: AOJu0Yx8ygmtRRc8QAVtvNC/IOZvjV9tB0YXJjmLvn0Yb67z016u+DTY
	wyiGqylLdwIq9VftGv0FFw5VRHOuBlIUzFeylHtebw1okT1QAvMY
X-Google-Smtp-Source: AGHT+IGyDDIg1aC6s0HHZl9mHq4QXU8vW4dyRxMVMH3OgmiR7yCPGZ+rEhGL0LF+eJlB+B6i8uyotQ==
X-Received: by 2002:a05:6214:27ce:b0:6e8:fcde:58d5 with SMTP id 6a1803df08f44-6eaeabb8c59mr58663586d6.42.1742006469656;
        Fri, 14 Mar 2025 19:41:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJ2Vir8eJNrhFdQTUplJCEBtX2u7djh+F57aPh4R0VkaQ==
Received: by 2002:a0c:e2d3:0:b0:6d8:b1cf:a07d with SMTP id 6a1803df08f44-6eadbcedde9ls23485696d6.2.-pod-prod-02-us;
 Fri, 14 Mar 2025 19:41:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU358gJ79EhPTFpVzRg5kAGyf+z6O2IoEpcnMWO+ozdL3IHtglyuopFaXdgxCmCF+VcU76rtsmh3SY=@googlegroups.com
X-Received: by 2002:a05:6122:d27:b0:51d:e9c0:e607 with SMTP id 71dfb90a1353d-524498a3aa7mr4508425e0c.4.1742006468725;
        Fri, 14 Mar 2025 19:41:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1742006468; cv=none;
        d=google.com; s=arc-20240605;
        b=NaV30aKF06+sWQZBAwjwiySvFr4k5px/eGqXSr//BRe1o9Ef0jE+cn/mtQXLDEygzt
         VapWdwgaAYdHBVrD3BNyrDaIYsVpR6pzMZUzj7xT1sj+kXPr677avJ84FjP2q6+oz/Uu
         bofc5yK0OfMdBddESb+Xb1ApCUVudEl4El1mr/ppBz+Fv9gdaR0vH3yWlI/IdDz2S7Xj
         B791E1NqibiwpEIZQ26g8EPFX6XBIN2xfC/oyUFK7CFvZuG6b8JFiherLntWTpPkT8QF
         TRjuhKLCq9FKpsBV9KN1FqqERBVfamaQWNgkqkCalxZUiBDgp3eXQMEtXwrJtlFPPb8G
         LTaw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language:subject
         :references:cc:to:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=15gdaJdchlrAww0ZPYIU2PXFNpF4h7zH7gWYODgucLk=;
        fh=FrBQafGL9NcTFyMux2JNVle9kwSiAivKVkaJS5UNr5M=;
        b=Ply0yKK1r8Y5PyBdCFAzdfthnp2HTxSdjAb3bJlhXgDY4tAtnlm5k60AcaLN1HWzKT
         9WyWt2F2a5dk0FrelolZfuAH3/IRiRoKHxsHw47b8KG0LfZ4oUgc8cPeeZ8hYB6z5O7s
         eDs6wYlBTFf3hvZLIFN4p2bSXFk5Pqx/ekmPY1ZceRJUg9h592EUFTLfcCV2KB+xNxPK
         LzYLEbb42kkyVJIrmpOfK7qMuRFkM+RVVgUiIMSCCo+TLzDDeXeapV+FtDnXWh0dIJ0+
         PUC/TZ8V0JAiMOFcwhsniNrYEr6V1staESyO1sstbV83q0KiCAvzYselVK+nhsHCVWAs
         ICnA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Bwbm9EFd;
       spf=pass (google.com: domain of akiyks@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=akiyks@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5243a5a6ac7si287766e0c.2.2025.03.14.19.41.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Mar 2025 19:41:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of akiyks@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-22401f4d35aso52834375ad.2
        for <kasan-dev@googlegroups.com>; Fri, 14 Mar 2025 19:41:08 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVX4rIiwwuHFbOOOOTJNoX2Mg8VcGKZBzGqzYglgU0q5v4blxYRhgEqzG7xprFsUIawS2Q6hdu6nzE=@googlegroups.com
X-Gm-Gg: ASbGnctoIeW8wF5IJ+ZWw/EfUa/a5D7ADVjdECoJAnJoAmYyR7aiMp4CHuDLw6A3aeI
	UJ6OiB2pRAP6W6wFmFVwn4V+vsAdXvUEGJpheutCB0QA3qgE8WlbRgtMDAIJaDaxryvVsnaWnxu
	vhjOKWnGqXCdJwg9hb1WnSPNrDNGBzB22lyWy86+IGxUAns3U4i4ytY2fZfu3IOy8WJaEbHoyzL
	4ZSen91GZ7lwlJPvZ61XjfNuyCd1dzwwMwW5iNgfZPHCKo3RCNFhKoyDSWL2EWxlZ7xkw8KRHf9
	Nvt6k5p166PuKZ3uFpl/mXVlIbYQXm7YN6WG+6YtCAfsIgumNx6U7cqtghxQipCr2w2A4FxJkZm
	X01Porx/gERcQqKs=
X-Received: by 2002:a17:903:2b0f:b0:223:49cb:5eaa with SMTP id d9443c01a7336-225e0aeeaadmr76664625ad.35.1742006467666;
        Fri, 14 Mar 2025 19:41:07 -0700 (PDT)
Received: from [10.0.2.15] (KD106167137155.ppp-bb.dion.ne.jp. [106.167.137.155])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-225c6ba740bsm35410785ad.122.2025.03.14.19.41.04
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Mar 2025 19:41:07 -0700 (PDT)
Message-ID: <c6a697af-281a-4a91-8885-a4478dfe2cef@gmail.com>
Date: Sat, 15 Mar 2025 11:41:03 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
To: ignacio@iencinas.com
Cc: corbet@lwn.net, dvyukov@google.com, elver@google.com,
 kasan-dev@googlegroups.com, linux-doc@vger.kernel.org,
 linux-kernel-mentees@lists.linux.dev, linux-kernel@vger.kernel.org,
 skhan@linuxfoundation.org, workflows@vger.kernel.org,
 Akira Yokosawa <akiyks@gmail.com>
References: <1d66a62e-faee-4604-9136-f90eddcfa7c0@iencinas.com>
Subject: Re: [PATCH] Documentation: kcsan: fix "Plain Accesses and Data Races"
 URL in kcsan.rst
Content-Language: en-US
From: Akira Yokosawa <akiyks@gmail.com>
In-Reply-To: <1d66a62e-faee-4604-9136-f90eddcfa7c0@iencinas.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akiyks@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Bwbm9EFd;       spf=pass
 (google.com: domain of akiyks@gmail.com designates 2607:f8b0:4864:20::636 as
 permitted sender) smtp.mailfrom=akiyks@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Hello,

Ignacio Encinas Rubio wrote:
> On 12/3/25 23:36, Jonathan Corbet wrote:
>> It would be best, of course, to get the memory-model documentation
>> properly into our built docs...someday...
> 
> I hadn't thought about this. If this sentiment is shared by the LKMM
> people I would be happy to work on this. Has this ever been
> proposed/discussed before?
>

This might be something Jon would like to keep secret, but ...

See the message and the thread it belongs at:

    https://lore.kernel.org/lkml/Pine.LNX.4.44L0.1907310947340.1497-100000@iolanthe.rowland.org/

It happened in 2019 responding to Mauro's attempt to conversion of
LKMM docs.

I haven't see any change in sentiment among LKMM maintainers since.

Your way forward would be to keep those .txt files *pure plain text"
and to convert them on-the-fly into reST.  Of course only if such an
effort sounds worthwhile to you.

Another approach might be to include those docs literally.
Similar approach has applied to

    Documentation/
	atomic_t.txt
	atomic_bitops.txt
        memory-barriers.txt

Regards,
Akira

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c6a697af-281a-4a91-8885-a4478dfe2cef%40gmail.com.
