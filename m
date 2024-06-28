Return-Path: <kasan-dev+bncBCCMH5WKTMGRBE657GZQMGQE2N4CFVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E0A7C91B95B
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 10:04:36 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-6b077edfd2fsf5357176d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 01:04:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719561875; cv=pass;
        d=google.com; s=arc-20160816;
        b=mnwYWZaPQHrgDBO6hDqB7cXpndevza142bJlCkEHsyveGTacmABnbnJBTnG9iW0WnI
         HSc60ZPeXCCl86b3EhFzdK2VkHjgij6a223pB2CC/xyl7NG/LyjQEKkKDR6BibUwouvl
         jKsVnc/FwMsTisY+/osMT67dW4XEQ03boPds9PTS4JKO37QORMsf+EGC44EU3lOyIRCN
         r5Mwv3xi/LwZ3Trs3dwyLIRoTYN1Q0ztuwQjEGP1MnA60ih+bwu5p65mRLAvUMMRftzL
         Ho3cYD7K4wuEj/w0tDRLz6B+oNiTAr9uIKWq4fNz7yXr3bSlNzZDYEtkpYJCNEhnKBk5
         WLPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vgh6QHl1X1PrIV5hgxO41jN+pYDkB9ztxHl7gWAF2bw=;
        fh=qa7XUtv6XYF0057W0yCvm9YeQqLE+OpA9E72WGNBDaY=;
        b=LWBJjY2/FCYHbbbDPKO2c/n8jpc53zZ5iySDlrssBfYwaTGk8xLaes4piMZ6bSvZPa
         bkxDH1kVtK8kIuGKRJztnkUaThZiHaTF3kltq6EZEv+8F/Wpw6Pg6Ni+Wa8Zd9+fLxT4
         c/h2dbJILvN31uYT7B99AB34EL6tGOvgMZZUOFip0JL/QVaX7dO+LhzWo1KN8Ppm4/Y6
         gmP9sTy3yY6Y54r4AqRqJHaGx1cRU5fdO49vih5RAH16TW1nEB2/sp/Y0mYGCuH6wsH0
         q/EWrHWNEju6VkXjRhMb5BEOgTaz8oVNXSXTikzWPmTOCiC09Qbm7Ohsf8KDg5xNCXst
         mrbQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="cZdaX4/I";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719561875; x=1720166675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vgh6QHl1X1PrIV5hgxO41jN+pYDkB9ztxHl7gWAF2bw=;
        b=OFFOzLxDx+c6nbnJzdRbBFglBgqRGQJ5+PS5vBgFz3je7acjILFg9SguWazRHmHGmo
         1BiTf2QAE1TVD1ijwBwAA9RmU4NAtkwcPedttZJZVKIjGAjoNmHkinYJavnAfn/T0Xcd
         Uf2JkKkAw73RfWWvkWcD3rAskDSYtSnSNAo8h7pxxFOCg3MDZwAY5gL9W/uaZNFzrptI
         fwGbFDNVIigxfpTKnIn64/VhPaYgAGg9TWfZbvDy7pGS3vQu5RHc0GkJbNwBLTQ7uxuY
         4ccRYOT8kSOn95d7X9DLEwFaRHlK14r10E5baoVoBN8pr+7H+GE/GXe8zV5Go3FHXsxT
         fgDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719561875; x=1720166675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vgh6QHl1X1PrIV5hgxO41jN+pYDkB9ztxHl7gWAF2bw=;
        b=ZI5Zb6T1/M5W1GYehWOEonqyUX5cFn3L5KeZOZCks2bfB5xOezlPRx20vhVYGiC0Hu
         7NVXH/1AnHYXsb68loTzSkmDaD9lz8HvSMHUeTMobwaOkBweelnw9fTiToMd4WkC3e0D
         aXDOQKQJ6EQ1uIiWTfkF1Dpg13KX5fJhIT6gsakpn2tCXzRlGotJuKxS3m6lbp2APLp/
         0iDqg3/scu7IVsPkTltfYXqw0U+H1GE4g+S5unDLoP0deDyC9bmJCkyYi4ccz+l6xvYn
         Wr1hsWJAtFwzKWdrhHeOQ7CioWEk3huOuG7gnzMoqjvfpcBjmVFb4UaFxHvGGYXByPIW
         mMqQ==
X-Forwarded-Encrypted: i=2; AJvYcCX34HB9iqBHZg56KVe7TZph48G3oYAhPo6LAS9Kx6qGJdBn17wxAPqI5GdQq7Vr/mCIF2bmhDPOeFB+gjYqTrnnbhvocz1u5A==
X-Gm-Message-State: AOJu0Yx4XMob4h5GAzJBepOPRqww1oEYE79kCynAvkpmM9e7SHU+xiiR
	PCOP2q6veVpYWc9CHQDxmAYdGV4Geua7MjaUcewcymUEO4CLWpkG
X-Google-Smtp-Source: AGHT+IHxHdb/7bju0jw/F8Z42Dcq8BYIwpgMENwsDcY6kSqNGwjhK5nHjh4Hi3R9WtTeWULtadFJ7w==
X-Received: by 2002:a0c:f389:0:b0:6b2:cef9:712c with SMTP id 6a1803df08f44-6b540aab5a6mr165695896d6.49.1719561875356;
        Fri, 28 Jun 2024 01:04:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:528d:b0:6b0:88f4:b00e with SMTP id
 6a1803df08f44-6b59fcbad07ls6028336d6.1.-pod-prod-05-us; Fri, 28 Jun 2024
 01:04:34 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWLQLrEE/lYrn7k0R50WaQK5LAt5h+y5kk78yoQytGVFCAPKG+vSZk6FmcT/SZC4kyQD+x0CDMSwWSr1B7aEs+Y+5jNkXfcUEp/Lg==
X-Received: by 2002:a05:6122:2a52:b0:4ed:185:258c with SMTP id 71dfb90a1353d-4ef6d7ccb92mr14668390e0c.2.1719561874569;
        Fri, 28 Jun 2024 01:04:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719561874; cv=none;
        d=google.com; s=arc-20160816;
        b=0riZPcqfe0gil/yCnioCm4DdqBcvKpcQcZlrr/apDXy6bF5dFdEiIb5rSQ892oqZ7r
         t/V+EHXBJKnJYQDzdObSeA1nr6Mt5A7rAGmHSPD1KiBfeVmpt3b27PxyIcV2pyWLq7yt
         CEL+2WCtg1u4RBJB+s9yRk0fHfLwDJV/AbxWDCBX+jphLf9KSpFQyhXx7Oub6ptii52w
         w4daRV86cvucu2l1YsAlR1tqaHNC48NFgQ2wnOmy9Q70rtOAgICw8tLCGbTrYiHQyQcM
         qJmWv64pmt5CM9ctkGFHrC+u3wKrwB3jSL/Cl47FEmo4b8sTL7GEeERmjFFu5J5F1lgV
         Ntvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1Sgyvv0YJuBT0GMeHDfvUWM7p1X2ARTlWPgT25XarGw=;
        fh=cEYKgKHUcFa04S8I63OylbGX+GaCbxzKtmO4whvTWnc=;
        b=XyzcBPyj8bXia5x+CPrRNou13qLmreuunTkcu4lQDfAtmK7nyJ6adqJg2W2kq0p+GQ
         8b/8M/7sjFP89HtNJOSaGbcigbirHvZfQGrv5rbzdgYXQC7WkwTTytg86zTmvVCvOVsc
         EHoWIZns/tLPi9RH5rJuF2QWg07dSz2OODafGeS77iQEeA0GCOVMQcAJijiaavdQXI/V
         WifZhy2+jLHT1JMT0xh3zVx384orfoFR5pD5jbTIQwXSVb7WHdb1IPV2wpdtxYs9IWR5
         HYBStkGxEJeqF2VHqxXtnuy2eZ630Vh/prqa8CSjDBFP4M1KCxU4OjAd5SenSbG+yKbK
         XKKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="cZdaX4/I";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4f2922a09a7si20352e0c.5.2024.06.28.01.04.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jun 2024 01:04:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2c7c61f7ee3so227821a91.1
        for <kasan-dev@googlegroups.com>; Fri, 28 Jun 2024 01:04:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX0Hoez3RKSZMa9erg4oeLds5VNphXzdeLWShGxuR+bM3kUtWEgvl/kgYUjRhRoGAE+NOdWWLz5EkE9mdICynQTaIuL0hsrEaa70A==
X-Received: by 2002:a17:90a:d38b:b0:2c4:dfa6:df00 with SMTP id
 98e67ed59e1d1-2c86127e0eemr12912932a91.8.1719561873523; Fri, 28 Jun 2024
 01:04:33 -0700 (PDT)
MIME-Version: 1.0
References: <20240627145754.27333-1-iii@linux.ibm.com> <20240627145754.27333-3-iii@linux.ibm.com>
In-Reply-To: <20240627145754.27333-3-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jun 2024 10:03:51 +0200
Message-ID: <CAG_fn=U-HQOtES0bRSRXvrsjW=aHpQeMNzS2ZK+dPgWJxx60bg@mail.gmail.com>
Subject: Re: [PATCH 2/2] kmsan: do not pass NULL pointers as 0
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kernel test robot <lkp@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="cZdaX4/I";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1036
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Thu, Jun 27, 2024 at 5:14=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com=
> wrote:
>
> sparse complains about passing NULL pointers as 0.  Fix all instances.

Thanks a lot for fixing this!

> Reported-by: kernel test robot <lkp@intel.com>
> Closes: https://lore.kernel.org/oe-kbuild-all/202406272033.KejtfLkw-lkp@i=
ntel.com/

Rant: I noticed recently that checkpatch.pl aggressively demands
having the Closes: tag follow Reported-by:, even when it is not
strictly necessary per
https://www.kernel.org/doc/html/latest/process/submitting-patches.html#usin=
g-reported-by-tested-by-reviewed-by-suggested-by-and-fixes.

> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DU-HQOtES0bRSRXvrsjW%3DaHpQeMNzS2ZK%2BdPgWJxx60bg%40mail.=
gmail.com.
