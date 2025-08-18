Return-Path: <kasan-dev+bncBCLM76FUZ4IBB6PARXCQMGQEKNOYR5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FC6EB2B046
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 20:27:07 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3e6670d5bafsf44606835ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 11:27:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755541626; cv=pass;
        d=google.com; s=arc-20240605;
        b=J+2n1qezxp4SEw22/VeWFVnQ/A7SMo6nPLWRdMAcJuqjL0t6d8yuw8TzgWErGv8wgP
         mm7IOVe1FntDkkfdklKZyT8CVBPS14nIly36UBnm0MVQMc6O9M2iLgKApXsW6os7Zss4
         je8CNLBkSj6krx6N+ILdC1KgoEEwn7Y70eyh2AKRHMUJzb3U9mmeOiVz780z3TfND6oC
         jNmjQwnko3ii3H1TdnILw57GXEsVAAJjGCqoY7bDtsn0SMyQAfbp3nGT5Gx7ENYxjf31
         Lkq8rqnJedgVyMxjF7Z0WbKXWH5dBgpYOHdzL33VmdB6olS2oPwIy1TnMJstC39MfFa6
         wQ/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=9CMI3hA9cGj3n8ODPOCyko5aN0meMYbD11qyvDxT0uM=;
        fh=RocGKZfmajkwkbj4gYXpWHI/c+bRPtU1lwBEhhRJQ24=;
        b=SxOskgvdlOMdtq7BLrgHXdwZOKzui0cPMtsEptJohsZbvYekPOQ+miIsI8cLdwXmcB
         UrS2yAk5mpenpyW21fDjpqeSxmYpV3FbkQaS9AIYon//bFubqjO8bkTSKKgeNHS5ptsB
         hhO1lHvIUtpxSbT0idO2MiTpzdiJL3bniS7RhZvf2BxJZoYZHQsnZVgCOjuOWdE4Lpy0
         ZloFYawFaiebqGgr2o7SKC80JtjE5TnJbP9z38tEVVQJ4UfWkxlAir1VznTGG9Ei/5Wz
         c1DqsSdlgtAn2SGhYdHkHprGUgS7ZVr1nk5wb1zbjiiA0+i5ZFkEjJshHO6D3d1P6IzJ
         Tp+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="wUt7S/Nl";
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755541626; x=1756146426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=9CMI3hA9cGj3n8ODPOCyko5aN0meMYbD11qyvDxT0uM=;
        b=BNFAuv+ZzSIrzZucIdk/O28NJM5AgIfMj7dvlvJJY6ckvbllDA7RQZfwNF8G3W9r1G
         X0seWdYyArqI/S08Up3j4kUtKKwB5pa9dC0D3QjXk4QGowIIm+tyDrjfCixJ5XHaOzzX
         ca0P2m5kVne/cRHbZ+a86DCNEbOBYvI8mLqmES6o2wBgDxz7zd9SvhrgqPzwdEi41ehW
         4an7v33NZv7bq2YZteWQhRemuBLzcmCZParw90eib7by3dquREKXXwXbPwY0sYX2Eu+P
         Yb3c1Qezk5UXDlUW5VIA2DEM/CMumNRFipt2Gsjhav+WmiLv6jwEP4SKm6cFcGHkIz2X
         qziA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755541626; x=1756146426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=9CMI3hA9cGj3n8ODPOCyko5aN0meMYbD11qyvDxT0uM=;
        b=gKbziVCyC0gihIR5SGvtao6c+K3cgyzM7T//3rAyBEy8NZ26MEY5HL1Bty/EiMzMzc
         EO1Ry12BiG5NIl+pAcYXfCjMA/dDGOroAG3PHtO6oB4Bdxd4I4FZqTG4CXuXVuMRG2+E
         MeYQqGZAKWESu+cfrGUYUMjX8U6awPlcy7VA+U891Z5Cmsj1PoM74ZqyMVjZQT804mAI
         YJrrcZV17kXe4S3uexNiBTJgrVoTOQZ5zuFcjugbfPvv2TN/q5w30US517moNW70d6BQ
         VXxDM9/Hr5KPT2aRmsADZMQkEFaCuEiOlvWFlbM0Vt8toZQ1KyRrWfypF2zxbPzjf3e5
         bL5w==
X-Forwarded-Encrypted: i=2; AJvYcCXFrJtFdm/uIS7o1f+AEwao2lDNahz8wyTp/w4xUYk1TqKHfK9XsS8tPYiK++F1cCOL33HOew==@lfdr.de
X-Gm-Message-State: AOJu0YzWTAtBEWAQTpF6kDNWKs1kBtuqYfFWSfI8RC3vuUk6VA8a+W88
	0nXGYoA0AQ+pU2Bd2+Uwgd4FXTKsLd5vf15S6KciniLdRpsOHtjRaCSz
X-Google-Smtp-Source: AGHT+IGtfC/2/Tik1nyyXzth2u3NIBGk13abMAtFDrw2NTFALaT9sq55l5pLJ0uc304KZuF/qEITFw==
X-Received: by 2002:a05:6e02:1a0d:b0:3e5:4b2e:3b03 with SMTP id e9e14a558f8ab-3e5837cd1b4mr214578105ab.3.1755541625793;
        Mon, 18 Aug 2025 11:27:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdpx7Pm5rvZPQsrppI8G0liiPwLxShhllz4PSmxEe4dXA==
Received: by 2002:a05:6e02:4601:b0:3dd:b6c9:5f59 with SMTP id
 e9e14a558f8ab-3e56fb9b562ls47367855ab.1.-pod-prod-05-us; Mon, 18 Aug 2025
 11:27:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUE86fEVb016VwOZcOqM6wz6opmpS5XgXTERVUi6OMtG7e+bZ/4KdoafAbi2aQ+Sh3dcPmSfo/S2Z4=@googlegroups.com
X-Received: by 2002:a05:6e02:1a62:b0:3e5:5ac7:d8e2 with SMTP id e9e14a558f8ab-3e58390092fmr160603105ab.17.1755541624107;
        Mon, 18 Aug 2025 11:27:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755541624; cv=none;
        d=google.com; s=arc-20240605;
        b=UfUb8GEmqgkXgeKArazEefWtzq5Z5gTf91HNLtHJY5noMYT5PXDRnn/nu3avYheoHy
         7P+a9A8ycbKmp8nvAkfZT2yhnpP7oULrOFaJpi9STSvG7q+reckN3aEOF5xB3rQ7O1Cb
         J4l1Q2/E3DI5oW/2osxIdm2pdAGaU7BPPQsvUZ41v+UhxF4DjFZroPaxbsTqeIENZ09U
         M86P1oE4aL1JR1jbHG8Wjkys5DpgSCGynP7Tz/Hc3o38ERzGNIIj+FMAl8YuJoklgHmG
         dtCDPZJVbzcXkqbuQ3rsOKcafwmEuhkz812yoCzmeWKgOwYjE+J/bNZghAqQX9rSr0tx
         Vdpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Xthx9ompS/Nj5CKJ3I4BXZ4xhbM39aiwRjdnUlZCUzI=;
        fh=vCEjo6PCqqw56cHOSUWjxEFULNCAI95CaFQqw1EKRxU=;
        b=WqcGaKETxBwLs7n/ln4TR/b9QqWPmsHUQCSFRIRI6mmWbn18eEt3D1Q/iOmZmlowef
         yT1xfc8YMKCU3+SCL5qYLtkooTy+448XdQ3pTOY8lEujDJmjOxIaKJuol5cW4uMbXp6H
         nQTxk0gor/fgDKnBwWOnJ7rUtuOBnIFoi3ZPlgqfdeGOaV70+qtontvEhH0aSc/uEEEF
         IGyNOCjtrduPJ5Z9tudWfxILy575EpMZsWP4gCKlMGE9C8x7rJUZc2uj5jjp1vSHq1Qn
         XoXUUMLdNA+kvVB/G1c3lp+98gyxIqRogK3AZEL+j94WXP7aEN0Lz1ZcH2Dd2nAoT855
         4iVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="wUt7S/Nl";
       spf=pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=justinstitt@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e66b6a671asi1484445ab.2.2025.08.18.11.27.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Aug 2025 11:27:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id ca18e2360f4ac-88432e31114so311331939f.2
        for <kasan-dev@googlegroups.com>; Mon, 18 Aug 2025 11:27:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVbB+2YNiuSw04Gk9IEzi+anPR2SlikHYPnSZ/FUBlRIHv30bwTPwNQKuB6BiZHTjgV9ydBVQWNWNs=@googlegroups.com
X-Gm-Gg: ASbGnctEx0eiEIr2Fu57GR/2VOVsy1ypGwJQWRW6WtMwPEaTpFp8rj43k6ZirDtrJGe
	lHq6QeoSHnr6UF6iyE/f8geZR8bau4CkFkx4Vb7TGaHWcfG7dLLPZEnU2afoF3sc3EGFqrLlyyo
	eXo3h86U9ulzgfI0uH1DNiHa9LYI2BrIDM+0eiwPtw+zwlOlq3CE7YH7xs4o8UirhibLrn9pd5+
	90fnuq5M6DHOcteLRK58SOoolzz+hsdFCIxdqIAO3Wl27juMChKUw3R+k0nLo+zDwS7h17YhepA
	15GMkK14/mIko5HCjyJ3vLEW2hhChNQjm9etHuRc8xMnM13JysFxISUxrkKEQoXUtt5i+WLNQRx
	K8TbLT+RRwRL4W5OZL5c4ENKzLCMlMTX6AgbG3msjc3D0gKKW8yFqvzbGb1Td5ktsTjfHQjSdJg
	==
X-Received: by 2002:a05:6602:6d06:b0:861:d8ca:3587 with SMTP id ca18e2360f4ac-884471192d0mr2123993939f.4.1755541623533;
        Mon, 18 Aug 2025 11:27:03 -0700 (PDT)
Received: from google.com (2.82.29.34.bc.googleusercontent.com. [34.29.82.2])
        by smtp.gmail.com with ESMTPSA id ca18e2360f4ac-8843f9c2cc7sm323121039f.18.2025.08.18.11.27.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 11:27:02 -0700 (PDT)
Date: Mon, 18 Aug 2025 11:26:57 -0700
From: "'Justin Stitt' via kasan-dev" <kasan-dev@googlegroups.com>
To: Thorsten Blum <thorsten.blum@linux.dev>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-hardening@vger.kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] kcsan: test: Replace deprecated strcpy() with strscpy()
Message-ID: <hqvjfoaw5ooucqp3mwswrjxletq6vdzztwvlaxvxf5a6bivdzf@7fcytrsqhz4y>
References: <20250815213742.321911-3-thorsten.blum@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250815213742.321911-3-thorsten.blum@linux.dev>
X-Original-Sender: justinstitt@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="wUt7S/Nl";       spf=pass
 (google.com: domain of justinstitt@google.com designates 2607:f8b0:4864:20::d2e
 as permitted sender) smtp.mailfrom=justinstitt@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Justin Stitt <justinstitt@google.com>
Reply-To: Justin Stitt <justinstitt@google.com>
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

Hi,

On Fri, Aug 15, 2025 at 11:37:44PM +0200, Thorsten Blum wrote:
> strcpy() is deprecated; use strscpy() instead.
> 
> Link: https://github.com/KSPP/linux/issues/88
> Signed-off-by: Thorsten Blum <thorsten.blum@linux.dev>
> ---
>  kernel/kcsan/kcsan_test.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
> 
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 49ab81faaed9..ea1cb4c8a894 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -125,7 +125,7 @@ static void probe_console(void *ignore, const char *buf, size_t len)
>  				goto out;
>  
>  			/* No second line of interest. */
> -			strcpy(observed.lines[nlines++], "<none>");
> +			strscpy(observed.lines[nlines++], "<none>");

Looks good.

Here's my checklist:
1) strcpy() and strscpy() have differing return values, but we aren't using
it.
2) strscpy() can fail with -E2BIG if source is too big, but it isn't in
this case.
3) two-arg version of strscpy() is OK to use here as the source has a known
size at compile time.

Reviewed-by: Justin Stitt <justinstitt@google.com>

>  		}
>  	}
>  
> @@ -231,7 +231,7 @@ static bool __report_matches(const struct expect_report *r)
>  
>  			if (!r->access[1].fn) {
>  				/* Dummy string if no second access is available. */
> -				strcpy(cur, "<none>");
> +				strscpy(expect[2], "<none>");
>  				break;
>  			}
>  		}
> -- 
> 2.50.1
> 
>

Thanks
Justin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/hqvjfoaw5ooucqp3mwswrjxletq6vdzztwvlaxvxf5a6bivdzf%407fcytrsqhz4y.
