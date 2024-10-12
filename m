Return-Path: <kasan-dev+bncBDW2JDUY5AORBAP2VO4AMGQEU2FKH2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 83C8A99B789
	for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 00:49:39 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-43056c979c9sf18702805e9.1
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Oct 2024 15:49:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728773379; cv=pass;
        d=google.com; s=arc-20240605;
        b=IJ+h1LhQKSjWCQNB4yWsyxwWHFbUENc2JeeffQ7g2JEBrNVxZj/31BZG0lpbk0IABu
         7lltaCY1QvdX4DRU9XbDzSEzLcowIC8+J1+NTkeJjmcJ/dCt2iAAkW+ooC4KTYQrAk7k
         PAhlbEcaOvdvyubQZOYD3ctQXsQ7knHOXjj5BQ8+cdcWFZj98WJj4BPHM9AfDJodotGL
         MlMRGDore4hGaglZke3rFTo0YCp2Y62WXozSIlj23Qv5oK4EndIdZkQJAwhOSlNOgJhv
         G31+iyVZ5U/i1xWRguF2XY4vB2ORz4Ppr+G3wYgWG2C/VF3PAANE/BXIJoOEu4JM7SDR
         40Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=KI0awJv5QmD+ESmzblJyO44ZE+7DBcQmGTOAWlhlUGM=;
        fh=C24X3be6f9HHVuBoVhKXmh5g6VwN9VEmjN6EWcUXNXo=;
        b=WB4rwhjX5KzWllkLjOntFuAK9mwIo+ubIM1fUXrUvf4tIcAmpMnhOYp739B+Adycv6
         IjXIcgF1K0G303GVSxmCqjFvGrtNPZRJYSkFGWyztmt0HcZ5xeZHIuOJe6+q2muWIeYZ
         nYc75JtqsFZZb/r4R7gQ9G68CgCsxzY6xAYSQEmfRCxp1p7fVJaGBNrbUc3f8du0jx9n
         DQVGzL95Xogp3ahJY5WMrB3zYwZc8XbxxCCspsLy4SzTYlq1IAzPJ9+qyNjR8oypMIWM
         p671sej0pnz0bqujDCM4EGqCx/ZYfiytzxFcNzhfB4abaDKdhBsNTgCgW+Z63sSymkCc
         2rxA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hddHj6lX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728773379; x=1729378179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=KI0awJv5QmD+ESmzblJyO44ZE+7DBcQmGTOAWlhlUGM=;
        b=gcImCxQDTccvu+ASY1JnmmPBZB/EJLaed1xfMmbGM/z9tDlGh/5KzHdA1DqnRgPghe
         I58VAUlvbcCtqR2cVullBjU5P6jFfziEUuqTZmQOrUIIy1KbEtnCubbo8mjCEWkYXdBt
         LTYvk42jp75R09egGuPMJG3ekQ2ES2RP4R3ppiAr8+WlCzSVMGlSof7mOIvyl2Ef8bh3
         s1r/Q67gfCVLq3yEwV/jo3l8uotvzY90WLm7bQk1cN6jI4JiHLkOpzrfSYwJOiv/OIVm
         bwQBMFUbHkJcj/HxrtHPhOPZVvCNToWAbaEYENUC6k8Ba0yUnAl3soH5poKRurlb0JWu
         46mA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728773379; x=1729378179; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KI0awJv5QmD+ESmzblJyO44ZE+7DBcQmGTOAWlhlUGM=;
        b=gC9Zp7QT/cx1vH9qKAVThrXxVAsSDat8bD2FqyTylfih0diFUfwMrSsu0i6Sl5CB64
         DMky/UtLIoSUlJwuGfHuukV0jb2PHvh+2oGYpsVJxlA4cTNiEQLzmCMgQLoZoyMjKHu3
         rHFpIz+tbHllgUbYEFSEZ0gn+8B26ZUiqczwGd8XXtnofgpVVAMfVY4QAup2vsfOntuU
         yX8sI65Ag8RVoshh52yVbIUECR+BvOGZL4yhKMwdTWfvlsGNfSeYFB/icVC45x/taprX
         IwfqwlElc2t5dAnRwRa+/1uv5eDbh2+dVbiKt196NZ8nbrUjB+fTLUnBcItkNXnmC1Tq
         uUhg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728773379; x=1729378179;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=KI0awJv5QmD+ESmzblJyO44ZE+7DBcQmGTOAWlhlUGM=;
        b=C70whsusaNEjIkJsm5IcX9L92UCcCKABET5ho7V4fLTHkOscDSkdBsTx38Ed331thf
         FJ8z+6Sq94DZMvNwhqKdytrKiR9pInFaUfbFcPepOi/L9sLfZ88O/bSqnjdQI/j2Z7Q7
         FiLQEQEaYa+IYT0I2ZoyCwKbUUj6+/8SWYFMfSHtpXoHnU8KUuNRz+TGYgyuwt/mWDIe
         7FVFJ9jwkvahfsHKMqEe1cz+stH83dY6UTrxMml3cBuTHIyHOYhlsf/zZB+uJ2+FGIsR
         nT5TREdl+lTV3LteJOQZ4cHpUS727xvrJgb3PDLn4qOZkwSwjvv37lJIkmpJtLS6Myla
         IoKg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrA0SvXGXyINBTOoyh4C+MpDkk7hn+c5NAE7B9pRDoJuODfJHhDlmGf0JVI74HrQCi4JoDQw==@lfdr.de
X-Gm-Message-State: AOJu0YyTkG4fvuHUMMGRpmoMR1VJ8hvr5+0vgwXJocxfUlGUU+tf6X6k
	vyn6PU8C7BhMFh/VNuVyPows6uKnxGSN8rLAdLwS7qhrkvyFvSXX
X-Google-Smtp-Source: AGHT+IEGfxdDUU6tcrGPzF+3FxRUDY+Octsk5tykrf55ud2rYIo2NTkfKHRsyoMXpvs3gBH7AbK/8w==
X-Received: by 2002:a05:600c:474a:b0:42c:c4c8:7090 with SMTP id 5b1f17b1804b1-4311decaa5dmr62285135e9.9.1728773377745;
        Sat, 12 Oct 2024 15:49:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b8a:b0:42c:af5b:facc with SMTP id
 5b1f17b1804b1-43115ff98eals1567075e9.1.-pod-prod-07-eu; Sat, 12 Oct 2024
 15:49:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWkmkmicgMJnrgf99yXkXrn4OGosxZvfn1owmK1aCn+Iyx0p+3l6Wj9joArHwMlIelcRLZQ1UNbX7c=@googlegroups.com
X-Received: by 2002:a05:600c:19d1:b0:426:627e:37af with SMTP id 5b1f17b1804b1-4311dea392dmr60761285e9.3.1728773375341;
        Sat, 12 Oct 2024 15:49:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728773375; cv=none;
        d=google.com; s=arc-20240605;
        b=i39kITFEv6Jiq12LyFjBW0bdymh55ArraI1TUeX0hncsPdc15mwC4gpSnbsR7nuHBY
         6R92mlhdAaIRMIxagKRCgR7mD2kK3vAXqkmPo02o8lpProQhEZDf0szzd0wprE5gccdO
         P/0m9niO95CH7rhpF6IMvaRsq2KBnBJheiHNLexZBi+kXaF/0P8loCyX1I1DoE+esQUP
         umm8sg2onlAV5lzMm/lUrf1BS0S+4exzyXDzOzfddX1ixL8lTMeCmaHUmtU3wvg0MFHH
         VUScQRcecMZ9sGgf7QH/H831dNY899D+tz62YnEcm4SKGcXfGg4K8MVz0tz8yuRND4rS
         kc4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=567XFgs0KNnQIhu74l9eLsWryemY/O3KSe7EFbZlnGk=;
        fh=eMUJ7pBH45SCTRjldLknfYXESHI45nzJ8OuuZFhk9s0=;
        b=dyZkxQk06vAd/oIQCuL5my7oEhEf7pWJTjKZPPkT5uA4nb0MlHZqB9x5WT7AUm7/7H
         H///sDSusyR4x4zk3iZVbgRjEVuvzmd3HmgeuHWql92OY9X86UPpo8zhJJfQ/2mOucJH
         LSd1l9Z+6Zm8zGfp8WJWB38ItmBnFECk3r5Fxs6AN/TAErat22ol+7wi+5NEtFWGTK7l
         ski/T/S5UE4zcRPt02XF4rR/t/xL4aliWU1DnIabkdzgDsMQgIC57isvma6mBFOEFmIB
         huVjVJBK/Vpaby6E6gtC+muH8QYL/CKWHvGPXQNb0Jp+v9UlylKe/1sjHOfVwYQWx1Pc
         68Iw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hddHj6lX;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-37d4b77884dsi98162f8f.4.2024.10.12.15.49.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 12 Oct 2024 15:49:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-43115b31366so27915435e9.3
        for <kasan-dev@googlegroups.com>; Sat, 12 Oct 2024 15:49:35 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXPjQyeMBJT83Y6jpQ/UNZtCFFEL1y2Tn62PL24tb5qnke9GOb6klAyPtHS1EZa+IpQZbEOW9U9D+8=@googlegroups.com
X-Received: by 2002:a5d:6645:0:b0:37d:4e03:ff86 with SMTP id
 ffacd0b85a97d-37d55313314mr4715694f8f.49.1728773374667; Sat, 12 Oct 2024
 15:49:34 -0700 (PDT)
MIME-Version: 1.0
References: <20241011071657.3032690-1-snovitoll@gmail.com> <CACzwLxj21h7nCcS2-KA_q7ybe+5pxH0uCDwu64q_9pPsydneWQ@mail.gmail.com>
In-Reply-To: <CACzwLxj21h7nCcS2-KA_q7ybe+5pxH0uCDwu64q_9pPsydneWQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sun, 13 Oct 2024 00:49:23 +0200
Message-ID: <CA+fCnZdasETx78HOLViEQHDZV1JS7ibzTbmfPzCb--3uN+tLiQ@mail.gmail.com>
Subject: Re: [PATCH] kasan: migrate copy_user_test to kunit
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: akpm@linux-foundation.org, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hddHj6lX;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::32e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Oct 11, 2024 at 11:12=E2=80=AFAM Sabyrzhan Tasbolatov
<snovitoll@gmail.com> wrote:
>
> This has been tested on:
> - x86_64 with CONFIG_KASAN_GENERIC
> - arm64 with CONFIG_KASAN_SW_TAGS
> - arm64 with CONFIG_KASAN_HW_TAGS
>
> - arm64 SW_TAGS has 1 failing test which is in the mainline,
> will try to address it in different patch, not related to changes in this=
 PR:
> [    9.480716]     # vmalloc_percpu: EXPECTATION FAILED at
> mm/kasan/kasan_test_c.c:1830
> [    9.480716]     Expected (u8)(__u8)((u64)(c_ptr) >> 56) < (u8)0xFF, bu=
t
> [    9.480716]         (u8)(__u8)((u64)(c_ptr) >> 56) =3D=3D 255 (0xff)
> [    9.480716]         (u8)0xFF =3D=3D 255 (0xff)
> [    9.481936]     # vmalloc_percpu: EXPECTATION FAILED at
> mm/kasan/kasan_test_c.c:1830
> [    9.481936]     Expected (u8)(__u8)((u64)(c_ptr) >> 56) < (u8)0xFF, bu=
t
> [    9.481936]         (u8)(__u8)((u64)(c_ptr) >> 56) =3D=3D 255 (0xff)
> [    9.481936]         (u8)0xFF =3D=3D 255 (0xff)

Could you share the kernel config that you use to get this failure?
This test works for me with my config...

> Here is my full console log of arm64-sw.log:
> https://gist.githubusercontent.com/novitoll/7ab93edca1f7d71925735075e84fc=
2ec/raw/6ef05758bcc396cd2f5796a5bcb5e41a091224cf/arm64-sw.log
>
> - arm64 HW_TAGS has 1 failing test related to new changes
> and AFAIU, it's known issue related to HW_TAGS:
>
> [ 11.167324] # copy_user_test_oob: EXPECTATION FAILED at
> mm/kasan/kasan_test_c.c:1992
> [ 11.167324] KASAN failure expected in "unused =3D
> strncpy_from_user(kmem, usermem, size + 1)", but none occurred
>
> Here is the console log of arm64-hw.log:
> https://gist.github.com/novitoll/7ab93edca1f7d71925735075e84fc2ec#file-ar=
m64-hw-log-L11208

I don't remember seeing this issue before, did you manage to figure
out why this happens?

Thank you for working on this!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdasETx78HOLViEQHDZV1JS7ibzTbmfPzCb--3uN%2BtLiQ%40mail.gm=
ail.com.
