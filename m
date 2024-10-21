Return-Path: <kasan-dev+bncBDW2JDUY5AORBIMX3K4AMGQEPNACF7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BE559A70B9
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 19:13:07 +0200 (CEST)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5c94273656csf2956964a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 10:13:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729530786; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z5Xmq9D1KqFg62zHt2lg1sRJX7R6CLq9VQQMXJzbOC1RtoFJu6TeiFYOR0NAJLm0Uf
         IYMmTccHiPDLhXeKDX0bQNpI8pOGmzWrK13+D99KTUQnopI655tIRSFhWdUeLR91Erd8
         o2JeTM6z9OPUVpXXHInGk1JXhfsWx/Z68r0BkAi7xWnScel52zR2Le817ooJV1N/qyQ8
         17ySO5+WfO6n5Gur7v2Umu7yaTWdh5RpcvSiKhXvKwXLOUrVpxcMfT9Ug/Y1QZXMjs0d
         lY2X6HQZIuf6mLn7k2rGyF8eqJ32JFxYfoB+7+YT7K2pU+eNZuFDVfqqEpCfX287s9cP
         e13g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=px1ximx4fuXQ7QbBGLOVO6CmTscQP6Nwf1Bihb0QhJ8=;
        fh=xfs/Fti0Twjyj2dk94/Kvo5sJqx4v10WV+TJhtYMIt0=;
        b=YE7wTUCVeLuftGcBealtH7TPBxl8eXk7iCnIIcost/2JcKA71WKTwKW7oi0Cg9VA2u
         0Jo49ScTo5zCe0B2rqomlI/6lDW7FwrjkQUAQsyxMtv4drcm1rDG258HJPnQdySMzm1z
         4W/uh9KPAzK6aDZrkdmD+YjqO0IB/MKRMAR/6JX/BUc4igFLSBkcEiNVu4aixfvTe67w
         KnoeiLpfQ4Br5ozMzfIO/pHssuKlg1Mg1DN9hWIz0U1VwUMWqKqFukN0+tShVqT8i6On
         PGUTim5/AZmUp7BUw1+1wqFIUxLncwP/Eee9OsHqyzJExPhuNHO394i0nWP0vAHdyh3k
         nUzQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lhqtTS1c;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729530786; x=1730135586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=px1ximx4fuXQ7QbBGLOVO6CmTscQP6Nwf1Bihb0QhJ8=;
        b=eGabW/r1pCbvyPO4JxQ1sxzGAflkgVtyid61T76RARD/aolDtEfxACbjFZgz1zjMH8
         u6+o+TS3H5v91wvoJuJJgd1lfjbGHR66yTld8yGUWLvFTxqKrXsqKyiksf6Ictav++2s
         mBefGIXxGSkeOLHlcufWhAKsJ/iIqdJdLh1j7PlhVq5pt7lZhZlvsHqbwdB7OqPsXrhE
         8NcUrb8LkYDwBhmZapgobBiwId7c7rEaOYV3HNQC09qGHg663cwcrUEw4knAnIqqyt8W
         /HPssAaht97ppzPGFi6refMwnCzWQiJ6MLJXWsv8ChyiLZvDyM4AS5ZMMCKqj0EtDir3
         +d8A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729530786; x=1730135586; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=px1ximx4fuXQ7QbBGLOVO6CmTscQP6Nwf1Bihb0QhJ8=;
        b=fKpIK3MGXcUZPnfBn1wuI9sItJlL+v+tKCec5ixTKtPOxMoY87KrYmnJxP5yvNcjki
         TfGKm8qDJ8pkZWef8Dw8j1SxZMXsaF66Kd46+WS7PQB5mWaAF2xiaDdS5BIZolh1ebdY
         DsLDAerEyJChvUAfRCvIyf5uhM1J8x7TcsIc3t/hO8M5zZAty8bb+JgPIMS0x+B4ldEN
         6hdSfxcLS1uV4zy54NWj8MNmLgktcwqQSMiGtZsYUFqxmAu0MdOdzt+ZrtfByt1DvfdA
         X2rgFKb2OD/kvjJRDxf+Yfjdi1julnKfdLLZG15CzlS+ArWkPROBYp8RQYo0YxAwTgB+
         uJkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729530786; x=1730135586;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=px1ximx4fuXQ7QbBGLOVO6CmTscQP6Nwf1Bihb0QhJ8=;
        b=uSK8ZLJfxcB90KMeoRcJ9cGFHcH0MVi+m1CPvdYqLbDnjMAEiwSelqg8wwqF8sd5FM
         1igDkn2CMVSSLFqUpAb4BnP17gdPTwtebchy1OsRXVkQaScuBoQgDspBPYqEYWMw3bkn
         WXIoNb65Z82bddtMElzfORN3fP64XYxCsun02PTxotjDqVM/2O+5cWQrAf7ljx2G8Viz
         LogFRoSRAppR0LTd5VI1Ndh+eWIhMt7jr9YBBrv4X+DaTvPf7YNZG5ajx2Wl1CVpYxUU
         xEE7lccmRDQsuQQ20wXY6aQlpce+DW6qwIztSOlwj0gnCNtiMowYTe1UOL6B2jlPP6SG
         TX0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZN9Xlfa/AcGvZhNhcplveGUXkd0MKu7K5qAavrIk032AzCmk+MzLCYLCn7rSinAyppo295g==@lfdr.de
X-Gm-Message-State: AOJu0Yzrh+4tOjyNBjYxzVUSB7+xywFQOFwU7iKHE+P5dcxueVy2X0Up
	Y8TBgKzlg93VATZ7SEGpTfWbjLSAoc4nSNtwxbH9wn3t7eZeHGue
X-Google-Smtp-Source: AGHT+IFYEu8Bdmqo6yaZfsI+cFTUgrU36xnyuG8cw8nsxhtVSZcndDmI0PqUmtJd8BW7zZt8JwGKWg==
X-Received: by 2002:a05:6402:26c1:b0:5c9:8ab0:2975 with SMTP id 4fb4d7f45d1cf-5ca0ac79006mr7699577a12.6.1729530785958;
        Mon, 21 Oct 2024 10:13:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:42d1:b0:5c9:1f95:5130 with SMTP id
 4fb4d7f45d1cf-5c9a5a2940fls283320a12.1.-pod-prod-07-eu; Mon, 21 Oct 2024
 10:13:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnCP8ZZcJDe2+lQ/f+yMxyWq6/wAPDRePO+m+kqGji2GY+Sn14RVyCf3uqaiEXwXFPGvRy1GntfnU=@googlegroups.com
X-Received: by 2002:a05:6402:510b:b0:5ca:d0c:c2c9 with SMTP id 4fb4d7f45d1cf-5ca0d0cc3c4mr11378654a12.19.1729530783938;
        Mon, 21 Oct 2024 10:13:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729530783; cv=none;
        d=google.com; s=arc-20240605;
        b=XtsJAjpBuqLLAczbtBpGCnRxuyXMntjRh2hQ2H30jKPOYv81t3N6bMlrj8yKfd4vgW
         fiO4OAD06OZeh6Y60q+sd9hit6CnYGiAW5rw6wKxkVzo40IfJn7zcAIdCcIg6hSXuGEV
         txSKFR31ttGzeEK1gHvJH+DfFLgYQ4dzRPByCP1kKVvvhdEh6/HYRiJj3MBTaAmvkfce
         a9UonWcUptu0SmnNrU+VU0g/J5d8qVQ70DnQwx1DoUPEEjCUvOB1NQFOx+8ltASfu6q3
         iFqrqIuzWzUdw6TBkoULEv93iwvWOJcXA4wbF2g6q432EYfk6taKAqwTUWxsXyULZ5VC
         TUfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Yu/DhZu6HvkLJQug5aPr8YQgLzNKRwKw+qMAOmhuUh8=;
        fh=TbOTSuTnCrLpJQiBFo93djnzqLTc9J+uXVimzoGSbW8=;
        b=iaDxRUkiCkn6o4HebBlVnwXsEZMP8xCyh43CcdyPBh+xNjTZ20t7BDCaJeHp4xt4+n
         cZHfb7prA3V+abn06T+zo9/hZUNOpRakbETn4K23cGTM+DHEsNTY9RWiMpvrJp6ucNOo
         O8h0nBNq42I3OW9b9qXb0i63KCzR5cP3i+aNcBq5Qw/aCVOO9JxGdev0oQI4MydZW4yp
         MGKefwFKQaOZACkMYFcs7TFs9zp9Ezq7TKRU1BgV8OZGatfahrunJbYyfHKVDfvKMNt8
         5ER694tQyU8loaw2+N5iatZg28MMUn8xV2cIK9GFStML2FTFz9X+6F6hE2EHH11+HtZ/
         IpIg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lhqtTS1c;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42a.google.com (mail-wr1-x42a.google.com. [2a00:1450:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5cb66a787d6si75986a12.5.2024.10.21.10.13.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 10:13:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a as permitted sender) client-ip=2a00:1450:4864:20::42a;
Received: by mail-wr1-x42a.google.com with SMTP id ffacd0b85a97d-37d4a5ecc44so3532447f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 10:13:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXWuRXS7yTVMdRKIcFLd8ffzT96e2uAq2I8rhSjw7TjACyw92AdjAxqKY7F5/GFrgA5zMuexgNWBP0=@googlegroups.com
X-Received: by 2002:a05:6000:4013:b0:371:8319:4dbd with SMTP id
 ffacd0b85a97d-37eab7436f6mr9252003f8f.17.1729530783265; Mon, 21 Oct 2024
 10:13:03 -0700 (PDT)
MIME-Version: 1.0
References: <20241021120013.3209481-1-elver@google.com>
In-Reply-To: <20241021120013.3209481-1-elver@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 21 Oct 2024 19:12:52 +0200
Message-ID: <CA+fCnZdr4drxL9UDjAS7sCaDCG_nBJkg=wfX8j=itvo9RdbOsw@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: Fix Software Tag-Based KASAN with GCC
To: Marco Elver <elver@google.com>
Cc: Will Deacon <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Mark Rutland <mark.rutland@arm.com>, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, syzbot+908886656a02769af987@syzkaller.appspotmail.com, 
	Andrew Pinski <pinskia@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lhqtTS1c;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42a
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

On Mon, Oct 21, 2024 at 2:00=E2=80=AFPM Marco Elver <elver@google.com> wrot=
e:
>
> Per [1], -fsanitize=3Dkernel-hwaddress with GCC currently does not disabl=
e
> instrumentation in functions with __attribute__((no_sanitize_address)).
>
> However, __attribute__((no_sanitize("hwaddress"))) does correctly
> disable instrumentation. Use it instead.
>
> Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D117196 [1]
> Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
> Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> Link: https://bugzilla.kernel.org/show_bug.cgi?id=3D218854
> Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrew Pinski <pinskia@gmail.com>
> Cc: Mark Rutland <mark.rutland@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  include/linux/compiler-gcc.h | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.h
> index f805adaa316e..cd6f9aae311f 100644
> --- a/include/linux/compiler-gcc.h
> +++ b/include/linux/compiler-gcc.h
> @@ -80,7 +80,11 @@
>  #define __noscs __attribute__((__no_sanitize__("shadow-call-stack")))
>  #endif
>
> +#ifdef __SANITIZE_HWADDRESS__
> +#define __no_sanitize_address __attribute__((__no_sanitize__("hwaddress"=
)))
> +#else
>  #define __no_sanitize_address __attribute__((__no_sanitize_address__))
> +#endif
>
>  #if defined(__SANITIZE_THREAD__)
>  #define __no_sanitize_thread __attribute__((__no_sanitize_thread__))
> --
> 2.47.0.rc1.288.g06298d1525-goog
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Thank you!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZdr4drxL9UDjAS7sCaDCG_nBJkg%3DwfX8j%3Ditvo9RdbOsw%40mail.=
gmail.com.
