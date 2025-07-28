Return-Path: <kasan-dev+bncBDXK3J6D5EHRBAGETXCAMGQEI3XBW3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id 73A53B139FC
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 13:41:54 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-7073bfeef28sf11427486d6.3
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Jul 2025 04:41:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753702913; cv=pass;
        d=google.com; s=arc-20240605;
        b=CJbOSKrSsXGGtgEPqTdQsdF8G3uRDL0D+d2p/IeYG2waMops1v5f1xV+TGYtbbO4ab
         HKCizX55e49cuYx47vKpzEeWooNkZTARcG24i0nHHMmSkDXk7knj9AaR/d7aLZQL15nU
         hy2Jf7gr7UJrdaaxiB7wFca2ChHK9m1qyVEN8AHgZi9viYO0lrfOyoSfzDx4hmwru28U
         ri+4SZ+wP0geDYaEkny6pCJgTLx3BAqIfq/bNrR1GonbVL9omd2lv3fqReM5ol3capqB
         S7xdhGGSH4faxq8S7Uv863UK3FG4Na6bVNR9izZzRQVNZoKEwFVkd4DyBK6B52AbOuN0
         ww5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=tAOxpCDYFAPlNUielOhUuLih/q/WL+rW13tPmwYKdNk=;
        fh=1Rxby4u6+kwL1CTtV6gLTWMgr9HMdoqvyusJcmxTm+k=;
        b=JTdg8KAFCtbOF7jyV6AL+95Zve/fboXP/7yGXCACz2xX2155YgBik3Gmft/EypH1Wn
         UhsbxzR1hPg0et61UFL3q8VUoIZxuAkw5+mtk50nsOn6i29T9kdDOnbZDMetZnpXxO64
         bFF+uEUKCcf4JsJI8lyXLRGXdF5+1PT2wYQz+25CBWKbvlj7W+CAhdeOtF/lP7F1lAH5
         eBqK0hgG54xJZIIyD8qCuiiKTP4k0NOsvy3C4SNlvBOG4xVuxEvSGRGaShAHQXAz/Fw4
         cw2k87Lpj3u3s+qXTR+kxh6NDGXmIjDYnqDO1P4CeS5piZchL1cUZwELJzDJljb/UpPb
         YQ7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UifswnEo;
       spf=pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753702913; x=1754307713; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tAOxpCDYFAPlNUielOhUuLih/q/WL+rW13tPmwYKdNk=;
        b=xq3HRfIlvLJK0chVW7FMqIjF84+cRDStAKMNAXvk/vvI1FoNuCz/7jPvcsMJt9z1bz
         xKkDKu8CE5vJd+MIDBuAr/v8mv3pbgLazr5EkCZSA8G1ECMKRwmgJaqVW9L/2bOt0s7m
         MvNqzh8ynq8EfLhzozkG5DQHP1yfK7/i8bzRrTrsbAqtRCQlnoctvkdGrKnLTAJYGQJ/
         ajJJBOdH7Y2NNlYn86/LFYyNzaMX63dW2D8/KPXPVQNMy8ojfkC1BEvt4eUPAIH2bOwM
         XZsvI/2rA4Yej9oq7noK5tyrSsXr9Pz33F7c9qeHHW6S48aDq5HnU1PwLEFgb3cZYzXY
         7igA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753702913; x=1754307713; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=tAOxpCDYFAPlNUielOhUuLih/q/WL+rW13tPmwYKdNk=;
        b=Pi1uqEZP2VrOQrHli/i2BzmnLiF7Rvf5/UK8gmnfl/LIuRd2UyRaPvM/nm4ZEN4ofP
         wNfdviJDACoQ63OzNGWRDzKfsfwztGHb9d4JJpmGkGxeUV+MHwu3vfyQEOXDHLqY581s
         4ln1tYzZx3GpgvkMqQwz+6UBTvBmlunRYIRcQ0fTfrbKPzw9MZbXKUiXgiaAMX2lgTk1
         diOsQITnA52IhTGcfZrAEbozRgfRUeksmDa6Y/YGmqCeiz7xBRC3+q3Hc1CLxZ9LWPCL
         yy5XnRfTM1GcWWgWb8PHuc3MAVUhe+YuA12OAhSuFtbgt1SOl9WzzKP/GmiQX3lD1Kfb
         CBKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753702913; x=1754307713;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tAOxpCDYFAPlNUielOhUuLih/q/WL+rW13tPmwYKdNk=;
        b=WagILcQSdeiOEWVORLmUfjDOqOtjS05uhhMSS1eu249EoMJHIhmio8g6xM1w6N9OvU
         Q0XgdH/JsQH84d38z2BQv942fjjBV/+jMNX7piiE8w3K0fzX/h9q76Hh7wQP68Ox/Q6L
         jurUBsF2p6UNr26g9lYDQCbEGWqBU7F4aIMl2JOLdCE82fko5HTY2rbiFnDEReyKfaeQ
         w1snNi7vuTjo8CQgryrrL8BjkND6Yjx13XzkxUQH5dURCSBT202aJ2CzZLmUS5hV1tGX
         BniPAOdp5R1IZrZsBl+TBSn11znB5T7VDcdKJVHeYcbE8peHRssfrg15lL0TKzwB8jOF
         dvNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWmlpwdwmBxe9ofDDxT4KhrCdZNCYs9dbUo///7WoKrMK7K8NbeJPJXDatMbedksA71490niA==@lfdr.de
X-Gm-Message-State: AOJu0YypK7ynPQWc385Tm7wbcCYTS3LjfN3hYKj2itshKlgYS1TKAkUw
	3pfFjsc/t0DVYuZp4OWFT7NLMH4fIbZ2j+9BDsNYb3eOIwqUQCgKYAER
X-Google-Smtp-Source: AGHT+IGtvyCSJ7Rv9wtiS3fvKNcKtgW7/B4X0E+VMUZj0TY3WYG0cp/yOE/R4FNpns2M9YrJDWtVHA==
X-Received: by 2002:a05:6214:224a:b0:707:9eb:d483 with SMTP id 6a1803df08f44-707205a1bcemr153779906d6.27.1753702912386;
        Mon, 28 Jul 2025 04:41:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeNjhPJMd/d652jdx0nY9IHHa/iSeJeFg0plIUYxzkezg==
Received: by 2002:a05:6214:588f:b0:707:1cc2:24d with SMTP id
 6a1803df08f44-7073a1794e4ls14725446d6.0.-pod-prod-08-us; Mon, 28 Jul 2025
 04:41:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGSK1ABsBInjXM4tgLOFxiXWI109phflAVvVRwbWz5Fs5I/TZmusnh/bp8JV6R3PTiHFOXPmPtz8k=@googlegroups.com
X-Received: by 2002:a05:6102:a4f:b0:4fa:37cc:2877 with SMTP id ada2fe7eead31-4fa3f7f54e6mr4017615137.0.1753702911461;
        Mon, 28 Jul 2025 04:41:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753702911; cv=none;
        d=google.com; s=arc-20240605;
        b=EjCHwLshgHRjRdajxlerrX4VmQrcRpm4liyx6bEWPJt+fgg1pL873ywmwX5850OHkz
         73EB0TAuu4Uj+BJtDd7OVr1zbkg9a65j/W/yUfTQkrygMuOztcggQFXV9a8+DawwpRmB
         PjPv8ryrlWL796QAA/ttTfSheSL9YT2Qh0f8SjaY8smVhL4g/EYrlHn3qmfFtL2Rj2nV
         M9/JJNXIZouROUcpsSX3NUtPYwJDsDi5lFhfPgQvAzorhtbFUGQk2aznO9MC8smt9OEI
         i7VitlrRQpwzD4OYeRlspYsuJA4Ll1uMkvs7JhvqIlpNgE1Y+9qiqn3asN0uHAcQ5y5H
         UnMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0RAuApdVZvmNYpd6CqvkkHn3l0yEyazEo63wOkp20M0=;
        fh=nCyUekU51LLvpR/EIiw08zzxai6FdSArjRUp8LiUpY8=;
        b=DqIs13FUOTkg09s+RMaHmqEYIMbsQ197JGRPU0K7HtEE3LEP4SnOvGBqKbk6neZiFQ
         ++wZlGuW3cyksUyZibIVPk1qfD7Zn1BFP1w6idywfGBtGKpO3HurS+CUIo3StHHm0Jhj
         dj4+HlPbiXi3C9IGFTwm/BVQILBF3XgnXUfZQCkOgFupuQT5QmjiM7fdvEHeb83ZGaow
         CB+nvF9WN/3VczoUZzsAxaNunQB1Fzw7rIXfcWgXH8VhPg6EEdVnWB7knL0puM4WarG2
         M6ux0hFaX23Zdic5yRN2wtPn9TBie/MhO0sHnfuWrIvXHCY1xFj9US0UxmmOcJMAmJQQ
         +10Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UifswnEo;
       spf=pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-88b8c880d50si452675241.1.2025.07.28.04.41.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 28 Jul 2025 04:41:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of jogidishank503@gmail.com designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id 41be03b00d2f7-b390d09e957so4615030a12.1
        for <kasan-dev@googlegroups.com>; Mon, 28 Jul 2025 04:41:51 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX1iPiHmx3Hrr9MzRzzZipJ26cUpl+uzMUK+PZKPVHjES8MZ0VzYAN/5RMN0Fme1SnbX+RtPmG8wWY=@googlegroups.com
X-Gm-Gg: ASbGncvySD3w7nBAgT000tr+KTlp7xbmarOrLit++vcQpQSXi/q9vpXosNp8cm7GgTc
	8/g69g4dP0vJZHWrBfRNudvMwcpXIba8hH5FEbm3ZMen8mkS3gRyoiBYQYiyNYg3LV43uQi6O/t
	RNh9IkwaOd2/ouPUIMSvoJw0BNx2FINqhO0ZMtJcTwYNf/v3Im4346jTxUJLe7ddHkViXkCoti8
	g7BjVer4sS3m8ZnxZrB9PXizBN+QBNTRU6sWxYW
X-Received: by 2002:a17:90a:ec8f:b0:31e:424e:5303 with SMTP id
 98e67ed59e1d1-31e77b1f040mr14189921a91.34.1753702910429; Mon, 28 Jul 2025
 04:41:50 -0700 (PDT)
MIME-Version: 1.0
References: <20250728104327.48469-1-jogidishank503@gmail.com> <CANpmjNN-xAqYrPUoC5Vka=uohtJzhOfJsD9hhqhPJzQGt=CHGQ@mail.gmail.com>
In-Reply-To: <CANpmjNN-xAqYrPUoC5Vka=uohtJzhOfJsD9hhqhPJzQGt=CHGQ@mail.gmail.com>
From: Jogi Dishank <jogidishank503@gmail.com>
Date: Mon, 28 Jul 2025 17:11:39 +0530
X-Gm-Features: Ac12FXwgNQhUEFcH8EUcpBGdznEMdfxR6tBcRADaovPQEaIeeONILcfptvQ1uug
Message-ID: <CADorM--0n1zeT8jxT3LtjmqrP5Cp1g-hFS=oz_12SptjZwRWtw@mail.gmail.com>
Subject: Re: [PATCH] kcsan: clean up redundant empty macro arguments in atomic ops.
To: Marco Elver <elver@google.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, rathod.darshan.0896@gmail.com
Content-Type: multipart/alternative; boundary="000000000000048ee2063afbc7ae"
X-Original-Sender: jogidishank503@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UifswnEo;       spf=pass
 (google.com: domain of jogidishank503@gmail.com designates
 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=jogidishank503@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

--000000000000048ee2063afbc7ae
Content-Type: text/plain; charset="UTF-8"

Yes, I build the kernel with the change.
And it's build without any error.


*On Mon, 28 Jul 2025 at 16:25, Marco Elver <elver@google.com
<elver@google.com>> wrote:*

>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
>
> *On Mon, 28 Jul 2025 at 12:43, Dishank Jogi <jogidishank503@gmail.com
> <jogidishank503@gmail.com>> wrote: > >
> --------------------------------------------------------- > > - Removed
> unnecessary trailing commas from DEFINE_TSAN_ATOMIC_RMW() macro >   calls
> within DEFINE_TSAN_ATOMIC_OPS() in kernel/kcsan/core.c > > - It passes
> checkpatch.pl <http://checkpatch.pl> with no errors or warnings and >
>  introduces no functional changes. > >
> --------------------------------------------------------- > >
> Signed-off-by: Dishank Jogi <jogidishank503@gmail.com
> <jogidishank503@gmail.com>> Nack. Did you compile the kernel with this? >
> --- >  kernel/kcsan/core.c | 12 ++++++------ >  1 file changed, 6
> insertions(+), 6 deletions(-) > > diff --git a/kernel/kcsan/core.c
> b/kernel/kcsan/core.c > index 8a7baf4e332e..f2ec7fa4a44d 100644 > ---
> a/kernel/kcsan/core.c > +++ b/kernel/kcsan/core.c > @@ -1257,12 +1257,12 @@
> static __always_inline void kcsan_atomic_builtin_memorder(int memorder) >
> #define DEFINE_TSAN_ATOMIC_OPS(bits)
>                        \ >         DEFINE_TSAN_ATOMIC_LOAD_STORE(bits);
>                                                    \ >
>  DEFINE_TSAN_ATOMIC_RMW(exchange, bits, _n);
>                 \ > -       DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits, );
>                                            \ > -
>  DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits, );
>                  \ > -       DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits, );
>                                              \ > -
>  DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits, );
>                 \ > -       DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits, );
>                                            \ > -
>  DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits, );
>                 \ > +       DEFINE_TSAN_ATOMIC_RMW(fetch_add, bits);
>                                          \ > +
>  DEFINE_TSAN_ATOMIC_RMW(fetch_sub, bits);
>                \ > +       DEFINE_TSAN_ATOMIC_RMW(fetch_and, bits);
>                                          \ > +
>  DEFINE_TSAN_ATOMIC_RMW(fetch_or, bits);
>               \ > +       DEFINE_TSAN_ATOMIC_RMW(fetch_xor, bits);
>                                        \ > +
>  DEFINE_TSAN_ATOMIC_RMW(fetch_nand, bits);
>               \ >         DEFINE_TSAN_ATOMIC_CMPXCHG(bits, strong, 0);
>                                          \ >
>  DEFINE_TSAN_ATOMIC_CMPXCHG(bits, weak, 1);
>                  \ >         DEFINE_TSAN_ATOMIC_CMPXCHG_VAL(bits) > -- >
> 2.43.0 >*
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CADorM--0n1zeT8jxT3LtjmqrP5Cp1g-hFS%3Doz_12SptjZwRWtw%40mail.gmail.com.

--000000000000048ee2063afbc7ae
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGRpdiBkaXI9Imx0ciI+PGRpdiBjbGFzcz0iZ21haWxfZGVmYXVsdCIgc3R5bGU9ImZvbnQtZmFt
aWx5OiZxdW90O2FyaWFsIGJsYWNrJnF1b3Q7LHNhbnMtc2VyaWYiPjxiPjwvYj48L2Rpdj48ZGl2
IGRpcj0ibHRyIj48ZGl2IGNsYXNzPSJnbWFpbF9kZWZhdWx0IiBzdHlsZT0iIj48Zm9udCBmYWNl
PSJhcmlhbCwgc2Fucy1zZXJpZiI+WWVzLCBJIGJ1aWxkwqB0aGUga2VybmVsIHdpdGggdGhlIGNo
YW5nZS7CoDxicj5BbmQgaXQmIzM5O3MgYnVpbGQgd2l0aG91dCBhbnkgZXJyb3IuwqA8L2ZvbnQ+
PC9kaXY+PC9kaXY+PGI+PGJyPjwvYj48ZGl2IGNsYXNzPSJnbWFpbF9xdW90ZSBnbWFpbF9xdW90
ZV9jb250YWluZXIiPjxkaXYgZGlyPSJsdHIiIGNsYXNzPSJnbWFpbF9hdHRyIj48Yj5PbiBNb24s
IDI4IEp1bCAyMDI1IGF0IDE2OjI1LCBNYXJjbyBFbHZlciAmbHQ7PGEgaHJlZj0ibWFpbHRvOmVs
dmVyQGdvb2dsZS5jb20iPmVsdmVyQGdvb2dsZS5jb208L2E+Jmd0OyB3cm90ZTo8YnI+PC9iPjwv
ZGl2PjxibG9ja3F1b3RlIGNsYXNzPSJnbWFpbF9xdW90ZSIgc3R5bGU9Im1hcmdpbjowcHggMHB4
IDBweCAwLjhleDtib3JkZXItbGVmdDoxcHggc29saWQgcmdiKDIwNCwyMDQsMjA0KTtwYWRkaW5n
LWxlZnQ6MWV4Ij48Yj5PbiBNb24sIDI4IEp1bCAyMDI1IGF0IDEyOjQzLCBEaXNoYW5rIEpvZ2kg
Jmx0OzxhIGhyZWY9Im1haWx0bzpqb2dpZGlzaGFuazUwM0BnbWFpbC5jb20iIHRhcmdldD0iX2Js
YW5rIj5qb2dpZGlzaGFuazUwM0BnbWFpbC5jb208L2E+Jmd0OyB3cm90ZTo8YnI+DQomZ3Q7PGJy
Pg0KJmd0OyAtLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0t
LS0tLS0tLS08YnI+DQomZ3Q7PGJyPg0KJmd0OyAtIFJlbW92ZWQgdW5uZWNlc3NhcnkgdHJhaWxp
bmcgY29tbWFzIGZyb20gREVGSU5FX1RTQU5fQVRPTUlDX1JNVygpIG1hY3JvPGJyPg0KJmd0O8Kg
IMKgY2FsbHMgd2l0aGluIERFRklORV9UU0FOX0FUT01JQ19PUFMoKSBpbiBrZXJuZWwva2NzYW4v
Y29yZS5jPGJyPg0KJmd0Ozxicj4NCiZndDsgLSBJdCBwYXNzZXMgPGEgaHJlZj0iaHR0cDovL2No
ZWNrcGF0Y2gucGwiIHJlbD0ibm9yZWZlcnJlciIgdGFyZ2V0PSJfYmxhbmsiPmNoZWNrcGF0Y2gu
cGw8L2E+IHdpdGggbm8gZXJyb3JzIG9yIHdhcm5pbmdzIGFuZDxicj4NCiZndDvCoCDCoGludHJv
ZHVjZXMgbm8gZnVuY3Rpb25hbCBjaGFuZ2VzLjxicj4NCiZndDs8YnI+DQomZ3Q7IC0tLS0tLS0t
LS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLTxicj4NCiZn
dDs8YnI+DQomZ3Q7IFNpZ25lZC1vZmYtYnk6IERpc2hhbmsgSm9naSAmbHQ7PGEgaHJlZj0ibWFp
bHRvOmpvZ2lkaXNoYW5rNTAzQGdtYWlsLmNvbSIgdGFyZ2V0PSJfYmxhbmsiPmpvZ2lkaXNoYW5r
NTAzQGdtYWlsLmNvbTwvYT4mZ3Q7PGJyPg0KPGJyPg0KTmFjay48YnI+DQo8YnI+DQpEaWQgeW91
IGNvbXBpbGUgdGhlIGtlcm5lbCB3aXRoIHRoaXM/PGJyPg0KPGJyPg0KJmd0OyAtLS08YnI+DQom
Z3Q7wqAga2VybmVsL2tjc2FuL2NvcmUuYyB8IDEyICsrKysrKy0tLS0tLTxicj4NCiZndDvCoCAx
IGZpbGUgY2hhbmdlZCwgNiBpbnNlcnRpb25zKCspLCA2IGRlbGV0aW9ucygtKTxicj4NCiZndDs8
YnI+DQomZ3Q7IGRpZmYgLS1naXQgYS9rZXJuZWwva2NzYW4vY29yZS5jIGIva2VybmVsL2tjc2Fu
L2NvcmUuYzxicj4NCiZndDsgaW5kZXggOGE3YmFmNGUzMzJlLi5mMmVjN2ZhNGE0NGQgMTAwNjQ0
PGJyPg0KJmd0OyAtLS0gYS9rZXJuZWwva2NzYW4vY29yZS5jPGJyPg0KJmd0OyArKysgYi9rZXJu
ZWwva2NzYW4vY29yZS5jPGJyPg0KJmd0OyBAQCAtMTI1NywxMiArMTI1NywxMiBAQCBzdGF0aWMg
X19hbHdheXNfaW5saW5lIHZvaWQga2NzYW5fYXRvbWljX2J1aWx0aW5fbWVtb3JkZXIoaW50IG1l
bW9yZGVyKTxicj4NCiZndDvCoCAjZGVmaW5lIERFRklORV9UU0FOX0FUT01JQ19PUFMoYml0cynC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoFw8YnI+DQomZ3Q7wqAgwqAgwqAg
wqAgwqBERUZJTkVfVFNBTl9BVE9NSUNfTE9BRF9TVE9SRShiaXRzKTvCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoFw8YnI+DQomZ3Q7wqAgwqAgwqAgwqAgwqBERUZJTkVfVFNBTl9BVE9NSUNfUk1X
KGV4Y2hhbmdlLCBiaXRzLCBfbik7wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgXDxicj4NCiZndDsgLcKgIMKgIMKg
IMKgREVGSU5FX1RTQU5fQVRPTUlDX1JNVyhmZXRjaF9hZGQsIGJpdHMsICk7wqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqBcPGJyPg0KJmd0OyAtwqAgwqAgwqAgwqBERUZJTkVfVFNBTl9BVE9NSUNfUk1XKGZldGNo
X3N1YiwgYml0cywgKTvCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoFw8YnI+DQomZ3Q7IC3CoCDCoCDCoCDCoERF
RklORV9UU0FOX0FUT01JQ19STVcoZmV0Y2hfYW5kLCBiaXRzLCApO8KgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
XDxicj4NCiZndDsgLcKgIMKgIMKgIMKgREVGSU5FX1RTQU5fQVRPTUlDX1JNVyhmZXRjaF9vciwg
Yml0cywgKTvCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCBcPGJyPg0KJmd0OyAtwqAgwqAgwqAgwqBERUZJTkVf
VFNBTl9BVE9NSUNfUk1XKGZldGNoX3hvciwgYml0cywgKTvCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoFw8YnI+
DQomZ3Q7IC3CoCDCoCDCoCDCoERFRklORV9UU0FOX0FUT01JQ19STVcoZmV0Y2hfbmFuZCwgYml0
cywgKTvCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCBcPGJyPg0KJmd0OyArwqAgwqAgwqAgwqBERUZJTkVfVFNBTl9B
VE9NSUNfUk1XKGZldGNoX2FkZCwgYml0cyk7wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqBcPGJyPg0KJmd0OyAr
wqAgwqAgwqAgwqBERUZJTkVfVFNBTl9BVE9NSUNfUk1XKGZldGNoX3N1YiwgYml0cyk7wqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqBcPGJyPg0KJmd0OyArwqAgwqAgwqAgwqBERUZJTkVfVFNBTl9BVE9NSUNfUk1X
KGZldGNoX2FuZCwgYml0cyk7wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqBcPGJyPg0KJmd0OyArwqAgwqAgwqAg
wqBERUZJTkVfVFNBTl9BVE9NSUNfUk1XKGZldGNoX29yLCBiaXRzKTvCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCBcPGJyPg0KJmd0OyArwqAgwqAgwqAgwqBERUZJTkVfVFNBTl9BVE9NSUNfUk1XKGZldGNoX3hv
ciwgYml0cyk7wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqBcPGJyPg0KJmd0OyArwqAgwqAgwqAgwqBERUZJTkVf
VFNBTl9BVE9NSUNfUk1XKGZldGNoX25hbmQsIGJpdHMpO8KgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIFw8YnI+DQom
Z3Q7wqAgwqAgwqAgwqAgwqBERUZJTkVfVFNBTl9BVE9NSUNfQ01QWENIRyhiaXRzLCBzdHJvbmcs
IDApO8KgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgXDxicj4NCiZndDvCoCDCoCDCoCDCoCDCoERFRklORV9UU0FOX0FU
T01JQ19DTVBYQ0hHKGJpdHMsIHdlYWssIDEpO8KgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgXDxicj4NCiZndDvC
oCDCoCDCoCDCoCDCoERFRklORV9UU0FOX0FUT01JQ19DTVBYQ0hHX1ZBTChiaXRzKTxicj4NCiZn
dDsgLS08YnI+DQomZ3Q7IDIuNDMuMDxicj4NCiZndDs8L2I+PGJyPg0KPC9ibG9ja3F1b3RlPjwv
ZGl2PjwvZGl2Pg0KDQo8cD48L3A+CgotLSA8YnIgLz4KWW91IHJlY2VpdmVkIHRoaXMgbWVzc2Fn
ZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0aGUgR29vZ2xlIEdyb3VwcyAmcXVvdDtr
YXNhbi1kZXYmcXVvdDsgZ3JvdXAuPGJyIC8+ClRvIHVuc3Vic2NyaWJlIGZyb20gdGhpcyBncm91
cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20gaXQsIHNlbmQgYW4gZW1haWwgdG8gPGEg
aHJlZj0ibWFpbHRvOmthc2FuLWRldit1bnN1YnNjcmliZUBnb29nbGVncm91cHMuY29tIj5rYXNh
bi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhp
cyBkaXNjdXNzaW9uIHZpc2l0IDxhIGhyZWY9Imh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9t
c2dpZC9rYXNhbi1kZXYvQ0FEb3JNLS0wbjF6ZVQ4anhUM0x0am1xclA1Q3AxZy1oRlMlM0Rvel8x
MlNwdGpad1JXdHclNDBtYWlsLmdtYWlsLmNvbT91dG1fbWVkaXVtPWVtYWlsJnV0bV9zb3VyY2U9
Zm9vdGVyIj5odHRwczovL2dyb3Vwcy5nb29nbGUuY29tL2QvbXNnaWQva2FzYW4tZGV2L0NBRG9y
TS0tMG4xemVUOGp4VDNMdGptcXJQNUNwMWctaEZTJTNEb3pfMTJTcHRqWndSV3R3JTQwbWFpbC5n
bWFpbC5jb208L2E+LjxiciAvPgo=
--000000000000048ee2063afbc7ae--
