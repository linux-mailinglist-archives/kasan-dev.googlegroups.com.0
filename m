Return-Path: <kasan-dev+bncBDO2BZXZRYJRBEWQTKQAMGQE2L6ZB4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id DCB246AD511
	for <lists+kasan-dev@lfdr.de>; Tue,  7 Mar 2023 03:57:23 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id o3-20020a5d6483000000b002cc4fe0f7fcsf1799692wri.7
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Mar 2023 18:57:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1678157843; cv=pass;
        d=google.com; s=arc-20160816;
        b=STTxiquN2PHoubS0ZGkBBMZuhn0MJErO9XBg+6A7RzPONiAYV0Jz3F3wRV9A7Juxx4
         9DfZHe8Vs6xZ9bJmp8ikH7RyGj4vK1CMCcn0tR5xj6w65rRek+ISpAtMk3nk+bo7aZd7
         dCM+jbKyHm0YISURkVULxJlUk4T+z50ikfIr0uk3KOjZ7KddEROpdfgDkDAyf+135bxs
         06T6W+SRfquhm4ymoA7pzDgZQJN8szSKWac/4zh/49vEHY8M2Pff4RYYV3chvx9FkiiI
         bU2zZY5rSLyHbXzisLHYD4Td+z0jRWvH7qwEEbowzQUXbHJCv0d5rSgiTgrFgWoAadel
         Q59Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=BtM1TmyWxaW4AktN6YEC+0pk/CaeHLqSteuelT6c9eo=;
        b=yIOVwxow4YVasALJj6wpWDpOptzupbN+PwHECRfe8eeM9GPUoxdvMo8SF/6V9hFDdZ
         XHqFL7lJNzSqSSo9aV/gz7PinkHs4T3lk2ThEbA+K63q/R8Sr1GVPEQGkmRCMVkC1Nxd
         eMRGSlW1LTcBHIOHXzf+JqjCutFuO9atpvD+OLr/LcHn31uhAvhfNlhnWm7RhPNrPYPH
         ZYxnBA7nj0YOlNSPYZ/h9pPZq9uI2Ke/i+Nifm4eT6kvRtHmfytPj/8ZS8nPAlatMnI3
         u+Z7TyVr0Md2FD4292mMjsZ1zyniDIJvNCvotAi+SRNMvzpMZJIgstOFYTT+C5AWeVrT
         1UsQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G0KrM8Mg;
       spf=pass (google.com: domain of chathura.abeyrathne.lk@gmail.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=chathura.abeyrathne.lk@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1678157843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BtM1TmyWxaW4AktN6YEC+0pk/CaeHLqSteuelT6c9eo=;
        b=sUjz+V5hSBCWkByyjQoCNl8HWRA/clV7iKyyJAU0vIF5GG3eifjdAQaCz4xO9ASb7x
         UIg+91Rv5+t+vEl1Hwk5WoYcd4FRoN3uyAD7QxOETHunViVlQT7avGHI6w1v94K1gzjM
         X/nKsdRzPiSPMFItLtfjzaVIClTqzjAYly4Laqwx123RhJJQfBZoKovUDUmMzC7X1Cxm
         FB6kCdO9dWyl9HqFLghbCrqf7KfJRpRKzrseyigotsOcn7qzMMmD793vhG8UIP0fwVTq
         3csblh7Lvfpsesfm9Z9+BREtPJj18UI6RB0QZjHNWx7pungw9YLLfyWj9ND0qIzrIG6k
         3T9Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1678157843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=BtM1TmyWxaW4AktN6YEC+0pk/CaeHLqSteuelT6c9eo=;
        b=A+VdTAhcMi0qGYx5l80bm11lfrsMa02omAA9QZiIH2LHer+RUygAEcrqCS3jeOw88q
         /TD+VPBVoCaUABI77X3ijPiiW6GX0amKO+vRZEV0NmOWdywplqg+l29SryZjwc+E06GF
         ON0tLaJ4gbR8K3ZysY2ZPrjokBUOuvomi6GjuCOmqvHMdPBPJP0JFgSrGCOIsQspX3ia
         huo14/ybA3WpVbkgCn6fePo7A2/mn/vF8Ye8io+3KR8ZTcyRK5IlM8X/LNRAE1ymT8ky
         U3hU6SurRbla6sKw9SQJwEhAprnZ3fb+F/+8LvCv9/IZU8aAwQKIpCsD/pSXaHv6YfDZ
         Juag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1678157843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BtM1TmyWxaW4AktN6YEC+0pk/CaeHLqSteuelT6c9eo=;
        b=2nXRpGkZ0dD2C/5mcc5hoppr7dPqrgcIZ+/34YxHo1sVuCVliop6VrrE2Sq6Gb9Ol7
         9lYZ2F6OnFshFC/ma23NDkucCt3wAK7weGkQskXb0oPESMiT6rM+/QgkqLl5dTNMYLD5
         zdEq56stqr0wNu1excXTFG6hP1zFl5sGcqmsIMczGcGXe/ZimzG/1PZQPoJAx6USGUUT
         lqTVWNOi/6lILCnhatX285iubFP02W4dbO1R+bCZXlYjtYkXISFAWI5VxXHLzK1OZTuD
         /25TKnrUJdJIrc3bBimjL5lXpMZv0qsnOEwwyAJL4qY/8JsvTo3mEKIwT5zBFq2ED7Uh
         nXew==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKVkCO3NArVxnb0TG75ejBmIzOJNZLfgNzryckIeopeinm5zZMh8
	KEplGTonrOf/I8fG2LAOODE=
X-Google-Smtp-Source: AK7set+vhBeZbu9kyhIGi0hfDGeVmld9N1R43nuM88T2CVucQ6DahzNmc8MFeNHpwLWTZ2rk8ZYBWQ==
X-Received: by 2002:adf:f88f:0:b0:2cb:8616:d3dd with SMTP id u15-20020adff88f000000b002cb8616d3ddmr2793781wrp.7.1678157843113;
        Mon, 06 Mar 2023 18:57:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3ba7:b0:3e2:19b0:7006 with SMTP id
 n39-20020a05600c3ba700b003e219b07006ls6250065wms.3.-pod-control-gmail; Mon,
 06 Mar 2023 18:57:21 -0800 (PST)
X-Received: by 2002:a05:600c:510e:b0:3ea:8ed9:8f03 with SMTP id o14-20020a05600c510e00b003ea8ed98f03mr11234425wms.24.1678157841605;
        Mon, 06 Mar 2023 18:57:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1678157841; cv=none;
        d=google.com; s=arc-20160816;
        b=weDCPBVwpuat53XP9R4lJ3BTJWsys7lravuwrTJsfq2/iDpOb3XsRscuuZLv+Zz+Bn
         NzrvBHaD82+4W9ln0D7Sf6HZu6qFt46Aj3i+rg/yjnjw/OHDrtroONuWhuiGiXkT3D+Z
         3KDMKpdSBy5ODlpLYKO5P+m8nbcGa3CuxwEDK0TLnhxRWnTiSInSZbKzCV637OeAYmh1
         Y3WR0Y/JGV+ArH7ipnuJxeXO9PPMaWy6YHucqLQzTDosKHWzysEyoG0tCdD8cxEn/x+5
         65GLbHRYHmw9O6kTmYHsraCm9X1CVYzv65nLqFtfILSQsyo4OIcz1uL+0QoeaDV0xfG4
         KEcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MXE3r4DRRZF4vWFB+51VIYNyLys1Cywxy6liIMjnpXg=;
        b=OQYQ6U+bP2ybJzYccGxwTBffo6Hbokd9gdfplrHO9VUosvbYU8ccb1UmLs4JFgwEo3
         y7K3HW79Eob93Ylj1MzQfF7qU358ir+vVMjDwUEzVZykCElbRUc20ARuv6TMWeyZWEDI
         +e3yN61aSIErvly7oSUrwH3762CyWrwgkbg92bcXquNkbO+9WwFKe+GsThblrswdcoiR
         pnmTrZ//j8Z8tMoin2fvh61KPDcwyT9iNb9KN4/XKA2F+3n7jkdMClBeXROBn7Yhz725
         Aa/lgp3Qs72uXOXGoGxa+fimuGg6PkGnBFGTwwS632aLRkLuMrU20548TR8O8ZaA3B4B
         zF1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=G0KrM8Mg;
       spf=pass (google.com: domain of chathura.abeyrathne.lk@gmail.com designates 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=chathura.abeyrathne.lk@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lf1-x136.google.com (mail-lf1-x136.google.com. [2a00:1450:4864:20::136])
        by gmr-mx.google.com with ESMTPS id b11-20020a05600018ab00b002c59c98f5dasi425408wri.3.2023.03.06.18.57.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 06 Mar 2023 18:57:21 -0800 (PST)
Received-SPF: pass (google.com: domain of chathura.abeyrathne.lk@gmail.com designates 2a00:1450:4864:20::136 as permitted sender) client-ip=2a00:1450:4864:20::136;
Received: by mail-lf1-x136.google.com with SMTP id i9so15381777lfc.6
        for <kasan-dev@googlegroups.com>; Mon, 06 Mar 2023 18:57:21 -0800 (PST)
X-Received: by 2002:ac2:46db:0:b0:4e1:d025:789e with SMTP id
 p27-20020ac246db000000b004e1d025789emr4022786lfo.13.1678157841053; Mon, 06
 Mar 2023 18:57:21 -0800 (PST)
MIME-Version: 1.0
References: <CAD7mqryyz0PGHotBxvME7Ff4V0zLS+OcL8=9z4TakaKagPBdLw@mail.gmail.com>
 <789371c4-47fd-3de5-d6c0-bb36b2864796@ghiti.fr> <CAD7mqrzv-jr_o2U3Kz7vTgcsOYPKgwHW-L=ARAucAPPJgs4HCw@mail.gmail.com>
 <CAD7mqryDQCYyJ1gAmtMm8SASMWAQ4i103ptTb0f6Oda=tPY2=A@mail.gmail.com>
 <067b7dda-8d3d-a26c-a0b1-bd6472a4b04d@ghiti.fr> <CACT4Y+avaVT4sBOioxm8N+iH26udKwAogRhjMwGWcp4zzC8JdA@mail.gmail.com>
In-Reply-To: <CACT4Y+avaVT4sBOioxm8N+iH26udKwAogRhjMwGWcp4zzC8JdA@mail.gmail.com>
From: Chathura Rajapaksha <chathura.abeyrathne.lk@gmail.com>
Date: Mon, 6 Mar 2023 21:57:09 -0500
Message-ID: <CAD7mqrxY_BLP3fS0BnZNaGK+4j2cFjPYyWKehh7oe1f95Ca7iA@mail.gmail.com>
Subject: Re: RISC-V Linux kernel not booting up with KASAN enabled
To: Dmitry Vyukov <dvyukov@google.com>
Cc: alex@ghiti.fr, linux-riscv@lists.infradead.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: chathura.abeyrathne.lk@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=G0KrM8Mg;       spf=pass
 (google.com: domain of chathura.abeyrathne.lk@gmail.com designates
 2a00:1450:4864:20::136 as permitted sender) smtp.mailfrom=chathura.abeyrathne.lk@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Thanks, Dmitry and Alex. Let me know if you need anything else from me.
Please let me know if you have a fix for this bug, I will be happy to verify.

Best regards,
Chath

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAD7mqrxY_BLP3fS0BnZNaGK%2B4j2cFjPYyWKehh7oe1f95Ca7iA%40mail.gmail.com.
