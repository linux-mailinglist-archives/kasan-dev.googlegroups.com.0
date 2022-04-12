Return-Path: <kasan-dev+bncBCT6537ZTEKRBJ4T22JAMGQEIZXY2UA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id B57294FE38A
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 16:16:08 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id w5-20020a67c905000000b00324c7bafd3asf1238409vsk.16
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Apr 2022 07:16:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649772967; cv=pass;
        d=google.com; s=arc-20160816;
        b=e2t7xNhzce5S934aUJksKeJmkWoarxcbU+hltIspkcHxpdqO9anevfox2anlWakwlc
         5CssnjGtX8hgUQXMP/SSXeQvUkKEnZQ6+NFv9mlwwbUgFn4gtDArX/A1dV9xid11MOxh
         7g1a4KI6IScF9OE9ziTIVosRByrLYPUWVIY+iAKkRZ8iDSrAzoIKlnwsaqHjIkGI0hO9
         iZtRbeOzSjn6UrVp1zD4cEksb2gbVyHerEKWQZYCWzsPpd4FYmKBB3kVP7aFQ6/2R3eq
         dkz4jpPm2SjU441Oadj/rgxuNiiLn/4b4wigfAz2G2L2WjKGaIP7O7eDzYnB5IwGJw1d
         /qRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=VU9DFXWLNKENVXbf+eKPUreu44XimblO0UtqHpe5+LI=;
        b=nGrzwIjbKa68aQ4oD9Zv3VTBGp9P6pprDiQiuvJypaM3rtY9LIDMYwbJVjA2ll1BMd
         EywQR37/F/AcNcSIak3aopJE55okDVTnMaUD7W3wDJBB4/sOgA4QXgTGpgJm6mobojVn
         hO+69rQsD3Lhr5LB70DOdJzYECYiEJ5iHqQUMZXANycql4VZSIZv6T8uuA6das+oGDM2
         qmrdzLiQtzfkS4CCRgISvBoaa4xLyvqwjTLUf6/qjm4zdnzb9bFfoL7QA+D9gnfdRNg5
         lZSK2VModI7uRQkYh5gysRjfRZWJVIw70FRp08SxcAn5r+eQFrl8961DTP1f59ZaEhQs
         TP/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=IJSMbnG8;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VU9DFXWLNKENVXbf+eKPUreu44XimblO0UtqHpe5+LI=;
        b=qi87iEeZraYJc0cFapHJcsH8cqyYV5/A3zsrjXxllkKwnRhWXhYvAeMcvlmVwK8enS
         BcR2xMc/vbjZ0rehZo3/87/xA3CWFbHB1DBtN37PISzOtEDTcPgYWueNWPDvT/ZCjT/8
         5eC5bEaTc3qY4tGaiwNo0Jqi7trrbUKibai8xcL00dkxWDzYxjABNk42JA9Skn3Pv44r
         bqiTqkAJJCAWDlbmp9/RXpx3rvFH0P76dRUThUlnN9IESnCaaqqNKfB0rqvmKj0DFfGS
         pE5vLabWqb0PD7P2I/cYGqHk0Nu2NWkAVp+OBs1MaydCgzVCE6QDwRWnBO0K/EAwj8XX
         iTkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VU9DFXWLNKENVXbf+eKPUreu44XimblO0UtqHpe5+LI=;
        b=oq6YQQXyxW31ceorvY3sy/dF7NGci9yY1dJK6c0W1KDlKwkj25v05Ar/BW8tsbKi7Y
         DGE+KfiTsBSJw3JVOq2046darvzUZEDVXOGxkFl8vEEg3i+4iVqCqx8I8Ws1xdaRf0YH
         5N255dfDgQ+5RBRPs/8xFUGsqVtyNjTWVgVaHLHu8hdnv0gPhUwPpSa3a4Cbpqedqmw0
         oMHxZk0wYOVfVuwCClhYEWzYZB/4JsRWourkOWGHHtJCy7rTleYnxekn7VKvEPWaRsay
         pJDkvAP/eydi+FwB+tD3jUJOCZCuyNOPgONJ/l9sc0sDrs5tcQuiI1lxo79cHCRJxs7i
         cOeg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530ow5+DJqD2sFDdyzOWWDt4kch3NQm7ScRAF4ZhS6t0l1ciuTj6
	eqSEy5uwHF3+O7VgxCQr05Y=
X-Google-Smtp-Source: ABdhPJz6udotla6tGz+O0ENasfTY65NR7X9pvbngG7mR9k6EjWCVD2hxayAATdSP4QuBFqz/8Y0tWQ==
X-Received: by 2002:a67:cb81:0:b0:328:da1:312b with SMTP id h1-20020a67cb81000000b003280da1312bmr8794532vsl.6.1649772967449;
        Tue, 12 Apr 2022 07:16:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:3ca4:b0:328:415a:878d with SMTP id
 c36-20020a0561023ca400b00328415a878dls4676827vsv.3.gmail; Tue, 12 Apr 2022
 07:16:06 -0700 (PDT)
X-Received: by 2002:a05:6102:c2:b0:328:6313:a07c with SMTP id u2-20020a05610200c200b003286313a07cmr2465445vsp.41.1649772966716;
        Tue, 12 Apr 2022 07:16:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649772966; cv=none;
        d=google.com; s=arc-20160816;
        b=s2vuxbZ01ljPXQ4X/Q/oRg/um4tWO6OVinJ+J3eOOmm8cQIQsJRU9kcAn9OK5lO0bk
         JTdiWMPMOOG79jKoGg8Agg0UNxZ2+5drib1tYuabT1RNR72E2+6Cq1hRvgWh+0MRpcUC
         AFSdjCoCAbEbEohOVac/fy0QRpQ4vqTiLwBS8MyEpSzEOHGtGZ5TwcL4/9IwxXsORZwi
         inVG9CF5ad0Ej9Z13QHern8G03acH86NsusmdWggRW6qs37qHLpX9MFv6sP+HAc/xFIf
         frvgUSTKSGQa4MM3ivr4jwQPeYu1i90f1ZOBFo4xezWGRGnHFh+MymgMm331Mk8DUXLy
         F62A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VZmM9EPcGSQlgz+kYS2izYo6zL5xWSQuZ08uT1qVjbw=;
        b=xDl4tW7aQxarqOgMmnqU3cBJC59VCQDsHmA4xuDQHt1xiGVmI/MaLmFv+M6J1dkLFe
         itFlqNNjRDJ/BvB93RibqgRZOGJFo51fuB6/fFSgZUUF3mfTT3XLwLmonHKR/EdKvcCv
         2eQNsjS4xUEYgGQqfY/1Tj/wIFkx0TfPCK5A4i3PveQD16JwX2LwR67TistH0DwS5McN
         sBoyCerB7qdCw7ta1MD8hRfre69HX1xk/Jt/MooF2tVP72qTiYhw/dujbgL4nhvZpyCt
         dmD9oD1CxretYHtnE1e/aSo7UeaDevLTYNgiEosg396g3B5qstFenJTKanJQAyGjHsuN
         03XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=IJSMbnG8;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id e2-20020a056102224200b0031b82c6b2c2si966538vsb.0.2022.04.12.07.16.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Apr 2022 07:16:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id q19so2308731ybd.6
        for <kasan-dev@googlegroups.com>; Tue, 12 Apr 2022 07:16:06 -0700 (PDT)
X-Received: by 2002:a25:c094:0:b0:641:10e0:cfd8 with SMTP id
 c142-20020a25c094000000b0064110e0cfd8mr12836500ybf.88.1649772966219; Tue, 12
 Apr 2022 07:16:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220412062942.022903016@linuxfoundation.org>
In-Reply-To: <20220412062942.022903016@linuxfoundation.org>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Tue, 12 Apr 2022 19:45:55 +0530
Message-ID: <CA+G9fYseyeNoxQwEWtiiU8dLs_1coNa+sdV-1nqoif6tER_46Q@mail.gmail.com>
Subject: Re: [PATCH 5.15 000/277] 5.15.34-rc1 review
To: Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Marco Elver <elver@google.com>
Cc: linux-kernel@vger.kernel.org, stable@vger.kernel.org, 
	torvalds@linux-foundation.org, akpm@linux-foundation.org, linux@roeck-us.net, 
	shuah@kernel.org, patches@kernelci.org, lkft-triage@lists.linaro.org, 
	pavel@denx.de, jonathanh@nvidia.com, f.fainelli@gmail.com, 
	sudipm.mukherjee@gmail.com, slade@sladewatkins.com, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=IJSMbnG8;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Tue, 12 Apr 2022 at 12:11, Greg Kroah-Hartman
<gregkh@linuxfoundation.org> wrote:
>
> This is the start of the stable review cycle for the 5.15.34 release.
> There are 277 patches in this series, all will be posted as a response
> to this one.  If anyone has any issues with these being applied, please
> let me know.
>
> Responses should be made by Thu, 14 Apr 2022 06:28:59 +0000.
> Anything received after that time might be too late.
>
> The whole patch series can be found in one patch at:
>         https://www.kernel.org/pub/linux/kernel/v5.x/stable-review/patch-5.15.34-rc1.gz
> or in the git tree and branch at:
>         git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable-rc.git linux-5.15.y
> and the diffstat can be found below.
>
> thanks,
>
> greg k-h


On linux stable-rc 5.15 x86 and i386 builds failed due to below error [1]
with config [2].

The finding is when kunit config is enabled the builds pass.
CONFIG_KUNIT=y

But with CONFIG_KUNIT not set the builds failed.

x86_64-linux-gnu-ld: mm/kfence/core.o: in function `__kfence_alloc':
core.c:(.text+0x901): undefined reference to `filter_irq_stacks'
make[1]: *** [/builds/linux/Makefile:1183: vmlinux] Error 1

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>

I see these three commits, I will bisect and get back to you

2f222c87ceb4 kfence: limit currently covered allocations when pool nearly full
e25487912879 kfence: move saving stack trace of allocations into
__kfence_alloc()
d99355395380 kfence: count unexpectedly skipped allocations


--
Linaro LKFT
https://lkft.linaro.org

[1] https://builds.tuxbuild.com/27h6Ztu4T35pY178Xg8EyAj7gIW/
[2] https://builds.tuxbuild.com/27h6Ztu4T35pY178Xg8EyAj7gIW/config

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYseyeNoxQwEWtiiU8dLs_1coNa%2BsdV-1nqoif6tER_46Q%40mail.gmail.com.
