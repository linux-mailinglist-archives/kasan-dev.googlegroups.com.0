Return-Path: <kasan-dev+bncBC7M5BFO7YCRBCOM66TQMGQECXQJIVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 39E90799EE1
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Sep 2023 17:51:39 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-414e1c2b660sf36331981cf.1
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Sep 2023 08:51:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694361098; cv=pass;
        d=google.com; s=arc-20160816;
        b=EYEB8YhiPku8MULdVFVbcS9u6grSdZuSRUYJLt3pZY0Rjj3AJFDLggs3CxgNOI0JnY
         3Un8G3Y846JRHe3ofQFP0gh8EmjLrCCJeTGEO2vfI/xcEW6H5ifjOt9k3J8qqgeLJDmf
         /QQ2NqKLfNSUR1IPU5Y51tLgU7XZO9TIzAxsLJUH12VjPkMPq8VnPsfaHdCWUxlbjg46
         x3JM9WDy7S3m11f4J5mCpzFcnFSEvGE74UZisow4LpHWwGrt90oZ/NZ2JFGkMsPM6tlD
         jk3LBdZGwTAeO/aWq9GnRzPhyjD8y4OqpKBhM1zt+Iz4DomQZ0gpEclzYomdm9P4OH4k
         hbRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=ZBytUzYifu4VCHSN4muW+uiAg3IaWljmbHm7GVtNLRs=;
        fh=adScp5UDE1YnVcPA6fwd6dUvHXI9u3Gf0Weaxk78Ejs=;
        b=ZbgWIWCbXMXTsak5zE2vvAwzgACOPXb2k3xJv/ei38s3gOZ2V868v6ikEz98kzN0PY
         8FL2y3kxf2Ls+l2uZ4Ve/u9oVWJ73v8CuN+OG3XIE6laxV7PAyMGZgY6Ugv6OqLzq/5M
         6klD2WinSEIXsDyT5uFDcyp8bDd4X75pGlg0+0godXGiFumYq1QfcY4dOd0vKqblvHCz
         cbl4gpOheysMOf9TGYcy5uGQTxKKAMgWQi7UFCd/rDt4BKHZNJ4w3w5fIJaZV+YNAMV2
         PJ0nbuz/XQkaLXP0Vur+9Fcj2vQgD77ZH1HWOH67dq3g+SNl24JVl4rO/UFlmvb6KB57
         OEQw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=BAvGmOB2;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694361098; x=1694965898; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZBytUzYifu4VCHSN4muW+uiAg3IaWljmbHm7GVtNLRs=;
        b=n77PfQOjpG6LrholbJzKpluBE0fZ92WGvhbHLjBxsW6LYGMrkdTDSSg/nDpPzmV/dY
         tJzUwAKUy6DlyATTU9w/FmiE7pIm5MjPCirMWv70VzxWD5qQczGWGG1g+N0UeYzhw6pJ
         IZcDhL9vZ1TtomlW7+MiBoN1WfnxxJ8oit4SMH7J/PZNcOGdCymdl7ObQSZZmVoOIcS8
         hswhnsUugigz9M4dYWh2yb+ZiVy6hpFZ+T5omgEQpbux+hSy/FxKHKq3rdj4yJf3lZdr
         F/AQk2gfj2DufqJun2DzlHMkkLDuKNL4ukpmcVvKEKHugYHrKmm7pgn7ZJWpbeZhfLK6
         Tedw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694361098; x=1694965898;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ZBytUzYifu4VCHSN4muW+uiAg3IaWljmbHm7GVtNLRs=;
        b=BFmWDEsVllkg09aTOtacvQCxVlGjaG6bMFmrBqw2tvVN1VT7gKU936Bt5kDInrejmz
         miQvncwFEZHcrgC01M0ePFLSK2MBRu2UPuPa5qlhGEmkraS4OYkhefKV1axkESpEWGf6
         jAgZ7gSeBdC1ziWzPnUCkCKkGe/yW7t8XuPo5WnA8jgwbAskmNce+oKz7mrk4lZzxcPm
         L8weoDpVr6WxbRI6z5sQq6pwEwDns4Srn+P4aO4679FfrE9kFTUQ5waLvVhxv+IQDVCP
         uULSfd5ap7NLHdd5AjI3qSmJORbD5VyaC0pLwe43K0rG2ibEv/Roh94QPDlafBYxZFxl
         mPcg==
X-Gm-Message-State: AOJu0YzHvqV/EaVHVDsXQokFnBjZdpnemMO/LcnGYFJFK/nlicq9OPge
	OTtMGjEKFeratKly56igjWI=
X-Google-Smtp-Source: AGHT+IET8+k/FDeds6NgWFVs8IYskrtGwIhgszVP1BzbUmzQ2SCNtvUqPFYFm8QoJWYP743rmu7jhw==
X-Received: by 2002:a05:622a:1a9d:b0:403:aa3a:36d with SMTP id s29-20020a05622a1a9d00b00403aa3a036dmr13743766qtc.5.1694361097883;
        Sun, 10 Sep 2023 08:51:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:5592:b0:415:2683:c8f8 with SMTP id
 fk18-20020a05622a559200b004152683c8f8ls160008qtb.2.-pod-prod-00-us; Sun, 10
 Sep 2023 08:51:37 -0700 (PDT)
X-Received: by 2002:a05:6122:12eb:b0:493:fbe7:e71d with SMTP id k11-20020a05612212eb00b00493fbe7e71dmr3646528vkp.6.1694361096951;
        Sun, 10 Sep 2023 08:51:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694361096; cv=none;
        d=google.com; s=arc-20160816;
        b=DgIYug8vpwX2I4w3oB6pp6ysq90yAO58IUAfnKMIQSnwFGThmVcg+A8zfe1Ws/B8+S
         kGB2Qe3SLehJRMYEfnVJfHid9wQH8LpJ4BLI5uY8zIygihnqHJfwvzXT3BvGWw48+5Wl
         PPZ+vEe9hxEHZJJgLvSFn/R8afxpy/8v5XQ1plrAESqMdpGvxskROSLTtrj66YkwrtTW
         25S3aW6+/HZ7iSEHvfzMjY6S2kCiQE7E5yvFl9dsq/oPLi6nIbk3JTuoG/KuoPgV9q6N
         WATjZ3XwuxWkuZnf1Zg96Zt1FfVInylU804DC8qI6Ftqfj+qNAf/Kp3csqv3WL0ZJwGT
         Ge+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=Khig5fiAk2UrEWc554zDncIUcso6vVaeyXzrWK+GM7s=;
        fh=adScp5UDE1YnVcPA6fwd6dUvHXI9u3Gf0Weaxk78Ejs=;
        b=UXt+9Eu495MP4y0Sz8XHw88w6syPmL+RgW5BbWLJDCwRjweHlCmIwsFcpri2UoT0+W
         5ubGcolYPPVv+CtZFjeg9QQe2CQj+xnmXSQsZJQzulb9akCKxsoS3RF7xXEyWJ2yK7qA
         QXNAyToqFy7w8Bpst6MMtXNcRonpirxaKdvnK/1wclJUI67kZPk/DP8VQTQHOjNNpf4e
         1x7RXtUQl3FGMViEY6dG09j9ylLFlgcB/CDQ6+fa9gntFHhj+DgvtELItMI+dzsAO832
         Z8dJ9udl6eEmwNccexO20liWP22C8QkjKUOl3YmP0uo8xkbAOpuaLS7u2AIFW22DaKWp
         UDtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=BAvGmOB2;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-pj1-x1029.google.com (mail-pj1-x1029.google.com. [2607:f8b0:4864:20::1029])
        by gmr-mx.google.com with ESMTPS id dw8-20020a05613028c800b007a6109a9b8esi651245uab.0.2023.09.10.08.51.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 10 Sep 2023 08:51:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::1029 as permitted sender) client-ip=2607:f8b0:4864:20::1029;
Received: by mail-pj1-x1029.google.com with SMTP id 98e67ed59e1d1-268bc714ce0so3305518a91.0
        for <kasan-dev@googlegroups.com>; Sun, 10 Sep 2023 08:51:36 -0700 (PDT)
X-Received: by 2002:a17:90b:33c2:b0:267:f8f4:73ab with SMTP id lk2-20020a17090b33c200b00267f8f473abmr14111217pjb.16.1694361095692;
        Sun, 10 Sep 2023 08:51:35 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id w30-20020a17090a6ba100b0026b3a86b0d5sm4557834pjj.33.2023.09.10.08.51.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Sep 2023 08:51:34 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Sun, 10 Sep 2023 08:51:33 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: Feiyang Chen <chenfeiyang@loongson.cn>
Cc: chenhuacai@kernel.org, dvyukov@google.com, andreyknvl@gmail.com,
	loongarch@lists.linux.dev, kasan-dev@googlegroups.com,
	chris.chenfeiyang@gmail.com, loongson-kernel@lists.loongnix.cn
Subject: Re: [PATCH 2/2] LoongArch: Allow building with kcov coverage
Message-ID: <66522279-c933-4952-9a5a-64301074a74a@roeck-us.net>
References: <cover.1688369658.git.chenfeiyang@loongson.cn>
 <8d10b1220434432dbc089fab8df4e1cca048cd0c.1688369658.git.chenfeiyang@loongson.cn>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <8d10b1220434432dbc089fab8df4e1cca048cd0c.1688369658.git.chenfeiyang@loongson.cn>
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=BAvGmOB2;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2607:f8b0:4864:20::1029
 as permitted sender) smtp.mailfrom=groeck7@gmail.com
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

On Tue, Jul 04, 2023 at 08:53:32PM +0800, Feiyang Chen wrote:
> Add ARCH_HAS_KCOV to the LoongArch Kconfig. Also disable
> instrumentation of vdso.
> 
> Signed-off-by: Feiyang Chen <chenfeiyang@loongson.cn>

When trying to build loongarch:allmodconfig, this patch results in

Error log:
In file included from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/options.h:8,
                 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/tm.h:46,
                 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/backend.h:28,
                 from /opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/gcc-plugin.h:30,
                 from scripts/gcc-plugins/gcc-common.h:7,
                 from scripts/gcc-plugins/latent_entropy_plugin.c:78:
/opt/kernel/gcc-12.2.0-2.39-nolibc/loongarch64-linux-gnu/bin/../lib/gcc/loongarch64-linux-gnu/12.2.0/plugin/include/config/loongarch/loongarch-opts.h:31:10: fatal error: loongarch-def.h: No such file or directory
   31 | #include "loongarch-def.h"

for me. I tried with gcc 12.2 / binutils 2.39 and gcc 13.1 / binutils 2.40.

Reverting the patch or explicitly disabling CONFIG_GCC_PLUGINS fixes
the problem.

What compiler / binutils version combination is needed for this to work,
or, alternatively, how would I have to configure the compiler ?

Thanks,
Guenter

> ---
>  arch/loongarch/Kconfig       | 1 +
>  arch/loongarch/vdso/Makefile | 2 ++
>  2 files changed, 3 insertions(+)
> 
> diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
> index ed9a148cdcde..4c21a961ab88 100644
> --- a/arch/loongarch/Kconfig
> +++ b/arch/loongarch/Kconfig
> @@ -14,6 +14,7 @@ config LOONGARCH
>  	select ARCH_HAS_ACPI_TABLE_UPGRADE	if ACPI
>  	select ARCH_HAS_CPU_FINALIZE_INIT
>  	select ARCH_HAS_FORTIFY_SOURCE
> +	select ARCH_HAS_KCOV
>  	select ARCH_HAS_NMI_SAFE_THIS_CPU_OPS
>  	select ARCH_HAS_PTE_SPECIAL
>  	select ARCH_HAS_TICK_BROADCAST if GENERIC_CLOCKEVENTS_BROADCAST
> diff --git a/arch/loongarch/vdso/Makefile b/arch/loongarch/vdso/Makefile
> index 7bb794604af3..7dc87377688b 100644
> --- a/arch/loongarch/vdso/Makefile
> +++ b/arch/loongarch/vdso/Makefile
> @@ -5,6 +5,8 @@ ifdef CONFIG_KASAN
>  KASAN_SANITIZE := n
>  endif
>  
> +KCOV_INSTRUMENT := n
> +
>  # Include the generic Makefile to check the built vdso.
>  include $(srctree)/lib/vdso/Makefile
>  
> -- 
> 2.39.3
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66522279-c933-4952-9a5a-64301074a74a%40roeck-us.net.
