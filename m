Return-Path: <kasan-dev+bncBDV2D5O34IDRBPVQ2D5AKGQEINRDVKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id D055B25EBA4
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Sep 2020 00:59:10 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id v5sf3793624wrs.17
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Sep 2020 15:59:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599346750; cv=pass;
        d=google.com; s=arc-20160816;
        b=kOBH8uHLMG4/kc4dFETq7xfrUOsa8lK0QcGskERqkilGKZyP1fhK7HmYrxZRYajci9
         AfVqpydL151FYsfGJJIx5VjBMgw8Z54OjmL5kivzKIuEn4BsKtS56k+0m0x8UAPgKeJI
         oxT7BtWsljAappxQyWJ+MCfPn3fYd3RDJyxyV261vf/S/Wywqyeba4Iro8yCOVLI5l/p
         t2Qe4RJQwYx+sDLpeEx4K/bq6C65NgGxlBpIcYIiN60VFzFUt+8AsfhOLG70QMs8bYdz
         Yy2R0BssKSr/caBVDNBhExYnlpU2NX2UMIkTEuWDQ9BEb2GysSYQUWaHP3OmtOiNWeds
         TN9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Lz+8fFTdILIVylsXFdKi0adGyrFOd6YUD0YVx3ZTSbw=;
        b=R5VBmEcnZblzTTjAwL0D51C/di7gUpMaWJZW0dNz0gpsn7PUpmZR6s+zmdR4wrH8vb
         23tidlGzLZ5dpz+FxaSq3sHl+PkGvIU+b3P5PtdnEVARbMWILr0grufh72GLS2ZNXuFJ
         V7DiModR7jiRUuuL9XGRqarRPkroUWezbEIZThAvdnJnZU4nGzP8Al5l3OhOTN/1HTP5
         L9EchoF+60nX/vCx9DmBJOrevkorEBL8bXjjxVHkUhRjJiE80aw0OQm83TajHzODL1sR
         l+8z8enJorwRWpy07KRtYzw/BUN0xmTcrZ4JCNTPUnTxE70Hdn/xsgOgzKwDGZ1pi6pP
         ZRCg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=vaHSEXrZ;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Lz+8fFTdILIVylsXFdKi0adGyrFOd6YUD0YVx3ZTSbw=;
        b=Y2EWvmin6xRNpc6fD+U/wacCUgmosBopUAs7U+jMGAudsO0aZi/7ovLzeZuUDYYWMS
         8O/Amnc+fZNn2Ndiw6Lfh8VYkJZw6ITkm9r0MDpMY4z1vgGpA/N18n2Lrod5FqLMZqfF
         gz5TQd4BDEJycR95w0X9G6YmvhpCYb+2NQcXK1wa0nw936b3mA1ic6166/Q7iRfi3FQm
         yoPDdf5qvcCjzMt1HczRk9gF3xOjFaUFk8MCoZ6MpYnNX50vLRmvKz9gEOXwmAHBjR+v
         GoDKWiKkHEbHmibKH3GBKeqZJi5fRceE9CDCFDBc+s6pSy1oJNBqtqGx8l6eSFuENT1c
         BKRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Lz+8fFTdILIVylsXFdKi0adGyrFOd6YUD0YVx3ZTSbw=;
        b=FgywOjXFJzgfJtLrWQW+5ztpwzDx1tZfjjTrj3ON7zlwgX3U6IPyCvoO0zB89S7F2i
         +X6SnmpJ1E/VqO31WNBahwtyTn9uB8AEh7EFLe4l7+gnr2D8EOaL4PEBAWKNcSwWtS8y
         7XdvMFrOPnLZYDSixtk/L9LNyGc7adOY3aRKhLorXUH5WKpnLQK0hHXPOzusDGBRE5bZ
         3SB9NWWPQRDnwQEdklghx39a2KzovcFHxKU+yvFJ8FR7kZfL9RgXTOrSTqSyLkGHX89K
         st3OhU5J1HNpkuO0mxBPSU2xfJwCl0rlc4fko8ZxuO030EjXl7c4pSloKf5C+Ju+BkYM
         yHYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5330aoB4Kpe+F0jvyTK9ysva6hXgkZquRYelKmUlcKwgNEwLP6nC
	pBxSJ3j7voH0Q4kd9zdVdyc=
X-Google-Smtp-Source: ABdhPJxm5zCF/j1IlZifBN8lkvAhTCIZmLX21OjaLE4doCKHy/nxbrZ7IqwrqjF89ndRe9ywM0f/jA==
X-Received: by 2002:a1c:678a:: with SMTP id b132mr14386301wmc.10.1599346750557;
        Sat, 05 Sep 2020 15:59:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1b8a:: with SMTP id b132ls6254713wmb.2.gmail; Sat, 05
 Sep 2020 15:59:10 -0700 (PDT)
X-Received: by 2002:a1c:1d52:: with SMTP id d79mr14688729wmd.82.1599346749996;
        Sat, 05 Sep 2020 15:59:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599346749; cv=none;
        d=google.com; s=arc-20160816;
        b=t+OKy2OKi3eY/iil6dlGN4Nxrt77J/K66qi7LmiaRwRVPJUvWODZ42lIiEg//w81E1
         UvbTsKZKZg3rZ0hUqoSWWnmJc9hlDa6OIys117zZBh7vcPOaHrndWRIzDM00nTdtUNki
         yApXCRFXIAJR1df/eIBKauu384PqEGInGWjaeBNilAKjwUWE3MuR6/aVdWjmqyfloQvH
         S6hPLziRRr8yAAAfL7rfzb/eoAiA3lor12g3urs+kIdVTFkzgDkdTKEsBusRqUDbxbV+
         4heU1l4vMV5dxf1hpIQ0xt5Cr5w358/WY2jac/9kme7TmgdKVS/OmXeWKsTsDkIdrQmT
         F4FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=f90W80hQ28lIF5OQ4LUv4gqljn8+jRHIdXfT/P9SWyM=;
        b=gvEQr31yBxpBJBN1HQkIUEMrvE7DXAoWDYhmJBTFVBmG8IdlWJLcFCqeMkUDxnBQ9s
         v4cjvCGqXLSBRdPmSXb6zm96UDcHpuabZfBvONyQE3FvGleedj9k3KLRV6FTc55RwTHf
         +u3yBsfeOCgqI3NuWZKh3kfxMVpBJUBZQFIiydbN1s3Ubgs8EbX0c2xAmvggndVF7eqr
         eAKFfd9vkK+hERvtTXrxMEH5k1Gk+Zi4KNZzB+1rkcHo7mCAt8J1z5rrzTtAbg2ZI5pO
         mgfomhyigRpePkmjKnHNwGDotwGcuojmS29ObizCyMJkyfpZAyGBVCIVSowRNOuojq6x
         aWBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=vaHSEXrZ;
       spf=pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id k14si318796wrx.1.2020.09.05.15.59.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 05 Sep 2020 15:59:09 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of rdunlap@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) client-ip=2001:8b0:10b:1236::1;
Received: from [2601:1c0:6280:3f0::19c2]
	by casper.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kEh9I-0002Ad-0O; Sat, 05 Sep 2020 22:59:08 +0000
Subject: Re: [RFC PATCH 2/2] x86/cmdline: Use strscpy to initialize
 boot_command_line
To: Arvind Sankar <nivedita@alum.mit.edu>, x86@kernel.org,
 kasan-dev@googlegroups.com
Cc: Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org
References: <20200905222323.1408968-1-nivedita@alum.mit.edu>
 <20200905222323.1408968-3-nivedita@alum.mit.edu>
From: Randy Dunlap <rdunlap@infradead.org>
Message-ID: <f5a29e70-7d11-16ec-8d72-ed71da4124c1@infradead.org>
Date: Sat, 5 Sep 2020 15:59:04 -0700
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.11.0
MIME-Version: 1.0
In-Reply-To: <20200905222323.1408968-3-nivedita@alum.mit.edu>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: rdunlap@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=vaHSEXrZ;
       spf=pass (google.com: best guess record for domain of
 rdunlap@infradead.org designates 2001:8b0:10b:1236::1 as permitted sender) smtp.mailfrom=rdunlap@infradead.org
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

On 9/5/20 3:23 PM, Arvind Sankar wrote:
> The x86 boot protocol requires the kernel command line to be a
> NUL-terminated string of length at most COMMAND_LINE_SIZE (including the
> terminating NUL). In case the bootloader messed up and the command line
> is too long (hence not NUL-terminated), use strscpy to copy the command
> line into boot_command_line. This ensures that boot_command_line is
> NUL-terminated, and it also avoids accessing beyond the actual end of
> the command line if it was properly NUL-terminated.
> 
> Note that setup_arch() will already force command_line to be
> NUL-terminated by using strlcpy(), as well as boot_command_line if a
> builtin command line is configured. If boot_command_line was not
> initially NUL-terminated, the strlen() inside of strlcpy()/strlcat()
> will run beyond boot_command_line, but this is almost certainly
> harmless in practice.
> 
> Signed-off-by: Arvind Sankar <nivedita@alum.mit.edu>

Hi,
Just for my enlightenment, what would be wrong with:

(which is done in arch/m68/kernel/setup_no.c)

> ---
>  arch/x86/kernel/head64.c  |  2 +-
>  arch/x86/kernel/head_32.S | 11 +++++------
>  2 files changed, 6 insertions(+), 7 deletions(-)
> 
> diff --git a/arch/x86/kernel/head64.c b/arch/x86/kernel/head64.c
> index cbb71c1b574f..740dd05b9462 100644
> --- a/arch/x86/kernel/head64.c
> +++ b/arch/x86/kernel/head64.c
> @@ -410,7 +410,7 @@ static void __init copy_bootdata(char *real_mode_data)
>  	cmd_line_ptr = get_cmd_line_ptr();
>  	if (cmd_line_ptr) {
>  		command_line = __va(cmd_line_ptr);
> 		memcpy(boot_command_line, command_line, COMMAND_LINE_SIZE);
> +		boot_command_line[COMMAND_LINE_SIZE - 1] = 0;
>  	}
>  
>  	/*


thanks.
-- 
~Randy

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f5a29e70-7d11-16ec-8d72-ed71da4124c1%40infradead.org.
