Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBWUJ7KCAMGQETU4IQXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id E52AA380B33
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 16:10:35 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id s8-20020a5b04480000b029049fb35700b9sf36723292ybp.5
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 07:10:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621001435; cv=pass;
        d=google.com; s=arc-20160816;
        b=J9DEkrp4kSK9wVI8/LovbBClN+9ct9QFDTq2b55dw0ksM8OwqOqmAhwpZWHDy6eVa/
         Tv12pCkLWIhRxPmQvzPN+f/HyiJvzmoK1cCKsMUTRar5iYRa/jKZOzYae+xVqMY6dbJ+
         Qr3mYfdvsUBKw0umrrOO4EDGpRdR+cVodnpxSDmMGb2wjTVz55ABZpuAgvThD9Y2c7i1
         qBqxciKCAAEwCgnweOngxZgWKdznK1+bnjNEieMzlNVMnGCQxd79kQqQZdo1REzPUyr6
         nZ4dYEFbHYQGy3D3bpUq2fGMQTs98v6XrIefnuIubUP5kqXv7m2QzvpSx5cNZNNUx/DV
         wtSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Fzb4rqSwVKVgEjWquOCvHCN6tT4Vn3m2WJhD2GlcEwE=;
        b=ldSeCw2YoAWQv624cilb50BhrPPN7ulnKO0MioPZGiswsFGKAIy/BE9VvGpql0KyAo
         TRvGi4BSdMJLIWqantzHkzrvmpWOCFNLPa8uQnzKaoisG85DdfD0dpMrMMQbPyrL5P45
         8MZP8lMTDzodQ6wXbTz1If8yR2Gd+3Ssf+Cm0qGZuROPsJXokXRMvauf791WfM/jsu6l
         cJ/r61aJdGA/xXbpq7wxsx6aoxtIDqb/T0HmVeOhsCVGhO2bI9lYI8HSRqnMlJpnJb1U
         Jb/+hNXdJ2GtHAsJJ3wIGrp/YinGN5yX4t/a6ENLh/g4o2/zKLjJ5vViuQtoPlxzkFFS
         Ijng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=KXerAm9P;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Fzb4rqSwVKVgEjWquOCvHCN6tT4Vn3m2WJhD2GlcEwE=;
        b=d8C3wI9mGJcujcASxelUi/UPRB9tx60MsE7j7rEGHdA38h1U8UHqYJyHkxQLFvO/yC
         JfVTERHQvNkKJKqEsqW/qnb/iwcLjHtLrG6nRDZ8ubHf3jYDaujiXDIQEQtHBzBvAHHb
         C1EOE6SN0g4lSjaA5JvGDkNFYY1bgeVobg+Vqljl3wU82CW1Nf4PxRF0eCTRJ5PkwfFt
         DfIcejM0K7tEHDgLlxGLxbioss9s2Sau/qCUgCGPBeXYoNW+Ya+O9ps/94UkC99a1MBg
         8ONh17JAqwhhcMbVAo3fLJLeUoOoc9pfye+QKePZr4qzikNTX/ojYZS0e+bv3GhuW+LV
         ogdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fzb4rqSwVKVgEjWquOCvHCN6tT4Vn3m2WJhD2GlcEwE=;
        b=Km5AzCagFxI8IJv/s9g+get5MxKY9SZhtX39Es4CsQrhiRUIbblh14O+ouSUIAyD/T
         irP6+4ob92b9PEuiKWF1kY0BdIP902WzcZKn6M+R74F6PTJHaF/TZyLFgCLVBRktApmE
         8iYOyQesEl65fQUkxKAM4BTnuB3agfvnYBg68wifGd2pgHcwuvhHDn4n5rTbT4q2MU9y
         5SaRT2sAbf1dFSgUvC2zcbISy7PIz2n/oU4ovThLhi6YMzQyVHZTG8KBVlkDzD9SVTQq
         6zYqVNf3VKOvwgXXAZQYypO2M/pzkBfyJ8ooaPkXiUn/3aw7LbsriDfje+jbDjXnbqLp
         l7iA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530qUVENlTW1Oh4+yi154v84YkqrMhHKYZxHLtp7H10rC3DlKAlY
	7Hlo+fNuqNrjk7T7n/h+TLM=
X-Google-Smtp-Source: ABdhPJz3MeOuh3zoEsn+ZudAmxqK5/UWNE9sbGXxemA3Ft3C7I5cM6zhtzAqEfWwFbxFKWOsU8yPDw==
X-Received: by 2002:a25:a3a2:: with SMTP id e31mr61336381ybi.351.1621001434992;
        Fri, 14 May 2021 07:10:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2787:: with SMTP id n129ls4360511ybn.6.gmail; Fri, 14
 May 2021 07:10:34 -0700 (PDT)
X-Received: by 2002:a25:68c3:: with SMTP id d186mr11522192ybc.66.1621001434561;
        Fri, 14 May 2021 07:10:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621001434; cv=none;
        d=google.com; s=arc-20160816;
        b=cPeBduOvNtemIbpOefSD3CeVMs8RZ6/txC8fdhvDRHwpzshEsMDVEXfazxZ8Ezy2lx
         tgm/wIKS326QUmFKv7IHkBpjLd3DIZndKEWwggqS/ZT0FFl6nqS59JxlA4XW1qJGv81w
         ZvuMQtIQEyi2KctCKDler5MFFNfltMDrIM1PspgCpamPHDynrF5socrzNueaxgdK9l+H
         Lmd0j1P9ezH9QMW6YQnSJ1bqk0syAujaA743fD5Yvq6rPkCn6nUD3M/b/Uc8O710KOx5
         Ibys2/rBJ6AnQdDKNykdCxXVAb/5gjxWVwBugLi4pLH5hBhrKluT6SdvRnjpnn1UNTX2
         ZH5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0Nxy7Xlpzt2QAaXIetxrlxgQk9jtY2mWLK0b7dOuIHY=;
        b=T1Zo3aYKcBjWkt7faHz9JVphTdUD2t4F3vyzU8shDJTZcCxtJbu7J0rNcgpyBoEIU8
         MKR2C7REFdEBli0/fmr3HPgEX7Pq8mctG0qkdox7geJnw6J+vpThHJdOj2PbncwkkIUl
         QxDYpQU/SzILczU4RLgf0My2C7qiJ0DG0AjacQa4/hoAol2iR0d5eAS0lIh+CzxGOWya
         TDLbuQP6h+7jdyqPDX9RWwREmuuIM0GfhwZH2BoAmKv+J5uEdgObxXtmTEUThx0TKDk9
         2iw4ce1y9ZPJKQmZK+W6reBWU+Z4CqjgW6ZbJC1FTXwL2BCJnltz1OPWR8V3zyzKD0Ix
         ZhKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=KXerAm9P;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e5si388051ybb.3.2021.05.14.07.10.34
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 07:10:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id EC583613E9;
	Fri, 14 May 2021 14:10:32 +0000 (UTC)
Date: Fri, 14 May 2021 16:10:30 +0200
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Marco Elver <elver@google.com>, Nathan Chancellor <nathan@kernel.org>,
	Nick Desaulniers <ndesaulniers@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	clang-built-linux@googlegroups.com
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
Message-ID: <YJ6E1scEoTATEJav@kroah.com>
References: <20210514140015.2944744-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210514140015.2944744-1-arnd@kernel.org>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=KXerAm9P;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Fri, May 14, 2021 at 04:00:08PM +0200, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> clang points out that an initcall funciton should return an 'int':
> 
> kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
> late_initcall(kcsan_debugfs_init);
> ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
> include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
>  #define late_initcall(fn)               __define_initcall(fn, 7)
> 
> Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  kernel/kcsan/debugfs.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index c1dd02f3be8b..e65de172ccf7 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -266,9 +266,10 @@ static const struct file_operations debugfs_ops =
>  	.release = single_release
>  };
>  
> -static void __init kcsan_debugfs_init(void)
> +static int __init kcsan_debugfs_init(void)
>  {
>  	debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
> +	return 0;
>  }
>  
>  late_initcall(kcsan_debugfs_init);
> -- 
> 2.29.2
> 
Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YJ6E1scEoTATEJav%40kroah.com.
