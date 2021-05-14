Return-Path: <kasan-dev+bncBD4NDKWHQYDRBAMD7OCAMGQEXLWIZZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id EF982380FBC
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 20:29:22 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id p133-20020a37428b0000b02902de31dd8da3sf22520613qka.1
        for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 11:29:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1621016962; cv=pass;
        d=google.com; s=arc-20160816;
        b=JaIIv1V7O/tZ8Z7crOZyXlHNDdAYTYimcx64vzls3tSE/mfUsNeUeJgHFzP3Mu9EAq
         OgJp7R7S9JW3T3fYxEqY8uqf55JbChCY7RsnXgBAyfVWtpiFXYvZDitRKpYTlLVNgV6n
         9pba97uqtApPq5qhIi2/syv8Liq3avL2BS6RSMXflKNPO1Dn0Bj6+PrdK6wxn4CKzV6y
         36nNc8+iVlx6XtKBjWXODYJSGhhm5C1GFUjhSY4yCHrN5oP6SvUIbecJekXHkOpev0LQ
         iVzhCkRmQJ8CtVh7jsZkJVNYUhl/uRWLIIbWBpqNNEfHjcPQPJSwSqMh5F6rDvaQBqtm
         nirQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=0FyKdm+lqlrZJ8TWDW3hsexnOafa4oq0oRGzmIEnKHo=;
        b=A4tKR+fp3NrQ3Oph520085b6noK6tnNfQmnV/mMz0wWBrqK16xy3/vazObmAumHJOA
         tTKk90vKAu8dhpJsxbwn3dRg9USYHHUurp1Y4XJzBM1azjN9NeenFfmPCf6iZC6R9sL0
         aw8EeHCxlellJEqfJkLRp4Bl+kjLkHjRjouL4N5I0/GsxBoq9LpMn5sTKZdg+tujOTSt
         XhcdzxjTFZXD+/xoh3SnVzqoOL24rcx+RyBBLVUqt94SvCcEfqnEdQ+Zvf5QZFypf/5+
         /Il3XO8Nlidc8ymzkmFw+ICL7O4E87Qz3n1cKDoENQMa6rOwnOA9W9VsZQsxCjd4B1vJ
         AC6Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tXUuvnKN;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0FyKdm+lqlrZJ8TWDW3hsexnOafa4oq0oRGzmIEnKHo=;
        b=A+EhWxUiCAvgO0cu8Q4gRbWrb4xapqEs8CIFH/wRte6VFAN2lL5FIprBUlESr/bTNJ
         fNJNrvSf7kXXWzl/pc3IiIkRBknoepzRetEgdzcimV/Eb5TziujerRxM0yuNXodUWWr4
         maHXLH9sgBOeM9dq1EGNJQMFf4DSoxLX0vNZ5UP2DbTRmRAFVJKcRduJxRECG/BA2ZTi
         g/aPBewB+9i39nGZS+oYduFbQ6dxZd/CWR6r/N9TtRJ+F70HevssKUdybYNpFeHi3v3u
         sF+EUkz1XJMLwhcGDbxLMUC1PsTUjZv3zsxaQ9j+opXo7vQbCVfP/Z1ip3CwMp37ITb/
         arRg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0FyKdm+lqlrZJ8TWDW3hsexnOafa4oq0oRGzmIEnKHo=;
        b=HlT5Pmpml++mkpp+4sxaV1WTapeX1vKaU9Bwl2082iCTCwKT1WBnin2lLH2nTgD9ds
         i+biy5WXYUt9Zu7qVaKOTMUj/P4l/CIUZhCJ2uRAYpsjDlRhhOz2WCJZPPy+kTomQVXS
         DdWVaH1z4Yh5+rslSUBzqpv5ekqjxO9UsRS7fpOlJYY4zk3lUo4HiAHfVQDZ/AIDnzem
         R+yeN6/L8ceM2nMXU3xIZekF+V1KfNJcarQiDpCqFAEwA/62T6Eps/Z7ZF290YjLMxMU
         JDLkR8mMRkFnYEkrOstFp4WBH/r0tjG+JX0d6+WWjqMI7oppZCuNDVXVPusf/YMzp2lP
         cObA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5337j05aaIzTi5brZqutkukHDJ8KJgGdN0YcWlt7rBq4QenUcwzL
	nHH7tXXv1SghKSvRkyhsQws=
X-Google-Smtp-Source: ABdhPJxkZ5YRWsTCbxHiFvUf4tWsay5n+gH6QtKApIcRsDOsagCgLJPfS6+3aqLmVNMQyd1mrclNTA==
X-Received: by 2002:ac8:4e3a:: with SMTP id d26mr6780498qtw.32.1621016961833;
        Fri, 14 May 2021 11:29:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7d86:: with SMTP id c6ls5026683qtd.1.gmail; Fri, 14 May
 2021 11:29:21 -0700 (PDT)
X-Received: by 2002:a05:622a:40d:: with SMTP id n13mr44899399qtx.59.1621016961414;
        Fri, 14 May 2021 11:29:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1621016961; cv=none;
        d=google.com; s=arc-20160816;
        b=IViUT7TVZWSXWT0iO9/0d3TRJPLhmYgnsO4UvUkGp8JTikDBbpsDXzO693XQ8XLueo
         ifz9C957VVH0rqahbcOKWYyI/yvJadn4jCrz5MkDYKVr9Vgc33YVBpgZUeuqsi3xgZT5
         r/i1jVdjTtxClBZMrKTMuxicu6Tkj2VsgeLSaQPUJ/14O6dMgG9f3zC/EVNoZUJMGKRp
         0LZYoo+PULq4HZ+dtB47x+7hKLvfNffkGIi1v1sw973fYDX1EBs5h50JSI/JhhOgYWxd
         1zlQM3EEW6PXWhNlmEJi+M90T45S3thrw4oNDccMq3Mfe2LtZThNSiWeuF6GGAGfMmWC
         9c3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=DVkh83Us4Gtqht2wF2X6mkkdk/eMRZQpRtWlxQ/Vnz4=;
        b=TeHsFu6lwtRKjemEONY/1/YD1wZ4rwubhFLzbhhhQu46hdjn7IoZQPwxJMN0CoJNFc
         ZqvADArQ3fp40FIUMoNaRzd28CLBVCFBM46yI4GxAKfDZbQrvhjMQqt1CF25Pi93FV64
         v+4v0yEup9ze3heAd1ixCEJBrur84Ufpal69Tbk09MR4mko2+MPK9rEiWBY5gZ1M9VeJ
         EP0W1E4dMGuL/Brc6vajDozkCguEaszKW80rg3OirfRYyAna3WUlKhxXB45Z5qd1wxD6
         4QdxNUeUrbeS26c2DfFSDnksoinzeoVR0kqSzLvAHVbtbAefulkJB84Oz1W0vAPgew3Q
         +dJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=tXUuvnKN;
       spf=pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=nathan@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id q5si759519qke.0.2021.05.14.11.29.21
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 14 May 2021 11:29:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of nathan@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 6694561442;
	Fri, 14 May 2021 18:29:19 +0000 (UTC)
Subject: Re: [PATCH] kcsan: fix debugfs initcall return type
To: Arnd Bergmann <arnd@kernel.org>, Marco Elver <elver@google.com>,
 Nick Desaulniers <ndesaulniers@google.com>,
 "Paul E. McKenney" <paulmck@kernel.org>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Cc: Arnd Bergmann <arnd@arndb.de>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
 clang-built-linux@googlegroups.com
References: <20210514140015.2944744-1-arnd@kernel.org>
From: Nathan Chancellor <nathan@kernel.org>
Message-ID: <0ad11966-b286-395e-e9ca-e278de6ef872@kernel.org>
Date: Fri, 14 May 2021 11:29:18 -0700
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.1
MIME-Version: 1.0
In-Reply-To: <20210514140015.2944744-1-arnd@kernel.org>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: nathan@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=tXUuvnKN;       spf=pass
 (google.com: domain of nathan@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=nathan@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On 5/14/2021 7:00 AM, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> clang points out that an initcall funciton should return an 'int':
> 
> kernel/kcsan/debugfs.c:274:15: error: returning 'void' from a function with incompatible result type 'int'
> late_initcall(kcsan_debugfs_init);
> ~~~~~~~~~~~~~~^~~~~~~~~~~~~~~~~~~
> include/linux/init.h:292:46: note: expanded from macro 'late_initcall'
>   #define late_initcall(fn)               __define_initcall(fn, 7)
> 
> Fixes: e36299efe7d7 ("kcsan, debugfs: Move debugfs file creation out of early init")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>

For the record, this requires CONFIG_LTO_CLANG to be visible.

Reviewed-by: Nathan Chancellor <nathan@kernel.org>

> ---
>   kernel/kcsan/debugfs.c | 3 ++-
>   1 file changed, 2 insertions(+), 1 deletion(-)
> 
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index c1dd02f3be8b..e65de172ccf7 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -266,9 +266,10 @@ static const struct file_operations debugfs_ops =
>   	.release = single_release
>   };
>   
> -static void __init kcsan_debugfs_init(void)
> +static int __init kcsan_debugfs_init(void)
>   {
>   	debugfs_create_file("kcsan", 0644, NULL, NULL, &debugfs_ops);
> +	return 0;
>   }
>   
>   late_initcall(kcsan_debugfs_init);
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0ad11966-b286-395e-e9ca-e278de6ef872%40kernel.org.
