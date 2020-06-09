Return-Path: <kasan-dev+bncBCG6FGHT7ALRBNFH7X3AKGQEMAYZ4TA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id E58A41F36CF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Jun 2020 11:17:40 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 11sf449330wmj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Jun 2020 02:17:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591694260; cv=pass;
        d=google.com; s=arc-20160816;
        b=IMW2WxjTJ6s6G1y0kCVIqpHieMpFzCenK/LC0CLIbNtf8NFe5O8F4R0o5Z/5MzWyv7
         rqNjS8WyLbVNVw97MVM1GNcRxRjgXmcAR4f4ahoJ9G1D9kFbdiUSjP/w+e+eljzCpLDr
         5H0Fh29WrlFPzQcexTKVKoFNwaOopEncg21NeWtHrxFTwGr7LE6ibnga0dTCGAMvd023
         o/tXAhCe1ceZF+nSO5O6rWLxI69/YfIj44Tom6gfkYvsN/odSbbUsbviQ66UN+T5mjwS
         jaCPyCtUAD86O6YaRsJc+NsUaRNKlbgEb+RQRRCWLbQ/CK74GsU+oy9WZnX/2KN31FRz
         /V7g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=XGB8WtCvxHpji9vcY2vTGLMrUnf+oMR+rdk9sFSDUK4=;
        b=pxAluSy9f6h9DcylxYSURH8ZiQX2cmowfPEHBCfDaE19/WOSeBjFWkI2+sKBWfrc5s
         aLyTzr2l0qb8ExjQmKwmHvrOw7A8/wExXgKypBWC7tzVXlxR5UsudYCVnc0O9x1mMk1s
         8qp0aQx5HWdvqwgzNqoJHaDyc/ImYqToyydBtBXqvvNB3ZXXZO0nLv+s5nVhbakPtLTy
         s5k5FSTC+YRstJjvRKYIQeizUfkR/Wg707XyUSB2OHBpyvRZ0aalGwFff66AUaFYFU6z
         SD7ml2G+oDvyqVdstoSYrUXpljEj0x3t3g1R6EefOVGi2n7k8J05CeEDXF59weKBQmc1
         T7zw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XGB8WtCvxHpji9vcY2vTGLMrUnf+oMR+rdk9sFSDUK4=;
        b=qNHQD3BuMInKGOcqImBAaBJZtaovJY9PzYRDaK37vM+UkTkdWUPHm00zse5RCHLfIk
         +w7PVKCwXic4TqnCxurCc2Hzs7LcHXdcwqYPfEXArgTMYDiOvZi6tlm8RYpdjRBg2UPe
         IRwiJsex1CkfM/oWXXTe6r0yy0jPWrEQpi0ltWt5uN2VRD6f22l8n+yIPqiWsphuY2d/
         nfMfc40ArHjqNtqpuGpSo9tLzy3AqYki5eFdb4tOgwgD1olHAYMAixbY9Cu5kc1uKedg
         thAy0xXaayVfyXK4Ve+QkRBwQPD1IW+sd4HSsdgpE8ZUKQ+9Z37X9d8m+fhoB1Avieqw
         h5aw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=XGB8WtCvxHpji9vcY2vTGLMrUnf+oMR+rdk9sFSDUK4=;
        b=T6gH1lL8fnO3938yKIf6zQIDLOXZAyPvT4PCSju9nxjTG3XPJ2jiD+67TX2njUSNyZ
         GIJoHe/W2oSUnQXTcDgOyAZ7m1iGciqkCnbP/jcfjvdkEcJoJ8CJnpauApM3vHDPrvEj
         8f7ZXwMKDk1FgUOcPQKhRDTMFJ+d5gQuB9DpxAGdn/yCCS5o37hhm6iTmOR0hU8Lqseb
         sbHof/6vW/uz3s7cmqet2Q9OXc9LS4ld5IbdoxWVwQ0hkaaC691iRuSAzDGNwMh7Ix7z
         oqfwEbxgDlctFjka18K/68Sq7gipYPgJwshO8OptLLa/P/JdEHbitZnok066WqXRAOCE
         welA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5320Xnk/8VaYb1Z/DWmBo8JBHazVzJQsiDXNs+HXo8rvrvZZLopS
	UpJmbKaG5T07l8E49QLtka4=
X-Google-Smtp-Source: ABdhPJwpDEn/2h4wrCjUERAKcW1Yrlh/wi1bpICA8MoFbYABmlwMY1fXPFQoG5F3uvXHKQsVdXQz/w==
X-Received: by 2002:a1c:1d16:: with SMTP id d22mr3112481wmd.174.1591694260593;
        Tue, 09 Jun 2020 02:17:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:aace:: with SMTP id i14ls2223491wrc.3.gmail; Tue, 09 Jun
 2020 02:17:40 -0700 (PDT)
X-Received: by 2002:adf:f889:: with SMTP id u9mr3592329wrp.394.1591694260062;
        Tue, 09 Jun 2020 02:17:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591694260; cv=none;
        d=google.com; s=arc-20160816;
        b=lW/r261HgIDVyiZdj1ZGHHrbXKYEAuHoG9hmtu9/Nm1E8zNv9wetdOOitbnmjMjdU5
         ryWop56IVpYTDpluNiC+G1kja+NY+g4KPZKSsCApSHXfgWJItE78KRDoKGCvDNuIdzOi
         LKSGVKlzwFqrfWl5HSr4TzhBQrV+37FquAVuLJzL0RRmOUnkpYnqZTSKfkDoGR3AthgW
         1UJf2wqj4WwBY2txFYSSV4esRgRAQw/PYMnmYzb8jYvibh3O94S5u/iDzAjZXuAUfdae
         rGzXV3MS9YYGleeMTj1DRKvZRuu/Wsj3dhPbKgvCv6jDfBuqD11H09cCYl/cjL9UZYV/
         tJIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=/uutpXxTe2OeTy5pWdpdxTZOotIgLjiyfHof2RMGKXA=;
        b=Lc5r4qPoRgnj4wkgDBnZmyAD+Eo+42sJFWUPvA7OrOxtAjgzBEv4HtRIFVP5fInlka
         Xmm2At/1AFeEMudkORHQFyP2VOiLqgvgUb9YtePQfHip60j/RYOIZluhQKAcfHWYRuv3
         xwg5QdPWZd/RqixoCbxP7mYmIPVtHO+6lhrnpDD9jqCG3NCPfpi3DA/ChJEw9+qarhUX
         S/lwf/86eWG92w0CIEYiSAFn/MLf5t0I7aW35S+6hrAvuVUjZ56nlEDeAPQSHkjvO9W7
         AVCHP/jNez/RzEdX6zMX7oiFDt5hLD8MgHkUgz09cdWvI4QxjashFkA3dsdaEXvCH1WV
         pJmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id m16si200433wmg.2.2020.06.09.02.17.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Jun 2020 02:17:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 18405B13F;
	Tue,  9 Jun 2020 09:17:43 +0000 (UTC)
Subject: Re: [PATCH v2] tsan: Add optional support for distinguishing
 volatiles
To: Marco Elver <elver@google.com>, gcc-patches@gcc.gnu.org, jakub@redhat.com
Cc: kasan-dev@googlegroups.com, dvyukov@google.com, bp@alien8.de,
 Dmitry Vyukov <dvuykov@google.com>
References: <20200609074834.215975-1-elver@google.com>
From: =?UTF-8?Q?Martin_Li=c5=a1ka?= <mliska@suse.cz>
Message-ID: <e7b5f092-5d78-7be4-fd43-3785961b80f9@suse.cz>
Date: Tue, 9 Jun 2020 11:17:38 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.1
MIME-Version: 1.0
In-Reply-To: <20200609074834.215975-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
X-Original-Sender: mliska@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=mliska@suse.cz
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

On 6/9/20 9:48 AM, Marco Elver wrote:
> v2:
> * Add Optimization keyword to -param=tsan-distinguish-volatile= as the
>    parameter can be different per TU.
> * Add tree-dump check to test.

Hello.

I support the patch.
@Jakub: Can you please approve the patch?

Thanks,
Martin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e7b5f092-5d78-7be4-fd43-3785961b80f9%40suse.cz.
