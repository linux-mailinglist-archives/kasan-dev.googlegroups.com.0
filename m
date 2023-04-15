Return-Path: <kasan-dev+bncBDR7LJOD4ENBBB4W5GQQMGQEXBJJWBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 93C5D6E2F64
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Apr 2023 08:58:17 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id n10-20020a056e02100a00b00325c9240af7sf11111601ilj.10
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Apr 2023 23:58:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681541896; cv=pass;
        d=google.com; s=arc-20160816;
        b=mh4Gj/O9nwNMvLY8N7eByq7wXrNRCzecRYccRBpqTYPGX9hqr9kblbEv+xyVsir+pT
         U9oC2yTon8axRbfJFlxpCO80Cag7rWnZzZxhlzcZ94nSndGIKHdb7PxhnDEbuBHTrLYq
         NQfU5IlY8P5+9eGc9oH6HyoJkLEfyaYdVRFdrv4E3iNJXyzn606DcwaSm8F1+hPq/HSy
         Dmmv6S5sEfgc5KyY0wn4svWHYDsBdj8J6mnUpeqiHKbqItCTQweb+fFycuibsThuJboU
         8GCOL6lm8HGn9kxitZzGdPsZFjRLAFD2rPz75JHoKpiOoJIKGIvLaVrbnQcLELH7zmjF
         OzxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=bvc0BGYS8/POxZEqR3a4vmWEe4oix0HDYSr+gQ5roEw=;
        b=wNv2qpZMuKTQ6iYL2rZbfSy1nnBImgKfcxSSFg1f9xds0Fo74J7yTGn6aD59xaYM9W
         hYSHoHDc8OqX8e2jOurG9nX0l+wyXmk3rPorFNCL1uOXejdwwu9sWEjAXGux+mWODLE2
         nzpZXtdVtP9wFFuuYQG99U/wCXaH4rzFdeNzXUPlzjV3O3IFcLI4m+ETA2kzl+8tLTYY
         ovOfXDXkv2im+cKLjUYxs/FWlp76PYlwNHTbCbzFAntkDuzfuvKwbMWOGuPdIfmgTQOn
         RBXH9UahKUoE4YlWfJ8v4MJfmtgkwadP7yPKj4aeCHbbW6n2wtGaWIo8J4GZzQeyS03H
         6w4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=DJTp27DR;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681541896; x=1684133896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bvc0BGYS8/POxZEqR3a4vmWEe4oix0HDYSr+gQ5roEw=;
        b=jY75f7pu4el1fJTtYXiJXk6sl3oTjptBAIYeQB8OrXQk7wCJQ7XiTsRFCijUsl7OLd
         7pQGZvvhi4zFwLf5MWYyiSNSXqrH9aDNnAWHIdAGyAxCxFHiHOEotRkJc4n9/okEf/LS
         w/P6bGiQdCrGqCWyxG/6XPirmCW7eTILSM1Goem93RoolVTbxS9tLtdo7EKj18oGM5mn
         x/wphjLjd+CqfL5jccpj2bQ6f/z2Rf+fPHnV98auvFzb5w4p8y6vNhZxEy5e5hgQ2hC8
         93eRRxUqTRkJ2Y9ltXwF6Kj3JljAqM52KBVWIvWpnmfeIRjvD9SsHzrAOFbxA+w55L0H
         CrDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681541896; x=1684133896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bvc0BGYS8/POxZEqR3a4vmWEe4oix0HDYSr+gQ5roEw=;
        b=Q+Hl377DI4apqY3VsqdiaZdfacRtY6Si4hp2nKgQodfeuka2Gur5DLzffNdtvdvXX6
         450AsUWymbU8VDs+K8NtxQMtgVvPh/O6F/DkwM8HdsDZ29kduEiHoaQlgeoCc0Fd9jqj
         PYKN5ikSU+7vtLC3X/6RQVFMxSg2UIs/XDo7pPfv8W9mSf/GYSzvR8cpGZvGIVNsz8lY
         j6kz4H4MxrrI/J0Iq91QuMYvGgaZfF5ai4mlk5LYuFAp8gQtqPlhHdYEqL8uoglbXiIv
         t6XM9HoqpYyITZdO2fQrMlyaUbh8Cs9sWpGbqRt7ZxPrG9JozbqmjjHbC7Uhlw3xUmNf
         CDhQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9dMuoRKVx4AUM0a+epMgoya5kMjgUZmWkTtF9ikz2XsJD7Wa0lT
	MMVks4Lnp8wrlk4GlPxLNLQ=
X-Google-Smtp-Source: AKy350YCLihxaqOZB5WhRyNyDRl/Is1TehqdndQTTHsF3Eujd0KpElMIrYqSBrDk4+tdGBsF3lp3Iw==
X-Received: by 2002:a5e:da06:0:b0:745:68ef:e410 with SMTP id x6-20020a5eda06000000b0074568efe410mr3196457ioj.0.1681541895953;
        Fri, 14 Apr 2023 23:58:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2184:b0:32a:ad14:88b with SMTP id
 j4-20020a056e02218400b0032aad14088bls1040567ila.0.-pod-prod-gmail; Fri, 14
 Apr 2023 23:58:15 -0700 (PDT)
X-Received: by 2002:a92:c70b:0:b0:31f:9b6e:2f4a with SMTP id a11-20020a92c70b000000b0031f9b6e2f4amr5821017ilp.15.1681541895490;
        Fri, 14 Apr 2023 23:58:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681541895; cv=none;
        d=google.com; s=arc-20160816;
        b=zw1JGHZMXHGcVsQQfg4/LLOo2Xs+Ypz9cDeC2QUGi4KbldOpFKf0c6fST2NLoOwq8l
         bSKo8q401YtewajrVHa1lPEOM2AUollRNCnxiG1ahyVmjLOvUY2Rakgc8eDorQVotXvJ
         HLjnorGbyHEy2WTFCXCZQVUI3vmBxkv4su5BFuvnvq7OvB2WMhkp24MRtoY/VQN0+hLa
         5sh6gDUDGnpXNRJd19q9uHWIgy2kqZoA6htsWS5ZLlpOSC2zgCUh8kzBmSLmecnYaKzv
         1eX8wkGh4Ho1LwIHBch++nltNyvZYPYu4RubtM91RyLdvwlAIIe66jt2rS2r+trhxoJp
         uhtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ZJQMIaZu4KVcFRqyZTsotNIVVhw2hXDbq0PaE5k6CMg=;
        b=wBtYEXcfI0P9jrQgJhqy/umNo5tZM3/jmfE4WKazXAkAyZ0Z10YbBTpF+J4XmP8FGp
         iktHOOFPW8s5zfBLXX2Xk+9m9KbQRk2BGx1FmWUOoFGbbbeIOubdXltxIM4pTFd3NzBT
         SWXUwIZNxy4Fpkl0TkGUvgOlN9gZmaZmGH+Clrl2w2Ce9BYZPFJQB/naJBgPtlPQvIv4
         XBTyQUdZM4F9mGCEkLFIP1IpEJLMALwL1E+hARR/9LInnLOHQZwDU4KUYxJPDWzfCwq7
         1uc111DpSP3Xa6XL6//ZE+VH643/vzWS6XzlDQQ36C8L4/vEi0gVQ0AE8tzgiW5ChioS
         GWzA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@chromium.org header.s=google header.b=DJTp27DR;
       spf=pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
Received: from mail-pj1-x102b.google.com (mail-pj1-x102b.google.com. [2607:f8b0:4864:20::102b])
        by gmr-mx.google.com with ESMTPS id b3-20020a056638150300b0040bd078c5e9si454930jat.1.2023.04.14.23.58.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Apr 2023 23:58:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of senozhatsky@chromium.org designates 2607:f8b0:4864:20::102b as permitted sender) client-ip=2607:f8b0:4864:20::102b;
Received: by mail-pj1-x102b.google.com with SMTP id f2so12071154pjs.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Apr 2023 23:58:15 -0700 (PDT)
X-Received: by 2002:a17:902:6944:b0:19e:e001:6a75 with SMTP id k4-20020a170902694400b0019ee0016a75mr5558903plt.6.1681541894865;
        Fri, 14 Apr 2023 23:58:14 -0700 (PDT)
Received: from google.com (KD124209188001.ppp-bb.dion.ne.jp. [124.209.188.1])
        by smtp.gmail.com with ESMTPSA id s14-20020a170902988e00b0019c93ee6902sm3989398plp.109.2023.04.14.23.58.10
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Apr 2023 23:58:14 -0700 (PDT)
Date: Sat, 15 Apr 2023 15:58:08 +0900
From: Sergey Senozhatsky <senozhatsky@chromium.org>
To: Pavankumar Kondeti <quic_pkondeti@quicinc.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Petr Mladek <pmladek@suse.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	John Ogness <john.ogness@linutronix.de>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org
Subject: Re: [PATCH] printk: Export console trace point for
 kcsan/kasan/kfence/kmsan
Message-ID: <20230415065808.GI25053@google.com>
References: <20230413100859.1492323-1-quic_pkondeti@quicinc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230413100859.1492323-1-quic_pkondeti@quicinc.com>
X-Original-Sender: senozhatsky@chromium.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@chromium.org header.s=google header.b=DJTp27DR;       spf=pass
 (google.com: domain of senozhatsky@chromium.org designates
 2607:f8b0:4864:20::102b as permitted sender) smtp.mailfrom=senozhatsky@chromium.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=chromium.org
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

On (23/04/13 15:38), Pavankumar Kondeti wrote:
> The console tracepoint is used by kcsan/kasan/kfence/kmsan test
> modules. Since this tracepoint is not exported, these modules iterate
> over all available tracepoints to find the console trace point.
> Export the trace point so that it can be directly used.
> 
> Signed-off-by: Pavankumar Kondeti <quic_pkondeti@quicinc.com>

Reviewed-by: Sergey Senozhatsky <senozhatsky@chromium.org> # printk

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230415065808.GI25053%40google.com.
