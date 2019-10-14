Return-Path: <kasan-dev+bncBCM2HQW3QYHRBIU6SLWQKGQENUD2XHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3d.google.com (mail-yb1-xb3d.google.com [IPv6:2607:f8b0:4864:20::b3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 76D29D65DF
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 17:07:15 +0200 (CEST)
Received: by mail-yb1-xb3d.google.com with SMTP id 133sf13919906ybn.19
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 08:07:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571065634; cv=pass;
        d=google.com; s=arc-20160816;
        b=g66TS8+Qw1/Zflt2X7lIbPSx5kG1qx3pmvOY2YXsTWVCqiIJVWbU7hUgD3Ju1EH17w
         7yEN97EiMZuL2z1naEpjOZuvoO49bTHWP5UYxxUZoELdbw5EZv25t+pUE0XPTvxHIlp/
         /sJKf8yOOGdvOjDE7pj3W4e/AZLXJ00QTeNkPL35HSyrdi94RXWMDYNm3e8tSkRMGzi6
         StyIpa0DoDrwZNqO10wzmw1bDLmdivFZEjTXj0QfSt9Sxr11elzusW45YR6HM9HIFlNM
         g7s1h4C+HXWSpfYMERB6oWhRPOZiaRlJiZ4VdnM0PduGYBsyRF7LcpIYnfppncpg0fvp
         lkfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=FOfuMV2+2PX5tVCarsEf6g62rj3z5uZXAXV9d4Yce7A=;
        b=D5iDNzRdYeloYowpQRy0DfgiR0A5OZ210AqndzeqPB4OPytrPyToYEVAhEbpNrExZ7
         znLWPTYPAr/zcMHIqAj/FDNGsevRDfbTCXO5TCNwtQoJ/szqmbfndBAD4C65S9/hEh7T
         47nsR8/lPsis6rF1rz14LYW38f8Pj9o+U/htzAIpyFCYahz82uCu8o6rrHBDa0a8RJzf
         3VO61v/TdtollLaZCB0cWX5we2hADS4kKo3vWVl7RT3l8lCx9kwh61E1m3cEvDTk2Y5y
         Ws1VQB4TfQprGicvHjqXg/v4n7v3raF+l3YmB3tiUE+J90cVZSUTXkZXKIJE+Gj8ydc1
         kFHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=cJB7Budp;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FOfuMV2+2PX5tVCarsEf6g62rj3z5uZXAXV9d4Yce7A=;
        b=frjpDsTKj1P505AexEKUZ10tR3WyuK7rlGpzYC3uAhXgatmtUuZBHLZzfy0OdrnZhV
         caMY3rVgMRAIVjotr3BP31XNqzkxCdh9YI8VsvJ35LNhOOn9Bt6FnTPWFVXzM+mKPKId
         PLkPlvylQKmmSdqnLHg9Fr5ramrzqXuitq+Wao8kdLghKIngcvZtql2+JeRoBUa7Jei5
         Eih4qAs5Wjg4x/asywo0QnOwR+iHI+dG/hVwlHzMH9U+nZamEvP3U3hxqLTovn9pkSOv
         Gn+r4epMNACB2lte5K7CTy+8YzLgYrEV7NLOOl78UjH4EtIPynzXJeBx/C7k/l+wHARG
         i9nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=FOfuMV2+2PX5tVCarsEf6g62rj3z5uZXAXV9d4Yce7A=;
        b=fUNZckNeyUl8RTogKiov7kPay0HBymwWBvk9f9js2Ck8cFlrG9LoeXDbcyBxi/OBuI
         zZzcqB9RSzbjgWea8UpwLhzfZhmg98ItbdBnFaKfV4BSvxnIDz/cT/DmaMv+9KYjF5/S
         Eq+yXqF+NZx8s58Qu2W17ghe8qCVwhKs20wwuC3xrLr/csWyxgFoA6vzE0WJETwuzuMz
         Sky6a54qnz2Pxt6ECcryi0D9+bVyrbIf3syqHK8gkq/rH0WA3GgDYe8kuCXEwYXxDitX
         t4HAnwaHild1YeAtoOmi1aFdjzPyfniIGNDvbBReA/j5QlVK5Bs4fRspEdMFGHx1LOq+
         ZCaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWrYbKoZMIsvsBjKNlGO4cCCyHGYhG/+bn/04fz2f+T0e6oq7k4
	EO/meD9TNEwrOQtLgcON2gY=
X-Google-Smtp-Source: APXvYqyaMVfecsNns7VpXu8pVTmud1SY2HILo3ZwPDzP3/hiEN5PX4Ha9jq8pyh1kPdgUVhrFjsvTQ==
X-Received: by 2002:a81:2f58:: with SMTP id v85mr13889009ywv.226.1571065634498;
        Mon, 14 Oct 2019 08:07:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:8109:: with SMTP id o9ls2351253ybk.3.gmail; Mon, 14 Oct
 2019 08:07:14 -0700 (PDT)
X-Received: by 2002:a25:2784:: with SMTP id n126mr20399053ybn.279.1571065634102;
        Mon, 14 Oct 2019 08:07:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571065634; cv=none;
        d=google.com; s=arc-20160816;
        b=ZbAB5faAif5fJmx2b2YHO+qG6ppsXBF0jcpheSz1smTnzCwsyFavgLbOPnkAtcqCQb
         IfDehAugudUrk9lmELXxMlpiaJnZEaMUZ2/V2SnDFudhLC0g4YwkDy/ihfWadpfECuSm
         oqYEfV1+/w6bjn//2tpXATQTY2f0v6Jt4nZG7R8TL7okg11wAr2dm/GJ8uK1lzy4K2Te
         EnxsRLOl7/5xQ6+EdOHJOapthN8giCL8fMMM4J2MgxhSmFlrHWsbJ2+aEerRyAmsTfqY
         VyySZDSB8WWXuu8zGuQx01jB4MsHRkIf7iV+OpX9xenM3t8dfWFGrtEdsV3ZUSG9/jfr
         Rfcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=+kPyuVZ7GikTrqAAnx8uWQZ3WSRuJyPoCPBltjrCcIU=;
        b=D8+szXzJcRcXVhzjOhWbPIlJStGq5Q5V0O6PvdJiF5qQQnTPc6/xcW5EfaIzaNRJSP
         jZcqK4X2zfxESux4gizydB/l++rd1NvAqN44Ioe5AjUYvOpCv6WULcE+94BT5+yU1HyH
         3rAmVk0bpQwJLdbVSndWw4Cyx+5X3JoWjC0gdmnJHocNuJhmKYTJ1pZF0V6BDbQxarjU
         IW5GZhF2zbrJX0/7ND5EGcLAXLYDG3NBpqCPO7Wd3gwSG391s3T9tJu7y7MXQIq8sRlr
         q8IZ40Hwu2Fbzh9RpO/Ds+xZlLq1/UvQR5VvtdHTUx82Wpe/6YU3rZCykGQM9qyPMRTd
         pjIw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=cJB7Budp;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id u129si779165ywc.1.2019.10.14.08.07.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2019 08:07:14 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from willy by bombadil.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iK1wE-0000ND-79; Mon, 14 Oct 2019 15:07:10 +0000
Date: Mon, 14 Oct 2019 08:07:10 -0700
From: Matthew Wilcox <willy@infradead.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
Subject: Re: [PATCH 2/2] kasan: add test for invalid size in memmove
Message-ID: <20191014150710.GY32665@bombadil.infradead.org>
References: <20191014103654.17982-1-walter-zh.wu@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191014103654.17982-1-walter-zh.wu@mediatek.com>
User-Agent: Mutt/1.12.1 (2019-06-15)
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=cJB7Budp;
       spf=pass (google.com: best guess record for domain of
 willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
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

On Mon, Oct 14, 2019 at 06:36:54PM +0800, Walter Wu wrote:
> Test size is negative numbers in memmove in order to verify
> whether it correctly get KASAN report.

You're not testing negative numbers, though.  memmove() takes an unsigned
type, so you're testing a very large number.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014150710.GY32665%40bombadil.infradead.org.
