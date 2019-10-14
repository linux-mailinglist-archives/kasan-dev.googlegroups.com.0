Return-Path: <kasan-dev+bncBCM2HQW3QYHRBKU5SLWQKGQEEMJUQ7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DF86D65D3
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 17:05:15 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id n4sf18141715qtp.19
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 08:05:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571065514; cv=pass;
        d=google.com; s=arc-20160816;
        b=okM3YsMVcBpO7Q1M7cgittwq5lAuGYdTQHVWchBkaIHUpHudCOOxkp0k+guf2xcVhS
         w3GCScSHTogOMm+1CtuO8NXOkVCZM/0d3GUFslJY/8p4dNQw7SGYXCyadMqKwkhzycc2
         d1p3cRbpv3B1K5N3HYWsUCi8yWKiuayzWNfwgBhoiVmKeM+RIYJn23YT5iiVMgxFnQBV
         XNBLJWR44GJmhrBpfkXtLJ0FwMg0pdcYdAK2Hh5jyKQy3EiUQN3gmAJsmQ+E7ABGa9fw
         KreeyjAKhylQQ+Z3PsJKLWiM4ywQRA/1MkTrfG8WpHVZ5T9jpc0sulm1kgjCYbcg1RvR
         Qp5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=9e5FhMBK7DD0U+Tq3HdEZObn2tDy9KKbOofovwCXM88=;
        b=jzw6b0kgpQt8VerY+fCk+SfyzWLIw/CF6nwVXZZhNa7JO4BEdkXrplLi6ZPh8CaSGi
         UU2AWPXXJe+Rn8z+rNZugbh1lxaLwq9XXkLKhhAr0U11109qLG7nzPUw5fl2idUJUw1R
         t5Ix58/ezgkWS7Gaz0oKSljoyzHMg1ZWudhtsD9g14klhzrGgmqkBmzaOb1rGqACVkaN
         f1vdJWa2sGNk1/NId52iowHsS5r6PaTj24yMzEK0WF7roJftbpQ5GTfAh1uwCmqHDa4c
         5wYZ0Vl/GREx52P85yhJg5xs85tjIeWqz2eqvVOU77pWh2hZHliCCubQ1X3rElMUrehx
         c6Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=o99ZYYOV;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9e5FhMBK7DD0U+Tq3HdEZObn2tDy9KKbOofovwCXM88=;
        b=Smrxau89SOsHrEPemDEpF0BmgTw9UmFNPXqMq+OYjPRg+JPpN7L6GtnNv67jiwWxlJ
         VNsa14hROlyUhQf60xtKi89VIr6IEGB2B9/qmQAJcIWqEYhz4zYvFvmqzvcXoomV/0VE
         WWCc4JEpUOrfkJAPHVHBH7+mEV5ESWlS9oCoN/53JMEOCufKHBzr8gsCl0KiNJpEuPMD
         8HYPGnEqMxRM/3YZCQT1Mf4mguwKDnlG5WsOgMhGCe3iXpEiYbhOSBEmRyKHtdlF0oNE
         Q8xjqsO+CqLfoiZBmEVQFi+NR3mEWLfa4llW/8jUPuBwbDp7hyBLDVUtfiCjt8YwY1KJ
         +oDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=9e5FhMBK7DD0U+Tq3HdEZObn2tDy9KKbOofovwCXM88=;
        b=Ny8G1eYG2MmIU6WJaTzWOo/v4FES89+IeYgk+8c+CM+qLZ6wZio9e9l3EAgO3W8dDt
         n16LYiWpzviX/zpFFv1lSyVJP+sqz123cAgVnW95GPluxi0/Py/qLQ6B/K/KEC0tHorr
         rQhsqP7QfJUbyUx4tEELnAsdMmB8mlX4PSGA4BH8QqhFpqyLmHLbAw5+lYGYpIiMrdrG
         if7JCqFkyR+Qm8/7hfBzGaGnPAuzSDWjhmeQRawfP6wTaIEviwJLOl5atI9z9dC0URa8
         DQqymwtK/pAC3PUoLNKMm3R9xAo1TglalkqwH3YVreNpxv6OOOppUzNbSrmkFdd9xtZk
         9e5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWm4/7JiO9x1Lpk933tZXZ+vQ3iOhk6XAe+/yQ3BD/R0NbFBlzo
	QtaOIEp2clf9XyvN48efzQo=
X-Google-Smtp-Source: APXvYqwXwVPBRKjB8hgn6YET6wd8jTbtET1khlRNuhnTOXnvq6HCqQftV3aVAjzoTqRw15TyCWU14g==
X-Received: by 2002:a37:af46:: with SMTP id y67mr30522649qke.84.1571065514209;
        Mon, 14 Oct 2019 08:05:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:d246:: with SMTP id o6ls2623698qvh.9.gmail; Mon, 14 Oct
 2019 08:05:13 -0700 (PDT)
X-Received: by 2002:a05:6214:1812:: with SMTP id o18mr31424530qvw.157.1571065513213;
        Mon, 14 Oct 2019 08:05:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571065513; cv=none;
        d=google.com; s=arc-20160816;
        b=Kz/fID7keGfFRO7frqNF77VyI8QmGGDn+FfhajcQ2j6c1ZAb8ZuQelasbdaoo3Tg7x
         vFhcKONrGEo5AqAcBhkyBnZiQ3epmTU67CN9aRmkzZ9Rr12rQ/CeImGehDzj9z8s03Gu
         IvwGQ0eGtSVNzaf4IsR8h3NtU6NlAgemm1PrRnopeX9Bgutca3YZbofHACZimeggdJQB
         DPYRCOlYEFUtDlK8l5pSmdEGOyJ48pBjRZQCzySIZj5+xp0wiZdz6Ine7XHNwbj7Y1yH
         31goJ+a4CaW67DbCXrxpeJBT84PoB1/7sU/AJ5P1OpGhQREI/SwEbiL2k3vxDdPEWqBK
         TFEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=5I0CZjdT/2pnYNFsgHQmuSO9JIMdOamZSLZFBh5OmRw=;
        b=Gg8yjWyW5VCs+451aLhmXFC1qVRpzne4C+dYRqxLJwAuIFKtHJXd3tZoPn2mrBsy6T
         PCnBzHGjj2zWbbQdVF8WpmrCulKmBrdsQ+XGN5AydYZeh4/tXGFTL9XQqlCEYcXtF4BG
         NuVOvEmD6KhrwesGMcrRRzjQh31U4LqN6Z3PLzWZwnNTdmmAVbweQ1QDJtBMv6zYXbza
         n4yUscYSWH7Lih5WqvsXtSkmWAqtYWik3GVpJD20RidIjzYSvgBFiBNhR0eoU1979cVi
         GlTiRvcN4f+tQNojtwwhoPuW/xElB1VVttStdNtRit2AhRjpGVFb5wXXgzezC1OVrw0o
         ZeKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20170209 header.b=o99ZYYOV;
       spf=pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) smtp.mailfrom=willy@infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:e::133])
        by gmr-mx.google.com with ESMTPS id x44si1077942qtc.3.2019.10.14.08.05.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2019 08:05:13 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of willy@infradead.org designates 2607:7c80:54:e::133 as permitted sender) client-ip=2607:7c80:54:e::133;
Received: from willy by bombadil.infradead.org with local (Exim 4.92.3 #3 (Red Hat Linux))
	id 1iK1uE-0007fP-VL; Mon, 14 Oct 2019 15:05:06 +0000
Date: Mon, 14 Oct 2019 08:05:06 -0700
From: Matthew Wilcox <willy@infradead.org>
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linux-mediatek@lists.infradead.org, wsd_upstream@mediatek.com
Subject: Re: [PATCH 1/2] kasan: detect negative size in memory operation
 function
Message-ID: <20191014150506.GX32665@bombadil.infradead.org>
References: <20191014103632.17930-1-walter-zh.wu@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20191014103632.17930-1-walter-zh.wu@mediatek.com>
User-Agent: Mutt/1.12.1 (2019-06-15)
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20170209 header.b=o99ZYYOV;
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

On Mon, Oct 14, 2019 at 06:36:32PM +0800, Walter Wu wrote:
> @@ -110,8 +111,9 @@ void *memset(void *addr, int c, size_t len)
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> -	check_memory_region((unsigned long)src, len, false, _RET_IP_);
> -	check_memory_region((unsigned long)dest, len, true, _RET_IP_);
> +	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
> +	!check_memory_region((unsigned long)dest, len, true, _RET_IP_))

This indentation is wrong.  Should be:
+	if (!check_memory_region((unsigned long)src, len, false, _RET_IP_) ||
+	    !check_memory_region((unsigned long)dest, len, true, _RET_IP_))

(also in one subsequent function)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191014150506.GX32665%40bombadil.infradead.org.
