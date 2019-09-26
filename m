Return-Path: <kasan-dev+bncBDVIHK4E4ILBBT4AWLWAKGQEFU5S7WI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B43DBEE14
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 11:09:35 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id v18sf658349wro.16
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Sep 2019 02:09:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569488975; cv=pass;
        d=google.com; s=arc-20160816;
        b=Rln4VJqCr5J/qx3kAkqADhzkQS+MY3uK0Ag3eKp4rL9fAZp9jTIFd9xxACxS5eGXl6
         HEm6VJ/wAvmKuQnqpRHNDGpvgQxrWcY7wRnksvWnOb9Af5nce7nzNF0p/FwYD56BF8m6
         uYGoPZ2sDMQqOkn2AB+V4Br1AZABxjvrVG33jad8QoRBZ1lW8I0OKahTrT7m7duFxJKQ
         GO6jN2SYoeXeESpCdAIGrjygrzDsBd5DGqXJ1IpHEh8EoSfppHfEc+/FBy5vrZmxxaUi
         7waYHZidTPiL5bLQFCfSVCMBeyGzCQIE+bte6XNqt4HypZhdAWUit0Mlv46ZT0Y1PfyY
         kAGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=rxAt+3ZH3ZwAkfghrGH4+oWtDH4D3+clhmoOxGQQ3t8=;
        b=G7V/nuyz/bvH9uVMRMMNXGuBtLo25wI90EyM9EbxP+FvhmiLWL9GKozX403xovv7oS
         Wvr+4rCNQQ/ydschUfjKLs8dol2dO2atHPNLWkoLxvpiAaDxkbxybQS1t7F9zFu9AjiA
         2oFfZk2M5Op0udjC9OJkPZbpb2+iBHN5KXZ7cAwrf59Ap/l6arhCRv0E0d5CYwM6dNmj
         8TA8YLFEQSBW58iruEHQ3EHjMjP04sJeyKv/owNl/0IPWEutPJRspYZOXS495pEwPpnh
         TRutXGDmXrI71hWT9kChWBkh8t2UmfZ3PehDGn17mPx+MQHD7qmQgD6iDXE7/xb6mqLL
         OmuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b="eZ/L2L86";
       spf=neutral (google.com: 2a00:1450:4864:20::544 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=rxAt+3ZH3ZwAkfghrGH4+oWtDH4D3+clhmoOxGQQ3t8=;
        b=dWoTI2ei5G+ihic48Rso8CxsKidt0vHFrvNAp6jzTwIk77CdsJ91izjHoueaarleOy
         qQc409sJtpX+LWrB9NaS3Dq5NOCo2mGNOVjogMqVqgxizcPrvTtPHOpEPUcC99ebgkG3
         8KvHXwFfrJ+yAlcUkGkispErwlsAjO4RmswD+Fl6J9spoeEAAis/bUjiZC1sZBlQUEOL
         VyfX+htA+eP7MbpOWcB6s+vNBur+FCIB7Cu/kQ+LswjKciq2C4d355s1VHSUaug58cxy
         9hZXAbCdE4GQaOtNdLJztbUfelIssUmoHq5kyaVgYnVxIDOtgyFMGnDscaG2QXIMsA+E
         XIHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=rxAt+3ZH3ZwAkfghrGH4+oWtDH4D3+clhmoOxGQQ3t8=;
        b=LmUDB95/KLzRy513Cg7Ajb+1Wzx9k3nX8G0ARQzoZRZgNie5t8Jqqu8myIbC5F1C2C
         HCxMW9tfontCITdFJghGNO6Ngwr5zia7s38cRRPhs4eA8qmLyvlYZ/hW1R3a/UiUAzIA
         sjC4b4KIjanl1oinzlAzEf/8iT24ulGcO4qkonOslXK3KEYNTovCNQ2nd61A9OJ7xbPP
         fYe/bILFbuiOtznpfyvHEE0t9Gt10QmIg1b3I7LfJFhelMfIrKaz/15/SiIfVYTrJqIR
         V6b5fBCclfBJjSuO92dbEdstGp2MvNTLr3vo0Xe0a26FKVRAO7eSlexgcgx4Ejvx/cC0
         MchA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVE4suL0HOsGurGq7MVi231wDiTO3SkI7F5EIWBzLBlPwAwSYAj
	Dg5HT7rweOEiSNfIM4rz61k=
X-Google-Smtp-Source: APXvYqyfAmuymkMChFANchkDWqbePox0pNXP7yjpbprsgonxPRvbRoAeV1lIvF5yPIs6+QjWIbFxIg==
X-Received: by 2002:adf:e5c3:: with SMTP id a3mr1890332wrn.217.1569488975303;
        Thu, 26 Sep 2019 02:09:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:526c:: with SMTP id l12ls428746wrc.12.gmail; Thu, 26 Sep
 2019 02:09:34 -0700 (PDT)
X-Received: by 2002:adf:cd81:: with SMTP id q1mr1666568wrj.185.1569488974856;
        Thu, 26 Sep 2019 02:09:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569488974; cv=none;
        d=google.com; s=arc-20160816;
        b=Gz4W4pKn2/JP7L5fMAkIiZhrs1MwaEp8CBk2pQGYiueEWKqLULRrnRpDgWSAYzzs5N
         aqtuL12DaeOyBGlS0Qy9FROwlAW88HG6sIyfbPjoXTrRKrDsEHanKN+DhBonmmu56B5u
         Uxyca1zVhdLKbhD4p+hmon+R1fe+ijnA2fiqMfq81cxOzsT7o67EHVmqw9x95gD4q4qr
         5q2W1PwWckUm14c2Tw3fzvsW8KdkruUF0heMyyCwq/iJb7WK6wYyZfHm1ptC6yePMIdH
         DZCos2kAg3d9crFChReDFNJSbH8hKPRZs+DhHndxJFjWomOtxCcdJOKosmEvm6W6nOi7
         IAqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=hGYADD5SGijdLvajVeEAR1iT5VRxJ+M854JgFDPO0NA=;
        b=ji17zjhaVJB5rywmRjc7zRetSZ4hR05nOiZe7zyKiS8+VMfmbIk+rxOuGVECWbmvy4
         KoZ1iU1ANvArJ0bksi8nSYwb5Mf3ZiUo6JpPCvMPAxLgfYh1ZPY7CLV/BYGYzvlqU/m4
         vuHi63U1xOzc5TbgHysNF/D0GLzUrVHY/6jfXEftN9VDgs1KhYV5ck5ErDl5Sa9hCYfl
         U2f70C7j7h6iLf5iQ3RXiWx9rHoMPXBkf11lWTVv9tDJZhOGXBgFGc0IqlPmHRsVhdUa
         y8Dz5/g4VuF+bDNSpu+yrdrNVpjwRAAcXbQWs8uNV2N04PrsfyeaJuQKH25Ek5iRJouk
         H1Eg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623 header.b="eZ/L2L86";
       spf=neutral (google.com: 2a00:1450:4864:20::544 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
Received: from mail-ed1-x544.google.com (mail-ed1-x544.google.com. [2a00:1450:4864:20::544])
        by gmr-mx.google.com with ESMTPS id i7si81694wrs.1.2019.09.26.02.09.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 26 Sep 2019 02:09:34 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::544 is neither permitted nor denied by best guess record for domain of kirill@shutemov.name) client-ip=2a00:1450:4864:20::544;
Received: by mail-ed1-x544.google.com with SMTP id c4so1308916edl.0
        for <kasan-dev@googlegroups.com>; Thu, 26 Sep 2019 02:09:34 -0700 (PDT)
X-Received: by 2002:a50:fa09:: with SMTP id b9mr2360050edq.165.1569488974289;
        Thu, 26 Sep 2019 02:09:34 -0700 (PDT)
Received: from box.localdomain ([86.57.175.117])
        by smtp.gmail.com with ESMTPSA id b16sm163968eju.74.2019.09.26.02.09.33
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 26 Sep 2019 02:09:33 -0700 (PDT)
Received: by box.localdomain (Postfix, from userid 1000)
	id EB10F102322; Thu, 26 Sep 2019 12:09:35 +0300 (+03)
Date: Thu, 26 Sep 2019 12:09:35 +0300
From: "Kirill A. Shutemov" <kirill@shutemov.name>
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	Qian Cai <cai@lca.pw>,
	"Kirill A. Shutemov" <kirill.shutemov@linux.intel.com>,
	Matthew Wilcox <willy@infradead.org>,
	Mel Gorman <mgorman@techsingularity.net>,
	Michal Hocko <mhocko@kernel.org>
Subject: Re: [PATCH 1/3] mm, page_owner: fix off-by-one error in
 __set_page_owner_handle()
Message-ID: <20190926090935.ofbyb2sjhi33nfp3@box>
References: <20190925143056.25853-1-vbabka@suse.cz>
 <20190925143056.25853-2-vbabka@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20190925143056.25853-2-vbabka@suse.cz>
User-Agent: NeoMutt/20180716
X-Original-Sender: kirill@shutemov.name
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@shutemov-name.20150623.gappssmtp.com header.s=20150623
 header.b="eZ/L2L86";       spf=neutral (google.com: 2a00:1450:4864:20::544 is
 neither permitted nor denied by best guess record for domain of
 kirill@shutemov.name) smtp.mailfrom=kirill@shutemov.name
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

On Wed, Sep 25, 2019 at 04:30:50PM +0200, Vlastimil Babka wrote:
> As noted by Kirill, commit 7e2f2a0cd17c ("mm, page_owner: record page owner for
> each subpage") has introduced an off-by-one error in __set_page_owner_handle()
> when looking up page_ext for subpages. As a result, the head page page_owner
> info is set twice, while for the last tail page, it's not set at all.
> 
> Fix this and also make the code more efficient by advancing the page_ext
> pointer we already have, instead of calling lookup_page_ext() for each subpage.
> Since the full size of struct page_ext is not known at compile time, we can't
> use a simple page_ext++ statement, so introduce a page_ext_next() inline
> function for that.
> 
> Reported-by: Kirill A. Shutemov <kirill@shutemov.name>
> Fixes: 7e2f2a0cd17c ("mm, page_owner: record page owner for each subpage")
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

Acked-by: Kirill A. Shutemov <kirill.shutemov@linux.intel.com>

-- 
 Kirill A. Shutemov

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190926090935.ofbyb2sjhi33nfp3%40box.
